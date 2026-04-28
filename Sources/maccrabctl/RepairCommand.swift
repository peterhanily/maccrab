// RepairCommand.swift
// maccrabctl
//
// `maccrabctl repair` — diagnose + auto-fix common MacCrab install
// issues. Added v1.7.5 after the v1.7.3 silent-heartbeat incident
// surfaced a need for "I'm having trouble, fix what you can" UX
// without forcing the user to manually run pgrep / lsof / stat /
// systemextensionsctl.
//
// Three phases:
// 1. Diagnose — report process liveness, heartbeat staleness,
//    sysext state, orphaned tmp files, on-disk perms.
// 2. Auto-repair (safe-only) — clean orphaned writeSnapshot tmp
//    files, SIGHUP daemon to reload config, SIGUSR1 to refresh
//    threat-intel feeds. Nothing destructive; nothing requiring sudo.
// 3. Recommend — print operator-action steps for issues we can't
//    fix automatically (reboot to clear zombie sysexts, re-approve
//    extension, grant FDA).

import Foundation

private struct AnsiColor {
    static let red = "\u{1B}[31m"
    static let green = "\u{1B}[32m"
    static let yellow = "\u{1B}[33m"
    static let cyan = "\u{1B}[36m"
    static let bold = "\u{1B}[1m"
    static let reset = "\u{1B}[0m"
}

private func sectionHeader(_ title: String) {
    print("\n\(AnsiColor.bold)── \(title) ──\(AnsiColor.reset)")
}

private func ok(_ msg: String) {
    print("\(AnsiColor.green)✓\(AnsiColor.reset) \(msg)")
}

private func warn(_ msg: String) {
    print("\(AnsiColor.yellow)!\(AnsiColor.reset) \(msg)")
}

private func bad(_ msg: String) {
    print("\(AnsiColor.red)✗\(AnsiColor.reset) \(msg)")
}

private func info(_ msg: String) {
    print("\(AnsiColor.cyan)→\(AnsiColor.reset) \(msg)")
}

@discardableResult
private func runShell(_ command: String, args: [String]) -> (status: Int32, stdout: String, stderr: String) {
    let proc = Process()
    proc.executableURL = URL(fileURLWithPath: command)
    proc.arguments = args
    let outPipe = Pipe()
    let errPipe = Pipe()
    proc.standardOutput = outPipe
    proc.standardError = errPipe
    do {
        try proc.run()
        proc.waitUntilExit()
    } catch {
        return (-1, "", error.localizedDescription)
    }
    let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
    let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
    return (
        proc.terminationStatus,
        String(data: outData, encoding: .utf8) ?? "",
        String(data: errData, encoding: .utf8) ?? ""
    )
}

func runRepair(args: [String]) async {
    let dryRun = args.contains("--dry-run") || args.contains("-n")
    let supportDir = "/Library/Application Support/MacCrab"

    print("\(AnsiColor.bold)MacCrab repair\(AnsiColor.reset)")
    if dryRun {
        info("dry-run mode: diagnostics only, no auto-fix actions")
    }

    // ─── 1. Process liveness ───────────────────────────────────────
    sectionHeader("Daemon process")
    let pgrep = runShell("/usr/bin/pgrep", args: ["-lf", "com.maccrab.agent"])
    if pgrep.status == 0 && !pgrep.stdout.isEmpty {
        ok("Daemon is running:")
        for line in pgrep.stdout.split(separator: "\n") {
            print("    \(line)")
        }
    } else {
        bad("Daemon process is NOT running")
        info("This is the most likely cause of \"Detection engine appears silent\" — sysext is approved but the launchd-managed process isn't alive")
    }

    // ─── 2. Heartbeat staleness ────────────────────────────────────
    sectionHeader("Heartbeat liveness")
    let heartbeatPath = supportDir + "/heartbeat.json"
    if let attrs = try? FileManager.default.attributesOfItem(atPath: heartbeatPath),
       let mtime = attrs[.modificationDate] as? Date {
        let age = Date().timeIntervalSince(mtime)
        let mtimeStr = mtime.formatted(date: .abbreviated, time: .standard)
        if age < 60 {
            ok("heartbeat.json fresh (last write \(mtimeStr), \(Int(age))s ago)")
        } else if age < 300 {
            warn("heartbeat.json stale: \(Int(age))s old (last write \(mtimeStr)). Threshold is 120s.")
        } else {
            bad("heartbeat.json badly stale: \(Int(age))s old (last write \(mtimeStr)). Daemon hasn't written in over 5 minutes.")
        }
    } else {
        bad("heartbeat.json missing — daemon has never started OR couldn't write to \(supportDir)")
    }

    // ─── 3. System Extension state ─────────────────────────────────
    sectionHeader("System extension state")
    let sysextList = runShell("/usr/bin/systemextensionsctl", args: ["list"])
    let maccrabLines = sysextList.stdout.split(separator: "\n")
        .filter { $0.contains("maccrab") }
    let activated = maccrabLines.filter { $0.contains("[activated enabled]") }
    let zombies = maccrabLines.filter { $0.contains("[terminated waiting to uninstall on reboot]") }
    if let active = activated.first, activated.count == 1 {
        ok("Active sysext: \(active.trimmingCharacters(in: .whitespaces))")
    } else if activated.isEmpty {
        bad("No activated sysext found — open MacCrab.app and approve the extension in System Settings → General → Login Items & Extensions → Endpoint Security Extensions")
    } else {
        warn("\(activated.count) sysexts marked activated — unexpected state, reboot recommended")
    }
    if zombies.count > 2 {
        warn("\(zombies.count) prior MacCrab versions queued for uninstall on reboot")
        info("This stack of pending uninstalls can cause sysextd to fail to start the active version cleanly. Recommendation: reboot to clear them.")
    } else if !zombies.isEmpty {
        info("\(zombies.count) prior version(s) queued for uninstall on reboot — normal during upgrade")
    }

    // ─── 4. Orphaned writeSnapshot temp files ──────────────────────
    sectionHeader("Orphaned snapshot temp files")
    let tmpFiles = (try? FileManager.default.contentsOfDirectory(atPath: supportDir)) ?? []
    let orphans = tmpFiles.filter { $0.hasSuffix(".tmp") }
    if orphans.isEmpty {
        ok("No orphaned .tmp files in \(supportDir)")
    } else {
        warn("\(orphans.count) orphaned .tmp file(s) found:")
        for f in orphans { print("    \(f)") }
        if !dryRun {
            for f in orphans {
                let path = supportDir + "/" + f
                if (try? FileManager.default.removeItem(atPath: path)) != nil {
                    info("removed \(path)")
                }
            }
        } else {
            info("dry-run: would remove these")
        }
    }

    // ─── 5. SIGHUP the daemon to force config + rule reload ────────
    sectionHeader("Daemon reload")
    if pgrep.status == 0 && !pgrep.stdout.isEmpty {
        if !dryRun {
            let kill = runShell("/usr/bin/pkill", args: ["-HUP", "com.maccrab.agent"])
            if kill.status == 0 {
                ok("Sent SIGHUP — daemon will reload config + rules without restart")
            } else {
                warn("pkill -HUP failed (status \(kill.status))")
            }
        } else {
            info("dry-run: would send SIGHUP to com.maccrab.agent")
        }
    } else {
        info("Skipping reload — daemon process not running")
    }

    // ─── 6. Operator-action recommendations ────────────────────────
    sectionHeader("Recommendations")
    if pgrep.status != 0 || pgrep.stdout.isEmpty {
        info("\(AnsiColor.bold)Reboot the machine.\(AnsiColor.reset) The most common reason MacCrab's process is dead while the sysext is marked active is leftover sysextd state from a previous upgrade. After reboot:")
        print("    1. Wait 30 seconds")
        print("    2. Run `pgrep -lf com.maccrab.agent` — should return a PID")
        print("    3. Run `maccrabctl repair` again to confirm liveness")
    }
    if zombies.count > 2 {
        info("Reboot will clear the \(zombies.count) prior versions queued for uninstall.")
    }
    if activated.isEmpty {
        info("Open /Applications/MacCrab.app and click \"Enable Protection\" on the Overview tab. macOS will prompt for approval in System Settings → General → Login Items & Extensions.")
    }
    print()
}
