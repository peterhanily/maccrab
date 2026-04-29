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
    let fixStorage = args.contains("--fix-storage")
    let supportDir = "/Library/Application Support/MacCrab"

    print("\(AnsiColor.bold)MacCrab repair\(AnsiColor.reset)")
    if dryRun {
        info("dry-run mode: diagnostics only, no auto-fix actions")
    }
    if fixStorage {
        info("--fix-storage: will back up corrupt events.db files and let the daemon recreate them on next launch")
    }

    // v1.7.6: --fix-storage path is the escape hatch for the case where
    // launchd has hit its respawn-throttle ceiling and the daemon
    // stopped trying. Mirrors what v1.7.6+ daemons do automatically on
    // init failure (DaemonSetup.recoverEventStore).
    if fixStorage {
        sectionHeader("Storage recovery (--fix-storage)")
        let dbPath = supportDir + "/events.db"
        if !FileManager.default.fileExists(atPath: dbPath) {
            ok("No events.db found at \(dbPath) — nothing to recover")
        } else {
            // Best-effort integrity check before backing up: if the DB
            // is healthy, recovery would lose data unnecessarily.
            let probe = runShell("/usr/bin/sqlite3", args: [dbPath, "PRAGMA integrity_check;"])
            let result = probe.stdout.trimmingCharacters(in: .whitespacesAndNewlines)

            // v1.7.9: schema-version sanity check on the alerts table.
            // PRAGMA integrity_check passes for the v1.7.5 → v1.7.6 bug
            // (alerts table missing llm_investigation_json column from
            // a silently-skipped migration) because the file IS valid
            // SQLite — it's just stale. Probe the columns we expect
            // alerts to carry; if any are missing, the DB is "logically
            // broken" even though physically intact.
            let alertsSchema = runShell("/usr/bin/sqlite3",
                                         args: [dbPath, "PRAGMA table_info(alerts);"])
            let expectedAlertColumns = ["llm_investigation_json"]
            let alertsCols = alertsSchema.stdout
            let missingAlertCols = expectedAlertColumns.filter { !alertsCols.contains($0) }
            let logicallyBroken = !missingAlertCols.isEmpty

            if result == "ok" && !logicallyBroken {
                warn("integrity_check returned 'ok' AND alerts schema looks current — events.db doesn't appear corrupt.")
                info("If the daemon still crashes on init, the issue is something else (permissions, locking). Skipping backup. Re-run with --force-fix-storage to back up anyway.")
                if !args.contains("--force-fix-storage") {
                    return
                }
                info("--force-fix-storage set — proceeding with backup despite both checks passing")
            } else if logicallyBroken {
                warn("alerts table missing expected column(s): \(missingAlertCols.joined(separator: ", "))")
                info("This is the v1.7.5 → v1.7.6 SchemaMigrator bug shape. Installing v1.7.6+ alone repairs the schema in-place — back up only if the daemon still can't recover.")
                if !args.contains("--force-fix-storage") {
                    return
                }
                info("--force-fix-storage set — backing up despite repairable schema state")
            } else {
                warn("integrity_check failed: \(result.prefix(200)) — backing up corrupt files")
            }
            if !dryRun {
                let ts = Int(Date().timeIntervalSince1970)
                for suffix in ["", "-wal", "-shm", "-journal"] {
                    let src = "\(supportDir)/events.db\(suffix)"
                    let dst = "\(supportDir)/events.db\(suffix).corrupt-\(ts)"
                    if FileManager.default.fileExists(atPath: src) {
                        let mv = runShell("/bin/mv", args: [src, dst])
                        if mv.status == 0 {
                            info("moved \(src) → \(dst)")
                        } else {
                            warn("mv failed (status \(mv.status)): \(mv.stderr.prefix(200)) — may need sudo")
                        }
                    }
                }
                ok("Files backed up. Daemon will recreate events.db on next launch (within ~10 s via launchd respawn)")
            } else {
                info("dry-run: would back up events.db / -wal / -shm / -journal to .corrupt-<ts> sibling files")
            }
        }
        // Continue with the standard diagnose phases below so the
        // operator sees the post-recovery state.
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
