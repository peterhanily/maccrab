// ManualResponse.swift
// MacCrabCore
//
// User-initiated response actions invoked from the dashboard. These run in
// the MacCrabApp process context (non-root user), distinct from the
// auto-response ResponseEngine that lives inside the sysext.
//
// - killProcess: kill(2) by PID, pkill -f by path fallback. EPERM →
//   permissionDenied (root-owned process).
// - quarantineFile: move to ~/Library/Application Support/MacCrab/quarantine
//   with com.apple.quarantine xattr and chmod 000 so accidental re-exec
//   is blocked.
// - blockDestination: pfctl via `osascript do shell script with
//   administrator privileges`, so the user gets one authorization prompt.
//   Uses a separate anchor (`com.maccrab.dashboard`) to not collide with
//   ResponseEngine's automated blocks under `com.maccrab`.
//
// All three throw typed errors so the UI can show actionable feedback
// instead of generic "failed" toasts.

import Foundation
import Darwin
import os.log

public enum ManualResponse {

    public enum ActionError: Error, CustomStringConvertible {
        case invalidInput(String)
        case permissionDenied(String)
        case notFound(String)
        case failed(String)
        case cancelled

        public var description: String {
            switch self {
            case .invalidInput(let s): return "Invalid input: \(s)"
            case .permissionDenied(let s): return s
            case .notFound(let s): return s
            case .failed(let s): return s
            case .cancelled: return "Authorization cancelled"
            }
        }
    }

    private static let logger = Logger(subsystem: "com.maccrab.app", category: "manual-response")

    // MARK: Kill Process

    /// Terminate a process. Prefers kill-by-PID when available; falls back
    /// to pkill -f against the full executable path.
    public static func killProcess(pid: Int32?, path: String) throws -> String {
        if let pid, pid > 1 {
            let rc = kill(pid, SIGTERM)
            if rc == 0 {
                logger.notice("SIGTERM sent to PID \(pid, privacy: .public)")
                return "SIGTERM sent to PID \(pid)"
            }
            switch errno {
            case EPERM:
                throw ActionError.permissionDenied(
                    "PID \(pid) is root-owned — use Terminal: sudo kill \(pid)"
                )
            case ESRCH:
                throw ActionError.notFound("PID \(pid) already exited")
            default:
                throw ActionError.failed("kill(\(pid)) errno=\(errno)")
            }
        }

        guard !path.isEmpty else {
            throw ActionError.invalidInput("No PID and no process path to match")
        }

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
        proc.arguments = ["-f", path]
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice
        do {
            try proc.run()
        } catch {
            throw ActionError.failed("pkill launch failed: \(error.localizedDescription)")
        }
        proc.waitUntilExit()
        switch proc.terminationStatus {
        case 0: return "Process terminated"
        case 1: throw ActionError.notFound("No running processes matched \(path)")
        default: throw ActionError.failed("pkill exit=\(proc.terminationStatus)")
        }
    }

    // MARK: Quarantine File

    /// Move a file to the per-user MacCrab quarantine vault, stamp the
    /// com.apple.quarantine xattr, chmod 000 the quarantined copy, and
    /// drop a JSON sidecar for forensics.
    public static func quarantineFile(
        path: String,
        ruleId: String,
        ruleTitle: String,
        alertId: String
    ) throws -> String {
        guard !path.isEmpty else {
            throw ActionError.invalidInput("No file path on this alert")
        }
        let fm = FileManager.default
        guard fm.fileExists(atPath: path) else {
            throw ActionError.notFound("File no longer exists: \(path)")
        }

        let home = NSHomeDirectory()
        let quarantineDir = "\(home)/Library/Application Support/MacCrab/quarantine"
        do {
            try fm.createDirectory(
                atPath: quarantineDir,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        } catch {
            throw ActionError.failed("Can't create quarantine dir: \(error.localizedDescription)")
        }

        let filename = (path as NSString).lastPathComponent
        let stamp = ISO8601DateFormatter().string(from: Date())
            .replacingOccurrences(of: ":", with: "-")
            .replacingOccurrences(of: "+", with: "Z")
        let dest = "\(quarantineDir)/\(stamp)_\(filename)"

        do {
            try fm.moveItem(atPath: path, toPath: dest)
        } catch let err as NSError
            where err.domain == NSCocoaErrorDomain
            && (err.code == NSFileWriteNoPermissionError
                || err.code == NSFileReadNoPermissionError) {
            throw ActionError.permissionDenied(
                "Can't move \(filename) — it's outside your home directory. "
                + "Use Terminal: sudo mv '\(path)' '\(dest)'"
            )
        } catch {
            throw ActionError.failed("Move failed: \(error.localizedDescription)")
        }

        // com.apple.quarantine xattr format: flags;timestamp;agent;uuid
        let xattrValue = "0083;\(Int(Date().timeIntervalSince1970));MacCrab;\(UUID().uuidString)"
        _ = xattrValue.withCString { cVal in
            dest.withCString { cPath in
                setxattr(cPath, "com.apple.quarantine", cVal, strlen(cVal), 0, 0)
            }
        }
        chmod(dest, 0o000)

        let sidecar: [String: Any] = [
            "original_path": path,
            "quarantined_at": stamp,
            "rule_id": ruleId,
            "rule_title": ruleTitle,
            "alert_id": alertId,
            "via": "dashboard",
        ]
        if let data = try? JSONSerialization.data(
            withJSONObject: sidecar,
            options: [.prettyPrinted, .sortedKeys]
        ) {
            try? data.write(to: URL(fileURLWithPath: dest + ".json"))
        }

        logger.notice("Quarantined \(path, privacy: .public) → \(dest, privacy: .public)")
        return "Moved to \(dest)"
    }

    // MARK: Block Destination

    private static let dashboardAnchor = "com.maccrab.dashboard"
    private static let blockedListPath =
        "\(NSHomeDirectory())/Library/Application Support/MacCrab/dashboard_blocked_ips.txt"

    /// Add an IP to the dashboard's PF anchor so outbound traffic to it is
    /// dropped. Uses AppleScript `with administrator privileges` so the
    /// user authorizes once; pfctl requires root.
    public static func blockDestination(ip: String) throws -> String {
        let trimmed = ip.trimmingCharacters(in: .whitespaces)
        guard isValidIP(trimmed) else {
            throw ActionError.invalidInput("Not a valid IP: \(ip)")
        }

        // Persist the blocked IP in a per-user list so subsequent invocations
        // accumulate (pfctl -f replaces the whole anchor each time).
        var ips = (try? String(contentsOfFile: blockedListPath, encoding: .utf8))
            .map { $0.split(separator: "\n").map(String.init) } ?? []
        if !ips.contains(trimmed) {
            ips.append(trimmed)
            let dir = (blockedListPath as NSString).deletingLastPathComponent
            try? FileManager.default.createDirectory(
                atPath: dir,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            try? ips.joined(separator: "\n").write(
                toFile: blockedListPath, atomically: true, encoding: .utf8
            )
        }

        // Build the PF anchor config and drop it in /tmp. Using a file (not
        // stdin) keeps the osascript command short and avoids shell-escape
        // landmines inside AppleScript's nested quoting.
        let ipList = ips.joined(separator: " ")
        let anchorConfig = """
        table <maccrab_blocked> persist { \(ipList) }
        block drop quick from any to <maccrab_blocked>
        block drop quick from <maccrab_blocked> to any
        """
        let tmpPath = "/tmp/maccrab-dashboard-block-\(UUID().uuidString).conf"
        do {
            try anchorConfig.write(toFile: tmpPath, atomically: true, encoding: .utf8)
        } catch {
            throw ActionError.failed("Can't write PF config: \(error.localizedDescription)")
        }
        defer { try? FileManager.default.removeItem(atPath: tmpPath) }

        // AppleScript passes the command to /bin/sh. `-a com.maccrab.dashboard`
        // keeps our rules in a named anchor that doesn't collide with the
        // sysext's automated blocks under `com.maccrab`.
        let shellCmd = "/sbin/pfctl -a \(dashboardAnchor) -f '\(tmpPath)' 2>&1"
        let script = "do shell script \"\(shellCmd)\" with administrator privileges"

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        proc.arguments = ["-e", script]
        let errPipe = Pipe()
        proc.standardError = errPipe
        proc.standardOutput = FileHandle.nullDevice
        do {
            try proc.run()
        } catch {
            throw ActionError.failed("osascript launch failed: \(error.localizedDescription)")
        }
        proc.waitUntilExit()
        if proc.terminationStatus != 0 {
            let errData = (try? errPipe.fileHandleForReading.readToEnd()) ?? nil
            let errStr = errData.flatMap { String(data: $0, encoding: .utf8) } ?? ""
            if errStr.contains("User canceled") || errStr.contains("-128") {
                throw ActionError.cancelled
            }
            throw ActionError.failed("pfctl failed: \(errStr.prefix(200))")
        }
        logger.notice("Blocked \(trimmed, privacy: .public) via PF anchor \(dashboardAnchor, privacy: .public)")
        return "Blocked \(trimmed) via PF (\(ips.count) total)"
    }

    private static func isValidIP(_ ip: String) -> Bool {
        var a4 = in_addr()
        var a6 = in6_addr()
        if inet_pton(AF_INET, ip, &a4) == 1 { return true }
        if inet_pton(AF_INET6, ip, &a6) == 1 { return true }
        return false
    }
}
