// SafePIDValidator.swift
// MacCrabCore
//
// Refuses to kill PIDs whose termination would damage the user's machine
// or trap the user out of their own system. Used by ResponseEngine and
// SupplyChainGate before any kill(pid, SIGTERM/SIGKILL).
//
// Sending SIGTERM to PID 1 panics the kernel. Killing WindowServer logs
// the user out. Killing opendirectoryd locks them out of authentication.
// Killing securityd kills keychain. The validator is a defense-in-depth
// guard for the case where a rule fires with a system PID — either from
// a hallucinated alert, a corrupted rule, or a recycled PID race.

import Foundation
import Darwin
import os.log

public enum SafePIDValidator {

    private static let logger = Logger(subsystem: "com.maccrab.prevention", category: "safe-pid-validator")

    /// Process basenames that must never be killed. Killing any of these
    /// either panics the kernel, strands the user, or breaks MacCrab's own
    /// ability to keep protecting the machine.
    public static let criticalProcessNames: Set<String> = [
        // Kernel & init
        "kernel_task", "launchd",
        // Window/login chain — losing these strands the user
        "WindowServer", "loginwindow", "Dock", "Finder", "SystemUIServer",
        // Auth, keychain, code signing
        "securityd", "trustd", "opendirectoryd",
        // System config / network / DNS
        "configd", "mDNSResponder", "discoveryd", "networkd", "symptomsd",
        // Logging
        "syslogd", "logd", "notifyd", "distnoted",
        // Audio / power / Bluetooth / display
        "coreaudiod", "powerd", "bluetoothd", "WirelessRadioManager",
        // Preferences
        "cfprefsd",
        // Spotlight
        "mds", "mds_stores",
        // MacCrab itself — never kill our own components, even by accident
        "maccrabd", "com.maccrab.agent", "MacCrab", "maccrabctl", "maccrab-mcp",
    ]

    /// Path prefixes that mark a binary as Apple-shipped system code.
    /// Refuse anything running from these paths even if the basename isn't
    /// on the critical list — covers the case where the name list missed
    /// something or a critical service was renamed across macOS releases.
    public static let protectedPathPrefixes: [String] = [
        "/System/",
        "/usr/libexec/",
        "/sbin/",
        "/usr/sbin/",
    ]

    /// Returns nil if the PID is safe to kill, or a human-readable rejection
    /// reason otherwise. The reason is suitable for logging.
    public static func reasonToReject(pid: Int32) -> String? {
        if pid <= 1 {
            return "PID \(pid) is reserved (kernel_task/launchd)"
        }
        if pid == getpid() {
            return "PID \(pid) is MacCrab itself"
        }

        // Resolve to a path. If proc_pidpath fails the process is gone or we
        // lack permission — be conservative and reject. This also defends
        // against the recycled-PID hazard: by the time we kill, the PID may
        // belong to a different process than the rule intended.
        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        let len = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard len > 0 else {
            return "PID \(pid) cannot be resolved (process gone or permission denied)"
        }
        let path = String(cString: buffer)
        let name = (path as NSString).lastPathComponent

        if criticalProcessNames.contains(name) {
            return "process \(name) (PID \(pid)) is on the critical-system protect list"
        }
        for prefix in protectedPathPrefixes {
            if path.hasPrefix(prefix) {
                return "process at \(path) (PID \(pid)) runs from a protected system path (\(prefix))"
            }
        }
        return nil
    }

    /// Convenience: true when reasonToReject returns nil. Logs a warning on
    /// rejection so callers don't need their own log line.
    public static func isSafeToKill(pid: Int32) -> Bool {
        if let reason = reasonToReject(pid: pid) {
            logger.warning("Refusing to kill: \(reason, privacy: .public)")
            return false
        }
        return true
    }
}
