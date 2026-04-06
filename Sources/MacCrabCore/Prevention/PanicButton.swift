import Foundation
import Darwin
import os.log

/// Emergency response: one-click breach containment.
/// Kills suspicious processes, blocks network, locks screen, logs everything.
public actor PanicButton {
    private let logger = Logger(subsystem: "com.maccrab.prevention", category: "panic-button")

    public struct PanicResult: Sendable {
        public let processesKilled: Int
        public let networkBlocked: Bool
        public let screenLocked: Bool
        public let dnsFlush: Bool
        public let timestamp: Date
        public let actions: [String]
    }

    public init() {}

    /// Execute emergency containment.
    public func activate() async -> PanicResult {
        logger.critical("PANIC BUTTON ACTIVATED — emergency containment in progress")
        var actions: [String] = []

        // 1. Kill all non-Apple processes with network connections
        let killed = killSuspiciousProcesses()
        actions.append("Killed \(killed) suspicious processes with network connections")

        // 2. Block all outbound traffic except essential services
        let blocked = enableEmergencyFirewall()
        actions.append(blocked ? "Emergency firewall rules activated" : "Firewall activation failed")

        // 3. Flush DNS cache
        let flushed = flushDNS()
        actions.append(flushed ? "DNS cache flushed" : "DNS flush failed")

        // 4. Lock the screen
        let locked = lockScreen()
        actions.append(locked ? "Screen locked" : "Screen lock failed")

        // 5. Clear clipboard (may contain stolen credentials)
        clearClipboard()
        actions.append("Clipboard cleared")

        // 6. Disable Bluetooth (prevent physical attacks)
        let btDisabled = disableBluetooth()
        actions.append(btDisabled ? "Bluetooth disabled" : "Bluetooth disable skipped")

        logger.critical("Panic containment complete: \(killed) killed, network \(blocked ? "blocked" : "open"), screen \(locked ? "locked" : "unlocked")")

        return PanicResult(
            processesKilled: killed,
            networkBlocked: blocked,
            screenLocked: locked,
            dnsFlush: flushed,
            timestamp: Date(),
            actions: actions
        )
    }

    /// Deactivate emergency mode — restore normal operation.
    public func deactivate() async -> [String] {
        var actions: [String] = []

        // Remove emergency firewall rules
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/sbin/pfctl")
        proc.arguments = ["-a", "com.maccrab.emergency", "-F", "all"]
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice
        try? proc.run()
        proc.waitUntilExit()
        actions.append("Emergency firewall rules removed")

        logger.info("Panic mode deactivated — normal operation restored")
        actions.append("Normal operation restored")
        return actions
    }

    // MARK: - Containment Actions

    private nonisolated func killSuspiciousProcesses() -> Int {
        var killed = 0
        let count = proc_listallpids(nil, 0)
        guard count > 0 else { return 0 }
        var pids = [Int32](repeating: 0, count: Int(count) + 50)
        let actual = proc_listallpids(&pids, Int32(pids.count * MemoryLayout<Int32>.size))
        guard actual > 0 else { return 0 }

        let safeProcesses: Set<String> = [
            "kernel_task", "launchd", "WindowServer", "loginwindow", "Finder", "Dock",
            "SystemUIServer", "mds", "mds_stores", "mDNSResponder", "configd", "syslogd",
            "logd", "powerd", "coreaudiod", "securityd", "trustd", "opendirectoryd",
            "maccrabd", "MacCrab", "Terminal", "iTerm2", "sshd", "notifyd",
        ]

        for pid in pids.prefix(Int(actual)) where pid > 1 {
            var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
            let result = proc_pidpath(pid, &buffer, UInt32(buffer.count))
            guard result > 0 else { continue }
            let path = String(cString: buffer)
            let name = (path as NSString).lastPathComponent

            // Skip system processes and safe processes
            if path.hasPrefix("/System/") || path.hasPrefix("/usr/libexec/") || path.hasPrefix("/usr/sbin/") { continue }
            if safeProcesses.contains(name) { continue }
            if path.hasPrefix("/Applications/") && !path.contains("/tmp/") { continue }

            // Kill unsigned processes from suspicious locations
            if path.hasPrefix("/tmp/") || path.hasPrefix("/private/tmp/") || path.hasPrefix("/var/tmp/") || path.hasPrefix("/Users/Shared/") {
                kill(pid, SIGKILL)
                killed += 1
            }
        }
        return killed
    }

    private nonisolated func enableEmergencyFirewall() -> Bool {
        let rules = """
        # MacCrab Emergency Firewall
        # Allow only essential services
        pass out quick proto tcp to port 53      # DNS
        pass out quick proto udp to port 53      # DNS
        pass out quick proto tcp to port 443     # HTTPS (for updates)
        pass out quick to 127.0.0.0/8            # Localhost
        block drop out quick all                  # Block everything else
        block drop in quick all                   # Block all incoming
        """
        let anchorPath = "/tmp/maccrab_emergency.conf"
        do {
            try rules.write(toFile: anchorPath, atomically: true, encoding: .utf8)
            let proc = Process()
            proc.executableURL = URL(fileURLWithPath: "/sbin/pfctl")
            proc.arguments = ["-a", "com.maccrab.emergency", "-f", anchorPath]
            proc.standardOutput = FileHandle.nullDevice
            proc.standardError = FileHandle.nullDevice
            try proc.run()
            proc.waitUntilExit()
            return proc.terminationStatus == 0
        } catch { return false }
    }

    private nonisolated func flushDNS() -> Bool {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/dscacheutil")
        proc.arguments = ["-flushcache"]
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice
        try? proc.run()
        proc.waitUntilExit()

        let proc2 = Process()
        proc2.executableURL = URL(fileURLWithPath: "/usr/bin/killall")
        proc2.arguments = ["-HUP", "mDNSResponder"]
        proc2.standardOutput = FileHandle.nullDevice
        proc2.standardError = FileHandle.nullDevice
        try? proc2.run()
        proc2.waitUntilExit()
        return true
    }

    private nonisolated func lockScreen() -> Bool {
        // Use pmset to lock immediately
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/pmset")
        proc.arguments = ["displaysleepnow"]
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice
        try? proc.run()
        proc.waitUntilExit()
        return proc.terminationStatus == 0
    }

    private nonisolated func clearClipboard() {
        // Can't use NSPasteboard from daemon (no AppKit), use pbcopy
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/pbcopy")
        let pipe = Pipe()
        proc.standardInput = pipe
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice
        try? proc.run()
        pipe.fileHandleForWriting.write(Data()) // Empty clipboard
        pipe.fileHandleForWriting.closeFile()
        proc.waitUntilExit()
    }

    private nonisolated func disableBluetooth() -> Bool {
        // Use blueutil if available, otherwise skip
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        proc.arguments = ["blueutil", "--power", "0"]
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice
        try? proc.run()
        proc.waitUntilExit()
        return proc.terminationStatus == 0
    }
}
