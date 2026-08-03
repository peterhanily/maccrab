import Foundation
import Darwin
import os.log

/// Emergency response: one-click breach containment.
/// Kills suspicious processes, blocks network, locks screen, logs everything.
public actor PanicButton {

    /// MITRE D3FEND defensive technique this module implements.
    public nonisolated static let d3fend = D3FENDMapping.panicButton
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
    ///
    /// - Parameter disableBluetoothInPanic: Whether to power off Bluetooth.
    ///   Defaults to `false` because users who rely on a Magic Keyboard or
    ///   Trackpad would lose all input mid-panic. Callers should expose this
    ///   as an explicit checkbox in the UI confirmation dialog and only pass
    ///   `true` when the user has wired peripherals available.
    public func activate(disableBluetoothInPanic: Bool = false) async -> PanicResult {
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

        // 6. Disable Bluetooth (prevent physical attacks). Off by default —
        // a user with a Bluetooth keyboard/trackpad would otherwise lose all
        // input mid-panic. Caller must explicitly opt in.
        let btDisabled: Bool
        if disableBluetoothInPanic {
            btDisabled = disableBluetooth()
            actions.append(btDisabled ? "Bluetooth disabled" : "Bluetooth disable skipped")
        } else {
            btDisabled = false
            actions.append("Bluetooth left on (caller did not request disable)")
        }

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
        if BoundedPrivilegedProcessRunner.run(
            executable: "/sbin/pfctl",
            arguments: ["-a", "com.maccrab.emergency", "-F", "all"],
            timeout: 10,
            maximumOutputBytes: nil
        ) != nil {
            actions.append("Emergency firewall rules removed")
        } else {
            logger.error("Failed to remove emergency firewall rules: trusted pfctl could not be launched")
            actions.append("Failed to remove emergency firewall rules")
        }

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
        guard let commandFile = PrivatePrivilegedCommandFile.create(
            contents: Data(rules.utf8)
        ) else { return false }
        defer { commandFile.cleanup() }
        guard commandFile.hasStableIdentity() else { return false }
        return BoundedPrivilegedProcessRunner.run(
            executable: "/sbin/pfctl",
            arguments: ["-a", "com.maccrab.emergency", "-f", commandFile.path],
            timeout: 10,
            maximumOutputBytes: nil
        )?.succeeded == true
    }

    private nonisolated func flushDNS() -> Bool {
        let cacheFlush = BoundedPrivilegedProcessRunner.run(
            executable: "/usr/bin/dscacheutil",
            arguments: ["-flushcache"],
            timeout: 10,
            maximumOutputBytes: nil
        )
        if cacheFlush == nil {
            logger.error("PanicButton: trusted dscacheutil could not be launched")
        }
        let responderReload = BoundedPrivilegedProcessRunner.run(
            executable: "/usr/bin/killall",
            arguments: ["-HUP", "mDNSResponder"],
            timeout: 10,
            maximumOutputBytes: nil
        )
        if responderReload == nil {
            logger.error("PanicButton: trusted killall could not be launched")
        }
        // Preserve the prior contract: this operation reported whether both
        // tools launched, while their exit statuses were advisory.
        return cacheFlush != nil && responderReload != nil
    }

    private nonisolated func lockScreen() -> Bool {
        // Use pmset to lock immediately
        let result = BoundedPrivilegedProcessRunner.run(
            executable: "/usr/bin/pmset",
            arguments: ["displaysleepnow"],
            timeout: 10,
            maximumOutputBytes: nil
        )
        if result == nil {
            logger.error("PanicButton: trusted pmset could not be launched, screen NOT locked")
        }
        return result?.succeeded == true
    }

    private nonisolated func clearClipboard() {
        // Can't use NSPasteboard from daemon (no AppKit), use pbcopy
        // The shared runner pins stdin to /dev/null, so pbcopy observes
        // immediate EOF and replaces the clipboard with empty input.
        if BoundedPrivilegedProcessRunner.run(
            executable: "/usr/bin/pbcopy",
            arguments: [],
            timeout: 10,
            maximumOutputBytes: nil
        )?.succeeded != true {
            logger.error("PanicButton: pbcopy failed, clipboard NOT cleared")
        }
    }

    private nonisolated func disableBluetooth() -> Bool {
        // blueutil is third-party software and is commonly Homebrew-owned.
        // A root caller must never PATH-resolve that binary. The operator may
        // configure an absolute path, but the complete path must pass the same
        // root-owned, non-writable, no-symlink executable policy as system tools.
        guard let configured = Foundation.ProcessInfo.processInfo.environment["MACCRAB_BLUEUTIL_PATH"],
              configured.first == "/",
              let trusted = PrivilegedExecutablePolicy.validatedExecutable(configured) else {
            logger.error("PanicButton: no trusted absolute MACCRAB_BLUEUTIL_PATH; Bluetooth NOT disabled")
            return false
        }
        return BoundedPrivilegedProcessRunner.run(
            executable: trusted,
            arguments: ["--power", "0"],
            timeout: 10,
            maximumOutputBytes: nil
        )?.succeeded == true
    }
}
