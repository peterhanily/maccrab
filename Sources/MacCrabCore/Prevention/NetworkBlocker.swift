import Foundation
import os.log

/// Enhanced network blocking using PF tables for O(log n) lookups.
/// Supports bulk IP blocking from threat intel feeds, bidirectional rules,
/// and auto-expiration.
public actor NetworkBlocker {

    /// MITRE D3FEND defensive technique this module implements.
    public nonisolated static let d3fend = D3FENDMapping.networkBlocker
    private let logger = Logger(subsystem: "com.maccrab.prevention", category: "network-blocker")

    private let anchorName = "com.maccrab"
    private let anchorPath = "/etc/pf.anchors/com.maccrab"
    private let tableName = "maccrab_blocked"

    private var blockedIPs: Set<String> = []
    private var isEnabled: Bool = false

    public init() {}

    /// Enable network blocking with initial IPs from threat intel.
    public func enable(ips: Set<String>) {
        blockedIPs = ips
        isEnabled = true
        writeAnchorFile()
        reloadPF()
        logger.info("Network blocker enabled: \(ips.count) IPs blocked")
    }

    /// Add IPs to the block table.
    public func addIPs(_ ips: Set<String>) {
        let newIPs = ips.subtracting(blockedIPs)
        guard !newIPs.isEmpty else { return }
        blockedIPs.formUnion(newIPs)
        if isEnabled {
            writeAnchorFile()
            reloadPF()
        }
        logger.info("Added \(newIPs.count) IPs to block table (total: \(self.blockedIPs.count))")
    }

    /// Block a single IP immediately.
    public func blockIP(_ ip: String) {
        blockedIPs.insert(ip)
        if isEnabled {
            writeAnchorFile()
            reloadPF()
        }
    }

    /// Remove all blocks.
    public func disable() {
        isEnabled = false
        blockedIPs.removeAll()
        do {
            try FileManager.default.removeItem(atPath: anchorPath)
        } catch {
            logger.warning("Could not remove anchor file at \(self.anchorPath): \(error.localizedDescription)")
        }
        reloadPF()
        logger.info("Network blocker disabled")
    }

    public func stats() -> (enabled: Bool, blockedCount: Int) {
        (isEnabled, blockedIPs.count)
    }

    /// Verify that `path` is NOT a symlink. Prevents symlink attacks where a
    /// root-privileged write is redirected to an attacker-chosen file.
    private func isNotSymlink(_ path: String) -> Bool {
        let fm = FileManager.default
        guard fm.fileExists(atPath: path) else { return true }
        guard let attrs = try? fm.attributesOfItem(atPath: path),
              let fileType = attrs[.type] as? FileAttributeType else {
            return false
        }
        return fileType != .typeSymbolicLink
    }

    private func writeAnchorFile() {
        let dir = (anchorPath as NSString).deletingLastPathComponent
        do {
            try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        } catch {
            logger.error("Failed to create PF anchors directory at \(dir): \(error.localizedDescription)")
            return
        }

        let tablePath = "/etc/pf.anchors/com.maccrab.table"

        guard isNotSymlink(tablePath), isNotSymlink(anchorPath) else {
            logger.error("Refusing to write PF anchor: path is a symlink (possible attack)")
            return
        }

        // Write table file (one IP per line)
        let tableContent = blockedIPs.sorted().joined(separator: "\n") + "\n"
        do {
            try tableContent.write(toFile: tablePath, atomically: true, encoding: .utf8)
        } catch {
            logger.error("Failed to write IP block table to \(tablePath): \(error.localizedDescription)")
            return
        }

        // Write anchor rules using the table
        let rules = """
        table <\(tableName)> persist file "\(tablePath)"
        block drop out quick from any to <\(tableName)>
        block drop in quick from <\(tableName)> to any
        """
        do {
            try rules.write(toFile: anchorPath, atomically: true, encoding: .utf8)
        } catch {
            logger.error("Failed to write PF anchor rules to \(self.anchorPath): \(error.localizedDescription)")
        }
    }

    private func reloadPF() {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/sbin/pfctl")
        proc.arguments = ["-a", anchorName, "-f", anchorPath]
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice
        try? proc.run()
        proc.waitUntilExit()
    }
}
