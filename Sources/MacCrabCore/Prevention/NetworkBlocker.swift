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

    /// Operator disable latch — see the identical latch on DNSSinkhole. The
    /// threat-intel refresh callback in DaemonSetup used to call `enable(ips:)`
    /// unconditionally, silently re-arming the PF blocklist on the next feed
    /// refresh after the user had switched it off in the Prevention workspace.
    /// Feed-driven repopulation now goes through `refreshFromFeed`.
    private var operatorDisabled: Bool = false

    /// Cached result of the last enforcement probe, so `stats()` on the
    /// heartbeat path does not shell out to pfctl every tick.
    private var lastEnforcement: PFEnforcement.Status?

    public init() {}

    /// Drop IPs that must never be blocked — loopback, RFC1918/link-local, the
    /// current default gateway, and critical resolvers (Apple, Cloudflare,
    /// Google, Quad9, …) — and reject malformed entries, so a poisoned threat
    /// feed or a single false positive can't sever the host's own connectivity.
    /// Mirrors the gate ManualResponse/ResponseAction already apply.
    // `internal` (not private) so the protected-IP filter is unit-tested
    // directly without triggering enable()'s pfctl side effects. This is the
    // gate that keeps a poisoned threat-intel feed from PF-blocking DNS / the
    // gateway and bricking the host's network.
    func safeSubset(_ ips: Set<String>) -> Set<String> {
        var safe = Set<String>()
        var rejected = 0
        for ip in ips {
            if let reason = SafeBlockableIP.reasonToReject(ip: ip) {
                rejected += 1
                logger.warning("Refusing to block \(ip, privacy: .public): \(reason, privacy: .public)")
            } else {
                safe.insert(ip)
            }
        }
        if rejected > 0 { logger.notice("NetworkBlocker rejected \(rejected) unsafe/invalid IP(s)") }
        return safe
    }

    /// Enable network blocking with initial IPs from threat intel.
    public func enable(ips: Set<String>) {
        // An explicit enable is an operator/boot intent: clear the latch.
        operatorDisabled = false
        blockedIPs = safeSubset(ips)
        isEnabled = true
        writeAnchorFile()
        reloadPF()
        // v1.21.6-rc.45: do not claim a block that is not happening. This used
        // to log "Network blocker enabled: N IPs blocked" unconditionally,
        // because `pfctl -f` exits 0 even when PF is disabled.
        let pf = PFEnforcement.probe(anchorName: anchorName)
        lastEnforcement = pf
        if pf.enforcing {
            logger.info("Network blocker enforcing: \(self.blockedIPs.count) IPs blocked")
        } else {
            logger.warning("Network blocker CONFIGURED with \(self.blockedIPs.count) IPs but NOT enforcing — \(pf.reason, privacy: .public). No traffic is being blocked.")
        }
    }

    /// Feed-driven repopulation, for the threat-intel refresh callback ONLY.
    /// Identical to `enable(ips:)` except that it respects the operator disable
    /// latch. Anything reacting to a feed update must call this; only a
    /// deliberate operator or boot-time action may call `enable`.
    public func refreshFromFeed(ips: Set<String>) {
        guard !operatorDisabled else {
            logger.info("Network blocker feed refresh skipped — operator-disabled")
            return
        }
        enable(ips: ips)
    }

    /// Add IPs to the block table.
    public func addIPs(_ ips: Set<String>) {
        let newIPs = safeSubset(ips).subtracting(blockedIPs)
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
        if let reason = SafeBlockableIP.reasonToReject(ip: ip) {
            logger.warning("Refusing to block \(ip, privacy: .public): \(reason, privacy: .public)")
            return
        }
        blockedIPs.insert(ip)
        if isEnabled {
            writeAnchorFile()
            reloadPF()
        }
    }

    /// Remove all blocks.
    /// Sets the operator disable latch so the threat-intel refresh callback
    /// cannot silently re-arm PF blocking behind the user's back.
    public func disable() {
        isEnabled = false
        operatorDisabled = true
        blockedIPs.removeAll()
        do {
            try FileManager.default.removeItem(atPath: anchorPath)
        } catch {
            logger.warning("Could not remove anchor file at \(self.anchorPath): \(error.localizedDescription)")
        }
        reloadPF()
        logger.info("Network blocker disabled")
    }

    /// `enabled` is OPERATOR INTENT (the module is switched on). It is NOT a
    /// claim that packets are being dropped — read `enforcing` for that. The
    /// two were conflated until v1.21.6-rc.45, which is how the product
    /// reported blocking on a host where PF was disabled.
    public func stats() -> (enabled: Bool, blockedCount: Int, enforcing: Bool, reason: String) {
        let pf = lastEnforcement ?? PFEnforcement.probe(anchorName: anchorName)
        return (isEnabled, blockedIPs.count, isEnabled && pf.enforcing, pf.reason)
    }

    /// Live enforcement truth for this anchor.
    public func enforcement() -> PFEnforcement.Status {
        let pf = PFEnforcement.probe(anchorName: anchorName)
        lastEnforcement = pf
        return pf
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
        guard let result = BoundedPrivilegedProcessRunner.run(
            executable: "/sbin/pfctl",
            arguments: ["-a", anchorName, "-f", anchorPath],
            timeout: 10,
            maximumOutputBytes: nil
        ) else {
            logger.error("NetworkBlocker: bounded pfctl launch refused — the anchor file was written but NOT loaded, so no blocking is in effect")
            return
        }
        if !result.succeeded {
            logger.error("NetworkBlocker: pfctl did not complete successfully (status \(result.terminationStatus ?? -1, privacy: .public), timedOut=\(result.timedOut, privacy: .public)) loading anchor \(self.anchorName, privacy: .public) — blocking may not be in effect")
        }
    }
}
