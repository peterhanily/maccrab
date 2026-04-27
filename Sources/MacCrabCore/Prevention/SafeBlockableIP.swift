// SafeBlockableIP.swift
// MacCrabCore
//
// Refuses to PF-block IP addresses whose loss would brick the user's
// network or break the OS. Mirrors DNSSinkhole's protectedDomainPatterns
// for IP-level blocks. Used by ResponseEngine.blockNetworkDestination.
//
// Threat model: a poisoned threat-intel feed entry, a hallucinated LLM
// response, or a corrupted rule names 1.1.1.1 (Cloudflare DNS), 8.8.8.8
// (Google DNS), 17.0.0.0/8 (Apple), 127.0.0.0/8 (loopback), or the
// user's gateway as a "block this destination" target. The PF rule
// MacCrab installs would silently take down DNS resolution, code-
// signing OCSP, iCloud sync, or LAN connectivity. The validator
// refuses these and logs the rejection.

import Foundation
import Darwin
import os.log

public enum SafeBlockableIP {

    private static let logger = Logger(subsystem: "com.maccrab.prevention", category: "safe-blockable-ip")

    /// Hard-coded protected IP addresses (not CIDR ranges — those go below).
    /// Each is a service whose loss would visibly break the user's machine.
    public static let protectedExactIPs: Set<String> = [
        // Cloudflare public DNS / DoH
        "1.1.1.1", "1.0.0.1",
        "2606:4700:4700::1111", "2606:4700:4700::1001",
        // Google public DNS / DoH
        "8.8.8.8", "8.8.4.4",
        "2001:4860:4860::8888", "2001:4860:4860::8844",
        // Quad9
        "9.9.9.9", "149.112.112.112",
        "2620:fe::fe", "2620:fe::9",
        // OpenDNS
        "208.67.222.222", "208.67.220.220",
        // Common loopback / unspecified
        "127.0.0.1", "0.0.0.0", "::1", "::",
    ]

    /// CIDR ranges that are off-limits. Stored as
    /// `(networkAddressInHostByteOrder, prefixLength)` for IPv4 only —
    /// IPv6 ranges are handled by exact-match in `protectedExactIPs`
    /// (the rough cut works because Apple/loopback/link-local are the
    /// only IPv4 ranges we care about; IPv6 protected addresses are
    /// individually well-known).
    public static let protectedIPv4CIDRs: [(network: UInt32, prefix: Int, label: String)] = [
        // Loopback — blocking 127.0.0.0/8 breaks everything
        (network: ipv4("127.0.0.0"), prefix: 8, label: "127.0.0.0/8 (loopback)"),
        // Apple's public IP range — sinkholing breaks iCloud, code-signing
        // OCSP, App Store, software update, etc.
        (network: ipv4("17.0.0.0"), prefix: 8, label: "17.0.0.0/8 (Apple)"),
        // Link-local — DHCP failure recovery, mDNS infrastructure
        (network: ipv4("169.254.0.0"), prefix: 16, label: "169.254.0.0/16 (link-local)"),
        // Multicast — blocking breaks Bonjour/AirPlay/SSDP
        (network: ipv4("224.0.0.0"), prefix: 4, label: "224.0.0.0/4 (multicast)"),
        // Carrier-grade NAT — used by ISPs; blocking can break legitimate traffic
        (network: ipv4("100.64.0.0"), prefix: 10, label: "100.64.0.0/10 (carrier-grade NAT)"),
    ]

    /// Returns nil if `ip` is safe to PF-block, or a human-readable
    /// rejection reason otherwise.
    public static func reasonToReject(ip: String) -> String? {
        let trimmed = ip.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if trimmed.isEmpty {
            return "empty IP"
        }
        if protectedExactIPs.contains(trimmed) {
            return "\(trimmed) is a public DNS / loopback / unspecified address"
        }

        // IPv4 CIDR membership check — only attempt if the input parses as v4.
        var addr4 = in_addr()
        if trimmed.withCString({ inet_pton(AF_INET, $0, &addr4) }) == 1 {
            let host = UInt32(bigEndian: addr4.s_addr)
            for cidr in protectedIPv4CIDRs {
                let mask = cidr.prefix == 0 ? UInt32(0) : (UInt32.max << UInt32(32 - cidr.prefix))
                if (host & mask) == (cidr.network & mask) {
                    return "\(trimmed) is in protected range \(cidr.label)"
                }
            }
        }

        // Default gateway — blocking it cuts the user off from the LAN.
        // Resolved fresh on every call (cheap; fewer than ~10 ms).
        if let gw = currentDefaultGateway(), trimmed == gw {
            return "\(trimmed) is the current default gateway — blocking would sever LAN/WAN"
        }

        return nil
    }

    /// Convenience wrapper. Logs warning on rejection.
    public static func isSafeToBlock(ip: String) -> Bool {
        if let reason = reasonToReject(ip: ip) {
            logger.warning("Refusing to block: \(reason, privacy: .public)")
            return false
        }
        return true
    }

    // MARK: - Helpers

    private static func ipv4(_ s: String) -> UInt32 {
        var addr = in_addr()
        guard s.withCString({ inet_pton(AF_INET, $0, &addr) }) == 1 else { return 0 }
        return UInt32(bigEndian: addr.s_addr)
    }

    /// Resolve the current IPv4 default gateway by parsing
    /// `route -n get default`. Returns nil on failure (no route, parse error).
    static func currentDefaultGateway() -> String? {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/sbin/route")
        proc.arguments = ["-n", "get", "default"]
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = FileHandle.nullDevice
        do { try proc.run() } catch { return nil }
        proc.waitUntilExit()
        guard proc.terminationStatus == 0,
              let data = try? pipe.fileHandleForReading.readToEnd() ?? nil,
              let out = String(data: data, encoding: .utf8) else {
            return nil
        }
        for line in out.split(separator: "\n") {
            let parts = line.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: true)
            guard parts.count == 2 else { continue }
            let key = String(parts[0]).trimmingCharacters(in: CharacterSet.whitespaces)
            if key == "gateway" {
                return String(parts[1]).trimmingCharacters(in: CharacterSet.whitespaces).lowercased()
            }
        }
        return nil
    }
}
