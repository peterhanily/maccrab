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

    /// IPv4 CIDR ranges that are off-limits. Stored as
    /// `(networkAddressInHostByteOrder, prefixLength)`.
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

    /// IPv6 CIDR ranges that are off-limits. v1.6.21 BLOCKER fix: pre-fix
    /// only exact-match was supported, so `2001:4860:4860::8889` (one byte
    /// off from Google DNS `2001:4860:4860::8888`) bypassed the check and
    /// blocking it would silently break IPv6 DNS resolution.
    /// Stored as `(networkBytes [16 bytes], prefixLength)`.
    public static let protectedIPv6CIDRs: [(network: [UInt8], prefix: Int, label: String)] = [
        // ::1/128 — IPv6 loopback (covered by exact-match too, kept for explicitness)
        (network: ipv6("::1"), prefix: 128, label: "::1/128 (IPv6 loopback)"),
        // ::/128 — IPv6 unspecified
        (network: ipv6("::"), prefix: 128, label: "::/128 (IPv6 unspecified)"),
        // fe80::/10 — IPv6 link-local
        (network: ipv6("fe80::"), prefix: 10, label: "fe80::/10 (IPv6 link-local)"),
        // ff00::/8 — IPv6 multicast (blocking breaks Bonjour over IPv6)
        (network: ipv6("ff00::"), prefix: 8, label: "ff00::/8 (IPv6 multicast)"),
        // 2606:4700:4700::/48 — Cloudflare DNS over IPv6
        (network: ipv6("2606:4700:4700::"), prefix: 48, label: "2606:4700:4700::/48 (Cloudflare DNS)"),
        // 2001:4860:4860::/48 — Google DNS over IPv6
        (network: ipv6("2001:4860:4860::"), prefix: 48, label: "2001:4860:4860::/48 (Google DNS)"),
        // 2620:fe::/48 — Quad9 DNS over IPv6
        (network: ipv6("2620:fe::"), prefix: 48, label: "2620:fe::/48 (Quad9 DNS)"),
        // 2620:119::/48 — OpenDNS over IPv6
        (network: ipv6("2620:119::"), prefix: 48, label: "2620:119::/48 (OpenDNS)"),
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

        // IPv6 CIDR membership check (v1.6.21 BLOCKER fix). Compare the
        // first `prefix` bits of the address against the network bytes.
        var addr6 = in6_addr()
        if trimmed.withCString({ inet_pton(AF_INET6, $0, &addr6) }) == 1 {
            let bytes: [UInt8] = withUnsafeBytes(of: &addr6) { buf in
                Array(buf.bindMemory(to: UInt8.self))
            }
            for cidr in protectedIPv6CIDRs {
                if ipv6PrefixMatches(addressBytes: bytes, networkBytes: cidr.network, prefix: cidr.prefix) {
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

    /// Parse an IPv6 string into a 16-byte network-order array. Returns
    /// 16 zero bytes on failure (which won't match any real address).
    private static func ipv6(_ s: String) -> [UInt8] {
        var addr = in6_addr()
        guard s.withCString({ inet_pton(AF_INET6, $0, &addr) }) == 1 else {
            return [UInt8](repeating: 0, count: 16)
        }
        return withUnsafeBytes(of: &addr) { buf in
            Array(buf.bindMemory(to: UInt8.self))
        }
    }

    /// Compare the first `prefix` bits of two 16-byte IPv6 addresses.
    private static func ipv6PrefixMatches(addressBytes: [UInt8], networkBytes: [UInt8], prefix: Int) -> Bool {
        guard addressBytes.count == 16, networkBytes.count == 16 else { return false }
        let fullBytes = prefix / 8
        let remainderBits = prefix % 8
        // Compare full bytes
        for i in 0..<fullBytes {
            if addressBytes[i] != networkBytes[i] { return false }
        }
        // Compare partial byte
        if remainderBits > 0 && fullBytes < 16 {
            let mask: UInt8 = 0xFF << (8 - remainderBits)
            if (addressBytes[fullBytes] & mask) != (networkBytes[fullBytes] & mask) {
                return false
            }
        }
        return true
    }

    /// 30-second TTL cache for the default gateway. Pre-v1.6.21 every
    /// `isSafeToBlock` call shelled out to `route -n get default` (~5-10ms
    /// per call); under a PF block storm at 100/sec that was 5% CPU just
    /// on gateway discovery. Most machines have one default gateway per
    /// session; refreshing every 30s captures network changes without
    /// hammering route(8).
    private static let gatewayCacheTTL: TimeInterval = 30
    private static var cachedGateway: String?
    private static var cachedGatewayAt: Date = .distantPast
    private static let gatewayCacheLock = NSLock()

    /// Resolve the current IPv4 default gateway by parsing
    /// `route -n get default`. Returns nil on failure (no route, parse error).
    /// Cached for 30s; first call after init or after the TTL expires reads
    /// fresh.
    static func currentDefaultGateway() -> String? {
        gatewayCacheLock.lock()
        let now = Date()
        if now.timeIntervalSince(cachedGatewayAt) < gatewayCacheTTL {
            let cached = cachedGateway
            gatewayCacheLock.unlock()
            return cached
        }
        gatewayCacheLock.unlock()

        let resolved = resolveDefaultGatewayUncached()

        gatewayCacheLock.lock()
        cachedGateway = resolved
        cachedGatewayAt = Date()
        gatewayCacheLock.unlock()
        return resolved
    }

    private static func resolveDefaultGatewayUncached() -> String? {
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
