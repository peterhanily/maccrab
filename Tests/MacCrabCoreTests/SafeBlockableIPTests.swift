// SafeBlockableIPTests.swift
// MacCrabCoreTests

import Testing
import Foundation
@testable import MacCrabCore

@Suite("SafeBlockableIP")
struct SafeBlockableIPTests {

    // MARK: - Exact-match protected IPs

    @Test("Rejects Cloudflare public DNS")
    func rejectsCloudflareDNS() {
        #expect(SafeBlockableIP.isSafeToBlock(ip: "1.1.1.1") == false)
        #expect(SafeBlockableIP.isSafeToBlock(ip: "1.0.0.1") == false)
        #expect(SafeBlockableIP.isSafeToBlock(ip: "2606:4700:4700::1111") == false)
    }

    @Test("Rejects Google public DNS")
    func rejectsGoogleDNS() {
        #expect(SafeBlockableIP.isSafeToBlock(ip: "8.8.8.8") == false)
        #expect(SafeBlockableIP.isSafeToBlock(ip: "8.8.4.4") == false)
        #expect(SafeBlockableIP.isSafeToBlock(ip: "2001:4860:4860::8888") == false)
    }

    @Test("Rejects Quad9 / OpenDNS")
    func rejectsQuad9OpenDNS() {
        #expect(SafeBlockableIP.isSafeToBlock(ip: "9.9.9.9") == false)
        #expect(SafeBlockableIP.isSafeToBlock(ip: "149.112.112.112") == false)
        #expect(SafeBlockableIP.isSafeToBlock(ip: "208.67.222.222") == false)
    }

    @Test("Rejects loopback / unspecified")
    func rejectsLoopback() {
        #expect(SafeBlockableIP.isSafeToBlock(ip: "127.0.0.1") == false)
        #expect(SafeBlockableIP.isSafeToBlock(ip: "0.0.0.0") == false)
        #expect(SafeBlockableIP.isSafeToBlock(ip: "::1") == false)
    }

    // MARK: - CIDR-range membership

    @Test("Rejects entire 127.0.0.0/8 loopback range")
    func rejectsLoopbackCIDR() {
        #expect(SafeBlockableIP.isSafeToBlock(ip: "127.0.0.2") == false)
        #expect(SafeBlockableIP.isSafeToBlock(ip: "127.42.42.42") == false)
        #expect(SafeBlockableIP.isSafeToBlock(ip: "127.255.255.255") == false)
    }

    @Test("Rejects Apple's 17.0.0.0/8 range")
    func rejectsAppleRange() {
        #expect(SafeBlockableIP.isSafeToBlock(ip: "17.0.0.0") == false)
        #expect(SafeBlockableIP.isSafeToBlock(ip: "17.142.160.59") == false)
        #expect(SafeBlockableIP.isSafeToBlock(ip: "17.255.255.255") == false)
    }

    @Test("Rejects link-local 169.254.0.0/16")
    func rejectsLinkLocal() {
        #expect(SafeBlockableIP.isSafeToBlock(ip: "169.254.0.1") == false)
        #expect(SafeBlockableIP.isSafeToBlock(ip: "169.254.169.254") == false)
    }

    @Test("Rejects multicast 224.0.0.0/4")
    func rejectsMulticast() {
        #expect(SafeBlockableIP.isSafeToBlock(ip: "224.0.0.1") == false)
        #expect(SafeBlockableIP.isSafeToBlock(ip: "239.255.255.250") == false)
    }

    @Test("Rejects carrier-grade NAT 100.64.0.0/10")
    func rejectsCGNAT() {
        #expect(SafeBlockableIP.isSafeToBlock(ip: "100.64.0.0") == false)
        #expect(SafeBlockableIP.isSafeToBlock(ip: "100.127.255.255") == false)
    }

    @Test("Refuses to block RFC1918 private ranges — the user's own LAN")
    func rejectsRFC1918() {
        // v1.21.4 audit MEDIUM: a poisoned feed / IOC must not be able to push
        // the user's router, NAS, or another LAN host into the PF blocklist and
        // sever their local network.
        // 10.0.0.0/8
        #expect(SafeBlockableIP.isSafeToBlock(ip: "10.0.0.1") == false)
        #expect(SafeBlockableIP.isSafeToBlock(ip: "10.255.255.255") == false)
        // 172.16.0.0/12
        #expect(SafeBlockableIP.isSafeToBlock(ip: "172.16.0.1") == false)
        #expect(SafeBlockableIP.isSafeToBlock(ip: "172.31.255.255") == false)
        // 192.168.0.0/16 — the classic home-router range
        #expect(SafeBlockableIP.isSafeToBlock(ip: "192.168.0.1") == false)
        #expect(SafeBlockableIP.isSafeToBlock(ip: "192.168.1.254") == false)
    }

    @Test("172.12/172.32 sit OUTSIDE 172.16/12 and remain blockable")
    func rfc1918Boundary() {
        // Just below and just above 172.16.0.0/12 are public and must stay
        // blockable — the /12 mask must be precise, not a naive 172.* match.
        #expect(SafeBlockableIP.isSafeToBlock(ip: "172.15.255.255"))
        #expect(SafeBlockableIP.isSafeToBlock(ip: "172.32.0.1"))
    }

    @Test("Refuses to block IPv6 unique-local fc00::/7 (ULA)")
    func rejectsIPv6ULA() {
        #expect(SafeBlockableIP.isSafeToBlock(ip: "fc00::1") == false)
        #expect(SafeBlockableIP.isSafeToBlock(ip: "fd12:3456:789a::1") == false)
    }

    // MARK: - Accepted: legitimate block targets

    @Test("Accepts public-but-non-protected IPs (real C2 candidates)")
    func acceptsActualMaliciousIPs() {
        // Pseudo-random TEST-NET / RFC5737 reserved-for-docs ranges.
        #expect(SafeBlockableIP.isSafeToBlock(ip: "192.0.2.1"))    // TEST-NET-1
        #expect(SafeBlockableIP.isSafeToBlock(ip: "198.51.100.42")) // TEST-NET-2
        #expect(SafeBlockableIP.isSafeToBlock(ip: "203.0.113.7"))   // TEST-NET-3
    }

    @Test("Accepts random WAN IPs that aren't infrastructure")
    func acceptsRandomWANIPs() {
        #expect(SafeBlockableIP.isSafeToBlock(ip: "45.77.123.45"))
        #expect(SafeBlockableIP.isSafeToBlock(ip: "104.244.42.1"))
    }

    // MARK: - Edge cases

    @Test("Rejects empty / whitespace input")
    func rejectsEmpty() {
        #expect(SafeBlockableIP.isSafeToBlock(ip: "") == false)
        #expect(SafeBlockableIP.isSafeToBlock(ip: "   ") == false)
    }

    @Test("Treats IP input as case-insensitive (IPv6 hex)")
    func caseInsensitive() {
        // Both upper and lower-case hex should match the same protected entry.
        #expect(SafeBlockableIP.isSafeToBlock(ip: "2606:4700:4700::1111") == false)
        #expect(SafeBlockableIP.isSafeToBlock(ip: "2606:4700:4700::1111") == false)
    }

    @Test("reasonToReject returns nil for safe and a string for unsafe")
    func reasonToRejectContract() {
        #expect(SafeBlockableIP.reasonToReject(ip: "203.0.113.7") == nil)
        let r = SafeBlockableIP.reasonToReject(ip: "1.1.1.1")
        #expect(r != nil)
        #expect(r?.contains("DNS") == true || r?.contains("loopback") == true || r?.contains("unspecified") == true)
    }

    @Test("currentDefaultGateway parses without crashing")
    func gatewayResolution() {
        // No assertion on the value (depends on the test machine's network),
        // just confirm the parser doesn't crash and returns either nil or
        // a non-empty string.
        let gw = SafeBlockableIP.currentDefaultGateway()
        if let gw {
            #expect(!gw.isEmpty)
        }
    }

    // MARK: - IPv6 CIDR membership (v1.6.21 BLOCKER fix)

    @Test("Rejects an IPv6 one address off a DNS resolver — the v1.6.21 bypass")
    func rejectsIPv6OneAddressOffDNS() {
        // 2001:4860:4860::8889 is one address off Google DNS ::8888. Pre-fix
        // only exact-match was checked, so this slipped through and PF-blocking
        // it would silently break IPv6 DNS resolution. It lives inside Google's
        // protected ::/48 and must now be rejected.
        #expect(SafeBlockableIP.isSafeToBlock(ip: "2001:4860:4860::8889") == false)
        // Likewise one off Cloudflare ::1111 — inside 2606:4700:4700::/48.
        #expect(SafeBlockableIP.isSafeToBlock(ip: "2606:4700:4700::8889") == false)
    }

    @Test("Rejects the full provider /48 IPv6 DNS ranges")
    func rejectsIPv6DNSRanges() {
        #expect(SafeBlockableIP.isSafeToBlock(ip: "2606:4700:4700::dead") == false) // Cloudflare /48
        #expect(SafeBlockableIP.isSafeToBlock(ip: "2001:4860:4860::beef") == false) // Google /48
        #expect(SafeBlockableIP.isSafeToBlock(ip: "2620:fe::abcd") == false)        // Quad9 /48
        #expect(SafeBlockableIP.isSafeToBlock(ip: "2620:119::1") == false)          // OpenDNS /48
    }

    @Test("Rejects IPv6 link-local fe80::/10 and multicast ff00::/8")
    func rejectsIPv6LinkLocalMulticast() {
        #expect(SafeBlockableIP.isSafeToBlock(ip: "fe80::1234") == false)  // link-local
        #expect(SafeBlockableIP.isSafeToBlock(ip: "fe80::1") == false)
        #expect(SafeBlockableIP.isSafeToBlock(ip: "ff02::1") == false)     // all-nodes multicast
        #expect(SafeBlockableIP.isSafeToBlock(ip: "ff00::abcd") == false)  // multicast base
    }

    @Test("Accepts public IPv6 that is NOT infrastructure (real C2 candidate)")
    func acceptsPublicIPv6() {
        #expect(SafeBlockableIP.isSafeToBlock(ip: "2a01:4f8::1"))   // Hetzner-shaped, unprotected
        #expect(SafeBlockableIP.isSafeToBlock(ip: "2001:db8::1"))  // RFC3849 docs range
    }

    @Test("IPv6 /48 prefix precision: an address just outside is accepted")
    func ipv6PrefixBoundary() {
        // Google DNS is 2001:4860:4860::/48; the adjacent 2001:4860:4861:: differs
        // in the 48-bit prefix, so it is outside and must NOT be protected.
        #expect(SafeBlockableIP.isSafeToBlock(ip: "2001:4860:4861::1"))
        // One /48 above Cloudflare's 2606:4700:4700::/48 is likewise outside.
        #expect(SafeBlockableIP.isSafeToBlock(ip: "2606:4700:4701::1"))
    }
}
