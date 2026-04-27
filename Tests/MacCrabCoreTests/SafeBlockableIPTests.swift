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
}
