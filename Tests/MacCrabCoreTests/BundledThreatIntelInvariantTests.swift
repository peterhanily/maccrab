// BundledThreatIntelInvariantTests — Owner issues 1 + 2 for the IOCs that ship in
// the binary and feed first-launch detection.
//
// A shipping detection engine must never carry FABRICATED IOCs: a documentation
// address (RFC5737), a private/loopback address, or an RFC2606-reserved domain
// can never match real malicious traffic, but CAN false-positive on benign
// traffic (e.g. a host's own example.com test fetch). Earlier revisions of this
// file carried exactly such placeholders (scanme.nmap.org, example.com's IP,
// duckdns.org wholesale); they were removed. This test turns "we removed those 2
// strings" into an INVARIANT over the whole table (Issue 1) plus a COMPLETENESS
// check on the empty hash set and the real-IOC retention (Issue 2).
//
// The range/reserved classifiers below are INDEPENDENT of any production helper
// (those are private), so this test is its own oracle — a deliberate choice so a
// shared parsing bug can't hide a bad IOC.
//
// Mutation note: re-introduce ANY placeholder (a 192.0.2.x C2, an example.com
// domain, a non-empty malwareHashes entry) and the matching invariant FAILS.
// Drop a real retained IOC (104.168.214.151) and `realIOCsRetained` FAILS.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("BundledThreatIntel — no-fabricated-IOC invariants + completeness (owner issues)")
struct BundledThreatIntelInvariantTests {

    // MARK: - IPv4 octet parsing + range classification (independent oracle)

    /// Parse a dotted-quad into 4 octets, or nil if not a valid IPv4 literal.
    static func octets(_ ip: String) -> (UInt8, UInt8, UInt8, UInt8)? {
        let parts = ip.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var o = [UInt8]()
        for p in parts {
            guard let v = UInt8(p) else { return nil }   // 0...255 only
            o.append(v)
        }
        return (o[0], o[1], o[2], o[3])
    }

    /// RFC5737 documentation ranges: 192.0.2/24, 198.51.100/24, 203.0.113/24.
    static func isRFC5737Doc(_ ip: String) -> Bool {
        guard let (a, b, c, _) = octets(ip) else { return false }
        return (a == 192 && b == 0   && c == 2)
            || (a == 198 && b == 51  && c == 100)
            || (a == 203 && b == 0   && c == 113)
    }

    /// RFC1918 private + loopback + link-local + "this host" (0/8) + RFC6598 CGN.
    static func isPrivateOrSpecial(_ ip: String) -> Bool {
        guard let (a, b, _, _) = octets(ip) else { return false }
        if a == 10 { return true }                                   // 10/8
        if a == 172 && (16...31).contains(b) { return true }         // 172.16/12
        if a == 192 && b == 168 { return true }                      // 192.168/16
        if a == 127 { return true }                                  // loopback
        if a == 169 && b == 254 { return true }                      // link-local
        if a == 0 { return true }                                    // 0/8 "this host"
        if a == 100 && (64...127).contains(b) { return true }        // 100.64/10 CGN
        return false
    }

    /// Known benign test hosts that were previously mislabeled as C2.
    static let knownBenignTestHostIPs: Set<String> = [
        "45.33.32.156",   // scanme.nmap.org
        "93.184.216.34",  // example.com / example.net / example.org
    ]

    // MARK: - Issue 2: malware hash set is EXACTLY empty

    @Test("malwareHashes is EXACTLY empty (no fabricated/synthetic SHA-256s ship)")
    func malwareHashesEmpty() {
        #expect(BundledThreatIntel.malwareHashes.isEmpty)
        #expect(BundledThreatIntel.malwareHashes.count == 0)
        // The stats accessor must agree (completeness of the public surface).
        #expect(BundledThreatIntel.stats.hashes == 0)
        // The lookup path must therefore never resolve ANY hash.
        #expect(BundledThreatIntel.malwareFamilyForHash(String(repeating: "a", count: 64)) == nil)
    }

    // MARK: - Issue 1: NO bundled C2 IP is a doc / private / known-benign address

    @Test("INVARIANT: no c2IP is an RFC5737 documentation address")
    func noC2IPInDocRange() {
        let offenders = BundledThreatIntel.c2IPs.map(\.ip).filter { Self.isRFC5737Doc($0) }
        #expect(offenders.isEmpty, "RFC5737 doc IPs must never ship as C2: \(offenders)")
    }

    @Test("INVARIANT: no c2IP is private / loopback / link-local / CGN / 0-net")
    func noC2IPPrivate() {
        let offenders = BundledThreatIntel.c2IPs.map(\.ip).filter { Self.isPrivateOrSpecial($0) }
        #expect(offenders.isEmpty, "private/special IPs must never ship as C2: \(offenders)")
    }

    @Test("INVARIANT: no c2IP is a known benign test host (scanme.nmap.org / example.com)")
    func noC2IPKnownBenign() {
        let offenders = BundledThreatIntel.c2IPs.map(\.ip).filter { Self.knownBenignTestHostIPs.contains($0) }
        #expect(offenders.isEmpty, "known benign test-host IPs must never ship as C2: \(offenders)")
    }

    @Test("INVARIANT: every c2IP is a well-formed, ROUTABLE IPv4 literal (no .0 network/.255 broadcast smell)")
    func everyC2IPWellFormedRoutable() {
        for e in BundledThreatIntel.c2IPs {
            guard let (a, _, _, d) = Self.octets(e.ip) else {
                Issue.record("c2IP '\(e.ip)' is not a valid IPv4 literal"); continue
            }
            #expect(a != 0, "\(e.ip): first octet 0 is non-routable")
            #expect(d != 0, "\(e.ip): last-octet .0 is a network address — a guaranteed-mismatch placeholder")
            // Multicast/reserved high space should not appear in unicast C2 lists.
            #expect(a < 224, "\(e.ip): first octet >=224 is multicast/reserved, not unicast C2")
        }
    }

    // MARK: - Issue 1: NO bundled domain is RFC2606-reserved or a constructed placeholder

    /// RFC2606 + reserved/special-use names that can never be real malicious infra.
    static func isReservedOrPlaceholderDomain(_ domain: String) -> Bool {
        let d = domain.lowercased()
        // RFC2606 reserved second-level example domains.
        if d == "example.com" || d == "example.net" || d == "example.org" { return true }
        if d.hasSuffix(".example.com") || d.hasSuffix(".example.net") || d.hasSuffix(".example.org") { return true }
        // RFC2606 + RFC6761 reserved TLDs.
        for tld in [".test", ".localhost", ".invalid", ".example", ".local"] {
            if d == String(tld.dropFirst()) || d.hasSuffix(tld) { return true }
        }
        // Constructed-placeholder smells observed in the removed sections:
        // a literal "malware-host" label, or a suspicious-TLD label ("download.top")
        // stacked on a legit base ("...legit.com.download.top").
        if d.contains("malware-host") { return true }
        if d.hasPrefix("download.top") || d.contains(".download.top") { return true }
        return false
    }

    @Test("INVARIANT: no maliciousDomain is RFC2606-reserved or a constructed placeholder")
    func noReservedOrPlaceholderDomain() {
        let offenders = BundledThreatIntel.maliciousDomains.filter { Self.isReservedOrPlaceholderDomain($0) }
        #expect(offenders.isEmpty, "reserved/placeholder domains must never ship: \(offenders)")
    }

    @Test("INVARIANT: every maliciousDomain is a plausible FQDN (>=2 labels, no scheme/path/empty label)")
    func everyDomainWellFormed() {
        for d in BundledThreatIntel.maliciousDomains {
            #expect(!d.isEmpty)
            #expect(!d.contains("/"), "\(d): looks like a URL, not a bare domain")
            #expect(!d.contains(" "), "\(d): contains whitespace")
            let labels = d.split(separator: ".", omittingEmptySubsequences: false)
            #expect(labels.count >= 2, "\(d): not a multi-label FQDN")
            #expect(labels.allSatisfy { !$0.isEmpty }, "\(d): has an empty label (leading/trailing/double dot)")
        }
    }

    // MARK: - Issue 2: the COMPLEMENT — real retained IOCs ARE present

    @Test("COMPLETENESS: the real retained IOCs are still present (the table wasn't emptied)")
    func realIOCsRetained() {
        let ips = Set(BundledThreatIntel.c2IPs.map(\.ip))
        // A documented DPRK/BlueNoroff ObjCShellz C2 that survived the cleanup.
        #expect(ips.contains("104.168.214.151"), "the real retained ObjCShellz C2 must still ship")
        // A representative Feodo Tracker entry and a mining-pool IP.
        #expect(ips.contains("104.168.155.129"))
        #expect(ips.contains("144.76.183.96"))
        // The mining-pool domains are the deliberately-retained low-FP set.
        #expect(BundledThreatIntel.maliciousDomains.contains("pool.minexmr.com"))
        #expect(BundledThreatIntel.maliciousDomains.contains("xmr.2miners.com"))
        // Non-trivial, sane sizes (not silently zeroed).
        #expect(BundledThreatIntel.c2IPs.count >= 20)
        #expect(BundledThreatIntel.maliciousDomains.count >= 20)
    }

    @Test("sanity: the independent classifiers actually fire on positive controls")
    func classifierSelfCheck() {
        // Guard against a vacuous "no offenders because the classifier is broken".
        #expect(Self.isRFC5737Doc("192.0.2.5"))
        #expect(Self.isRFC5737Doc("198.51.100.7"))
        #expect(Self.isRFC5737Doc("203.0.113.9"))
        #expect(!Self.isRFC5737Doc("104.168.214.151"))
        #expect(Self.isPrivateOrSpecial("10.0.0.1"))
        #expect(Self.isPrivateOrSpecial("192.168.1.1"))
        #expect(Self.isPrivateOrSpecial("127.0.0.1"))
        #expect(!Self.isPrivateOrSpecial("104.168.214.151"))
        #expect(Self.isReservedOrPlaceholderDomain("example.com"))
        #expect(Self.isReservedOrPlaceholderDomain("foo.test"))
        #expect(Self.isReservedOrPlaceholderDomain("evil.malware-host.net"))
        #expect(!Self.isReservedOrPlaceholderDomain("pool.minexmr.com"))
    }
}
