// ThreatIntelDomainEnricher — now reads the LIVE IOC cache (no fixture domains).
// Tests seed a controlled feed_cache.json and verify the real-cache lookup.

import Foundation
import Testing
import MacCrabCore
@testable import MacCrabForensics

@Suite("ThreatIntelDomainEnricher")
struct ThreatIntelDomainEnricherTests {

    /// Mirror of the daemon's feed_cache.json (default JSON date strategy round-trips).
    struct TestFeedCache: Codable {
        let hashes: [ThreatIntelFeed.IOCRecord]
        let ips: [ThreatIntelFeed.IOCRecord]
        let domains: [ThreatIntelFeed.IOCRecord]
        let urls: [ThreatIntelFeed.IOCRecord]
        let lastUpdate: Date?
        let lastSuccessfulPull: Date?
    }

    /// Returns the `threat_intel` cache dir holding the seeded feed_cache.json.
    static func seed(domains: [String], ips: [String] = []) throws -> String {
        let dir = NSTemporaryDirectory() + "ti-\(UUID().uuidString)/threat_intel"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        func rec(_ v: String) -> ThreatIntelFeed.IOCRecord {
            ThreatIntelFeed.IOCRecord(value: v, source: "URLhaus", firstSeen: nil,
                                      lastSeenInFeed: Date(), malwareFamily: "TestFam", tags: [])
        }
        let cache = TestFeedCache(hashes: [], ips: ips.map(rec), domains: domains.map(rec),
                                  urls: [], lastUpdate: Date(), lastSuccessfulPull: Date())
        try JSONEncoder().encode(cache).write(to: URL(fileURLWithPath: dir + "/feed_cache.json"))
        return dir
    }

    @Test("a domain in the live IOC cache flips the flag + labels source/family")
    func malicious() async throws {
        let dir = try Self.seed(domains: ["bad.example.test"])
        defer { try? FileManager.default.removeItem(atPath: (dir as NSString).deletingLastPathComponent) }
        let e = ThreatIntelDomainEnricher(cacheDir: dir)
        let r = try await e.enrich(.path(URL(string: "https://bad.example.test/foo")!), stage: .onDemand)
        #expect(r.fields["threatintel.is_known_malicious"] == .bool(true))
        #expect(r.fields["threatintel.source"] == .string("URLhaus"))
        #expect(r.fields["threatintel.malware_family"] == .string("TestFam"))
    }

    @Test("an unlisted domain does not flip the flag")
    func unknown() async throws {
        let dir = try Self.seed(domains: ["bad.example.test"])
        defer { try? FileManager.default.removeItem(atPath: (dir as NSString).deletingLastPathComponent) }
        let e = ThreatIntelDomainEnricher(cacheDir: dir)
        let r = try await e.enrich(.path(URL(string: "https://google.com/")!), stage: .onDemand)
        #expect(r.fields["threatintel.is_known_malicious"] == .bool(false))
    }

    @Test("empty/absent cache → honest no-match (no fixture lies)")
    func emptyCache() async throws {
        let e = ThreatIntelDomainEnricher(cacheDir: NSTemporaryDirectory() + "nope-\(UUID().uuidString)")
        let r = try await e.enrich(.path(URL(string: "https://anything.test/")!), stage: .onDemand)
        #expect(r.fields["threatintel.is_known_malicious"] == .bool(false))
    }

    @Test("idempotent on a path-subject across re-runs")
    func idempotent() async throws {
        let dir = try Self.seed(domains: ["bad.example.test"])
        defer { try? FileManager.default.removeItem(atPath: (dir as NSString).deletingLastPathComponent) }
        let e = ThreatIntelDomainEnricher(cacheDir: dir)
        let s = EnrichmentSubject.path(URL(string: "https://bad.example.test/path")!)
        let a = try await e.enrich(s, stage: .postEmission)
        let b = try await e.enrich(s, stage: .postEmission)
        #expect(a.fields == b.fields)
    }

    @Test("a process event subject has no domain (no network host in the payload)")
    func eventNoDomain() async throws {
        let e = ThreatIntelDomainEnricher(cacheDir: NSTemporaryDirectory())
        let payload = EnrichmentEventPayload(id: "e1", processExecutablePath: "/usr/bin/curl",
                                             processPID: 1, timestamp: Date(), categoryRaw: nil)
        let r = try await e.enrich(.event(payload), stage: .postEmission)
        #expect(r.fields["threatintel.domain_present"] == .bool(false))
    }
}
