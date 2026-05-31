// V2IntelFeedHonestyTests.swift
// MacCrabAppTests
//
// PULL fix part B: pins the operator-visible freshness/honesty
// contract for the threat-intel feed surface. The bug was that an
// empty/200 feed body was stamped as a successful pull, freezing the
// IOC count at the bundled set while the dashboard claimed "just
// updated". These tests assert the cache now carries an honest
// per-feed last-error + a top-level lastSuccessfulPull, and that the
// dashboard loader surfaces both.
//
// Tests use temp directories so they don't touch the real on-disk
// caches at /Library/Application Support/MacCrab/threat_intel or
// ~/Library/Application Support/MacCrab/threat_intel.

import Testing
import Foundation
@testable import MacCrabApp
@testable import MacCrabCore

@Suite("V2 threat-intel feed freshness honesty")
struct V2IntelFeedHonestyTests {

    /// On-disk JSON shape of the feed cache, mirroring the private
    /// `ThreatIntelFeed.CacheData` Codable struct including the new
    /// `lastSuccessfulPull` field. Encoding-only — the loader decodes
    /// via the real CacheData, so this is the producer side.
    private struct OnDiskCache: Codable {
        let hashes: [ThreatIntelFeed.IOCRecord]
        let ips: [ThreatIntelFeed.IOCRecord]
        let domains: [ThreatIntelFeed.IOCRecord]
        let urls: [ThreatIntelFeed.IOCRecord]
        let lastUpdate: Date?
        let lastSuccessfulPull: Date?
        let perFeedLastUpdate: [String: Date]?
        let perFeedLastError: [String: ThreatIntelFeed.FeedError]?
    }

    private func makeTempDir(_ tag: String) throws -> String {
        let dir = NSTemporaryDirectory()
            + "maccrab-intel-honesty-\(tag)-\(UUID().uuidString)"
        try FileManager.default.createDirectory(
            atPath: dir, withIntermediateDirectories: true
        )
        return dir
    }

    private func record(_ value: String, source: String) -> ThreatIntelFeed.IOCRecord {
        ThreatIntelFeed.IOCRecord(
            value: value, source: source,
            firstSeen: Date().addingTimeInterval(-86_400),
            lastSeenInFeed: Date(), malwareFamily: nil,
            tags: [], fileType: nil
        )
    }

    /// Write a cache where URLhaus last FAILED with an empty body (its
    /// perFeedLastUpdate is an hour old — the prior good success that
    /// was preserved, not overwritten) while MalwareBazaar succeeded
    /// 5 min ago. lastSuccessfulPull reflects the most recent real pull.
    private func writeMixedCache(dir: String) throws {
        try FileManager.default.createDirectory(
            atPath: dir, withIntermediateDirectories: true
        )
        let now = Date()
        let cache = OnDiskCache(
            hashes: [record("abc", source: "MalwareBazaar")],
            ips: [],
            domains: [record("bad.example", source: "URLhaus")],
            urls: [record("http://bad.example/x", source: "URLhaus")],
            lastUpdate: now,
            lastSuccessfulPull: now.addingTimeInterval(-5 * 60),
            perFeedLastUpdate: [
                "MalwareBazaar": now.addingTimeInterval(-5 * 60),
                "URLhaus":       now.addingTimeInterval(-60 * 60),
            ],
            perFeedLastError: [
                "URLhaus": ThreatIntelFeed.FeedError(
                    at: now, reason: "0 records parsed (empty feed)"
                )
            ]
        )
        let data = try JSONEncoder().encode(cache)
        try data.write(to: URL(fileURLWithPath: dir + "/feed_cache.json"))
    }

    @Test("a feed whose last attempt failed surfaces its error + warning status, not a healthy stamp")
    func failingFeedSurfacesError() throws {
        let tmp = try makeTempDir("failing")
        try writeMixedCache(dir: tmp + "/threat_intel")
        defer { try? FileManager.default.removeItem(atPath: tmp) }

        let rows = V2LiveDataProvider.loadFeedsFromCache(preferring: tmp)
        let urlhaus = rows.first { $0.name == "URLhaus" }
        let bazaar = rows.first { $0.name == "MalwareBazaar" }
        #expect(urlhaus != nil)
        #expect(urlhaus?.lastError == "0 records parsed (empty feed)",
                "failed feed must surface its reason, not a silent stall")
        #expect(urlhaus?.status == .warning,
                "a feed with a recorded error must read as .warning")
        // The healthy feed carries no error and stays .info.
        #expect(bazaar?.lastError == nil)
        #expect(bazaar?.status == .info)
    }

    @Test("lastSuccessfulPull reflects the last real pull, threaded through the cache")
    func lastSuccessfulPullRoundTrips() throws {
        let tmp = try makeTempDir("pull")
        try writeMixedCache(dir: tmp + "/threat_intel")
        defer { try? FileManager.default.removeItem(atPath: tmp) }

        let pull = V2LiveDataProvider.lastSuccessfulPull(preferring: tmp)
        #expect(pull != nil, "lastSuccessfulPull must survive the cache round-trip")
        // Stamped 5 min ago in the fixture; allow generous slack.
        let age = -(pull?.timeIntervalSinceNow ?? 0)
        #expect(age > 0 && age < 60 * 60)
    }

    @Test("caches written before the lastSuccessfulPull field decode cleanly with nil")
    func legacyCacheDecodesWithNilPull() throws {
        let tmp = try makeTempDir("legacy")
        let dir = tmp + "/threat_intel"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: tmp) }
        // A pre-fix cache JSON with NO lastSuccessfulPull key.
        let legacy = """
        {"hashes":[],"ips":[],"domains":[],"urls":[],"lastUpdate":null,"perFeedLastUpdate":{},"perFeedLastError":{}}
        """
        try legacy.data(using: .utf8)!.write(to: URL(fileURLWithPath: dir + "/feed_cache.json"))

        // No crash, no fabricated pull date.
        #expect(V2LiveDataProvider.lastSuccessfulPull(preferring: tmp) == nil)
        #expect(V2LiveDataProvider.loadFeedsFromCache(preferring: tmp).isEmpty)
    }
}
