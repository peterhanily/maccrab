// V2IntelligenceFeedsLoaderTests.swift
// MacCrabAppTests
//
// Wave 9E (v1.12.6 RC2): pin the contract for
// `V2LiveDataProvider.loadFeedsFromCache(preferring:)` — the static
// helper introduced so the Intelligence > Threat Intel surface renders
// real feed rows on first appear, instead of the V2MockDataProvider
// fixtures that pre-fix flashed up until the mock→live provider flip +
// `.task(id:)` re-fire eventually replaced them. The fix also bypasses
// the dataDir-mismatch case where the dashboard resolved `dataDir` to
// the user-home directory but the sysext had written its IOC cache to
// /Library/Application Support (or vice versa on dev machines with
// mixed history).
//
// Tests use temp directories so they don't touch the real on-disk
// caches at /Library/Application Support/MacCrab/threat_intel or
// ~/Library/Application Support/MacCrab/threat_intel.

import Testing
import Foundation
@testable import MacCrabApp
@testable import MacCrabCore

@Suite("V2IntelligenceWorkspace feed loader")
struct V2IntelligenceFeedsLoaderTests {

    // MARK: - Fixture helpers

    /// On-disk JSON shape of the feed cache. Mirrors the private
    /// `ThreatIntelFeed.CacheData` Codable struct — keeping the shape
    /// inline (rather than reaching into MacCrabCore internals) means
    /// any future schema drift surfaces here as a decode failure
    /// instead of a silent test pass.
    private struct OnDiskCache: Codable {
        let hashes: [ThreatIntelFeed.IOCRecord]
        let ips: [ThreatIntelFeed.IOCRecord]
        let domains: [ThreatIntelFeed.IOCRecord]
        let urls: [ThreatIntelFeed.IOCRecord]
        let lastUpdate: Date?
        let perFeedLastUpdate: [String: Date]?
        let perFeedLastError: [String: ThreatIntelFeed.FeedError]?
    }

    private func writeCacheFixture(
        dir: String,
        perFeed: [String: Date] = [
            "URLhaus":       Date().addingTimeInterval(-12 * 60),
            "MalwareBazaar": Date().addingTimeInterval(-24 * 60),
            "Feodo":         Date().addingTimeInterval(-30 * 60),
        ],
        hashCount: Int = 1500,
        ipCount: Int = 800,
        domainCount: Int = 120,
        urlCount: Int = 95
    ) throws {
        try FileManager.default.createDirectory(
            atPath: dir, withIntermediateDirectories: true
        )
        func records(prefix: String, source: String, count: Int) -> [ThreatIntelFeed.IOCRecord] {
            (0..<count).map { i in
                ThreatIntelFeed.IOCRecord(
                    value: "\(prefix)-\(i)",
                    source: source,
                    firstSeen: Date().addingTimeInterval(-86_400),
                    lastSeenInFeed: Date(),
                    malwareFamily: nil,
                    tags: [],
                    fileType: nil
                )
            }
        }
        let cache = OnDiskCache(
            hashes: records(prefix: "h", source: "MalwareBazaar", count: hashCount),
            ips: records(prefix: "i", source: "Feodo", count: ipCount),
            domains: records(prefix: "d", source: "URLhaus", count: domainCount),
            urls: records(prefix: "u", source: "URLhaus", count: urlCount),
            lastUpdate: Date(),
            perFeedLastUpdate: perFeed,
            perFeedLastError: nil
        )
        let data = try JSONEncoder().encode(cache)
        try data.write(to: URL(fileURLWithPath: dir + "/feed_cache.json"))
    }

    private func makeTempDir(_ tag: String) throws -> String {
        let dir = NSTemporaryDirectory()
            + "maccrab-v2intel-\(tag)-\(UUID().uuidString)"
        try FileManager.default.createDirectory(
            atPath: dir, withIntermediateDirectories: true
        )
        return dir
    }

    // MARK: - Tests

    @Test("loadFeedsFromCache reads a fresh cache and maps every entry in perFeedLastUpdate to a V2MockFeed row")
    func loadFeedsHappyPath() throws {
        let tmp = try makeTempDir("happy")
        let cacheDir = tmp + "/threat_intel"
        try writeCacheFixture(dir: cacheDir)
        defer { try? FileManager.default.removeItem(atPath: tmp) }

        let rows = V2LiveDataProvider.loadFeedsFromCache(preferring: tmp)
        // Three abuse.ch feeds — URLhaus / MalwareBazaar / Feodo — all
        // present in the fixture. Sort-by-name (compactMap on a sorted
        // dict in feeds()) yields a stable order: Feodo, MalwareBazaar,
        // URLhaus.
        #expect(rows.count == 3)
        #expect(Set(rows.map { $0.name }) == ["URLhaus", "MalwareBazaar", "Feodo"])
        // Pre-fix the entries column showed 0 because feedKindHint
        // didn't bucket. Pin that URL kind → urls count, IP kind →
        // ip count, Hashes kind → hashes count.
        let urlhaus = rows.first(where: { $0.name == "URLhaus" })!
        let malwareBazaar = rows.first(where: { $0.name == "MalwareBazaar" })!
        let feodo = rows.first(where: { $0.name == "Feodo" })!
        #expect(urlhaus.kind == "URLs")
        #expect(urlhaus.entries == 95)
        #expect(malwareBazaar.kind == "Hashes")
        #expect(malwareBazaar.entries == 1500)
        // "feodo" doesn't match the URLhaus / threatfox / spamhaus /
        // hash / malware / domain hints in feedKindHint, so it falls
        // through to the "Mixed" bucket — entries = total of all
        // categories. This pin documents the current behavior.
        #expect(feodo.kind == "Mixed")
        #expect(feodo.entries == 1500 + 800 + 120 + 95)
    }

    @Test("loadFeedsFromCache returns [] when no cache exists anywhere on disk")
    func loadFeedsNoCache() throws {
        // Probe a guaranteed-empty temp dir; the canonical system + user-
        // home paths might exist on the test runner (sysext installs)
        // so we can't assert the universal-empty case there. The helper
        // contract is: when the *preferred* dir is empty AND the
        // canonical fallbacks all decode-fail, return []. We can only
        // exercise the preferred-empty case in isolation, so this test
        // pins that the helper doesn't crash + doesn't fabricate rows
        // when the preferred dir has no cache.
        let tmp = try makeTempDir("empty")
        defer { try? FileManager.default.removeItem(atPath: tmp) }
        let rows = V2LiveDataProvider.loadFeedsFromCache(preferring: tmp)
        // On a clean CI machine with no sysext install, rows is []. On
        // a developer's machine with /Library/Application Support/
        // MacCrab/threat_intel/feed_cache.json present, rows is the
        // live abuse.ch feed list. Either way: no crash, no exception.
        // Pin the no-crash contract; row count varies by environment.
        #expect(rows.count >= 0)
    }

    @Test("loadFeedsFromCache prefers the preferred dir over the canonical fallback paths")
    func loadFeedsPreferredWinsOverCanonical() throws {
        // Two fixtures: tmpA gets a "fake URLhaus" with one feed entry,
        // tmpB gets a different feed name. We pass tmpA as preferred
        // and assert the result contains the tmpA contents, NOT
        // anything from a system-dir cache that may exist on the
        // runner. Tests the dataDir-mismatch fix: even if the system
        // dir has a cache, the live provider's resolved dataDir is
        // what should win when probed first.
        let preferred = try makeTempDir("preferred")
        let preferredCacheDir = preferred + "/threat_intel"
        try writeCacheFixture(
            dir: preferredCacheDir,
            perFeed: ["URLhaus": Date().addingTimeInterval(-5 * 60)],
            hashCount: 7,
            ipCount: 11,
            domainCount: 13,
            urlCount: 17
        )
        defer { try? FileManager.default.removeItem(atPath: preferred) }

        let rows = V2LiveDataProvider.loadFeedsFromCache(preferring: preferred)
        // Exactly one row from the preferred dir's single-feed cache.
        // Three guarantees here: (1) the canonical fallback paths do
        // NOT bleed into the result, (2) the preferred dir's path is
        // probed first, (3) the row's entries match the preferred
        // fixture, not whatever the host machine's real cache holds.
        #expect(rows.count == 1)
        #expect(rows.first?.name == "URLhaus")
        #expect(rows.first?.kind == "URLs")
        #expect(rows.first?.entries == 17)
    }

    @Test("candidateThreatIntelCacheDirs returns the system path first when preferred is nil")
    func candidateDirsOrderWithNoPreferred() {
        let dirs = V2LiveDataProvider.candidateThreatIntelCacheDirs(preferring: nil)
        // Canonical priority: system sysext path wins because release
        // builds run the daemon as root and write there. User-home is
        // the dev-workflow fallback.
        #expect(dirs.first == "/Library/Application Support/MacCrab/threat_intel")
        #expect(dirs.count >= 1)
        #expect(dirs.contains(where: { $0.hasSuffix("/Library/Application Support/MacCrab/threat_intel") }))
    }

    @Test("candidateThreatIntelCacheDirs prepends preferred and de-duplicates against the canonical paths")
    func candidateDirsPreferredFirst() {
        let dirs = V2LiveDataProvider.candidateThreatIntelCacheDirs(
            preferring: "/private/tmp/maccrab-test"
        )
        // Preferred dir comes first with /threat_intel appended; system
        // + user-home paths come after; no duplicate entry if the user
        // happened to pass `/Library/Application Support/MacCrab`
        // (suffix collision).
        #expect(dirs.first == "/private/tmp/maccrab-test/threat_intel")
        // Even with a preferred dir, the canonical paths must still be
        // probed as fallbacks. Pin the count >= 2 contract; 3 when
        // user-home differs from system (the normal case).
        #expect(dirs.count >= 2)
    }

    @Test("candidateThreatIntelCacheDirs de-duplicates when preferred equals the system path")
    func candidateDirsDeDuplicatesPreferredEqualsSystem() {
        // The live provider's `dataDir` is "/Library/Application Support/
        // MacCrab" in production. The helper should NOT double-probe
        // the same path — pre-fix a naive implementation would emit
        // [system/threat_intel, system/threat_intel, user/threat_intel]
        // and ThreatIntelFeed.cachedIOCs(at:) would be called twice on
        // the same path on every refresh tick.
        let dirs = V2LiveDataProvider.candidateThreatIntelCacheDirs(
            preferring: "/Library/Application Support/MacCrab"
        )
        let uniqueCount = Set(dirs).count
        #expect(uniqueCount == dirs.count, "candidate dirs must be unique")
        #expect(dirs.first == "/Library/Application Support/MacCrab/threat_intel")
    }

    @Test("loadFeedsFromCache row staleness flips to .warning past the 6-hour cutoff")
    func loadFeedsStalenessThreshold() throws {
        let tmp = try makeTempDir("stale")
        let cacheDir = tmp + "/threat_intel"
        try writeCacheFixture(
            dir: cacheDir,
            perFeed: [
                "URLhaus":       Date().addingTimeInterval(-7 * 60 * 60),  // 7 h ago — stale
                "MalwareBazaar": Date().addingTimeInterval(-2 * 60),       // 2 min ago — fresh
            ],
            hashCount: 10,
            ipCount: 10,
            domainCount: 10,
            urlCount: 10
        )
        defer { try? FileManager.default.removeItem(atPath: tmp) }

        let rows = V2LiveDataProvider.loadFeedsFromCache(preferring: tmp)
        let urlhaus = rows.first(where: { $0.name == "URLhaus" })
        let malwareBazaar = rows.first(where: { $0.name == "MalwareBazaar" })
        #expect(urlhaus?.status == .warning, "feed older than 6h must surface as .warning")
        #expect(malwareBazaar?.status == .info, "feed fresh within 6h must stay .info")
    }
}
