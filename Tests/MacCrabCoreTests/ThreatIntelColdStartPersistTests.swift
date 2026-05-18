// ThreatIntelColdStartPersistTests.swift
// v1.12.6 Wave 9F — pin the bundled-IOC cold-start persist behavior so
// the dashboard's Intelligence-tab cold-mount sees IOCs immediately
// rather than waiting on the initial network fetch (~14 min latency
// observed in field on a fresh install).
//
// Pre-9F: BundledThreatIntel.loadInto added IOCs to in-memory state
// only; the cache file on disk was written only after the first
// updateAllFeeds() completed.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("ThreatIntelFeed: Wave 9F bundled cold-start persist")
struct ThreatIntelColdStartPersistTests {

    private static func makeTempDir() -> String {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("ti-9f-\(UUID().uuidString)").path
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        return dir
    }

    @Test("persistCacheNow writes file with current in-memory IOCs")
    func persistCacheNowWritesFile() async throws {
        let dir = Self.makeTempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }

        let feed = ThreatIntelFeed(cacheDir: dir)
        await feed.addCustomIOCs(
            hashes: ["b800000000000000000000000000000000000000000000000000000000000001"],
            ips: ["198.51.100.1"],
            domains: ["bundled-test.example"]
        )
        await feed.persistCacheNow()

        let cachePath = dir + "/feed_cache.json"
        #expect(FileManager.default.fileExists(atPath: cachePath))

        // Reading the cache via the same path the dashboard uses
        // must surface the IOCs we just added.
        let iocs = ThreatIntelFeed.cachedIOCs(at: dir)
        #expect(iocs != nil)
        #expect(iocs?.hashes.count == 1)
        #expect(iocs?.ips.count == 1)
        #expect(iocs?.domains.count == 1)
    }

    @Test("start awaits cache hydration before returning")
    func startHydratesInline() async throws {
        let dir = Self.makeTempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }

        // Seed the cache dir with a pre-existing feed_cache.json so we
        // can observe whether start() loads it BEFORE returning.
        let seedFeed = ThreatIntelFeed(cacheDir: dir)
        await seedFeed.addCustomIOCs(
            ips: ["203.0.113.7"],
            domains: ["warm-boot.example"]
        )
        await seedFeed.persistCacheNow()

        // Fresh actor: simulate daemon boot. After start() returns,
        // the in-memory state must already include the seeded IOCs —
        // otherwise the bundled-IOC persist that runs immediately
        // after start() in DaemonSetup could overwrite the file with
        // bundled-only data and lose the network IOCs.
        let feed = ThreatIntelFeed(cacheDir: dir)
        await feed.start()
        await feed.stop()

        let ipHit = await feed.isIPMalicious("203.0.113.7")
        let domHit = await feed.isDomainMalicious("warm-boot.example")
        #expect(ipHit)
        #expect(domHit)
    }

    @Test("Warm-boot persist preserves union of cached + bundled IOCs")
    func warmBootPersistMergesData() async throws {
        let dir = Self.makeTempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }

        // Cold boot 1: cache has prior network IOCs.
        do {
            let feed = ThreatIntelFeed(cacheDir: dir)
            await feed.addCustomIOCs(
                domains: ["network-fetched.example"]
            )
            await feed.persistCacheNow()
        }

        // Cold boot 2: simulate DaemonSetup ordering: start() →
        // bundled loadInto → persistCacheNow. The file on disk after
        // boot 2 must contain BOTH "network-fetched.example" and
        // the bundled domain.
        do {
            let feed = ThreatIntelFeed(cacheDir: dir)
            await feed.start()      // Hydrates from boot-1 cache file
            await feed.addCustomIOCs(domains: ["bundled-fresh.example"])
            await feed.persistCacheNow()
            await feed.stop()
        }

        let iocs = ThreatIntelFeed.cachedIOCs(at: dir)
        let domains = Set(iocs?.domains.map(\.value) ?? [])
        #expect(domains.contains("network-fetched.example"),
                "warm-boot persist must not drop prior cached IOCs")
        #expect(domains.contains("bundled-fresh.example"),
                "warm-boot persist must include fresh bundled IOCs")
    }
}
