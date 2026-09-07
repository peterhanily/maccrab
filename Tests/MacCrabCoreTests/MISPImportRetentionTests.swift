import Foundation
import Testing
@testable import MacCrabCore

@Suite("MISP import provenance and retention")
struct MISPImportRetentionTests {
    private struct CachedFeed: Encodable {
        let hashes: [ThreatIntelFeed.IOCRecord]
        let ips: [ThreatIntelFeed.IOCRecord]
        let domains: [ThreatIntelFeed.IOCRecord]
        let urls: [ThreatIntelFeed.IOCRecord] = []
    }

    private func temporaryDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("misp-retention-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory
    }

    private func writeCache(
        to directory: URL,
        hashes: [ThreatIntelFeed.IOCRecord] = [],
        ips: [ThreatIntelFeed.IOCRecord] = [],
        domains: [ThreatIntelFeed.IOCRecord] = []
    ) throws {
        let data = try JSONEncoder().encode(CachedFeed(hashes: hashes, ips: ips, domains: domains))
        try data.write(to: directory.appendingPathComponent("feed_cache.json"))
    }

    @Test("Recurring MISP imports are capped without starting network refresh")
    func recurringImportsStayCapped() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let feed = ThreatIntelFeed(cacheDir: directory.path, maxHashes: 2, maxIPs: 2, maxDomains: 2)

        for round in 1...4 {
            let hashes = (0..<3).map { offset in
                let suffix = String(round * 3 + offset, radix: 16)
                return String(repeating: "0", count: 64 - suffix.count) + suffix
            }
            let result = await feed.addMISPIOCs(
                hashes: hashes,
                ips: (0..<3).map { "198.51.100.\(round * 3 + $0)" },
                domains: (0..<3).map { "round-\(round)-\($0).example" }
            )
            #expect(result.accepted == 9)
            #expect(result.rejected.isEmpty)
            let counts = await feed.stats()
            #expect(counts.hashes == 2)
            #expect(counts.ips == 2)
            #expect(counts.domains == 2)
        }
        #expect(await feed.networkFetchAttempts == 0)
        await feed.persistCacheNow()
        let cached = try #require(ThreatIntelFeed.cachedIOCs(at: directory.path))
        #expect((cached.hashes + cached.ips + cached.domains).allSatisfy { $0.source == "MISP" })
        #expect((cached.hashes + cached.ips + cached.domains).allSatisfy { $0.firstSeen == nil })
    }

    @Test("A successful MISP refresh ages out old feed rows while preserving Custom")
    func sharedAgePolicyPreservesCustom() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let old = Date(timeIntervalSince1970: 1)
        let pinned = ThreatIntelFeed.IOCRecord(
            value: "operator.example", source: "Custom", firstSeen: old, lastSeenInFeed: old
        )
        try writeCache(to: directory, domains: [
            pinned,
            .init(value: "old-misp.example", source: "MISP", firstSeen: old, lastSeenInFeed: old),
            .init(value: "old-urlhaus.example", source: "URLhaus", firstSeen: old, lastSeenInFeed: old),
        ])
        let feed = ThreatIntelFeed(cacheDir: directory.path, maxAge: 86400)
        #expect(await feed.start(networkRefresh: false))
        await feed.addMISPIOCs(domains: ["current.example"])

        #expect(await feed.recordForDomain("old-misp.example") == nil)
        #expect(await feed.recordForDomain("old-urlhaus.example") == nil)
        #expect(await feed.recordForDomain("operator.example") == pinned)
        #expect(await feed.recordForDomain("current.example")?.source == "MISP")
        #expect(await feed.networkFetchAttempts == 0)
        await feed.stop()
    }

    @Test("Custom collisions survive MISP refresh and cache round trip")
    func customCollisionsSurviveRoundTrip() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let hash = String(repeating: "a", count: 64)
        let feed = ThreatIntelFeed(cacheDir: directory.path, maxHashes: 2, maxIPs: 2, maxDomains: 2)
        await feed.addCustomIOCs(hashes: [hash], ips: ["203.0.113.1"], domains: ["shared.example"])
        let pinnedHash = await feed.recordForHash(hash)
        let pinnedIP = await feed.recordForIP("203.0.113.1")
        let pinnedDomain = await feed.recordForDomain("shared.example")
        let result = await feed.addMISPIOCs(
            hashes: [hash.uppercased(), String(repeating: "b", count: 64)],
            ips: ["203.0.113.1", "203.0.113.2"],
            domains: [" SHARED.EXAMPLE ", "misp-only.example"]
        )
        #expect(result.accepted == 6)
        #expect(result.rejected.isEmpty)
        #expect(await feed.recordForHash(hash) == pinnedHash)
        #expect(await feed.recordForIP("203.0.113.1") == pinnedIP)
        #expect(await feed.recordForDomain("shared.example") == pinnedDomain)
        await feed.persistCacheNow()

        let reopened = ThreatIntelFeed(cacheDir: directory.path)
        #expect(await reopened.start(networkRefresh: false))
        #expect(await reopened.recordForHash(hash) == pinnedHash)
        #expect(await reopened.recordForIP("203.0.113.1") == pinnedIP)
        #expect(await reopened.recordForDomain("shared.example") == pinnedDomain)
        #expect(await reopened.recordForDomain("misp-only.example")?.source == "MISP")
        #expect(await reopened.networkFetchAttempts == 0)
        await reopened.stop()
    }

    @Test("Ambiguous old Custom records are never reclassified or deleted")
    func legacyCustomProvenanceRemainsUntouched() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let old = Date(timeIntervalSince1970: 1)
        let legacy = ["legacy-one.example", "legacy-two.example"].map {
            ThreatIntelFeed.IOCRecord(value: $0, source: "Custom", firstSeen: old, lastSeenInFeed: old)
        }
        try writeCache(to: directory, domains: legacy)
        let feed = ThreatIntelFeed(cacheDir: directory.path, maxDomains: 1, maxAge: 86400)
        #expect(await feed.start(networkRefresh: false))
        await feed.addMISPIOCs(domains: ["legacy-one.example", "new-misp.example"])
        for record in legacy {
            #expect(await feed.recordForDomain(record.value) == record)
        }
        #expect(await feed.recordForDomain("new-misp.example") == nil,
                "Existing Custom pins consume the shared cap without being silently deleted")
        await feed.persistCacheNow()
        let cached = try #require(ThreatIntelFeed.cachedIOCs(at: directory.path))
        #expect(Set(cached.domains) == Set(legacy))
        await feed.stop()
    }

    @Test("Empty, rejected and terminal MISP imports preserve the last good cache")
    func unsuccessfulImportsDoNotClearRecords() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let feed = ThreatIntelFeed(cacheDir: directory.path)
        await feed.addMISPIOCs(domains: ["known.example"])
        let before = await feed.recordForDomain("known.example")
        let empty = await feed.addMISPIOCs()
        #expect(empty.accepted == 0)
        let rejected = await feed.addMISPIOCs(hashes: ["not a hash"])
        #expect(rejected.accepted == 0)
        #expect(rejected.rejected == ["not a hash"])
        #expect(await feed.recordForDomain("known.example") == before)
        await feed.stop()
        let stopped = await feed.addMISPIOCs(domains: ["later.example"])
        #expect(stopped.accepted == 0)
        #expect(stopped.rejected == ["later.example"])
        #expect(await feed.recordForDomain("later.example") == nil)
        #expect(await feed.recordForDomain("known.example") == before)
    }

    @Test("Every external source preserves an independent operator pin")
    func feedMergePreservesCustomMetadata() {
        let pinned = ThreatIntelFeed.IOCRecord(
            value: "shared.example", source: "Custom", firstSeen: Date(timeIntervalSince1970: 1),
            lastSeenInFeed: Date(timeIntervalSince1970: 2), tags: ["operator"]
        )
        for source in ["MISP", "URLhaus", "Feodo", "MalwareBazaar"] {
            let incoming = ThreatIntelFeed.IOCRecord(value: pinned.value, source: source, firstSeen: nil)
            #expect(ThreatIntelFeed.mergingFeedRecord(incoming, existing: pinned) == pinned)
        }
        let earlier = ThreatIntelFeed.IOCRecord(value: pinned.value, source: "URLhaus", firstSeen: nil)
        let incoming = ThreatIntelFeed.IOCRecord(value: pinned.value, source: "MISP", firstSeen: nil)
        #expect(ThreatIntelFeed.mergingFeedRecord(incoming, existing: earlier) == incoming,
                "A fresh MISP observation must not claim another feed supplied it")
    }
}
