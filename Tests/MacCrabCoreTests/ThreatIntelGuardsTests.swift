// ThreatIntelGuardsTests.swift
// v1.9 Phase-5 — pin TI-H1 (PSL guard) and TI-H2 (anchored URL match)
// against false-positive regressions.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("ThreatIntelFeed: TI-H1 multi-tenant suffix guard")
struct ThreatIntelPSLGuardTests {

    /// Build a fresh actor backed by a tmp cache dir. Loaded with no
    /// network — we'll inject IOCs via a small file dropped into the
    /// cache dir + loadCustomFile, mirroring the production
    /// `*.domains.txt` drop-in path that v1.9 Phase-5.7 wired.
    private static func makeFeed() async -> (ThreatIntelFeed, String) {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("ti-test-\(UUID().uuidString)").path
        try? FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
        return (ThreatIntelFeed(cacheDir: tmp), tmp)
    }

    private static func writeDomainsFile(_ entries: [String], to dir: String) -> String {
        let p = dir + "/test.domains.txt"
        try? entries.joined(separator: "\n").write(toFile: p, atomically: true, encoding: .utf8)
        return p
    }

    private static func writeURLsFile(_ entries: [String], to dir: String) -> String {
        let p = dir + "/test.urls.txt"
        try? entries.joined(separator: "\n").write(toFile: p, atomically: true, encoding: .utf8)
        return p
    }

    @Test("Suffix walk skips multi-tenant platforms (pages.dev, vercel.app, etc.)")
    func suffixWalkSkipsPlatforms() async throws {
        let (feed, dir) = await Self.makeFeed()
        // Operator pins `pages.dev` directly as a custom IOC (rare,
        // but if a user / feed entry does this, siblings must
        // still be safe via the platform allowlist).
        let path = Self.writeDomainsFile(["pages.dev"], to: dir)
        _ = try await feed.loadCustomFile(path: path, type: .domain)
        // Direct hit: pages.dev IS in records, exact-match works.
        let direct = await feed.isDomainMalicious("pages.dev")
        #expect(direct == true)
        // Sibling: legit.pages.dev should NOT be flagged via suffix
        // walk because pages.dev is on the platform allowlist.
        let sibling = await feed.isDomainMalicious("legit-app.pages.dev")
        #expect(sibling == false, "platform suffix walk must not blanket-flag siblings")
    }

    @Test("Suffix walk still works for non-platform parents")
    func suffixWalkStillWorksForRealParents() async throws {
        let (feed, dir) = await Self.makeFeed()
        let path = Self.writeDomainsFile(["evil.com"], to: dir)
        _ = try await feed.loadCustomFile(path: path, type: .domain)
        // sub.evil.com should suffix-match evil.com.
        let hit = await feed.isDomainMalicious("sub.evil.com")
        #expect(hit == true)
    }

    @Test("Direct exact-match against a platform-subdomain still hits")
    func exactMatchOnPlatformStillHits() async throws {
        let (feed, dir) = await Self.makeFeed()
        let path = Self.writeDomainsFile(["attacker.pages.dev"], to: dir)
        _ = try await feed.loadCustomFile(path: path, type: .domain)
        let direct = await feed.isDomainMalicious("attacker.pages.dev")
        #expect(direct == true)
        // Different subdomain should NOT match.
        let other = await feed.isDomainMalicious("legit.pages.dev")
        #expect(other == false)
    }
}

@Suite("ThreatIntelFeed: TI-H2 anchored URL match")
struct ThreatIntelAnchoredURLTests {

    @Test("URL match requires prefix or exact, not arbitrary substring")
    func anchoredMatch() async throws {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("ti-anchor-\(UUID().uuidString)").path
        try? FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
        let feed = ThreatIntelFeed(cacheDir: tmp)
        let path = tmp + "/evil.urls.txt"
        try? "http://evil.com/payload.exe".write(toFile: path, atomically: true, encoding: .utf8)
        _ = try await feed.loadCustomFile(path: path, type: .url)

        // Exact match.
        #expect(await feed.isURLMalicious("http://evil.com/payload.exe") == true)
        // Prefix match (ioc is a prefix of the queried URL).
        #expect(await feed.isURLMalicious("http://evil.com/payload.exe?session=123") == true)
        // Innocuous URL that contains the IOC as a substring (e.g. a
        // tracker query param) — pre-fix this would FP; now safe.
        #expect(await feed.isURLMalicious("https://safe.example.com/?ref=http://evil.com/payload.exe") == false)
    }
}
