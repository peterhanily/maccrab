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

@Suite("ThreatIntelFeed: shared path-tenant hosts are never domain IOCs")
struct ThreatIntelSharedHostTests {

    private static func makeDir() -> String {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("ti-shared-\(UUID().uuidString)").path
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        return dir
    }

    /// The shape a v1.22.1 cache holds after a URLhaus pull: hosts of
    /// malware URLs on GitHub and Google Drive stored as domain IOCs.
    private static func writeCache(to dir: String, domains: [(String, String)]) throws {
        func record(_ value: String, _ source: String) -> [String: Any] {
            ["value": value, "source": source, "lastSeenInFeed": Date().timeIntervalSinceReferenceDate,
             "tags": [String]()]
        }
        let cache: [String: Any] = [
            "hashes": [[String: Any]](), "ips": [[String: Any]](), "urls": [[String: Any]](),
            "domains": domains.map { record($0.0, $0.1) },
        ]
        let data = try JSONSerialization.data(withJSONObject: cache)
        try data.write(to: URL(fileURLWithPath: dir + "/feed_cache.json"))
    }

    @Test("shared platforms are recognised by suffix; tenant hosts and dedicated domains are not")
    func classification() {
        for host in ["github.com", "api.github.com", "raw.githubusercontent.com", "codeload.github.com",
                     "drive.google.com", "www.dropbox.com", "cdn.discordapp.com", "img1.wsimg.com",
                     "web.archive.org", "files.pythonhosted.org", "RAW.GITHUBUSERCONTENT.COM"] {
            #expect(ThreatIntelFeed.isSharedPathTenantHost(host), "\(host)")
        }
        for host in ["attacker.github.io", "evil-github.com", "notgithub.com", "wer-ldr.duckdns.org",
                     "lively-fog-af49.pablosoftwareplus.workers.dev", "pingu.ltd"] {
            #expect(!ThreatIntelFeed.isSharedPathTenantHost(host), "\(host)")
        }
    }

    @Test("a v1.22.1 cache's URLhaus-derived shared hosts are dropped on load and never match")
    func poisonedCacheIsCleaned() async throws {
        let dir = Self.makeDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        try Self.writeCache(to: dir, domains: [
            ("github.com", "URLhaus"), ("raw.githubusercontent.com", "URLhaus"),
            ("drive.google.com", "URLhaus"), ("evil-dedicated.top", "URLhaus"),
            ("docs.google.com", "Custom"),
        ])

        let cached = Set(ThreatIntelFeed.cachedIOCs(at: dir)?.domains.map(\.value) ?? [])
        #expect(cached == ["evil-dedicated.top", "docs.google.com"])

        let feed = ThreatIntelFeed(cacheDir: dir)
        _ = await feed.start(networkRefresh: false)
        await feed.stop()
        // The field false positives: CRITICAL alerts for GitHub and Drive.
        #expect(await feed.isDomainMalicious("api.github.com") == false)
        #expect(await feed.isDomainMalicious("github.com") == false)
        #expect(await feed.isDomainMalicious("raw.githubusercontent.com") == false)
        #expect(await feed.isDomainMalicious("drive.google.com") == false)
        // A dedicated malicious domain still matches, subdomains included.
        #expect(await feed.isDomainMalicious("evil-dedicated.top"))
        #expect(await feed.isDomainMalicious("cdn.evil-dedicated.top"))
        // An operator pin stays authoritative.
        #expect(await feed.isDomainMalicious("docs.google.com"))
    }

    @Test("a shared host imported on purpose matches exactly but never blanket-flags its subdomains")
    func importedSharedHostDoesNotWalk() async {
        let feed = ThreatIntelFeed(cacheDir: Self.makeDir())
        await feed.addMISPIOCs(domains: ["github.com", "githubusercontent.com"])
        #expect(await feed.isDomainMalicious("github.com"))
        #expect(await feed.isDomainMalicious("api.github.com") == false)
        #expect(await feed.isDomainMalicious("raw.githubusercontent.com") == false)
    }
}
