// ChromiumLitePluginTests.swift
//
// Unit coverage for the com.maccrab.forensics.chromium-lite collector
// that backs the `chrome_downloads_recent` MCP tool:
//
//   1. parseDownloads against a synthetic Chromium `History` fixture
//      (downloads + downloads_url_chains) returns the expected records,
//      including the ordered redirect chain, the referrer, the on-disk
//      target path, and the FILETIME-epoch start_time conversion.
//   2. discoverProfiles enumerates multiple Chrome profiles + the
//      Opera-style flat (base-as-profile) layout, and skips dirs with
//      no History.
//   3. the WAL-safe locked-DB copy path is exercised end to end: a
//      WAL-mode fixture, held open by a second (writer) connection to
//      simulate a running browser, is snapshotted via LiveDBSnapshot
//      and parsed READONLY from the frozen snapshot.

import Testing
import Foundation
import CSQLCipher
@testable import MacCrabForensics

@Suite("ChromiumLitePlugin — Chromium download provenance")
struct ChromiumLitePluginTests {

    // MARK: - In-memory CollectorOutput

    /// Captures every committed artifact so the test can assert on the
    /// emitted rows without standing up an ArtifactStore.
    actor CollectingOutput: CollectorOutput {
        private(set) var records: [ArtifactRecord] = []
        @discardableResult
        func commit(_ record: ArtifactRecord) async throws -> Int64 {
            records.append(record)
            return Int64(records.count)
        }
    }

    // MARK: - Fixture helpers

    /// FILETIME microseconds (Chromium start_time) for a given Unix
    /// time in seconds.
    static func filetimeMicros(forUnix unix: Double) -> Int64 {
        Int64((unix + 11_644_473_600) * 1_000_000)
    }

    struct FixtureDownload {
        let id: Int64
        let targetPath: String
        let tabURL: String
        let referrer: String
        let mime: String
        let startTime: Int64
        let totalBytes: Int64
        let receivedBytes: Int64
        let state: Int64
        let siteURL: String
        /// Ordered redirect chain (chain_index 0..n). Empty → no rows.
        let chain: [String]
    }

    /// Build a synthetic Chromium `History` SQLite database (WAL mode,
    /// as a real browser keeps it) at `path`.
    static func makeHistoryFixture(at path: String, downloads: [FixtureDownload]) throws {
        var handle: OpaquePointer?
        let rc = sqlite3_open_v2(
            path, &handle,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
            nil
        )
        guard rc == SQLITE_OK, let db = handle else {
            throw FixtureError.openFailed
        }
        defer { sqlite3_close(db) }

        sqlite3_exec(db, "PRAGMA journal_mode=WAL;", nil, nil, nil)
        sqlite3_exec(db, """
            CREATE TABLE downloads(
                id INTEGER PRIMARY KEY,
                target_path TEXT,
                tab_url TEXT,
                referrer TEXT,
                mime_type TEXT,
                start_time INTEGER,
                total_bytes INTEGER,
                received_bytes INTEGER,
                state INTEGER,
                site_url TEXT
            );
            """, nil, nil, nil)
        sqlite3_exec(db, """
            CREATE TABLE downloads_url_chains(
                id INTEGER,
                chain_index INTEGER,
                url TEXT,
                PRIMARY KEY(id, chain_index)
            );
            """, nil, nil, nil)

        for d in downloads {
            let sql = """
                INSERT INTO downloads
                    (id, target_path, tab_url, referrer, mime_type, start_time,
                     total_bytes, received_bytes, state, site_url)
                VALUES
                    (\(d.id), '\(d.targetPath)', '\(d.tabURL)', '\(d.referrer)',
                     '\(d.mime)', \(d.startTime), \(d.totalBytes), \(d.receivedBytes),
                     \(d.state), '\(d.siteURL)');
                """
            guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else {
                throw FixtureError.insertFailed(String(cString: sqlite3_errmsg(db)))
            }
            for (idx, url) in d.chain.enumerated() {
                let csql = "INSERT INTO downloads_url_chains(id, chain_index, url) VALUES (\(d.id), \(idx), '\(url)');"
                guard sqlite3_exec(db, csql, nil, nil, nil) == SQLITE_OK else {
                    throw FixtureError.insertFailed(String(cString: sqlite3_errmsg(db)))
                }
            }
        }
    }

    enum FixtureError: Error { case openFailed, insertFailed(String) }

    static func stringValue(_ v: JSONValue?) -> String? {
        if case .string(let s)? = v { return s }
        return nil
    }
    static func intValue(_ v: JSONValue?) -> Int64? {
        if case .integer(let i)? = v { return i }
        return nil
    }
    static func arrayValue(_ v: JSONValue?) -> [JSONValue]? {
        if case .array(let a)? = v { return a }
        return nil
    }

    // MARK: - Test 1: parse a synthetic fixture

    @Test("parseDownloads returns expected records incl. redirect chain + FILETIME epoch")
    func parsesSyntheticFixture() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("chromium-parse-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let historyPath = dir.appendingPathComponent("History").path

        // Download 1: a DMG delivered via an ad-network redirect chain.
        let unix1 = 1_760_000_000.0   // fixed, well within Chromium's range
        // Download 2: a PDF with no chain rows (origin_url empty).
        let unix2 = 1_759_000_000.0
        try Self.makeHistoryFixture(at: historyPath, downloads: [
            FixtureDownload(
                id: 1,
                targetPath: "/Users/x/Downloads/evil.dmg",
                tabURL: "https://landing.example/promo",
                referrer: "https://ads.example/click",
                mime: "application/x-apple-diskimage",
                startTime: Self.filetimeMicros(forUnix: unix1),
                totalBytes: 1000, receivedBytes: 1000, state: 1,
                siteURL: "https://landing.example",
                chain: ["https://ads.example/click", "https://cdn.evil.example/evil.dmg"]
            ),
            FixtureDownload(
                id: 2,
                targetPath: "/Users/x/Downloads/report.pdf",
                tabURL: "https://example.org/file",
                referrer: "",
                mime: "application/pdf",
                startTime: Self.filetimeMicros(forUnix: unix2),
                totalBytes: 2048, receivedBytes: 2048, state: 1,
                siteURL: "https://example.org",
                chain: []
            ),
        ])

        let output = CollectingOutput()
        let (committed, rejected) = try await ChromiumLitePlugin.parseDownloads(
            snapshotPath: historyPath,
            browser: "chrome",
            profile: "Default",
            sourcePath: historyPath,
            caseID: "case-1",
            output: output,
            now: Date()
        )
        #expect(committed == 2)
        #expect(rejected == 0)

        let records = await output.records
        #expect(records.count == 2)

        // Row ordering is start_time DESC → download 1 first.
        guard let r1 = records.first(where: { Self.intValue($0.data["download_id"]) == 1 }) else {
            Issue.record("download 1 not emitted"); return
        }
        #expect(r1.contentType == "chromium.download")
        #expect(r1.privacyClass == .metadata)
        #expect(r1.pluginID == "com.maccrab.forensics.chromium-lite")
        #expect(Self.stringValue(r1.data["url"]) == "https://cdn.evil.example/evil.dmg")   // chain last
        #expect(Self.stringValue(r1.data["origin_url"]) == "https://ads.example/click")    // chain first
        #expect(Self.stringValue(r1.data["referrer"]) == "https://ads.example/click")
        #expect(Self.stringValue(r1.data["tab_url"]) == "https://landing.example/promo")
        #expect(Self.stringValue(r1.data["target_path"]) == "/Users/x/Downloads/evil.dmg")
        #expect(Self.stringValue(r1.data["mime_type"]) == "application/x-apple-diskimage")
        #expect(Self.stringValue(r1.data["browser"]) == "chrome")
        #expect(Self.stringValue(r1.data["profile"]) == "Default")
        #expect(Self.intValue(r1.data["total_bytes"]) == 1000)
        #expect(Self.intValue(r1.data["received_bytes"]) == 1000)
        #expect(Self.arrayValue(r1.data["redirect_chain"])?.count == 2)
        // FILETIME microseconds → Unix seconds, within a second.
        #expect(abs(r1.observedAt.timeIntervalSince1970 - unix1) < 1.0)
        // sourcePath points at the LIVE history path (provenance).
        #expect(r1.sourcePath == historyPath)
        #expect(r1.actor == NSUserName())

        // Download 2: no chain → origin_url empty, redirect_chain absent,
        // url falls back to the tab URL.
        guard let r2 = records.first(where: { Self.intValue($0.data["download_id"]) == 2 }) else {
            Issue.record("download 2 not emitted"); return
        }
        #expect(Self.stringValue(r2.data["origin_url"]) == "")
        #expect(r2.data["redirect_chain"] == nil)
        #expect(Self.stringValue(r2.data["url"]) == "https://example.org/file")
        #expect(abs(r2.observedAt.timeIntervalSince1970 - unix2) < 1.0)

        // Distinct dedup hashes per download.
        #expect(r1.sha256 != r2.sha256)
    }

    // MARK: - Test 2: multi-profile discovery

    @Test("discoverProfiles enumerates Chrome profiles, the Opera flat layout, and skips History-less dirs")
    func multiProfileDiscovery() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("chromium-discover-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let fm = FileManager.default

        // Chrome-style base: Default/History, Profile 1/History, a
        // Guest Profile dir WITHOUT History, and a non-directory file.
        let chromeBase = root.appendingPathComponent("Google/Chrome")
        for p in ["Default", "Profile 1", "Guest Profile"] {
            try fm.createDirectory(at: chromeBase.appendingPathComponent(p), withIntermediateDirectories: true)
        }
        try Data().write(to: chromeBase.appendingPathComponent("Default/History"))
        try Data().write(to: chromeBase.appendingPathComponent("Profile 1/History"))
        // Guest Profile intentionally has no History.
        try Data().write(to: chromeBase.appendingPathComponent("Local State"))   // stray non-dir

        let chromeProfiles = ChromiumLitePlugin.discoverProfiles(baseDir: chromeBase.path)
        let chromeNames = chromeProfiles.map(\.profile).sorted()
        #expect(chromeNames == ["Default", "Profile 1"])
        #expect(!chromeNames.contains("Guest Profile"))
        // Every returned path exists + ends in /History.
        for pr in chromeProfiles {
            #expect(pr.historyPath.hasSuffix("/History"))
            #expect(fm.fileExists(atPath: pr.historyPath))
        }

        // Opera-style flat base: History directly in the base.
        let operaBase = root.appendingPathComponent("com.operasoftware.Opera")
        try fm.createDirectory(at: operaBase, withIntermediateDirectories: true)
        try Data().write(to: operaBase.appendingPathComponent("History"))
        let operaProfiles = ChromiumLitePlugin.discoverProfiles(baseDir: operaBase.path)
        #expect(operaProfiles.count == 1)
        #expect(operaProfiles.first?.profile == "Default")
        #expect(operaProfiles.first?.historyPath == operaBase.appendingPathComponent("History").path)

        // A base that doesn't exist yields nothing.
        #expect(ChromiumLitePlugin.discoverProfiles(baseDir: root.appendingPathComponent("Nope").path).isEmpty)
    }

    // MARK: - Test 3: WAL-safe locked-DB copy path

    @Test("snapshot of a WAL-mode History held open by a writer parses READONLY from the frozen copy")
    func lockedCopyPathExercised() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("chromium-locked-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let historyPath = dir.appendingPathComponent("History").path

        let unix = 1_761_000_000.0
        try Self.makeHistoryFixture(at: historyPath, downloads: [
            FixtureDownload(
                id: 7,
                targetPath: "/Users/x/Downloads/installer.dmg",
                tabURL: "https://vendor.example/get",
                referrer: "https://vendor.example/",
                mime: "application/x-apple-diskimage",
                startTime: Self.filetimeMicros(forUnix: unix),
                totalBytes: 50, receivedBytes: 50, state: 1,
                siteURL: "https://vendor.example",
                chain: ["https://vendor.example/get", "https://dl.vendor.example/installer.dmg"]
            ),
        ])

        // Simulate a running browser: hold a second connection open on
        // the live DB while we snapshot it. The backup API drains the
        // WAL into the copy, so the snapshot is internally consistent.
        var writer: OpaquePointer?
        #expect(sqlite3_open_v2(historyPath, &writer, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, nil) == SQLITE_OK)
        defer { if writer != nil { sqlite3_close(writer) } }

        let destDir = dir.appendingPathComponent("snapshots")
        let snap = try LiveDBSnapshot.snapshot(sourcePath: historyPath, destDir: destDir)
        #expect(FileManager.default.fileExists(atPath: snap.path.path))
        // The live DB is untouched — parse from the frozen snapshot only.
        let output = CollectingOutput()
        let (committed, _) = try await ChromiumLitePlugin.parseDownloads(
            snapshotPath: snap.path.path,
            browser: "brave",
            profile: "Default",
            sourcePath: historyPath,
            caseID: "case-locked",
            output: output,
            now: Date()
        )
        #expect(committed == 1)
        let records = await output.records
        #expect(Self.stringValue(records.first?.data["url"]) == "https://dl.vendor.example/installer.dmg")
        #expect(Self.stringValue(records.first?.data["browser"]) == "brave")
    }

    // MARK: - Manifest sanity

    @Test("manifest advertises chrome_downloads_recent, requires no TCC, and validates")
    func manifestShape() throws {
        let m = ChromiumLitePlugin.manifest
        #expect(m.id == "com.maccrab.forensics.chromium-lite")
        #expect(m.tccRequirements.isEmpty)   // owner-readable — no FDA
        #expect(m.mcpTools.contains { $0.name == "chrome_downloads_recent" })
        #expect(m.outputs.contains { $0.contentType == "chromium.download" && $0.privacyClass == .metadata })
        try m.validate()   // namespace + shape invariants (mirrors Pass 2026-A)
    }
}
