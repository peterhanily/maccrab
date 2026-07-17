// QuarantineEnricherTests.swift
// Covers the xattr-gated / GUID-keyed lookup fast path and the negative
// sentinel cache added in the per-event CPU optimization batch.
//
// Detection-safety context: the `quarantine.*` enrichment keys written by
// `enrich()` are display-only — no rule, sequence, campaign, behavior scorer,
// or noise filter consumes them — so these lookup-path changes cannot alter a
// detection outcome. The tests below verify the fast-path mechanics.

import Testing
import Foundation
@testable import MacCrabCore

// MARK: - Test helpers

/// Set a `com.apple.quarantine` xattr on `path`. Returns true on success.
@discardableResult
private func setQuarantineXattr(_ path: String, value: String) -> Bool {
    let bytes = Array(value.utf8)
    let rc = path.withCString { pathPtr -> Int32 in
        "com.apple.quarantine".withCString { namePtr -> Int32 in
            bytes.withUnsafeBytes { raw in
                setxattr(pathPtr, namePtr, raw.baseAddress, raw.count, 0, 0)
            }
        }
    }
    return rc == 0
}

/// Create an empty temp file with no xattrs. Caller removes it.
private func makeTempFile() -> String {
    let path = NSTemporaryDirectory()
        + "maccrab-qtn-\(UUID().uuidString).bin"
    _ = FileManager.default.createFile(atPath: path, contents: Data("x".utf8))
    return path
}

/// Build a minimal QuarantineEventsV2-shaped SQLite DB at a fresh temp path
/// with a single row keyed by `guid`. Uses the system sqlite3 CLI (macOS
/// ships /usr/bin/sqlite3). Returns the DB path, or nil if the CLI is absent.
private func buildQuarantineDB(guid: String, dataURL: String, agent: String) -> String? {
    let cli = "/usr/bin/sqlite3"
    guard FileManager.default.fileExists(atPath: cli) else { return nil }
    let dbPath = NSTemporaryDirectory() + "maccrab-qtndb-\(UUID().uuidString).sqlite"
    let sql = """
        CREATE TABLE LSQuarantineEvent (
          LSQuarantineEventIdentifier TEXT PRIMARY KEY,
          LSQuarantineTimeStamp REAL,
          LSQuarantineAgentBundleIdentifier TEXT,
          LSQuarantineAgentName TEXT,
          LSQuarantineDataURLString TEXT,
          LSQuarantineOriginURLString TEXT,
          LSQuarantineOriginTitle TEXT,
          LSQuarantineTypeNumber INTEGER
        );
        INSERT INTO LSQuarantineEvent
          (LSQuarantineEventIdentifier, LSQuarantineTimeStamp,
           LSQuarantineAgentBundleIdentifier, LSQuarantineDataURLString,
           LSQuarantineOriginURLString, LSQuarantineOriginTitle)
        VALUES
          ('\(guid)', 700000000.0, '\(agent)', '\(dataURL)',
           'https://example.com/', 'Origin Page');
        """
    let p = Process()
    p.executableURL = URL(fileURLWithPath: cli)
    p.arguments = [dbPath, sql]
    do {
        try p.run()
        p.waitUntilExit()
    } catch {
        return nil
    }
    guard p.terminationStatus == 0,
          FileManager.default.fileExists(atPath: dbPath) else { return nil }
    return dbPath
}

// MARK: - Tests

@Suite("QuarantineEnricher fast path")
struct QuarantineEnricherFastPathTests {

    /// #2 xattr gate: a file with no com.apple.quarantine xattr resolves to nil,
    /// and the GUID probe itself returns nil — so `lookup` never opens the DB.
    @Test("No quarantine xattr yields nil without touching the DB")
    func noXattrYieldsNil() async {
        let file = makeTempFile()
        defer { try? FileManager.default.removeItem(atPath: file) }

        // The xattr probe (the gate) short-circuits before any DB access.
        #expect(QuarantineEnricher.quarantineGUID(forPath: file) == nil)

        // Point the enricher at a DB path that does NOT exist. If the gate were
        // bypassed we'd fall through to lookupByGUID, which would still return
        // nil — but the gate guarantees nil is reached via the xattr probe.
        let enricher = QuarantineEnricher(dbPath: NSTemporaryDirectory()
            + "maccrab-absent-\(UUID().uuidString).sqlite")
        let info = await enricher.lookup(filePath: file)
        #expect(info == nil)
    }

    /// #6 negative cache is honored: once a record-less path is looked up, a
    /// subsequent lookup short-circuits BEFORE re-probing the xattr — proven by
    /// the fact that adding a resolvable quarantine xattr afterwards does NOT
    /// change the result, while a fresh enricher (no negative cache) DOES
    /// resolve the very same file + xattr + DB.
    @Test("Negative cache is honored on repeat lookup")
    func negativeCacheHonored() async {
        let guid = "2853CF89-E284-42FC-84C8-013ECE017C50"
        let dataURL = "https://example.com/evil.dmg"
        guard let dbPath = buildQuarantineDB(
            guid: guid, dataURL: dataURL, agent: "com.apple.Safari"
        ) else {
            // sqlite3 CLI unavailable — cannot build the fixture DB.
            Issue.record("could not build quarantine fixture DB (no /usr/bin/sqlite3)")
            return
        }
        defer { try? FileManager.default.removeItem(atPath: dbPath) }

        let file = makeTempFile()
        defer { try? FileManager.default.removeItem(atPath: file) }

        let enricher = QuarantineEnricher(dbPath: dbPath)

        // 1) No xattr yet -> nil, and `file` is now negatively cached.
        let first = await enricher.lookup(filePath: file)
        #expect(first == nil)

        // 2) Now make the file resolvable: attach a quarantine xattr whose GUID
        //    keys the row in the fixture DB.
        #expect(setQuarantineXattr(file, value: "0081;00000000;UnitTest;\(guid)"))

        // 3) Same enricher: negative cache short-circuits -> still nil.
        let second = await enricher.lookup(filePath: file)
        #expect(second == nil)

        // 4) Control: a fresh enricher (empty caches) resolves the same file,
        //    xattr, and DB -> non-nil. This proves step 3's nil came from the
        //    honored negative cache, not from an unresolvable row.
        let control = QuarantineEnricher(dbPath: dbPath)
        let resolved = await control.lookup(filePath: file)
        #expect(resolved != nil)
        #expect(resolved?.downloadURL == dataURL)
    }

    /// The GUID-keyed path resolves the exact row for a file that carries a
    /// quarantine xattr (end-to-end: xattr -> GUID -> lookupByGUID).
    @Test("Present xattr resolves via GUID key")
    func presentXattrResolvesViaGUID() async {
        let guid = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
        let dataURL = "https://downloads.example.org/tool.pkg"
        guard let dbPath = buildQuarantineDB(
            guid: guid, dataURL: dataURL, agent: "com.google.Chrome"
        ) else {
            Issue.record("could not build quarantine fixture DB (no /usr/bin/sqlite3)")
            return
        }
        defer { try? FileManager.default.removeItem(atPath: dbPath) }

        let file = makeTempFile()
        defer { try? FileManager.default.removeItem(atPath: file) }
        #expect(setQuarantineXattr(file, value: "0083;00000000;Chrome;\(guid)"))

        let enricher = QuarantineEnricher(dbPath: dbPath)
        let info = await enricher.lookup(filePath: file)
        #expect(info?.downloadURL == dataURL)
        #expect(info?.downloadAgent == "com.google.Chrome")

        // enrich() surfaces the same provenance into the display-only dict.
        var enrichments: [String: String] = [:]
        await enricher.enrich(&enrichments, forFile: file)
        #expect(enrichments["quarantine.download_url"] == dataURL)
    }

    /// enrich() is a no-op for a file with no quarantine record.
    @Test("enrich leaves dict untouched with no record")
    func enrichNoRecord() async {
        let file = makeTempFile()
        defer { try? FileManager.default.removeItem(atPath: file) }

        let enricher = QuarantineEnricher(dbPath: NSTemporaryDirectory()
            + "maccrab-absent-\(UUID().uuidString).sqlite")
        var enrichments: [String: String] = [:]
        await enricher.enrich(&enrichments, forFile: file)
        #expect(enrichments.isEmpty)
    }
}
