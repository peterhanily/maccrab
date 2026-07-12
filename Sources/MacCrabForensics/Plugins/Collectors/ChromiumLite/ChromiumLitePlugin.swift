// ChromiumLitePlugin — com.maccrab.forensics.chromium-lite.
//
// Reads the download-provenance rows Chromium-family browsers
// (Chrome / Brave / Edge / Arc / Chromium / Vivaldi / Opera) keep
// in their per-profile `History` SQLite database:
//   - downloads              (target_path, tab_url, referrer, …)
//   - downloads_url_chains   (the ordered redirect chain per id)
//
// This closes the origin-domain half of the delivery-provenance
// weld: LSQuarantine's origin_url is empty on Chrome-dominated
// boxes, but the referrer + redirect chain live here. Chromium's
// data under ~/Library/Application Support is owner-readable and is
// NOT FDA/TCC-gated — hence tccRequirements is empty (unlike Safari,
// whose ~/Library/Safari store is FDA-gated).
//
// STRICTLY read-only: every `History` file is copied via the
// backup-API snapshot (WAL-safe even while the browser is running)
// and parsed from the frozen <sha>.db snapshot opened READONLY. The
// live database is never opened read-write and never mutated.
//
// Privacy class metadata throughout.

import Foundation
import CSQLCipher
import CryptoKit

public struct ChromiumLitePlugin: Collector {

    public static let manifest = PluginManifest(
        id: "com.maccrab.forensics.chromium-lite",
        version: "1.0.0",
        displayName: "Chromium Lite",
        description: "Recent Chromium-family (Chrome / Brave / Edge / Arc / Chromium / Vivaldi / Opera) downloads with referrer, redirect chain, and on-disk target path. Owner-readable, no Full Disk Access required. Metadata-only.",
        type: .collector,
        runtime: .tierA,
        tccRequirements: [],
        inputs: [],
        outputs: [
            OutputSpec(
                contentType: "chromium.download",
                privacyClass: .metadata,
                viewerHint: ViewerHint(
                    viewer: .timeline,
                    fieldRoles: [
                        "observed_at": .timestamp,
                        "url": .title,
                        "target_path": .subtitle,
                    ]
                )
            ),
        ],
        mcpTools: [
            MCPToolDescriptor(
                name: "chrome_downloads_recent",
                description: "Recent Chromium-family (Chrome/Brave/Edge/Arc) downloads with referrer + redirect chain + target path.",
                exposesPrivacyClass: .metadata
            ),
        ],
        schemaVersion: 1,
        stability: .preview
    )

    public init() async throws {}

    // MARK: - Known browser bases

    /// A Chromium-family install root, relative to
    /// `~/Library/Application Support/`. Profiles live in immediate
    /// subdirectories (`Default`, `Profile 1`, …); Opera keeps its
    /// `History` directly in the base with no profile subdir — the
    /// unified `discoverProfiles` handles both by probing the base
    /// itself as well as each immediate subdirectory.
    struct BrowserBase {
        let browser: String
        let relPath: String
    }

    static let browserBases: [BrowserBase] = [
        BrowserBase(browser: "chrome",        relPath: "Google/Chrome"),
        BrowserBase(browser: "chrome-beta",   relPath: "Google/Chrome Beta"),
        BrowserBase(browser: "chrome-canary", relPath: "Google/Chrome Canary"),
        BrowserBase(browser: "chromium",      relPath: "Chromium"),
        BrowserBase(browser: "brave",         relPath: "BraveSoftware/Brave-Browser"),
        BrowserBase(browser: "edge",          relPath: "Microsoft Edge"),
        BrowserBase(browser: "arc",           relPath: "Arc/User Data"),
        BrowserBase(browser: "vivaldi",       relPath: "Vivaldi"),
        BrowserBase(browser: "opera",         relPath: "com.operasoftware.Opera"),
    ]

    // MARK: - Collect

    public func collect(
        case caseContext: CaseContext,
        window: TimeWindow?,
        output: any CollectorOutput
    ) async throws -> CollectionResult {

        let casesRoot = caseContext.directory.deletingLastPathComponent()
        let layout = CaseDirectoryLayout(casesRoot: casesRoot, caseID: caseContext.caseID)

        let appSupport = NSHomeDirectory() + "/Library/Application Support/"
        var notes: [String] = []
        var committed = 0
        var rejected = 0
        var profilesFound = 0
        let now = Date()

        for base in Self.browserBases {
            let baseDir = appSupport + base.relPath
            let profiles = Self.discoverProfiles(baseDir: baseDir)
            for (profile, historyPath) in profiles {
                profilesFound += 1
                // Per-profile do/catch: one locked or malformed profile
                // must never abort the whole run.
                do {
                    let snap = try LiveDBSnapshot.snapshot(sourcePath: historyPath, layout: layout)
                    let (c, r) = try await Self.parseDownloads(
                        snapshotPath: snap.path.path,
                        browser: base.browser,
                        profile: profile,
                        sourcePath: historyPath,
                        caseID: caseContext.caseID,
                        output: output,
                        now: now
                    )
                    committed += c
                    rejected += r
                    notes.append("\(base.browser)/\(profile): \(c) download(s) emitted")
                } catch {
                    notes.append("\(base.browser)/\(profile): snapshot/parse failed: \(error)")
                }
            }
        }

        if profilesFound == 0 {
            notes.append("No Chromium-family History databases found under \(appSupport)")
        }

        return CollectionResult(
            artifactsCommitted: committed,
            artifactsRejected: rejected,
            notes: notes,
            status: committed > 0 ? .ok : .partial
        )
    }

    // MARK: - Profile discovery

    /// Enumerate the readable `History` databases under one browser
    /// base. Returns `(profile, historyPath)` for the base itself
    /// (Opera's flat layout) plus every immediate subdirectory that
    /// holds a readable `History` file (Chrome's `Default` / `Profile
    /// N` layout). `History` is a regular SQLite file with NO
    /// extension — do not filter on suffix.
    static func discoverProfiles(baseDir: String) -> [(profile: String, historyPath: String)] {
        let fm = FileManager.default
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: baseDir, isDirectory: &isDir), isDir.boolValue else {
            return []
        }

        var result: [(String, String)] = []

        // Base-as-profile (Opera keeps History directly in the base).
        let baseHistory = baseDir + "/History"
        if isReadableRegularFile(baseHistory) {
            result.append(("Default", baseHistory))
        }

        // Immediate subdirectories that contain a readable History.
        if let entries = try? fm.contentsOfDirectory(atPath: baseDir) {
            for entry in entries.sorted() {
                let subdir = baseDir + "/" + entry
                var subIsDir: ObjCBool = false
                guard fm.fileExists(atPath: subdir, isDirectory: &subIsDir), subIsDir.boolValue else {
                    continue
                }
                let hist = subdir + "/History"
                if isReadableRegularFile(hist) {
                    result.append((entry, hist))
                }
            }
        }

        return result
    }

    static func isReadableRegularFile(_ path: String) -> Bool {
        let fm = FileManager.default
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: path, isDirectory: &isDir), !isDir.boolValue else {
            return false
        }
        return fm.isReadableFile(atPath: path)
    }

    // MARK: - Parse

    /// Parse the `downloads` + `downloads_url_chains` tables from a
    /// snapshot (opened READONLY) and commit one `chromium.download`
    /// artifact per row.
    static func parseDownloads(
        snapshotPath: String,
        browser: String,
        profile: String,
        sourcePath: String,
        caseID: String,
        output: any CollectorOutput,
        now: Date
    ) async throws -> (committed: Int, rejected: Int) {
        var db: OpaquePointer?
        let rc = sqlite3_open_v2(snapshotPath, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil)
        guard rc == SQLITE_OK, let h = db else {
            if let h = db { sqlite3_close(h) }
            return (0, 0)
        }
        defer { sqlite3_close(h) }

        // Chromium schema (History, macOS builds):
        //   downloads(id, target_path, tab_url, referrer, mime_type,
        //             start_time, total_bytes, received_bytes, state,
        //             site_url, …)
        //   downloads_url_chains(id, chain_index, url)
        // start_time is MICROSECONDS since 1601-01-01 UTC (Windows
        // FILETIME epoch), NOT the Safari/NSDate 2001 epoch.
        let sql = """
            SELECT d.id,
                   COALESCE(d.target_path, ''),
                   COALESCE(d.tab_url, ''),
                   COALESCE(d.referrer, ''),
                   COALESCE(d.mime_type, ''),
                   d.start_time,
                   d.total_bytes,
                   d.received_bytes,
                   d.state,
                   COALESCE(d.site_url, '')
            FROM downloads d
            ORDER BY d.start_time DESC
            LIMIT 5000
            """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(h, sql, -1, &stmt, nil) == SQLITE_OK else { return (0, 0) }
        defer { sqlite3_finalize(stmt) }

        // Reused per-row chain lookup — the full ordered redirect
        // chain for one download id.
        let chainSQL = "SELECT COALESCE(url, '') FROM downloads_url_chains WHERE id = ? ORDER BY chain_index ASC"
        var chainStmt: OpaquePointer?
        _ = sqlite3_prepare_v2(h, chainSQL, -1, &chainStmt, nil)
        defer { if chainStmt != nil { sqlite3_finalize(chainStmt) } }

        // Chromium start_time epoch: microseconds since 1601-01-01 UTC.
        let filetimeEpochOffset: TimeInterval = 11_644_473_600

        var committed = 0
        var rejected = 0
        while sqlite3_step(stmt) == SQLITE_ROW {
            let downloadID = sqlite3_column_int64(stmt, 0)
            let targetPath = text(stmt, 1)
            let tabURL     = text(stmt, 2)
            let referrer   = text(stmt, 3)
            let mimeType   = text(stmt, 4)
            let startTime  = sqlite3_column_int64(stmt, 5)
            let totalBytes = sqlite3_column_int64(stmt, 6)
            let received   = sqlite3_column_int64(stmt, 7)
            let state      = sqlite3_column_int64(stmt, 8)
            let siteURL    = text(stmt, 9)

            let chain = redirectChain(chainStmt, downloadID: downloadID)
            let firstURL = chain.first ?? ""
            let finalURL = chain.last ?? ""

            let observed = startTime > 0
                ? Date(timeIntervalSince1970: Double(startTime) / 1_000_000 - filetimeEpochOffset)
                : now

            // `url` (final resolved URL) drives the timeline title; fall
            // back to the tab URL when the chain is empty.
            let displayURL = finalURL.isEmpty ? tabURL : finalURL

            var data: [String: JSONValue] = [
                "download_id": .integer(downloadID),
                "url": .string(displayURL),
                "origin_url": .string(firstURL),
                "referrer": .string(referrer),
                "tab_url": .string(tabURL),
                "site_url": .string(siteURL),
                "target_path": .string(targetPath),
                "mime_type": .string(mimeType),
                "total_bytes": .integer(totalBytes),
                "received_bytes": .integer(received),
                "state": .integer(state),
                "browser": .string(browser),
                "profile": .string(profile),
            ]
            if !chain.isEmpty {
                data["redirect_chain"] = .array(chain.map { .string($0) })
            }

            let originHost = URL(string: referrer.isEmpty ? firstURL : referrer)?.host
                ?? URL(string: displayURL)?.host
                ?? "?"
            let fileName = targetPath.isEmpty
                ? (URL(string: displayURL)?.lastPathComponent ?? "?")
                : (targetPath as NSString).lastPathComponent

            let seed = "chromium.download:\(browser):\(profile):\(downloadID):\(finalURL)"
            let sha = SHA256.hash(data: Data(seed.utf8)).map { String(format: "%02x", $0) }.joined()

            let record = ArtifactRecord(
                caseID: caseID,
                pluginID: ChromiumLitePlugin.manifest.id,
                pluginVersion: ChromiumLitePlugin.manifest.version,
                schemaVersion: ChromiumLitePlugin.manifest.schemaVersion,
                contentType: "chromium.download",
                sourcePath: sourcePath,
                sha256: sha,
                observedAt: observed,
                capturedAt: now,
                summary: "\(browser)/\(profile): \(fileName) ← \(originHost)",
                sizeBytes: Int64(targetPath.utf8.count + finalURL.utf8.count),
                confidence: .observed,
                privacyClass: .metadata,
                actor: NSUserName(),
                data: data
            )
            do {
                try await output.commit(record)
                committed += 1
            } catch {
                rejected += 1
            }
        }
        return (committed, rejected)
    }

    // MARK: - Row helpers

    /// The full ordered redirect chain (`chain_index ASC`) for one
    /// download id, using the reused prepared statement. Empty when
    /// the download has no chain rows or the statement failed to
    /// prepare.
    private static func redirectChain(_ chainStmt: OpaquePointer?, downloadID: Int64) -> [String] {
        guard let chainStmt else { return [] }
        sqlite3_reset(chainStmt)
        sqlite3_clear_bindings(chainStmt)
        sqlite3_bind_int64(chainStmt, 1, downloadID)
        var urls: [String] = []
        while sqlite3_step(chainStmt) == SQLITE_ROW {
            urls.append(text(chainStmt, 0))
        }
        return urls
    }

    /// Read a TEXT column as a Swift String, treating NULL as "".
    /// The SELECTs COALESCE their text columns, so this is belt-and-
    /// suspenders against a NULL text pointer (which would crash
    /// `String(cString:)`).
    private static func text(_ stmt: OpaquePointer?, _ index: Int32) -> String {
        guard let c = sqlite3_column_text(stmt, index) else { return "" }
        return String(cString: c)
    }
}
