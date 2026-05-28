// SafariLitePlugin — com.maccrab.forensics.safari-lite.
//
// Plan §13.3 Safari-lite (recommended first split, before
// Safari-deep with cookies). Reads Safari's per-user state:
//   - History.db    (SQLite, snapshotted)
//   - Downloads.plist
//   - Extensions/Extensions.plist
//
// Privacy class metadata throughout. Cookies / LocalStorage /
// IndexedDB belong in Safari-deep (content class, default-off)
// and stay in §13.3 backlog.

import Foundation
import CSQLCipher
import CryptoKit

public struct SafariLitePlugin: Collector {

    public static let manifest = PluginManifest(
        id: "com.maccrab.forensics.safari-lite",
        version: "1.0.0",
        displayName: "Safari Lite",
        description: "Inventory Safari's history visits, downloads, and installed extensions. Metadata-only; cookies / LocalStorage belong in Safari-deep (post-v1.16 backlog).",
        type: .collector,
        runtime: .tierA,
        tccRequirements: [.fullDiskAccess],
        inputs: [],
        outputs: [
            OutputSpec(
                contentType: "safari.history_visit",
                privacyClass: .metadata,
                viewerHint: ViewerHint(
                    viewer: .chart,
                    fieldRoles: [
                        "observed_at": .timestamp,
                        "url": .title,
                        "domain": .subtitle,
                        "visit_count_at_url": .count,
                    ],
                    chart: ChartHint(chartType: .bar, groupField: "domain")
                )
            ),
            OutputSpec(
                contentType: "safari.download",
                privacyClass: .metadata,
                viewerHint: ViewerHint(
                    viewer: .timeline,
                    fieldRoles: [
                        "observed_at": .timestamp,
                        "url": .link,
                        "filename": .title,
                        "origin_url": .subtitle,
                    ]
                )
            ),
            OutputSpec(
                contentType: "safari.extension",
                privacyClass: .metadata,
                viewerHint: ViewerHint(
                    viewer: .table,
                    fieldRoles: [
                        "name": .title,
                        "bundle_identifier": .identifier,
                        "version": .subtitle,
                        "signed": .status,
                    ],
                    columns: ["name", "bundle_identifier", "version", "signed"]
                )
            ),
        ],
        mcpTools: [
            MCPToolDescriptor(
                name: "safari_visits_to_domain",
                description: "Recent Safari history visits to a specific domain.",
                exposesPrivacyClass: .metadata
            ),
            MCPToolDescriptor(
                name: "safari_recent_downloads",
                description: "Recent Safari downloads with quarantine UUID correlation.",
                exposesPrivacyClass: .metadata
            ),
        ],
        schemaVersion: 1,
        stability: .preview
    )

    public init() async throws {}

    public func collect(
        case caseContext: CaseContext,
        window: TimeWindow?,
        output: any CollectorOutput
    ) async throws -> CollectionResult {

        let casesRoot = caseContext.directory.deletingLastPathComponent()
        let layout = CaseDirectoryLayout(casesRoot: casesRoot, caseID: caseContext.caseID)

        let safariRoot = NSHomeDirectory() + "/Library/Safari"
        var notes: [String] = []
        var committed = 0
        var rejected = 0
        let now = Date()

        // History.db — SQLite, snapshot before parse.
        let historyPath = safariRoot + "/History.db"
        if FileManager.default.isReadableFile(atPath: historyPath) {
            do {
                let snap = try LiveDBSnapshot.snapshot(sourcePath: historyPath, layout: layout)
                let (vc, rj) = try await Self.parseHistory(
                    snapshotPath: snap.path.path,
                    caseContext: caseContext,
                    snapshotSourcePath: historyPath,
                    output: output,
                    now: now
                )
                committed += vc
                rejected += rj
                notes.append("Safari History.db: \(vc) visits emitted")
            } catch {
                notes.append("Safari History.db snapshot/parse failed: \(error)")
            }
        } else {
            notes.append("Safari History.db not readable at \(historyPath) (FDA may be missing)")
        }

        // Downloads.plist
        let downloadsPath = safariRoot + "/Downloads.plist"
        if FileManager.default.isReadableFile(atPath: downloadsPath) {
            let (dc, dr) = await Self.parseDownloads(
                path: downloadsPath,
                caseContext: caseContext,
                output: output,
                now: now
            )
            committed += dc
            rejected += dr
            notes.append("Safari Downloads.plist: \(dc) downloads emitted")
        } else {
            notes.append("Safari Downloads.plist not present at \(downloadsPath)")
        }

        // Extensions/Extensions.plist
        let extensionsPath = safariRoot + "/Extensions/Extensions.plist"
        if FileManager.default.isReadableFile(atPath: extensionsPath) {
            let (ec, er) = await Self.parseExtensions(
                path: extensionsPath,
                caseContext: caseContext,
                output: output,
                now: now
            )
            committed += ec
            rejected += er
            notes.append("Safari Extensions.plist: \(ec) extensions emitted")
        } else {
            notes.append("Safari Extensions.plist not present at \(extensionsPath)")
        }

        return CollectionResult(
            artifactsCommitted: committed,
            artifactsRejected: rejected,
            notes: notes,
            status: committed > 0 ? .ok : .partial
        )
    }

    // MARK: - History.db

    private static func parseHistory(
        snapshotPath: String,
        caseContext: CaseContext,
        snapshotSourcePath: String,
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

        // History schema (macOS 13-15):
        //   history_items(id, url, domain_expansion, visit_count, daily_visit_counts)
        //   history_visits(id, history_item, visit_time, title, load_successful, ...)
        // visit_time is NSDate epoch (2001-01-01 reference).
        let sql = """
            SELECT v.id, i.url, v.title, v.visit_time, v.load_successful, i.visit_count
            FROM history_visits v
            JOIN history_items i ON i.id = v.history_item
            ORDER BY v.visit_time DESC
            LIMIT 5000
            """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(h, sql, -1, &stmt, nil) == SQLITE_OK else { return (0, 0) }
        defer { sqlite3_finalize(stmt) }

        let nsDateRef: TimeInterval = 978_307_200
        var committed = 0
        var rejected = 0
        while sqlite3_step(stmt) == SQLITE_ROW {
            let visitID = sqlite3_column_int64(stmt, 0)
            let url = String(cString: sqlite3_column_text(stmt, 1))
            let title: String? = sqlite3_column_type(stmt, 2) == SQLITE_NULL
                ? nil
                : String(cString: sqlite3_column_text(stmt, 2))
            let visitTime = sqlite3_column_double(stmt, 3)
            let loadSuccess = sqlite3_column_int(stmt, 4) != 0
            let visitCount = Int(sqlite3_column_int(stmt, 5))

            let observed = Date(timeIntervalSince1970: nsDateRef + visitTime)
            let domain = URL(string: url)?.host ?? ""

            var data: [String: JSONValue] = [
                "visit_id": .integer(visitID),
                "url": .string(url),
                "domain": .string(domain),
                "load_successful": .bool(loadSuccess),
                "visit_count_at_url": .integer(Int64(visitCount)),
            ]
            if let t = title { data["title"] = .string(t) }

            let seed = "safari.history:\(visitID):\(url)"
            let sha = SHA256.hash(data: Data(seed.utf8)).map { String(format: "%02x", $0) }.joined()
            let record = ArtifactRecord(
                caseID: caseContext.caseID,
                pluginID: SafariLitePlugin.manifest.id,
                pluginVersion: SafariLitePlugin.manifest.version,
                schemaVersion: SafariLitePlugin.manifest.schemaVersion,
                contentType: "safari.history_visit",
                sourcePath: snapshotSourcePath,
                sha256: sha,
                observedAt: observed,
                capturedAt: now,
                summary: "\(domain.isEmpty ? "(no domain)" : domain) — \(title ?? url)",
                sizeBytes: Int64(url.utf8.count),
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

    // MARK: - Downloads.plist

    private static func parseDownloads(
        path: String,
        caseContext: CaseContext,
        output: any CollectorOutput,
        now: Date
    ) async -> (committed: Int, rejected: Int) {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
              let dict = plist as? [String: Any],
              let entries = dict["DownloadHistory"] as? [[String: Any]] else {
            return (0, 0)
        }
        var committed = 0
        var rejected = 0
        for entry in entries {
            let urlStr = (entry["DownloadEntryURL"] as? String) ?? ""
            let dest = (entry["DownloadEntryPath"] as? String) ?? ""
            let identifier = (entry["DownloadEntryIdentifier"] as? String) ?? UUID().uuidString
            let mimeType = entry["DownloadEntryMimeType"] as? String
            let bytesReceived = entry["DownloadEntryProgressBytesSoFar"] as? Int64 ?? 0
            let totalBytes = entry["DownloadEntryProgressTotalToLoad"] as? Int64 ?? 0
            let startedDate = entry["DownloadEntryDateAddedKey"] as? Date

            var data: [String: JSONValue] = [
                "identifier": .string(identifier),
                "url": .string(urlStr),
                "destination_path": .string(dest),
                "bytes_received": .integer(bytesReceived),
                "total_bytes": .integer(totalBytes),
                "complete": .bool(totalBytes > 0 && bytesReceived >= totalBytes),
            ]
            if let m = mimeType { data["mime_type"] = .string(m) }

            let observed = startedDate ?? now
            let seed = "safari.download:\(identifier):\(urlStr)"
            let sha = SHA256.hash(data: Data(seed.utf8)).map { String(format: "%02x", $0) }.joined()
            let record = ArtifactRecord(
                caseID: caseContext.caseID,
                pluginID: SafariLitePlugin.manifest.id,
                pluginVersion: SafariLitePlugin.manifest.version,
                schemaVersion: SafariLitePlugin.manifest.schemaVersion,
                contentType: "safari.download",
                sourcePath: path,
                sha256: sha,
                observedAt: observed,
                capturedAt: now,
                summary: "Download: \(URL(string: urlStr)?.lastPathComponent ?? urlStr) → \(dest)",
                sizeBytes: Int64(urlStr.utf8.count + dest.utf8.count),
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

    // MARK: - Extensions.plist

    private static func parseExtensions(
        path: String,
        caseContext: CaseContext,
        output: any CollectorOutput,
        now: Date
    ) async -> (committed: Int, rejected: Int) {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
              let dict = plist as? [String: Any],
              let installed = dict["Installed Extensions"] as? [[String: Any]] else {
            return (0, 0)
        }
        var committed = 0
        var rejected = 0
        for ext in installed {
            let bundleID = (ext["Bundle Identifier"] as? String) ?? ""
            let archive = (ext["Archive File Name"] as? String) ?? ""
            let displayName = (ext["Bundle Directory Name"] as? String) ?? archive
            let enabled = (ext["Enabled"] as? Bool) ?? false

            var data: [String: JSONValue] = [
                "bundle_identifier": .string(bundleID),
                "display_name": .string(displayName),
                "archive_file_name": .string(archive),
                "enabled": .bool(enabled),
            ]

            let seed = "safari.extension:\(bundleID):\(archive)"
            let sha = SHA256.hash(data: Data(seed.utf8)).map { String(format: "%02x", $0) }.joined()
            let record = ArtifactRecord(
                caseID: caseContext.caseID,
                pluginID: SafariLitePlugin.manifest.id,
                pluginVersion: SafariLitePlugin.manifest.version,
                schemaVersion: SafariLitePlugin.manifest.schemaVersion,
                contentType: "safari.extension",
                sourcePath: path,
                sha256: sha,
                observedAt: now,
                capturedAt: now,
                summary: "Safari extension: \(displayName)\(enabled ? " (enabled)" : " (disabled)")",
                sizeBytes: 0,
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
}
