// KnowledgeCPlugin — com.maccrab.forensics.knowledgec.
//
// Reads macOS's per-user CoreDuet KnowledgeC database, which
// tracks app usage events, focus mode changes, app-in-use spans,
// web visits, and location updates. Plan §13.6 candidate.
//
// Source: ~/Library/Application Support/Knowledge/knowledgeC.db
// Privacy class: metadata.

import Foundation
import CSQLCipher
import CryptoKit

public struct KnowledgeCPlugin: Collector {

    public static let manifest = PluginManifest(
        id: "com.maccrab.forensics.knowledgec",
        version: "1.0.0",
        displayName: "KnowledgeC",
        description: "Inventories macOS CoreDuet KnowledgeC events: app usage spans, focus transitions, web visits (URLs only, no titles), location updates. Privacy class metadata.",
        type: .collector,
        runtime: .tierA,
        tccRequirements: [.fullDiskAccess],
        inputs: [],
        outputs: [
            OutputSpec(
                contentType: "knowledgec.event",
                privacyClass: .metadata,
                viewerHint: ViewerHint(
                    viewer: .chart,
                    fieldRoles: [
                        "observed_at": .timestamp,
                        "stream_name": .title,
                        "bundle_id": .identifier,
                    ],
                    chart: ChartHint(chartType: .histogram, bucketField: "observed_at")
                )
            ),
        ],
        mcpTools: [
            MCPToolDescriptor(
                name: "knowledgec_app_usage_recent",
                description: "Recent KnowledgeC app-usage events with bundle id + duration + foreground/background.",
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
        let path = NSHomeDirectory() + "/Library/Application Support/Knowledge/knowledgeC.db"

        guard FileManager.default.isReadableFile(atPath: path) else {
            return CollectionResult(
                artifactsCommitted: 0,
                artifactsRejected: 0,
                notes: ["knowledgeC.db not readable at \(path)"],
                status: .partial
            )
        }

        let snap: LiveDBSnapshotResult
        do {
            snap = try LiveDBSnapshot.snapshot(sourcePath: path, layout: layout)
        } catch {
            return CollectionResult(
                artifactsCommitted: 0,
                artifactsRejected: 0,
                notes: ["knowledgeC snapshot failed: \(error)"],
                status: .error
            )
        }

        var db: OpaquePointer?
        let rc = sqlite3_open_v2(snap.path.path, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil)
        guard rc == SQLITE_OK, let h = db else {
            if let h = db { sqlite3_close(h) }
            return CollectionResult(
                artifactsCommitted: 0,
                artifactsRejected: 0,
                notes: ["knowledgeC open failed"],
                status: .error
            )
        }
        defer { sqlite3_close(h) }

        // KnowledgeC schema: ZOBJECT table holds events with
        // ZSTREAMNAME pointing to the event type (e.g.
        // "/app/usage", "/app/inFocus", "/visit/web", etc.).
        // Apple-internal; community-derived. Columns:
        //   Z_PK, ZSTREAMNAME, ZSTARTDATE, ZENDDATE, ZVALUESTRING
        //   (often the bundle id)
        let sql = """
            SELECT Z_PK, COALESCE(ZSTREAMNAME, ''),
                   COALESCE(ZSTARTDATE, 0), COALESCE(ZENDDATE, 0),
                   COALESCE(ZVALUESTRING, '')
            FROM ZOBJECT
            ORDER BY ZSTARTDATE DESC
            LIMIT 20000
            """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(h, sql, -1, &stmt, nil) == SQLITE_OK else {
            return CollectionResult(
                artifactsCommitted: 0, artifactsRejected: 0,
                notes: ["knowledgeC schema unexpected — ZOBJECT query failed"],
                status: .partial
            )
        }
        defer { sqlite3_finalize(stmt) }

        let nsDateRef: TimeInterval = 978_307_200
        var committed = 0, rejected = 0
        let now = Date()

        while sqlite3_step(stmt) == SQLITE_ROW {
            let pk = sqlite3_column_int64(stmt, 0)
            let streamName = String(cString: sqlite3_column_text(stmt, 1))
            let startRaw = sqlite3_column_double(stmt, 2)
            let endRaw = sqlite3_column_double(stmt, 3)
            let valueString = String(cString: sqlite3_column_text(stmt, 4))

            let started = Date(timeIntervalSince1970: nsDateRef + startRaw)
            let duration = endRaw > 0 ? endRaw - startRaw : 0

            let data: [String: JSONValue] = [
                "z_pk": .integer(pk),
                "stream_name": .string(streamName),
                "value_string": .string(valueString),
                "duration_seconds": .double(duration),
                "started_at_iso": .string(ISO8601DateFormatter().string(from: started)),
            ]
            let seed = "knowledgec.event:\(pk):\(streamName)"
            let sha = SHA256.hash(data: Data(seed.utf8)).map { String(format: "%02x", $0) }.joined()
            let record = ArtifactRecord(
                caseID: caseContext.caseID,
                pluginID: Self.manifest.id,
                pluginVersion: Self.manifest.version,
                schemaVersion: Self.manifest.schemaVersion,
                contentType: "knowledgec.event",
                sourcePath: path,
                sha256: sha,
                observedAt: started,
                capturedAt: now,
                summary: "\(streamName): \(valueString)\(duration > 0 ? " (\(Int(duration))s)" : "")",
                sizeBytes: Int64(streamName.utf8.count + valueString.utf8.count),
                confidence: .observed,
                privacyClass: .metadata,
                actor: NSUserName(),
                data: data
            )
            do {
                try await output.commit(record)
                committed += 1
            } catch { rejected += 1 }
        }

        return CollectionResult(
            artifactsCommitted: committed,
            artifactsRejected: rejected,
            notes: ["KnowledgeC: \(committed) events emitted"],
            status: .ok
        )
    }
}
