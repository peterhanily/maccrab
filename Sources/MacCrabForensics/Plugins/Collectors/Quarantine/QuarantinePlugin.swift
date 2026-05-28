// QuarantinePlugin — com.maccrab.forensics.quarantine.
//
// Inventories macOS LaunchServices quarantine events: every
// downloaded item (binary, archive, document) that macOS tagged
// with a quarantine xattr carries a row in this SQLite file with
// the originating URL + the application that performed the
// download + a UUID that can be cross-referenced against the
// file's `com.apple.quarantine` xattr.
//
// Plan §13.6 candidate.

import Foundation
import CSQLCipher
import CryptoKit

public struct QuarantinePlugin: Collector {

    public static let manifest = PluginManifest(
        id: "com.maccrab.forensics.quarantine",
        version: "1.0.0",
        displayName: "Quarantine Aggregator",
        description: "Reads ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2 — every download macOS tagged with the quarantine xattr. UUID + originating URL + downloading application + timestamp. Privacy class metadata.",
        type: .collector,
        runtime: .tierA,
        tccRequirements: [.fullDiskAccess],
        inputs: [],
        outputs: [
            OutputSpec(
                contentType: "quarantine.event",
                privacyClass: .metadata,
                viewerHint: ViewerHint(
                    viewer: .chart,
                    fieldRoles: [
                        "observed_at": .timestamp,
                        "agent_name": .title,
                        "origin_url": .subtitle,
                    ],
                    chart: ChartHint(chartType: .histogram, bucketField: "observed_at", bucket: .day)
                )
            ),
        ],
        mcpTools: [
            MCPToolDescriptor(
                name: "quarantine_recent_downloads",
                description: "Recent macOS quarantine events: download URL + agent + timestamp.",
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
        let path = NSHomeDirectory() + "/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"

        guard FileManager.default.isReadableFile(atPath: path) else {
            return CollectionResult(
                artifactsCommitted: 0, artifactsRejected: 0,
                notes: ["QuarantineEventsV2 not readable at \(path)"],
                status: .partial
            )
        }

        let snap: LiveDBSnapshotResult
        do {
            snap = try LiveDBSnapshot.snapshot(sourcePath: path, layout: layout)
        } catch {
            return CollectionResult(
                artifactsCommitted: 0, artifactsRejected: 0,
                notes: ["Quarantine snapshot failed: \(error)"],
                status: .error
            )
        }

        var db: OpaquePointer?
        let rc = sqlite3_open_v2(snap.path.path, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil)
        guard rc == SQLITE_OK, let h = db else {
            if let h = db { sqlite3_close(h) }
            return CollectionResult(
                artifactsCommitted: 0, artifactsRejected: 0,
                notes: ["Quarantine open failed"], status: .error
            )
        }
        defer { sqlite3_close(h) }

        // LSQuarantineEvent columns: LSQuarantineEventIdentifier
        // (UUID), LSQuarantineTimeStamp (Mac absolute time),
        // LSQuarantineAgentName, LSQuarantineAgentBundleIdentifier,
        // LSQuarantineDataURLString, LSQuarantineOriginURLString,
        // LSQuarantineSenderName.
        let sql = """
            SELECT
                COALESCE(LSQuarantineEventIdentifier, ''),
                COALESCE(LSQuarantineTimeStamp, 0),
                COALESCE(LSQuarantineAgentName, ''),
                COALESCE(LSQuarantineAgentBundleIdentifier, ''),
                COALESCE(LSQuarantineDataURLString, ''),
                COALESCE(LSQuarantineOriginURLString, '')
            FROM LSQuarantineEvent
            ORDER BY LSQuarantineTimeStamp DESC
            LIMIT 5000
            """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(h, sql, -1, &stmt, nil) == SQLITE_OK else {
            return CollectionResult(
                artifactsCommitted: 0, artifactsRejected: 0,
                notes: ["Quarantine schema unexpected"], status: .partial
            )
        }
        defer { sqlite3_finalize(stmt) }

        let nsDateRef: TimeInterval = 978_307_200
        var committed = 0, rejected = 0
        let now = Date()
        while sqlite3_step(stmt) == SQLITE_ROW {
            let uuid = String(cString: sqlite3_column_text(stmt, 0))
            let ts = sqlite3_column_double(stmt, 1)
            let agentName = String(cString: sqlite3_column_text(stmt, 2))
            let agentBundle = String(cString: sqlite3_column_text(stmt, 3))
            let dataURL = String(cString: sqlite3_column_text(stmt, 4))
            let originURL = String(cString: sqlite3_column_text(stmt, 5))

            let observed = ts > 0 ? Date(timeIntervalSince1970: nsDateRef + ts) : now
            let domain = URL(string: dataURL)?.host ?? URL(string: originURL)?.host ?? ""

            let data: [String: JSONValue] = [
                "uuid": .string(uuid),
                "agent_name": .string(agentName),
                "agent_bundle_identifier": .string(agentBundle),
                "data_url": .string(dataURL),
                "origin_url": .string(originURL),
                "domain": .string(domain),
            ]
            let seed = "quarantine.event:\(uuid):\(dataURL)"
            let sha = SHA256.hash(data: Data(seed.utf8)).map { String(format: "%02x", $0) }.joined()
            let record = ArtifactRecord(
                caseID: caseContext.caseID,
                pluginID: Self.manifest.id,
                pluginVersion: Self.manifest.version,
                schemaVersion: Self.manifest.schemaVersion,
                contentType: "quarantine.event",
                sourcePath: path,
                sha256: sha,
                observedAt: observed,
                capturedAt: now,
                summary: "\(agentName.isEmpty ? "?" : agentName) → \(URL(string: dataURL)?.lastPathComponent ?? dataURL)",
                sizeBytes: Int64(dataURL.utf8.count + originURL.utf8.count),
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
            notes: ["Quarantine: \(committed) events emitted"],
            status: .ok
        )
    }
}
