// FaceTimePlugin — com.maccrab.forensics.facetime.
//
// Plan §13.4 (deprioritised, but listed). Reads
// ~/Library/Application Support/CallHistoryDB/CallHistory.storedata
// for FaceTime call records: peer + start + duration + answered
// flag + AppleID context.
//
// Privacy class personalComms. Pass 2026-D rejects on plaintext.

import Foundation
import CSQLCipher
import CryptoKit

public struct FaceTimePlugin: Collector {

    public static let manifest = PluginManifest(
        id: "com.maccrab.forensics.facetime",
        version: "1.0.0",
        displayName: "FaceTime",
        description: "Reads ~/Library/Application Support/CallHistoryDB/CallHistory.storedata for FaceTime call records. Privacy class personalComms.",
        type: .collector,
        runtime: .tierA,
        tccRequirements: [.fullDiskAccess],
        inputs: [],
        outputs: [
            OutputSpec(contentType: "facetime.call", privacyClass: .personalComms),
        ],
        mcpTools: [],
        schemaVersion: 1,
        stability: .preview
    )

    public init() async throws {}

    public func collect(case caseContext: CaseContext, window: TimeWindow?, output: any CollectorOutput) async throws -> CollectionResult {
        let casesRoot = caseContext.directory.deletingLastPathComponent()
        let layout = CaseDirectoryLayout(casesRoot: casesRoot, caseID: caseContext.caseID)
        let path = NSHomeDirectory() + "/Library/Application Support/CallHistoryDB/CallHistory.storedata"
        guard FileManager.default.isReadableFile(atPath: path) else {
            return CollectionResult(artifactsCommitted: 0, artifactsRejected: 0, notes: ["CallHistory.storedata not readable"], status: .partial)
        }
        let snap: LiveDBSnapshotResult
        do { snap = try LiveDBSnapshot.snapshot(sourcePath: path, layout: layout) }
        catch { return CollectionResult(artifactsCommitted: 0, artifactsRejected: 0, notes: ["snapshot failed: \(error)"], status: .error) }
        var db: OpaquePointer?
        guard sqlite3_open_v2(snap.path.path, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil) == SQLITE_OK, let h = db else {
            return CollectionResult(artifactsCommitted: 0, artifactsRejected: 0, notes: ["open failed"], status: .error)
        }
        defer { sqlite3_close(h) }
        // Tolerant: Core Data-backed schema; the actual call table
        // is ZCALLRECORD. Columns: ZADDRESS / ZDATE / ZDURATION /
        // ZANSWERED / ZSERVICE_PROVIDER / ZNAME / ZORIGINATED.
        let sql = """
            SELECT Z_PK, COALESCE(ZADDRESS, ''), ZDATE, ZDURATION,
                   COALESCE(ZANSWERED, 0), COALESCE(ZSERVICE_PROVIDER, ''),
                   COALESCE(ZNAME, ''), COALESCE(ZORIGINATED, 0)
            FROM ZCALLRECORD
            ORDER BY ZDATE DESC
            LIMIT 5000
            """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(h, sql, -1, &stmt, nil) == SQLITE_OK else {
            return CollectionResult(artifactsCommitted: 0, artifactsRejected: 0, notes: ["schema not ZCALLRECORD"], status: .partial)
        }
        defer { sqlite3_finalize(stmt) }
        var committed = 0
        var rejected = 0
        let now = Date()
        let nsDateRef: TimeInterval = 978_307_200
        while sqlite3_step(stmt) == SQLITE_ROW {
            let pk = sqlite3_column_int64(stmt, 0)
            let address = String(cString: sqlite3_column_text(stmt, 1))
            let dateRaw = sqlite3_column_double(stmt, 2)
            let duration = sqlite3_column_double(stmt, 3)
            let answered = sqlite3_column_int(stmt, 4) != 0
            let service = String(cString: sqlite3_column_text(stmt, 5))
            let displayName = String(cString: sqlite3_column_text(stmt, 6))
            let originated = sqlite3_column_int(stmt, 7) != 0
            let observed = dateRaw == 0 ? now : Date(timeIntervalSince1970: nsDateRef + dateRaw)
            let data: [String: JSONValue] = [
                "call_pk": .integer(pk),
                "peer_address": .string(address),
                "display_name": .string(displayName),
                "duration_seconds": .double(duration),
                "answered": .bool(answered),
                "service_provider": .string(service),
                "originated_by_user": .bool(originated),
            ]
            let seed = "facetime.call:\(pk):\(address)"
            let sha = SHA256.hash(data: Data(seed.utf8)).map { String(format: "%02x", $0) }.joined()
            let record = ArtifactRecord(
                caseID: caseContext.caseID,
                pluginID: Self.manifest.id,
                pluginVersion: Self.manifest.version,
                schemaVersion: Self.manifest.schemaVersion,
                contentType: "facetime.call",
                sourcePath: path,
                sha256: sha,
                observedAt: observed,
                capturedAt: now,
                summary: "\(originated ? "→" : "←") \(service) \(address) \(answered ? "answered" : "missed") (\(Int(duration))s)",
                sizeBytes: 0,
                confidence: .observed,
                privacyClass: .personalComms,
                actor: NSUserName(),
                data: data
            )
            do { try await output.commit(record); committed += 1 } catch { rejected += 1 }
        }
        return CollectionResult(artifactsCommitted: committed, artifactsRejected: rejected, notes: ["FaceTime: \(committed) calls catalogued"], status: .ok)
    }
}
