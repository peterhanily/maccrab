// iMessageBodiesPlugin — com.maccrab.forensics.imessage-bodies.
//
// Plan §13.1 opt-in path. Complements imessage-metadata: emits
// imessage.message_body artifacts with the full text body.
//
// Privacy class CONTENT. Pass 2026-D rejects on plaintext cases.
// The plan's §13.1 explicit opt-in: operator must create an
// encrypted case + grant ai_content_allowed before MCP can see
// these.

import Foundation
import CSQLCipher
import CryptoKit

public struct iMessageBodiesPlugin: Collector {

    public static let manifest = PluginManifest(
        id: "com.maccrab.forensics.imessage-bodies",
        version: "1.0.0",
        displayName: "iMessage Bodies",
        description: "Opt-in companion to imessage-metadata. Emits imessage.message_body artifacts with full text. Privacy class CONTENT — plaintext cases reject at INSERT (Pass 2026-D); MCP exposure requires case.ai_content_allowed.",
        type: .collector,
        runtime: .tierA,
        tccRequirements: [.fullDiskAccess],
        inputs: [],
        outputs: [
            OutputSpec(
                contentType: "imessage.message_body",
                privacyClass: .content,
                optInRequired: true,
                viewerHint: ViewerHint(
                    viewer: .transcript,
                    fieldRoles: [
                        "observed_at": .timestamp,
                        "is_from_me": .sender,
                        "text": .body,
                        "guid": .identifier,
                    ]
                )
            ),
        ],
        mcpTools: [],
        schemaVersion: 1,
        stability: .preview
    )

    public init() async throws {}

    public func collect(case caseContext: CaseContext, window: TimeWindow?, output: any CollectorOutput) async throws -> CollectionResult {
        let casesRoot = caseContext.directory.deletingLastPathComponent()
        let layout = CaseDirectoryLayout(casesRoot: casesRoot, caseID: caseContext.caseID)
        let chatDB = NSHomeDirectory() + "/Library/Messages/chat.db"
        guard FileManager.default.isReadableFile(atPath: chatDB) else {
            return CollectionResult(artifactsCommitted: 0, artifactsRejected: 0, notes: ["chat.db not readable"], status: .partial)
        }
        let snap: LiveDBSnapshotResult
        do { snap = try LiveDBSnapshot.snapshot(sourcePath: chatDB, layout: layout) }
        catch { return CollectionResult(artifactsCommitted: 0, artifactsRejected: 0, notes: ["snapshot failed: \(error)"], status: .error) }

        var db: OpaquePointer?
        guard sqlite3_open_v2(snap.path.path, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil) == SQLITE_OK, let h = db else {
            return CollectionResult(artifactsCommitted: 0, artifactsRejected: 0, notes: ["snapshot open failed"], status: .error)
        }
        defer { sqlite3_close(h) }

        let sql = "SELECT m.ROWID, COALESCE(m.guid, ''), COALESCE(m.text, ''), m.date, m.is_from_me FROM message m WHERE COALESCE(m.text, '') != '' ORDER BY m.date DESC LIMIT 20000"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(h, sql, -1, &stmt, nil) == SQLITE_OK else {
            return CollectionResult(artifactsCommitted: 0, artifactsRejected: 0, notes: ["query failed"], status: .partial)
        }
        defer { sqlite3_finalize(stmt) }

        var committed = 0
        var rejected = 0
        let now = Date()
        let nsDateRef: TimeInterval = 978_307_200
        while sqlite3_step(stmt) == SQLITE_ROW {
            let rowid = sqlite3_column_int64(stmt, 0)
            let guid = String(cString: sqlite3_column_text(stmt, 1))
            let text = String(cString: sqlite3_column_text(stmt, 2))
            let dateRaw = sqlite3_column_int64(stmt, 3)
            let dateOffset: TimeInterval = abs(dateRaw) > 1_000_000_000_000_000
                ? TimeInterval(dateRaw) / 1_000_000_000.0
                : TimeInterval(dateRaw)
            let isFromMe = sqlite3_column_int(stmt, 4) != 0
            let observed = dateRaw == 0 ? now : Date(timeIntervalSince1970: nsDateRef + dateOffset)

            let seed = "imessage.message_body:\(rowid):\(guid)"
            let sha = SHA256.hash(data: Data(seed.utf8)).map { String(format: "%02x", $0) }.joined()
            let data: [String: JSONValue] = [
                "message_rowid": .integer(rowid),
                "guid": .string(guid),
                "text": .string(text),
                "is_from_me": .bool(isFromMe),
            ]
            let record = ArtifactRecord(
                caseID: caseContext.caseID,
                pluginID: Self.manifest.id,
                pluginVersion: Self.manifest.version,
                schemaVersion: Self.manifest.schemaVersion,
                contentType: "imessage.message_body",
                sourcePath: chatDB,
                sha256: sha,
                observedAt: observed,
                capturedAt: now,
                summary: "\(isFromMe ? "→" : "←") msg \(rowid)",
                sizeBytes: Int64(text.utf8.count),
                confidence: .observed,
                privacyClass: .content,
                actor: NSUserName(),
                data: data
            )
            do { try await output.commit(record); committed += 1 }
            catch ArtifactStoreError.plaintextCaseRejectsNonMetadata { rejected += 1 }
            catch { rejected += 1 }
        }
        var notes = ["iMessage bodies: \(committed) message bodies committed"]
        if rejected > 0 { notes.append("\(rejected) rejected — plaintext case can't hold content; create encrypted") }
        return CollectionResult(artifactsCommitted: committed, artifactsRejected: rejected, notes: notes, status: committed > 0 ? .ok : .partial)
    }
}
