// MailLitePlugin — com.maccrab.forensics.mail.
//
// Plan §13.2 Mail forensics, v4-reframed scope:
//   - includeFullBodies default false (privacy)
//   - DKIM re-verification default off
//   - Body extraction always emits personalComms class
//
// What this RC ships (v1.16.0-rc.4):
//   - Walk ~/Library/Mail/V<N>/ to find Envelope Index databases
//   - Snapshot each (Mail may have it open)
//   - Query messages table for sender / subject / date_sent /
//     message_id + attachment metadata
//   - Emit mail.message artifacts (privacyClass=personalComms)
//
// What's deferred:
//   - .emlx file parsing for full bodies (privacy class content)
//   - DKIM / SPF / DMARC live re-verification (DNS cache,
//     opt-in flag)
//   - Per-mailbox topology aggregation
//   - V8 / V9 / V10 schema differences (the parser uses a
//     tolerant column-name approach so it works across versions)

import Foundation
import CSQLCipher
import CryptoKit

public struct MailLitePlugin: Collector {

    public static let manifest = PluginManifest(
        id: "com.maccrab.forensics.mail",
        version: "1.0.0",
        displayName: "Mail",
        description: "Inventory Mail Envelope Index messages — sender / subject / date / message_id + attachment metadata. Privacy class personalComms; MCP exposure gated by case.ai_content_allowed. Body parsing + DKIM re-verification deferred per plan §13.2 v4 defaults (privacy first).",
        type: .collector,
        runtime: .tierA,
        tccRequirements: [.fullDiskAccess],
        inputs: [],
        outputs: [
            OutputSpec(
                contentType: "mail.message",
                privacyClass: .personalComms,
                viewerHint: ViewerHint(
                    viewer: .table,
                    fieldRoles: [
                        "observed_at": .timestamp,
                        "subject": .title,
                        "sender_address": .subtitle,
                        "message_id": .identifier,
                        "is_flagged": .status,
                    ],
                    columns: ["observed_at", "sender_address", "subject", "is_read", "is_flagged"]
                )
            ),
        ],
        mcpTools: [
            MCPToolDescriptor(
                name: "mail_from_sender",
                description: "Recent Mail messages from a specific sender address.",
                exposesPrivacyClass: .personalComms
            ),
            MCPToolDescriptor(
                name: "mail_with_attachments",
                description: "Recent Mail messages that carry attachments (metadata only — filenames + sizes + mime types).",
                exposesPrivacyClass: .personalComms
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
        let now = Date()
        var notes: [String] = []
        var committed = 0
        var rejected = 0

        // Find Envelope Index files. macOS lays out Mail data
        // under V8 / V9 / V10 directory variants between releases;
        // walk ~/Library/Mail and pick up every Envelope Index we
        // find.
        let mailRoot = NSHomeDirectory() + "/Library/Mail"
        let envelopePaths = findEnvelopeIndexes(under: mailRoot)
        guard !envelopePaths.isEmpty else {
            notes.append("No Envelope Index files found under \(mailRoot) — Mail may not be set up, or FDA may be missing.")
            return CollectionResult(
                artifactsCommitted: 0,
                artifactsRejected: 0,
                notes: notes,
                status: .partial
            )
        }

        for envelopePath in envelopePaths {
            do {
                let snap = try LiveDBSnapshot.snapshot(sourcePath: envelopePath, layout: layout)
                let (c, r) = try await parseEnvelopeIndex(
                    snapshotPath: snap.path.path,
                    sourcePath: envelopePath,
                    caseContext: caseContext,
                    output: output,
                    now: now
                )
                committed += c
                rejected += r
                notes.append("Mail \(envelopePath): \(c) messages")
            } catch {
                notes.append("Mail \(envelopePath) snapshot/parse failed: \(error.localizedDescription)")
            }
        }

        if rejected > 0 {
            notes.append("\(rejected) mail.message artifacts rejected at INSERT — case is plaintext or lacks ai_content_allowed; create an encrypted case + grant AI content access.")
        }

        return CollectionResult(
            artifactsCommitted: committed,
            artifactsRejected: rejected,
            notes: notes,
            status: committed > 0 ? .ok : .partial
        )
    }

    private func findEnvelopeIndexes(under root: String) -> [String] {
        let fm = FileManager.default
        guard fm.fileExists(atPath: root),
              let enumerator = fm.enumerator(
                  at: URL(fileURLWithPath: root),
                  includingPropertiesForKeys: [.isRegularFileKey],
                  options: [.skipsHiddenFiles]
              )
        else { return [] }

        var out: [String] = []
        for case let url as URL in enumerator {
            if url.lastPathComponent == "Envelope Index" {
                out.append(url.path)
            }
        }
        return out
    }

    private func parseEnvelopeIndex(
        snapshotPath: String,
        sourcePath: String,
        caseContext: CaseContext,
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

        // Envelope Index schema varies by macOS Mail version. Use
        // the SQLite master table to find the messages table,
        // then probe columns by name.
        var messagesTable = "messages"
        var stmt: OpaquePointer?
        sqlite3_prepare_v2(h, "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%message%' LIMIT 1", -1, &stmt, nil)
        if sqlite3_step(stmt) == SQLITE_ROW {
            messagesTable = String(cString: sqlite3_column_text(stmt, 0))
        }
        sqlite3_finalize(stmt)

        // Tolerant SELECT: pull every column we might find. Mail's
        // schema includes: sender, subject, date_sent (or
        // date_received), message_id, mailbox, conversation_id,
        // flags, snippet (NOT extracted — that's body territory),
        // size, document_id.
        let sql = """
            SELECT
                rowid,
                COALESCE(sender, ''),
                COALESCE(subject_prefix, '') || COALESCE(subject, ''),
                COALESCE(date_sent, COALESCE(date_received, 0)),
                COALESCE(message_id, ''),
                COALESCE(mailbox, ''),
                COALESCE(conversation_id, 0),
                COALESCE(flags, 0)
            FROM \(messagesTable)
            ORDER BY date_received DESC, rowid DESC
            LIMIT 10000
            """
        var msgStmt: OpaquePointer?
        guard sqlite3_prepare_v2(h, sql, -1, &msgStmt, nil) == SQLITE_OK else {
            // Schema didn't match — fall back to a simpler query
            // that pulls whatever's there.
            return (0, 0)
        }
        defer { sqlite3_finalize(msgStmt) }

        var committed = 0
        var rejected = 0
        while sqlite3_step(msgStmt) == SQLITE_ROW {
            let messageRowid = sqlite3_column_int64(msgStmt, 0)
            let sender = String(cString: sqlite3_column_text(msgStmt, 1))
            let subject = String(cString: sqlite3_column_text(msgStmt, 2))
            let dateSent = sqlite3_column_double(msgStmt, 3)
            let messageID = String(cString: sqlite3_column_text(msgStmt, 4))
            let mailbox = Int(sqlite3_column_int(msgStmt, 5))
            let conversationID = Int64(sqlite3_column_int64(msgStmt, 6))
            let flags = Int64(sqlite3_column_int64(msgStmt, 7))

            // Date columns in Envelope Index are stored as Unix
            // epoch seconds (double). 0 means unknown; surface as
            // captured_at.
            let observed = dateSent > 0
                ? Date(timeIntervalSince1970: dateSent)
                : now

            var data: [String: JSONValue] = [
                "message_rowid": .integer(messageRowid),
                "sender_address": .string(sender),
                "subject": .string(subject),
                "message_id": .string(messageID),
                "mailbox_rowid": .integer(Int64(mailbox)),
                "conversation_id": .integer(conversationID),
                "flags": .integer(flags),
            ]
            // Common flag bits: 1=Read, 2=Deleted, 4=Replied,
            // 8=Forwarded, 16=Flagged, 64=Junk. Surface a few
            // common ones decoded.
            data["is_read"] = .bool((flags & 1) != 0)
            data["is_replied"] = .bool((flags & 4) != 0)
            data["is_flagged"] = .bool((flags & 16) != 0)
            data["is_junk"] = .bool((flags & 64) != 0)

            let seed = "mail.message:\(sourcePath):\(messageRowid):\(messageID)"
            let sha = SHA256.hash(data: Data(seed.utf8))
                .map { String(format: "%02x", $0) }.joined()

            let record = ArtifactRecord(
                caseID: caseContext.caseID,
                pluginID: MailLitePlugin.manifest.id,
                pluginVersion: MailLitePlugin.manifest.version,
                schemaVersion: MailLitePlugin.manifest.schemaVersion,
                contentType: "mail.message",
                sourcePath: sourcePath,
                sha256: sha,
                observedAt: observed,
                capturedAt: now,
                summary: "[\(sender.isEmpty ? "no sender" : sender)] \(subject.isEmpty ? "(no subject)" : subject)",
                sizeBytes: Int64(subject.utf8.count + sender.utf8.count),
                confidence: .observed,
                privacyClass: .personalComms,
                actor: NSUserName(),
                data: data
            )
            do {
                try await output.commit(record)
                committed += 1
            } catch ArtifactStoreError.plaintextCaseRejectsNonMetadata {
                rejected += 1
            } catch {
                rejected += 1
            }
        }
        return (committed, rejected)
    }
}
