// iMessageMetadataPlugin — com.maccrab.forensics.imessage-metadata.
//
// Plan §13.1 iMessage-metadata.
//
// Headline scope: metadata-first. We emit handles, threads,
// per-message metadata (no body text), and URLs extracted from
// message bodies. The bodies themselves never leave the parser.
// Attachment payloads + soft-delete recovery are opt-in flags
// (deferred from this RC; the manifest declares the surface so
// future iterations are additive).
//
// Demo positioning (per plan §13.1):
// "Show me every URL anyone sent me in the last 7 days — no
// message bodies." Privacy proof point: Messages is the most-
// privacy-sensitive data source operators routinely ask about;
// metadata-first model demonstrates the platform's discipline.

import Foundation
import CSQLCipher
import CryptoKit

public struct iMessageMetadataPlugin: Collector {

    public static let manifest = PluginManifest(
        id: "com.maccrab.forensics.imessage-metadata",
        version: "1.0.0",
        displayName: "iMessage Metadata",
        description: "Walks ~/Library/Messages/chat.db with metadata-first defaults — handles, threads, per-message metadata (handle + date + is_from_me + has_attachments, NO TEXT) and URLs extracted from message bodies. Privacy class personalComms; bodies never leave the parser. Attachment payloads + soft-delete recovery are opt-in flags (deferred).",
        type: .collector,
        runtime: .tierA,
        tccRequirements: [.fullDiskAccess],
        inputs: [],
        outputs: [
            OutputSpec(contentType: "imessage.handle", privacyClass: .personalComms),
            OutputSpec(contentType: "imessage.thread", privacyClass: .personalComms),
            OutputSpec(contentType: "imessage.message_meta", privacyClass: .personalComms),
            OutputSpec(contentType: "imessage.url_mention", privacyClass: .personalComms),
        ],
        mcpTools: [
            MCPToolDescriptor(
                name: "imessage_urls_recent",
                description: "Recent URLs mentioned in iMessage conversations (no message bodies).",
                exposesPrivacyClass: .personalComms
            ),
            MCPToolDescriptor(
                name: "imessage_threads_with_handle",
                description: "Threads involving a specific handle (phone / email).",
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
        let chatDB = NSHomeDirectory() + "/Library/Messages/chat.db"

        guard FileManager.default.isReadableFile(atPath: chatDB) else {
            return CollectionResult(
                artifactsCommitted: 0,
                artifactsRejected: 0,
                notes: ["chat.db not readable at \(chatDB) (FDA likely missing or Messages not set up)"],
                status: .partial
            )
        }

        var notes: [String] = []
        let now = Date()
        var committed = 0
        var rejected = 0

        do {
            let snap = try LiveDBSnapshot.snapshot(sourcePath: chatDB, layout: layout)
            var db: OpaquePointer?
            let rc = sqlite3_open_v2(snap.path.path, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil)
            guard rc == SQLITE_OK, let h = db else {
                if let h = db { sqlite3_close(h) }
                return CollectionResult(
                    artifactsCommitted: 0, artifactsRejected: 0,
                    notes: ["chat.db snapshot open failed (rc=\(rc))"],
                    status: .error
                )
            }
            defer { sqlite3_close(h) }

            // Handles (phone numbers / emails / Apple IDs).
            let (hc, hr) = await emitHandles(db: h, caseContext: caseContext, sourcePath: chatDB, output: output, now: now)
            committed += hc; rejected += hr
            notes.append("imessage.handle: \(hc) emitted")

            // Threads.
            let (tc, tr) = await emitThreads(db: h, caseContext: caseContext, sourcePath: chatDB, output: output, now: now)
            committed += tc; rejected += tr
            notes.append("imessage.thread: \(tc) emitted")

            // Message metadata + URL extraction.
            let (mc, mr, uc, ur) = await emitMessageMetaAndURLs(
                db: h, caseContext: caseContext, sourcePath: chatDB, output: output, now: now
            )
            committed += mc + uc; rejected += mr + ur
            notes.append("imessage.message_meta: \(mc) emitted, \(mr) rejected")
            notes.append("imessage.url_mention: \(uc) emitted, \(ur) rejected")
        } catch {
            return CollectionResult(
                artifactsCommitted: 0, artifactsRejected: 0,
                notes: ["chat.db snapshot failed: \(error.localizedDescription)"],
                status: .error
            )
        }

        return CollectionResult(
            artifactsCommitted: committed,
            artifactsRejected: rejected,
            notes: notes,
            status: committed > 0 ? .ok : .partial
        )
    }

    // MARK: - Handle / thread / message_meta emission

    private func emitHandles(db: OpaquePointer, caseContext: CaseContext, sourcePath: String, output: any CollectorOutput, now: Date) async -> (Int, Int) {
        let sql = "SELECT ROWID, id, COALESCE(service, ''), COALESCE(country, ''), COALESCE(uncanonicalized_id, '') FROM handle"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return (0, 0) }
        defer { sqlite3_finalize(stmt) }

        var committed = 0
        var rejected = 0
        while sqlite3_step(stmt) == SQLITE_ROW {
            let rowid = sqlite3_column_int64(stmt, 0)
            let id = String(cString: sqlite3_column_text(stmt, 1))
            let service = String(cString: sqlite3_column_text(stmt, 2))
            let country = String(cString: sqlite3_column_text(stmt, 3))
            let uncanon = String(cString: sqlite3_column_text(stmt, 4))

            let data: [String: JSONValue] = [
                "handle_rowid": .integer(rowid),
                "id": .string(id),
                "service": .string(service),
                "country": .string(country),
                "uncanonicalized_id": .string(uncanon),
            ]
            let seed = "imessage.handle:\(rowid):\(id):\(service)"
            let sha = SHA256.hash(data: Data(seed.utf8)).map { String(format: "%02x", $0) }.joined()
            let record = ArtifactRecord(
                caseID: caseContext.caseID,
                pluginID: Self.manifest.id,
                pluginVersion: Self.manifest.version,
                schemaVersion: Self.manifest.schemaVersion,
                contentType: "imessage.handle",
                sourcePath: sourcePath,
                sha256: sha,
                observedAt: now,
                capturedAt: now,
                summary: "\(service.isEmpty ? "?" : service): \(id)",
                sizeBytes: Int64(id.utf8.count),
                confidence: .observed,
                privacyClass: .personalComms,
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

    private func emitThreads(db: OpaquePointer, caseContext: CaseContext, sourcePath: String, output: any CollectorOutput, now: Date) async -> (Int, Int) {
        let sql = "SELECT ROWID, COALESCE(chat_identifier, ''), COALESCE(service_name, ''), COALESCE(display_name, ''), COALESCE(group_id, '') FROM chat"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return (0, 0) }
        defer { sqlite3_finalize(stmt) }

        var committed = 0
        var rejected = 0
        while sqlite3_step(stmt) == SQLITE_ROW {
            let rowid = sqlite3_column_int64(stmt, 0)
            let chatID = String(cString: sqlite3_column_text(stmt, 1))
            let service = String(cString: sqlite3_column_text(stmt, 2))
            let displayName = String(cString: sqlite3_column_text(stmt, 3))
            let groupID = String(cString: sqlite3_column_text(stmt, 4))

            let data: [String: JSONValue] = [
                "chat_rowid": .integer(rowid),
                "chat_identifier": .string(chatID),
                "service_name": .string(service),
                "display_name": .string(displayName),
                "group_id": .string(groupID),
                "is_group": .bool(!groupID.isEmpty),
            ]
            let seed = "imessage.thread:\(rowid):\(chatID)"
            let sha = SHA256.hash(data: Data(seed.utf8)).map { String(format: "%02x", $0) }.joined()
            let record = ArtifactRecord(
                caseID: caseContext.caseID,
                pluginID: Self.manifest.id,
                pluginVersion: Self.manifest.version,
                schemaVersion: Self.manifest.schemaVersion,
                contentType: "imessage.thread",
                sourcePath: sourcePath,
                sha256: sha,
                observedAt: now,
                capturedAt: now,
                summary: "\(service): \(displayName.isEmpty ? chatID : displayName)\(groupID.isEmpty ? "" : " (group)")",
                sizeBytes: 0,
                confidence: .observed,
                privacyClass: .personalComms,
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

    private func emitMessageMetaAndURLs(
        db: OpaquePointer,
        caseContext: CaseContext,
        sourcePath: String,
        output: any CollectorOutput,
        now: Date
    ) async -> (mc: Int, mr: Int, uc: Int, ur: Int) {
        // chat.db's `date` column is in mac absolute time
        // nanoseconds since 2001-01-01.
        let nsDateRef: TimeInterval = 978_307_200
        let sql = """
            SELECT m.ROWID, COALESCE(m.guid, ''), COALESCE(m.text, ''), m.handle_id, m.date,
                   m.is_from_me, m.is_read, m.is_delivered, m.cache_has_attachments
            FROM message m
            ORDER BY m.date DESC
            LIMIT 20000
            """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return (0, 0, 0, 0) }
        defer { sqlite3_finalize(stmt) }

        var mc = 0, mr = 0, uc = 0, ur = 0
        let urlRegex = try? NSRegularExpression(
            pattern: "https?://[A-Za-z0-9._/~%?&=#:+\\-,@!$()*'\\[\\]]+",
            options: []
        )

        while sqlite3_step(stmt) == SQLITE_ROW {
            let rowid = sqlite3_column_int64(stmt, 0)
            let guid = String(cString: sqlite3_column_text(stmt, 1))
            // IMPORTANT: read `text` only into a local for URL
            // extraction; never commit it as an artifact field.
            let text = String(cString: sqlite3_column_text(stmt, 2))
            let handleID = sqlite3_column_int64(stmt, 3)
            // Pre-iOS 11 messages have `date` as seconds; post is
            // nanoseconds. Heuristic: if value > 10^15 the unit
            // is nanoseconds.
            let dateRaw = sqlite3_column_int64(stmt, 4)
            let dateOffset: TimeInterval = abs(dateRaw) > 1_000_000_000_000_000
                ? TimeInterval(dateRaw) / 1_000_000_000.0
                : TimeInterval(dateRaw)
            let isFromMe = sqlite3_column_int(stmt, 5) != 0
            let isRead = sqlite3_column_int(stmt, 6) != 0
            let isDelivered = sqlite3_column_int(stmt, 7) != 0
            let hasAttachments = sqlite3_column_int(stmt, 8) != 0

            let observed = dateRaw == 0 ? now : Date(timeIntervalSince1970: nsDateRef + dateOffset)

            // 1. message_meta — explicitly omits the text body.
            let metaData: [String: JSONValue] = [
                "message_rowid": .integer(rowid),
                "guid": .string(guid),
                "handle_rowid": .integer(handleID),
                "is_from_me": .bool(isFromMe),
                "is_read": .bool(isRead),
                "is_delivered": .bool(isDelivered),
                "has_attachments": .bool(hasAttachments),
                "text_length": .integer(Int64(text.utf8.count)),
            ]
            let metaSeed = "imessage.message_meta:\(rowid):\(guid)"
            let metaSha = SHA256.hash(data: Data(metaSeed.utf8)).map { String(format: "%02x", $0) }.joined()
            let metaRecord = ArtifactRecord(
                caseID: caseContext.caseID,
                pluginID: Self.manifest.id,
                pluginVersion: Self.manifest.version,
                schemaVersion: Self.manifest.schemaVersion,
                contentType: "imessage.message_meta",
                sourcePath: sourcePath,
                sha256: metaSha,
                observedAt: observed,
                capturedAt: now,
                summary: "\(isFromMe ? "→" : "←") msg \(rowid)\(hasAttachments ? " 📎" : "") (len \(text.utf8.count))",
                sizeBytes: Int64(text.utf8.count),
                confidence: .observed,
                privacyClass: .personalComms,
                actor: NSUserName(),
                data: metaData
            )
            do {
                try await output.commit(metaRecord)
                mc += 1
            } catch {
                mr += 1
            }

            // 2. URL extraction — emit one chat.url_mention per
            // distinct URL found in the message text. The URL
            // itself is the only fragment of message content that
            // crosses into the artifact store.
            if let regex = urlRegex, !text.isEmpty {
                let nsText = text as NSString
                let matches = regex.matches(in: text, range: NSRange(location: 0, length: nsText.length))
                var seenURLs = Set<String>()
                for match in matches {
                    let url = nsText.substring(with: match.range)
                    if seenURLs.contains(url) { continue }
                    seenURLs.insert(url)
                    let domain = URL(string: url)?.host ?? ""

                    let urlData: [String: JSONValue] = [
                        "url": .string(url),
                        "domain": .string(domain),
                        "message_rowid": .integer(rowid),
                        "guid": .string(guid),
                        "handle_rowid": .integer(handleID),
                        "is_from_me": .bool(isFromMe),
                    ]
                    let urlSeed = "imessage.url_mention:\(rowid):\(url)"
                    let urlSha = SHA256.hash(data: Data(urlSeed.utf8)).map { String(format: "%02x", $0) }.joined()
                    let urlRecord = ArtifactRecord(
                        caseID: caseContext.caseID,
                        pluginID: Self.manifest.id,
                        pluginVersion: Self.manifest.version,
                        schemaVersion: Self.manifest.schemaVersion,
                        contentType: "imessage.url_mention",
                        sourcePath: sourcePath,
                        sha256: urlSha,
                        observedAt: observed,
                        capturedAt: now,
                        summary: "URL mention: \(domain.isEmpty ? url : domain)",
                        sizeBytes: Int64(url.utf8.count),
                        confidence: .observed,
                        privacyClass: .personalComms,
                        actor: NSUserName(),
                        data: urlData
                    )
                    do {
                        try await output.commit(urlRecord)
                        uc += 1
                    } catch {
                        ur += 1
                    }
                }
            }
        }
        return (mc, mr, uc, ur)
    }
}
