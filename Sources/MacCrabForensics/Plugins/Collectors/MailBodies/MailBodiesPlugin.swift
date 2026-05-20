// MailBodiesPlugin — com.maccrab.forensics.mail-bodies.
//
// Plan §13.2 opt-in companion to mail. Walks .emlx files under
// ~/Library/Mail/V*/.../Messages/ and extracts header + body
// blocks. v1.16.0-rc.14 ships an envelope-only RC of bodies:
// emits the mail.message_body artifact with the From/To/Subject
// headers + body preview (first 32 KB). Full MIME multipart walk
// + attachment payload extraction are follow-ups.
//
// Privacy class personalComms (sender/recipient pairs are
// inherently personal). Pass 2026-D rejects on plaintext cases.

import Foundation
import CryptoKit

public struct MailBodiesPlugin: Collector {

    public static let manifest = PluginManifest(
        id: "com.maccrab.forensics.mail-bodies",
        version: "1.0.0",
        displayName: "Mail Bodies",
        description: "Opt-in companion to mail. Walks .emlx files for header + body preview (first 32 KB). Full MIME multipart walk + attachment extraction deferred. Privacy class personalComms.",
        type: .collector,
        runtime: .tierA,
        tccRequirements: [.fullDiskAccess],
        inputs: [],
        outputs: [
            OutputSpec(contentType: "mail.message_body", privacyClass: .personalComms, optInRequired: true),
        ],
        mcpTools: [],
        schemaVersion: 1,
        stability: .preview
    )

    public init() async throws {}

    public func collect(case caseContext: CaseContext, window: TimeWindow?, output: any CollectorOutput) async throws -> CollectionResult {
        let mailRoot = NSHomeDirectory() + "/Library/Mail"
        guard let enumerator = FileManager.default.enumerator(at: URL(fileURLWithPath: mailRoot), includingPropertiesForKeys: nil) else {
            return CollectionResult(artifactsCommitted: 0, artifactsRejected: 0, notes: ["mail root not enumerable"], status: .partial)
        }
        var committed = 0
        var rejected = 0
        let now = Date()
        var processed = 0
        for case let url as URL in enumerator {
            guard url.pathExtension == "emlx" else { continue }
            processed += 1
            if processed > 2000 { break } // cap
            guard let data = try? Data(contentsOf: url) else { continue }
            // .emlx format: first line is the byte count; rest is
            // standard RFC 822 message + optional Apple metadata
            // plist after the message body.
            guard let raw = String(data: data, encoding: .utf8) ?? String(data: data, encoding: .isoLatin1) else { continue }
            let lines = raw.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
            // Headers run from the second line until the first blank line.
            var headerEnd = 1
            for (i, l) in lines.enumerated() where i >= 1 && l.trimmingCharacters(in: .whitespaces).isEmpty {
                headerEnd = i
                break
            }
            let headers = Array(lines[1..<headerEnd])
            let bodyLines = Array(lines[(headerEnd + 1)..<min(lines.count, headerEnd + 200)])
            let from = Self.extractHeader(from: headers, name: "From")
            let to = Self.extractHeader(from: headers, name: "To")
            let subject = Self.extractHeader(from: headers, name: "Subject")
            let messageID = Self.extractHeader(from: headers, name: "Message-ID")
            let bodyPreview = String(bodyLines.joined(separator: "\n").prefix(32 * 1024))

            let seed = "mail.message_body:\(url.path):\(messageID)"
            let sha = SHA256.hash(data: Data(seed.utf8)).map { String(format: "%02x", $0) }.joined()
            let recordData: [String: JSONValue] = [
                "path": .string(url.path),
                "from": .string(from),
                "to": .string(to),
                "subject": .string(subject),
                "message_id": .string(messageID),
                "body_preview": .string(bodyPreview),
                "body_preview_bytes": .integer(Int64(bodyPreview.utf8.count)),
            ]
            let record = ArtifactRecord(
                caseID: caseContext.caseID,
                pluginID: Self.manifest.id,
                pluginVersion: Self.manifest.version,
                schemaVersion: Self.manifest.schemaVersion,
                contentType: "mail.message_body",
                sourcePath: url.path,
                sha256: sha,
                observedAt: now,
                capturedAt: now,
                summary: "[\(from)] \(subject.isEmpty ? "(no subject)" : subject)",
                sizeBytes: Int64(bodyPreview.utf8.count),
                confidence: .observed,
                privacyClass: .personalComms,
                actor: NSUserName(),
                data: recordData
            )
            do { try await output.commit(record); committed += 1 } catch { rejected += 1 }
        }
        return CollectionResult(artifactsCommitted: committed, artifactsRejected: rejected, notes: ["mail bodies: \(committed) message bodies committed"], status: .ok)
    }

    static func extractHeader(from lines: [String], name: String) -> String {
        for line in lines {
            if line.lowercased().hasPrefix("\(name.lowercased()):") {
                let start = line.index(line.startIndex, offsetBy: name.count + 1)
                return String(line[start...]).trimmingCharacters(in: .whitespaces)
            }
        }
        return ""
    }
}
