import Foundation
import MacCrabForensics

/// Uses the existing encrypted artifact store. No intermediate plaintext
/// export, additional database, or background collector is created.
enum ReviewCaseWorkflow {
    static let pluginID = "com.maccrab.host.review"
    static let contentType = "rave.review.saved"
    static let supported: Set<String> = ["com.maccrab.forensics.script-trace", "com.maccrab.forensics.repo-tripwire",
        "com.maccrab.forensics.secret-trail", "com.maccrab.forensics.clickfix-review"]

    static func prepare(_ artifacts: [CommittedArtifact]) throws -> RaveReviewDocument {
        guard !artifacts.isEmpty, artifacts.count <= 5000,
              Set(artifacts.map { $0.record.caseID }).count == 1 else { throw RaveReviewError.invalid }
        let selected = artifacts.filter { supported.contains($0.record.pluginID) }
        let groups = Dictionary(grouping: selected, by: { $0.record.pluginID })
        guard !groups.isEmpty, groups.count <= 8 else { throw RaveReviewError.unsupported }
        let snapshots = try groups.keys.sorted().map { plugin -> RaveSnapshot in
            let group = groups[plugin]!
            guard Set(group.map { $0.record.pluginVersion }).count == 1,
                  group.allSatisfy({ $0.record.schemaVersion == 1 }) else { throw RaveReviewError.incompatible }
            let rows: [[String: Any]] = group.map { ["contentType": $0.record.contentType,
                "data": $0.record.data.mapValues(\.foundationValue)] }
            let coverage = rows.filter { $0["contentType"] as? String == "rave.collection" }.compactMap { $0["data"] }
            let report: [String: Any] = ["schemaVersion": 1, "pluginID": plugin,
                "pluginVersion": group[0].record.pluginVersion, "coverage": coverage, "artifacts": rows]
            return try RaveReviewImport.decode(JSONSerialization.data(withJSONObject: report))
        }
        var snapshot = try RaveReviewImport.combine(snapshots)
        if selected.count < artifacts.count {
            snapshot.gaps.append("Other case records are outside the supported review adapters.")
            snapshot = try RaveReviewEngine.assess(snapshot)
        }
        let document = RaveReviewDocument(mode: "investigate", snapshot: snapshot)
        try RaveReviewDocumentIO.validate(document)
        return document
    }
    static func prepare(handle: CaseHandle) async throws -> RaveReviewDocument {
        guard handle.encryptionState != .plaintext else { throw RaveReviewError.invalid }
        let rows = try await handle.store.query(.init(caseID: handle.caseID, limit: 5001))
        guard rows.count <= 5000 else { throw RaveReviewError.oversized }
        // Earlier saved reviews are annotations, not new acquisition evidence.
        return try prepare(rows.filter { $0.record.contentType != contentType })
    }
    @discardableResult static func save(_ document: RaveReviewDocument, handle: CaseHandle) async throws -> CommittedArtifact {
        guard handle.encryptionState != .plaintext else { throw RaveReviewError.invalid }
        let bytes = try RaveReviewDocumentIO.encode(document)
        let data = try JSONDecoder().decode([String: JSONValue].self, from: bytes)
        let record = ArtifactRecord(caseID: handle.caseID, pluginID: pluginID, pluginVersion: "1.0.0", schemaVersion: 1,
            contentType: contentType, sha256: RaveReviewDocumentIO.sha256(bytes), observedAt: Date(),
            summary: "Saved review · \(document.mode) · \(document.decisions.count) operator notes",
            sizeBytes: Int64(bytes.count), confidence: .derived, privacyClass: document.requiresCredentialPrivacy ? .credentialAdjacent : .content, data: data)
        let id = try await handle.store.commit(record)
        return .init(id: id, record: record)
    }
}
