import Testing
import Foundation
import CryptoKit
import MacCrabForensics
@testable import MacCrabApp

@Suite("Encrypted review workflow")
struct ReviewWorkflowTests {
    func rows(caseID: String) -> [CommittedArtifact] {
        let plugin = "com.maccrab.forensics.script-trace"
        let payloads: [(String, [String: JSONValue])] = [
            ("script_trace.summary", ["sourceScope": .array([.object(["path": .string("fixture.sh"), "kind": .string("script")])])]),
            ("script_trace.finding", ["path": .string("fixture.sh"), "code": .string("network-send")]),
            ("rave.collection", ["outcome": .string("complete"), "sourceID": .string("source-1")])]
        return payloads.enumerated().map { index, item in
            .init(id: Int64(index + 1), record: .init(caseID: caseID, pluginID: plugin, pluginVersion: "0.1.1", schemaVersion: 1,
                contentType: item.0, sha256: "fixture-\(index)", observedAt: Date(), privacyClass: .content, data: item.1))
        }
    }
    @Test func prepareRequiresSingleCaseAndPreservesCoverage() throws {
        let input = rows(caseID: "fixture")
        let document = try ReviewCaseWorkflow.prepare(input)
        #expect(document.snapshot.facts.count == 1)
        #expect(document.snapshot.gaps.isEmpty)
        #expect(try RaveReviewEngine.compare(document.snapshot, document.snapshot).count == 1)
        #expect(throws: (any Error).self) { try ReviewCaseWorkflow.prepare(input + rows(caseID: "other")) }
        let partial = try ReviewCaseWorkflow.prepare(Array(input.dropLast()))
        #expect(partial.snapshot.gaps.contains("source-coverage-missing"))
    }
    @Test func caseReviewDecisionSurvivesEncryptedCloseAndReopen() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).resolvingSymlinksInPath()
        defer { try? FileManager.default.removeItem(at: root) }
        let manager = CaseManager(casesRoot: root, dekVault: InMemoryDEKVault())
        let handle = try await manager.createCase(name: "Review fixture")
        for row in rows(caseID: handle.caseID) { try await handle.store.commit(row.record) }
        var document = try await ReviewCaseWorkflow.prepare(handle: handle)
        document.decisions = [try .init(document: document, reviewer: "Fixture analyst", disposition: "investigate", note: "Acquire execution evidence.")]
        try await ReviewCaseWorkflow.save(document, handle: handle)
        let reopened = try await manager.openCase(id: handle.caseID)
        let saved = try await reopened.store.query(.init(caseID: reopened.caseID, contentType: ReviewCaseWorkflow.contentType))
        #expect(saved.count == 1)
        let review = try NativeReview(#require(saved.first))
        #expect(review.document.decisions == document.decisions)
        #expect(review.snapshot.facts == document.snapshot.facts)
        #expect(try RaveReviewDocumentIO.digest(review.document) == RaveReviewDocumentIO.digest(document))
        #expect(try review.findings.count == 1)
        // A normal SQLite header and the retained path must not be visible in
        // the encrypted main database or its WAL.
        for suffix in ["", "-wal"] {
            let url = URL(fileURLWithPath: handle.layout.sqliteFile.path + suffix)
            if let data = try? Data(contentsOf: url) {
                #expect(!data.starts(with: Data("SQLite format 3".utf8)))
                #expect(data.range(of: Data("fixture.sh".utf8)) == nil)
                #expect(data.range(of: Data("Fixture analyst".utf8)) == nil)
            }
        }
        let exported = root.appendingPathComponent("review.json")
        try ReviewFileIO.write(RaveReviewDocumentIO.encode(document), to: exported)
        let imported = try RaveReviewDocumentIO.decode(ReviewFileIO.read(exported))
        #expect(imported.decisions == document.decisions)
    }
    @Test func plaintextCaseCannotSaveReview() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).resolvingSymlinksInPath()
        defer { try? FileManager.default.removeItem(at: root) }
        let manager = CaseManager(casesRoot: root, dekVault: InMemoryDEKVault())
        let handle = try await manager.createCase(name: "Plain fixture", encrypted: false)
        let document = try ReviewCaseWorkflow.prepare(rows(caseID: handle.caseID))
        await #expect(throws: (any Error).self) { try await ReviewCaseWorkflow.save(document, handle: handle) }
        #expect(try await handle.store.count(caseID: handle.caseID) == 0)
    }
    @Test func reviewExportRefusesLinkedParentDirectory() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let real = root.appendingPathComponent("real"), link = root.appendingPathComponent("link")
        try FileManager.default.createDirectory(at: real, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: real)
        try Data("fixture".utf8).write(to: real.appendingPathComponent("review.json"))
        #expect(throws: (any Error).self) { try ReviewFileIO.read(link.appendingPathComponent("review.json")) }
        #expect(throws: (any Error).self) { try ReviewFileIO.write(Data(), to: link.appendingPathComponent("review.json")) }
    }
    @Test func importedReviewCannotMasqueradeAsAnotherPlugin() throws {
        let document = try ReviewCaseWorkflow.prepare(rows(caseID: "fixture"))
        let raw = try JSONDecoder().decode(JSONValue.self, from: RaveReviewDocumentIO.encode(document))
        let artifact = CommittedArtifact(id: 1, record: .init(caseID: "fixture", pluginID: "com.maccrab.forensics.trust-delta",
            pluginVersion: "0.2.0", schemaVersion: 1, contentType: "trust_delta.review", sha256: "fixture", observedAt: Date(),
            privacyClass: .content, data: ["document": raw]))
        #expect(throws: (any Error).self) { try NativeReview(artifact) }
    }
}
