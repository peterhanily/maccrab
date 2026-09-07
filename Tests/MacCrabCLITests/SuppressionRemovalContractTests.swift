import Foundation
import Testing
@testable import MacCrabCore
@testable import maccrabctl

@Suite("Saved suppression removal contracts")
struct SuppressionRemovalContractTests {
    private func directory() throws -> URL {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("maccrab-suppression-contract-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        return root
    }

    @Test("legacy rule-path removal preserves every unrelated path")
    func legacyRemoval() async throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let path = root.appendingPathComponent("suppressions.json")
        try JSONEncoder().encode(["fixture.rule": ["/Applications/One.app", "/Applications/Two.app"],
                                  "fixture.other": ["/Applications/Three.app"]]).write(to: path)
        let removed = try await MacCrabCtl.removeRuleSuppressions(directory: root.path,
            ruleId: "fixture.rule", processPath: "/Applications/One.app")
        #expect(removed == 1)
        let saved = try JSONDecoder().decode([String: [String]].self, from: Data(contentsOf: path))
        #expect(saved["fixture.rule"] == ["/Applications/Two.app"])
        #expect(saved["fixture.other"] == ["/Applications/Three.app"])
    }

    @Test("v2 removal preserves unrelated scope, TTL and reason in private store and readable snapshot")
    func versionTwoRemoval() async throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let manager = SuppressionManager(dataDir: root.path, publishReadableSnapshot: true)
        let removedEntry = Suppression(scope: .rulePath(ruleId: "fixture.rule", path: "/Applications/One.app"),
                                       source: .cli, reason: "Ordinary temporary allowlist")
        let retained = Suppression(createdAt: Date(timeIntervalSince1970: 1000),
            expiresAt: Date(timeIntervalSince1970: 3000), scope: .ruleHash(ruleId: "fixture.rule", sha256: "fixture-hash"),
            source: .ui, reason: "Keep this separate review decision")
        await manager.add(removedEntry)
        await manager.add(retained)
        let removed = try await MacCrabCtl.removeRuleSuppressions(directory: root.path,
            ruleId: "fixture.rule", processPath: "/Applications/One.app")
        #expect(removed == 1)
        let saved = try #require(try SuppressionFile.read(at: root.appendingPathComponent("suppressions.json")))
        let snapshot = try #require(try SuppressionFile.read(at: root.appendingPathComponent("suppressions_snapshot.json")))
        #expect(saved.entries == [retained])
        #expect(snapshot.entries == [retained])
        #expect(snapshot.writtenAt != nil)
    }

    @Test("an unavailable storage directory refuses removal and leaves runtime state unchanged")
    func failedSave() async throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let manager = SuppressionManager(dataDir: root.path, publishReadableSnapshot: true)
        let entry = Suppression(scope: .rule("fixture.rule"), source: .cli, reason: "Ordinary fixture")
        await manager.add(entry)
        // Represents a volume disappearing after the store was loaded.
        try FileManager.default.removeItem(at: root)
        var failed = false
        do { _ = try await manager.removePersisted(ids: [entry.id]) }
        catch { failed = true }
        #expect(failed)
        let current = await manager.list(includeExpired: true)
        let persistError = await manager.lastPersistError
        #expect(current == [entry])
        #expect(persistError != nil)
    }
}
