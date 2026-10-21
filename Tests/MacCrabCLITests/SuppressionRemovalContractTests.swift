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
        let removal = try await MacCrabCtl.removeRuleSuppressions(directory: root.path,
            ruleId: "fixture.rule", processPath: "/Applications/One.app",
            inboxDirectory: root.appendingPathComponent("inbox").path)
        guard case .savedLegacy(1) = removal else {
            Issue.record("a v1 store is edited in place: \(removal)")
            return
        }
        let saved = try JSONDecoder().decode([String: [String]].self, from: Data(contentsOf: path))
        #expect(saved["fixture.rule"] == ["/Applications/Two.app"])
        #expect(saved["fixture.other"] == ["/Applications/Three.app"])
    }

    @Test("v2 removal asks the engine for each matching entry and leaves the store to it")
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
        let inbox = root.appendingPathComponent("inbox")
        let removal = try await MacCrabCtl.removeRuleSuppressions(directory: root.path,
            ruleId: "fixture.rule", processPath: "/Applications/One.app", inboxDirectory: inbox.path)
        guard case let .requested(requests) = removal else {
            Issue.record("a v2 removal goes through the engine: \(removal)")
            return
        }
        // Only the rule-path entry matches; the engine removes it from memory
        // and file together, so the CLI writes neither.
        #expect(requests.map(\.id) == [removedEntry.id])
        let name = try #require(requests.first.map { "remove-suppression-\($0.request.uuidString).json" })
        let payload = try #require(try JSONSerialization.jsonObject(
            with: Data(contentsOf: inbox.appendingPathComponent(name))) as? [String: Any])
        #expect(payload["id"] as? String == removedEntry.id)
        let saved = try #require(try SuppressionFile.read(at: root.appendingPathComponent("suppressions.json")))
        #expect(Set(saved.entries.map(\.id)) == [removedEntry.id, retained.id])
    }

    @Test("rules unsuppress reaches the root-only inbox under sudo")
    func unsuppressUsesTheRequestInbox() throws {
        let source = try String(contentsOf: URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/maccrabctl/AlertCommands.swift"), encoding: .utf8)
        let start = try #require(source.range(of: "static func unsuppressRule(ruleId: String, processPath: String?) async {"))
        let body = source[start.lowerBound...].prefix(2_000)
        #expect(body.contains("inboxDirectory: requestInboxDirectory(dataDir: dataDir)"))
        #expect(!body.contains("removePersisted("))
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
