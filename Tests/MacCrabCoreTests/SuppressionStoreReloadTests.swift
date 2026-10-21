import Foundation
import Testing
@testable import MacCrabCore

/// The engine removes allowlist entries against the saved store, which
/// `maccrabctl allow add` writes behind its back, and keeps every remaining
/// entry indexed when a case twin or a duplicate leaves.
@Suite("Suppression store reload and index removal")
struct SuppressionStoreReloadTests {
    private func directory() throws -> String {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("maccrab-suppression-reload-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        return root.path
    }

    @Test("a removal through the engine keeps, and can remove, entries the CLI saved since the last reload")
    func reloadBeforeRemoval() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let engine = SuppressionManager(dataDir: dir)
        let old = Suppression(scope: .rule("old.rule"), source: .cli, reason: "Fixture")
        await engine.add(old)
        // maccrabctl allow add, in another process.
        let cli = SuppressionManager(dataDir: dir)
        await cli.load()
        let added = Suppression(scope: .rule("added.rule"), source: .cli, reason: "Fixture")
        await cli.add(added)

        let removed = try await engine.reloadAndRemovePersisted(ids: [old.id])
        #expect(removed.map(\.id) == [old.id])
        let reread = SuppressionManager(dataDir: dir)
        await reread.load()
        #expect(await reread.list(includeExpired: true).map(\.id) == [added.id])
        // And the entry the engine had never loaded can be removed.
        #expect(try await engine.reloadAndRemovePersisted(ids: [added.id]).map(\.id) == [added.id])
    }

    @Test("the engine's TTL sweep keeps entries the CLI saved since the last reload")
    func sweepKeepsCLIAdditions() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let engine = SuppressionManager(dataDir: dir)
        let expiring = Suppression(createdAt: Date(timeIntervalSince1970: 1000),
                                   expiresAt: Date(timeIntervalSince1970: 2000),
                                   scope: .rule("expiring.rule"), source: .cli, reason: "Fixture")
        await engine.add(expiring)
        let cli = SuppressionManager(dataDir: dir)
        await cli.load()
        let added = Suppression(scope: .rule("added.rule"), source: .cli, reason: "Fixture")
        await cli.add(added)

        let swept = await engine.reloadAndSweepExpired(now: Date(timeIntervalSince1970: 3000))
        #expect(swept.map(\.id) == [expiring.id])
        let reread = SuppressionManager(dataDir: dir)
        await reread.load()
        #expect(await reread.list(includeExpired: true).map(\.id) == [added.id])
        // The CLI's entry is in force in the engine from then on.
        #expect(await engine.matchingSuppression(ruleId: "added.rule", processPath: nil,
                                                 processSHA256: nil, hostname: nil) != nil)
        // Nothing expired: no reload, nothing written.
        #expect(await engine.reloadAndSweepExpired(now: Date(timeIntervalSince1970: 3000)).isEmpty)
    }

    @Test("a sweep over a store that cannot be read leaves it alone")
    func sweepSkipsAnUnreadableStore() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let engine = SuppressionManager(dataDir: dir)
        await engine.add(Suppression(createdAt: Date(timeIntervalSince1970: 1000),
                                     expiresAt: Date(timeIntervalSince1970: 2000),
                                     scope: .rule("expiring.rule"), source: .cli, reason: "Fixture"))
        try Data("corrupt".utf8).write(to: URL(fileURLWithPath: dir + "/suppressions.json"))
        #expect(await engine.reloadAndSweepExpired(now: Date(timeIntervalSince1970: 3000)).isEmpty)
        #expect(try String(contentsOfFile: dir + "/suppressions.json", encoding: .utf8) == "corrupt")
    }

    @Test("a store that cannot be decoded removes nothing")
    func undecodableStoreRemovesNothing() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let engine = SuppressionManager(dataDir: dir)
        let entry = Suppression(scope: .rule("kept.rule"), source: .cli, reason: "Fixture")
        await engine.add(entry)
        try Data("corrupt".utf8).write(to: URL(fileURLWithPath: dir + "/suppressions.json"))
        await #expect(throws: (any Error).self) {
            try await engine.reloadAndRemovePersisted(ids: [entry.id])
        }
        #expect(try String(contentsOfFile: dir + "/suppressions.json", encoding: .utf8) == "corrupt")
    }

    @Test("removing one of two case twins or duplicates keeps the other matching")
    func twinsKeepTheirIndex() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let manager = SuppressionManager(dataDir: dir)
        let digest = String(repeating: "ab", count: 32)
        let upper = Suppression(scope: .ruleHash(ruleId: "hash.rule", sha256: digest.uppercased()), source: .cli, reason: "Upper")
        let lower = Suppression(scope: .ruleHash(ruleId: "hash.rule", sha256: digest), source: .cli, reason: "Lower")
        await manager.add(upper)
        await manager.add(lower)
        await manager.remove(id: upper.id)
        #expect(await manager.matchingSuppression(ruleId: "hash.rule", processPath: nil,
                                                  processSHA256: digest, hostname: nil) != nil)
        let first = Suppression(scope: .rulePath(ruleId: "path.rule", path: "/opt/tool"), source: .cli, reason: "First")
        let second = Suppression(scope: .rulePath(ruleId: "path.rule", path: "/opt/tool"), source: .cli, reason: "Second")
        await manager.add(first)
        await manager.add(second)
        await manager.remove(id: first.id)
        #expect(await manager.matchingSuppression(ruleId: "path.rule", processPath: "/opt/tool",
                                                  processSHA256: nil, hostname: nil) != nil)
    }

    @Test("the engine's remove-suppression handler reloads the saved store first")
    func engineHandlerReloads() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let source = try String(contentsOf: root.appendingPathComponent("Sources/MacCrabAgentKit/DaemonTimers.swift"),
                                encoding: .utf8)
        let handler = try #require(source.range(of: "private static func handleRemoveSuppressionRequests("))
        let body = source[handler.lowerBound...].prefix(4_000)
        #expect(body.contains("suppressionManager.reloadAndRemovePersisted(ids: [id])"))
        #expect(!body.contains("suppressionManager.removePersisted("))
        // The maintenance sweep saves against the saved store too.
        #expect(source.contains("await state.suppressionManager.reloadAndSweepExpired()"))
        #expect(!source.contains("state.suppressionManager.sweepExpired("))
    }
}
