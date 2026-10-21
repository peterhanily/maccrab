import Foundation
import Testing
@testable import MacCrabCore
@testable import maccrabctl

/// `maccrabctl allow` must never present a refused read as an empty
/// allowlist, must remove entries through the engine, and must store hash
/// entries in the form the engine matches.
@Suite("Allowlist CLI")
struct AllowCommandTests {
    private func directory() throws -> URL {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("maccrab-allow-cli-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        return root
    }

    private func save(_ entries: [Suppression], to url: URL) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        try encoder.encode(SuppressionFile(entries: entries)).write(to: url)
    }

    @Test("a store this user cannot read is an error, or the engine's snapshot, never an empty list",
          .enabled(if: geteuid() != 0, "root reads a mode-000 file"))
    func refusedReadIsNotEmpty() async throws {
        let root = try directory()
        defer {
            try? FileManager.default.setAttributes([.posixPermissions: 0o600],
                                                   ofItemAtPath: root.appendingPathComponent("suppressions.json").path)
            try? FileManager.default.removeItem(at: root)
        }
        let entry = Suppression(scope: .host("build-mac"), source: .cli, reason: "Fixture")
        let store = root.appendingPathComponent("suppressions.json")
        try save([entry], to: store)
        try FileManager.default.setAttributes([.posixPermissions: 0o000], ofItemAtPath: store.path)
        guard case .unreadable(let path, _) = await MacCrabCtl.readAllowlist(dataDir: root.path) else {
            Issue.record("a refused read was reported as entries")
            return
        }
        #expect(path == store.path)
        // The engine publishes an admin-readable snapshot after every change.
        try save([entry], to: root.appendingPathComponent("suppressions_snapshot.json"))
        guard case .entries(let entries, let fromSnapshot) = await MacCrabCtl.readAllowlist(dataDir: root.path) else {
            Issue.record("the published snapshot was not read")
            return
        }
        #expect(fromSnapshot)
        #expect(entries.map(\.id) == [entry.id])
    }

    @Test("a readable store, or none yet, is read directly")
    func readableStore() async throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        guard case .entries(let none, false) = await MacCrabCtl.readAllowlist(dataDir: root.path) else {
            Issue.record("a missing store is not an error")
            return
        }
        #expect(none.isEmpty)
        let entry = Suppression(scope: .rule("fixture.rule"), source: .cli, reason: "Fixture")
        try save([entry], to: root.appendingPathComponent("suppressions.json"))
        guard case .entries(let entries, false) = await MacCrabCtl.readAllowlist(dataDir: root.path) else {
            Issue.record("a readable store was not read directly")
            return
        }
        #expect(entries.map(\.id) == [entry.id])
    }

    @Test("allow remove queues the engine's remove-suppression request for the exact id")
    func removalGoesThroughTheEngine() throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let inbox = root.appendingPathComponent("inbox").path
        let id = UUID().uuidString
        let request = try MacCrabCtl.submitAllowRemoval(id: id, dataDir: root.path, inboxDirectory: inbox)
        let name = "remove-suppression-\(request.uuidString).json"
        #expect(RuntimeConfigurationFiles.requestID(filename: name, operation: "remove-suppression") == request)
        let data = try Data(contentsOf: URL(fileURLWithPath: inbox).appendingPathComponent(name))
        let payload = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(payload["id"] as? String == id)
        // The store is left to the engine, which removes from memory and file together.
        #expect(!FileManager.default.fileExists(atPath: root.appendingPathComponent("suppressions.json").path))
        let source = try String(contentsOf: URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/maccrabctl/AllowCommand.swift"), encoding: .utf8)
        let remove = try #require(source.range(of: "private static func allowRemove(args: [String]) async {"))
        let body = source[remove.lowerBound...].prefix(3_000)
        #expect(body.contains("submitAllowRemoval("))
        #expect(!body.contains("removePersisted("))
        // Under sudo the request must reach the root-only inbox.
        #expect(body.contains("inboxDirectory: requestInboxDirectory(dataDir: dataDir)"))
    }

    @Test("status, allow stats and suppression list read the allowlist as allow list does")
    func readoutsUseTheSharedRead() throws {
        let sources = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/maccrabctl")
        func body(_ file: String, after signature: String, length: Int = 1_500) throws -> Substring {
            let source = try String(contentsOf: sources.appendingPathComponent(file), encoding: .utf8)
            let start = try #require(source.range(of: signature), "\(signature) in \(file)")
            return source[start.lowerBound...].prefix(length)
        }
        let status = try body("StatusCommand.swift", after: "static func showStatus() async {", length: 40_000)
        #expect(status.contains("allowlistStatusLine(dataDir:"))
        let stats = try body("AllowCommand.swift", after: "private static func allowStats() async {")
        #expect(stats.contains("switch await readAllowlist("))
        let list = try body("AlertCommands.swift", after: "static func listSuppressions() {")
        let denied = try #require(list.range(of: "suppressionStoreAccessDenied("))
        let empty = try #require(list.range(of: "No suppressions configured."))
        #expect(denied.lowerBound < empty.lowerBound, "the refused read is checked before the empty message")
    }

    @Test("--hash takes a 64-character hex digest in either case and stores lowercase")
    func hashValidation() {
        let upper = String(repeating: "AB", count: 32)
        #expect(MacCrabCtl.normalizedSHA256(upper) == upper.lowercased())
        #expect(MacCrabCtl.normalizedSHA256(String(upper.prefix(63))) == nil)
        #expect(MacCrabCtl.normalizedSHA256(String(repeating: "g", count: 64)) == nil)
        #expect(MacCrabCtl.normalizedSHA256(String(upper.prefix(12))) == nil)
        // Fullwidth hex digits pass Character.isHexDigit but never match.
        #expect(MacCrabCtl.normalizedSHA256(String(repeating: "\u{FF21}\u{FF22}", count: 32)) == nil)
    }

    @Test("status and stats read the allowlist as list does",
          .enabled(if: geteuid() != 0, "root reads a mode-000 file"))
    func statusAndStatsReadLikeList() async throws {
        let root = try directory()
        let store = root.appendingPathComponent("suppressions.json")
        defer {
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: store.path)
            try? FileManager.default.removeItem(at: root)
        }
        #expect(await MacCrabCtl.allowlistStatusLine(dataDir: root.path) == "Suppressions:    None configured")
        let entries = [
            Suppression(scope: .rulePath(ruleId: "r1", path: "/a"), source: .cli, reason: "Fixture"),
            Suppression(scope: .rulePath(ruleId: "r1", path: "/b"), source: .cli, reason: "Fixture"),
            Suppression(scope: .path("/c"), source: .cli, reason: "Fixture"),
            Suppression(scope: .host("build-mac"), source: .cli, reason: "Fixture"),
        ]
        try save(entries, to: store)
        // The counters match the manager's own.
        let manager = SuppressionManager(dataDir: root.path)
        await manager.load()
        let counted = MacCrabCtl.allowlistStats(entries)
        let managed = await manager.stats()
        #expect(counted.ruleCount == managed.ruleCount && counted.pathCount == managed.pathCount
            && counted.totalEntries == managed.totalEntries && counted.expired == managed.expired)
        try FileManager.default.setAttributes([.posixPermissions: 0o000], ofItemAtPath: store.path)
        let refused = await MacCrabCtl.allowlistStatusLine(dataDir: root.path)
        #expect(refused.contains("needs sudo"), "\(refused)")
        #expect(MacCrabCtl.suppressionStoreAccessDenied(store.path))
        #expect(!MacCrabCtl.suppressionStoreAccessDenied(root.appendingPathComponent("missing.json").path))
        try save(entries, to: root.appendingPathComponent("suppressions_snapshot.json"))
        let snapshot = await MacCrabCtl.allowlistStatusLine(dataDir: root.path)
        #expect(snapshot.contains("4 allowlist entry(ies) (engine snapshot)"), "\(snapshot)")
    }

    @Test("allow add never saves over a store it could not read",
          .enabled(if: geteuid() != 0, "root reads a mode-000 file"))
    func addNeverOverwritesAnUnreadableStore() async throws {
        let root = try directory()
        let store = root.appendingPathComponent("suppressions.json")
        defer {
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: store.path)
            try? FileManager.default.removeItem(at: root)
        }
        try save([Suppression(scope: .rule("kept.one"), source: .cli, reason: "Fixture"),
                  Suppression(scope: .rule("kept.two"), source: .cli, reason: "Fixture")], to: store)
        let before = try Data(contentsOf: store)
        try FileManager.default.setAttributes([.posixPermissions: 0o000], ofItemAtPath: store.path)
        let outcome = await MacCrabCtl.addAllowlistEntry(
            Suppression(scope: .rule("new.one"), source: .cli, reason: "Fixture"), dataDir: root.path)
        guard case .unreadable(_, .inaccessible) = outcome else {
            Issue.record("an unreadable store was saved over: \(outcome)")
            return
        }
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: store.path)
        #expect(try Data(contentsOf: store) == before)
    }

    @Test("a corrupt store reports its reason and never falls back to the snapshot")
    func corruptStoreIsNotReplacedBySnapshot() async throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        try Data("not an allowlist".utf8).write(to: root.appendingPathComponent("suppressions.json"))
        try save([Suppression(scope: .rule("stale.one"), source: .cli, reason: "Fixture")],
                 to: root.appendingPathComponent("suppressions_snapshot.json"))
        guard case .unreadable(_, .undecodable) = await MacCrabCtl.readAllowlist(dataDir: root.path) else {
            Issue.record("a corrupt store was not reported as such")
            return
        }
    }

    @Test("a rule+hash entry matches the event digest whatever case either side was written in")
    func hashMatchingIgnoresCase() async {
        let manager = SuppressionManager(dataDir: FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-allow-hash-\(UUID().uuidString)").path)
        let lower = String(repeating: "ab", count: 32)
        await manager.add(Suppression(scope: .ruleHash(ruleId: "fixture.rule", sha256: lower.uppercased()),
                                      source: .cli, reason: "Typed in uppercase"))
        let matched = await manager.matchingSuppression(ruleId: "fixture.rule", processPath: nil,
                                                        processSHA256: lower, hostname: nil)
        #expect(matched != nil)
        // And an entry saved in lowercase matches a digest reported in uppercase.
        await manager.add(Suppression(scope: .ruleHash(ruleId: "second.rule", sha256: lower),
                                      source: .cli, reason: "Typed in lowercase"))
        let upperEvent = await manager.matchingSuppression(ruleId: "second.rule", processPath: nil,
                                                           processSHA256: lower.uppercased(), hostname: nil)
        #expect(upperEvent != nil)
        let mismatched = await manager.matchingSuppression(ruleId: "other.rule", processPath: nil,
                                                           processSHA256: lower, hostname: nil)
        #expect(mismatched == nil)
    }
}
