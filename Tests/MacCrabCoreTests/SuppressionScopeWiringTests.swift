import Foundation
import Testing
@testable import MacCrabCore

/// `maccrabctl allow` writes rule+hash and host entries; the engine's
/// match-aware check must be able to apply them.
@Suite("Hash and host suppression scopes reach the match check")
struct SuppressionScopeWiringTests {
    private func manager() throws -> (SuppressionManager, String) {
        let dir = NSTemporaryDirectory() + "maccrab_supp_scope_\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        return (SuppressionManager(dataDir: dir), dir)
    }

    private let match = RuleMatch(ruleId: "rule.x", ruleName: "X", severity: .high,
                                  description: "", mitreTechniques: [], tags: [])

    @Test("a rule+hash entry applies to the digest and reports its presence")
    func hashScope() async throws {
        let (mgr, dir) = try manager()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let digest = String(repeating: "ab", count: 32)
        #expect(!(await mgr.hasHashScope(ruleId: "rule.x")))
        _ = await mgr.add(Suppression(scope: .ruleHash(ruleId: "rule.x", sha256: digest),
                                      source: .cli, reason: "test"))
        #expect(await mgr.hasHashScope(ruleId: "rule.x"))
        #expect(!(await mgr.hasHashScope(ruleId: "rule.y")))
        #expect(await mgr.isSuppressed(match: match, processPath: "/any", processSHA256: digest))
        #expect(!(await mgr.isSuppressed(match: match, processPath: "/any", processSHA256: nil)))
    }

    @Test("a host entry matches this host's full name or its first label")
    func hostScope() async throws {
        let (mgr, dir) = try manager()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        #expect(!SuppressionManager.localHostName.isEmpty)
        _ = await mgr.add(Suppression(scope: .host("build-mac"), source: .cli, reason: "test"))
        #expect(await mgr.isSuppressed(match: match, processPath: "/p", hostname: "build-mac.local"))
        #expect(await mgr.isSuppressed(match: match, processPath: "/p", hostname: "build-mac"))
        #expect(!(await mgr.isSuppressed(match: match, processPath: "/p", hostname: "other.local")))
        #expect(!(await mgr.isSuppressed(match: match, processPath: "/p", hostname: "")))
    }

    @Test("the hasher serves a cached digest without hashing, and a restored-mtime rewrite misses")
    func hasherCacheIdentity() async throws {
        let path = NSTemporaryDirectory() + "maccrab_hash_\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(atPath: path) }
        try Data(repeating: 0x41, count: 4096).write(to: URL(fileURLWithPath: path))
        let hasher = FileHasher()
        #expect(await hasher.cachedHash(path: path) == nil)
        let original = try #require(await hasher.hash(path: path))
        #expect(await hasher.cachedHash(path: path) == original)

        let mtime = try FileManager.default.attributesOfItem(atPath: path)[.modificationDate] as? Date
        let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: path))
        try handle.write(contentsOf: Data(repeating: 0x42, count: 4096))
        try handle.close()
        try FileManager.default.setAttributes([.modificationDate: try #require(mtime)], ofItemAtPath: path)
        #expect(await hasher.cachedHash(path: path) == nil)
        let rewritten = try #require(await hasher.hash(path: path))
        #expect(rewritten != original)
    }
}
