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

    @Test("a rule+hash entry applies to the digest")
    func hashScope() async throws {
        let (mgr, dir) = try manager()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let digest = String(repeating: "ab", count: 32)
        _ = await mgr.add(Suppression(scope: .ruleHash(ruleId: "rule.x", sha256: digest),
                                      source: .cli, reason: "test"))
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

    @Test("a same-size rewrite with a restored mtime is hashed again, not served from the cache")
    func hasherCacheIdentity() async throws {
        let path = NSTemporaryDirectory() + "maccrab_hash_\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(atPath: path) }
        try Data(repeating: 0x41, count: 4096).write(to: URL(fileURLWithPath: path))
        let hasher = FileHasher()
        let original = try #require(await hasher.hash(path: path))

        let mtime = try FileManager.default.attributesOfItem(atPath: path)[.modificationDate] as? Date
        let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: path))
        try handle.write(contentsOf: Data(repeating: 0x42, count: 4096))
        try handle.close()
        try FileManager.default.setAttributes([.modificationDate: try #require(mtime)], ofItemAtPath: path)
        let rewritten = try #require(await hasher.hash(path: path))
        #expect(rewritten != original)
    }
}
