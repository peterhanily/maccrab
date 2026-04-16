// SuppressionV2Tests.swift
// TTL + scope + audit-log features added in Allowlist v2.
// The v1 behavioral tests live in SuppressionTests.swift and still cover
// the original flat-dict API path.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("Suppression v2")
struct SuppressionV2Tests {

    private func makeTempDir() throws -> String {
        let dir = NSTemporaryDirectory() + "maccrab_supp_v2_\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        return dir
    }

    private func cleanup(_ dir: String) {
        try? FileManager.default.removeItem(atPath: dir)
    }

    private func auditLines(in dir: String) -> [String] {
        let p = dir + "/suppressions_audit.jsonl"
        guard let s = try? String(contentsOfFile: p, encoding: .utf8) else { return [] }
        return s.split(separator: "\n").map(String.init)
    }

    // MARK: - v1 migration

    @Test("v1 flat-dict JSON is migrated to v2 on load")
    func migratesV1() async throws {
        let dir = try makeTempDir()
        defer { cleanup(dir) }

        let v1 = [
            "rule-a": ["/bin/legit1", "/bin/legit2"],
            "rule-b": ["/bin/other"],
        ]
        let data = try JSONEncoder().encode(v1)
        try data.write(to: URL(fileURLWithPath: dir + "/suppressions.json"))

        let mgr = SuppressionManager(dataDir: dir)
        await mgr.load()

        // v1 API still works
        #expect(await mgr.isSuppressed(ruleId: "rule-a", processPath: "/bin/legit1"))
        #expect(await mgr.isSuppressed(ruleId: "rule-b", processPath: "/bin/other"))
        #expect(!(await mgr.isSuppressed(ruleId: "rule-a", processPath: "/bin/not-allowed")))

        // File has been rewritten in v2 schema with "version": 2
        let rewritten = try String(contentsOfFile: dir + "/suppressions.json", encoding: .utf8)
        #expect(rewritten.contains("\"version\" : 2") || rewritten.contains("\"version\":2"))
        #expect(rewritten.contains("\"migration\""))
    }

    // MARK: - Scope types

    @Test("ruleHash scope suppresses when SHA-256 matches, regardless of path")
    func ruleHashScope() async throws {
        let dir = try makeTempDir()
        defer { cleanup(dir) }

        let mgr = SuppressionManager(dataDir: dir)
        await mgr.load()
        _ = await mgr.add(Suppression(
            scope: .ruleHash(ruleId: "rule-x", sha256: "deadbeef00"),
            source: .cli, reason: "known vendor tool"
        ))

        let hit = await mgr.matchingSuppression(
            ruleId: "rule-x",
            processPath: "/weird/relocated/path/tool",
            processSHA256: "deadbeef00",
            hostname: nil
        )
        #expect(hit != nil)

        let miss = await mgr.matchingSuppression(
            ruleId: "rule-x",
            processPath: "/weird/relocated/path/tool",
            processSHA256: "cafebabe00",
            hostname: nil
        )
        #expect(miss == nil)
    }

    @Test("rule-only scope suppresses every process for that rule")
    func ruleOnlyScope() async throws {
        let dir = try makeTempDir()
        defer { cleanup(dir) }

        let mgr = SuppressionManager(dataDir: dir)
        await mgr.load()
        _ = await mgr.add(Suppression(
            scope: .rule("rule-universal"),
            source: .cli, reason: "too noisy — temporarily disabled"
        ))

        #expect(await mgr.isSuppressed(ruleId: "rule-universal", processPath: "/any/path"))
        #expect(await mgr.isSuppressed(ruleId: "rule-universal", processPath: "/other/path"))
        #expect(!(await mgr.isSuppressed(ruleId: "rule-different", processPath: "/any/path")))
    }

    @Test("path scope suppresses alerts from one process across all rules")
    func pathScope() async throws {
        let dir = try makeTempDir()
        defer { cleanup(dir) }

        let mgr = SuppressionManager(dataDir: dir)
        await mgr.load()
        _ = await mgr.add(Suppression(
            scope: .path("/usr/local/bin/vendor-agent"),
            source: .ui, reason: "vendor installer — trusted"
        ))

        #expect(await mgr.isSuppressed(ruleId: "rule-a", processPath: "/usr/local/bin/vendor-agent"))
        #expect(await mgr.isSuppressed(ruleId: "rule-b", processPath: "/usr/local/bin/vendor-agent"))
        #expect(!(await mgr.isSuppressed(ruleId: "rule-a", processPath: "/bin/other")))
    }

    @Test("host scope suppresses alerts from one host across all rules")
    func hostScope() async throws {
        let dir = try makeTempDir()
        defer { cleanup(dir) }

        let mgr = SuppressionManager(dataDir: dir)
        await mgr.load()
        _ = await mgr.add(Suppression(
            scope: .host("build-agent-42"),
            source: .cli, reason: "CI host"
        ))

        let match = await mgr.matchingSuppression(
            ruleId: "any", processPath: "/any",
            processSHA256: nil, hostname: "build-agent-42"
        )
        #expect(match != nil)
    }

    // MARK: - TTL

    @Test("Expired suppression does NOT match")
    func expiredDoesNotMatch() async throws {
        let dir = try makeTempDir()
        defer { cleanup(dir) }

        let mgr = SuppressionManager(dataDir: dir)
        await mgr.load()
        _ = await mgr.add(Suppression(
            expiresAt: Date(timeIntervalSinceNow: -60),  // already expired
            scope: .rulePath(ruleId: "rule-x", path: "/tmp/foo"),
            source: .cli, reason: "ephemeral allow"
        ))

        #expect(!(await mgr.isSuppressed(ruleId: "rule-x", processPath: "/tmp/foo")))
    }

    @Test("Unexpired TTL suppression still matches")
    func unexpiredMatches() async throws {
        let dir = try makeTempDir()
        defer { cleanup(dir) }

        let mgr = SuppressionManager(dataDir: dir)
        await mgr.load()
        _ = await mgr.add(Suppression(
            expiresAt: Date(timeIntervalSinceNow: 3600),
            scope: .rulePath(ruleId: "rule-x", path: "/tmp/foo"),
            source: .cli, reason: "for the next hour"
        ))

        #expect(await mgr.isSuppressed(ruleId: "rule-x", processPath: "/tmp/foo"))
    }

    @Test("sweepExpired removes expired entries and emits audit records")
    func sweepRemovesExpired() async throws {
        let dir = try makeTempDir()
        defer { cleanup(dir) }

        let mgr = SuppressionManager(dataDir: dir)
        await mgr.load()
        _ = await mgr.add(Suppression(
            expiresAt: Date(timeIntervalSinceNow: -60),
            scope: .rule("expired-rule"),
            source: .cli, reason: "stale"
        ))
        _ = await mgr.add(Suppression(
            expiresAt: Date(timeIntervalSinceNow: 3600),
            scope: .rule("fresh-rule"),
            source: .cli, reason: "not stale"
        ))

        let expired = await mgr.sweepExpired()
        #expect(expired.count == 1)

        let list = await mgr.list()
        #expect(list.count == 1)
        #expect(list.first?.reason == "not stale")

        let audit = auditLines(in: dir)
        #expect(audit.contains { $0.contains("\"expire\"") })
    }

    // MARK: - Audit trail

    @Test("add writes an audit line")
    func auditOnAdd() async throws {
        let dir = try makeTempDir()
        defer { cleanup(dir) }

        let mgr = SuppressionManager(dataDir: dir)
        await mgr.load()
        _ = await mgr.add(Suppression(
            scope: .rule("r1"), source: .cli, reason: "test"
        ))

        let audit = auditLines(in: dir)
        #expect(audit.count == 1)
        #expect(audit[0].contains("\"add\""))
        #expect(audit[0].contains("\"r1\""))
        #expect(audit[0].contains("\"cli\""))
    }

    @Test("remove writes an audit line")
    func auditOnRemove() async throws {
        let dir = try makeTempDir()
        defer { cleanup(dir) }

        let mgr = SuppressionManager(dataDir: dir)
        await mgr.load()
        let added = await mgr.add(Suppression(
            scope: .rule("r1"), source: .cli, reason: "test"
        ))
        _ = await mgr.remove(id: added.id)

        let audit = auditLines(in: dir)
        #expect(audit.count == 2)
        #expect(audit[1].contains("\"remove\""))
    }

    // MARK: - Persistence

    @Test("v2 entries round-trip through disk")
    func persistenceRoundTrip() async throws {
        let dir = try makeTempDir()
        defer { cleanup(dir) }

        let mgr1 = SuppressionManager(dataDir: dir)
        await mgr1.load()
        _ = await mgr1.add(Suppression(
            scope: .ruleHash(ruleId: "r1", sha256: "aaaa"),
            source: .ui, reason: "ui-added"
        ))
        _ = await mgr1.add(Suppression(
            expiresAt: Date(timeIntervalSinceNow: 86400),
            scope: .path("/bin/safe"),
            source: .cli, reason: "cli-added"
        ))

        let mgr2 = SuppressionManager(dataDir: dir)
        await mgr2.load()
        let list = await mgr2.list()
        #expect(list.count == 2)
        #expect(list.contains { $0.reason == "ui-added" })
        #expect(list.contains { $0.reason == "cli-added" })
    }

    // MARK: - Stats

    @Test("stats reports total + expired counts")
    func statsCounts() async throws {
        let dir = try makeTempDir()
        defer { cleanup(dir) }

        let mgr = SuppressionManager(dataDir: dir)
        await mgr.load()
        _ = await mgr.add(Suppression(
            scope: .rule("r1"), source: .cli, reason: "live"
        ))
        _ = await mgr.add(Suppression(
            expiresAt: Date(timeIntervalSinceNow: -100),
            scope: .rule("r2"), source: .cli, reason: "expired"
        ))

        let s = await mgr.stats()
        #expect(s.totalEntries == 2)
        #expect(s.expired == 1)
    }
}
