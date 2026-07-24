// Phase3SequenceReloadTests.swift
// v1.21.5-rc.3 — locks mother-of-all-audits finding #6: SequenceEngine.loadRules
// is additive and never evicts, so the v1.21.5 deprecated-skip + rule_profile
// gate could not actually turn a previously-loaded sequence OFF on SIGHUP — it
// kept firing until a full restart. reloadRules() clears + last-known-good.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("Phase 3 (6): SequenceEngine.reloadRules evicts; loadRules is additive")
struct SequenceEngineReloadTests {

    private func rule(id: String, status: String) -> SequenceRule {
        SequenceRule(
            id: id, title: "t-\(id)", description: "d", level: .high,
            tags: ["attack.execution"], window: 60,
            correlationType: .processLineage, ordered: true,
            steps: [
                SequenceStep(id: "s1", logsourceCategory: "process_creation",
                             predicates: [Predicate(field: "process.executable",
                                                    modifier: .startswith, values: ["/tmp/"], negate: false)]),
                SequenceStep(id: "s2", logsourceCategory: "file_event",
                             predicates: [Predicate(field: "file.path",
                                                    modifier: .contains, values: ["/x"], negate: false)]),
            ],
            trigger: .allSteps, status: status)
    }

    private func writeRules(_ rules: [SequenceRule], to dir: URL) throws {
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let enc = JSONEncoder()
        for r in rules {
            try enc.encode(r).write(to: dir.appendingPathComponent("\(r.id).json"))
        }
    }

    @Test("reloadRules EVICTS a sequence dropped from the incoming set / profile")
    func reloadEvicts() async throws {
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("seqreload-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: tmp) }
        let dirAll = tmp.appendingPathComponent("all")
        let dirStable = tmp.appendingPathComponent("stable")
        try writeRules([rule(id: "SEQ-EXP", status: "experimental"),
                        rule(id: "SEQ-STABLE", status: "stable")], to: dirAll)
        try writeRules([rule(id: "SEQ-STABLE", status: "stable")], to: dirStable)

        let engine = SequenceEngine(lineage: ProcessLineage())
        _ = try await engine.loadRules(from: dirAll, enabledStatuses: ["experimental", "stable"])
        var ids = Set(await engine.listRules().map(\.id))
        #expect(ids.contains("SEQ-EXP") && ids.contains("SEQ-STABLE"))

        // Tighten to profile "stable" AND reload from a dir without the experimental rule.
        let reloaded = try await engine.reloadRules(from: dirStable, enabledStatuses: ["stable"])
        ids = Set(await engine.listRules().map(\.id))
        #expect(!ids.contains("SEQ-EXP"), "reloadRules must EVICT the experimental sequence (finding #6)")
        #expect(ids.contains("SEQ-STABLE"))
        #expect(reloaded == 1)
    }

    @Test("loadRules is additive — the stale rule PERSISTS (this is exactly why reloadRules exists)")
    func loadRulesIsAdditive() async throws {
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("seqadd-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: tmp) }
        let dirAll = tmp.appendingPathComponent("all")
        let dirStable = tmp.appendingPathComponent("stable")
        try writeRules([rule(id: "SEQ-EXP", status: "experimental"),
                        rule(id: "SEQ-STABLE", status: "stable")], to: dirAll)
        try writeRules([rule(id: "SEQ-STABLE", status: "stable")], to: dirStable)

        let engine = SequenceEngine(lineage: ProcessLineage())
        _ = try await engine.loadRules(from: dirAll, enabledStatuses: ["experimental", "stable"])
        _ = try await engine.loadRules(from: dirStable, enabledStatuses: ["stable"])   // additive re-load
        let ids = Set(await engine.listRules().map(\.id))
        #expect(ids.contains("SEQ-EXP"), "loadRules is additive; the stale experimental sequence survives")
    }

    @Test("reloadRules evicting a rule with IN-FLIGHT partials keeps the partial count exact")
    func reloadEvictsPartialsWithExactAccounting() async throws {
        // rc.3-verify regression: reloadRules must decrement totalPartialCount for
        // evicted rules (like setEnabled), not just drop the dict entry — else the
        // counter inflates and later evicts LIVE partials from surviving rules.
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("seqacct-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: tmp) }
        let dirAll = tmp.appendingPathComponent("all")
        let dirStable = tmp.appendingPathComponent("stable")
        try writeRules([rule(id: "SEQ-EXP", status: "experimental"),
                        rule(id: "SEQ-STABLE", status: "stable")], to: dirAll)
        try writeRules([rule(id: "SEQ-STABLE", status: "stable")], to: dirStable)

        let engine = SequenceEngine(lineage: ProcessLineage())
        _ = try await engine.loadRules(from: dirAll, enabledStatuses: ["experimental", "stable"])
        // Seed in-flight partials for BOTH rules by driving each rule's first step
        // (a /tmp/ process_creation event) — no second step, so they stay partial.
        for pid in Int32(1)...Int32(5) {
            let ev = Event(eventCategory: .process, eventType: .start, eventAction: "exec",
                           process: MacCrabCore.ProcessInfo(
                            pid: pid, ppid: 1, rpid: 1, name: "x", executable: "/tmp/x\(pid)",
                            commandLine: "/tmp/x\(pid)", args: [], workingDirectory: "/tmp",
                            userId: 501, userName: "t", groupId: 20, startTime: Date(),
                            codeSignature: nil, ancestors: [], architecture: "arm64", isPlatformBinary: false))
            _ = await engine.evaluate(ev)
        }
        // Both rules share the same step-1 predicate (/tmp/ exec), so each of the
        // 5 events seeds one partial per rule → 10 total, 5 per rule.
        let seeded = await engine.activePartialMatchCount
        #expect(seeded == 10, "precondition: 5 events × 2 rules = 10 in-flight partials, got \(seeded)")

        // Reload to the stable-only set → SEQ-EXP and its 5 partials are evicted.
        _ = try await engine.reloadRules(from: dirStable, enabledStatuses: ["stable"])
        let after = await engine.activePartialMatchCount
        // With correct accounting only SEQ-STABLE's 5 partials remain. The bug left
        // totalPartialCount at 10 (dict had 5 but the counter wasn't decremented),
        // so `after == seeded` was the regression; it must now be seeded/2.
        #expect(after == 5, "evicted rule's partials must be de-counted, not phantomed (got \(after))")
        #expect(after < seeded)
    }

    @Test("reloadRules retains last-known-good when the incoming dir yields zero rules")
    func reloadEmptyKeepsLastKnownGood() async throws {
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("seqlkg-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: tmp) }
        let dirAll = tmp.appendingPathComponent("all")
        let emptyDir = tmp.appendingPathComponent("empty")
        try writeRules([rule(id: "SEQ-EXP", status: "experimental"),
                        rule(id: "SEQ-STABLE", status: "stable")], to: dirAll)
        try FileManager.default.createDirectory(at: emptyDir, withIntermediateDirectories: true)

        let engine = SequenceEngine(lineage: ProcessLineage())
        _ = try await engine.loadRules(from: dirAll, enabledStatuses: ["experimental", "stable"])
        let n = try await engine.reloadRules(from: emptyDir, enabledStatuses: ["stable"])
        #expect(n == 2, "an empty/corrupt compiled dir must not wipe sequence detection")
        #expect(await engine.listRules().count == 2)
    }
}
