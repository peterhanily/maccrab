// Phase3SequenceReloadTests.swift
// v1.21.5-rc.3 — locks mother-of-all-audits finding #6: SequenceEngine.loadRules
// is additive and never evicts, so the v1.21.5 deprecated-skip + rule_profile
// gate could not actually turn a previously-loaded sequence OFF on SIGHUP — it
// kept firing until a full restart. reloadRules() clears + last-known-good.

import Testing
import Foundation
import CryptoKit
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

    private func writeManifest(sequenceFiles: [String], above sequenceDir: URL) throws {
        let hashes = Dictionary(uniqueKeysWithValues: sequenceFiles.map { fileName in
            let hash: String
            if let data = try? Data(contentsOf: sequenceDir.appendingPathComponent(fileName)) {
                hash = SHA256.hash(data: data)
                    .map { String(format: "%02x", $0) }
                    .joined()
            } else {
                // A declared-but-missing fixture is rejected by exact inventory
                // before its placeholder hash is consulted.
                hash = String(repeating: "0", count: 64)
            }
            return ("sequences/\(fileName)", hash)
        })
        let data = try JSONSerialization.data(
            withJSONObject: [
                "schema_version": 1,
                "bundle_version": "test",
                "hashes": hashes,
            ],
            options: [.sortedKeys]
        )
        try data.write(to: sequenceDir.deletingLastPathComponent()
            .appendingPathComponent("manifest.json"))
    }

    private func processEvent(_ executable: String, pid: Int32 = 500) -> Event {
        Event(
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: MacCrabCore.ProcessInfo(
                pid: pid, ppid: 1, rpid: 1, name: (executable as NSString).lastPathComponent,
                executable: executable, commandLine: executable, args: [], workingDirectory: "/tmp",
                userId: 501, userName: "test", groupId: 20, startTime: Date(),
                codeSignature: nil, ancestors: [], architecture: "arm64", isPlatformBinary: false
            )
        )
    }

    private func versionedRule(
        id: String,
        seedId: String,
        finishId: String,
        seedExecutable: String,
        finishExecutable: String
    ) -> SequenceRule {
        SequenceRule(
            id: id, title: "versioned-\(id)", description: "reload-state test",
            level: .high, tags: ["attack.execution"], window: 600,
            correlationType: .none, ordered: true,
            steps: [
                SequenceStep(
                    id: seedId, logsourceCategory: "process_creation",
                    predicates: [Predicate(field: "Image", modifier: .endswith,
                                           values: [seedExecutable], negate: false)]
                ),
                SequenceStep(
                    id: finishId, logsourceCategory: "process_creation",
                    predicates: [Predicate(field: "Image", modifier: .endswith,
                                           values: [finishExecutable], negate: false)],
                    afterStep: seedId
                ),
            ],
            trigger: .allSteps, status: "stable"
        )
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

    @Test("reload purges partials when a surviving rule ID changes definition")
    func reloadChangedSameIdCannotCrossComplete() async throws {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("seq-changed-definition-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: tmp) }
        let oldDir = tmp.appendingPathComponent("old")
        let newDir = tmp.appendingPathComponent("new")
        let oldRule = versionedRule(
            id: "SEQ-SAME-ID", seedId: "old-a", finishId: "old-b",
            seedExecutable: "/old-seed", finishExecutable: "/old-finish"
        )
        let newRule = versionedRule(
            id: "SEQ-SAME-ID", seedId: "new-a", finishId: "new-b",
            seedExecutable: "/new-seed", finishExecutable: "/new-finish"
        )
        try writeRules([oldRule], to: oldDir)
        try writeRules([newRule], to: newDir)

        let engine = SequenceEngine(lineage: ProcessLineage())
        _ = try await engine.loadRules(from: oldDir)
        _ = await engine.evaluate(processEvent("/tmp/old-seed"))
        #expect(await engine.activePartialMatchCount == 1)

        _ = try await engine.reloadRules(from: newDir)
        #expect(await engine.activePartialMatchCount == 0,
                "same ID does not make old-definition matched steps compatible")

        let seedResult = await engine.evaluate(processEvent("/tmp/new-seed"))
        #expect(seedResult.isEmpty,
                "old-a + new-a must not satisfy the new two-step allSteps trigger")
        #expect(await engine.activePartialMatchCount == 1)
        let finishResult = await engine.evaluate(processEvent("/tmp/new-finish"))
        #expect(finishResult.count == 1,
                "the new definition must still complete from two fresh events")
    }

    @Test("reload preserves an explicit disable without purging unchanged disabled telemetry")
    func reloadPreservesExplicitDisabledState() async throws {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("seq-disabled-reload-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: tmp) }
        let originalDir = tmp.appendingPathComponent("original")
        let changedDir = tmp.appendingPathComponent("changed")
        let original = versionedRule(
            id: "SEQ-DISABLED", seedId: "seed", finishId: "finish",
            seedExecutable: "/disabled-seed", finishExecutable: "/disabled-finish"
        )
        let changed = versionedRule(
            id: "SEQ-DISABLED", seedId: "new-seed", finishId: "new-finish",
            seedExecutable: "/changed-seed", finishExecutable: "/changed-finish"
        )
        try writeRules([original], to: originalDir)
        try writeRules([changed], to: changedDir)

        let engine = SequenceEngine(lineage: ProcessLineage())
        _ = try await engine.loadRules(from: originalDir)
        _ = await engine.evaluate(processEvent("/tmp/disabled-seed"))
        #expect(await engine.activePartialMatchCount == 1)
        let statsBeforeDisable = await engine.statsSnapshot()
        #expect(statsBeforeDisable.first?.evaluationCount == 1)

        await engine.setEnabled("SEQ-DISABLED", enabled: false)
        #expect(await engine.activePartialMatchCount == 0)
        #expect(await engine.activeRuleCount == 0)

        // An identical reload must project the runtime disable onto the decoded
        // definition BEFORE equality testing. Otherwise enabled=true from disk
        // looks like a definition change and purges otherwise-compatible stats.
        _ = try await engine.reloadRules(from: originalDir)
        #expect(await engine.listRules().first?.enabled == false)
        #expect(await engine.activeRuleCount == 0)
        #expect(await engine.statsSnapshot() == statsBeforeDisable,
                "an unchanged disabled rule must retain its telemetry")

        let disabledSeed = await engine.evaluate(processEvent("/tmp/disabled-seed"))
        let disabledFinish = await engine.evaluate(processEvent("/tmp/disabled-finish"))
        #expect(disabledSeed.isEmpty && disabledFinish.isEmpty)
        #expect(await engine.activePartialMatchCount == 0,
                "SIGHUP must not silently re-enable an operator-disabled sequence")
        #expect(await engine.statsSnapshot() == statsBeforeDisable,
                "disabled events are not evaluations and must not alter stats")

        // Operator state is keyed by surviving rule ID, not definition hash. A
        // content update may reset incompatible runtime state, but must not undo
        // the explicit disable.
        _ = try await engine.reloadRules(from: changedDir)
        #expect(await engine.listRules().first?.enabled == false)
        #expect(await engine.activeRuleCount == 0)
        _ = await engine.evaluate(processEvent("/tmp/changed-seed"))
        _ = await engine.evaluate(processEvent("/tmp/changed-finish"))
        #expect(await engine.activePartialMatchCount == 0)
    }

    @Test("reload purges pending-only state for a removed rule")
    func reloadPurgesPendingWithoutPartialBucket() async throws {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("seq-pending-reload-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: tmp) }
        let oldDir = tmp.appendingPathComponent("old")
        let removedDir = tmp.appendingPathComponent("removed")
        let readdedDir = tmp.appendingPathComponent("readded")
        let target = versionedRule(
            id: "SEQ-PENDING", seedId: "seed", finishId: "finish",
            seedExecutable: "/pending-seed", finishExecutable: "/pending-finish"
        )
        let other = versionedRule(
            id: "SEQ-OTHER", seedId: "other-a", finishId: "other-b",
            seedExecutable: "/other-seed", finishExecutable: "/other-finish"
        )
        try writeRules([target], to: oldDir)
        try writeRules([other], to: removedDir)
        try writeRules([target, other], to: readdedDir)

        let engine = SequenceEngine(lineage: ProcessLineage())
        _ = try await engine.loadRules(from: oldDir)
        let early = await engine.evaluate(processEvent("/tmp/pending-finish"))
        #expect(early.isEmpty)
        #expect(await engine.activePartialMatchCount == 0,
                "a later-first event occupies only pendingLaterSteps")

        _ = try await engine.reloadRules(from: removedDir)
        _ = try await engine.reloadRules(from: readdedDir)

        let seed = await engine.evaluate(processEvent("/tmp/pending-seed"))
        #expect(seed.isEmpty,
                "a pre-removal pending event must not replay after the rule is re-added")
        #expect(await engine.activePartialMatchCount == 1)
        let freshFinish = await engine.evaluate(processEvent("/tmp/pending-finish"))
        #expect(freshFinish.count == 1)
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

    @Test("reload rejects one corrupt file atomically instead of committing N-1")
    func reloadCorruptFileKeepsEveryLastKnownGoodSurface() async throws {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("seq-partial-failure-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: tmp) }
        let oldDir = tmp.appendingPathComponent("old")
        let candidateDir = tmp.appendingPathComponent("candidate")
        let oldA = versionedRule(
            id: "SEQ-OLD-A", seedId: "a1", finishId: "a2",
            seedExecutable: "/old-a-seed", finishExecutable: "/old-a-finish"
        )
        let oldB = versionedRule(
            id: "SEQ-OLD-B", seedId: "b1", finishId: "b2",
            seedExecutable: "/old-b-seed", finishExecutable: "/old-b-finish"
        )
        try writeRules([oldA, oldB], to: oldDir)
        try writeRules([oldA], to: candidateDir)
        try Data("{not-json".utf8).write(
            to: candidateDir.appendingPathComponent("broken.json")
        )

        let engine = SequenceEngine(lineage: ProcessLineage())
        _ = try await engine.loadRules(from: oldDir)
        _ = await engine.evaluate(processEvent("/tmp/old-b-seed"))
        #expect(await engine.activePartialMatchCount == 1)

        await #expect(throws: SequenceEngineError.self) {
            _ = try await engine.reloadRules(from: candidateDir)
        }
        #expect(Set(await engine.listRules().map(\.id)) == ["SEQ-OLD-A", "SEQ-OLD-B"])
        #expect(await engine.activePartialMatchCount == 1,
                "a rejected candidate must not purge last-known-good in-flight state")
    }

    @Test("manifest inventory rejects truncation but an updated manifest permits removal")
    func manifestInventoryDistinguishesTruncationFromIntentionalRemoval() async throws {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("seq-manifest-shrink-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: tmp) }
        let oldDir = tmp.appendingPathComponent("old")
        let releaseRoot = tmp.appendingPathComponent("release")
        let candidateDir = releaseRoot.appendingPathComponent("sequences")
        let keep = versionedRule(
            id: "SEQ-KEEP", seedId: "k1", finishId: "k2",
            seedExecutable: "/keep-seed", finishExecutable: "/keep-finish"
        )
        let remove = versionedRule(
            id: "SEQ-REMOVE", seedId: "r1", finishId: "r2",
            seedExecutable: "/remove-seed", finishExecutable: "/remove-finish"
        )
        try writeRules([keep, remove], to: oldDir)
        try writeRules([keep], to: candidateDir)
        try writeManifest(
            sequenceFiles: ["SEQ-KEEP.json", "SEQ-REMOVE.json"],
            above: candidateDir
        )

        let engine = SequenceEngine(lineage: ProcessLineage())
        _ = try await engine.loadRules(from: oldDir)
        await #expect(throws: SequenceEngineError.self) {
            _ = try await engine.reloadRules(from: candidateDir)
        }
        #expect(await engine.ruleCount == 2,
                "a manifest-declared missing file is a truncated candidate")

        // Updating the producer-owned exact inventory is explicit removal intent;
        // no arbitrary 70% threshold is allowed to veto it.
        try writeManifest(sequenceFiles: ["SEQ-KEEP.json"], above: candidateDir)
        #expect(try await engine.reloadRules(from: candidateDir) == 1)
        #expect(Set(await engine.listRules().map(\.id)) == ["SEQ-KEEP"])

        // A filename-stable mixed generation is also rejected: the staged bytes
        // must match the same explicit manifest generation, not just its names.
        let changedKeep = versionedRule(
            id: "SEQ-KEEP", seedId: "new-k1", finishId: "new-k2",
            seedExecutable: "/changed-seed", finishExecutable: "/changed-finish"
        )
        try writeRules([changedKeep], to: candidateDir)
        await #expect(throws: SequenceEngineError.self) {
            _ = try await engine.reloadRules(from: candidateDir)
        }
        let retained = await engine.listRules().first { $0.id == "SEQ-KEEP" }
        #expect(retained?.steps.first?.id == "k1",
                "hash-rejected bytes must not replace last-known-good")
    }

    @Test("a nonempty corpus intentionally filtered to zero replaces the old profile")
    func intentionalZeroRuleProfileIsNotMistakenForCorruption() async throws {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("seq-zero-profile-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: tmp) }
        let oldDir = tmp.appendingPathComponent("old")
        let releaseRoot = tmp.appendingPathComponent("release")
        let candidateDir = releaseRoot.appendingPathComponent("sequences")
        let stable = versionedRule(
            id: "SEQ-STABLE-ONLY", seedId: "s1", finishId: "s2",
            seedExecutable: "/stable-seed", finishExecutable: "/stable-finish"
        )
        let experimental = rule(id: "SEQ-EXPERIMENTAL-ONLY", status: "experimental")
        try writeRules([stable], to: oldDir)
        try writeRules([experimental], to: candidateDir)
        try writeManifest(
            sequenceFiles: ["SEQ-EXPERIMENTAL-ONLY.json"],
            above: candidateDir
        )

        let engine = SequenceEngine(lineage: ProcessLineage())
        _ = try await engine.loadRules(from: oldDir, enabledStatuses: ["stable"])
        _ = await engine.evaluate(processEvent("/tmp/stable-seed"))
        #expect(await engine.activePartialMatchCount == 1)

        #expect(try await engine.reloadRules(
            from: candidateDir,
            enabledStatuses: ["stable"]
        ) == 0)
        #expect(await engine.ruleCount == 0)
        #expect(await engine.activePartialMatchCount == 0,
                "profile removal must also purge incompatible in-flight state")
    }
}
