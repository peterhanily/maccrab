// CorrDetectionAuditFixTests.swift
// v1.21.4 — regression tests for the `corr-detection` deep-audit findings
// (deep-audit-findings-2026-07-16.md) on the RULE + SEQUENCE detection engines:
//
//   #274  processLineage correlation was a silent no-op → the 6 processLineage
//         rules with no step-level `process:` relation (incl. the CRITICAL
//         ransomware_kill_chain) fired on wholly unrelated processes.
//   #275  SequenceEngine.resolveField was a drifting hand-copy of
//         RuleEngine.resolveField → aliases only RuleEngine knew silently
//         dead-lettered sequence rules. Both now share ONE resolver.
//   #276  The runtime eval-budget breach counter never decayed/reset → a benign
//         rule auto-disabled under transient load stayed disabled forever, with
//         no self-heal even across a SIGHUP reload.
//   #272  Sequence rules had zero per-rule telemetry → a dead sequence rule was
//         invisible.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("corr-detection audit fixes (v1.21.4)")
struct CorrDetectionAuditFixTests {

    // MARK: - Builders

    private func proc(
        _ exec: String,
        pid: Int32,
        parentName: String = "launchd"
    ) -> MacCrabCore.ProcessInfo {
        MacCrabCore.ProcessInfo(
            pid: pid, ppid: 1, rpid: 1,
            name: (exec as NSString).lastPathComponent,
            executable: exec, commandLine: exec, args: [exec],
            workingDirectory: "/tmp", userId: 501, userName: "t", groupId: 20,
            startTime: Date(), codeSignature: nil,
            ancestors: [ProcessAncestor(pid: 1, executable: "/sbin/launchd", name: parentName)],
            architecture: "arm64", isPlatformBinary: false)
    }

    private func procEvent(_ exec: String, pid: Int32, parentName: String = "launchd") -> Event {
        Event(eventCategory: .process, eventType: .start, eventAction: "exec",
              process: proc(exec, pid: pid, parentName: parentName))
    }

    /// download (`*/curl`) → execute (`/tmp/*`), ordered.
    private func dlExecRule(
        id: String = "seq-corr-test",
        correlation: CorrelationType
    ) -> SequenceRule {
        SequenceRule(
            id: id, title: "Download then Execute (corr test)", description: "test",
            level: .high, tags: ["attack.execution"],
            window: 60, correlationType: correlation, ordered: true,
            steps: [
                SequenceStep(id: "download", logsourceCategory: "process_creation",
                             predicates: [Predicate(field: "Image", modifier: .endswith, values: ["/curl"], negate: false)],
                             condition: .allOf, afterStep: nil, processRelation: nil),
                SequenceStep(id: "execute", logsourceCategory: "process_creation",
                             predicates: [Predicate(field: "Image", modifier: .startswith, values: ["/tmp/"], negate: false)],
                             condition: .allOf, afterStep: "download", processRelation: nil),
            ],
            trigger: .allSteps, enabled: true)
    }

    // MARK: - #274 processLineage now actually enforces lineage

    @Test("#274: processLineage does NOT complete across two unrelated processes")
    func processLineageRejectsUnrelated() async throws {
        let lineage = ProcessLineage()
        // curl at pid 100 (child of shell 50); the second-step process 250 is in
        // an unrelated tree (parent 999) — no ancestry to the bound step.
        await lineage.recordProcess(pid: 50, ppid: 1, path: "/bin/zsh", name: "zsh", startTime: Date())
        await lineage.recordProcess(pid: 100, ppid: 50, path: "/usr/bin/curl", name: "curl", startTime: Date())
        await lineage.recordProcess(pid: 250, ppid: 999, path: "/tmp/payload", name: "payload", startTime: Date())

        let engine = SequenceEngine(lineage: lineage)
        try await engine.addRule(dlExecRule(correlation: .processLineage))

        _ = await engine.evaluate(procEvent("/usr/bin/curl", pid: 100))
        let final = await engine.evaluate(procEvent("/tmp/payload", pid: 250))
        #expect(!final.contains { $0.ruleId == "seq-corr-test" },
                "an execute from an unrelated process tree must NOT complete a processLineage chain")
    }

    @Test("#274: processLineage completes when the second step is a descendant of the first")
    func processLineageAcceptsDescendant() async throws {
        let lineage = ProcessLineage()
        // curl at 100 (child of shell 50); payload 150 is a CHILD of curl.
        await lineage.recordProcess(pid: 50, ppid: 1, path: "/bin/zsh", name: "zsh", startTime: Date())
        await lineage.recordProcess(pid: 100, ppid: 50, path: "/usr/bin/curl", name: "curl", startTime: Date())
        await lineage.recordProcess(pid: 150, ppid: 100, path: "/tmp/payload", name: "payload", startTime: Date())

        let engine = SequenceEngine(lineage: lineage)
        try await engine.addRule(dlExecRule(correlation: .processLineage))

        _ = await engine.evaluate(procEvent("/usr/bin/curl", pid: 100))
        let final = await engine.evaluate(procEvent("/tmp/payload", pid: 150))
        #expect(final.contains { $0.ruleId == "seq-corr-test" },
                "an execute that is a descendant of the download must complete the chain")
    }

    // MARK: - #275 shared resolver: SequenceEngine now knows RuleEngine's aliases

    @Test("#275: a sequence rule resolves ParentName (an alias the drifted copy lacked)")
    func sequenceResolvesSharedAlias() async throws {
        let engine = SequenceEngine(lineage: ProcessLineage())
        // ParentName lived ONLY in RuleEngine.resolveField; the old hand-copied
        // SequenceEngine resolver hit its `default:` enrichments branch and
        // returned nil, so this step could never match. It must now resolve.
        let rule = SequenceRule(
            id: "seq-alias", title: "alias", description: "t", level: .high, tags: [],
            window: 60, correlationType: .none, ordered: false,
            steps: [
                SequenceStep(id: "s1", logsourceCategory: "process_creation",
                             predicates: [Predicate(field: "ParentName", modifier: .endswith, values: ["bash"], negate: false)],
                             condition: .allOf, afterStep: nil, processRelation: nil),
            ],
            trigger: .allSteps, enabled: true)
        try await engine.addRule(rule)

        let matches = await engine.evaluate(procEvent("/tmp/tool", pid: 300, parentName: "bash"))
        #expect(matches.contains { $0.ruleId == "seq-alias" },
                "ParentName must resolve via the shared FieldResolver (dead in the old drifted copy)")
    }

    @Test("#275: RuleEngine and SequenceEngine resolve the same aliases identically")
    func sharedResolverParity() {
        let event = procEvent("/tmp/tool", pid: 301, parentName: "bash")
        // A grab-bag of aliases the drifted SequenceEngine copy did NOT have.
        for field in ["ParentName", "WorkingDirectory", "process.is_platform_binary", "Architecture"] {
            #expect(RuleEngine.resolveField(field, from: event) != nil,
                    "shared resolver should resolve \(field)")
        }
    }

    // MARK: - #276 auto-disable breach counter self-heals

    private func nvramEvent() -> Event {
        let p = MacCrabCore.ProcessInfo(
            pid: 4321, ppid: 1, rpid: 1, name: "nvram",
            executable: "/usr/sbin/nvram",
            commandLine: "nvram boot-args=amfi_get_out_of_my_way=1",
            args: ["/usr/sbin/nvram"], workingDirectory: "/tmp",
            userId: 501, userName: "t", groupId: 20, startTime: Date(),
            codeSignature: nil,
            ancestors: [ProcessAncestor(pid: 1, executable: "/bin/bash", name: "bash")],
            architecture: "arm64", isPlatformBinary: false)
        return Event(eventCategory: .process, eventType: .start, eventAction: "exec", process: p)
    }
    private let nvramRuleId = "d1a2b3c4-0342-4000-a000-000000000342"

    @Test("#276: a clean reload re-enables a runtime-auto-disabled rule (self-heal)")
    func reloadSelfHealsAutoDisabled() async throws {
        ensureRulesCompiled()
        let dir = URL(fileURLWithPath: "/tmp/maccrab_v3")
        // Tiny budget: every eval is over budget; disable after 3 in a row.
        let engine = RuleEngine(slowRuleThresholdNs: 1, autoDisableMaxBreaches: 3)
        _ = try await engine.loadRules(from: dir)

        for _ in 0..<4 { _ = await engine.evaluate(nvramEvent()) }
        #expect(await engine.autoDisabledRules.contains(nvramRuleId),
                "precondition: the rule is auto-disabled by the eval-budget guard")

        _ = try await engine.reloadRules(from: dir)
        #expect(!(await engine.autoDisabledRules.contains(nvramRuleId)),
                "a clean reload must clear the runtime auto-disable (no permanent silencing)")
        #expect(await engine.evaluate(nvramEvent()).contains { $0.ruleId == nvramRuleId },
                "the rule must fire again after the self-healing reload")
    }

    @Test("#276: an operator-disabled rule STILL survives reload (auto vs operator distinction)")
    func operatorDisableSurvivesReload() async throws {
        ensureRulesCompiled()
        let dir = URL(fileURLWithPath: "/tmp/maccrab_v3")
        let engine = RuleEngine()  // default budget — nothing auto-disables
        _ = try await engine.loadRules(from: dir)

        await engine.setEnabled(nvramRuleId, enabled: false)   // explicit operator intent
        _ = try await engine.reloadRules(from: dir)
        #expect(await engine.listRules().first { $0.id == nvramRuleId }?.enabled == false,
                "an operator-disabled rule must stay disabled across reload (not swept up by the auto-disable reset)")
    }

    @Test("#276: an explicit re-enable clears the guard and lets the rule fire again")
    func explicitReenableClearsGuard() async throws {
        ensureRulesCompiled()
        let engine = RuleEngine(slowRuleThresholdNs: 1, autoDisableMaxBreaches: 3)
        _ = try await engine.loadRules(from: URL(fileURLWithPath: "/tmp/maccrab_v3"))

        for _ in 0..<4 { _ = await engine.evaluate(nvramEvent()) }
        #expect(await engine.autoDisabledRules.contains(nvramRuleId))

        await engine.setEnabled(nvramRuleId, enabled: true)
        #expect(!(await engine.autoDisabledRules.contains(nvramRuleId)),
                "explicit re-enable must drop the rule from autoDisabledRules")
        #expect(await engine.evaluate(nvramEvent()).contains { $0.ruleId == nvramRuleId },
                "the rule fires again after an explicit re-enable")
    }

    // MARK: - #272 SequenceEngine per-rule telemetry

    @Test("#272: SequenceEngine telemetry counts evaluations, fires, and activeRuleCount")
    func sequenceTelemetry() async throws {
        let engine = SequenceEngine(lineage: ProcessLineage())
        try await engine.addRule(dlExecRule(id: "seq-telemetry", correlation: .processSame))
        #expect(await engine.activeRuleCount == 1, "one enabled sequence rule")

        _ = await engine.evaluate(procEvent("/usr/bin/curl", pid: 100))     // step1 dispatched
        _ = await engine.evaluate(procEvent("/tmp/payload", pid: 100))      // step2 dispatched + completes

        let stats = await engine.statsSnapshot()
        let s = stats.first { $0.ruleId == "seq-telemetry" }
        #expect(s != nil, "the rule must appear in the telemetry snapshot")
        #expect(s?.evaluationCount == 2, "two process events were dispatched to the rule")
        #expect(s?.fireCount == 1, "the sequence completed exactly once")
        #expect(s?.lastFiredAt != nil, "a completed sequence records a last-fire timestamp")
    }
}
