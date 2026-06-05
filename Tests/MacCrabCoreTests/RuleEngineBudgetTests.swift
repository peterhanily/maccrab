// RuleEngineBudgetTests.swift
// v1.18 — the eval-budget guard that auto-disables a rule whose regex stalls
// the serial event loop (ReDoS / catastrophic backtracking). Previously such
// rules were only logged. Uses an injectable tiny budget so the mechanism is
// deterministic without an actual multi-second regex stall.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("RuleEngine: eval-budget auto-disable (v1.18)")
struct RuleEngineBudgetTests {

    private func nvramEvent() -> Event {
        let proc = MacCrabCore.ProcessInfo(
            pid: 4321, ppid: 1, rpid: 1, name: "nvram",
            executable: "/usr/sbin/nvram",
            commandLine: "nvram boot-args=amfi_get_out_of_my_way=1",
            args: ["/usr/sbin/nvram"], workingDirectory: "/tmp",
            userId: 501, userName: "t", groupId: 20, startTime: Date(),
            codeSignature: nil,
            ancestors: [ProcessAncestor(pid: 1, executable: "/bin/bash", name: "bash")],
            architecture: "arm64", isPlatformBinary: false)
        return Event(eventCategory: .process, eventType: .start, eventAction: "exec", process: proc)
    }

    @Test("shouldAutoDisable trips on a single pathological eval OR persistent breaches")
    func decision() async {
        let e = RuleEngine(autoDisablePathologicalNs: 1_000_000_000, autoDisableMaxBreaches: 5)
        #expect(await e.shouldAutoDisable(elapsedNs: 2_000_000_000, breaches: 1) == true)   // one catastrophic eval
        #expect(await e.shouldAutoDisable(elapsedNs: 1_000, breaches: 5) == true)            // persistent over-budget
        #expect(await e.shouldAutoDisable(elapsedNs: 1_000, breaches: 4) == false)           // below both
    }

    @Test("a rule that repeatedly blows the eval budget is auto-disabled and stops firing")
    func autoDisableStopsFiring() async throws {
        ensureRulesCompiled()
        // Tiny budget: every eval is "over budget"; disable after 3 of them.
        let engine = RuleEngine(slowRuleThresholdNs: 1, autoDisableMaxBreaches: 3)
        _ = try await engine.loadRules(from: URL(fileURLWithPath: "/tmp/maccrab_v3"))
        let before = await engine.ruleCount
        let nvram = "d1a2b3c4-0342-4000-a000-000000000342"

        // First eval: the rule is still enabled and fires.
        #expect(await engine.evaluate(nvramEvent()).contains { $0.ruleId == nvram })

        // Drive it past the breach threshold.
        for _ in 0..<3 { _ = await engine.evaluate(nvramEvent()) }

        #expect(await engine.autoDisabledRules.contains(nvram),
                "the rule should be auto-disabled after repeated over-budget evals")
        #expect(!(await engine.evaluate(nvramEvent()).contains { $0.ruleId == nvram }),
                "an auto-disabled rule must no longer fire (stops stalling ingest)")
        #expect(await engine.ruleCount == before, "auto-disable must not REMOVE the rule")
    }

    @Test("rules under budget are never auto-disabled")
    func underBudgetSurvives() async throws {
        ensureRulesCompiled()
        // Default 50ms budget — normal evals are microseconds, never over budget.
        let engine = RuleEngine()
        _ = try await engine.loadRules(from: URL(fileURLWithPath: "/tmp/maccrab_v3"))
        for _ in 0..<5 { _ = await engine.evaluate(nvramEvent()) }
        #expect(await engine.autoDisabledRules.isEmpty, "fast rules must never be auto-disabled")
        #expect(await engine.evaluate(nvramEvent()).contains { $0.ruleId == "d1a2b3c4-0342-4000-a000-000000000342" })
    }
}
