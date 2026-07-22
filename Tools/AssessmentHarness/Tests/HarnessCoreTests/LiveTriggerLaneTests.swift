// LiveTriggerLaneTests.swift
// assessment-framework (P5): the safety core — the disposable-host guard must
// fail closed, and the live lane must refuse anywhere it is not explicitly safe.

import Testing
import Foundation
@testable import HarnessCore

@Suite("Assessment P5: live-trigger safety guard")
struct LiveTriggerLaneTests {

    private func inputs(disposable: Bool, sysext: Bool, dataDir: Bool) -> DisposableHostGuard.Inputs {
        .init(disposableFlagSet: disposable, productionSysextActive: sysext, dataDirOverridePresent: dataDir)
    }

    @Test("Guard allows only an explicitly-disposable host with no production sysext and no data-dir override")
    func allowsOnlyClean() {
        #expect(DisposableHostGuard().evaluate(inputs(disposable: true, sysext: false, dataDir: false)) == .allowed)
    }

    @Test("Guard refuses when the host is not marked disposable")
    func refusesNonDisposable() {
        let d = DisposableHostGuard().evaluate(inputs(disposable: false, sysext: false, dataDir: false))
        #expect(d.isAllowed == false)
        if case .refused(let r) = d { #expect(r.contains("not marked disposable")) } else { Issue.record("expected refusal") }
    }

    @Test("Guard refuses when a production sysext is active (a real install)")
    func refusesProductionSysext() {
        let d = DisposableHostGuard().evaluate(inputs(disposable: true, sysext: true, dataDir: false))
        if case .refused(let r) = d { #expect(r.contains("System Extension")) } else { Issue.record("expected refusal") }
    }

    @Test("Guard refuses when MACCRAB_DATA_DIR is set (that is Lane 2, not live)")
    func refusesDataDir() {
        let d = DisposableHostGuard().evaluate(inputs(disposable: true, sysext: false, dataDir: true))
        if case .refused(let r) = d { #expect(r.contains("MACCRAB_DATA_DIR")) } else { Issue.record("expected refusal") }
    }

    @Test("Live lane refuses on a non-disposable host and never runs triggers")
    func laneRefuses() {
        let lane = LiveTriggerLane(guardInputs: inputs(disposable: false, sysext: false, dataDir: false))
        let outcome = lane.run(manifest: LiveTriggerLane.starterManifest)
        if case .refused = outcome {} else { Issue.record("live lane must refuse on a non-disposable host") }
    }

    @Test("Live lane past the guard returns a (stubbed) ran outcome, not a refusal")
    func lanePastGuard() {
        // On a disposable host the guard allows; the on-device trigger execution
        // is a stub here, so verdicts is empty but the outcome is .ran.
        let lane = LiveTriggerLane(guardInputs: inputs(disposable: true, sysext: false, dataDir: false))
        if case .ran = lane.run(manifest: LiveTriggerLane.starterManifest) {} else {
            Issue.record("guard allowed but lane did not reach the ran branch")
        }
    }

    @Test("Starter manifest is aligned with the offline corpus and benign")
    func manifestAligned() {
        let entry = LiveTriggerLane.starterManifest.first { $0.technique == "T1059.004" }!
        #expect(entry.expectedRuleId == Corpora.reverseShell.targetRuleId)
        #expect(entry.benignCommand.contains("127.0.0.1"))   // black-hole, not a real C2
    }
}
