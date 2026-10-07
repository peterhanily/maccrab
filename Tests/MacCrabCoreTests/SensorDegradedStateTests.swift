// SensorDegradedStateTests.swift
// v1.22.7: `es_sensor_degraded` is a level-triggered STATE, not the meta-alert's
// one-tick rising edge. Before this a sustained-loss episode read `true` for a
// single 30 s heartbeat tick and `false` for the rest of it. Pinned here:
//   1. the state is raised on the fire tick and HELD through the episode;
//   2. it clears only after `stateClearCleanTicks` CONSECUTIVE clean ticks,
//      and a dirty tick inside that window restarts the count;
//   3. the meta-alert stays edge-triggered — fire counts are unchanged;
//   4. the loss fraction is judged against the supplied offer denominator with
//      the ES-collector and merged-lane stages both counted, and the
//      cumulative→delta box stamps the open time once per episode;
//   5. the spike latch ALONE never holds the state: a tick is dirty only with
//      loss evidence (a fire, a drop at any stage, the exec collapse) or the
//      bounded sustained-loss latch — the latch itself stays armed for as
//      long as the file rate exceeds the frozen baseline, which on a build
//      host is the whole session;
//   6. each merged lane is judged against its OWN offers, so a priority-lane
//      eviction storm is not diluted by a lossless file lane, and the
//      heartbeat text names the lane and never restates "spiked"/"evasion"
//      over a held tick's 0% numbers.

import Testing
import Foundation
@testable import MacCrabCore
@testable import MacCrabAgentKit

@Suite("D2 degraded state is level-triggered (v1.22.7)")
struct SensorDegradedStateTests {

    typealias Eval = SensorDegradationEvaluator
    typealias Input = SensorDegradationEvaluator.Input

    /// Seed + settle so every branch is live (fileEwma ≈ 1000, processEwma ≈ 500).
    private func warmedBaseline() -> Eval.Baseline {
        var b = Eval.Baseline()
        for _ in 0..<Eval.processBaselineSettleTicks {
            b = Eval.evaluate(input: Input(fileEventsThisTick: 1000, processEventsThisTick: 500,
                                           kernelDropDelta: 0, collectorDropDelta: 0,
                                           benignHighIOSigner: false), baseline: b).newBaseline
        }
        return b
    }

    /// Spike + kernel drops + exec collapse: the spikeWithLoss branch.
    private func floodTick(_ b: Eval.Baseline) -> Eval.Result {
        Eval.evaluate(
            input: Input(fileEventsThisTick: 50_000, processEventsThisTick: 10,
                         kernelDropDelta: 100, collectorDropDelta: 0, benignHighIOSigner: false),
            baseline: b)
    }

    /// Calm tick at baseline with no loss of any kind.
    private func quietTick(_ b: Eval.Baseline) -> Eval.Result {
        Eval.evaluate(
            input: Input(fileEventsThisTick: 1_000, processEventsThisTick: 500,
                         kernelDropDelta: 0, collectorDropDelta: 0, benignHighIOSigner: false),
            baseline: b)
    }

    /// One elevated-loss tick without a spike (≈19% ≥ the 15% bound).
    private func lossTick(_ b: Eval.Baseline) -> Eval.Result {
        Eval.evaluate(
            input: Input(fileEventsThisTick: 2_500, processEventsThisTick: 500,
                         kernelDropDelta: 700, collectorDropDelta: 0, benignHighIOSigner: false),
            baseline: b)
    }

    /// Spike held with NO loss of any kind: the file rate stays 50× the frozen
    /// baseline (so the latch stays armed) but every loss counter is 0 and
    /// exec is at baseline — a build host after the opening tick.
    private func losslessSpikeTick(_ b: Eval.Baseline) -> Eval.Result {
        Eval.evaluate(
            input: Input(fileEventsThisTick: 50_000, processEventsThisTick: 500,
                         kernelDropDelta: 0, collectorDropDelta: 0, benignHighIOSigner: false),
            baseline: b)
    }

    /// The zero-drop fire a settled host produces: spike + exec collapse with
    /// every drop counter at 0 (the base evaluator test proves it fires).
    private func collapseOpenTick(_ b: Eval.Baseline) -> Eval.Result {
        Eval.evaluate(
            input: Input(fileEventsThisTick: 50_000, processEventsThisTick: 10,
                         kernelDropDelta: 0, collectorDropDelta: 0, benignHighIOSigner: false),
            baseline: b)
    }

    /// No spike in the processed file types, but 20_000 evictions at the
    /// priority lane against 123_000 priority offers (16%) while the file lane
    /// offers 150_000 lossless events: all-lanes reads 20k/273k = 7%.
    private func priorityStormInput(perLane: Bool) -> Input {
        Input(fileEventsThisTick: 2_500, processEventsThisTick: 500,
              kernelDropDelta: 0, collectorDropDelta: 0, benignHighIOSigner: false,
              laneDropDelta: 20_000, offeredThisTick: 273_000,
              priorityLane: perLane ? Eval.LaneSample(offered: 123_000, lost: 20_000) : nil,
              fileLane: perLane ? Eval.LaneSample(offered: 150_000, lost: 0) : nil)
    }

    private func fired(_ r: Eval.Result) -> Bool {
        if case .degraded = r.outcome { return true }
        return false
    }

    @Test("rising edge: the fire tick raises the state and records branch + severity")
    func risingEdgeRaisesState() {
        let r = floodTick(warmedBaseline())
        #expect(fired(r))
        #expect(r.degradedState)
        #expect(r.activeReason == .spikeWithLoss)
        #expect(r.activeSeverity == .high)
        #expect(r.newBaseline.stateActive)
        #expect(r.newBaseline.cleanTicks == 0)
    }

    @Test("sustained flood: the state is true on every tick while the alert fires exactly once")
    func sustainedFloodHoldsState() {
        var b = warmedBaseline()
        var fires = 0
        var degradedTicks = 0
        for _ in 0..<6 {
            let r = floodTick(b); b = r.newBaseline
            if fired(r) { fires += 1 }
            if r.degradedState { degradedTicks += 1 }
        }
        #expect(fires == 1, "the meta-alert must stay edge-triggered")
        #expect(degradedTicks == 6, "the state must hold for the whole episode, got \(degradedTicks)")
    }

    @Test("clearing: the state survives N-1 consecutive clean ticks and clears on the Nth")
    func clearsAfterConsecutiveCleanTicks() {
        var b = warmedBaseline()
        for _ in 0..<3 { b = floodTick(b).newBaseline }
        #expect(b.stateActive)
        for i in 1..<Eval.stateClearCleanTicks {
            let r = quietTick(b); b = r.newBaseline
            #expect(r.outcome == .noAlert)
            #expect(!b.degradedActive, "the spike latch itself re-arms on the first clean tick")
            #expect(r.degradedState, "clean tick \(i) of \(Eval.stateClearCleanTicks) must not clear the state")
            #expect(r.activeReason == .spikeWithLoss, "the episode is still described while clearing")
        }
        let r = quietTick(b); b = r.newBaseline
        #expect(!r.degradedState)
        #expect(r.activeReason == nil)
        #expect(r.activeSeverity == nil)
        #expect(!b.stateActive)
        #expect(b.cleanTicks == 0)
    }

    @Test("clearing: a dirty tick inside the clean window restarts the count")
    func dirtyTickRestartsCleanCount() {
        var b = warmedBaseline()
        for _ in 0..<3 { b = floodTick(b).newBaseline }
        b = quietTick(b).newBaseline                      // clean tick 1 (latch re-armed)
        let again = floodTick(b); b = again.newBaseline   // fresh episode → re-fire
        #expect(fired(again))
        #expect(again.degradedState)
        #expect(b.cleanTicks == 0)
        for _ in 1..<Eval.stateClearCleanTicks {
            b = quietTick(b).newBaseline
            #expect(b.stateActive)
        }
        b = quietTick(b).newBaseline
        #expect(!b.stateActive)
    }

    @Test("sustained-loss branch: state held across the episode, one fire, clears after the window plus the clean ticks")
    func sustainedLossHoldsState() {
        var b = warmedBaseline()
        var fires = 0
        var degradedTicks = 0
        for _ in 0..<6 {
            let r = lossTick(b); b = r.newBaseline
            if fired(r) { fires += 1 }
            if r.degradedState { degradedTicks += 1 }
        }
        #expect(fires == 1)
        // The windowed branch opens on the 2nd elevated tick and holds through the 6th.
        #expect(degradedTicks == 5, "got \(degradedTicks)")
        #expect(b.recentElevatedMask == 0b1111)

        // Clean ticks: the 4-tick window needs 3 clean ticks before fewer than
        // 2 elevated ticks remain (0b1110 → 0b1100 → 0b1000), which re-arms the
        // latch; the state then needs `stateClearCleanTicks` consecutive clean
        // ticks on top. So the state clears on clean tick 2 + stateClearCleanTicks.
        var clearedOnCleanTick = 0
        for i in 1...12 {
            let r = quietTick(b); b = r.newBaseline
            #expect(r.outcome == .noAlert)
            if !r.degradedState { clearedOnCleanTick = i; break }
        }
        #expect(clearedOnCleanTick == 2 + Eval.stateClearCleanTicks, "cleared on \(clearedOnCleanTick)")
        #expect(b.activeReason == nil)
    }

    @Test("alert volume is unchanged: one fire per episode, a fresh episode fires again")
    func alertVolumeUnchanged() {
        var b = warmedBaseline()
        var fires = 0
        var degradedTicks = 0
        for _ in 0..<6 { let r = floodTick(b); b = r.newBaseline; if fired(r) { fires += 1 }; if r.degradedState { degradedTicks += 1 } }
        for _ in 0..<4 { let r = quietTick(b); b = r.newBaseline; if fired(r) { fires += 1 }; if r.degradedState { degradedTicks += 1 } }
        for _ in 0..<6 { let r = floodTick(b); b = r.newBaseline; if fired(r) { fires += 1 }; if r.degradedState { degradedTicks += 1 } }
        #expect(fires == 2)
        // 6 flood + (stateClearCleanTicks - 1) clearing + 6 flood ticks read degraded.
        #expect(degradedTicks == 12 + Eval.stateClearCleanTicks - 1)
    }

    @Test("loss fraction: judged against the supplied offer denominator with collector and lane stages both counted")
    func lossFractionUsesOfferDenominator() {
        let b = warmedBaseline()
        // 10_000 offered; 100 kernel + 300 collector-stage + 600 lane-stage = 1_000 lost → 10%.
        let r = Eval.evaluate(
            input: Input(fileEventsThisTick: 2_500, processEventsThisTick: 500,
                         kernelDropDelta: 100, collectorDropDelta: 300, benignHighIOSigner: false,
                         laneDropDelta: 600, offeredThisTick: 10_000),
            baseline: b)
        #expect(r.offered == 10_000)
        #expect(r.laneDropDelta == 600)
        #expect(abs(r.lossFraction - 0.10) < 1e-9, "got \(r.lossFraction)")
        // Without an offer count the pre-v1.22.7 denominator (processed file +
        // process events + drops = 4_000) is derived, and the same losses read
        // 25% — eight processed event types are not the sensor's offer.
        let derived = Eval.evaluate(
            input: Input(fileEventsThisTick: 2_500, processEventsThisTick: 500,
                         kernelDropDelta: 100, collectorDropDelta: 300, benignHighIOSigner: false,
                         laneDropDelta: 600),
            baseline: b)
        #expect(derived.offered == 4_000)
        #expect(abs(derived.lossFraction - 0.25) < 1e-9, "got \(derived.lossFraction)")
    }

    @Test("lane-stage losses alone still satisfy the spike conjunction (the stage split dropped no signal)")
    func laneDropsSatisfyConjunction() {
        let r = Eval.evaluate(
            input: Input(fileEventsThisTick: 50_000, processEventsThisTick: 600,
                         kernelDropDelta: 0, collectorDropDelta: 0, benignHighIOSigner: false,
                         laneDropDelta: 5_000, offeredThisTick: 60_000),
            baseline: warmedBaseline())
        #expect(fired(r), "merged-lane evictions under a spike must still fire")
        #expect(r.reason == .spikeWithLoss)
    }

    @Test("honest denominator: a loud lane that is mostly delivered is not sustained loss")
    func honestDenominatorPreventsInflatedFraction() {
        // A NOTIFY_SIGNAL-style flood on the priority lane: 120_000 offered per
        // tick, 10_000 evicted at that SAME lane = 8.3%, below the 15% bound
        // whichever pair is judged. The pre-v1.22.7 denominator (eight
        // processed types = 3_000, plus the 10_000 drops) read 77%.
        var b = warmedBaseline()
        var fires = 0
        for _ in 0..<4 {
            let r = Eval.evaluate(
                input: Input(fileEventsThisTick: 2_500, processEventsThisTick: 500,
                             kernelDropDelta: 0, collectorDropDelta: 0, benignHighIOSigner: false,
                             laneDropDelta: 10_000, offeredThisTick: 120_000,
                             priorityLane: Eval.LaneSample(offered: 120_000, lost: 10_000),
                             fileLane: Eval.LaneSample(offered: 0, lost: 0)),
                baseline: b)
            b = r.newBaseline
            #expect(abs(r.lossFraction - 10_000.0 / 120_000.0) < 1e-9)
            #expect(r.worstLane == nil, "the lane's own fraction equals the combined one")
            if fired(r) { fires += 1 }
        }
        #expect(fires == 0)
        #expect(!b.stateActive)
    }

    @Test("per-lane: a priority-lane eviction storm is judged against priority offers, not diluted by a lossless file lane")
    func priorityLaneStormIsNotDiluted() {
        var b = warmedBaseline()
        var fires = 0
        var reason: Eval.Reason?
        for i in 0..<4 {
            let r = Eval.evaluate(input: priorityStormInput(perLane: true), baseline: b)
            b = r.newBaseline
            #expect(abs(r.lossFraction - 20_000.0 / 123_000.0) < 1e-9, "tick \(i): got \(r.lossFraction)")
            #expect(r.worstLane == .priority)
            #expect(r.worstLaneSample == Eval.LaneSample(offered: 123_000, lost: 20_000))
            if fired(r) { fires += 1; reason = r.reason }
        }
        #expect(fires == 1, "the sustained-loss branch opens on the 2nd elevated tick and latches")
        #expect(reason == .sustainedLoss)
        #expect(b.stateActive)

        // The same losses judged only all-lanes read 7% and never fire — the
        // dilution the per-lane pair exists to remove.
        var diluted = warmedBaseline()
        var dilutedFires = 0
        for _ in 0..<4 {
            let r = Eval.evaluate(input: priorityStormInput(perLane: false), baseline: diluted)
            diluted = r.newBaseline
            #expect(abs(r.lossFraction - 20_000.0 / 273_000.0) < 1e-9)
            #expect(r.worstLane == nil)
            if fired(r) { dilutedFires += 1 }
        }
        #expect(dilutedFires == 0)
    }

    @Test("a latched spike with zero loss does not hold the state: it clears after the clean ticks while the latch stays armed")
    func latchedSpikeWithoutLossClearsState() {
        var b = warmedBaseline()
        let open = collapseOpenTick(b); b = open.newBaseline
        #expect(fired(open))
        #expect(open.degradedState)
        #expect(open.lossEvidenceThisTick)
        for i in 1...6 {
            let r = losslessSpikeTick(b); b = r.newBaseline
            #expect(!fired(r), "tick \(i): the latch must still suppress a re-fire")
            #expect(b.degradedActive, "tick \(i): the latch stays armed while the rate exceeds the frozen baseline")
            #expect(!r.lossEvidenceThisTick)
            #expect(r.lossFraction == 0)
            if i < Eval.stateClearCleanTicks {
                #expect(r.degradedState, "tick \(i) of \(Eval.stateClearCleanTicks) must still read degraded")
                #expect(r.activeReason == .spikeWithLoss)
            } else {
                #expect(!r.degradedState, "tick \(i): no loss evidence for \(Eval.stateClearCleanTicks) ticks must clear the state")
                #expect(r.activeReason == nil)
                #expect(r.activeSeverity == nil)
            }
        }
    }

    @Test("loss resuming inside a still-latched spike re-opens the state without a second fire")
    func lossResumingInsideLatchedSpikeReopensState() {
        var b = warmedBaseline()
        b = collapseOpenTick(b).newBaseline
        for _ in 0..<4 { b = losslessSpikeTick(b).newBaseline }
        #expect(!b.stateActive)
        #expect(b.degradedActive)
        let resumed = Eval.evaluate(
            input: Input(fileEventsThisTick: 50_000, processEventsThisTick: 500,
                         kernelDropDelta: 100, collectorDropDelta: 0, benignHighIOSigner: false),
            baseline: b)
        b = resumed.newBaseline
        #expect(!fired(resumed), "the latch holds — alert volume is unchanged")
        #expect(resumed.degradedState)
        #expect(resumed.lossEvidenceThisTick)
        #expect(resumed.activeReason == .spikeWithLoss)
        #expect(resumed.activeSeverity == .high)
        #expect(b.cleanTicks == 0)
        // And it clears again on the usual schedule once the loss stops.
        for _ in 1..<Eval.stateClearCleanTicks { b = losslessSpikeTick(b).newBaseline; #expect(b.stateActive) }
        b = losslessSpikeTick(b).newBaseline
        #expect(!b.stateActive)
    }

    @Test("heartbeat text: a held tick with no loss says so instead of restating the opening branch")
    func heldTickDetailIsNeutral() {
        var b = warmedBaseline()
        for _ in 0..<3 { b = floodTick(b).newBaseline }
        var held = quietTick(b)   // clean tick 1: state held, nothing lost
        #expect(held.degradedState)
        #expect(!held.lossEvidenceThisTick)
        held.degradedSince = Date(timeIntervalSince1970: 1_790_000_000)
        let text = Eval.heartbeatDescription(for: held, nowUnix: 1_790_000_060)
        #expect(text.severity == "high")
        #expect(text.detail.contains("state held"))
        #expect(text.detail.contains("no loss this tick"))
        #expect(text.detail.contains("opened 60 s ago"))
        #expect(text.detail.contains("0 kernel-dropped"))
        #expect(text.detail.contains("(0% loss)"))
        #expect(text.detail.contains("clears after 1 more clean tick"))
        #expect(!text.detail.contains("spiked"))
        #expect(!text.detail.contains("evasion"))

        // Held by the sustained-loss latch after the loss stopped: the window
        // is what keeps it open, and the text says that.
        var s = warmedBaseline()
        for _ in 0..<6 { s = lossTick(s).newBaseline }
        let windowHeld = quietTick(s)
        #expect(windowHeld.degradedState && !windowHeld.lossEvidenceThisTick)
        let windowText = Eval.heartbeatDescription(for: windowHeld, nowUnix: 0)
        #expect(windowText.detail.contains("sustained-loss window is still elevated"))
        #expect(!windowText.detail.contains("evasion"))
    }

    @Test("heartbeat text: fire ticks and held ticks with loss describe the opening branch with this tick's stage counts")
    func fireTickDetailNamesBranchAndStages() {
        let open = floodTick(warmedBaseline())
        let text = Eval.heartbeatDescription(for: open, nowUnix: 0)
        #expect(text.severity == "high")
        #expect(text.detail.contains("spiked above baseline"))
        #expect(text.detail.contains("100 kernel-dropped"))
        #expect(text.detail.contains("0 dropped at the ES-collector stage"))
        #expect(text.detail.contains("0 evicted at the merged detection lanes"))
        let held = floodTick(open.newBaseline)
        #expect(!fired(held) && held.degradedState && held.lossEvidenceThisTick)
        #expect(Eval.heartbeatDescription(for: held, nowUnix: 0).detail.contains("spiked above baseline"))
        let closed = quietTick(quietTick(open.newBaseline).newBaseline)
        #expect(!closed.degradedState)
        let closedText = Eval.heartbeatDescription(for: closed, nowUnix: 0)
        #expect(closedText.severity.isEmpty && closedText.detail.isEmpty)
    }

    @Test("heartbeat text: names the lane whose own fraction is being judged")
    func detailNamesWorstLane() {
        var b = warmedBaseline()
        var opened: Eval.Result?
        for _ in 0..<2 {
            let r = Eval.evaluate(input: priorityStormInput(perLane: true), baseline: b)
            b = r.newBaseline
            if fired(r) { opened = r }
        }
        guard let r = opened else { Issue.record("expected the priority storm to fire"); return }
        let text = Eval.heartbeatDescription(for: r, nowUnix: 0)
        #expect(text.detail.contains("sustained event loss"))
        #expect(text.detail.contains("16% loss at the priority lane: 20000 lost of 123000 priority-lane offers"))
    }

    @Test("seed tick and a calm tick report a zero loss fraction and no state")
    func calmTicksReportZero() {
        let seed = Eval.evaluate(
            input: Input(fileEventsThisTick: 1_000, processEventsThisTick: 500,
                         kernelDropDelta: 0, collectorDropDelta: 0, benignHighIOSigner: false),
            baseline: Eval.Baseline())
        #expect(seed.lossFraction == 0)
        #expect(!seed.degradedState)
        let calm = quietTick(warmedBaseline())
        #expect(calm.lossFraction == 0)
        #expect(!calm.degradedState)
        #expect(calm.activeReason == nil)
    }
}

@Suite("D2 SensorDegradationState box: since-time and offer deltas (v1.22.7)")
struct SensorDegradedStateBoxTests {

    typealias Eval = SensorDegradationEvaluator

    @Test("degradedSince is stamped once at the opening tick, held, and cleared with the state")
    func sinceTimeLifecycle() {
        let box = SensorDegradationState()
        let t0 = Date(timeIntervalSince1970: 1_790_000_000)
        var file: UInt64 = 0, process: UInt64 = 0, kernel: UInt64 = 0, offered: UInt64 = 0
        var tick = 0
        func step() -> Eval.Result {
            box.step(
                fileCumulative: file, processCumulative: process,
                kernelDropCumulative: kernel, collectorDropCumulative: 0,
                benignHighIOSigner: false,
                laneDropCumulative: 0, offeredCumulative: offered,
                now: t0.addingTimeInterval(Double(tick) * 30))
        }
        func calm() { tick += 1; file += 1_000; process += 500; offered += 1_500 }
        func flood() { tick += 1; file += 50_000; process += 10; kernel += 100; offered += 50_110 }

        // First call establishes the cumulative snapshot; then seed + settle.
        var r = step()
        #expect(r.degradedSince == nil)
        for _ in 0...Eval.processBaselineSettleTicks {
            calm(); r = step()
            #expect(r.degradedSince == nil)
            #expect(!r.degradedState)
        }

        flood(); r = step()
        let openedAt = t0.addingTimeInterval(Double(tick) * 30)
        guard case .degraded = r.outcome else { Issue.record("expected the flood to fire"); return }
        #expect(r.degradedState)
        #expect(r.degradedSince == openedAt)

        flood(); r = step()
        #expect(r.outcome == .noAlert)
        #expect(r.degradedState)
        #expect(r.degradedSince == openedAt, "held, never re-stamped inside an episode")

        for _ in 0..<Eval.stateClearCleanTicks {
            calm(); r = step()
        }
        #expect(!r.degradedState)
        #expect(r.degradedSince == nil)

        // A later, separate episode gets its own open time.
        for _ in 0..<2 { calm(); r = step() }
        flood(); r = step()
        #expect(r.degradedSince == t0.addingTimeInterval(Double(tick) * 30))
    }

    @Test("the offer delta is the loss-fraction denominator and the lane stage is split out")
    func offerDeltaIsDenominator() {
        let box = SensorDegradationState()
        _ = box.step(fileCumulative: 0, processCumulative: 0, kernelDropCumulative: 0,
                     collectorDropCumulative: 0, benignHighIOSigner: false,
                     laneDropCumulative: 0, offeredCumulative: 0)
        _ = box.step(fileCumulative: 1_000, processCumulative: 500, kernelDropCumulative: 0,
                     collectorDropCumulative: 0, benignHighIOSigner: false,
                     laneDropCumulative: 0, offeredCumulative: 1_500)
        let r = box.step(fileCumulative: 2_000, processCumulative: 1_000, kernelDropCumulative: 50,
                         collectorDropCumulative: 150, benignHighIOSigner: false,
                         laneDropCumulative: 300, offeredCumulative: 11_500)
        #expect(r.offered == 10_000)
        #expect(r.kernelDropDelta == 50)
        #expect(r.collectorDropDelta == 150)
        #expect(r.laneDropDelta == 300)
        #expect(abs(r.lossFraction - 0.05) < 1e-9, "got \(r.lossFraction)")
    }

    @Test("per-lane cumulative pairs become per-tick samples and the worst lane is named")
    func laneDeltasFeedTheEvaluator() {
        let box = SensorDegradationState()
        _ = box.step(fileCumulative: 0, processCumulative: 0, kernelDropCumulative: 0,
                     collectorDropCumulative: 0, benignHighIOSigner: false,
                     laneDropCumulative: 0, offeredCumulative: 0,
                     priorityLaneCumulative: (offered: 0, lost: 0),
                     fileLaneCumulative: (offered: 0, lost: 0))
        _ = box.step(fileCumulative: 1_000, processCumulative: 500, kernelDropCumulative: 0,
                     collectorDropCumulative: 0, benignHighIOSigner: false,
                     laneDropCumulative: 0, offeredCumulative: 1_500,
                     priorityLaneCumulative: (offered: 500, lost: 0),
                     fileLaneCumulative: (offered: 1_000, lost: 0))
        let r = box.step(fileCumulative: 3_500, processCumulative: 1_000, kernelDropCumulative: 0,
                         collectorDropCumulative: 0, benignHighIOSigner: false,
                         laneDropCumulative: 20_000, offeredCumulative: 274_500,
                         priorityLaneCumulative: (offered: 123_500, lost: 20_000),
                         fileLaneCumulative: (offered: 151_000, lost: 0))
        #expect(r.offered == 273_000)
        #expect(r.laneDropDelta == 20_000)
        #expect(r.worstLane == .priority)
        #expect(r.worstLaneSample == Eval.LaneSample(offered: 123_000, lost: 20_000))
        #expect(abs(r.lossFraction - 20_000.0 / 123_000.0) < 1e-9, "got \(r.lossFraction)")
    }

    @Test("an offer counter reset (client reconnect) clamps to zero instead of a giant denominator")
    func offerResetClamps() {
        let box = SensorDegradationState()
        _ = box.step(fileCumulative: 0, processCumulative: 0, kernelDropCumulative: 0,
                     collectorDropCumulative: 0, benignHighIOSigner: false,
                     laneDropCumulative: 0, offeredCumulative: 100_000)
        let r = box.step(fileCumulative: 10, processCumulative: 5, kernelDropCumulative: 0,
                         collectorDropCumulative: 0, benignHighIOSigner: false,
                         laneDropCumulative: 0, offeredCumulative: 50)
        #expect(r.offered == 0)
        #expect(r.lossFraction == 0)
    }
}
