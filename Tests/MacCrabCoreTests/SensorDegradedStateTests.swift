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
//      cumulative→delta box stamps the open time once per episode.

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
        // A NOTIFY_SIGNAL-style flood: 120_000 offered per tick, 10_000 evicted
        // at the lane = 8.3%, below the 15% bound. The pre-v1.22.7 denominator
        // (eight processed types = 3_000, plus the 10_000 drops) read 77%.
        var b = warmedBaseline()
        var fires = 0
        for _ in 0..<4 {
            let r = Eval.evaluate(
                input: Input(fileEventsThisTick: 2_500, processEventsThisTick: 500,
                             kernelDropDelta: 0, collectorDropDelta: 0, benignHighIOSigner: false,
                             laneDropDelta: 10_000, offeredThisTick: 120_000),
                baseline: b)
            b = r.newBaseline
            #expect(abs(r.lossFraction - 10_000.0 / 120_000.0) < 1e-9)
            if fired(r) { fires += 1 }
        }
        #expect(fires == 0)
        #expect(!b.stateActive)
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
