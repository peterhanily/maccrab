// SensorDegradationEvaluatorTests.swift
// v1.21.4 Phase-1 D2 — deterministic unit coverage for the sensor-degraded /
// possible-evasion meta-alert evaluator. Drives the PURE evaluator (and the
// cumulative→delta box) with synthetic heartbeat inputs; no live daemon.
//
// The conjunction under test: a file-event ingest spike above a rolling EWMA
// baseline AND (kernel drops > 0 OR ES-collector-stage userspace drops > 0 OR
// the process/exec channel collapses). The key properties proved here:
//   1. Fires exactly ONCE under a sustained flood (rising-edge latch).
//   2. NEVER on a benign high-I/O burst with NO drops of any kind (the
//      conjunction gate) — a rate spike alone is not enough.
//   3. The benign-signer downgrade emits at LOW severity (coverage loss is
//      never fully silent).
//   4. F1 regression guard: after Phase-3/4 a flood produces COLLECTOR-stage
//      drops (backpressure / stream-yield), not kernel drops — D2 must still
//      fire on that branch, else the live money-test flood degrades the sensor
//      silently.

import Testing
import Foundation
@testable import MacCrabCore
@testable import MacCrabAgentKit

@Suite("D2 sensor-degraded evaluator")
struct SensorDegradationEvaluatorTests {

    typealias Eval = SensorDegradationEvaluator
    typealias Input = SensorDegradationEvaluator.Input

    /// Warm the evaluator through one seed tick + one normal tick so the
    /// baseline is established (fileEwma ≈ 1000, processEwma ≈ 500) before the
    /// test drives the interesting tick.
    private func warmedBaseline() -> Eval.Baseline {
        var b = Eval.Baseline()
        b = Eval.evaluate(input: Input(fileEventsThisTick: 1000, processEventsThisTick: 500,
                                       kernelDropDelta: 0, collectorDropDelta: 0,
                                       benignHighIOSigner: false), baseline: b).newBaseline
        b = Eval.evaluate(input: Input(fileEventsThisTick: 1000, processEventsThisTick: 500,
                                       kernelDropDelta: 0, collectorDropDelta: 0,
                                       benignHighIOSigner: false), baseline: b).newBaseline
        return b
    }

    @Test("seed tick never fires (no history)")
    func seedTickNoFire() {
        let r = Eval.evaluate(
            input: Input(fileEventsThisTick: 999_999, processEventsThisTick: 0,
                         kernelDropDelta: 999, collectorDropDelta: 0, benignHighIOSigner: false),
            baseline: Eval.Baseline()
        )
        #expect(r.outcome == .noAlert)
        #expect(r.newBaseline.seeded)
    }

    @Test("fires exactly once under a sustained flood (latch holds)")
    func firesOnceUnderSustainedFlood() {
        var b = warmedBaseline()
        var fireCount = 0
        for _ in 0..<6 {
            let r = Eval.evaluate(
                input: Input(fileEventsThisTick: 50_000, processEventsThisTick: 10,
                             kernelDropDelta: 100, collectorDropDelta: 0, benignHighIOSigner: false),
                baseline: b
            )
            b = r.newBaseline
            if case .degraded = r.outcome { fireCount += 1 }
        }
        #expect(fireCount == 1)
    }

    @Test("benign high-I/O burst with NO drops of any kind never fires (conjunction gate)")
    func benignBurstNeverFires() {
        var b = warmedBaseline()
        for _ in 0..<6 {
            // Rate spike (file 50k) but process throughput NORMAL (no exec
            // starvation) and ZERO drops (kernel AND collector) → conjunction
            // is false.
            let r = Eval.evaluate(
                input: Input(fileEventsThisTick: 50_000, processEventsThisTick: 500,
                             kernelDropDelta: 0, collectorDropDelta: 0, benignHighIOSigner: false),
                baseline: b
            )
            b = r.newBaseline
            #expect(r.outcome == .noAlert)
        }
    }

    @Test("kernel-drop branch: spike + drops fires even if process throughput holds")
    func firesOnKernelDropBranch() {
        let b = warmedBaseline()
        let r = Eval.evaluate(
            input: Input(fileEventsThisTick: 50_000, processEventsThisTick: 500,
                         kernelDropDelta: 42, collectorDropDelta: 0, benignHighIOSigner: false),
            baseline: b
        )
        guard case let .degraded(severity, benign) = r.outcome else {
            Issue.record("expected .degraded"); return
        }
        #expect(severity == .high)
        #expect(!benign)
    }

    // F1 regression guard. This is the live money-test scenario: after the
    // Phase-3 retain-worker + Phase-4 client split, a flood drives KERNEL drops
    // to ~0 and instead overflows the collector-stage worker/stream buffers.
    // Before this fix D2's conjunction only watched kernelDropDelta, so the
    // sensor degraded SILENTLY (measured live: 175k backpressure drops, kernel
    // drops 0, D2 never fired). It must fire on the collector-drop branch.
    @Test("collector-drop branch: spike + backpressure/stream-yield drops fires with ZERO kernel drops (F1)")
    func firesOnCollectorDropBranch() {
        let b = warmedBaseline()
        let r = Eval.evaluate(
            input: Input(fileEventsThisTick: 50_000, processEventsThisTick: 500,
                         kernelDropDelta: 0, collectorDropDelta: 9001, benignHighIOSigner: false),
            baseline: b
        )
        guard case let .degraded(severity, benign) = r.outcome else {
            Issue.record("expected .degraded on collector-drop OR branch (F1)"); return
        }
        #expect(severity == .high)
        #expect(!benign)
    }

    @Test("process-collapse branch: spike + exec collapse fires even with zero kernel-drop delta")
    func firesOnProcessCollapseBranch() {
        let b = warmedBaseline()
        // drop delta 0, but process events collapse from ~500 baseline to 10.
        let r = Eval.evaluate(
            input: Input(fileEventsThisTick: 50_000, processEventsThisTick: 10,
                         kernelDropDelta: 0, collectorDropDelta: 0, benignHighIOSigner: false),
            baseline: b
        )
        guard case .degraded = r.outcome else {
            Issue.record("expected .degraded on process-collapse OR branch"); return
        }
    }

    @Test("benign-signer downgrade: same conjunction, but LOW severity")
    func benignSignerDowngradesToLow() {
        let b = warmedBaseline()
        let r = Eval.evaluate(
            input: Input(fileEventsThisTick: 50_000, processEventsThisTick: 10,
                         kernelDropDelta: 100, collectorDropDelta: 0, benignHighIOSigner: true),
            baseline: b
        )
        guard case let .degraded(severity, benign) = r.outcome else {
            Issue.record("expected .degraded"); return
        }
        #expect(severity == .low)      // downgraded, but still emitted
        #expect(benign)
    }

    @Test("sub-floor spike does not count (min file-event floor)")
    func subFloorSpikeIgnored() {
        let b = warmedBaseline()
        // 1500 < minFileEventsForSpike (2000) → no spike. Drops here are a LOW
        // fraction (200 of ~1710 = 12% < the 15% sustained bound), so the #12
        // sustained-loss branch is also inert — isolating the spike-floor guard.
        // (A sub-floor rate with a HIGH drop fraction now DOES fire via sustained
        // loss — see sustainedLossWithoutSpikeFires.)
        let r = Eval.evaluate(
            input: Input(fileEventsThisTick: 1_500, processEventsThisTick: 10,
                         kernelDropDelta: 100, collectorDropDelta: 100, benignHighIOSigner: false),
            baseline: b
        )
        #expect(r.outcome == .noAlert)
    }

    @Test("re-arms after recovery, then fires again on a fresh episode")
    func reArmsAfterRecovery() {
        var b = warmedBaseline()

        // Episode 1: flood → fires.
        var r = Eval.evaluate(
            input: Input(fileEventsThisTick: 50_000, processEventsThisTick: 10,
                         kernelDropDelta: 100, collectorDropDelta: 0, benignHighIOSigner: false),
            baseline: b)
        b = r.newBaseline
        #expect({ if case .degraded = r.outcome { return true } else { return false } }())

        // Recovery: rate back to baseline, no drops → no fire + re-arm.
        r = Eval.evaluate(
            input: Input(fileEventsThisTick: 1_000, processEventsThisTick: 500,
                         kernelDropDelta: 0, collectorDropDelta: 0, benignHighIOSigner: false),
            baseline: b)
        b = r.newBaseline
        #expect(r.outcome == .noAlert)
        #expect(!b.degradedActive)

        // Episode 2: flood again → fires again (proves the latch re-armed).
        r = Eval.evaluate(
            input: Input(fileEventsThisTick: 50_000, processEventsThisTick: 10,
                         kernelDropDelta: 100, collectorDropDelta: 0, benignHighIOSigner: false),
            baseline: b)
        #expect({ if case .degraded = r.outcome { return true } else { return false } }())
    }

    // MARK: - #12 sustained drop-fraction branch (the gradual-ramp evasion)

    /// One elevated-loss tick (no spike): file 2500 (≥ 2000 floor, < baseline×3
    /// so no spike), 700 dropped of 3700 offered ≈ 19% ≥ the 15% bound.
    private func lossTick(_ b: Eval.Baseline) -> Eval.Result {
        Eval.evaluate(
            input: Input(fileEventsThisTick: 2_500, processEventsThisTick: 500,
                         kernelDropDelta: 700, collectorDropDelta: 0, benignHighIOSigner: false),
            baseline: b)
    }

    @Test("#12: SUSTAINED drop fraction (≥2 ticks) with NO spike fires (the gradual-ramp evasion)")
    func sustainedLossWithoutSpikeFires() {
        var b = warmedBaseline()   // fileEwma ≈ 1000
        let t1 = lossTick(b); b = t1.newBaseline
        #expect(t1.outcome == .noAlert, "a single elevated tick must NOT fire (could be a transient burst)")
        let t2 = lossTick(b)
        guard case let .degraded(severity, benign) = t2.outcome else {
            Issue.record("expected .degraded once the loss has PERSISTED two ticks"); return
        }
        #expect(severity == .high)
        #expect(!benign)
    }

    @Test("#12: a SINGLE transient drop burst on a quiet host does NOT fire (rc.3-verify FP fix)")
    func singleTransientBurstNoFire() {
        let b = warmedBaseline()
        // file 100 + process 50 + 1900 kernel drops = offered 2050 (clears the
        // floor via the drops alone), fraction 93% — but it is ONE tick, so the
        // sustained branch must stay silent (a Spotlight/build/wake burst).
        let r = Eval.evaluate(
            input: Input(fileEventsThisTick: 100, processEventsThisTick: 50,
                         kernelDropDelta: 1_900, collectorDropDelta: 0, benignHighIOSigner: false),
            baseline: b)
        #expect(r.outcome == .noAlert, "one transient burst is not sustained loss — no evasion alert")
    }

    @Test("#12: sustained loss fires exactly once, then re-arms when the loss subsides")
    func sustainedLossLatchesThenReArms() {
        var b = warmedBaseline()
        var fireCount = 0
        // 6 ticks of chronic loss, no spike → fires once (on the 2nd tick; latch).
        for _ in 0..<6 {
            let r = lossTick(b); b = r.newBaseline
            if case .degraded = r.outcome { fireCount += 1 }
        }
        #expect(fireCount == 1)
        // Drops stop → re-arm + reset the consecutive-tick counter.
        let calm = Eval.evaluate(
            input: Input(fileEventsThisTick: 1_000, processEventsThisTick: 500,
                         kernelDropDelta: 0, collectorDropDelta: 0, benignHighIOSigner: false),
            baseline: b)
        b = calm.newBaseline
        #expect(!b.sustainedLossActive)
        #expect(b.sustainedLossTicks == 0)
        // Fresh loss episode → fires again after it re-persists two ticks.
        let f1 = lossTick(b); b = f1.newBaseline
        #expect(f1.outcome == .noAlert)
        let f2 = lossTick(b)
        #expect({ if case .degraded = f2.outcome { return true } else { return false } }())
    }

    @Test("#12: a low drop fraction (below the bound) with no spike does NOT fire")
    func lowDropFractionNoSpikeNoFire() {
        let b = warmedBaseline()
        // 100 dropped of ~3100 offered = 3% < 15% bound, and no spike.
        let r = Eval.evaluate(
            input: Input(fileEventsThisTick: 2_500, processEventsThisTick: 500,
                         kernelDropDelta: 100, collectorDropDelta: 0, benignHighIOSigner: false),
            baseline: b)
        #expect(r.outcome == .noAlert)
    }

    @Test("#12: idle box below the volume floor does not trip the fraction branch")
    func idleBoxBelowVolumeFloorNoFire() {
        let b = warmedBaseline()
        // 1000 dropped but only ~1150 offered (< 2000 floor) → fraction untrusted.
        let r = Eval.evaluate(
            input: Input(fileEventsThisTick: 100, processEventsThisTick: 50,
                         kernelDropDelta: 1_000, collectorDropDelta: 0, benignHighIOSigner: false),
            baseline: b)
        #expect(r.outcome == .noAlert)
    }

    @Test("baseline is frozen during a spike (a flood cannot poison it)")
    func baselineFrozenDuringSpike() {
        let b = warmedBaseline()
        let before = b.fileEventEwma
        let r = Eval.evaluate(
            input: Input(fileEventsThisTick: 500_000, processEventsThisTick: 10,
                         kernelDropDelta: 100, collectorDropDelta: 0, benignHighIOSigner: false),
            baseline: b)
        #expect(r.newBaseline.fileEventEwma == before)   // unchanged while spiking
    }
}

@Suite("D2 SensorDegradationState box (cumulative → delta)")
struct SensorDegradationStateTests {

    @Test("first tick establishes no delta; second tick seeds; flood fires once")
    func cumulativeToDeltaFlow() {
        let box = SensorDegradationState()
        // Tick 1: first cumulative snapshot — no delta yet.
        var r = box.step(fileCumulative: 0, processCumulative: 0, kernelDropCumulative: 0,
                         collectorDropCumulative: 0, benignHighIOSigner: false)
        #expect(r.outcome == .noAlert)
        // Tick 2: delta (1000, 500, 0) → seeds baseline.
        r = box.step(fileCumulative: 1000, processCumulative: 500, kernelDropCumulative: 0,
                     collectorDropCumulative: 0, benignHighIOSigner: false)
        #expect(r.outcome == .noAlert)
        // Tick 3: delta (1000, 500, 0) → normal, establishes baseline.
        r = box.step(fileCumulative: 2000, processCumulative: 1000, kernelDropCumulative: 0,
                     collectorDropCumulative: 0, benignHighIOSigner: false)
        #expect(r.outcome == .noAlert)
        // Tick 4: delta (50000, 10, 100) → flood + drops + exec collapse → fires.
        r = box.step(fileCumulative: 52_000, processCumulative: 1010, kernelDropCumulative: 100,
                     collectorDropCumulative: 0, benignHighIOSigner: false)
        #expect({ if case .degraded = r.outcome { return true } else { return false } }())
        // Tick 5: sustained flood → latched, no second fire.
        r = box.step(fileCumulative: 102_000, processCumulative: 1020, kernelDropCumulative: 200,
                     collectorDropCumulative: 0, benignHighIOSigner: false)
        #expect(r.outcome == .noAlert)
    }

    // F1 through the cumulative→delta box: replicate the live RC flood exactly.
    // Kernel drops stay pinned at 0 (the split + retain-worker prevented them);
    // the ES-collector-stage drop counter climbs. Process/exec throughput even
    // RISES (as observed live), so the process-collapse branch is also inert.
    // The ONLY branch that can fire is collectorDrop — proving the fix end to
    // end through the same delta machinery the heartbeat uses.
    @Test("F1: kernel drops pinned at 0, collector drops climb under flood → fires")
    func firesOnCollectorDropFloodViaStateBox() {
        let box = SensorDegradationState()
        // Seed + establish a calm baseline (file ~1000/tick, process ~500/tick).
        _ = box.step(fileCumulative: 0, processCumulative: 0, kernelDropCumulative: 0,
                     collectorDropCumulative: 0, benignHighIOSigner: false)
        _ = box.step(fileCumulative: 1000, processCumulative: 500, kernelDropCumulative: 0,
                     collectorDropCumulative: 0, benignHighIOSigner: false)
        _ = box.step(fileCumulative: 2000, processCumulative: 1000, kernelDropCumulative: 0,
                     collectorDropCumulative: 0, benignHighIOSigner: false)
        // Flood tick: +50k file writes, kernel drops STILL 0, collector drops
        // +175k, exec throughput up not down (+600).
        let r = box.step(fileCumulative: 52_000, processCumulative: 1600, kernelDropCumulative: 0,
                         collectorDropCumulative: 175_000, benignHighIOSigner: false)
        guard case let .degraded(severity, _) = r.outcome else {
            Issue.record("F1: expected .degraded from collector-drop flood (kernel drops 0)"); return
        }
        #expect(severity == .high)
    }

    @Test("client reconnect (counter reset) is not miscounted as a burst")
    func reconnectResetClampsDelta() {
        let box = SensorDegradationState()
        _ = box.step(fileCumulative: 0, processCumulative: 0, kernelDropCumulative: 0,
                     collectorDropCumulative: 0, benignHighIOSigner: false)
        _ = box.step(fileCumulative: 100_000, processCumulative: 5000, kernelDropCumulative: 0,
                     collectorDropCumulative: 0, benignHighIOSigner: false)
        // Reconnect: cumulative counters reset to a LOWER value. The delta must
        // clamp to 0 (not wrap to a giant unsigned burst) → no spurious fire.
        let r = box.step(fileCumulative: 10, processCumulative: 5, kernelDropCumulative: 0,
                         collectorDropCumulative: 0, benignHighIOSigner: false)
        #expect(r.outcome == .noAlert)
    }
}
