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
        // 1500 < minFileEventsForSpike (2000), so no spike even with drops.
        let r = Eval.evaluate(
            input: Input(fileEventsThisTick: 1_500, processEventsThisTick: 10,
                         kernelDropDelta: 100, collectorDropDelta: 5000, benignHighIOSigner: false),
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
