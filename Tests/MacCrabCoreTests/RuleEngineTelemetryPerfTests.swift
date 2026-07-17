// RuleEngineTelemetryPerfTests.swift
//
// Tier-A per-event perf batch (#5 + #9): per-rule telemetry recording was
// COW-copying a ~2 KB reservoir buffer and drawing an `arc4random` sample on
// every event for every active rule. The reservoir is now mutated in place
// through the `ruleStats` `_modify` subscript, and the Vitter Algorithm R
// draw uses a fast seeded SplitMix64 PRNG.
//
// These tests lock down the DETECTION-EXACT contract: the recorded COUNTS
// (evaluationCount / fireCount / totalExecNs / lastFiredAt) are exact and
// independent of the RNG, and the reservoir still samples with a bounded,
// non-empty buffer after N events. The random source only affects WHICH exec
// samples survive in the bounded reservoir — telemetry, never a rule verdict.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("RuleEngine telemetry recording (Tier-A #5 + #9)")
struct RuleEngineTelemetryPerfTests {

    // MARK: - RuleStats.record (unit)

    @Test("Reservoir is bounded and non-empty after N > reservoirSize events")
    func reservoirBoundedAndNonEmpty() {
        var stats = RuleEngine.RuleStats(ruleId: "r")
        var rng = SplitMix64(seed: 1)
        let reservoirSize = 8
        for i in 1...100 {
            stats.record(elapsedNs: UInt64(i), fired: false,
                         eventTimestamp: Date(), reservoirSize: reservoirSize, rng: &rng)
        }
        #expect(stats.execSamplesNs.count == reservoirSize)   // bounded
        #expect(!stats.execSamplesNs.isEmpty)                 // still samples
        #expect(stats.evaluationCount == 100)                 // exact count
    }

    @Test("Under reservoirSize: every sample is appended, none dropped")
    func reservoirFillsBeforeCap() {
        var stats = RuleEngine.RuleStats(ruleId: "r")
        var rng = SplitMix64(seed: 42)
        for i in 1...5 {
            stats.record(elapsedNs: UInt64(i * 1_000), fired: false,
                         eventTimestamp: Date(), reservoirSize: 8, rng: &rng)
        }
        #expect(stats.execSamplesNs.count == 5)
        #expect(stats.execSamplesNs == [1_000, 2_000, 3_000, 4_000, 5_000])
    }

    @Test("Counts are exact: evaluationCount / fireCount / totalExecNs / lastFiredAt")
    func countsAreExact() {
        var stats = RuleEngine.RuleStats(ruleId: "r")
        var rng = SplitMix64(seed: 7)
        let fireAt = Date(timeIntervalSince1970: 1_000_000)
        var expectedFires: UInt64 = 0
        var expectedTotal: UInt64 = 0
        var lastFire: Date?
        for i in 1...300 {
            let elapsed = UInt64(i)
            let fired = (i % 5 == 0)
            let ts = fired ? fireAt.addingTimeInterval(Double(i)) : Date.distantPast
            stats.record(elapsedNs: elapsed, fired: fired,
                         eventTimestamp: ts, reservoirSize: 256, rng: &rng)
            expectedTotal &+= elapsed
            if fired { expectedFires &+= 1; lastFire = ts }
        }
        #expect(stats.evaluationCount == 300)
        #expect(stats.fireCount == expectedFires)
        #expect(stats.totalExecNs == expectedTotal)
        #expect(stats.lastFiredAt == lastFire)
    }

    @Test("Recorded counts do NOT depend on the RNG seed (detection-exact)")
    func countsAreRNGIndependent() {
        func run(seed: UInt64) -> RuleEngine.RuleStats {
            var stats = RuleEngine.RuleStats(ruleId: "r")
            var rng = SplitMix64(seed: seed)
            for i in 1...500 {
                stats.record(elapsedNs: UInt64(i), fired: (i % 3 == 0),
                             eventTimestamp: Date(timeIntervalSince1970: Double(i)),
                             reservoirSize: 16, rng: &rng)
            }
            return stats
        }
        let a = run(seed: 111)
        let b = run(seed: 999)
        // Byte-identical counts regardless of which samples the reservoir kept.
        #expect(a.evaluationCount == b.evaluationCount)
        #expect(a.fireCount == b.fireCount)
        #expect(a.totalExecNs == b.totalExecNs)
        #expect(a.lastFiredAt == b.lastFiredAt)
        // Both reservoirs stay bounded and populated.
        #expect(a.execSamplesNs.count == 16)
        #expect(b.execSamplesNs.count == 16)
    }

    // MARK: - SplitMix64 (unit)

    @Test("SplitMix64 is deterministic per seed and produces varied output")
    func splitMix64Basic() {
        var a = SplitMix64(seed: 0xDEAD_BEEF)
        var b = SplitMix64(seed: 0xDEAD_BEEF)
        let seqA = (0..<8).map { _ in a.next() }
        let seqB = (0..<8).map { _ in b.next() }
        #expect(seqA == seqB)                       // same seed → same stream
        #expect(Set(seqA).count == seqA.count)      // no trivial repeats in 8 draws
        var c = SplitMix64(seed: 1)
        #expect(c.next() != 0)                       // not a degenerate all-zero generator
    }

    // MARK: - Engine hot path (integration): recordEvaluation via evaluate()

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

    @Test("evaluate() records exact eval/fire counts and a bounded reservoir")
    func engineRecordsExactCountsThroughModifySubscript() async throws {
        ensureRulesCompiled()
        let engine = RuleEngine()
        _ = try await engine.loadRules(from: URL(fileURLWithPath: "/tmp/maccrab_v3"))
        let nvram = "d1a2b3c4-0342-4000-a000-000000000342"

        let iterations = 10
        for _ in 0..<iterations { _ = await engine.evaluate(nvramEvent()) }

        let path = NSTemporaryDirectory() + "maccrab-tele-\(UUID().uuidString).json"
        defer { try? FileManager.default.removeItem(atPath: path) }
        await engine.writeTelemetrySnapshot(to: path)

        let snap = RuleEngine.readTelemetrySnapshot(at: path)
        let stat = snap?.stats.first { $0.ruleId == nvram }
        #expect(stat != nil, "the nvram rule should have telemetry after evaluate()")
        // Every process-category evaluation increments the count exactly once —
        // no COW path can drop or double-count.
        #expect(stat?.evaluationCount == UInt64(iterations))
        #expect(stat?.fireCount == UInt64(iterations))   // nvram fires every time
        // Reservoir populated and bounded (10 < 256, so all samples retained).
        #expect(stat?.execSamplesNs.count == iterations)
        #expect(stat?.execSamplesNs.isEmpty == false)
    }
}
