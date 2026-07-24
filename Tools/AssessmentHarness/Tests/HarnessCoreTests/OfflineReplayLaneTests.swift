// OfflineReplayLaneTests.swift
// assessment-framework (P1, revised in v1.21.5-rc.3): pins the Lane-1 vertical
// slice AFTER the fidelity fix. The corpus now drives the post-shell-parse ARGV
// the sensor actually emits (commandLine = args.joined), and the held-out split
// contains genuine behavioral-layer MISSES, so the measured score is HONEST —
// not the tautological all-1.0 the mother-of-all-audits flagged as a false-green.

import Testing
import Foundation
@testable import HarnessCore

@Suite("Assessment P1: offline replay (T1059.004 reverse shell)")
struct OfflineReplayLaneTests {

    // Ground truth derived from Corpora.reverseShell (v1.21.5-rc.3):
    //   visible positives      = 5  (all fire → recall 1.0)
    //   held-out positives     = 14 (12 caught via generalization, 2 honest misses)
    //   negatives              = 17 (none fire → precision 1.0)
    private let expectedTP = 17          // 5 visible + 12 held-out catches
    private let expectedFN = 2           // 2 held-out behavioral-layer misses
    private let expectedHeldOutRecall = 12.0 / 14.0   // ≈ 0.857 — HONEST, < 1.0
    private let expectedObfCoverage = 17.0 / 19.0     // 17 of 19 representations

    @Test("Reverse-shell rule scores HONESTLY on the faithful corpus (held-out recall < 1.0)")
    func honestScore() async throws {
        let score = try await OfflineReplayLane().run(corpus: Corpora.reverseShell)
        #expect(score.tp == expectedTP)
        #expect(score.fp == 0)
        #expect(score.fn == expectedFN)
        #expect(score.precision == 1.0)                 // no benign near-miss fires
        #expect(score.recall == 1.0)                    // every visible variant fires
        // The anti-false-green property: held-out recall is a real fraction < 1.0
        // because the corpus contains representations no command-line rule can see.
        #expect(score.heldOutRecall == expectedHeldOutRecall)
        #expect((score.heldOutRecall ?? 1.0) < 1.0, "held-out recall must be < 1.0 — the corpus MUST be able to miss")
        #expect((score.heldOutRecall ?? 0.0) > 0.80, "the hardened rule should still clear the generalization bar")
        #expect(score.obfuscationCoverage == expectedObfCoverage)
        #expect(score.metadataComplete == true)
    }

    @Test("The corpus can DISCRIMINATE: it contains both held-out catches and honest misses")
    func corpusIsHonestNotTautological() {
        let heldOut = Corpora.reverseShell.samples.filter { $0.malicious && $0.heldOut }
        #expect(heldOut.count >= 10, "a meaningful generalization test needs several held-out variants")
        // At least one documented behavioral-layer miss must exist, or held-out
        // recall could never be < 1.0 and the axis would be theater again.
        let documentedMisses = heldOut.filter {
            $0.representation == "base64-piped" || $0.representation == "script-file-delivery"
        }
        #expect(documentedMisses.count == 2, "the two documented behavioral-layer misses must be present")
        // Held-out representations are disjoint from the visible (enumerated) set —
        // held-out must not merely re-list what the author trained on.
        let visibleReps = Set(Corpora.reverseShell.samples.filter { $0.malicious && !$0.heldOut }.map(\.representation))
        let heldOutReps = Set(heldOut.map(\.representation))
        #expect(visibleReps.isDisjoint(with: heldOutReps))
    }

    @Test("Event construction is faithful to ESCollector: commandLine == argv.joined, no spurious quotes")
    func eventReconstructionFidelity() {
        // A python payload delivered directly: the sensor sees argv with the outer
        // quotes already stripped, so the event's commandLine has NO `'` after `-c`.
        let argv = ["python3", "-c", "import os,socket,subprocess;s=socket.socket()"]
        let ev = OfflineReplayLane.processCreationEvent(argv: argv)
        #expect(ev.process.commandLine == "python3 -c import os,socket,subprocess;s=socket.socket()")
        #expect(!ev.process.commandLine.contains("-c '"), "a live event never carries the stripped outer quote")
        #expect(ev.process.args == argv)
        #expect(ev.eventCategory == .process && ev.eventType == .creation)
    }

    @Test("Run is deterministic — identical measured score across two runs")
    func determinism() async throws {
        let lane = OfflineReplayLane()
        let a = try await lane.run(corpus: Corpora.reverseShell)
        let b = try await lane.run(corpus: Corpora.reverseShell)
        #expect(a.precision == b.precision)
        #expect(a.recall == b.recall)
        #expect(a.heldOutRecall == b.heldOutRecall)
        #expect(a.obfuscationCoverage == b.obfuscationCoverage)
        #expect(a.tp == b.tp && a.fp == b.fp && a.fn == b.fn)
    }

    @Test("Precision oracle passes the honest score under default thresholds")
    func oraclePass() async throws {
        let score = try await OfflineReplayLane().run(corpus: Corpora.reverseShell)
        let r = PrecisionOracle().decide(observed: score,
                                         expected: .init(technique: "T1059.004"),
                                         thresholds: .default)
        #expect(r.verdict == .pass, "reasons: \(r.reasons)")
    }

    @Test("Oracle returns inconclusive when a gated axis is unmeasured")
    func oracleInconclusive() throws {
        let score = DetectionScore(precision: 1.0, obfuscationCoverage: 1.0)
        let r = PrecisionOracle().decide(observed: score,
                                         expected: .init(technique: "T1059.004"),
                                         thresholds: .default)
        #expect(r.verdict == .inconclusive)
    }

    @Test("Oracle fails a weak score")
    func oracleFail() throws {
        let score = DetectionScore(precision: 0.4, recall: 1.0, heldOutRecall: 0.2,
                                   obfuscationCoverage: 0.3)
        let r = PrecisionOracle().decide(observed: score,
                                         expected: .init(technique: "T1059.004"),
                                         thresholds: .default)
        #expect(r.verdict == .fail)
    }
}
