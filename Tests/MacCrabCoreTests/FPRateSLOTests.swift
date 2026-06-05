// FPRateSLOTests.swift
// v1.18 — the false-positive-RATE SLO gate. A committed corpus of BENIGN-but-
// rule-firing activity on trusted subjects (the dev-machine noise the v1.18
// recalibration + suppressible decouple + Gate 8 are meant to silence) is
// replayed through the REAL detection stack (RuleEngine.evaluate → NoiseFilter)
// and the post-suppression survivor count is asserted under a committed budget,
// with ZERO unsuppressed criticals (exercising the old critical-bypass path).
//
// This turns "we cut the noise" from a claim into a regression-gated number: if
// a future change re-breaks suppression (e.g. re-couples severity to the gates,
// or weakens a trust gate), the survivor count rises and this test fails.
//
// The corpus (fixtures/fp_corpus.json) is the seed; grow it from real sanitized
// idle telemetry to tighten the budget over time.

import Testing
import Foundation
@testable import MacCrabCore

struct FPCorpusEvent: Codable {
    let name: String
    let executable: String
    let commandLine: String
    var signer: String?        // "apple" | "devId" | "unsigned"
    var notarized: Bool?
    var platform: Bool?
    var parentExec: String?
}

@Suite("FP-rate SLO: benign corpus stays under budget (v1.18)")
struct FPRateSLOTests {

    /// Total surviving alerts allowed across the whole benign corpus. The corpus
    /// is designed to fully suppress (trusted subjects + suppressible rules), so
    /// the real target is 0; the small budget is regression headroom. Ratchet it
    /// down as the corpus grows.
    static let budget = 3

    private func signerType(_ s: String?) -> SignerType? {
        switch s {
        case "apple": return .apple
        case "devId": return .devId
        case "unsigned": return .unsigned
        default: return nil
        }
    }

    private func event(_ f: FPCorpusEvent) -> Event {
        let sig: CodeSignatureInfo? = signerType(f.signer).map {
            CodeSignatureInfo(signerType: $0, teamId: nil, signingId: nil, authorities: [],
                              flags: 0, isNotarized: f.notarized ?? false, issuerChain: nil,
                              certHashes: nil, isAdhocSigned: nil, entitlements: nil)
        }
        let p = MacCrabCore.ProcessInfo(
            pid: 4321, ppid: 1, rpid: 1, name: (f.executable as NSString).lastPathComponent,
            executable: f.executable, commandLine: f.commandLine, args: [f.executable],
            workingDirectory: "/tmp", userId: 501, userName: "t", groupId: 20, startTime: Date(),
            codeSignature: sig,
            ancestors: [ProcessAncestor(pid: 1, executable: f.parentExec ?? "/bin/zsh", name: "parent")],
            architecture: "arm64", isPlatformBinary: f.platform ?? false)
        return Event(eventCategory: .process, eventType: .start, eventAction: "exec", process: p)
    }

    @Test("the benign corpus produces no more than the budget of surviving alerts, and zero unsuppressed criticals")
    func corpusUnderBudget() async throws {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().appendingPathComponent("fixtures/fp_corpus.json")
        let corpus = try JSONDecoder().decode([FPCorpusEvent].self, from: Data(contentsOf: url))
        #expect(corpus.count >= 10, "FP corpus should be seeded (got \(corpus.count))")

        ensureRulesCompiled()
        let engine = RuleEngine()
        _ = try await engine.loadRules(from: URL(fileURLWithPath: "/tmp/maccrab_v3"))

        var survivors: [(name: String, rule: RuleMatch)] = []
        for f in corpus {
            let ev = event(f)
            var matches = await engine.evaluate(ev)
            NoiseFilter.apply(&matches, event: ev, isWarmingUp: false)
            for m in matches { survivors.append((f.name, m)) }
        }

        let criticals = survivors.filter { $0.rule.severity == .critical }
        // Diagnostic detail on any survivor so a failure is actionable.
        let detail = survivors.map { "[\($0.rule.severity)] \($0.rule.ruleName) on '\($0.name)'" }.joined(separator: "; ")

        #expect(criticals.isEmpty,
                "a benign event on a trusted subject must never produce an unsuppressed CRITICAL (the old bypass path): \(criticals.map { $0.rule.ruleName })")
        #expect(survivors.count <= Self.budget,
                "benign corpus produced \(survivors.count) surviving alerts (budget \(Self.budget)): \(detail)")
    }
}
