// LLMEvalTests.swift
// Minimal LLM evaluation harness. Loads labeled fixtures from
// Tests/MacCrabCoreTests/LLMEvalFixtures/*.json and scores verdict
// accuracy. Uses a deterministic MockLLMBackend for CI runs so the
// harness can gate on regressions without cloud API calls.
//
// To run against a real backend, set MACCRAB_EVAL_BACKEND=claude (or
// ollama, openai) with the appropriate API-key env. The real-backend
// variant is opt-in and skipped in the default CI matrix.

import Testing
import Foundation
@testable import MacCrabCore

// MARK: - Fixture

private struct EvalFixture: Codable {
    let label: String
    let alert: AlertDoc
    let expectedVerdict: String
    let description: String

    struct AlertDoc: Codable {
        let id: String
        let ruleId: String
        let ruleTitle: String
        let severity: String
        let processPath: String
        let processName: String
        let description: String
        let mitreTactics: String
        let mitreTechniques: String
    }

    func asAlert() -> Alert {
        Alert(
            id: alert.id,
            ruleId: alert.ruleId,
            ruleTitle: alert.ruleTitle,
            severity: Severity(rawValue: alert.severity) ?? .medium,
            eventId: UUID().uuidString,
            processPath: alert.processPath,
            processName: alert.processName,
            description: alert.description,
            mitreTactics: alert.mitreTactics,
            mitreTechniques: alert.mitreTechniques
        )
    }
}

// MARK: - Deterministic mock backend

/// Maps alert ruleId → expected verdict. Lets the harness exercise the
/// full parse + retry path without network I/O. Swap for a real
/// backend in opt-in evaluation runs.
private actor DeterministicBackend: LLMBackend {
    let providerName = "deterministic-mock"
    private let responses: [String: Verdict]

    init(responses: [String: Verdict]) {
        self.responses = responses
    }

    func isAvailable() async -> Bool { true }

    func complete(
        systemPrompt: String, userPrompt: String,
        maxTokens: Int, temperature: Double
    ) async -> String? {
        // Parse the same bounded JSON envelope the real backend receives.
        // The old YAML-line scrape silently stopped finding `rule_id` when
        // the production prompt moved to JSON, leaving this evaluation rail
        // at 0% without testing the parser contract it claimed to exercise.
        let marker = "UNTRUSTED_ALERT_CONTEXT_JSON:\n"
        guard let markerRange = userPrompt.range(of: marker) else { return nil }
        let remainder = userPrompt[markerRange.upperBound...]
        guard let jsonLine = remainder.split(separator: "\n").first,
              let data = String(jsonLine).data(using: .utf8),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let alert = root["alert"] as? [String: Any],
              let ruleId = alert["rule_id"] as? String,
              let alertId = alert["id"] as? String else {
            return nil
        }
        let verdict = responses[ruleId]?.rawValue ?? "insufficient_evidence"

        // Keep the canned response valid under the current grounding
        // boundary: identity must match the requested alert and at least one
        // supplied evidence item must be cited. Provenance fields are stamped
        // locally by LLMInvestigator and therefore are intentionally omitted.
        let payload: [String: Any] = [
            "alertId": alertId,
            "confidence": 0.75,
            "verdict": verdict,
            "summary": "Deterministic evaluation fixture verdict.",
            "evidenceChain": [[
                "kind": "alert",
                "id": alertId,
                "note": "Alert supplied to the deterministic evaluation fixture",
            ]],
            "mitreReasoning": [],
            "suggestedActions": [],
            "confidencePenalties": [],
        ]
        guard JSONSerialization.isValidJSONObject(payload),
              let response = try? JSONSerialization.data(withJSONObject: payload),
              let encoded = String(data: response, encoding: .utf8) else {
            return nil
        }
        return encoded
    }
}

// MARK: - Suite

@Suite("LLM eval harness")
struct LLMEvalTests {

    /// Locate the LLMEvalFixtures directory relative to this test file.
    private func fixturesDir() -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("LLMEvalFixtures")
    }

    private func loadFixtures() throws -> [EvalFixture] {
        let dir = fixturesDir()
        let fm = FileManager.default
        guard let entries = try? fm.contentsOfDirectory(atPath: dir.path) else {
            return []
        }
        return try entries
            .filter { $0.hasSuffix(".json") }
            .map { dir.appendingPathComponent($0) }
            .map { try Data(contentsOf: $0) }
            .map { try JSONDecoder().decode(EvalFixture.self, from: $0) }
    }

    @Test("Fixture directory is populated")
    func fixturesExist() throws {
        let fixtures = try loadFixtures()
        #expect(!fixtures.isEmpty,
                "LLMEvalFixtures should contain at least one labeled case")
    }

    @Test("Deterministic backend scores 100% on its own canned responses")
    func deterministicBackend() async throws {
        let fixtures = try loadFixtures()
        guard !fixtures.isEmpty else { return }

        let responses = Dictionary(uniqueKeysWithValues: fixtures.compactMap { f -> (String, Verdict)? in
            guard let v = Verdict(rawValue: f.expectedVerdict) else { return nil }
            return (f.alert.ruleId, v)
        })

        let backend = DeterministicBackend(responses: responses)
        let service = LLMService(
            backend: backend,
            config: LLMConfig(),
            minInterval: 0
        )

        var correct = 0
        for f in fixtures {
            let alert = f.asAlert()
            let inv = await service.investigate(alert: alert)
            if inv?.verdict.rawValue == f.expectedVerdict {
                correct += 1
            }
        }
        let accuracy = Double(correct) / Double(fixtures.count)
        #expect(accuracy == 1.0,
                "Deterministic backend must score 100% on its own labels (got \(accuracy))")
    }

    @Test("Accuracy calculation produces precision ≥ 66% on sample fixtures")
    func accuracyCalculation() async throws {
        let fixtures = try loadFixtures()
        guard fixtures.count >= 3 else { return }

        // Build a backend that gets the first 2/3 right and misses the rest.
        var responses: [String: Verdict] = [:]
        for (i, f) in fixtures.enumerated() {
            let v: Verdict = (i < (fixtures.count * 2 / 3))
                ? (Verdict(rawValue: f.expectedVerdict) ?? .insufficientEvidence)
                : .insufficientEvidence  // deliberately wrong for the remainder
            responses[f.alert.ruleId] = v
        }
        let backend = DeterministicBackend(responses: responses)
        let service = LLMService(
            backend: backend,
            config: LLMConfig(),
            minInterval: 0
        )

        var correct = 0
        for f in fixtures {
            let alert = f.asAlert()
            let inv = await service.investigate(alert: alert)
            if inv?.verdict.rawValue == f.expectedVerdict {
                correct += 1
            }
        }
        let accuracy = Double(correct) / Double(fixtures.count)
        #expect(accuracy >= 0.66 || accuracy >= (2.0 / 3.0) - 0.01)
    }
}
