// LLMInvestigatorTests.swift
// Phase 4 agentic triage: parser coverage + one end-to-end integration
// test via a fake LLMBackend that returns canned JSON.

import Testing
import Foundation
@testable import MacCrabCore

// MARK: - Sample JSON fixtures

private let validInvestigationJSON = """
{
  "alertId": "alert-42",
  "confidence": 0.82,
  "verdict": "likely_malicious",
  "summary": "An unsigned binary launched from /tmp wrote a LaunchAgent plist and attempted outbound DNS to a freshly-registered domain. Multiple independent signals align with dropper behaviour.",
  "evidenceChain": [
    {"kind": "event", "id": "evt-1", "note": "exec of /tmp/stage from sshd descendant"},
    {"kind": "enrichment", "id": "sha256", "note": "binary hash matches MISP feed entry 0x1234"}
  ],
  "mitreReasoning": [
    {"tacticId": "TA0003", "techniqueId": "T1543.001", "reasoning": "LaunchAgent plist write is standard macOS persistence"}
  ],
  "suggestedActions": [
    {
      "kind": "quarantine",
      "title": "Quarantine the dropped binary",
      "rationale": "Hash matches known-bad feed; prevents further execution without data loss.",
      "d3fendRef": "D3-EHPV",
      "blastRadius": "low",
      "requiresConfirmation": true,
      "previewCommand": "mv /tmp/stage /var/quarantine/$(uuidgen).bin"
    },
    {
      "kind": "document",
      "title": "Attach MISP IoC reference to the alert",
      "rationale": "So the analyst can cross-reference.",
      "d3fendRef": null,
      "blastRadius": "low",
      "requiresConfirmation": false,
      "previewCommand": null
    }
  ],
  "confidencePenalties": [
    "Could not verify the destination domain's registration age within the 4k token window"
  ],
  "modelVersion": "claude-sonnet-4-6",
  "generatedAt": "2026-04-16T10:30:00Z"
}
"""

// MARK: - Mock backend

private actor FakeLLMBackend: LLMBackend {
    let providerName: String = "FakeLLM"
    var responses: [String]
    var callIndex: Int = 0

    init(responses: [String]) {
        self.responses = responses
    }

    func isAvailable() async -> Bool { true }

    func complete(
        systemPrompt: String,
        userPrompt: String,
        maxTokens: Int,
        temperature: Double
    ) async -> String? {
        guard callIndex < responses.count else { return nil }
        let r = responses[callIndex]
        callIndex += 1
        return r
    }
}

// MARK: - Parser suite

@Suite("LLMInvestigator parser")
struct LLMInvestigatorParserTests {

    @Test("Parses a well-formed investigation JSON")
    func parsesValid() {
        let result = LLMInvestigator.parse(
            response: validInvestigationJSON,
            alertId: "alert-42",
            fallbackModel: "claude-sonnet-4-6"
        )
        guard case let .ok(inv) = result else {
            Issue.record("Expected .ok, got \(result)")
            return
        }
        #expect(inv.alertId == "alert-42")
        #expect(inv.verdict == .likelyMalicious)
        #expect(inv.confidence == 0.82)
        #expect(inv.evidenceChain.count == 2)
        #expect(inv.suggestedActions.count == 2)
        #expect(inv.suggestedActions[0].kind == .quarantine)
        #expect(inv.suggestedActions[0].blastRadius == .low)
        #expect(inv.suggestedActions[0].requiresConfirmation == true)
        #expect(inv.suggestedActions[0].d3fendRef == "D3-EHPV")
        #expect(inv.suggestedActions[0].previewCommand?.contains("quarantine") == true)
    }

    @Test("Strips ```json code fences wrapper")
    func stripsCodeFences() {
        let wrapped = "```json\n" + validInvestigationJSON + "\n```"
        let result = LLMInvestigator.parse(
            response: wrapped, alertId: "alert-42", fallbackModel: "m"
        )
        guard case .ok = result else {
            Issue.record("Expected .ok after fence stripping")
            return
        }
    }

    @Test("Strips plain ``` fences")
    func stripsPlainFences() {
        let wrapped = "```\n" + validInvestigationJSON + "\n```"
        let result = LLMInvestigator.parse(
            response: wrapped, alertId: "alert-42", fallbackModel: "m"
        )
        guard case .ok = result else {
            Issue.record("Expected .ok after plain fence stripping")
            return
        }
    }

    @Test("Backfills alertId when model omits it")
    func backfillsAlertId() {
        // Rebuild JSON with an empty alertId
        let modified = validInvestigationJSON.replacingOccurrences(
            of: "\"alertId\": \"alert-42\"",
            with: "\"alertId\": \"\""
        )
        let result = LLMInvestigator.parse(
            response: modified, alertId: "injected-id", fallbackModel: "m"
        )
        guard case let .ok(inv) = result else {
            Issue.record("Expected .ok")
            return
        }
        #expect(inv.alertId == "injected-id")
    }

    @Test("Backfills modelVersion when empty")
    func backfillsModel() {
        let modified = validInvestigationJSON.replacingOccurrences(
            of: "\"modelVersion\": \"claude-sonnet-4-6\"",
            with: "\"modelVersion\": \"\""
        )
        let result = LLMInvestigator.parse(
            response: modified, alertId: "alert-42", fallbackModel: "fallback-model"
        )
        guard case let .ok(inv) = result else {
            Issue.record("Expected .ok")
            return
        }
        #expect(inv.modelVersion == "fallback-model")
    }

    @Test("Rejects malformed JSON with a reason")
    func rejectsMalformed() {
        let result = LLMInvestigator.parse(
            response: "this is not JSON { bad",
            alertId: "x", fallbackModel: "m"
        )
        guard case let .malformed(reason) = result else {
            Issue.record("Expected .malformed, got \(result)")
            return
        }
        #expect(!reason.isEmpty)
    }

    @Test("Rejects JSON missing required fields")
    func rejectsIncomplete() {
        let incomplete = "{\"verdict\": \"likely_benign\"}"
        let result = LLMInvestigator.parse(
            response: incomplete, alertId: "x", fallbackModel: "m"
        )
        guard case .malformed = result else {
            Issue.record("Expected .malformed for incomplete JSON")
            return
        }
    }

    @Test("Unknown verdict string → malformed")
    func rejectsUnknownVerdict() {
        let bad = validInvestigationJSON.replacingOccurrences(
            of: "\"likely_malicious\"",
            with: "\"vibes_bad\""
        )
        let result = LLMInvestigator.parse(
            response: bad, alertId: "alert-42", fallbackModel: "m"
        )
        guard case .malformed = result else {
            Issue.record("Expected .malformed for unknown verdict")
            return
        }
    }
}

// MARK: - End-to-end suite (mock backend)

@Suite("LLMInvestigator end-to-end")
struct LLMInvestigatorE2ETests {

    private func makeAlert() -> Alert {
        Alert(
            id: "alert-42",
            ruleId: "maccrab.test.rule",
            ruleTitle: "Test rule",
            severity: .high,
            eventId: "evt-1",
            processPath: "/tmp/stage",
            processName: "stage",
            description: "Suspicious activity",
            mitreTactics: "TA0003",
            mitreTechniques: "T1543.001"
        )
    }

    @Test("investigate returns parsed LLMInvestigation on valid response")
    func endToEndValid() async {
        let backend = FakeLLMBackend(responses: [validInvestigationJSON])
        let service = LLMService(backend: backend, config: LLMConfig())
        let alert = makeAlert()

        let result = await service.investigate(alert: alert)
        let inv = try? #require(result)
        #expect(inv?.alertId == "alert-42")
        #expect(inv?.verdict == .likelyMalicious)
        #expect(inv?.suggestedActions.count == 2)
    }

    @Test("investigate returns nil when backend returns nil")
    func endToEndBackendFail() async {
        let backend = FakeLLMBackend(responses: [])  // empty → both calls nil
        let service = LLMService(backend: backend, config: LLMConfig())
        let alert = makeAlert()

        let result = await service.investigate(alert: alert)
        #expect(result == nil)
    }
}
