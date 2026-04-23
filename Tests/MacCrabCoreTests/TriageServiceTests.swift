// TriageServiceTests.swift
//
// Coverage for the v1.6.6 Triage Auto-Disposition feature. The actual
// LLM round-trip is exercised by the integration tests; here we lock
// the prompt shape and the response-parsing logic, which is the source
// of most subtle bugs when models wander off-format.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("TriageService: prompt assembly")
struct TriagePromptTests {

    private func fixtureAlert() -> Alert {
        Alert(
            id: "a1", timestamp: Date(),
            ruleId: "csrutil_status", ruleTitle: "SIP Status Queried via csrutil",
            severity: .low, eventId: "e1",
            processPath: "/usr/bin/csrutil", processName: "csrutil",
            description: "CommandLine: csrutil status",
            mitreTactics: "TA0007",
            mitreTechniques: "T1518.001",
            suppressed: false
        )
    }

    @Test("All four disposition labels appear in the system prompt")
    func systemPromptListsLabels() {
        let (system, _) = TriageService.buildPrompt(alert: fixtureAlert(), similarCount: 1, dailyTotal: nil)
        for label in TriageDisposition.allCases {
            #expect(system.contains(label.rawValue), "System prompt must name the \(label.rawValue) disposition")
        }
    }

    @Test("User prompt carries rule title + process + MITRE data")
    func userPromptCarriesFacts() {
        let (_, user) = TriageService.buildPrompt(alert: fixtureAlert(), similarCount: 1, dailyTotal: nil)
        #expect(user.contains("SIP Status Queried via csrutil"))
        #expect(user.contains("csrutil"))
        #expect(user.contains("TA0007"))
        #expect(user.contains("T1518.001"))
    }

    @Test("similarCount appears so the model can weigh recurrence")
    func similarCountIncluded() {
        let (_, user) = TriageService.buildPrompt(alert: fixtureAlert(), similarCount: 42, dailyTotal: nil)
        #expect(user.contains("42"))
    }

    @Test("dailyTotal included when provided, omitted when nil")
    func dailyTotalOptional() {
        let (_, withTotal) = TriageService.buildPrompt(alert: fixtureAlert(), similarCount: 1, dailyTotal: 128)
        let (_, withoutTotal) = TriageService.buildPrompt(alert: fixtureAlert(), similarCount: 1, dailyTotal: nil)
        #expect(withTotal.contains("128"))
        #expect(withTotal.lowercased().contains("prior 24h"))
        #expect(!withoutTotal.lowercased().contains("prior 24h"))
    }
}

@Suite("TriageService: response parsing")
struct TriageParsingTests {

    @Test("Well-formed response parses disposition and reason")
    func wellFormed() {
        let r = TriageService.parse(response: """
        DISPOSITION: suppress
        REASON: csrutil status from interactive terminal, low-risk admin workflow.
        """)
        #expect(r.disposition == .suppress)
        #expect(r.rationale.contains("interactive terminal"))
    }

    @Test("Case insensitive disposition header")
    func caseInsensitive() {
        let r = TriageService.parse(response: """
        disposition: escalate
        reason: unsigned process writing to system LaunchDaemons.
        """)
        #expect(r.disposition == .escalate)
    }

    @Test("Markdown bullets tolerated on the disposition line")
    func markdownOnDisposition() {
        let r = TriageService.parse(response: """
        **DISPOSITION:** keep
        **REASON:** Process is developer-signed but unusual path.
        """)
        #expect(r.disposition == .keep)
        #expect(r.rationale.contains("developer-signed"))
    }

    @Test("Off-format response with a bare label as first word")
    func fallbackFirstWord() {
        let r = TriageService.parse(response: "escalate — this is clear ransomware behavior.")
        #expect(r.disposition == .escalate)
        #expect(r.rationale.lowercased().contains("ransomware"))
    }

    @Test("Completely off-script response lands on inconclusive")
    func offScriptInconclusive() {
        let r = TriageService.parse(response: "I would need more context to make a determination here.")
        #expect(r.disposition == .inconclusive)
    }

    @Test("Long rationale is truncated with ellipsis")
    func rationaleTruncation() {
        let long = String(repeating: "word ", count: 100)  // ~500 chars
        let r = TriageService.parse(response: """
        DISPOSITION: keep
        REASON: \(long)
        """)
        #expect(r.disposition == .keep)
        #expect(r.rationale.count <= 241, "Rationale must be capped — got \(r.rationale.count) chars")
        #expect(r.rationale.hasSuffix("…"))
    }

    @Test("Empty response → inconclusive with empty rationale passthrough")
    func empty() {
        let r = TriageService.parse(response: "")
        #expect(r.disposition == .inconclusive)
    }

    @Test("All four labels survive round-trip through the parser")
    func allLabelsRoundTrip() {
        for label in TriageDisposition.allCases where label != .inconclusive {
            let r = TriageService.parse(response: "DISPOSITION: \(label.rawValue)\nREASON: test.")
            #expect(r.disposition == label, "Label \(label.rawValue) must round-trip")
        }
    }
}
