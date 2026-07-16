// AIAttributionRendererTests.swift
// v1.10 TraceGraph (PR-7) — enforces §11.3 of the spec: AI attribution
// below the assertion threshold MUST be rendered as inferred (dashed,
// "suggested", hedged prose) — never asserted as fact.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("TraceGraph: AIAttributionRenderer (§11.3)")
struct AIAttributionRendererTests {

    @Test("Confidence at default threshold (0.85) is asserted as fact")
    func atThresholdAsserted() {
        let r = AIAttributionRenderer.render(confidence: 0.85)
        #expect(r.assertedAsFact)
        #expect(r.edgeStyle == .solid)
        #expect(!r.showSuggestedLabel)
        #expect(r.phrasingTemplate == .factual)
    }

    @Test("Confidence below threshold is rendered as inferred")
    func belowThresholdInferred() {
        let r = AIAttributionRenderer.render(confidence: 0.84)
        #expect(!r.assertedAsFact)
        #expect(r.edgeStyle == .dashed)
        #expect(r.showSuggestedLabel)
        #expect(r.phrasingTemplate == .suggested)
    }

    @Test("Direct traceparent (1.0) is always asserted")
    func directTraceparentAsserted() {
        let r = AIAttributionRenderer.render(confidence: 1.0)
        #expect(r.assertedAsFact)
    }

    @Test("Lineage fallback (0.7) is rendered as inferred at default threshold")
    func lineageFallbackInferred() {
        let r = AIAttributionRenderer.render(confidence: 0.7)
        #expect(!r.assertedAsFact)
        #expect(r.edgeStyle == .dashed)
    }

    @Test("Custom assertion threshold from TracePolicy is honored")
    func customThreshold() {
        // Stricter policy: only assert at 0.95+.
        let r1 = AIAttributionRenderer.render(confidence: 0.92, assertionThreshold: 0.95)
        #expect(!r1.assertedAsFact)

        let r2 = AIAttributionRenderer.render(confidence: 0.96, assertionThreshold: 0.95)
        #expect(r2.assertedAsFact)
    }

    @Test("Factual sentence uses agent name directly")
    func factualSentence() {
        let s = AIAttributionRenderer.explainerSentence(
            agentName: "Claude Desktop",
            confidence: 0.95
        )
        // Per §11.3, MUST NOT phrase as "Claude Desktop launched ..."
        // (that's overclaiming when not factual). Factual phrasing is
        // OK for asserted edges.
        #expect(s.contains("Claude Desktop"))
        #expect(s.contains("associated with"))
    }

    @Test("Suggested sentence hedges with 'appears to involve' + 'Confidence: suggested'")
    func suggestedSentence() {
        // Per §11.3 prescribed phrasing.
        let s = AIAttributionRenderer.explainerSentence(
            agentName: "Cursor",
            confidence: 0.6
        )
        #expect(s.contains("Cursor"))
        #expect(s.contains("appears to involve"))
        #expect(s.contains("Confidence: suggested"))
        // Must NOT assert as fact.
        #expect(!s.contains("Cursor launched"))
    }

    @Test("Confidence-for-display always echoes input")
    func confidenceForDisplay() {
        for c in [0.0, 0.3, 0.7, 0.85, 1.0] {
            let r = AIAttributionRenderer.render(confidence: c)
            #expect(r.confidenceForDisplay == c)
        }
    }

    // MARK: - Severity-reason gate (v1.21.4 — consumed by TraceMaterializer)

    @Test("gatedSeverityReason softens an asserted AI-agent reason below threshold")
    func gateSoftensBelowThreshold() {
        let shell = AIAttributionRenderer.gatedSeverityReason(
            "AI-agent associated shell execution", confidence: 0.7
        )
        #expect(shell == "possible AI-agent shell execution (attribution inferred, not asserted)")
        #expect(!shell.contains(AIAttributionRenderer.assertedAgentReasonMarker))

        let activity = AIAttributionRenderer.gatedSeverityReason(
            "AI-agent associated activity", confidence: 0.1
        )
        #expect(activity == "possible AI-agent activity (attribution inferred, not asserted)")
    }

    @Test("gatedSeverityReason leaves an asserted reason untouched at/above threshold")
    func gateNoopAtOrAboveThreshold() {
        let reason = "AI-agent associated activity"
        #expect(AIAttributionRenderer.gatedSeverityReason(reason, confidence: 0.85) == reason)
        #expect(AIAttributionRenderer.gatedSeverityReason(reason, confidence: 0.99) == reason)
    }

    @Test("gatedSeverityReason ignores non-agent reasons even far below threshold")
    func gateIgnoresNonAgentReasons() {
        for reason in ["credential file access", "external network connection", "launch agent persistence"] {
            #expect(AIAttributionRenderer.gatedSeverityReason(reason, confidence: 0.01) == reason)
        }
    }

    @Test("gatedSeverityReason honors a custom (stricter) policy threshold")
    func gateCustomThreshold() {
        let reason = "AI-agent associated activity"
        // 0.9 clears the default 0.85 (untouched) …
        #expect(AIAttributionRenderer.gatedSeverityReason(reason, confidence: 0.9) == reason)
        // … but not a stricter 0.95 policy (softened).
        let softened = AIAttributionRenderer.gatedSeverityReason(
            reason, confidence: 0.9, assertionThreshold: 0.95
        )
        #expect(softened.contains("possible AI-agent activity"))
    }
}
