// V2InvestigationAgentEdgeStyleTests.swift
// MacCrabAppTests
//
// §11.3 honesty gate — VISUAL. The Investigation graph must not draw a
// low-/unknown-confidence `associated_with_agent` edge as SOLID (asserted) like
// a high-confidence one; below the assertion threshold it renders inferred
// (dashed + "suggested"). `agentEdgeIsInferred` is the decision EdgeOverlay
// keys on; it delegates to MacCrabCore's AIAttributionRenderer so it mirrors the
// prose gate exactly (asserted iff confidence >= threshold). These pin the gate.

import Testing
import Foundation
@testable import MacCrabApp

@Suite("V2InvestigationWorkspace.agentEdgeIsInferred (§11.3 visual gate)")
struct V2InvestigationAgentEdgeStyleTests {

    // Default policy threshold is 0.85 (TracePolicy.aiAttributionAssertionThreshold
    // / AIAttributionRenderer.defaultAssertionThreshold).

    @Test("unknown confidence ⇒ inferred (cannot assert what we don't have)")
    func nilConfidenceIsInferred() {
        #expect(V2InvestigationWorkspace.agentEdgeIsInferred(confidence: nil))
    }

    @Test("below the default threshold ⇒ inferred (dashed + suggested)")
    func belowThresholdIsInferred() {
        #expect(V2InvestigationWorkspace.agentEdgeIsInferred(confidence: 0.5))
        #expect(V2InvestigationWorkspace.agentEdgeIsInferred(confidence: 0.849))
    }

    @Test("at / above the default threshold ⇒ asserted (solid)")
    func atOrAboveThresholdIsAsserted() {
        #expect(!V2InvestigationWorkspace.agentEdgeIsInferred(confidence: 0.85))
        #expect(!V2InvestigationWorkspace.agentEdgeIsInferred(confidence: 0.99))
    }

    @Test("a policy override moves the solid/dashed boundary")
    func honorsCustomThreshold() {
        // Loosen the policy: 0.7 now clears the bar ⇒ asserted.
        #expect(!V2InvestigationWorkspace.agentEdgeIsInferred(confidence: 0.7, assertionThreshold: 0.6))
        // Tighten it: the same 0.7 now falls short ⇒ inferred.
        #expect(V2InvestigationWorkspace.agentEdgeIsInferred(confidence: 0.7, assertionThreshold: 0.8))
    }
}
