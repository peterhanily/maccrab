// AIAttributionRenderer.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-7) — enforces §11.3 of the v1.10.0 spec:
//
//   "Any associated_with_agent edge with confidence below 0.85 is
//    rendered in the UI as inferred: dashed line, 'suggested' label,
//    confidence shown, not asserted as fact in deterministic
//    explainer prose."
//
// AI attribution carries unique reputational risk — a false attribution
// to "Claude Desktop", "Claude Code", "Cursor", or "Codex" damages
// trust in both MacCrab and the named vendor. So the threshold rule
// is enforced in code, not as a styling preference: every callsite
// that surfaces an AI-attribution edge consults this renderer.
//
// The 0.85 threshold default lives in `TracePolicy.aiAttributionAssertionThreshold`
// (PR-15.10); callers pass the active threshold here so a policy
// override propagates correctly. The default constant below matches
// §11.3 for direct callers that don't have a policy in hand.

import Foundation

public enum AIAttributionRenderer {

    /// Default assertion threshold per §11.3. Overridable via
    /// `TracePolicy.aiAttributionAssertionThreshold`.
    public static let defaultAssertionThreshold: Double = 0.85

    /// How an AI-attribution edge should be presented to the user.
    public struct Rendering: Sendable, Equatable {

        /// True iff confidence is at or above the assertion threshold.
        /// When true, the explainer may state the agent involvement as
        /// a fact ("Claude Desktop launched this process"). When false,
        /// the explainer must hedge ("appears to involve Claude Desktop
        /// based on temporal proximity and process lineage").
        public let assertedAsFact: Bool

        /// UI styling hint: solid edge when asserted, dashed when inferred.
        public let edgeStyle: EdgeStyle

        /// True when the UI should show the "suggested" label next to
        /// the agent name.
        public let showSuggestedLabel: Bool

        /// The confidence value to display in the UI tooltip.
        public let confidenceForDisplay: Double

        /// The phrasing template the explainer should use for the
        /// natural-language sentence describing this attribution.
        public let phrasingTemplate: PhrasingTemplate

        public enum EdgeStyle: String, Sendable, Equatable {
            case solid           // assertedAsFact == true
            case dashed          // assertedAsFact == false (inferred)
        }

        public enum PhrasingTemplate: String, Sendable, Equatable {
            /// "Claude Desktop launched this process."
            case factual
            /// "This trace appears to involve Claude Desktop based on
            /// temporal proximity and process lineage. Confidence: suggested."
            case suggested
        }
    }

    /// Decide how to render an AI-attribution edge for a given
    /// `confidence` value, using the supplied `assertionThreshold`
    /// (caller pulls this from `TracePolicy`).
    public static func render(
        confidence: Double,
        assertionThreshold: Double = AIAttributionRenderer.defaultAssertionThreshold
    ) -> Rendering {
        let asserted = confidence >= assertionThreshold
        return Rendering(
            assertedAsFact: asserted,
            edgeStyle: asserted ? .solid : .dashed,
            showSuggestedLabel: !asserted,
            confidenceForDisplay: confidence,
            phrasingTemplate: asserted ? .factual : .suggested
        )
    }

    /// Generate the natural-language explainer sentence for an
    /// AI-attribution edge. Uses `agentName` for the subject and
    /// the confidence-driven template above.
    public static func explainerSentence(
        agentName: String,
        confidence: Double,
        assertionThreshold: Double = AIAttributionRenderer.defaultAssertionThreshold
    ) -> String {
        let rendering = render(confidence: confidence, assertionThreshold: assertionThreshold)
        switch rendering.phrasingTemplate {
        case .factual:
            return "\(agentName) is associated with this process."
        case .suggested:
            return "This trace appears to involve \(agentName) based on temporal proximity and process lineage. Confidence: suggested."
        }
    }
}
