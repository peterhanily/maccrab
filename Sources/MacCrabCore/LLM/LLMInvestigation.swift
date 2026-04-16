// LLMInvestigation.swift
// MacCrabCore
//
// Structured output schema for agentic LLM alert triage (Phase 4).
// The LLM is asked to return JSON matching this shape; anything else is
// retried once and then degraded to a freeform summary so upstream
// callers always get a well-typed answer — no string parsing required.
//
// Every Alert can carry an optional LLMInvestigation. The Phase 1
// foundation added the field; this file defines the rich schema it
// points at.

import Foundation

// MARK: - LLMInvestigation

public struct LLMInvestigation: Codable, Sendable, Hashable {

    /// The alert this investigation analyzed. Same as Alert.id.
    public let alertId: String

    /// Calibrated probability the alert is a true positive (0.0–1.0).
    /// The LLM is instructed to err on the side of caution — high
    /// confidence requires multiple independent signals.
    public let confidence: Double

    /// Top-line assessment.
    public let verdict: Verdict

    /// 2-4 sentence analyst-facing summary of what happened and why it
    /// matters. No markdown, no code blocks.
    public let summary: String

    /// Ordered citations the LLM consulted, earliest-first. Each
    /// evidence item references an Event or Alert the LLM actually
    /// looked at — keeps the assessment auditable.
    public let evidenceChain: [Evidence]

    /// MITRE ATT&CK mappings the LLM inferred (may extend beyond what
    /// the detection rule itself tagged).
    public let mitreReasoning: [MITREMap]

    /// Actions the LLM suggests. Every action carries a D3FEND reference,
    /// blast-radius classification, and a requires_confirmation flag.
    /// Nothing auto-executes — the UI preview and confirm each action.
    public let suggestedActions: [SuggestedAction]

    /// Self-notes from the LLM about where it's uncertain. Displayed
    /// alongside the summary so analysts know what the model flagged
    /// as weak evidence.
    public let confidencePenalties: [String]

    /// Model + version string that produced this output (e.g.
    /// "claude-sonnet-4-6", "llama3.1:8b", "gpt-4o-2026-04").
    public let modelVersion: String

    /// When the analysis was generated.
    public let generatedAt: Date

    public init(
        alertId: String,
        confidence: Double,
        verdict: Verdict,
        summary: String,
        evidenceChain: [Evidence] = [],
        mitreReasoning: [MITREMap] = [],
        suggestedActions: [SuggestedAction] = [],
        confidencePenalties: [String] = [],
        modelVersion: String,
        generatedAt: Date = Date()
    ) {
        self.alertId = alertId
        self.confidence = confidence
        self.verdict = verdict
        self.summary = summary
        self.evidenceChain = evidenceChain
        self.mitreReasoning = mitreReasoning
        self.suggestedActions = suggestedActions
        self.confidencePenalties = confidencePenalties
        self.modelVersion = modelVersion
        self.generatedAt = generatedAt
    }
}

// MARK: - Verdict

/// Top-level LLM assessment. Values chosen so humans can filter alert
/// queues on verdict without reading the summary for every row.
public enum Verdict: String, Codable, Sendable, Hashable, CaseIterable {
    /// Strong evidence of malicious activity — elevate immediately.
    case likelyMalicious       = "likely_malicious"
    /// Most likely benign — candidate for auto-suppression after review.
    case likelyBenign          = "likely_benign"
    /// Evidence is mixed; a human analyst should decide.
    case needsHuman            = "needs_human"
    /// Not enough context to assess. Often means the LLM lacks
    /// nearest-neighbor event history or a relevant threat-intel feed.
    case insufficientEvidence  = "insufficient_evidence"
}

// MARK: - Evidence

/// Single citation in the evidence chain. References either an Event or
/// Alert that was part of the LLM's reasoning input.
public struct Evidence: Codable, Sendable, Hashable {
    public enum Kind: String, Codable, Sendable {
        case event, alert, enrichment, threatIntel = "threat_intel"
    }
    public let kind: Kind
    public let id: String           // Event UUID, Alert id, or arbitrary ref
    public let note: String         // one-line reason this piece matters

    public init(kind: Kind, id: String, note: String) {
        self.kind = kind
        self.id = id
        self.note = note
    }
}

// MARK: - MITREMap

public struct MITREMap: Codable, Sendable, Hashable {
    public let tacticId: String?        // e.g. "TA0005"
    public let techniqueId: String?     // e.g. "T1562.001"
    public let reasoning: String        // why the LLM believes this applies

    public init(tacticId: String? = nil, techniqueId: String? = nil, reasoning: String) {
        self.tacticId = tacticId
        self.techniqueId = techniqueId
        self.reasoning = reasoning
    }
}

// MARK: - SuggestedAction

/// An action the LLM recommends. The UI (Phase 4 follow-up) renders
/// these with Preview / Confirm / Dismiss controls — NEVER auto-executes.
public struct SuggestedAction: Codable, Sendable, Hashable {

    public enum Kind: String, Codable, Sendable, CaseIterable {
        /// Silently document for later (adds a note, no mutation).
        case document
        /// Allowlist the alert (rule+path or broader scope).
        case suppress
        /// Quarantine the offending file into a safe holding pen.
        case quarantine
        /// Block a network destination at the DNS sinkhole or firewall.
        case blockNetwork = "block_network"
        /// Kill or contain the offending process.
        case containProcess = "contain_process"
        /// Revoke a TCC permission.
        case revokeTCC = "revoke_tcc"
        /// Rotate a potentially compromised credential.
        case rotateCredential = "rotate_credential"
        /// Escalate to a human — page oncall / open a ticket.
        case escalate
    }

    public enum BlastRadius: String, Codable, Sendable, CaseIterable {
        case low      // no service impact, reversible
        case medium   // possible brief disruption
        case high     // user-visible impact, destructive if wrong
    }

    public let kind: Kind
    public let title: String                // short action label
    public let rationale: String            // why the LLM thinks this is right
    public let d3fendRef: String?           // e.g. "D3-PL" (Process Lockout)
    public let blastRadius: BlastRadius
    public let requiresConfirmation: Bool   // every destructive action → true
    /// Exact command or payload that would run. Empty string for
    /// document/escalate. Surfaced in the UI preview before confirmation.
    public let previewCommand: String?

    public init(
        kind: Kind,
        title: String,
        rationale: String,
        d3fendRef: String? = nil,
        blastRadius: BlastRadius,
        requiresConfirmation: Bool = true,
        previewCommand: String? = nil
    ) {
        self.kind = kind
        self.title = title
        self.rationale = rationale
        self.d3fendRef = d3fendRef
        self.blastRadius = blastRadius
        self.requiresConfirmation = requiresConfirmation
        self.previewCommand = previewCommand
    }
}
