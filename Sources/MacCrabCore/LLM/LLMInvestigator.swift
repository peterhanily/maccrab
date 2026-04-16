// LLMInvestigator.swift
// MacCrabCore
//
// Phase 4 agentic triage: asks the configured LLM backend to produce a
// structured LLMInvestigation for an alert. The model is given a rigid
// JSON schema and a low-temperature prompt that emphasises evidence
// citation and human-in-the-loop confirmation for every destructive
// suggested action. Nothing auto-executes from this module — it only
// produces advisory output.

import Foundation
import os.log

// MARK: - Parse result

/// Outcome of parsing a raw LLM response into LLMInvestigation.
public enum InvestigationParseResult: Sendable {
    case ok(LLMInvestigation)
    case malformed(reason: String)
}

// MARK: - Prompt builder

extension LLMPrompts {

    public static let alertInvestigationSystem = """
        You are a macOS SOC analyst triaging a single alert. Produce ONLY
        a JSON object matching this schema — no prose, no markdown, no
        code fences, nothing else.

        {
          "alertId": "<the alert id given>",
          "confidence": <float 0.0-1.0 — probability of true positive>,
          "verdict": "likely_malicious" | "likely_benign" | "needs_human" | "insufficient_evidence",
          "summary": "<2-4 sentence analyst-facing explanation>",
          "evidenceChain": [
            {"kind": "event"|"alert"|"enrichment"|"threat_intel", "id": "<id>", "note": "<one-line>"}
          ],
          "mitreReasoning": [
            {"tacticId": "TA0005"|null, "techniqueId": "T1562.001"|null, "reasoning": "<why>"}
          ],
          "suggestedActions": [
            {
              "kind": "document"|"suppress"|"quarantine"|"block_network"|"contain_process"|"revoke_tcc"|"rotate_credential"|"escalate",
              "title": "<short label>",
              "rationale": "<why this action>",
              "d3fendRef": "D3-XXX"|null,
              "blastRadius": "low"|"medium"|"high",
              "requiresConfirmation": true,
              "previewCommand": "<exact command or null>"
            }
          ],
          "confidencePenalties": ["<short note of uncertainty>"],
          "modelVersion": "<model name and version>",
          "generatedAt": "<ISO-8601 timestamp>"
        }

        REASONING RULES:
        1. Start from the alert's rule title, severity, and MITRE tags. Weigh
           process path + signer + command line. Escalate confidence only
           when MULTIPLE independent signals agree.
        2. Emit evidenceChain entries in the order you consulted them. Each
           entry MUST reference an id you were actually shown.
        3. Every destructive suggestedAction (kill, quarantine, block,
           revoke) MUST have requiresConfirmation=true and a concrete
           previewCommand. The UI will NEVER auto-execute — it shows the
           preview and waits for a human click.
        4. If you are uncertain, set verdict=needs_human and list your
           uncertainty in confidencePenalties. Do NOT fabricate confidence.
        5. Set d3fendRef from the official MITRE D3FEND matrix when the
           suggested action maps cleanly. Otherwise null.

        Return ONLY the JSON object. No preamble, no explanation.
        """

    public static func alertInvestigationUser(alert: Alert, event: Event?) -> String {
        var s = ""
        s += "ALERT:\n"
        s += "  id: \(alert.id)\n"
        s += "  rule_id: \(alert.ruleId)\n"
        s += "  rule_title: \(alert.ruleTitle)\n"
        s += "  severity: \(alert.severity.rawValue)\n"
        if let d = alert.description {
            s += "  description: \(d)\n"
        }
        if !alert.mitreTacticsList.isEmpty {
            s += "  mitre_tactics: \(alert.mitreTacticsList.joined(separator: ","))\n"
        }
        if !alert.mitreTechniquesList.isEmpty {
            s += "  mitre_techniques: \(alert.mitreTechniquesList.joined(separator: ","))\n"
        }
        if let p = alert.processName {
            s += "  process_name: \(p)\n"
        }
        if let pp = alert.processPath {
            s += "  process_path: \(pp)\n"
        }
        if let cid = alert.campaignId {
            s += "  campaign_id: \(cid)\n"
        }
        if let hint = alert.remediationHint {
            s += "  remediation_hint: \(hint)\n"
        }

        if let event {
            s += "\nEVENT:\n"
            s += "  id: \(event.id.uuidString)\n"
            s += "  category: \(event.eventCategory.rawValue)\n"
            s += "  action: \(event.eventAction)\n"
            s += "  process.executable: \(event.process.executable)\n"
            s += "  process.commandline: \(event.process.commandLine)\n"
            s += "  process.user: \(event.process.userName)\n"
            if let sig = event.process.codeSignature {
                s += "  process.signer: \(sig.signerType.rawValue)\n"
                if let team = sig.teamId {
                    s += "  process.team_id: \(team)\n"
                }
                if let adhoc = sig.isAdhocSigned {
                    s += "  process.is_adhoc: \(adhoc)\n"
                }
            }
            if let sha = event.process.hashes?.sha256 {
                s += "  process.sha256: \(sha)\n"
            }
            if let sess = event.process.session, let src = sess.launchSource {
                s += "  process.launch_source: \(src.rawValue)\n"
            }
            if let f = event.file {
                s += "  file.path: \(f.path)\n"
                s += "  file.action: \(f.action.rawValue)\n"
            }
            if let n = event.network {
                s += "  network.destination: \(n.destinationIp):\(n.destinationPort)\n"
                if let h = n.destinationHostname {
                    s += "  network.hostname: \(h)\n"
                }
            }
            if !event.process.ancestors.isEmpty {
                s += "  process.ancestors:\n"
                for (i, a) in event.process.ancestors.prefix(5).enumerated() {
                    s += "    \(i). \(a.name) (\(a.executable))\n"
                }
            }
        }

        s += "\nReturn the JSON investigation object now."
        return s
    }

    /// Retry prompt emitted when the model's first response failed to parse.
    public static func alertInvestigationRetryFeedback(reason: String) -> String {
        """
        Your previous response was invalid JSON (reason: \(reason)).
        Return ONLY the JSON object matching the schema. No prose.
        """
    }
}

// MARK: - LLMService extension

extension LLMService {

    private static let investigatorLogger = Logger(
        subsystem: "com.maccrab.llm", category: "investigator"
    )

    /// Run agentic triage against a single alert + its event context.
    /// Returns a structured LLMInvestigation, or nil when the backend is
    /// unavailable / both parse attempts fail / the response is too large.
    ///
    /// Caller is expected to surface the result to a human analyst —
    /// suggestedActions are advisory and nothing is ever auto-executed
    /// from this method.
    public func investigate(
        alert: Alert,
        event: Event? = nil,
        temperature: Double = 0.1,
        maxTokens: Int = 2048
    ) async -> LLMInvestigation? {
        let system = LLMPrompts.alertInvestigationSystem
        let user = LLMPrompts.alertInvestigationUser(alert: alert, event: event)

        // First attempt
        guard let first = await self.query(
            systemPrompt: system,
            userPrompt: user,
            maxTokens: maxTokens,
            temperature: temperature,
            useCache: false
        ) else {
            return nil
        }

        if case let .ok(inv) = LLMInvestigator.parse(
            response: first.response, alertId: alert.id,
            fallbackModel: first.provider
        ) {
            return inv
        }

        // Single retry with explicit feedback.
        let retryPrompt = user + "\n\n" +
            LLMPrompts.alertInvestigationRetryFeedback(reason: "could not be decoded")
        guard let second = await self.query(
            systemPrompt: system,
            userPrompt: retryPrompt,
            maxTokens: maxTokens,
            temperature: temperature,
            useCache: false
        ) else {
            return nil
        }

        if case let .ok(inv) = LLMInvestigator.parse(
            response: second.response, alertId: alert.id,
            fallbackModel: second.provider
        ) {
            return inv
        }

        Self.investigatorLogger.warning("Investigation failed to parse after retry")
        return nil
    }
}

// MARK: - Parser

public enum LLMInvestigator {

    /// Parse a raw LLM response into LLMInvestigation. Strips common
    /// markdown code fences the model may add despite instructions.
    public static func parse(
        response: String,
        alertId: String,
        fallbackModel: String
    ) -> InvestigationParseResult {
        let trimmed = stripCodeFences(response.trimmingCharacters(in: .whitespacesAndNewlines))
        guard let data = trimmed.data(using: .utf8) else {
            return .malformed(reason: "not valid UTF-8")
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        do {
            var inv = try decoder.decode(LLMInvestigation.self, from: data)
            // If the model omitted alertId or modelVersion we backfill them
            // rather than bouncing the response — the UI only needs them
            // populated, doesn't care whether the model or we added them.
            if inv.alertId.isEmpty {
                inv = withAlertId(inv, alertId)
            }
            if inv.modelVersion.isEmpty {
                inv = withModelVersion(inv, fallbackModel)
            }
            return .ok(inv)
        } catch {
            return .malformed(reason: error.localizedDescription)
        }
    }

    /// Strip ```json ... ``` or ``` ... ``` fences the model sometimes
    /// wraps around the output.
    static func stripCodeFences(_ s: String) -> String {
        var t = s
        let fencePrefixes = ["```json", "```JSON", "```"]
        for prefix in fencePrefixes {
            if t.hasPrefix(prefix) {
                t = String(t.dropFirst(prefix.count))
                if t.hasPrefix("\n") { t = String(t.dropFirst()) }
                break
            }
        }
        if t.hasSuffix("```") {
            t = String(t.dropLast(3)).trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return t
    }

    // Helpers: copy LLMInvestigation with a single field replaced. Swift
    // doesn't synthesize this, so we do it manually.
    private static func withAlertId(_ i: LLMInvestigation, _ id: String) -> LLMInvestigation {
        LLMInvestigation(
            alertId: id, confidence: i.confidence, verdict: i.verdict,
            summary: i.summary, evidenceChain: i.evidenceChain,
            mitreReasoning: i.mitreReasoning, suggestedActions: i.suggestedActions,
            confidencePenalties: i.confidencePenalties,
            modelVersion: i.modelVersion, generatedAt: i.generatedAt
        )
    }
    private static func withModelVersion(_ i: LLMInvestigation, _ v: String) -> LLMInvestigation {
        LLMInvestigation(
            alertId: i.alertId, confidence: i.confidence, verdict: i.verdict,
            summary: i.summary, evidenceChain: i.evidenceChain,
            mitreReasoning: i.mitreReasoning, suggestedActions: i.suggestedActions,
            confidencePenalties: i.confidencePenalties,
            modelVersion: v, generatedAt: i.generatedAt
        )
    }
}
