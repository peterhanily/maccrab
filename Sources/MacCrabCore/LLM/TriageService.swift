// TriageService.swift
// MacCrabCore
//
// Ask the LLM to propose a disposition for a single alert — suppress
// the rule/process pair, keep watching, or escalate. The dashboard
// surfaces the recommendation as a one-click action next to the alert,
// along with a terse rationale so the analyst can decide whether to
// accept or override.
//
// The service does NOT take the action on its own — producing a
// recommendation is informational; actually suppressing or escalating
// still requires analyst confirmation. This is deliberate: the v1.6.x
// FP history is full of rules where "suppress if LLM agrees" would
// have hidden a real signal, and we want the LLM's output to inform
// human decisions rather than replace them.

import Foundation
import os.log

// MARK: - TriageDisposition

/// Discrete triage outcomes. `inconclusive` is produced when the LLM
/// refuses, times out, or gives an off-script answer — surfaced to the
/// dashboard as "model unsure, triage manually".
public enum TriageDisposition: String, Sendable, CaseIterable, Hashable {
    case suppress
    case keep
    case escalate
    case inconclusive
}

// MARK: - TriageRecommendation

public struct TriageRecommendation: Sendable, Hashable {
    public let disposition: TriageDisposition
    public let rationale: String
    public let provider: String
    public let latencySeconds: Double
    public let usedCache: Bool

    public init(disposition: TriageDisposition, rationale: String,
                provider: String, latencySeconds: Double, usedCache: Bool) {
        self.disposition = disposition
        self.rationale = rationale
        self.provider = provider
        self.latencySeconds = latencySeconds
        self.usedCache = usedCache
    }
}

// MARK: - TriageService

/// Single-backend triage recommender. Wraps LLMService with the
/// prompt templates and output parsing for disposition classification.
/// For multi-backend consensus, pair with `LLMConsensusService` — this
/// service targets the "one model, one recommendation" case.
public actor TriageService {
    private let logger = Logger(subsystem: "com.maccrab.llm", category: "triage")

    private let llm: LLMService

    public init(llm: LLMService) {
        self.llm = llm
    }

    /// Produce a disposition recommendation for a single alert.
    ///
    /// - Parameters:
    ///   - alert: the alert under triage.
    ///   - similarCount: how many sibling alerts share this alert's
    ///     cluster fingerprint. Passed to the LLM as context so its
    ///     disposition can account for "this fired 30 times today"
    ///     vs "this is a one-off".
    ///   - dailyTotal: total alert volume for the host over the
    ///     prior 24 hours. Optional; omitted from the prompt when nil.
    public func recommend(
        for alert: Alert,
        similarCount: Int = 1,
        dailyTotal: Int? = nil
    ) async -> TriageRecommendation? {
        guard await llm.isAvailable() else { return nil }

        let (system, user) = Self.buildPrompt(
            alert: alert,
            similarCount: similarCount,
            dailyTotal: dailyTotal
        )

        guard let response = await llm.query(
            systemPrompt: system,
            userPrompt: user,
            maxTokens: 220,
            temperature: 0.1
        ) else {
            return nil
        }

        let parsed = Self.parse(response: response.response)
        return TriageRecommendation(
            disposition: parsed.disposition,
            rationale: parsed.rationale,
            provider: response.provider,
            latencySeconds: response.latency,
            usedCache: response.cached
        )
    }

    // MARK: Prompt assembly

    /// Build the (system, user) prompt pair for a triage query. Public-
    /// level helper so tests can assert the shape of the prompt
    /// without invoking an LLM.
    static func buildPrompt(
        alert: Alert,
        similarCount: Int,
        dailyTotal: Int?
    ) -> (system: String, user: String) {
        let system = """
        You are a veteran macOS security analyst triaging alerts.
        Your job is to recommend ONE disposition for the alert below:

          suppress    — the alert is almost certainly benign; suppress future firings of the same rule+process pair.
          keep        — the alert is probably benign but not obviously so; keep watching in case more context arrives.
          escalate    — the alert looks like a real security issue; surface it for analyst review.
          inconclusive — you genuinely cannot tell from the provided context.

        Output format (EXACT, two lines):
        Line 1: `DISPOSITION: <one of the four labels above>`
        Line 2: `REASON: <one short sentence, <=160 chars, plain English>`

        Do not output anything else. Do not use markdown.
        """

        var lines = [
            "Rule: \(alert.ruleTitle) (\(alert.ruleId))",
            "Severity: \(alert.severity.rawValue)",
            "Process: \(alert.processName ?? "<unknown>")\(alert.processPath.map { " (\($0))" } ?? "")",
            "Description: \(alert.description ?? "<none>")",
            "MITRE tactics: \(alert.mitreTacticsList.joined(separator: ", "))",
            "MITRE techniques: \(alert.mitreTechniquesList.joined(separator: ", "))",
            "Similar alerts in the last hour (same rule+process): \(similarCount)",
        ]
        if let dailyTotal {
            lines.append("Total alerts on this host over prior 24h: \(dailyTotal)")
        }

        let user = """
        Alert under triage:
        \(lines.joined(separator: "\n"))

        Respond in the exact DISPOSITION / REASON format described.
        """
        return (system, user)
    }

    // MARK: Response parsing

    /// Pull the disposition label and rationale out of an LLM response
    /// that was supposed to follow the DISPOSITION/REASON template. In
    /// practice models wander — we accept any line beginning with
    /// "DISPOSITION" (case-insensitive) and take the first valid label
    /// word; same with "REASON".
    static func parse(response: String) -> (disposition: TriageDisposition, rationale: String) {
        let lines = response.split(whereSeparator: \.isNewline).map(String.init)
        var disposition: TriageDisposition = .inconclusive
        var rationale = ""

        for raw in lines {
            let line = raw.trimmingCharacters(in: .whitespaces)
            // Strip leading markdown markers (`**`, `__`, `>`, `-`, `*`)
            // so a model that chatters back `**DISPOSITION:**` still
            // routes to the DISPOSITION branch.
            let stripped = line.drop { "*_>- `".contains($0) }
            let lower = String(stripped).lowercased()
            if disposition == .inconclusive, lower.hasPrefix("disposition") {
                disposition = extractDisposition(from: String(stripped)) ?? .inconclusive
            } else if rationale.isEmpty, lower.hasPrefix("reason") {
                rationale = extractAfterColon(String(stripped))
            }
        }

        // Fallback: if we never saw the prefixed form, try to read the
        // first word of the response as a label.
        if disposition == .inconclusive {
            let firstWord = lines.first?
                .trimmingCharacters(in: .whitespaces)
                .lowercased()
                .components(separatedBy: CharacterSet(charactersIn: " :,.")).first ?? ""
            if let match = TriageDisposition(rawValue: firstWord) {
                disposition = match
            }
        }

        // If no reason found, use the full response trimmed.
        if rationale.isEmpty {
            rationale = response
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .replacingOccurrences(of: "\n", with: " ")
        }

        // Cap rationale length so the dashboard doesn't get blown out
        // by a chatty model.
        if rationale.count > 240 {
            let idx = rationale.index(rationale.startIndex, offsetBy: 240)
            rationale = String(rationale[..<idx]) + "…"
        }

        return (disposition, rationale)
    }

    private static func extractDisposition(from line: String) -> TriageDisposition? {
        let after = extractAfterColon(line).lowercased()
        let trimmed = after.trimmingCharacters(in: CharacterSet(charactersIn: "*`'\"_ ,.:;"))
        let first = trimmed.components(separatedBy: .whitespaces).first ?? ""
        return TriageDisposition(rawValue: first)
    }

    private static func extractAfterColon(_ line: String) -> String {
        guard let colonIdx = line.firstIndex(of: ":") else { return "" }
        let after = line[line.index(after: colonIdx)...]
        return after.trimmingCharacters(in: .whitespaces)
    }
}
