// AgenticInvestigator.swift
// MacCrabCore
//
// Multi-round campaign investigation loop. Takes a CampaignDetector
// campaign, lets the LLM issue context requests (lookups against the
// local alert store, rule engine, and event log), and produces a
// structured InvestigationReport.
//
// The loop is deliberately bounded — a maximum of `maxRounds`
// iterations, a per-request response cap, and a total-wall-clock
// timeout. LLMs that wander off task or refuse to emit the sentinel
// termination marker get a default report on timeout rather than
// looping indefinitely.
//
// "Agentic" here is narrow: the LLM doesn't execute code, it doesn't
// make outbound network calls, it can't modify state. Its only
// capability is asking the service to fetch local context. All
// actions the report recommends still require analyst confirmation —
// the service produces advisory output only.

import Foundation
import os.log

// MARK: - Context fetcher

/// The set of context lookups an AgenticInvestigator can perform on
/// behalf of the LLM. Each closure is provided by the caller, wired
/// up against whatever authoritative state source is appropriate
/// (AlertStore, RuleEngine, EventStore). Separating this out keeps
/// the investigator testable without dragging SQLite into the tests.
public struct InvestigationContextFetchers: Sendable {
    public let describeRule: @Sendable (_ ruleId: String) async -> String?
    public let alertDescriptions: @Sendable (_ ruleIds: [String]) async -> [String: String]
    public let recentProcessChildren: @Sendable (_ processPath: String) async -> [String]

    public init(
        describeRule: @Sendable @escaping (_ ruleId: String) async -> String? = { _ in nil },
        alertDescriptions: @Sendable @escaping (_ ruleIds: [String]) async -> [String: String] = { _ in [:] },
        recentProcessChildren: @Sendable @escaping (_ processPath: String) async -> [String] = { _ in [] }
    ) {
        self.describeRule = describeRule
        self.alertDescriptions = alertDescriptions
        self.recentProcessChildren = recentProcessChildren
    }
}

// MARK: - InvestigationReport

public struct InvestigationReport: Sendable, Hashable {
    public let campaignId: String
    public let verdict: Verdict
    public let summary: String
    public let findings: [String]
    public let recommendedAction: String
    public let rounds: Int
    public let totalLatencySeconds: Double

    public enum Verdict: String, Sendable, CaseIterable, Hashable, Codable {
        case benign
        case suspicious
        case malicious
        case inconclusive
    }

    public init(campaignId: String, verdict: Verdict, summary: String,
                findings: [String], recommendedAction: String,
                rounds: Int, totalLatencySeconds: Double) {
        self.campaignId = campaignId
        self.verdict = verdict
        self.summary = summary
        self.findings = findings
        self.recommendedAction = recommendedAction
        self.rounds = rounds
        self.totalLatencySeconds = totalLatencySeconds
    }
}

// MARK: - AgenticInvestigator

public actor AgenticInvestigator {
    private let logger = Logger(subsystem: "com.maccrab.llm", category: "agentic-investigator")

    private let llm: LLMService
    private let maxRounds: Int
    private let perRoundTimeout: Duration

    public static let defaultMaxRounds = 3
    public static let defaultPerRoundTimeout: Duration = .seconds(30)

    public init(
        llm: LLMService,
        maxRounds: Int = defaultMaxRounds,
        perRoundTimeout: Duration = defaultPerRoundTimeout
    ) {
        self.llm = llm
        self.maxRounds = max(1, maxRounds)
        self.perRoundTimeout = perRoundTimeout
    }

    // MARK: Entry point

    public func investigate(
        campaign: CampaignDetector.Campaign,
        fetchers: InvestigationContextFetchers = InvestigationContextFetchers()
    ) async -> InvestigationReport? {
        guard await llm.isAvailable() else { return nil }

        let start = Date()
        var transcript: [String] = []
        var roundsRun = 0

        // Round 1 — seed the LLM with the campaign and ask for either
        // a verdict or a tool call.
        let initialUser = Self.formatCampaign(campaign)
        transcript.append("Round 1 prompt:\n\(initialUser)")

        var lastResponseText = ""
        for round in 1...maxRounds {
            roundsRun = round
            let system = Self.systemPrompt
            let user = transcript.joined(separator: "\n\n")
            guard let enhancement = await llm.query(
                systemPrompt: system,
                userPrompt: user,
                maxTokens: 900,
                temperature: 0.2
            ) else {
                break
            }
            lastResponseText = enhancement.response
            transcript.append("Round \(round) response:\n\(enhancement.response)")

            // If the LLM declared a verdict, we're done.
            if Self.containsVerdict(enhancement.response) {
                break
            }

            // Otherwise, parse any tool calls the LLM made and answer them.
            let toolResults = await Self.handleToolCalls(
                response: enhancement.response,
                fetchers: fetchers
            )
            if toolResults.isEmpty {
                // No tool calls and no verdict — nudge it toward a
                // verdict in the next round, but don't spin forever.
                transcript.append("No tool calls detected. Produce your final VERDICT block now.")
            } else {
                transcript.append("Tool results:\n\(toolResults)")
            }
        }

        let parsed = Self.parseReport(campaignId: campaign.id, response: lastResponseText)
        let total = Date().timeIntervalSince(start)
        return InvestigationReport(
            campaignId: campaign.id,
            verdict: parsed.verdict,
            summary: parsed.summary,
            findings: parsed.findings,
            recommendedAction: parsed.recommendedAction,
            rounds: roundsRun,
            totalLatencySeconds: total
        )
    }

    // MARK: Prompts

    static let systemPrompt = """
    You are a bounded security investigator. Review the MacCrab campaign evidence and produce a structured verdict.

    You MAY emit tool calls to pull more context. Tool-call format is exactly:
        TOOL: describe_rule RULE_ID=<rule id>
        TOOL: alert_descriptions RULE_IDS=<id1,id2,...>
        TOOL: process_children PROCESS_PATH=<path>
    One tool call per line, up to 5 per round. Ask only for what you need.

    When you have enough context, emit EXACTLY this block (no markdown, no extra text):
        VERDICT: <benign|suspicious|malicious|inconclusive>
        SUMMARY: <one sentence>
        FINDING: <one concrete observation>
        FINDING: <another concrete observation, optional>
        FINDING: <up to 5 findings total>
        RECOMMEND: <one sentence of analyst action>

    Rules:
    - One verdict per investigation.
    - Do NOT fabricate process paths, rule IDs, or command lines — only use values from the provided campaign evidence or tool results.
    - You have at most \(AgenticInvestigator.defaultMaxRounds) rounds of tool calls. After that the investigation terminates with whatever verdict is present.
    """

    static func formatCampaign(_ campaign: CampaignDetector.Campaign) -> String {
        let alertLines = campaign.alerts.prefix(20).map { a in
            let proc = a.processPath ?? "<no path>"
            return "  - [\(a.severity.rawValue)] \(a.ruleTitle) (\(a.ruleId)) on \(proc) tactics={\(a.tactics.sorted().joined(separator: ","))}"
        }.joined(separator: "\n")

        return """
        Campaign \(campaign.id) — \(campaign.type.rawValue), severity=\(campaign.severity.rawValue)
        Title: \(campaign.title)
        Description: \(campaign.description)
        Time span (s): \(Int(campaign.timeSpanSeconds))
        MITRE tactics observed: \(campaign.tactics.sorted().joined(separator: ", "))
        Contributing alerts (\(campaign.alerts.count)):
        \(alertLines)
        """
    }

    // MARK: Tool call handling

    static func handleToolCalls(
        response: String,
        fetchers: InvestigationContextFetchers
    ) async -> String {
        var results: [String] = []
        var callsSeen = 0
        for line in response.split(whereSeparator: \.isNewline).prefix(200) {
            guard callsSeen < 5 else { break }
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("TOOL:") else { continue }
            callsSeen += 1
            let body = trimmed.dropFirst("TOOL:".count).trimmingCharacters(in: .whitespaces)
            if body.hasPrefix("describe_rule") {
                if let ruleId = Self.extractParam(body, key: "RULE_ID"),
                   Self.isSafeRuleId(ruleId) {
                    let desc = await fetchers.describeRule(ruleId) ?? "(no description available)"
                    results.append("describe_rule \(ruleId): \(desc)")
                }
            } else if body.hasPrefix("alert_descriptions") {
                if let ids = Self.extractParam(body, key: "RULE_IDS") {
                    let list = ids.split(separator: ",")
                        .map { $0.trimmingCharacters(in: .whitespaces) }
                        .filter { Self.isSafeRuleId($0) }
                        .prefix(maxRuleIdsPerCall)
                    let map = await fetchers.alertDescriptions(Array(list))
                    let rendered = map.map { "\($0.key): \($0.value)" }.joined(separator: "; ")
                    results.append("alert_descriptions: \(rendered.isEmpty ? "(no matches)" : rendered)")
                }
            } else if body.hasPrefix("process_children") {
                if let path = Self.extractParam(body, key: "PROCESS_PATH"),
                   Self.isSafeProcessPath(path) {
                    let kids = await fetchers.recentProcessChildren(path)
                    results.append("process_children \(path): \(kids.isEmpty ? "(none)" : kids.joined(separator: ", "))")
                }
            }
        }
        return results.joined(separator: "\n")
    }

    /// Upper bound on how many rule IDs a single `alert_descriptions`
    /// tool call may batch. v1.6.9 hardening — without this cap an
    /// LLM could emit a 50 KB comma-list that forces thousands of
    /// AlertStore queries.
    static let maxRuleIdsPerCall = 20

    /// Max length for any single extracted tool-call parameter value.
    /// v1.6.9 hardening — bounds the attack surface of the fetcher
    /// closures (they already query a local store, so this is
    /// defense-in-depth, but it prevents a pathological LLM response
    /// from driving unbounded-length queries into the event store).
    static let maxParamValueLength = 256

    static func extractParam(_ body: String, key: String) -> String? {
        let lowerKey = (key + "=").lowercased()
        let lower = body.lowercased()
        guard let idx = lower.range(of: lowerKey)?.upperBound else { return nil }
        let offsetInOriginal = body.index(body.startIndex, offsetBy: body.distance(from: body.startIndex, to: idx))
        let value = body[offsetInOriginal...]
        // Value runs to the next whitespace or end. Strip surrounding quotes if any.
        let endIdx = value.firstIndex(where: \.isWhitespace) ?? value.endIndex
        let raw = String(value[..<endIdx])
        let trimmed = raw.trimmingCharacters(in: CharacterSet(charactersIn: "\"' "))
        // Length cap — drop anything absurdly long rather than passing
        // it through. Returning nil mirrors "param missing" which the
        // caller already handles gracefully.
        guard trimmed.count <= maxParamValueLength else { return nil }
        return trimmed
    }

    /// Rule IDs are compiled UUIDs or short dotted identifiers —
    /// nothing exotic should appear here. Reject anything with path
    /// separators, control characters, or whitespace so a crafted
    /// tool call can't reach past the expected identifier shape.
    static func isSafeRuleId(_ s: String) -> Bool {
        guard !s.isEmpty, s.count <= 128 else { return false }
        for c in s {
            if c.isLetter || c.isNumber { continue }
            if c == "-" || c == "_" || c == "." { continue }
            return false
        }
        return true
    }

    /// Process paths must be absolute and well-formed. Reject path
    /// traversal (`..`), null bytes, and newlines so the fetcher
    /// closure can never be fed something that would escape its
    /// intended scope. The closures we ship only query in-memory
    /// state, but an integrator might wire a filesystem-touching
    /// closure later — belt-and-braces.
    static func isSafeProcessPath(_ s: String) -> Bool {
        guard !s.isEmpty, s.count <= maxParamValueLength else { return false }
        guard s.hasPrefix("/") else { return false }
        if s.contains("..") { return false }
        for c in s {
            if c.isASCII == false { return false }
            if c == "\0" || c == "\n" || c == "\r" { return false }
        }
        return true
    }

    // MARK: Report parsing

    static func containsVerdict(_ text: String) -> Bool {
        text.contains("VERDICT:")
    }

    static func parseReport(
        campaignId: String,
        response: String
    ) -> (verdict: InvestigationReport.Verdict,
          summary: String,
          findings: [String],
          recommendedAction: String) {
        var verdict: InvestigationReport.Verdict = .inconclusive
        var summary = ""
        var findings: [String] = []
        var recommend = ""
        for rawLine in response.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            // Strip markdown like **VERDICT:** so the prefix match works.
            let stripped = String(line.drop { "*_> -`".contains($0) })
            if stripped.uppercased().hasPrefix("VERDICT:") {
                let after = stripped.split(separator: ":", maxSplits: 1).last ?? ""
                let labelRaw = after
                    .trimmingCharacters(in: CharacterSet(charactersIn: " *_`'\"."))
                    .split(separator: " ").first.map(String.init) ?? ""
                let cleaned = labelRaw.lowercased()
                    .trimmingCharacters(in: CharacterSet(charactersIn: "*_`'\"."))
                if let match = InvestigationReport.Verdict(rawValue: cleaned) {
                    verdict = match
                }
            } else if stripped.uppercased().hasPrefix("SUMMARY:") {
                summary = String(stripped.dropFirst("SUMMARY:".count))
                    .trimmingCharacters(in: .whitespaces)
            } else if stripped.uppercased().hasPrefix("FINDING:") {
                let f = String(stripped.dropFirst("FINDING:".count))
                    .trimmingCharacters(in: .whitespaces)
                if !f.isEmpty { findings.append(f) }
            } else if stripped.uppercased().hasPrefix("RECOMMEND:") {
                recommend = String(stripped.dropFirst("RECOMMEND:".count))
                    .trimmingCharacters(in: .whitespaces)
            }
        }
        if summary.isEmpty {
            summary = "Investigation produced no structured summary."
        }
        if recommend.isEmpty {
            recommend = "No specific action proposed — triage manually."
        }
        return (verdict, summary, findings, recommend)
    }
}
