// AttributionEvidence.swift
// MacCrabCore
//
// v1.9 Agent Traces — credibility layer for agent attribution.
//
// Every event MacCrab attributes to an AI agent carries an AttributionEvidence
// object explaining WHY it was attributed. The evidence is stored as JSON in
// `events.agent_evidence_json` (additive column added by schema v3 migration);
// the common indexed fields (trace_id, span_id, agent_tool, machine_confidence)
// flatten into their own columns so rules can match on them without parsing
// JSON. Machine attribution is immutable; user reattribute verdicts live in a
// separate `attribution_overlay` overlay surface (PR-4).
//
// `schemaVersion` is set from day one so a future field rename does not
// silently produce unparseable rows. The decoder treats missing/unknown
// versions as `legacy` and returns whatever fields parsed.

import Foundation

/// Why MacCrab believes a given event was caused by a particular AI tool.
///
/// Stored as JSON in `events.agent_evidence_json`. The fields that drive
/// indexing and rule matching (trace_id, agent_tool, machine_agent_confidence)
/// are also flattened to their own columns; this struct is the explanation
/// layer that powers UI tooltips and audit trails.
public struct AttributionEvidence: Codable, Sendable, Hashable {

    /// Schema version for forward compatibility. PR-1 ships v1; future field
    /// additions/renames bump this and update the decoder.
    public static let currentSchemaVersion: Int = 1

    /// Where the attribution came from.
    ///
    /// PR-1 ships only the two high-confidence sources. The `temporal` window
    /// fallback was deliberately cut from v1.9 per Plan v2 review — it is
    /// deferred to v1.9.1 once we have field telemetry on lineage hit rate.
    public enum Source: String, Codable, Sendable {
        /// Direct hit: TRACEPARENT was present in the exec env block.
        case traceparentEnv = "traceparent_env"
        /// Lineage walk found an ancestor pid bound to a known agent.
        case lineageRegistry = "lineage_registry"
        /// Attribution was UNRESOLVED because a kernel telemetry gap was active
        /// for the event's window and the ancestor chain was empty — an honest
        /// "we lost the lineage to a drop" marker, not a real attribution.
        case telemetryGap = "telemetry_gap"
        /// Decoder fallback for any unknown future Source value.
        case unknown = "unknown"
    }

    /// How much weight rules and the UI may give this attribution.
    ///
    /// Maps 1-1 to Source today, but kept as its own enum so the relationship
    /// can change without a schema break (e.g. a future strict-traceparent vs
    /// lax-traceparent split).
    public enum Confidence: String, Codable, Sendable {
        /// Backed by an inherited W3C trace context. Eligible to drive
        /// high-severity rules.
        case traceparent
        /// Backed by ancestor lineage match against AIToolRegistry. Eligible
        /// to drive medium-severity rules.
        case lineage
        /// Not attribution at all: lineage/session was unresolved and a kernel
        /// telemetry gap was active for the window. Emitted so a drop-induced
        /// attribution loss is honest rather than a silent nil. Must NOT drive
        /// any rule (it asserts nothing about the actor).
        case telemetryGap = "telemetry_gap"
        /// Decoder fallback for any unknown future Confidence value.
        case unknown
    }

    public let schemaVersion: Int
    public let source: Source
    public let confidence: Confidence
    public let agentTool: AIToolType?
    public let traceId: String?
    public let spanId: String?
    public let parentSpanId: String?
    public let matchedPid: pid_t
    public let matchedAncestorPid: pid_t?
    public let hopCount: Int?

    public init(
        source: Source,
        confidence: Confidence,
        agentTool: AIToolType?,
        traceId: String?,
        spanId: String?,
        parentSpanId: String?,
        matchedPid: pid_t,
        matchedAncestorPid: pid_t? = nil,
        hopCount: Int? = nil,
        schemaVersion: Int = AttributionEvidence.currentSchemaVersion
    ) {
        self.schemaVersion = schemaVersion
        self.source = source
        self.confidence = confidence
        self.agentTool = agentTool
        self.traceId = traceId
        self.spanId = spanId
        self.parentSpanId = parentSpanId
        self.matchedPid = matchedPid
        self.matchedAncestorPid = matchedAncestorPid
        self.hopCount = hopCount
    }

    // MARK: - Decoding (legacy-tolerant)

    private enum CodingKeys: String, CodingKey {
        case schemaVersion, source, confidence, agentTool
        case traceId, spanId, parentSpanId
        case matchedPid, matchedAncestorPid, hopCount
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        // Missing schemaVersion is treated as 0 = legacy. Future readers
        // can branch on this to apply field migrations.
        self.schemaVersion = (try? c.decode(Int.self, forKey: .schemaVersion)) ?? 0

        // Tolerant enum decoding: an unknown Source / Confidence value from a
        // newer writer becomes `.unknown` rather than failing the whole row.
        let sourceRaw = (try? c.decode(String.self, forKey: .source)) ?? ""
        self.source = Source(rawValue: sourceRaw) ?? .unknown

        let confRaw = (try? c.decode(String.self, forKey: .confidence)) ?? ""
        self.confidence = Confidence(rawValue: confRaw) ?? .unknown

        let toolRaw = try? c.decode(String.self, forKey: .agentTool)
        self.agentTool = toolRaw.flatMap { AIToolType(rawValue: $0) }

        self.traceId = try? c.decode(String.self, forKey: .traceId)
        self.spanId = try? c.decode(String.self, forKey: .spanId)
        self.parentSpanId = try? c.decode(String.self, forKey: .parentSpanId)
        self.matchedPid = (try? c.decode(pid_t.self, forKey: .matchedPid)) ?? 0
        self.matchedAncestorPid = try? c.decode(pid_t.self, forKey: .matchedAncestorPid)
        self.hopCount = try? c.decode(Int.self, forKey: .hopCount)
    }

    // MARK: - JSON helpers

    /// Encode as a compact JSON string for the `agent_evidence_json` column.
    /// Returns nil only on encoder failure (impossible for the field set here).
    public func jsonString() -> String? {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        guard let data = try? encoder.encode(self),
              let str = String(data: data, encoding: .utf8) else {
            return nil
        }
        return str
    }

    /// Decode from `events.agent_evidence_json`. Returns nil on missing/invalid
    /// input; never throws — the column is opportunistic enrichment, never a
    /// load-bearing dependency.
    public static func from(jsonString: String?) -> AttributionEvidence? {
        guard let str = jsonString,
              let data = str.data(using: .utf8) else {
            return nil
        }
        return try? JSONDecoder().decode(AttributionEvidence.self, from: data)
    }
}
