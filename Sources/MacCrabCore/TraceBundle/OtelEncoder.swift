// OtelEncoder.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-10b) — emits the `otel/spans.json` bundle
// artifact per §22.2 of the v1.10.0 spec.
//
// Output shape: OTLP/JSON `resourceSpans[]` with one or more
// `scopeSpans[]` carrying spans for each ProcessNode in the trace.
// Each span uses the bundled trace_id where available; spawn
// relationships become parent_span_id links.
//
// Resource attributes carry `service.name` and the
// `otel.semconv.version` recorded in the manifest so older bundles
// remain readable when upstream conventions rename fields.
//
// MacCrab-specific extensions use the documented `maccrab.*`
// namespace per §22.2.

import Foundation
import CryptoKit

public enum OtelEncoder {

    private static let serviceName = "maccrab.tracegraph"

    /// Build the OTLP-JSON-shaped span document.
    public static func encode(
        trace: Trace,
        entities: [TraceEntity],
        edges: [TraceEdge],
        otelConventionVersion: String
    ) -> [String: Any] {
        let resourceAttributes: [[String: Any]] = [
            attribute(key: "service.name", stringValue: serviceName),
            attribute(key: "otel.semconv.version", stringValue: otelConventionVersion),
            attribute(key: "maccrab.bundle.format", stringValue: BundleManifest.currentFormat),
            attribute(key: "maccrab.trace.id", stringValue: trace.id),
            attribute(key: "maccrab.trace.severity", stringValue: trace.severity),
        ]

        let processEntities = entities.filter { $0.entityType == ProcessNode.entityType }
        let spans = processEntities.compactMap { entity -> [String: Any]? in
            buildSpan(for: entity, trace: trace, edges: edges, allEntities: entities)
        }

        let scopeSpans: [String: Any] = [
            "scope": ["name": serviceName, "version": MacCrabVersion.current],
            "spans": spans,
        ]

        let resourceSpans: [String: Any] = [
            "resource": ["attributes": resourceAttributes],
            "scopeSpans": [scopeSpans],
        ]

        return ["resourceSpans": [resourceSpans]]
    }

    public static func encodeToData(
        trace: Trace,
        entities: [TraceEntity],
        edges: [TraceEdge],
        otelConventionVersion: String
    ) throws -> Data {
        let document = encode(
            trace: trace,
            entities: entities,
            edges: edges,
            otelConventionVersion: otelConventionVersion
        )
        return try JSONSerialization.data(
            withJSONObject: document,
            options: [.sortedKeys]
        )
    }

    // MARK: - Span construction

    private static func buildSpan(
        for entity: TraceEntity,
        trace: Trace,
        edges: [TraceEdge],
        allEntities: [TraceEntity]
    ) -> [String: Any]? {
        guard let processNode = decode(ProcessNode.self, from: entity) else { return nil }

        let traceId = processNode.agentTraceId ?? deterministicHexId(from: trace.id, length: 32)
        let spanId = processNode.agentSpanId ?? deterministicHexId(from: entity.id, length: 16)

        // Parent span: pick the first incoming `spawned` edge.
        let parentEdge = edges.first { edge in
            edge.targetEntityId == entity.id && edge.relation == EdgeRelation.spawned.rawValue
        }
        let parentSpanId: String?
        if let parentEdge,
           let parentEntity = allEntities.first(where: { $0.id == parentEdge.sourceEntityId }),
           let parentProcessNode = decode(ProcessNode.self, from: parentEntity) {
            parentSpanId = parentProcessNode.agentSpanId
                ?? deterministicHexId(from: parentEntity.id, length: 16)
        } else {
            parentSpanId = nil
        }

        var attributes: [[String: Any]] = [
            attribute(key: "process.executable.path", stringValue: processNode.executablePath),
            attribute(key: "process.pid", intValue: Int(processNode.pid)),
            attribute(key: "maccrab.process.key", stringValue: processNode.processKey),
            attribute(key: "maccrab.is_apple_signed", boolValue: processNode.isAppleSigned),
            attribute(key: "maccrab.is_notarized", boolValue: processNode.isNotarized),
        ]
        if let teamId = processNode.signingTeamId {
            attributes.append(attribute(key: "maccrab.signing.team_id", stringValue: teamId))
        }
        if let traceId = processNode.agentTraceId {
            attributes.append(attribute(key: "gen_ai.agent.trace_id", stringValue: traceId))
        }

        var span: [String: Any] = [
            "traceId": traceId,
            "spanId": spanId,
            "name": processNode.executablePath,
            "kind": 1,                                   // SPAN_KIND_INTERNAL
            "startTimeUnixNano": String(unixNanoString(date: processNode.startTime)),
            "endTimeUnixNano": String(unixNanoString(date: processNode.endTime ?? processNode.startTime)),
            "attributes": attributes,
        ]
        if let parentSpanId {
            span["parentSpanId"] = parentSpanId
        }

        return span
    }

    // MARK: - Helpers

    private static func attribute(key: String, stringValue: String) -> [String: Any] {
        ["key": key, "value": ["stringValue": stringValue]]
    }

    private static func attribute(key: String, intValue: Int) -> [String: Any] {
        ["key": key, "value": ["intValue": String(intValue)]]
    }

    private static func attribute(key: String, boolValue: Bool) -> [String: Any] {
        ["key": key, "value": ["boolValue": boolValue]]
    }

    private static func unixNanoString(date: Date) -> UInt64 {
        UInt64(max(0, date.timeIntervalSince1970 * 1_000_000_000))
    }

    /// Build a deterministic hex string of the requested length from
    /// a source string. Used when no real OTel trace_id / span_id is
    /// available — the OTLP shape requires hex ids of fixed length.
    ///
    /// A3-06(b): derive from a truncated SHA-256 rather than a 64-bit
    /// FNV-1a. The old FNV path only had ~64 bits of entropy (the
    /// 32-hex trace_id was two halves both derived from the same 64-bit
    /// hash), so two distinct entities could be steered onto a shared
    /// span_id / trace_id. SHA-256 is a cryptographic hash: an attacker
    /// can't cheaply drive two sources onto the same id, and the 32-hex
    /// trace_id now carries a full 128 bits of independent output.
    /// `internal` (not `private`) so the tests can exercise it directly.
    static func deterministicHexId(from source: String, length: Int) -> String {
        let hex = SHA256.hash(data: Data(source.utf8))
            .map { String(format: "%02x", $0) }
            .joined()
        // SHA-256 yields 64 hex chars; span_id (16) and trace_id (32) both fit.
        return String(hex.prefix(length))
    }

    private static func decode<T: Decodable>(_ type: T.Type, from entity: TraceEntity) -> T? {
        guard let data = entity.attributesJson.data(using: .utf8) else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        return try? decoder.decode(T.self, from: data)
    }
}
