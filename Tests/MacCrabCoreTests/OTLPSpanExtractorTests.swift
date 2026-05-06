// OTLPSpanExtractorTests.swift
// v1.9 PR-3b — agent_tool resolution order + extractor → SpanRecord round-trip.

import Testing
import Foundation
@testable import MacCrabCore

// MARK: - Hand-rolled protobuf encode helpers (test-only)

private enum E {
    static func varint(_ v: UInt64) -> [UInt8] {
        var x = v; var out: [UInt8] = []
        while x >= 0x80 { out.append(UInt8((x & 0x7F) | 0x80)); x >>= 7 }
        out.append(UInt8(x & 0x7F))
        return out
    }
    static func tag(_ field: Int, _ wire: Int) -> [UInt8] {
        varint(UInt64((field << 3) | wire))
    }
    static func lenDelim(_ field: Int, _ payload: [UInt8]) -> [UInt8] {
        var o = tag(field, 2)
        o.append(contentsOf: varint(UInt64(payload.count)))
        o.append(contentsOf: payload)
        return o
    }
    static func varintField(_ field: Int, _ value: UInt64) -> [UInt8] {
        var o = tag(field, 0); o.append(contentsOf: varint(value)); return o
    }
    static func fixed64(_ field: Int, _ value: UInt64) -> [UInt8] {
        var o = tag(field, 1)
        for i in 0..<8 { o.append(UInt8((value >> (8 * i)) & 0xFF)) }
        return o
    }
    static func string(_ field: Int, _ s: String) -> [UInt8] {
        lenDelim(field, Array(s.utf8))
    }
    /// Build an AnyValue with a single string_value (field 1).
    static func anyValueString(_ s: String) -> [UInt8] {
        string(1, s)
    }
    /// Build a KeyValue: key (1, string), value (2, AnyValue).
    static func keyValue(_ key: String, _ value: String) -> [UInt8] {
        var o = string(1, key)
        o.append(contentsOf: lenDelim(2, anyValueString(value)))
        return o
    }
    /// Build a Span body with the listed fields. attributes is rendered
    /// as repeated KeyValue (field 9).
    static func span(
        traceId: [UInt8],
        spanId: [UInt8],
        parentSpanId: [UInt8]? = nil,
        name: String,
        startNs: UInt64 = 100,
        endNs: UInt64 = 200,
        attributes: [(String, String)] = []
    ) -> [UInt8] {
        var o: [UInt8] = []
        o.append(contentsOf: lenDelim(1, traceId))
        o.append(contentsOf: lenDelim(2, spanId))
        if let p = parentSpanId { o.append(contentsOf: lenDelim(4, p)) }
        o.append(contentsOf: string(5, name))
        o.append(contentsOf: fixed64(7, startNs))
        o.append(contentsOf: fixed64(8, endNs))
        for (k, v) in attributes {
            o.append(contentsOf: lenDelim(9, keyValue(k, v)))
        }
        return o
    }
    /// Build a ScopeSpans body. Spans is repeated field 2.
    static func scopeSpans(scopeName: String?, spans: [[UInt8]]) -> [UInt8] {
        var o: [UInt8] = []
        if let n = scopeName, !n.isEmpty {
            o.append(contentsOf: lenDelim(1, string(1, n)))
        }
        for s in spans { o.append(contentsOf: lenDelim(2, s)) }
        return o
    }
    /// Build a Resource with a single attributes list.
    static func resource(serviceName: String?) -> [UInt8] {
        guard let s = serviceName else { return [] }
        return lenDelim(1, keyValue("service.name", s))
    }
    /// Build a ResourceSpans body.
    static func resourceSpans(resource: [UInt8], scope: [UInt8]) -> [UInt8] {
        var o: [UInt8] = []
        if !resource.isEmpty {
            o.append(contentsOf: lenDelim(1, resource))
        }
        o.append(contentsOf: lenDelim(2, scope))
        return o
    }
    /// Build the outer ExportTraceServiceRequest.
    static func exportRequest(_ resourceSpans: [[UInt8]]) -> [UInt8] {
        var o: [UInt8] = []
        for rs in resourceSpans { o.append(contentsOf: lenDelim(1, rs)) }
        return o
    }
}

private let traceIdBytes: [UInt8] = [
    0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6,
    0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e, 0x47, 0x36,
]
private let spanIdBytes: [UInt8] = [
    0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7,
]
private let parentSpanIdBytes: [UInt8] = [
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
]

// MARK: - agent_tool resolution

@Suite("OTLPSpanExtractor: agent_tool resolution order")
struct AgentToolResolutionTests {

    @Test("Span name prefix wins over service.name")
    func spanNameWinsOverService() {
        let resolved = OTLPSpanExtractor.resolveAgentTool(
            spanName: "claude_code.tool.Bash",
            serviceName: "codex",   // would have resolved to .codex
            providerName: nil,
            legacyGenAiSystem: nil
        )
        #expect(resolved == .claudeCode)
    }

    @Test("service.name resolves when span name is generic")
    func serviceNameSecondary() {
        #expect(OTLPSpanExtractor.resolveAgentTool(
            spanName: "rpc.invoke",
            serviceName: "claude-code",
            providerName: nil,
            legacyGenAiSystem: nil
        ) == .claudeCode)
        #expect(OTLPSpanExtractor.resolveAgentTool(
            spanName: "rpc.invoke",
            serviceName: "codex",
            providerName: nil,
            legacyGenAiSystem: nil
        ) == .codex)
    }

    @Test("gen_ai.provider.name maps when other signals miss")
    func providerNameTertiary() {
        #expect(OTLPSpanExtractor.resolveAgentTool(
            spanName: "client.call",
            serviceName: nil,
            providerName: "anthropic",
            legacyGenAiSystem: nil
        ) == .claudeCode)
        #expect(OTLPSpanExtractor.resolveAgentTool(
            spanName: "client.call",
            serviceName: nil,
            providerName: "openai",
            legacyGenAiSystem: nil
        ) == .codex)
    }

    @Test("legacy gen_ai.system used when provider absent")
    func legacyFallback() {
        #expect(OTLPSpanExtractor.resolveAgentTool(
            spanName: "client.call",
            serviceName: nil,
            providerName: nil,
            legacyGenAiSystem: "anthropic"
        ) == .claudeCode)
    }

    @Test("Returns nil when nothing maps")
    func nilWhenAllUnknown() {
        let r = OTLPSpanExtractor.resolveAgentTool(
            spanName: "internal.thing",
            serviceName: "unrelated-service",
            providerName: "vendor-xyz",
            legacyGenAiSystem: nil
        )
        #expect(r == nil)
    }
}

// MARK: - End-to-end nested decode

@Suite("OTLPNestedDecoder: full request walk")
struct OTLPNestedDecodeTests {

    @Test("Decodes service.name + span name + ids + start/end + attributes")
    func happyPath() throws {
        let span = E.span(
            traceId: traceIdBytes, spanId: spanIdBytes,
            parentSpanId: parentSpanIdBytes,
            name: "claude_code.tool.execution",
            startNs: 1_000_000,
            endNs:   2_000_000,
            attributes: [
                ("tool_name", "Bash"),
                ("duration_ms", "42"),
            ]
        )
        let scope = E.scopeSpans(scopeName: "claude_code.otel", spans: [span])
        let res = E.resource(serviceName: "claude-code")
        let rs = E.resourceSpans(resource: res, scope: scope)
        let body = Data(E.exportRequest([rs]))

        let groups = try OTLPNestedDecoder.decodeRequest(body)
        #expect(groups.count == 1)
        let g = groups[0]
        #expect(g.serviceName == "claude-code")
        #expect(g.scopeName == "claude_code.otel")
        #expect(g.spans.count == 1)
        let s = g.spans[0]
        #expect(s.traceIdHex == "4bf92f3577b34da6a3ce929d0e0e4736")
        #expect(s.spanIdHex == "00f067aa0ba902b7")
        #expect(s.parentSpanIdHex == "fedcba9876543210")
        #expect(s.name == "claude_code.tool.execution")
        #expect(s.startTimeUnixNano == 1_000_000)
        #expect(s.endTimeUnixNano == 2_000_000)
        #expect(s.attributes.count == 2)
        #expect(s.attributes[0] == ("tool_name", "Bash"))
        #expect(s.attributes[1] == ("duration_ms", "42"))
    }

    @Test("Two spans in one ScopeSpans land in order")
    func multipleSpans() throws {
        let s1 = E.span(traceId: traceIdBytes, spanId: spanIdBytes,
                        name: "claude_code.tool.A", startNs: 1, endNs: 2)
        let s2 = E.span(traceId: traceIdBytes,
                        spanId: [0,0,0,0,0,0,0,1],
                        name: "claude_code.tool.B", startNs: 3, endNs: 4)
        let scope = E.scopeSpans(scopeName: "scope", spans: [s1, s2])
        let rs = E.resourceSpans(resource: E.resource(serviceName: "claude-code"), scope: scope)
        let body = Data(E.exportRequest([rs]))
        let groups = try OTLPNestedDecoder.decodeRequest(body)
        #expect(groups[0].spans.map(\.name) == ["claude_code.tool.A", "claude_code.tool.B"])
    }

    @Test("Parent span id absent when not provided")
    func noParentSpanId() throws {
        let span = E.span(traceId: traceIdBytes, spanId: spanIdBytes,
                          parentSpanId: nil, name: "root", startNs: 1, endNs: 2)
        let scope = E.scopeSpans(scopeName: nil, spans: [span])
        let rs = E.resourceSpans(resource: [], scope: scope)
        let body = Data(E.exportRequest([rs]))
        let groups = try OTLPNestedDecoder.decodeRequest(body)
        #expect(groups[0].spans[0].parentSpanIdHex == "")
    }
}

// MARK: - Extractor → SpanRecord

@Suite("OTLPSpanExtractor: groups → [SpanRecord]")
struct OTLPSpanExtractorIntegrationTests {

    @Test("Produces SpanRecord with sanitised attributes JSON")
    func extractorWithSanitisation() throws {
        let span = E.span(
            traceId: traceIdBytes, spanId: spanIdBytes,
            name: "claude_code.tool.execution",
            startNs: 100, endNs: 200,
            attributes: [
                ("tool_name", "Bash"),
                ("api_key", "sk-ant-secret-AAAAAAAAAAAAAAAAAAAA"),
                ("note", "leaked sk-ant-api03-XXXXXXXXXXXXXXXXXXXX in prompt"),
            ]
        )
        let body = Data(E.exportRequest([
            E.resourceSpans(
                resource: E.resource(serviceName: "claude-code"),
                scope: E.scopeSpans(scopeName: "scope", spans: [span])
            )
        ]))
        let groups = try OTLPNestedDecoder.decodeRequest(body)
        let result = OTLPSpanExtractor.extract(from: groups)
        #expect(result.spans.count == 1)
        let r = result.spans[0]
        #expect(r.traceId == "4bf92f3577b34da6a3ce929d0e0e4736")
        #expect(r.spanName == "claude_code.tool.execution")
        #expect(r.serviceName == "claude-code")
        #expect(r.agentTool == .claudeCode)
        // The "api_key" attribute was redacted by key.
        #expect(result.totalAttributesKeyRedacted == 1)
        // The "note" attribute had a vendor key shape redacted by value.
        #expect(result.totalAttributesValueRedacted == 1)
        // Output JSON must NOT contain either secret form.
        let json = r.attributesJson ?? ""
        #expect(!json.contains("sk-ant-secret"))
        #expect(!json.contains("sk-ant-api03"))
        #expect(json.contains("[ANTHROPIC_KEY]"))
    }
}

// MARK: - v1.9.0 audit Sec-H1: span identity field sanitization

@Suite("OTLPSpanExtractor: span identity field redaction (audit Sec-H1)")
struct OTLPSpanExtractorIdentityRedactionTests {

    @Test("Hostile span.name with embedded anthropic key is redacted before persistence")
    func spanNameRedacted() throws {
        // Pre-fix: a buggy/hostile agent could emit
        //   span.name = "tool.invoke(sk-ant-api03-…)"
        // and the secret would land in the `span_name` column unmodified
        // (only attributes_json was sanitised). The column is not
        // covered by AES-GCM either, so the secret persisted in plaintext.
        let span = E.span(
            traceId: traceIdBytes, spanId: spanIdBytes,
            name: "claude_code.tool.invoke(sk-ant-api03-FAKEKEYFAKEKEYFAKE)",
            startNs: 100, endNs: 200,
            attributes: []
        )
        let body = Data(E.exportRequest([
            E.resourceSpans(
                resource: E.resource(serviceName: "claude-code"),
                scope: E.scopeSpans(scopeName: "scope", spans: [span])
            )
        ]))
        let groups = try OTLPNestedDecoder.decodeRequest(body)
        let result = OTLPSpanExtractor.extract(from: groups)
        let r = result.spans[0]
        // Span name must NOT contain the raw key.
        #expect(!r.spanName.contains("sk-ant-api03"))
        #expect(r.spanName.contains("[ANTHROPIC_KEY]"))
        // The agent_tool resolver should still map to .claudeCode
        // because the prefix `claude_code.` survives redaction.
        #expect(r.agentTool == .claudeCode)
    }

    @Test("Hostile service.name embedded secret is redacted")
    func serviceNameRedacted() throws {
        let span = E.span(
            traceId: traceIdBytes, spanId: spanIdBytes,
            name: "tool.execute",
            startNs: 100, endNs: 200,
            attributes: []
        )
        // service.name is set on the resource. We embed an aws key
        // shape to verify resource-level sanitization.
        let body = Data(E.exportRequest([
            E.resourceSpans(
                // AKIAFAKEEXAMPLENOTRE = synthetic 16-uppercase tail
                // matching the AWS access-key regex without using the
                // canonical AKIAIOSFODNN7EXAMPLE that some secret
                // scanners are tuned to allowlist (and others aren't).
                resource: E.resource(serviceName: "claude-code AKIAFAKEEXAMPLENOTRE"),
                scope: E.scopeSpans(scopeName: "scope", spans: [span])
            )
        ]))
        let groups = try OTLPNestedDecoder.decodeRequest(body)
        let result = OTLPSpanExtractor.extract(from: groups)
        let r = result.spans[0]
        let svc = r.serviceName ?? ""
        #expect(!svc.contains("AKIAFAKEEXAMPLENOTRE"))
        #expect(svc.contains("[AWS_ACCESS_KEY]"))
    }

    @Test("Legitimate service.name 'claude-code' resolves agent tool unchanged")
    func legitimateServiceNamePreserved() throws {
        let span = E.span(
            traceId: traceIdBytes, spanId: spanIdBytes,
            name: "tool.execute",
            startNs: 100, endNs: 200,
            attributes: []
        )
        let body = Data(E.exportRequest([
            E.resourceSpans(
                resource: E.resource(serviceName: "claude-code"),
                scope: E.scopeSpans(scopeName: "scope", spans: [span])
            )
        ]))
        let groups = try OTLPNestedDecoder.decodeRequest(body)
        let result = OTLPSpanExtractor.extract(from: groups)
        let r = result.spans[0]
        // Sanitization must not over-redact a legitimate service name.
        // The agent_tool resolver depends on this exact match.
        #expect(r.serviceName == "claude-code")
        #expect(r.agentTool == .claudeCode)
    }

    @Test("gen_ai.provider.name + gen_ai.system are sanitized in their column projection")
    func genAiFieldsRedacted() throws {
        let span = E.span(
            traceId: traceIdBytes, spanId: spanIdBytes,
            name: "tool.execute",
            startNs: 100, endNs: 200,
            attributes: [
                ("gen_ai.provider.name", "anthropic"),
                // Stripe shape uses underscore (`sk_test_…`), not dash
                // — explicit so we test the stripeKey path rather
                // than the openaiKey path which also matches `sk-…`.
                ("gen_ai.system",        "openai sk_test_FAKEKEY1234567890123456789012"),
            ]
        )
        let body = Data(E.exportRequest([
            E.resourceSpans(
                resource: E.resource(serviceName: nil),
                scope: E.scopeSpans(scopeName: "scope", spans: [span])
            )
        ]))
        let groups = try OTLPNestedDecoder.decodeRequest(body)
        let result = OTLPSpanExtractor.extract(from: groups)
        let r = result.spans[0]
        // The legitimate "anthropic" string survives.
        #expect(r.providerName == "anthropic")
        // The system field had a stripe key shape mixed in; it must be
        // redacted in the column projection.
        let legacy = r.legacyGenAiSystem ?? ""
        #expect(!legacy.contains("FAKEKEY1234567890123456789012"))
        #expect(legacy.contains("[STRIPE_KEY]"))
    }
}
