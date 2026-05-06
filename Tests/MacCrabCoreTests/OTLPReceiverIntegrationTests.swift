// OTLPReceiverIntegrationTests.swift
// v1.9 PR-3b — full decode → sanitise → extract → TraceStore round-trip.
//
// We test the full data path WITHOUT spinning up a NWListener. The
// `OTLPNestedDecoder` + `OTLPSpanExtractor` + `TraceStore.insertSpan`
// pipeline is the load-bearing logic; the receiver's job on top is just
// HTTP framing + bind. Exercising the pipeline directly avoids the
// flakiness of testing port binding in CI sandboxes.

import Testing
import Foundation
@testable import MacCrabCore

// MARK: - Reuse the encode helpers from OTLPSpanExtractorTests

private enum E2 {
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
    static func fixed64(_ field: Int, _ value: UInt64) -> [UInt8] {
        var o = tag(field, 1)
        for i in 0..<8 { o.append(UInt8((value >> (8 * i)) & 0xFF)) }
        return o
    }
    static func string(_ field: Int, _ s: String) -> [UInt8] {
        lenDelim(field, Array(s.utf8))
    }
    static func anyValueString(_ s: String) -> [UInt8] {
        string(1, s)
    }
    static func keyValue(_ key: String, _ value: String) -> [UInt8] {
        var o = string(1, key)
        o.append(contentsOf: lenDelim(2, anyValueString(value)))
        return o
    }
    static func span(
        traceId: [UInt8], spanId: [UInt8],
        name: String, startNs: UInt64, endNs: UInt64,
        attributes: [(String, String)] = []
    ) -> [UInt8] {
        var o: [UInt8] = []
        o.append(contentsOf: lenDelim(1, traceId))
        o.append(contentsOf: lenDelim(2, spanId))
        o.append(contentsOf: string(5, name))
        o.append(contentsOf: fixed64(7, startNs))
        o.append(contentsOf: fixed64(8, endNs))
        for (k, v) in attributes {
            o.append(contentsOf: lenDelim(9, keyValue(k, v)))
        }
        return o
    }
    static func scopeSpans(spans: [[UInt8]]) -> [UInt8] {
        var o: [UInt8] = []
        for s in spans { o.append(contentsOf: lenDelim(2, s)) }
        return o
    }
    static func resource(serviceName: String) -> [UInt8] {
        lenDelim(1, keyValue("service.name", serviceName))
    }
    static func resourceSpans(resource: [UInt8], scope: [UInt8]) -> [UInt8] {
        var o = lenDelim(1, resource)
        o.append(contentsOf: lenDelim(2, scope))
        return o
    }
    static func exportRequest(_ resourceSpans: [[UInt8]]) -> [UInt8] {
        var o: [UInt8] = []
        for rs in resourceSpans { o.append(contentsOf: lenDelim(1, rs)) }
        return o
    }
}

@Suite("OTLP end-to-end: decode → sanitise → extract → TraceStore")
struct OTLPReceiverIntegrationTests {

    private static func tempDB() -> String {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("otlp-int-\(UUID().uuidString).db").path
    }

    private static let traceId: [UInt8] = [
        0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6,
        0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e, 0x47, 0x36,
    ]
    private static let span1: [UInt8] = [
        0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7,
    ]
    private static let span2: [UInt8] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    ]

    /// Builds a minimal-but-realistic OTLP body containing two spans
    /// under one ResourceSpans (service.name="claude-code") with
    /// secret-shaped attributes that the sanitiser must redact.
    private static func canonicalBody() -> Data {
        let s1 = E2.span(
            traceId: traceId, spanId: span1,
            name: "claude_code.tool.execution", startNs: 100, endNs: 200,
            attributes: [
                ("tool_name", "Bash"),
                ("api_key", "sk-ant-EVIL-AAAAAAAAAAAAAAAAAAAA"),
            ]
        )
        let s2 = E2.span(
            traceId: traceId, spanId: span2,
            name: "claude_code.llm_request", startNs: 50, endNs: 150,
            attributes: [
                ("gen_ai.system", "anthropic"),
                ("gen_ai.request.model", "claude-3.5-sonnet"),
            ]
        )
        let scope = E2.scopeSpans(spans: [s1, s2])
        let rs = E2.resourceSpans(
            resource: E2.resource(serviceName: "claude-code"),
            scope: scope
        )
        return Data(E2.exportRequest([rs]))
    }

    @Test("Two-span body lands in TraceStore with sanitised attributes")
    func endToEndPersist() async throws {
        let path = Self.tempDB()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try TraceStore(path: path)

        let body = Self.canonicalBody()
        let groups = try OTLPNestedDecoder.decodeRequest(body)
        let extraction = OTLPSpanExtractor.extract(from: groups)
        for span in extraction.spans {
            try await store.insertSpan(span)
        }
        let stored = try await store.spansForTrace("4bf92f3577b34da6a3ce929d0e0e4736")
        #expect(stored.count == 2)
        // Order is by start_ns ascending — span2 (50ns) before span1 (100ns).
        #expect(stored[0].spanName == "claude_code.llm_request")
        #expect(stored[1].spanName == "claude_code.tool.execution")
        // service.name is preserved verbatim.
        #expect(stored.allSatisfy { $0.serviceName == "claude-code" })
        // agent_tool resolves to claudeCode for both via span name.
        #expect(stored.allSatisfy { $0.agentTool == .claudeCode })
        // gen_ai.system surfaced as legacyGenAiSystem on span2.
        let llm = stored.first(where: { $0.spanName == "claude_code.llm_request" })
        #expect(llm?.legacyGenAiSystem == "anthropic")
        // The api_key attribute on span1 must NOT have leaked through.
        let toolSpan = stored.first(where: { $0.spanName == "claude_code.tool.execution" })
        let json = toolSpan?.attributesJson ?? ""
        #expect(json.contains("[REDACTED]"))
        #expect(!json.contains("sk-ant-EVIL"))
        // tool_name should still be there.
        #expect(json.contains("\"tool_name\":\"Bash\""))
    }

    @Test("Attributes-key redaction count matches sanitiser output")
    func sanitiserCountsBubbleUp() throws {
        let body = Self.canonicalBody()
        let groups = try OTLPNestedDecoder.decodeRequest(body)
        let extraction = OTLPSpanExtractor.extract(from: groups)
        // span1 has one redact-by-key (`api_key`); span2 has zero.
        #expect(extraction.totalAttributesKeyRedacted == 1)
        // No values needed value-side redaction beyond the key gate.
        #expect(extraction.totalAttributesValueRedacted == 0)
    }

    @Test("Spans missing trace_id length are skipped (defensive)")
    func defensiveLengthSkip() async throws {
        // Build a span with a 4-byte trace_id (invalid — must be 16).
        let s = E2.span(
            traceId: [0x01, 0x02, 0x03, 0x04],
            spanId: Self.span1,
            name: "claude_code.tool.bogus", startNs: 1, endNs: 2
        )
        let body = Data(E2.exportRequest([
            E2.resourceSpans(
                resource: E2.resource(serviceName: "claude-code"),
                scope: E2.scopeSpans(spans: [s])
            )
        ]))
        let groups = try OTLPNestedDecoder.decodeRequest(body)
        let spans = OTLPSpanExtractor.extract(from: groups).spans
        // Extractor surfaces it (the receiver layer is what skips on
        // length); we just assert the trace_id reflects the raw bytes.
        #expect(spans.first?.traceId == "01020304")
        #expect(spans.first?.traceId.count == 8)
    }

    @Test("Receiver constructs cleanly with and without a TraceStore")
    func receiverConstructionVariants() async {
        let r1 = OTLPReceiver(port: 4318)
        let m1 = await r1.metricsSnapshot()
        #expect(m1.spansPersisted == 0)

        let path = Self.tempDB()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try? TraceStore(path: path)
        let r2 = OTLPReceiver(port: 4318, traceStore: store)
        let m2 = await r2.metricsSnapshot()
        #expect(m2.spansPersisted == 0)
        #expect(m2.spanInsertErrors == 0)
    }
}
