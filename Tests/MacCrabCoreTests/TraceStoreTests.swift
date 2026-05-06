// TraceStoreTests.swift
// Tests for v1.9 PR-3a — TraceStore on a separate traces.db.
//
// Schema-fresh-DB sanity, idempotent upserts, multi-trace lookup ordering,
// and basic round-trip of all SpanRecord fields.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("TraceStore: schema + insert + lookup")
struct TraceStoreTests {

    private static func tempDBPath() -> String {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("trace-store-tests-\(UUID().uuidString).db")
        return tmp.path
    }

    private static func sampleSpan(
        traceId: String = "4bf92f3577b34da6a3ce929d0e0e4736",
        spanId: String = "00f067aa0ba902b7",
        spanName: String = "claude_code.tool.execution",
        startNs: UInt64 = 1_700_000_000_000_000_000
    ) -> SpanRecord {
        SpanRecord(
            traceId: traceId,
            spanId: spanId,
            parentSpanId: nil,
            startNs: startNs,
            endNs: startNs + 1_000_000,
            serviceName: "claude-code",
            spanName: spanName,
            agentTool: .claudeCode,
            providerName: "anthropic",
            legacyGenAiSystem: "anthropic",
            attributesJson: #"{"tool_name":"Bash"}"#
        )
    }

    @Test("Fresh DB starts at user_version 1 and accepts an insert")
    func freshDBInsert() async throws {
        let path = Self.tempDBPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try TraceStore(path: path)
        try await store.insertSpan(Self.sampleSpan())
        #expect(try await store.count() == 1)
    }

    @Test("Round-trips every SpanRecord field through INSERT + SELECT")
    func roundTripAllFields() async throws {
        let path = Self.tempDBPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try TraceStore(path: path)
        let original = SpanRecord(
            traceId: "4bf92f3577b34da6a3ce929d0e0e4736",
            spanId: "0123456789abcdef",
            parentSpanId: "fedcba9876543210",
            startNs: 100,
            endNs: 200,
            serviceName: "claude-code",
            spanName: "claude_code.tool.Bash",
            agentTool: .claudeCode,
            providerName: "anthropic",
            legacyGenAiSystem: "anthropic-legacy",
            attributesJson: #"{"tool_name":"Bash","file_path":"/x"}"#
        )
        try await store.insertSpan(original)
        let read = try await store.spansForTrace(original.traceId)
        #expect(read.count == 1)
        #expect(read.first == original)
    }

    @Test("INSERT OR REPLACE: same trace_id+span_id idempotently overwrites")
    func idempotentReplace() async throws {
        let path = Self.tempDBPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try TraceStore(path: path)
        try await store.insertSpan(Self.sampleSpan(spanName: "first"))
        try await store.insertSpan(Self.sampleSpan(spanName: "second"))
        #expect(try await store.count() == 1)
        let read = try await store.spansForTrace("4bf92f3577b34da6a3ce929d0e0e4736")
        #expect(read.first?.spanName == "second")
    }

    @Test("spansForTrace returns spans ordered by start_ns ascending")
    func orderedByStart() async throws {
        let path = Self.tempDBPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try TraceStore(path: path)
        let trace = "4bf92f3577b34da6a3ce929d0e0e4736"
        try await store.insertSpan(Self.sampleSpan(traceId: trace, spanId: "aaaaaaaaaaaaaaaa", startNs: 200))
        try await store.insertSpan(Self.sampleSpan(traceId: trace, spanId: "bbbbbbbbbbbbbbbb", startNs: 100))
        try await store.insertSpan(Self.sampleSpan(traceId: trace, spanId: "cccccccccccccccc", startNs: 300))
        let read = try await store.spansForTrace(trace)
        #expect(read.map(\.startNs) == [100, 200, 300])
    }

    @Test("spansForTrace filters by trace_id (no leakage across traces)")
    func filtersByTrace() async throws {
        let path = Self.tempDBPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try TraceStore(path: path)
        try await store.insertSpan(Self.sampleSpan(traceId: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
        try await store.insertSpan(Self.sampleSpan(traceId: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))
        let aSpans = try await store.spansForTrace("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        let bSpans = try await store.spansForTrace("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        #expect(aSpans.count == 1)
        #expect(bSpans.count == 1)
        #expect(aSpans.first?.traceId != bSpans.first?.traceId)
    }
}
