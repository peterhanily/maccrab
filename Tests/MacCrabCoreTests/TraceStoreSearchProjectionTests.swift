import Testing
import Foundation
@testable import MacCrabCore

/// `attributes_json` is AES-GCM encrypted — correctly, since it carries
/// usernames, absolute project paths, session/org ids and tool inputs. But that
/// left every span attribute unqueryable: no FTS, no LIKE, no way to answer
/// "which agent trace touched ~/.ssh/id_rsa". The `search_text` projection
/// restores search WITHOUT weakening the encryption, mirroring what
/// tracegraph.db already does with `trace_entities.display_name`.
@Suite("TraceStore: searchable projection")
struct TraceStoreSearchProjectionTests {

    private func record(
        traceId: String = "t1", spanId: String = "s1",
        spanName: String = "claude_code.tool.execution",
        attrs: [String: String] = [:]
    ) -> SpanRecord {
        let json = attrs.isEmpty ? nil
            : String(data: try! JSONSerialization.data(withJSONObject: attrs), encoding: .utf8)
        return SpanRecord(
            traceId: traceId, spanId: spanId, parentSpanId: nil,
            startNs: 1_700_000_000_000_000_000, endNs: 1_700_000_001_000_000_000,
            serviceName: "claude-code", spanName: spanName,
            agentTool: .claudeCode, providerName: "anthropic",
            legacyGenAiSystem: nil, attributesJson: json)
    }

    // MARK: - Projection content

    @Test("structural columns are always projected")
    func projectsStructuralColumns() {
        let p = TraceStore.searchProjection(for: record())
        #expect(p.contains("claude_code.tool.execution"))
        #expect(p.contains("claude-code"))
        #expect(p.contains("anthropic"))
    }

    @Test("attribute keys and path-shaped values are projected")
    func projectsKeysAndPaths() {
        let p = TraceStore.searchProjection(
            for: record(attrs: ["tool.name": "Read", "file.path": "/Users/x/.ssh/id_rsa"]))
        #expect(p.contains("tool.name"), "attribute keys are schema, always safe")
        #expect(p.contains("Read"))
        #expect(p.contains("/Users/x/.ssh/id_rsa"),
                "the path is the whole point — this is what an analyst searches for")
    }

    // MARK: - Privacy contract

    @Test("free-form prose is NOT projected into the plaintext column")
    func doesNotProjectProse() {
        let prompt = "please refactor the auth module and delete the old tests"
        let p = TraceStore.searchProjection(for: record(attrs: ["prompt": prompt]))
        #expect(p.contains("prompt"), "the key is projected")
        #expect(!p.contains(prompt),
                "prompt text must stay in the ENCRYPTED blob — whitespace is the discriminator")
        #expect(!p.contains("refactor"))
    }

    @Test("over-long values are NOT projected even without whitespace")
    func doesNotProjectOverlongValues() {
        let blob = String(repeating: "A", count: TraceStore.maxProjectedValueLength + 1)
        let p = TraceStore.searchProjection(for: record(attrs: ["blob": blob]))
        #expect(!p.contains(blob))
    }

    @Test("projectability rule: paths and identifiers yes, prose no")
    func projectabilityRule() {
        #expect(TraceStore.isProjectableValue("/Users/x/.aws/credentials"))
        #expect(TraceStore.isProjectableValue("Bash"))
        #expect(!TraceStore.isProjectableValue("some words here"))
        #expect(!TraceStore.isProjectableValue(""))
        #expect(!TraceStore.isProjectableValue("line\nbreak"))
    }

    // MARK: - Round trip through the store

    @Test("a span is findable by a path buried in its encrypted attributes")
    func searchFindsPathFromEncryptedAttrs() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("ts-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let store = try TraceStore(directory: dir.path)

        try await store.insertSpan(record(
            spanId: "s-hit", attrs: ["file.path": "/Users/x/.ssh/id_rsa"]))
        try await store.insertSpan(record(
            traceId: "t2", spanId: "s-miss", attrs: ["file.path": "/tmp/harmless.txt"]))

        let hits = try await store.searchSpans(matching: ".ssh/id_rsa")
        #expect(hits.count == 1)
        #expect(hits.first?.spanId == "s-hit")

        let none = try await store.searchSpans(matching: "no-such-thing")
        #expect(none.isEmpty)
    }

    @Test("LIKE wildcards in the query are escaped, not honoured")
    func escapesLikeWildcards() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("ts-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let store = try TraceStore(directory: dir.path)
        try await store.insertSpan(record(attrs: ["file.path": "/tmp/a.txt"]))

        // A bare "%" must not match everything.
        #expect(try await store.searchSpans(matching: "%").isEmpty,
                "an unescaped % would turn any query into match-all")
    }

    @Test("backfill makes pre-migration rows searchable and is idempotent")
    func backfillPopulatesNullProjections() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("ts-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let store = try TraceStore(directory: dir.path)
        try await store.insertSpan(record(attrs: ["file.path": "/Users/x/.aws/credentials"]))

        // Simulate a pre-migration row: clear the projection the insert wrote.
        try await store.clearSearchProjectionForTesting()
        #expect(try await store.searchSpans(matching: ".aws/credentials").isEmpty,
                "precondition: a NULL projection is unsearchable")

        let filled = try await store.backfillSearchProjection()
        #expect(filled == 1)
        #expect(try await store.searchSpans(matching: ".aws/credentials").count == 1,
                "backfill must recover searchability from the ENCRYPTED attributes")

        #expect(try await store.backfillSearchProjection() == 0,
                "backfill only touches NULL rows — second run is a no-op")
    }
}
