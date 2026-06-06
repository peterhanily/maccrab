// EventStorePayloadCapTests.swift
//
// v1.12.6: regression coverage for the per-event raw_json size cap added
// to `EventStore.insert(event:)`.
//
// Background: live events.db rows had four payloads near 1 MB each
// (base64-encoded appcast.xml passed through `python3 -c '...'`).
// Median exec event raw_json is ~700 B; P99 < 16 KB. The 64 KB cap
// trims the long-tail outliers while leaving normal traffic untouched.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("EventStore: payload size cap (v1.12.6)")
struct EventStorePayloadCapTests {

    // MARK: Helpers

    private func makeTempStore() async throws -> (EventStore, URL) {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-payloadcap-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        let store = try EventStore(directory: tmp.path)
        return (store, tmp)
    }

    private func makeEvent(args: [String], commandLine: String? = nil) -> Event {
        let proc = ProcessInfo(
            pid: 1234, ppid: 1, rpid: 1,
            name: "payloadcap-test",
            executable: "/usr/local/bin/payloadcap-test",
            commandLine: commandLine ?? args.joined(separator: " "),
            args: args,
            workingDirectory: "/",
            userId: 501, userName: "tester", groupId: 20,
            startTime: Date(),
            ancestors: [],
            isPlatformBinary: false
        )
        return Event(
            timestamp: Date(),
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: proc
        )
    }

    /// Fetch the single stored event back. Asserts exactly one row.
    private func fetchOnly(_ store: EventStore) async throws -> Event {
        let rows = try await store.events(since: .distantPast, limit: 10)
        #expect(rows.count == 1)
        return rows[0]
    }

    // MARK: - Tests

    @Test("maxRawJsonBytes default is 65536")
    func defaultCapValue() {
        // Sanity assertion so any future change to the constant is
        // visible in the PR diff. The 64 KB cap is field-calibrated
        // and not safe to nudge without re-validating the long tail.
        #expect(EventStore.maxRawJsonBytes == 65_536)
    }

    @Test("insertEvent passes through under cap (no enrichment markers)")
    func passthroughUnderCap() async throws {
        let (store, tmp) = try await makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        // Build an event with ~10 KB of args spread over many small entries.
        // Stays well under the 64 KB cap.
        let smallArgs = (0..<200).map { _ in String(repeating: "x", count: 50) }
        let event = makeEvent(args: smallArgs)

        let beforeCount = await store.payloadTruncatedTotal()
        try await store.insert(event: event)

        let stored = try await fetchOnly(store)
        #expect(stored.enrichments["payload.truncated"] == nil)
        #expect(stored.enrichments["payload.original_bytes"] == nil)
        #expect(stored.process.args == smallArgs)
        #expect(await store.payloadTruncatedTotal() == beforeCount)
    }

    @Test("insertEvent truncates a single oversized arg")
    func truncateSingleOversizedArg() async throws {
        let (store, tmp) = try await makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let bigArg = String(repeating: "A", count: 200_000)  // 200 KB
        let event = makeEvent(args: ["/usr/bin/python3", "-c", bigArg])

        try await store.insert(event: event)

        let stored = try await fetchOnly(store)

        // Marker for the oversized arg.
        #expect(stored.process.args.count == 3)
        #expect(stored.process.args[0] == "/usr/bin/python3")
        #expect(stored.process.args[1] == "-c")
        #expect(stored.process.args[2] == "<truncated:200000 bytes>")

        // Enrichments.
        #expect(stored.enrichments["payload.truncated"] == "true")
        let originalBytesStr = stored.enrichments["payload.original_bytes"]
        #expect(originalBytesStr != nil)
        if let s = originalBytesStr, let originalBytes = Int(s) {
            // Original event encoded to > 200 KB (the arg itself was 200 KB).
            #expect(originalBytes > 200_000)
        }

        // Counter incremented.
        #expect(await store.payloadTruncatedTotal() == 1)
    }

    @Test("insertEvent truncates multiple oversized args")
    func truncateMultipleOversizedArgs() async throws {
        let (store, tmp) = try await makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        // Three args, each > argTruncationThreshold (4 KB), total > 64 KB.
        let big1 = String(repeating: "1", count: 30_000)
        let big2 = String(repeating: "2", count: 30_000)
        let big3 = String(repeating: "3", count: 30_000)
        let event = makeEvent(args: [big1, big2, big3])

        try await store.insert(event: event)

        let stored = try await fetchOnly(store)
        #expect(stored.process.args == [
            "<truncated:30000 bytes>",
            "<truncated:30000 bytes>",
            "<truncated:30000 bytes>",
        ])
        #expect(stored.enrichments["payload.truncated"] == "true")
    }

    @Test("insertEvent leaves small args alone, truncates only oversized ones")
    func mixedArgSizes() async throws {
        let (store, tmp) = try await makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let small = "small-arg"
        let big = String(repeating: "B", count: 100_000)
        let event = makeEvent(args: [small, big, small])

        try await store.insert(event: event)

        let stored = try await fetchOnly(store)
        #expect(stored.process.args.count == 3)
        #expect(stored.process.args[0] == small)
        #expect(stored.process.args[1] == "<truncated:100000 bytes>")
        #expect(stored.process.args[2] == small)
        #expect(stored.enrichments["payload.truncated"] == "true")
    }

    @Test("insertEvent applies final fallback for non-arg overflow (huge commandLine)")
    func nonArgOverflowFallback() async throws {
        let (store, tmp) = try await makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        // Empty args; mass lives in commandLine. Per-arg pass won't help.
        // 200 KB commandLine forces pass 2 (commandLine collapse).
        let bigCmd = String(repeating: "C", count: 200_000)
        let event = makeEvent(args: [], commandLine: bigCmd)

        try await store.insert(event: event)

        let stored = try await fetchOnly(store)
        // Must still be stored. (events() returning it proves the row landed.)
        #expect(stored.enrichments["payload.truncated"] == "true")
        // commandLine must be collapsed to a marker (pass 2 of the pipeline).
        #expect(stored.process.commandLine.hasPrefix("<truncated:"))
        #expect(stored.process.commandLine.hasSuffix("bytes>"))
    }

    @Test("insertEvent keeps stored raw_json under maxRawJsonBytes after truncation")
    func storedRowFitsUnderCap() async throws {
        // We can't directly read the raw_json column from outside the
        // actor, but we can re-encode the round-tripped event and assert
        // it fits. (The decoded form's encoded size is the upper bound
        // of what landed in the DB for the structured-truncation case.)
        let (store, tmp) = try await makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let bigArg = String(repeating: "Z", count: 500_000)
        let event = makeEvent(args: [bigArg])

        try await store.insert(event: event)
        let stored = try await fetchOnly(store)

        let encoder = JSONEncoder()
        let bytes = try encoder.encode(stored).count
        #expect(bytes <= EventStore.maxRawJsonBytes)
    }

    @Test("insertEvent boundary: event exactly at cap is not truncated")
    func boundaryExactlyAtCap() async throws {
        let (store, tmp) = try await makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        // Calibrate an arg so the encoded event lands right around the cap,
        // then assert it's NOT truncated.
        //
        // Determinism note: the event's timestamp encodes as a Double whose
        // decimal-string length varies run-to-run (e.g. "…316.2495" vs
        // "…316.249535"), so an arg calibrated against one timestamp can encode
        // a few bytes larger when a fresh event is built below. We therefore
        // calibrate to a small headroom UNDER the cap so that drift can't push
        // the final instance over — the over-cap side is covered separately by
        // `boundaryOneByteOver`. Without the margin this test flaked under the
        // parallel suite (passed in isolation).
        let encoder = JSONEncoder()
        let target = EventStore.maxRawJsonBytes - 64
        var lo = 1
        var hi = target
        var calibratedArg = ""
        for _ in 0..<32 {
            let mid = (lo + hi) / 2
            let candidate = String(repeating: "a", count: mid)
            let event = makeEvent(args: [candidate])
            let size = try encoder.encode(event).count
            if size == target {
                calibratedArg = candidate
                break
            } else if size < target {
                calibratedArg = candidate
                lo = mid + 1
            } else {
                hi = mid - 1
            }
        }
        // We may not hit exactly the cap byte-for-byte; assert we found
        // a candidate at-or-under the cap and that it round-trips intact.
        let event = makeEvent(args: [calibratedArg])
        let encodedSize = try encoder.encode(event).count
        #expect(encodedSize <= EventStore.maxRawJsonBytes)

        try await store.insert(event: event)
        let stored = try await fetchOnly(store)
        #expect(stored.enrichments["payload.truncated"] == nil)
        #expect(stored.process.args == [calibratedArg])
    }

    @Test("insertEvent boundary: 1 byte over cap triggers truncation")
    func boundaryOneByteOver() async throws {
        let (store, tmp) = try await makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        // Build an event whose encoded form is just barely over the cap.
        // Start from a known-large arg and let the cap path kick in.
        let arg = String(repeating: "x", count: EventStore.maxRawJsonBytes)
        let event = makeEvent(args: [arg])
        let encoder = JSONEncoder()
        let originalSize = try encoder.encode(event).count
        #expect(originalSize > EventStore.maxRawJsonBytes)

        try await store.insert(event: event)
        let stored = try await fetchOnly(store)
        #expect(stored.enrichments["payload.truncated"] == "true")
        // Per-arg threshold is 4 KB, so this arg should be replaced.
        #expect(stored.process.args[0].hasPrefix("<truncated:"))
    }

    @Test("payloadTruncatedTotal accumulates across multiple oversized inserts")
    func counterAccumulates() async throws {
        let (store, tmp) = try await makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        for i in 0..<3 {
            let big = String(repeating: "D", count: 100_000 + i)
            try await store.insert(event: makeEvent(args: [big]))
        }
        // And one under-cap insert should NOT bump the counter.
        try await store.insert(event: makeEvent(args: ["small"]))

        #expect(await store.payloadTruncatedTotal() == 3)
    }
}
