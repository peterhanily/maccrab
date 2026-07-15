// BatchedEventWriterTests.swift
// v1.21.4 (F2 / A1) — the async batched events.db writer that decouples the
// hot detection consumer from per-event SQLite transactions. These drive a
// REAL EventStore in a temp dir so batching + overflow behaviour travel the
// true insert path.

import Testing
import Foundation
@testable import MacCrabCore
@testable import MacCrabAgentKit

@Suite("F2/A1 BatchedEventWriter")
struct BatchedEventWriterTests {

    private func makeEvent(_ i: Int) -> Event {
        let proc = ProcessInfo(
            pid: Int32(3000 + i), ppid: 1, rpid: 1,
            name: "bw\(i)", executable: "/bin/bw\(i)",
            commandLine: "/bin/bw\(i)", args: [],
            workingDirectory: "/",
            userId: 501, userName: "t", groupId: 20,
            startTime: Date(timeIntervalSince1970: 1_700_000_000 + Double(i)), ancestors: [],
            isPlatformBinary: false
        )
        return Event(
            timestamp: Date(timeIntervalSince1970: 1_700_000_000 + Double(i)),
            eventCategory: .process, eventType: .start,
            eventAction: "exec", process: proc
        )
    }

    private func tempStore() throws -> (EventStore, URL) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("bw-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return (try EventStore(directory: dir.path), dir)
    }

    /// Poll count() until it reaches `target` or the retry budget is spent
    /// (the drain is async, so the row count converges rather than being
    /// instantaneous).
    private func waitForCount(_ store: EventStore, target: Int, tries: Int = 40) async throws -> Int {
        var last = 0
        for _ in 0..<tries {
            last = try await store.count()
            if last >= target { return last }
            try? await Task.sleep(nanoseconds: 25_000_000) // 25ms
        }
        return last
    }

    @Test("shutdown flushes a below-threshold partial batch — every event persists")
    func shutdownFlushesPartial() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        // Threshold high enough that no auto-drain fires: the ONLY flush is
        // shutdown's, so this proves the shutdown path alone persists the batch.
        let writer = BatchedEventWriter(store: store, flushThreshold: 100_000, hardCap: 100_000)
        for i in 0..<100 { await writer.enqueue(makeEvent(i)) }
        #expect(try await store.count() == 0, "nothing flushed before shutdown (batched, not inline)")
        await writer.shutdown()
        #expect(try await store.count() == 100, "shutdown flushes the partial batch")
        #expect(writer.droppedCount == 0)
    }

    @Test("crossing the flush threshold drains automatically off the caller")
    func autoDrainOnThreshold() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let writer = BatchedEventWriter(store: store, flushThreshold: 50, hardCap: 100_000)
        for i in 0..<500 { await writer.enqueue(makeEvent(i)) }
        // The auto-drain loops until the buffer empties, so all 500 land without
        // an explicit shutdown — poll for convergence.
        let n = try await waitForCount(store, target: 500)
        #expect(n == 500, "auto-drain persisted all events (got \(n))")
        #expect(writer.droppedCount == 0)
    }

    @Test("hard cap drops the NEWEST events and counts them distinctly")
    func hardCapDropsAndCounts() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        // High threshold so no drain runs until shutdown; cap at 10 so the
        // 11th..25th enqueue overflow and drop.
        let writer = BatchedEventWriter(store: store, flushThreshold: 100_000, hardCap: 10)
        for i in 0..<25 { await writer.enqueue(makeEvent(i)) }
        #expect(writer.droppedCount == 15, "25 enqueued, cap 10 → 15 dropped")
        await writer.shutdown()
        #expect(try await store.count() == 10, "only the first 10 (pre-overflow) persisted")
    }
}
