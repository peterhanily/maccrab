// AlertSinkTests.swift
// MacCrabCoreTests
//
// Pin the v1.6.19 AlertSink contract: every alert reaches AlertStore through
// AlertSink (single chokepoint) and AlertSink applies AlertDeduplicator
// before insertion. These tests are the regression net for the v1.6.9
// NoiseFilter-layering bug class — if a future change re-introduces a
// direct AlertStore.insert outside the sink, these tests will not catch
// it (that's the job of pre-release-audit.sh in task #10), but they DO
// catch silent breakage of dedup ordering, missing await chains, and
// double-counting bugs.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("AlertSink contract")
struct AlertSinkTests {

    // MARK: - Helpers

    private func makeSink() async throws -> (sink: AlertSink, store: AlertStore, dir: URL) {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-alertsink-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let store = try AlertStore(directory: tempDir.path)
        let dedup = AlertDeduplicator(suppressionWindow: 60)
        let sink = AlertSink(alertStore: store, deduplicator: dedup)
        return (sink, store, tempDir)
    }

    private func makeAlert(
        ruleId: String = "test.rule",
        processPath: String? = "/usr/bin/example",
        severity: Severity = .medium
    ) -> Alert {
        Alert(
            ruleId: ruleId,
            ruleTitle: "Test rule",
            severity: severity,
            eventId: UUID().uuidString,
            processPath: processPath,
            processName: processPath.map { ($0 as NSString).lastPathComponent },
            description: "test description",
            mitreTactics: nil, mitreTechniques: nil,
            suppressed: false
        )
    }

    /// Reuses the global `makeEvent(...)` helper from MacCrabCoreTests.swift.
    private func event(executable: String = "/usr/bin/example", pid: Int32 = 1234) -> Event {
        makeEvent(processName: (executable as NSString).lastPathComponent,
                  processPath: executable,
                  commandLine: executable,
                  pid: pid)
    }

    // MARK: - Tests

    @Test("submit(alert:event:) inserts the alert into AlertStore on first call")
    func submitInsertsFirst() async throws {
        let (sink, store, dir) = try await makeSink()
        defer { try? FileManager.default.removeItem(at: dir) }

        let inserted = try await sink.submit(alert: makeAlert(), event: event())
        #expect(inserted == true)

        let count = try await store.count()
        #expect(count == 1)
    }

    @Test("submit(alert:event:) suppresses duplicate within the dedup window")
    func submitSuppressesDuplicate() async throws {
        let (sink, store, dir) = try await makeSink()
        defer { try? FileManager.default.removeItem(at: dir) }

        let ev = event()
        let first = try await sink.submit(alert: makeAlert(), event: ev)
        let second = try await sink.submit(alert: makeAlert(), event: ev)
        #expect(first == true)
        #expect(second == false)

        let count = try await store.count()
        #expect(count == 1)

        let stats = await sink.stats()
        #expect(stats.inserted == 1)
        #expect(stats.suppressed == 1)
    }

    @Test("submit(alert:event:) does not dedup across different processPaths")
    func submitDistinguishesProcesses() async throws {
        let (sink, store, dir) = try await makeSink()
        defer { try? FileManager.default.removeItem(at: dir) }

        let eventA = event(executable: "/usr/bin/a")
        let eventB = event(executable: "/usr/bin/b")
        let a = try await sink.submit(alert: makeAlert(), event: eventA)
        let b = try await sink.submit(alert: makeAlert(), event: eventB)
        #expect(a == true)
        #expect(b == true)

        let count = try await store.count()
        #expect(count == 2)
    }

    @Test("submit(alert:) without event uses alert.processPath as dedup key")
    func submitNoEventUsesProcessPath() async throws {
        let (sink, store, dir) = try await makeSink()
        defer { try? FileManager.default.removeItem(at: dir) }

        let first = try await sink.submit(alert: makeAlert(processPath: "/Applications/Foo.app/Contents/MacOS/Foo"))
        let second = try await sink.submit(alert: makeAlert(processPath: "/Applications/Foo.app/Contents/MacOS/Foo"))
        #expect(first == true)
        #expect(second == false)

        let count = try await store.count()
        #expect(count == 1)
    }

    @Test("submit(alert:) falls back to ruleId when processPath is nil")
    func submitNoEventFallsBackToRuleId() async throws {
        let (sink, store, dir) = try await makeSink()
        defer { try? FileManager.default.removeItem(at: dir) }

        let first = try await sink.submit(alert: makeAlert(processPath: nil))
        let second = try await sink.submit(alert: makeAlert(processPath: nil))
        #expect(first == true)
        #expect(second == false)

        let count = try await store.count()
        #expect(count == 1)
    }

    @Test("insertEngineBatch passes through without re-dedup")
    func insertEngineBatchPassthrough() async throws {
        let (sink, store, dir) = try await makeSink()
        defer { try? FileManager.default.removeItem(at: dir) }

        // Engine path: caller has already filtered + deduped. Sink inserts
        // the batch as-is. This call must not trigger AlertSink's own dedup
        // — that would suppress legitimate engine emissions.
        let alerts = [
            makeAlert(ruleId: "a"),
            makeAlert(ruleId: "b"),
            makeAlert(ruleId: "c"),
        ]
        try await sink.insertEngineBatch(alerts: alerts)

        let count = try await store.count()
        #expect(count == 3)

        // After a passthrough batch, follow-up direct submits with the SAME
        // ruleId should still go through dedup against their (ruleId, path)
        // tuple — engine batch insertion doesn't pollute the dedup table.
        // (insertEngineBatch deliberately bypasses AlertDeduplicator state.)
        let extra = try await sink.submit(alert: makeAlert(ruleId: "a"), event: event())
        #expect(extra == true)
    }

    @Test("insertEngineBatch with empty array is a no-op")
    func insertEngineBatchEmpty() async throws {
        let (sink, store, dir) = try await makeSink()
        defer { try? FileManager.default.removeItem(at: dir) }

        try await sink.insertEngineBatch(alerts: [])
        let count = try await store.count()
        #expect(count == 0)
    }

    @Test("Concurrent submits with the same key insert exactly one (TOCTOU pin)")
    func concurrentSubmitsAtomic() async throws {
        // Pre-fix, AlertSink called shouldSuppress and recordAlert as two
        // separate actor hops — a TOCTOU window between them allowed two
        // concurrent submits with the same key to both observe "not
        // suppressed" and both insert. Post-fix, shouldSuppressAndRecord is
        // a single atomic actor method. This test pins that behavior:
        // emit 50 concurrent submits with the same key and verify exactly
        // one inserts.
        let (sink, store, dir) = try await makeSink()
        defer { try? FileManager.default.removeItem(at: dir) }

        let ev = event()
        await withTaskGroup(of: Bool.self) { group in
            for _ in 0..<50 {
                group.addTask {
                    (try? await sink.submit(alert: self.makeAlert(), event: ev)) ?? false
                }
            }
            var insertedCount = 0
            for await wasInserted in group where wasInserted {
                insertedCount += 1
            }
            #expect(insertedCount == 1)
        }

        let count = try await store.count()
        #expect(count == 1)

        let stats = await sink.stats()
        #expect(stats.inserted == 1)
        #expect(stats.suppressed == 49)
    }

    @Test("stats() reflects inserted and suppressed counts after mixed traffic")
    func statsAccumulate() async throws {
        let (sink, _, dir) = try await makeSink()
        defer { try? FileManager.default.removeItem(at: dir) }

        let ev = event()
        // 1st insert: new
        _ = try await sink.submit(alert: makeAlert(ruleId: "x"), event: ev)
        // 2nd insert: same key → suppressed
        _ = try await sink.submit(alert: makeAlert(ruleId: "x"), event: ev)
        // 3rd insert: different rule → new
        _ = try await sink.submit(alert: makeAlert(ruleId: "y"), event: ev)
        // 4th insert: different processPath fallback (no event) → new
        _ = try await sink.submit(alert: makeAlert(ruleId: "z", processPath: "/bin/z"))

        let stats = await sink.stats()
        #expect(stats.inserted == 3)
        #expect(stats.suppressed == 1)
    }
}
