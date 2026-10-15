import Testing
import Foundation
@testable import MacCrabApp
@testable import MacCrabCore

/// Local reader references remain alive: dropping a cache is NOT proof of
/// sqlite3_close. Assert real writer progress and permanent retirement.
@Suite("Events idle retention and WAL reader retirement", .serialized)
@MainActor
struct WalPinIdleReleaseTests {
    private func event(_ index: Int) -> Event {
        let time = Date(timeIntervalSince1970: 1_700_000_000 + Double(index))
        return Event(timestamp: time, eventCategory: .process, eventType: .start,
                     eventAction: "exec", process: MacCrabCore.ProcessInfo(
                        pid: Int32(7_000 + index), ppid: 1, rpid: 1,
                        name: "idle-fixture", executable: "/usr/bin/idle-fixture",
                        commandLine: "idle-fixture", args: [], workingDirectory: "/",
                        userId: 501, userName: "fixture", groupId: 20,
                        startTime: time, ancestors: [], isPlatformBinary: false))
    }
    private func query() -> EventQuerySession.Query {
        .init(filter: nil, since: .distantPast, until: .distantFuture,
              category: nil, acceptsIncremental: false)
    }
    private func directory() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("walpin-\(UUID())")
    }
    private func writeHeartbeat(_ dir: URL, pid: Int = 71_001, age: Double = 0) throws {
        let raw: [String: Any] = ["engine_pid": pid, "engine_started_at_unix": 1_700_000_000.0,
            "engine_version": "fixture", "engine_build": "fixture", "boot_phase": "ready",
            "liveness": true, "written_at_unix": Date().timeIntervalSince1970 - age]
        try JSONSerialization.data(withJSONObject: raw)
            .write(to: dir.appendingPathComponent("heartbeat.json"), options: .atomic)
    }
    private func expectRetired(_ reader: EventStore) async throws {
        #expect(await reader.permitsIdleReadOnlyRetention() == false)
        do {
            _ = try await reader.exactEventsSnapshot(since: .distantPast, limit: 10)
            Issue.record("Old read-only handle was not permanently retired")
        } catch is CancellationError { }
    }

    @Test("Certified idle reader stays warm without blocking the writer checkpoint")
    func idleReaderRetention() async throws {
        let dir = directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let writer = try EventStore(directory: dir.path)
        try await writer.insert(event: event(0))
        try writeHeartbeat(dir)
        let reader = try EventStore(directory: dir.path, forceReadOnly: true)
        let app = AppState(engineSource: .init(directory: dir.path), startBackgroundWork: false)
        defer { app.discardEventReaderForTesting() }
        app.primeCachedEventStoreForTesting(reader)
        let initial = try await app.readEventQuery(query(), limit: 10)
        #expect(initial?.events.count == 1)
        let decodedBefore = await reader.journalBaseBlockDecodesForTesting
        #expect(decodedBefore > 0 && app.eventReaderAdmissionsForTesting == 0)
        app.stopPolling()
        await app.waitForEventReaderCertificationForTesting()
        #expect(app.hasCachedEventStoreForTesting)
        #expect(await reader.permitsIdleReadOnlyRetention())
        try await writer.insert(event: event(1))
        #expect(await writer.walCheckpointTruncate(), "Retained idle reader must hold no WAL read mark")
        do {
            _ = try await app.readEventQuery(query(), limit: 10)
            Issue.record("Paused owner admitted a new event read")
        } catch is CancellationError { }
        app.resumeEventReaderForTesting()
        let resumed = try await app.readEventQuery(query(), limit: 10)
        #expect(resumed?.events.count == 2)
        #expect(await reader.permitsIdleReadOnlyRetention())
        #expect(await reader.journalBaseBlockDecodesForTesting > decodedBefore,
                "Same retained reader must perform normal authenticated refresh")
        #expect(app.eventReaderAdmissionsForTesting == 0)
        #expect(await writer.walCheckpointTruncate())
    }

    @Test("Resume before certification retires rather than un-retiring")
    func pendingCertificateResume() async throws {
        let dir = directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let writer = try EventStore(directory: dir.path)
        try writeHeartbeat(dir)
        let reader = try EventStore(directory: dir.path, forceReadOnly: true)
        let app = AppState(engineSource: .init(directory: dir.path), startBackgroundWork: false)
        defer { app.discardEventReaderForTesting() }
        app.primeCachedEventStoreForTesting(reader)
        app.stopPolling()
        // No suspension: the MainActor certificate task cannot have run.
        app.resumeEventReaderForTesting()
        #expect(!app.hasCachedEventStoreForTesting)
        try await expectRetired(reader)
        #expect(await writer.walCheckpointTruncate())
    }

    private final class VerificationGate: @unchecked Sendable {
        private let lock = NSLock()
        private let release = DispatchSemaphore(value: 0)
        private var entered = false
        private var timedOut = false
        var hasEntered: Bool { lock.lock(); defer { lock.unlock() }; return entered }
        var didTimeOut: Bool { lock.lock(); defer { lock.unlock() }; return timedOut }
        func blockOnce() {
            lock.lock()
            guard !entered else { lock.unlock(); return }
            entered = true
            lock.unlock()
            let timeout = release.wait(timeout: .now() + 5) == .timedOut
            lock.lock(); timedOut = timeout; lock.unlock()
        }
        func unblock() { release.signal() }
    }
    private func awaitCondition(_ predicate: () -> Bool) async -> Bool {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(2))
        while !predicate(), clock.now < deadline { try? await Task.sleep(for: .milliseconds(1)) }
        return predicate()
    }

    @Test("Active and actor-queued leases cause immediate permanent retirement")
    func activeAndQueuedReadsRetire() async throws {
        let dir = directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let writer = try EventStore(directory: dir.path)
        for index in 0..<10 { try await writer.insert(event: event(index)) }
        try writeHeartbeat(dir)
        let reader = try EventStore(directory: dir.path, forceReadOnly: true)
        let app = AppState(engineSource: .init(directory: dir.path), startBackgroundWork: false)
        defer { app.discardEventReaderForTesting() }
        app.primeCachedEventStoreForTesting(reader)
        let gate = VerificationGate()
        defer { gate.unblock() }
        await reader.setJournalIndexRebuildHookForTesting { _ in gate.blockOnce() }
        let first = Task { try await app.readEventQuery(query(), limit: 10) }
        let entered = await awaitCondition { gate.hasEntered }
        #expect(entered)
        let queued = Task { try await app.readEventAggregates(sinceDay: "2000-01-01", category: nil) }
        let bothAdmitted = await awaitCondition { app.eventReaderAdmissionsForTesting == 2 }
        #expect(bothAdmitted, "Queued call must count before reaching the busy actor")
        app.stopPolling()
        #expect(!app.hasCachedEventStoreForTesting)
        gate.unblock()
        let firstResult = await first.result
        let queuedResult = await queued.result
        for result in [firstResult.map { _ in () }, queuedResult.map { _ in () }] {
            switch result {
            case .success: Issue.record("Retired/queued query published success")
            case .failure(let error): #expect(error is CancellationError)
            }
        }
        await reader.setJournalIndexRebuildHookForTesting(nil)
        #expect(!gate.didTimeOut && app.eventReaderAdmissionsForTesting == 0)
        try await expectRetired(reader)
        #expect(await writer.walCheckpointTruncate())
    }

    @Test("A thrown read failure retires its exact cache and releases admission")
    func failedReadRetires() async throws {
        let dir = directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let writer = try EventStore(directory: dir.path)
        let app = AppState(engineSource: .init(directory: dir.path), startBackgroundWork: false)
        defer { app.discardEventReaderForTesting() }
        let failed = try EventStore(directory: dir.path, forceReadOnly: true)
        app.primeCachedEventStoreForTesting(failed)
        failed.retireReadOnlyReads()
        do {
            _ = try await app.readEventQuery(query(), limit: 10)
            Issue.record("Retired reader did not throw")
        } catch is CancellationError { }
        #expect(!app.hasCachedEventStoreForTesting && app.eventReaderAdmissionsForTesting == 0)
        #expect(await writer.walCheckpointTruncate())
    }

    @Test("Unknown fallback outcome disables idle reuse without cancelling foreground reads")
    func fallbackDoesNotCancelOtherRead() async throws {
        let dir = directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let writer = try EventStore(directory: dir.path)
        try await writer.insert(event: event(0))
        try writeHeartbeat(dir)
        let reader = try EventStore(directory: dir.path, forceReadOnly: true)
        let app = AppState(engineSource: .init(directory: dir.path), startBackgroundWork: false)
        defer { app.discardEventReaderForTesting() }
        app.primeCachedEventStoreForTesting(reader)
        async let exact = app.readEventQuery(query(), limit: 10)
        async let fallback = app.fetchEvidence(alertId: "absent-fixture-alert")
        let (page, evidence) = try await (exact, fallback)
        #expect(page?.events.count == 1 && evidence.isEmpty)
        #expect(app.hasCachedEventStoreForTesting && app.eventReaderAdmissionsForTesting == 0)
        #expect(await reader.permitsIdleReadOnlyRetention(), "Unknown outcome must not retire a shared active reader")
        let following = try await app.readEventQuery(query(), limit: 10)
        #expect(following?.events.count == 1)
        app.stopPolling()
        #expect(!app.hasCachedEventStoreForTesting)
        try await expectRetired(reader)
        #expect(await writer.walCheckpointTruncate())
    }

    @Test("Changed, stale or missing engine identity prevents retained reuse", arguments: ["restart", "stale", "missing", "deferral"])
    func sourceInvalidation(change: String) async throws {
        let dir = directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let writer = try EventStore(directory: dir.path)
        try writeHeartbeat(dir)
        let reader = try EventStore(directory: dir.path, forceReadOnly: true)
        let app = AppState(engineSource: .init(directory: dir.path), startBackgroundWork: false)
        defer { app.discardEventReaderForTesting() }
        app.primeCachedEventStoreForTesting(reader)
        app.stopPolling()
        await app.waitForEventReaderCertificationForTesting()
        #expect(app.hasCachedEventStoreForTesting)
        switch change {
        case "restart": try writeHeartbeat(dir, pid: 71_002)
        case "stale": try writeHeartbeat(dir, age: 121)
        case "missing": try FileManager.default.removeItem(at: dir.appendingPathComponent("heartbeat.json"))
        default: app.reconcileEventReadDeferral(true)
        }
        app.resumeEventReaderForTesting()
        #expect(!app.hasCachedEventStoreForTesting)
        try await expectRetired(reader)
        #expect(await writer.walCheckpointTruncate())
        let historical = try await app.readEventQuery(query(), limit: 10)
        #expect(historical != nil, "Unavailable identity disables reuse, not historical reads")
    }

    @Test("Missing or replaced backing inode refuses reuse despite unchanged engine identity", arguments: [false, true])
    func backingFileInvalidation(replace: Bool) async throws {
        let dir = directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        do { _ = try EventStore(directory: dir.path) }
        try writeHeartbeat(dir)
        let reader = try EventStore(directory: dir.path, forceReadOnly: true)
        let app = AppState(engineSource: .init(directory: dir.path), startBackgroundWork: false)
        defer { app.discardEventReaderForTesting() }
        app.primeCachedEventStoreForTesting(reader)
        app.stopPolling()
        await app.waitForEventReaderCertificationForTesting()
        #expect(app.hasCachedEventStoreForTesting)
        let before = try #require(EventReaderFileIdentity.read(directory: dir.path))
        let path = dir.appendingPathComponent("events.db")
        try FileManager.default.moveItem(at: path, to: dir.appendingPathComponent("original.sqlite"))
        if replace { try Data("inert replacement fixture".utf8).write(to: path) }
        #expect(EventReaderFileIdentity.read(directory: dir.path) != before)
        app.resumeEventReaderForTesting()
        #expect(!app.hasCachedEventStoreForTesting)
        try await expectRetired(reader)
    }
}
