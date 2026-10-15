import Foundation
import Testing
@testable import MacCrabApp
@testable import MacCrabCore

/// Real authenticated reads of inert, task-owned data. The DEBUG hook runs
/// after Core returns, never instead of Core or inside a SQLite transaction.
@Suite("Events storage completion versus cancelled presentation", .serialized)
@MainActor
struct EventReaderPostReturnCancellationTests {
    typealias Operation = AppState.EventReaderOperationForTesting
    private let epoch = Date(timeIntervalSince1970: 1_700_000_000)

    private func event(_ index: Int) -> Event {
        let time = epoch.addingTimeInterval(Double(index))
        return Event(timestamp: time, eventCategory: .process, eventType: .start,
            eventAction: "exec", process: MacCrabCore.ProcessInfo(
                pid: Int32(8_000 + index), ppid: 1, rpid: 1,
                name: "publicationfixture", executable: "/usr/bin/true",
                commandLine: "publicationfixture", args: [], workingDirectory: "/private/tmp",
                userId: 501, userName: "fixture", groupId: 20,
                startTime: time, ancestors: [], isPlatformBinary: false))
    }

    private func query(_ filter: String? = nil) -> EventQuerySession.Query {
        .init(filter: filter, since: .distantPast, until: .distantFuture,
              category: nil, acceptsIncremental: false)
    }

    private func directory() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-post-return-\(UUID().uuidString)")
    }

    private func read(_ operation: Operation, app: AppState, id: UUID) async throws -> Bool {
        switch operation {
        case .exactQuery:
            return try await app.readEventQuery(query(), limit: 10) != nil
        case .searchQuery:
            return try await app.readEventQuery(query("publicationfixture"), limit: 10) != nil
        case .olderPage:
            let cursor = PaginationCursor(timestamp: epoch.addingTimeInterval(10), id: id.uuidString)
            return try await app.readOlderEventQuery(before: cursor, query: query(), pageSize: 10) != nil
        case .incremental:
            await app.loadEventsIncremental()
            return !app.events.isEmpty
        case .eventLookup:
            return await app.fetchEvent(id: id.uuidString) != nil
        case .aggregates:
            return try await app.readEventAggregates(sinceDay: "2000-01-01", category: nil) != nil
        case .histogram:
            return try await app.readEventHistogram(spanSeconds: 60, stepSeconds: 10,
                endingAt: epoch.addingTimeInterval(10), category: nil) != nil
        }
    }

    @Test("Post-return cancellation rejects publication without retiring a healthy warm reader",
          arguments: [Operation.exactQuery, .searchQuery, .olderPage, .incremental,
                      .eventLookup, .aggregates, .histogram])
    func postReturnCancellation(operation: Operation) async throws {
        let dir = directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let writer = try EventStore(directory: dir.path)
        let expected = (0..<3).map { event($0) }
        for value in expected { try await writer.insert(event: value) }
        let reader = try EventStore(directory: dir.path, forceReadOnly: true)
        let app = AppState(engineSource: .init(directory: dir.path), startBackgroundWork: false)
        defer { app.eventReaderDidReturnForTesting = nil; app.discardEventReaderForTesting() }
        app.primeCachedEventStoreForTesting(reader)
        let initial = try await app.readEventQuery(query(), limit: 10)
        #expect(initial?.events.map(\.id) == expected.reversed().map(\.id))
        let before = await reader.journalIndexRefreshDiagnostics()
        let owner = UUID()
        if operation == .incremental { app.setEventsWorkspaceVisible(true, owner: owner) }
        defer { app.setEventsWorkspaceVisible(false, owner: owner) }
        var reachedReturn = false
        app.eventReaderDidReturnForTesting = { returned in
            guard returned == operation else { return }
            reachedReturn = true
            withUnsafeCurrentTask { $0?.cancel() }
        }
        // Only the child is cancelled; recovery/checkpoint assertions remain live.
        let task = Task { try await read(operation, app: app, id: expected[0].id) }
        let result = await task.result
        app.eventReaderDidReturnForTesting = nil
        #expect(reachedReturn)
        switch result {
        case .success(let published): #expect(!published)
        case .failure(let error): #expect(error is CancellationError)
        }
        #expect(app.events.isEmpty)
        #expect(app.hasCachedEventStoreForTesting && app.eventReaderAdmissionsForTesting == 0)
        #expect(await reader.permitsIdleReadOnlyRetention(), "No surviving statement or transaction may pin WAL")
        #expect(await writer.walCheckpointTruncate())
        let following = try await app.readEventQuery(query(), limit: 10)
        #expect(following?.events.map(\.id) == expected.reversed().map(\.id))
        let after = await reader.journalIndexRefreshDiagnostics()
        #expect(after.fullRebuilds == before.fullRebuilds)
        #expect(after.appendRefreshes == before.appendRefreshes)
    }

    @MainActor
    private final class ReturnGate {
        var waiting = false
        private var open = false
        private var continuation: CheckedContinuation<Void, Never>?

        func wait() async {
            guard !open else { return }
            await withCheckedContinuation { continuation = $0; waiting = true }
        }

        func release() {
            open = true
            let pending = continuation
            continuation = nil
            pending?.resume()
        }
    }

    private func waitUntil(_ predicate: () -> Bool) async -> Bool {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(2))
        while !predicate(), clock.now < deadline { try? await Task.sleep(for: .milliseconds(1)) }
        return predicate()
    }

    @Test("Cancelled completed chart does not retire a concurrent page lease or its authenticated index")
    func concurrentReturnedReads() async throws {
        let dir = directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let writer = try EventStore(directory: dir.path)
        let expected = (0..<3).map { event($0) }
        for value in expected { try await writer.insert(event: value) }
        let reader = try EventStore(directory: dir.path, forceReadOnly: true)
        let app = AppState(engineSource: .init(directory: dir.path), startBackgroundWork: false)
        defer { app.eventReaderDidReturnForTesting = nil; app.discardEventReaderForTesting() }
        app.primeCachedEventStoreForTesting(reader)
        let chartGate = ReturnGate(), pageGate = ReturnGate()
        defer { chartGate.release(); pageGate.release() }
        app.eventReaderDidReturnForTesting = { operation in
            if operation == .histogram { await chartGate.wait() }
            if operation == .exactQuery { await pageGate.wait() }
        }
        let chart = Task { try await app.readEventHistogram(spanSeconds: 60, stepSeconds: 10,
            endingAt: epoch.addingTimeInterval(10), category: nil) }
        let chartReturned = await waitUntil { chartGate.waiting }
        guard chartReturned else {
            chartGate.release(); chart.cancel(); _ = await chart.result
            Issue.record("Chart never reached the post-return boundary")
            return
        }
        let before = await reader.journalIndexRefreshDiagnostics()
        let page = Task { try await app.readEventQuery(query(), limit: 10) }
        let pageReturned = await waitUntil { pageGate.waiting }
        guard pageReturned else {
            pageGate.release(); chartGate.release(); page.cancel(); chart.cancel()
            _ = await page.result; _ = await chart.result
            Issue.record("Concurrent page never reached the post-return boundary")
            return
        }
        #expect(app.eventReaderAdmissionsForTesting == 2)
        chart.cancel()
        chartGate.release()
        switch await chart.result {
        case .success: Issue.record("Cancelled chart published its obsolete result")
        case .failure(let error): #expect(error is CancellationError)
        }
        #expect(app.hasCachedEventStoreForTesting && app.eventReaderAdmissionsForTesting == 1)
        #expect(await reader.permitsIdleReadOnlyRetention())
        #expect(await writer.walCheckpointTruncate())
        pageGate.release()
        let result = try await page.value
        #expect(result?.events.map(\.id) == expected.reversed().map(\.id))
        app.eventReaderDidReturnForTesting = nil
        let following = try await app.readEventQuery(query(), limit: 10)
        #expect(following?.events.count == expected.count)
        let after = await reader.journalIndexRefreshDiagnostics()
        #expect(after.fullRebuilds == before.fullRebuilds)
        #expect(app.eventReaderAdmissionsForTesting == 0)
    }

    @Test("Actual Core failure or in-read cancellation still retires before the post-return hook",
          arguments: [false, true])
    func coreFailureStillRetires(cancelDuringRead: Bool) async throws {
        let dir = directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let writer = try EventStore(directory: dir.path)
        try await writer.insert(event: event(0))
        let reader = try EventStore(directory: dir.path, forceReadOnly: true)
        if cancelDuringRead {
            await reader.setJournalIndexRebuildHookForTesting { _ in
                withUnsafeCurrentTask { $0?.cancel() }
            }
        } else {
            await reader.setJournalRebuildFailAfterPartialForTesting(true)
        }
        let app = AppState(engineSource: .init(directory: dir.path), startBackgroundWork: false)
        defer { app.eventReaderDidReturnForTesting = nil; app.discardEventReaderForTesting() }
        app.primeCachedEventStoreForTesting(reader)
        var returned = false
        app.eventReaderDidReturnForTesting = { _ in returned = true }
        let task = Task { try await app.readEventQuery(query(), limit: 10) }
        let result = await task.result
        await reader.setJournalIndexRebuildHookForTesting(nil)
        switch result {
        case .success: Issue.record("Failed/cancelled Core verification returned a successful page")
        case .failure(let error):
            if cancelDuringRead {
                #expect(error is CancellationError)
            } else if let storeError = error as? EventStoreError {
                guard case .decodingFailed = storeError else { throw storeError }
            } else { throw error }
        }
        #expect(!returned && !app.hasCachedEventStoreForTesting)
        #expect(app.eventReaderAdmissionsForTesting == 0)
        #expect(await reader.permitsIdleReadOnlyRetention() == false)
        #expect(await writer.walCheckpointTruncate())
    }

    @Test("Source invalidation after Core returns still retires the old reader and rejects publication")
    func postReturnSourceInvalidation() async throws {
        let dir = directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let writer = try EventStore(directory: dir.path)
        try await writer.insert(event: event(0))
        let reader = try EventStore(directory: dir.path, forceReadOnly: true)
        let app = AppState(engineSource: .init(directory: dir.path), startBackgroundWork: false)
        defer { app.eventReaderDidReturnForTesting = nil; app.discardEventReaderForTesting() }
        app.primeCachedEventStoreForTesting(reader)
        var returned = false
        app.eventReaderDidReturnForTesting = { operation in
            guard operation == .exactQuery else { return }
            returned = true
            app.reconcileEventReadDeferral(true)
        }
        do {
            _ = try await app.readEventQuery(query(), limit: 10)
            Issue.record("Old-generation result was published after source invalidation")
        } catch is CancellationError { }
        #expect(returned && app.eventReadsDeferred)
        #expect(!app.hasCachedEventStoreForTesting && app.eventReaderAdmissionsForTesting == 0)
        #expect(await reader.permitsIdleReadOnlyRetention() == false)
        #expect(await writer.walCheckpointTruncate())
    }
}
