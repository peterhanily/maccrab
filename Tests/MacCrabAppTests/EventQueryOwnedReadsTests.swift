import Foundation
import Testing
@testable import MacCrabApp
@testable import MacCrabCore

#if DEBUG
/// Inert protocol fixtures suspend at the backend boundary. No live stores,
/// SQLite, filesystem, preferences, native collectors or UI automation.
@MainActor
@Suite("Events navigation preserves bounded backend ownership")
struct EventQueryOwnedReadsTests {
    private final class Reader: EventQueryReading {
        var engineSource = V2EngineSource(
            directory: "/private/tmp/maccrab-owned-read-fixture-" + UUID().uuidString
        )
        var eventQueryEpoch: UInt64 = 0
        var eventReadsDeferred = false
        var queries: [EventQuerySession.Query] = []
        var olderCalls = 0
        var histogramEnds: [Date] = []
        var aggregateCalls = 0
        var backendCancellations = 0
        var page: CheckedContinuation<EventQuerySession.Page?, Error>?
        var histogram: CheckedContinuation<EventQuerySession.Histogram?, Error>?
        var aggregate: CheckedContinuation<[EventStore.AggregateRow]?, Error>?

        func readEventQuery(_ query: EventQuerySession.Query, limit: Int) async throws -> EventQuerySession.Page? {
            queries.append(query)
            return try await pageRead()
        }
        func readOlderEventQuery(before cursor: PaginationCursor, query: EventQuerySession.Query,
                                 pageSize: Int) async throws -> EventQuerySession.Page? {
            olderCalls += 1
            return try await pageRead()
        }
        private func pageRead() async throws -> EventQuerySession.Page? {
            let watchdog = cleanupWatchdog()
            defer { watchdog.cancel() }
            let result: EventQuerySession.Page? = try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { page = $0 }
            } onCancel: { Task { @MainActor [weak self] in self?.backendCancellations += 1 } }
            try Task.checkCancellation() // Model the real Core's cooperative boundary.
            return result
        }
        func readEventAggregates(sinceDay: String, category: MacCrabCore.EventCategory?) async throws -> [EventStore.AggregateRow]? {
            aggregateCalls += 1
            let watchdog = cleanupWatchdog()
            defer { watchdog.cancel() }
            let result: [EventStore.AggregateRow]? = try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { aggregate = $0 }
            } onCancel: { Task { @MainActor [weak self] in self?.backendCancellations += 1 } }
            try Task.checkCancellation()
            return result
        }
        func readEventHistogram(spanSeconds: TimeInterval, stepSeconds: Int, endingAt: Date,
                                category: MacCrabCore.EventCategory?) async throws -> EventQuerySession.Histogram? {
            histogramEnds.append(endingAt)
            let watchdog = cleanupWatchdog()
            defer { watchdog.cancel() }
            let result: EventQuerySession.Histogram? = try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { histogram = $0 }
            } onCancel: { Task { @MainActor [weak self] in self?.backendCancellations += 1 } }
            try Task.checkCancellation()
            return result
        }
        func finishPage(_ result: Result<EventQuerySession.Page?, Error>) {
            let pending = page; page = nil; pending?.resume(with: result)
        }
        func finishHistogram(_ value: EventQuerySession.Histogram?) {
            let pending = histogram; histogram = nil; pending?.resume(returning: value)
        }
        func finishAggregate(_ value: [EventStore.AggregateRow]?) {
            let pending = aggregate; aggregate = nil; pending?.resume(returning: value)
        }
        func releaseAll() {
            finishPage(.success(nil)); finishHistogram(nil); finishAggregate(nil)
        }
        private func cleanupWatchdog() -> Task<Void, Never> {
            Task { @MainActor [weak self] in
                do { try await Task.sleep(for: .seconds(30)); try Task.checkCancellation() }
                catch { return }
                Issue.record("Fixture backend did not unwind within the independent cleanup bound")
                self?.releaseAll()
            }
        }
    }
    private let instant = Date(timeIntervalSince1970: 1_700_000_000)
    private func query(_ text: String? = nil, since: Date = .distantPast) -> EventQuerySession.Query {
        .init(filter: text, since: since, until: .distantFuture, category: nil, acceptsIncremental: true)
    }
    private func key(_ text: String = "") -> EventQuerySession.PresentationKey {
        .init(range: "day", filter: text, category: nil, center: nil, halfWindowSeconds: 1800)
    }
    private func row(_ detail: String) -> EventViewModel {
        .init(id: UUID(), timestamp: instant, action: "fixture", category: .process,
              processName: "fixture", pid: 1, detail: detail, signerType: "fixture")
    }
    private func until(_ predicate: () -> Bool) async -> Bool {
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while !predicate() && ContinuousClock.now < deadline { await Task.yield() }
        return predicate()
    }

    @Test("Page switch during a suspended backend read detaches publication, then return joins")
    func switchWhileBackendSuspended() async throws {
        let reader = Reader()
        let owned = EventQuerySession(reader: reader), expected = row("new")
        let first = Task { await owned.loadEvents(query(), presentationKey: key()) }
        defer { first.cancel(); owned.cancelBackendReads(); reader.releaseAll() }
        let began = await until { reader.page != nil }
        try #require(began)
        owned.invalidatePendingReads() // Actual workspace disappearance callback.
        first.cancel()                 // Actual SwiftUI .task disappearance.
        await first.value
        #expect(reader.backendCancellations == 0)
        #expect(owned.events.isEmpty && !owned.readiness.phase.isFreshCompletion)
        let returned = Task { await owned.loadEvents(query(), presentationKey: key()) }
        defer { returned.cancel() }
        let loading = await until { owned.backendWaitersForTesting.exact == 1 }
        try #require(loading)
        reader.finishPage(.success(.init(events: [expected], nextCursor: nil)))
        await returned.value
        #expect(reader.queries.count == 1 && reader.backendCancellations == 0)
        #expect(owned.events.map(\.id) == [expected.id] && owned.readiness.phase == .loadedNonempty)
    }

    @Test("Changed moving bound runs its exact query after drain, never publishes old coverage")
    func movingBoundWaitsThenReadsExactly() async throws {
        let reader = Reader(), old = row("old"), fresh = row("fresh")
        let session = EventQuerySession(reader: reader)
        let first = Task { await session.loadEvents(query(since: instant.addingTimeInterval(-30)), presentationKey: key()) }
        defer { first.cancel(); session.cancelBackendReads(); reader.releaseAll() }
        let began = await until { reader.page != nil }
        try #require(began)
        session.invalidatePendingReads(); first.cancel(); await first.value
        let newQuery = query(since: instant.addingTimeInterval(-10))
        let returned = Task { await session.loadEvents(newQuery, presentationKey: key()) }
        defer { returned.cancel() }
        let waiting = await until { session.backendWaitersForTesting.exact == 1 }
        try #require(waiting)
        reader.finishPage(.success(.init(events: [old], nextCursor: nil)))
        let replacement = await until { reader.queries.count == 2 && reader.page != nil }
        try #require(replacement)
        #expect(reader.queries.last == newQuery && session.events.isEmpty && reader.backendCancellations == 0)
        reader.finishPage(.success(.init(events: [fresh], nextCursor: nil)))
        await returned.value
        #expect(session.events.map(\.id) == [fresh.id])
    }

    @Test("Incompatible filter cancels the old owner, holds its lane and rejects late success")
    func incompatibleQuery() async throws {
        let reader = Reader()
        let owned = EventQuerySession(reader: reader)
        let first = Task { await owned.loadEvents(query(), presentationKey: key()) }
        defer { first.cancel(); owned.cancelBackendReads(); reader.releaseAll() }
        let began = await until { reader.page != nil }
        try #require(began)
        let replacement = Task { await owned.loadEvents(query("new-filter"), presentationKey: key("new-filter")) }
        defer { replacement.cancel() }
        let cancelled = await until { reader.backendCancellations == 1 }
        try #require(cancelled)
        #expect(reader.queries.count == 1)
        reader.finishPage(.success(.init(events: [row("obsolete")], nextCursor: nil)))
        let second = await until { reader.queries.count == 2 && reader.page != nil }
        try #require(second)
        #expect(owned.events.isEmpty)
        reader.finishPage(.success(.init(events: [], nextCursor: nil)))
        await first.value; await replacement.value
        #expect(owned.readiness.phase == .loadedEmpty)
    }

    @Test("Histogram tick cancellation does not cancel its backend; new end gets a new read")
    func histogramRefreshOwnership() async throws {
        let reader = Reader()
        let owned = EventQuerySession(reader: reader)
        let first = Task { await owned.fetchHistogramBins(spanSeconds: 60, stepSeconds: 10,
                                                          endingAt: instant, category: nil) }
        defer { first.cancel(); owned.cancelBackendReads(); reader.releaseAll() }
        let began = await until { reader.histogram != nil }
        try #require(began)
        first.cancel(); _ = await first.value
        let nextEnd = instant.addingTimeInterval(5)
        let second = Task { await owned.fetchHistogramBins(spanSeconds: 60, stepSeconds: 10,
                                                           endingAt: nextEnd, category: nil) }
        defer { second.cancel() }
        let waiting = await until { owned.backendWaitersForTesting.auxiliary == 1 }
        try #require(waiting)
        reader.finishHistogram(.init(bins: [(instant, 9)], effectiveSince: instant,
                                     effectiveUntil: instant, coverageWarning: nil))
        let replacement = await until { reader.histogramEnds.count == 2 && reader.histogram != nil }
        try #require(replacement)
        #expect(reader.histogramEnds == [instant, nextEnd] && reader.backendCancellations == 0)
        reader.finishHistogram(.init(bins: [(nextEnd, 2)], effectiveSince: instant,
                                     effectiveUntil: nextEnd, coverageWarning: nil))
        let bins = await second.value
        #expect(bins.count == 1 && bins.first?.0 == nextEnd && bins.first?.1 == 2)
    }

    @Test("Histogram and aggregate modes share one occupied auxiliary lane")
    func auxiliaryModeSharesLane() async throws {
        let reader = Reader()
        let session = EventQuerySession(reader: reader)
        let chart = Task { await session.fetchHistogramBins(spanSeconds: 60, stepSeconds: 10,
                                                            endingAt: instant, category: nil) }
        defer { chart.cancel(); session.cancelBackendReads(); reader.releaseAll() }
        let began = await until { reader.histogram != nil }
        try #require(began)
        let aggregate = Task { await session.fetchAggregates(sinceDay: "2020-01-01", category: nil) }
        defer { aggregate.cancel() }
        let cancelled = await until { reader.backendCancellations == 1 }
        try #require(cancelled)
        #expect(reader.aggregateCalls == 0)
        reader.finishHistogram(nil)
        let started = await until { reader.aggregate != nil }
        try #require(started)
        reader.finishAggregate([])
        _ = await chart.value; _ = await aggregate.value
        #expect(reader.aggregateCalls == 1 && session.aggregateReadiness.phase == .loadedEmpty)
    }

    @Test("Exact and aggregate mode changes cancel incompatible owners, even with chart hidden")
    func exactAggregateModeChanges() async throws {
        let reader = Reader()
        let owned = EventQuerySession(reader: reader)
        let exact = Task { await owned.loadEvents(query(), presentationKey: key()) }
        defer { exact.cancel(); owned.cancelBackendReads(); reader.releaseAll() }
        let began = await until { reader.page != nil }
        try #require(began)
        owned.deactivateExactPresentation()
        let firstCancelled = await until { reader.backendCancellations == 1 }
        try #require(firstCancelled)
        await exact.value
        let aggregate = Task { await owned.fetchAggregates(sinceDay: "2020-01-01", category: nil) }
        defer { aggregate.cancel() }
        let summaryBegan = await until { reader.aggregate != nil }
        try #require(summaryBegan)
        // The cancelled exact lane remains occupied until its backend returns.
        let returned = Task { await owned.loadEvents(query(), presentationKey: key()) }
        defer { returned.cancel() }
        let bothCancelled = await until {
            reader.backendCancellations == 2 && owned.backendWaitersForTesting.exact == 1
        }
        try #require(bothCancelled)
        #expect(reader.queries.count == 1)
        reader.finishPage(.success(.init(events: [row("obsolete")], nextCursor: nil)))
        reader.finishAggregate([])
        let replacement = await until { reader.queries.count == 2 && reader.page != nil }
        try #require(replacement)
        reader.finishPage(.success(.init(events: [], nextCursor: nil)))
        await returned.value; _ = await aggregate.value
        #expect(owned.readiness.phase == .loadedEmpty)
        #expect(!owned.aggregateReadiness.phase.isFreshCompletion)
    }

    @Test("Older pagination and newest-page replacement share one backend lane")
    func paginationSharesExactLane() async throws {
        let reader = Reader(), firstRow = row("first"), oldRow = row("older"), newRow = row("replacement")
        let owned = EventQuerySession(reader: reader)
        let initial = Task { await owned.loadEvents(query(), presentationKey: key()) }
        defer { initial.cancel(); owned.cancelBackendReads(); reader.releaseAll() }
        let began = await until { reader.page != nil }
        try #require(began)
        reader.finishPage(.success(.init(events: [firstRow], nextCursor:
            .init(timestamp: instant, id: firstRow.id.uuidString))))
        await initial.value
        let older = Task { await owned.loadOlderEvents() }
        defer { older.cancel() }
        let pageBegan = await until { reader.olderCalls == 1 && reader.page != nil }
        try #require(pageBegan)
        let replacement = Task { await owned.loadEvents(query(), presentationKey: key()) }
        defer { replacement.cancel() }
        let queued = await until { owned.backendWaitersForTesting.exact == 2 }
        try #require(queued)
        #expect(reader.queries.count == 1 && reader.backendCancellations == 0)
        reader.finishPage(.success(.init(events: [oldRow], nextCursor: nil)))
        let restarted = await until { reader.queries.count == 2 && reader.page != nil }
        try #require(restarted)
        #expect(!owned.events.contains(where: { $0.id == oldRow.id }))
        reader.finishPage(.success(.init(events: [newRow], nextCursor: nil)))
        await older.value; await replacement.value
        #expect(owned.events.map(\.id) == [newRow.id] && reader.olderCalls == 1)
    }

    @Test("Window teardown blocks admission until resume; source change rejects old results",
          arguments: [false, true])
    func teardownOrSourceReplacement(sourceChanged: Bool) async throws {
        let reader = Reader()
        let owned = EventQuerySession(reader: reader)
        let first = Task { await owned.loadEvents(query(), presentationKey: key()) }
        defer { first.cancel(); owned.cancelBackendReads(); reader.releaseAll() }
        let began = await until { reader.page != nil }
        try #require(began)
        if sourceChanged { reader.eventQueryEpoch += 1; owned.reconcileBackendContext() }
        else { owned.cancelBackendReads() }
        await first.value
        let cancelled = await until { reader.backendCancellations == 1 }
        try #require(cancelled)
        if !sourceChanged {
            await owned.loadEvents(query(), presentationKey: key())
            #expect(reader.queries.count == 1)
            let beforeResume = owned.retryTick
            owned.resumeBackendReads()
            #expect(owned.retryTick == beforeResume + 1)
            owned.resumeBackendReads()
            #expect(owned.retryTick == beforeResume + 1) // One explicit visible retry, not polling.
        }
        let replacement = Task { await owned.loadEvents(query(), presentationKey: key()) }
        defer { replacement.cancel() }
        reader.finishPage(.success(.init(events: [row("obsolete")], nextCursor: nil)))
        let restarted = await until { reader.queries.count == 2 && reader.page != nil }
        try #require(restarted)
        #expect(owned.events.isEmpty)
        reader.finishPage(.failure(NSError(domain: "InertCoreRead", code: 7)))
        await replacement.value
        #expect(owned.readiness.phase == .failed && owned.eventSearchCoverageWarning != nil)
    }

    @Test("Cancelled presentation does not keep a released window session alive")
    func deinitCancelsOwner() async throws {
        let reader = Reader()
        var session: EventQuerySession? = EventQuerySession(reader: reader)
        weak var weakSession = session
        let first = Task { [session] in await session?.loadEvents(query(), presentationKey: key()) }
        defer { first.cancel(); session?.cancelBackendReads(); reader.releaseAll() }
        let began = await until { reader.page != nil }
        try #require(began)
        first.cancel(); _ = await first.value
        session = nil
        let released = await until { weakSession == nil && reader.backendCancellations == 1 }
        #expect(released)
        reader.releaseAll()
    }
}
#endif
