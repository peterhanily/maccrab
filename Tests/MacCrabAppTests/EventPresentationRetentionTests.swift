import Foundation
import Combine
import Testing
@testable import MacCrabApp
@testable import MacCrabCore

@MainActor
@Suite("Bounded window Events presentation")
struct EventPresentationRetentionTests {
    private let instant = Date(timeIntervalSince1970: 1_700_000_000)
    private func query(_ filter: String? = nil, since: Date = .distantPast) -> EventQuerySession.Query {
        .init(filter: filter, since: since, until: .distantFuture, category: nil, acceptsIncremental: true)
    }
    private func key(_ filter: String = "", range: String = "day") -> EventQuerySession.PresentationKey {
        .init(range: range, filter: filter, category: nil, center: nil, halfWindowSeconds: 1800)
    }
    private func row(_ detail: String = "fixture", at date: Date? = nil) -> EventViewModel {
        .init(id: UUID(), timestamp: date ?? instant, action: "fixture", category: .process,
              processName: "fixture", pid: 1, detail: detail, signerType: "fixture")
    }
    @MainActor private final class Reader: EventQueryReading {
        var engineSource = V2EngineSource(directory: "/private/tmp/inert-events-presentation-" + UUID().uuidString)
        var eventQueryEpoch: UInt64 = 0
        var eventReadsDeferred = false
        var rows: [EventViewModel] = []
        var pending: CheckedContinuation<EventQuerySession.Page?, Error>?
        var suspend = false
        var fail = false
        var calls = 0
        func readEventQuery(_ query: EventQuerySession.Query, limit: Int) async throws -> EventQuerySession.Page? {
            calls += 1
            if suspend { return try await withCheckedThrowingContinuation { pending = $0 } }
            if fail { throw NSError(domain: "InertFixture", code: 1) }
            return .init(events: rows, nextCursor: nil)
        }
        func readOlderEventQuery(before: PaginationCursor, query: EventQuerySession.Query,
                                 pageSize: Int) async throws -> EventQuerySession.Page? { nil }
        func readEventAggregates(sinceDay: String, category: MacCrabCore.EventCategory?) async throws -> [EventStore.AggregateRow]? { nil }
        func readEventHistogram(spanSeconds: TimeInterval, stepSeconds: Int, endingAt: Date,
                                category: MacCrabCore.EventCategory?) async throws -> EventQuerySession.Histogram? { nil }
        func finish(_ rows: [EventViewModel]?) {
            let continuation = pending
            pending = nil
            continuation?.resume(returning: rows.map { .init(events: $0, nextCursor: nil) })
        }
    }
    private func waitForRead(_ reader: Reader) async -> Bool {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(2))
        while reader.pending == nil && clock.now < deadline { try? await Task.sleep(for: .milliseconds(1)) }
        return reader.pending != nil
    }

    @Test("Leave-return keeps matching rows visibly cached until a fresh read completes")
    func returnWhileReadIsSlow() async throws {
        let reader = Reader(), original = row(), fresh = row("new")
        reader.rows = [original]
        let session = EventQuerySession(reader: reader, now: { instant })
        await session.loadEvents(query(), presentationKey: key())
        #expect(session.readiness.phase == .loadedNonempty)
        session.invalidatePendingReads()
        #expect(session.events.map(\.id) == [original.id] && session.showingCachedEvents)
        #expect(!session.canReceiveIncremental && session.cursor == nil)
        #expect(session.canPresentCached(query(), key: key()))
        reader.suspend = true
        let task = Task { await session.loadEvents(query(), presentationKey: key()) }
        defer { task.cancel(); reader.finish(nil) }
        let waiting = await waitForRead(reader)
        try #require(waiting)
        #expect(session.events.map(\.id) == [original.id])
        #expect(session.readiness.phase == .refreshingCached && session.isLoading)
        reader.finish([fresh])
        await task.value
        #expect(reader.calls == 2)
        #expect(session.events.map(\.id) == [fresh.id] && !session.showingCachedEvents)
        #expect(session.readiness.phase == .loadedNonempty)
    }

    @Test("Changed query/range, expired cache, pressure and engine epoch cannot show old content", arguments: 0..<5)
    func rejectsIncompatiblePresentation(reason: Int) async throws {
        let reader = Reader()
        reader.rows = [row()]
        var clock = instant
        let session = EventQuerySession(reader: reader, now: { clock })
        await session.loadEvents(query(), presentationKey: key())
        session.invalidatePendingReads()
        var nextQuery = query(), nextKey = key()
        switch reason {
        case 0: nextQuery = query("different"); nextKey = key("different")
        case 1: nextKey = key(range: "hour")
        case 2: clock = instant.addingTimeInterval(EventQuerySession.retainedLifetime + 1)
        case 3: reader.eventReadsDeferred = true
        default: reader.eventQueryEpoch += 1
        }
        #expect(!session.canPresentCached(nextQuery, key: nextKey))
        #expect(!session.canDisplay(nextQuery, key: nextKey))
        reader.suspend = true
        let task = Task { await session.loadEvents(nextQuery, presentationKey: nextKey) }
        defer { task.cancel(); reader.finish(nil) }
        if reason != 3 {
            let waiting = await waitForRead(reader)
            try #require(waiting)
            #expect(session.events.isEmpty)
            reader.finish([])
        }
        await task.value
        #expect(!session.showingCachedEvents)
    }

    @Test("Failed refresh retains labeled data; empty cached results never imply a fresh all-clear")
    func failureAndEmpty() async {
        let reader = Reader()
        reader.rows = [row()]
        let session = EventQuerySession(reader: reader, now: { instant })
        await session.loadEvents(query(), presentationKey: key())
        session.invalidatePendingReads()
        reader.fail = true
        await session.loadEvents(query(), presentationKey: key())
        #expect(!session.events.isEmpty && session.showingCachedEvents)
        #expect(session.readiness.phase == .failed && session.eventSearchCoverageWarning != nil)
        reader.fail = false; reader.rows = []
        await session.loadEvents(query(), presentationKey: key())
        #expect(session.readiness.phase == .loadedEmpty)
        session.invalidatePendingReads()
        #expect(!session.canPresentCached(query(), key: key()))
        #expect(!session.readiness.phase.isFreshCompletion)
    }

    @Test("Hidden snapshot has explicit row and all-string-byte bounds")
    func retentionBounds() async {
        let reader = Reader()
        reader.rows = (0..<800).map { _ in row() }
        let expectedIDs = Array(reader.rows.prefix(EventQuerySession.retainedRowLimit)).map(\.id)
        let session = EventQuerySession(reader: reader, now: { instant })
        await session.loadEvents(query(), presentationKey: key())
        session.invalidatePendingReads()
        #expect(session.events.count == EventQuerySession.retainedRowLimit)
        #expect(session.events.map(\.id) == expectedIDs)
        var large = row()
        large.commandLine = String(repeating: "x", count: EventQuerySession.retainedPayloadLimit + 1)
        reader.rows = [large]
        await session.loadEvents(query(), presentationKey: key())
        session.invalidatePendingReads()
        #expect(session.events.isEmpty && !session.showingCachedEvents)
        #expect(!session.canPresentCached(query(), key: key()))

        // No individual field exceeds the limit: accounting must sum across
        // all fields, including ones not used by the table's visible columns.
        var distributed = row()
        distributed.executablePath = String(repeating: "p", count: EventQuerySession.retainedPayloadLimit / 2)
        distributed.processSHA256 = String(repeating: "h", count: EventQuerySession.retainedPayloadLimit / 2)
        reader.rows = [distributed]
        await session.loadEvents(query(), presentationKey: key())
        session.invalidatePendingReads()
        #expect(session.events.isEmpty && !session.showingCachedEvents)
    }

    @Test("A read completing after leaving cannot overwrite the retained snapshot")
    func lateReturn() async throws {
        let reader = Reader(), original = row(), late = row("late")
        reader.rows = [original]
        let session = EventQuerySession(reader: reader, now: { instant })
        await session.loadEvents(query(), presentationKey: key())
        reader.suspend = true
        let task = Task { await session.loadEvents(query(), presentationKey: key()) }
        defer { task.cancel(); reader.finish(nil) }
        let waiting = await waitForRead(reader)
        try #require(waiting)
        session.invalidatePendingReads()
        reader.finish([late])
        await task.value
        #expect(session.events.map(\.id) == [original.id])
        #expect(session.readiness.phase == .unavailable && !session.isLoading)
    }

    @Test("Moving range removes aged rows and refuses expansion of the cached lower bound")
    func timeBoundCompatibility() async {
        let reader = Reader(), older = row(at: instant.addingTimeInterval(-20)), newer = row(at: instant)
        reader.rows = [newer, older]
        let session = EventQuerySession(reader: reader, now: { instant })
        await session.loadEvents(query(since: instant.addingTimeInterval(-30)), presentationKey: key())
        session.invalidatePendingReads()
        #expect(!session.canPresentCached(query(since: instant.addingTimeInterval(-60)), key: key()))
        reader.fail = true
        await session.loadEvents(query(since: instant.addingTimeInterval(-10)), presentationKey: key())
        #expect(session.events.map(\.id) == [newer.id])
        #expect(session.showingCachedEvents && session.readiness.phase == .failed)
    }

    @Test("Cache age has an exact inclusive boundary and refuses reversed or nonfinite clocks")
    func cacheClockBoundaries() async {
        let reader = Reader()
        reader.rows = [row()]
        var clock = instant
        let session = EventQuerySession(reader: reader, now: { clock })
        await session.loadEvents(query(), presentationKey: key())
        session.invalidatePendingReads()
        for offset in [0.0, EventQuerySession.retainedLifetime] {
            clock = instant.addingTimeInterval(offset)
            #expect(session.canPresentCached(query(), key: key()))
        }
        for offset in [-1.0, EventQuerySession.retainedLifetime + 0.001,
                       Double.infinity, -Double.infinity, Double.nan] {
            clock = instant.addingTimeInterval(offset)
            #expect(!session.canPresentCached(query(), key: key()))
            #expect(!session.canDisplay(query(), key: key()))
        }
    }

    @Test("Fixed upper bound, category, center, half-window and incremental mode are part of compatibility")
    func fixedPresentationBounds() async {
        let reader = Reader()
        reader.rows = [row()]
        let session = EventQuerySession(reader: reader, now: { instant })
        await session.loadEvents(query(), presentationKey: key())
        session.invalidatePendingReads()
        let incompatible: [(EventQuerySession.Query, EventQuerySession.PresentationKey?)] = [
            (.init(filter: nil, since: .distantPast, until: instant, category: nil, acceptsIncremental: true), key()),
            (.init(filter: nil, since: .distantPast, until: .distantFuture, category: .file, acceptsIncremental: true), key()),
            (.init(filter: nil, since: .distantPast, until: .distantFuture, category: nil, acceptsIncremental: false), key()),
            (query(), .init(range: "day", filter: "", category: "file", center: nil, halfWindowSeconds: 1800)),
            (query(), .init(range: "day", filter: "", category: nil, center: instant, halfWindowSeconds: 1800)),
            (query(), .init(range: "day", filter: "", category: nil, center: nil, halfWindowSeconds: 900)),
            (query(), nil)
        ]
        for (next, nextKey) in incompatible {
            #expect(!session.canPresentCached(next, key: nextKey))
            #expect(!session.canDisplay(next, key: nextKey))
        }
        #expect(session.canPresentCached(query(), key: key()))
    }

    @Test("Replacing the reader source at the same epoch refuses cached display and new reads")
    func sourceReplacementFailsClosed() async {
        let reader = Reader()
        reader.rows = [row()]
        let session = EventQuerySession(reader: reader, now: { instant })
        await session.loadEvents(query(), presentationKey: key())
        session.invalidatePendingReads()
        reader.engineSource = .init(directory: "/private/tmp/inert-replaced-events-source-" + UUID().uuidString)
        #expect(!session.canPresentCached(query(), key: key()))
        #expect(!session.canDisplay(query(), key: key()))
        await session.loadEvents(query(), presentationKey: key())
        #expect(reader.calls == 1)
        #expect(session.events.isEmpty && !session.showingCachedEvents && !session.isLoading)
        #expect(session.readiness.phase == .unavailable)
    }

    @Test("Cancellation of the current returned read cannot overwrite cached rows or stay ready")
    func cancelledCurrentRead() async throws {
        let reader = Reader(), original = row(), late = row("cancelled result")
        reader.rows = [original]
        let session = EventQuerySession(reader: reader, now: { instant })
        await session.loadEvents(query(), presentationKey: key())
        session.invalidatePendingReads()
        reader.suspend = true
        let task = Task { await session.loadEvents(query(), presentationKey: key()) }
        defer { task.cancel(); reader.finish(nil) }
        let waiting = await waitForRead(reader)
        try #require(waiting)
        task.cancel()
        reader.finish([late])
        await task.value
        #expect(session.events.map(\.id) == [original.id])
        #expect(session.showingCachedEvents && !session.isLoading && !session.canReceiveIncremental)
        #expect(session.readiness.phase == .deferred && !session.readiness.phase.isFreshCompletion)
        #expect(session.eventSearchCoverageWarning != nil)
    }

    @Test("Synchronous row publication never borrows freshness from the preceding read", arguments: [false, true])
    func rowPublicationBeginsWithCurrentReadiness(retainMatchingRows: Bool) async throws {
        let reader = Reader(), original = row(), replacement = row("replacement")
        reader.rows = [original]
        let session = EventQuerySession(reader: reader, now: { instant })
        await session.loadEvents(query(), presentationKey: key())
        let oldGeneration = session.readiness.generation
        try #require(session.readiness.phase == .loadedNonempty)
        try #require(session.canReceiveIncremental)
        let nextQuery = retainMatchingRows ? query() : query("replacement")
        let nextKey = retainMatchingRows ? key() : key("replacement")
        var observations: [(phase: UIContentReadiness.Phase, generation: UUID,
                            incremental: Bool, ids: [UUID])] = []
        // @Published delivers synchronously before its stored property changes.
        // Observe the same boundary as EventStream's onReceive, not a later
        // MainActor turn after all lifecycle fields have already settled.
        let observation = session.$events.dropFirst().sink { emitted in
            observations.append((session.readiness.phase, session.readiness.generation,
                                 session.canReceiveIncremental, emitted.map(\.id)))
        }
        defer { observation.cancel() }
        reader.suspend = true
        let task = Task { await session.loadEvents(nextQuery, presentationKey: nextKey) }
        defer { task.cancel(); reader.finish(nil) }
        let waiting = await waitForRead(reader)
        try #require(waiting)
        try #require(observations.count == 1)
        #expect(observations[0].phase == (retainMatchingRows ? .refreshingCached : .loading))
        #expect(observations[0].generation != oldGeneration)
        #expect(!observations[0].incremental)
        #expect(observations[0].ids == (retainMatchingRows ? [original.id] : []))
        reader.finish([replacement])
        await task.value
        try #require(observations.count == 2)
        #expect(observations.allSatisfy { !$0.phase.isFreshCompletion && !$0.incremental })
        #expect(observations[1].generation == observations[0].generation)
        #expect(observations[1].ids == [replacement.id])
        #expect(session.events.map(\.id) == [replacement.id])
        #expect(session.readiness.phase == .loadedNonempty)
        #expect(session.readiness.generation == observations[0].generation)
    }

    @Test("An overlapping old view owner cannot invalidate the same session's new read")
    func overlappingVisibilityOwnersPreserveCurrentRead() async throws {
        let reader = Reader(), original = row(), fresh = row("new owner result")
        reader.rows = [original]
        let app = AppState(engineSource: reader.engineSource, startBackgroundWork: false)
        let session = EventQuerySession(reader: reader, now: { instant })
        let oldOwner = UUID(), newOwner = UUID()
        defer {
            app.setEventsWorkspaceVisible(false, owner: oldOwner)
            app.setEventsWorkspaceVisible(false, owner: newOwner)
            app.stopPolling()
        }
        app.setEventsWorkspaceVisible(true, owner: oldOwner, session: session)
        await session.loadEvents(query(), presentationKey: key())
        app.setEventsWorkspaceVisible(true, owner: newOwner, session: session)
        reader.suspend = true
        let task = Task { await session.loadEvents(query(), presentationKey: key()) }
        defer { task.cancel(); reader.finish(nil) }
        let waiting = await waitForRead(reader)
        try #require(waiting)
        let inFlightGeneration = session.readiness.generation

        app.setEventsWorkspaceVisible(false, owner: oldOwner)
        #expect(app.eventsWorkspaceVisible)
        #expect(session.isLoading && session.readiness.phase == .refreshingCached)
        #expect(session.readiness.generation == inFlightGeneration)
        reader.finish([fresh])
        await task.value
        #expect(session.events.map(\.id) == [fresh.id])
        #expect(session.readiness.phase == .loadedNonempty && session.canReceiveIncremental)
        // A duplicate disappearance must also be inert for the remaining owner.
        app.setEventsWorkspaceVisible(false, owner: oldOwner)
        #expect(session.readiness.generation == inFlightGeneration)
        #expect(session.readiness.phase == .loadedNonempty)

        app.setEventsWorkspaceVisible(false, owner: newOwner)
        #expect(!app.eventsWorkspaceVisible)
        #expect(session.readiness.phase == .unavailable && !session.canReceiveIncremental)
        #expect(session.readiness.generation != inFlightGeneration)
        #expect(session.events.map(\.id) == [fresh.id] && session.showingCachedEvents)
    }
}
