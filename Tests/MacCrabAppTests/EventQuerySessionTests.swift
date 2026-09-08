import Foundation
import Combine
import Testing
@testable import MacCrabApp
@testable import MacCrabCore

@MainActor
@Suite("Independent Events window queries")
struct EventQuerySessionTests {
    private func query(_ filter: String? = nil, until: Date = .distantFuture,
                       live: Bool = false) -> EventQuerySession.Query {
        .init(filter: filter, since: .distantPast, until: until, category: nil, acceptsIncremental: live)
    }

    private func row(_ name: String, at date: Date = Date()) -> EventViewModel {
        .init(id: UUID(), timestamp: date, action: "fixture", category: .process,
              processName: name, pid: 101, detail: name, signerType: "unsigned")
    }

    private func event(_ name: String, at date: Date) -> Event {
        .init(timestamp: date, eventCategory: .process, eventType: .info, eventAction: "fixture",
              process: MacCrabCore.ProcessInfo(pid: 101, ppid: 1, rpid: 1, name: name,
                executable: "/fixture/" + name, commandLine: "/fixture/" + name,
                args: [], workingDirectory: "/", userId: 501, userName: "fixture", groupId: 20,
                startTime: date, ancestors: [], isPlatformBinary: false))
    }

    private func waitUntil(_ condition: () -> Bool) async -> Bool {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(2))
        while !condition(), clock.now < deadline {
            try? await Task.sleep(for: .milliseconds(1))
        }
        return condition()
    }

    @MainActor
    private final class Reader: EventQueryReading {
        let engineSource = V2EngineSource(directory: "/private/tmp/maccrab-query-session-fixture-" + UUID().uuidString)
        var eventQueryEpoch: UInt64 = 0
        var eventReadsDeferred = false
        var result = EventQuerySession.Page(events: [], nextCursor: nil)
        var deferQuery = false
        var blockedQueries: Set<String> = []
        var pendingQueries: [String: CheckedContinuation<EventQuerySession.Page?, Error>] = [:]
        var blockPage = false
        var pendingPage: CheckedContinuation<EventQuerySession.Page?, Error>?
        var histogramError = false
        var histogramCalls = 0
        var blockHistogram = false
        var pendingHistogram: CheckedContinuation<EventQuerySession.Histogram?, Error>?

        func readEventQuery(_ query: EventQuerySession.Query, limit: Int) async throws -> EventQuerySession.Page? {
            let key = query.filter ?? ""
            if blockedQueries.contains(key) {
                return try await withCheckedThrowingContinuation { pendingQueries[key] = $0 }
            }
            return deferQuery ? nil : result
        }
        func readOlderEventQuery(before: PaginationCursor, query: EventQuerySession.Query,
                                 pageSize: Int) async throws -> EventQuerySession.Page? {
            if blockPage { return try await withCheckedThrowingContinuation { pendingPage = $0 } }
            return result
        }
        func readEventAggregates(sinceDay: String, category: MacCrabCore.EventCategory?) async throws -> [EventStore.AggregateRow]? { [] }
        func readEventHistogram(spanSeconds: TimeInterval, stepSeconds: Int, endingAt: Date,
                                category: MacCrabCore.EventCategory?) async throws -> EventQuerySession.Histogram? {
            histogramCalls += 1
            if histogramError { throw NSError(domain: "FixtureReadFailure", code: 1) }
            if blockHistogram { return try await withCheckedThrowingContinuation { pendingHistogram = $0 } }
            return .init(bins: [(endingAt, 1)], effectiveSince: endingAt.addingTimeInterval(-spanSeconds),
                         effectiveUntil: endingAt, coverageWarning: nil)
        }
        func finish(_ key: String, with value: EventQuerySession.Page?) {
            pendingQueries.removeValue(forKey: key)?.resume(returning: value)
        }
        func releasePending() {
            for continuation in pendingQueries.values { continuation.resume(returning: nil) }
            pendingQueries.removeAll()
            pendingPage?.resume(returning: nil)
            pendingPage = nil
            pendingHistogram?.resume(returning: nil)
            pendingHistogram = nil
        }
    }

    @Test("real searches and exact page cursors are independent across two windows")
    func actualStoreIsolation() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("maccrab-query-windows-\(UUID())")
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try EventStore(directory: directory.path)
        let base = Date().addingTimeInterval(-600)
        let values = (0..<6).map { event($0.isMultiple(of: 2) ? "windowalpha" : "windowbeta",
                                         at: base.addingTimeInterval(Double($0) * 60)) }
        for value in values { try await store.insert(event: value) }
        let app = AppState(engineSource: .init(directory: directory.path), startBackgroundWork: false)
        defer { app.stopPolling() }
        let first = EventQuerySession(reader: app)
        let second = EventQuerySession(reader: app)
        await first.loadEvents(query(), limit: 2)
        await second.loadEvents(query(until: values[3].timestamp), limit: 2)
        #expect(first.events.map(\.id) == [values[5].id, values[4].id])
        #expect(second.events.map(\.id) == [values[3].id, values[2].id])
        let secondCursor = try #require(second.cursor)
        await first.loadOlderEvents(pageSize: 2)
        #expect(first.events.map(\.id) == [values[5].id, values[4].id, values[3].id, values[2].id])
        #expect(second.cursor?.id == secondCursor.id)
        await second.loadOlderEvents(pageSize: 2)
        #expect(second.events.map(\.id) == [values[3].id, values[2].id, values[1].id, values[0].id])

        await first.loadEvents(query("windowalpha"))
        await second.loadEvents(query("windowbeta"))
        #expect(!first.events.isEmpty && !second.events.isEmpty)
        #expect(first.events.allSatisfy { $0.processName == "windowalpha" })
        #expect(second.events.allSatisfy { $0.processName == "windowbeta" })
        #expect(first.cursor == nil && second.cursor == nil)
        #expect(first.eventSearchActive && second.eventSearchActive)
        #expect(app.events.isEmpty, "Window search must not replace the shared recent cache used by Alerts")
        #expect(!app.eventSearchActive)
    }

    @Test("late query results cannot replace a newer query", arguments: [false, true])
    func delayedQueryReplacement(cancelOld: Bool) async throws {
        let reader = Reader()
        let session = EventQuerySession(reader: reader)
        let old = row("old"), newest = row("new")
        reader.result = .init(events: [old], nextCursor: .init(timestamp: old.timestamp, id: old.id.uuidString))
        await session.loadEvents(query())
        reader.blockedQueries = ["delayed"]
        let pending = Task { await session.loadEvents(query("delayed")) }
        defer { pending.cancel(); reader.releasePending() }
        let suspended = await waitUntil { reader.pendingQueries["delayed"] != nil }
        try #require(suspended)
        #expect(session.events.isEmpty && session.cursor == nil)
        #expect(session.isLoading)
        if cancelOld { pending.cancel() }
        reader.result = .init(events: [newest], nextCursor: nil)
        await session.loadEvents(query("new"))
        reader.finish("delayed", with: .init(events: [old], nextCursor: nil))
        await pending.value
        #expect(session.events.map(\.id) == [newest.id])
        #expect(!session.isLoading)
    }

    @Test("late older pages cannot append after query replacement or cancellation", arguments: [false, true])
    func delayedPageReplacement(replaceQuery: Bool) async throws {
        let reader = Reader()
        let session = EventQuerySession(reader: reader)
        let original = row("original"), older = row("older"), replacement = row("replacement")
        reader.result = .init(events: [original], nextCursor: .init(timestamp: original.timestamp, id: original.id.uuidString))
        await session.loadEvents(query())
        reader.blockPage = true
        let pending = Task { await session.loadOlderEvents() }
        defer { pending.cancel(); reader.releasePending() }
        let suspended = await waitUntil { reader.pendingPage != nil }
        try #require(suspended)
        if replaceQuery {
            reader.result = .init(events: [replacement], nextCursor: nil)
            await session.loadEvents(query("replacement"))
        } else { pending.cancel() }
        reader.pendingPage?.resume(returning: .init(events: [older], nextCursor: nil))
        reader.pendingPage = nil
        await pending.value
        #expect(session.events.map(\.id) == [replaceQuery ? replacement.id : original.id])
        #expect(!session.isLoadingOlderEvents)
    }

    @Test("engine epoch reset rejects a pending read and clears old pagination")
    func sourceEpochReset() async throws {
        let reader = Reader()
        let session = EventQuerySession(reader: reader)
        reader.blockedQueries = ["delayed"]
        let pending = Task { await session.loadEvents(query("delayed")) }
        defer { pending.cancel(); reader.releasePending() }
        let suspended = await waitUntil { reader.pendingQueries["delayed"] != nil }
        try #require(suspended)
        reader.eventQueryEpoch += 1
        session.synchronizeSourceEpoch()
        reader.finish("delayed", with: .init(events: [row("old boot")], nextCursor: nil))
        await pending.value
        #expect(session.events.isEmpty && session.cursor == nil)
        #expect(session.sourceEpoch == 1 && !session.isLoading)
    }

    @Test("shared incremental polling reaches visible live windows but does not overwrite search")
    func sharedIncrementalDelivery() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("maccrab-query-poll-\(UUID())")
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try EventStore(directory: directory.path)
        let baseline = event("windowalpha", at: Date().addingTimeInterval(-120))
        try await store.insert(event: baseline)
        let app = AppState(engineSource: .init(directory: directory.path), startBackgroundWork: false)
        defer { app.stopPolling() }
        let first = EventQuerySession(reader: app), second = EventQuerySession(reader: app), search = EventQuerySession(reader: app)
        await first.loadEvents(query(live: true))
        await second.loadEvents(query(live: true))
        await search.loadEvents(query("windowalpha"))
        for session in [first, second, search] {
            app.setEventsWorkspaceVisible(true, owner: session.id, session: session)
        }
        await app.loadEventsIncremental()
        let added = event("windowbeta", at: Date().addingTimeInterval(-60))
        try await store.insert(event: added)
        await app.loadEventsIncremental()
        #expect(first.events.map(\.id).contains(added.id))
        #expect(second.events.map(\.id).contains(added.id))
        #expect(search.events.map(\.id) == [baseline.id])
        app.setEventsWorkspaceVisible(false, owner: first.id)
        let later = event("windowgamma", at: Date().addingTimeInterval(-10))
        try await store.insert(event: later)
        await app.loadEventsIncremental()
        #expect(!first.events.map(\.id).contains(later.id))
        #expect(second.events.map(\.id).contains(later.id))
        #expect(app.events.map(\.id).contains(later.id))
    }

    @Test("coverage warnings and deferred-query retry stay in their own window")
    func coverageAndRetryIsolation() async {
        let reader = Reader()
        let first = EventQuerySession(reader: reader), second = EventQuerySession(reader: reader)
        reader.histogramError = true
        _ = await first.fetchHistogramBins(spanSeconds: 60, stepSeconds: 10, endingAt: Date(), category: nil)
        #expect(first.eventHistogramCoverageWarning != nil)
        reader.histogramError = false
        _ = await second.fetchHistogramBins(spanSeconds: 60, stepSeconds: 10, endingAt: Date(), category: nil)
        #expect(second.eventHistogramCoverageWarning == nil)
        #expect(first.eventHistogramCoverageWarning != nil)
        reader.deferQuery = true
        await first.loadEvents(query("deferred"))
        #expect(first.events.isEmpty && first.eventSearchCoverageWarning != nil)
        first.pollTick()
        first.pollTick()
        #expect(first.retryTick == 1 && second.retryTick == 0)
    }

    @Test("hidden histograms perform no read and reject previously visible results")
    func histogramVisibilityBoundary() async throws {
        let reader = Reader()
        let session = EventQuerySession(reader: reader)
        let end = Date()
        defer { reader.releasePending() }
        let hidden = await session.fetchHistogramBins(spanSeconds: 60, stepSeconds: 10,
            endingAt: end, category: nil, isVisible: false)
        #expect(hidden.isEmpty && reader.histogramCalls == 0)
        reader.histogramError = true
        _ = await session.fetchHistogramBins(spanSeconds: 60, stepSeconds: 10,
            endingAt: end, category: nil, isVisible: true)
        #expect(session.eventHistogramCoverageWarning != nil && reader.histogramCalls == 1)
        _ = await session.fetchHistogramBins(spanSeconds: 60, stepSeconds: 10,
            endingAt: end, category: nil, isVisible: false)
        #expect(session.eventHistogramCoverageWarning == nil && reader.histogramCalls == 1)

        reader.histogramError = false
        reader.blockHistogram = true
        let pending = Task { await session.fetchHistogramBins(spanSeconds: 60, stepSeconds: 10,
            endingAt: end, category: nil, isVisible: true) }
        defer { pending.cancel() }
        let suspended = await waitUntil { reader.pendingHistogram != nil }
        try #require(suspended)
        _ = await session.fetchHistogramBins(spanSeconds: 60, stepSeconds: 10,
            endingAt: end, category: nil, isVisible: false)
        #expect(reader.histogramCalls == 2)
        reader.pendingHistogram?.resume(returning: .init(bins: [(end, 7)],
            effectiveSince: end.addingTimeInterval(-30), effectiveUntil: end,
            coverageWarning: "Previous visible query was partial"))
        reader.pendingHistogram = nil
        let late = await pending.value
        #expect(late.isEmpty)
        #expect(session.eventHistogramCoverageWarning == nil)
        #expect(session.eventHistogramEffectiveSince == nil && session.eventHistogramEffectiveUntil == nil)

        reader.blockHistogram = false
        let shown = await session.fetchHistogramBins(spanSeconds: 60, stepSeconds: 10,
            endingAt: end, category: nil, isVisible: true)
        #expect(shown.count == 1 && reader.histogramCalls == 3)
        #expect(session.eventHistogramEffectiveUntil == end)
    }

    @Test("the actual shared poll opens no reader for search and centred-only windows")
    func actualIncrementalConsumerGate() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("maccrab-query-gate-\(UUID())")
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try EventStore(directory: directory.path)
        let baseline = event("windowalpha", at: Date().addingTimeInterval(-60))
        try await store.insert(event: baseline)
        let app = AppState(engineSource: .init(directory: directory.path), startBackgroundWork: false)
        defer { app.stopPolling() }
        let search = EventQuerySession(reader: app), centred = EventQuerySession(reader: app)
        await search.loadEvents(query("windowalpha"))
        await centred.loadEvents(query(until: baseline.timestamp))
        #expect(search.events.map(\.id) == [baseline.id])
        #expect(centred.events.map(\.id) == [baseline.id])
        for session in [search, centred] {
            app.setEventsWorkspaceVisible(true, owner: session.id, session: session)
        }
        // Release the real cached handle, while retaining both visible query
        // registrations. A stray poll read would reopen it and populate events.
        app.stopPolling()
        #expect(!app.hasCachedEventStoreForTesting)
        await app.loadEventsIncremental()
        #expect(!app.hasCachedEventStoreForTesting && app.events.isEmpty)

        // Positive control: the same store and shared poll can read once a
        // loaded live window needs incremental rows.
        let live = EventQuerySession(reader: app)
        await live.loadEvents(query(live: true))
        app.setEventsWorkspaceVisible(true, owner: live.id, session: live)
        app.stopPolling()
        await app.loadEventsIncremental()
        #expect(app.hasCachedEventStoreForTesting)
        #expect(app.events.map(\.id) == [baseline.id])
    }

    @Test("new window queries defer during startup and resume their own selection when ready")
    func newSessionsAcrossStartupReadiness() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("maccrab-query-startup-\(UUID())")
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try EventStore(directory: directory.path)
        let first = event("readyalpha", at: Date().addingTimeInterval(-120))
        let second = event("readybeta", at: first.timestamp.addingTimeInterval(60))
        try await store.insert(event: first)
        try await store.insert(event: second)
        let heartbeatPath = directory.appendingPathComponent("heartbeat.json")
        let startedAt = Date().addingTimeInterval(-5).timeIntervalSince1970
        func writeHeartbeat(_ phase: String, revision: Int) throws {
            let raw: [String: Any] = ["engine_pid": 101, "engine_started_at_unix": startedAt,
                "engine_version": "1.22.0", "engine_build": "fixture", "boot_phase": phase,
                "written_at_unix": Date().timeIntervalSince1970, "liveness": phase == "ready"]
            try JSONSerialization.data(withJSONObject: raw).write(to: heartbeatPath, options: .atomic)
            try FileManager.default.setAttributes(
                [.modificationDate: Date(timeIntervalSince1970: 1_780_000_000 + Double(revision))],
                ofItemAtPath: heartbeatPath.path)
        }
        try writeHeartbeat("starting", revision: 0)
        let app = AppState(engineSource: .init(directory: directory.path), startBackgroundWork: false)
        defer { app.stopPolling() }
        app.refreshHeartbeat()
        #expect(app.eventReadsDeferred)
        let search = EventQuerySession(reader: app), centred = EventQuerySession(reader: app)
        for session in [search, centred] {
            app.setEventsWorkspaceVisible(true, owner: session.id, session: session)
        }
        let searchQuery = query("readybeta"), centredQuery = query(until: first.timestamp)
        await search.loadEvents(searchQuery)
        await centred.loadEvents(centredQuery)
        await app.loadEventsIncremental()
        #expect(search.events.isEmpty && centred.events.isEmpty)
        #expect(!app.hasCachedEventStoreForTesting)
        let startingEpoch = search.sourceEpoch

        try writeHeartbeat("ready", revision: 1)
        app.refreshHeartbeat()
        #expect(!app.eventReadsDeferred)
        // EventStream's task key observes these source epochs and reissues
        // each window's selected query. The routine poll must not substitute
        // an unfiltered read before those initial queries have loaded.
        #expect(search.sourceEpoch > startingEpoch && centred.sourceEpoch == search.sourceEpoch)
        await app.loadEventsIncremental()
        #expect(!app.hasCachedEventStoreForTesting)
        await search.loadEvents(searchQuery)
        await centred.loadEvents(centredQuery)
        #expect(search.events.map(\.id) == [second.id])
        #expect(centred.events.map(\.id) == [first.id])
        #expect(search.eventSearchActive && !centred.eventSearchActive)
        #expect(app.hasCachedEventStoreForTesting && app.events.isEmpty)
    }

    @Test("search and centred-only windows do not admit shared incremental reads")
    func incrementalEligibilityAndUpperBound() async {
        let reader = Reader()
        let app = AppState(engineSource: reader.engineSource, startBackgroundWork: false)
        let search = EventQuerySession(reader: reader), centred = EventQuerySession(reader: reader)
        await search.loadEvents(query("search"))
        await centred.loadEvents(query(live: false))
        for session in [search, centred] {
            app.setEventsWorkspaceVisible(true, owner: session.id, session: session)
        }
        #expect(app.eventsWorkspaceVisible)
        #expect(!app.shouldReadIncrementalEvents)
        let live = EventQuerySession(reader: reader)
        let cutoff = Date()
        let baseline = row("baseline", at: cutoff.addingTimeInterval(-10))
        reader.result = .init(events: [baseline], nextCursor: nil)
        await live.loadEvents(query(until: cutoff, live: true))
        app.setEventsWorkspaceVisible(true, owner: live.id, session: live)
        #expect(app.shouldReadIncrementalEvents)
        live.receiveIncremental([row("outside requested upper bound", at: cutoff.addingTimeInterval(1))], epoch: 0)
        #expect(live.events.map(\.id) == [baseline.id])
        app.setEventsWorkspaceVisible(false, owner: live.id)
        #expect(!app.shouldReadIncrementalEvents)
    }

    @Test("query and source replacement reset paused presentation before delayed reads finish")
    func pausedPresentationReset() async throws {
        let reader = Reader()
        let session = EventQuerySession(reader: reader)
        let baseline = row("previous query")
        reader.result = .init(events: [baseline], nextCursor: nil)
        var paused = false
        var retainedTable: [EventViewModel] = []
        // These are the actual session publishers consumed by EventStream.
        let rows = session.$events.sink { if !paused { retainedTable = $0 } }
        let resets = session.$presentationResetTick.dropFirst().sink { _ in retainedTable = [] }
        defer { rows.cancel(); resets.cancel(); reader.releasePending() }
        await session.loadEvents(query())
        #expect(retainedTable.map(\.id) == [baseline.id])
        paused = true
        reader.blockedQueries = ["replacement"]
        let pending = Task { await session.loadEvents(query("replacement")) }
        defer { pending.cancel() }
        let suspended = await waitUntil { reader.pendingQueries["replacement"] != nil }
        try #require(suspended)
        #expect(retainedTable.isEmpty, "Pause must not retain old rows beneath a new query label")
        reader.finish("replacement", with: .init(events: [row("replacement")], nextCursor: nil))
        await pending.value
        // An explicit completed query is displayed even while paused; a later
        // source reset must clear that retained table independently of arrivals.
        retainedTable = session.events
        #expect(!retainedTable.isEmpty)
        reader.eventReadsDeferred = true
        reader.eventQueryEpoch += 1
        session.synchronizeSourceEpoch()
        #expect(retainedTable.isEmpty && session.events.isEmpty)
    }
}
