import Foundation
import Testing
@testable import MacCrabApp
@testable import MacCrabCore

@MainActor
@Suite("Events exact presentation admission")
struct EventStreamQueryPolicyTests {
    private final class Reader: EventQueryReading {
        let engineSource = V2EngineSource(directory: "/private/tmp/unused-event-presentation-fixture")
        var eventQueryEpoch: UInt64 = 0
        var eventReadsDeferred = false
        var queryCalls = 0
        var pageCalls = 0
        var queryGate: DashboardReadTestGate?
        var pageGate: DashboardReadTestGate?
        var aggregateGate: DashboardReadTestGate?
        var histogramGate: DashboardReadTestGate?
        let row = EventViewModel(id: UUID(), timestamp: Date(timeIntervalSince1970: 1_700_000_000),
            action: "fixture", category: .file, processName: "ordinary", pid: 1,
            detail: "in-memory fixture", signerType: "unsigned")

        func readEventQuery(_ query: EventQuerySession.Query, limit: Int) async throws -> EventQuerySession.Page? {
            queryCalls += 1
            if let queryGate { await queryGate.pause() }
            return .init(events: [row], nextCursor: .init(timestamp: row.timestamp, id: row.id.uuidString),
                         coverageWarning: "synthetic exact coverage")
        }
        func readOlderEventQuery(before: PaginationCursor, query: EventQuerySession.Query,
                                 pageSize: Int) async throws -> EventQuerySession.Page? {
            pageCalls += 1
            if let pageGate { await pageGate.pause() }
            return .init(events: [row], nextCursor: before)
        }
        func readEventAggregates(sinceDay: String, category: MacCrabCore.EventCategory?) async throws -> [EventStore.AggregateRow]? {
            if let aggregateGate { await aggregateGate.pause() }
            return [.init(day: "2023-11-14", category: .file, processSigner: "", processPath: "", count: 1)]
        }
        func readEventHistogram(spanSeconds: TimeInterval, stepSeconds: Int, endingAt: Date,
                                category: MacCrabCore.EventCategory?) async throws -> EventQuerySession.Histogram? {
            if let histogramGate { await histogramGate.pause() }
            return .init(bins: [(endingAt, 1)], effectiveSince: endingAt.addingTimeInterval(-spanSeconds),
                         effectiveUntil: endingAt, coverageWarning: "synthetic histogram coverage")
        }
    }

    private func query() -> EventQuerySession.Query {
        .init(filter: nil, since: .distantPast, until: .distantFuture,
              category: nil, acceptsIncremental: true)
    }

    @Test("A hidden exact table issues no read or debounce and clears its old pagination")
    func hiddenPresentationDoesNotRead() async {
        let reader = Reader()
        let session = EventQuerySession(reader: reader)
        await session.loadEvents(query())
        #expect(reader.queryCalls == 1 && session.hasMoreEvents && session.canReceiveIncremental)
        await session.loadEvents(query(), debounce: true, isPresented: false)
        await session.loadOlderEvents()
        #expect(reader.queryCalls == 1 && reader.pageCalls == 0)
        #expect(session.events.isEmpty && session.cursor == nil && !session.hasMoreEvents)
        #expect(!session.canReceiveIncremental && !session.isLoading && !session.eventSearchActive)
        #expect(session.eventSearchCoverageWarning == nil)
        let retry = session.retryTick
        session.pollTick()
        #expect(session.retryTick == retry)
    }

    @Test("An exact result arriving after aggregate transition cannot repopulate rows")
    func lateExactResultIsRetired() async {
        let reader = Reader()
        let gate = DashboardReadTestGate()
        reader.queryGate = gate
        defer { gate.release() }
        let session = EventQuerySession(reader: reader)
        let read = Task { await session.loadEvents(query()) }
        await gate.waitUntilPaused()
        session.deactivateExactPresentation()
        gate.release()
        await read.value
        #expect(session.events.isEmpty && session.cursor == nil && !session.hasMoreEvents)
        #expect(session.eventSearchCoverageWarning == nil && !session.canReceiveIncremental)
        // Returning to exact mode must perform a genuinely new read, not reuse
        // the obsolete completion or claim its cursor is current.
        reader.queryGate = nil
        await session.loadEvents(query())
        #expect(reader.queryCalls == 2 && session.events.count == 1 && session.canReceiveIncremental)
    }

    @Test("An older page cannot append after exact presentation is deactivated")
    func latePageIsRetired() async {
        let reader = Reader()
        let session = EventQuerySession(reader: reader)
        await session.loadEvents(query())
        let gate = DashboardReadTestGate()
        reader.pageGate = gate
        defer { gate.release() }
        let page = Task { await session.loadOlderEvents() }
        await gate.waitUntilPaused()
        session.deactivateExactPresentation()
        gate.release()
        await page.value
        #expect(session.events.isEmpty && session.cursor == nil && !session.isLoadingOlderEvents)
    }

    @Test("Exact-only deactivation preserves independent summary reads; full invalidation does not",
          arguments: [false, true])
    func summaryGenerationsAreIndependent(fullInvalidation: Bool) async {
        // Summary modes deliberately share one backend lane; test each mode's
        // independent presentation receipt without demanding overlapping work.
        for useHistogram in [false, true] {
            let reader = Reader(), gate = DashboardReadTestGate()
            if useHistogram { reader.histogramGate = gate }
            else { reader.aggregateGate = gate }
            defer { gate.release() }
            let session = EventQuerySession(reader: reader)
            let result = Task { () -> Int in
                if useHistogram {
                    return await session.fetchHistogramBins(spanSeconds: 60, stepSeconds: 10,
                        endingAt: Date(timeIntervalSince1970: 1_700_000_000), category: nil).count
                }
                return await session.fetchAggregates(sinceDay: "2023-11-14", category: nil).count
            }
            await gate.waitUntilPaused()
            if fullInvalidation { session.invalidatePendingReads() }
            else { session.deactivateExactPresentation() }
            gate.release()
            #expect(await result.value == (fullInvalidation ? 0 : 1))
            if useHistogram {
                #expect(session.eventHistogramCoverageWarning == (fullInvalidation ? nil : "synthetic histogram coverage"))
            }
        }
    }

    @Test("Only a subsequent nonempty text edit is debounced")
    func initialAndNonTextQueryChangesAreImmediate() {
        #expect(!EventStream.shouldDebounce(previousFilter: nil, nextFilter: ""))
        #expect(!EventStream.shouldDebounce(previousFilter: nil, nextFilter: "prefilled"))
        #expect(!EventStream.shouldDebounce(previousFilter: "term", nextFilter: "term"))
        #expect(!EventStream.shouldDebounce(previousFilter: "term", nextFilter: ""))
        #expect(EventStream.shouldDebounce(previousFilter: "", nextFilter: "t"))
        #expect(EventStream.shouldDebounce(previousFilter: "t", nextFilter: "te"))
    }
}
