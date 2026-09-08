import Foundation
import Combine
import MacCrabCore

/// The shared reader owns the connection. Windows own only query presentation.
@MainActor
protocol EventQueryReading: AnyObject {
    var engineSource: V2EngineSource { get }
    var eventQueryEpoch: UInt64 { get }
    var eventReadsDeferred: Bool { get }
    func readEventQuery(_ query: EventQuerySession.Query, limit: Int) async throws -> EventQuerySession.Page?
    func readOlderEventQuery(before: PaginationCursor, query: EventQuerySession.Query,
                             pageSize: Int) async throws -> EventQuerySession.Page?
    func readEventAggregates(sinceDay: String, category: MacCrabCore.EventCategory?) async throws -> [EventStore.AggregateRow]?
    func readEventHistogram(spanSeconds: TimeInterval, stepSeconds: Int, endingAt: Date,
                            category: MacCrabCore.EventCategory?) async throws -> EventQuerySession.Histogram?
}

@MainActor
final class EventQuerySession: ObservableObject {
    struct Query: Equatable {
        let filter: String?
        let since: Date
        let until: Date
        let category: MacCrabCore.EventCategory?
        let acceptsIncremental: Bool
        var isSearch: Bool { filter.map { !$0.isEmpty } ?? false }
    }
    struct Page {
        let events: [EventViewModel]
        let nextCursor: PaginationCursor?
        var coverageWarning: String? = nil
    }
    struct Histogram {
        let bins: [(Date, Int)]
        let effectiveSince: Date
        let effectiveUntil: Date
        let coverageWarning: String?
    }

    let id = UUID()
    let source: V2EngineSource
    private let reader: any EventQueryReading
    @Published private(set) var sourceEpoch: UInt64
    @Published private(set) var retryTick: UInt64 = 0
    /// Query/source replacements invalidate a paused view's retained table too.
    @Published private(set) var presentationResetTick: UInt64 = 0
    @Published private(set) var events: [EventViewModel] = []
    @Published private(set) var eventSearchActive = false
    @Published private(set) var hasMoreEvents = false
    @Published private(set) var isLoading = false
    @Published private(set) var isLoadingOlderEvents = false
    @Published private(set) var eventSearchCoverageWarning: String?
    @Published private(set) var eventHistogramCoverageWarning: String?
    @Published private(set) var eventAggregateCoverageWarning: String?
    @Published private(set) var eventHistogramEffectiveSince: Date?
    @Published private(set) var eventHistogramEffectiveUntil: Date?
    private(set) var cursor: PaginationCursor?
    private var query: Query?
    private var queryGeneration: UInt64 = 0
    private var pageGeneration: UInt64 = 0
    private var histogramGeneration: UInt64 = 0
    private var aggregateGeneration: UInt64 = 0
    private var queryLoaded = false
    private var retryNeeded = false

    init(reader: any EventQueryReading) {
        self.reader = reader
        source = reader.engineSource
        sourceEpoch = reader.eventQueryEpoch
    }

    /// A detached database read may outlive the requesting view. Invalidate its
    /// receipt as well as cancelling the SwiftUI task that requested it.
    func invalidatePendingReads() {
        queryGeneration &+= 1
        pageGeneration &+= 1
        histogramGeneration &+= 1
        aggregateGeneration &+= 1
        isLoading = false
        isLoadingOlderEvents = false
        retryNeeded = false
        queryLoaded = false
    }

    func synchronizeSourceEpoch() {
        guard sourceEpoch != reader.eventQueryEpoch else { return }
        invalidatePendingReads()
        sourceEpoch = reader.eventQueryEpoch
        presentationResetTick &+= 1
        events = []
        cursor = nil
        hasMoreEvents = false
        queryLoaded = false
        eventSearchCoverageWarning = nil
        eventHistogramCoverageWarning = nil
        eventAggregateCoverageWarning = nil
        eventHistogramEffectiveSince = nil
        eventHistogramEffectiveUntil = nil
    }

    private func acceptsEpoch(_ epoch: UInt64) -> Bool {
        !Task.isCancelled && epoch == sourceEpoch && epoch == reader.eventQueryEpoch
            && source == reader.engineSource && !reader.eventReadsDeferred
    }

    private func accepts(_ generation: UInt64, epoch: UInt64) -> Bool {
        generation == queryGeneration && acceptsEpoch(epoch)
    }

    func loadEvents(_ next: Query, limit: Int = 500, debounce: Bool = false) async {
        guard !Task.isCancelled else { return }
        synchronizeSourceEpoch()
        queryGeneration &+= 1
        pageGeneration &+= 1
        isLoadingOlderEvents = false
        retryNeeded = false
        query = next
        presentationResetTick &+= 1
        let generation = queryGeneration
        let epoch = sourceEpoch
        // A new label must never describe the preceding query's rows/cursor,
        // including during debounce, pressure, or a failed replacement read.
        events = []
        cursor = nil
        hasMoreEvents = false
        queryLoaded = false
        eventSearchActive = next.isSearch
        eventSearchCoverageWarning = nil
        isLoading = true
        defer { if generation == queryGeneration { isLoading = false } }
        do {
            if debounce { try await Task.sleep(for: .milliseconds(300)) }
            guard accepts(generation, epoch: epoch) else { return }
            guard let page = try await reader.readEventQuery(next, limit: limit) else {
                if accepts(generation, epoch: epoch) {
                    retryNeeded = true
                    eventSearchCoverageWarning = "Event read is temporarily deferred. It will retry on the next refresh."
                }
                return
            }
            guard accepts(generation, epoch: epoch) else { return }
            events = page.events
            cursor = page.nextCursor
            hasMoreEvents = page.nextCursor != nil
            eventSearchCoverageWarning = page.coverageWarning
            queryLoaded = true
        } catch is CancellationError {
            if accepts(generation, epoch: epoch) {
                retryNeeded = true
                eventSearchCoverageWarning = "Event read was interrupted. It will retry on the next refresh."
            }
        } catch {
            guard accepts(generation, epoch: epoch) else { return }
            eventSearchCoverageWarning = "Event evidence could not be read completely: " + error.localizedDescription
        }
    }

    func loadOlderEvents(pageSize: Int = 200) async {
        guard let query, !query.isSearch, queryLoaded, let cursor,
              !isLoadingOlderEvents else { return }
        let generation = queryGeneration
        let epoch = sourceEpoch
        pageGeneration &+= 1
        let pageToken = pageGeneration
        guard accepts(generation, epoch: epoch) else { return }
        isLoadingOlderEvents = true
        defer { if pageToken == pageGeneration { isLoadingOlderEvents = false } }
        do {
            guard let page = try await reader.readOlderEventQuery(before: cursor, query: query, pageSize: pageSize),
                  accepts(generation, epoch: epoch), pageToken == pageGeneration else { return }
            let existing = Set(events.map(\.id))
            events.append(contentsOf: page.events.filter { !existing.contains($0.id) })
            self.cursor = page.nextCursor
            hasMoreEvents = page.nextCursor != nil
            eventSearchCoverageWarning = page.coverageWarning
        } catch is CancellationError {
        } catch {
            guard accepts(generation, epoch: epoch), pageToken == pageGeneration else { return }
            eventSearchCoverageWarning = "Older event evidence could not be read completely: " + error.localizedDescription
        }
    }

    /// Called by the existing shared poll; no per-window timer or connection.
    func pollTick() {
        synchronizeSourceEpoch()
        if retryNeeded && !isLoading {
            retryNeeded = false
            retryTick &+= 1
        }
    }

    var canReceiveIncremental: Bool {
        sourceEpoch == reader.eventQueryEpoch && source == reader.engineSource
            && !reader.eventReadsDeferred && queryLoaded && !isLoading
            && query?.acceptsIncremental == true && query?.isSearch == false
    }

    func receiveIncremental(_ rows: [EventViewModel], epoch: UInt64, warning: String? = nil) {
        guard canReceiveIncremental, epoch == sourceEpoch, epoch == reader.eventQueryEpoch,
              !reader.eventReadsDeferred, queryLoaded, !isLoading,
              let query, query.acceptsIncremental, !query.isSearch else { return }
        if let warning { eventSearchCoverageWarning = warning; return }
        let existing = Set(events.map(\.id))
        let newest = events.map(\.timestamp).max() ?? query.since
        let appended = rows.filter {
            $0.timestamp >= newest && $0.timestamp >= query.since && $0.timestamp <= query.until
                && !existing.contains($0.id)
                && (query.category == nil || $0.category.rawValue == query.category?.rawValue)
        }
        guard !appended.isEmpty else { return }
        events = Array((appended + events).prefix(5000))
    }

    func fetchAggregates(sinceDay: String, category: MacCrabCore.EventCategory?) async -> [EventStore.AggregateRow] {
        guard !Task.isCancelled else { return [] }
        synchronizeSourceEpoch()
        aggregateGeneration &+= 1
        let token = aggregateGeneration
        let epoch = sourceEpoch
        eventAggregateCoverageWarning = nil
        do {
            guard let rows = try await reader.readEventAggregates(sinceDay: sinceDay, category: category),
                  token == aggregateGeneration, acceptsEpoch(epoch) else { return [] }
            eventAggregateCoverageWarning = nil
            return rows
        } catch is CancellationError {
            return []
        } catch {
            guard token == aggregateGeneration, acceptsEpoch(epoch) else { return [] }
            eventAggregateCoverageWarning = "Daily summaries are incomplete: " + error.localizedDescription
            return []
        }
    }

    func fetchHistogramBins(spanSeconds: TimeInterval, stepSeconds: Int, endingAt: Date,
                            category: MacCrabCore.EventCategory?, isVisible: Bool = true) async -> [(Date, Int)] {
        guard !Task.isCancelled else { return [] }
        synchronizeSourceEpoch()
        histogramGeneration &+= 1
        let token = histogramGeneration
        let epoch = sourceEpoch
        eventHistogramCoverageWarning = nil
        eventHistogramEffectiveSince = nil
        eventHistogramEffectiveUntil = nil
        // Hiding the chart also invalidates an in-flight read, so its old
        // coverage interval cannot return after the hidden task completes.
        guard isVisible, !reader.eventReadsDeferred else { return [] }
        do {
            guard let result = try await reader.readEventHistogram(spanSeconds: spanSeconds, stepSeconds: stepSeconds,
                                                                  endingAt: endingAt, category: category),
                  token == histogramGeneration, acceptsEpoch(epoch) else { return [] }
            eventHistogramCoverageWarning = result.coverageWarning
            eventHistogramEffectiveSince = result.effectiveSince
            eventHistogramEffectiveUntil = result.effectiveUntil
            return result.bins
        } catch is CancellationError {
            return []
        } catch {
            guard token == histogramGeneration, acceptsEpoch(epoch) else { return [] }
            eventHistogramEffectiveSince = nil
            eventHistogramEffectiveUntil = nil
            eventHistogramCoverageWarning = "Histogram evidence could not be read completely: " + error.localizedDescription
            return []
        }
    }
}
