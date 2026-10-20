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

    /// A window retains one presentation, not views or database leases. At most
    /// two bounded backend flights can finish across ordinary page navigation.
    /// The time-range label is separate from its moving `since` bound.
    struct PresentationKey: Equatable {
        let range: String
        let filter: String
        let category: String?
        let center: Date?
        let halfWindowSeconds: TimeInterval
    }
    struct Controls {
        var intentFilter = ""
        var intentCenter: Date?
        var intentHalfWindow: TimeInterval = 1800
        var filter = ""
        var category: EventCategory?
        var range: TimeRange = .last24h
        var paused = false
    }
    var controls = Controls()

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
    @Published private(set) var showingCachedEvents = false
    @Published private(set) var readiness = UIContentReadiness(workspace: .events)
    @Published private(set) var aggregateReadiness = UIContentReadiness(workspace: .events)
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
    private var presentationKey: PresentationKey?
    private var lastSuccessAt: Date?
    private let now: () -> Date
    private struct ExactReadKey: Equatable {
        let epoch: UInt64
        let query: Query
        let limit: Int
        let cursor: PaginationCursor?
        let presentation: PresentationKey?

        func mayFinishBefore(_ next: Self) -> Bool {
            epoch == next.epoch && presentation == next.presentation
                && query.filter == next.query.filter && query.until == next.query.until
                && query.category == next.query.category
                && query.acceptsIncremental == next.query.acceptsIncremental
                && next.query.since >= query.since
        }
    }
    private enum AuxiliaryReadKey: Equatable {
        case aggregates(epoch: UInt64, sinceDay: String, category: MacCrabCore.EventCategory?)
        case histogram(epoch: UInt64, span: TimeInterval, step: Int, end: Date,
                       category: MacCrabCore.EventCategory?)

        func mayFinishBefore(_ next: Self) -> Bool {
            switch (self, next) {
            case let (.aggregates(a, day, category), .aggregates(b, nextDay, nextCategory)):
                return a == b && day == nextDay && category == nextCategory
            case let (.histogram(a, span, step, end, category),
                      .histogram(b, nextSpan, nextStep, nextEnd, nextCategory)):
                return a == b && span == nextSpan && step == nextStep
                    && category == nextCategory && nextEnd >= end
            default: return false
            }
        }
    }
    private enum AuxiliaryResult {
        case aggregates([EventStore.AggregateRow]?)
        case histogram(Histogram?)
    }
    private let exactReads = EventReadFlight<ExactReadKey, Page?>()
    private let auxiliaryReads = EventReadFlight<AuxiliaryReadKey, AuxiliaryResult>()
    private var acceptsBackendReads = true
    static let retainedRowLimit = 500
    static let retainedPayloadLimit = 4 * 1024 * 1024
    static let retainedLifetime: TimeInterval = 60

    init(reader: any EventQueryReading, now: @escaping () -> Date = Date.init) {
        self.reader = reader
        self.now = now
        source = reader.engineSource
        sourceEpoch = reader.eventQueryEpoch
    }

    /// Actual window close/background, never ordinary workspace disappearance.
    /// Existing Core cancellation and reader retirement remain authoritative.
    func cancelBackendReads() {
        acceptsBackendReads = false
        exactReads.cancel()
        auxiliaryReads.cancel()
        invalidatePendingReads()
    }

    func resumeBackendReads() {
        guard !acceptsBackendReads else { return }
        acceptsBackendReads = true
        synchronizeSourceEpoch()
        // Visible EventStream restarts through its existing query task. There
        // is no hidden read, timer or task spawned by this method.
        retryTick &+= 1
    }

    func reconcileBackendContext() {
        synchronizeSourceEpoch()
        if source != reader.engineSource || reader.eventReadsDeferred {
            exactReads.cancel()
            auxiliaryReads.cancel()
            invalidatePendingReads()
        }
    }

    #if DEBUG
    var backendWaitersForTesting: (exact: Int, auxiliary: Int) {
        (exactReads.waiterCountForTesting, auxiliaryReads.waiterCountForTesting)
    }
    #endif

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
        readiness.invalidate()
        aggregateReadiness.invalidate()
        // No hidden polling or pagination. Keep at most one small, explicitly
        // stale first page; the next visit must read again before claiming fresh.
        events = Array(events.prefix(Self.retainedRowLimit))
        if retainedPayloadBytes > Self.retainedPayloadLimit {
            events = []
            lastSuccessAt = nil
        }
        cursor = nil
        hasMoreEvents = false
        showingCachedEvents = !events.isEmpty
    }

    private var retainedPayloadBytes: Int {
        events.reduce(0) { total, row in
            total + [row.action, row.processName, row.detail, row.signerType,
                     row.executablePath, row.commandLine, row.userName,
                     row.workingDirectory, row.architecture, row.aiTool,
                     row.parentName, row.parentExecutable, row.processSHA256]
                .reduce(0) { $0 + $1.utf8.count }
        }
    }

    func matchesPresentation(_ next: Query, key: PresentationKey?) -> Bool {
        guard let key, key == presentationKey, let query,
              source == reader.engineSource, sourceEpoch == reader.eventQueryEpoch,
              !reader.eventReadsDeferred,
              next.filter == query.filter, next.category == query.category,
              next.until == query.until, next.since >= query.since,
              next.acceptsIncremental == query.acceptsIncremental else { return false }
        return true
    }

    func canDisplay(_ next: Query, key: PresentationKey?) -> Bool {
        matchesPresentation(next, key: key) && (queryLoaded || canPresentCached(next, key: key))
    }

    /// Compatibility is checked before first paint as well as before a read.
    /// Only advancing the lower time bound is allowed for a moving range.
    func canPresentCached(_ next: Query, key: PresentationKey?) -> Bool {
        guard matchesPresentation(next, key: key), let lastSuccessAt, !events.isEmpty else { return false }
        let age = now().timeIntervalSince(lastSuccessAt)
        return age.isFinite && age >= 0 && age <= Self.retainedLifetime
    }

    /// The exact-row table is not presented in aggregate mode. Retire only its
    /// query/page receipts, backend and presentation, not the independent
    /// aggregate operation (whose SwiftUI task may already have started).
    func deactivateExactPresentation() {
        exactReads.cancel()
        queryGeneration &+= 1
        pageGeneration &+= 1
        query = nil
        presentationKey = nil
        lastSuccessAt = nil
        showingCachedEvents = false
        readiness.invalidate()
        queryLoaded = false
        retryNeeded = false
        events = []
        cursor = nil
        hasMoreEvents = false
        eventSearchActive = false
        eventSearchCoverageWarning = nil
        isLoading = false
        isLoadingOlderEvents = false
        presentationResetTick &+= 1
    }

    func synchronizeSourceEpoch() {
        guard sourceEpoch != reader.eventQueryEpoch else { return }
        exactReads.cancel()
        auxiliaryReads.cancel()
        invalidatePendingReads()
        sourceEpoch = reader.eventQueryEpoch
        presentationResetTick &+= 1
        events = []
        cursor = nil
        hasMoreEvents = false
        queryLoaded = false
        lastSuccessAt = nil
        showingCachedEvents = false
        eventSearchCoverageWarning = nil
        eventHistogramCoverageWarning = nil
        eventAggregateCoverageWarning = nil
        eventHistogramEffectiveSince = nil
        eventHistogramEffectiveUntil = nil
    }

    private func acceptsEpoch(_ epoch: UInt64) -> Bool {
        acceptsBackendReads && !Task.isCancelled && epoch == sourceEpoch && epoch == reader.eventQueryEpoch
            && source == reader.engineSource && !reader.eventReadsDeferred
    }

    private func accepts(_ generation: UInt64, epoch: UInt64) -> Bool {
        generation == queryGeneration && acceptsEpoch(epoch)
    }

    func loadEvents(_ next: Query, limit: Int = 500, debounce: Bool = false,
                    isPresented: Bool = true, presentationKey nextKey: PresentationKey? = nil) async {
        guard acceptsBackendReads, !Task.isCancelled else { return }
        guard isPresented else {
            deactivateExactPresentation()
            return
        }
        // A true mode change, unlike workspace departure, invalidates the old
        // aggregate operation even when the chart is hidden in the new mode.
        auxiliaryReads.cancel { if case .aggregates = $0 { return true }; return false }
        aggregateGeneration &+= 1
        aggregateReadiness.invalidate()
        synchronizeSourceEpoch()
        let retainRows = canPresentCached(next, key: nextKey)
        queryGeneration &+= 1
        pageGeneration &+= 1
        isLoadingOlderEvents = false
        retryNeeded = false
        query = next
        presentationKey = nextKey
        if !retainRows { presentationResetTick &+= 1 }
        let generation = queryGeneration
        let epoch = sourceEpoch
        // A new label must never describe the preceding query's rows/cursor,
        // including during debounce, pressure, or a failed replacement read.
        let retained = retainRows ? events.filter { $0.timestamp >= next.since && $0.timestamp <= next.until } : []
        // Combine delivers $events synchronously, before the setter completes.
        // Retire freshness before publishing any replacement table contents.
        queryLoaded = false
        showingCachedEvents = !retained.isEmpty
        if !retainRows { lastSuccessAt = nil }
        cursor = nil
        hasMoreEvents = false
        eventSearchActive = next.isSearch
        eventSearchCoverageWarning = nil
        isLoading = true
        let readyTicket = readiness.begin(retainingCachedContent: showingCachedEvents)
        events = retained
        defer {
            if generation == queryGeneration {
                isLoading = false
                if Task.isCancelled {
                    readiness.complete(.deferred, for: readyTicket)
                    eventSearchCoverageWarning = String(localized: "events.readInterrupted", defaultValue: "Event read was interrupted. Refresh to retry.")
                } else if source != reader.engineSource || epoch != reader.eventQueryEpoch || reader.eventReadsDeferred {
                    readiness.complete(.unavailable, for: readyTicket)
                }
            }
        }
        do {
            if debounce { try await Task.sleep(for: .milliseconds(300)) }
            guard accepts(generation, epoch: epoch) else {
                if generation == queryGeneration { readiness.complete(.unavailable, for: readyTicket) }
                return
            }
            let readKey = ExactReadKey(epoch: epoch, query: next, limit: limit,
                                       cursor: nil, presentation: nextKey)
            let reader = reader
            let result = try await exactReads.read(key: readKey,
                cancelExisting: { !$0.mayFinishBefore(readKey) },
                isCurrent: { [weak self] in self?.accepts(generation, epoch: epoch) == true },
                operation: { [reader] in try await reader.readEventQuery(next, limit: limit) })
            guard let page = result else {
                if accepts(generation, epoch: epoch) {
                    retryNeeded = true
                    eventSearchCoverageWarning = String(localized: "events.readDeferredDetail", defaultValue: "Event read is temporarily deferred. It will retry on the next refresh.")
                    readiness.complete(.deferred, for: readyTicket)
                }
                return
            }
            guard accepts(generation, epoch: epoch) else { return }
            events = page.events
            cursor = page.nextCursor
            hasMoreEvents = page.nextCursor != nil
            eventSearchCoverageWarning = page.coverageWarning
            queryLoaded = true
            lastSuccessAt = now()
            showingCachedEvents = false
            readiness.complete(page.coverageWarning == nil
                ? (events.isEmpty ? .loadedEmpty : .loadedNonempty) : .partial, for: readyTicket)
        } catch is CancellationError {
            if accepts(generation, epoch: epoch) {
                retryNeeded = true
                eventSearchCoverageWarning = String(localized: "events.readInterrupted", defaultValue: "Event read was interrupted. Refresh to retry.")
                readiness.complete(.deferred, for: readyTicket)
            }
        } catch let error as EventStoreError where AppState.isTransientReadPressure(error) {
            // The engine was busy or under memory pressure: retry on the next
            // poll instead of stopping at a failure.
            if accepts(generation, epoch: epoch) {
                retryNeeded = true
                eventSearchCoverageWarning = String(localized: "events.readInterrupted", defaultValue: "Event read was interrupted. Refresh to retry.")
                readiness.complete(.deferred, for: readyTicket)
            }
        } catch {
            guard accepts(generation, epoch: epoch) else { return }
            eventSearchCoverageWarning = String(localized: "events.readFailed", defaultValue: "Couldn’t load events.") + "\n" + error.localizedDescription
            readiness.complete(.failed, for: readyTicket)
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
            let readKey = ExactReadKey(epoch: epoch, query: query, limit: pageSize,
                                       cursor: cursor, presentation: presentationKey)
            let reader = reader
            let result = try await exactReads.read(key: readKey,
                cancelExisting: { !$0.mayFinishBefore(readKey) },
                isCurrent: { [weak self] in
                    self?.accepts(generation, epoch: epoch) == true && self?.pageGeneration == pageToken
                }, operation: { [reader] in
                    try await reader.readOlderEventQuery(before: cursor, query: query, pageSize: pageSize)
                })
            guard let page = result,
                  accepts(generation, epoch: epoch), pageToken == pageGeneration else { return }
            let existing = Set(events.map(\.id))
            events.append(contentsOf: page.events.filter { !existing.contains($0.id) })
            self.cursor = page.nextCursor
            hasMoreEvents = page.nextCursor != nil
            eventSearchCoverageWarning = page.coverageWarning
            if page.coverageWarning != nil {
                let ticket = readiness.begin(retainingCachedContent: false)
                readiness.complete(.partial, for: ticket)
            }
        } catch is CancellationError {
        } catch {
            guard accepts(generation, epoch: epoch), pageToken == pageGeneration else { return }
            eventSearchCoverageWarning = String(localized: "events.readPartial", defaultValue: "Event results are incomplete.") + "\n" + error.localizedDescription
            let ticket = readiness.begin(retainingCachedContent: false)
            readiness.complete(.partial, for: ticket)
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

    func receiveIncremental(_ rows: [EventViewModel], epoch: UInt64, warning: String? = nil,
                            saturated: Bool = false) {
        guard canReceiveIncremental, epoch == sourceEpoch, epoch == reader.eventQueryEpoch,
              !reader.eventReadsDeferred, queryLoaded, !isLoading,
              let query, query.acceptsIncremental, !query.isSearch else { return }
        if let warning {
            eventSearchCoverageWarning = warning
            let ticket = readiness.begin(retainingCachedContent: false)
            readiness.complete(.partial, for: ticket)
            return
        }
        // A full live page may have skipped events since the newest row shown,
        // and across categories. Reload this window's own query, filtered in
        // SQL, rather than prepend over a hole that "Load older" cannot reach.
        if saturated {
            retryNeeded = true
            return
        }
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
        guard acceptsBackendReads, !Task.isCancelled else { return [] }
        exactReads.cancel()
        synchronizeSourceEpoch()
        aggregateGeneration &+= 1
        let token = aggregateGeneration
        let epoch = sourceEpoch
        eventAggregateCoverageWarning = nil
        let readyTicket = aggregateReadiness.begin(retainingCachedContent: false)
        defer {
            if token == aggregateGeneration && Task.isCancelled {
                aggregateReadiness.complete(.deferred, for: readyTicket)
            }
        }
        do {
            let key = AuxiliaryReadKey.aggregates(epoch: epoch, sinceDay: sinceDay, category: category)
            let reader = reader
            let value = try await auxiliaryReads.read(key: key,
                cancelExisting: { !$0.mayFinishBefore(key) },
                isCurrent: { [weak self] in
                    self?.aggregateGeneration == token && self?.acceptsEpoch(epoch) == true
                }, operation: { [reader] in
                    .aggregates(try await reader.readEventAggregates(sinceDay: sinceDay, category: category))
                })
            guard case .aggregates(let result) = value else { throw CancellationError() }
            guard token == aggregateGeneration, acceptsEpoch(epoch) else { return [] }
            guard let rows = result else {
                eventAggregateCoverageWarning = String(localized: "events.summariesDeferred", defaultValue: "Daily summaries are temporarily deferred.")
                aggregateReadiness.complete(.deferred, for: readyTicket)
                return []
            }
            eventAggregateCoverageWarning = nil
            aggregateReadiness.complete(rows.isEmpty ? .loadedEmpty : .loadedNonempty, for: readyTicket)
            return rows
        } catch is CancellationError {
            return []
        } catch {
            guard token == aggregateGeneration, acceptsEpoch(epoch) else { return [] }
            eventAggregateCoverageWarning = String(localized: "events.summariesIncomplete", defaultValue: "Daily summary coverage is incomplete.") + "\n" + error.localizedDescription
            aggregateReadiness.complete(.failed, for: readyTicket)
            return []
        }
    }

    func fetchHistogramBins(spanSeconds: TimeInterval, stepSeconds: Int, endingAt: Date,
                            category: MacCrabCore.EventCategory?, isVisible: Bool = true) async -> [(Date, Int)] {
        guard acceptsBackendReads, !Task.isCancelled else { return [] }
        synchronizeSourceEpoch()
        histogramGeneration &+= 1
        let token = histogramGeneration
        let epoch = sourceEpoch
        eventHistogramCoverageWarning = nil
        eventHistogramEffectiveSince = nil
        eventHistogramEffectiveUntil = nil
        // Hiding the chart also invalidates an in-flight read, so its old
        // coverage interval cannot return after the hidden task completes.
        guard isVisible, !reader.eventReadsDeferred else {
            auxiliaryReads.cancel { if case .histogram = $0 { return true }; return false }
            return []
        }
        do {
            let key = AuxiliaryReadKey.histogram(epoch: epoch, span: spanSeconds, step: stepSeconds,
                                                end: endingAt, category: category)
            let reader = reader
            let value = try await auxiliaryReads.read(key: key,
                cancelExisting: { !$0.mayFinishBefore(key) },
                isCurrent: { [weak self] in
                    self?.histogramGeneration == token && self?.acceptsEpoch(epoch) == true
                }, operation: { [reader] in
                    .histogram(try await reader.readEventHistogram(spanSeconds: spanSeconds,
                        stepSeconds: stepSeconds, endingAt: endingAt, category: category))
                })
            guard case .histogram(let result) = value, let result,
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
            eventHistogramCoverageWarning = String(localized: "events.histogramIncomplete", defaultValue: "Histogram coverage is incomplete. Missing intervals are unknown, not zero.") + "\n" + error.localizedDescription
            return []
        }
    }
}
