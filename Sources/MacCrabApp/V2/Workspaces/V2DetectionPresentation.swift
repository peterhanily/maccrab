import Combine
import Foundation

/// A result belongs to this invocation, unlike a provider-global error slot.
enum V2DetectionRulesRead: Sendable {
    case success([V2MockRule])
    case failed
    case cancelled

    var rows: [V2MockRule] {
        if case .success(let rows) = self { return rows }
        return []
    }
}

@MainActor
protocol V2DetectionRuleReading: AnyObject {
    func detectionRulesSnapshot() async -> V2DetectionRulesRead
}

/// Owned by one dashboard window, not by the conditional workspace View.
/// One completed snapshot, one filtered result and one refresh flight only.
/// Bounds account for retained field/search bytes, not an allocator/RSS claim.
@MainActor
final class V2DetectionPresentation: ObservableObject {
    struct Identity: Equatable {
        let provider: ObjectIdentifier
        let directory: String
        let epoch: UInt64
    }
    enum Phase: Equatable { case unavailable, loading, cached, refreshingCached, ready, failed }
    nonisolated static let maximumRows = 20_000
    nonisolated static let maximumAccountedBytes = 16 * 1_024 * 1_024

    @Published private(set) var phase: Phase = .unavailable
    @Published private(set) var revision = UUID()
    @Published private(set) var readiness = UIContentReadiness(workspace: .detection)
    private let unavailableReadiness = UIContentReadiness(workspace: .detection)
    private var identity: Identity?
    private var snapshot: V2DetectionRuleSnapshot?
    @Published private var filtered: [V2MockRule] = []
    private var filteredQuery: String?
    private var filteredRevision: UUID?
    private var request = UUID()
    private var filterRequest = UUID()
    private var presented = false
    private var completedAt: Date?
    private var requestedQuery = ""
    private var readinessTicket: UIContentReadiness.Ticket?
    private struct Flight {
        let id: UUID
        let identity: Identity
        let task: Task<Prepared, Never>
    }
    private enum Prepared: Sendable {
        case success(V2DetectionRuleSnapshot)
        case failed
        case cancelled
    }
    private var flight: Flight?
    private let onJoin: (() -> Void)?

    init(onJoin: (() -> Void)? = nil) { self.onJoin = onJoin }

    static func normalizedQuery(_ value: String) -> String {
        value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    func snapshot(for key: Identity) -> V2DetectionRuleSnapshot? {
        identity == key ? snapshot : nil
    }

    func rows(for key: Identity, query: String) -> [V2MockRule] {
        guard identity == key, let snapshot else { return [] }
        let normalized = Self.normalizedQuery(query)
        if normalized.isEmpty { return snapshot.rules }
        guard filteredQuery == normalized, filteredRevision == revision else { return [] }
        return filtered
    }

    func hasFilteredResult(for key: Identity, query: String) -> Bool {
        guard identity == key, snapshot != nil else { return false }
        let normalized = Self.normalizedQuery(query)
        return normalized.isEmpty || (filteredQuery == normalized && filteredRevision == revision)
    }

    func isCurrent(for key: Identity, now: Date = Date()) -> Bool {
        guard identity == key, presented, phase == .ready, let completedAt else { return false }
        let age = now.timeIntervalSince(completedAt)
        return age >= 0 && age <= 120
    }

    func readiness(for key: Identity, query: String) -> UIContentReadiness {
        guard identity == key, requestedQuery == Self.normalizedQuery(query) else { return unavailableReadiness }
        if phase == .ready {
            guard isCurrent(for: key) else { return unavailableReadiness }
            if !hasFilteredResult(for: key, query: query), readiness.phase.isFreshCompletion {
                return unavailableReadiness
            }
        }
        return readiness
    }

    func status(for key: Identity, query: String = "") -> String {
        guard identity == key else { return "Rule list unavailable until this source is read." }
        switch phase {
        case .unavailable: return "Rule list unavailable. No detection-health conclusion can be drawn."
        case .loading: return "Loading the rule list…"
        case .cached: return "Cached rule snapshot. Current status has not been refreshed."
        case .refreshingCached: return "Showing a cached rule snapshot while current status refreshes."
        case .failed:
            return snapshot == nil
                ? "Rule refresh failed or exceeded the display budget. No complete rule list is available."
                : "Rule refresh failed or exceeded the display budget. The displayed snapshot is cached, not current."
        case .ready:
            if !isCurrent(for: key) { return "Cached rule snapshot. Current status needs another refresh." }
            if !hasFilteredResult(for: key, query: query) { return "Filtering the refreshed rule snapshot…" }
            return snapshot?.rules.isEmpty == true
                ? "The rule read returned no rows. This is not a healthy-detection or all-clear result."
                : "Rule list refreshed. Detection coverage is reported separately."
        }
    }

    func leave() {
        presented = false
        request = UUID()
        filterRequest = UUID()
        flight?.task.cancel()
        // Never retain a successful empty read as a later reassuring empty UI.
        if snapshot?.rules.isEmpty == true { snapshot = nil; filtered = []; filteredQuery = nil }
        phase = snapshot == nil ? .unavailable : .cached
        readiness.invalidate()
        readinessTicket = nil
    }

    func refresh(identity key: Identity, query: String, provider: any V2DataProvider) async {
        await refresh(identity: key, query: query, directory: provider.dataDir) {
            if let reader = provider as? any V2DetectionRuleReading {
                return await reader.detectionRulesSnapshot()
            }
            // Only explicitly labelled DEBUG fixtures may use the legacy API.
            // An offline/unknown live provider's [] is not a certified read.
            guard provider.mode == .mock else { return .failed }
            let rows = await provider.rules()
            return Task.isCancelled ? .cancelled : .success(rows)
        }
    }

    func refresh(identity key: Identity, query: String = "", directory: String? = nil,
                 operation: @escaping @MainActor () async -> V2DetectionRulesRead) async {
        guard !Task.isCancelled else { return }
        if identity != key {
            flight?.task.cancel()
            identity = key
            snapshot = nil
            filtered = []
            filteredQuery = nil
            filteredRevision = nil
            completedAt = nil
            revision = UUID()
            filterRequest = UUID()
        }
        presented = true
        let normalized = Self.normalizedQuery(query)
        let queryChanged = requestedQuery != normalized
        requestedQuery = normalized
        if queryChanged { filterRequest = UUID() }
        let token = UUID()
        request = token
        phase = snapshot == nil ? .loading : .refreshingCached
        if flight == nil || flight?.identity != key || queryChanged || readinessTicket == nil {
            readinessTicket = readiness.begin(retainingCachedContent: hasFilteredResult(for: key, query: query))
        }
        while let active = flight {
            onJoin?()
            let result = await active.task.value
            if flight?.id == active.id { flight = nil }
            guard !Task.isCancelled, presented, request == token, identity == key else { return }
            if active.identity == key, !active.task.isCancelled {
                publish(result, key: key)
                return
            }
        }
        let previous = snapshot
        let task = Task { @MainActor in
            let result = await operation()
            guard !Task.isCancelled else { return Prepared.cancelled }
            switch result {
            case .cancelled: return .cancelled
            case .failed: return .failed
            case .success(let rows):
                return await Task.detached(priority: .userInitiated) {
                    guard let prepared = Self.prepare(rows, previous: previous, directory: directory) else { return Prepared.failed }
                    return Prepared.success(prepared)
                }.value
            }
        }
        let active = Flight(id: UUID(), identity: key, task: task)
        flight = active
        let result = await task.value
        if flight?.id == active.id { flight = nil }
        guard !Task.isCancelled, !task.isCancelled, presented, request == token, identity == key else { return }
        publish(result, key: key)
    }

    private func publish(_ result: Prepared, key: Identity) {
        switch result {
        case .cancelled:
            phase = snapshot == nil ? .unavailable : .cached
            if let ticket = readinessTicket { _ = readiness.complete(.unavailable, for: ticket) }
            readinessTicket = nil
        case .failed:
            phase = .failed
            if let ticket = readinessTicket { _ = readiness.complete(.failed, for: ticket) }
            readinessTicket = nil
        case .success(let value):
            // A telemetry-only refresh changes row counters, not search
            // membership. Rebase the accepted filter to the new row values
            // without blanking/debouncing the visible table every poll.
            let reuseFilter = filteredRevision == revision && filteredQuery != nil
                && snapshot?.haystack == value.haystack
            let selectedIDs = reuseFilter ? Set(filtered.map(\.id)) : []
            snapshot = value
            revision = UUID()
            if reuseFilter {
                filtered = value.rules.filter { selectedIDs.contains($0.id) }
                filteredRevision = revision
            } else { filteredRevision = nil }
            filterRequest = UUID()
            completedAt = Date()
            phase = .ready
            completeDisplayedReadiness(key: key)
        }
    }

    private func completeDisplayedReadiness(key: Identity) {
        guard phase == .ready, hasFilteredResult(for: key, query: requestedQuery),
              let ticket = readinessTicket else { return }
        _ = readiness.complete(rows(for: key, query: requestedQuery).isEmpty ? .loadedEmpty : .loadedNonempty,
                               for: ticket)
        readinessTicket = nil
    }

    func filter(identity key: Identity, query: String, debounce: Bool = true) async {
        guard !Task.isCancelled, identity == key, presented, let snapshot else { return }
        let normalized = Self.normalizedQuery(query)
        if requestedQuery != normalized {
            requestedQuery = normalized
            filterRequest = UUID()
            readinessTicket = readiness.begin(retainingCachedContent: hasFilteredResult(for: key, query: query))
            if phase == .failed, let ticket = readinessTicket {
                _ = readiness.complete(.failed, for: ticket)
                readinessTicket = nil
            } else if (phase == .cached || phase == .unavailable), let ticket = readinessTicket {
                _ = readiness.complete(.unavailable, for: ticket)
                readinessTicket = nil
            }
        }
        if hasFilteredResult(for: key, query: normalized) {
            completeDisplayedReadiness(key: key)
            return
        }
        if readinessTicket == nil, phase == .ready || phase == .loading || phase == .refreshingCached {
            readinessTicket = readiness.begin(retainingCachedContent: false)
        }
        let token = UUID(), sourceRevision = revision
        filterRequest = token
        if debounce {
            do { try await Task.sleep(for: .milliseconds(200)) } catch { return }
        }
        guard !Task.isCancelled, filterRequest == token else { return }
        let rows = await Task.detached(priority: .userInitiated) {
            snapshot.rules.filter { (snapshot.haystack[$0.id] ?? "").contains(normalized) }
        }.value
        guard !Task.isCancelled, presented, identity == key, revision == sourceRevision,
              filterRequest == token else { return }
        filteredQuery = normalized
        filteredRevision = sourceRevision
        filtered = rows
        completeDisplayedReadiness(key: key)
    }

    /// Bounded display-only admission. No rule is silently dropped to fit.
    nonisolated static func prepare(_ rows: [V2MockRule], previous: V2DetectionRuleSnapshot?,
                                    directory: String?) -> V2DetectionRuleSnapshot? {
        guard rows.count <= maximumRows else { return nil }
        var charged = 0
        func add(_ bytes: Int) -> Bool {
            let next = charged.addingReportingOverflow(bytes)
            guard bytes >= 0, !next.overflow, next.partialValue <= maximumAccountedBytes else { return false }
            charged = next.partialValue
            return true
        }
        for row in rows {
            guard add(256) else { return nil }
            for value in [row.id, row.title, row.category, row.description, row.status ?? "", row.severityOverrideRaw ?? ""] + row.mitre {
                guard add(value.utf8.count) else { return nil }
            }
        }
        let reusable = previous.map { old in
            old.rules.count == rows.count && zip(old.rules, rows).allSatisfy { left, right in
                left.id == right.id && left.title == right.title && left.category == right.category
                    && left.description == right.description && left.mitre == right.mitre
            }
        } ?? false
        let haystack = reusable ? previous!.haystack : Dictionary(
            rows.map { ($0.id, V2DetectionWorkspace.ruleSearchHaystack(for: $0)) }, uniquingKeysWith: { first, _ in first })
        let labels = reusable ? previous!.compositeLabels : Dictionary(
            rows.filter { $0.category == "Sequence" || $0.category == "Graph" }.map { ($0.id.lowercased(), $0.title) },
            uniquingKeysWith: { _, last in last })
        let disabled = directory.map { V2DetectionRuleSnapshot.disabledIDs(in: $0 + "/user_rules") } ?? []
        for (key, value) in haystack { guard add(key.utf8.count), add(value.utf8.count) else { return nil } }
        for (key, value) in labels { guard add(key.utf8.count), add(value.utf8.count) else { return nil } }
        for key in disabled { guard add(key.utf8.count) else { return nil } }
        return .init(rules: rows, haystack: haystack, compositeLabels: labels, disabledOverrideIDs: disabled)
    }
}
