import Foundation
import Combine
import MacCrabCore

/// The query population, not local severity/search presentation. Exact source
/// and engine birth identity prevent a previous provider's rows flashing while
/// SwiftUI has not yet started the replacement .task.
struct V2AlertsPresentationContext: Hashable {
    struct Engine: Hashable {
        let pid: Int
        let startedAtUnix: Double
        let version: String
        let build: String

        init(_ identity: EngineTelemetryIdentity) {
            pid = identity.pid
            startedAtUnix = identity.startedAtUnix
            version = identity.version
            build = identity.build
        }
    }

    let query: V2AlertsLoadContext
    let directory: String?
    let engine: Engine?

    var fetchLimit: Int {
        query.windowStart != nil || query.timeRange == "24h" || query.timeRange == "7d" ? 200 : 1000
    }

    func lowerBound(now: Date) -> Date {
        if let start = query.windowStart { return start }
        switch query.timeRange {
        case "24h": return now.addingTimeInterval(-86_400)
        case "7d": return now.addingTimeInterval(-7 * 86_400)
        case "30d": return now.addingTimeInterval(-30 * 86_400)
        default: return .distantPast
        }
    }
}

/// One window-owned value snapshot; no view, database handle or read transaction
/// survives navigation. The hidden-cache limits account string UTF-8 bytes, NOT
/// Swift heap usage. An oversized successful response remains visible while
/// active, but is not retained across pause/disappearance.
@MainActor
final class V2AlertsPresentationModel: ObservableObject {
    static let maximumRows = 1000
    static let maximumRetainedStringBytes = 4 * 1024 * 1024

    @Published private(set) var context: V2AlertsPresentationContext?
    @Published private(set) var rows: [V2MockAlert] = []
    @Published private(set) var hasSnapshot = false
    @Published private(set) var isFresh = false
    @Published private(set) var error: String?
    @Published private(set) var readiness = UIContentReadiness(workspace: .alerts)
    private let mismatchedReadiness = UIContentReadiness(workspace: .alerts)
    private var retainable = false
    private var current: UUID?
    private var task: Task<Void, Never>?

    func rows(for expected: V2AlertsPresentationContext) -> [V2MockAlert] {
        context == expected ? rows : []
    }

    func hasSnapshot(for expected: V2AlertsPresentationContext) -> Bool {
        context == expected && hasSnapshot
    }

    func isFresh(for expected: V2AlertsPresentationContext) -> Bool {
        context == expected && isFresh
    }

    func error(for expected: V2AlertsPresentationContext) -> String? {
        context == expected ? error : nil
    }

    func readiness(for expected: V2AlertsPresentationContext) -> UIContentReadiness {
        context == expected ? readiness : mismatchedReadiness
    }

    /// Same-context poll ticks join the current read, even when it takes longer
    /// than a polling interval. Only true context supersession cancels it.
    func refresh(
        context expected: V2AlertsPresentationContext,
        now: Date = Date(),
        isCurrent: @escaping @MainActor () -> Bool,
        fetch: @escaping @MainActor (Date, Int) async -> V2AlertsReadSnapshot
    ) async {
        guard !Task.isCancelled, isCurrent() else { return }
        // Retain the occupied flight until a non-cooperative provider actually
        // returns. A navigation storm cannot enqueue additional backend reads.
        // Only the latest still-current consumer may start after that join.
        while let predecessor = task, predecessor.isCancelled || context != expected {
            predecessor.cancel()
            await predecessor.value
            guard !Task.isCancelled, isCurrent() else { return }
        }
        if let task {
            await task.value
            return
        }
        if context != expected {
            rows = []
            hasSnapshot = false
            retainable = false
            error = nil
        }
        context = expected
        isFresh = false
        let identifier = UUID()
        current = identifier
        let marker = readiness.begin(retainingCachedContent: hasSnapshot)
        let lowerBound = expected.lowerBound(now: now)
        let next = Task { @MainActor [weak self] in
            defer {
                if self?.current == identifier {
                    self?.current = nil
                    self?.task = nil
                }
            }
            guard !Task.isCancelled, isCurrent(), self?.current == identifier else { return }
            let result = await fetch(lowerBound, expected.fetchLimit)
            guard !Task.isCancelled, isCurrent(), let self,
                  self.current == identifier, self.context == expected else { return }
            switch result {
            case .success(let resultRows):
                // Never silently truncate an out-of-contract response into a
                // seemingly complete/empty successful snapshot.
                guard resultRows.count <= expected.fetchLimit,
                      resultRows.count <= Self.maximumRows else {
                    self.error = "Alert response exceeded the requested row limit. Cached rows are not current."
                    self.readiness.complete(.failed, for: marker)
                    return
                }
                self.rows = resultRows.filter { alert in
                    alert.timestamp >= lowerBound
                        && (expected.query.windowEnd.map { alert.timestamp <= $0 } ?? true)
                }
                self.hasSnapshot = true
                self.isFresh = true
                self.error = nil
                self.retainable = Self.fitsRetentionBudget(self.rows)
                self.readiness.complete(self.rows.isEmpty ? .loadedEmpty : .loadedNonempty, for: marker)
            case .failed(let detail):
                self.error = detail
                self.readiness.complete(.failed, for: marker)
            case .cancelled:
                self.readiness.complete(.unavailable, for: marker)
            }
        }
        task = next
        await next.value
    }

    /// Kept snapshots are explicitly stale. An unknown source/engine identity
    /// cannot justify reuse after a navigation or foreground boundary.
    func pause() {
        task?.cancel()
        // The running task owns clearing its slot after the backend unwinds.
        isFresh = false
        readiness.invalidate()
        if !retainable || context?.directory == nil || context?.engine == nil {
            rows = []
            hasSnapshot = false
            retainable = false
        }
    }

    private static func fitsRetentionBudget(_ rows: [V2MockAlert]) -> Bool {
        guard rows.count <= maximumRows else { return false }
        var bytes = 0
        func add(_ value: String) -> Bool {
            let count = value.utf8.count
            guard count <= maximumRetainedStringBytes - bytes else { return false }
            bytes += count
            return true
        }
        for row in rows {
            let required = [row.id, row.title, row.ruleId, row.process, row.processPath,
                            row.parent, row.user, row.aiTool, row.workingDirectory,
                            row.processSHA256, row.hostName, row.triggeringEventsJson,
                            row.category, row.description]
            for value in required { if !add(value) { return false } }
            let optional = [row.remediationHint, row.llmVerdict, row.llmSummary,
                            row.llmModel, row.analystNote, row.analystOwner,
                            row.analystStatus, row.analystTicketRef]
            for value in optional { if let value, !add(value) { return false } }
            for group in [row.mitre, row.actionsTaken, row.d3fendTechniques, row.llmSuggestedActions] {
                for value in group { if !add(value) { return false } }
            }
        }
        return true
    }
}
