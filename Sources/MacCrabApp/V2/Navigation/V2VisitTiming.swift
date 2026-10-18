import Foundation
import OSLog

/// Diagnostic intervals for one supported visit in one dashboard window.
/// Not ObservableObject: recording a phase must not invalidate the view graph.
/// There is no history, polling, timer, file output, payload/identity field or
/// performance/health threshold. Callers retain their existing freshness and
/// source guards; this recorder never authorizes publication or an action.
@MainActor
final class V2VisitTiming {
    enum Workspace: String, Sendable { case detection, alerts }
    enum Freshness: String, Sendable { case cached, fresh }
    enum Content: String, Sendable { case empty, nonempty, partial }
    enum Stop: String, CaseIterable, Sendable {
        case superseded, contextChanged, windowInactive, windowClosed
        case readFailed, readDeferred, readUnavailable, cancelled
    }
    enum Terminal: String, Sendable {
        case nativeTableLayout, superseded, contextChanged, windowInactive, windowClosed
        case readFailed, readDeferred, readUnavailable, cancelled, invalidClock
    }
    struct Ticket: Equatable, Sendable {
        fileprivate let id: UUID
    }
    /// Private correlation only. Neither UUID is ever included in a summary.
    /// The table revision covers its exact immutable inputs (including local
    /// filters/selection); the model revision rejects obsolete publications.
    struct AcceptedInput: Equatable, Sendable {
        let tableRevision: UUID
        let modelRevision: UUID
        let freshness: Freshness
        let content: Content
    }
    struct Summary: Equatable, Sendable {
        let workspace: Workspace
        let terminal: Terminal
        let freshness: Freshness?
        let content: Content?
        let providerReadyNS: UInt64?
        let readAcceptedNS: UInt64?
        let nativeTableLayoutNS: UInt64?
        let elapsedNS: UInt64?

        /// Only fixed enum values and navigation-relative integers may escape.
        /// Missing observations remain null, never zero or inferred success.
        var logLine: String {
            func number(_ value: UInt64?) -> String { value.map { String($0) } ?? "null" }
            return "ui_visit_timing.v1 workspace=\(workspace.rawValue) terminal=\(terminal.rawValue)"
                + " freshness=\(freshness?.rawValue ?? "null") content=\(content?.rawValue ?? "null")"
                + " navigation_accepted_ns=0 provider_ready_ns=\(number(providerReadyNS))"
                + " read_accepted_ns=\(number(readAcceptedNS)) native_table_layout_ns=\(number(nativeTableLayoutNS))"
                + " elapsed_ns=\(number(elapsedNS))"
        }
    }
    private struct Visit {
        let ticket: Ticket
        let workspace: Workspace
        let start: UInt64
        var lastObserved: UInt64
        var providerReady: UInt64?
        var readAccepted: UInt64?
        var acceptedInput: AcceptedInput?
    }
    private static let logger = Logger(subsystem: "com.maccrab.app", category: "ui-visit-timing")
    private let now: @MainActor () -> UInt64
    private let emit: @MainActor (Summary) -> Void
    private var visit: Visit?

    init(now: @escaping @MainActor () -> UInt64 = { DispatchTime.now().uptimeNanoseconds },
         emit: (@MainActor (Summary) -> Void)? = nil) {
        self.now = now
        self.emit = emit ?? { summary in
            Self.logger.info("\(summary.logLine, privacy: .public)")
        }
    }

    /// Called only when the app accepts a supported navigation/startup visit,
    /// not by the five-second refresh loop or by a SwiftUI body evaluation.
    @discardableResult
    func begin(_ workspace: Workspace) -> Ticket {
        let instant = now()
        let prior = visit
        let ticket = Ticket(id: UUID())
        visit = Visit(ticket: ticket, workspace: workspace, start: instant, lastObserved: instant)
        if let prior {
            emit(summary(prior, terminal: .superseded, at: instant))
        }
        return ticket
    }

    /// After a terminal summary, ordinary refreshes have no ticket to record.
    func currentTicket(for workspace: Workspace) -> Ticket? {
        visit?.workspace == workspace ? visit?.ticket : nil
    }

    @discardableResult
    func providerReady(for ticket: Ticket) -> Bool {
        guard var current = visit, current.ticket == ticket,
              current.providerReady == nil, current.readAccepted == nil else { return false }
        guard let elapsed = observeTime(&current) else { return false }
        current.providerReady = elapsed
        visit = current
        return true
    }

    /// The first accepted display snapshot for this visit. Cached content is
    /// explicitly distinguished from a fresh read; later polls cannot rewrite
    /// its origin. Empty means accepted empty content, not an invented row.
    @discardableResult
    func readAccepted(_ input: AcceptedInput, for ticket: Ticket) -> Bool {
        guard var current = visit, current.ticket == ticket else { return false }
        if let accepted = current.acceptedInput {
            // A replacement is not a continuation of the old snapshot's
            // timeline. Never reset its clock or complete it from new inputs.
            if accepted != input { _ = stop(.contextChanged, for: ticket) }
            return false
        }
        guard let elapsed = observeTime(&current) else { return false }
        current.readAccepted = elapsed
        current.acceptedInput = input
        visit = current
        return true
    }

    /// Invoke only after a guarded current read returns. In particular, an
    /// offline placeholder before provider adoption is not a failed read.
    /// Retained snapshots may still supply explicitly cached host layout.
    @discardableResult
    func readFinishedWithoutSnapshot(phase: UIContentReadiness.Phase, hasSnapshot: Bool,
                                     observedLiveRead: Bool, for ticket: Ticket) -> Bool {
        guard observedLiveRead, !hasSnapshot else { return false }
        switch phase {
        case .failed: return stop(.readFailed, for: ticket)
        case .deferred: return stop(.readDeferred, for: ticket)
        case .unavailable: return stop(.readUnavailable, for: ticket)
        default: return false
        }
    }

    /// Caller must have observed a native table HOST layout under the current
    /// attachment lease and a positive viewport after installing accepted data.
    /// This is not row realization, pixel visibility, first paint or freshness
    /// verification; the fixed terminal name intentionally says only layout.
    @discardableResult
    func nativeTableDidLayout(_ input: AcceptedInput, for ticket: Ticket,
                             activeAttachment: Bool, positiveViewport: Bool) -> Bool {
        guard activeAttachment, positiveViewport, var current = visit,
              current.ticket == ticket, current.readAccepted != nil,
              current.acceptedInput == input else { return false }
        guard let elapsed = observeTime(&current) else { return false }
        visit = nil
        emit(Summary(workspace: current.workspace, terminal: .nativeTableLayout,
                     freshness: input.freshness, content: input.content,
                     providerReadyNS: current.providerReady, readAcceptedNS: current.readAccepted,
                     nativeTableLayoutNS: elapsed, elapsedNS: elapsed))
        return true
    }

    @discardableResult
    func stop(_ reason: Stop, for ticket: Ticket) -> Bool {
        guard let current = visit, current.ticket == ticket else { return false }
        visit = nil
        // Stop and Terminal deliberately use the same fixed spelling.
        let terminal: Terminal
        switch reason {
        case .superseded: terminal = .superseded
        case .contextChanged: terminal = .contextChanged
        case .windowInactive: terminal = .windowInactive
        case .windowClosed: terminal = .windowClosed
        case .readFailed: terminal = .readFailed
        case .readDeferred: terminal = .readDeferred
        case .readUnavailable: terminal = .readUnavailable
        case .cancelled: terminal = .cancelled
        }
        emit(summary(current, terminal: terminal, at: now()))
        return true
    }

    private func observeTime(_ current: inout Visit) -> UInt64? {
        let instant = now()
        guard instant >= current.lastObserved else {
            visit = nil
            emit(summary(current, terminal: .invalidClock, at: instant))
            return nil
        }
        current.lastObserved = instant
        return instant - current.start
    }

    private func summary(_ current: Visit, terminal: Terminal, at instant: UInt64) -> Summary {
        let valid = instant >= current.lastObserved
        return Summary(workspace: current.workspace, terminal: valid ? terminal : .invalidClock,
                       freshness: current.acceptedInput?.freshness, content: current.acceptedInput?.content,
                       providerReadyNS: current.providerReady, readAcceptedNS: current.readAccepted,
                       nativeTableLayoutNS: nil, elapsedNS: valid ? instant - current.start : nil)
    }
}
