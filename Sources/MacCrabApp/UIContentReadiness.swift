import Foundation

/// Presentation-only readiness, not a detection-health or render-completion
/// receipt. Keep this value with the window's bounded presentation model.
/// Callers must still check their provider/source/query context before publishing.
/// No private input, record identity, count, timestamp or error text is retained.
struct UIContentReadiness: Equatable, Sendable {
    enum Workspace: String, CaseIterable, Sendable {
        case events, alerts, detection
    }

    enum Phase: String, CaseIterable, Hashable, Sendable {
        case loading
        case refreshingCached = "refreshing_cached"
        case loadedNonempty = "loaded_nonempty"
        case loadedEmpty = "loaded_empty"
        case partial
        case deferred
        case unavailable
        case failed

        /// Only a successful current read may establish a fresh presentation.
        /// In particular, cached/partial/failed/deferred never imply all-clear.
        var isFreshCompletion: Bool {
            self == .loadedNonempty || self == .loadedEmpty
        }

        /// Fixed copy only: never pass through query, provider or error strings.
        var displayText: String {
            switch self {
            case .loading: return "Loading content"
            case .refreshingCached: return "Refreshing cached content"
            case .loadedNonempty: return "Content loaded"
            case .loadedEmpty: return "No matching content"
            case .partial: return "Partial content"
            case .deferred: return "Waiting for engine"
            case .unavailable: return "Content unavailable"
            case .failed: return "Content read failed"
            }
        }
    }

    enum Completion: CaseIterable, Sendable {
        case loadedNonempty, loadedEmpty, partial, deferred, unavailable, failed

        fileprivate var phase: Phase {
            switch self {
            case .loadedNonempty: return .loadedNonempty
            case .loadedEmpty: return .loadedEmpty
            case .partial: return .partial
            case .deferred: return .deferred
            case .unavailable: return .unavailable
            case .failed: return .failed
            }
        }
    }

    struct Ticket: Equatable, Sendable {
        fileprivate let generation: UUID
    }

    let workspace: Workspace
    private(set) var generation = UUID()
    private(set) var phase: Phase = .unavailable
    private var activeTicket: Ticket?

    init(workspace: Workspace) {
        self.workspace = workspace
    }

    /// Start on genuine presentation supersession/refresh, not on every poll
    /// tick while a read is already active. Cached content must match the
    /// caller's source, epoch and complete presentation key before this call.
    @discardableResult
    mutating func begin(retainingCachedContent: Bool) -> Ticket {
        generation = UUID()
        phase = retainingCachedContent ? .refreshingCached : .loading
        let ticket = Ticket(generation: generation)
        activeTicket = ticket
        return ticket
    }

    /// Publish only after the current result has been applied to the displayed
    /// presentation. Stale/cancelled callers must not manufacture loaded-empty.
    /// A failed read with retained rows uses .failed plus the page's explicit
    /// cached-content label; the marker never labels retained rows fresh.
    @discardableResult
    mutating func complete(_ completion: Completion, for ticket: Ticket) -> Bool {
        guard activeTicket == ticket, generation == ticket.generation else { return false }
        phase = completion.phase
        activeTicket = nil
        return true
    }

    /// Source/filter retirement cancels publication without claiming success.
    /// Rotating the opaque token makes previously observed markers obsolete.
    mutating func invalidate() {
        generation = UUID()
        phase = .unavailable
        activeTicket = nil
    }

    /// Project a successful read onto the final displayed/filter result. This
    /// is a value copy: it neither publishes the model nor reopens its ticket.
    /// Never turn partial, cached, deferred or failed data into fresh empty.
    func forDisplayedContent(isEmpty: Bool) -> UIContentReadiness {
        guard phase.isFreshCompletion else { return self }
        var displayed = self
        displayed.phase = isEmpty ? .loadedEmpty : .loadedNonempty
        return displayed
    }

    /// Versioned, bounded machine contract. All fields are fixed enum values
    /// except the random token; none are derived from records or private inputs.
    var accessibilityIdentifier: String {
        "maccrab.content.v1.\(workspace.rawValue).\(generation.uuidString.lowercased()).\(phase.rawValue)"
    }
}
