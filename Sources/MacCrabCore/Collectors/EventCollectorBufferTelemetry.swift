import Foundation
import os

/// The two final detection lanes. This classifier is shared by collector-side
/// buffers and the downstream merger so a dropped OLD event is attributed with
/// the same rule it would have used had it survived to `DaemonState`.
public enum EventPipelineLane: Int, CaseIterable, Sendable, Hashable {
    case priority
    case file

    public var key: String {
        switch self {
        case .priority: return "priority"
        case .file: return "file"
        }
    }

    /// Enrichment key the ES worker stamps on an `open` that was admitted by
    /// the dynamic-AI demand policy alone (an attributed agent's ordinary text
    /// read) rather than by the static credential / agent-content allowlists.
    /// Only that class of OPEN is a flood source, so only it rides the file
    /// lane (see `finalLane(for:)`).
    public static let openAdmissionEnrichmentKey = "open_admission"
    /// The value for a dynamic-AI-admitted OPEN.
    public static let dynamicAIOpenAdmission = "dynamic_ai"

    /// The type-level rule: the file family rides the file lane except the
    /// two rare, high-value `.file` actions a write flood must never evict —
    /// `open` (credential / honeyfile / agent-content reads, which the
    /// single-event credential rules, the wall-clock sequence windows and
    /// the injection-evidence weld all need in order and persisted) and
    /// `btm_add` (the only sensor for a ghost login item). A dynamic-AI OPEN,
    /// or a protected OPEN past the ES worker's budget, rides the file lane
    /// instead, and a protected file event the worker admitted rides the
    /// priority lane; both are decided per event in `finalLane(for:)`.
    public static func routesToFile(_ category: EventCategory, action: String) -> Bool {
        guard category == .file else { return false }
        switch action {
        case "open", "btm_add": return false
        default: return true
        }
    }

    /// Enrichment key the ES worker stamps on a protected event: admitted to
    /// the priority lane, or (for an OPEN, which otherwise keeps it) refused.
    public static let protectedFileLaneEnrichmentKey = "protected_file_lane"
    /// The value for a protected file event admitted to the priority lane.
    public static let protectedFileLanePriority = "priority"
    /// The value for a protected OPEN the worker's budget refused.
    public static let protectedFileLaneFile = "file"

    /// Persistence locations, anchored where launchd, sudo, cron and the
    /// shells read them. The file lane evicts its oldest events under
    /// overload, and an agent could read a few thousand files to push its own
    /// LaunchAgent write out of the lane before it was evaluated. Anchoring
    /// matters for the budget: writes to a path that merely contains a marker
    /// (`/tmp/LaunchAgents/x`, `/tmp/a/.zshrc`) cost nothing and would drain
    /// it ahead of a real plist write.
    private static let persistencePrefixes = [
        "/Library/LaunchAgents/", "/Library/LaunchDaemons/", "/Library/StartupItems/",
        "/Library/Security/SecurityAgentPlugins/", "/Library/ScriptingAdditions/",
        "/etc/sudoers", "/private/etc/sudoers", "/usr/lib/cron/tabs/", "/var/at/tabs/",
        "/private/var/at/tabs/",
    ]
    private static let homePersistencePrefixes = [
        "/Library/LaunchAgents/", "/Library/LaunchDaemons/", "/Library/ScriptingAdditions/",
    ]
    private static let homePersistenceFiles: Set<String> = [
        "/.ssh/authorized_keys", "/.zshrc", "/.zshenv", "/.zprofile", "/.bashrc",
        "/.bash_profile", "/.profile",
    ]

    static func isPersistenceLocation(_ path: String) -> Bool {
        if persistencePrefixes.contains(where: { path.hasPrefix($0) }) { return true }
        guard let inHome = homeRelativePath(path) else { return false }
        return homePersistencePrefixes.contains { inHome.hasPrefix($0) }
            || homePersistenceFiles.contains(String(inHome))
    }

    /// The part of `path` inside a user's home (`/Users/<name>`) or root's,
    /// starting with its `/`; nil for any other path.
    private static func homeRelativePath(_ path: String) -> Substring? {
        for root in ["/private/var/root/", "/var/root/"] where path.hasPrefix(root) {
            return path.dropFirst(root.count - 1)
        }
        guard path.hasPrefix("/Users/") else { return nil }
        let afterUsers = path.dropFirst("/Users/".count)
        guard let slash = afterUsers.firstIndex(of: "/"), slash != afterUsers.startIndex else { return nil }
        return afterUsers[slash...]
    }

    /// An event the ES worker admits to the priority lane only through
    /// `ProtectedFileLaneBudget`:
    /// - a SETMODE (the callback keeps only mode changes that grant execution
    ///   or setuid/setgid, the `chmod +x` of a dropped payload);
    /// - any file event at a persistence location;
    /// - a credential / honeyfile / agent-content OPEN (one the static
    ///   allowlists admitted, so not stamped dynamic-AI).
    /// All are rare next to bulk file traffic, but unprivileged code can raise
    /// any of them at syscall rate on its own files, and the priority lane is
    /// a drop-oldest buffer that also carries exec/fork/exit.
    public static func isProtectedFileCandidate(_ event: Event) -> Bool {
        guard event.eventCategory == .file else { return false }
        if event.eventAction == "open" {
            return event.enrichments[openAdmissionEnrichmentKey] != dynamicAIOpenAdmission
        }
        guard routesToFile(event.eventCategory, action: event.eventAction) else { return false }
        if event.eventAction == "setmode" { return true }
        guard let path = event.file?.path else { return false }
        return isPersistenceLocation(path)
    }

    /// Spends one budget token on a protected event and stamps its lane: nil
    /// for an event that is not a candidate, true when it was admitted to the
    /// priority lane, false when the budget refused it. A refused OPEN is
    /// stamped for the file lane; any other refused event already rides it.
    /// OPENs spend their own budget: an `open()` loop on the caller's own
    /// `.env` must not use up the tokens a real LaunchAgent write needs.
    static func stampProtectedLane(
        _ event: inout Event,
        budget: ProtectedFileLaneBudget,
        openBudget: ProtectedFileLaneBudget,
        nowNanos: UInt64
    ) -> Bool? {
        guard isProtectedFileCandidate(event) else { return nil }
        let isOpen = event.eventAction == "open"
        if (isOpen ? openBudget : budget).admit(nowNanos: nowNanos) {
            event.enrichments[protectedFileLaneEnrichmentKey] = protectedFileLanePriority
            return true
        }
        if isOpen {
            event.enrichments[protectedFileLaneEnrichmentKey] = protectedFileLaneFile
        }
        return false
    }

    /// The per-event lane. v1.22.7: an `open` stamped
    /// `open_admission = dynamic_ai` rides the FILE lane. Measured on the
    /// maintainer's host (attempt4 capture): 47,931 admitted dynamic-AI OPENs
    /// in one 30 s esbuild burst backlogged the priority lane to 76,684 and
    /// evicted exec/fork/exit — the one loss nothing downstream can
    /// reconstruct. Every other `open` (the static credential / agent-content
    /// allowlists, and any non-ES producer) keeps the priority lane, which is
    /// near-empty once that flood and NOTIFY_SIGNAL are off it: the ambient
    /// 74-minute sample had the file lane evicting 68% of its offers against
    /// 21% on priority, and the sequence engine measures its windows in
    /// wall-clock processing time, so a credential OPEN must not trail its
    /// exec by a lane backlog.
    public static func finalLane(for event: Event) -> EventPipelineLane {
        if event.eventCategory == .file, event.eventAction == "open",
           event.enrichments[openAdmissionEnrichmentKey] == dynamicAIOpenAdmission
            || event.enrichments[protectedFileLaneEnrichmentKey] == protectedFileLaneFile {
            return .file
        }
        guard routesToFile(event.eventCategory, action: event.eventAction) else {
            return .priority
        }
        if event.enrichments[protectedFileLaneEnrichmentKey] == protectedFileLanePriority {
            return .priority
        }
        return .file
    }
}

/// How many protected events (`EventPipelineLane.isProtectedFileCandidate`)
/// one ES worker may put on the priority lane: a token bucket of `capacity`
/// refilled at `refillPerSecond`. The priority lane is a drop-oldest buffer
/// that also carries exec/fork/exit, and a `chmod 755` loop, a write loop on
/// the caller's own `~/.zshrc` or an `open()` loop on its own `.env` costs
/// nothing to run, so an unbounded class would let it evict lineage. Past the
/// budget an event rides the file lane. Owned by one serial `ESMessageWorker`
/// queue, so it needs no lock.
final class ProtectedFileLaneBudget {
    /// The OPEN budget: credential and agent-content reads come in bursts
    /// (every `git` reads `~/.gitconfig`), and even this rate is a small
    /// fraction of what the priority lane drains.
    static func forProtectedOpens() -> ProtectedFileLaneBudget {
        ProtectedFileLaneBudget(capacity: 256, refillPerSecond: 64)
    }

    private let capacity: Double
    private let refillPerNanosecond: Double
    private var tokens: Double
    private var lastNanos: UInt64?

    init(capacity: Int = 64, refillPerSecond: Double = 16) {
        self.capacity = Double(capacity)
        self.refillPerNanosecond = refillPerSecond / 1_000_000_000
        self.tokens = Double(capacity)
    }

    /// Spends one token if one is available at `nowNanos` (monotonic).
    func admit(nowNanos: UInt64) -> Bool {
        if let last = lastNanos, nowNanos > last {
            tokens = Swift.min(capacity, tokens + Double(nowNanos - last) * refillPerNanosecond)
        }
        lastNanos = Swift.max(lastNanos ?? nowNanos, nowNanos)
        guard tokens >= 1 else { return false }
        tokens -= 1
        return true
    }
}

/// Compile-time bounded identity for every collector feeding the merged
/// detection pipeline. Never derive these labels from event data.
public enum EventPipelineSource: Int, CaseIterable, Sendable, Hashable {
    case endpointSecurity
    case kdebug
    case eslogger
    case unifiedLog
    case tcc
    case network

    public var key: String {
        switch self {
        case .endpointSecurity: return "ESCollector"
        case .kdebug: return "KdebugCollector"
        case .eslogger: return "EsloggerCollector"
        case .unifiedLog: return "UnifiedLogCollector"
        case .tcc: return "TCCMonitor"
        case .network: return "NetworkCollector"
        }
    }
}

/// Source identity must survive inside the downstream bounded stream because
/// `.bufferingNewest` returns the OLD evicted element, not the new offer.
/// Immutable reference slots avoid retaining an inline Event-sized allocation
/// for every high-water queue slot after a burst drains. The Event remains a
/// value: producer/consumer mutation of a copy cannot mutate this payload.
public final class EventPipelineEnvelope: Sendable {
    public let source: EventPipelineSource
    public let event: Event

    public init(source: EventPipelineSource, event: Event) {
        self.source = source
        self.event = event
    }
}

/// One collector's bounded AsyncStream accounting. Arrays are indexed by the
/// fixed two-case lane enum; dictionaries are allocated only by heartbeat reads.
public struct EventCollectorBufferSnapshot: Sendable, Equatable {
    public let offeredByLane: [String: UInt64]
    public let droppedByLane: [String: UInt64]
    public let terminatedByLane: [String: UInt64]
    public let capacity: UInt64

    public init(
        offeredByLane: [String: UInt64],
        droppedByLane: [String: UInt64],
        terminatedByLane: [String: UInt64],
        capacity: UInt64
    ) {
        self.offeredByLane = offeredByLane
        self.droppedByLane = droppedByLane
        self.terminatedByLane = terminatedByLane
        self.capacity = capacity
    }

    public var droppedTotal: UInt64 {
        droppedByLane.values.reduce(UInt64(0), Self.addSaturating)
    }

    public var terminatedTotal: UInt64 {
        terminatedByLane.values.reduce(UInt64(0), Self.addSaturating)
    }

    private static func addSaturating(_ lhs: UInt64, _ rhs: UInt64) -> UInt64 {
        let (sum, overflow) = lhs.addingReportingOverflow(rhs)
        return overflow ? UInt64.max : sum
    }
}

/// Thread-safe fixed-cardinality counters attached to a collector's own
/// AsyncStream boundary. The result and both events are handled in one lock:
/// the new event supplies the offered/terminated lane, while `.dropped`'s OLD
/// event supplies the loss lane.
public final class EventCollectorBufferTelemetry: @unchecked Sendable {
    private struct State {
        var offered = [UInt64](repeating: 0, count: EventPipelineLane.allCases.count)
        var dropped = [UInt64](repeating: 0, count: EventPipelineLane.allCases.count)
        var terminated = [UInt64](repeating: 0, count: EventPipelineLane.allCases.count)
    }

    private let state = OSAllocatedUnfairLock<State>(initialState: State())
    private let capacity: UInt64

    public init(capacity: Int) {
        self.capacity = UInt64(max(0, capacity))
    }

    @inline(__always)
    public func recordYield(
        offered event: Event,
        result: AsyncStream<Event>.Continuation.YieldResult
    ) {
        let offeredLane = EventPipelineLane.finalLane(for: event)
        state.withLock { locked in
            Self.incrementSaturating(&locked.offered[offeredLane.rawValue])
            switch result {
            case .dropped(let oldEvent):
                let droppedLane = EventPipelineLane.finalLane(for: oldEvent)
                Self.incrementSaturating(&locked.dropped[droppedLane.rawValue])
            case .terminated:
                Self.incrementSaturating(&locked.terminated[offeredLane.rawValue])
            case .enqueued:
                break
            @unknown default:
                // A future result cannot be assumed accepted. Count it as a
                // terminal loss so backlog never grows from an unclassified
                // offer and the evidence gap stays visible.
                Self.incrementSaturating(&locked.terminated[offeredLane.rawValue])
            }
        }
    }

    public func snapshot() -> EventCollectorBufferSnapshot {
        state.withLock { locked in
            var offered: [String: UInt64] = [:]
            var dropped: [String: UInt64] = [:]
            var terminated: [String: UInt64] = [:]
            for lane in EventPipelineLane.allCases {
                offered[lane.key] = locked.offered[lane.rawValue]
                dropped[lane.key] = locked.dropped[lane.rawValue]
                terminated[lane.key] = locked.terminated[lane.rawValue]
            }
            return EventCollectorBufferSnapshot(
                offeredByLane: offered,
                droppedByLane: dropped,
                terminatedByLane: terminated,
                capacity: capacity
            )
        }
    }

    @inline(__always)
    private static func incrementSaturating(_ value: inout UInt64) {
        if value < UInt64.max { value += 1 }
    }
}
