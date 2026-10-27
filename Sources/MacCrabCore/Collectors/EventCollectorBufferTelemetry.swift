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

    /// Spends one of the source process's budget tokens on a protected event
    /// and stamps its lane: nil for an event that is not a candidate, true
    /// when it was admitted to the priority lane, false when the budget
    /// refused it, which `refusals` counts. A refused OPEN is stamped for the
    /// file lane; any other refused event already rides it. The budgets are
    /// per process and per class (`PerProcessLaneBudgets`): an `open()` loop
    /// on the caller's own `.env` spends only that process's OPEN tokens, so
    /// it can take neither another process's credential read nor its own
    /// LaunchAgent write off the priority lane, and a decoy, keychain or
    /// wallet read spends a class of its own that the loop cannot reach.
    @discardableResult
    static func stampProtectedLane(
        _ event: inout Event,
        budgets: PerProcessLaneBudgets,
        nowNanos: UInt64,
        refusals: ESSeqTracker
    ) -> Bool? {
        guard isProtectedFileCandidate(event) else { return nil }
        let kind: PerProcessLaneBudgets.Kind
        if event.eventAction == "open" {
            kind = ESCollector.highValueOpenPathMarkers.matches(event.file?.path ?? "") ? .highValueOpen : .open
        } else {
            kind = .write
        }
        let pid = pid_t(truncatingIfNeeded: event.process.pid)
        if budgets.admit(kind, pid: pid, nowNanos: nowNanos) {
            event.enrichments[protectedFileLaneEnrichmentKey] = protectedFileLanePriority
            return true
        }
        if kind != .write {
            event.enrichments[protectedFileLaneEnrichmentKey] = protectedFileLaneFile
        }
        refusals.recordProtectedLaneRefused()
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

/// A token bucket of `capacity` refilled at `refillPerSecond`, the unit of
/// every protected-lane budget (`PerProcessLaneBudgets` holds one per source
/// process and class, and one per class for the whole worker). The priority
/// lane is a drop-oldest buffer that also carries exec/fork/exit, and a
/// `chmod 755` loop, a write loop on the caller's own `~/.zshrc` or an
/// `open()` loop on its own `.env` costs nothing to run, so an unbounded
/// class would let it evict lineage; a fork-and-open storm is as cheap, so
/// the per-process buckets alone would not bound the lane either. Past a
/// budget an event rides the file lane. Owned by one serial
/// `ESMessageWorker` queue, so it needs no lock.
final class ProtectedFileLaneBudget {
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

    /// The last clock reading this bucket saw; nil until its first `admit`.
    /// `BoundedBudgetTable` evicts by it.
    var lastSeenNanos: UInt64? { lastNanos }
}

/// One `ProtectedFileLaneBudget` per key, so a budget drained by one source
/// cannot refuse another's. Bounded: once `capacity` keys are held, an insert
/// first drops every key idle for `idleEvictionNanos`, and if none is, the
/// least recently seen one. Unlocked — the owner serializes access (the ES
/// worker's queue, or `SignalRateLimiter`'s lock).
final class BoundedBudgetTable<Key: Hashable> {
    private let capacity: Int
    private let idleEvictionNanos: UInt64
    private let makeBudget: () -> ProtectedFileLaneBudget
    private var budgets: [Key: ProtectedFileLaneBudget] = [:]

    init(capacity: Int, idleEvictionNanos: UInt64 = 60_000_000_000,
         makeBudget: @escaping () -> ProtectedFileLaneBudget) {
        self.capacity = Swift.max(1, capacity)
        self.idleEvictionNanos = idleEvictionNanos
        self.makeBudget = makeBudget
    }

    /// Spends one of `key`'s tokens at `nowNanos`; a key never seen before
    /// starts with a full bucket.
    func admit(key: Key, nowNanos: UInt64) -> Bool {
        admitReportingFirstSighting(key: key, nowNanos: nowNanos).admitted
    }

    /// `admit`, also saying whether this is the key's first token since it
    /// entered the table (or re-entered it after eviction).
    func admitReportingFirstSighting(key: Key, nowNanos: UInt64) -> (admitted: Bool, firstSighting: Bool) {
        if let budget = budgets[key] {
            return (budget.admit(nowNanos: nowNanos), false)
        }
        if budgets.count >= capacity {
            evict(nowNanos: nowNanos)
        }
        let budget = makeBudget()
        budgets[key] = budget
        return (budget.admit(nowNanos: nowNanos), true)
    }

    var count: Int { budgets.count }

    private func evict(nowNanos: UInt64) {
        var oldestKey: Key?
        var oldestSeen = UInt64.max
        for (key, budget) in budgets {
            let seen = budget.lastSeenNanos ?? 0
            if nowNanos > seen, nowNanos - seen >= idleEvictionNanos {
                budgets[key] = nil
            } else if seen < oldestSeen {
                oldestSeen = seen
                oldestKey = key
            }
        }
        if budgets.count >= capacity, let key = oldestKey {
            budgets[key] = nil
        }
    }
}

/// One ES worker's protected-lane budgets, split by class: the write family
/// and SETMODE, the static credential / agent-content OPENs (every `git`
/// reads `~/.gitconfig`), and the high-value OPENs — a deployed decoy or
/// honeyfile, a keychain, a wallet — which get tokens of their own so that a
/// process which drained its OPEN budget on its own `.gitconfig` cannot then
/// read a decoy or the login keychain off the priority lane.
///
/// Each class is bounded twice. A bucket per source process (write 64 then
/// 16 a second, OPEN 256 then 64, high-value 64 then 16) means a loop spends
/// only its own tokens: it can take neither another process's credential
/// read nor its own LaunchAgent write off the priority lane. One bucket per
/// worker (write 256 then 64, OPEN 1,024 then 256, high-value 256 then 64),
/// spent only after a process's own bucket admitted, bounds what a storm of
/// fresh processes — a fork each doing its own 256 opens — can put on the
/// lane in all; being several times a single bucket, one looping process
/// cannot drain it for the others. Past either bound an event rides the
/// file lane and is counted as refused. A process never seen before starts
/// with full buckets; the tables hold `trackedProcesses` pids each and evict
/// idle ones first. Owned by one serial `ESMessageWorker` queue, so it
/// needs no lock.
final class PerProcessLaneBudgets {
    enum Kind {
        case write
        case open
        case highValueOpen
    }

    typealias Shape = (capacity: Int, refillPerSecond: Double)

    private let write: BoundedBudgetTable<pid_t>
    private let open: BoundedBudgetTable<pid_t>
    private let highValueOpen: BoundedBudgetTable<pid_t>
    private let writeAggregate: ProtectedFileLaneBudget
    private let openAggregate: ProtectedFileLaneBudget
    private let highValueOpenAggregate: ProtectedFileLaneBudget

    init(trackedProcesses: Int = 512,
         write: Shape = (capacity: 64, refillPerSecond: 16),
         open: Shape = (capacity: 256, refillPerSecond: 64),
         highValueOpen: Shape = (capacity: 64, refillPerSecond: 16),
         writeAggregate: Shape = (capacity: 256, refillPerSecond: 64),
         openAggregate: Shape = (capacity: 1_024, refillPerSecond: 256),
         highValueOpenAggregate: Shape = (capacity: 256, refillPerSecond: 64)) {
        func table(_ shape: Shape) -> BoundedBudgetTable<pid_t> {
            BoundedBudgetTable(capacity: trackedProcesses) {
                ProtectedFileLaneBudget(capacity: shape.capacity, refillPerSecond: shape.refillPerSecond)
            }
        }
        func bucket(_ shape: Shape) -> ProtectedFileLaneBudget {
            ProtectedFileLaneBudget(capacity: shape.capacity, refillPerSecond: shape.refillPerSecond)
        }
        self.write = table(write)
        self.open = table(open)
        self.highValueOpen = table(highValueOpen)
        self.writeAggregate = bucket(writeAggregate)
        self.openAggregate = bucket(openAggregate)
        self.highValueOpenAggregate = bucket(highValueOpenAggregate)
    }

    /// Spends one of `pid`'s tokens of `kind` at `nowNanos` (monotonic), and
    /// then one of the worker's for that class. A process's own bucket is
    /// consulted first, so a refused loop never reaches the shared one.
    func admit(_ kind: Kind, pid: pid_t, nowNanos: UInt64) -> Bool {
        let own: BoundedBudgetTable<pid_t>
        let shared: ProtectedFileLaneBudget
        switch kind {
        case .write: (own, shared) = (write, writeAggregate)
        case .open: (own, shared) = (open, openAggregate)
        case .highValueOpen: (own, shared) = (highValueOpen, highValueOpenAggregate)
        }
        guard own.admit(key: pid, nowNanos: nowNanos) else { return false }
        return shared.admit(nowNanos: nowNanos)
    }

    /// The most processes any one class tracks; a test aid.
    var trackedProcessCount: Int {
        Swift.max(write.count, open.count, highValueOpen.count)
    }
}

/// How many kept NOTIFY_SIGNAL messages reach the priority lane. The callback
/// keeps only a fatal signal aimed at MacCrab or at a security tool, but one
/// process can send that signal in a loop, or name a decoy after a security
/// tool and signal it, and every kept message rides the lane that carries
/// exec/fork/exit. Two bounds. Each (source pid, target pid) pair gets a
/// small bucket, checked before any path is decoded. Each relevant target
/// then gets a shared bucket that every source's repeats draw on, so a kill
/// loop at a decoy spends the decoy's budget and never the engine's or a
/// real tool's; a pair's first signal bypasses it, so every distinct source
/// keeps its first signal at a target whatever the others did. Ordinary
/// targets never reach the shared bucket, so the build-storm SIGTERMs cannot
/// spend it. Locked: the ES callback may run on more than one thread across
/// clients.
final class SignalRateLimiter: @unchecked Sendable {
    struct Pair: Hashable {
        let source: pid_t
        let target: pid_t
    }

    private let lock = NSLock()
    private let pairs: BoundedBudgetTable<Pair>
    private let targets: BoundedBudgetTable<pid_t>

    init(pairCapacity: Int = 8, pairRefillPerSecond: Double = 2,
         targetCapacity: Int = 64, targetRefillPerSecond: Double = 16,
         trackedPairs: Int = 1024, trackedTargets: Int = 1024) {
        pairs = BoundedBudgetTable(capacity: trackedPairs, idleEvictionNanos: 10_000_000_000) {
            ProtectedFileLaneBudget(capacity: pairCapacity, refillPerSecond: pairRefillPerSecond)
        }
        targets = BoundedBudgetTable(capacity: trackedTargets, idleEvictionNanos: 10_000_000_000) {
            ProtectedFileLaneBudget(capacity: targetCapacity, refillPerSecond: targetRefillPerSecond)
        }
    }

    /// Whether this pair may still have a signal kept, and whether this is
    /// the pair's first; spent before the target's executable is decoded, so
    /// a flood at one target costs the callback an integer probe per message,
    /// not a path decode.
    func admitPair(source: pid_t, target: pid_t, nowNanos: UInt64) -> (admitted: Bool, firstSighting: Bool) {
        lock.lock(); defer { lock.unlock() }
        let result = pairs.admitReportingFirstSighting(key: Pair(source: source, target: target), nowNanos: nowNanos)
        if !result.admitted { pairRefusedCount &+= 1 }
        return result
    }

    /// Whether one more repeat signal at this relevant target may be kept.
    func admitKept(target: pid_t, nowNanos: UInt64) -> Bool {
        lock.lock(); defer { lock.unlock() }
        let admitted = targets.admit(key: target, nowNanos: nowNanos)
        if !admitted { aggregateRefusedCount &+= 1 }
        return admitted
    }

    /// Pairs currently tracked; a test aid.
    var trackedPairCount: Int {
        lock.lock(); defer { lock.unlock() }
        return pairs.count
    }

    private var pairRefusedCount: UInt64 = 0
    private var aggregateRefusedCount: UInt64 = 0

    /// Fatal signals whose (source, target) pair had no token left.
    var pairRefusedTotal: UInt64 {
        lock.lock(); defer { lock.unlock() }
        return pairRefusedCount
    }

    /// Fatal signals at a relevant target refused by the target's shared
    /// budget. Surfaced as `es_signal_aggregate_refused_total`.
    var aggregateRefusedTotal: UInt64 {
        lock.lock(); defer { lock.unlock() }
        return aggregateRefusedCount
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
