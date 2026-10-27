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
final class ProtectedFileLaneBudget: BoundedTableEntry {
    private let capacity: Double
    private let refillPerNanosecond: Double
    private var tokens: Double
    private var lastNanos: UInt64?

    /// `initialTokens` defaults to a full bucket; a table inserting a key over
    /// a live one hands it a single token instead.
    init(capacity: Int = 64, refillPerSecond: Double = 16, initialTokens: Int? = nil) {
        self.capacity = Double(capacity)
        self.refillPerNanosecond = refillPerSecond / 1_000_000_000
        self.tokens = Double(Swift.min(capacity, initialTokens ?? capacity))
    }

    /// Spends one token if one is available at `nowNanos` (monotonic).
    func admit(nowNanos: UInt64) -> Bool {
        refill(nowNanos: nowNanos)
        guard tokens >= 1 else { return false }
        tokens -= 1
        return true
    }

    /// Whether `admit` would succeed at `nowNanos`, without spending.
    func hasToken(nowNanos: UInt64) -> Bool {
        refill(nowNanos: nowNanos)
        return tokens >= 1
    }

    private func refill(nowNanos: UInt64) {
        if let last = lastNanos, nowNanos > last {
            tokens = Swift.min(capacity, tokens + Double(nowNanos - last) * refillPerNanosecond)
        }
        lastNanos = Swift.max(lastNanos ?? nowNanos, nowNanos)
    }

    /// The last clock reading this bucket saw; nil until its first use.
    /// `BoundedTable` evicts by it.
    var lastSeenNanos: UInt64? { lastNanos }
}

/// What a `BoundedTable` remembers per key: anything that can say when it was
/// last used, so idle and least-recently-used eviction can read it.
protocol BoundedTableEntry: AnyObject {
    var lastSeenNanos: UInt64? { get }
}

/// A fixed number of keyed entries, so a budget drained by one source cannot
/// refuse another's. Once `capacity` keys are held, a new key first makes
/// room by dropping every key idle for `idleEvictionNanos`; that full scan
/// runs at most once per quarter idle window, so a table held full costs a
/// new key a hash probe, not a scan. If no room is made, the policy decides.
/// A lane table frees an eighth of itself in one pass, least recently seen
/// first, and each key that then takes a slot a live entry left is marked
/// `churned`: it is no first sighting, and its entry is built as the maker
/// sees fit for a key that arrived under churn (one token, no allowance). A
/// signal table refuses the key outright. Either way, cycling through fresh
/// keys cannot buy a fresh bucket each time. Churn is forgotten once an idle
/// window passes with no live eviction, so a storm that has stopped does not
/// mark later newcomers. Unlocked — the owner serializes access (the ES
/// worker's queue, or `SignalRateLimiter`'s lock).
final class BoundedTable<Key: Hashable, Entry: BoundedTableEntry> {
    enum OverflowPolicy {
        /// Recycle the least recently seen live entries; newcomers in their slots are `churned`.
        case evictLeastRecentlyUsed
        /// Fail closed: refuse the newcomer until a key has gone idle.
        case refuseWhenFull
    }

    struct Lookup {
        /// The key's entry, or nil when a full fail-closed table refused it.
        let entry: Entry?
        /// The key entered the table without displacing a live one.
        let firstSighting: Bool
        /// The key entered the table in a slot a live entry was recycled from.
        let churned: Bool
    }

    private let capacity: Int
    private let idleEvictionNanos: UInt64
    private let policy: OverflowPolicy
    private let make: (_ churned: Bool) -> Entry
    private var entries: [Key: Entry] = [:]
    /// Live entries recycled but not yet replaced; the inserts that take
    /// their slots are the churned ones.
    private var liveEvictionCredits = 0
    private var lastLiveEvictionNanos: UInt64 = 0
    private var lastSweepNanos: UInt64?
    /// Full scans for idle keys run so far; a test aid.
    private(set) var sweepCount = 0

    init(capacity: Int, idleEvictionNanos: UInt64 = 60_000_000_000,
         policy: OverflowPolicy = .evictLeastRecentlyUsed,
         make: @escaping (_ churned: Bool) -> Entry) {
        self.capacity = Swift.max(1, capacity)
        self.idleEvictionNanos = idleEvictionNanos
        self.policy = policy
        self.make = make
    }

    /// The key's entry, inserting it if absent as the policy allows.
    func lookup(key: Key, nowNanos: UInt64) -> Lookup {
        if let entry = entries[key] {
            return Lookup(entry: entry, firstSighting: false, churned: false)
        }
        if liveEvictionCredits > 0, nowNanos > lastLiveEvictionNanos,
           nowNanos - lastLiveEvictionNanos >= idleEvictionNanos {
            liveEvictionCredits = 0
        }
        if entries.count >= capacity {
            if sweepIsDue(nowNanos: nowNanos) {
                evictIdle(nowNanos: nowNanos)
            }
            if entries.count >= capacity {
                switch policy {
                case .refuseWhenFull:
                    return Lookup(entry: nil, firstSighting: false, churned: false)
                case .evictLeastRecentlyUsed:
                    liveEvictionCredits += evictLeastRecentlySeenBatch(nowNanos: nowNanos)
                    lastLiveEvictionNanos = nowNanos
                }
            }
        }
        let churned = liveEvictionCredits > 0
        if churned { liveEvictionCredits -= 1 }
        let entry = make(churned)
        entries[key] = entry
        return Lookup(entry: entry, firstSighting: !churned, churned: churned)
    }

    /// The key's entry if it is tracked, never inserting it.
    func existing(key: Key) -> Entry? {
        entries[key]
    }

    /// Whether `key` is tracked, without inserting it.
    func contains(key: Key) -> Bool {
        entries[key] != nil
    }

    var count: Int { entries.count }

    private func isIdle(_ seen: UInt64?, nowNanos: UInt64) -> Bool {
        let seen = seen ?? 0
        return nowNanos > seen && nowNanos - seen >= idleEvictionNanos
    }

    /// A full scan for idle keys runs at most once per quarter idle window,
    /// and at once if the clock has gone backwards.
    private func sweepIsDue(nowNanos: UInt64) -> Bool {
        guard let last = lastSweepNanos, nowNanos >= last else { return true }
        return nowNanos - last >= Swift.max(1, idleEvictionNanos / 4)
    }

    private func evictIdle(nowNanos: UInt64) {
        lastSweepNanos = nowNanos
        sweepCount += 1
        let idle = entries.compactMap { isIdle($0.value.lastSeenNanos, nowNanos: nowNanos) ? $0.key : nil }
        for key in idle { entries[key] = nil }
    }

    /// Frees an eighth of the table in one pass, least recently seen first,
    /// so the next inserts find room without scanning; returns how many of
    /// the entries it dropped were live.
    private func evictLeastRecentlySeenBatch(nowNanos: UInt64) -> Int {
        let batch = Swift.max(1, capacity / 8)
        let oldest = entries.map { (key: $0.key, seen: $0.value.lastSeenNanos) }
            .sorted { ($0.seen ?? 0) < ($1.seen ?? 0) }
            .prefix(batch)
        var live = 0
        for item in oldest {
            entries[item.key] = nil
            if !isIdle(item.seen, nowNanos: nowNanos) { live += 1 }
        }
        return live
    }
}

/// One process's standing in one class of `PerProcessLaneBudgets`: its own
/// bucket, and — unless it entered the table over a live entry — the small
/// allowance it may spend without touching the worker's shared bucket.
final class ProcessLaneBudget: BoundedTableEntry {
    let bucket: ProtectedFileLaneBudget
    let exempt: ProtectedFileLaneBudget?

    init(bucket: ProtectedFileLaneBudget, exempt: ProtectedFileLaneBudget?) {
        self.bucket = bucket
        self.exempt = exempt
    }

    var lastSeenNanos: UInt64? { bucket.lastSeenNanos }
}

/// One ES worker's protected-lane budgets, split by class: the write family
/// and SETMODE, the static credential / agent-content OPENs (every `git`
/// reads `~/.gitconfig`), and the high-value OPENs — a deployed decoy or
/// honeyfile, a keychain, a wallet — which get tokens of their own so that a
/// process which drained its OPEN budget on its own `.gitconfig` cannot then
/// read a decoy or the login keychain off the priority lane.
///
/// Three bounds hold in every class, and the guarantee they give is this: a
/// process's protected event is admitted to the priority lane if its own
/// bucket has a token and either its allowance or the worker's shared bucket
/// has one.
///
/// 1. A bucket per source process (write 64 then 16 a second, OPEN 256 then
///    64, high-value 64 then 16): a loop spends only its own tokens, so it
///    can take neither another process's credential read nor its own
///    LaunchAgent write off the lane. Peeked, not spent, until the event is
///    admitted, so a shared-bucket refusal costs the process nothing.
/// 2. A bucket per worker (write 256 then 64, OPEN 1,024 then 256,
///    high-value 256 then 64), spent only after a process's own bucket had a
///    token, bounds what any number of processes can put on the lane in all.
/// 3. An allowance per process that the shared bucket never sees: its first
///    event, then four more refilling at one every four seconds. The shared
///    bucket refills at four processes' worth, so four or five long-lived
///    loopers on their own alert-free files hold it at zero for as long as
///    they run; the allowance is what still carries an uninvolved process's
///    credential read, or that of an IDE or shell tracked for an hour, past
///    them. A process that entered the table over a live entry (the table
///    was full of live processes) gets no allowance and one token, so the
///    allowance cannot be multiplied by rotating pids.
///
/// Hence a storm of fresh processes puts at most (live processes, at most
/// `trackedProcesses`) times the allowance of five, plus the shared bucket's
/// burst and refill, on the lane; the rest rides the file lane, counted as
/// refused. The residual: a process seen for the first time while more than
/// `trackedProcesses` live processes are storming is one of the churned
/// ones, and is bounded by the shared bucket like the storm. The tables
/// evict idle processes first. Owned by one serial `ESMessageWorker` queue,
/// so it needs no lock.
final class PerProcessLaneBudgets {
    enum Kind {
        case write
        case open
        case highValueOpen
    }

    typealias Shape = (capacity: Int, refillPerSecond: Double)

    private let write: BoundedTable<pid_t, ProcessLaneBudget>
    private let open: BoundedTable<pid_t, ProcessLaneBudget>
    private let highValueOpen: BoundedTable<pid_t, ProcessLaneBudget>
    private let writeAggregate: ProtectedFileLaneBudget
    private let openAggregate: ProtectedFileLaneBudget
    private let highValueOpenAggregate: ProtectedFileLaneBudget

    init(trackedProcesses: Int = 512,
         write: Shape = (capacity: 64, refillPerSecond: 16),
         open: Shape = (capacity: 256, refillPerSecond: 64),
         highValueOpen: Shape = (capacity: 64, refillPerSecond: 16),
         writeAggregate: Shape = (capacity: 256, refillPerSecond: 64),
         openAggregate: Shape = (capacity: 1_024, refillPerSecond: 256),
         highValueOpenAggregate: Shape = (capacity: 256, refillPerSecond: 64),
         allowance: Shape = (capacity: 4, refillPerSecond: 0.25)) {
        func table(_ shape: Shape) -> BoundedTable<pid_t, ProcessLaneBudget> {
            BoundedTable(capacity: trackedProcesses, policy: .evictLeastRecentlyUsed) { churned in
                ProcessLaneBudget(
                    bucket: ProtectedFileLaneBudget(capacity: shape.capacity, refillPerSecond: shape.refillPerSecond,
                                                    initialTokens: churned ? 1 : nil),
                    exempt: churned ? nil : ProtectedFileLaneBudget(
                        capacity: allowance.capacity, refillPerSecond: allowance.refillPerSecond))
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

    /// Whether `pid`'s event of `kind` at `nowNanos` (monotonic) rides the
    /// priority lane: its own bucket must have a token, and then its
    /// allowance or the worker's shared bucket pays. The own token is spent
    /// only on admission.
    func admit(_ kind: Kind, pid: pid_t, nowNanos: UInt64) -> Bool {
        let own: BoundedTable<pid_t, ProcessLaneBudget>
        let shared: ProtectedFileLaneBudget
        switch kind {
        case .write: (own, shared) = (write, writeAggregate)
        case .open: (own, shared) = (open, openAggregate)
        case .highValueOpen: (own, shared) = (highValueOpen, highValueOpenAggregate)
        }
        let lookup = own.lookup(key: pid, nowNanos: nowNanos)
        guard let process = lookup.entry, process.bucket.hasToken(nowNanos: nowNanos) else { return false }
        let exempt = lookup.firstSighting || process.exempt?.admit(nowNanos: nowNanos) == true
        guard exempt || shared.admit(nowNanos: nowNanos) else { return false }
        return process.bucket.admit(nowNanos: nowNanos)
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
/// exec/fork/exit. Two bounds.
///
/// Each (source pid, target pid) pair gets a small bucket. A tracked pair is
/// probed before any path is decoded; an untracked one is decoded first and
/// enters the table only if its target proved relevant, so the build's
/// fatal signals at ordinary processes never fill it. When the table is full
/// of live pairs a new pair is refused, so cycling through sources or
/// decoys cannot buy fresh budgets; the refusals are counted as
/// `es_signal_pair_refused_total`.
///
/// A pair's repeats then draw on a shared bucket: the target's own for the
/// engine and for a tool whose executable is root-owned at a canonical path
/// (read from the stat ES reports, with no syscall on the callback), and one
/// decoy bucket that every other target shares, so a kill loop at decoys
/// spends neither the engine's budget nor a real tool's. A pair's first
/// signal bypasses it, so every distinct source keeps its first signal at a
/// target whatever the others did. Kept signals are therefore bounded by the
/// pair table's first sightings per idle window plus the shared buckets,
/// whatever the attacker's process count. Locked: the ES callback may run on
/// more than one thread across clients.
final class SignalRateLimiter: @unchecked Sendable {
    struct Pair: Hashable {
        let source: pid_t
        let target: pid_t
    }

    private let lock = NSLock()
    private let pairs: BoundedTable<Pair, ProtectedFileLaneBudget>
    private let targets: BoundedTable<pid_t, ProtectedFileLaneBudget>
    /// The one repeat budget every target outside a root-owned canonical
    /// location shares: a binary the attacker named after a tool, wherever
    /// and however many, draws on this and never on the engine's or a real
    /// tool's own bucket.
    private let decoyRepeats: ProtectedFileLaneBudget
    private let rootOwnedCanonical: (_ path: String, _ ownerUID: uid_t?) -> Bool

    init(pairCapacity: Int = 8, pairRefillPerSecond: Double = 2,
         targetCapacity: Int = 64, targetRefillPerSecond: Double = 16,
         trackedPairs: Int = 1024, trackedTargets: Int = 1024,
         rootOwnedCanonical: @escaping (_ path: String, _ ownerUID: uid_t?) -> Bool
             = SignalRateLimiter.isRootOwnedCanonicalExecutable) {
        pairs = BoundedTable(capacity: trackedPairs, idleEvictionNanos: 10_000_000_000, policy: .refuseWhenFull) { _ in
            ProtectedFileLaneBudget(capacity: pairCapacity, refillPerSecond: pairRefillPerSecond)
        }
        targets = BoundedTable(capacity: trackedTargets, idleEvictionNanos: 10_000_000_000, policy: .refuseWhenFull) { _ in
            ProtectedFileLaneBudget(capacity: targetCapacity, refillPerSecond: targetRefillPerSecond)
        }
        decoyRepeats = ProtectedFileLaneBudget(capacity: targetCapacity, refillPerSecond: targetRefillPerSecond)
        self.rootOwnedCanonical = rootOwnedCanonical
    }

    /// Whether an executable lives where only root writes: the SIP-protected
    /// system trees by prefix, and under /Library or /Applications only when
    /// the file is root-owned (`ownerUID`, from the stat in the ES message),
    /// since an admin can create directories there. Anything else — /tmp, a
    /// home, /opt/homebrew, a mounted volume, or an owner not known — is
    /// where a decoy named after a tool would live.
    static func isRootOwnedCanonicalExecutable(_ path: String, ownerUID: uid_t?) -> Bool {
        for prefix in ["/System/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/bin/", "/sbin/"]
        where path.hasPrefix(prefix) {
            return true
        }
        guard path.hasPrefix("/Library/") || path.hasPrefix("/Applications/") else { return false }
        return ownerUID == 0
    }

    /// For a tracked pair, whether a signal may still be kept; nil for a pair
    /// not tracked, which `admitPair` inserts once its target proved
    /// relevant. One lock and an integer probe, before any path decode.
    func admitIfTracked(source: pid_t, target: pid_t, nowNanos: UInt64) -> Bool? {
        lock.lock(); defer { lock.unlock() }
        guard let bucket = pairs.existing(key: Pair(source: source, target: target)) else { return nil }
        let admitted = bucket.admit(nowNanos: nowNanos)
        if !admitted { pairRefusedCount &+= 1 }
        return admitted
    }

    /// Whether this pair may have a signal kept, inserting it if the table has
    /// room, and whether this is the pair's first. A pair the table is too full
    /// to take is refused.
    func admitPair(source: pid_t, target: pid_t, nowNanos: UInt64) -> (admitted: Bool, firstSighting: Bool) {
        lock.lock(); defer { lock.unlock() }
        let lookup = pairs.lookup(key: Pair(source: source, target: target), nowNanos: nowNanos)
        guard let bucket = lookup.entry, bucket.admit(nowNanos: nowNanos) else {
            pairRefusedCount &+= 1
            return (false, false)
        }
        return (true, lookup.firstSighting)
    }

    /// Whether one more repeat signal at this relevant target may be kept:
    /// from the target's own bucket for the engine (`executable` nil) and
    /// for a tool root-owned at a canonical path, from the shared decoy
    /// bucket for every other target.
    func admitKept(target: pid_t, executable: String?, ownerUID: uid_t?, nowNanos: UInt64) -> Bool {
        let ownBucket = executable.map { rootOwnedCanonical($0, ownerUID) } ?? true
        lock.lock(); defer { lock.unlock() }
        let admitted: Bool
        if ownBucket {
            admitted = targets.lookup(key: target, nowNanos: nowNanos).entry?.admit(nowNanos: nowNanos) ?? false
        } else {
            admitted = decoyRepeats.admit(nowNanos: nowNanos)
        }
        if !admitted { aggregateRefusedCount &+= 1 }
        return admitted
    }

    /// Pairs currently tracked; a test aid.
    var trackedPairCount: Int {
        lock.lock(); defer { lock.unlock() }
        return pairs.count
    }

    /// Full scans of the pair table for idle pairs; a test aid.
    var pairSweepCount: Int {
        lock.lock(); defer { lock.unlock() }
        return pairs.sweepCount
    }

    private var pairRefusedCount: UInt64 = 0
    private var aggregateRefusedCount: UInt64 = 0

    /// Fatal signals at a relevant target whose (source, target) pair had no
    /// token left, or that a pair table full of live pairs refused. Surfaced
    /// as `es_signal_pair_refused_total`.
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
