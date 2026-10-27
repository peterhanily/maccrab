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

    /// Every default honeyfile and honey-prompt decoy, relative to the home
    /// it is deployed in.
    private static let deployedDecoys: Set<String> = Set(
        HoneyfileManager.defaultHoneyfileSet(homeDir: "").map(\.path)
            + HoneyPromptManager.defaultHoneyPromptSet(homeDir: "").map(\.path))

    /// Whether `path` is a deployed honeyfile or honey-prompt decoy: exactly
    /// one of the default paths, inside a user's home or root's. The same
    /// name anywhere else (`/tmp/x/.aws/credentials.bak`, `/Users/Shared/…`,
    /// junk beside the decoys) is not, so on a host where every default
    /// decoy is deployed no loop on files a process can create spends this
    /// class's budget; reading the deployed files themselves is the finding.
    /// A default path that was never deployed there (another user's home, or
    /// a host where deception was set up before v1.12.0 or never) can be
    /// created and looped on.
    static func isHoneyfileOrDecoyPath(_ path: String) -> Bool {
        guard !path.hasPrefix("/Users/Shared/"), let inHome = homeRelativePath(path) else { return false }
        return deployedDecoys.contains(String(inHome))
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
    /// LaunchAgent write off the priority lane. A keychain, wallet or
    /// password-database read spends a class of its own that the loop cannot
    /// reach, and a deployed honeyfile or decoy read, matched by exact path,
    /// another that no loop on junk files can reach either.
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
            let path = event.file?.path ?? ""
            if isHoneyfileOrDecoyPath(path) {
                kind = .honeyfileOpen
            } else if ESCollector.highValueOpenPathMarkers.matches(path) {
                kind = .highValueOpen
            } else {
                kind = .open
            }
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
/// process and class with an allowance beside it, and a shared bucket and a
/// newcomer allowance per class for the whole worker) and of the signal
/// budgets (`SignalRateLimiter`). The priority lane is a drop-oldest buffer
/// that also carries exec/fork/exit, and a `chmod 755` loop, a write loop on
/// the caller's own `~/.zshrc` or an `open()` loop on its own `.env` costs
/// nothing to run, so an unbounded class would let it evict lineage; a
/// fork-and-open storm is as cheap, so the per-process buckets alone would
/// not bound the lane either. Past a budget an event rides the file lane.
/// Unlocked: its owner serializes access (one serial `ESMessageWorker`
/// queue, or `SignalRateLimiter`'s lock).
final class ProtectedFileLaneBudget: BoundedTableEntry {
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
/// refuse another's. A new key takes a clean free slot if there is one (never
/// held, or left by an idle key). When there is none, it first makes room by
/// dropping every key idle for `idleEvictionNanos`; that full scan runs at
/// most once per quarter idle window, so a table held full costs a new key a
/// hash probe, not a scan. If the table is still full, the policy decides. A
/// lane table frees an eighth of itself in one pass, idle keys first and then
/// the most recently inserted live ones, so a storm of new keys recycles its
/// own slots first: a live key is recycled only when at least 448 live keys
/// were inserted before it. A key that takes a slot a live
/// entry left is `churned`: it is no first sighting, and its entry is built
/// as the maker sees fit for a key that arrived under churn. A signal table
/// refuses the key outright. Either way, cycling through fresh keys cannot
/// buy a first sighting each time. Churn is forgotten once an idle window
/// passes with no live entry recycled (`churnIsForgotten`), and the slots
/// live entries left are clean again. Unlocked — the owner serializes access
/// (the ES worker's queue, or `SignalRateLimiter`'s lock).
final class BoundedTable<Key: Hashable, Entry: BoundedTableEntry> {
    enum OverflowPolicy {
        /// Recycle a batch, idle entries first and then the most recently
        /// inserted live ones; newcomers in the slots live entries left are `churned`.
        case evictNewestFirst
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

    private struct Slot {
        let entry: Entry
        /// Insertion order: a batch recycles the newest live slots first.
        let inserted: UInt64
    }

    private let capacity: Int
    private let idleEvictionNanos: UInt64
    private let policy: OverflowPolicy
    private let make: (_ churned: Bool) -> Entry
    private var slots: [Key: Slot] = [:]
    private var insertions: UInt64 = 0
    /// Free slots live entries left that no newcomer has taken yet; never
    /// more than the free slots. A newcomer takes a clean free slot first, so
    /// these mark it only once every free slot is one of them.
    private var liveEvictionCredits = 0
    /// When a batch last recycled a live entry; nil if none ever has.
    private var lastLiveEvictionNanos: UInt64?
    private var lastSweepNanos: UInt64?
    /// Full scans for idle keys run so far; a test aid.
    private(set) var sweepCount = 0

    init(capacity: Int, idleEvictionNanos: UInt64 = 60_000_000_000,
         policy: OverflowPolicy = .evictNewestFirst,
         make: @escaping (_ churned: Bool) -> Entry) {
        self.capacity = Swift.max(1, capacity)
        self.idleEvictionNanos = idleEvictionNanos
        self.policy = policy
        self.make = make
    }

    /// The key's entry, inserting it if absent as the policy allows.
    func lookup(key: Key, nowNanos: UInt64) -> Lookup {
        if let slot = slots[key] {
            return Lookup(entry: slot.entry, firstSighting: false, churned: false)
        }
        if churnIsForgotten(nowNanos: nowNanos) {
            liveEvictionCredits = 0
        }
        if cleanFreeSlots == 0, sweepIsDue(nowNanos: nowNanos) {
            evictIdle(nowNanos: nowNanos)
        }
        if slots.count >= capacity {
            switch policy {
            case .refuseWhenFull:
                return Lookup(entry: nil, firstSighting: false, churned: false)
            case .evictNewestFirst:
                evictBatch(nowNanos: nowNanos)
            }
        }
        let churned = cleanFreeSlots == 0
        if churned { liveEvictionCredits -= 1 }
        let entry = make(churned)
        insertions &+= 1
        slots[key] = Slot(entry: entry, inserted: insertions)
        return Lookup(entry: entry, firstSighting: !churned, churned: churned)
    }

    /// Whether no batch has recycled a live entry for an idle window, or
    /// ever: the table is not churning, so a key that arrived while it was
    /// need no longer be treated as a churned one.
    func churnIsForgotten(nowNanos: UInt64) -> Bool {
        guard let last = lastLiveEvictionNanos else { return true }
        return nowNanos >= last && nowNanos - last >= idleEvictionNanos
    }

    /// The key's entry if it is tracked, never inserting it.
    func existing(key: Key) -> Entry? {
        slots[key]?.entry
    }

    /// Whether `key` is tracked, without inserting it.
    func contains(key: Key) -> Bool {
        slots[key] != nil
    }

    var count: Int { slots.count }

    /// Free slots no live entry left.
    private var cleanFreeSlots: Int { capacity - slots.count - liveEvictionCredits }

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
        let idle = slots.compactMap { isIdle($0.value.entry.lastSeenNanos, nowNanos: nowNanos) ? $0.key : nil }
        for key in idle { slots[key] = nil }
    }

    /// Frees an eighth of the table in one pass, idle entries first and then
    /// the most recently inserted live ones, so the next inserts find room
    /// without scanning. Each live entry it drops is a credit, and only a
    /// batch that dropped one restarts the churn window.
    private func evictBatch(nowNanos: UInt64) {
        let batch = Swift.max(1, capacity / 8)
        let chosen = slots
            .map { (key: $0.key, idle: isIdle($0.value.entry.lastSeenNanos, nowNanos: nowNanos), inserted: $0.value.inserted) }
            .sorted { $0.idle != $1.idle ? $0.idle : $0.inserted > $1.inserted }
            .prefix(batch)
        var live = 0
        for item in chosen {
            slots[item.key] = nil
            if !item.idle { live += 1 }
        }
        if live > 0 {
            liveEvictionCredits += live
            lastLiveEvictionNanos = nowNanos
        }
    }
}

/// One process's standing in one class of `PerProcessLaneBudgets`: its own
/// bucket, and the small allowance it may spend without touching the
/// worker's shared bucket. A process that arrived under churn has no
/// allowance until the table's churn is forgotten.
final class ProcessLaneBudget: BoundedTableEntry {
    let bucket: ProtectedFileLaneBudget
    var allowance: ProtectedFileLaneBudget?

    init(bucket: ProtectedFileLaneBudget, allowance: ProtectedFileLaneBudget?) {
        self.bucket = bucket
        self.allowance = allowance
    }

    var lastSeenNanos: UInt64? { bucket.lastSeenNanos }
}

/// One ES worker's protected-lane budgets, split by class: the write family
/// and SETMODE; the static credential / agent-content OPENs (every `git`
/// reads `~/.gitconfig`); the high-value OPENs of a keychain, a wallet or a
/// password database; and the OPENs of a deployed honeyfile or decoy,
/// matched by exact path. The last two get tokens of their own, so that a
/// process which drained its OPEN budget on its own `.gitconfig` cannot then
/// read the login keychain or a decoy off the priority lane, and junk named
/// like a keychain spends only the high-value class, never the honeyfile
/// one.
///
/// In every class a process's protected event is admitted to the priority
/// lane when its own bucket has a token and a payer has one.
///
/// 1. Its own bucket (write 64 then 16 a second, OPEN 256 then 64,
///    high-value and honeyfile 64 then 16): a loop spends only its own
///    tokens, so it can take neither another process's credential read nor
///    its own LaunchAgent write off the lane. Peeked, not spent, until a
///    payer pays, so a refusal costs the process nothing.
/// 2. The payer. A process seen for the first time pays nothing for its
///    first event. A tracked process pays from its allowance (four events,
///    refilling one every four seconds, that nothing else can spend) and then
///    from the worker's shared bucket (write 256 then 64 a second, OPEN 1,024
///    then 256, high-value and honeyfile 256 then 64). The shared bucket
///    refills at four processes' worth, so four or five long-lived loopers on
///    their own alert-free files hold it at zero for as long as they run; the
///    allowance is what still carries the credential read of an uninvolved
///    process, or of an IDE or shell tracked for an hour, past them.
/// 3. Churn. When the table is full of live processes, a batch recycles the
///    most recently inserted ones (`BoundedTable`), so a storm of fresh pids
///    recycles its own slots first: a live process is recycled only when at
///    least 448 live processes were inserted before it. A process that
///    takes such a slot is a newcomer under churn. Its first event is paid by
///    the newcomer allowance (128, refilling 32 a second), which no tracked
///    process can spend, and its later events by the shared bucket. It gets
///    its own allowance once the table's churn is forgotten (an idle window,
///    60 s, with no live process recycled). Rotating pids therefore
///    multiplies neither the allowance nor the free first event.
///
/// Per class and per worker, over any T seconds:
///
///     admitted ≤ B + R × T
///     B = P × (1 + A) + S + N
///     R = s + n + P × a + P × (1 + A) / W
///
/// where P is the tracked processes (512), A the allowance (4) and a its
/// refill (0.25/s), S the shared capacity and s its refill, N the newcomer
/// allowance (128) and n its refill (32/s), and W the idle window (60 s). The
/// last term is the turnover: a slot can take a newly allowanced process at
/// most once per idle window. That is B = 3,712 and R ≈ 459/s for OPEN, and
/// B = 2,944 and R ≈ 267/s for each of write, high-value and honeyfile; the
/// four classes together put at most their sum on the lane. The rest rides
/// the file lane, counted as refused.
///
/// What remains:
/// - A process's first event of a class is refused only while the class's
///   table is churning (it recycled a live process within the last idle
///   window, which takes P distinct processes with an event of the class in
///   the idle window before that) and new processes have been arriving
///   faster than n for longer than N / (rate − n) seconds.
/// - A live process loses its standing only if at least P − P/8 (448) live
///   processes were inserted before it.
/// - A newcomer under churn depends on the shared bucket for its later events
///   until churn is forgotten.
/// - A process with no event of a class for an idle window may be forgotten
///   and is a newcomer again.
///
/// Owned by one serial `ESMessageWorker` queue, so it needs no lock.
final class PerProcessLaneBudgets {
    enum Kind {
        case write
        case open
        case highValueOpen
        case honeyfileOpen
    }

    typealias Shape = (capacity: Int, refillPerSecond: Double)

    /// One class: its per-process table, the worker's shared bucket, and the
    /// newcomer allowance that only a churned newcomer's first event spends.
    private struct Lane {
        let processes: BoundedTable<pid_t, ProcessLaneBudget>
        let shared: ProtectedFileLaneBudget
        let newcomers: ProtectedFileLaneBudget
    }

    private let write: Lane
    private let open: Lane
    private let highValueOpen: Lane
    private let honeyfileOpen: Lane
    private let allowance: Shape

    init(trackedProcesses: Int = 512,
         write: Shape = (capacity: 64, refillPerSecond: 16),
         open: Shape = (capacity: 256, refillPerSecond: 64),
         highValueOpen: Shape = (capacity: 64, refillPerSecond: 16),
         honeyfileOpen: Shape = (capacity: 64, refillPerSecond: 16),
         writeAggregate: Shape = (capacity: 256, refillPerSecond: 64),
         openAggregate: Shape = (capacity: 1_024, refillPerSecond: 256),
         highValueOpenAggregate: Shape = (capacity: 256, refillPerSecond: 64),
         honeyfileOpenAggregate: Shape = (capacity: 256, refillPerSecond: 64),
         allowance: Shape = (capacity: 4, refillPerSecond: 0.25),
         newcomers: Shape = (capacity: 128, refillPerSecond: 32)) {
        func bucket(_ shape: Shape) -> ProtectedFileLaneBudget {
            ProtectedFileLaneBudget(capacity: shape.capacity, refillPerSecond: shape.refillPerSecond)
        }
        func lane(_ own: Shape, _ shared: Shape) -> Lane {
            Lane(processes: BoundedTable(capacity: trackedProcesses, policy: .evictNewestFirst) { churned in
                     ProcessLaneBudget(bucket: bucket(own), allowance: churned ? nil : bucket(allowance))
                 },
                 shared: bucket(shared),
                 newcomers: bucket(newcomers))
        }
        self.write = lane(write, writeAggregate)
        self.open = lane(open, openAggregate)
        self.highValueOpen = lane(highValueOpen, highValueOpenAggregate)
        self.honeyfileOpen = lane(honeyfileOpen, honeyfileOpenAggregate)
        self.allowance = allowance
    }

    /// Whether `pid`'s event of `kind` at `nowNanos` (monotonic) rides the
    /// priority lane: its own bucket must have a token, and then a first
    /// sighting is free, a churned newcomer's first event is paid by the
    /// newcomer allowance, and anything else by the process's allowance; the
    /// shared bucket pays whatever those cannot. The own token is spent only
    /// on admission.
    func admit(_ kind: Kind, pid: pid_t, nowNanos: UInt64) -> Bool {
        let lane: Lane
        switch kind {
        case .write: lane = write
        case .open: lane = open
        case .highValueOpen: lane = highValueOpen
        case .honeyfileOpen: lane = honeyfileOpen
        }
        let lookup = lane.processes.lookup(key: pid, nowNanos: nowNanos)
        guard let process = lookup.entry, process.bucket.hasToken(nowNanos: nowNanos) else { return false }
        if process.allowance == nil, lane.processes.churnIsForgotten(nowNanos: nowNanos) {
            process.allowance = ProtectedFileLaneBudget(
                capacity: allowance.capacity, refillPerSecond: allowance.refillPerSecond)
        }
        let paid: Bool
        if lookup.firstSighting {
            paid = true
        } else if lookup.churned {
            paid = lane.newcomers.admit(nowNanos: nowNanos) || lane.shared.admit(nowNanos: nowNanos)
        } else {
            paid = process.allowance?.admit(nowNanos: nowNanos) == true || lane.shared.admit(nowNanos: nowNanos)
        }
        return paid && process.bucket.admit(nowNanos: nowNanos)
    }

    /// The most processes any one class tracks; a test aid.
    var trackedProcessCount: Int {
        Swift.max(write.processes.count, open.processes.count, highValueOpen.processes.count,
                  honeyfileOpen.processes.count)
    }
}

/// How many kept NOTIFY_SIGNAL messages reach the priority lane. The callback
/// keeps only a fatal signal aimed at MacCrab or at a security tool, but one
/// process can send that signal in a loop, or name a decoy after a security
/// tool and signal it, and every kept message rides the lane that carries
/// exec/fork/exit.
///
/// Each (source pid, target pid) pair gets a small bucket (8, then 2 a
/// second). A tracked pair is probed before any path is decoded; an untracked
/// one is decoded first and enters the table only if its target proved
/// relevant, so the build's fatal signals at ordinary processes never fill
/// it. A pair's first signal is kept. Its repeats also draw on a repeat
/// budget (64, then 16 a second) chosen by target: the engine's own; one per
/// executable identity (device and inode, from the stat ES reports) for a
/// tool whose executable is root-owned and singly linked at a canonical
/// path; and one decoy budget that every other target shares. A kill loop at
/// decoys therefore spends neither the engine's budget nor a real tool's,
/// and running more copies of one tool's binary buys no more budget.
///
/// A pair table full of live pairs fails closed for decoys: a new pair at a
/// decoy is refused, so cycling through sources or decoys cannot buy fresh
/// first signals. A new pair at the engine or at a canonical tool is not
/// tracked either, but its signal is kept while that target's repeat budget
/// lasts. Untracked senders signalling the same target spend that budget
/// too, so about 64 cooperating processes (a table held full by decoy pairs
/// plus a flood at the engine or tool) can still crowd out a genuine kill.
/// Refusals are counted apart: a tracked pair out of tokens as
/// `es_signal_pair_refused_total`, a signal whose new pair the full table
/// could not take as `es_signal_pair_table_full_total` (kept or not), and a
/// repeat budget's refusal as `es_signal_aggregate_refused_total`.
///
/// Over any T seconds:
///
///     kept ≤ P × (1 + T / W) + (2 + I) × (64 + 16 × T)
///
/// where P is the tracked pairs (1,024), W the pair idle window (10 s), and I
/// the distinct canonical tool identities signalled. I cannot grow without
/// root: each identity needs a root-owned, singly linked executable at a
/// canonical path, named after a security tool. Locked: the ES callback may
/// run on more than one thread across clients.
final class SignalRateLimiter: @unchecked Sendable {
    struct Pair: Hashable {
        let source: pid_t
        let target: pid_t
    }

    /// What ES reports about a signal target's executable file, read off the
    /// message with no syscall.
    struct ExecutableStat: Equatable {
        let owner: uid_t
        let links: nlink_t
        let device: dev_t
        let inode: ino_t

        init(owner: uid_t, links: nlink_t, device: dev_t, inode: ino_t) {
            self.owner = owner
            self.links = links
            self.device = device
            self.inode = inode
        }

        init(_ value: Darwin.stat) {
            self.init(owner: value.st_uid, links: value.st_nlink, device: value.st_dev, inode: value.st_ino)
        }
    }

    /// The repeat budget a relevant target draws on.
    enum RepeatBudget: Hashable {
        case engine
        /// A canonical tool, by the identity of its executable file.
        case tool(device: dev_t, inode: ino_t)
        case decoy
    }

    /// What became of a pair the table did not track yet.
    enum PairVerdict: Equatable {
        /// The pair entered the table: its first signal.
        case first
        /// Another thread inserted the pair first: a repeat.
        case repeated
        /// The pair's bucket had no token left.
        case bucketEmpty
        /// The table, full of live pairs, could not take the pair.
        case tableFull
    }

    private struct ToolIdentity: Hashable {
        let device: dev_t
        let inode: ino_t
    }

    private let lock = NSLock()
    private let pairs: BoundedTable<Pair, ProtectedFileLaneBudget>
    private let engineRepeats: ProtectedFileLaneBudget
    private let toolRepeats: BoundedTable<ToolIdentity, ProtectedFileLaneBudget>
    /// The one repeat budget every target outside a root-owned canonical
    /// location shares: a binary the attacker named after a tool, wherever
    /// and however many, draws on this and never on the engine's or a real
    /// tool's own bucket.
    private let decoyRepeats: ProtectedFileLaneBudget
    private let rootOwnedCanonical: (_ path: String, _ stat: ExecutableStat?) -> Bool

    init(pairCapacity: Int = 8, pairRefillPerSecond: Double = 2,
         targetCapacity: Int = 64, targetRefillPerSecond: Double = 16,
         trackedPairs: Int = 1024, trackedTools: Int = 1024,
         rootOwnedCanonical: @escaping (_ path: String, _ stat: ExecutableStat?) -> Bool
             = SignalRateLimiter.isRootOwnedCanonicalExecutable) {
        pairs = BoundedTable(capacity: trackedPairs, idleEvictionNanos: 10_000_000_000, policy: .refuseWhenFull) { _ in
            ProtectedFileLaneBudget(capacity: pairCapacity, refillPerSecond: pairRefillPerSecond)
        }
        toolRepeats = BoundedTable(capacity: trackedTools, idleEvictionNanos: 10_000_000_000, policy: .refuseWhenFull) { _ in
            ProtectedFileLaneBudget(capacity: targetCapacity, refillPerSecond: targetRefillPerSecond)
        }
        engineRepeats = ProtectedFileLaneBudget(capacity: targetCapacity, refillPerSecond: targetRefillPerSecond)
        decoyRepeats = ProtectedFileLaneBudget(capacity: targetCapacity, refillPerSecond: targetRefillPerSecond)
        self.rootOwnedCanonical = rootOwnedCanonical
    }

    /// Whether an executable lives where only root writes: the SIP-protected
    /// system trees by prefix, and under /Library or /Applications only when
    /// the file is root-owned and has a single link (`stat`, from the ES
    /// message), since an admin can create directories there, and a second
    /// link could be a hard link to some other root-owned file. Anything
    /// else (/tmp, a home, /opt/homebrew, a mounted volume, or a stat not
    /// known) is where a decoy named after a tool would live.
    static func isRootOwnedCanonicalExecutable(_ path: String, stat: ExecutableStat?) -> Bool {
        for prefix in ["/System/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/bin/", "/sbin/"]
        where path.hasPrefix(prefix) {
            return true
        }
        guard path.hasPrefix("/Library/") || path.hasPrefix("/Applications/"), let stat else { return false }
        return stat.owner == 0 && stat.links == 1
    }

    /// The repeat budget for a relevant target: the engine's, a canonical
    /// tool's by executable identity, or the shared decoy budget.
    func repeatBudget(engine: Bool, executable: String?, stat: ExecutableStat?) -> RepeatBudget {
        if engine { return .engine }
        guard let executable, rootOwnedCanonical(executable, stat) else { return .decoy }
        return .tool(device: stat?.device ?? 0, inode: stat?.inode ?? 0)
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

    /// Inserts an untracked pair whose target proved relevant, if the table
    /// has room, and spends one of its tokens.
    func admitPair(source: pid_t, target: pid_t, nowNanos: UInt64) -> PairVerdict {
        lock.lock(); defer { lock.unlock() }
        let lookup = pairs.lookup(key: Pair(source: source, target: target), nowNanos: nowNanos)
        guard let bucket = lookup.entry else {
            pairTableFullCount &+= 1
            return .tableFull
        }
        guard bucket.admit(nowNanos: nowNanos) else {
            pairRefusedCount &+= 1
            return .bucketEmpty
        }
        return lookup.firstSighting ? .first : .repeated
    }

    /// Whether one more signal at a relevant target may be kept on `budget`.
    func admitRepeat(_ budget: RepeatBudget, nowNanos: UInt64) -> Bool {
        lock.lock(); defer { lock.unlock() }
        let admitted: Bool
        switch budget {
        case .engine:
            admitted = engineRepeats.admit(nowNanos: nowNanos)
        case .tool(let device, let inode):
            admitted = toolRepeats.lookup(key: ToolIdentity(device: device, inode: inode), nowNanos: nowNanos)
                .entry?.admit(nowNanos: nowNanos) ?? false
        case .decoy:
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
    private var pairTableFullCount: UInt64 = 0
    private var aggregateRefusedCount: UInt64 = 0

    /// Fatal signals at a relevant target whose tracked (source, target) pair
    /// had no token left. Surfaced as `es_signal_pair_refused_total`.
    var pairRefusedTotal: UInt64 {
        lock.lock(); defer { lock.unlock() }
        return pairRefusedCount
    }

    /// Fatal signals at a relevant target whose new pair a pair table full of
    /// live pairs could not take: refused at a decoy, kept at the engine or a
    /// canonical tool while its repeat budget lasts. Surfaced as
    /// `es_signal_pair_table_full_total`.
    var pairTableFullTotal: UInt64 {
        lock.lock(); defer { lock.unlock() }
        return pairTableFullCount
    }

    /// Fatal signals at a relevant target refused by its repeat budget.
    /// Surfaced as `es_signal_aggregate_refused_total`.
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
