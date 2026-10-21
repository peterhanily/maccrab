// ProcessLineage.swift
// MacCrabCore
//
// Maintains a directed acyclic graph of parent-child process relationships.
// Used by EventEnricher to attach ancestry chains to events without
// relying on the kernel's limited parent pointer (which is lost on exit).

import Foundation

// MARK: - LineageNode

/// Internal node representing a single process in the lineage graph.
struct LineageNode: Sendable {

    /// Process ID.
    let pid: pid_t

    /// Parent process ID. Reset to launchd when the parent's pid is reused,
    /// as the kernel reparents orphans.
    var ppid: pid_t

    /// Full path to the executable on disk.
    let path: String

    /// Base name of the executable.
    let name: String

    /// Full command line.
    let commandLine: String

    /// Code signer type (if known). An unverified `.apple` claim for a
    /// non-platform binary is held as unknown until verification answers.
    var signerType: String?

    /// Timestamp when the process was first observed (exec/fork).
    let startTime: Date

    /// Timestamp when the process exited, or `nil` if still running.
    var exitTime: Date?

    // MARK: v1.10 TraceGraph additions
    //
    // Filled in by `setProcessKey(...)` after the v1.9 collector has
    // recorded the process. v1.9 callers don't set these — they remain
    // nil and the v1.10 skeleton view is unavailable for those nodes.
    // This keeps the LineageNode shape additive: existing tests still
    // pass; v1.10 features only activate when `setProcessKey` is wired
    // by the v1.10 EntityResolver / RollingCausalGraph layer.

    var processKey: String? = nil
    var parentProcessKey: String? = nil
    var signingSummary: ProcessSkeleton.SigningSummary? = nil
}

// MARK: - ProcessLineage

/// Thread-safe process lineage tracker.
///
/// Records process birth and death events and maintains a sliding-window DAG
/// so that ancestor chains can be reconstructed long after parent processes
/// have exited.
public actor ProcessLineage {

    /// Immutable, point-in-time relationship view for a bounded set of PIDs.
    /// SequenceEngine uses one batch per event instead of suspending once or
    /// twice for every partial match. The view preserves `isDescendant`'s exact
    /// semantics (including an untracked immediate parent) and `ancestors`'
    /// stricter sibling semantics (the direct parent itself must be tracked).
    struct RelationshipSnapshot: Sendable {
        fileprivate let ancestorPIDsByPID: [pid_t: Set<pid_t>]
        fileprivate let trackedDirectParentByPID: [pid_t: pid_t]

        func isDescendant(_ pid: pid_t, of ancestor: pid_t) -> Bool {
            ancestorPIDsByPID[pid]?.contains(ancestor) == true
        }

        func areSiblings(_ lhs: pid_t, _ rhs: pid_t) -> Bool {
            guard let lhsParent = trackedDirectParentByPID[lhs],
                  let rhsParent = trackedDirectParentByPID[rhs] else { return false }
            return lhsParent == rhsParent
        }

        /// Bounded checkpoint-facing evidence. The snapshot already caps every
        /// walk at ProcessLineage.maxAncestorDepth; callers apply their own
        /// persisted-field ceiling when merging event-provided ancestry.
        func ancestorPIDs(of pid: pid_t) -> Set<pid_t> {
            ancestorPIDsByPID[pid] ?? []
        }

        /// A numeric event PPID is not proof that the parent node was observed.
        /// Persist the exact tracked edge used by areSiblings instead.
        func trackedDirectParent(of pid: pid_t) -> pid_t? {
            trackedDirectParentByPID[pid]
        }
    }

    struct RelationshipSnapshotDiagnostics: Sendable {
        let requestCount: UInt64
        let requestedPIDCount: UInt64
        let largestBatch: Int
    }

    // MARK: Configuration

    /// How long to retain nodes for exited processes before pruning.
    private let retentionWindow: TimeInterval

    /// Maximum depth when walking the ancestor chain.
    private let maxAncestorDepth: Int

    /// Hard cap on the number of tracked nodes. When exceeded, the oldest
    /// exited process is evicted (falling back to the oldest running process
    /// if all processes are still alive). Prevents unbounded growth from
    /// zombie PIDs accumulating during high-fork-rate workloads.
    private let maxProcessCount: Int

    /// Exited nodes in the order their exits were recorded, so eviction pops
    /// the oldest exit instead of copying and scanning every exited node on
    /// each insert at the cap (about 1 ms per fork, on an actor every event
    /// awaits). An entry is stale once its node is pruned, evicted or its pid
    /// reused (the stored exit time no longer matches); stale entries are
    /// skipped when they reach the front.
    private var exitOrder: [(pid: pid_t, exitTime: Date)] = []
    private var exitOrderHead = 0

    /// Nodes whose exit ES never delivers (it mutes events acted by /System/
    /// images), in insertion order. A spawn loop of short-lived /System/
    /// binaries leaves such nodes "running"; once no recorded exit is left to
    /// evict, eviction checks these for liveness before taking the oldest
    /// running process, which would be launchd, a login shell or an agent's
    /// root. Stale entries are skipped like `exitOrder`'s, and a node still
    /// alive past `livenessGrace` leaves the queue: it is long-lived, and the
    /// liveness sweep marks it once it exits.
    private var unobservedExits: [(pid: pid_t, startTime: Date)] = []
    private var unobservedExitsHead = 0
    private static let maximumLivenessChecksPerEviction = 64

    /// Removed nodes whose children are still tracked, by start time. The
    /// children keep naming the removed pid, so a descendant check bound to it
    /// still holds (an `npm postinstall` shell exits, its detached RAT calls
    /// home). They are reparented to launchd only when another process, which
    /// starts later, takes the pid. The same process recorded again keeps
    /// them: an evicted node that execs, or an exited one re-recorded by its
    /// own late file event.
    private var removedParents: [pid_t: Date] = [:]

    // MARK: Storage

    /// Primary index: pid -> node.
    private var nodes: [pid_t: LineageNode] = [:]

    /// Reverse index: ppid -> set of child pids, for fast child lookups.
    private var childrenIndex: [pid_t: Set<pid_t>] = [:]

    // MARK: Ancestor memoization (Tier-B #16)
    //
    // A live pid's ancestor chain is invariant, so a long-running writer's
    // hundreds of file events would otherwise re-walk + re-allocate the same
    // chain every event. This memo returns the previously computed array.
    //
    // INVALIDATION (detection-exactness): the ENTIRE memo is cleared on any
    // *structural* mutation to the node graph — `recordProcess` (add or
    // pid-reuse overwrite) and `removeNode` (LRU eviction / prune). A per-pid
    // invalidation would be INSUFFICIENT: adding or removing ANY node changes
    // the ancestor chain of that node's *descendants*, not just the node
    // itself (a parent recorded AFTER its child extends the child's chain; a
    // pruned/evicted ancestor shortens every descendant's chain; a pid-reuse
    // overwrite rewrites the chain content). Clearing everything on those two
    // mutations makes a stale chain impossible to observe.
    //
    // `recordExit` deliberately does NOT invalidate: it only sets `exitTime`,
    // which `ancestors(of:)` never reads (the walk uses pid/ppid/path/name and
    // node existence only) and it removes no node — so no ancestors() result
    // changes. `setProcessKey` likewise only touches the v1.10 identity fields
    // the walk doesn't read.
    private var ancestorsMemo: [pid_t: [ProcessAncestor]] = [:]

    /// Operation-count diagnostics for the SequenceEngine batching invariant.
    /// These are internal-only and saturating: observability must not become a
    /// process-lifetime overflow trap.
    private var relationshipSnapshotRequestCount: UInt64 = 0
    private var relationshipSnapshotRequestedPIDCount: UInt64 = 0
    private var relationshipSnapshotLargestBatch = 0

    // MARK: v1.10 TraceGraph promotion buffer
    //
    // When a node carrying a `processKey` is evicted (LRU pressure or
    // retention pruning), its skeleton is captured here so a higher
    // layer (RollingCausalGraph in PR-8) can drain the buffer and
    // promote the skeletons into `CompactPersistentLineage` storage.
    //
    // The buffer is bounded — under a recycle storm, oldest skeletons
    // drop first. The drain cadence is the wiring layer's responsibility.
    //
    // This satisfies the §6.3.1 invariant "silent ancestry loss is not
    // allowed": every evicted node with a processKey has its skeleton
    // captured before discard. There is a brief window between eviction
    // and the next drain where ancestry queries against `tracegraph.db`
    // CompactPersistentLineage would miss the skeleton; the rolling
    // graph in PR-8 keeps the freshly-pending skeletons in its own
    // local view to cover that window.
    private var pendingPromotions: [ProcessSkeleton] = []
    private let pendingPromotionsCap: Int = 1024

    // MARK: Initialization

    /// Creates a new lineage tracker.
    ///
    /// - Parameters:
    ///   - retentionWindow: Duration (in seconds) to keep exited process nodes.
    ///     Defaults to 3600 (1 hour).
    ///   - maxAncestorDepth: Maximum number of ancestors to return when walking
    ///     the parent chain. Defaults to 20.
    // v1.6.22: maxProcessCount default cut from 50_000 → 10_000. LRU eviction
    // prefers exited processes, and a busy machine has ~200–800 live PIDs;
    // 10_000 covers all live PIDs plus a 1-hour retention window of recently-
    // exited ones with comfortable headroom. ~30 MB private heap reclaimed.
    public init(
        retentionWindow: TimeInterval = 3600,
        maxAncestorDepth: Int = 20,
        maxProcessCount: Int = 10_000,
        processIsRunning: @escaping @Sendable (pid_t, Date) -> Bool = ProcessLineage.liveProcessMatches
    ) {
        self.retentionWindow = retentionWindow
        self.maxAncestorDepth = min(
            max(maxAncestorDepth, 1),
            SequenceCheckpointLimits.maximumProcessAncestors
        )
        self.maxProcessCount = maxProcessCount
        self.processIsRunning = processIsRunning
    }

    // MARK: Liveness

    /// Exits that never arrive. ES keeps exec visible through the /System/
    /// process mute but not exit, and can drop an exit under load. Such a node
    /// stayed "running" until evicted, eviction at the cap then removed the
    /// oldest running process (a long-lived ancestor such as the login shell),
    /// and a process that reused the pid adopted its children. `prune` marks
    /// these exited, at most every `livenessSweepInterval`, once they are
    /// `livenessGrace` old; they then leave through the retention path.
    private static let livenessSweepInterval: TimeInterval = 30
    private static let livenessGrace: TimeInterval = 10
    private var lastLivenessSweep: Date?
    private let processIsRunning: @Sendable (pid_t, Date) -> Bool

    /// Whether `pid` is still the process that started at `startTime`. Only
    /// ESRCH proves an exit; a process this daemon may not inspect counts as
    /// running. A node's start time is the birth time ES reports, or for
    /// other sources the moment the process was first seen, which is no
    /// earlier, so a holder that started over a second later reused the pid.
    public static func liveProcessMatches(pid: pid_t, startedAt startTime: Date) -> Bool {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else {
            return errno != ESRCH
        }
        let started = TimeInterval(info.pbi_start_tvsec)
            + TimeInterval(info.pbi_start_tvusec) / 1_000_000
        return started <= startTime.timeIntervalSince1970 + 1
    }

    private func markVanishedProcessesExited() {
        let now = Date()
        if let last = lastLivenessSweep,
           now.timeIntervalSince(last) < Self.livenessSweepInterval {
            return
        }
        lastLivenessSweep = now
        let settled = now.addingTimeInterval(-Self.livenessGrace)
        let vanished = nodes.values.compactMap { node -> pid_t? in
            guard node.exitTime == nil, node.pid > 1, node.startTime < settled,
                  !processIsRunning(node.pid, node.startTime) else { return nil }
            return node.pid
        }
        for pid in vanished {
            nodes[pid]?.exitTime = now
            exitOrder.append((pid, now))
        }
        compactExitOrderIfNeeded()
    }

    // MARK: Recording

    /// Record a new process (exec or fork).
    ///
    /// If a node with the same pid already exists (pid reuse), the old node
    /// is replaced and the children index is updated accordingly.
    ///
    /// - Parameters:
    ///   - pid: Process ID of the new process.
    ///   - ppid: Parent process ID.
    ///   - path: Full executable path.
    ///   - name: Process name (basename).
    ///   - startTime: Time the process was observed starting.
    public func recordProcess(
        pid: pid_t,
        ppid: pid_t,
        path: String,
        name: String,
        startTime: Date,
        commandLine: String = "",
        signerType: String? = nil
    ) {
        // If this pid was previously tracked (pid reuse), clean up old entry.
        if let old = nodes[pid] {
            childrenIndex[old.ppid]?.remove(pid)
            // A pid whose process was seen exiting has been reused. Its old
            // children still name it as parent; walking them would climb into
            // the new, unrelated process (e.g. a `claude` that took the pid
            // and made a long-lived orphan an "AI child"). The kernel
            // reparented them to launchd; mirror that.
            // A running node whose exit never arrived (a muted /System/ exit)
            // is reused too when the new process started later.
            if old.exitTime != nil || abs(old.startTime.timeIntervalSince(startTime)) > 1 {
                adoptOrphans(of: pid)
            }
        } else if let removedStart = removedParents.removeValue(forKey: pid),
                  abs(removedStart.timeIntervalSince(startTime)) > 1 {
            adoptOrphans(of: pid)
        }

        let node = LineageNode(
            pid: pid,
            ppid: ppid,
            path: path,
            name: name,
            commandLine: commandLine,
            signerType: signerType,
            startTime: startTime,
            exitTime: nil
        )

        nodes[pid] = node
        childrenIndex[ppid, default: []].insert(pid)
        if path.hasPrefix("/System/") {
            unobservedExits.append((pid, startTime))
            compactUnobservedExitsIfNeeded()
        }

        // Structural change: a new/overwritten node can alter the ancestor
        // chain of any descendant. Drop the whole memo. (See ancestorsMemo.)
        invalidateAncestorsMemo()

        if nodes.count > maxProcessCount {
            evictLRUProcess()
        }
    }

    /// The children of a pid whose process is gone were reparented to launchd
    /// by the kernel; mirror that before another process takes the pid.
    private func adoptOrphans(of pid: pid_t) {
        guard let orphans = childrenIndex.removeValue(forKey: pid) else { return }
        for child in orphans where nodes[child]?.ppid == pid {
            nodes[child]?.ppid = 1
            childrenIndex[1, default: []].insert(child)
        }
    }

    /// Clear the ancestor memo. Called on every structural mutation to the
    /// node graph so `ancestors(of:)` can never return a stale chain.
    private func invalidateAncestorsMemo() {
        ancestorsMemo.removeAll(keepingCapacity: true)
    }

    /// Evict one process to stay within `maxProcessCount`.
    /// Prefers the exited process with the oldest exit time; falls back to the
    /// running process with the oldest start time.
    private func evictLRUProcess() {
        // Prefer an exited process (least valuable for lineage queries)
        while exitOrderHead < exitOrder.count {
            let entry = exitOrder[exitOrderHead]
            exitOrderHead += 1
            if let node = nodes[entry.pid], node.exitTime == entry.exitTime {
                removeNode(pid: entry.pid)
                compactExitOrderIfNeeded()
                return
            }
        }
        compactExitOrderIfNeeded()
        if evictVanishedUnobservedProcess() { return }
        if let victim = nodes.values.min(by: { $0.startTime < $1.startTime }) {
            removeNode(pid: victim.pid)
        }
    }

    /// Evict the first exit-unobservable node found dead. A live node younger
    /// than `livenessGrace` goes to the back of the queue, at most
    /// `maximumLivenessChecksPerEviction` per eviction; an older live node
    /// leaves the queue for good, so the hundreds of long-lived /System/
    /// processes in a session cost one check each instead of using up every
    /// eviction's budget and letting it fall back to launchd.
    private func evictVanishedUnobservedProcess() -> Bool {
        var rotations = 0
        let settled = Date().addingTimeInterval(-Self.livenessGrace)
        let pending = unobservedExits.count - unobservedExitsHead
        defer { compactUnobservedExitsIfNeeded() }
        for _ in 0..<pending where rotations < Self.maximumLivenessChecksPerEviction {
            let entry = unobservedExits[unobservedExitsHead]
            unobservedExitsHead += 1
            guard let node = nodes[entry.pid], node.exitTime == nil,
                  node.startTime == entry.startTime else { continue }
            if !processIsRunning(entry.pid, entry.startTime) {
                removeNode(pid: entry.pid)
                return true
            }
            if entry.startTime >= settled {
                rotations += 1
                unobservedExits.append(entry)
            }
        }
        return false
    }

    private func compactUnobservedExitsIfNeeded() {
        if unobservedExitsHead > 0, unobservedExitsHead * 2 >= unobservedExits.count {
            unobservedExits.removeFirst(unobservedExitsHead)
            unobservedExitsHead = 0
        }
        // At most one valid entry per node, so dropping stale (pruned,
        // exited, reused) and repeated (an exec re-recording the node) ones
        // keeps the queue below the bound.
        if unobservedExits.count > 2 * maxProcessCount + 1_024 {
            var queued = Set<pid_t>()
            unobservedExits = unobservedExits[unobservedExitsHead...].filter { entry in
                guard let node = nodes[entry.pid], node.exitTime == nil,
                      node.startTime == entry.startTime else { return false }
                return queued.insert(entry.pid).inserted
            }
            unobservedExitsHead = 0
        }
    }

    /// Drop consumed entries, and rebuild from the live exited nodes if
    /// stale entries (pruned or reused pids behind the front) pile up.
    private func compactExitOrderIfNeeded() {
        if exitOrderHead > 0, exitOrderHead * 2 >= exitOrder.count {
            exitOrder.removeFirst(exitOrderHead)
            exitOrderHead = 0
        }
        if exitOrder.count > 2 * maxProcessCount + 1_024 {
            exitOrder = nodes.values.compactMap { node in
                node.exitTime.map { (node.pid, $0) }
            }.sorted { $0.exitTime < $1.exitTime }
            exitOrderHead = 0
        }
    }

    private func removeNode(pid: pid_t) {
        guard let node = nodes.removeValue(forKey: pid) else { return }
        // v1.10 TraceGraph: capture a skeleton for promotion before
        // discarding the node, so ancestry doesn't silently disappear
        // when LRU pressure or pruning evicts a process the rolling
        // graph still cares about. Only nodes that have been enriched
        // with a processKey participate; v1.9-only nodes (no processKey)
        // are evicted as before.
        if let processKey = node.processKey {
            let skeleton = ProcessSkeleton(
                processKey: processKey,
                pid: node.pid,
                ppid: node.ppid,
                startTime: node.startTime,
                executablePath: node.path,
                parentProcessKey: node.parentProcessKey,
                signingSummary: node.signingSummary,
                firstSeen: node.startTime,
                lastSeen: node.exitTime ?? node.startTime
            )
            pendingPromotions.append(skeleton)
            if pendingPromotions.count > pendingPromotionsCap {
                pendingPromotions.removeFirst(pendingPromotions.count - pendingPromotionsCap)
            }
        }
        childrenIndex[node.ppid]?.remove(pid)
        if childrenIndex[node.ppid]?.isEmpty == true {
            childrenIndex.removeValue(forKey: node.ppid)
            if nodes[node.ppid] == nil { removedParents.removeValue(forKey: node.ppid) }
        }
        // The children keep the removed pid as their parent; see
        // `removedParents`.
        if childrenIndex[pid]?.isEmpty == false {
            removedParents[pid] = node.startTime
        }

        // Removing a node shortens the chain of any descendant that walked
        // through it. Drop the whole memo. (See ancestorsMemo.)
        invalidateAncestorsMemo()
    }

    // MARK: - v1.10 TraceGraph public surface

    /// Attach v1.10 identity fields to an already-recorded process.
    /// Called by the EntityResolver / RollingCausalGraph layer after
    /// the v1.9 collector path has called `recordProcess`. Idempotent —
    /// repeat calls overwrite previous values, which matches the
    /// "latest observation wins" semantics elsewhere in the lineage.
    public func setProcessKey(
        pid: pid_t,
        processKey: String,
        parentProcessKey: String? = nil,
        signingSummary: ProcessSkeleton.SigningSummary? = nil
    ) {
        guard nodes[pid] != nil else { return }
        nodes[pid]?.processKey = processKey
        nodes[pid]?.parentProcessKey = parentProcessKey
        nodes[pid]?.signingSummary = signingSummary
    }

    /// Materialize a `ProcessSkeleton` view for a tracked process, if
    /// the v1.10 identity fields have been set. Returns nil for nodes
    /// that have only the v1.9 fields (no processKey).
    public func skeleton(forPid pid: pid_t) -> ProcessSkeleton? {
        guard let node = nodes[pid], let processKey = node.processKey else { return nil }
        return ProcessSkeleton(
            processKey: processKey,
            pid: node.pid,
            ppid: node.ppid,
            startTime: node.startTime,
            executablePath: node.path,
            parentProcessKey: node.parentProcessKey,
            signingSummary: node.signingSummary,
            firstSeen: node.startTime,
            lastSeen: node.exitTime ?? node.startTime
        )
    }

    /// Drain the pending-promotion buffer. Returned skeletons should
    /// be passed to `CompactPersistentLineage.promote(_:)` by the
    /// caller; the buffer is cleared as a side effect.
    public func drainPendingPromotions() -> [ProcessSkeleton] {
        let drained = pendingPromotions
        pendingPromotions.removeAll(keepingCapacity: true)
        return drained
    }

    /// Diagnostic surface for v1.10 wiring tests.
    public var pendingPromotionCount: Int { pendingPromotions.count }

    /// Queued exit-unobservable entries, for the bound test.
    var unobservedExitQueueLength: Int { unobservedExits.count - unobservedExitsHead }

    /// Record that a process has exited.
    ///
    /// The node is not immediately removed; it is retained until the next
    /// `prune()` pass finds it older than the retention window.
    ///
    /// - Parameter pid: Process ID of the exiting process.
    public func recordExit(pid: pid_t) {
        guard nodes[pid] != nil else { return }
        let now = Date()
        nodes[pid]?.exitTime = now
        exitOrder.append((pid, now))
        compactExitOrderIfNeeded()
    }

    // MARK: Queries

    /// Walk the parent chain and return an ordered array of ancestors,
    /// starting with the direct parent.
    ///
    /// Stops when:
    /// - The parent is not found in the graph.
    /// - `maxAncestorDepth` is reached.
    /// - A cycle is detected (should not happen in a DAG, but guards against
    ///   corrupted data).
    ///
    /// - Parameter pid: The process whose ancestry to retrieve.
    /// - Returns: Ordered ancestor list from direct parent outward.
    public func ancestors(of pid: pid_t) -> [ProcessAncestor] {
        // Tier-B #16: return the memoized chain if present. The memo is
        // cleared on every structural graph mutation (see ancestorsMemo), so
        // a hit is byte-identical to a fresh walk. Caching the empty result is
        // safe too: a parent recorded later triggers `recordProcess` →
        // invalidate, so the next call re-walks.
        if let cached = ancestorsMemo[pid] { return cached }

        var result: [ProcessAncestor] = []
        var visited: Set<pid_t> = [pid]
        var currentPid = pid

        for _ in 0 ..< maxAncestorDepth {
            guard let node = nodes[currentPid] else { break }
            let parentPid = node.ppid

            // Guard against cycles and self-parenting (pid 0 or 1).
            guard parentPid != currentPid, !visited.contains(parentPid) else { break }

            guard let parent = nodes[parentPid] else { break }
            result.append(ProcessAncestor(
                pid: parent.pid,
                executable: parent.path,
                name: parent.name
            ))

            visited.insert(parentPid)
            currentPid = parentPid
        }

        // Defensive bound: the memo is normally kept small by clearing on every
        // structural mutation, but in a mutation-free window with many distinct
        // queried pids it could otherwise grow. Cap it at the same ceiling as
        // the node graph itself. (Correctness is unaffected — this only drops
        // cached entries, which are recomputed on demand.)
        if ancestorsMemo.count >= maxProcessCount {
            ancestorsMemo.removeAll(keepingCapacity: true)
        }
        ancestorsMemo[pid] = result
        return result
    }

    /// Check whether a process with the given pid is tracked in the graph.
    ///
    /// - Parameter pid: Process ID to look up.
    /// - Returns: `true` if the process has been recorded and not yet pruned.
    public func contains(pid: pid_t) -> Bool {
        nodes[pid] != nil
    }

    /// Return the set of direct child pids for a given process.
    ///
    /// - Parameter pid: The parent process ID.
    /// - Returns: Array of child pids (order is not guaranteed).
    public func children(of pid: pid_t) -> [pid_t] {
        Array(childrenIndex[pid] ?? [])
    }

    /// Check whether `pid` is a descendant of `ancestor` anywhere in the chain.
    ///
    /// Walks up the parent chain from `pid` (max `maxAncestorDepth` steps).
    ///
    /// - Parameters:
    ///   - pid: The potential descendant.
    ///   - ancestor: The potential ancestor.
    /// - Returns: `true` if `ancestor` appears in the parent chain of `pid`.
    public func isDescendant(_ pid: pid_t, of ancestor: pid_t) -> Bool {
        var visited: Set<pid_t> = [pid]
        var currentPid = pid

        for _ in 0 ..< maxAncestorDepth {
            guard let node = nodes[currentPid] else { return false }
            let parentPid = node.ppid

            if parentPid == ancestor { return true }
            guard parentPid != currentPid, !visited.contains(parentPid) else { return false }

            visited.insert(parentPid)
            currentPid = parentPid
        }

        return false
    }

    /// Resolve all ancestry needed by one evaluation in a single actor hop.
    /// Each requested PID is walked at most once and every walk is bounded by
    /// `maxAncestorDepth`. The returned value never observes a mix of lineage
    /// generations, unlike thousands of individually awaited queries.
    func relationshipSnapshot(for pids: Set<pid_t>) -> RelationshipSnapshot {
        if relationshipSnapshotRequestCount < UInt64.max {
            relationshipSnapshotRequestCount += 1
        }
        let requested = UInt64(pids.count)
        if relationshipSnapshotRequestedPIDCount > UInt64.max - requested {
            relationshipSnapshotRequestedPIDCount = UInt64.max
        } else {
            relationshipSnapshotRequestedPIDCount += requested
        }
        relationshipSnapshotLargestBatch = max(relationshipSnapshotLargestBatch, pids.count)

        var ancestorPIDsByPID: [pid_t: Set<pid_t>] = [:]
        var trackedDirectParentByPID: [pid_t: pid_t] = [:]
        let trackedCapacity = min(pids.count, nodes.count)
        ancestorPIDsByPID.reserveCapacity(trackedCapacity)
        trackedDirectParentByPID.reserveCapacity(trackedCapacity)

        for pid in pids {
            // A partial can outlive its ProcessLineage node. Avoid allocating a
            // visited set for each such miss when the partial pool is saturated.
            guard nodes[pid] != nil else { continue }
            var ancestors: Set<pid_t> = []
            var visited: Set<pid_t> = [pid]
            var currentPid = pid

            for depth in 0 ..< maxAncestorDepth {
                guard let node = nodes[currentPid] else { break }
                let parentPid = node.ppid

                // `isDescendant` checks equality before its cycle guard, so an
                // untracked parent (and even a corrupt cycle edge) remains a
                // positive one-hop relationship. Record before stopping.
                ancestors.insert(parentPid)

                if depth == 0,
                   parentPid != currentPid,
                   !visited.contains(parentPid),
                   nodes[parentPid] != nil {
                    // `ancestors(of:)`, used by sibling checks, only exposes a
                    // direct parent when that parent node is itself tracked.
                    trackedDirectParentByPID[pid] = parentPid
                }

                guard parentPid != currentPid, !visited.contains(parentPid) else { break }
                visited.insert(parentPid)
                currentPid = parentPid
            }
            if !ancestors.isEmpty {
                ancestorPIDsByPID[pid] = ancestors
            }
        }

        return RelationshipSnapshot(
            ancestorPIDsByPID: ancestorPIDsByPID,
            trackedDirectParentByPID: trackedDirectParentByPID
        )
    }

    func relationshipSnapshotDiagnostics() -> RelationshipSnapshotDiagnostics {
        RelationshipSnapshotDiagnostics(
            requestCount: relationshipSnapshotRequestCount,
            requestedPIDCount: relationshipSnapshotRequestedPIDCount,
            largestBatch: relationshipSnapshotLargestBatch
        )
    }

    // MARK: Maintenance

    /// Remove exited processes whose exit time is older than the retention window.
    ///
    /// Should be called periodically (e.g. every few minutes) to bound memory
    /// usage. Running processes (exitTime == nil) are never pruned.
    public func prune() {
        markVanishedProcessesExited()
        let cutoff = Date().addingTimeInterval(-retentionWindow)
        var pidsToRemove: [pid_t] = []

        for (pid, node) in nodes {
            if let exitTime = node.exitTime, exitTime < cutoff {
                pidsToRemove.append(pid)
            }
        }

        for pid in pidsToRemove {
            // Also remove any children index entry keyed by this pid.
            // The child nodes themselves are not removed (they remain in `nodes`
            // and will be pruned on their own schedule).
            removeNode(pid: pid)
        }
    }

    /// Get the command line for a specific process (if tracked).
    public func commandLine(of pid: pid_t) -> String? {
        nodes[pid]?.commandLine.isEmpty == false ? nodes[pid]?.commandLine : nil
    }

    /// Get the signer type for a specific process (if tracked).
    /// Records a verified signer for a tracked process. A pid since reused by
    /// another executable keeps its own node.
    public func recordVerifiedSignerType(pid: pid_t, path: String, signerType: String) {
        guard var node = nodes[pid], node.path == path, node.signerType != signerType else {
            return
        }
        node.signerType = signerType
        nodes[pid] = node
    }

    public func signerType(of pid: pid_t) -> String? {
        nodes[pid]?.signerType
    }

    /// Get info about the parent of a process.
    public func parentInfo(of pid: pid_t) -> (commandLine: String?, signerType: String?, path: String?)? {
        guard let node = nodes[pid], let parent = nodes[node.ppid] else { return nil }
        return (
            parent.commandLine.isEmpty ? nil : parent.commandLine,
            parent.signerType,
            parent.path
        )
    }

    /// Combined accessor (Tier-B #10): return the ancestor chain AND the
    /// direct parent's enrichment fields in a single actor hop.
    ///
    /// Semantically identical to calling `ancestors(of:)` and
    /// `parentInfo(of:)` separately — it literally calls both — but crosses
    /// the actor boundary once instead of twice. Because both reads happen in
    /// one non-suspending actor section they also observe a single consistent
    /// graph snapshot (the two separate `await`s could straddle a concurrent
    /// mutation); that is strictly more consistent, never less.
    public func ancestorsAndParentInfo(of pid: pid_t)
        -> (ancestors: [ProcessAncestor], parentInfo: (commandLine: String?, signerType: String?, path: String?)?) {
        (ancestors(of: pid), parentInfo(of: pid))
    }

    // MARK: Node Lookup

    /// Return the process name for a given pid, or nil if not tracked.
    public func name(of pid: pid_t) -> String? {
        nodes[pid]?.name
    }

    /// Return the executable path for a given pid, or nil if not tracked.
    public func path(of pid: pid_t) -> String? {
        nodes[pid]?.path
    }

    // MARK: Diagnostics

    /// The number of nodes currently tracked (for monitoring / tests).
    public var nodeCount: Int {
        nodes.count
    }
}
