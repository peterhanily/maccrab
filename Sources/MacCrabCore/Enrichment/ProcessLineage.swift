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

    /// Parent process ID.
    let ppid: pid_t

    /// Full path to the executable on disk.
    let path: String

    /// Base name of the executable.
    let name: String

    /// Full command line.
    let commandLine: String

    /// Code signer type (if known).
    let signerType: String?

    /// Timestamp when the process was first observed (exec/fork).
    let startTime: Date

    /// Timestamp when the process exited, or `nil` if still running.
    var exitTime: Date?
}

// MARK: - ProcessLineage

/// Thread-safe process lineage tracker.
///
/// Records process birth and death events and maintains a sliding-window DAG
/// so that ancestor chains can be reconstructed long after parent processes
/// have exited.
public actor ProcessLineage {

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

    // MARK: Storage

    /// Primary index: pid -> node.
    private var nodes: [pid_t: LineageNode] = [:]

    /// Reverse index: ppid -> set of child pids, for fast child lookups.
    private var childrenIndex: [pid_t: Set<pid_t>] = [:]

    // MARK: Initialization

    /// Creates a new lineage tracker.
    ///
    /// - Parameters:
    ///   - retentionWindow: Duration (in seconds) to keep exited process nodes.
    ///     Defaults to 3600 (1 hour).
    ///   - maxAncestorDepth: Maximum number of ancestors to return when walking
    ///     the parent chain. Defaults to 20.
    public init(retentionWindow: TimeInterval = 3600, maxAncestorDepth: Int = 20, maxProcessCount: Int = 50_000) {
        self.retentionWindow = retentionWindow
        self.maxAncestorDepth = maxAncestorDepth
        self.maxProcessCount = maxProcessCount
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

        if nodes.count > maxProcessCount {
            evictLRUProcess()
        }
    }

    /// Evict one process to stay within `maxProcessCount`.
    /// Prefers the exited process with the oldest exit time; falls back to the
    /// running process with the oldest start time.
    private func evictLRUProcess() {
        // Prefer an exited process (least valuable for lineage queries)
        if let victim = nodes.values.filter({ $0.exitTime != nil }).min(by: { ($0.exitTime ?? .distantPast) < ($1.exitTime ?? .distantPast) }) {
            removeNode(pid: victim.pid)
        } else if let victim = nodes.values.min(by: { $0.startTime < $1.startTime }) {
            removeNode(pid: victim.pid)
        }
    }

    private func removeNode(pid: pid_t) {
        guard let node = nodes.removeValue(forKey: pid) else { return }
        childrenIndex[node.ppid]?.remove(pid)
        if childrenIndex[node.ppid]?.isEmpty == true {
            childrenIndex.removeValue(forKey: node.ppid)
        }
        childrenIndex.removeValue(forKey: pid)
    }

    /// Record that a process has exited.
    ///
    /// The node is not immediately removed; it is retained until the next
    /// `prune()` pass finds it older than the retention window.
    ///
    /// - Parameter pid: Process ID of the exiting process.
    public func recordExit(pid: pid_t) {
        guard nodes[pid] != nil else { return }
        nodes[pid]?.exitTime = Date()
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

    // MARK: Maintenance

    /// Remove exited processes whose exit time is older than the retention window.
    ///
    /// Should be called periodically (e.g. every few minutes) to bound memory
    /// usage. Running processes (exitTime == nil) are never pruned.
    public func prune() {
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
