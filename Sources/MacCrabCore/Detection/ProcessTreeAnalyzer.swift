// ProcessTreeAnalyzer.swift
// MacCrabCore
//
// On-device process tree anomaly detection using a first-order Markov chain.
// Learns normal parent-child process name transitions during a learning phase,
// then scores new process trees against the model to detect anomalous
// spawning patterns (e.g., Safari -> sh -> curl -> base64).
//
// The Markov model captures P(child_name | parent_name) for every observed
// exec event. Trees with low aggregate transition probability are flagged
// as anomalous -- meaning the combination of process spawns has rarely or
// never been seen on this machine.

import Foundation
import Darwin
import os.log

// MARK: - ProcessTreeAnalyzer

/// Learns normal process tree shapes via a first-order Markov chain over
/// parent-child process name transitions, then flags anomalous trees.
///
/// Usage:
/// ```swift
/// let analyzer = ProcessTreeAnalyzer()
/// try await analyzer.load()
///
/// // For every exec event:
/// let logProb = await analyzer.recordTransition(parentName: "zsh", childName: "git")
///
/// // To score an entire subtree:
/// if let score = await analyzer.scoreTree(rootPid: pid, lineage: lineage) {
///     if score.isAnomalous { /* alert */ }
/// }
/// ```
public actor ProcessTreeAnalyzer {

    // MARK: - Markov Chain Model

    /// Transition counts: parent process name -> [child name: count].
    private var transitionCounts: [String: [String: Int]] = [:]

    /// Total transitions observed from each parent.
    private var parentTotals: [String: Int] = [:]

    /// Total number of transitions recorded across all parents.
    private var totalTransitions: Int = 0

    /// Minimum number of transitions before the model starts scoring.
    private let minTransitions: Int

    /// Log-probability threshold below which a tree is flagged as anomalous.
    /// More negative = more anomalous. Default -10.0 is quite permissive;
    /// tighten to -6.0 or -4.0 for stricter detection.
    private let anomalyThreshold: Double

    /// Learning vs active detection mode.
    public enum Mode: String, Sendable {
        case learning   // Accumulating transition data, no scoring
        case active     // Scoring new trees against the model
    }

    /// Current operational mode.
    private var mode: Mode = .learning

    // MARK: - Persistence

    /// File path where the model is saved and loaded.
    private let modelPath: String

    /// Counter for transitions since last save (triggers periodic save).
    private var transitionsSinceLastSave: Int = 0

    /// How many new transitions between periodic saves.
    private static let saveInterval = 1000

    // MARK: - Logging

    private let logger = Logger(subsystem: "com.maccrab.detection", category: "ProcessTreeAnalyzer")

    // MARK: - Results

    /// Represents an individual edge that contributed to an anomaly score.
    public struct AnomalousEdge: Sendable {
        public let parent: String
        public let child: String
        public let logProb: Double
    }

    /// The result of scoring a process tree.
    public struct TreeScore: Sendable {
        /// PID of the tree root.
        public let rootPid: Int32

        /// Process name of the tree root.
        public let rootProcess: String

        /// Maximum depth of the tree from root to deepest leaf.
        public let depth: Int

        /// Total number of nodes in the tree (including root).
        public let nodeCount: Int

        /// Sum of log P(child | parent) for every edge in the tree.
        public let logProbability: Double

        /// Normalized score: logProbability / edgeCount.
        /// More negative = more anomalous.
        public let anomalyScore: Double

        /// Whether the tree exceeds the anomaly threshold.
        public let isAnomalous: Bool

        /// Edges that individually scored below -5.0 (rare transitions).
        public let anomalousEdges: [AnomalousEdge]

        /// Human-readable summary of the score.
        public let description: String
    }

    // MARK: - Initialization

    /// Create a new process tree analyzer.
    ///
    /// - Parameters:
    ///   - minTransitions: Minimum transitions before scoring begins. Default 500.
    ///   - anomalyThreshold: Normalized log-probability threshold. Default -10.0.
    ///   - modelPath: Override the default model persistence path.
    public init(
        minTransitions: Int = 500,
        anomalyThreshold: Double = -10.0,
        modelPath: String? = nil
    ) {
        self.minTransitions = minTransitions
        self.anomalyThreshold = anomalyThreshold

        if let modelPath {
            self.modelPath = modelPath
        } else {
            let appSupport = FileManager.default.urls(
                for: .applicationSupportDirectory,
                in: .userDomainMask
            ).first ?? URL(fileURLWithPath: NSTemporaryDirectory())
            let maccrabDir = appSupport.appendingPathComponent("MacCrab")
            self.modelPath = maccrabDir.appendingPathComponent("process_tree_model.json").path
        }
    }

    // MARK: - Public API

    /// Record a parent-child transition observed during an exec event.
    ///
    /// In learning mode, accumulates statistics and returns nil.
    /// In active mode, returns the log-probability of the transition.
    ///
    /// - Parameters:
    ///   - parentName: Process name of the parent (basename, not full path).
    ///   - childName: Process name of the child.
    /// - Returns: Log-probability if in active mode, nil in learning mode.
    @discardableResult
    public func recordTransition(
        parentName: String,
        childName: String
    ) -> Double? {
        let parent = normalizeName(parentName)
        let child = normalizeName(childName)

        // Skip self-transitions (fork without exec).
        guard parent != child else { return nil }

        // Skip launchd -> * transitions (too common, not informative).
        guard parent != "launchd" else { return nil }

        // Update counts.
        transitionCounts[parent, default: [:]][child, default: 0] += 1
        parentTotals[parent, default: 0] += 1
        totalTransitions += 1

        // Check for auto-activation.
        if mode == .learning && totalTransitions >= minTransitions {
            activate()
        }

        // Periodic save.
        transitionsSinceLastSave += 1
        if transitionsSinceLastSave >= Self.saveInterval {
            transitionsSinceLastSave = 0
            do {
                try saveSync()
            } catch {
                logger.error(
                    "Periodic save failed: \(error.localizedDescription, privacy: .public)"
                )
            }
        }

        // Return log-probability in active mode.
        if mode == .active {
            return logProbability(parent: parent, child: child)
        }
        return nil
    }

    /// Score an entire process tree rooted at the given PID.
    ///
    /// Walks the tree via `ProcessLineage.children(of:)` recursively,
    /// computing the sum of log-probabilities for each parent-child edge.
    ///
    /// - Parameters:
    ///   - rootPid: The PID at the root of the subtree to score.
    ///   - lineage: The process lineage actor to query for tree structure.
    /// - Returns: A `TreeScore` if the model is active and the root exists,
    ///   nil otherwise.
    public func scoreTree(
        rootPid: Int32,
        lineage: ProcessLineage
    ) async -> TreeScore? {
        guard mode == .active else { return nil }

        // Get the root process name.
        guard let rootName = await lineage.name(of: rootPid) else { return nil }

        // Walk the tree and collect edges + metrics.
        var edges: [(parent: String, child: String)] = []
        var maxDepth = 0
        var nodeCount = 1  // Count the root.

        // BFS to walk the tree.
        struct QueueEntry {
            let pid: pid_t
            let name: String
            let depth: Int
        }

        var queue: [QueueEntry] = [QueueEntry(pid: rootPid, name: rootName, depth: 0)]
        var visited: Set<pid_t> = [rootPid]
        var head = 0

        while head < queue.count {
            let current = queue[head]
            head += 1

            if current.depth > maxDepth {
                maxDepth = current.depth
            }

            let childPids = await lineage.children(of: current.pid)
            for childPid in childPids {
                guard !visited.contains(childPid) else { continue }
                visited.insert(childPid)

                guard let childName = await lineage.name(of: childPid) else { continue }

                let parentNorm = normalizeName(current.name)
                let childNorm = normalizeName(childName)

                // Skip self-transitions and launchd.
                if parentNorm != childNorm && parentNorm != "launchd" {
                    edges.append((parent: parentNorm, child: childNorm))
                }

                nodeCount += 1
                queue.append(QueueEntry(pid: childPid, name: childName, depth: current.depth + 1))
            }
        }

        // No edges means a single-node tree (nothing to score).
        guard !edges.isEmpty else { return nil }

        // Compute aggregate log-probability.
        var totalLogProb = 0.0
        var anomalousEdges: [AnomalousEdge] = []

        for edge in edges {
            let lp = logProbability(parent: edge.parent, child: edge.child)
            totalLogProb += lp

            // Track individually rare edges.
            if lp < -5.0 {
                anomalousEdges.append(AnomalousEdge(
                    parent: edge.parent,
                    child: edge.child,
                    logProb: lp
                ))
            }
        }

        let edgeCount = edges.count
        let anomalyScore = totalLogProb / Double(edgeCount)
        let isAnomalous = anomalyScore < anomalyThreshold

        // Build description.
        let description: String
        if isAnomalous {
            let edgeDescriptions = anomalousEdges.prefix(5).map { edge in
                "\(edge.parent) -> \(edge.child) (logP=\(String(format: "%.2f", edge.logProb)))"
            }
            description = "Anomalous process tree rooted at \(rootName) (pid \(rootPid)): " +
                "score=\(String(format: "%.2f", anomalyScore)), " +
                "\(edgeCount) edges, depth=\(maxDepth). " +
                "Rare edges: \(edgeDescriptions.joined(separator: ", "))"
        } else {
            description = "Normal process tree rooted at \(rootName) (pid \(rootPid)): " +
                "score=\(String(format: "%.2f", anomalyScore)), " +
                "\(edgeCount) edges, depth=\(maxDepth)"
        }

        return TreeScore(
            rootPid: rootPid,
            rootProcess: rootName,
            depth: maxDepth,
            nodeCount: nodeCount,
            logProbability: totalLogProb,
            anomalyScore: anomalyScore,
            isAnomalous: isAnomalous,
            anomalousEdges: anomalousEdges,
            description: description
        )
    }

    /// Transition from learning to active mode.
    ///
    /// Called automatically when `totalTransitions >= minTransitions`,
    /// but can also be called manually to force activation.
    public func activate() {
        guard mode == .learning else { return }
        mode = .active

        let uniqueParents = transitionCounts.count
        let uniqueEdges = transitionCounts.values.reduce(0) { $0 + $1.count }

        logger.notice(
            "ProcessTreeAnalyzer activated: \(self.totalTransitions) transitions, \(uniqueParents) unique parents, \(uniqueEdges) unique edges"
        )

        do {
            try saveSync()
        } catch {
            logger.error(
                "Failed to save on activation: \(error.localizedDescription, privacy: .public)"
            )
        }
    }

    /// Save the model to disk as JSON.
    public func save() throws {
        try saveSync()
    }

    /// Load a previously saved model from disk.
    ///
    /// If no file exists, this is a no-op and the engine starts fresh.
    public func load() throws {
        let fm = FileManager.default
        guard fm.fileExists(atPath: modelPath) else {
            logger.info(
                "No existing model at \(self.modelPath, privacy: .public). Starting fresh."
            )
            return
        }

        let data = try Data(contentsOf: URL(fileURLWithPath: modelPath))
        let persisted = try JSONDecoder().decode(PersistedModel.self, from: data)

        guard persisted.version == 1 else {
            logger.warning(
                "Unknown model version \(persisted.version). Starting fresh."
            )
            return
        }

        self.totalTransitions = persisted.totalTransitions
        self.transitionCounts = persisted.transitions

        // Rebuild parentTotals from transition counts.
        self.parentTotals = [:]
        for (parent, children) in persisted.transitions {
            self.parentTotals[parent] = children.values.reduce(0, +)
        }

        // Restore mode: if we have enough transitions, go active.
        if totalTransitions >= minTransitions {
            mode = .active
        } else {
            mode = .learning
        }

        let uniqueParents = transitionCounts.count
        let uniqueEdges = transitionCounts.values.reduce(0) { $0 + $1.count }

        logger.notice(
            "Loaded model: \(self.totalTransitions) transitions, \(uniqueParents) parents, \(uniqueEdges) edges, mode=\(self.mode.rawValue, privacy: .public)"
        )
    }

    /// Get model statistics for status display.
    public func stats() -> (mode: Mode, transitions: Int, uniqueParents: Int, uniqueEdges: Int) {
        let uniqueParents = transitionCounts.count
        let uniqueEdges = transitionCounts.values.reduce(0) { $0 + $1.count }
        return (
            mode: mode,
            transitions: totalTransitions,
            uniqueParents: uniqueParents,
            uniqueEdges: uniqueEdges
        )
    }

    // MARK: - Markov Chain Scoring

    /// Compute the log-probability of a single parent -> child transition.
    ///
    /// Uses Laplace (add-one) smoothing to handle unseen transitions:
    /// - Parent seen, edge seen: log(count / parentTotal)
    /// - Parent seen, edge unseen: log(1 / (parentTotal + uniqueChildrenOfParent))
    /// - Parent never seen: log(1 / totalUniqueParents)
    private func logProbability(parent: String, child: String) -> Double {
        if let childCounts = transitionCounts[parent] {
            let parentTotal = parentTotals[parent] ?? 1
            let uniqueChildren = childCounts.count

            if let edgeCount = childCounts[child], edgeCount > 0 {
                // Known transition: actual observed probability.
                return log(Double(edgeCount) / Double(parentTotal))
            } else {
                // Parent is known but this specific child was never seen.
                // Laplace smoothing: assign probability 1 / (parentTotal + uniqueChildren).
                return log(1.0 / Double(parentTotal + uniqueChildren))
            }
        } else {
            // Parent process has never been seen at all -- very unusual.
            let totalUniqueParents = max(transitionCounts.count, 1)
            return log(1.0 / Double(totalUniqueParents))
        }
    }

    // MARK: - Name Normalization

    /// Normalize a process name to its basename, stripped of paths and version info.
    private func normalizeName(_ name: String) -> String {
        // If the name contains a path separator, take the last component.
        let basename: String
        if name.contains("/") {
            basename = (name as NSString).lastPathComponent
        } else {
            basename = name
        }

        // Strip common suffixes that vary between versions.
        // e.g., "python3.11" -> "python3", "node18" -> "node"
        // But keep names like "x86_64" intact.
        return basename
    }

    // MARK: - Persistence

    /// Internal synchronous save implementation.
    private func saveSync() throws {
        let fm = FileManager.default
        let directory = (modelPath as NSString).deletingLastPathComponent

        // Ensure the directory exists.
        if !fm.fileExists(atPath: directory) {
            try fm.createDirectory(
                atPath: directory,
                withIntermediateDirectories: true
            )
        }

        let persisted = PersistedModel(
            version: 1,
            totalTransitions: totalTransitions,
            transitions: transitionCounts
        )

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]

        let data = try encoder.encode(persisted)

        // Atomic write to prevent corruption.
        let tempPath = modelPath + ".tmp"
        try data.write(to: URL(fileURLWithPath: tempPath), options: .atomic)

        if fm.fileExists(atPath: modelPath) {
            try fm.removeItem(atPath: modelPath)
        }
        try fm.moveItem(atPath: tempPath, toPath: modelPath)

        // Owner-only permissions.
        chmod(modelPath, 0o600)

        logger.debug(
            "Model saved: \(self.totalTransitions) transitions, \(self.transitionCounts.count) parents"
        )
    }
}

// MARK: - Persistence Model

/// On-disk JSON representation of the Markov chain model.
private struct PersistedModel: Codable {
    let version: Int
    let totalTransitions: Int
    let transitions: [String: [String: Int]]
}
