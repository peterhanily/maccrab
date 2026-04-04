// BaselineEngine.swift
// MacCrabCore
//
// Process lineage baseline anomaly detection engine for MacCrab (Layer 3).
// Learns normal parent-child process relationships over a configurable
// learning period (default 7 days), then alerts on never-before-seen edges.
// This detects novel attack techniques that no signature rule covers --
// if an attacker spawns a process from an unusual parent, this engine will
// catch it even without a specific rule.

import Foundation
import Darwin
import os.log

// MARK: - BaselineEngine

/// Learns the normal process-spawning graph on this machine and alerts when a
/// parent-child relationship is observed that was never seen during the
/// learning period.
///
/// Usage:
/// ```swift
/// let engine = BaselineEngine()
/// try await engine.load()
/// // for each process-creation event:
/// if let match = await engine.evaluate(event) {
///     // handle anomaly
/// }
/// ```
public actor BaselineEngine {

    // MARK: - Types

    /// A directed edge in the process-spawning graph: parent spawned child.
    public struct ProcessEdge: Codable, Hashable, Sendable {
        public let parentPath: String   // normalized executable path
        public let childPath: String    // normalized executable path

        public init(parentPath: String, childPath: String) {
            self.parentPath = parentPath
            self.childPath = childPath
        }

        /// Serialization key used for JSON persistence (e.g. "/usr/bin/zsh -> /usr/bin/ls").
        var serializationKey: String {
            "\(parentPath) -> \(childPath)"
        }

        /// Parse a serialization key back into a ProcessEdge.
        static func fromSerializationKey(_ key: String) -> ProcessEdge? {
            let components = key.components(separatedBy: " -> ")
            guard components.count == 2 else { return nil }
            return ProcessEdge(parentPath: components[0], childPath: components[1])
        }
    }

    /// Statistics for a single observed edge.
    public struct EdgeStats: Codable, Sendable {
        public var count: Int           // how many times observed
        public var firstSeen: Date
        public var lastSeen: Date

        public init(count: Int = 1, firstSeen: Date = Date(), lastSeen: Date = Date()) {
            self.count = count
            self.firstSeen = firstSeen
            self.lastSeen = lastSeen
        }
    }

    /// Configuration for the baseline engine.
    public struct Config: Codable, Sendable {
        /// Duration of the learning phase in seconds. Default: 7 days.
        public var learningPeriod: TimeInterval

        /// Detection sensitivity level.
        public var sensitivity: Sensitivity

        /// Whether the engine is enabled.
        public var enabled: Bool

        /// Only track edges from these parent paths (empty means track all).
        public var focusPaths: [String]

        /// Never alert on process creations from these parent paths.
        public var exemptParents: [String]

        /// Never alert on process creations of these child paths.
        public var exemptChildren: [String]

        /// Specific parent->child edges to never alert on.
        public var exemptEdges: [ProcessEdge]

        public init(
            learningPeriod: TimeInterval = 7 * 86400,
            sensitivity: Sensitivity = .high,
            enabled: Bool = true,
            focusPaths: [String] = [],
            exemptParents: [String] = [],
            exemptChildren: [String] = [],
            exemptEdges: [ProcessEdge] = []
        ) {
            self.learningPeriod = learningPeriod
            self.sensitivity = sensitivity
            self.enabled = enabled
            self.focusPaths = focusPaths
            self.exemptParents = exemptParents
            self.exemptChildren = exemptChildren
            self.exemptEdges = exemptEdges
        }
    }

    /// Sensitivity determines how aggressively we alert on novel edges.
    public enum Sensitivity: String, Codable, Sendable {
        /// Alert on ANY new edge after learning. Most comprehensive.
        case high
        /// Same as high but applies broader built-in exemptions for common
        /// system processes to reduce noise.
        case medium
        /// Only alert on edges where the parent is in the focusPaths list.
        case low
    }

    /// The current operational state of the engine.
    public enum BaselineState: String, Codable, Sendable {
        case learning   // collecting baseline data
        case active     // detecting anomalies
        case disabled   // engine is turned off
    }

    /// A snapshot of the engine's status for display in the UI.
    public struct BaselineStatus: Sendable {
        public let state: BaselineState
        public let learningStarted: Date
        public let learningRemaining: TimeInterval?  // nil when active or disabled
        public let totalEdges: Int
        public let totalAnomalies: Int
        public let lastSaved: Date?
    }

    // MARK: - Errors

    public enum BaselineEngineError: Error, LocalizedError {
        case persistenceDirectoryCreationFailed(String)
        case serializationFailed(String)
        case deserializationFailed(String)
        case fileWriteFailed(String)

        public var errorDescription: String? {
            switch self {
            case .persistenceDirectoryCreationFailed(let path):
                return "Failed to create baseline persistence directory: \(path)"
            case .serializationFailed(let detail):
                return "Baseline serialization failed: \(detail)"
            case .deserializationFailed(let detail):
                return "Baseline deserialization failed: \(detail)"
            case .fileWriteFailed(let detail):
                return "Baseline file write failed: \(detail)"
            }
        }
    }

    // MARK: - State

    /// Current operational state.
    private var state: BaselineState

    /// When the learning phase began.
    private var learningStarted: Date

    /// The learned edge map: every parent->child relationship observed.
    private var edges: [ProcessEdge: EdgeStats]

    /// Edges that were detected as anomalies (novel, never seen during learning).
    private var detectedNovelEdges: [ProcessEdge]

    /// Engine configuration.
    private var config: Config

    /// Path to the persisted baseline file.
    private let persistPath: String

    /// Last time the baseline was saved to disk.
    private var lastSaved: Date?

    // MARK: Statistics

    /// Total number of edge observations (including duplicates).
    private var totalEdgesRecorded: Int = 0

    /// Number of anomalies detected since entering active mode.
    private var anomaliesDetected: Int = 0

    /// Counter for periodic auto-save during learning (save every N new edges).
    private var edgesSinceLastSave: Int = 0

    // MARK: Auto-save

    /// Handle for the periodic auto-save task.
    private var autoSaveTask: Task<Void, Never>?

    // MARK: Logging

    private let logger = Logger(subsystem: "com.maccrab.detection", category: "BaselineEngine")

    // MARK: Constants

    /// How many new edges between periodic saves during learning.
    private static let saveEdgeInterval = 1000

    /// Auto-save timer interval (5 minutes).
    private static let autoSaveInterval: TimeInterval = 300

    /// Built-in parent exemptions for medium sensitivity to reduce noise from
    /// routine macOS system processes.
    private static let mediumSensitivityExemptParents: Set<String> = [
        "/usr/libexec/xpcproxy",
        "/sbin/launchd",
        "/usr/sbin/cfprefsd",
        "/usr/libexec/runningboardd",
        "/usr/libexec/trustd",
        "/usr/libexec/diskarbitrationd",
        "/System/Library/CoreServices/launchservicesd",
        "/System/Library/PrivateFrameworks/SkyLight.framework/Versions/A/Resources/WindowServer",
    ]

    // MARK: - Initialization

    /// Create a new baseline engine.
    ///
    /// - Parameter config: Optional configuration. Uses defaults if nil.
    public init(config: Config? = nil) {
        let cfg = config ?? Config()
        self.config = cfg
        self.state = cfg.enabled ? .learning : .disabled
        self.learningStarted = Date()
        self.edges = [:]
        self.detectedNovelEdges = []

        // Build persistence path: ~/Library/Application Support/MacCrab/baseline.json
        let appSupport = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first ?? URL(fileURLWithPath: NSTemporaryDirectory())
        let maccrabDir = appSupport.appendingPathComponent("MacCrab")
        self.persistPath = maccrabDir.appendingPathComponent("baseline.json").path
    }

    // MARK: - Public API

    /// Evaluate a process-creation event against the baseline.
    ///
    /// During the learning phase, the edge is recorded in the baseline.
    /// During the active phase, novel edges produce a `RuleMatch`.
    ///
    /// - Parameter event: The event to evaluate.
    /// - Returns: A `RuleMatch` if the event represents an anomalous edge, nil otherwise.
    public func evaluate(_ event: Event) async -> RuleMatch? {
        guard config.enabled, state != .disabled else { return nil }

        // Only evaluate process creation events.
        guard event.eventCategory == .process,
              event.eventType == .creation else {
            return nil
        }

        // Extract parent path from the first ancestor.
        guard let parentExecutable = event.process.ancestors.first?.executable else {
            return nil
        }

        let childExecutable = event.process.executable

        // Normalize paths to reduce false positives.
        let parentPath = normalizePath(parentExecutable)
        let childPath = normalizePath(childExecutable)

        // Apply focus path filter: if focusPaths is set, only track matching parents.
        if !config.focusPaths.isEmpty {
            let parentMatchesFocus = config.focusPaths.contains { focus in
                parentPath.hasPrefix(focus) || parentPath == focus
            }
            if !parentMatchesFocus {
                return nil
            }
        }

        // Check exemptions early (applies to both learning and active phases).
        if isExempt(parentPath: parentPath, childPath: childPath) {
            return nil
        }

        let edge = ProcessEdge(parentPath: parentPath, childPath: childPath)
        let now = Date()
        totalEdgesRecorded += 1

        switch state {
        case .learning:
            return recordLearningEdge(edge, at: now)

        case .active:
            return evaluateActiveEdge(edge, at: now, event: event)

        case .disabled:
            return nil
        }
    }

    /// Force an immediate transition from learning to active detection mode.
    public func activateDetection() {
        guard state == .learning else {
            logger.info("activateDetection called but state is \(self.state.rawValue, privacy: .public), ignoring")
            return
        }

        let edgeCount = edges.count
        state = .active
        logger.notice(
            "Baseline activated with \(edgeCount) unique edges after learning period"
        )

        // Persist the finalized baseline.
        do {
            try saveSync()
        } catch {
            logger.error("Failed to save baseline on activation: \(error.localizedDescription, privacy: .public)")
        }
    }

    /// Reset the baseline and restart the learning phase from scratch.
    public func resetBaseline() {
        edges.removeAll()
        detectedNovelEdges.removeAll()
        totalEdgesRecorded = 0
        anomaliesDetected = 0
        edgesSinceLastSave = 0
        learningStarted = Date()
        state = config.enabled ? .learning : .disabled

        logger.notice("Baseline reset. Learning phase restarted.")

        do {
            try saveSync()
        } catch {
            logger.error("Failed to save after baseline reset: \(error.localizedDescription, privacy: .public)")
        }
    }

    /// Get a snapshot of the engine's current status.
    public func status() -> BaselineStatus {
        let remaining: TimeInterval?
        if state == .learning {
            let elapsed = Date().timeIntervalSince(learningStarted)
            let left = config.learningPeriod - elapsed
            remaining = max(0, left)
        } else {
            remaining = nil
        }

        return BaselineStatus(
            state: state,
            learningStarted: learningStarted,
            learningRemaining: remaining,
            totalEdges: edges.count,
            totalAnomalies: anomaliesDetected,
            lastSaved: lastSaved
        )
    }

    /// Persist the current baseline to disk as JSON.
    public func save() throws {
        try saveSync()
    }

    /// Load a previously persisted baseline from disk.
    ///
    /// If no file exists, this is a no-op (engine continues in its current state).
    public func load() throws {
        let fm = FileManager.default
        guard fm.fileExists(atPath: persistPath) else {
            logger.info("No existing baseline file at \(self.persistPath, privacy: .public). Starting fresh.")
            return
        }

        let data = try Data(contentsOf: URL(fileURLWithPath: persistPath))
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        let persisted: PersistedBaseline
        do {
            persisted = try decoder.decode(PersistedBaseline.self, from: data)
        } catch {
            throw BaselineEngineError.deserializationFailed(error.localizedDescription)
        }

        // Restore state.
        self.state = persisted.state
        self.learningStarted = persisted.learningStarted
        self.config = persisted.config
        self.totalEdgesRecorded = persisted.stats.totalEdgesRecorded
        self.anomaliesDetected = persisted.stats.anomaliesDetected

        // Restore edges from serialized key format.
        self.edges = [:]
        for (key, stats) in persisted.edges {
            if let edge = ProcessEdge.fromSerializationKey(key) {
                self.edges[edge] = stats
            } else {
                logger.warning("Skipping malformed edge key during load: \(key, privacy: .public)")
            }
        }

        // Restore novel edges.
        self.detectedNovelEdges = persisted.novelEdges.compactMap { ProcessEdge.fromSerializationKey($0) }

        logger.notice(
            "Loaded baseline: state=\(persisted.state.rawValue, privacy: .public), \(self.edges.count) edges, \(self.anomaliesDetected) anomalies"
        )
    }

    /// Add a user-supplied exemption for a specific edge (e.g., "this is normal").
    ///
    /// The edge is added to the config's exemptEdges list and also inserted into
    /// the baseline so it will not alert again.
    public func addExemption(_ edge: ProcessEdge) {
        config.exemptEdges.append(edge)

        // Also add to the baseline edge map so future evaluations skip it.
        let now = Date()
        if edges[edge] == nil {
            edges[edge] = EdgeStats(count: 1, firstSeen: now, lastSeen: now)
        }

        // Remove from novel edges if present.
        detectedNovelEdges.removeAll { $0 == edge }

        logger.info("Added exemption: \(edge.parentPath, privacy: .public) -> \(edge.childPath, privacy: .public)")
    }

    /// Return the full learned edge map (for visualization / lineage explorer).
    public func allEdges() -> [ProcessEdge: EdgeStats] {
        edges
    }

    /// Return all edges that were detected as novel anomalies.
    public func novelEdges() -> [ProcessEdge] {
        detectedNovelEdges
    }

    /// Start the periodic auto-save timer. Call once after initialization.
    ///
    /// The timer saves every 5 minutes during the learning phase and is
    /// cancelled when the engine is deinitialized.
    public func startAutoSave() {
        stopAutoSave()

        autoSaveTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: UInt64(BaselineEngine.autoSaveInterval * 1_000_000_000))

                guard !Task.isCancelled else { break }
                guard let self else { break }

                do {
                    try await self.save()
                } catch {
                    // Logged inside saveSync; nothing more to do here.
                }
            }
        }
    }

    /// Stop the periodic auto-save timer.
    public func stopAutoSave() {
        autoSaveTask?.cancel()
        autoSaveTask = nil
    }

    /// Update the engine configuration at runtime.
    public func updateConfig(_ newConfig: Config) {
        self.config = newConfig

        if !newConfig.enabled {
            state = .disabled
        } else if state == .disabled {
            state = .learning
            learningStarted = Date()
        }

        logger.info(
            "Configuration updated: sensitivity=\(newConfig.sensitivity.rawValue, privacy: .public), enabled=\(newConfig.enabled)"
        )
    }

    // MARK: - Private: Learning Phase

    /// Record an edge observation during the learning phase.
    /// Returns nil (no alerts during learning). Handles auto-transition to active.
    private func recordLearningEdge(_ edge: ProcessEdge, at now: Date) -> RuleMatch? {
        if var existing = edges[edge] {
            existing.count += 1
            existing.lastSeen = now
            edges[edge] = existing
        } else {
            edges[edge] = EdgeStats(count: 1, firstSeen: now, lastSeen: now)
            edgesSinceLastSave += 1

            // Periodic save every N new unique edges.
            if edgesSinceLastSave >= Self.saveEdgeInterval {
                edgesSinceLastSave = 0
                do {
                    try saveSync()
                } catch {
                    logger.error(
                        "Periodic save during learning failed: \(error.localizedDescription, privacy: .public)"
                    )
                }
            }
        }

        // Check if the learning period has elapsed.
        let elapsed = now.timeIntervalSince(learningStarted)
        if elapsed >= config.learningPeriod {
            logger.notice(
                "Learning period complete (\(Int(elapsed / 86400)) days). Transitioning to active detection with \(self.edges.count) baseline edges."
            )
            state = .active

            do {
                try saveSync()
            } catch {
                logger.error(
                    "Failed to save baseline on learning->active transition: \(error.localizedDescription, privacy: .public)"
                )
            }
        }

        return nil
    }

    // MARK: - Private: Active Phase

    /// Evaluate an edge during the active (detection) phase.
    /// Returns a RuleMatch if the edge is novel and not exempt.
    private func evaluateActiveEdge(
        _ edge: ProcessEdge,
        at now: Date,
        event: Event
    ) -> RuleMatch? {
        // If edge exists in baseline, just update stats and move on.
        if var existing = edges[edge] {
            existing.count += 1
            existing.lastSeen = now
            edges[edge] = existing
            return nil
        }

        // New edge -- never seen during learning.

        // Sensitivity gating.
        switch config.sensitivity {
        case .low:
            // Only alert if the parent is in focusPaths.
            let parentInFocus = config.focusPaths.contains { focus in
                edge.parentPath.hasPrefix(focus) || edge.parentPath == focus
            }
            if !parentInFocus {
                // Record silently and move on.
                edges[edge] = EdgeStats(count: 1, firstSeen: now, lastSeen: now)
                return nil
            }

        case .medium:
            // Apply built-in exemptions for noisy system processes.
            if Self.mediumSensitivityExemptParents.contains(edge.parentPath) {
                edges[edge] = EdgeStats(count: 1, firstSeen: now, lastSeen: now)
                return nil
            }

        case .high:
            // Alert on everything novel.
            break
        }

        // Determine severity: high if parent is a focus path, medium otherwise.
        let severity: Severity
        if !config.focusPaths.isEmpty {
            let parentInFocus = config.focusPaths.contains { focus in
                edge.parentPath.hasPrefix(focus) || edge.parentPath == focus
            }
            severity = parentInFocus ? .high : .medium
        } else {
            severity = .medium
        }

        // Build a detailed description.
        let parentName = (edge.parentPath as NSString).lastPathComponent
        let childName = (edge.childPath as NSString).lastPathComponent
        let description = """
            Novel process lineage detected: \(parentName) spawned \(childName). \
            This parent-child relationship was never observed during the \
            \(Int(config.learningPeriod / 86400))-day learning period \
            (\(edges.count) baseline edges). \
            Parent: \(edge.parentPath) | Child: \(edge.childPath) | \
            PID: \(event.process.pid) | User: \(event.process.userName)
            """

        let match = RuleMatch(
            ruleId: "baseline-anomaly",
            ruleName: "Novel Process Lineage: \(parentName) -> \(childName)",
            severity: severity,
            description: description,
            mitreTechniques: ["T1059", "T1204"],
            tags: ["attack.execution", "baseline.anomaly"]
        )

        // Add the novel edge to the baseline so we don't alert on it repeatedly.
        edges[edge] = EdgeStats(count: 1, firstSeen: now, lastSeen: now)
        detectedNovelEdges.append(edge)
        anomaliesDetected += 1

        logger.warning(
            "Baseline anomaly: \(edge.parentPath, privacy: .public) -> \(edge.childPath, privacy: .public)"
        )

        return match
    }

    // MARK: - Private: Exemptions

    /// Check if a parent-child pair is exempt from detection.
    private func isExempt(parentPath: String, childPath: String) -> Bool {
        // Check parent exemptions.
        for exempt in config.exemptParents {
            if parentPath == exempt || parentPath.hasPrefix(exempt) {
                return true
            }
        }

        // Check child exemptions.
        for exempt in config.exemptChildren {
            if childPath == exempt || childPath.hasPrefix(exempt) {
                return true
            }
        }

        // Check specific edge exemptions.
        let edge = ProcessEdge(parentPath: parentPath, childPath: childPath)
        if config.exemptEdges.contains(edge) {
            return true
        }

        return false
    }

    // MARK: - Private: Path Normalization

    /// Normalize an executable path to reduce false positives from version
    /// changes, Homebrew updates, and .app bundle internals.
    ///
    /// Examples:
    /// - "/Applications/Safari.app/Contents/MacOS/Safari"
    ///   -> "/Applications/Safari.app/.../Safari"
    /// - "/usr/local/Cellar/python@3.11/3.11.6/bin/python3"
    ///   -> "/usr/local/Cellar/.../python3"
    /// - "/opt/homebrew/Cellar/node/21.1.0/bin/node"
    ///   -> "/opt/homebrew/Cellar/.../node"
    /// - "/nix/store/abc123-python-3.11.6/bin/python3"
    ///   -> "/nix/store/.../python3"
    private func normalizePath(_ path: String) -> String {
        var normalized = path

        // 1. Collapse .app bundle internals:
        //    "/Applications/Foo.app/Contents/MacOS/Foo" -> "/Applications/Foo.app/.../Foo"
        if let appRange = normalized.range(of: ".app/") {
            let appPrefix = String(normalized[normalized.startIndex...appRange.lowerBound]) + "app"
            let basename = (normalized as NSString).lastPathComponent
            normalized = "\(appPrefix)/.../\(basename)"
            return normalized
        }

        // 2. Collapse Homebrew Cellar version paths:
        //    "/usr/local/Cellar/python@3.11/3.11.6/bin/python3" -> "/usr/local/Cellar/.../python3"
        //    "/opt/homebrew/Cellar/node/21.1.0/bin/node" -> "/opt/homebrew/Cellar/.../node"
        if let cellarRange = normalized.range(of: "/Cellar/") {
            let cellarPrefix = String(normalized[normalized.startIndex..<cellarRange.upperBound])
            let basename = (normalized as NSString).lastPathComponent
            // Strip trailing slash from prefix for cleaner output.
            let prefix = cellarPrefix.hasSuffix("/")
                ? String(cellarPrefix.dropLast())
                : cellarPrefix
            normalized = "\(prefix)/.../\(basename)"
            return normalized
        }

        // 3. Collapse Nix store hash paths:
        //    "/nix/store/abc123-python-3.11.6/bin/python3" -> "/nix/store/.../python3"
        if normalized.hasPrefix("/nix/store/") {
            let basename = (normalized as NSString).lastPathComponent
            normalized = "/nix/store/.../\(basename)"
            return normalized
        }

        // 4. Strip version-like path components anywhere in the path.
        //    Matches components that look like "3.11.6", "1.0", "v2.1.0", "21.1.0_1".
        let components = normalized.components(separatedBy: "/")
        let versionPattern = #"^v?\d+(\.\d+)+(_\d+)?$"#
        let versionRegex = try? NSRegularExpression(pattern: versionPattern)

        var filtered: [String] = []
        var didStrip = false
        for component in components {
            let range = NSRange(component.startIndex..., in: component)
            if let regex = versionRegex,
               regex.firstMatch(in: component, range: range) != nil {
                if !didStrip {
                    filtered.append("...")
                    didStrip = true
                }
                // Skip the version component (collapse consecutive versions to one "...").
            } else {
                didStrip = false
                filtered.append(component)
            }
        }

        let rebuilt = filtered.joined(separator: "/")
        if rebuilt != normalized {
            return rebuilt
        }

        return normalized
    }

    // MARK: - Private: Persistence

    /// Internal synchronous save implementation.
    private func saveSync() throws {
        let fm = FileManager.default
        let directory = (persistPath as NSString).deletingLastPathComponent

        // Ensure the directory exists.
        if !fm.fileExists(atPath: directory) {
            do {
                try fm.createDirectory(atPath: directory, withIntermediateDirectories: true)
            } catch {
                throw BaselineEngineError.persistenceDirectoryCreationFailed(directory)
            }
        }

        // Serialize edges to key-value format.
        var serializedEdges: [String: EdgeStats] = [:]
        for (edge, stats) in edges {
            serializedEdges[edge.serializationKey] = stats
        }

        let serializedNovelEdges = detectedNovelEdges.map { $0.serializationKey }

        let persisted = PersistedBaseline(
            state: state,
            learningStarted: learningStarted,
            config: config,
            edges: serializedEdges,
            novelEdges: serializedNovelEdges,
            stats: PersistedStats(
                totalEdgesRecorded: totalEdgesRecorded,
                anomaliesDetected: anomaliesDetected
            )
        )

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]

        let data: Data
        do {
            data = try encoder.encode(persisted)
        } catch {
            throw BaselineEngineError.serializationFailed(error.localizedDescription)
        }

        // Write atomically to prevent corruption from crashes during write.
        let tempPath = persistPath + ".tmp"
        do {
            try data.write(to: URL(fileURLWithPath: tempPath), options: .atomic)
            // Atomic move: if the file already exists, remove it first.
            if fm.fileExists(atPath: persistPath) {
                try fm.removeItem(atPath: persistPath)
            }
            try fm.moveItem(atPath: tempPath, toPath: persistPath)
        } catch {
            // Clean up temp file on failure.
            try? fm.removeItem(atPath: tempPath)
            throw BaselineEngineError.fileWriteFailed(error.localizedDescription)
        }

        // Restrict baseline file permissions: owner-only read/write (rw-------).
        chmod(persistPath, 0o600)

        lastSaved = Date()

        logger.debug(
            "Baseline saved: \(self.edges.count) edges, state=\(self.state.rawValue, privacy: .public)"
        )
    }
}

// MARK: - Persistence Model

/// The on-disk JSON structure for the persisted baseline.
private struct PersistedBaseline: Codable {
    let state: BaselineEngine.BaselineState
    let learningStarted: Date
    let config: BaselineEngine.Config
    let edges: [String: BaselineEngine.EdgeStats]
    let novelEdges: [String]
    let stats: PersistedStats
}

/// Persisted statistics counters.
private struct PersistedStats: Codable {
    let totalEdgesRecorded: Int
    let anomaliesDetected: Int
}
