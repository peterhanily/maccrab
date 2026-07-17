// SequenceEngine.swift
// MacCrabCore
//
// Temporal sequence rule engine for MacCrab.
// Evaluates multi-step detection rules where events must occur in a specific
// order, within a time window, optionally correlated by process lineage or
// shared attributes. This is the novel detection capability -- no other
// open-source macOS security tool provides temporal sequence correlation.
//
// Example: "A file is downloaded, then executed, then establishes a network
// connection to an external host -- all within 120 seconds, all sharing
// process ancestry."

import Foundation
import os.log

// MARK: - Sequence Rule Types

/// How the steps of a sequence rule relate to each other.
public enum CorrelationType: String, Codable, Sendable {
    /// All steps must share process ancestry (parent/child/grandchild chain).
    case processLineage
    /// All steps must originate from the exact same PID.
    case processSame
    /// All steps must involve the same file path.
    case filePath
    /// All steps must involve the same network destination (ip:port).
    case networkEndpoint
    /// No correlation required between steps.
    case none
}

/// How a step's process relates to another step's process.
public enum ProcessRelation: String, Codable, Sendable {
    /// Exact same process (same PID).
    case same
    /// Child or grandchild of the referenced step's process.
    case descendant
    /// Parent or grandparent of the referenced step's process.
    case ancestor
    /// Shares a parent with the referenced step's process.
    case sibling
    /// Exact same process — alias rule authors write as "same_process"
    /// (semantically identical to `same`). Before v1.18 this token failed to
    /// decode and silently dropped the entire rule at load.
    case sameProcess = "same_process"
    /// Anywhere in the referenced process's tree: the same process, an
    /// ancestor, or a descendant. Authors write "same_tree".
    case sameTree = "same_tree"
    /// No process-relationship constraint — the step is correlated by the
    /// window + ordering alone. Authors write "any".
    case any
}

/// Defines which steps must complete before the sequence fires.
public enum TriggerCondition: Codable, Sendable {
    /// All steps in the sequence must match.
    case allSteps
    /// A specific set of step IDs must match (AND logic).
    case steps([String])
    /// At least N steps (any N) must match.
    case anySteps(Int)

    // MARK: Codable

    private enum CodingKeys: String, CodingKey {
        case type
        case value
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let type = try container.decode(String.self, forKey: .type)
        switch type {
        case "all_steps":
            self = .allSteps
        case "steps":
            let ids = try container.decode([String].self, forKey: .value)
            self = .steps(ids)
        case "any_steps":
            let count = try container.decode(Int.self, forKey: .value)
            self = .anySteps(count)
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .type,
                in: container,
                debugDescription: "Unknown trigger condition type: \(type)"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .allSteps:
            try container.encode("all_steps", forKey: .type)
        case .steps(let ids):
            try container.encode("steps", forKey: .type)
            try container.encode(ids, forKey: .value)
        case .anySteps(let count):
            try container.encode("any_steps", forKey: .type)
            try container.encode(count, forKey: .value)
        }
    }
}

/// A single step within a sequence rule.
///
/// Each step defines what kind of event it matches (via logsource category and
/// predicates), ordering constraints, and optional process relationship
/// constraints relative to another step.
public struct SequenceStep: Codable, Sendable {
    /// Unique identifier for this step within the rule (e.g. "download", "execute").
    public let id: String

    /// The logsource category this step matches (e.g. "process_creation", "file_event").
    public let logsourceCategory: String

    /// Predicates that the event must satisfy for this step.
    public let predicates: [Predicate]

    /// How predicates are combined: all must match, or any suffices.
    public let condition: RuleCondition

    /// If set, this step must occur after the named step ID.
    public let afterStep: String?

    /// If set, the event's process must have this relationship to the
    /// referenced step's process.
    public let processRelation: ProcessRelationSpec?

    public init(
        id: String,
        logsourceCategory: String,
        predicates: [Predicate],
        condition: RuleCondition = .allOf,
        afterStep: String? = nil,
        processRelation: ProcessRelationSpec? = nil
    ) {
        self.id = id
        self.logsourceCategory = logsourceCategory
        self.predicates = predicates
        self.condition = condition
        self.afterStep = afterStep
        self.processRelation = processRelation
    }
}

/// Specifies a process relationship constraint between two steps.
public struct ProcessRelationSpec: Codable, Sendable {
    /// The kind of relationship required.
    public let relation: ProcessRelation
    /// The step ID whose process is the reference point.
    public let relativeToStep: String

    public init(relation: ProcessRelation, relativeToStep: String) {
        self.relation = relation
        self.relativeToStep = relativeToStep
    }
}

/// A sequence rule defines ordered (or unordered) steps that must all match
/// within a time window, optionally correlated by a shared attribute.
public struct SequenceRule: Codable, Sendable, Identifiable {
    public let id: String
    public let title: String
    public let description: String
    public let level: Severity
    public let tags: [String]

    /// Maximum elapsed time (seconds) from the first matched step to the last.
    public let window: TimeInterval

    /// How steps relate to each other (shared process, file, network, etc.).
    public let correlationType: CorrelationType

    /// Whether steps must occur in their defined order.
    public let ordered: Bool

    /// The individual steps that compose this sequence.
    public let steps: [SequenceStep]

    /// Which steps must complete for the sequence to fire.
    public let trigger: TriggerCondition

    /// Whether this rule is active.
    public var enabled: Bool

    /// v1.18: carried from the YAML. `false` = must-fire — the completed-sequence
    /// match survives the NoiseFilter trust/suppression gates. Optional + decode-
    /// safe (a compiled rule predating the key, or one without it, decodes to nil
    /// → treated as `true`/suppressible at the match site). The 9 high-value kill
    /// chains declare `suppressible: false`; before this was plumbed those matches
    /// defaulted suppressible and were silently gate-dropped on platform binaries.
    public let suppressible: Bool?

    public init(
        id: String,
        title: String,
        description: String,
        level: Severity,
        tags: [String],
        window: TimeInterval,
        correlationType: CorrelationType,
        ordered: Bool,
        steps: [SequenceStep],
        trigger: TriggerCondition,
        enabled: Bool = true,
        suppressible: Bool? = nil
    ) {
        self.id = id
        self.title = title
        self.description = description
        self.level = level
        self.tags = tags
        self.window = window
        self.correlationType = correlationType
        self.ordered = ordered
        self.steps = steps
        self.trigger = trigger
        self.enabled = enabled
        self.suppressible = suppressible
    }
}

// MARK: - Sequence Engine

/// The temporal sequence detection engine.
///
/// Tracks in-flight partial matches across events and fires alerts when a
/// complete sequence is detected within the configured time window. Runs as
/// an actor for safe concurrent access from the event processing pipeline.
///
/// Usage:
/// ```swift
/// let engine = SequenceEngine(lineage: processLineage)
/// let count = try await engine.loadRules(from: sequenceRulesURL)
/// // For each incoming event:
/// let matches = await engine.evaluate(event)
/// ```
public actor SequenceEngine {

    // MARK: - Internal Tracking Types

    /// Records a single matched step within an in-flight sequence.
    struct MatchedStep: Sendable {
        let stepId: String
        let eventId: UUID
        let timestamp: Date
        let processPid: pid_t
        let processPath: String
        let filePath: String?
        let networkDest: String?
    }

    /// Tracks an in-flight sequence being assembled from individual events.
    ///
    /// Each partial match corresponds to one potential instance of a sequence
    /// rule. As new events arrive and match subsequent steps, the partial
    /// match is advanced. Once the trigger condition is satisfied, the
    /// sequence fires and the partial match is consumed.
    struct PartialMatch: Sendable {
        let ruleId: String
        let createdAt: Date
        var matchedSteps: [String: MatchedStep]   // stepId -> matched event info
        let correlationKey: String?                // shared value binding steps together

        /// Timestamp of the most recently matched step.
        var latestTimestamp: Date {
            matchedSteps.values.map(\.timestamp).max() ?? createdAt
        }
    }

    // MARK: - State

    /// All loaded sequence rules keyed by rule ID.
    private var rules: [String: SequenceRule] = [:]

    /// Index from logsource category to rule IDs that have at least one step
    /// matching that category. Enables fast dispatch: only rules with a
    /// relevant step are considered for each event.
    private var ruleIndex: [String: Set<String>] = [:]

    /// Active partial matches keyed by rule ID.
    private var partialMatches: [String: [PartialMatch]] = [:]

    /// A later (non-initial) step that matched an ordered rule but arrived
    /// BEFORE its initial step, so there was no partial to advance yet.
    private struct PendingStep: Sendable {
        let step: SequenceStep
        let matched: MatchedStep
        let arrivedAt: Date
    }

    /// v1.21.4 (corr-event-pipeline #95): backfill buffer for out-of-order
    /// later steps, keyed by rule ID. The A2 event-pipeline split routes `.file`
    /// events to a separate consumer from process/network events; under a file
    /// flood the file consumer lags, so a cross-family ordered rule's later
    /// step (process/network, on the fast priority consumer) can reach
    /// `evaluate` BEFORE its `step[0]` file event. Ordered mode only seeds a
    /// partial from `step[0]`, so that later step would otherwise be dropped and
    /// 23 of the highest-value kill chains (supply-chain, dropper→C2, ransomware)
    /// would silently never complete. We stash the un-advanceable later step
    /// here and replay it once `step[0]` seeds a partial. Bounded per rule +
    /// window-pruned so a later step whose predicate matches broadly (an exec
    /// with no preceding download) can't grow the buffer unbounded.
    private var pendingLaterSteps: [String: [PendingStep]] = [:]

    /// Per-rule cap on buffered out-of-order later steps. Oldest evicted first.
    private static let maxPendingPerRule = 256

    /// Running count of all partial matches across all rules, to enforce the
    /// global cap without iterating every time.
    private var totalPartialCount: Int = 0

    /// Hard cap on total partial matches to bound memory usage.
    private let maxPartialMatches: Int

    /// How often (in seconds) the engine sweeps for expired partial matches.
    private let sweepInterval: TimeInterval

    /// Last time an expiration sweep was performed.
    private var lastSweep: Date = Date()

    /// Reference to the process lineage graph for ancestry checks.
    private let lineage: ProcessLineage

    /// LRU cache of compiled `NSRegularExpression` instances keyed by pattern.
    /// On cache hit the entry is promoted; on eviction the least-recently-used
    /// entry is removed. Matches RuleEngine's LRU cache strategy: a sequence-
    /// number sidecar dict drives O(1) hit promotion and O(n) overflow-only
    /// eviction (vs. the previous O(n) lastIndex+remove+append on every hit).
    private var regexCache: [String: NSRegularExpression] = [:]
    private var regexAccessSeq: [String: UInt64] = [:]
    private var regexAccessCounter: UInt64 = 0
    private static let maxRegexCacheSize = 2048

    /// Reference to a partial match by rule ID and creation time, used for
    /// O(1) LRU eviction. Entries are appended at the back (newest) and
    /// removed from the front (oldest), so the array stays naturally sorted
    /// by creation time without any explicit sorting.
    private struct PartialMatchRef: Sendable {
        let ruleId: String
        let createdAt: Date
    }

    /// Queue of partial-match references ordered oldest-first (append new,
    /// remove from front). Used by `evictOldest` to avoid the O(n log n)
    /// sort that previously collected and sorted ALL partial matches.
    private var evictionQueue: [PartialMatchRef] = []

    private let logger = Logger(subsystem: "com.maccrab.detection", category: "SequenceEngine")

    // MARK: - Initialization

    /// Creates a new sequence engine.
    ///
    /// - Parameters:
    ///   - lineage: The process lineage tracker used for ancestry-based
    ///     correlation checks.
    ///   - maxPartialMatches: Upper bound on total in-flight partial matches
    ///     across all rules. Oldest are evicted when exceeded. Defaults to 10000.
    ///   - sweepInterval: How often (seconds) to scan for expired partial
    ///     matches. Defaults to 1 second.
    public init(
        lineage: ProcessLineage,
        maxPartialMatches: Int = 10_000,
        sweepInterval: TimeInterval = 1.0
    ) {
        self.lineage = lineage
        self.maxPartialMatches = maxPartialMatches
        self.sweepInterval = sweepInterval
    }

    // MARK: - Regex Caching

    /// Returns a compiled `NSRegularExpression` for the given pattern, using the
    /// LRU cache to avoid recompilation. Returns `nil` if the pattern is invalid.
    private func cachedRegex(for pattern: String) -> NSRegularExpression? {
        if let cached = regexCache[pattern] {
            regexAccessCounter += 1
            regexAccessSeq[pattern] = regexAccessCounter
            return cached
        }
        // v1.21.4 (corr-detection #271): `.caseInsensitive` is a deliberate
        // engine-wide choice (matches RuleEngine.cachedRegex and the case-folding
        // string modifiers), NOT Sigma's case-sensitive `|re` default. Rule
        // authors who need a case-sensitive sub-match use an inline ICU flag
        // group — `(?-i:...)` — which overrides this base option for its scope.
        guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else {
            return nil
        }
        // Evict least-recently-used when cache is full. O(n) min scan only
        // on overflow, not per hit.
        if regexCache.count >= Self.maxRegexCacheSize {
            if let lru = regexAccessSeq.min(by: { $0.value < $1.value })?.key {
                regexCache.removeValue(forKey: lru)
                regexAccessSeq.removeValue(forKey: lru)
            }
        }
        regexAccessCounter += 1
        regexCache[pattern] = regex
        regexAccessSeq[pattern] = regexAccessCounter
        return regex
    }

    // MARK: - Rule Loading

    /// Load sequence rules from JSON files in a directory.
    ///
    /// Each `.json` file must contain a single `SequenceRule`. Files that fail
    /// to parse are logged and skipped.
    ///
    /// - Parameter directory: URL to the directory containing rule files.
    /// - Returns: The number of rules successfully loaded.
    @discardableResult
    public func loadRules(from directory: URL) throws -> Int {
        let fm = FileManager.default
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: directory.path, isDirectory: &isDir), isDir.boolValue else {
            throw SequenceEngineError.directoryNotFound(directory.path)
        }

        let contents = try fm.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles]
        )

        let jsonFiles = contents.filter { $0.pathExtension == "json" }
        if jsonFiles.isEmpty {
            logger.warning("No .json sequence rule files found in \(directory.path)")
        }

        let decoder = JSONDecoder()
        var loaded = 0

        for file in jsonFiles {
            do {
                let data = try Data(contentsOf: file)
                var rule = try decoder.decode(SequenceRule.self, from: data)
                rule.enabled = true

                // Validate rule structure before accepting it.
                try validateRule(rule)

                rules[rule.id] = rule

                // Build the category -> ruleId index so we can quickly find
                // which rules have steps relevant to an incoming event.
                for step in rule.steps {
                    ruleIndex[step.logsourceCategory, default: []].insert(rule.id)
                }

                loaded += 1
            } catch {
                logger.error("Failed to load sequence rule from \(file.lastPathComponent): \(error.localizedDescription)")
            }
        }

        // Pre-compile all regex patterns so that evaluateModifier never has to
        // compile on the hot path.
        for rule in rules.values {
            for step in rule.steps {
                for predicate in step.predicates where predicate.modifier == .regex {
                    for pattern in predicate.values {
                        _ = cachedRegex(for: pattern)
                    }
                }
            }
        }

        logger.info("Loaded \(loaded) sequence rules from \(directory.path)")
        return loaded
    }

    /// Add a single rule programmatically (useful for tests).
    public func addRule(_ rule: SequenceRule) throws {
        try validateRule(rule)
        rules[rule.id] = rule
        for step in rule.steps {
            ruleIndex[step.logsourceCategory, default: []].insert(rule.id)
        }
    }

    /// Validate that a rule is internally consistent.
    private func validateRule(_ rule: SequenceRule) throws {
        guard !rule.steps.isEmpty else {
            throw SequenceEngineError.invalidRule(rule.id, "Rule has no steps")
        }

        let stepIds = Set(rule.steps.map(\.id))
        guard stepIds.count == rule.steps.count else {
            throw SequenceEngineError.invalidRule(rule.id, "Duplicate step IDs")
        }

        // Validate afterStep references.
        for step in rule.steps {
            if let afterStep = step.afterStep, !stepIds.contains(afterStep) {
                throw SequenceEngineError.invalidRule(
                    rule.id,
                    "Step '\(step.id)' references unknown afterStep '\(afterStep)'"
                )
            }
        }

        // Validate processRelation references.
        for step in rule.steps {
            if let spec = step.processRelation, !stepIds.contains(spec.relativeToStep) {
                throw SequenceEngineError.invalidRule(
                    rule.id,
                    "Step '\(step.id)' references unknown relativeToStep '\(spec.relativeToStep)'"
                )
            }
        }

        // Validate trigger condition references.
        switch rule.trigger {
        case .steps(let ids):
            for id in ids {
                guard stepIds.contains(id) else {
                    throw SequenceEngineError.invalidRule(
                        rule.id,
                        "Trigger references unknown step ID '\(id)'"
                    )
                }
            }
        case .anySteps(let n):
            guard n > 0, n <= rule.steps.count else {
                throw SequenceEngineError.invalidRule(
                    rule.id,
                    "anySteps(\(n)) is out of range for \(rule.steps.count) steps"
                )
            }
        case .allSteps:
            break
        }
    }

    // MARK: - Rule Management

    /// Enable or disable a sequence rule by ID.
    public func setEnabled(_ ruleId: String, enabled: Bool) {
        guard rules[ruleId] != nil else {
            logger.warning("setEnabled called for unknown sequence rule: \(ruleId)")
            return
        }
        rules[ruleId]?.enabled = enabled

        // If disabling, discard any in-flight partial matches for this rule.
        if !enabled {
            if let removed = partialMatches.removeValue(forKey: ruleId) {
                totalPartialCount -= removed.count
                evictionQueue.removeAll { $0.ruleId == ruleId }
            }
        }
    }

    /// Returns all loaded sequence rules.
    public func listRules() -> [SequenceRule] {
        Array(rules.values)
    }

    /// Returns the total number of loaded sequence rules.
    public var ruleCount: Int {
        rules.count
    }

    /// Returns the current number of in-flight partial matches (for diagnostics).
    public var activePartialMatchCount: Int {
        totalPartialCount
    }

    /// Number of ENABLED sequence rules — the count that actually evaluates,
    /// distinct from `ruleCount` (loaded). Mirrors `RuleEngine.enabledRuleCount`
    /// so a caller/heartbeat can surface effective temporal-tier coverage
    /// separately from the single-event tier (corr-detection #272).
    public var activeRuleCount: Int {
        rules.values.reduce(0) { $0 + ($1.enabled ? 1 : 0) }
    }

    // MARK: - Telemetry (corr-detection #272)

    /// Per-rule runtime telemetry for the temporal tier. `RuleEngine` has had
    /// per-rule `RuleStats` since v1.7.1, but sequence (and graph) rules had
    /// NONE — a sequence rule that never evaluates or never fires was invisible
    /// (the heartbeat's `rules_active` counts only single-event rules). These
    /// counters make a dead sequence rule observable.
    public struct SequenceRuleStats: Codable, Sendable, Hashable {
        public let ruleId: String
        public var evaluationCount: UInt64
        public var fireCount: UInt64
        public var lastFiredAt: Date?
        public init(ruleId: String,
                    evaluationCount: UInt64 = 0,
                    fireCount: UInt64 = 0,
                    lastFiredAt: Date? = nil) {
            self.ruleId = ruleId
            self.evaluationCount = evaluationCount
            self.fireCount = fireCount
            self.lastFiredAt = lastFiredAt
        }
    }

    private var ruleStats: [String: SequenceRuleStats] = [:]

    /// Snapshot of per-rule sequence telemetry (evaluations, fires, last-fire),
    /// sorted most-fired first. Lets a caller/heartbeat/status surface a
    /// never-evaluated or never-fired sequence rule that was previously invisible.
    public func statsSnapshot() -> [SequenceRuleStats] {
        Array(ruleStats.values).sorted { $0.fireCount > $1.fireCount }
    }

    // MARK: - Event Evaluation

    /// Evaluate an event against all applicable sequence rules.
    ///
    /// This is the main entry point called for each incoming event. It:
    /// 1. Maps the event to a logsource category.
    /// 2. Finds sequence rules with steps matching that category.
    /// 3. For each matching rule, checks if the event matches any step.
    /// 4. Creates new partial matches or advances existing ones.
    /// 5. Checks correlation and ordering constraints.
    /// 6. Returns `RuleMatch` results for any completed sequences.
    /// 7. Periodically sweeps expired partial matches.
    ///
    /// - Parameter event: The incoming security event.
    /// - Returns: Array of `RuleMatch` for sequences that completed on this event.
    public func evaluate(_ event: Event) async -> [RuleMatch] {
        // Periodic housekeeping: sweep expired partials and enforce memory cap.
        let now = Date()
        if now.timeIntervalSince(lastSweep) >= sweepInterval {
            sweepExpired()
            lastSweep = now
        }

        // Pre-emptive sweep: trigger early cleanup when at 80% capacity to
        // reduce the likelihood of hitting the hard cap during event bursts.
        if totalPartialCount > maxPartialMatches * 8 / 10 {
            sweepExpired()
            lastSweep = now
        }

        let category = mapEventCategoryToLogsource(event.eventCategory, eventType: event.eventType)

        // Find rule IDs that have at least one step matching this category.
        guard let candidateRuleIds = ruleIndex[category] else {
            return []
        }

        var completedMatches: [RuleMatch] = []

        for ruleId in candidateRuleIds {
            guard let rule = rules[ruleId], rule.enabled else { continue }

            // corr-detection #272: this rule was dispatched for evaluation
            // (its category matched this event and it is enabled). Count it so a
            // sequence rule that is loaded+enabled but never actually exercised
            // is distinguishable from one that fires.
            ruleStats[ruleId, default: SequenceRuleStats(ruleId: ruleId)].evaluationCount &+= 1

            // Find which steps of this rule match the event's category AND predicates.
            let matchingSteps = rule.steps.filter { step in
                step.logsourceCategory == category && evaluateStepPredicates(step, against: event)
            }

            guard !matchingSteps.isEmpty else { continue }

            // Build a MatchedStep from the event for use in partial matches.
            let eventMatchedStep: (SequenceStep) -> MatchedStep = { step in
                MatchedStep(
                    stepId: step.id,
                    eventId: event.id,
                    timestamp: event.timestamp,
                    processPid: event.process.pid,
                    processPath: event.process.executable,
                    filePath: event.file?.path,
                    networkDest: self.networkDestination(from: event)
                )
            }

            // --- Phase 1: Try to advance existing partial matches ---
            var advancedPartials: [(Int, PartialMatch)] = []  // (index, updated partial)
            var completedIndices: Set<Int> = []
            // #95: step IDs that advanced at least one partial on this event. A
            // matching later step NOT in this set found no partial to advance and
            // is a backfill-buffer candidate (see Phase 3 below).
            var advancedStepIds: Set<String> = []

            let existingPartials = partialMatches[ruleId] ?? []
            for (idx, partial) in existingPartials.enumerated() {
                // Check if this partial has expired.
                if now.timeIntervalSince(partial.createdAt) > rule.window {
                    continue
                }

                for step in matchingSteps {
                    // Advance is delegated to the shared `advancePartial` (used
                    // identically by the Phase-3 replay path) so the correlation/
                    // ordering/afterStep/processRelation checks can never drift
                    // between the live and replayed paths (cf. corr-detection #275).
                    guard let updated = await advancePartial(
                        rule: rule, step: step,
                        matched: eventMatchedStep(step), partial: partial
                    ) else { continue }
                    advancedPartials.append((idx, updated))
                    advancedStepIds.insert(step.id)

                    // Check if trigger condition is now satisfied.
                    if isTriggerSatisfied(rule.trigger, matchedStepIds: Set(updated.matchedSteps.keys), totalSteps: rule.steps.count) {
                        completedIndices.insert(idx)
                        completedMatches.append(makeMatch(rule: rule, partial: updated))
                    }

                    // Only advance once per step per partial -- break to next partial.
                    break
                }
            }

            // Apply updates: replace advanced partials, remove completed ones.
            if !advancedPartials.isEmpty || !completedIndices.isEmpty {
                var updatedList = existingPartials

                // Apply advances (only those not also completed).
                for (idx, updated) in advancedPartials {
                    if !completedIndices.contains(idx) {
                        updatedList[idx] = updated
                    }
                }

                // Remove completed (iterate in reverse to preserve indices).
                for idx in completedIndices.sorted().reversed() {
                    updatedList.remove(at: idx)
                    totalPartialCount -= 1
                }

                partialMatches[ruleId] = updatedList
            }

            // --- Phase 2: Create new partial matches for initial steps ---
            // #95: track whether this event seeded a fresh partial from the
            // initial step — only then is it worth replaying any buffered
            // out-of-order later steps against the rule (Phase 3).
            var seededInitial = false
            for step in matchingSteps {
                let isInitialStep: Bool
                if rule.ordered {
                    // In ordered mode, only the first step can start a new partial.
                    isInitialStep = (step.id == rule.steps.first?.id)
                } else {
                    // In unordered mode, any step can start a new partial, as long
                    // as it has no unsatisfied afterStep or processRelation constraints.
                    isInitialStep = (step.afterStep == nil) && (step.processRelation == nil)
                }

                guard isInitialStep else { continue }

                let matched = eventMatchedStep(step)
                let correlationKey = generateCorrelationKey(
                    rule.correlationType,
                    matched: matched,
                    ruleId: rule.id
                )

                // Avoid creating a duplicate partial if this event already started
                // one for the same rule with the same correlation key in this evaluation.
                let existingForRule = partialMatches[ruleId] ?? []
                let alreadyStarted = existingForRule.contains { partial in
                    partial.correlationKey == correlationKey
                    && partial.matchedSteps[step.id]?.eventId == event.id
                }
                guard !alreadyStarted else { continue }

                var newPartial = PartialMatch(
                    ruleId: ruleId,
                    createdAt: now,
                    matchedSteps: [:],
                    correlationKey: correlationKey
                )
                newPartial.matchedSteps[step.id] = matched

                // Edge case: single-step rule or anySteps(1).
                if isTriggerSatisfied(rule.trigger, matchedStepIds: Set(newPartial.matchedSteps.keys), totalSteps: rule.steps.count) {
                    completedMatches.append(makeMatch(rule: rule, partial: newPartial))
                    // Don't store the partial -- it's already complete.
                } else {
                    partialMatches[ruleId, default: []].append(newPartial)
                    totalPartialCount += 1
                    evictionQueue.append(PartialMatchRef(ruleId: ruleId, createdAt: now))
                    seededInitial = true
                }
            }

            // --- Phase 3 (#95): out-of-order backfill for ordered rules ---
            // If this event just seeded an initial partial, replay any later
            // steps that arrived early (via the fast priority consumer while the
            // file consumer lagged) so the sequence can still complete.
            if seededInitial, let buffered = pendingLaterSteps[ruleId], !buffered.isEmpty {
                completedMatches.append(contentsOf: await replayPendingSteps(ruleId: ruleId, rule: rule, now: now))
            }
            // Buffer this event's matching later step(s) that found NO partial to
            // advance — they may belong to an initial step still queued on the
            // other consumer. Ordered rules only (unordered mode seeds from any
            // constraint-free step, so there is no out-of-order gap to bridge).
            if rule.ordered {
                let initialStepId = rule.steps.first?.id
                for step in matchingSteps where step.id != initialStepId && !advancedStepIds.contains(step.id) {
                    bufferPendingStep(ruleId: ruleId, step: step, matched: eventMatchedStep(step), now: now)
                }
            }
        }

        // Enforce the global partial match cap.
        if totalPartialCount > maxPartialMatches {
            evictOldest(count: totalPartialCount - maxPartialMatches)
        }

        // corr-detection #272: record fires for every sequence completed on
        // this event (both Phase-1 advances and Phase-2 single-step completions
        // land in `completedMatches`), so per-rule fire counts + last-fire are
        // observable via `statsSnapshot()`.
        for match in completedMatches {
            ruleStats[match.ruleId, default: SequenceRuleStats(ruleId: match.ruleId)].fireCount &+= 1
            ruleStats[match.ruleId]?.lastFiredAt = event.timestamp
        }

        return completedMatches
    }

    // MARK: - Predicate Evaluation

    /// Evaluate all predicates for a step against an event.
    private func evaluateStepPredicates(_ step: SequenceStep, against event: Event) -> Bool {
        let predicates = step.predicates
        guard !predicates.isEmpty else { return true }

        switch step.condition {
        case .allOf:
            return predicates.allSatisfy { evaluatePredicate($0, against: event) }
        case .anyOf:
            return predicates.contains { evaluatePredicate($0, against: event) }
        case .oneOfEach:
            let groups = Dictionary(grouping: predicates, by: { $0.field })
            return groups.values.allSatisfy { group in
                group.contains { evaluatePredicate($0, against: event) }
            }
        }
    }

    /// Evaluate a single predicate against an event.
    ///
    /// This is a self-contained copy of the logic from `RuleEngine` to avoid
    /// cross-actor dependency and keep the sequence engine independently testable.
    private func evaluatePredicate(_ predicate: Predicate, against event: Event) -> Bool {
        let rawResult: Bool

        if predicate.modifier == .exists {
            let fieldValue = resolveField(predicate.field, from: event)
            rawResult = fieldValue?.isEmpty == false
        } else {
            guard let fieldValue = resolveField(predicate.field, from: event) else {
                let rawMiss = false
                return predicate.negate ? !rawMiss : rawMiss
            }
            rawResult = evaluateModifier(
                predicate.modifier,
                fieldValue: fieldValue,
                values: predicate.values,
                lowercasedValues: predicate.lowercasedValues
            )
        }

        return predicate.negate ? !rawResult : rawResult
    }

    /// Apply a modifier comparison. The predicate matches when the field
    /// satisfies the comparison for *any* value in the list (OR semantics).
    ///
    /// `lowercasedValues` are pre-folded at `Predicate` init/decode time (rule
    /// LOAD), so the case-insensitive string modifiers compare against them
    /// directly instead of calling `.lowercased()` on the rule constant per
    /// event. Detection is unchanged: `lowercasedValues == values.map { $0.lowercased() }`
    /// by construction, so `fieldLower == $0.lowercased()` and `fieldLower == $0`
    /// (over `lowercasedValues`) yield identical results. Mirrors
    /// `RuleEngine.evaluateModifier`.
    private func evaluateModifier(
        _ modifier: PredicateModifier,
        fieldValue: String,
        values: [String],
        lowercasedValues: [String]
    ) -> Bool {
        let fieldLower = fieldValue.lowercased()

        switch modifier {
        case .equals:
            return lowercasedValues.contains { fieldLower == $0 }
        case .contains:
            return lowercasedValues.contains { fieldLower.contains($0) }
        case .startswith:
            return lowercasedValues.contains { fieldLower.hasPrefix($0) }
        case .endswith:
            return lowercasedValues.contains { fieldLower.hasSuffix($0) }
        case .regex:
            return values.contains { pattern in
                cachedRegex(for: pattern)
                    .map { regex in
                        regex.firstMatch(
                            in: fieldValue,
                            options: [],
                            range: NSRange(fieldValue.startIndex..., in: fieldValue)
                        ) != nil
                    } ?? false
            }
        case .exists:
            return !fieldValue.isEmpty
        case .gt:
            guard let fieldNum = Double(fieldValue) else { return false }
            return values.contains { Double($0).map { fieldNum > $0 } ?? false }
        case .lt:
            guard let fieldNum = Double(fieldValue) else { return false }
            return values.contains { Double($0).map { fieldNum < $0 } ?? false }
        case .gte:
            guard let fieldNum = Double(fieldValue) else { return false }
            return values.contains { Double($0).map { fieldNum >= $0 } ?? false }
        case .lte:
            guard let fieldNum = Double(fieldValue) else { return false }
            return values.contains { Double($0).map { fieldNum <= $0 } ?? false }
        }
    }

    // MARK: - Field Resolution

    /// Resolve a Sigma/ECS field name to a string value from the event.
    ///
    /// v1.21.4 (corr-detection #275): delegates to the ONE canonical
    /// `RuleEngine.resolveField` (a nonisolated static, so this call is
    /// synchronous). Previously this was a hand-copied switch that drifted from
    /// RuleEngine's ~50-alias table — every alias RuleEngine gained but this
    /// copy missed (grandparent, hashes, session, honeyfile, ProcessAncestors,
    /// env, AiTool, TCCDecision, …) silently dead-lettered any sequence rule
    /// that predicated on it (the FileAction/Architecture/NotarizationStatus
    /// trio in #11 was one instance). Sharing the table makes that class of
    /// drift-bug structurally impossible; the shared cases are semantically
    /// identical to what this copy returned.
    private func resolveField(_ path: String, from event: Event) -> String? {
        RuleEngine.resolveField(path, from: event)
    }

    // MARK: - Category Mapping

    /// Map an event's category and type to the Sigma logsource category string.
    private func mapEventCategoryToLogsource(
        _ category: EventCategory,
        eventType: EventType
    ) -> String {
        switch category {
        case .process:
            switch eventType {
            case .creation, .start:
                return "process_creation"
            case .end:
                return "process_termination"
            default:
                return "process_event"
            }
        case .file:
            return "file_event"
        case .network:
            return "network_connection"
        case .authentication:
            return "authentication"
        case .tcc:
            return "tcc_event"
        case .registry:
            return "registry_event"
        }
    }

    // MARK: - Correlation

    /// Generate a correlation key for a newly matched step based on the rule's
    /// correlation type.
    ///
    /// The key groups partial matches so that only events sharing the same
    /// correlation value can advance the same partial match.
    private func generateCorrelationKey(
        _ type: CorrelationType,
        matched: MatchedStep,
        ruleId: String
    ) -> String? {
        switch type {
        case .processSame:
            return String(matched.processPid)
        case .processLineage:
            // Use the process path as a loose key; actual ancestry is verified
            // at match time via checkProcessRelation / lineage queries.
            // The root ancestor PID would be ideal but requires an async call;
            // we use the PID as the key and verify ancestry dynamically.
            return String(matched.processPid)
        case .filePath:
            return matched.filePath
        case .networkEndpoint:
            return matched.networkDest
        case .none:
            // Each partial match is independent -- use a unique key.
            return "\(ruleId):\(UUID().uuidString)"
        }
    }

    // MARK: - Advance / Match Construction (#95 shared helpers)

    /// Try to advance `partial` by matching `step` with an already-built
    /// `MatchedStep`. Returns the updated partial if every constraint
    /// (correlation, ordering, afterStep, processRelation) passes, else nil.
    ///
    /// Operates purely on `MatchedStep` — never a live `Event` — so the Phase-1
    /// live path and the Phase-3 replay path share ONE constraint implementation
    /// and cannot drift (cf. corr-detection #275). Callers own trigger/completion
    /// and list mutation. `matched.timestamp`/`processPid`/`processPath` stand in
    /// for the former `event.timestamp`/`process.pid`/`process.executable`, which
    /// are identical because `MatchedStep` is built from that same event.
    private func advancePartial(
        rule: SequenceRule,
        step: SequenceStep,
        matched: MatchedStep,
        partial: PartialMatch
    ) async -> PartialMatch? {
        // Skip if this step is already matched in this partial.
        guard partial.matchedSteps[step.id] == nil else { return nil }

        // Correlation constraint. For `.processLineage`, a step that declares
        // its OWN `processRelation` governs its process linkage, so the
        // rule-level lineage gate must NOT additionally reject it. Pre-GA review
        // regression: the #274 lineage gate (added to stop processLineage rules
        // with NO step relation firing on unrelated processes) also killed steps
        // that INTENTIONALLY declare `.any` — e.g. archive_to_cloud_exfil's
        // `cloud_upload` (`archive_sensitive.any`), where the upload tool is
        // launched independently by the shell rather than spawned by the archive
        // process, so it's never in the archive step's ancestry. `.any` is an
        // explicit "no process constraint" by the rule author; honor it here and
        // let the step-level relation below be the authoritative check. Steps
        // with NO explicit relation still get the #274 lineage gate.
        let stepGovernsProcessLinkage =
            rule.correlationType == .processLineage && step.processRelation != nil
        if !stepGovernsProcessLinkage {
            if !(await checkCorrelation(rule.correlationType, partial: partial, candidate: matched)) {
                return nil
            }
        }
        // Ordering constraint.
        if rule.ordered {
            if !checkOrdering(step: step, rule: rule, partial: partial, candidateTimestamp: matched.timestamp) {
                return nil
            }
        }
        // Explicit afterStep constraint.
        if let afterStepId = step.afterStep {
            guard let afterMatched = partial.matchedSteps[afterStepId],
                  matched.timestamp >= afterMatched.timestamp else {
                return nil
            }
        }
        // Process relationship constraint.
        if let spec = step.processRelation {
            guard let refStep = partial.matchedSteps[spec.relativeToStep] else {
                return nil
            }
            let relationHolds = await checkProcessRelation(
                spec.relation,
                eventPid: matched.processPid,
                eventPath: matched.processPath,
                referencePid: refStep.processPid,
                referencePath: refStep.processPath
            )
            guard relationHolds else { return nil }
        }

        var updated = partial
        updated.matchedSteps[step.id] = matched
        return updated
    }

    /// Build the `RuleMatch` for a completed sequence. Single construction point
    /// shared by Phase 1, Phase 2, and the Phase-3 replay so the emitted fields
    /// can't diverge between paths.
    private func makeMatch(rule: SequenceRule, partial: PartialMatch) -> RuleMatch {
        RuleMatch(
            ruleId: rule.id,
            ruleName: rule.title,
            severity: rule.level,
            description: buildDescription(rule: rule, partial: partial),
            mitreTechniques: rule.tags.filter { $0.hasPrefix("attack.t") },
            tags: rule.tags,
            suppressible: rule.suppressible ?? true
        )
    }

    /// Buffer an ordered rule's later step that arrived before its initial step
    /// (the A2 cross-consumer race — see `pendingLaterSteps`). Bounded per rule
    /// (oldest evicted) and deduped by (eventId, stepId) so the same event can't
    /// be buffered twice across re-evaluations.
    private func bufferPendingStep(ruleId: String, step: SequenceStep, matched: MatchedStep, now: Date) {
        var buf = pendingLaterSteps[ruleId] ?? []
        if buf.contains(where: { $0.matched.eventId == matched.eventId && $0.step.id == step.id }) {
            return
        }
        buf.append(PendingStep(step: step, matched: matched, arrivedAt: now))
        if buf.count > Self.maxPendingPerRule {
            buf.removeFirst(buf.count - Self.maxPendingPerRule)
        }
        pendingLaterSteps[ruleId] = buf
    }

    /// Replay buffered out-of-order later steps for `ruleId` against the rule's
    /// current partials (called right after an initial step seeds a new partial).
    /// Buffered steps are tried oldest-first BY EVENT TIMESTAMP so a 3+ step chain
    /// that arrived fully reversed still assembles in rule order. A step that
    /// advances a partial is consumed (removed from the buffer); one that
    /// completes a sequence returns a `RuleMatch`. Window-expired buffered steps
    /// are pruned. Uses the SAME `advancePartial` as the live path.
    private func replayPendingSteps(ruleId: String, rule: SequenceRule, now: Date) async -> [RuleMatch] {
        guard var pending = pendingLaterSteps[ruleId], !pending.isEmpty else { return [] }

        // Drop buffered steps older than the rule window.
        pending.removeAll { now.timeIntervalSince($0.arrivedAt) > rule.window }
        guard !pending.isEmpty else { pendingLaterSteps[ruleId] = nil; return [] }

        var matches: [RuleMatch] = []
        var consumed = Set<Int>()
        var partials = partialMatches[ruleId] ?? []

        let order = pending.indices.sorted {
            pending[$0].matched.timestamp < pending[$1].matched.timestamp
        }
        for pi in order {
            let pend = pending[pi]
            for (idx, partial) in partials.enumerated() {
                if now.timeIntervalSince(partial.createdAt) > rule.window { continue }
                guard let updated = await advancePartial(
                    rule: rule, step: pend.step, matched: pend.matched, partial: partial
                ) else { continue }
                consumed.insert(pi)
                if isTriggerSatisfied(rule.trigger, matchedStepIds: Set(updated.matchedSteps.keys), totalSteps: rule.steps.count) {
                    partials.remove(at: idx)
                    totalPartialCount -= 1
                    matches.append(makeMatch(rule: rule, partial: updated))
                } else {
                    partials[idx] = updated
                }
                break  // one partial advanced per buffered step
            }
        }

        partialMatches[ruleId] = partials
        if !consumed.isEmpty {
            pending = pending.enumerated().filter { !consumed.contains($0.offset) }.map(\.element)
        }
        pendingLaterSteps[ruleId] = pending.isEmpty ? nil : pending
        return matches
    }

    /// Check whether a candidate matched step satisfies the rule's correlation
    /// constraint with respect to an existing partial match.
    private func checkCorrelation(
        _ type: CorrelationType,
        partial: PartialMatch,
        candidate: MatchedStep
    ) async -> Bool {
        switch type {
        case .none:
            // No correlation required -- always passes.
            return true

        case .processSame:
            // All steps must come from the same PID.
            guard let key = partial.correlationKey else { return true }
            return String(candidate.processPid) == key

        case .processLineage:
            // v1.21.4 (corr-detection #274): a rule declaring
            // `correlation: process.lineage` must ACTUALLY enforce that its
            // steps belong to one process tree. This branch previously returned
            // `true` unconditionally — a silent no-op — so the 6 processLineage
            // rules that carry NO step-level `process:` relation (incl. the
            // CRITICAL ransomware_kill_chain) fired on wholly unrelated
            // processes (any shell exec + any tmutil disable + any dd wipe in
            // the window), a large false-positive surface. Now: the candidate
            // must be in the same process tree (self / ancestor / descendant) as
            // at least one already-bound step. For ordered kill chains the first
            // (root) step stays bound, so sibling steps spawned by that root
            // still correlate through it. Step-level `processRelation` (checked
            // separately in Phase 1) further refines rules that declare it.
            for bound in partial.matchedSteps.values {
                if candidate.processPid == bound.processPid { return true }
                if await lineage.isDescendant(candidate.processPid, of: bound.processPid) { return true }
                if await lineage.isDescendant(bound.processPid, of: candidate.processPid) { return true }
            }
            return false

        case .filePath:
            guard let key = partial.correlationKey else { return true }
            return candidate.filePath == key

        case .networkEndpoint:
            guard let key = partial.correlationKey else { return true }
            return candidate.networkDest == key
        }
    }

    /// Check ordering constraints for a step within a partial match.
    ///
    /// In ordered mode, a step can only match if all preceding steps (by
    /// definition order in the rule) are already matched, and the candidate
    /// event's timestamp is not before any already-matched step's timestamp.
    private func checkOrdering(
        step: SequenceStep,
        rule: SequenceRule,
        partial: PartialMatch,
        candidateTimestamp: Date
    ) -> Bool {
        guard let stepIndex = rule.steps.firstIndex(where: { $0.id == step.id }) else {
            return false
        }

        // All preceding steps must already be matched.
        for i in 0 ..< stepIndex {
            let precedingStepId = rule.steps[i].id
            guard let precedingMatch = partial.matchedSteps[precedingStepId] else {
                return false
            }
            // Candidate must not occur before the preceding step.
            if candidateTimestamp < precedingMatch.timestamp {
                return false
            }
        }

        return true
    }

    // MARK: - Process Relationship Checking

    /// Check whether a process relationship holds between the event's process
    /// and a reference step's process using the lineage graph.
    ///
    /// - Parameters:
    ///   - relation: The required relationship.
    ///   - eventPid: PID of the current event's process.
    ///   - eventPath: Executable path of the current event's process.
    ///   - referencePid: PID of the reference step's process.
    ///   - referencePath: Executable path of the reference step's process.
    /// - Returns: `true` if the relationship holds.
    private func checkProcessRelation(
        _ relation: ProcessRelation,
        eventPid: pid_t,
        eventPath: String,
        referencePid: pid_t,
        referencePath: String
    ) async -> Bool {
        switch relation {
        case .same:
            return eventPid == referencePid

        case .descendant:
            // Event process is a child/grandchild of the reference process.
            return await lineage.isDescendant(eventPid, of: referencePid)

        case .ancestor:
            // Event process is a parent/grandparent of the reference process.
            return await lineage.isDescendant(referencePid, of: eventPid)

        case .sibling:
            // Event process and reference process share a direct parent.
            // Look up both PIDs in the lineage to find their parents.
            let eventAncestors = await lineage.ancestors(of: eventPid)
            let refAncestors = await lineage.ancestors(of: referencePid)

            guard let eventParent = eventAncestors.first,
                  let refParent = refAncestors.first else {
                return false
            }
            return eventParent.pid == refParent.pid

        case .sameProcess:
            // Identical to .same (exact PID); separate token used by authors.
            return eventPid == referencePid

        case .sameTree:
            // Same process, or anywhere in its ancestry/descendants.
            if eventPid == referencePid { return true }
            if await lineage.isDescendant(eventPid, of: referencePid) { return true }
            return await lineage.isDescendant(referencePid, of: eventPid)

        case .any:
            // No process-relationship constraint; correlate by window/order only.
            return true
        }
    }

    // MARK: - Trigger Evaluation

    /// Check if a trigger condition is satisfied given the current set of
    /// matched step IDs.
    private func isTriggerSatisfied(
        _ trigger: TriggerCondition,
        matchedStepIds: Set<String>,
        totalSteps: Int
    ) -> Bool {
        switch trigger {
        case .allSteps:
            return matchedStepIds.count == totalSteps

        case .steps(let requiredIds):
            return requiredIds.allSatisfy { matchedStepIds.contains($0) }

        case .anySteps(let n):
            return matchedStepIds.count >= n
        }
    }

    // MARK: - Housekeeping

    /// Remove partial matches whose creation time exceeds their rule's window.
    ///
    /// Called periodically from `evaluate(_:)` based on `sweepInterval`.
    private func sweepExpired() {
        let now = Date()

        for (ruleId, partials) in partialMatches {
            guard let rule = rules[ruleId] else {
                // Rule was removed; discard all its partials.
                totalPartialCount -= partials.count
                partialMatches.removeValue(forKey: ruleId)
                continue
            }

            let beforeCount = partials.count
            let surviving = partials.filter { now.timeIntervalSince($0.createdAt) <= rule.window }
            partialMatches[ruleId] = surviving.isEmpty ? nil : surviving
            totalPartialCount -= (beforeCount - surviving.count)
        }

        // #95: prune the out-of-order backfill buffer on the same cadence — a
        // buffered later step older than its rule's window can never combine
        // with a future initial step, so drop it (and any buffer whose rule was
        // removed) to keep the buffer from accreting under sustained load.
        for (ruleId, buffered) in pendingLaterSteps {
            guard let rule = rules[ruleId] else {
                pendingLaterSteps.removeValue(forKey: ruleId)
                continue
            }
            let surviving = buffered.filter { now.timeIntervalSince($0.arrivedAt) <= rule.window }
            pendingLaterSteps[ruleId] = surviving.isEmpty ? nil : surviving
        }

        // Trim eviction queue: remove front entries whose partial matches
        // have already been expired. We look up the largest window across
        // all rules as a conservative upper bound -- any ref older than
        // that is certainly gone.
        let maxWindow = rules.values.map(\.window).max() ?? 0
        while let front = evictionQueue.first,
              now.timeIntervalSince(front.createdAt) > maxWindow {
            evictionQueue.removeFirst()
        }
    }

    /// Evict the oldest partial matches to bring total count back under the cap.
    ///
    /// Uses the `evictionQueue` which is naturally ordered oldest-first
    /// (entries are appended at creation time). This avoids the previous
    /// O(n log n) sort of all 10K+ partial matches on every eviction.
    /// Stale refs (whose partial was already removed by sweepExpired or
    /// a completed sequence) are simply skipped.
    private func evictOldest(count: Int) {
        guard count > 0 else { return }

        var removed = 0
        while removed < count && !evictionQueue.isEmpty {
            let ref = evictionQueue.removeFirst()

            // Look up the partials array for this rule.
            guard var partials = partialMatches[ref.ruleId] else {
                // Rule's partials were already fully cleared (e.g. rule disabled).
                continue
            }

            // Find the actual partial match by creation time. If it was
            // already removed (expired, completed, or duplicate ref), skip.
            guard let idx = partials.firstIndex(where: { $0.createdAt == ref.createdAt }) else {
                continue
            }

            partials.remove(at: idx)
            totalPartialCount -= 1
            removed += 1

            if partials.isEmpty {
                partialMatches.removeValue(forKey: ref.ruleId)
            } else {
                partialMatches[ref.ruleId] = partials
            }
        }

        if removed > 0 {
            logger.warning("Evicted \(removed) oldest partial matches (cap: \(self.maxPartialMatches))")
        }
    }

    // MARK: - Helpers

    /// Extract a network destination string (ip:port) from an event.
    private func networkDestination(from event: Event) -> String? {
        guard let net = event.network else { return nil }
        return "\(net.destinationIp):\(net.destinationPort)"
    }

    /// Build a human-readable description for a completed sequence match.
    private func buildDescription(rule: SequenceRule, partial: PartialMatch) -> String {
        let stepSummaries = partial.matchedSteps
            .sorted { $0.value.timestamp < $1.value.timestamp }
            .map { stepId, matched in
                let elapsed = matched.timestamp.timeIntervalSince(partial.createdAt)
                return "\(stepId) (pid:\(matched.processPid), +\(String(format: "%.1f", elapsed))s)"
            }
            .joined(separator: " -> ")

        return "\(rule.description) [sequence: \(stepSummaries)]"
    }
}

// MARK: - Errors

/// Errors thrown by the sequence engine.
public enum SequenceEngineError: Error, LocalizedError {
    case directoryNotFound(String)
    case invalidRule(String, String)

    public var errorDescription: String? {
        switch self {
        case .directoryNotFound(let path):
            return "Sequence rule directory not found: \(path)"
        case .invalidRule(let ruleId, let detail):
            return "Invalid sequence rule '\(ruleId)': \(detail)"
        }
    }
}
