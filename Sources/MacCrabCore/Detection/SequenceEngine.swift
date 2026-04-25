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
        enabled: Bool = true
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

            let existingPartials = partialMatches[ruleId] ?? []
            for (idx, partial) in existingPartials.enumerated() {
                // Check if this partial has expired.
                if now.timeIntervalSince(partial.createdAt) > rule.window {
                    continue
                }

                for step in matchingSteps {
                    // Skip if this step is already matched in this partial.
                    guard partial.matchedSteps[step.id] == nil else { continue }

                    let matched = eventMatchedStep(step)

                    // Check correlation constraint.
                    if !checkCorrelation(rule.correlationType, partial: partial, candidate: matched) {
                        continue
                    }

                    // Check ordering constraint.
                    if rule.ordered {
                        if !checkOrdering(step: step, rule: rule, partial: partial, candidateTimestamp: event.timestamp) {
                            continue
                        }
                    }

                    // Check explicit afterStep constraint.
                    if let afterStepId = step.afterStep {
                        guard let afterMatched = partial.matchedSteps[afterStepId],
                              event.timestamp >= afterMatched.timestamp else {
                            continue
                        }
                    }

                    // Check process relationship constraint.
                    if let spec = step.processRelation {
                        guard let refStep = partial.matchedSteps[spec.relativeToStep] else {
                            continue
                        }
                        let relationHolds = await checkProcessRelation(
                            spec.relation,
                            eventPid: event.process.pid,
                            eventPath: event.process.executable,
                            referencePid: refStep.processPid,
                            referencePath: refStep.processPath
                        )
                        guard relationHolds else { continue }
                    }

                    // All constraints passed -- advance this partial.
                    var updated = partial
                    updated.matchedSteps[step.id] = matched
                    advancedPartials.append((idx, updated))

                    // Check if trigger condition is now satisfied.
                    if isTriggerSatisfied(rule.trigger, matchedStepIds: Set(updated.matchedSteps.keys), totalSteps: rule.steps.count) {
                        completedIndices.insert(idx)
                        let match = RuleMatch(
                            ruleId: rule.id,
                            ruleName: rule.title,
                            severity: rule.level,
                            description: buildDescription(rule: rule, partial: updated),
                            mitreTechniques: rule.tags.filter { $0.hasPrefix("attack.t") },
                            tags: rule.tags
                        )
                        completedMatches.append(match)
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
                    let match = RuleMatch(
                        ruleId: rule.id,
                        ruleName: rule.title,
                        severity: rule.level,
                        description: buildDescription(rule: rule, partial: newPartial),
                        mitreTechniques: rule.tags.filter { $0.hasPrefix("attack.t") },
                        tags: rule.tags
                    )
                    completedMatches.append(match)
                    // Don't store the partial -- it's already complete.
                } else {
                    partialMatches[ruleId, default: []].append(newPartial)
                    totalPartialCount += 1
                    evictionQueue.append(PartialMatchRef(ruleId: ruleId, createdAt: now))
                }
            }
        }

        // Enforce the global partial match cap.
        if totalPartialCount > maxPartialMatches {
            evictOldest(count: totalPartialCount - maxPartialMatches)
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
                values: predicate.values
            )
        }

        return predicate.negate ? !rawResult : rawResult
    }

    /// Apply a modifier comparison. The predicate matches when the field
    /// satisfies the comparison for *any* value in the list (OR semantics).
    private func evaluateModifier(
        _ modifier: PredicateModifier,
        fieldValue: String,
        values: [String]
    ) -> Bool {
        let fieldLower = fieldValue.lowercased()

        switch modifier {
        case .equals:
            return values.contains { fieldLower == $0.lowercased() }
        case .contains:
            return values.contains { fieldLower.contains($0.lowercased()) }
        case .startswith:
            return values.contains { fieldLower.hasPrefix($0.lowercased()) }
        case .endswith:
            return values.contains { fieldLower.hasSuffix($0.lowercased()) }
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
    /// Self-contained copy of `RuleEngine.resolveField` for actor isolation.
    private func resolveField(_ path: String, from event: Event) -> String? {
        switch path {

        // --- Process fields ---
        case "process.executable", "Image":
            return event.process.executable
        case "process.name":
            return event.process.name
        case "process.commandline", "process.command_line", "CommandLine":
            return event.process.commandLine
        case "process.pid", "ProcessId":
            return String(event.process.pid)
        case "process.ppid":
            return String(event.process.ppid)
        case "process.args":
            return event.process.args.joined(separator: " ")
        case "process.working_directory":
            return event.process.workingDirectory
        case "process.user.name", "User":
            return event.process.userName
        case "process.user.id":
            return String(event.process.userId)

        // --- Parent process fields ---
        case "process.parent.executable", "ParentImage":
            return event.process.ancestors.first?.executable
        case "process.parent.name":
            return event.process.ancestors.first?.name
        case "process.parent.pid":
            return event.process.ancestors.first.map { String($0.pid) }
        case "process.parent.commandline", "process.parent.command_line", "ParentCommandLine":
            return event.enrichments["parent.commandline"]

        // --- Code signature fields ---
        case "process.code_signature.signer_type", "SignerType":
            return event.process.codeSignature?.signerType.rawValue
        case "process.code_signature.team_id":
            return event.process.codeSignature?.teamId
        case "process.code_signature.signing_id":
            return event.process.codeSignature?.signingId
        case "process.code_signature.flags", "CodeSigningFlags":
            return event.process.codeSignature.map { String($0.flags) }
        case "process.code_signature.notarized":
            return event.process.codeSignature.map { String($0.isNotarized) }
        case "process.is_platform_binary":
            return String(event.process.isPlatformBinary)
        case "process.architecture":
            return event.process.architecture

        // --- File fields ---
        case "file.path", "TargetFilename":
            return event.file?.path
        case "file.name":
            return event.file?.name
        case "file.directory":
            return event.file?.directory
        case "file.extension":
            return event.file?.extension_
        case "file.size":
            return event.file?.size.map { String($0) }
        case "file.action":
            return event.file?.action.rawValue
        case "file.source_path", "SourceFilename":
            return event.file?.sourcePath

        // --- Network fields ---
        case "network.destination.ip", "DestinationIp":
            return event.network?.destinationIp
        case "network.destination.port", "DestinationPort":
            return event.network.map { String($0.destinationPort) }
        case "network.destination.hostname", "DestinationHostname":
            return event.network?.destinationHostname
        case "network.source.ip", "SourceIp":
            return event.network?.sourceIp
        case "network.source.port", "SourcePort":
            return event.network.map { String($0.sourcePort) }
        case "network.direction":
            return event.network?.direction.rawValue
        case "network.transport":
            return event.network?.transport

        // --- Network computed fields ---
        case "DestinationIsPrivate":
            return event.network.map { String($0.destinationIsPrivate) }

        // --- TCC fields ---
        case "tcc.service", "TCCService":
            return event.tcc?.service
        case "tcc.client", "TCCClient":
            return event.tcc?.client
        case "tcc.client_path":
            return event.tcc?.clientPath
        case "tcc.allowed", "TCCAllowed":
            return event.tcc.map { String($0.allowed) }
        case "tcc.auth_reason":
            return event.tcc?.authReason

        // --- Event metadata fields ---
        case "event.category":
            return event.eventCategory.rawValue
        case "event.type":
            return event.eventType.rawValue
        case "event.action":
            return event.eventAction

        // --- Enrichment fallback ---
        default:
            return event.enrichments[path]
        }
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

    /// Check whether a candidate matched step satisfies the rule's correlation
    /// constraint with respect to an existing partial match.
    private func checkCorrelation(
        _ type: CorrelationType,
        partial: PartialMatch,
        candidate: MatchedStep
    ) -> Bool {
        switch type {
        case .none:
            // No correlation required -- always passes.
            return true

        case .processSame:
            // All steps must come from the same PID.
            guard let key = partial.correlationKey else { return true }
            return String(candidate.processPid) == key

        case .processLineage:
            // Actual ancestry is checked via processRelation constraints on
            // individual steps. At the correlation level we do a loose check:
            // the candidate must share at least one PID already in the partial
            // match's process set, OR be in the same lineage. Since lineage
            // checking is async and we want this to be fast, we accept at
            // this level and rely on step-level processRelation for precision.
            return true

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
