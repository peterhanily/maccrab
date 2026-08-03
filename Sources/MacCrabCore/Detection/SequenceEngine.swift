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
import CryptoKit
import os.log

// MARK: - Sequence Rule Types

/// How the steps of a sequence rule relate to each other.
public enum CorrelationType: String, Codable, Sendable, Hashable {
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
public enum ProcessRelation: String, Codable, Sendable, Hashable {
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
public enum TriggerCondition: Codable, Sendable, Hashable {
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
public struct SequenceStep: Codable, Sendable, Hashable {
    /// Unique identifier for this step within the rule (e.g. "download", "execute").
    public let id: String

    /// The logsource category this step matches (e.g. "process_creation", "file_event").
    public let logsourceCategory: String

    /// Predicates that the event must satisfy for this step.
    public let predicates: [Predicate]

    /// How predicates are combined: all must match, or any suffices.
    public let condition: RuleCondition

    /// Full Sigma boolean expression for complex step conditions. When
    /// present this takes precedence over the legacy flat `condition`, exactly
    /// as it does for CompiledRule. Optional preserves decoding of previously
    /// compiled sequence rules, which legitimately contain only the flat form.
    public let conditionTree: ConditionNode?

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
        conditionTree: ConditionNode? = nil,
        afterStep: String? = nil,
        processRelation: ProcessRelationSpec? = nil
    ) {
        self.id = id
        self.logsourceCategory = logsourceCategory
        self.predicates = predicates
        self.condition = condition
        self.conditionTree = conditionTree
        self.afterStep = afterStep
        self.processRelation = processRelation
    }

    private enum CodingKeys: String, CodingKey {
        case id, logsourceCategory, predicates, condition, afterStep, processRelation
        case conditionTree = "condition_tree"
    }
}

/// Specifies a process relationship constraint between two steps.
public struct ProcessRelationSpec: Codable, Sendable, Hashable {
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
public struct SequenceRule: Codable, Sendable, Identifiable, Hashable {
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

    /// v1.21.5: Sigma `status` carried from the YAML (stable / experimental /
    /// deprecated) so `loadRules(enabledStatuses:)` can apply the F-04
    /// rule_profile gate to sequences. Optional + decode-safe: compilers before
    /// v1.21.5 didn't emit the key for sequences, so a stale compiled dir
    /// decodes to nil — the loader grandfathers nil as "stable".
    public let status: String?

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
        suppressible: Bool? = nil,
        status: String? = nil
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
        self.status = status
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
        let id: UUID
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

    /// A recent later (non-initial) step for an ordered rule. These entries are
    /// retained for the rule window even after advancing a currently-known
    /// partial: another initial event may have happened before this step but be
    /// delivered later by the other pipeline lane. Treating the entry as
    /// single-consumer state makes detection depend on lane delivery order.
    private struct PendingStep: Sendable {
        let step: SequenceStep
        let matched: MatchedStep
        let arrivedAt: Date
    }

    private struct EventEvaluationPlan {
        let ruleId: String
        let rule: SequenceRule
        let matchingSteps: [SequenceStep]
    }

    /// v1.21.4 (corr-event-pipeline #95): backfill buffer for out-of-order
    /// later steps, keyed by rule ID. The A2 event-pipeline split routes `.file`
    /// events to a separate consumer from process/network events; under a file
    /// flood the file consumer lags, so a cross-family ordered rule's later
    /// step (process/network, on the fast priority consumer) can reach
    /// `evaluate` BEFORE its `step[0]` file event. Ordered mode only seeds a
    /// partial from `step[0]`, so that later step would otherwise be dropped and
    /// 23 of the highest-value kill chains (supply-chain, dropper→C2, ransomware)
    /// would silently never complete. We retain recent later steps here and
    /// replay them whenever a delayed `step[0]` seeds a partial. A later event is
    /// history, not a consumable token: the live path fans one event out to every
    /// compatible partial, and replay must do the same for partials that become
    /// known later. Bounded per rule + window-pruned so a broadly matching later
    /// step cannot grow the history without limit.
    private var pendingLaterSteps: [String: [PendingStep]] = [:]

    /// Per-rule cap on buffered out-of-order later steps. Oldest evicted first.
    private static let maxPendingPerRule = 256

    /// Exact number of partials currently present in `partialMatches`.
    ///
    /// This deliberately derives from the source of truth instead of caching a
    /// second mutable count. The old counter was updated independently on seed,
    /// completion, sweep, eviction, disable, and reload paths. Worse, an
    /// `evaluate` can suspend while querying `ProcessLineage`, allowing another
    /// evaluation to enter the actor and consume the same stale snapshot. Both
    /// calls then decremented the counter for one stored partial, driving it
    /// negative and permanently disabling the global cap. The dictionary has at
    /// most one bucket per sequence rule, so deriving the count is bounded by the
    /// rule corpus size rather than the (10,000-item) partial pool size.
    private var totalPartialCount: Int {
        partialMatches.values.reduce(into: 0) { $0 += $1.count }
    }

    /// Hard cap on total partial matches to bound memory usage.
    private let maxPartialMatches: Int

    /// How often (in seconds) the engine sweeps for expired partial matches.
    private let sweepInterval: TimeInterval

    /// Last time an expiration sweep was performed.
    private var lastSweep: Date = Date()

    /// v1.21.4 (#20): last time the pre-emptive (>80%-capacity) sweep ran.
    /// Before this, the pre-emptive sweep ran a full O(partials) `sweepExpired`
    /// on EVERY event once partials exceeded 80% of the cap — under a sustained
    /// flood that is one full pool scan per event. It is now throttled to at most
    /// once per `preemptiveSweepInterval`.
    ///
    /// Detection-exactness is preserved: `sweepExpired` only removes ALREADY-
    /// expired partials, and an expired partial is also skipped during Phase-1/3
    /// advancement (`now - createdAt > window` → `continue`), so it can never
    /// produce a match regardless of when it is physically removed. The ONE
    /// operation that can drop a LIVE partial is `evictOldest`, and the cap-
    /// enforcement path in `evaluate` now calls `sweepExpired` immediately before
    /// `evictOldest`. That reproduces the pre-throttle invariant — whenever
    /// `evictOldest` ran, the per-event pre-emptive sweep had already cleared
    /// expired partials on the same event — so eviction still sees the identical
    /// live-only set and drops the identical partials.
    private var lastPreemptiveSweep: Date = .distantPast

    /// Minimum interval between pre-emptive (>80%-capacity) sweeps. Smaller than
    /// `sweepInterval` so memory is still trimmed between the 1s regular sweeps,
    /// but bounded so a flood cannot force a per-event full-pool scan.
    private static let preemptiveSweepInterval: TimeInterval = 0.25

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

    /// Reference to a partial match by stable identity, used for LRU eviction.
    /// Entries are appended at the back (newest) and
    /// removed from the front (oldest), so the array stays naturally sorted
    /// by creation time without any explicit sorting.
    private struct PartialMatchRef: Sendable {
        let ruleId: String
        let partialId: UUID
        let createdAt: Date
    }

    /// Queue of partial-match references ordered oldest-first (append new,
    /// advance `evictionQueueHead` at the front). A head index avoids Array's
    /// O(n) `removeFirst()` shift on every cap eviction. Completed/expired
    /// partials leave stale refs until the bounded compactor runs; the queue is
    /// periodically rebuilt from the authoritative partial-ID set so metadata
    /// cannot grow with lifetime seed throughput.
    private var evictionQueue: [PartialMatchRef] = []
    private var evictionQueueHead = 0

    /// Maximum stale-reference slack above the configured live-partial cap.
    /// This amortizes rebuild cost while bounding auxiliary metadata even when
    /// partials seed and complete rapidly without ever hitting the live cap.
    private static let evictionQueueStaleSlack = 256

    /// Constructor bounds are defensive because this initializer is public.
    /// The upper bound leaves headroom for both the 80%-capacity multiplication
    /// and eviction-reference slack; the lower bound prevents a malformed
    /// negative/zero cap from disabling every multi-event sequence.
    private static let minimumPartialMatchLimit = 1
    private static let maximumPartialMatchLimit =
        (Int.max - evictionQueueStaleSlack) / 8
    private static let defaultSweepInterval: TimeInterval = 1.0

    /// Cumulative partial matches dropped by the global cap. Read via
    /// `partialsEvictedTotal` and published in the heartbeat — see that
    /// accessor for why an unmetered eviction is a detection-integrity problem
    /// and not just a diagnostics gap.
    private var evictedPartialCount: Int = 0

    /// `SequenceEngine` is an actor, but actor isolation is reentrant at every
    /// `await`. Evaluation performs asynchronous lineage queries after taking
    /// snapshots of partial state, so actor isolation alone does not make the
    /// read/advance/replace transaction atomic. This FIFO lease serializes all
    /// public state-mutating operations across those suspension points.
    private enum MutationLeaseAcquisition: Sendable, Equatable {
        case acquired
        case cancelled
        case saturated
    }

    private struct MutationWaiter {
        let id: UUID
        let continuation: CheckedContinuation<MutationLeaseAcquisition, Never>
    }

    private var mutationLeaseHeld = false
    private var mutationWaiters: [MutationWaiter] = []
    private var mutationWaiterHead = 0
    private let mutationWaiterLimit: Int
    private var mutationWaiterHighWatermark = 0
    private var cancelledMutationWaiterCount: UInt64 = 0
    private var saturatedMutationWaiterCount: UInt64 = 0
    private static let defaultMutationWaiterLimit = 1_024

    private let logger = Logger(subsystem: "com.maccrab.detection", category: "SequenceEngine")

    // MARK: - Initialization

    /// Creates a new sequence engine.
    ///
    /// - Parameters:
    ///   - lineage: The process lineage tracker used for ancestry-based
    ///     correlation checks.
    ///   - maxPartialMatches: Upper bound on total in-flight partial matches
    ///     across all rules. Oldest are evicted when exceeded. Values outside
    ///     the arithmetic-safe range are clamped. Defaults to 10000.
    ///   - sweepInterval: How often (seconds) to scan for expired partial
    ///     matches. NaN, infinity, and negative values fall back to 1 second;
    ///     zero intentionally requests a sweep on every evaluation.
    public init(
        lineage: ProcessLineage,
        maxPartialMatches: Int = 10_000,
        sweepInterval: TimeInterval = 1.0
    ) {
        self.lineage = lineage
        self.maxPartialMatches = min(
            max(maxPartialMatches, Self.minimumPartialMatchLimit),
            Self.maximumPartialMatchLimit
        )
        self.sweepInterval = sweepInterval.isFinite && sweepInterval >= 0
            ? sweepInterval
            : Self.defaultSweepInterval
        self.mutationWaiterLimit = Self.defaultMutationWaiterLimit
    }

    /// Internal constructor used by bounded-queue tests. Production callers use
    /// the public initializer above and its fixed 1,024-waiter ceiling.
    init(
        lineage: ProcessLineage,
        maxPartialMatches: Int = 10_000,
        sweepInterval: TimeInterval = 1.0,
        mutationWaiterLimit: Int
    ) {
        self.lineage = lineage
        self.maxPartialMatches = min(
            max(maxPartialMatches, Self.minimumPartialMatchLimit),
            Self.maximumPartialMatchLimit
        )
        self.sweepInterval = sweepInterval.isFinite && sweepInterval >= 0
            ? sweepInterval
            : Self.defaultSweepInterval
        self.mutationWaiterLimit = max(1, mutationWaiterLimit)
    }

    // MARK: - Reentrancy Guard

    private var activeMutationWaiterCount: Int {
        max(0, mutationWaiters.count - mutationWaiterHead)
    }

    private func acquireMutationLease() async -> MutationLeaseAcquisition {
        guard !Task.isCancelled else { return .cancelled }

        if !mutationLeaseHeld {
            mutationLeaseHeld = true
            return .acquired
        }

        guard activeMutationWaiterCount < mutationWaiterLimit else {
            Self.incrementSaturating(&saturatedMutationWaiterCount)
            return .saturated
        }

        let waiterId = UUID()
        let result = await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                mutationWaiters.append(MutationWaiter(
                    id: waiterId,
                    continuation: continuation
                ))
                mutationWaiterHighWatermark = max(
                    mutationWaiterHighWatermark,
                    activeMutationWaiterCount
                )
            }
        } onCancel: {
            Task { await self.cancelMutationWaiter(waiterId) }
        }

        // Cancellation can race the lease handoff after the waiter has been
        // removed from the FIFO. In that case the continuation legitimately
        // owns the lease; release it here before reporting cancellation.
        if result == .acquired, Task.isCancelled {
            releaseMutationLease()
            return .cancelled
        }
        return result
    }

    private func cancelMutationWaiter(_ waiterId: UUID) {
        guard mutationWaiterHead < mutationWaiters.count,
              let index = mutationWaiters[mutationWaiterHead...]
                .firstIndex(where: { $0.id == waiterId }) else { return }

        let waiter = mutationWaiters.remove(at: index)
        Self.incrementSaturating(&cancelledMutationWaiterCount)
        compactMutationWaiterPrefix()
        waiter.continuation.resume(returning: .cancelled)
    }

    private func compactMutationWaiterPrefix() {
        guard mutationWaiterHead > 0 else { return }
        if mutationWaiterHead == mutationWaiters.count {
            mutationWaiters.removeAll(keepingCapacity: true)
            mutationWaiterHead = 0
        } else if mutationWaiterHead >= 1_024
                    || mutationWaiterHead >= mutationWaiters.count - mutationWaiterHead {
            mutationWaiters.removeFirst(mutationWaiterHead)
            mutationWaiterHead = 0
        }
    }

    private func releaseMutationLease() {
        if mutationWaiterHead < mutationWaiters.count {
            let next = mutationWaiters[mutationWaiterHead]
            mutationWaiterHead += 1
            compactMutationWaiterPrefix()
            next.continuation.resume(returning: .acquired)
        } else {
            mutationWaiters.removeAll(keepingCapacity: true)
            mutationWaiterHead = 0
            mutationLeaseHeld = false
        }
    }

    private static func incrementSaturating(_ value: inout UInt64) {
        if value < UInt64.max { value += 1 }
    }

    private func acquireMutationLeaseOrThrow() async throws {
        switch await acquireMutationLease() {
        case .acquired:
            return
        case .cancelled:
            throw CancellationError()
        case .saturated:
            throw SequenceEngineError.mutationQueueSaturated(mutationWaiterLimit)
        }
    }

    // MARK: - State Consistency

    /// Remove a rule ID from every dispatch-index bucket before replacing its
    /// definition. `loadRules` is additive, so a same-ID rule can otherwise
    /// leave stale category memberships from its prior definition.
    private func removeRuleFromIndex(_ ruleId: String) {
        for category in Array(ruleIndex.keys) {
            ruleIndex[category]?.remove(ruleId)
            if ruleIndex[category]?.isEmpty == true {
                ruleIndex.removeValue(forKey: category)
            }
        }
    }

    /// Drop all in-flight state whose interpretation depends on the specified
    /// rule definitions. Each surface is keyed independently: a pending-only
    /// rule has no `partialMatches` bucket, so cleanup must never be nested under
    /// a partial-bucket loop.
    private func purgeRuntimeState(for ruleIds: Set<String>, resetStats: Bool) {
        guard !ruleIds.isEmpty else { return }
        for ruleId in ruleIds {
            partialMatches.removeValue(forKey: ruleId)
            pendingLaterSteps.removeValue(forKey: ruleId)
            if resetStats {
                ruleStats.removeValue(forKey: ruleId)
            }
        }
        compactEvictionQueue(force: true)
    }

    /// Install or replace one additive rule. Equivalent same-ID definitions keep
    /// their in-flight state; changed definitions cannot safely consume steps
    /// captured under the old predicate/order/trigger semantics.
    private func installRule(_ rule: SequenceRule) {
        if let previous = rules[rule.id] {
            if previous != rule {
                purgeRuntimeState(for: [rule.id], resetStats: true)
            }
            removeRuleFromIndex(rule.id)
        }
        rules[rule.id] = rule
        for step in rule.steps {
            ruleIndex[step.logsourceCategory, default: []].insert(rule.id)
        }
    }

    /// Number of unconsumed queue entries, excluding the retained Array prefix.
    private var activeEvictionReferenceCount: Int {
        max(0, evictionQueue.count - evictionQueueHead)
    }

    private var evictionReferenceRetentionLimit: Int {
        let liveBound = max(maxPartialMatches, totalPartialCount)
        guard liveBound <= Int.max - Self.evictionQueueStaleSlack else {
            return Int.max
        }
        return liveBound + Self.evictionQueueStaleSlack
    }

    /// Rebuild the eviction queue from stable IDs that still exist in the source
    /// of truth. Forced rebuilds accompany sweep/reload/disable; opportunistic
    /// rebuilds cap stale metadata at live-cap + a small amortization allowance.
    private func compactEvictionQueue(force: Bool = false) {
        let liveCount = totalPartialCount
        let prefixNeedsCompaction = evictionQueueHead >= 1_024
            && evictionQueueHead * 2 >= evictionQueue.count
        guard force
                || activeEvictionReferenceCount > evictionReferenceRetentionLimit
                || prefixNeedsCompaction else { return }

        var liveIds = Set<UUID>()
        liveIds.reserveCapacity(liveCount)
        for partials in partialMatches.values {
            for partial in partials {
                liveIds.insert(partial.id)
            }
        }

        if evictionQueueHead < evictionQueue.count {
            evictionQueue = evictionQueue[evictionQueueHead...].filter {
                liveIds.contains($0.partialId)
            }
        } else {
            evictionQueue.removeAll(keepingCapacity: true)
        }
        evictionQueueHead = 0
    }

    /// Pop in O(1) amortized time. Array storage is occasionally compacted in
    /// bulk instead of shifted once per cap eviction.
    private func popOldestEvictionReference() -> PartialMatchRef? {
        guard evictionQueueHead < evictionQueue.count else {
            evictionQueue.removeAll(keepingCapacity: true)
            evictionQueueHead = 0
            return nil
        }

        let ref = evictionQueue[evictionQueueHead]
        evictionQueueHead += 1
        if evictionQueueHead == evictionQueue.count {
            evictionQueue.removeAll(keepingCapacity: true)
            evictionQueueHead = 0
        } else if evictionQueueHead >= 1_024,
                  evictionQueueHead * 2 >= evictionQueue.count {
            evictionQueue = Array(evictionQueue[evictionQueueHead...])
            evictionQueueHead = 0
        }
        return ref
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

    private struct RuleLoadBatch {
        let rules: [SequenceRule]
        let sourceFileNames: Set<String>
        let sourceFileHashes: [String: String]
        let failures: [String]
    }

    private struct RuleBundleManifest: Decodable {
        let hashes: [String: String]
    }

    /// Load sequence rules from JSON files in a directory.
    ///
    /// Each `.json` file must contain a single `SequenceRule`. Files that fail
    /// to parse are logged and skipped.
    ///
    /// - Parameter directory: URL to the directory containing rule files.
    /// - Parameter enabledStatuses: v1.21.5 (F-04 parity): when non-nil, only
    ///   rules whose Sigma `status` is in the set are loaded — sequences
    ///   previously bypassed the rule_profile gate entirely, so the 36
    ///   experimental sequence rules ran on default "stable" installs. nil
    ///   (the default) = no filtering, which keeps direct callers and the
    ///   test suite on the legacy behavior.
    /// - Returns: The number of rules successfully loaded.
    @discardableResult
    public func loadRules(from directory: URL, enabledStatuses: Set<String>? = nil) async throws -> Int {
        try await acquireMutationLeaseOrThrow()
        defer { releaseMutationLease() }
        try Task.checkCancellation()
        return try loadRulesWithLease(from: directory, enabledStatuses: enabledStatuses)
    }

    /// Synchronous implementation for callers that already hold the mutation
    /// lease. Initial load remains best-effort, matching `RuleEngine`: malformed
    /// files are logged and skipped because N-1 rules are better than zero when
    /// no last-known-good corpus exists yet. Reload stages the same batch but
    /// rejects any failure before changing live state.
    private func loadRulesWithLease(from directory: URL, enabledStatuses: Set<String>? = nil) throws -> Int {
        let batch = try readRuleBatch(from: directory, enabledStatuses: enabledStatuses)
        for rule in batch.rules {
            installRule(rule)
        }
        precompileRegexes()
        logger.info("Loaded \(batch.rules.count) sequence rules from \(directory.path)")
        return batch.rules.count
    }

    /// Read and validate a stable directory snapshot without mutating engine
    /// state. `RuleFileLoadingPolicy` provides the no-follow bounded file read;
    /// the second listing catches a compiler/installer changing the candidate
    /// inventory while it is being staged.
    private func readRuleBatch(
        from directory: URL,
        enabledStatuses: Set<String>?
    ) throws -> RuleLoadBatch {
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

        let jsonFiles = contents
            .filter { $0.pathExtension == "json" && $0.lastPathComponent != "manifest.json" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
        let sourceFileNames = Set(jsonFiles.map(\.lastPathComponent))
        if jsonFiles.isEmpty {
            logger.warning("No .json sequence rule files found in \(directory.path)")
        }

        let decoder = JSONDecoder()
        var staged: [SequenceRule] = []
        var sourceFileHashes: [String: String] = [:]
        var failures: [String] = []

        for file in jsonFiles {
            do {
                let data = try RuleFileLoadingPolicy.read(file)
                sourceFileHashes[file.lastPathComponent] = SHA256.hash(data: data)
                    .map { String(format: "%02x", $0) }
                    .joined()
                var rule = try decoder.decode(SequenceRule.self, from: data)
                // v1.21.5: deprecated = retired detection; must not run under
                // ANY profile — including nil ("all"). Skipped BEFORE the
                // profile filter because the `rule.enabled = true` below would
                // otherwise stomp the compiled enabled=false and revive it.
                // Mirrors single-event semantics (deprecated stays disabled
                // even under rule_profile "all").
                if (rule.status ?? "stable").lowercased() == "deprecated" {
                    continue
                }
                // v1.21.5 stable-profile gate: skip rules outside the active
                // profile. A rule with NO status key is treated as "stable" —
                // compilers before v1.21.5 didn't emit status for sequences,
                // so a stale compiled_rules dir would otherwise lose ALL 41
                // sequences (including the 5 stable ones) until the operator
                // recompiles. Grandfathering nil keeps them running.
                if let allowed = enabledStatuses,
                   !allowed.contains((rule.status ?? "stable").lowercased()) {
                    continue
                }
                rule.enabled = true

                // Validate rule structure before accepting it.
                try validateRule(rule)
                staged.append(rule)
            } catch {
                logger.error("Failed to load sequence rule from \(file.lastPathComponent): \(error.localizedDescription)")
                failures.append(file.lastPathComponent)
            }
        }

        let finalContents = try fm.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles]
        )
        let finalSourceFileNames = Set(finalContents.compactMap { file -> String? in
            guard file.pathExtension == "json", file.lastPathComponent != "manifest.json" else {
                return nil
            }
            return file.lastPathComponent
        })
        guard finalSourceFileNames == sourceFileNames else {
            throw SequenceEngineError.ruleDirectoryChangedDuringReload(directory.path)
        }

        return RuleLoadBatch(
            rules: staged,
            sourceFileNames: sourceFileNames,
            sourceFileHashes: sourceFileHashes,
            failures: failures
        )
    }

    private func precompileRegexes() {
        for rule in rules.values {
            for step in rule.steps {
                for predicate in step.predicates where predicate.modifier == .regex {
                    for pattern in predicate.values {
                        _ = cachedRegex(for: pattern)
                    }
                }
            }
        }
    }

    /// Validate a release corpus against its explicit parent manifest. This is
    /// the sharp-shrink guard: unlike a percentage threshold, an exact inventory
    /// permits any intentional removal when the producer updates `manifest.json`
    /// and rejects even one missing file when it does not. Developer/test trees
    /// without a manifest keep their legacy flexibility.
    ///
    /// - Returns: `true` when an explicit manifest was present (including an
    ///   intentional manifest declaring zero sequence files).
    private func validateReloadInventory(
        directory: URL,
        sourceFileNames: Set<String>,
        sourceFileHashes: [String: String]
    ) throws -> Bool {
        let manifestURL = directory.deletingLastPathComponent()
            .appendingPathComponent("manifest.json")
        guard FileManager.default.fileExists(atPath: manifestURL.path) else {
            return false
        }

        let manifest: RuleBundleManifest
        do {
            let data = try RuleFileLoadingPolicy.read(manifestURL)
            manifest = try JSONDecoder().decode(RuleBundleManifest.self, from: data)
        } catch {
            throw SequenceEngineError.invalidRuleManifest(error.localizedDescription)
        }

        var expectedHashes: [String: String] = [:]
        for (rawPath, hash) in manifest.hashes {
            var path = rawPath
            while path.hasPrefix("./") { path.removeFirst(2) }
            let components = path.split(separator: "/", omittingEmptySubsequences: false)
            guard components.count == 2,
                  components[0] == "sequences",
                  components[1].hasSuffix(".json") else { continue }
            expectedHashes[String(components[1])] = hash.lowercased()
        }
        let expected = Set(expectedHashes.keys)
        guard expected == sourceFileNames else {
            throw SequenceEngineError.ruleInventoryMismatch(
                missing: expected.subtracting(sourceFileNames).sorted(),
                unexpected: sourceFileNames.subtracting(expected).sorted()
            )
        }

        let hashMismatches = expected.filter { fileName in
            sourceFileHashes[fileName]?.lowercased() != expectedHashes[fileName]
        }.sorted()
        guard hashMismatches.isEmpty else {
            throw SequenceEngineError.ruleManifestHashMismatch(hashMismatches)
        }
        return true
    }

    /// Full-replace reload (SIGHUP / live profile change). `loadRules` is
    /// ADDITIVE — it merges into the live set and never evicts — so a sequence
    /// that becomes `deprecated`, falls outside a tightened `rule_profile`, or is
    /// deleted from the compiled dir would keep firing from its previously-loaded
    /// copy until a full daemon restart (mother-of-all-audits #6: the v1.21.5
    /// deprecated-skip + profile gate in loadRules gate LOADING but cannot EVICT).
    /// This stages a replacement rule set + dispatch index, mirroring the
    /// last-known-good contract in `RuleEngine.reloadRules`, then swaps only
    /// after validation. Last-known-good is atomic: any per-file
    /// failure or explicit manifest-inventory mismatch rejects the candidate
    /// before live state changes. A legacy manifest-less physically empty
    /// directory retains the prior corpus, while a nonempty corpus filtered to
    /// zero by an intentional profile change is allowed to become zero.
    public func reloadRules(from directory: URL, enabledStatuses: Set<String>? = nil) async throws -> Int {
        try await acquireMutationLeaseOrThrow()
        defer { releaseMutationLease() }
        try Task.checkCancellation()

        // Stage and validate everything first. No live rule, index, partial,
        // pending step, stat, or regex state changes on any rejection path.
        let batch = try readRuleBatch(from: directory, enabledStatuses: enabledStatuses)
        if !batch.failures.isEmpty {
            throw SequenceEngineError.partialRuleLoadFailure(
                failedFiles: batch.failures.sorted(),
                loaded: batch.rules.count
            )
        }
        let duplicateRuleIds = Dictionary(grouping: batch.rules, by: \.id)
            .compactMap { ruleId, definitions in
                definitions.count > 1 ? ruleId : nil
            }
            .sorted()
        if !duplicateRuleIds.isEmpty {
            throw SequenceEngineError.duplicateRuleIds(duplicateRuleIds)
        }
        let hasExplicitInventory = try validateReloadInventory(
            directory: directory,
            sourceFileNames: batch.sourceFileNames,
            sourceFileHashes: batch.sourceFileHashes
        )
        try Task.checkCancellation()

        let prevRules = rules
        if batch.sourceFileNames.isEmpty,
           !hasExplicitInventory,
           !prevRules.isEmpty {
            logger.warning("Sequence reload from \(directory.path) produced 0 rules; retaining \(prevRules.count) last-known-good rule(s)")
            return prevRules.count
        }

        var nextRules: [String: SequenceRule] = [:]
        var nextIndex: [String: Set<String>] = [:]
        for stagedRule in batch.rules {
            var rule = stagedRule
            // A successful reload replaces rule CONTENT, but an explicit runtime
            // disable is operator state. Preserve it for every surviving ID,
            // including a changed definition, exactly as RuleEngine does. Apply
            // it before equivalence testing below so an unchanged disabled rule
            // remains equal and keeps its telemetry rather than being spuriously
            // treated as a definition change solely because the loader defaults
            // every decoded rule to enabled.
            if prevRules[rule.id]?.enabled == false {
                rule.enabled = false
            }
            if let previous = nextRules[rule.id] {
                for step in previous.steps {
                    nextIndex[step.logsourceCategory]?.remove(rule.id)
                    if nextIndex[step.logsourceCategory]?.isEmpty == true {
                        nextIndex.removeValue(forKey: step.logsourceCategory)
                    }
                }
            }
            nextRules[rule.id] = rule
            for step in rule.steps {
                nextIndex[step.logsourceCategory, default: []].insert(rule.id)
            }
        }

        rules = nextRules
        ruleIndex = nextIndex

        // Retain in-flight state only when BOTH identity and the complete rule
        // definition are unchanged. A same-ID edit is not compatible state: an
        // old step key can otherwise combine with a new step and satisfy
        // `.allSteps` by count without every new-definition step ever occurring.
        let equivalentRuleIds = Set(rules.compactMap { ruleId, rule in
            prevRules[ruleId] == rule ? ruleId : nil
        })
        let stateRuleIds = Set(partialMatches.keys)
            .union(pendingLaterSteps.keys)
            .union(ruleStats.keys)
        purgeRuntimeState(
            for: stateRuleIds.subtracting(equivalentRuleIds),
            resetStats: true
        )
        // Even when no invalidated rule currently owns a bucket, remove stale
        // completed/expired refs and any queue-only state from old definitions.
        compactEvictionQueue(force: true)
        precompileRegexes()
        logger.info("Reloaded \(batch.rules.count) sequence rules from \(directory.path)")
        return batch.rules.count
    }

    /// Add a single rule programmatically (useful for tests).
    public func addRule(_ rule: SequenceRule) async throws {
        try await acquireMutationLeaseOrThrow()
        defer { releaseMutationLease() }
        try Task.checkCancellation()

        try validateRule(rule)
        installRule(rule)
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

        // Complex step conditions are executable rule logic. Reject malformed
        // trees at load rather than clamping/ignoring bad indices and silently
        // changing a detection's meaning. Legacy flat steps have no tree and
        // retain their prior evaluation path.
        for step in rule.steps {
            if let tree = step.conditionTree {
                do {
                    try tree.validate(predicateCount: step.predicates.count)
                } catch {
                    throw SequenceEngineError.invalidRule(
                        rule.id,
                        "Step '\(step.id)' has invalid condition_tree: \(error.localizedDescription)"
                    )
                }
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
    public func setEnabled(_ ruleId: String, enabled: Bool) async {
        guard await acquireMutationLease() == .acquired else { return }
        defer { releaseMutationLease() }
        guard !Task.isCancelled else { return }

        guard rules[ruleId] != nil else {
            logger.warning("setEnabled called for unknown sequence rule: \(ruleId)")
            return
        }
        rules[ruleId]?.enabled = enabled

        // If disabling, discard any in-flight partial matches for this rule.
        if !enabled {
            partialMatches.removeValue(forKey: ruleId)
            pendingLaterSteps.removeValue(forKey: ruleId)
            compactEvictionQueue(force: true)
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

    /// Cumulative count of partial matches evicted by the global cap since
    /// start. Eviction is oldest-first across a SINGLE global queue shared by
    /// every rule, so a flood of a cheap step[0] flushes other rules' in-flight
    /// kill-chain state — and until now the only trace of that was one
    /// `logger.warning`: no counter, no heartbeat gauge, no alert, so the flush
    /// primitive was completely unobservable from outside the log. Surfaced as
    /// `sequence_partials_evicted_total`.
    public var partialsEvictedTotal: Int {
        evictedPartialCount
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

    /// Internal diagnostics used by deterministic invariants tests. Keeping the
    /// representation private while exposing aggregate facts lets tests prove
    /// equal timestamps still have distinct identities and stale metadata stays
    /// bounded without reaching into actor state.
    struct EvictionQueueDiagnostics: Sendable {
        let referenceCount: Int
        let uniquePartialIdCount: Int
        let uniqueCreationTimeCount: Int
        let retentionLimit: Int
        let referencesMatchLivePartials: Bool
    }

    struct ConfigurationDiagnostics: Sendable {
        let maxPartialMatches: Int
        let sweepInterval: TimeInterval
    }

    struct MutationLeaseDiagnostics: Sendable {
        let held: Bool
        let waiterCount: Int
        let waiterStorageCount: Int
        let waiterLimit: Int
        let waiterHighWatermark: Int
        let cancelledWaiterCount: UInt64
        let saturatedWaiterCount: UInt64
    }

    func configurationDiagnostics() -> ConfigurationDiagnostics {
        ConfigurationDiagnostics(
            maxPartialMatches: maxPartialMatches,
            sweepInterval: sweepInterval
        )
    }

    func evictionQueueDiagnostics() -> EvictionQueueDiagnostics {
        let refs = evictionQueueHead < evictionQueue.count
            ? Array(evictionQueue[evictionQueueHead...])
            : []
        let refIds = Set(refs.map(\.partialId))
        let liveIds = Set(partialMatches.values.flatMap { $0.map(\.id) })
        return EvictionQueueDiagnostics(
            referenceCount: refs.count,
            uniquePartialIdCount: refIds.count,
            uniqueCreationTimeCount: Set(refs.map(\.createdAt)).count,
            retentionLimit: evictionReferenceRetentionLimit,
            referencesMatchLivePartials: refIds == liveIds
        )
    }

    func mutationLeaseDiagnostics() -> MutationLeaseDiagnostics {
        MutationLeaseDiagnostics(
            held: mutationLeaseHeld,
            waiterCount: activeMutationWaiterCount,
            waiterStorageCount: mutationWaiters.count,
            waiterLimit: mutationWaiterLimit,
            waiterHighWatermark: mutationWaiterHighWatermark,
            cancelledWaiterCount: cancelledMutationWaiterCount,
            saturatedWaiterCount: saturatedMutationWaiterCount
        )
    }

    /// Internal deterministic test hook: hold the same production lease while
    /// awaiting an external gate. The actor remains reentrant, allowing tests to
    /// prove queued cancellation/removal without timing a filesystem or lineage
    /// operation. No production caller references this method.
    func holdMutationLeaseForTesting(
        while operation: @escaping @Sendable () async -> Void
    ) async {
        guard await acquireMutationLease() == .acquired else { return }
        defer { releaseMutationLease() }
        await operation()
    }

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
        guard await acquireMutationLease() == .acquired else { return [] }
        defer { releaseMutationLease() }
        guard !Task.isCancelled else { return [] }

        // Periodic housekeeping: sweep expired partials and enforce memory cap.
        let now = Date()
        if now.timeIntervalSince(lastSweep) >= sweepInterval {
            sweepExpired()
            lastSweep = now
        }

        // Pre-emptive sweep: trigger early cleanup when at 80% capacity to
        // reduce the likelihood of hitting the hard cap during event bursts.
        // v1.21.4 (#20): throttled to at most once per `preemptiveSweepInterval`
        // (was: a full O(partials) sweep on EVERY event above 80%). Any expired
        // partial this throttle lets linger is cleared right before `evictOldest`
        // (see the cap-enforcement block below), so eviction — the only path that
        // can drop a LIVE partial — stays detection-exact. See `lastPreemptiveSweep`.
        if totalPartialCount > maxPartialMatches * 8 / 10,
           now.timeIntervalSince(lastPreemptiveSweep) >= Self.preemptiveSweepInterval {
            sweepExpired()
            lastSweep = now
            lastPreemptiveSweep = now
        }

        let category = mapEventCategoryToLogsource(event.eventCategory, eventType: event.eventType)

        // Find rule IDs that have at least one step matching this category.
        guard let candidateRuleIds = ruleIndex[category] else {
            return []
        }

        var plans: [EventEvaluationPlan] = []
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
            plans.append(EventEvaluationPlan(
                ruleId: ruleId,
                rule: rule,
                matchingSteps: matchingSteps
            ))
        }

        guard !plans.isEmpty else { return [] }

        // Build one atomic ProcessLineage view for every relationship that this
        // event can actually evaluate. The old path awaited the lineage actor up
        // to twice per bound step per partial while retaining the mutation lease;
        // at the 10K cap that turned one broad miss into tens of thousands of
        // suspension/handoff points and head-of-line blocked the priority lane.
        var relationshipPIDs: Set<pid_t> = []
        for plan in plans where planNeedsLineageSnapshot(plan) {
            relationshipPIDs.insert(event.process.pid)
            for partial in partialMatches[plan.ruleId] ?? [] {
                for matched in partial.matchedSteps.values {
                    relationshipPIDs.insert(matched.processPid)
                }
            }
            for pending in pendingLaterSteps[plan.ruleId] ?? [] {
                relationshipPIDs.insert(pending.matched.processPid)
            }
        }

        let relationshipSnapshot: ProcessLineage.RelationshipSnapshot?
        if relationshipPIDs.isEmpty {
            relationshipSnapshot = nil
        } else {
            relationshipSnapshot = await lineage.relationshipSnapshot(for: relationshipPIDs)
            guard !Task.isCancelled else { return [] }
        }

        var completedMatches: [RuleMatch] = []

        for plan in plans {
            let ruleId = plan.ruleId
            let rule = plan.rule
            let matchingSteps = plan.matchingSteps

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
                    // Advance is delegated to the shared `advancePartial` (used
                    // identically by the Phase-3 replay path) so the correlation/
                    // ordering/afterStep/processRelation checks can never drift
                    // between the live and replayed paths (cf. corr-detection #275).
                    guard let updated = advancePartial(
                        rule: rule, step: step,
                        matched: eventMatchedStep(step), partial: partial,
                        relationshipSnapshot: relationshipSnapshot
                    ) else { continue }
                    advancedPartials.append((idx, updated))

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
                    id: UUID(),
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
                    evictionQueue.append(PartialMatchRef(
                        ruleId: ruleId,
                        partialId: newPartial.id,
                        createdAt: now
                    ))
                    seededInitial = true
                }
            }

            // --- Phase 3 (#95): out-of-order backfill for ordered rules ---
            // If this event just seeded an initial partial, replay any later
            // steps that arrived early (via the fast priority consumer while the
            // file consumer lagged) so the sequence can still complete.
            if seededInitial, let buffered = pendingLaterSteps[ruleId], !buffered.isEmpty {
                completedMatches.append(contentsOf: replayPendingSteps(
                    ruleId: ruleId,
                    rule: rule,
                    now: now,
                    relationshipSnapshot: relationshipSnapshot
                ))
            }
            // Retain every matching later step, even when it advanced a partial
            // above. It may also belong to an initial event that happened earlier
            // but is still queued on the other consumer. Ordered rules only
            // (unordered mode seeds from any constraint-free step, so there is no
            // out-of-order gap to bridge). Appending AFTER replay also prevents one
            // event that matches both step[0] and a later step from satisfying two
            // steps of the same freshly-seeded partial.
            if rule.ordered {
                let initialStepId = rule.steps.first?.id
                for step in matchingSteps where step.id != initialStepId {
                    bufferPendingStep(ruleId: ruleId, step: step, matched: eventMatchedStep(step), now: now)
                }
            }
        }

        // Enforce the global partial match cap.
        if totalPartialCount > maxPartialMatches {
            // #20: sweep expired partials FIRST so `evictOldest` only ever drops
            // LIVE partials as a genuine last resort. Before the pre-emptive-sweep
            // throttle, the >80% sweep had already cleared expired partials on this
            // same event before control reached here; the throttle can skip that,
            // so we clear them here to keep eviction's input — and therefore which
            // partials get dropped — identical to the pre-throttle path.
            sweepExpired()
            if totalPartialCount > maxPartialMatches {
                evictOldest(count: totalPartialCount - maxPartialMatches)
            }
        }

        // corr-detection #272: record fires for every sequence completed on
        // this event (both Phase-1 advances and Phase-2 single-step completions
        // land in `completedMatches`), so per-rule fire counts + last-fire are
        // observable via `statsSnapshot()`.
        for match in completedMatches {
            ruleStats[match.ruleId, default: SequenceRuleStats(ruleId: match.ruleId)].fireCount &+= 1
            ruleStats[match.ruleId]?.lastFiredAt = event.timestamp
        }

        // Completion removes authoritative partials but deliberately does not
        // search/remove arbitrary queue entries on the hot path. Bound those
        // stale refs in amortized batches instead.
        compactEvictionQueue()

        return completedMatches
    }

    // MARK: - Predicate Evaluation

    /// Evaluate all predicates for a step against an event.
    private func evaluateStepPredicates(_ step: SequenceStep, against event: Event) -> Bool {
        let predicates = step.predicates

        if let tree = step.conditionTree {
            // A tree without predicates is malformed. validateRule rejects it,
            // but keep the hot path fail-closed if an invariant ever regresses.
            guard !predicates.isEmpty else { return false }
            return evaluateConditionNode(tree, predicates: predicates, against: event)
        }

        // Preserve the legacy meaning of an intentionally predicate-free flat
        // step. This behavior applies only when no condition_tree is present.
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

    /// Evaluate the compiler-preserved Sigma boolean structure. Predicate leaf
    /// evaluation deliberately calls the same sequence evaluator as the legacy
    /// flat path, so field resolution, modifiers, negation and case folding are
    /// byte-for-byte identical; only boolean grouping changes.
    private func evaluateConditionNode(
        _ node: ConditionNode,
        predicates: [Predicate],
        against event: Event
    ) -> Bool {
        switch node {
        case .and(let operands):
            guard !operands.isEmpty else { return false }
            return operands.allSatisfy {
                evaluateConditionNode($0, predicates: predicates, against: event)
            }
        case .or(let operands):
            guard !operands.isEmpty else { return false }
            return operands.contains {
                evaluateConditionNode($0, predicates: predicates, against: event)
            }
        case .not(let operand):
            return !evaluateConditionNode(operand, predicates: predicates, against: event)
        case .predicate(let index):
            guard index >= 0, index < predicates.count else { return false }
            return evaluatePredicate(predicates[index], against: event)
        case .predicateGroup(let range, let mode):
            guard !range.isEmpty,
                  range.lowerBound >= 0,
                  range.upperBound <= predicates.count else { return false }
            let group = predicates[range]
            switch mode {
            case .allOf:
                return group.allSatisfy { evaluatePredicate($0, against: event) }
            case .anyOf:
                return group.contains { evaluatePredicate($0, against: event) }
            case .oneOfEach:
                let groups = Dictionary(grouping: group, by: { $0.field })
                return groups.values.allSatisfy { predicates in
                    predicates.contains { evaluatePredicate($0, against: event) }
                }
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

    private func processRelationNeedsLineage(_ relation: ProcessRelation) -> Bool {
        switch relation {
        case .descendant, .ancestor, .sibling, .sameTree:
            return true
        case .same, .sameProcess, .any:
            return false
        }
    }

    private func stepNeedsLineageSnapshot(_ step: SequenceStep, rule: SequenceRule) -> Bool {
        if rule.correlationType == .processLineage, step.processRelation == nil {
            return true
        }
        guard let relation = step.processRelation?.relation else { return false }
        return processRelationNeedsLineage(relation)
    }

    private func isInitialStep(_ step: SequenceStep, in rule: SequenceRule) -> Bool {
        if rule.ordered {
            return step.id == rule.steps.first?.id
        }
        return step.afterStep == nil && step.processRelation == nil
    }

    /// Whether the live advance or a possible Phase-3 replay can issue an
    /// ancestry query. Keeping this precise avoids even the single batch actor
    /// hop for predicate matches whose relations are PID-local (`same`/`any`).
    private func planNeedsLineageSnapshot(_ plan: EventEvaluationPlan) -> Bool {
        let existingPartials = partialMatches[plan.ruleId] ?? []
        let liveAdvanceCanQuery = existingPartials.contains { partial in
            plan.matchingSteps.contains { step in
                partial.matchedSteps[step.id] == nil
                    && stepNeedsLineageSnapshot(step, rule: plan.rule)
            }
        }
        if liveAdvanceCanQuery {
            return true
        }

        let canSeed = plan.matchingSteps.contains(where: {
            isInitialStep($0, in: plan.rule)
        })
        guard canSeed, let pending = pendingLaterSteps[plan.ruleId], !pending.isEmpty else {
            return false
        }
        return pending.contains(where: {
            stepNeedsLineageSnapshot($0.step, rule: plan.rule)
        })
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
        partial: PartialMatch,
        relationshipSnapshot: ProcessLineage.RelationshipSnapshot?
    ) -> PartialMatch? {
        // Skip if this step is already matched in this partial.
        guard partial.matchedSteps[step.id] == nil else { return nil }

        // One source event may match predicates for several sequence steps, but
        // the live path advances a partial at most once per event. Preserve that
        // invariant across retained-history replay (and duplicate delivery): the
        // same event identity must never satisfy two distinct steps in one chain.
        guard !partial.matchedSteps.values.contains(where: {
            $0.eventId == matched.eventId
        }) else { return nil }

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
            if !checkCorrelation(
                rule.correlationType,
                partial: partial,
                candidate: matched,
                relationshipSnapshot: relationshipSnapshot
            ) {
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
            let relationHolds = checkProcessRelation(
                spec.relation,
                eventPid: matched.processPid,
                eventPath: matched.processPath,
                referencePid: refStep.processPid,
                referencePath: refStep.processPath,
                relationshipSnapshot: relationshipSnapshot
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

    /// Retain an ordered rule's recent later step for delayed initial events (the
    /// A2 cross-consumer race — see `pendingLaterSteps`). Bounded per rule (oldest
    /// evicted) and deduped by (eventId, stepId) so the same event cannot occupy
    /// the history twice across re-evaluations.
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

    /// Replay retained out-of-order later steps for `ruleId` against the rule's
    /// current partials (called right after an initial step seeds a new partial).
    /// Steps are tried oldest-first BY EVENT TIMESTAMP, with rule-step order as
    /// the equal-timestamp tie-break, so a 3+ step chain delivered fully reversed
    /// still assembles in rule order. Each retained event fans out to EVERY
    /// compatible partial, matching Phase 1. It remains in the bounded history so
    /// another initial event that happened earlier but is delivered later can
    /// replay it too; a partial already containing that step or source event
    /// rejects it idempotently. Window-expired entries are pruned. Uses the SAME
    /// `advancePartial` as the live path.
    private func replayPendingSteps(
        ruleId: String,
        rule: SequenceRule,
        now: Date,
        relationshipSnapshot: ProcessLineage.RelationshipSnapshot?
    ) -> [RuleMatch] {
        guard var pending = pendingLaterSteps[ruleId], !pending.isEmpty else { return [] }

        // Drop buffered steps older than the rule window.
        pending.removeAll { now.timeIntervalSince($0.arrivedAt) > rule.window }
        guard !pending.isEmpty else { pendingLaterSteps[ruleId] = nil; return [] }

        var matches: [RuleMatch] = []
        var partials = partialMatches[ruleId] ?? []

        let stepOrder = Dictionary(uniqueKeysWithValues: rule.steps.enumerated().map {
            ($0.element.id, $0.offset)
        })
        let order = pending.indices.sorted {
            let lhs = pending[$0]
            let rhs = pending[$1]
            if lhs.matched.timestamp != rhs.matched.timestamp {
                return lhs.matched.timestamp < rhs.matched.timestamp
            }
            return (stepOrder[lhs.step.id] ?? Int.max)
                < (stepOrder[rhs.step.id] ?? Int.max)
        }
        for pi in order {
            let pend = pending[pi]
            var replayed: [PartialMatch] = []
            replayed.reserveCapacity(partials.count)
            for partial in partials {
                if now.timeIntervalSince(partial.createdAt) > rule.window {
                    replayed.append(partial)
                    continue
                }
                guard let updated = advancePartial(
                    rule: rule,
                    step: pend.step,
                    matched: pend.matched,
                    partial: partial,
                    relationshipSnapshot: relationshipSnapshot
                ) else {
                    replayed.append(partial)
                    continue
                }
                if isTriggerSatisfied(rule.trigger, matchedStepIds: Set(updated.matchedSteps.keys), totalSteps: rule.steps.count) {
                    matches.append(makeMatch(rule: rule, partial: updated))
                } else {
                    replayed.append(updated)
                }
            }
            partials = replayed
        }

        partialMatches[ruleId] = partials
        pendingLaterSteps[ruleId] = pending.isEmpty ? nil : pending
        return matches
    }

    /// Check whether a candidate matched step satisfies the rule's correlation
    /// constraint with respect to an existing partial match.
    private func checkCorrelation(
        _ type: CorrelationType,
        partial: PartialMatch,
        candidate: MatchedStep,
        relationshipSnapshot: ProcessLineage.RelationshipSnapshot?
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
            guard let relationshipSnapshot else { return false }
            for bound in partial.matchedSteps.values {
                if candidate.processPid == bound.processPid { return true }
                if relationshipSnapshot.isDescendant(candidate.processPid, of: bound.processPid) {
                    return true
                }
                if relationshipSnapshot.isDescendant(bound.processPid, of: candidate.processPid) {
                    return true
                }
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
        eventPath _: String,
        referencePid: pid_t,
        referencePath _: String,
        relationshipSnapshot: ProcessLineage.RelationshipSnapshot?
    ) -> Bool {
        switch relation {
        case .same:
            return eventPid == referencePid

        case .descendant:
            // Event process is a child/grandchild of the reference process.
            return relationshipSnapshot?.isDescendant(eventPid, of: referencePid) == true

        case .ancestor:
            // Event process is a parent/grandparent of the reference process.
            return relationshipSnapshot?.isDescendant(referencePid, of: eventPid) == true

        case .sibling:
            // Event process and reference process share a direct parent.
            return relationshipSnapshot?.areSiblings(eventPid, referencePid) == true

        case .sameProcess:
            // Identical to .same (exact PID); separate token used by authors.
            return eventPid == referencePid

        case .sameTree:
            // Same process, or anywhere in its ancestry/descendants.
            if eventPid == referencePid { return true }
            guard let relationshipSnapshot else { return false }
            if relationshipSnapshot.isDescendant(eventPid, of: referencePid) { return true }
            return relationshipSnapshot.isDescendant(referencePid, of: eventPid)

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
                partialMatches.removeValue(forKey: ruleId)
                continue
            }

            let surviving = partials.filter { now.timeIntervalSince($0.createdAt) <= rule.window }
            partialMatches[ruleId] = surviving.isEmpty ? nil : surviving
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

        // Rebuild from exact live IDs. Age-only front trimming retained every
        // completed ref until the corpus's largest window elapsed, allowing the
        // auxiliary queue to scale with seed throughput rather than live state.
        compactEvictionQueue(force: true)
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
        while removed < count, let ref = popOldestEvictionReference() {

            // Look up the partials array for this rule.
            guard var partials = partialMatches[ref.ruleId] else {
                // Rule's partials were already fully cleared (e.g. rule disabled).
                continue
            }

            // Find the exact partial. Creation timestamps are not identities:
            // one event can seed multiple unordered steps at the same instant,
            // and a stale ref for a completed one must not evict its sibling.
            guard let idx = partials.firstIndex(where: { $0.id == ref.partialId }) else {
                continue
            }

            partials.remove(at: idx)
            removed += 1

            if partials.isEmpty {
                partialMatches.removeValue(forKey: ref.ruleId)
            } else {
                partialMatches[ref.ruleId] = partials
            }
        }

        if removed > 0 {
            evictedPartialCount = Self.saturatingTelemetryAdd(
                evictedPartialCount,
                removed
            )
            logger.warning("Evicted \(removed) oldest partial matches (cap: \(self.maxPartialMatches), cumulative: \(self.evictedPartialCount))")
        }
        compactEvictionQueue()
    }

    /// Cumulative diagnostics must never become a crash surface. Exposed at
    /// internal scope so the Int.max boundary can be tested without performing
    /// an impossible lifetime number of real evictions.
    static func saturatingTelemetryAdd(_ current: Int, _ delta: Int) -> Int {
        guard delta > 0 else { return current }
        guard current >= 0, current <= Int.max - delta else { return Int.max }
        return current + delta
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
    case partialRuleLoadFailure(failedFiles: [String], loaded: Int)
    case invalidRuleManifest(String)
    case ruleInventoryMismatch(missing: [String], unexpected: [String])
    case ruleManifestHashMismatch([String])
    case ruleDirectoryChangedDuringReload(String)
    case duplicateRuleIds([String])
    case mutationQueueSaturated(Int)

    public var errorDescription: String? {
        switch self {
        case .directoryNotFound(let path):
            return "Sequence rule directory not found: \(path)"
        case .invalidRule(let ruleId, let detail):
            return "Invalid sequence rule '\(ruleId)': \(detail)"
        case .partialRuleLoadFailure(let failedFiles, let loaded):
            return "Sequence reload rejected: \(failedFiles.count) file(s) failed while \(loaded) rule(s) staged (\(failedFiles.joined(separator: ", ")))"
        case .invalidRuleManifest(let detail):
            return "Sequence reload manifest is invalid: \(detail)"
        case .ruleInventoryMismatch(let missing, let unexpected):
            let missingText = missing.isEmpty ? "none" : missing.joined(separator: ", ")
            let unexpectedText = unexpected.isEmpty ? "none" : unexpected.joined(separator: ", ")
            return "Sequence reload inventory does not match manifest (missing: \(missingText); unexpected: \(unexpectedText))"
        case .ruleManifestHashMismatch(let files):
            return "Sequence reload file hash does not match manifest: \(files.joined(separator: ", "))"
        case .ruleDirectoryChangedDuringReload(let path):
            return "Sequence rule directory changed while reload was staging: \(path)"
        case .duplicateRuleIds(let ruleIds):
            return "Sequence reload rejected duplicate rule id(s): \(ruleIds.joined(separator: ", "))"
        case .mutationQueueSaturated(let limit):
            return "Sequence engine mutation queue reached its bounded limit of \(limit) waiter(s)"
        }
    }
}
