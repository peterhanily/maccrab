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
    struct MatchedStep: SequenceStepBinding {
        let stepId: String
        let eventId: UUID
        let timestamp: Date
        let processPid: pid_t
        /// Event-time ancestry is retained with the match because the in-memory
        /// ProcessLineage DAG is process-local. Without it, a restored partial
        /// could only complete PID-local rules; grandchild/sibling relations
        /// would silently fail after restart even though the partial survived.
        let processParentPid: pid_t
        /// Exact evidence used by ProcessLineage's sibling contract. Equal
        /// numeric PPIDs are insufficient unless the parent node was observed.
        let processParentWasTracked: Bool
        let processAncestorPids: [pid_t]
        let filePath: String?
        let networkDest: String?

        func hasAncestor(_ candidatePID: pid_t) -> Bool {
            processParentPid == candidatePID || processAncestorPids.contains(candidatePID)
        }
    }

    /// Tracks an in-flight sequence being assembled from individual events.
    ///
    /// Each partial match corresponds to one potential instance of a sequence
    /// rule. As new events arrive and match subsequent steps, the partial
    /// match is advanced. Once the trigger condition is satisfied, the
    /// sequence fires and the partial match is consumed.
    struct PartialMatch: Sendable, Equatable {
        let id: UUID
        let ruleId: String
        let createdAt: Date
        var matchedSteps: SequenceMatchedSteps<MatchedStep>
        let correlationKey: String?                // nil only for independent .none states
        var checkpointWeight: Int

        /// Timestamp of the most recently matched step.
        var latestTimestamp: Date {
            matchedSteps.values.map(\.timestamp).max() ?? createdAt
        }
    }

    // MARK: - State

    /// All loaded sequence rules keyed by rule ID.
    private var rules: [String: SequenceRule] = [:]

    /// pendingFoldStepID(for:) of every loaded rule that has one, keyed by
    /// rule ID, so admission and pressure relief read fold eligibility with
    /// one lookup instead of walking the rule's steps. installRule and
    /// reloadRules set it wherever they set `rules`, as they do
    /// heavyDependencyMasks. setEnabled leaves it alone: eligibility ignores
    /// `enabled`, and a disabled rule has no bucket to fold.
    private(set) var pendingFoldStepIDByRule: [String: String] = [:]

    /// Rule-ID -> step-ID -> fixed heavyweight evidence dependency. Populated
    /// with rule definitions so covered events do no condition-tree traversal
    /// merely to decide whether a step is currently evaluable.
    private var heavyDependencyMasks: [String: [String: HeavyEnrichmentDependencyMask]] = [:]

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
    struct PendingStep: Sendable, Equatable {
        let step: SequenceStep
        let matched: MatchedStep
        let arrivedAt: Date
        var checkpointWeight: Int
        /// Non-nil only for a live admission of the rule's fold-eligible step
        /// whose event carries an ES audit identity. Restored entries keep nil
        /// and are never folded. About 40 B inline per entry (0.3 MiB at the
        /// 8,192-entry cap); the step ID and ancestry buffers are shared with
        /// the rule and the matched step through copy-on-write, not copied.
        var foldKey: PendingFoldKey? = nil
    }

    /// Writer identity plus the exact relation evidence the folded step's
    /// constraints read (see foldPendingBucket). Runtime only: never encoded,
    /// never restored.
    struct PendingFoldKey: Hashable, Sendable {
        let stepID: String
        let pid: pid_t
        let pidVersion: UInt32
        let parentPid: pid_t
        let parentWasTracked: Bool
        let ancestorPids: [pid_t]
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
    /// replay them whenever a delayed `step[0]` seeds a partial, and, against
    /// just the partials it advanced, whenever a live event binds a middle step
    /// without completing (a later step processed before that middle step
    /// failed its ordering check then). A later event is
    /// history, not a consumable token: the live path fans one event out to every
    /// compatible partial, and replay must do the same for partials that become
    /// known later. Window-pruned and bounded by the shared count and
    /// semantic-weight limits. At a limit, relievePendingPressure retires
    /// expired history, folds one writer's duplicate entries (foldPendingBucket)
    /// and only then sheds the oldest entry of the largest rule bucket.
    /// Smaller buckets are never trimmed while a larger one exists. A broadly
    /// matching rule sheds its own history once its bucket is the largest;
    /// until then its admissions trim the largest bucket toward an equal share.
    private var pendingLaterSteps: [String: [PendingStep]] = [:]

    /// Per-rule cap on buffered out-of-order later steps.
    ///
    /// rc.10 proved that the old 256-entry sub-cap discarded exact history long
    /// before the already-enforced global/serialized-state budgets were full:
    /// 510,591 per-rule evictions were observed while the aggregate journal held
    /// only 330 entries. One genuinely hot rule may still use the complete
    /// global allowance while no other rule competes for it; under contention
    /// the victim is the oldest entry of the largest bucket, so a hot rule
    /// pays for its own pressure while it holds the largest bucket. This
    /// expands no resource envelope—the independent global count and 7.5 MiB
    /// semantic-weight ceilings remain authoritative.
    static let maxPendingPerRule = SequenceCheckpointLimits.maximumTotalPendingSteps

    /// Global cap shared by runtime, capture, and restore. A per-rule bound is
    /// not a global memory bound when the rule corpus itself is large.
    static let maxPendingTotal = SequenceCheckpointLimits.maximumTotalPendingSteps

    private struct PendingStepRef: Sendable, Equatable {
        let identity: SequenceCheckpointPendingIdentity
    }

    /// Arrival-ordered global identity queue, persisted as pendingEvictionOrder
    /// (validators require exact identity coverage). Since v1.22.6 it no longer
    /// chooses victims; removals leave stale references for the bounded lazy
    /// compaction, and capture compacts it exactly. The head index is no
    /// longer advanced.
    private var pendingEvictionQueue: [PendingStepRef] = []
    private var pendingEvictionQueueHead = 0
    private static let pendingEvictionQueueStaleSlack = 256

    /// Cumulative history items shed by either per-rule or global bounds.
    private var evictedPendingStepCount: Int = 0
    private var pendingPerRuleCountShedTotal: UInt64 = 0
    private var pendingGlobalCountShedTotal: UInt64 = 0
    private var pendingSemanticWeightShedTotal: UInt64 = 0
    private var lastPendingPressure: PendingPressureSnapshot?

    /// Exact admission ledger for the bounded pending-step journal. These are
    /// updated from exact unique admissions and identity differences on bucket
    /// replacement, so a full bucket that admits one item while evicting another
    /// cannot hide behind an unchanged depth gauge.
    private var pendingStepsOfferedTotal: UInt64 = 0
    private var pendingStepsCompletedTotal: UInt64 = 0
    private var pendingStepsExplicitlyShedTotal: UInt64 = 0
    private var pendingStepsOfferedByRule: [String: UInt64] = [:]
    private var pendingStepsCompletedByRule: [String: UInt64] = [:]
    private var pendingStepsExplicitlyShedByRule: [String: UInt64] = [:]

    /// Runtime-only fold bookkeeping. Not persisted; not part of the journal.
    /// The serial counts unique pending admissions across all rules; a rule
    /// whose last fold attempt was low-yield is not attempted again until the
    /// serial reaches its entry here.
    private var pendingAdmissionSerial: UInt64 = 0
    private var pendingFoldBlockedUntilSerial: [String: UInt64] = [:]
    private var pendingFoldAttemptsTotal: UInt64 = 0
    private var pendingFoldedStepsTotal: UInt64 = 0
    private var lastPendingFold: PendingFoldSnapshot?
    /// A fold attempt that removes fewer than this many entries blocks further
    /// attempts on that rule for this many unique pending admissions, so fold
    /// work stays O(bucket/256) per admission even when each attempt could
    /// remove only one entry. The price: after a low-yield attempt, a
    /// single-writer burst on that rule can shed up to 255 live entries before
    /// the next attempt folds it.
    private static let pendingFoldRetryAdmissions: UInt64 = 256

    /// Victim order at a pending count or weight limit, published with the
    /// pending pressure diagnostics.
    static let pendingVictimPolicy = "largest_bucket_oldest_first"
    /// Deterministic saturation-path operation counts; read only by tests.
    /// Identity rebuilds are setPendingBucket calls plus queue rebuilds that
    /// actually run. Element visits are the records scanned by the
    /// pressure-boundary expiry sweep, the records summed or shifted by
    /// in-place front removal, and the records a fold attempt reads (twice
    /// when it merges): the linear work that remains per boundary.
    private var pendingIdentityRebuildCount: UInt64 = 0
    private var pendingForcedQueueCompactionCount: UInt64 = 0
    private var pendingCapacityElementVisitCount: UInt64 = 0

    /// Replay on advance (replayPendingStepsAfterAdvance): scans of a rule's
    /// pending history, the retained entries they took as candidates, and the
    /// later-step bindings and completions they made. Process-lifetime
    /// diagnostics; the replay never changes pending history, so none of them
    /// is a journal key.
    private var advanceReplayScansTotal: UInt64 = 0
    private var advanceReplayCandidatesTotal: UInt64 = 0
    private var advanceReplayBindingsTotal: UInt64 = 0
    private var advanceReplayCompletionsTotal: UInt64 = 0

    private enum PendingStepRemovalDisposition {
        case completed
        case explicitlyShed
    }

    /// Recovery is a startup-only operation. Empty runtime collections are not
    /// proof that no event was evaluated: a miss or single-step completion can
    /// leave them empty while still racing a detached checkpoint read.
    private var checkpointRestoreAllowed = true
    /// Bumped by every change to the installed rules, so an evaluation that
    /// planned before waiting for the mutation lease can tell its plan is stale.
    private var ruleSetGeneration: UInt64 = 0

    /// Conservative serialized-state weight, updated through the centralized
    /// bucket setters below. Capture verifies it against a full recomputation
    /// but never mutates detection state.
    private var checkpointStateWeight = SequenceCheckpointCodec.semanticStateBaseWeight

    /// Monotonic, process-local generation for the semantics-bearing recovery
    /// state (rule definitions/enabled states, partials, and pending history).
    /// It is only an observation hint: the checkpoint's canonical semantic
    /// digest is authoritative and prevents generation wrap/restart ambiguity.
    private var checkpointGeneration: UInt64 = 0

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
    /// rule corpus size rather than the bounded partial pool size.
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

    /// Reference to a partial match by stable identity, appended at seed time.
    /// Since v1.22.6 victims come from the largest partial bucket; this order
    /// is kept because the checkpoint persists it as evictionOrder with exact
    /// coverage.
    struct PartialMatchRef: Sendable, Equatable {
        let ruleId: String
        let partialId: UUID
        let createdAt: Date
    }

    /// Queue of partial-match references in creation order (append new). The
    /// head index is no longer advanced; eviction removes bucket fronts and
    /// leaves stale refs here. Completed/expired
    /// partials leave stale refs until the bounded compactor runs; the queue is
    /// periodically rebuilt from the authoritative partial-ID set so metadata
    /// cannot grow with lifetime seed throughput.
    private var evictionQueue: [PartialMatchRef] = []
    private var evictionQueueHead = 0

    /// Maximum stale-reference slack above the configured live-partial cap.
    /// This amortizes rebuild cost while bounding auxiliary metadata even when
    /// partials seed and complete rapidly without ever hitting the live cap.
    private static let evictionQueueStaleSlack = 256

    /// Explicit provisional logical-state ceiling, independent of the unchanged
    /// canonical checkpoint-byte budget. A larger requested cap cannot silently
    /// expand this policy. Resource suitability still requires runtime evidence.
    private static let minimumPartialMatchLimit = 1
    private static let maximumPartialMatchLimit = SequenceCheckpointLimits.maximumTotalPartialMatches
    private static let defaultSweepInterval: TimeInterval = 1.0

    /// Cumulative partial matches dropped by the count or semantic-weight cap. Read via
    /// `partialsEvictedTotal` and published in the heartbeat — see that
    /// accessor for why an unmetered eviction is a detection-integrity problem
    /// and not just a diagnostics gap.
    private var evictedPartialCount: Int = 0
    private var partialPressureTotals = PartialPressureTotals()
    private var lastPartialPressure: PartialPressureSnapshot?

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
    ///     across all rules. The oldest partials of the largest rule bucket
    ///     are evicted when exceeded. Values outside
    ///     1...13,000 range are clamped. Defaults to 13,000; the independent
    ///     checkpoint-byte limit can bind sooner, with visible loss reporting.
    ///   - sweepInterval: How often (seconds) to scan for expired partial
    ///     matches. NaN, infinity, and negative values fall back to 1 second;
    ///     zero intentionally requests a sweep on every evaluation.
    public init(
        lineage: ProcessLineage,
        maxPartialMatches: Int = 13_000,
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
        maxPartialMatches: Int = 13_000,
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

    /// Cheap hot-path dirtiness signal. No hashing, encoding, compression, or
    /// filesystem work is permitted here; the checkpoint coordinator performs
    /// those operations after copying a bounded Sendable snapshot out of actor
    /// isolation.
    private func markCheckpointStateMutation() {
        Self.incrementSaturating(&checkpointGeneration)
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
        var checkpointStateChanged = false
        for ruleId in ruleIds {
            if partialMatches[ruleId] != nil {
                setPartialBucket([], for: ruleId)
                checkpointStateChanged = true
            }
            if pendingLaterSteps[ruleId] != nil {
                setPendingBucket([], for: ruleId)
                checkpointStateChanged = true
            }
            pendingFoldBlockedUntilSerial.removeValue(forKey: ruleId)
            if resetStats {
                ruleStats.removeValue(forKey: ruleId)
            }
        }
        compactEvictionQueue(force: true)
        compactPendingEvictionQueue(force: true)
        if checkpointStateChanged { markCheckpointStateMutation() }
    }

    /// Install or replace one additive rule. Equivalent same-ID definitions keep
    /// their in-flight state; changed definitions cannot safely consume steps
    /// captured under the old predicate/order/trigger semantics.
    private func installRule(_ rule: SequenceRule) {
        let definitionChanged = rules[rule.id] != rule
        if let previous = rules[rule.id] {
            if previous != rule {
                purgeRuntimeState(for: [rule.id], resetStats: true)
            }
            removeRuleFromIndex(rule.id)
        }
        rules[rule.id] = rule
        pendingFoldStepIDByRule[rule.id] = Self.pendingFoldStepID(for: rule)
        ruleSetGeneration &+= 1
        heavyDependencyMasks[rule.id] = Dictionary(
            uniqueKeysWithValues: rule.steps.map { step in
                (step.id, HeavyEnrichmentRuleCoverage.dependencyMask(
                    predicates: step.predicates,
                    conditionTree: step.conditionTree
                ))
            }
        )
        for step in rule.steps {
            ruleIndex[step.logsourceCategory, default: []].insert(rule.id)
        }
        if definitionChanged { markCheckpointStateMutation() }
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

    private var totalPendingStepCount: Int {
        pendingLaterSteps.values.reduce(into: 0) { $0 += $1.count }
    }

    private var activePendingEvictionReferenceCount: Int {
        max(0, pendingEvictionQueue.count - pendingEvictionQueueHead)
    }

    private func pendingIdentity(
        ruleId: String,
        pending: PendingStep
    ) -> SequenceCheckpointPendingIdentity {
        SequenceCheckpointPendingIdentity(
            ruleID: ruleId,
            stepID: pending.step.id,
            eventID: pending.matched.eventId
        )
    }

    private func compactPendingEvictionQueue(force: Bool = false) {
        if force { Self.incrementSaturating(&pendingForcedQueueCompactionCount) }
        let liveCount = totalPendingStepCount
        let retentionLimit = liveCount > Int.max - Self.pendingEvictionQueueStaleSlack
            ? Int.max
            : liveCount + Self.pendingEvictionQueueStaleSlack
        let prefixNeedsCompaction = pendingEvictionQueueHead >= 1_024
            && pendingEvictionQueueHead * 2 >= pendingEvictionQueue.count
        guard force
                || activePendingEvictionReferenceCount > retentionLimit
                || prefixNeedsCompaction else { return }

        Self.incrementSaturating(&pendingIdentityRebuildCount)
        // Keep only the first reference to each live identity. A removed entry
        // leaves its reference here until a rebuild; if the same identity is
        // admitted again before that, a plain liveness filter would keep both
        // references and capture would reject the duplicate.
        var liveIdentities = Set(pendingLaterSteps.flatMap { ruleId, pending in
            pending.map { pendingIdentity(ruleId: ruleId, pending: $0) }
        })
        if pendingEvictionQueueHead < pendingEvictionQueue.count {
            pendingEvictionQueue = pendingEvictionQueue[pendingEvictionQueueHead...].filter {
                liveIdentities.remove($0.identity) != nil
            }
        } else {
            pendingEvictionQueue.removeAll(keepingCapacity: true)
        }
        pendingEvictionQueueHead = 0
    }

    public enum PartialPressureReason: String, Sendable {
        case globalCount = "global_count"
        case semanticWeight = "semantic_weight"
    }

    /// Fixed-size accounting only: no event identities, rule labels or content.
    /// Internal value type permits deterministic saturation testing without a
    /// mutable test hook into a live engine's counters.
    struct PartialPressureTotals: Sendable {
        private(set) var globalCount: Int = 0
        private(set) var semanticWeight: Int = 0

        var classifiedTotal: Int {
            SequenceEngine.saturatingTelemetryAdd(globalCount, semanticWeight)
        }

        mutating func record(_ count: Int, reason: PartialPressureReason) {
            switch reason {
            case .globalCount:
                globalCount = SequenceEngine.saturatingTelemetryAdd(globalCount, count)
            case .semanticWeight:
                semanticWeight = SequenceEngine.saturatingTelemetryAdd(semanticWeight, count)
            }
        }
    }

    /// Latest actual partial removal, sampled after expiry retirement. Both
    /// sides of the boundary are captured synchronously inside the mutation.
    public struct PartialPressureSnapshot: Sendable {
        public let reason: PartialPressureReason
        public let observedAt: Date
        public let pendingCountBefore: Int
        public let partialCountBefore: Int
        public let partialCountAfter: Int
        public let stateWeightBytesBefore: Int
        public let stateWeightBytesAfter: Int
        public let removedPartials: Int
    }

    public struct PartialPressureDiagnostics: Sendable {
        public let globalCountShedTotal: Int
        public let semanticWeightShedTotal: Int
        public let totalShed: Int
        /// Equality of saturating totals, not proof of an exact lifetime count
        /// once countersAtLimit is true.
        public let classificationConserved: Bool
        public let countersAtLimit: Bool
        public let globalCountLimit: Int
        public let stateWeightLimitBytes: Int
        public let lastPressure: PartialPressureSnapshot?
    }

    /// One actor read includes the existing aggregate and both reason totals;
    /// no await can expose a partially recorded pressure boundary.
    public func partialPressureDiagnostics() -> PartialPressureDiagnostics {
        let classified = partialPressureTotals.classifiedTotal
        return PartialPressureDiagnostics(
            globalCountShedTotal: partialPressureTotals.globalCount,
            semanticWeightShedTotal: partialPressureTotals.semanticWeight,
            totalShed: evictedPartialCount,
            classificationConserved: classified == evictedPartialCount,
            countersAtLimit: classified == Int.max || evictedPartialCount == Int.max,
            globalCountLimit: maxPartialMatches,
            stateWeightLimitBytes: SequenceCheckpointCodec.maximumSemanticStateWeight,
            lastPressure: lastPartialPressure
        )
    }

    private func recordPartialPressure(
        _ count: Int, reason: PartialPressureReason, observedAt: Date,
        pendingCountBefore: Int, partialCountBefore: Int, stateWeightBytesBefore: Int
    ) {
        guard count > 0 else { return }
        partialPressureTotals.record(count, reason: reason)
        lastPartialPressure = PartialPressureSnapshot(
            reason: reason, observedAt: observedAt,
            pendingCountBefore: pendingCountBefore,
            partialCountBefore: partialCountBefore, partialCountAfter: totalPartialCount,
            stateWeightBytesBefore: stateWeightBytesBefore,
            stateWeightBytesAfter: checkpointStateWeight, removedPartials: count
        )
    }

    public enum PendingPressureReason: String, Sendable {
        case perRuleCount = "per_rule_count"
        case globalCount = "global_count"
        case semanticWeight = "semantic_weight"
    }

    /// One actual removal boundary, after expiry retirement and folding. The
    /// representative is the first live victim under the largest-bucket policy
    /// (heartbeat keys keep their historical representative_fifo_victim_* names
    /// for compatibility), not an estimate of the dominant step.
    /// Rule/step IDs are trusted definitions; no event identities are retained.
    public struct PendingPressureSnapshot: Sendable {
        public let reason: PendingPressureReason
        public let observedAt: Date
        public let pendingCountBefore: Int
        public let partialCountBefore: Int
        public let rulePendingCountBefore: Int
        public let stateWeightBytesBefore: Int
        public let representativeVictimRuleID: String
        public let representativeVictimStepID: String
        public fileprivate(set) var removedPendingSteps: UInt64
    }

    /// The latest fold that removed entries. Rule/step IDs are trusted
    /// definitions; no event identities are retained.
    public struct PendingFoldSnapshot: Sendable {
        public let observedAt: Date
        public let ruleID: String
        public let stepID: String
        public let removedPendingSteps: UInt64
        public let foldedGroups: Int
    }

    public struct PendingPressureDiagnostics: Sendable {
        public let perRuleCountShedTotal: UInt64
        public let globalCountShedTotal: UInt64
        public let semanticWeightShedTotal: UInt64
        public let journalExplicitlyShedTotal: UInt64
        public let classificationConserved: Bool
        public let perRuleCountLimit: Int
        public let globalCountLimit: Int
        public let stateWeightLimitBytes: Int
        public let victimPolicy: String
        /// Same-writer entries folded at a limit. They are journal completed,
        /// never shed, so classificationConserved does not include them.
        public let foldedStepsTotal: UInt64
        public let foldAttemptsTotal: UInt64
        public let lastFold: PendingFoldSnapshot?
        /// Replay on advance: retained later steps bound, and sequences
        /// completed, when a middle step bound after them. Pending history is
        /// read, never changed, so these are not part of the journal.
        public let advanceReplayBindingsTotal: UInt64
        public let advanceReplayCompletionsTotal: UInt64
        public let lastPressure: PendingPressureSnapshot?
    }

    /// One actor snapshot prevents interleaved evaluations from making the new
    /// reason totals appear inconsistent with a separately sampled journal.
    func pendingPressureDiagnostics() -> PendingPressureDiagnostics {
        var classified = pendingPerRuleCountShedTotal
        Self.addSaturating(pendingGlobalCountShedTotal, to: &classified)
        Self.addSaturating(pendingSemanticWeightShedTotal, to: &classified)
        return PendingPressureDiagnostics(
            perRuleCountShedTotal: pendingPerRuleCountShedTotal,
            globalCountShedTotal: pendingGlobalCountShedTotal,
            semanticWeightShedTotal: pendingSemanticWeightShedTotal,
            journalExplicitlyShedTotal: pendingStepsExplicitlyShedTotal,
            classificationConserved: classified == pendingStepsExplicitlyShedTotal,
            perRuleCountLimit: Self.maxPendingPerRule,
            globalCountLimit: Self.maxPendingTotal,
            stateWeightLimitBytes: SequenceCheckpointCodec.maximumSemanticStateWeight,
            victimPolicy: Self.pendingVictimPolicy,
            foldedStepsTotal: pendingFoldedStepsTotal,
            foldAttemptsTotal: pendingFoldAttemptsTotal,
            lastFold: lastPendingFold,
            advanceReplayBindingsTotal: advanceReplayBindingsTotal,
            advanceReplayCompletionsTotal: advanceReplayCompletionsTotal,
            lastPressure: lastPendingPressure
        )
    }

    /// The journal, its by-rule split, the eviction counter, the checkpoint
    /// weight and the pressure totals, read in one actor call so that the
    /// pairs the qualification recorder cross-checks agree: the journal's
    /// queued count with the pending-steps gauge, and its shed total with the
    /// eviction counter. Separately awaited reads would let an evaluation run
    /// between them, although the recorder requires each pair to match
    /// exactly. The eviction recency behind the heartbeat's continuity
    /// verdict is not part of this snapshot; it is read in a separate call.
    public struct PendingHistoryDiagnostics: Sendable {
        public let journal: SequenceConservationTelemetry
        public let journalByRule: [String: SequenceConservationTelemetry]
        public let evictedTotal: Int
        public let weight: CheckpointWeightDiagnostics
        public let pressure: PendingPressureDiagnostics
    }

    public func pendingHistoryDiagnostics() -> PendingHistoryDiagnostics {
        PendingHistoryDiagnostics(
            journal: pendingStepConservation(),
            journalByRule: pendingStepConservationByRule(),
            evictedTotal: evictedPendingStepCount,
            weight: checkpointWeightDiagnostics(),
            pressure: pendingPressureDiagnostics()
        )
    }

    /// Saturation-path operation counts, so tests can pin the cost of capacity
    /// relief: identity rebuilds (setPendingBucket calls plus queue rebuilds
    /// that actually run), forced queue compactions, element visits (see
    /// pendingCapacityElementVisitCount) and fold attempts.
    struct PendingCapacityOperationDiagnostics: Sendable, Equatable {
        let identityRebuilds: UInt64
        let forcedQueueCompactions: UInt64
        let elementVisits: UInt64
        let foldAttempts: UInt64
    }

    func pendingCapacityOperationDiagnostics() -> PendingCapacityOperationDiagnostics {
        PendingCapacityOperationDiagnostics(
            identityRebuilds: pendingIdentityRebuildCount,
            forcedQueueCompactions: pendingForcedQueueCompactionCount,
            elementVisits: pendingCapacityElementVisitCount,
            foldAttempts: pendingFoldAttemptsTotal
        )
    }

    /// Replay-on-advance scans of a rule's pending history, so tests can pin
    /// when the scan runs. Its bindings and completions are published in
    /// PendingPressureDiagnostics.
    func advanceReplayScanCount() -> UInt64 {
        advanceReplayScansTotal
    }

    /// Retained entries the replay-on-advance scans took as candidates:
    /// in-window entries for steps after the lowest newly bound one. Lets
    /// tests pin that a scan never considers the bound step's own (possibly
    /// folded) history.
    func advanceReplayCandidateCount() -> UInt64 {
        advanceReplayCandidatesTotal
    }

    private func pendingPressureSnapshot(
        reason: PendingPressureReason, pendingCount: Int, ruleID: String, stepID: String
    ) -> PendingPressureSnapshot {
        PendingPressureSnapshot(
            reason: reason, observedAt: Date(), pendingCountBefore: pendingCount,
            partialCountBefore: totalPartialCount,
            rulePendingCountBefore: pendingLaterSteps[ruleID]?.count ?? 0,
            stateWeightBytesBefore: checkpointStateWeight,
            representativeVictimRuleID: ruleID, representativeVictimStepID: stepID,
            removedPendingSteps: 0
        )
    }

    private func recordPendingEvictions(_ count: Int, before: PendingPressureSnapshot) {
        guard count > 0 else { return }
        let removed = UInt64(count)
        switch before.reason {
        case .perRuleCount:
            Self.addSaturating(removed, to: &pendingPerRuleCountShedTotal)
        case .globalCount:
            Self.addSaturating(removed, to: &pendingGlobalCountShedTotal)
        case .semanticWeight:
            Self.addSaturating(removed, to: &pendingSemanticWeightShedTotal)
        }
        var snapshot = before
        snapshot.removedPendingSteps = removed
        lastPendingPressure = snapshot
        evictedPendingStepCount = Self.saturatingTelemetryAdd(
            evictedPendingStepCount,
            count
        )
        lastPendingStepEvictionAt = Date()
    }

    /// When pending-step eviction last actually happened.
    ///
    /// The cumulative counters answer "has this ever occurred", which is the
    /// right question for a diagnostic and the WRONG one for a health flag: a
    /// lifetime total never decreases, so a health signal derived from
    /// `> 0` latches on at the first eviction and can never clear for the life
    /// of the process. That is exactly what shipped — one transient eviction
    /// during a load spike left the menu bar reading "protection degraded"
    /// indefinitely, which trains an operator to ignore the one indicator that
    /// is supposed to mean something.
    ///
    /// Recency lets the caller ask the question a health flag should ask: is
    /// sequence state being lost *now*?
    private(set) var lastPendingStepEvictionAt: Date?

    /// As above, for partial-match eviction.
    private(set) var lastPartialEvictionAt: Date?

    /// True when eviction occurred within `window`. Nil timestamps mean it has
    /// never happened, which is healthy.
    public func evictionIsOngoing(within window: TimeInterval, now: Date = Date()) -> Bool {
        for stamp in [lastPendingStepEvictionAt, lastPartialEvictionAt] {
            if let stamp, now.timeIntervalSince(stamp) <= window { return true }
        }
        return false
    }

    /// Test seam: drive the recency stamps directly so a regression can pin the
    /// latch behaviour without having to manufacture a real cap overflow.
    func setEvictionTimestampsForTesting(pending: Date?, partial: Date?) {
        lastPendingStepEvictionAt = pending
        lastPartialEvictionAt = partial
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
        var proposedRules = rules
        for rule in batch.rules { proposedRules[rule.id] = rule }
        try validateCheckpointableRuleCorpus(Array(proposedRules.values))
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
        guard jsonFiles.count <= SequenceCheckpointLimits.maximumRules else {
            throw SequenceEngineError.invalidRule(
                "<corpus>",
                "Sequence rule file count exceeds \(SequenceCheckpointLimits.maximumRules)"
            )
        }
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
        var nextHeavyDependencies: [String: [String: HeavyEnrichmentDependencyMask]] = [:]
        var nextFoldStepIDs: [String: String] = [:]
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
            nextFoldStepIDs[rule.id] = Self.pendingFoldStepID(for: rule)
            nextHeavyDependencies[rule.id] = Dictionary(
                uniqueKeysWithValues: rule.steps.map { step in
                    (step.id, HeavyEnrichmentRuleCoverage.dependencyMask(
                        predicates: step.predicates,
                        conditionTree: step.conditionTree
                    ))
                }
            )
            for step in rule.steps {
                nextIndex[step.logsourceCategory, default: []].insert(rule.id)
            }
        }

        let ruleFingerprintStateChanged = prevRules != nextRules
        try validateCheckpointableRuleCorpus(Array(nextRules.values))
        rules = nextRules
        pendingFoldStepIDByRule = nextFoldStepIDs
        ruleIndex = nextIndex
        heavyDependencyMasks = nextHeavyDependencies
        ruleSetGeneration &+= 1
        if ruleFingerprintStateChanged { markCheckpointStateMutation() }

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
        // A fold throttle can outlive its rule's state; drop removed rules'.
        pendingFoldBlockedUntilSerial = pendingFoldBlockedUntilSerial.filter { rules[$0.key] != nil }
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
        var proposedRules = rules
        proposedRules[rule.id] = rule
        try validateCheckpointableRuleCorpus(Array(proposedRules.values))
        installRule(rule)
    }

    /// Validate that a rule is internally consistent.
    private func validateRule(_ rule: SequenceRule) throws {
        guard rule.window.isFinite, rule.window > 0 else {
            throw SequenceEngineError.invalidRule(
                rule.id,
                "Window must be finite and greater than zero"
            )
        }
        guard !rule.steps.isEmpty else {
            throw SequenceEngineError.invalidRule(rule.id, "Rule has no steps")
        }

        let stepIds = Set(rule.steps.map(\.id))
        guard stepIds.count == rule.steps.count else {
            throw SequenceEngineError.invalidRule(rule.id, "Duplicate step IDs")
        }
        let stepIndex = Dictionary(uniqueKeysWithValues: rule.steps.enumerated().map {
            ($0.element.id, $0.offset)
        })

        // Validate afterStep references.
        for step in rule.steps {
            if let afterStep = step.afterStep {
                guard stepIds.contains(afterStep), afterStep != step.id else {
                    throw SequenceEngineError.invalidRule(
                        rule.id,
                        "Step '\(step.id)' has an unknown or self afterStep '\(afterStep)'"
                    )
                }
                if rule.ordered,
                   (stepIndex[afterStep] ?? Int.max) >= (stepIndex[step.id] ?? 0) {
                    throw SequenceEngineError.invalidRule(
                        rule.id,
                        "Ordered step '\(step.id)' afterStep must reference an earlier step"
                    )
                }
            }
        }

        // Validate processRelation references.
        for step in rule.steps {
            if let spec = step.processRelation {
                guard stepIds.contains(spec.relativeToStep),
                      spec.relativeToStep != step.id else {
                    throw SequenceEngineError.invalidRule(
                        rule.id,
                        "Step '\(step.id)' has an unknown or self relativeToStep '\(spec.relativeToStep)'"
                    )
                }
                if rule.ordered,
                   (stepIndex[spec.relativeToStep] ?? Int.max)
                        >= (stepIndex[step.id] ?? 0) {
                    throw SequenceEngineError.invalidRule(
                        rule.id,
                        "Ordered step '\(step.id)' process relation must reference an earlier step"
                    )
                }
            }
        }

        if !rule.ordered {
            var reachable = Set(rule.steps.compactMap { step in
                step.afterStep == nil && step.processRelation == nil ? step.id : nil
            })
            var changed = true
            while changed {
                changed = false
                for step in rule.steps where !reachable.contains(step.id) {
                    let dependencies = [
                        step.afterStep,
                        step.processRelation?.relativeToStep,
                    ].compactMap { $0 }
                    if !dependencies.isEmpty,
                       dependencies.allSatisfy(reachable.contains) {
                        reachable.insert(step.id)
                        changed = true
                    }
                }
            }
            guard reachable.count == rule.steps.count else {
                throw SequenceEngineError.invalidRule(
                    rule.id,
                    "Unordered dependency graph is cyclic or unreachable from a seed step"
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
            guard !ids.isEmpty, Set(ids).count == ids.count else {
                throw SequenceEngineError.invalidRule(
                    rule.id,
                    "Trigger step IDs must be nonempty and unique"
                )
            }
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

        do {
            try SequenceCheckpointCodec.validateRuleFingerprintShape(rule)
        } catch {
            throw SequenceEngineError.invalidRule(rule.id, error.localizedDescription)
        }
    }

    private func validateCheckpointableRuleCorpus(_ proposedRules: [SequenceRule]) throws {
        do {
            _ = try SequenceCheckpointCodec.ruleFingerprint(proposedRules)
        } catch {
            throw SequenceEngineError.invalidRule(
                "<corpus>",
                "Rule corpus is not checkpointable: \(error.localizedDescription)"
            )
        }
    }

    // MARK: - Rule Management

    /// Enable or disable a sequence rule by ID.
    public func setEnabled(_ ruleId: String, enabled: Bool) async {
        guard await acquireMutationLease() == .acquired else { return }
        defer { releaseMutationLease() }
        guard !Task.isCancelled else { return }

        guard let previous = rules[ruleId] else {
            logger.warning("setEnabled called for unknown sequence rule: \(ruleId)")
            return
        }
        guard previous.enabled != enabled else { return }
        rules[ruleId]?.enabled = enabled
        ruleSetGeneration &+= 1
        markCheckpointStateMutation()

        // If disabling, discard any in-flight partial matches for this rule.
        if !enabled {
            setPartialBucket([], for: ruleId)
            setPendingBucket([], for: ruleId)
            pendingFoldBlockedUntilSerial.removeValue(forKey: ruleId)
            compactEvictionQueue(force: true)
            compactPendingEvictionQueue(force: true)
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
    /// start. Victims are the oldest partials of the largest rule bucket (count
    /// or semantic weight), so a flood of one rule's cheap step[0] sheds that
    /// rule's own in-flight state once its bucket is the largest; until then
    /// it trims the largest bucket toward an equal share, never every rule's
    /// oldest state. Surfaced as `sequence_partials_evicted_total`.
    public var partialsEvictedTotal: Int {
        evictedPartialCount
    }

    /// Live pending later-step history shed by the count or weight limit
    /// (largest bucket first). Expired retirement and same-writer folds are
    /// journal completed, not counted here.
    /// A nonzero value means out-of-order sequence continuity was degraded.
    public var pendingStepsEvictedTotal: Int {
        evictedPendingStepCount
    }

    /// Producer-owned conservation boundary for out-of-order sequence history.
    /// Mutations are synchronous on this actor, so there is no unclassified
    /// in-flight state between admission and a terminal/queued disposition.
    func pendingStepConservation() -> SequenceConservationTelemetry {
        SequenceConservationTelemetry(
            offered: pendingStepsOfferedTotal,
            completed: pendingStepsCompletedTotal,
            queued: UInt64(totalPendingStepCount),
            inFlight: 0,
            explicitlyShed: pendingStepsExplicitlyShedTotal
        )
    }

    /// Trusted rule IDs are the only labels. Retain cumulative entries after a
    /// reload/removal so the rule responsible for an earlier shed episode does
    /// not disappear from the next diagnostic heartbeat.
    func pendingStepConservationByRule() -> [String: SequenceConservationTelemetry] {
        let keys = Set(pendingStepsOfferedByRule.keys)
            .union(pendingStepsCompletedByRule.keys)
            .union(pendingStepsExplicitlyShedByRule.keys)
            .union(pendingLaterSteps.keys)
        return Dictionary(uniqueKeysWithValues: keys.map { ruleId in
            (ruleId, SequenceConservationTelemetry(
                offered: pendingStepsOfferedByRule[ruleId] ?? 0,
                completed: pendingStepsCompletedByRule[ruleId] ?? 0,
                queued: UInt64(pendingLaterSteps[ruleId]?.count ?? 0),
                inFlight: 0,
                explicitlyShed: pendingStepsExplicitlyShedByRule[ruleId] ?? 0
            ))
        })
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

    /// Exact representation counts plus inline type sizes, not retained heap or
    /// RSS estimates. Strings/ancestor arrays and checkpoint copies still need
    /// native resource measurement before this policy can be release-qualified.
    struct PartialRepresentationDiagnostics: Sendable {
        let partialCount: Int
        let emptyBindings: Int
        let inlineSingleBindings: Int
        let dictionaryBindings: Int
        let totalMatchedSteps: Int
        let matchedStepStride: Int
        let containerStride: Int
        let dictionaryStride: Int
        let partialStride: Int
    }

    func partialRepresentationDiagnostics() -> PartialRepresentationDiagnostics {
        var empty = 0
        var single = 0
        var multiple = 0
        var matchedSteps = 0
        for partial in partialMatches.values.joined() {
            matchedSteps += partial.matchedSteps.count
            if partial.matchedSteps.isEmpty { empty += 1 }
            else if partial.matchedSteps.isInlineSingle { single += 1 }
            else { multiple += 1 }
        }
        return PartialRepresentationDiagnostics(
            partialCount: totalPartialCount, emptyBindings: empty,
            inlineSingleBindings: single, dictionaryBindings: multiple,
            totalMatchedSteps: matchedSteps,
            matchedStepStride: MemoryLayout<MatchedStep>.stride,
            containerStride: MemoryLayout<SequenceMatchedSteps<MatchedStep>>.stride,
            dictionaryStride: MemoryLayout<[String: MatchedStep]>.stride,
            partialStride: MemoryLayout<PartialMatch>.stride
        )
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

    public struct CheckpointWeightDiagnostics: Sendable, Equatable {
        public let cachedWeight: Int
        public let recomputedWeight: Int
        public let maximumWeight: Int
        public let partialCount: Int
        public let pendingCount: Int
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

    func checkpointWeightDiagnostics() -> CheckpointWeightDiagnostics {
        CheckpointWeightDiagnostics(
            cachedWeight: checkpointStateWeight,
            // The heartbeat calls this every 30 seconds on the detection
            // actor. Re-summing immutable per-record weights independently
            // verifies bucket accounting without allocating and sorting a
            // second complete checkpoint model on that latency-sensitive path.
            // checkpointCapture performs the deeper field-by-field audit.
            recomputedWeight: recomputedCheckpointAccountingWeight(),
            maximumWeight: SequenceCheckpointCodec.maximumSemanticStateWeight,
            partialCount: totalPartialCount,
            pendingCount: totalPendingStepCount
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

    // MARK: - Durable recovery checkpoint

    private nonisolated static func checkpointPartial(
        _ partial: PartialMatch,
        rule: SequenceRule
    ) -> SequenceCheckpointPartial {
        SequenceCheckpointPartial(
            id: partial.id,
            ruleID: partial.ruleId,
            createdAt: partial.createdAt,
            matchedSteps: partial.matchedSteps.values
                .sorted { $0.stepId < $1.stepId }
                .map { checkpointMatchedStep($0, for: rule) },
            correlationKey: partial.correlationKey
        )
    }

    private nonisolated static func checkpointPending(
        _ pending: PendingStep,
        ruleId: String,
        rule: SequenceRule
    ) -> SequenceCheckpointPendingStep {
        SequenceCheckpointPendingStep(
            ruleID: ruleId,
            stepID: pending.step.id,
            matched: checkpointMatchedStep(pending.matched, for: rule),
            arrivedAt: pending.arrivedAt
        )
    }

    private func partialBucketWeight(ruleId: String, partials: [PartialMatch]) -> Int {
        guard !partials.isEmpty else { return 0 }
        return partials.reduce(
            SequenceCheckpointCodec.estimatedBucketOverhead(ruleID: ruleId)
        ) { Self.saturatingTelemetryAdd($0, $1.checkpointWeight) }
    }

    private func pendingBucketWeight(ruleId: String, pending: [PendingStep]) -> Int {
        guard !pending.isEmpty else { return 0 }
        return pending.reduce(
            SequenceCheckpointCodec.estimatedBucketOverhead(ruleID: ruleId)
        ) { Self.saturatingTelemetryAdd($0, $1.checkpointWeight) }
    }

    private func recomputedCheckpointAccountingWeight() -> Int {
        var total = SequenceCheckpointCodec.semanticStateBaseWeight
        for (ruleId, partials) in partialMatches where !partials.isEmpty {
            total = Self.saturatingTelemetryAdd(
                total,
                partialBucketWeight(ruleId: ruleId, partials: partials)
            )
        }
        for (ruleId, pending) in pendingLaterSteps where !pending.isEmpty {
            total = Self.saturatingTelemetryAdd(
                total,
                pendingBucketWeight(ruleId: ruleId, pending: pending)
            )
        }
        return total
    }

    private func setPartialBucket(_ partials: [PartialMatch], for ruleId: String) {
        let oldWeight = partialBucketWeight(
            ruleId: ruleId,
            partials: partialMatches[ruleId] ?? []
        )
        if checkpointStateWeight < oldWeight {
            checkpointStateWeight = recomputedCheckpointAccountingWeight()
        }
        checkpointStateWeight -= min(checkpointStateWeight, oldWeight)
        let newWeight = partialBucketWeight(ruleId: ruleId, partials: partials)
        checkpointStateWeight = Self.saturatingTelemetryAdd(checkpointStateWeight, newWeight)
        partialMatches[ruleId] = partials.isEmpty ? nil : partials
    }

    /// A unique seed adds exactly one record and, only for a new bucket, its
    /// overhead. Mutate the dictionary's array in place rather than copying and
    /// re-summing the complete bucket twice for every ordinary initial event.
    /// Replacements/retirement retain the audited general setter above.
    private func appendUniquePartial(_ partial: PartialMatch, for ruleId: String) {
        let startsBucket = partialMatches[ruleId]?.isEmpty ?? true
        partialMatches[ruleId, default: []].append(partial)
        let overhead = startsBucket
            ? SequenceCheckpointCodec.estimatedBucketOverhead(ruleID: ruleId)
            : 0
        checkpointStateWeight = Self.saturatingTelemetryAdd(
            checkpointStateWeight,
            Self.saturatingTelemetryAdd(overhead, partial.checkpointWeight)
        )
    }

    private func setPendingBucket(
        _ pending: [PendingStep],
        for ruleId: String,
        removedDisposition: PendingStepRemovalDisposition = .completed
    ) {
        Self.incrementSaturating(&pendingIdentityRebuildCount)
        let oldPending = pendingLaterSteps[ruleId] ?? []
        let oldIdentities = Set(oldPending.map {
            pendingIdentity(ruleId: ruleId, pending: $0)
        })
        let newIdentities = Set(pending.map {
            pendingIdentity(ruleId: ruleId, pending: $0)
        })
        let offeredCount = UInt64(newIdentities.subtracting(oldIdentities).count)
        Self.addSaturating(offeredCount, to: &pendingStepsOfferedTotal)
        Self.addSaturating(
            offeredCount,
            for: ruleId,
            in: &pendingStepsOfferedByRule
        )
        let removedCount = UInt64(oldIdentities.subtracting(newIdentities).count)
        switch removedDisposition {
        case .completed:
            Self.addSaturating(removedCount, to: &pendingStepsCompletedTotal)
            Self.addSaturating(
                removedCount,
                for: ruleId,
                in: &pendingStepsCompletedByRule
            )
        case .explicitlyShed:
            Self.addSaturating(removedCount, to: &pendingStepsExplicitlyShedTotal)
            Self.addSaturating(
                removedCount,
                for: ruleId,
                in: &pendingStepsExplicitlyShedByRule
            )
        }

        let oldWeight = pendingBucketWeight(
            ruleId: ruleId,
            pending: oldPending
        )
        if checkpointStateWeight < oldWeight {
            checkpointStateWeight = recomputedCheckpointAccountingWeight()
        }
        checkpointStateWeight -= min(checkpointStateWeight, oldWeight)
        let newWeight = pendingBucketWeight(ruleId: ruleId, pending: pending)
        checkpointStateWeight = Self.saturatingTelemetryAdd(checkpointStateWeight, newWeight)
        pendingLaterSteps[ruleId] = pending.isEmpty ? nil : pending
    }

    /// The caller has already rejected duplicate (eventID, stepID) identities.
    /// An append changes precisely one admission and one record weight. Avoid
    /// copying the bucket, rebuilding both full identity sets, and rescanning
    /// every cached weight while the shared sequence mutation lease is held.
    /// General replacement/retirement still uses setPendingBucket; capture
    /// independently audits this incremental weight against the exact model.
    private func appendUniquePendingStep(_ pending: PendingStep, for ruleId: String) {
        let startsBucket = pendingLaterSteps[ruleId]?.isEmpty ?? true
        pendingLaterSteps[ruleId, default: []].append(pending)
        Self.addSaturating(1, to: &pendingStepsOfferedTotal)
        Self.addSaturating(1, for: ruleId, in: &pendingStepsOfferedByRule)
        let bucketOverhead = startsBucket
            ? SequenceCheckpointCodec.estimatedBucketOverhead(ruleID: ruleId)
            : 0
        checkpointStateWeight = Self.saturatingTelemetryAdd(
            checkpointStateWeight,
            Self.saturatingTelemetryAdd(bucketOverhead, pending.checkpointWeight)
        )
        pendingAdmissionSerial &+= 1
    }

    /// Removes `count` entries from the front (oldest admission) of one bucket,
    /// in place, and records exactly what
    /// setPendingBucket(Array(bucket.dropFirst(count)), removedDisposition:)
    /// would: offered unchanged; `count` completed or explicitly_shed identities
    /// (bucket identities are unique: bufferPendingStep dedupes and the
    /// restore validator rejects duplicates) in total and by rule; checkpoint
    /// weight reduced by the removed records plus the bucket overhead when the
    /// bucket empties. Global-queue references of removed identities stay for
    /// the existing lazy compaction. No identity Set is built, but the cost is
    /// still linear: the removed records are summed and removeFirst shifts
    /// every survivor. Callers must not hold a local copy of this bucket
    /// across the call (that forces a whole-bucket copy-on-write).
    private func removePendingFront(
        ruleId: String,
        count: Int,
        disposition: PendingStepRemovalDisposition
    ) {
        guard count > 0, let size = pendingLaterSteps[ruleId]?.count, count <= size else { return }
        var removedWeight = pendingLaterSteps[ruleId]?[0..<count].reduce(0) {
            Self.saturatingTelemetryAdd($0, $1.checkpointWeight)
        } ?? 0
        if count == size {
            removedWeight = Self.saturatingTelemetryAdd(
                removedWeight,
                SequenceCheckpointCodec.estimatedBucketOverhead(ruleID: ruleId)
            )
        }
        // Recompute only when the cached total is below the weight removed
        // here, which only accounting drift can cause. (setPendingBucket
        // recomputes when the total is below the whole old bucket's weight.)
        if checkpointStateWeight < removedWeight {
            checkpointStateWeight = recomputedCheckpointAccountingWeight()
        }
        checkpointStateWeight -= min(checkpointStateWeight, removedWeight)
        if count == size {
            pendingLaterSteps[ruleId] = nil
        } else {
            pendingLaterSteps[ruleId]?.removeFirst(count)
        }
        Self.addSaturating(UInt64(size), to: &pendingCapacityElementVisitCount)
        let removed = UInt64(count)
        switch disposition {
        case .completed:
            Self.addSaturating(removed, to: &pendingStepsCompletedTotal)
            Self.addSaturating(removed, for: ruleId, in: &pendingStepsCompletedByRule)
        case .explicitlyShed:
            Self.addSaturating(removed, to: &pendingStepsExplicitlyShedTotal)
            Self.addSaturating(removed, for: ruleId, in: &pendingStepsExplicitlyShedByRule)
        }
    }

    private nonisolated static func weightedPartial(
        _ partial: PartialMatch,
        rule: SequenceRule
    ) -> PartialMatch {
        var weighted = partial
        weighted.checkpointWeight = SequenceCheckpointCodec.estimatedWeight(
            of: checkpointPartial(weighted, rule: rule)
        )
        return weighted
    }

    private nonisolated static func weightedPending(
        _ pending: PendingStep,
        ruleId: String,
        rule: SequenceRule
    ) -> PendingStep {
        var weighted = pending
        weighted.checkpointWeight = SequenceCheckpointCodec.estimatedWeight(
            of: checkpointPending(weighted, ruleId: ruleId, rule: rule)
        )
        return weighted
    }

    /// Enforce the conservative carrier budget on runtime state, while the
    /// event mutation is still in progress. Pending replay history is shed
    /// before live partials; within each kind the victim is the oldest entry
    /// of the bucket with the most semantic weight; both losses are explicit
    /// telemetry. Before any pending entry is shed, every fold-eligible
    /// bucket holding at least two entries gets at most one throttled fold
    /// attempt per call: the victim first, then the others through
    /// foldOtherPendingBucket. Bucket weights are summed once per call and
    /// then adjusted per removal, so no identity map is built; each partial
    /// removal still copies its bucket once.
    private func enforceCheckpointStateWeightBudget() {
        let limit = SequenceCheckpointCodec.maximumSemanticStateWeight
        guard checkpointStateWeight > limit else { return }
        // An entry can expire after the periodic sweep, including while an
        // evaluation awaits its lineage snapshot. Retire that history as
        // completed before attributing any removal to the carrier limit.
        sweepExpiredBeforePressure()
        var pendingShed = 0
        var partialsRemoved = 0
        if checkpointStateWeight > limit, !pendingLaterSteps.isEmpty {
            var weights = Dictionary(uniqueKeysWithValues: pendingLaterSteps.map {
                ($0.key, pendingBucketWeight(ruleId: $0.key, pending: $0.value))
            })
            var foldTried = Set<String>()
            var pressureBefore: PendingPressureSnapshot?
            while checkpointStateWeight > limit,
                  let victim = largestPendingBucketRuleID(weights: weights) {
                if foldTried.insert(victim).inserted, foldPendingBucketIfDue(ruleId: victim) > 0 {
                    weights[victim] = pendingLaterSteps[victim].map {
                        pendingBucketWeight(ruleId: victim, pending: $0)
                    }
                    continue
                }
                if let folded = foldOtherPendingBucket(tried: &foldTried) {
                    weights[folded] = pendingLaterSteps[folded].map {
                        pendingBucketWeight(ruleId: folded, pending: $0)
                    }
                    continue
                }
                guard let front = pendingLaterSteps[victim]?.first else { break }
                if pressureBefore == nil {
                    pressureBefore = pendingPressureSnapshot(
                        reason: .semanticWeight, pendingCount: totalPendingStepCount,
                        ruleID: victim, stepID: front.step.id
                    )
                }
                removePendingFront(ruleId: victim, count: 1, disposition: .explicitlyShed)
                pendingShed += 1
                weights[victim] = pendingLaterSteps[victim] == nil
                    ? nil
                    : (weights[victim] ?? 0) - front.checkpointWeight
            }
            if let pressureBefore { recordPendingEvictions(pendingShed, before: pressureBefore) }
        }
        if checkpointStateWeight > limit, pendingLaterSteps.isEmpty, !partialMatches.isEmpty {
            let observedAt = Date()
            let partialCountBefore = totalPartialCount
            let weightBefore = checkpointStateWeight
            var weights = Dictionary(uniqueKeysWithValues: partialMatches.map {
                ($0.key, partialBucketWeight(ruleId: $0.key, partials: $0.value))
            })
            while checkpointStateWeight > limit,
                  let victim = largestPartialBucketRuleID(weights: weights),
                  let partials = partialMatches[victim], let front = partials.first {
                // The front is the oldest seed: partials are appended at seed time.
                setPartialBucket(Array(partials.dropFirst()), for: victim)
                partialsRemoved += 1
                weights[victim] = partialMatches[victim] == nil
                    ? nil
                    : (weights[victim] ?? 0) - front.checkpointWeight
            }
            recordPartialPressure(
                partialsRemoved, reason: .semanticWeight, observedAt: observedAt,
                pendingCountBefore: 0,
                partialCountBefore: partialCountBefore, stateWeightBytesBefore: weightBefore
            )
        }
        if partialsRemoved > 0 {
            evictedPartialCount = Self.saturatingTelemetryAdd(
                evictedPartialCount,
                partialsRemoved
            )
            lastPartialEvictionAt = Date()
        }
        if pendingShed > 0 || partialsRemoved > 0 {
            markCheckpointStateMutation()
            compactPendingEvictionQueue()
            compactEvictionQueue()
        }
        if checkpointStateWeight > limit {
            logger.error("Sequence checkpoint weight exceeded without evictable runtime state")
        }
    }

    /// Copy the bounded semantics-bearing state while holding the same lease as
    /// evaluation/reload. The returned value is Sendable; canonical encoding,
    /// hashing, LZFSE compression, and disk I/O are intentionally performed by
    /// SequenceCheckpointCoordinator after this method leaves actor isolation.
    func checkpointCapture(at capturedAt: Date = Date()) async throws -> SequenceCheckpointCapture {
        try await acquireMutationLeaseOrThrow()
        defer { releaseMutationLease() }
        try Task.checkCancellation()

        compactEvictionQueue(force: true)
        compactPendingEvictionQueue(force: true)
        let checkpointPartialBuckets: [SequenceCheckpointPartialBucket] =
            partialMatches.keys.sorted().compactMap { ruleId in
                guard let partials = partialMatches[ruleId], !partials.isEmpty,
                      let rule = rules[ruleId] else { return nil }
                return SequenceCheckpointPartialBucket(
                    ruleID: ruleId,
                    partials: partials.map { Self.checkpointPartial($0, rule: rule) }
                )
            }

        let checkpointPendingBuckets: [SequenceCheckpointPendingBucket] =
            pendingLaterSteps.keys.sorted().compactMap { ruleId in
                guard let pending = pendingLaterSteps[ruleId], !pending.isEmpty,
                      let rule = rules[ruleId] else { return nil }
                return SequenceCheckpointPendingBucket(
                    ruleID: ruleId,
                    steps: pending.map {
                        Self.checkpointPending($0, ruleId: ruleId, rule: rule)
                    }
                )
            }

        // Deep field-by-field audit on the normal 30-second checkpoint path.
        // The same materialized buckets are reused below, avoiding the former
        // double allocation/sort. This catches a missed per-record reweight;
        // the heartbeat's cheap resummation catches bucket-account drift.
        let recomputedWeight = SequenceCheckpointCodec.estimatedSemanticStateWeight(
            partialBuckets: checkpointPartialBuckets,
            pendingBuckets: checkpointPendingBuckets
        )
        guard recomputedWeight == checkpointStateWeight else {
            throw SequenceCheckpointError.invalidPayload(
                "runtime checkpoint weight accounting drifted (cached \(checkpointStateWeight), exact \(recomputedWeight))"
            )
        }
        guard checkpointStateWeight <= SequenceCheckpointCodec.maximumSemanticStateWeight else {
            throw SequenceCheckpointError.invalidPayload(
                "runtime checkpoint state exceeds its carrier budget"
            )
        }

        let livePartialIDs = Set(
            checkpointPartialBuckets.flatMap { bucket in
                bucket.partials.map { $0.id }
            }
        )
        let activeReferences = evictionQueueHead < evictionQueue.count
            ? Array(evictionQueue[evictionQueueHead...])
            : []
        let checkpointEvictionOrder = activeReferences.map(\.partialId)
        guard checkpointEvictionOrder.count == livePartialIDs.count,
              Set(checkpointEvictionOrder) == livePartialIDs else {
            throw SequenceCheckpointError.invalidPayload(
                "live eviction queue does not exactly cover active partials"
            )
        }

        let livePendingIdentities = Set(checkpointPendingBuckets.flatMap { bucket in
            bucket.steps.map {
                SequenceCheckpointPendingIdentity(
                    ruleID: bucket.ruleID,
                    stepID: $0.stepID,
                    eventID: $0.matched.eventID
                )
            }
        })
        let activePendingReferences = pendingEvictionQueueHead < pendingEvictionQueue.count
            ? Array(pendingEvictionQueue[pendingEvictionQueueHead...])
            : []
        let checkpointPendingEvictionOrder = activePendingReferences.map(\.identity)
        guard checkpointPendingEvictionOrder.count <= Self.maxPendingTotal,
              checkpointPendingEvictionOrder.count == livePendingIdentities.count,
              Set(checkpointPendingEvictionOrder) == livePendingIdentities else {
            throw SequenceCheckpointError.invalidPayload(
                "live pending eviction queue does not exactly cover pending history"
            )
        }

        return SequenceCheckpointCapture(
            capturedAt: capturedAt,
            sourceGeneration: checkpointGeneration,
            rules: rules.values.sorted { $0.id < $1.id },
            partialBuckets: checkpointPartialBuckets,
            pendingBuckets: checkpointPendingBuckets,
            evictionOrder: checkpointEvictionOrder,
            pendingEvictionOrder: checkpointPendingEvictionOrder
        )
    }

    /// Process-local hint used after a detached write to determine whether new
    /// events changed state while the older snapshot was being persisted.
    func checkpointGenerationSnapshot() -> UInt64 {
        checkpointGeneration
    }

    /// Atomically validate and install a decoded checkpoint after rules load.
    /// Every rule/step/identity/cap/timestamp check completes before any live
    /// state is replaced. Existing live state refuses restore so a late caller
    /// cannot discard events that arrived during daemon startup.
    func restoreCheckpoint(
        _ payload: SequenceCheckpointPayload,
        now: Date = Date()
    ) async throws -> SequenceCheckpointApplyResult {
        try await acquireMutationLeaseOrThrow()
        defer { releaseMutationLease() }
        try Task.checkCancellation()

        guard checkpointRestoreAllowed,
              totalPartialCount == 0,
              pendingLaterSteps.values.allSatisfy(\.isEmpty) else {
            throw SequenceCheckpointError.engineAlreadyActive
        }

        let validated = try SequenceCheckpointValidator.validate(
            payload,
            rules: rules,
            maximumPartialMatches: maxPartialMatches,
            maximumPendingPerRule: Self.maxPendingPerRule,
            now: now
        )

        var restoredPartials: [String: [PartialMatch]] = [:]
        var partialByID: [UUID: PartialMatch] = [:]
        for bucket in validated.partialBuckets {
            guard let rule = rules[bucket.ruleID] else {
                throw SequenceCheckpointError.invalidPayload(
                    "validated partial bucket lost active rule \(bucket.ruleID)"
                )
            }
            let values = bucket.partials.map { record in
                let matchedSteps = SequenceMatchedSteps(uniqueKeysWithValues: record.matchedSteps.map {
                    ($0.stepID, Self.runtimeMatchedStep($0))
                })
                let partial = PartialMatch(
                    id: record.id,
                    ruleId: record.ruleID,
                    createdAt: record.createdAt,
                    matchedSteps: matchedSteps,
                    // Legacy v1 nonce shape was validated above before this
                    // schema-v2 normalization. Independent identity is the
                    // unchanged partial UUID, never a merged correlation key.
                    correlationKey: rule.correlationType == .none ? nil : record.correlationKey,
                    checkpointWeight: 0
                )
                return Self.weightedPartial(partial, rule: rule)
            }
            restoredPartials[bucket.ruleID] = values
            for partial in values { partialByID[partial.id] = partial }
        }

        var restoredPending: [String: [PendingStep]] = [:]
        var pendingByIdentity: [SequenceCheckpointPendingIdentity: PendingStep] = [:]
        for bucket in validated.pendingBuckets {
            guard let rule = rules[bucket.ruleID] else {
                throw SequenceCheckpointError.invalidPayload(
                    "validated pending bucket lost active rule \(bucket.ruleID)"
                )
            }
            let stepsByID = Dictionary(uniqueKeysWithValues: rule.steps.map { ($0.id, $0) })
            let restoredBucket = try bucket.steps.map { record in
                guard let step = stepsByID[record.stepID] else {
                    throw SequenceCheckpointError.invalidPayload(
                        "validated pending step lost definition \(record.stepID)"
                    )
                }
                let pending = PendingStep(
                    step: step,
                    matched: Self.runtimeMatchedStep(record.matched),
                    arrivedAt: record.arrivedAt,
                    checkpointWeight: 0
                )
                return Self.weightedPending(
                    pending,
                    ruleId: bucket.ruleID,
                    rule: rule
                )
            }
            restoredPending[bucket.ruleID] = restoredBucket
            for pending in restoredBucket {
                pendingByIdentity[pendingIdentity(ruleId: bucket.ruleID, pending: pending)] = pending
            }
        }

        var restoredEvictionQueue: [PartialMatchRef] = []
        restoredEvictionQueue.reserveCapacity(validated.evictionOrder.count)
        for partialID in validated.evictionOrder {
            guard let partial = partialByID[partialID] else {
                throw SequenceCheckpointError.invalidPayload(
                    "validated eviction identity lost partial \(partialID)"
                )
            }
            restoredEvictionQueue.append(PartialMatchRef(
                ruleId: partial.ruleId,
                partialId: partial.id,
                createdAt: partial.createdAt
            ))
        }


        var restoredPendingEvictionQueue: [PendingStepRef] = []
        restoredPendingEvictionQueue.reserveCapacity(validated.pendingEvictionOrder.count)
        for identity in validated.pendingEvictionOrder {
            guard pendingByIdentity[identity] != nil else {
                throw SequenceCheckpointError.invalidPayload(
                    "validated pending eviction identity lost step \(identity.eventID)"
                )
            }
            restoredPendingEvictionQueue.append(PendingStepRef(identity: identity))
        }

        partialMatches.removeAll(keepingCapacity: true)
        pendingLaterSteps.removeAll(keepingCapacity: true)
        checkpointStateWeight = SequenceCheckpointCodec.semanticStateBaseWeight
        for (ruleId, partials) in restoredPartials {
            setPartialBucket(partials, for: ruleId)
        }
        for (ruleId, pending) in restoredPending {
            setPendingBucket(pending, for: ruleId)
        }
        evictionQueue = restoredEvictionQueue
        evictionQueueHead = 0
        pendingEvictionQueue = restoredPendingEvictionQueue
        pendingEvictionQueueHead = 0
        lastSweep = now
        lastPreemptiveSweep = .distantPast
        markCheckpointStateMutation()
        checkpointRestoreAllowed = false

        return SequenceCheckpointApplyResult(
            partialCount: restoredPartials.values.reduce(0) { $0 + $1.count },
            pendingCount: restoredPending.values.reduce(0) { $0 + $1.count },
            expiredPartialCount: validated.expiredPartialCount,
            expiredPendingCount: validated.expiredPendingCount,
            generation: checkpointGeneration
        )
    }

    private nonisolated static func checkpointMatchedStep(
        _ matched: MatchedStep,
        for rule: SequenceRule
    ) -> SequenceCheckpointMatchedStep {
        let ancestryRequired = rule.correlationType == .processLineage
            || rule.steps.contains { step in
                guard let relation = step.processRelation?.relation else { return false }
                switch relation {
                case .descendant, .ancestor, .sameTree:
                    return true
                case .same, .sameProcess, .sibling, .any:
                    return false
                }
            }
        let siblingEvidenceRequired = rule.steps.contains {
            $0.processRelation?.relation == .sibling
        }
        return SequenceCheckpointMatchedStep(
            stepID: matched.stepId,
            eventID: matched.eventId,
            timestamp: matched.timestamp,
            processPID: matched.processPid,
            processParentPID: ancestryRequired || siblingEvidenceRequired
                ? matched.processParentPid : 0,
            processParentWasTracked: siblingEvidenceRequired
                && matched.processParentWasTracked,
            processAncestorPIDs: ancestryRequired ? matched.processAncestorPids : [],
            filePath: rule.correlationType == .filePath ? matched.filePath : nil,
            networkDestination: rule.correlationType == .networkEndpoint
                ? matched.networkDest : nil
        )
    }

    private nonisolated static func runtimeMatchedStep(
        _ matched: SequenceCheckpointMatchedStep
    ) -> MatchedStep {
        MatchedStep(
            stepId: matched.stepID,
            eventId: matched.eventID,
            timestamp: matched.timestamp,
            processPid: matched.processPID,
            processParentPid: matched.processParentPID,
            processParentWasTracked: matched.processParentWasTracked,
            processAncestorPids: matched.processAncestorPIDs,
            filePath: matched.filePath,
            networkDest: matched.networkDestination
        )
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
        await evaluate(event, dependencyFilter: nil)
    }

    /// Re-evaluate only sequence steps that consume newly completed heavyweight
    /// evidence. Independent steps are never replayed, so an event cannot seed
    /// or advance unrelated partial state a second time.
    public func reevaluate(
        _ event: Event,
        forCompleted components: Set<HeavyEnrichmentComponent>
    ) async -> [RuleMatch] {
        let dependencyFilter = HeavyEnrichmentDependencyMask(components: components)
        guard !dependencyFilter.isEmpty else { return [] }
        return await evaluate(event, dependencyFilter: dependencyFilter)
    }

    private func evaluate(
        _ event: Event,
        dependencyFilter: HeavyEnrichmentDependencyMask?
    ) async -> [RuleMatch] {
        // Predicate planning is pure over the event and the installed rules,
        // which change only synchronously on this actor, so it runs before the
        // mutation lease: an event matching no step (most file events) no
        // longer waits behind another lane holding the lease across its
        // lineage await. A plan made before the wait is rebuilt if the rules
        // changed meanwhile. Events that match nothing change no partial or
        // pending state, and sweeps only remove already-expired state.
        // Any evaluated event, matching or not, closes the startup restore gate.
        checkpointRestoreAllowed = false
        let plannedGeneration = ruleSetGeneration
        var plans = evaluationPlans(
            for: event,
            dependencyFilter: dependencyFilter,
            countEvaluations: true
        )
        guard !plans.isEmpty else {
            // Housekeeping keeps its cadence: only an event arriving when a
            // sweep is due takes the lease, and only to sweep.
            if housekeepingDue(now: Date()),
               await acquireMutationLease() == .acquired {
                defer { releaseMutationLease() }
                runHousekeeping(now: Date())
            }
            return []
        }

        guard await acquireMutationLease() == .acquired else { return [] }
        defer { releaseMutationLease() }
        guard !Task.isCancelled else { return [] }
        if ruleSetGeneration != plannedGeneration {
            plans = evaluationPlans(
                for: event,
                dependencyFilter: dependencyFilter,
                countEvaluations: false
            )
            guard !plans.isEmpty else {
                runHousekeeping(now: Date())
                return []
            }
        }

        let now = Date()
        runHousekeeping(now: now)

        // Build one atomic ProcessLineage view for every relationship that this
        // event can actually evaluate. The old path awaited the lineage actor up
        // to twice per bound step per partial while retaining the mutation lease;
        // at the 10K cap that turned one broad miss into tens of thousands of
        // suspension/handoff points and head-of-line blocked the priority lane.
        var relationshipPIDs: Set<pid_t> = []
        for plan in plans where planNeedsLineageSnapshot(plan) {
            relationshipPIDs.insert(event.process.pid)
            // An ordered first-step-only event cannot advance an existing
            // partial. With no pending history it cannot replay one either.
            // Keep the incoming PID's authoritative ancestry for its durable
            // seed, but do not rebuild unused ancestry for the retained pool.
            // Any possible advance keeps every partial PID.
            let canAdvanceExisting = !plan.rule.ordered || plan.matchingSteps.contains {
                $0.id != plan.rule.steps.first?.id
            }
            // Only an ordered step[0] match can seed, and only a seed runs the
            // full replay over pending history (Phase 3), so only such an
            // event requests pending PIDs. Replay on advance relies on each
            // entry's carried evidence (its recorded parent and ancestry), so
            // lineage learned after an entry was evaluated reaches it only
            // through a later seed's full replay. Requesting the history's
            // PIDs for every later-step event made a flood of buffered writes
            // cost O(history) lineage lookups per event.
            let canSeed = plan.rule.ordered
                && plan.matchingSteps.contains { $0.id == plan.rule.steps.first?.id }
            let canReplayPending = canSeed && pendingLaterSteps[plan.ruleId]?.isEmpty == false
            guard canAdvanceExisting || canReplayPending else { continue }
            for partial in partialMatches[plan.ruleId] ?? [] {
                for matched in partial.matchedSteps.values {
                    relationshipPIDs.insert(matched.processPid)
                }
            }
            if canReplayPending {
                for pending in pendingLaterSteps[plan.ruleId] ?? [] {
                    relationshipPIDs.insert(pending.matched.processPid)
                }
            }
        }

        let relationshipSnapshot: ProcessLineage.RelationshipSnapshot?
        if relationshipPIDs.isEmpty {
            relationshipSnapshot = nil
        } else {
            relationshipSnapshot = await lineage.relationshipSnapshot(for: relationshipPIDs)
            guard !Task.isCancelled else { return [] }
        }

        let eventTrackedParent = relationshipSnapshot?.trackedDirectParent(
            of: event.process.pid
        )
        var eventAncestorPIDs: [pid_t] = []
        eventAncestorPIDs.reserveCapacity(SequenceCheckpointLimits.maximumProcessAncestors)
        var seenEventAncestors = Set<pid_t>()
        func appendAncestor(_ pid: pid_t) {
            guard eventAncestorPIDs.count < SequenceCheckpointLimits.maximumProcessAncestors,
                  pid >= 0,
                  pid != event.process.pid,
                  seenEventAncestors.insert(pid).inserted else { return }
            eventAncestorPIDs.append(pid)
        }
        // Prioritize the authoritative snapshot evidence used by live matching;
        // then fill any remaining bounded slots from event enrichment.
        for pid in (relationshipSnapshot?.ancestorPIDs(of: event.process.pid) ?? []).sorted() {
            appendAncestor(pid)
        }
        for ancestor in event.process.ancestors { appendAncestor(ancestor.pid) }
        eventAncestorPIDs.sort()

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
                    processParentPid: eventTrackedParent ?? event.process.ppid,
                    processParentWasTracked: eventTrackedParent != nil,
                    processAncestorPids: eventAncestorPIDs,
                    filePath: event.file?.path,
                    networkDest: self.networkDestination(from: event)
                )
            }

            // Independent partial UUIDs remain unique per logical state,
            // not stable event identities. Remember only this event's unexpired
            // resident bindings before advancing: a replay must not seed them again.
            // Taking this snapshot AFTER Phase 1 would also suppress a genuine
            // new unordered seed merely because it advanced another partial.
            // No completed/evicted-event history is retained, and distinct event
            // UUIDs or distinct steps remain independent sequence candidates.
            var residentUncorrelatedStepIDs = Set<String>()
            if rule.correlationType == .none {
                for partial in partialMatches[ruleId] ?? []
                    where now.timeIntervalSince(partial.createdAt) <= rule.window {
                    for matched in partial.matchedSteps.values where matched.eventId == event.id {
                        residentUncorrelatedStepIDs.insert(matched.stepId)
                    }
                }
            }

            // --- Phase 1: Try to advance existing partial matches ---
            var advancedPartials: [(Int, PartialMatch)] = []  // (index, updated partial)
            var completedIndices: Set<Int> = []
            // Ordered partials this event advanced without completing, with the
            // index of the step it bound, for the replay on advance (Phase 3).
            var advancedStepIndexByPartial: [UUID: Int] = [:]
            // Ordered partials already contain their initial step, so a
            // first-step-only event cannot advance any of them. Avoid a full
            // bucket scan whose only outcome would be advancePartial's existing
            // step rejection. A later matching step (or unordered rule) keeps
            // the original fan-out/order semantics.
            let canAdvance = !rule.ordered || matchingSteps.contains {
                $0.id != rule.steps.first?.id
            }
            let existingPartials = canAdvance ? (partialMatches[ruleId] ?? []) : []
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
                    } else if rule.ordered,
                              let bound = rule.steps.firstIndex(where: { $0.id == step.id }) {
                        advancedStepIndexByPartial[updated.id] = bound
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

                // One event may complete thousands of compatible partials.
                // Repeated Array.remove(at:) shifts survivors on every removal;
                // filtering indices once preserves their exact relative order.
                if !completedIndices.isEmpty {
                    updatedList = updatedList.enumerated().compactMap {
                        completedIndices.contains($0.offset) ? nil : $0.element
                    }
                }

                setPartialBucket(updatedList, for: ruleId)
                markCheckpointStateMutation()
            }

            // --- Phase 2: Create new partial matches for initial steps ---
            // #95: track whether this event seeded a fresh partial from the
            // initial step — only then is it worth replaying all buffered
            // out-of-order later steps against every partial of the rule
            // (Phase 3). Otherwise Phase 3 replays only the steps after the
            // one Phase 1 bound, against the partials it advanced.
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
                    matched: matched
                )
                if (rule.correlationType == .filePath
                        || rule.correlationType == .networkEndpoint),
                   correlationKey == nil {
                    // Missing the required binding is not an independent key.
                    // Storing nil would make checkCorrelation's old guard path
                    // admit every later file/network value.
                    continue
                }

                // A .none key carries no correlation constraint, so key equality
                // cannot establish the identity of an already-resident binding.
                // Other correlation modes keep their existing admission policy.
                let alreadyStarted: Bool
                if rule.correlationType == .none {
                    alreadyStarted = residentUncorrelatedStepIDs.contains(step.id)
                } else {
                    alreadyStarted = partialMatches[ruleId]?.contains { partial in
                        partial.correlationKey == correlationKey
                        && partial.matchedSteps[step.id]?.eventId == event.id
                    } == true
                }
                guard !alreadyStarted else { continue }

                var newPartial = PartialMatch(
                    id: UUID(),
                    ruleId: ruleId,
                    createdAt: now,
                    matchedSteps: [:],
                    correlationKey: correlationKey,
                    checkpointWeight: 0
                )
                newPartial.matchedSteps[step.id] = matched
                newPartial = Self.weightedPartial(newPartial, rule: rule)

                // Edge case: single-step rule or anySteps(1).
                if isTriggerSatisfied(rule.trigger, matchedStepIds: Set(newPartial.matchedSteps.keys), totalSteps: rule.steps.count) {
                    completedMatches.append(makeMatch(rule: rule, partial: newPartial))
                    // Don't store the partial -- it's already complete.
                } else {
                    appendUniquePartial(newPartial, for: ruleId)
                    evictionQueue.append(PartialMatchRef(
                        ruleId: ruleId,
                        partialId: newPartial.id,
                        createdAt: now
                    ))
                    markCheckpointStateMutation()
                    seededInitial = true
                }
            }

            // --- Phase 3 (#95): out-of-order backfill for ordered rules ---
            // If this event just seeded an initial partial, replay any later
            // steps that arrived early (via the fast priority consumer while the
            // file consumer lagged) so the sequence can still complete. That
            // replay walks every partial, including any Phase 1 advanced.
            // Otherwise, if Phase 1 bound a middle step without completing a
            // partial, replay only the retained steps after that step, against
            // only those partials: a later step processed before the middle one
            // failed its ordering check then, and otherwise only a later seed's
            // full replay revisits it.
            if seededInitial, let buffered = pendingLaterSteps[ruleId], !buffered.isEmpty {
                completedMatches.append(contentsOf: replayPendingSteps(
                    ruleId: ruleId,
                    rule: rule,
                    now: now,
                    relationshipSnapshot: relationshipSnapshot
                ))
            } else if !advancedStepIndexByPartial.isEmpty {
                completedMatches.append(contentsOf: replayPendingStepsAfterAdvance(
                    ruleId: ruleId,
                    rule: rule,
                    advancedStepIndexByPartial: advancedStepIndexByPartial,
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
            // NOT gated on `ruleCanSufferLaneInversion`. Each collector has an
            // independent producer Task and the two final lanes have independent
            // consumers, so neither same-lane nor priority-before-file event-time
            // order is guaranteed. In particular, seven stable process-first
            // rules have later file steps, and their process event may arrive
            // through ES/eslogger/kdebug after a later file event. The bounded
            // history is honest continuity protection for those inversions; its
            // eviction telemetry must stay visible rather than trading overload
            // for silent sequence false negatives.
            if rule.ordered {
                let initialStepId = rule.steps.first?.id
                let foldStepID = pendingFoldStepIDByRule[ruleId]
                for step in matchingSteps where step.id != initialStepId {
                    let matched = eventMatchedStep(step)
                    let foldKey = step.id == foldStepID
                        ? Self.pendingFoldKey(
                            stepID: step.id,
                            matched: matched,
                            identity: event.process.auditIdentity
                        )
                        : nil
                    bufferPendingStep(
                        ruleId: ruleId, step: step, matched: matched, foldKey: foldKey, now: now
                    )
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
            sweepExpiredBeforePressure()
            if totalPartialCount > maxPartialMatches {
                evictOldest(count: totalPartialCount - maxPartialMatches)
            }
        }

        enforceCheckpointStateWeightBudget()

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
    /// Whether the periodic or pre-emptive sweep below is due.
    private func housekeepingDue(now: Date) -> Bool {
        now.timeIntervalSince(lastSweep) >= sweepInterval
            || (totalPartialCount > maxPartialMatches * 8 / 10
                && now.timeIntervalSince(lastPreemptiveSweep) >= Self.preemptiveSweepInterval)
    }

    /// Periodic housekeeping: sweep expired partials and enforce memory cap.
    /// Requires the mutation lease.
    private func runHousekeeping(now: Date) {
        if now.timeIntervalSince(lastSweep) >= sweepInterval {
            sweepExpired(now: now)
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
            sweepExpired(now: now)
            lastSweep = now
            lastPreemptiveSweep = now
        }
    }

    /// The steps of each enabled rule that this event satisfies. Pure over the
    /// event and the installed rules; counts each eligible rule's evaluation
    /// once when asked.
    private func evaluationPlans(
        for event: Event,
        dependencyFilter: HeavyEnrichmentDependencyMask?,
        countEvaluations: Bool
    ) -> [EventEvaluationPlan] {
        let category = mapEventCategoryToLogsource(
            event.eventCategory,
            eventType: event.eventType,
            action: event.eventAction
        )
        let unresolvedMask = HeavyEnrichmentRuleCoverage.unresolvedMask(in: event)

        // Find rule IDs that have at least one step matching this category.
        guard let candidateRuleIds = ruleIndex[category] else {
            return []
        }

        // Resolution and folding are pure functions of this Event value. Keep
        // the memo local to this evaluation (including each enriched replay),
        // and use it only during synchronous predicate planning before lineage
        // awaits. No field cache is stored on the actor or shared between events.
        let fieldMemo = RuleEngine.FieldMemo(event: event)
        var plans: [EventEvaluationPlan] = []
        for ruleId in candidateRuleIds {
            guard let rule = rules[ruleId], rule.enabled else { continue }

            // Preserve rule-step order and STEP-granularity replay eligibility,
            // but materialize only the matching plan, not an intermediate array
            // of eligible steps. A miss allocates no step array, and a replay
            // resolves each relevant step's dependency mask only once.
            let ruleDependencyMasks = heavyDependencyMasks[ruleId]
            var matchingSteps: [SequenceStep] = []
            var countedEvaluation = false
            for step in rule.steps where step.logsourceCategory == category {
                let stepDependencyMask = ruleDependencyMasks?[step.id]
                    ?? HeavyEnrichmentRuleCoverage.dependencyMask(
                        predicates: step.predicates,
                        conditionTree: step.conditionTree
                    )
                if let dependencyFilter,
                   stepDependencyMask.intersection(dependencyFilter).isEmpty { continue }

                // Count an enabled, eligible rule exactly once, even when all
                // eligible steps fail predicates or have unresolved evidence.
                // Unrelated component replay must not count or seed this rule.
                if !countedEvaluation {
                    if countEvaluations {
                        ruleStats[ruleId, default: SequenceRuleStats(ruleId: ruleId)].evaluationCount &+= 1
                    }
                    countedEvaluation = true
                }
                if evaluateStepPredicates(
                    step,
                    against: event,
                    dependencyMask: stepDependencyMask,
                    unresolvedMask: unresolvedMask,
                    memo: fieldMemo
                ) {
                    matchingSteps.append(step)
                }
            }

            guard !matchingSteps.isEmpty else { continue }
            plans.append(EventEvaluationPlan(
                ruleId: ruleId,
                rule: rule,
                matchingSteps: matchingSteps
            ))
        }
        return plans
    }

    private func evaluateStepPredicates(
        _ step: SequenceStep,
        against event: Event,
        dependencyMask: HeavyEnrichmentDependencyMask,
        unresolvedMask: HeavyEnrichmentDependencyMask,
        memo: RuleEngine.FieldMemo
    ) -> Bool {
        let predicates = step.predicates

        // Fail the whole step while any evidence it references is unresolved.
        // This happens before predicate negation and condition-tree `not`.
        guard dependencyMask.intersection(unresolvedMask).isEmpty else { return false }

        if let tree = step.conditionTree {
            // A tree without predicates is malformed. validateRule rejects it,
            // but keep the hot path fail-closed if an invariant ever regresses.
            guard !predicates.isEmpty else { return false }
            return evaluateConditionNode(tree, predicates: predicates, against: event, memo: memo)
        }

        // Preserve the legacy meaning of an intentionally predicate-free flat
        // step. This behavior applies only when no condition_tree is present.
        guard !predicates.isEmpty else { return true }

        switch step.condition {
        case .allOf:
            return predicates.allSatisfy { evaluatePredicate($0, against: event, memo: memo) }
        case .anyOf:
            return predicates.contains { evaluatePredicate($0, against: event, memo: memo) }
        case .oneOfEach:
            let groups = Dictionary(grouping: predicates, by: { $0.field })
            return groups.values.allSatisfy { group in
                group.contains { evaluatePredicate($0, against: event, memo: memo) }
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
        against event: Event,
        memo: RuleEngine.FieldMemo
    ) -> Bool {
        switch node {
        case .and(let operands):
            guard !operands.isEmpty else { return false }
            return operands.allSatisfy {
                evaluateConditionNode($0, predicates: predicates, against: event, memo: memo)
            }
        case .or(let operands):
            guard !operands.isEmpty else { return false }
            return operands.contains {
                evaluateConditionNode($0, predicates: predicates, against: event, memo: memo)
            }
        case .not(let operand):
            return !evaluateConditionNode(operand, predicates: predicates, against: event, memo: memo)
        case .predicate(let index):
            guard index >= 0, index < predicates.count else { return false }
            return evaluatePredicate(predicates[index], against: event, memo: memo)
        case .predicateGroup(let range, let mode):
            guard !range.isEmpty,
                  range.lowerBound >= 0,
                  range.upperBound <= predicates.count else { return false }
            let group = predicates[range]
            switch mode {
            case .allOf:
                return group.allSatisfy { evaluatePredicate($0, against: event, memo: memo) }
            case .anyOf:
                return group.contains { evaluatePredicate($0, against: event, memo: memo) }
            case .oneOfEach:
                let groups = Dictionary(grouping: group, by: { $0.field })
                return groups.values.allSatisfy { predicates in
                    predicates.contains { evaluatePredicate($0, against: event, memo: memo) }
                }
            }
        }
    }

    /// Evaluate a single predicate against an event.
    ///
    /// Uses RuleEngine's value-bound memo, not another actor call. Exact field
    /// names remain distinct keys; absent and empty fields retain their meaning.
    private func evaluatePredicate(
        _ predicate: Predicate, against event: Event, memo: RuleEngine.FieldMemo
    ) -> Bool {
        let rawResult: Bool

        if predicate.modifier == .exists {
            let fieldValue = memo.value(for: predicate.field)
            rawResult = fieldValue?.isEmpty == false
        } else {
            guard let fieldValue = memo.value(for: predicate.field) else {
                let rawMiss = false
                return predicate.negate ? !rawMiss : rawMiss
            }
            rawResult = evaluateModifier(
                predicate.modifier,
                fieldValue: fieldValue,
                field: predicate.field,
                values: predicate.values,
                lowercasedValues: predicate.lowercasedValues,
                memo: memo
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
        field: String,
        values: [String],
        lowercasedValues: [String],
        memo: RuleEngine.FieldMemo
    ) -> Bool {
        // Regex, numeric and presence checks consume the original value. Only
        // the four case-insensitive string modifiers need a folded copy; reuse
        // that exact Swift lowercasing once per field, as RuleEngine does.
        let needsLower: Bool
        switch modifier {
        case .equals, .contains, .startswith, .endswith: needsLower = true
        default: needsLower = false
        }
        let fieldLower = needsLower
            ? (memo.lowercasedValue(for: field) ?? fieldValue.lowercased()) : ""

        switch modifier {
        case .equals:
            return lowercasedValues.contains { fieldLower == $0 }
        case .contains:
            return ExactSubstringSearch.containsAny(fieldLower, lowercasedValues)
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
        eventType: EventType,
        action: String
    ) -> String {
        switch category {
        case .process:
            switch eventType {
            case .creation, .start:
                // A fork is not a process creation in the Sigma sense: the
                // child still runs its parent's image with an empty command
                // line, so image-only rules fired again on every fork and a
                // shell-step sequence seed matched every forked shell. No
                // rule selects forks; lineage reads them outside the engines.
                return action == "fork" ? "process_fork" : "process_creation"
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
        matched: MatchedStep
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
            // Every partial still receives its own UUID. No additional random
            // String is needed for a mode whose correlation check always passes.
            return nil
        }
    }

    /// Whether the live advance or a possible Phase-3 replay can issue an
    /// ancestry query. Keeping this precise avoids even the single batch actor
    /// hop for predicate matches whose relations are PID-local (`same`/`any`).
    private func planNeedsLineageSnapshot(_ plan: EventEvaluationPlan) -> Bool {
        // Any matched event in a lineage-dependent rule may become a durable
        // seed or pending candidate. Capture the authoritative snapshot proof
        // now even when no relation is evaluated on this call; it cannot be
        // reconstructed after ProcessLineage restarts.
        // These definition-level cases exhaust every relationship operation
        // that consults ProcessLineage. For all remaining rules, inspecting
        // every stored partial/pending step cannot change the answer; that
        // redundant scan formerly ran even for first-step-only seed traffic.
        return plan.rule.correlationType == .processLineage
            || plan.rule.steps.contains(where: {
                guard let relation = $0.processRelation?.relation else { return false }
                switch relation {
                case .descendant, .ancestor, .sibling, .sameTree:
                    return true
                case .same, .sameProcess, .any:
                    return false
                }
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
    /// and list mutation. `matched.timestamp`/`processPid` stand in for the
    /// former `event.timestamp`/`process.pid`, which are identical because
    /// `MatchedStep` is built from that same event.
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
                event: matched,
                reference: refStep,
                relationshipSnapshot: relationshipSnapshot
            )
            guard relationHolds else { return nil }
        }

        var updated = partial
        updated.matchedSteps[step.id] = matched
        return Self.weightedPartial(updated, rule: rule)
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

    /// Whether the declared step categories expose the intentional slow-file /
    /// fast-priority inversion shape.
    ///
    /// The pipeline split makes this one obvious inversion: a later step on the
    /// fast lane can reach `evaluate` before its step[0] on the slow one. This
    /// classifier is useful for inventory/diagnostics, but it is deliberately
    /// not a scheduling proof: independent collector producer Tasks can reorder
    /// event time within one lane, and the two lane consumers can run in either
    /// order.
    ///
    /// Do not gate pending-step parking on this value without first carrying a
    /// source/order proof through `EventPipelineEnvelope` into this actor.
    static func ruleCanSufferLaneInversion(_ rule: SequenceRule) -> Bool {
        guard let initial = rule.steps.first else { return false }
        // A slow-lane step[0] is the declared split's obvious overtaken case.
        guard stepRidesFileLane(initial) else { return false }
        // ...and only by a later step on the FAST lane.
        return rule.steps.dropFirst().contains { !stepRidesFileLane($0) }
    }

    /// Whether a step MIGHT be delivered on the slow file lane.
    ///
    /// Deliberately conservative: a step's file action lives inside its
    /// predicates rather than on the step, and `EventPipelineLane` sends only
    /// SOME file actions down the slow lane (`open` and `btm_add` ride the
    /// priority lane). Rather than decode predicates to recover the action set —
    /// fragile, and wrong in the dangerous direction if it under-approximates —
    /// treat every `file_event` step as possibly-slow.
    ///
    /// This deliberately describes category potential only. It says nothing
    /// about cross-producer arrival order and must not control correctness.
    static func stepRidesFileLane(_ step: SequenceStep) -> Bool {
        step.logsourceCategory == "file_event"
    }

    /// Retain an ordered rule's recent later step for delayed initial events (the
    /// A2 cross-consumer race — see `pendingLaterSteps`). At capacity the largest
    /// bucket's oldest entry is shed, after expiry and folding; deduped by
    /// (eventId, stepId) so the same event cannot occupy the history twice
    /// across re-evaluations.
    private func bufferPendingStep(
        ruleId: String,
        step: SequenceStep,
        matched: MatchedStep,
        foldKey: PendingFoldKey?,
        now: Date
    ) {
        if pendingLaterSteps[ruleId]?.contains(where: {
            $0.matched.eventId == matched.eventId && $0.step.id == step.id
        }) == true {
            return
        }
        guard let rule = rules[ruleId] else { return }
        var pending = PendingStep(
            step: step,
            matched: matched,
            arrivedAt: now,
            checkpointWeight: 0,
            foldKey: foldKey
        )
        pending = Self.weightedPending(pending, ruleId: ruleId, rule: rule)
        pendingEvictionQueue.append(PendingStepRef(
            identity: pendingIdentity(ruleId: ruleId, pending: pending)
        ))
        // Account admission before retirement so an expired item is completed,
        // and a genuinely displaced live item is shed, in separate mutations.
        appendUniquePendingStep(pending, for: ruleId)
        relievePendingPressure(admittingRuleID: ruleId)
        // The per-admission lazy compaction that bounds stale references.
        compactPendingEvictionQueue()
        markCheckpointStateMutation()
    }

    /// Count-limit relief after one unique admission. Synchronous (no await);
    /// runs inside the evaluation that holds the mutation lease.
    ///  1. Retire expired history (compare-only sweep) as completed.
    ///  2. While a count limit is exceeded, pick the victim bucket: the admitting
    ///     rule if it alone exceeds the per-rule cap, else the largest bucket.
    ///     Max-min fair: the largest bucket pays. A flooding rule pays with its
    ///     own history once its bucket is the largest; until then each of its
    ///     over-cap admissions trims the largest bucket toward an equal share.
    ///  3. Before any shed, give each fold-eligible bucket holding at least
    ///     two entries at most one throttled fold attempt per call
    ///     (foldPendingBucketIfDue; fold removals are completed): the victim,
    ///     then the admitting rule, then every other one through
    ///     foldOtherPendingBucket, most entries first and then the smaller
    ///     rule ID, stopping at the first attempt that removes entries.
    ///     Within a call that order is fixed, so Dictionary order cannot
    ///     decide it, and, throttle permitting, duplicates in any bucket are
    ///     folded before a live entry is shed. Across one event's rule plans,
    ///     which run in the hashed Set order of ruleIndex, an earlier plan's
    ///     relief can fold and throttle a bucket before this event's own
    ///     entry reaches it, so whether the event sheds (within the accepted
    ///     residual of up to 255 sheds after a low-yield attempt) and which
    ///     bucket folds can still depend on plan order.
    ///  4. Otherwise shed the victim's front (oldest admission) as
    ///     explicitly_shed. One pressure record per call; the first live
    ///     victim is the representative.
    /// Each call follows a single append, so it sheds at most one live entry.
    /// Work per over-cap admission besides fold attempts: the admission's
    /// dedupe scan of its own bucket, the compare-only sweep over all retained
    /// state, the shift of the victim bucket, and foldOtherPendingBucket's
    /// pass over the rule buckets (a throttle lookup for each bucket holding
    /// at least two entries, an eligibility lookup for each that is not
    /// blocked, then a sort of the due fold-eligible ones). A fold attempt
    /// reads its bucket, twice when it merges, and hashes each keyed entry
    /// once. One call can attempt every due fold-eligible bucket, as when
    /// their throttles lapse together, but each attempt either removes at
    /// least 256 entries, which earlier admissions added, or blocks its rule
    /// for the next 256 admissions, so fold work averages O(capacity / 256)
    /// entry reads per admission.
    private func relievePendingPressure(admittingRuleID: String) {
        func overLimit() -> Bool {
            totalPendingStepCount > Self.maxPendingTotal
                || (pendingLaterSteps[admittingRuleID]?.count ?? 0) > Self.maxPendingPerRule
        }
        guard overLimit() else { return }
        sweepExpiredBeforePressure()
        var foldTried = Set<String>()
        var pressureBefore: PendingPressureSnapshot?
        var shed = 0
        while overLimit() {
            let victim: String
            if (pendingLaterSteps[admittingRuleID]?.count ?? 0) > Self.maxPendingPerRule {
                victim = admittingRuleID
            } else if let largest = largestPendingBucketRuleID(weights: nil) {
                victim = largest
            } else {
                break
            }
            if foldTried.insert(victim).inserted, foldPendingBucketIfDue(ruleId: victim) > 0 {
                continue
            }
            if victim != admittingRuleID, foldTried.insert(admittingRuleID).inserted,
               foldPendingBucketIfDue(ruleId: admittingRuleID) > 0 {
                continue
            }
            if foldOtherPendingBucket(tried: &foldTried) != nil { continue }
            guard let front = pendingLaterSteps[victim]?.first else { break }
            if pressureBefore == nil {
                let victimCount = pendingLaterSteps[victim]?.count ?? 0
                pressureBefore = pendingPressureSnapshot(
                    reason: victimCount > Self.maxPendingPerRule ? .perRuleCount : .globalCount,
                    pendingCount: totalPendingStepCount, ruleID: victim, stepID: front.step.id
                )
            }
            removePendingFront(ruleId: victim, count: 1, disposition: .explicitlyShed)
            shed += 1
        }
        if let pressureBefore { recordPendingEvictions(shed, before: pressureBefore) }
    }

    /// Victim order at a capacity limit: more semantic weight (weight pressure
    /// only), then more entries, then the older front, then the smaller rule
    /// ID. A total order, so the choice never depends on Dictionary iteration
    /// order and a restored engine picks the same victim from the same buckets.
    private struct BucketVictimRank {
        let weight: Int
        let count: Int
        let front: Date
        let ruleId: String

        func ranksAhead(of other: BucketVictimRank) -> Bool {
            if weight != other.weight { return weight > other.weight }
            if count != other.count { return count > other.count }
            if front != other.front { return front < other.front }
            return ruleId < other.ruleId
        }
    }

    /// Max-min fair pending victim bucket, O(#rules). With `weights` (weight
    /// pressure) the most semantic weight ranks first; otherwise the most
    /// entries. Reads only; never mutates.
    private func largestPendingBucketRuleID(weights: [String: Int]?) -> String? {
        var best: BucketVictimRank?
        for (ruleId, bucket) in pendingLaterSteps {
            guard let front = bucket.first else { continue }
            let rank = BucketVictimRank(
                weight: weights?[ruleId] ?? 0, count: bucket.count,
                front: front.arrivedAt, ruleId: ruleId
            )
            if best.map({ rank.ranksAhead(of: $0) }) ?? true { best = rank }
        }
        return best?.ruleId
    }

    /// The partial-pool counterpart of largestPendingBucketRuleID; the front's
    /// age is its createdAt.
    private func largestPartialBucketRuleID(weights: [String: Int]?) -> String? {
        var best: BucketVictimRank?
        for (ruleId, bucket) in partialMatches {
            guard let front = bucket.first else { continue }
            let rank = BucketVictimRank(
                weight: weights?[ruleId] ?? 0, count: bucket.count,
                front: front.createdAt, ruleId: ruleId
            )
            if best.map({ rank.ranksAhead(of: $0) }) ?? true { best = rank }
        }
        return best?.ruleId
    }

    // MARK: - At-capacity same-writer fold (v1.22.6)
    //
    // Scope. Only inside pressure relief, after expired history is retired and
    // before any live entry would be shed: the point where earlier releases
    // discarded live history outright. Only the step pendingFoldStepID(for:)
    // names (S1 = steps[1]: `.descendant` of steps[0], the only step of its
    // logsource category, correlation processLineage or none, and no later
    // step relating to S1 or relying on lineage correlation without its own
    // relation). Only entries with equal fold keys: the ES audit identity
    // (pid, pidversion) plus identical processParentPid,
    // processParentWasTracked and processAncestorPids. Restored entries carry
    // no key and never fold.
    //
    // Dominance. For a partial whose only binding is steps[0] at event time t0
    // by process p0, advancePartial accepts an S1 entry E iff (a) E's process
    // is a descendant of p0, decided by the lineage snapshot for E's pid and by
    // E's recorded parent and ancestry, all identical within a key group; and
    // (b) E.timestamp >= t0 (checkOrdering; an afterStep can name only
    // steps[0]). The correlation check is skipped (processLineage with a step
    // relation) or always passes (none), and the one-event-one-step guard never
    // rejects E because no other step shares S1's category. So the group's
    // representative R, its earliest event (earliest arrival on a tie), is
    // accepted whenever any member is, unless t(R) < t0 <= t(member).
    // replayPendingSteps binds, per partial, the earliest-timestamp entry that
    // passes; the folded history is a subset of the unfolded one in which every
    // removed member is represented by an earlier member of its group, so a
    // replay binds the same entry, or R where R's own arrival had already aged
    // out of the unfolded history. Binding R after its own arrival aged out
    // can add a completion the unfolded history would miss (its remaining
    // members bind later times), and every such completion is a valid
    // event-time chain. R takes the group's latest arrival, so a group is
    // retained exactly as long as its newest member would have been.
    // Binding R instead of a later member keeps the pid and relation evidence
    // and lowers the bound time, so later ordering and afterStep checks are at
    // least as permissive; eligibility keeps later steps independent of which
    // writer binds S1, so an exact event-time tie between two writers can
    // change only which equally timed entry is cited. Live Phase-1 advancement
    // reads no pending history, and the replay on advance it triggers reads
    // only steps after the newly bound one (index >= 2), so neither reads
    // folded index-1 history.
    //
    // Residual (owner-accepted 2026-11-03, SEQ Q1). A writer acts only after it
    // exists, so a seed exec'd before the writer was born has t0 <= t(R). The
    // one loss is an ancestor that execs the seed image after the writer's
    // first matching write, with that seed evaluated only after the writer's
    // later writes were folded: R fails (b) where a folded later write would
    // have passed. npm/pnpm lifecycle scripts cannot produce it, because their
    // first shell is itself the seed and exists before any descendant writes.

    /// Merge every group of entries with equal fold keys into its
    /// representative: the member with the earliest event time (the earliest
    /// arrival on a tie), re-weighted and placed at the group's last index
    /// with the group's latest arrival, so an arrival-ordered bucket stays
    /// arrival-ordered. Unkeyed entries and single-entry groups keep their
    /// place. Removals are completed through the audited setter. A pass that
    /// finds nothing to merge returns without touching the bucket, so it costs
    /// one read and one key hash per keyed entry and no identity rebuild.
    private func foldPendingBucket(ruleId: String, rule: SequenceRule) -> (removed: Int, groups: Int) {
        guard let bucket = pendingLaterSteps[ruleId], bucket.count > 1 else { return (0, 0) }
        var groupIndexByKey: [PendingFoldKey: Int] = [:]
        var groups: [PendingFoldGroup] = []
        // Each entry's group, so the rebuild below hashes no key a second time.
        var groupOfEntry = [Int](repeating: -1, count: bucket.count)
        for (index, entry) in bucket.enumerated() {
            guard let key = entry.foldKey else { continue }
            guard let existing = groupIndexByKey[key] else {
                groupIndexByKey[key] = groups.count
                groupOfEntry[index] = groups.count
                groups.append(PendingFoldGroup(
                    size: 1, representative: index, last: index, latestArrival: entry.arrivedAt
                ))
                continue
            }
            groupOfEntry[index] = existing
            groups[existing].size += 1
            groups[existing].last = index
            groups[existing].latestArrival = max(groups[existing].latestArrival, entry.arrivedAt)
            // Strictly earlier only: an equal event time keeps the earlier arrival.
            if entry.matched.timestamp < bucket[groups[existing].representative].matched.timestamp {
                groups[existing].representative = index
            }
        }
        Self.addSaturating(UInt64(bucket.count), to: &pendingCapacityElementVisitCount)
        let mergedGroups = groups.reduce(0) { $0 + ($1.size > 1 ? 1 : 0) }
        guard mergedGroups > 0 else { return (0, 0) }

        var folded: [PendingStep] = []
        folded.reserveCapacity(bucket.count)
        for (index, entry) in bucket.enumerated() {
            let groupIndex = groupOfEntry[index]
            guard groupIndex >= 0, groups[groupIndex].size > 1 else {
                folded.append(entry)
                continue
            }
            let group = groups[groupIndex]
            guard index == group.last else { continue }
            let representative = bucket[group.representative]
            folded.append(Self.weightedPending(
                PendingStep(
                    step: representative.step,
                    matched: representative.matched,
                    arrivedAt: group.latestArrival,
                    checkpointWeight: 0,
                    foldKey: representative.foldKey
                ),
                ruleId: ruleId,
                rule: rule
            ))
        }
        Self.addSaturating(UInt64(bucket.count), to: &pendingCapacityElementVisitCount)
        setPendingBucket(folded, for: ruleId, removedDisposition: .completed)
        return (bucket.count - folded.count, mergedGroups)
    }

    /// One fold-key group during a fold pass: member count, representative
    /// and last member indices, and the latest member arrival.
    private struct PendingFoldGroup {
        var size: Int
        var representative: Int
        var last: Int
        var latestArrival: Date
    }

    /// One throttled fold attempt; returns entries removed. Called only from
    /// relievePendingPressure and enforceCheckpointStateWeightBudget, directly
    /// or through foldOtherPendingBucket, after their expiry sweep and before
    /// any shed. A blocked rule, a rule that is not fold-eligible and a bucket
    /// holding fewer than two entries (nothing to merge) return 0 without
    /// counting an attempt or touching the throttle; the throttle is read
    /// first, so a blocked rule costs one lookup. An attempt that removes
    /// fewer than pendingFoldRetryAdmissions entries blocks the rule's next
    /// attempt for that many unique admissions.
    private func foldPendingBucketIfDue(ruleId: String) -> Int {
        if let until = pendingFoldBlockedUntilSerial[ruleId], pendingAdmissionSerial < until { return 0 }
        guard let stepID = pendingFoldStepIDByRule[ruleId],
              (pendingLaterSteps[ruleId]?.count ?? 0) >= 2,
              let rule = rules[ruleId] else { return 0 }
        Self.incrementSaturating(&pendingFoldAttemptsTotal)
        let (removed, groups) = foldPendingBucket(ruleId: ruleId, rule: rule)
        if UInt64(removed) < Self.pendingFoldRetryAdmissions {
            pendingFoldBlockedUntilSerial[ruleId] = pendingAdmissionSerial &+ Self.pendingFoldRetryAdmissions
        } else {
            pendingFoldBlockedUntilSerial.removeValue(forKey: ruleId)
        }
        if removed > 0 {
            Self.addSaturating(UInt64(removed), to: &pendingFoldedStepsTotal)
            lastPendingFold = PendingFoldSnapshot(
                observedAt: Date(), ruleID: ruleId, stepID: stepID,
                removedPendingSteps: UInt64(removed), foldedGroups: groups
            )
            markCheckpointStateMutation()
        }
        return removed
    }

    /// The last fold step before a relief path sheds live history: one
    /// throttled attempt on each fold-eligible bucket that holds at least two
    /// entries, is not blocked and is not yet in `tried`, most entries first
    /// and then the smaller rule ID. Each bucket it tries joins `tried`.
    /// Stops at the first attempt that removes entries and returns that rule.
    /// The order is total, so Dictionary order cannot decide which bucket a
    /// call folds or whether the call sheds. The order of one event's rule
    /// plans still can: an earlier plan's relief may fold and throttle a
    /// bucket before this event's own entry reaches it (relievePendingPressure,
    /// step 3).
    private func foldOtherPendingBucket(tried: inout Set<String>) -> String? {
        var candidates: [(ruleId: String, count: Int)] = []
        for (ruleId, bucket) in pendingLaterSteps where bucket.count >= 2 {
            // The throttle first: a blocked rule costs one lookup. It stays
            // blocked for the whole call, since the serial advances only on
            // admission.
            if let until = pendingFoldBlockedUntilSerial[ruleId], pendingAdmissionSerial < until { continue }
            guard !tried.contains(ruleId), pendingFoldStepIDByRule[ruleId] != nil else { continue }
            candidates.append((ruleId, bucket.count))
        }
        candidates.sort { $0.count != $1.count ? $0.count > $1.count : $0.ruleId < $1.ruleId }
        for candidate in candidates {
            tried.insert(candidate.ruleId)
            if foldPendingBucketIfDue(ruleId: candidate.ruleId) > 0 { return candidate.ruleId }
        }
        return nil
    }

    /// The single later step whose same-writer duplicates may be folded at
    /// capacity, or nil. Shape half of the fold eligibility; the event half is
    /// the ES audit identity (pendingFoldKey). Pure over the rule definition.
    /// The single definition of the shape half: the engine reads it through
    /// pendingFoldStepIDByRule, which installRule and reloadRules fill from it.
    static func pendingFoldStepID(for rule: SequenceRule) -> String? {
        guard rule.ordered, rule.steps.count >= 2,
              rule.correlationType == .processLineage || rule.correlationType == .none else { return nil }
        let seed = rule.steps[0]
        let folded = rule.steps[1]
        guard folded.processRelation == ProcessRelationSpec(relation: .descendant, relativeToStep: seed.id),
              rule.steps.lazy.filter({ $0.logsourceCategory == folded.logsourceCategory }).count == 1
        else { return nil }
        // Later steps must never depend on WHICH entry bound the folded step.
        for later in rule.steps.dropFirst(2) {
            if let relation = later.processRelation {
                guard relation.relativeToStep == seed.id else { return nil }
            } else if rule.correlationType == .processLineage {
                return nil
            }
        }
        return folded.id
    }

    /// The event half of the fold eligibility: an ES audit identity for the
    /// matched process itself. Without one, pid reuse could merge two
    /// different writers, so the entry is never folded.
    static func pendingFoldKey(
        stepID: String,
        matched: MatchedStep,
        identity: AuditIdentity?
    ) -> PendingFoldKey? {
        guard let identity, identity.pid == matched.processPid else { return nil }
        return PendingFoldKey(
            stepID: stepID,
            pid: matched.processPid,
            pidVersion: identity.pidversion,
            parentPid: matched.processParentPid,
            parentWasTracked: matched.processParentWasTracked,
            ancestorPids: matched.processAncestorPids
        )
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
    /// `advancePartial` as the live path. A live advance that completes nothing
    /// runs the narrower replayPendingStepsAfterAdvance instead.
    private func replayPendingSteps(
        ruleId: String,
        rule: SequenceRule,
        now: Date,
        relationshipSnapshot: ProcessLineage.RelationshipSnapshot?
    ) -> [RuleMatch] {
        guard var pending = pendingLaterSteps[ruleId], !pending.isEmpty else { return [] }
        let originalPending = pending
        let originalPartials = partialMatches[ruleId] ?? []

        // Drop buffered steps older than the rule window.
        pending.removeAll { now.timeIntervalSince($0.arrivedAt) > rule.window }
        guard !pending.isEmpty else {
            setPendingBucket([], for: ruleId)
            if !originalPending.isEmpty {
                compactPendingEvictionQueue(force: true)
                markCheckpointStateMutation()
            }
            return []
        }

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

        setPartialBucket(partials, for: ruleId)
        setPendingBucket(pending, for: ruleId)
        if partials != originalPartials || pending != originalPending {
            if pending != originalPending {
                compactPendingEvictionQueue(force: true)
            }
            markCheckpointStateMutation()
        }
        return matches
    }

    /// Replay on advance. Phase 1 just bound step k of each partial in
    /// `advancedStepIndexByPartial` without completing it. A later step that
    /// was processed before that bind failed checkOrdering then (step k was
    /// missing), and replayPendingSteps runs only when a step[0] seeds, so the
    /// partial would otherwise wait for another live later step or a new seed.
    /// Replays only retained entries for steps after k, only against those
    /// partials, earliest event time first (then rule-step order, then bucket
    /// position), through the shared advancePartial: each step binds its
    /// earliest passing entry and one entry fans out to every target, as in
    /// replayPendingSteps. Read-only on pending history: nothing is consumed,
    /// pruned or rewritten, so the journal and the pending weight do not move;
    /// an entry past its window is skipped and left for the sweep to retire.
    /// Synchronous: no await, so the lease keeps read-advance-replace atomic.
    ///
    /// Bound. For the partials this event advanced, the completions here are
    /// exactly those live Phase 1 would produce if each retained later event
    /// still inside its window were delivered again right after this middle
    /// event, in event-time order, with the evidence recorded at its own
    /// evaluation and under the same processing-time windows. Every other
    /// partial has already been tried against them: live when they arrived,
    /// by its seed's full replay, or by an earlier replay on advance.
    /// Those windows run on processing time (partial createdAt, entry
    /// arrivedAt), so a seed evaluated L seconds late stretches the event-time
    /// span a chain may cover by L, as it already does for a live completion
    /// after a lagged seed. Residuals: a later-timed middle event processed
    /// first binds and is never rebound, so a later step timed between the two
    /// middles cannot complete; and relations are decided from each entry's
    /// recorded parent and ancestry (a non-seed requests no pending PIDs), so
    /// lineage learned after an entry was evaluated is used only by a later
    /// seed's full replay.
    ///
    /// For an ordered rule a second pass binds nothing. An entry that failed
    /// either found its preceding step unbound, and any entry binding that
    /// step later in the pass sorts after it at a strictly later time (equal
    /// times sort the earlier step first), so checkOrdering keeps rejecting
    /// it; or it failed against a bound prefix, relation evidence and snapshot
    /// that nothing in this call changes. The loop only confirms that, within
    /// a bounded number of passes.
    private func replayPendingStepsAfterAdvance(
        ruleId: String,
        rule: SequenceRule,
        advancedStepIndexByPartial: [UUID: Int],
        now: Date,
        relationshipSnapshot: ProcessLineage.RelationshipSnapshot?
    ) -> [RuleMatch] {
        // Binding the last step needs no scan: no step follows it.
        guard rule.ordered,
              let lowestBound = advancedStepIndexByPartial.values.min(),
              lowestBound + 1 < rule.steps.count,
              let pending = pendingLaterSteps[ruleId], !pending.isEmpty else { return [] }
        Self.incrementSaturating(&advanceReplayScansTotal)
        let stepOrder = Dictionary(uniqueKeysWithValues: rule.steps.enumerated().map {
            ($0.element.id, $0.offset)
        })
        // The same window test as the full replay and the sweep.
        let candidates = pending.indices.filter { index in
            guard let order = stepOrder[pending[index].step.id], order > lowestBound else { return false }
            return now.timeIntervalSince(pending[index].arrivedAt) <= rule.window
        }.sorted { lhsIndex, rhsIndex in
            let lhs = pending[lhsIndex]
            let rhs = pending[rhsIndex]
            if lhs.matched.timestamp != rhs.matched.timestamp {
                return lhs.matched.timestamp < rhs.matched.timestamp
            }
            let lhsOrder = stepOrder[lhs.step.id] ?? Int.max
            let rhsOrder = stepOrder[rhs.step.id] ?? Int.max
            if lhsOrder != rhsOrder { return lhsOrder < rhsOrder }
            return lhsIndex < rhsIndex
        }
        guard !candidates.isEmpty else { return [] }
        Self.addSaturating(UInt64(candidates.count), to: &advanceReplayCandidatesTotal)
        var partials = partialMatches[ruleId] ?? []
        let targets = partials.indices.filter { advancedStepIndexByPartial[partials[$0].id] != nil }
        guard !targets.isEmpty else { return [] }

        var completed = Set<Int>()
        var matches: [RuleMatch] = []
        var bindings: UInt64 = 0
        var passes = 0
        var progressed = true
        while progressed, passes < rule.steps.count, completed.count < targets.count {
            progressed = false
            passes += 1
            for candidate in candidates {
                let entry = pending[candidate]
                guard let order = stepOrder[entry.step.id] else { continue }
                for target in targets where !completed.contains(target) {
                    let partial = partials[target]
                    guard let bound = advancedStepIndexByPartial[partial.id], order > bound,
                          now.timeIntervalSince(partial.createdAt) <= rule.window,
                          let updated = advancePartial(
                              rule: rule,
                              step: entry.step,
                              matched: entry.matched,
                              partial: partial,
                              relationshipSnapshot: relationshipSnapshot
                          ) else { continue }
                    progressed = true
                    bindings += 1
                    if isTriggerSatisfied(rule.trigger, matchedStepIds: Set(updated.matchedSteps.keys), totalSteps: rule.steps.count) {
                        matches.append(makeMatch(rule: rule, partial: updated))
                        completed.insert(target)
                    } else {
                        partials[target] = updated
                    }
                }
            }
        }
        guard bindings > 0 else { return [] }
        if !completed.isEmpty {
            partials = partials.enumerated().compactMap {
                completed.contains($0.offset) ? nil : $0.element
            }
        }
        // The only mutation. Completed partials leave stale eviction
        // references for the amortized compaction, as Phase-1 completions do.
        setPartialBucket(partials, for: ruleId)
        markCheckpointStateMutation()
        Self.addSaturating(bindings, to: &advanceReplayBindingsTotal)
        Self.addSaturating(UInt64(matches.count), to: &advanceReplayCompletionsTotal)
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
            guard let key = partial.correlationKey else { return false }
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
                if relationshipSnapshot?.isDescendant(candidate.processPid, of: bound.processPid) == true
                    || candidate.hasAncestor(bound.processPid) {
                    return true
                }
                if relationshipSnapshot?.isDescendant(bound.processPid, of: candidate.processPid) == true
                    || bound.hasAncestor(candidate.processPid) {
                    return true
                }
            }
            return false

        case .filePath:
            guard let key = partial.correlationKey else { return false }
            return candidate.filePath == key

        case .networkEndpoint:
            guard let key = partial.correlationKey else { return false }
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

    /// Check whether a process relationship holds between two matched steps.
    /// The live ProcessLineage snapshot is preferred; bounded event-time
    /// ancestry carried by each match preserves the same relationship after an
    /// engine restart when that process-local DAG begins empty.
    ///
    /// - Parameters:
    ///   - relation: The required relationship.
    ///   - event: Current candidate step.
    ///   - reference: Already-bound reference step.
    /// - Returns: `true` if the relationship holds.
    private func checkProcessRelation(
        _ relation: ProcessRelation,
        event: MatchedStep,
        reference: MatchedStep,
        relationshipSnapshot: ProcessLineage.RelationshipSnapshot?
    ) -> Bool {
        let eventPid = event.processPid
        let referencePid = reference.processPid
        switch relation {
        case .same:
            return eventPid == referencePid

        case .descendant:
            // Event process is a child/grandchild of the reference process.
            return relationshipSnapshot?.isDescendant(eventPid, of: referencePid) == true
                || event.hasAncestor(referencePid)

        case .ancestor:
            // Event process is a parent/grandparent of the reference process.
            return relationshipSnapshot?.isDescendant(referencePid, of: eventPid) == true
                || reference.hasAncestor(eventPid)

        case .sibling:
            // Event process and reference process share a direct parent.
            return relationshipSnapshot?.areSiblings(eventPid, referencePid) == true
                || (event.processParentWasTracked
                    && reference.processParentWasTracked
                    && event.processParentPid > 0
                    && event.processParentPid == reference.processParentPid)

        case .sameProcess:
            // Identical to .same (exact PID); separate token used by authors.
            return eventPid == referencePid

        case .sameTree:
            // Same process, or anywhere in its ancestry/descendants.
            if eventPid == referencePid { return true }
            if relationshipSnapshot?.isDescendant(eventPid, of: referencePid) == true
                || event.hasAncestor(referencePid) {
                return true
            }
            return relationshipSnapshot?.isDescendant(referencePid, of: eventPid) == true
                || reference.hasAncestor(eventPid)

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
    private func sweepExpired(now: Date = Date()) {
        var checkpointStateChanged = false

        for (ruleId, partials) in Array(partialMatches) {
            guard let rule = rules[ruleId] else {
                // Rule was removed; discard all its partials.
                setPartialBucket([], for: ruleId)
                checkpointStateChanged = true
                continue
            }

            let surviving = partials.filter { now.timeIntervalSince($0.createdAt) <= rule.window }
            // Filtering preserves exact records/order. Equal counts therefore
            // prove a no-op without deep equality over every matched step, and
            // avoid re-summing/replacing an unchanged bucket during pressure.
            if surviving.count != partials.count {
                checkpointStateChanged = true
                setPartialBucket(surviving, for: ruleId)
            }
        }

        // #95: prune the out-of-order backfill buffer on the same cadence — a
        // buffered later step older than its rule's window can never combine
        // with a future initial step, so drop it (and any buffer whose rule was
        // removed) to keep the buffer from accreting under sustained load.
        for (ruleId, buffered) in Array(pendingLaterSteps) {
            guard let rule = rules[ruleId] else {
                setPendingBucket([], for: ruleId)
                checkpointStateChanged = true
                continue
            }
            let surviving = buffered.filter { now.timeIntervalSince($0.arrivedAt) <= rule.window }
            if surviving.count != buffered.count {
                checkpointStateChanged = true
                setPendingBucket(surviving, for: ruleId)
            }
        }

        // Rebuild from exact live IDs. Age-only front trimming retained every
        // completed ref until the corpus's largest window elapsed, allowing the
        // auxiliary queue to scale with seed throughput rather than live state.
        compactEvictionQueue(force: true)
        compactPendingEvictionQueue(force: true)
        if checkpointStateChanged { markCheckpointStateMutation() }
    }

    /// Retire already-expired state at an actual count/weight boundary, before
    /// any live state can be shed. Compare-only: an unexpired bucket is not
    /// copied, re-summed or hashed, and neither global queue is compacted here
    /// (stale references stay bounded by the lazy compaction and are removed
    /// exactly at capture). The comparison itself still scans all retained
    /// state once per boundary. No await; no cap enforcement inside.
    private func sweepExpiredBeforePressure() {
        let cutoff = Date()
        var changed = false
        var visited = 0
        for ruleId in Array(partialMatches.keys) {
            guard let rule = rules[ruleId] else {
                setPartialBucket([], for: ruleId)
                changed = true
                continue
            }
            let isExpired: (PartialMatch) -> Bool = {
                cutoff.timeIntervalSince($0.createdAt) > rule.window
            }
            visited += partialMatches[ruleId]?.count ?? 0
            guard partialMatches[ruleId]?.contains(where: isExpired) == true else { continue }
            setPartialBucket(partialMatches[ruleId]?.filter { !isExpired($0) } ?? [], for: ruleId)
            changed = true
        }
        for ruleId in Array(pendingLaterSteps.keys) {
            guard let rule = rules[ruleId] else {
                setPendingBucket([], for: ruleId)
                changed = true
                continue
            }
            let isExpired: (PendingStep) -> Bool = {
                cutoff.timeIntervalSince($0.arrivedAt) > rule.window
            }
            var prefix = 0
            var expired = 0
            // Scoped read: the bucket reference ends before any removal below.
            if let bucket = pendingLaterSteps[ruleId] {
                visited += bucket.count
                prefix = bucket.prefix(while: isExpired).count
                expired = prefix + bucket[prefix...].lazy.filter(isExpired).count
            }
            guard expired > 0 else { continue }
            if expired == prefix {
                // Arrival-ordered bucket: the expired entries are its front.
                removePendingFront(ruleId: ruleId, count: prefix, disposition: .completed)
            } else {
                // Arrival order regressed (a wall-clock step or a crafted restore).
                setPendingBucket(pendingLaterSteps[ruleId]?.filter { !isExpired($0) } ?? [], for: ruleId)
            }
            changed = true
        }
        Self.addSaturating(UInt64(visited), to: &pendingCapacityElementVisitCount)
        lastSweep = cutoff
        if changed { markCheckpointStateMutation() }
    }

    /// Evict partial matches to bring the total back under the cap. Each
    /// victim is the front (oldest seed) of the largest partial bucket; ties
    /// break by older front, then the smaller rule ID. The global
    /// evictionQueue is not consulted. Each removal copies the victim bucket
    /// once, as the earlier remove(at:) on a bucket copy did.
    private func evictOldest(count: Int) {
        guard count > 0 else { return }

        let pressureObservedAt = Date()
        let partialCountBefore = totalPartialCount
        let pendingCountBefore = totalPendingStepCount
        let stateWeightBefore = checkpointStateWeight
        var removed = 0
        while removed < count,
              let victim = largestPartialBucketRuleID(weights: nil),
              let partials = partialMatches[victim], !partials.isEmpty {
            // The front is the oldest seed: partials are appended at seed time.
            setPartialBucket(Array(partials.dropFirst()), for: victim)
            removed += 1
        }

        if removed > 0 {
            recordPartialPressure(
                removed, reason: .globalCount, observedAt: pressureObservedAt,
                pendingCountBefore: pendingCountBefore,
                partialCountBefore: partialCountBefore, stateWeightBytesBefore: stateWeightBefore
            )
            markCheckpointStateMutation()
            evictedPartialCount = Self.saturatingTelemetryAdd(
                evictedPartialCount,
                removed
            )
            lastPartialEvictionAt = Date()
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

    private static func addSaturating(_ delta: UInt64, to value: inout UInt64) {
        value = value > UInt64.max - delta ? UInt64.max : value + delta
    }

    private static func addSaturating(
        _ delta: UInt64,
        for key: String,
        in values: inout [String: UInt64]
    ) {
        let current = values[key] ?? 0
        values[key] = current > UInt64.max - delta ? UInt64.max : current + delta
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
