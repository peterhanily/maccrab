// RuleEngine.swift
// MacCrabCore
//
// Core rule evaluation engine for MacCrab.
// Loads compiled Sigma rules (JSON predicate format) and matches them against
// security events in real time. Rules are indexed by logsource category for
// fast dispatch so that only relevant rules are evaluated per event.

import Foundation
import os.log

// MARK: - Compiled Rule Types

/// The logsource block from a compiled Sigma rule.
public struct LogSource: Codable, Sendable, Hashable {
    public let category: String
    public let product: String

    public init(category: String, product: String) {
        self.category = category
        self.product = product
    }
}

/// A single predicate within a compiled rule.
///
/// During evaluation the engine resolves `field` against the event, applies the
/// `modifier` comparison against each element of `values`, and optionally inverts
/// the result when `negate` is true.
public struct Predicate: Codable, Sendable, Hashable {
    public let field: String
    public let modifier: PredicateModifier
    public let values: [String]
    public let negate: Bool

    /// Pre-lowercased values for case-insensitive comparison. Computed once at
    /// init time to avoid repeated `.lowercased()` calls on the hot path.
    public let lowercasedValues: [String]

    public init(field: String, modifier: PredicateModifier, values: [String], negate: Bool) {
        self.field = field
        self.modifier = modifier
        self.values = values
        self.negate = negate
        self.lowercasedValues = values.map { $0.lowercased() }
    }

    // Custom Codable: lowercasedValues is derived, not serialized.
    private enum CodingKeys: String, CodingKey {
        case field, modifier, values, negate
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.field = try container.decode(String.self, forKey: .field)
        self.modifier = try container.decode(PredicateModifier.self, forKey: .modifier)
        self.values = try container.decode([String].self, forKey: .values)
        self.negate = try container.decode(Bool.self, forKey: .negate)
        self.lowercasedValues = self.values.map { $0.lowercased() }
    }
}

/// Supported comparison modifiers for rule predicates.
public enum PredicateModifier: String, Codable, Sendable, Hashable {
    case equals
    case contains
    case startswith
    case endswith
    case regex
    case exists
    case gt
    case lt
    case gte
    case lte
}

/// How the predicates within a rule are combined (legacy flat format).
public enum RuleCondition: String, Codable, Sendable, Hashable {
    case allOf = "all_of"
    case anyOf = "any_of"
    case oneOfEach = "one_of_each"
}

/// A recursive boolean condition tree for complex Sigma rules.
///
/// Preserves the full boolean structure of Sigma conditions like
/// `(selection_a and not filter_b) or ioc_c` without flattening.
/// Leaf nodes reference predicates by index into the rule's predicate array.
public indirect enum ConditionNode: Sendable, Hashable {
    case and([ConditionNode])
    case or([ConditionNode])
    case not(ConditionNode)
    /// References a predicate by its index in the `predicates` array.
    case predicate(Int)
    /// References a contiguous range of predicates (for multi-field selections).
    case predicateGroup(range: Range<Int>, mode: RuleCondition)
}

extension ConditionNode: Codable {
    private enum CodingKeys: String, CodingKey {
        case type, operands, index, rangeStart, rangeEnd, mode
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let type = try container.decode(String.self, forKey: .type)

        switch type {
        case "and":
            let ops = try container.decode([ConditionNode].self, forKey: .operands)
            self = .and(ops)
        case "or":
            let ops = try container.decode([ConditionNode].self, forKey: .operands)
            self = .or(ops)
        case "not":
            let ops = try container.decode([ConditionNode].self, forKey: .operands)
            guard let first = ops.first else {
                throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "NOT node needs one operand"))
            }
            self = .not(first)
        case "predicate":
            let idx = try container.decode(Int.self, forKey: .index)
            self = .predicate(idx)
        case "group":
            let start = try container.decode(Int.self, forKey: .rangeStart)
            let end = try container.decode(Int.self, forKey: .rangeEnd)
            guard start >= 0, end >= start else {
                throw DecodingError.dataCorrupted(.init(
                    codingPath: decoder.codingPath,
                    debugDescription: "Invalid predicate group range: \(start)..<\(end) (must be non-negative with start <= end)"
                ))
            }
            let mode = try container.decodeIfPresent(RuleCondition.self, forKey: .mode) ?? .allOf
            self = .predicateGroup(range: start..<end, mode: mode)
        default:
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Unknown condition node type: \(type)"))
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .and(let ops):
            try container.encode("and", forKey: .type)
            try container.encode(ops, forKey: .operands)
        case .or(let ops):
            try container.encode("or", forKey: .type)
            try container.encode(ops, forKey: .operands)
        case .not(let op):
            try container.encode("not", forKey: .type)
            try container.encode([op], forKey: .operands)
        case .predicate(let idx):
            try container.encode("predicate", forKey: .type)
            try container.encode(idx, forKey: .index)
        case .predicateGroup(let range, let mode):
            try container.encode("group", forKey: .type)
            try container.encode(range.lowerBound, forKey: .rangeStart)
            try container.encode(range.upperBound, forKey: .rangeEnd)
            try container.encode(mode, forKey: .mode)
        }
    }
}

/// A fully compiled detection rule loaded from JSON.
public struct CompiledRule: Codable, Sendable, Hashable, Identifiable {
    public let id: String
    public let title: String
    public let description: String
    public let level: Severity
    /// v1.18: false = "must-fire" — this match survives the NoiseFilter trust
    /// gates regardless of severity. Default true. Stored optional so compiled
    /// JSON predating the field decodes to the safe default rather than failing.
    private let suppressibleRaw: Bool?
    public var suppressible: Bool { suppressibleRaw ?? true }
    public let tags: [String]
    public let logsource: LogSource
    public let predicates: [Predicate]
    public let condition: RuleCondition
    /// Hierarchical condition tree for complex boolean expressions.
    /// When present, takes precedence over the flat `condition` field.
    public let conditionTree: ConditionNode?
    public let falsepositives: [String]
    public var enabled: Bool
    /// Original Sigma `status` (stable / test / experimental / deprecated).
    /// Optional so compiled JSON predating the field decodes to nil. A
    /// DEPRECATED rule ships disabled (enabled=false) but is retained so its
    /// id/title still surface and existing suppressions keep working — this
    /// lets the UI label it "Deprecated" rather than an ambiguous "Disabled".
    public let status: String?

    /// True when the rule is parked as deprecated content.
    public var isDeprecated: Bool { status?.lowercased() == "deprecated" }

    private enum CodingKeys: String, CodingKey {
        case id, title, description, level, tags, logsource, predicates
        case condition, falsepositives, enabled, status
        case conditionTree = "condition_tree"
        case suppressibleRaw = "suppressible"
    }

    public init(
        id: String,
        title: String,
        description: String,
        level: Severity,
        suppressible: Bool = true,
        tags: [String],
        logsource: LogSource,
        predicates: [Predicate],
        condition: RuleCondition,
        conditionTree: ConditionNode? = nil,
        falsepositives: [String],
        enabled: Bool = true,
        status: String? = nil
    ) {
        self.id = id
        self.title = title
        self.description = description
        self.level = level
        self.suppressibleRaw = suppressible
        self.tags = tags
        self.logsource = logsource
        self.predicates = predicates
        self.condition = condition
        self.conditionTree = conditionTree
        self.falsepositives = falsepositives
        self.enabled = enabled
        self.status = status
    }
}

// MARK: - Rule Engine

/// The detection rule engine. Runs as an actor to guarantee safe concurrent
/// access from multiple event-processing tasks.
///
/// Usage:
/// ```swift
/// let engine = RuleEngine()
/// let count = try await engine.loadRules(from: rulesURL)
/// // later, for each event:
/// let matches = await engine.evaluate(event)
/// ```
public actor RuleEngine {

    // MARK: State

    /// Rules indexed by logsource category for fast dispatch.
    private var ruleIndex: [String: [CompiledRule]] = [:]

    /// All rules keyed by ID for individual lookups.
    private var allRules: [String: CompiledRule] = [:]

    /// Number of rule files that failed to decode on the most recent
    /// `loadRules`. Surfaced for health checks and, critically, consulted by
    /// `reloadRules` to enforce last-known-good rollback: a corrupt compiled
    /// file must not silently shrink the active ruleset (the CrowdStrike
    /// Channel-File-291 class — content is code; validate before promoting).
    public private(set) var lastLoadFailedCount: Int = 0

    /// LRU cache of compiled `NSRegularExpression` instances keyed by pattern.
    /// On cache hit the entry is promoted; on eviction the least-recently-used
    /// entry is removed. Backed by two Dictionaries: one holds the compiled
    /// regex, the other tracks the last-access sequence number for each
    /// pattern. Both lookups + the eviction min-scan are O(1) per hit and
    /// O(n) per overflow respectively, vs. the previous Array recency list
    /// which was O(n) on every hit (lastIndex+remove+append).
    private var regexCache: [String: NSRegularExpression] = [:]
    private var regexAccessSeq: [String: UInt64] = [:]
    private var regexAccessCounter: UInt64 = 0

    private let logger = Logger(subsystem: "com.maccrab.detection", category: "RuleEngine")

    // MARK: - v1.7.1 per-rule telemetry

    /// Per-rule runtime telemetry. Counts every evaluation (fired or not),
    /// accumulates total exec time, and records the most-recent fire so the
    /// dashboard can show "last fired 3 min ago / never fired."
    public struct RuleStats: Codable, Sendable, Hashable {
        public let ruleId: String
        public var evaluationCount: UInt64
        public var fireCount: UInt64
        public var totalExecNs: UInt64
        public var lastFiredAt: Date?

        /// v1.7.2: bounded reservoir of recent execution times (ns).
        /// Capped so memory stays predictable — when full, new samples
        /// replace random older ones (Vitter Algorithm R) so percentiles
        /// converge to the true distribution.
        public var execSamplesNs: [UInt64]

        public var meanExecNs: Double {
            evaluationCount > 0 ? Double(totalExecNs) / Double(evaluationCount) : 0
        }

        /// v1.7.2: percentiles computed from `execSamplesNs`. Returns nil
        /// when the sample reservoir is empty.
        public func percentile(_ p: Double) -> Double? {
            guard !execSamplesNs.isEmpty else { return nil }
            let sorted = execSamplesNs.sorted()
            let idx = min(sorted.count - 1, max(0, Int(Double(sorted.count) * p)))
            return Double(sorted[idx])
        }
        public var p50ExecNs: Double? { percentile(0.50) }
        public var p95ExecNs: Double? { percentile(0.95) }
        public var p99ExecNs: Double? { percentile(0.99) }

        public init(ruleId: String,
                    evaluationCount: UInt64 = 0,
                    fireCount: UInt64 = 0,
                    totalExecNs: UInt64 = 0,
                    lastFiredAt: Date? = nil,
                    execSamplesNs: [UInt64] = []) {
            self.ruleId = ruleId
            self.evaluationCount = evaluationCount
            self.fireCount = fireCount
            self.totalExecNs = totalExecNs
            self.lastFiredAt = lastFiredAt
            self.execSamplesNs = execSamplesNs
        }
    }

    /// Reservoir size per rule. 256 samples × 8 B × 420 rules ≈ 860 KB
    /// worst case — small enough not to register against the v1.6.22
    /// memory caps. Larger reservoirs would tighten percentile accuracy
    /// at the tail but rule exec times are tightly distributed; 256 is
    /// the empirical sweet spot for p50/p95/p99 to converge in <1s of
    /// busy-machine traffic.
    private static let reservoirSize = 256

    private var ruleStats: [String: RuleStats] = [:]

    private func recordEvaluation(ruleId: String, elapsedNs: UInt64, fired: Bool, eventTimestamp: Date) {
        var entry = ruleStats[ruleId] ?? RuleStats(ruleId: ruleId)
        entry.evaluationCount &+= 1
        entry.totalExecNs &+= elapsedNs
        if fired {
            entry.fireCount &+= 1
            entry.lastFiredAt = eventTimestamp
        }
        // v1.7.2: reservoir sample for percentile computation.
        // Vitter Algorithm R: under reservoirSize, just append; once
        // full, replace at index `random < n` with probability
        // reservoirSize / n.
        if entry.execSamplesNs.count < Self.reservoirSize {
            entry.execSamplesNs.append(elapsedNs)
        } else {
            let n = Int(entry.evaluationCount)
            let r = Int.random(in: 0..<n)
            if r < Self.reservoirSize {
                entry.execSamplesNs[r] = elapsedNs
            }
        }
        ruleStats[ruleId] = entry
    }

    /// On-disk snapshot for the dashboard's RuleBrowser drill-down.
    /// Daemon writes `<supportDir>/rule_telemetry.json` on the heartbeat
    /// tick; the app reads via `RuleEngine.readTelemetrySnapshot(at:)`.
    public struct TelemetrySnapshot: Codable, Sendable {
        public let writtenAt: Date
        public let stats: [RuleStats]
        public init(writtenAt: Date, stats: [RuleStats]) {
            self.writtenAt = writtenAt
            self.stats = stats
        }
    }

    /// v1.7.4: see MCPBaselineService.snapshotWriteInFlight for rationale.
    private var snapshotWriteInFlight = false

    public func writeTelemetrySnapshot(to path: String) {
        guard !snapshotWriteInFlight else {
            logger.info("Skipping rule telemetry snapshot — previous write still in flight")
            return
        }
        snapshotWriteInFlight = true
        defer { snapshotWriteInFlight = false }
        let snapshot = TelemetrySnapshot(
            writtenAt: Date(),
            stats: Array(ruleStats.values).sorted { $0.fireCount > $1.fireCount }
        )
        guard let data = try? JSONEncoder().encode(snapshot) else { return }
        let tmp = path + ".tmp"
        do {
            try data.write(to: URL(fileURLWithPath: tmp), options: .atomic)
            do {
                try FileManager.default.moveItem(atPath: tmp, toPath: path)
            } catch {
                try? FileManager.default.removeItem(atPath: path)
                try FileManager.default.moveItem(atPath: tmp, toPath: path)
            }
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o644],
                ofItemAtPath: path
            )
        } catch {
            logger.warning("Failed to write rule telemetry snapshot: \(error.localizedDescription, privacy: .public)")
        }
    }

    public nonisolated static func readTelemetrySnapshot(at path: String) -> TelemetrySnapshot? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { return nil }
        return try? JSONDecoder().decode(TelemetrySnapshot.self, from: data)
    }

    // MARK: Initialization

    // v1.18: runtime eval-budget guard against pathological (ReDoS) rules. A
    // rule whose regex backtracks catastrophically on attacker-influenced fields
    // stalls the SERIAL event loop; previously such rules were only logged. Now
    // a single pathological eval, or persistent over-budget cost, auto-disables
    // the rule so it can't keep stalling ingest. Thresholds are injectable so the
    // mechanism is deterministically testable without a real multi-second stall.
    private let slowRuleThresholdNs: UInt64
    private let autoDisablePathologicalNs: UInt64
    private let autoDisableMaxBreaches: Int
    private var ruleBudgetBreaches: [String: Int] = [:]
    /// Rules auto-disabled at runtime for exceeding the eval budget (suspected
    /// pathological / ReDoS patterns). Exposed for health/visibility.
    public private(set) var autoDisabledRules: Set<String> = []

    /// v1.18: a RELOAD that cleanly decodes but yields fewer than this fraction
    /// of the prior ruleset is rejected as a suspected truncated/partial content
    /// bundle (the Channel-File-291 COUNT class) — see reloadRules.
    private let reloadMinCountFraction: Double

    public init(
        slowRuleThresholdNs: UInt64 = 50_000_000,          // 50ms — an over-budget eval
        autoDisablePathologicalNs: UInt64 = 1_000_000_000, // 1s — a single catastrophic eval
        autoDisableMaxBreaches: Int = 20,                  // disable after this many over-budget evals
        reloadMinCountFraction: Double = 0.7               // reject a reload that drops >30% of rules
    ) {
        self.slowRuleThresholdNs = slowRuleThresholdNs
        self.autoDisablePathologicalNs = autoDisablePathologicalNs
        self.autoDisableMaxBreaches = max(1, autoDisableMaxBreaches)
        self.reloadMinCountFraction = reloadMinCountFraction
    }

    /// Whether a rule whose eval just took `elapsedNs` (with `breaches`
    /// accumulated over-budget evals) should be auto-disabled: one pathological
    /// eval (catastrophic backtracking), or persistent over-budget cost.
    func shouldAutoDisable(elapsedNs: UInt64, breaches: Int) -> Bool {
        elapsedNs >= autoDisablePathologicalNs || breaches >= autoDisableMaxBreaches
    }

    // MARK: Regex caching

    /// Maximum cached regex patterns. Evict least-recently-used when exceeded.
    private static let maxRegexCacheSize = 2048

    /// Returns a compiled `NSRegularExpression` for the given pattern, using the
    /// cache to avoid recompilation. Returns `nil` if the pattern is invalid.
    private func cachedRegex(for pattern: String) -> NSRegularExpression? {
        if let cached = regexCache[pattern] {
            // Promote to most-recently-used in O(1) via the counter.
            regexAccessCounter += 1
            regexAccessSeq[pattern] = regexAccessCounter
            return cached
        }
        guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else {
            logger.warning("Failed to compile regex pattern: \(pattern)")
            return nil
        }
        // Evict least-recently-used when cache is full. O(n) min scan over
        // the sequence-number sidecar — only runs on overflow, not per hit.
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

    // MARK: Rule loading

    /// Load compiled rules from a directory of JSON files.
    ///
    /// Each `.json` file in `directory` must contain a single `CompiledRule`.
    /// Returns the number of rules successfully loaded. Rules that fail to
    /// parse are logged and skipped.
    @discardableResult
    public func loadRules(from directory: URL) throws -> Int {
        let fm = FileManager.default
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: directory.path, isDirectory: &isDir), isDir.boolValue else {
            throw RuleEngineError.directoryNotFound(directory.path)
        }

        let contents = try fm.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles]
        )

        let jsonFiles = contents.filter { $0.pathExtension == "json" }
        logger.info("Found \(contents.count) files in \(directory.path), \(jsonFiles.count) are .json")
        if jsonFiles.isEmpty {
            logger.warning("No .json rule files found in \(directory.path)")
        }

        let decoder = JSONDecoder()
        var loaded = 0
        var failed = 0

        for file in jsonFiles {
            do {
                let data = try Data(contentsOf: file)
                let rule = try decoder.decode(CompiledRule.self, from: data)
                allRules[rule.id] = rule
                ruleIndex[rule.logsource.category, default: []].append(rule)
                loaded += 1
            } catch {
                failed += 1
                logger.error("Failed to load rule from \(file.lastPathComponent): \(error)")
                // Print full decode error for debugging
                print("  RULE LOAD ERROR: \(file.lastPathComponent): \(error)")
            }
        }
        lastLoadFailedCount = failed

        // Pre-compile all regex patterns so that evaluateModifier never has to
        // compile on the hot path.
        for rule in allRules.values {
            for predicate in rule.predicates where predicate.modifier == .regex {
                for pattern in predicate.values {
                    _ = cachedRegex(for: pattern)
                }
            }
        }

        logger.info("Loaded \(loaded) rules from \(directory.path)")
        return loaded
    }

    /// Reload rules, replacing all existing rules. Intended as a SIGHUP handler.
    ///
    /// The reload is safe-to-fail: if `loadRules` throws (e.g. the rules
    /// directory is missing or corrupt), the previous rule set is fully
    /// restored so the daemon continues evaluating events without a gap.
    ///
    /// Returns the number of rules loaded after the reload.
    @discardableResult
    public func reloadRules(from directory: URL) throws -> Int {
        // Preserve enabled/disabled state for rules that still exist after reload.
        let previousEnabledState = allRules.mapValues { $0.enabled }

        // Snapshot current state so we can roll back if the load fails.
        let snapshotIndex  = ruleIndex
        let snapshotRules  = allRules
        let snapshotRegex  = regexCache
        let snapshotRegexSeq = regexAccessSeq
        let snapshotRegexCounter = regexAccessCounter

        // Pre-fix: cache was wiped BEFORE load. During the (potentially
        // 100s ms long) loadRules call, concurrent evaluate() calls saw
        // a cold regex cache and paid recompile cost on the hot path.
        // Now: keep the existing rules + cache live during the load.
        // loadRules merges / overrides into ruleIndex + allRules; any
        // stale regex entries from rules that no longer exist will be
        // LRU-evicted naturally as the new rules' regexes are accessed.
        let count: Int
        do {
            // First clear ruleIndex so loadRules rebuilds the per-
            // category dispatch map from scratch — critical for
            // correctness if a rule's category changed. allRules is
            // a separate dict, gets repopulated by loadRules' inserts.
            ruleIndex.removeAll()
            allRules.removeAll()
            count = try loadRules(from: directory)
        } catch {
            // Restore previous state — engine must never be left empty.
            ruleIndex       = snapshotIndex
            allRules        = snapshotRules
            regexCache      = snapshotRegex
            regexAccessSeq  = snapshotRegexSeq
            regexAccessCounter = snapshotRegexCounter
            logger.error("Rule reload failed, previous rules restored: \(error)")
            throw error
        }

        // Last-known-good (atomic content swap): loadRules is best-effort and
        // silently SKIPS any file it can't decode, so a single corrupt compiled
        // rule would otherwise shrink the live ruleset with no error. On RELOAD
        // — where a known-good prior set exists — treat ANY decode failure as a
        // failed swap: roll back to the prior set and throw, rather than run
        // with a silently-reduced detection surface. (Initial boot loadRules
        // stays best-effort: N-1 rules beat zero on first start.)
        if lastLoadFailedCount > 0 {
            let failed = lastLoadFailedCount
            ruleIndex          = snapshotIndex
            allRules           = snapshotRules
            regexCache         = snapshotRegex
            regexAccessSeq     = snapshotRegexSeq
            regexAccessCounter = snapshotRegexCounter
            logger.error("Rule reload rejected: \(failed) file(s) failed to decode; restored \(snapshotRules.count) last-known-good rules")
            throw RuleEngineError.partialLoadFailure(failed: failed, loaded: count)
        }

        // v1.18: rule-COUNT regression guard (Channel-File-291 count class).
        // Even when every file decodes cleanly, a drastically smaller incoming
        // set — a truncated/partial bundle, a half-synced content dir — collapses
        // detection silently. Reject a reload that drops below the configured
        // fraction of the prior set and restore last-known-good. (Skipped when
        // there was no meaningful prior set, e.g. an empty engine.)
        if !snapshotRules.isEmpty && Double(count) < Double(snapshotRules.count) * reloadMinCountFraction {
            ruleIndex          = snapshotIndex
            allRules           = snapshotRules
            regexCache         = snapshotRegex
            regexAccessSeq     = snapshotRegexSeq
            regexAccessCounter = snapshotRegexCounter
            logger.fault("Rule reload rejected: incoming \(count) rules is below \(Int(self.reloadMinCountFraction * 100))% of the prior \(snapshotRules.count); restored last-known-good (suspected truncated content bundle)")
            throw RuleEngineError.ruleCountRegression(loaded: count, previous: snapshotRules.count)
        }

        // Restore enabled state for rules that were previously disabled.
        for (ruleId, wasEnabled) in previousEnabledState {
            if var rule = allRules[ruleId], !wasEnabled {
                rule.enabled = false
                allRules[ruleId] = rule
                // Update in index as well.
                let category = rule.logsource.category
                if let idx = ruleIndex[category]?.firstIndex(where: { $0.id == ruleId }) {
                    ruleIndex[category]?[idx] = rule
                }
            }
        }

        logger.info("Reloaded rules: \(count) total")
        return count
    }

    // MARK: Evaluation

    /// Evaluate an event against all applicable rules.
    ///
    /// Only rules whose logsource category matches the event's category are
    /// tested. Returns an array of `RuleMatch` for every rule that fires.
    public func evaluate(_ event: Event) -> [RuleMatch] {
        let category = mapEventCategoryToLogsource(event.eventCategory, eventType: event.eventType)
        guard let rules = ruleIndex[category] else { return [] }

        var matches: [RuleMatch] = []
        var rulesToDisable: [(id: String, title: String, ms: Double, breaches: Int)] = []

        for rule in rules where rule.enabled {
            let start = DispatchTime.now()
            let fired = evaluateRule(rule, against: event)
            let elapsed = DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds

            // v1.7.1: per-rule telemetry — fire count, total exec ns, last
            // fire timestamp. Updated even on non-firing evaluations so the
            // dashboard can show "rule never matched but executed N times"
            // (the typical state for low-fire detection rules).
            recordEvaluation(ruleId: rule.id, elapsedNs: elapsed, fired: fired, eventTimestamp: event.timestamp)

            // v1.18: eval-budget guard. An over-budget eval is logged AND
            // counted; a single pathological eval or persistent over-budget cost
            // marks the rule for auto-disable so a ReDoS pattern can't keep
            // stalling the serial event loop.
            if elapsed >= slowRuleThresholdNs {
                let ms = Double(elapsed) / 1_000_000
                logger.warning("Slow rule: \(rule.title) (\(rule.id)) took \(String(format: "%.1f", ms))ms")
                let breaches = (ruleBudgetBreaches[rule.id] ?? 0) + 1
                ruleBudgetBreaches[rule.id] = breaches
                if shouldAutoDisable(elapsedNs: elapsed, breaches: breaches) {
                    rulesToDisable.append((rule.id, rule.title, ms, breaches))
                }
            }

            if fired {
                let match = RuleMatch(
                    ruleId: rule.id,
                    ruleName: rule.title,
                    severity: rule.level,
                    description: rule.description,
                    mitreTechniques: rule.tags.filter { $0.hasPrefix("attack.t") },
                    tags: rule.tags,
                    suppressible: rule.suppressible
                )
                matches.append(match)
            }
        }

        // v1.18: apply auto-disables AFTER the loop (setEnabled mutates
        // ruleIndex). A pathological/ReDoS rule stops stalling ingest once
        // disabled; it can be re-enabled after the rule is fixed.
        for r in rulesToDisable where !autoDisabledRules.contains(r.id) {
            setEnabled(r.id, enabled: false)
            autoDisabledRules.insert(r.id)
            logger.fault("Auto-DISABLED rule \(r.title) (\(r.id)) — \(r.breaches) over-budget evals (last \(String(format: "%.1f", r.ms))ms); suspected pathological/ReDoS pattern.")
        }

        return matches
    }

    // MARK: Rule management

    /// Enable or disable an individual rule by ID.
    public func setEnabled(_ ruleId: String, enabled: Bool) {
        guard var rule = allRules[ruleId] else {
            logger.warning("setEnabled called for unknown rule ID: \(ruleId)")
            return
        }

        rule.enabled = enabled
        allRules[ruleId] = rule

        let category = rule.logsource.category
        if let idx = ruleIndex[category]?.firstIndex(where: { $0.id == ruleId }) {
            ruleIndex[category]?[idx] = rule
        }
    }

    /// Returns all loaded rules, optionally filtered by category.
    public func listRules(category: String? = nil) -> [CompiledRule] {
        if let category {
            return ruleIndex[category] ?? []
        }
        return Array(allRules.values)
    }

    /// Returns the total number of loaded rules.
    public var ruleCount: Int {
        allRules.count
    }

    // MARK: - Private Evaluation Logic

    /// Evaluate a single compiled rule against an event.
    private func evaluateRule(_ rule: CompiledRule, against event: Event) -> Bool {
        let predicates = rule.predicates
        guard !predicates.isEmpty else { return false }

        // Use hierarchical condition tree if available (complex boolean expressions).
        if let tree = rule.conditionTree {
            return evaluateConditionNode(tree, predicates: predicates, against: event)
        }

        // Legacy flat condition evaluation.
        switch rule.condition {
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

    /// Recursively evaluate a condition tree node.
    private func evaluateConditionNode(
        _ node: ConditionNode,
        predicates: [Predicate],
        against event: Event
    ) -> Bool {
        switch node {
        case .and(let operands):
            return operands.allSatisfy { evaluateConditionNode($0, predicates: predicates, against: event) }

        case .or(let operands):
            return operands.contains { evaluateConditionNode($0, predicates: predicates, against: event) }

        case .not(let operand):
            return !evaluateConditionNode(operand, predicates: predicates, against: event)

        case .predicate(let index):
            guard index >= 0 && index < predicates.count else { return false }
            return evaluatePredicate(predicates[index], against: event)

        case .predicateGroup(let range, let mode):
            let clamped = range.clamped(to: 0..<predicates.count)
            // An empty slice must not produce a vacuous-truth match.
            guard !clamped.isEmpty else { return false }
            let slice = predicates[clamped]
            switch mode {
            case .allOf:
                return slice.allSatisfy { evaluatePredicate($0, against: event) }
            case .anyOf:
                return slice.contains { evaluatePredicate($0, against: event) }
            case .oneOfEach:
                let groups = Dictionary(grouping: slice, by: { $0.field })
                return groups.values.allSatisfy { group in
                    group.contains { evaluatePredicate($0, against: event) }
                }
            }
        }
    }

    /// Evaluate a single predicate against an event.
    private func evaluatePredicate(_ predicate: Predicate, against event: Event) -> Bool {
        let rawResult: Bool

        // For the "exists" modifier we only check field presence.
        if predicate.modifier == .exists {
            let fieldValue = resolveField(predicate.field, from: event)
            rawResult = fieldValue?.isEmpty == false
        } else {
            guard let fieldValue = resolveField(predicate.field, from: event) else {
                // Field not present on event -- no match (unless negated).
                rawResult = false
                return predicate.negate ? !rawResult : rawResult
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

    /// Apply a modifier comparison between a resolved field value and the
    /// predicate's value list. The predicate matches when the field satisfies
    /// the comparison for *any* value in the list (OR semantics within a
    /// single predicate).
    ///
    /// `lowercasedValues` are pre-computed at Predicate init time to avoid
    /// repeated `.lowercased()` calls on the hot path.
    private func evaluateModifier(
        _ modifier: PredicateModifier,
        fieldValue: String,
        values: [String],
        lowercasedValues: [String]
    ) -> Bool {
        // v1.12.0 RC25 (perf): only lowercase the field value when the
        // modifier actually compares case-insensitive. Pre-fix every
        // call did `fieldValue.lowercased()` upfront — ~75K wasted
        // String allocations/sec for regex/gt/lt/exists predicates
        // (~30% of the rule corpus).
        let needsLower: Bool = {
            switch modifier {
            case .equals, .contains, .startswith, .endswith: return true
            default: return false
            }
        }()
        let fieldLower = needsLower ? fieldValue.lowercased() : ""

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
            // Handled above; included here for completeness.
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

    /// Resolve a dot-path (or Sigma alias) field name to a string value from the event.
    ///
    /// Supports both ECS-style paths (`process.executable`) and legacy Sigma
    /// field names (`Image`, `CommandLine`, `ParentImage`, etc.).
    /// Returns `nil` when the field is not present or not applicable.
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
            // ParentCommandLine requires enrichment data; fall back to enrichments dict.
            return event.enrichments["parent.commandline"]

        // --- Grandparent process fields ---
        case "process.grandparent.executable", "GrandparentImage":
            return event.process.ancestors.count >= 2 ? event.process.ancestors[1].executable : nil

        case "process.grandparent.name":
            return event.process.ancestors.count >= 2 ? event.process.ancestors[1].name : nil

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

        case "ParentSignerType":
            // Parent code signature isn't directly available on Event;
            // would require enrichment. Fall through to enrichments dict.
            return event.enrichments["ParentSignerType"]

        // --- Phase 1 hash enrichment ---
        case "process.hashes.sha256", "ProcessSHA256":
            return event.process.hashes?.sha256

        case "process.hashes.cdhash", "ProcessCDHash":
            return event.process.hashes?.cdhash

        case "process.hashes.md5", "ProcessMD5":
            return event.process.hashes?.md5

        // --- Phase 1 extended code signing ---
        case "process.code_signature.issuer", "SigningCertIssuer":
            // Leaf issuer CN (first entry in issuerChain, ordered leaf → root).
            return event.process.codeSignature?.issuerChain?.first

        case "process.code_signature.cert_hash", "SigningCertHash":
            return event.process.codeSignature?.certHashes?.first

        case "process.code_signature.is_adhoc", "IsAdhocSigned":
            return event.process.codeSignature?.isAdhocSigned.map { String($0) }

        // --- Phase 1 session / login context ---
        case "process.session.tty", "SessionTTY":
            return event.process.session?.tty

        case "process.session.login_user", "SessionLoginUser":
            return event.process.session?.loginUser

        case "process.session.ssh_remote_ip", "SessionSSHRemoteIP":
            return event.process.session?.sshRemoteIP

        case "process.session.launch_source", "LaunchSource":
            return event.process.session?.launchSource?.rawValue

        case "IsSSHLaunched":
            // Convenience boolean: launched via SSH session.
            return event.process.session.map {
                String($0.launchSource == .ssh)
            }

        // --- Deception: honeyfile access ---
        case "IsHoneyfile":
            // Set by EventEnricher when the file path matches a deployed
            // honeyfile. Any value present indicates a canary was touched.
            return event.enrichments["IsHoneyfile"]

        case "HoneyfileType":
            return event.enrichments["HoneyfileType"]

        // --- Phase 1 lineage + env ---
        case "process.ancestor_depth", "AncestorDepth":
            return String(event.process.ancestors.count)

        case "ProcessAncestors":
            // Newline-joined ancestor names + executables so a Sigma
            // `|contains` matches any process in the lineage chain (used by
            // ai_safety rules that key on an AI-tool ancestor). nil when no
            // lineage so `|contains` against nil is a clean non-match.
            guard !event.process.ancestors.isEmpty else { return nil }
            return event.process.ancestors
                .flatMap { [$0.name, $0.executable] }
                .joined(separator: "\n")

        case "process.env", "EnvVarsFlat":
            // Flatten the env dict into "KEY1=val1 KEY2=val2" so Sigma's
            // `contains` modifier can match against env fragments.
            guard let env = event.process.envVars, !env.isEmpty else { return nil }
            return env
                .sorted { $0.key < $1.key }
                .map { "\($0.key)=\($0.value)" }
                .joined(separator: " ")

        case "process.is_platform_binary", "IsPlatformBinary", "PlatformBinary":
            return String(event.process.isPlatformBinary)

        case "process.architecture", "Architecture":
            // v1.12.6 Wave 2A: previously Sigma's `Architecture:` fell
            // through to event.enrichments["Architecture"] which is never
            // populated (the ES collector writes the raw "arm64"/"x86_64"
            // string directly onto ProcessInfo.architecture). Rules in
            // Rules/defense_evasion/rosetta_*.yml predicate on this Sigma
            // field name — without the alias they silently never fired.
            return event.process.architecture

        // v1.12.6 Wave 2A: explicit Sigma aliases for fields the rule
        // corpus uses but the pre-v6 resolver mapped to wrong / unset
        // enrichment keys. Each case here corresponds to a column added
        // in EventStore schema v6 and unblocks at least one production
        // rule from the dead-letter list.

        case "process.is_notarized", "IsNotarized":
            // Three-state: nil when no codeSignature attached (unknown),
            // otherwise the Bool flattened to "true"/"false" so Sigma's
            // string equality compares against rule literals cleanly.
            return event.process.codeSignature.map { String($0.isNotarized) }

        case "NotarizationStatus":
            // Mirrors NotarizationChecker.NotarizationStatus rawValues
            // exactly so Rules/defense_evasion/notarization_absent_*.yml,
            // mas_receipt_access_by_non_sandbox.yml, and
            // sequences/notarized_dropper_pattern.yml can predicate on
            // 'notarized' / 'not_notarized' literally.
            //
            // v1.17.2: prefer the enriched `notarization.status` when present —
            // it carries the FULL spctl verdict including 'revoked' (a binary
            // whose Developer-ID cert Apple has since revoked; the AMOS/Atomic
            // Stealer post-takedown pattern) and 'unknown'. The codeSignature
            // boolean below is only two-state (isNotarized) and can't express
            // revoked, so a revoked-cert binary would otherwise read as plain
            // 'not_notarized' and be swept up by notarization_absent's
            // devId/notarized trust filters. The enrichment is populated by
            // NotarizationChecker (EventLoop) once its cache is warm; on a cold
            // first-seen exec it's absent, so we fall back to the boolean —
            // preserving the existing notarized/not_notarized behaviour.
            if let enriched = event.enrichments["notarization.status"], !enriched.isEmpty {
                return enriched
            }
            guard let sig = event.process.codeSignature else { return nil }
            return sig.isNotarized ? "notarized" : "not_notarized"

        case "process.user_id", "UserId":
            return String(event.process.userId)

        case "process.group_id", "GroupId":
            return String(event.process.groupId)

        case "WorkingDirectory":
            // Sigma alias for `process.working_directory` (already mapped
            // above). Keeps rule authors from having to know the dotted
            // form.
            return event.process.workingDirectory

        case "ResponsiblePid":
            return String(event.process.rpid)

        case "ParentName":
            return event.process.ancestors.first?.name

        case "AiTool", "AITool":
            // v1.12.6 Wave 9M: read `ai_tool` first then fall back to
            // `agent_tool`. EventStore v6 writer (Wave 9C) populates
            // the column via `ai_tool ?? agent_tool` because the
            // production AIProcessTracker emits `ai_tool` while the
            // legacy TraceCorrelator emits `agent_tool`. Pre-9M this
            // case read ONLY agent_tool, so rules matching on
            // `AiTool: claude_code` failed to fire against events
            // produced by the modern writer path. Two aliases match
            // either casing a rule author might write.
            return event.enrichments["ai_tool"]
                ?? event.enrichments[TraceCorrelator.EnrichmentKey.agentTool]

        case "AiToolChild", "AIToolChild":
            return event.enrichments["ai_tool_child"]

        case "SessionLaunchSource":
            // Synonym for `LaunchSource` already mapped above, kept
            // for grep'ability against the v6 column name.
            return event.process.session?.launchSource?.rawValue

        case "TCCDecision":
            // Match the SQL column convention: "granted" / "denied".
            return event.tcc.map { $0.allowed ? "granted" : "denied" }

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

        case "file.action", "FileAction":
            // "FileAction" is in `_KNOWN_PASSTHROUGH_FIELDS` in the rule
            // compiler — without this alias 15+ ai_safety/supply_chain
            // rules that predicate on `FileAction: 'create'` etc. would
            // silently never fire because resolveField() would hit the
            // `default:` enrichments-dict branch and return nil.
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
            // Try the enrichments dictionary for fields added by plugins.
            return event.enrichments[path]
        }
    }

    // MARK: - Category Mapping

    /// Map an event's category and type to the Sigma logsource category string
    /// used for rule indexing.
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
}

// MARK: - Errors

/// Errors thrown by the rule engine.
public enum RuleEngineError: Error, LocalizedError {
    case directoryNotFound(String)
    case invalidRuleFormat(String)
    case partialLoadFailure(failed: Int, loaded: Int)
    case ruleCountRegression(loaded: Int, previous: Int)

    public var errorDescription: String? {
        switch self {
        case .directoryNotFound(let path):
            return "Rule directory not found: \(path)"
        case .invalidRuleFormat(let detail):
            return "Invalid rule format: \(detail)"
        case .partialLoadFailure(let failed, let loaded):
            return "Rule reload rejected: \(failed) file(s) failed to decode (\(loaded) decoded); restored last-known-good ruleset"
        case .ruleCountRegression(let loaded, let previous):
            return "Rule reload rejected: incoming \(loaded) rules far below the prior \(previous); restored last-known-good ruleset"
        }
    }
}
