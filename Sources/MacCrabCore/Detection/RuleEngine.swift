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

    public init(field: String, modifier: PredicateModifier, values: [String], negate: Bool) {
        self.field = field
        self.modifier = modifier
        self.values = values
        self.negate = negate
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
    public let tags: [String]
    public let logsource: LogSource
    public let predicates: [Predicate]
    public let condition: RuleCondition
    /// Hierarchical condition tree for complex boolean expressions.
    /// When present, takes precedence over the flat `condition` field.
    public let conditionTree: ConditionNode?
    public let falsepositives: [String]
    public var enabled: Bool

    private enum CodingKeys: String, CodingKey {
        case id, title, description, level, tags, logsource, predicates
        case condition, falsepositives, enabled
        case conditionTree = "condition_tree"
    }

    public init(
        id: String,
        title: String,
        description: String,
        level: Severity,
        tags: [String],
        logsource: LogSource,
        predicates: [Predicate],
        condition: RuleCondition,
        conditionTree: ConditionNode? = nil,
        falsepositives: [String],
        enabled: Bool = true
    ) {
        self.id = id
        self.title = title
        self.description = description
        self.level = level
        self.tags = tags
        self.logsource = logsource
        self.predicates = predicates
        self.condition = condition
        self.conditionTree = conditionTree
        self.falsepositives = falsepositives
        self.enabled = enabled
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

    /// Cache of compiled `NSRegularExpression` instances keyed by pattern string.
    /// Avoids recompiling the same regex pattern on every evaluation.
    private var regexCache: [String: NSRegularExpression] = [:]

    private let logger = Logger(subsystem: "com.maccrab.detection", category: "RuleEngine")

    // MARK: Initialization

    public init() {}

    // MARK: Regex caching

    /// Returns a compiled `NSRegularExpression` for the given pattern, using the
    /// cache to avoid recompilation. Returns `nil` if the pattern is invalid.
    /// Maximum cached regex patterns. Evict oldest when exceeded.
    private static let maxRegexCacheSize = 2048

    private func cachedRegex(for pattern: String) -> NSRegularExpression? {
        if let cached = regexCache[pattern] {
            return cached
        }
        guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else {
            return nil
        }
        // Evict if cache is full (simple FIFO — remove arbitrary entry)
        if regexCache.count >= Self.maxRegexCacheSize, let firstKey = regexCache.keys.first {
            regexCache.removeValue(forKey: firstKey)
        }
        regexCache[pattern] = regex
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

        for file in jsonFiles {
            do {
                let data = try Data(contentsOf: file)
                let rule = try decoder.decode(CompiledRule.self, from: data)
                allRules[rule.id] = rule
                ruleIndex[rule.logsource.category, default: []].append(rule)
                loaded += 1
            } catch {
                logger.error("Failed to load rule from \(file.lastPathComponent): \(error)")
                // Print full decode error for debugging
                print("  RULE LOAD ERROR: \(file.lastPathComponent): \(error)")
            }
        }

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

        ruleIndex.removeAll()
        allRules.removeAll()
        regexCache.removeAll()

        let count: Int
        do {
            count = try loadRules(from: directory)
        } catch {
            // Restore previous state — engine must never be left empty.
            ruleIndex  = snapshotIndex
            allRules   = snapshotRules
            regexCache = snapshotRegex
            logger.error("Rule reload failed, previous rules restored: \(error)")
            throw error
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
    /// Threshold for logging slow rules (nanoseconds). Rules exceeding this
    /// are logged at warning level to help identify performance bottlenecks.
    private static let slowRuleThresholdNs: UInt64 = 50_000_000  // 50ms

    public func evaluate(_ event: Event) -> [RuleMatch] {
        let category = mapEventCategoryToLogsource(event.eventCategory, eventType: event.eventType)
        guard let rules = ruleIndex[category] else { return [] }

        var matches: [RuleMatch] = []

        for rule in rules where rule.enabled {
            let start = DispatchTime.now()
            let fired = evaluateRule(rule, against: event)
            let elapsed = DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds

            if elapsed > Self.slowRuleThresholdNs {
                let ms = Double(elapsed) / 1_000_000
                logger.warning("Slow rule: \(rule.title) (\(rule.id)) took \(String(format: "%.1f", ms))ms")
            }

            if fired {
                let match = RuleMatch(
                    ruleId: rule.id,
                    ruleName: rule.title,
                    severity: rule.level,
                    description: rule.description,
                    mitreTechniques: rule.tags.filter { $0.hasPrefix("attack.t") },
                    tags: rule.tags
                )
                matches.append(match)
            }
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
            let slice = predicates[range.clamped(to: 0..<predicates.count)]
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
                values: predicate.values
            )
        }

        return predicate.negate ? !rawResult : rawResult
    }

    /// Apply a modifier comparison between a resolved field value and the
    /// predicate's value list. The predicate matches when the field satisfies
    /// the comparison for *any* value in the list (OR semantics within a
    /// single predicate).
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

    public var errorDescription: String? {
        switch self {
        case .directoryNotFound(let path):
            return "Rule directory not found: \(path)"
        case .invalidRuleFormat(let detail):
            return "Invalid rule format: \(detail)"
        }
    }
}
