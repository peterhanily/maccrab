import CryptoKit
import Foundation

/// Typed rejection for a terminal overlay that attempts to rewrite immutable
/// source evidence. The base Event remains authoritative for every field not
/// explicitly carried by ``EventTerminalDelta``.
public enum EventTerminalDeltaError: Error, LocalizedError, Sendable, Equatable {
    case eventIdentityChanged
    case processIdentityChanged
    case severityRegressed
    case environmentResetCannotBeComposed

    public var errorDescription: String? {
        switch self {
        case .eventIdentityChanged:
            return "terminal event changed immutable event source identity"
        case .processIdentityChanged:
            return "terminal event changed immutable process source identity"
        case .severityRegressed:
            return "terminal event severity regressed below its immutable base"
        case .environmentResetCannotBeComposed:
            return "terminal environment reset cannot be represented as a sparse edit"
        }
    }
}

/// A required terminal field is either inherited from the immutable base or
/// replaced. Keeping `unchanged` explicit prevents a decoded omitted/default
/// value from accidentally erasing source evidence.
public enum EventTerminalRequiredChange<Value>: Codable, Sendable, Equatable
where Value: Codable & Sendable & Equatable {
    case unchanged
    case setValue(Value)

    private enum CodingKeys: String, CodingKey { case operation, value }
    private enum Operation: String, Codable { case unchanged, setValue }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(Operation.self, forKey: .operation) {
        case .unchanged:
            self = .unchanged
        case .setValue:
            self = .setValue(try container.decode(Value.self, forKey: .value))
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .unchanged:
            try container.encode(Operation.unchanged, forKey: .operation)
        case let .setValue(value):
            try container.encode(Operation.setValue, forKey: .operation)
            try container.encode(value, forKey: .value)
        }
    }

    fileprivate var changed: Bool {
        if case .setValue = self { return true }
        return false
    }

    fileprivate func applying(to base: Value) -> Value {
        switch self {
        case .unchanged: return base
        case let .setValue(value): return value
        }
    }
}

/// An optional terminal field distinguishes inheritance, an explicit nil, and
/// a concrete replacement. This tri-state is required for exact replay.
public enum EventTerminalOptionalChange<Value>: Codable, Sendable, Equatable
where Value: Codable & Sendable & Equatable {
    case unchanged
    case setNil
    case setValue(Value)

    private enum CodingKeys: String, CodingKey { case operation, value }
    private enum Operation: String, Codable { case unchanged, setNil, setValue }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(Operation.self, forKey: .operation) {
        case .unchanged:
            self = .unchanged
        case .setNil:
            self = .setNil
        case .setValue:
            self = .setValue(try container.decode(Value.self, forKey: .value))
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .unchanged:
            try container.encode(Operation.unchanged, forKey: .operation)
        case .setNil:
            try container.encode(Operation.setNil, forKey: .operation)
        case let .setValue(value):
            try container.encode(Operation.setValue, forKey: .operation)
            try container.encode(value, forKey: .value)
        }
    }

    fileprivate var changed: Bool {
        if case .unchanged = self { return false }
        return true
    }

    fileprivate func applying(to base: Value?) -> Value? {
        switch self {
        case .unchanged: return base
        case .setNil: return nil
        case let .setValue(value): return value
        }
    }
}

/// A deterministic sparse dictionary edit. Upserts contain only keys whose
/// terminal sanitized values differ; removals are unique and sorted.
public struct EventTerminalStringMapDelta: Codable, Sendable, Equatable {
    public let upserts: [String: String]
    public let removals: [String]

    public init(upserts: [String: String], removals: [String]) {
        let sanitized = EventPrivacySanitizer.sanitizeDynamicMap(upserts)
        self.upserts = sanitized
        self.removals = Array(Set(removals.map(
            EventPrivacySanitizer.sanitizeString
        ))).sorted().filter {
            sanitized[$0] == nil
        }
    }

    fileprivate init(base: [String: String], terminal: [String: String]) {
        var changed: [String: String] = [:]
        changed.reserveCapacity(terminal.count)
        for key in terminal.keys.sorted() where base[key] != terminal[key] {
            changed[key] = terminal[key]
        }
        self.upserts = changed
        self.removals = base.keys.filter { terminal[$0] == nil }.sorted()
    }

    public var isEmpty: Bool { upserts.isEmpty && removals.isEmpty }

    fileprivate func applying(to base: [String: String]) -> [String: String] {
        var result = base
        for key in removals { result.removeValue(forKey: key) }
        for key in upserts.keys.sorted() { result[key] = upserts[key] }
        return result
    }

    fileprivate func followed(
        by subsequent: EventTerminalStringMapDelta
    ) -> EventTerminalStringMapDelta {
        var combinedUpserts = self.upserts
        var combinedRemovals = Set(self.removals)
        for key in subsequent.removals {
            combinedUpserts.removeValue(forKey: key)
            combinedRemovals.insert(key)
        }
        for key in subsequent.upserts.keys.sorted() {
            combinedUpserts[key] = subsequent.upserts[key]
            combinedRemovals.remove(key)
        }
        return EventTerminalStringMapDelta(
            upserts: combinedUpserts,
            removals: combinedRemovals.sorted()
        )
    }
}

/// The complete, versionable set of fields that may change after the immutable
/// pre-alert journal boundary.
///
/// This is a true delta: large enrichment/environment dictionaries are never
/// repeated when one late value changes, and optional process fields preserve
/// explicit unchanged/set-nil/set-value semantics. Every other Event and
/// ProcessInfo field is immutable source evidence.
public struct EventTerminalDelta: Codable, Sendable, Equatable {
    public static let schemaVersion = 1

    public let version: Int
    public let eventID: UUID
    public let processUserName: EventTerminalRequiredChange<String>
    public let processCodeSignature: EventTerminalOptionalChange<CodeSignatureInfo>
    public let processHashes: EventTerminalOptionalChange<ProcessHashes>
    public let processEnvironment: EventTerminalOptionalChange<EventTerminalStringMapDelta>
    public let enrichments: EventTerminalStringMapDelta
    public let severity: EventTerminalRequiredChange<Severity>
    public let reviewedRuleMatches: EventTerminalRequiredChange<[RuleMatch]>

    /// Stable memberwise initializer for storage decoding/migration fixtures.
    /// Runtime callers should prefer `init(base:terminal:)` so immutable source
    /// validation and deterministic sanitization cannot be skipped.
    public init(
        version: Int = EventTerminalDelta.schemaVersion,
        eventID: UUID,
        processUserName: EventTerminalRequiredChange<String> = .unchanged,
        processCodeSignature: EventTerminalOptionalChange<CodeSignatureInfo> = .unchanged,
        processHashes: EventTerminalOptionalChange<ProcessHashes> = .unchanged,
        processEnvironment: EventTerminalOptionalChange<EventTerminalStringMapDelta> = .unchanged,
        enrichments: EventTerminalStringMapDelta = .init(upserts: [:], removals: []),
        severity: EventTerminalRequiredChange<Severity> = .unchanged,
        reviewedRuleMatches: EventTerminalRequiredChange<[RuleMatch]> = .unchanged
    ) {
        self.version = version
        self.eventID = eventID
        self.processUserName = processUserName
        self.processCodeSignature = processCodeSignature
        self.processHashes = processHashes
        self.processEnvironment = processEnvironment
        self.enrichments = enrichments
        self.severity = severity
        switch reviewedRuleMatches {
        case .unchanged:
            self.reviewedRuleMatches = .unchanged
        case let .setValue(matches):
            self.reviewedRuleMatches = .setValue(
                ReviewedRuleMatches.normalized(
                    EventPrivacySanitizer.sanitizeRuleMatches(matches)
                )
            )
        }
    }

    public init(base: Event, terminal: Event) throws {
        try Self.validateImmutableTransition(base: base, terminal: terminal)

        let baseEnvironment = base.process.envVars.map(
            EventPrivacySanitizer.sanitizeDynamicMap
        )
        let terminalEnvironment = terminal.process.envVars.map(
            EventPrivacySanitizer.sanitizeDynamicMap
        )
        let environmentChange: EventTerminalOptionalChange<EventTerminalStringMapDelta>
        switch (baseEnvironment, terminalEnvironment) {
        case (nil, nil):
            environmentChange = .unchanged
        case (_, nil):
            environmentChange = .setNil
        case (nil, let terminal?):
            environmentChange = .setValue(
                EventTerminalStringMapDelta(base: [:], terminal: terminal)
            )
        case (let base?, let terminal?):
            let delta = EventTerminalStringMapDelta(base: base, terminal: terminal)
            environmentChange = delta.isEmpty ? .unchanged : .setValue(delta)
        }

        let baseEnrichments = EventPrivacySanitizer.sanitizeDynamicMap(
            base.enrichments
        )
        let terminalEnrichments = EventPrivacySanitizer.sanitizeDynamicMap(
            terminal.enrichments
        )
        let baseMatches = ReviewedRuleMatches.normalized(
            EventPrivacySanitizer.sanitizeRuleMatches(base.ruleMatches)
        )
        let terminalMatches = ReviewedRuleMatches.normalized(
            EventPrivacySanitizer.sanitizeRuleMatches(terminal.ruleMatches)
        )

        self.init(
            eventID: base.id,
            processUserName: base.process.userName == terminal.process.userName
                ? .unchanged : .setValue(terminal.process.userName),
            processCodeSignature: Self.optionalChange(
                from: base.process.codeSignature,
                to: terminal.process.codeSignature
            ),
            processHashes: Self.optionalChange(
                from: base.process.hashes,
                to: terminal.process.hashes
            ),
            processEnvironment: environmentChange,
            enrichments: EventTerminalStringMapDelta(
                base: baseEnrichments,
                terminal: terminalEnrichments
            ),
            severity: base.severity == terminal.severity
                ? .unchanged : .setValue(terminal.severity),
            reviewedRuleMatches: baseMatches == terminalMatches
                ? .unchanged : .setValue(terminalMatches)
        )
    }

    public var isEmpty: Bool {
        !processUserName.changed
            && !processCodeSignature.changed
            && !processHashes.changed
            && !processEnvironment.changed
            && enrichments.isEmpty
            && !severity.changed
            && !reviewedRuleMatches.changed
    }

    /// Compose a later sparse transition without retaining the immutable base.
    /// Deferred enrichment uses this while each prior raw revision is still
    /// source-budgeted, then releases that revision before terminal storage.
    public func followed(
        by subsequent: EventTerminalDelta
    ) throws -> EventTerminalDelta {
        guard version == Self.schemaVersion,
              subsequent.version == Self.schemaVersion,
              eventID == subsequent.eventID else {
            throw EventTerminalDeltaError.eventIdentityChanged
        }

        let environment: EventTerminalOptionalChange<EventTerminalStringMapDelta>
        switch subsequent.processEnvironment {
        case .unchanged:
            environment = processEnvironment
        case .setNil:
            environment = .setNil
        case let .setValue(next):
            switch processEnvironment {
            case .unchanged:
                environment = .setValue(next)
            case let .setValue(current):
                environment = .setValue(current.followed(by: next))
            case .setNil:
                // Applying a sparse edit to nil and then replaying it against an
                // unknown nonnil base would retain old keys. Fail closed; current
                // production enrichment only performs nil -> value or value -> nil.
                throw EventTerminalDeltaError.environmentResetCannotBeComposed
            }
        }

        return EventTerminalDelta(
            eventID: eventID,
            processUserName: Self.latest(
                processUserName,
                subsequent.processUserName
            ),
            processCodeSignature: Self.latest(
                processCodeSignature,
                subsequent.processCodeSignature
            ),
            processHashes: Self.latest(
                processHashes,
                subsequent.processHashes
            ),
            processEnvironment: environment,
            enrichments: enrichments.followed(by: subsequent.enrichments),
            severity: Self.latest(severity, subsequent.severity),
            reviewedRuleMatches: Self.latest(
                reviewedRuleMatches,
                subsequent.reviewedRuleMatches
            )
        )
    }

    /// Apply only explicit sparse edits to an immutable at-rest base.
    public func applying(to base: Event) throws -> Event {
        guard version == Self.schemaVersion, eventID == base.id else {
            throw EventTerminalDeltaError.eventIdentityChanged
        }

        let finalSeverity = severity.applying(to: base.severity)
        guard finalSeverity >= base.severity else {
            throw EventTerminalDeltaError.severityRegressed
        }
        let baseEnvironment = base.process.envVars.map(
            EventPrivacySanitizer.sanitizeDynamicMap
        )
        let finalEnvironment: [String: String]?
        switch processEnvironment {
        case .unchanged:
            finalEnvironment = baseEnvironment
        case .setNil:
            finalEnvironment = nil
        case let .setValue(delta):
            finalEnvironment = delta.applying(to: baseEnvironment ?? [:])
        }
        let process = ProcessInfo(
            pid: base.process.pid,
            ppid: base.process.ppid,
            rpid: base.process.rpid,
            name: base.process.name,
            executable: base.process.executable,
            commandLine: base.process.commandLine,
            args: base.process.args,
            workingDirectory: base.process.workingDirectory,
            userId: base.process.userId,
            userName: processUserName.applying(to: base.process.userName),
            groupId: base.process.groupId,
            startTime: base.process.startTime,
            exitCode: base.process.exitCode,
            codeSignature: processCodeSignature.applying(
                to: base.process.codeSignature
            ),
            ancestors: base.process.ancestors,
            architecture: base.process.architecture,
            isPlatformBinary: base.process.isPlatformBinary,
            hashes: processHashes.applying(to: base.process.hashes),
            session: base.process.session,
            envVars: finalEnvironment,
            auditIdentity: base.process.auditIdentity
        )
        let baseEnrichments = EventPrivacySanitizer.sanitizeDynamicMap(
            base.enrichments
        )
        let matches = reviewedRuleMatches.applying(
            to: ReviewedRuleMatches.normalized(
                EventPrivacySanitizer.sanitizeRuleMatches(base.ruleMatches)
            )
        )
        return Event(
            id: base.id,
            timestamp: base.timestamp,
            eventCategory: base.eventCategory,
            eventType: base.eventType,
            eventAction: base.eventAction,
            process: process,
            file: base.file,
            network: base.network,
            tcc: base.tcc,
            enrichments: enrichments.applying(to: baseEnrichments),
            severity: finalSeverity,
            ruleMatches: ReviewedRuleMatches.normalized(matches)
        )
    }

    public func changes(_ base: Event) throws -> Bool {
        _ = try applying(to: base)
        return !isEmpty
    }

    /// Validate the source boundary without first materializing any mutable
    /// terminal fields. The delta validator uses this before its structural
    /// overflow branch so an attacker-sized rejected value never enters the
    /// sanitizer or an intermediate dictionary allocation.
    package static func validateImmutableTransition(
        base: Event,
        terminal: Event
    ) throws {
        guard sameImmutableEventIdentity(base, terminal) else {
            throw EventTerminalDeltaError.eventIdentityChanged
        }
        guard sameImmutableProcessIdentity(base.process, terminal.process) else {
            throw EventTerminalDeltaError.processIdentityChanged
        }
        guard terminal.severity >= base.severity else {
            throw EventTerminalDeltaError.severityRegressed
        }
    }

    private static func optionalChange<Value>(
        from base: Value?,
        to terminal: Value?
    ) -> EventTerminalOptionalChange<Value>
    where Value: Codable & Sendable & Equatable {
        guard base != terminal else { return .unchanged }
        guard let terminal else { return .setNil }
        return .setValue(terminal)
    }

    private static func latest<Value>(
        _ current: EventTerminalRequiredChange<Value>,
        _ subsequent: EventTerminalRequiredChange<Value>
    ) -> EventTerminalRequiredChange<Value>
    where Value: Codable & Sendable & Equatable {
        switch subsequent {
        case .unchanged: return current
        case .setValue: return subsequent
        }
    }

    private static func latest<Value>(
        _ current: EventTerminalOptionalChange<Value>,
        _ subsequent: EventTerminalOptionalChange<Value>
    ) -> EventTerminalOptionalChange<Value>
    where Value: Codable & Sendable & Equatable {
        switch subsequent {
        case .unchanged: return current
        case .setNil, .setValue: return subsequent
        }
    }

    private static func sameImmutableEventIdentity(
        _ lhs: Event,
        _ rhs: Event
    ) -> Bool {
        lhs.id == rhs.id
            && lhs.timestamp == rhs.timestamp
            && lhs.eventCategory == rhs.eventCategory
            && lhs.eventType == rhs.eventType
            && lhs.eventAction == rhs.eventAction
            && lhs.file == rhs.file
            && lhs.network == rhs.network
            && lhs.tcc == rhs.tcc
    }

    private static func sameImmutableProcessIdentity(
        _ lhs: ProcessInfo,
        _ rhs: ProcessInfo
    ) -> Bool {
        lhs.pid == rhs.pid
            && lhs.ppid == rhs.ppid
            && lhs.rpid == rhs.rpid
            && lhs.name == rhs.name
            && lhs.executable == rhs.executable
            && lhs.commandLine == rhs.commandLine
            && lhs.args == rhs.args
            && lhs.workingDirectory == rhs.workingDirectory
            && lhs.userId == rhs.userId
            && lhs.groupId == rhs.groupId
            && lhs.startTime == rhs.startTime
            && lhs.exitCode == rhs.exitCode
            && lhs.ancestors == rhs.ancestors
            && lhs.architecture == rhs.architecture
            && lhs.isPlatformBinary == rhs.isPlatformBinary
            && lhs.session == rhs.session
            && lhs.auditIdentity == rhs.auditIdentity
    }
}

public struct EventTerminalDeltaOverflowEvidence: Codable, Sendable, Equatable {
    public enum Reason: String, Codable, Sendable, Equatable {
        case structuralPreflight = "structural_preflight"
        case canonicalDeltaCeiling = "canonical_delta_ceiling"
        case storageCapacity = "storage_capacity"
    }

    public let eventID: UUID
    public let baseCanonicalSHA256: Data
    public let sourceIdentitySHA256: Data
    public let originalBytes: Int
    public let originalSHA256: Data
    public let reason: Reason
}

public struct EventTerminalDeltaPreparation: Sendable, Equatable {
    public let eventID: UUID
    public let baseCanonicalSHA256: Data
    public let sourceIdentitySHA256: Data
    public let delta: EventTerminalDelta
    public let canonicalDeltaJSON: Data
    public let canonicalDeltaSHA256: Data
    public let retainedByteEstimate: Int
    public let overflow: EventTerminalDeltaOverflowEvidence?
}

public struct EventTerminalDeltaOutcome: Sendable, Equatable {
    public enum Disposition: Sendable, Equatable {
        case unchangedBase
        case inserted
        case alreadyDurable
        case poisoned(EventTerminalDeltaOverflowEvidence)
    }

    public let eventID: UUID
    public let disposition: Disposition
    public let canonicalDeltaSHA256: Data
    public let terminalCanonicalSHA256: Data?
    public let terminalCanonicalByteCount: Int
}

public struct EventTerminalDeltaBatchResult: Sendable, Equatable {
    public let inputCount: Int
    public let outcomes: [EventTerminalDeltaOutcome]
    public let committedTransactionCount: Int
    public let storageMutationGeneration: UInt64
}

public enum EventTerminalDeltaValidatorError: Error, Sendable, Equatable {
    case invalidBaseReceipt
}

/// Allocation-bounded terminal preparation. Structural sizing and the
/// content-bound overflow digest are completed before JSONEncoder can allocate
/// a payload that storage cannot persist.
public enum EventTerminalDeltaValidator {
    public static let maximumCanonicalDeltaBytes = 8 * 1_024 * 1_024 - 16
    /// One shared J reservation covers the typed delta graph, canonical bytes,
    /// and fixed encoder/sanitizer scratch. It deliberately aliases ingress J
    /// so the process-wide R/J/S forward-progress equation has one frozen cap.
    public static let maximumPreparationWorkspaceBytes =
        EventJournalAdmissionValidator.maximumPreparationWorkspaceBytes

    public static func prepare(
        base: Event,
        terminal: Event,
        baseCanonicalSHA256: Data,
        sourceIdentitySHA256: Data
    ) throws -> EventTerminalDeltaPreparation {
        guard baseCanonicalSHA256.count == 32,
              sourceIdentitySHA256.count == 32 else {
            throw EventTerminalDeltaValidatorError.invalidBaseReceipt
        }
        try EventTerminalDelta.validateImmutableTransition(
            base: base,
            terminal: terminal
        )
        var preflight = DeltaPreflight(
            eventID: terminal.id,
            baseCanonicalSHA256: baseCanonicalSHA256,
            sourceIdentitySHA256: sourceIdentitySHA256
        )
        preflight.measure(base: base, terminal: terminal)
        let sourceDigest = preflight.finalizeDigest()
        guard !preflight.overflowed else {
            return overflow(
                eventID: terminal.id,
                baseDigest: baseCanonicalSHA256,
                sourceIdentity: sourceIdentitySHA256,
                bytes: preflight.retainedBytes,
                digest: sourceDigest,
                reason: .structuralPreflight
            )
        }
        let delta = try EventTerminalDelta(base: base, terminal: terminal)

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let encoded = try encoder.encode(delta)
        guard encoded.count <= maximumCanonicalDeltaBytes else {
            return overflow(
                eventID: terminal.id,
                baseDigest: baseCanonicalSHA256,
                sourceIdentity: sourceIdentitySHA256,
                bytes: preflight.retainedBytes,
                digest: sourceDigest,
                reason: .canonicalDeltaCeiling
            )
        }
        let charge = preflight.retainedBytes.addingReportingOverflow(
            encoded.count + 4_096
        )
        return EventTerminalDeltaPreparation(
            eventID: terminal.id,
            baseCanonicalSHA256: baseCanonicalSHA256,
            sourceIdentitySHA256: sourceIdentitySHA256,
            delta: delta,
            canonicalDeltaJSON: encoded,
            canonicalDeltaSHA256: Data(SHA256.hash(data: encoded)),
            retainedByteEstimate: charge.overflow
                ? Int.max : charge.partialValue,
            overflow: nil
        )
    }

    /// Prepare an already-composed sparse delta. This is the deferred path: it
    /// never needs to retain a second copy of the immutable raw base Event.
    public static func prepare(
        delta: EventTerminalDelta,
        baseCanonicalSHA256: Data,
        sourceIdentitySHA256: Data
    ) throws -> EventTerminalDeltaPreparation {
        guard baseCanonicalSHA256.count == 32,
              sourceIdentitySHA256.count == 32,
              delta.version == EventTerminalDelta.schemaVersion else {
            throw EventTerminalDeltaValidatorError.invalidBaseReceipt
        }
        var preflight = DeltaPreflight(
            eventID: delta.eventID,
            baseCanonicalSHA256: baseCanonicalSHA256,
            sourceIdentitySHA256: sourceIdentitySHA256
        )
        preflight.measure(delta: delta)
        let sourceDigest = preflight.finalizeDigest()
        guard !preflight.overflowed else {
            return overflow(
                eventID: delta.eventID,
                baseDigest: baseCanonicalSHA256,
                sourceIdentity: sourceIdentitySHA256,
                bytes: preflight.retainedBytes,
                digest: sourceDigest,
                reason: .structuralPreflight
            )
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let encoded = try encoder.encode(delta)
        guard encoded.count <= maximumCanonicalDeltaBytes else {
            return overflow(
                eventID: delta.eventID,
                baseDigest: baseCanonicalSHA256,
                sourceIdentity: sourceIdentitySHA256,
                bytes: preflight.retainedBytes,
                digest: sourceDigest,
                reason: .canonicalDeltaCeiling
            )
        }
        let charge = preflight.retainedBytes.addingReportingOverflow(
            encoded.count + 4_096
        )
        return EventTerminalDeltaPreparation(
            eventID: delta.eventID,
            baseCanonicalSHA256: baseCanonicalSHA256,
            sourceIdentitySHA256: sourceIdentitySHA256,
            delta: delta,
            canonicalDeltaJSON: encoded,
            canonicalDeltaSHA256: Data(SHA256.hash(data: encoded)),
            retainedByteEstimate: charge.overflow
                ? Int.max : charge.partialValue,
            overflow: nil
        )
    }

    private static func overflow(
        eventID: UUID,
        baseDigest: Data,
        sourceIdentity: Data,
        bytes: Int,
        digest: Data,
        reason: EventTerminalDeltaOverflowEvidence.Reason
    ) -> EventTerminalDeltaPreparation {
        let evidence = EventTerminalDeltaOverflowEvidence(
            eventID: eventID,
            baseCanonicalSHA256: baseDigest,
            sourceIdentitySHA256: sourceIdentity,
            originalBytes: bytes,
            originalSHA256: digest,
            reason: reason
        )
        return EventTerminalDeltaPreparation(
            eventID: eventID,
            baseCanonicalSHA256: baseDigest,
            sourceIdentitySHA256: sourceIdentity,
            delta: EventTerminalDelta(eventID: eventID),
            canonicalDeltaJSON: Data(),
            canonicalDeltaSHA256: digest,
            retainedByteEstimate: 4_096,
            overflow: evidence
        )
    }

    private struct DeltaPreflight {
        private var hasher = SHA256()
        private(set) var retainedBytes = 0
        private var elements = 0
        private var limitExceeded = false

        var overflowed: Bool {
            limitExceeded
                || retainedBytes > EventJournalAdmissionValidator
                    .maximumAcceptedSourceRetainedBytes
                || elements > EventJournalAdmissionValidator
                    .maximumPreflightElements
        }

        init(
            eventID: UUID,
            baseCanonicalSHA256: Data,
            sourceIdentitySHA256: Data
        ) {
            update("maccrab-terminal-delta-source-v1")
            update(eventID.uuidString.lowercased())
            update(baseCanonicalSHA256)
            update(sourceIdentitySHA256)
        }

        mutating func measure(base: Event, terminal: Event) {
            if base.process.userName != terminal.process.userName {
                field("process.userName", terminal.process.userName)
            }
            optionalCodeSignature(
                base.process.codeSignature,
                terminal.process.codeSignature
            )
            optionalHashes(base.process.hashes, terminal.process.hashes)
            map(
                "process.envVars",
                base.process.envVars ?? [:],
                terminal.process.envVars ?? [:],
                nilChanged: (base.process.envVars == nil)
                    != (terminal.process.envVars == nil)
            )
            map("enrichments", base.enrichments, terminal.enrichments)
            if base.severity != terminal.severity {
                field("severity", terminal.severity.rawValue)
            }
            let baseMatches = ReviewedRuleMatches.normalized(base.ruleMatches)
            let terminalMatches = ReviewedRuleMatches.normalized(
                terminal.ruleMatches
            )
            if baseMatches != terminalMatches {
                update("reviewedRuleMatches")
                element()
                for match in terminalMatches {
                    field("ruleId", match.ruleId)
                    field("ruleName", match.ruleName)
                    field("severity", match.severity.rawValue)
                    field("description", match.description)
                    strings("mitreTechniques", match.mitreTechniques)
                    strings("tags", match.tags)
                    field("suppressible", match.suppressible ? "1" : "0")
                }
            }
        }

        mutating func measure(delta: EventTerminalDelta) {
            switch delta.processUserName {
            case .unchanged: break
            case let .setValue(value): field("process.userName", value)
            }
            switch delta.processCodeSignature {
            case .unchanged: break
            case .setNil:
                update("process.codeSignature")
                element()
                update("nil")
            case let .setValue(value):
                codeSignature(value)
            }
            switch delta.processHashes {
            case .unchanged: break
            case .setNil:
                update("process.hashes")
                element()
                update("nil")
            case let .setValue(value):
                hashes(value)
            }
            switch delta.processEnvironment {
            case .unchanged: break
            case .setNil:
                update("process.envVars")
                element()
                update("nil")
            case let .setValue(value):
                mapDelta("process.envVars", value)
            }
            mapDelta("enrichments", delta.enrichments)
            switch delta.severity {
            case .unchanged: break
            case let .setValue(value): field("severity", value.rawValue)
            }
            switch delta.reviewedRuleMatches {
            case .unchanged: break
            case let .setValue(matches):
                update("reviewedRuleMatches")
                element()
                for match in matches {
                    field("ruleId", match.ruleId)
                    field("ruleName", match.ruleName)
                    field("severity", match.severity.rawValue)
                    field("description", match.description)
                    strings("mitreTechniques", match.mitreTechniques)
                    strings("tags", match.tags)
                    field("suppressible", match.suppressible ? "1" : "0")
                }
            }
        }

        mutating func finalizeDigest() -> Data {
            Data(hasher.finalize())
        }

        private mutating func optionalHashes(
            _ base: ProcessHashes?,
            _ terminal: ProcessHashes?
        ) {
            guard base != terminal else { return }
            update("process.hashes")
            element()
            guard let terminal else { update("nil"); return }
            optionalField("sha256", terminal.sha256)
            optionalField("cdhash", terminal.cdhash)
            optionalField("md5", terminal.md5)
        }

        private mutating func hashes(_ value: ProcessHashes) {
            update("process.hashes")
            element()
            optionalField("sha256", value.sha256)
            optionalField("cdhash", value.cdhash)
            optionalField("md5", value.md5)
        }

        private mutating func optionalCodeSignature(
            _ base: CodeSignatureInfo?,
            _ terminal: CodeSignatureInfo?
        ) {
            guard base != terminal else { return }
            update("process.codeSignature")
            element()
            guard let terminal else { update("nil"); return }
            field("signerType", terminal.signerType.rawValue)
            optionalField("teamId", terminal.teamId)
            optionalField("signingId", terminal.signingId)
            strings("authorities", terminal.authorities)
            field("flags", String(terminal.flags))
            field("isNotarized", terminal.isNotarized ? "1" : "0")
            optionalStrings("issuerChain", terminal.issuerChain)
            optionalStrings("certHashes", terminal.certHashes)
            if let value = terminal.isAdhocSigned {
                field("isAdhocSigned", value ? "1" : "0")
            } else { update("isAdhocSigned:nil") }
            optionalStrings("entitlements", terminal.entitlements)
        }

        private mutating func codeSignature(_ value: CodeSignatureInfo) {
            update("process.codeSignature")
            element()
            field("signerType", value.signerType.rawValue)
            optionalField("teamId", value.teamId)
            optionalField("signingId", value.signingId)
            strings("authorities", value.authorities)
            field("flags", String(value.flags))
            field("isNotarized", value.isNotarized ? "1" : "0")
            optionalStrings("issuerChain", value.issuerChain)
            optionalStrings("certHashes", value.certHashes)
            if let adhoc = value.isAdhocSigned {
                field("isAdhocSigned", adhoc ? "1" : "0")
            } else { update("isAdhocSigned:nil") }
            optionalStrings("entitlements", value.entitlements)
        }

        private mutating func mapDelta(
            _ name: String,
            _ delta: EventTerminalStringMapDelta
        ) {
            guard !delta.isEmpty else { return }
            update(name)
            element()
            for key in delta.removals.sorted() {
                field("key", key)
                update("removed")
            }
            for key in delta.upserts.keys.sorted() {
                field("key", key)
                field("value", delta.upserts[key] ?? "")
            }
        }

        private mutating func map(
            _ name: String,
            _ base: [String: String],
            _ terminal: [String: String],
            nilChanged: Bool = false
        ) {
            let keys = Set(base.keys).union(terminal.keys).sorted()
            let changed = keys.filter { base[$0] != terminal[$0] }
            guard nilChanged || !changed.isEmpty else { return }
            update(name)
            element()
            update(nilChanged ? "optional-changed" : "present")
            for key in changed {
                field("key", key)
                optionalField("value", terminal[key])
            }
        }

        private mutating func optionalStrings(
            _ name: String,
            _ values: [String]?
        ) {
            guard let values else { update(name + ":nil"); return }
            strings(name, values)
        }

        private mutating func strings(_ name: String, _ values: [String]) {
            update(name)
            element()
            for value in values { string(value) }
        }

        private mutating func optionalField(
            _ name: String,
            _ value: String?
        ) {
            if let value { field(name, value) }
            else { update(name + ":nil") }
        }

        private mutating func field(_ name: String, _ value: String) {
            update(name)
            string(value)
        }

        private mutating func string(_ value: String) {
            element()
            let byteCount = value.utf8.count
            if byteCount > EventJournalAdmissionValidator
                .maximumPreflightStringBytes {
                limitExceeded = true
            }
            addRetained(byteCount)
            updateLength(byteCount)
            var chunk: [UInt8] = []
            chunk.reserveCapacity(4_096)
            for byte in value.utf8 {
                chunk.append(byte)
                if chunk.count == 4_096 {
                    update(Data(chunk))
                    chunk.removeAll(keepingCapacity: true)
                }
            }
            if !chunk.isEmpty { update(Data(chunk)) }
        }

        private mutating func element() {
            if elements < Int.max { elements += 1 }
            else { limitExceeded = true }
            addRetained(64)
        }

        private mutating func addRetained(_ bytes: Int) {
            let sum = retainedBytes.addingReportingOverflow(max(0, bytes))
            retainedBytes = sum.overflow ? Int.max : sum.partialValue
            if sum.overflow { limitExceeded = true }
        }

        private mutating func update(_ value: String) {
            updateLength(value.utf8.count)
            hasher.update(data: Data(value.utf8))
        }

        private mutating func update(_ data: Data) {
            updateLength(data.count)
            hasher.update(data: data)
        }

        private mutating func updateLength(_ value: Int) {
            var encoded = UInt64(clamping: value).bigEndian
            withUnsafeBytes(of: &encoded) {
                hasher.update(bufferPointer: $0)
            }
        }
    }
}
