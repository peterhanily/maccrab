// Event.swift
// MacCrabCore
//
// Central event type for the MacCrab macOS security detection engine.
// Uses Elastic Common Schema (ECS) field names for Sigma rule compatibility.

import Foundation

// MARK: - Event

/// A single security-relevant event captured by MacCrab.
///
/// Every event carries full process context plus optional payloads for file,
/// network, or TCC activity. Enrichment plugins and the detection engine
/// annotate the event through `enrichments` and `ruleMatches`.
///
/// Conforms to `Codable` for serialization and `Sendable` for safe passage
/// across concurrency boundaries.
public struct Event: Codable, Sendable, Hashable, Identifiable {

    // MARK: Core fields

    /// Unique identifier for this event instance.
    public let id: UUID

    /// Time at which the event was captured.
    public let timestamp: Date

    /// High-level category (ECS `event.category`).
    public let eventCategory: EventCategory

    /// Type of action (ECS `event.type`).
    public let eventType: EventType

    /// Detailed action string (ECS `event.action`).
    /// Examples: `"exec"`, `"fork"`, `"exit"`, `"create"`, `"write"`, `"rename"`,
    /// `"unlink"`, `"close"`, `"signal"`, `"kextload"`, `"tcc_grant"`, `"tcc_revoke"`.
    public let eventAction: String

    // MARK: Context payloads

    /// The process that caused this event. Always present.
    public let process: ProcessInfo

    /// File metadata, present when `eventCategory == .file`.
    public let file: FileInfo?

    /// Network metadata, present when `eventCategory == .network`.
    public let network: NetworkInfo?

    /// TCC permission metadata, present when `eventCategory == .tcc`.
    public let tcc: TCCInfo?

    // MARK: Enrichment & detection

    /// Key-value pairs added by enrichment plugins after initial capture.
    public var enrichments: [String: String]

    /// Severity assigned to the event (defaults to `.informational`).
    public var severity: Severity

    /// Detection rules that matched this event, populated by the detection engine.
    public var ruleMatches: [RuleMatch]

    // MARK: Initializer

    public init(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        eventCategory: EventCategory,
        eventType: EventType,
        eventAction: String,
        process: ProcessInfo,
        file: FileInfo? = nil,
        network: NetworkInfo? = nil,
        tcc: TCCInfo? = nil,
        enrichments: [String: String] = [:],
        severity: Severity = .informational,
        ruleMatches: [RuleMatch] = []
    ) {
        self.id = id
        self.timestamp = timestamp
        self.eventCategory = eventCategory
        self.eventType = eventType
        self.eventAction = eventAction
        self.process = process
        self.file = file
        self.network = network
        self.tcc = tcc
        self.enrichments = enrichments
        self.severity = severity
        self.ruleMatches = ruleMatches
    }
}

// MARK: - Sigma field accessors

extension Event {

    /// Sigma `Image` -- full path to the process executable.
    public var Image: String { process.executable }

    /// Sigma `CommandLine` -- full command line string.
    public var CommandLine: String { process.commandLine }

    /// Sigma `User` -- user name that owns the process.
    public var User: String { process.userName }

    /// Sigma `ParentImage` -- executable path of the direct parent, if known.
    public var ParentImage: String? { process.ancestors.first?.executable }

    /// Sigma `ParentCommandLine` is not directly available (would require parent
    /// process lookup); returns `nil` to signal the field is unresolved.
    public var ParentCommandLine: String? { nil }

    /// Sigma `TargetFilename` -- target file path for file events.
    public var TargetFilename: String? { file?.path }

    /// Sigma `SourceFilename` -- source path for rename events.
    public var SourceFilename: String? { file?.sourcePath }

    /// Sigma `DestinationIp` -- destination IP for network events.
    public var DestinationIp: String? { network?.destinationIp }

    /// Sigma `DestinationPort` -- destination port for network events.
    public var DestinationPort: UInt16? { network?.destinationPort }

    /// Sigma `DestinationHostname` -- resolved hostname for network events.
    public var DestinationHostname: String? { network?.destinationHostname }

    /// Sigma `SourceIp` -- source IP for network events.
    public var SourceIp: String? { network?.sourceIp }

    /// Sigma `SourcePort` -- source port for network events.
    public var SourcePort: UInt16? { network?.sourcePort }
}

// MARK: - RuleMatch

/// Records a single detection rule match against an event.
public struct RuleMatch: Codable, Sendable, Hashable {

    /// Unique identifier for the rule that matched.
    public let ruleId: String

    /// Human-readable name of the rule.
    public let ruleName: String

    /// Severity assigned by the rule definition.
    public let severity: Severity

    /// Free-form description of why the rule matched.
    public let description: String

    /// MITRE ATT&CK technique IDs associated with the rule, if any.
    public let mitreTechniques: [String]

    /// Tags from the rule definition (e.g. `["persistence", "defense_evasion"]`).
    public let tags: [String]

    public init(
        ruleId: String,
        ruleName: String,
        severity: Severity,
        description: String,
        mitreTechniques: [String] = [],
        tags: [String] = []
    ) {
        self.ruleId = ruleId
        self.ruleName = ruleName
        self.severity = severity
        self.description = description
        self.mitreTechniques = mitreTechniques
        self.tags = tags
    }
}
