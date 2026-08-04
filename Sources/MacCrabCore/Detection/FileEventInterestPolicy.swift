// FileEventInterestPolicy.swift
// MacCrabCore
//
// Conservative, rule-derived admission for high-rate file callbacks.
//
// This policy answers only one question: can every enabled downstream file
// consumer be proven impossible from fields that are already known at the
// callback boundary?  Unknown fields, unsupported predicates, stale dynamic
// state, malformed descriptor trees, and incomplete descriptor snapshots all
// admit.  It is therefore safe to place before retained-message allocation,
// enrichment, rule evaluation, sequence buffering, and graph/storage writes.

import Dispatch
import Foundation
import os

// MARK: - Callback facts and source capabilities

/// A callback fact distinguishes "not supplied yet" from "known absent".
/// That distinction is load-bearing for negated predicates: RuleEngine treats
/// a missing field as a raw false match, which becomes true when negated, while
/// an unknown callback field might acquire a value during enrichment.
public enum FileEventFact<Value: Sendable & Equatable>: Sendable, Equatable {
    case unknown
    case absent
    case value(Value)

    public static func known(_ value: Value?) -> Self {
        value.map(Self.value) ?? .absent
    }
}

/// Ingress families that all become `file_event` after normalisation but do
/// not expose the same fields.  In particular, an ordinary ES file callback
/// can never acquire BTM-only metadata, whereas NOTIFY_BTM_LAUNCH_ITEM_ADD can.
public enum FileEventAdmissionSource: String, CaseIterable, Sendable, Hashable {
    case endpointSecurityFile = "endpoint_security_file"
    case endpointSecurityBTM = "endpoint_security_btm"
    case other
    case unknown

    public var capabilities: FileEventSourceCapabilities {
        switch self {
        case .endpointSecurityFile:
            return [.fileMetadata, .eventMetadata, .processIdentity, .codeSignature]
        case .endpointSecurityBTM:
            return [.fileMetadata, .eventMetadata, .processIdentity, .codeSignature, .btmMetadata]
        case .other, .unknown:
            // An unclassified source carries no authoritative absence claims.
            return []
        }
    }

    fileprivate var hasAuthoritativeCapabilities: Bool {
        self == .endpointSecurityFile || self == .endpointSecurityBTM
    }
}

public struct FileEventSourceCapabilities: OptionSet, Sendable, Hashable {
    public let rawValue: UInt8

    public init(rawValue: UInt8) { self.rawValue = rawValue }

    public static let fileMetadata = Self(rawValue: 1 << 0)
    public static let eventMetadata = Self(rawValue: 1 << 1)
    public static let processIdentity = Self(rawValue: 1 << 2)
    public static let codeSignature = Self(rawValue: 1 << 3)
    public static let btmMetadata = Self(rawValue: 1 << 4)
}

/// Fixed-layout callback facts.  The hot ES caller can populate this without a
/// dictionary or an `Event` allocation.  Fields that require later process
/// cache/enrichment work stay `.unknown`; a source-exclusive impossible field
/// is resolved to `.absent` by the source capability table.
public struct FileEventAdmissionFacts: Sendable, Equatable {
    public let source: FileEventAdmissionSource

    public let filePath: FileEventFact<String>
    public let fileName: FileEventFact<String>
    public let fileDirectory: FileEventFact<String>
    public let fileExtension: FileEventFact<String>
    public let fileSize: FileEventFact<String>
    public let fileAction: FileEventFact<String>
    public let fileSourcePath: FileEventFact<String>

    public let eventCategory: FileEventFact<String>
    public let eventType: FileEventFact<String>
    public let eventAction: FileEventFact<String>

    public let processID: FileEventFact<Int32>
    public let processExecutable: FileEventFact<String>
    public let processName: FileEventFact<String>
    public let processCommandLine: FileEventFact<String>
    public let parentExecutable: FileEventFact<String>
    public let signerType: FileEventFact<String>
    public let isPlatformBinary: FileEventFact<String>

    public let btmItemType: FileEventFact<String>
    public let btmLegacy: FileEventFact<String>
    public let btmManaged: FileEventFact<String>

    /// Values produced by the graph classifier/generator contract.  They are
    /// intentionally facts rather than a duplicate path classifier here.
    public let graphFileKind: FileEventFact<String>
    public let graphUntrustedContent: FileEventFact<Bool>
    public let graphPersistenceType: FileEventFact<String>

    public init(
        source: FileEventAdmissionSource = .unknown,
        filePath: FileEventFact<String> = .unknown,
        fileName: FileEventFact<String> = .unknown,
        fileDirectory: FileEventFact<String> = .unknown,
        fileExtension: FileEventFact<String> = .unknown,
        fileSize: FileEventFact<String> = .unknown,
        fileAction: FileEventFact<String> = .unknown,
        fileSourcePath: FileEventFact<String> = .unknown,
        eventCategory: FileEventFact<String> = .value(EventCategory.file.rawValue),
        eventType: FileEventFact<String> = .unknown,
        eventAction: FileEventFact<String> = .unknown,
        processID: FileEventFact<Int32> = .unknown,
        processExecutable: FileEventFact<String> = .unknown,
        processName: FileEventFact<String> = .unknown,
        processCommandLine: FileEventFact<String> = .unknown,
        parentExecutable: FileEventFact<String> = .unknown,
        signerType: FileEventFact<String> = .unknown,
        isPlatformBinary: FileEventFact<String> = .unknown,
        btmItemType: FileEventFact<String> = .unknown,
        btmLegacy: FileEventFact<String> = .unknown,
        btmManaged: FileEventFact<String> = .unknown,
        graphFileKind: FileEventFact<String> = .unknown,
        graphUntrustedContent: FileEventFact<Bool> = .unknown,
        graphPersistenceType: FileEventFact<String> = .unknown
    ) {
        self.source = source
        self.filePath = filePath
        self.fileName = fileName
        self.fileDirectory = fileDirectory
        self.fileExtension = fileExtension
        self.fileSize = fileSize
        self.fileAction = fileAction
        self.fileSourcePath = fileSourcePath
        self.eventCategory = eventCategory
        self.eventType = eventType
        self.eventAction = eventAction
        self.processID = processID
        self.processExecutable = processExecutable
        self.processName = processName
        self.processCommandLine = processCommandLine
        self.parentExecutable = parentExecutable
        self.signerType = signerType
        self.isPlatformBinary = isPlatformBinary
        self.btmItemType = btmItemType
        self.btmLegacy = btmLegacy
        self.btmManaged = btmManaged
        self.graphFileKind = graphFileKind
        self.graphUntrustedContent = graphUntrustedContent
        self.graphPersistenceType = graphPersistenceType
    }

    /// Convenience for the ordinary ES file family.  `sourcePath == nil` is a
    /// known absence only for non-rename callbacks; callers can pass `.unknown`
    /// through the full initializer if the raw event has not exposed it yet.
    public static func endpointSecurity(
        path: String,
        fileAction: FileAction,
        eventAction: String,
        eventType: EventType,
        sourcePath: String? = nil,
        processID: Int32? = nil,
        processExecutable: String? = nil,
        processName: String? = nil,
        processCommandLine: FileEventFact<String> = .unknown,
        parentExecutable: FileEventFact<String> = .unknown,
        signerType: FileEventFact<String> = .unknown,
        isPlatformBinary: Bool? = nil,
        graphFileKind: FileEventFact<String> = .unknown,
        graphUntrustedContent: FileEventFact<Bool> = .unknown,
        graphPersistenceType: FileEventFact<String> = .unknown
    ) -> Self {
        let nsPath = path as NSString
        let ext = nsPath.pathExtension
        return Self(
            source: .endpointSecurityFile,
            filePath: .value(path),
            fileName: .value(nsPath.lastPathComponent),
            fileDirectory: .value(nsPath.deletingLastPathComponent),
            fileExtension: ext.isEmpty ? .absent : .value(ext),
            fileAction: .value(fileAction.rawValue),
            fileSourcePath: .known(sourcePath),
            eventType: .value(eventType.rawValue),
            eventAction: .value(eventAction),
            processID: processID.map { .value($0) } ?? .unknown,
            processExecutable: processExecutable.map { .value($0) } ?? .unknown,
            processName: processName.map { .value($0) } ?? .unknown,
            processCommandLine: processCommandLine,
            parentExecutable: parentExecutable,
            signerType: signerType,
            isPlatformBinary: isPlatformBinary.map { .value(String($0)) } ?? .unknown,
            graphFileKind: graphFileKind,
            graphUntrustedContent: graphUntrustedContent,
            graphPersistenceType: graphPersistenceType
        )
    }
}

// MARK: - Dynamic AI consumer demand

/// The action namespace is explicit so `FileAction.close` is never confused
/// with normalised `event.action == close_modified`.
public enum DynamicFileEventActionDemand: Sendable, Equatable {
    case any
    case fileActions(Set<String>)
    case eventActions(Set<String>)
}

/// Generic path demand published by the dynamic consumer owner.  The policy
/// deliberately does not duplicate CredentialFence, ProjectBoundary, or file
/// scanner classifiers; those owners publish the exact current demand.
public enum DynamicFileEventPathDemand: Sendable, Equatable {
    case any
    /// Canonical semantic classifiers. These cases deliberately call the
    /// downstream owner's implementation instead of copying extension/path
    /// lists into the callback policy, where they would inevitably drift.
    case supportedTextFile
    case agentContentFile
    case defaultCredentialFence
    case projectBoundaryOutside(roots: [String])
    case equals([String], caseInsensitive: Bool)
    case prefixes([String], caseInsensitive: Bool)
    case suffixes([String], caseInsensitive: Bool)
    case contains([String], caseInsensitive: Bool)
    case extensions(Set<String>, caseInsensitive: Bool)
    case outsideRoots([String], caseInsensitive: Bool)
    /// ProjectBoundary-style demand: match paths outside every project root,
    /// except exact device sinks and slash-bounded cache/build/temp fragments
    /// the owner publishes from its authoritative exception set.
    case outsideRootsExcluding(
        roots: [String],
        allowedExact: Set<String>,
        allowedSubstrings: [String],
        caseInsensitive: Bool
    )
}

/// Every dynamic AI file consumer is named so a snapshot can be audited as a
/// census rather than an opaque union of path patterns. `agentLineageContext`
/// is intentionally narrow: the prompt-intent bridge consumes completed text
/// reads. It does not justify retaining every temp/cache write made by an AI
/// subprocess.
public enum AIFileEventConsumer: String, CaseIterable, Sendable, Hashable {
    case credentialFence = "credential_fence"
    case projectBoundary = "project_boundary"
    case fileInjectionScanner = "file_injection_scanner"
    case injectionEvidence = "injection_evidence"
    case agentLineageContext = "agent_lineage_context"
    case persistenceBehavior = "persistence_behavior"
}

public struct DynamicAIFileEventDemand: Sendable, Equatable {
    /// `nil` means every process.  AI owners should normally publish one entry
    /// per attributed PID so unrelated callbacks can be proven irrelevant.
    public let processID: Int32?
    public let consumer: AIFileEventConsumer?
    public let action: DynamicFileEventActionDemand
    public let path: DynamicFileEventPathDemand

    public init(
        processID: Int32? = nil,
        consumer: AIFileEventConsumer? = nil,
        action: DynamicFileEventActionDemand = .any,
        path: DynamicFileEventPathDemand = .any
    ) {
        self.processID = processID
        self.consumer = consumer
        self.action = action
        self.path = path
    }
}

/// Complete owner-side session facts used to build callback demand. The
/// publisher supplies roots from ProjectBoundary's authoritative live view;
/// an empty root means that consumer is inactive for this session and must not
/// be represented as an unbounded outside-root demand.
public struct DynamicAIFileEventSession: Sendable, Equatable {
    public let rootProcessID: Int32
    public let childProcessIDs: Set<Int32>
    public let projectRoots: [String]

    public init(
        rootProcessID: Int32,
        childProcessIDs: Set<Int32> = [],
        projectRoots: [String] = []
    ) {
        self.rootProcessID = rootProcessID
        self.childProcessIDs = childProcessIDs
        self.projectRoots = projectRoots
    }

    fileprivate var allProcessIDs: Set<Int32> {
        childProcessIDs.union([rootProcessID])
    }
}

/// Fresh, empty demand means no AI file consumer is active.  Unknown or stale
/// demand means admission: a restrictive stale PID list could otherwise blind
/// the first callback from a newly-created AI child.
public struct DynamicAIFileEventDemandSnapshot: Sendable, Equatable {
    public enum State: Sendable, Equatable { case unknown, current }

    public let state: State
    public let validUntilUptimeNanoseconds: UInt64
    /// Complete, fresh AI attribution set, independent of whether a process has
    /// a ProjectBoundary or another path-specific demand entry.
    public let attributedProcessIDs: Set<Int32>
    public let demands: [DynamicAIFileEventDemand]

    private init(
        state: State,
        validUntilUptimeNanoseconds: UInt64,
        attributedProcessIDs: Set<Int32>,
        demands: [DynamicAIFileEventDemand]
    ) {
        self.state = state
        self.validUntilUptimeNanoseconds = validUntilUptimeNanoseconds
        self.attributedProcessIDs = attributedProcessIDs
        self.demands = demands
    }

    public static let unknown = Self(
        state: .unknown,
        validUntilUptimeNanoseconds: 0,
        attributedProcessIDs: [],
        demands: []
    )

    public static func current(
        validUntilUptimeNanoseconds: UInt64,
        attributedProcessIDs: Set<Int32> = [],
        demands: [DynamicAIFileEventDemand]
    ) -> Self {
        Self(
            state: .current,
            validUntilUptimeNanoseconds: validUntilUptimeNanoseconds,
            attributedProcessIDs: attributedProcessIDs,
            demands: demands
        )
    }

    /// Build the complete demand of the current AI file feature set. Each
    /// consumer remains explicit even where another demand currently subsumes
    /// it; the census then catches a feature being added downstream without a
    /// callback contract.
    public static func currentCanonical(
        validUntilUptimeNanoseconds: UInt64,
        sessions: [DynamicAIFileEventSession]
    ) -> Self {
        let mutationActions = ProjectBoundary.mutationEventActions
        let persistenceFragments = [
            "/LaunchAgents/", "/LaunchDaemons/", "/StartupItems/",
            ".zshrc", ".bashrc", ".bash_profile",
        ]

        var attributed = Set<Int32>()
        var demands: [DynamicAIFileEventDemand] = []
        for session in sessions {
            let processIDs = session.allProcessIDs.sorted()
            attributed.formUnion(processIDs)
            for pid in processIDs {
                // The scanner's canonical classifier includes leading-dot
                // files such as `.env`; NSString.pathExtension alone does not.
                demands.append(DynamicAIFileEventDemand(
                    processID: pid,
                    consumer: .fileInjectionScanner,
                    action: .eventActions(["open", "close_modified"]),
                    path: .supportedTextFile
                ))
                demands.append(DynamicAIFileEventDemand(
                    processID: pid,
                    consumer: .injectionEvidence,
                    action: .eventActions(["open"]),
                    path: .agentContentFile
                ))
                // PromptIntentBridge reads only fileRead entries from the
                // lineage. General text OPENs (README.md, CLAUDE.md, source)
                // are its useful corpus; raw write volume is not.
                demands.append(DynamicAIFileEventDemand(
                    processID: pid,
                    consumer: .agentLineageContext,
                    action: .eventActions(["open"]),
                    path: .supportedTextFile
                ))
                demands.append(DynamicAIFileEventDemand(
                    processID: pid,
                    consumer: .credentialFence,
                    action: .any,
                    path: .defaultCredentialFence
                ))
                demands.append(DynamicAIFileEventDemand(
                    processID: pid,
                    consumer: .persistenceBehavior,
                    action: .eventActions(mutationActions),
                    path: .contains(persistenceFragments, caseInsensitive: false)
                ))
                if !session.projectRoots.isEmpty {
                    demands.append(DynamicAIFileEventDemand(
                        processID: pid,
                        consumer: .projectBoundary,
                        action: .eventActions(mutationActions),
                        path: .projectBoundaryOutside(roots: session.projectRoots)
                    ))
                }
            }
        }
        return .current(
            validUntilUptimeNanoseconds: validUntilUptimeNanoseconds,
            attributedProcessIDs: attributed,
            demands: demands
        )
    }

    public var consumerCensus: [AIFileEventConsumer: Int] {
        var result: [AIFileEventConsumer: Int] = [:]
        for demand in demands {
            if let consumer = demand.consumer {
                result[consumer, default: 0] += 1
            }
        }
        return result
    }
}

// MARK: - Deception semantic snapshot

/// Complete callback-safe view of every path that downstream enrichment can
/// label `IsHoneyfile=true`.
///
/// The ES callback must never consult either deception actor.  Their owners
/// publish this immutable set after manifest load/deploy/remove completes and
/// invalidate it before beginning a mutation. Unknown or expired state is
/// deliberately fail-open because rejecting while a newly-deployed canary is
/// absent from the snapshot would blind the must-fire deception rule.
public struct HoneyfilePathSnapshot: Sendable, Equatable {
    public enum State: Sendable, Equatable { case unknown, current }

    public let state: State
    public let validUntilUptimeNanoseconds: UInt64
    public let paths: Set<String>

    private init(
        state: State,
        validUntilUptimeNanoseconds: UInt64,
        paths: Set<String>
    ) {
        self.state = state
        self.validUntilUptimeNanoseconds = validUntilUptimeNanoseconds
        self.paths = paths
    }

    public static let unknown = Self(
        state: .unknown,
        validUntilUptimeNanoseconds: 0,
        paths: []
    )

    public static func current(
        paths: Set<String>,
        validUntilUptimeNanoseconds: UInt64
    ) -> Self {
        Self(
            state: .current,
            validUntilUptimeNanoseconds: validUntilUptimeNanoseconds,
            paths: paths
        )
    }

    /// A complete deception view is the union of the credential honeyfiles
    /// and AI-context honey-prompts. If either owner is unknown, the union is
    /// unknown; publishing a partial union would be an unsafe false negative.
    public func merging(_ other: Self) -> Self {
        guard state == .current, other.state == .current else { return .unknown }
        return .current(
            paths: paths.union(other.paths),
            validUntilUptimeNanoseconds: min(
                validUntilUptimeNanoseconds,
                other.validUntilUptimeNanoseconds
            )
        )
    }

    fileprivate func semanticFact(
        for facts: FileEventAdmissionFacts,
        nowUptimeNanoseconds: UInt64
    ) -> FileEventFact<String> {
        guard state == .current,
              nowUptimeNanoseconds <= validUntilUptimeNanoseconds else {
            return .unknown
        }
        switch facts.filePath {
        case .unknown:
            return .unknown
        case .absent:
            return .absent
        case .value(let path):
            // EventEnricher leaves the field absent for ordinary paths; it
            // does not materialize the string "false".
            return paths.contains(path) ? .value("true") : .absent
        }
    }
}

// MARK: - Built-in descriptors and complete snapshots

public struct BuiltinFileEventRequirement: Sendable {
    public enum Kind: Sendable {
        case predicates(
            predicates: [Predicate],
            condition: RuleCondition,
            conditionTree: ConditionNode?
        )
        case crossProcessCorrelation
        case dynamicAIConsumers
        case unconditional
    }

    public let id: String
    /// nil means every source.  An unknown source never fails a source scope.
    public let sources: Set<FileEventAdmissionSource>?
    public let kind: Kind

    public init(
        id: String,
        sources: Set<FileEventAdmissionSource>? = nil,
        kind: Kind
    ) {
        self.id = id
        self.sources = sources
        self.kind = kind
    }
}

extension BuiltinRuleCatalog {
    /// Hardcoded EventLoop consumers of file events.  AI consumers are dynamic
    /// because their useful process/path surface changes with active sessions;
    /// CrossProcessCorrelator owns its mature noise classifier; Git's logical
    /// branches are represented in the same predicate language as Sigma rules.
    public static var fileEventInterestRequirements: [BuiltinFileEventRequirement] {
        let gitPredicates = [
            Predicate(field: "process.commandline", modifier: .contains,
                      values: ["git credential"], negate: false),             // 0
            Predicate(field: "process.commandline", modifier: .contains,
                      values: ["fill", "approve"], negate: false),           // 1
            Predicate(field: "process.executable", modifier: .endswith,
                      values: ["/git", "/git-credential-osxkeychain"], negate: true), // 2
            Predicate(field: "file.path", modifier: .contains,
                      values: [".git/hooks/"], negate: false),                // 3
            Predicate(field: "file.path", modifier: .contains,
                      values: ["/tmp/", "/Downloads/", "/Users/Shared/"], negate: false), // 4
            Predicate(field: "process.commandline", modifier: .contains,
                      values: ["/sh", "/bash", "/zsh"], negate: false),    // 5
            Predicate(field: "file.path", modifier: .endswith,
                      values: ["/.gitconfig", "/.git/config"], negate: false), // 6
            Predicate(field: "process.executable", modifier: .endswith,
                      values: ["/git", "/git-config"], negate: true),        // 7
            Predicate(field: "file.path", modifier: .endswith,
                      values: ["/.git-credentials", "/.git-credential-store"], negate: false), // 8
        ]
        let gitTree: ConditionNode = .or([
            .and([.predicate(0), .predicate(1), .predicate(2)]),
            .and([.predicate(3), .predicate(4), .predicate(5)]),
            .and([.predicate(6), .predicate(7)]),
            .predicate(8),
        ])

        return [
            BuiltinFileEventRequirement(
                id: "maccrab.correlator.cross-process",
                kind: .crossProcessCorrelation
            ),
            BuiltinFileEventRequirement(
                id: "maccrab.git",
                kind: .predicates(
                    predicates: gitPredicates,
                    condition: .anyOf,
                    conditionTree: gitTree
                )
            ),
            BuiltinFileEventRequirement(
                id: "maccrab.ai-guard.file-consumers",
                kind: .dynamicAIConsumers
            ),
        ]
    }
}

public struct FileEventInterestDescriptorSnapshot: Sendable {
    public enum Component: String, CaseIterable, Sendable, Hashable {
        case singleEventRules = "single_event_rules"
        case sequenceRules = "sequence_rules"
        case graphRules = "graph_rules"
        case builtins
    }

    public let singleEventRules: [CompiledRule]
    public let sequenceRules: [SequenceRule]
    public let graphRules: [GraphRule]
    public let builtinRequirements: [BuiltinFileEventRequirement]
    public let includedComponents: Set<Component>

    public init(
        singleEventRules: [CompiledRule],
        sequenceRules: [SequenceRule],
        graphRules: [GraphRule],
        builtinRequirements: [BuiltinFileEventRequirement],
        includedComponents: Set<Component> = Set(Component.allCases)
    ) {
        self.singleEventRules = singleEventRules
        self.sequenceRules = sequenceRules
        self.graphRules = graphRules
        self.builtinRequirements = builtinRequirements
        self.includedComponents = includedComponents
    }
}

public struct FileEventInterestPolicyLimits: Sendable, Equatable {
    public var maximumRequirements: Int
    public var maximumPredicates: Int
    public var maximumConditionNodes: Int
    public var maximumPathRegexPredicates: Int
    public var maximumPathRegexPatterns: Int
    public var maximumDynamicDemands: Int
    public var maximumDynamicPatterns: Int
    public var maximumDynamicPatternUTF8Bytes: Int
    public var maximumDynamicPatternBytes: Int
    public var maximumDynamicGraceProcessIDs: Int

    public init(
        maximumRequirements: Int = 4_096,
        maximumPredicates: Int = 32_768,
        maximumConditionNodes: Int = 65_536,
        maximumPathRegexPredicates: Int = 512,
        maximumPathRegexPatterns: Int = 2_048,
        maximumDynamicDemands: Int = 4_096,
        maximumDynamicPatterns: Int = 32_768,
        maximumDynamicPatternUTF8Bytes: Int = 4_096,
        maximumDynamicPatternBytes: Int = 1_048_576,
        maximumDynamicGraceProcessIDs: Int = 4_096
    ) {
        self.maximumRequirements = maximumRequirements
        self.maximumPredicates = maximumPredicates
        self.maximumConditionNodes = maximumConditionNodes
        self.maximumPathRegexPredicates = maximumPathRegexPredicates
        self.maximumPathRegexPatterns = maximumPathRegexPatterns
        self.maximumDynamicDemands = maximumDynamicDemands
        self.maximumDynamicPatterns = maximumDynamicPatterns
        self.maximumDynamicPatternUTF8Bytes = maximumDynamicPatternUTF8Bytes
        self.maximumDynamicPatternBytes = maximumDynamicPatternBytes
        self.maximumDynamicGraceProcessIDs = maximumDynamicGraceProcessIDs
    }

    public static let `default` = Self()
}

public enum FileEventInterestFailOpenReason: Sendable, Equatable {
    case noDescriptorSnapshot
    case incompleteSnapshot(missing: [FileEventInterestDescriptorSnapshot.Component])
    case resourceLimit(String)
}

public struct FileEventInterestPolicyCensus: Sendable, Equatable {
    public var enabledFileSingleRules = 0
    public var enabledFileSequenceSteps = 0
    public var graphFileNodeRequirements = 0
    public var graphPersistenceNodeRequirements = 0
    public var builtinRequirements = 0
    public var compiledPredicates = 0
    public var unsupportedPredicates = 0
    public var projectedPathRegexPredicates = 0
    public var unsupportedPathRegexPredicates = 0
    public var malformedConditionsMadeBroad = 0

    public init() {}

    public var totalRequirements: Int {
        enabledFileSingleRules + enabledFileSequenceSteps
            + graphFileNodeRequirements + graphPersistenceNodeRequirements
            + builtinRequirements
    }
}

public struct FileEventInterestCompilation: Sendable {
    public let policy: FileEventInterestPolicy
    public let census: FileEventInterestPolicyCensus
    public let installedRestrictiveSnapshot: Bool
}

// MARK: - Compiled policy

private enum FileEventTruth: Sendable, Equatable {
    case yes
    case no
    case unknown

    var inverted: Self {
        switch self {
        case .yes: return .no
        case .no: return .yes
        case .unknown: return .unknown
        }
    }
}

private enum InterestField: Sendable, Hashable {
    case filePath, fileName, fileDirectory, fileExtension, fileSize
    case fileAction, fileSourcePath
    case eventCategory, eventType, eventAction
    case processExecutable, processName, processCommandLine, parentExecutable
    case signerType, isPlatformBinary
    case btmItemType, btmLegacy, btmManaged
    case isHoneyfile
    case unsupported

    init(_ raw: String) {
        switch raw {
        case "file.path", "TargetFilename": self = .filePath
        case "file.name": self = .fileName
        case "file.directory": self = .fileDirectory
        case "file.extension": self = .fileExtension
        case "file.size": self = .fileSize
        case "file.action", "FileAction": self = .fileAction
        case "file.source_path", "SourceFilename": self = .fileSourcePath
        case "event.category": self = .eventCategory
        case "event.type": self = .eventType
        case "event.action": self = .eventAction
        case "process.executable", "Image": self = .processExecutable
        case "process.name": self = .processName
        case "process.commandline", "CommandLine": self = .processCommandLine
        case "process.parent.executable", "ParentImage": self = .parentExecutable
        case "process.code_signature.signer_type", "SignerType": self = .signerType
        case "process.is_platform_binary", "IsPlatformBinary", "PlatformBinary": self = .isPlatformBinary
        case "BTMItemType": self = .btmItemType
        case "BTMLegacy": self = .btmLegacy
        case "BTMManaged": self = .btmManaged
        case "IsHoneyfile": self = .isHoneyfile
        default: self = .unsupported
        }
    }

    var supportsRegexProjection: Bool {
        switch self {
        case .filePath, .fileName, .fileDirectory, .fileSourcePath:
            return true
        default:
            return false
        }
    }

    func fact(from facts: FileEventAdmissionFacts) -> FileEventFact<String> {
        switch self {
        case .filePath: return facts.filePath
        case .fileName: return facts.fileName
        case .fileDirectory: return facts.fileDirectory
        case .fileExtension: return facts.fileExtension
        case .fileSize: return facts.fileSize
        case .fileAction: return facts.fileAction
        case .fileSourcePath: return facts.fileSourcePath
        case .eventCategory: return facts.eventCategory
        case .eventType: return facts.eventType
        case .eventAction: return facts.eventAction
        case .processExecutable: return facts.processExecutable
        case .processName: return facts.processName
        case .processCommandLine: return facts.processCommandLine
        case .parentExecutable: return facts.parentExecutable
        case .signerType: return facts.signerType
        case .isPlatformBinary: return facts.isPlatformBinary
        case .btmItemType:
            return authoritativeBTMFact(facts.btmItemType, source: facts.source)
        case .btmLegacy:
            return authoritativeBTMFact(facts.btmLegacy, source: facts.source)
        case .btmManaged:
            return authoritativeBTMFact(facts.btmManaged, source: facts.source)
        case .isHoneyfile:
            // Requires the independently-published semantic snapshot and is
            // resolved by InterestPredicate before ordinary fact lookup.
            return .unknown
        case .unsupported:
            return .unknown
        }
    }

    private func authoritativeBTMFact(
        _ fact: FileEventFact<String>,
        source: FileEventAdmissionSource
    ) -> FileEventFact<String> {
        if source.hasAuthoritativeCapabilities,
           !source.capabilities.contains(.btmMetadata) {
            return .absent
        }
        return fact
    }
}

/// Per-decision fixed-layout lowercase memo.  A path used by 100 predicates is
/// folded once, not 100 times; unlike a Dictionary this has no heap allocation
/// for the overwhelmingly common early-admit callback.
private struct InterestFactMemo {
    var filePath: String?
    var fileName: String?
    var fileDirectory: String?
    var fileExtension: String?
    var fileSize: String?
    var fileAction: String?
    var fileSourcePath: String?
    var eventCategory: String?
    var eventType: String?
    var eventAction: String?
    var processExecutable: String?
    var processName: String?
    var processCommandLine: String?
    var parentExecutable: String?
    var signerType: String?
    var isPlatformBinary: String?
    var btmItemType: String?
    var btmLegacy: String?
    var btmManaged: String?

    mutating func lowercased(_ value: String, for field: InterestField) -> String {
        switch field {
        case .filePath: return Self.cache(value, in: &filePath)
        case .fileName: return Self.cache(value, in: &fileName)
        case .fileDirectory: return Self.cache(value, in: &fileDirectory)
        case .fileExtension: return Self.cache(value, in: &fileExtension)
        case .fileSize: return Self.cache(value, in: &fileSize)
        case .fileAction: return Self.cache(value, in: &fileAction)
        case .fileSourcePath: return Self.cache(value, in: &fileSourcePath)
        case .eventCategory: return Self.cache(value, in: &eventCategory)
        case .eventType: return Self.cache(value, in: &eventType)
        case .eventAction: return Self.cache(value, in: &eventAction)
        case .processExecutable: return Self.cache(value, in: &processExecutable)
        case .processName: return Self.cache(value, in: &processName)
        case .processCommandLine: return Self.cache(value, in: &processCommandLine)
        case .parentExecutable: return Self.cache(value, in: &parentExecutable)
        case .signerType: return Self.cache(value, in: &signerType)
        case .isPlatformBinary: return Self.cache(value, in: &isPlatformBinary)
        case .btmItemType: return Self.cache(value, in: &btmItemType)
        case .btmLegacy: return Self.cache(value, in: &btmLegacy)
        case .btmManaged: return Self.cache(value, in: &btmManaged)
        case .isHoneyfile, .unsupported: return value.lowercased()
        }
    }

    private static func cache(_ value: String, in slot: inout String?) -> String {
        if let slot { return slot }
        let folded = value.lowercased()
        slot = folded
        return folded
    }
}

/// Compile-time, deterministic projection of a bounded file-path regex.
///
/// No regex engine runs on the ES callback. The compiler validates the small
/// pattern off-path, then extracts only constraints that are *necessary* for a
/// match: anchored literal-prefix alternatives and terminal literal-suffix
/// alternatives. A failed constraint proves `.no`; a passing constraint stays
/// `.unknown` because the unmodelled remainder may still fail. This preserves
/// fail-open semantics without exposing attacker-controlled paths to regex
/// backtracking.
private struct SafePathRegexProjection: Sendable {
    static let maximumPatternUTF8Bytes = 512
    static let maximumInputUTF8Bytes = 4_096
    static let maximumAlternatives = 32
    static let maximumConstraintUTF8Bytes = 256

    let anchoredPrefixes: [String]
    let terminalSuffixes: [String]

    init?(pattern: String) {
        guard Self.boundedUTF8Count(
            pattern,
            maximum: Self.maximumPatternUTF8Bytes
        ) != nil,
        Self.isSupportedShape(pattern),
        (try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive])) != nil else {
            return nil
        }

        let characters = Array(pattern)
        let prefixes = Self.extractAnchoredPrefixes(characters)
        let suffixes = Self.extractTerminalSuffixes(characters)
        guard !prefixes.isEmpty || !suffixes.isEmpty else { return nil }
        guard prefixes.count <= Self.maximumAlternatives,
              suffixes.count <= Self.maximumAlternatives,
              (prefixes + suffixes).allSatisfy({
                  Self.boundedUTF8Count(
                      $0,
                      maximum: Self.maximumConstraintUTF8Bytes
                  ) != nil && $0.unicodeScalars.allSatisfy { $0.isASCII }
              }) else {
            return nil
        }
        anchoredPrefixes = prefixes.map { $0.lowercased() }
        terminalSuffixes = suffixes.map { $0.lowercased() }
    }

    func evaluate(path rawPath: String) -> FileEventTruth {
        // Bound the raw callback token BEFORE lowercasing. Lowercasing an
        // unchecked hostile synthetic String would defeat the input cap, and
        // non-ASCII case folding is not guaranteed to match ICU's regex fold.
        guard Self.boundedASCIIUTF8Count(
            rawPath,
            maximum: Self.maximumInputUTF8Bytes
        ) != nil else {
            return .unknown
        }
        let path = rawPath.lowercased()
        if !anchoredPrefixes.isEmpty,
           !anchoredPrefixes.contains(where: path.hasPrefix) {
            return .no
        }
        // ICU `$` may match immediately before a final line terminator. A
        // filename may legally contain one, so suffix disproval is unsafe for
        // such a path even though the normal case remains cheap and exact.
        if !terminalSuffixes.isEmpty,
           !path.contains("\n"), !path.contains("\r"),
           !terminalSuffixes.contains(where: path.hasSuffix) {
            return .no
        }
        return .unknown
    }

    /// Counts at most `maximum + 1` bytes, so even a hostile synthetic String
    /// cannot turn the callback bound check into an unbounded linear scan.
    private static func boundedUTF8Count(_ value: String, maximum: Int) -> Int? {
        let count = value.utf8.prefix(maximum + 1).count
        return count <= maximum ? count : nil
    }

    private static func boundedASCIIUTF8Count(
        _ value: String,
        maximum: Int
    ) -> Int? {
        var count = 0
        for byte in value.utf8 {
            count += 1
            guard count <= maximum, byte < 0x80 else { return nil }
        }
        return count
    }

    /// Exclude regex features whose meaning makes a cheap projection fragile,
    /// and reject nested quantified groups even though the projection itself
    /// would never execute them. This keeps the accepted subset reviewable.
    private static func isSupportedShape(_ pattern: String) -> Bool {
        if pattern.contains("(?") { return false } // lookaround/inline options
        let chars = Array(pattern)
        var escaped = false
        var inClass = false
        var groupQuantifiers: [Bool] = []
        var lastClosedGroupContainedQuantifier = false
        var previousWasGroupClose = false
        var previousWasQuantifier = false
        var quantifierCount = 0
        var alternationCount = 0
        var index = 0

        while index < chars.count {
            let character = chars[index]
            if escaped {
                if character.isNumber { return false } // backreference
                escaped = false
                previousWasGroupClose = false
                previousWasQuantifier = false
                index += 1
                continue
            }
            if character == "\\" {
                escaped = true
                index += 1
                continue
            }
            if inClass {
                if character == "]" { inClass = false }
                index += 1
                continue
            }
            if character == "[" {
                inClass = true
                previousWasGroupClose = false
                previousWasQuantifier = false
                index += 1
                continue
            }
            if character == "(" {
                guard groupQuantifiers.count < 16 else { return false }
                groupQuantifiers.append(false)
                previousWasGroupClose = false
                previousWasQuantifier = false
                index += 1
                continue
            }
            if character == ")" {
                guard let contained = groupQuantifiers.popLast() else { return false }
                lastClosedGroupContainedQuantifier = contained
                previousWasGroupClose = true
                previousWasQuantifier = false
                index += 1
                continue
            }
            if character == "|" {
                // A top-level alternative is a separate regex branch. A
                // prefix/suffix extracted from only one branch is not a
                // necessary condition for the whole expression.
                guard !groupQuantifiers.isEmpty else { return false }
                alternationCount += 1
                guard alternationCount <= maximumAlternatives else { return false }
                previousWasGroupClose = false
                previousWasQuantifier = false
                index += 1
                continue
            }

            var isQuantifier = character == "*" || character == "+" || character == "?"
            if character == "{" {
                guard let close = chars[index...].firstIndex(of: "}") else { return false }
                index = close
                isQuantifier = true
            }
            if isQuantifier {
                quantifierCount += 1
                guard quantifierCount <= 16,
                      !previousWasQuantifier,
                      !(previousWasGroupClose && lastClosedGroupContainedQuantifier) else {
                    return false
                }
                for frame in groupQuantifiers.indices {
                    groupQuantifiers[frame] = true
                }
                previousWasGroupClose = false
                previousWasQuantifier = true
            } else if character != "^" && character != "$" {
                previousWasGroupClose = false
                previousWasQuantifier = false
            }
            index += 1
        }
        return !escaped && !inClass && groupQuantifiers.isEmpty
    }

    private static func extractAnchoredPrefixes(_ chars: [Character]) -> [String] {
        guard chars.first == "^" else { return [] }
        var index = 1
        let rawBase = parseLiteralForward(chars, index: &index)
        let base = requiredPrefix(
            from: rawBase,
            following: chars.indices.contains(index) ? chars[index] : nil
        )
        guard !base.isEmpty else { return [] }

        guard index < chars.count, chars[index] == "(",
              let group = parsePureLiteralAlternatives(chars, openingIndex: index),
              group.afterIndex >= chars.count || !isQuantifier(chars[group.afterIndex]) else {
            return [base]
        }
        index = group.afterIndex
        let rawTrailing = parseLiteralForward(chars, index: &index)
        let trailing = requiredPrefix(
            from: rawTrailing,
            following: chars.indices.contains(index) ? chars[index] : nil
        )
        return group.values.map { base + $0 + trailing }
    }

    /// `?`, `*`, and `{...}` can make the immediately-preceding literal
    /// optional. Removing that final character yields a weaker but still
    /// necessary prefix. `+` retains at least one occurrence and needs no trim.
    private static func requiredPrefix(
        from literal: String,
        following: Character?
    ) -> String {
        switch following {
        case "?", "*", "{": return String(literal.dropLast())
        default: return literal
        }
    }

    private static func extractTerminalSuffixes(_ chars: [Character]) -> [String] {
        guard let last = chars.indices.last,
              chars[last] == "$",
              !isEscaped(chars, index: last) else {
            return []
        }
        let end = last
        guard end > 0 else { return [] }

        if chars[end - 1] == ")",
           let opening = matchingOpeningParenthesis(chars, closingIndex: end - 1),
           let group = parsePureLiteralAlternatives(chars, openingIndex: opening),
           group.afterIndex == end {
            let prefix = parseLiteralBackward(chars, endExclusive: opening)
            let values = group.values.map { prefix + $0 }
            return values.allSatisfy({ !$0.isEmpty }) ? values : []
        }
        let literal = parseLiteralBackward(chars, endExclusive: end)
        return literal.isEmpty ? [] : [literal]
    }

    private static func parseLiteralForward(
        _ chars: [Character],
        index: inout Int
    ) -> String {
        var output = ""
        while index < chars.count {
            if chars[index] == "\\" {
                guard index + 1 < chars.count,
                      isEscapedLiteral(chars[index + 1]) else { break }
                output.append(chars[index + 1])
                index += 2
                continue
            }
            guard !isRegexMeta(chars[index]) else { break }
            output.append(chars[index])
            index += 1
        }
        return output
    }

    private static func parseLiteralBackward(
        _ chars: [Character],
        endExclusive: Int
    ) -> String {
        var pieces: [Character] = []
        var index = endExclusive - 1
        while index >= 0 {
            let character = chars[index]
            if index > 0, chars[index - 1] == "\\",
               !isEscaped(chars, index: index - 1),
               isEscapedLiteral(character) {
                pieces.append(character)
                index -= 2
                continue
            }
            guard !isRegexMeta(character) else { break }
            pieces.append(character)
            index -= 1
        }
        return String(pieces.reversed())
    }

    private static func parsePureLiteralAlternatives(
        _ chars: [Character],
        openingIndex: Int
    ) -> (values: [String], afterIndex: Int)? {
        guard chars.indices.contains(openingIndex), chars[openingIndex] == "(" else {
            return nil
        }
        var values: [String] = []
        var current = ""
        var index = openingIndex + 1
        while index < chars.count {
            let character = chars[index]
            if character == "\\" {
                guard index + 1 < chars.count,
                      isEscapedLiteral(chars[index + 1]) else { return nil }
                current.append(chars[index + 1])
                index += 2
                continue
            }
            if character == "|" {
                guard !current.isEmpty else { return nil }
                values.append(current)
                current = ""
                guard values.count < maximumAlternatives else { return nil }
                index += 1
                continue
            }
            if character == ")" {
                guard !current.isEmpty else { return nil }
                values.append(current)
                return (values, index + 1)
            }
            guard !isRegexMeta(character) else { return nil }
            current.append(character)
            index += 1
        }
        return nil
    }

    private static func matchingOpeningParenthesis(
        _ chars: [Character],
        closingIndex: Int
    ) -> Int? {
        var depth = 0
        var index = closingIndex
        while index >= 0 {
            if !isEscaped(chars, index: index) {
                if chars[index] == ")" { depth += 1 }
                if chars[index] == "(" {
                    depth -= 1
                    if depth == 0 { return index }
                }
            }
            index -= 1
        }
        return nil
    }

    private static func isEscaped(_ chars: [Character], index: Int) -> Bool {
        guard index > 0 else { return false }
        var slashes = 0
        var cursor = index - 1
        while cursor >= 0, chars[cursor] == "\\" {
            slashes += 1
            cursor -= 1
        }
        return slashes % 2 == 1
    }

    private static func isRegexMeta(_ character: Character) -> Bool {
        switch character {
        case ".", "^", "$", "*", "+", "?", "(", ")", "[", "]", "{", "}", "|":
            return true
        default:
            return false
        }
    }

    private static func isQuantifier(_ character: Character) -> Bool {
        character == "*" || character == "+" || character == "?" || character == "{"
    }

    private static func isEscapedLiteral(_ character: Character) -> Bool {
        switch character {
        case ".", "^", "$", "*", "+", "?", "(", ")", "[", "]", "{", "}", "|", "/", "\\", "-":
            return true
        default:
            return false
        }
    }
}

private struct InterestPredicate: Sendable {
    let field: InterestField
    let modifier: PredicateModifier
    let values: [String]
    let lowercasedValues: [String]
    let negate: Bool
    let regexProjections: [SafePathRegexProjection]?

    init(_ predicate: Predicate) {
        field = InterestField(predicate.field)
        modifier = predicate.modifier
        values = predicate.values
        lowercasedValues = predicate.lowercasedValues
        negate = predicate.negate
        if predicate.modifier == .regex,
           field.supportsRegexProjection,
           !predicate.values.isEmpty {
            let projections = predicate.values.compactMap(SafePathRegexProjection.init)
            regexProjections = projections.count == predicate.values.count ? projections : nil
        } else {
            regexProjections = nil
        }
    }

    func evaluate(
        _ facts: FileEventAdmissionFacts,
        honeyfiles: HoneyfilePathSnapshot,
        nowUptimeNanoseconds: UInt64,
        memo: inout InterestFactMemo
    ) -> FileEventTruth {
        guard field != .unsupported else { return .unknown }
        let fact = field == .isHoneyfile
            ? honeyfiles.semanticFact(for: facts, nowUptimeNanoseconds: nowUptimeNanoseconds)
            : field.fact(from: facts)
        let raw: FileEventTruth
        switch fact {
        case .unknown:
            raw = .unknown
        case .absent:
            raw = .no
        case .value(let value):
            raw = evaluateKnown(value, memo: &memo)
        }
        return negate ? raw.inverted : raw
    }

    private func evaluateKnown(
        _ value: String,
        memo: inout InterestFactMemo
    ) -> FileEventTruth {
        if modifier == .exists {
            return value.isEmpty ? .no : .yes
        }
        if modifier == .regex {
            guard let regexProjections else { return .unknown }
            for projection in regexProjections {
                if projection.evaluate(path: value) != .no {
                    return .unknown
                }
            }
            return .no
        }
        let lower = memo.lowercased(value, for: field)
        let matched: Bool
        switch modifier {
        case .equals:
            matched = lowercasedValues.contains(lower)
        case .contains:
            matched = lowercasedValues.contains { lower.contains($0) }
        case .startswith:
            matched = lowercasedValues.contains { lower.hasPrefix($0) }
        case .endswith:
            matched = lowercasedValues.contains { lower.hasSuffix($0) }
        case .gt, .lt, .gte, .lte:
            guard let number = Double(value) else { return .no }
            matched = values.contains { candidate in
                guard let other = Double(candidate) else { return false }
                switch modifier {
                case .gt: return number > other
                case .lt: return number < other
                case .gte: return number >= other
                case .lte: return number <= other
                default: return false
                }
            }
        case .regex:
            preconditionFailure("handled before non-regex switch")
        case .exists:
            matched = !value.isEmpty
        }
        return matched ? .yes : .no
    }
}

private indirect enum InterestCondition: Sendable {
    case all([InterestCondition])
    case any([InterestCondition])
    case not(InterestCondition)
    case predicate(Int)
    case unknown

    func evaluate(
        predicates: [InterestPredicate],
        facts: FileEventAdmissionFacts,
        honeyfiles: HoneyfilePathSnapshot,
        nowUptimeNanoseconds: UInt64,
        memo: inout InterestFactMemo
    ) -> FileEventTruth {
        switch self {
        case .predicate(let index):
            guard predicates.indices.contains(index) else { return .unknown }
            return predicates[index].evaluate(
                facts,
                honeyfiles: honeyfiles,
                nowUptimeNanoseconds: nowUptimeNanoseconds,
                memo: &memo
            )
        case .not(let operand):
            return operand.evaluate(
                predicates: predicates,
                facts: facts,
                honeyfiles: honeyfiles,
                nowUptimeNanoseconds: nowUptimeNanoseconds,
                memo: &memo
            ).inverted
        case .all(let operands):
            var sawUnknown = false
            for operand in operands {
                switch operand.evaluate(
                    predicates: predicates,
                    facts: facts,
                    honeyfiles: honeyfiles,
                    nowUptimeNanoseconds: nowUptimeNanoseconds,
                    memo: &memo
                ) {
                case .no: return .no
                case .unknown: sawUnknown = true
                case .yes: break
                }
            }
            return sawUnknown ? .unknown : .yes
        case .any(let operands):
            var sawUnknown = false
            for operand in operands {
                switch operand.evaluate(
                    predicates: predicates,
                    facts: facts,
                    honeyfiles: honeyfiles,
                    nowUptimeNanoseconds: nowUptimeNanoseconds,
                    memo: &memo
                ) {
                case .yes: return .yes
                case .unknown: sawUnknown = true
                case .no: break
                }
            }
            return sawUnknown ? .unknown : .no
        case .unknown:
            return .unknown
        }
    }
}

private struct PredicateRequirement: Sendable {
    let predicates: [InterestPredicate]
    let condition: InterestCondition

    func evaluate(
        _ facts: FileEventAdmissionFacts,
        honeyfiles: HoneyfilePathSnapshot,
        nowUptimeNanoseconds: UInt64,
        memo: inout InterestFactMemo
    ) -> FileEventTruth {
        condition.evaluate(
            predicates: predicates,
            facts: facts,
            honeyfiles: honeyfiles,
            nowUptimeNanoseconds: nowUptimeNanoseconds,
            memo: &memo
        )
    }
}

private struct GraphNodeRequirement: Sendable {
    let type: String
    let clauses: [String: GraphRule.NodeSpec.WhereClause]

    private enum Attribute {
        case unknown
        case absent
        case string(String)
        case bool(Bool)
    }

    func evaluate(
        _ facts: FileEventAdmissionFacts,
        dynamicAI: DynamicAIFileEventDemandSnapshot,
        nowUptimeNanoseconds: UInt64
    ) -> FileEventTruth {
        let nodeExists: FileEventTruth
        let classification: TraceGraphFileObservationPolicy.Classification?
        switch facts.filePath {
        case .unknown:
            nodeExists = .unknown
            classification = nil
        case .absent:
            nodeExists = .no
            classification = nil
        case .value(let path):
            nodeExists = .yes
            classification = TraceGraphFileObservationPolicy.classify(path: path)
        }
        if nodeExists == .no { return .no }

        let callbackAction: TraceGraphFileObservationPolicy.CallbackAction?
        let actionExists: FileEventTruth
        switch facts.eventAction {
        case .unknown:
            callbackAction = nil
            actionExists = .unknown
        case .absent:
            callbackAction = nil
            actionExists = .no
        case .value(let action):
            callbackAction = TraceGraphFileObservationPolicy.callbackAction(eventAction: action)
            actionExists = callbackAction == nil ? .no : .yes
        }
        if actionExists == .no { return .no }

        if type == FileNode.entityType {
            return and(
                and(nodeExists, actionExists),
                evaluateClauses(
                    facts,
                    persistence: false,
                    classification: classification,
                    dynamicAI: dynamicAI,
                    nowUptimeNanoseconds: nowUptimeNanoseconds
                )
            )
        }
        if type == PersistenceNode.entityType {
            let persistenceExists: FileEventTruth
            let persistenceFact = resolvedPersistenceFact(facts, classification: classification)
            switch persistenceFact {
            case .unknown: persistenceExists = .unknown
            case .absent: persistenceExists = .no
            case .value: persistenceExists = .yes
            }
            let actionCanPersist: FileEventTruth
            if let callbackAction {
                actionCanPersist = callbackAction.canCreatePersistence ? .yes : .no
            } else {
                actionCanPersist = actionExists
            }
            return and(
                and(and(nodeExists, persistenceExists), actionCanPersist),
                evaluateClauses(
                    facts,
                    persistence: true,
                    classification: classification,
                    dynamicAI: dynamicAI,
                    nowUptimeNanoseconds: nowUptimeNanoseconds
                )
            )
        }
        return .no
    }

    private func evaluateClauses(
        _ facts: FileEventAdmissionFacts,
        persistence: Bool,
        classification: TraceGraphFileObservationPolicy.Classification?,
        dynamicAI: DynamicAIFileEventDemandSnapshot,
        nowUptimeNanoseconds: UInt64
    ) -> FileEventTruth {
        var result = FileEventTruth.yes
        for (path, clause) in clauses {
            let attribute: Attribute
            if persistence, path == "persistence_type" {
                attribute = Self.attribute(resolvedPersistenceFact(facts, classification: classification))
            } else if !persistence, path == "file_kind" {
                attribute = Self.attribute(resolvedFileKindFact(facts, classification: classification))
            } else if !persistence, path == "untrusted_content" {
                attribute = untrustedAttribute(
                    facts,
                    dynamicAI: dynamicAI,
                    nowUptimeNanoseconds: nowUptimeNanoseconds
                )
            } else {
                attribute = .unknown
            }
            result = and(result, Self.matches(attribute, clause: clause))
            if result == .no { return .no }
        }
        return result
    }

    private func resolvedFileKindFact(
        _ facts: FileEventAdmissionFacts,
        classification: TraceGraphFileObservationPolicy.Classification?
    ) -> FileEventFact<String> {
        if case .unknown = facts.graphFileKind, let classification {
            return .value(classification.fileKind.rawValue)
        }
        return facts.graphFileKind
    }

    private func resolvedPersistenceFact(
        _ facts: FileEventAdmissionFacts,
        classification: TraceGraphFileObservationPolicy.Classification?
    ) -> FileEventFact<String> {
        if case .unknown = facts.graphPersistenceType, let classification {
            return .known(classification.persistenceType?.rawValue)
        }
        return facts.graphPersistenceType
    }

    private func untrustedAttribute(
        _ facts: FileEventAdmissionFacts,
        dynamicAI: DynamicAIFileEventDemandSnapshot,
        nowUptimeNanoseconds: UInt64
    ) -> Attribute {
        switch facts.graphUntrustedContent {
        case .value(let value): return .bool(value)
        case .absent: return .absent
        case .unknown: break
        }
        guard case .value(let path) = facts.filePath else { return .unknown }
        guard case .value(let eventAction) = facts.eventAction else { return .unknown }
        guard TraceGraphFileObservationPolicy.mayGenerateUntrustedContent(
            path: path,
            eventAction: eventAction
        ) else {
            return .bool(false)
        }
        switch dynamicAI.attribution(facts, nowUptimeNanoseconds: nowUptimeNanoseconds) {
        case .no: return .bool(false)
        case .yes, .unknown:
            // The callback is generator-eligible; only the downstream bounded
            // content scan can decide whether the marker is actually present.
            return .unknown
        }
    }

    private static func attribute(_ fact: FileEventFact<String>) -> Attribute {
        switch fact {
        case .unknown: return .unknown
        case .absent: return .absent
        case .value(let value): return .string(value)
        }
    }

    /// Mirrors GraphRuleEvaluator's first-present-clause precedence.
    private static func matches(
        _ attribute: Attribute,
        clause: GraphRule.NodeSpec.WhereClause
    ) -> FileEventTruth {
        if case .unknown = attribute { return .unknown }
        if let allowed = clause.in {
            if case .string(let value) = attribute {
                return allowed.contains(value) ? .yes : .no
            }
            return .no
        }
        if let denied = clause.notIn {
            if case .string(let value) = attribute {
                return denied.contains(value) ? .no : .yes
            }
            return .yes
        }
        if let exact = clause.equals {
            if case .string(let value) = attribute {
                return value == exact ? .yes : .no
            }
            return .no
        }
        if let exactBool = clause.equalsBool {
            if case .bool(let value) = attribute {
                return value == exactBool ? .yes : .no
            }
            return .no
        }
        return .yes
    }
}

private func and(_ lhs: FileEventTruth, _ rhs: FileEventTruth) -> FileEventTruth {
    if lhs == .no || rhs == .no { return .no }
    if lhs == .unknown || rhs == .unknown { return .unknown }
    return .yes
}

private enum CompiledFileEventRequirement: Sendable {
    case predicates(id: String, sources: Set<FileEventAdmissionSource>?, PredicateRequirement)
    case graph(id: String, GraphNodeRequirement)
    case crossProcess(id: String, sources: Set<FileEventAdmissionSource>?)
    case dynamicAI(id: String, sources: Set<FileEventAdmissionSource>?)
    case unconditional(id: String, sources: Set<FileEventAdmissionSource>?)

    var id: String {
        switch self {
        case .predicates(let id, _, _), .graph(let id, _),
             .crossProcess(let id, _), .dynamicAI(let id, _),
             .unconditional(let id, _):
            return id
        }
    }

    func evaluate(
        facts: FileEventAdmissionFacts,
        dynamicAI: DynamicAIFileEventDemandSnapshot,
        honeyfiles: HoneyfilePathSnapshot,
        nowUptimeNanoseconds: UInt64,
        memo: inout InterestFactMemo
    ) -> FileEventTruth {
        switch self {
        case .predicates(_, let sources, let requirement):
            return and(
                sourceTruth(sources, facts.source),
                requirement.evaluate(
                    facts,
                    honeyfiles: honeyfiles,
                    nowUptimeNanoseconds: nowUptimeNanoseconds,
                    memo: &memo
                )
            )
        case .graph(_, let requirement):
            return requirement.evaluate(
                facts,
                dynamicAI: dynamicAI,
                nowUptimeNanoseconds: nowUptimeNanoseconds
            )
        case .crossProcess(_, let sources):
            let source = sourceTruth(sources, facts.source)
            let path: FileEventTruth
            switch facts.filePath {
            case .unknown: path = .unknown
            case .absent: path = .no
            case .value(let value):
                path = CrossProcessCorrelator.shouldIgnoreFilePath(value) ? .no : .yes
            }
            return and(source, path)
        case .dynamicAI(_, let sources):
            return and(
                sourceTruth(sources, facts.source),
                dynamicAI.evaluate(facts, nowUptimeNanoseconds: nowUptimeNanoseconds)
            )
        case .unconditional(_, let sources):
            return sourceTruth(sources, facts.source)
        }
    }

    private func sourceTruth(
        _ sources: Set<FileEventAdmissionSource>?,
        _ source: FileEventAdmissionSource
    ) -> FileEventTruth {
        guard let sources else { return .yes }
        if source == .unknown { return .unknown }
        return sources.contains(source) ? .yes : .no
    }
}

extension DynamicAIFileEventDemandSnapshot {
    fileprivate func evaluate(
        _ facts: FileEventAdmissionFacts,
        nowUptimeNanoseconds: UInt64
    ) -> FileEventTruth {
        if state == .unknown || nowUptimeNanoseconds > validUntilUptimeNanoseconds {
            // Unknown attribution cannot prove that a temp/cache callback is
            // irrelevant: an AI process may be opening `/private/tmp/x.md`
            // for FileInjectionScanner or a credential-shaped temp file. The
            // targeted per-PID grace in the registry handles fresh-publication
            // races; stale/unknown state itself remains strictly fail-open.
            return .unknown
        }
        var sawUnknown = false
        for demand in demands {
            switch demand.evaluate(facts) {
            case .yes: return .yes
            case .unknown: sawUnknown = true
            case .no: break
            }
        }
        return sawUnknown ? .unknown : .no
    }

    fileprivate func attribution(
        _ facts: FileEventAdmissionFacts,
        nowUptimeNanoseconds: UInt64
    ) -> FileEventTruth {
        guard state == .current,
              nowUptimeNanoseconds <= validUntilUptimeNanoseconds else {
            return .unknown
        }
        switch facts.processID {
        case .unknown:
            return attributedProcessIDs.isEmpty && !demands.contains(where: { $0.processID == nil })
                ? .no : .unknown
        case .absent:
            return .no
        case .value(let pid):
            if attributedProcessIDs.contains(pid) { return .yes }
            if demands.contains(where: { $0.processID == nil || $0.processID == pid }) {
                return .yes
            }
            return .no
        }
    }
}

extension DynamicAIFileEventDemand {
    fileprivate func evaluate(_ facts: FileEventAdmissionFacts) -> FileEventTruth {
        let process: FileEventTruth
        if let processID {
            switch facts.processID {
            case .unknown: process = .unknown
            case .absent: process = .no
            case .value(let value): process = value == processID ? .yes : .no
            }
        } else {
            process = .yes
        }
        if process == .no { return .no }
        return and(process, and(action.evaluate(facts), path.evaluate(facts.filePath)))
    }
}

extension DynamicFileEventActionDemand {
    fileprivate func evaluate(_ facts: FileEventAdmissionFacts) -> FileEventTruth {
        switch self {
        case .any:
            return .yes
        case .fileActions(let actions):
            return Self.match(actions, fact: facts.fileAction)
        case .eventActions(let actions):
            return Self.match(actions, fact: facts.eventAction)
        }
    }

    private static func match(
        _ actions: Set<String>,
        fact: FileEventFact<String>
    ) -> FileEventTruth {
        switch fact {
        case .unknown: return .unknown
        case .absent: return .no
        case .value(let value): return actions.contains(value) ? .yes : .no
        }
    }
}

extension DynamicFileEventPathDemand {
    private static let maximumCallbackPathUTF8Bytes = 4_096

    fileprivate func evaluate(_ fact: FileEventFact<String>) -> FileEventTruth {
        if case .any = self { return .yes }
        guard case .value(let rawPath) = fact else {
            if case .absent = fact { return .no }
            return .unknown
        }
        guard rawPath.utf8.prefix(Self.maximumCallbackPathUTF8Bytes + 1).count
                <= Self.maximumCallbackPathUTF8Bytes else {
            return .unknown
        }

        switch self {
        case .any:
            return .yes
        case .supportedTextFile:
            return result(FileInjectionScanner.isSupportedTextPath(rawPath))
        case .agentContentFile:
            return result(ESCollector.isAgentContentReadPath(rawPath))
        case .defaultCredentialFence:
            return result(CredentialFence.defaultCredentialType(filePath: rawPath) != nil)
        case .projectBoundaryOutside(let roots):
            if ProjectBoundary.isDefaultGloballyAllowed(filePath: rawPath) {
                return .no
            }
            let path = (rawPath as NSString).standardizingPath
            let inside = roots.contains { rawRoot in
                let root = (rawRoot as NSString).standardizingPath
                return path == root || path.hasPrefix(root + "/")
            }
            return result(!inside)
        case .equals(let patterns, let insensitive):
            return result(compare(rawPath, patterns, insensitive: insensitive) { $0 == $1 })
        case .prefixes(let patterns, let insensitive):
            return result(compare(rawPath, patterns, insensitive: insensitive) { $0.hasPrefix($1) })
        case .suffixes(let patterns, let insensitive):
            return result(compare(rawPath, patterns, insensitive: insensitive) { $0.hasSuffix($1) })
        case .contains(let patterns, let insensitive):
            return result(compare(rawPath, patterns, insensitive: insensitive) { $0.contains($1) })
        case .extensions(let extensions, let insensitive):
            let ext = (rawPath as NSString).pathExtension
            if insensitive {
                return result(extensions.map { $0.lowercased() }.contains(ext.lowercased()))
            }
            return result(extensions.contains(ext))
        case .outsideRoots(let roots, let insensitive):
            let path = (rawPath as NSString).standardizingPath
            let inside = compare(path, roots.map { ($0 as NSString).standardizingPath },
                                 insensitive: insensitive) { candidate, root in
                candidate == root || candidate.hasPrefix(root + "/")
            }
            return result(!inside)
        case .outsideRootsExcluding(
            let roots,
            let allowedExact,
            let allowedSubstrings,
            let insensitive
        ):
            let path = (rawPath as NSString).standardizingPath
            let folded = insensitive ? path.lowercased() : path
            let exact = insensitive
                ? Set(allowedExact.map { ($0 as NSString).standardizingPath.lowercased() })
                : Set(allowedExact.map { ($0 as NSString).standardizingPath })
            if exact.contains(folded) { return .no }
            let allowed = allowedSubstrings.contains { fragment in
                folded.contains(insensitive ? fragment.lowercased() : fragment)
            }
            if allowed { return .no }
            let inside = compare(
                path,
                roots.map { ($0 as NSString).standardizingPath },
                insensitive: insensitive
            ) { candidate, root in
                candidate == root || candidate.hasPrefix(root + "/")
            }
            return result(!inside)
        }
    }

    private func compare(
        _ candidate: String,
        _ patterns: [String],
        insensitive: Bool,
        predicate: (String, String) -> Bool
    ) -> Bool {
        let lhs = insensitive ? candidate.lowercased() : candidate
        return patterns.contains { pattern in
            predicate(lhs, insensitive ? pattern.lowercased() : pattern)
        }
    }

    private func result(_ value: Bool) -> FileEventTruth { value ? .yes : .no }
}

public struct FileEventInterestDecision: Sendable, Equatable {
    public let admitted: Bool
    public let possibleConsumers: [String]
    public let failOpenReason: FileEventInterestFailOpenReason?
}

public struct FileEventInterestEffectivenessBucket: Sendable, Equatable {
    public let source: FileEventAdmissionSource
    public let action: String
    public let evaluated: Int
    public let admitted: Int
    public var rejected: Int { evaluated - admitted }
}

public struct FileEventInterestPolicy: Sendable {
    fileprivate let requirements: [CompiledFileEventRequirement]
    public let failOpenReason: FileEventInterestFailOpenReason?

    fileprivate init(
        requirements: [CompiledFileEventRequirement],
        failOpenReason: FileEventInterestFailOpenReason? = nil
    ) {
        self.requirements = requirements
        self.failOpenReason = failOpenReason
    }

    fileprivate static func admitAll(_ reason: FileEventInterestFailOpenReason) -> Self {
        Self(requirements: [], failOpenReason: reason)
    }

    @inline(__always)
    public func shouldAdmit(
        _ facts: FileEventAdmissionFacts,
        dynamicAI: DynamicAIFileEventDemandSnapshot = .unknown,
        honeyfiles: HoneyfilePathSnapshot = .unknown,
        nowUptimeNanoseconds: UInt64 = DispatchTime.now().uptimeNanoseconds
    ) -> Bool {
        if failOpenReason != nil { return true }
        var memo = InterestFactMemo()
        for requirement in requirements {
            if requirement.evaluate(
                facts: facts,
                dynamicAI: dynamicAI,
                honeyfiles: honeyfiles,
                nowUptimeNanoseconds: nowUptimeNanoseconds,
                memo: &memo
            ) != .no {
                return true
            }
        }
        return false
    }

    /// Slow diagnostic counterpart to the hot Bool.  It reports every path
    /// that is known-true or unknown, making broad consumers visible.
    public func diagnose(
        _ facts: FileEventAdmissionFacts,
        dynamicAI: DynamicAIFileEventDemandSnapshot = .unknown,
        honeyfiles: HoneyfilePathSnapshot = .unknown,
        nowUptimeNanoseconds: UInt64 = DispatchTime.now().uptimeNanoseconds
    ) -> FileEventInterestDecision {
        if let failOpenReason {
            return FileEventInterestDecision(
                admitted: true,
                possibleConsumers: [],
                failOpenReason: failOpenReason
            )
        }
        var memo = InterestFactMemo()
        let possible = requirements.compactMap { requirement -> String? in
            requirement.evaluate(
                facts: facts,
                dynamicAI: dynamicAI,
                honeyfiles: honeyfiles,
                nowUptimeNanoseconds: nowUptimeNanoseconds,
                memo: &memo
            ) == .no ? nil : requirement.id
        }
        return FileEventInterestDecision(
            admitted: !possible.isEmpty,
            possibleConsumers: possible,
            failOpenReason: nil
        )
    }

    /// Grouped evidence only: no global percentage that hides an ineffective
    /// OPEN lane behind a selective BTM or DELETE lane.
    public func effectiveness(
        probes: [FileEventAdmissionFacts],
        dynamicAI: DynamicAIFileEventDemandSnapshot = .unknown,
        honeyfiles: HoneyfilePathSnapshot = .unknown,
        nowUptimeNanoseconds: UInt64 = DispatchTime.now().uptimeNanoseconds
    ) -> [FileEventInterestEffectivenessBucket] {
        struct Key: Hashable { let source: FileEventAdmissionSource; let action: String }
        var buckets: [Key: (evaluated: Int, admitted: Int)] = [:]
        for facts in probes {
            let action: String
            switch facts.eventAction {
            case .value(let value): action = value
            case .absent: action = "<absent>"
            case .unknown: action = "<unknown>"
            }
            let key = Key(source: facts.source, action: action)
            buckets[key, default: (0, 0)].evaluated += 1
            if shouldAdmit(
                facts,
                dynamicAI: dynamicAI,
                honeyfiles: honeyfiles,
                nowUptimeNanoseconds: nowUptimeNanoseconds
            ) {
                buckets[key, default: (0, 0)].admitted += 1
            }
        }
        return buckets.map { key, value in
            FileEventInterestEffectivenessBucket(
                source: key.source,
                action: key.action,
                evaluated: value.evaluated,
                admitted: value.admitted
            )
        }.sorted {
            if $0.source.rawValue != $1.source.rawValue {
                return $0.source.rawValue < $1.source.rawValue
            }
            return $0.action < $1.action
        }
    }
}

// MARK: - Snapshot compiler

public enum FileEventInterestPolicyCompiler {
    public static func compile(
        _ snapshot: FileEventInterestDescriptorSnapshot,
        limits: FileEventInterestPolicyLimits = .default
    ) -> FileEventInterestCompilation {
        var census = FileEventInterestPolicyCensus()
        let complete = Set(FileEventInterestDescriptorSnapshot.Component.allCases)
        let missing = complete.subtracting(snapshot.includedComponents)
            .sorted { $0.rawValue < $1.rawValue }
        guard missing.isEmpty else {
            return FileEventInterestCompilation(
                policy: .admitAll(.incompleteSnapshot(missing: missing)),
                census: census,
                installedRestrictiveSnapshot: false
            )
        }

        var requirementEstimate = 0
        var predicateEstimate = 0
        var conditionNodeEstimate = 0
        var pathRegexPredicateEstimate = 0
        var pathRegexPatternEstimate = 0

        let singles = snapshot.singleEventRules.filter {
            $0.enabled && !$0.isDeprecated && $0.logsource.category == "file_event"
        }
        census.enabledFileSingleRules = singles.count
        requirementEstimate += singles.count
        predicateEstimate += singles.reduce(0) { $0 + $1.predicates.count }
        for predicate in singles.flatMap(\.predicates)
            where predicate.modifier == .regex
                && InterestField(predicate.field).supportsRegexProjection {
            pathRegexPredicateEstimate += 1
            pathRegexPatternEstimate += predicate.values.count
        }
        conditionNodeEstimate += singles.reduce(0) {
            $0 + conditionNodeCount($1.conditionTree, flatPredicateCount: $1.predicates.count)
        }

        let steps = snapshot.sequenceRules
            .filter { $0.enabled && ($0.status ?? "stable").lowercased() != "deprecated" }
            .flatMap { rule in
                rule.steps.filter { $0.logsourceCategory == "file_event" }
                    .map { (rule.id, $0) }
            }
        census.enabledFileSequenceSteps = steps.count
        requirementEstimate += steps.count
        predicateEstimate += steps.reduce(0) { $0 + $1.1.predicates.count }
        for predicate in steps.flatMap({ $0.1.predicates })
            where predicate.modifier == .regex
                && InterestField(predicate.field).supportsRegexProjection {
            pathRegexPredicateEstimate += 1
            pathRegexPatternEstimate += predicate.values.count
        }
        conditionNodeEstimate += steps.reduce(0) {
            $0 + conditionNodeCount($1.1.conditionTree, flatPredicateCount: $1.1.predicates.count)
        }

        let graphNodes = snapshot.graphRules
            .filter { ($0.status ?? "stable").lowercased() != "deprecated" }
            .flatMap { rule in
                rule.nodes.sorted { $0.key < $1.key }.compactMap { binding, node -> (String, GraphRule.NodeSpec)? in
                    guard node.type == FileNode.entityType || node.type == PersistenceNode.entityType else {
                        return nil
                    }
                    return ("\(rule.id)#\(binding)", node)
                }
            }
        census.graphFileNodeRequirements = graphNodes.filter { $0.1.type == FileNode.entityType }.count
        census.graphPersistenceNodeRequirements = graphNodes.filter { $0.1.type == PersistenceNode.entityType }.count
        requirementEstimate += graphNodes.count

        census.builtinRequirements = snapshot.builtinRequirements.count
        requirementEstimate += snapshot.builtinRequirements.count
        for builtin in snapshot.builtinRequirements {
            if case .predicates(let predicates, _, let tree) = builtin.kind {
                predicateEstimate += predicates.count
                for predicate in predicates
                    where predicate.modifier == .regex
                        && InterestField(predicate.field).supportsRegexProjection {
                    pathRegexPredicateEstimate += 1
                    pathRegexPatternEstimate += predicate.values.count
                }
                conditionNodeEstimate += conditionNodeCount(tree, flatPredicateCount: predicates.count)
            }
        }

        if requirementEstimate > limits.maximumRequirements {
            return failedLimit("requirements \(requirementEstimate) > \(limits.maximumRequirements)", census)
        }
        if predicateEstimate > limits.maximumPredicates {
            return failedLimit("predicates \(predicateEstimate) > \(limits.maximumPredicates)", census)
        }
        if conditionNodeEstimate > limits.maximumConditionNodes {
            return failedLimit("condition nodes \(conditionNodeEstimate) > \(limits.maximumConditionNodes)", census)
        }
        if pathRegexPredicateEstimate > limits.maximumPathRegexPredicates {
            return failedLimit(
                "path regex predicates \(pathRegexPredicateEstimate) > \(limits.maximumPathRegexPredicates)",
                census
            )
        }
        if pathRegexPatternEstimate > limits.maximumPathRegexPatterns {
            return failedLimit(
                "path regex patterns \(pathRegexPatternEstimate) > \(limits.maximumPathRegexPatterns)",
                census
            )
        }

        var requirements: [CompiledFileEventRequirement] = []
        requirements.reserveCapacity(requirementEstimate)

        // Put cheap/broad built-ins first.  Most ordinary callbacks are needed
        // by cross-process correlation, so they should not walk 100+ Sigma
        // expressions merely to reach the same admit verdict.
        for builtin in snapshot.builtinRequirements {
            switch builtin.kind {
            case .predicates(let predicates, let condition, let tree):
                let compiled = compilePredicateRequirement(
                    predicates: predicates,
                    condition: condition,
                    conditionTree: tree,
                    census: &census
                )
                requirements.append(.predicates(
                    id: builtin.id,
                    sources: builtin.sources,
                    compiled
                ))
            case .crossProcessCorrelation:
                requirements.append(.crossProcess(id: builtin.id, sources: builtin.sources))
            case .dynamicAIConsumers:
                requirements.append(.dynamicAI(id: builtin.id, sources: builtin.sources))
            case .unconditional:
                requirements.append(.unconditional(id: builtin.id, sources: builtin.sources))
            }
        }

        for (id, node) in graphNodes {
            requirements.append(.graph(
                id: id,
                GraphNodeRequirement(type: node.type, clauses: node.where ?? [:])
            ))
        }

        for (ruleID, step) in steps {
            let compiled = compilePredicateRequirement(
                predicates: step.predicates,
                condition: step.condition,
                conditionTree: step.conditionTree,
                census: &census
            )
            requirements.append(.predicates(
                id: "\(ruleID)#\(step.id)",
                sources: nil,
                compiled
            ))
        }

        for rule in singles {
            let compiled = compilePredicateRequirement(
                predicates: rule.predicates,
                condition: rule.condition,
                conditionTree: rule.conditionTree,
                census: &census
            )
            requirements.append(.predicates(id: rule.id, sources: nil, compiled))
        }

        return FileEventInterestCompilation(
            policy: FileEventInterestPolicy(requirements: requirements),
            census: census,
            installedRestrictiveSnapshot: true
        )
    }

    private static func failedLimit(
        _ detail: String,
        _ census: FileEventInterestPolicyCensus
    ) -> FileEventInterestCompilation {
        FileEventInterestCompilation(
            policy: .admitAll(.resourceLimit(detail)),
            census: census,
            installedRestrictiveSnapshot: false
        )
    }

    private static func conditionNodeCount(
        _ tree: ConditionNode?,
        flatPredicateCount: Int
    ) -> Int {
        guard let tree else { return max(1, flatPredicateCount) }
        var stack = [tree]
        var count = 0
        while let node = stack.popLast() {
            count += 1
            switch node {
            case .and(let children), .or(let children): stack.append(contentsOf: children)
            case .not(let child): stack.append(child)
            case .predicate, .predicateGroup: break
            }
        }
        return count
    }

    private static func compilePredicateRequirement(
        predicates: [Predicate],
        condition: RuleCondition,
        conditionTree: ConditionNode?,
        census: inout FileEventInterestPolicyCensus
    ) -> PredicateRequirement {
        let compiledPredicates = predicates.map(InterestPredicate.init)
        census.compiledPredicates += compiledPredicates.count
        census.unsupportedPredicates += compiledPredicates.filter { $0.field == .unsupported }.count
        for predicate in compiledPredicates where predicate.modifier == .regex {
            if predicate.regexProjections != nil {
                census.projectedPathRegexPredicates += 1
            } else {
                census.unsupportedPathRegexPredicates += 1
            }
        }

        let compiledCondition: InterestCondition
        if let conditionTree {
            do {
                try conditionTree.validate(predicateCount: predicates.count)
                compiledCondition = compileConditionNode(conditionTree, predicates: predicates)
            } catch {
                // A loaded engine rule has already passed validation.  If a
                // programmatic/operator descriptor bypasses that boundary, it
                // becomes an always-possible requirement rather than changing
                // meaning or being silently omitted.
                census.malformedConditionsMadeBroad += 1
                compiledCondition = .unknown
            }
        } else {
            compiledCondition = compileGroup(
                Array(predicates.indices),
                mode: condition,
                predicates: predicates
            )
        }
        return PredicateRequirement(
            predicates: compiledPredicates,
            condition: compiledCondition
        )
    }

    private static func compileConditionNode(
        _ node: ConditionNode,
        predicates: [Predicate]
    ) -> InterestCondition {
        switch node {
        case .and(let operands):
            return .all(operands.map { compileConditionNode($0, predicates: predicates) })
        case .or(let operands):
            return .any(operands.map { compileConditionNode($0, predicates: predicates) })
        case .not(let operand):
            return .not(compileConditionNode(operand, predicates: predicates))
        case .predicate(let index):
            return .predicate(index)
        case .predicateGroup(let range, let mode):
            return compileGroup(Array(range), mode: mode, predicates: predicates)
        }
    }

    private static func compileGroup(
        _ indices: [Int],
        mode: RuleCondition,
        predicates: [Predicate]
    ) -> InterestCondition {
        switch mode {
        case .allOf:
            return .all(indices.map(InterestCondition.predicate))
        case .anyOf:
            return .any(indices.map(InterestCondition.predicate))
        case .oneOfEach:
            var order: [String] = []
            var groups: [String: [InterestCondition]] = [:]
            for index in indices where predicates.indices.contains(index) {
                let field = predicates[index].field
                if groups[field] == nil { order.append(field) }
                groups[field, default: []].append(.predicate(index))
            }
            return .all(order.map { .any(groups[$0] ?? []) })
        }
    }
}

// MARK: - Atomic live registry

/// Lock-backed immutable snapshot swap for a synchronous ES callback.  No rule
/// actor hop is needed on admission; reload owners compile a complete snapshot
/// off-path and install it in one lock acquisition.
public final class FileEventInterestPolicyRegistry: @unchecked Sendable {
    private struct State {
        var policy: FileEventInterestPolicy = .admitAll(.noDescriptorSnapshot)
        var dynamicAI: DynamicAIFileEventDemandSnapshot = .unknown
        /// Short, per-PID bridge between a fork/exec observation and the next
        /// complete AI-owner publication. Expired entries are harmless and are
        /// pruned only off the callback path.
        var dynamicAIGrace: [Int32: UInt64] = [:]
        var honeyfiles: HoneyfilePathSnapshot = .unknown
        var generation: UInt64 = 0
    }

    private let state = OSAllocatedUnfairLock<State>(initialState: State())
    private let limits: FileEventInterestPolicyLimits

    public init(limits: FileEventInterestPolicyLimits = .default) {
        self.limits = limits
    }

    public var generation: UInt64 { state.withLock { $0.generation } }

    /// Installs either the compiled policy or an explicit admit-all failure
    /// policy.  Keeping an older restrictive snapshot after a failed reload
    /// would be unsafe: the new rule that failed compilation might need the
    /// callback the stale policy rejects.
    @discardableResult
    public func install(
        _ snapshot: FileEventInterestDescriptorSnapshot
    ) -> FileEventInterestCompilation {
        let compilation = FileEventInterestPolicyCompiler.compile(snapshot, limits: limits)
        state.withLock { locked in
            locked.policy = compilation.policy
            locked.generation &+= 1
        }
        return compilation
    }

    /// Invalid/oversized dynamic publication becomes unknown, hence admit.
    @discardableResult
    public func publishDynamicAI(
        _ snapshot: DynamicAIFileEventDemandSnapshot
    ) -> Bool {
        let accepted = Self.dynamicSnapshotWithinBounds(snapshot, limits: limits)
        state.withLock { locked in
            locked.dynamicAI = accepted ? snapshot : .unknown
            locked.generation &+= 1
        }
        return accepted
    }

    /// Admit one newly-observed process until AIProcessTracker publishes the
    /// next complete session snapshot. Callers grant this only when a fork/exec
    /// is an AI root or descends from a currently-attributed PID; it is not a
    /// general process-start grace. The map is fixed-cardinality and expiry is
    /// monotonic-clock based.
    @discardableResult
    public func grantDynamicAIGrace(
        processID: Int32,
        validUntilUptimeNanoseconds: UInt64,
        nowUptimeNanoseconds: UInt64 = DispatchTime.now().uptimeNanoseconds
    ) -> Bool {
        state.withLock { locked in
            guard validUntilUptimeNanoseconds > nowUptimeNanoseconds else {
                return false
            }
            if locked.dynamicAIGrace[processID] == nil,
               locked.dynamicAIGrace.count >= limits.maximumDynamicGraceProcessIDs {
                locked.dynamicAIGrace = locked.dynamicAIGrace.filter {
                    $0.value > nowUptimeNanoseconds
                }
            }
            guard locked.dynamicAIGrace[processID] != nil
                    || locked.dynamicAIGrace.count < limits.maximumDynamicGraceProcessIDs else {
                // A bound failure cannot safely reject the process whose
                // attribution is racing publication. Temporarily fail open;
                // the next complete publish restores restrictive state.
                locked.dynamicAI = .unknown
                locked.dynamicAIGrace.removeAll(keepingCapacity: true)
                locked.generation &+= 1
                return false
            }
            locked.dynamicAIGrace[processID] = max(
                locked.dynamicAIGrace[processID] ?? 0,
                validUntilUptimeNanoseconds
            )
            locked.generation &+= 1
            return true
        }
    }

    /// Exit/reconciliation hook. No callback depends on eager removal because
    /// every entry also expires, but revocation closes PID-reuse over-admission.
    public func revokeDynamicAIGrace(processID: Int32) {
        state.withLock { locked in
            if locked.dynamicAIGrace.removeValue(forKey: processID) != nil {
                locked.generation &+= 1
            }
        }
    }

    /// Callback-safe ancestry bridge used only for fork/exec admission. A
    /// positive result means the PID is present in a fresh complete owner
    /// snapshot (or its narrowly-targeted, unexpired publication grace). False
    /// also covers unknown/stale state: callers must never infer that a file
    /// callback is irrelevant from this helper; they use it only to decide
    /// whether a newly-created descendant should receive its own fail-open
    /// grace while EventLoop publishes the next complete snapshot.
    @inline(__always)
    public func isKnownDynamicAIProcess(
        _ processID: Int32,
        nowUptimeNanoseconds: UInt64 = DispatchTime.now().uptimeNanoseconds
    ) -> Bool {
        state.withLock { locked in
            if let expiry = locked.dynamicAIGrace[processID],
               nowUptimeNanoseconds <= expiry {
                return true
            }
            let snapshot = locked.dynamicAI
            guard snapshot.state == .current,
                  nowUptimeNanoseconds <= snapshot.validUntilUptimeNanoseconds else {
                return false
            }
            return snapshot.attributedProcessIDs.contains(processID)
                || snapshot.demands.contains {
                    $0.processID == nil || $0.processID == processID
                }
        }
    }

    /// Must be called before a honeyfile/honey-prompt manifest reload, deploy,
    /// or removal begins. The callback then admits until a complete post-
    /// mutation union is atomically published.
    public func invalidateHoneyfiles() {
        state.withLock { locked in
            locked.honeyfiles = .unknown
            locked.generation &+= 1
        }
    }

    public func publishHoneyfiles(_ snapshot: HoneyfilePathSnapshot) {
        state.withLock { locked in
            locked.honeyfiles = snapshot
            locked.generation &+= 1
        }
    }

    @inline(__always)
    public func shouldAdmit(
        _ facts: FileEventAdmissionFacts,
        nowUptimeNanoseconds: UInt64 = DispatchTime.now().uptimeNanoseconds
    ) -> Bool {
        let snapshot = state.withLock { locked in
            let dynamicAI: DynamicAIFileEventDemandSnapshot
            if case .value(let pid) = facts.processID,
               let expiry = locked.dynamicAIGrace[pid],
               nowUptimeNanoseconds <= expiry {
                dynamicAI = .unknown
            } else {
                dynamicAI = locked.dynamicAI
            }
            return (locked.policy, dynamicAI, locked.honeyfiles)
        }
        return snapshot.0.shouldAdmit(
            facts,
            dynamicAI: snapshot.1,
            honeyfiles: snapshot.2,
            nowUptimeNanoseconds: nowUptimeNanoseconds
        )
    }

    public func diagnose(
        _ facts: FileEventAdmissionFacts,
        nowUptimeNanoseconds: UInt64 = DispatchTime.now().uptimeNanoseconds
    ) -> FileEventInterestDecision {
        let snapshot = state.withLock { locked in
            let dynamicAI: DynamicAIFileEventDemandSnapshot
            if case .value(let pid) = facts.processID,
               let expiry = locked.dynamicAIGrace[pid],
               nowUptimeNanoseconds <= expiry {
                dynamicAI = .unknown
            } else {
                dynamicAI = locked.dynamicAI
            }
            return (locked.policy, dynamicAI, locked.honeyfiles)
        }
        return snapshot.0.diagnose(
            facts,
            dynamicAI: snapshot.1,
            honeyfiles: snapshot.2,
            nowUptimeNanoseconds: nowUptimeNanoseconds
        )
    }

    private static func dynamicSnapshotWithinBounds(
        _ snapshot: DynamicAIFileEventDemandSnapshot,
        limits: FileEventInterestPolicyLimits
    ) -> Bool {
        guard snapshot.state == .current else { return true }
        let demands = snapshot.demands
        guard demands.count <= limits.maximumDynamicDemands else { return false }
        guard limits.maximumDynamicPatterns >= 0 else { return false }
        var patterns = 0
        for demand in demands {
            let count = demand.path.patternCount
            guard count <= limits.maximumDynamicPatterns - patterns else {
                return false
            }
            patterns += count
        }
        var patternBytes = 0
        for demand in demands {
            guard demand.path.accumulateBoundedPatternBytes(
                into: &patternBytes,
                maximumPatternBytes: limits.maximumDynamicPatternUTF8Bytes,
                maximumTotalBytes: limits.maximumDynamicPatternBytes
            ) else {
                return false
            }
        }
        return true
    }
}

extension DynamicFileEventPathDemand {
    fileprivate var patternCount: Int {
        switch self {
        case .any: return 0
        case .supportedTextFile, .agentContentFile, .defaultCredentialFence:
            return 1
        case .projectBoundaryOutside(let roots):
            return roots.count
        case .equals(let values, _), .prefixes(let values, _),
             .suffixes(let values, _), .contains(let values, _),
             .outsideRoots(let values, _):
            return values.count
        case .extensions(let values, _):
            return values.count
        case .outsideRootsExcluding(let roots, let exact, let substrings, _):
            return roots.count + exact.count + substrings.count
        }
    }

    fileprivate func accumulateBoundedPatternBytes(
        into total: inout Int,
        maximumPatternBytes: Int,
        maximumTotalBytes: Int
    ) -> Bool {
        func add<S: Sequence>(_ values: S) -> Bool where S.Element == String {
            guard maximumPatternBytes >= 0, maximumTotalBytes >= 0,
                  total >= 0, total <= maximumTotalBytes else {
                return false
            }
            let scanLimit = maximumPatternBytes == Int.max
                ? Int.max : maximumPatternBytes + 1
            for value in values {
                let count = value.utf8.prefix(scanLimit).count
                guard count <= maximumPatternBytes,
                      count <= maximumTotalBytes,
                      total <= maximumTotalBytes - count else {
                    return false
                }
                total += count
            }
            return true
        }

        switch self {
        case .any, .supportedTextFile, .agentContentFile, .defaultCredentialFence:
            return true
        case .projectBoundaryOutside(let roots),
             .equals(let roots, _), .prefixes(let roots, _),
             .suffixes(let roots, _), .contains(let roots, _),
             .outsideRoots(let roots, _):
            return add(roots)
        case .extensions(let values, _):
            return add(values)
        case .outsideRootsExcluding(let roots, let exact, let substrings, _):
            return add(roots) && add(exact) && add(substrings)
        }
    }
}
