// HeavyEnrichmentPlane.swift
// MacCrabCore
//
// Bounded ownership for enrichment work that may block in Security.framework,
// sysctl, or filesystem I/O.  The event-ingestion lanes submit work here and
// keep moving; completed evidence is returned through an event-identity-bound
// deferred patch for a later detection pass.

import Foundation
import Darwin

// MARK: - Public evidence contract

/// Expensive evidence families owned by ``HeavyEnrichmentPlane``.
///
/// Raw values are deliberately fixed and are also used in the compact event
/// coverage marker.  Do not put paths, PIDs, rule IDs, or other event-derived
/// values into telemetry field names.
public enum HeavyEnrichmentComponent: String, Codable, Sendable, Hashable, CaseIterable {
    case codeSignature = "code_signature"
    case processHashes = "process_hashes"
    case environment
    case fileContent = "file_content"
    case userName = "user_name"
}

/// Compact dependency set shared by the single-event and sequence engines.
///
/// This is deliberately a fixed-width value rather than a `Set`: dependency
/// checks run before predicate evaluation and deferred replay must not add
/// allocation or hashing to either detection path.
public struct HeavyEnrichmentDependencyMask: OptionSet, Sendable, Hashable {
    public let rawValue: UInt8

    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }

    public static let codeSignature = Self(rawValue: 1 << 0)
    public static let processHashes = Self(rawValue: 1 << 1)
    public static let environment = Self(rawValue: 1 << 2)
    public static let fileContent = Self(rawValue: 1 << 3)
    public static let userName = Self(rawValue: 1 << 4)

    public init(components: Set<HeavyEnrichmentComponent>) {
        self = components.reduce(into: Self()) { result, component in
            result.formUnion(component.dependencyMask)
        }
    }
}

public extension HeavyEnrichmentComponent {
    var dependencyMask: HeavyEnrichmentDependencyMask {
        switch self {
        case .codeSignature: return .codeSignature
        case .processHashes: return .processHashes
        case .environment: return .environment
        case .fileContent: return .fileContent
        case .userName: return .userName
        }
    }

    /// Worst-case value ownership reserved before a heavyweight operation is
    /// accepted. Callers with a tighter authoritative bound (notably the file
    /// content scanner) pass it to `offer`; these defaults remain fail-safe for
    /// direct users of the plane.
    var defaultMaximumResultBytes: Int {
        switch self {
        case .codeSignature: return 256 * 1_024
        case .processHashes: return 4 * 1_024
        case .environment: return 8 * 1_024 * 1_024
        case .fileContent: return 64 * 1_024
        case .userName: return 16 * 1_024
        }
    }

    /// The one authoritative mapping from rule field names (canonical paths
    /// and supported Sigma aliases) to heavyweight evidence ownership.
    /// Numeric user IDs are intentionally absent: they are present on the raw
    /// event and do not depend on username resolution.
    static func dependency(forPredicateField field: String) -> HeavyEnrichmentComponent? {
        switch field {
        case "process.code_signature.signer_type", "SignerType",
             "process.code_signature.team_id",
             "process.code_signature.signing_id",
             "process.code_signature.flags", "CodeSigningFlags",
             "process.code_signature.notarized",
             "process.code_signature.issuer", "SigningCertIssuer",
             "process.code_signature.cert_hash", "SigningCertHash",
             "process.code_signature.is_adhoc", "IsAdhocSigned",
             "process.is_notarized", "IsNotarized", "NotarizationStatus":
            return .codeSignature

        case "process.hashes.sha256", "ProcessSHA256",
             "process.hashes.cdhash", "ProcessCDHash",
             "process.hashes.md5", "ProcessMD5":
            return .processHashes

        case "process.env", "EnvVarsFlat":
            return .environment

        case "FileContent":
            return .fileContent

        case "process.user.name", "User":
            return .userName

        default:
            return nil
        }
    }
}

/// Coverage/dependency operations used by both rule engines. Keeping tree
/// traversal here prevents the flat, condition-tree, and sequence paths from
/// acquiring different definitions of which evidence a predicate consumes.
enum HeavyEnrichmentRuleCoverage {
    static func dependencyMask(
        predicates: [Predicate],
        conditionTree: ConditionNode?
    ) -> HeavyEnrichmentDependencyMask {
        guard let conditionTree else {
            return predicates.reduce(into: HeavyEnrichmentDependencyMask()) { result, predicate in
                if let component = HeavyEnrichmentComponent.dependency(
                    forPredicateField: predicate.field
                ) {
                    result.formUnion(component.dependencyMask)
                }
            }
        }

        var result = HeavyEnrichmentDependencyMask()
        var stack = [conditionTree]
        while let node = stack.popLast() {
            switch node {
            case .and(let operands), .or(let operands):
                stack.append(contentsOf: operands)
            case .not(let operand):
                stack.append(operand)
            case .predicate(let index):
                guard predicates.indices.contains(index),
                      let component = HeavyEnrichmentComponent.dependency(
                        forPredicateField: predicates[index].field
                      ) else { continue }
                result.formUnion(component.dependencyMask)
            case .predicateGroup(let range, _):
                guard range.lowerBound >= 0,
                      range.upperBound <= predicates.count else { continue }
                for predicate in predicates[range] {
                    if let component = HeavyEnrichmentComponent.dependency(
                        forPredicateField: predicate.field
                    ) {
                        result.formUnion(component.dependencyMask)
                    }
                }
            }
        }
        return result
    }

    static func unresolvedMask(in event: Event) -> HeavyEnrichmentDependencyMask {
        DeferredEventEnrichment.coverage(in: event).keys.reduce(
            into: HeavyEnrichmentDependencyMask()
        ) { result, component in
            result.formUnion(component.dependencyMask)
        }
    }
}

/// Coverage state carried on an event while heavyweight evidence is absent.
public enum HeavyEnrichmentCoverage: String, Codable, Sendable, Hashable {
    case pending
    case rejected
    case timedOut = "timed_out"
    case cancelled
    case unavailable
}

/// A descriptor-derived identity.  A deferred file result is never a
/// path-only cache entry: same-path replacement produces a different identity.
public struct HeavyEnrichmentFileIdentity: Codable, Sendable, Hashable {
    public let deviceID: UInt64
    public let inodeNumber: UInt64
    public let sizeBytes: Int64
    public let modificationSeconds: Int64
    public let modificationNanoseconds: Int64
    public let statusChangeSeconds: Int64
    public let statusChangeNanoseconds: Int64

    public init(
        deviceID: UInt64,
        inodeNumber: UInt64,
        sizeBytes: Int64,
        modificationSeconds: Int64,
        modificationNanoseconds: Int64,
        statusChangeSeconds: Int64,
        statusChangeNanoseconds: Int64
    ) {
        self.deviceID = deviceID
        self.inodeNumber = inodeNumber
        self.sizeBytes = sizeBytes
        self.modificationSeconds = modificationSeconds
        self.modificationNanoseconds = modificationNanoseconds
        self.statusChangeSeconds = statusChangeSeconds
        self.statusChangeNanoseconds = statusChangeNanoseconds
    }

    /// Path metadata is captured only inside a heavyweight worker.  Callers
    /// must compare a before/after pair around path-based Security/hash work;
    /// one observation alone is not a stable snapshot.
    public static func capture(path: String) -> HeavyEnrichmentFileIdentity? {
        var metadata = stat()
        guard path.withCString({ stat($0, &metadata) }) == 0,
              (metadata.st_mode & S_IFMT) == S_IFREG else { return nil }
        return HeavyEnrichmentFileIdentity(
            deviceID: UInt64(metadata.st_dev),
            inodeNumber: UInt64(metadata.st_ino),
            sizeBytes: metadata.st_size,
            modificationSeconds: Int64(metadata.st_mtimespec.tv_sec),
            modificationNanoseconds: Int64(metadata.st_mtimespec.tv_nsec),
            statusChangeSeconds: Int64(metadata.st_ctimespec.tv_sec),
            statusChangeNanoseconds: Int64(metadata.st_ctimespec.tv_nsec)
        )
    }

    init(snapshot: BoundedRegularFileReader.Snapshot) {
        self.init(
            deviceID: snapshot.deviceID,
            inodeNumber: snapshot.inodeNumber,
            sizeBytes: snapshot.sizeBytes,
            modificationSeconds: Int64(snapshot.modificationDate.timeIntervalSince1970.rounded(.down)),
            modificationNanoseconds: Self.nanoseconds(in: snapshot.modificationDate),
            statusChangeSeconds: snapshot.statusChangeSeconds,
            statusChangeNanoseconds: snapshot.statusChangeNanoseconds
        )
    }

    private static func nanoseconds(in date: Date) -> Int64 {
        let seconds = date.timeIntervalSince1970
        let integral = seconds.rounded(.down)
        return Int64(((seconds - integral) * 1_000_000_000).rounded())
    }
}

public struct HeavyCodeSignatureEvidence: Sendable, Equatable {
    public let value: CodeSignatureInfo?
    public let fileIdentity: HeavyEnrichmentFileIdentity?

    public init(value: CodeSignatureInfo?, fileIdentity: HeavyEnrichmentFileIdentity?) {
        self.value = value
        self.fileIdentity = fileIdentity
    }
}

public struct HeavyProcessHashEvidence: Sendable, Equatable {
    public let value: ProcessHashes?
    public let fileIdentity: HeavyEnrichmentFileIdentity?

    public init(value: ProcessHashes?, fileIdentity: HeavyEnrichmentFileIdentity?) {
        self.value = value
        self.fileIdentity = fileIdentity
    }
}

public struct HeavyFileContentEvidence: Sendable, Equatable {
    public let content: String
    public let fileIdentity: HeavyEnrichmentFileIdentity

    public init(content: String, fileIdentity: HeavyEnrichmentFileIdentity) {
        self.content = content
        self.fileIdentity = fileIdentity
    }

    /// Descriptor-relative, no-follow, stable-snapshot content read used by
    /// the heavy plane.  The old FileContentEnricher token bucket returned nil
    /// on overload, losing the only event that proved a completed write.  Plane
    /// admission now makes overload explicit and conserves every accepted read.
    public static func read(
        path: String,
        maximumBytes: Int,
        maximumFileSize: Int64
    ) -> HeavyFileContentEvidence? {
        guard case .success(let snapshot) = BoundedRegularFileReader.readPrefixOutcome(
            at: path,
            maximumBytes: maximumBytes
        ), snapshot.sizeBytes <= maximumFileSize,
           let content = String(data: snapshot.data, encoding: .utf8) else {
            return nil
        }
        return HeavyFileContentEvidence(
            content: content,
            fileIdentity: HeavyEnrichmentFileIdentity(snapshot: snapshot)
        )
    }
}

/// Type-safe value returned by a heavyweight operation.
public enum HeavyEnrichmentValue: Sendable, Equatable {
    case codeSignature(HeavyCodeSignatureEvidence)
    case processHashes(HeavyProcessHashEvidence)
    case environment([String: String]?)
    case fileContent(HeavyFileContentEvidence?)
    case userName(String?)

    /// Conservative graph/string charge used by both sides of the deferred
    /// transfer. This is memory accounting, not canonical identity, so a cheap
    /// field-wise calculation is preferable to encoding or reflection.
    public var retainedByteEstimate: Int {
        switch self {
        case .codeSignature(let evidence):
            guard let value = evidence.value else { return 512 }
            var bytes = 1_024
            bytes = Self.add(bytes, value.teamId)
            bytes = Self.add(bytes, value.signingId)
            bytes = Self.add(bytes, value.authorities)
            bytes = Self.add(bytes, value.issuerChain ?? [])
            bytes = Self.add(bytes, value.certHashes ?? [])
            bytes = Self.add(bytes, value.entitlements ?? [])
            return bytes
        case .processHashes(let evidence):
            guard let value = evidence.value else { return 512 }
            var bytes = 512
            bytes = Self.add(bytes, value.sha256)
            bytes = Self.add(bytes, value.cdhash)
            bytes = Self.add(bytes, value.md5)
            return bytes
        case .environment(let environment):
            guard let environment else { return 512 }
            var bytes = 1_024
            for (key, value) in environment {
                bytes = Self.add(bytes, key.utf8.count)
                bytes = Self.add(bytes, value.utf8.count)
                bytes = Self.add(bytes, 128)
            }
            return bytes
        case .fileContent(let evidence):
            guard let evidence else { return 512 }
            return Self.add(512, evidence.content.utf8.count)
        case .userName(let value):
            return Self.add(256, value?.utf8.count ?? 0)
        }
    }

    private static func add(_ current: Int, _ value: String?) -> Int {
        add(current, value?.utf8.count ?? 0)
    }

    private static func add(_ current: Int, _ values: [String]) -> Int {
        values.reduce(current) { partial, value in
            add(add(partial, value.utf8.count), 64)
        }
    }

    private static func add(_ lhs: Int, _ rhs: Int) -> Int {
        let sum = lhs.addingReportingOverflow(max(0, rhs))
        return sum.overflow ? Int.max : sum.partialValue
    }

    fileprivate var hasEvidence: Bool {
        switch self {
        case .codeSignature(let evidence):
            return evidence.value != nil && evidence.fileIdentity != nil
        case .processHashes(let evidence):
            return evidence.value != nil && evidence.fileIdentity != nil
        case .environment(let value):
            return value != nil
        case .fileContent(let value):
            return value != nil
        case .userName(let value):
            return value?.isEmpty == false
        }
    }
}

/// Stable identity of the event to which a result may be applied.  Event ID is
/// necessary but not sufficient: process PID/start/executable and file path/
/// size prevent a caller from accidentally replaying a patch onto a rebuilt or
/// same-path replacement event.
public struct HeavyEnrichmentBinding: Sendable, Hashable {
    public let eventID: UUID
    public let processID: Int32
    public let processStartTime: Date
    public let executablePath: String
    public let userID: UInt32
    public let filePath: String?
    public let eventFileSize: UInt64?

    public init(event: Event) {
        eventID = event.id
        processID = event.process.pid
        processStartTime = event.process.startTime
        executablePath = event.process.executable
        userID = event.process.userId
        filePath = event.file?.path
        eventFileSize = event.file?.size
    }

    public func matches(_ event: Event) -> Bool {
        event.id == eventID
            && event.process.pid == processID
            && event.process.startTime == processStartTime
            && event.process.executable == executablePath
            && event.process.userId == userID
            && event.file?.path == filePath
            && event.file?.size == eventFileSize
    }

    public var retainedByteEstimate: Int {
        let strings = [executablePath, filePath ?? ""]
        return strings.reduce(512) { partial, value in
            let sum = partial.addingReportingOverflow(value.utf8.count + 64)
            return sum.overflow ? Int.max : sum.partialValue
        }
    }
}

/// Off-hot-path libproc proof used around sysctl environment capture.
/// Returning false on any uncertainty is deliberate: absence is deferred
/// coverage; attaching another process's environment is false evidence.
enum HeavyEnrichmentLiveProcessIdentity {
    static func matches(_ binding: HeavyEnrichmentBinding) -> Bool {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(
            binding.processID,
            PROC_PIDTBSDINFO,
            0,
            &info,
            size
        ) == size else { return false }

        let observedStart = TimeInterval(info.pbi_start_tvsec)
            + TimeInterval(info.pbi_start_tvusec) / 1_000_000
        guard abs(observedStart - binding.processStartTime.timeIntervalSince1970) < 0.01 else {
            return false
        }

        var pathBuffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard proc_pidpath(
            binding.processID,
            &pathBuffer,
            UInt32(pathBuffer.count)
        ) > 0 else { return false }
        return String(cString: pathBuffer) == binding.executablePath
    }
}

public struct HeavyEnrichmentTicket: Codable, Sendable, Hashable {
    public let rawValue: UUID
    public init(rawValue: UUID = UUID()) { self.rawValue = rawValue }
}

public enum HeavyEnrichmentTerminalOutcome: String, Codable, Sendable, Hashable {
    case completed
    case timedOut = "timed_out"
    case cancelled
}

/// One terminal deferred patch.  A patch is emitted for every accepted offer,
/// including coalesced subscribers and timeout/cancellation outcomes.
public struct DeferredEventEnrichment: Sendable, Equatable {
    public let ticket: HeavyEnrichmentTicket
    public let binding: HeavyEnrichmentBinding
    public let component: HeavyEnrichmentComponent
    public let outcome: HeavyEnrichmentTerminalOutcome
    public let value: HeavyEnrichmentValue?

    public init(
        ticket: HeavyEnrichmentTicket,
        binding: HeavyEnrichmentBinding,
        component: HeavyEnrichmentComponent,
        outcome: HeavyEnrichmentTerminalOutcome,
        value: HeavyEnrichmentValue?
    ) {
        self.ticket = ticket
        self.binding = binding
        self.component = component
        self.outcome = outcome
        self.value = value
    }

    public var retainedByteEstimate: Int {
        let valueBytes = value?.retainedByteEstimate ?? 512
        let bindingBytes = binding.retainedByteEstimate
        let sum = bindingBytes.addingReportingOverflow(valueBytes)
        guard !sum.overflow else { return Int.max }
        let overhead = sum.partialValue.addingReportingOverflow(512)
        return overhead.overflow ? Int.max : overhead.partialValue
    }

    /// Applies the patch only to the exact event/process/file identity it was
    /// created for.  Returns nil on any mismatch rather than risking stale
    /// signing or content evidence.
    public func applying(to event: Event) -> Event? {
        guard binding.matches(event) else { return nil }

        var coverage = Self.parseCoverage(event.enrichments[Self.coverageKey])
        let terminalCoverage: HeavyEnrichmentCoverage?
        switch outcome {
        case .timedOut:
            terminalCoverage = .timedOut
        case .cancelled:
            terminalCoverage = .cancelled
        case .completed:
            terminalCoverage = value?.hasEvidence == true ? nil : .unavailable
        }

        var codeSignature = event.process.codeSignature
        var hashes = event.process.hashes
        var envVars = event.process.envVars
        var userName = event.process.userName
        var enrichments = event.enrichments

        if outcome == .completed, let value {
            switch (component, value) {
            case (.codeSignature, .codeSignature(let evidence)):
                guard evidence.value == nil || evidence.fileIdentity != nil else {
                    return nil
                }
                codeSignature = evidence.value
            case (.processHashes, .processHashes(let evidence)):
                guard evidence.value == nil || evidence.fileIdentity != nil else {
                    return nil
                }
                hashes = evidence.value
            case (.environment, .environment(let environment)):
                envVars = environment
            case (.fileContent, .fileContent(let evidence)):
                if let evidence {
                    if let expectedSize = binding.eventFileSize,
                       UInt64(exactly: evidence.fileIdentity.sizeBytes) != expectedSize {
                        return nil
                    }
                    enrichments["FileContent"] = evidence.content
                }
            case (.userName, .userName(let resolved)):
                if let resolved, !resolved.isEmpty { userName = resolved }
            default:
                // A component/value mismatch is an internal contract breach.
                // Refuse the patch instead of applying evidence to the wrong
                // field family.
                return nil
            }
        }

        if let terminalCoverage {
            coverage[component] = terminalCoverage
        } else {
            coverage.removeValue(forKey: component)
        }
        Self.storeCoverage(coverage, in: &enrichments)

        let process = ProcessInfo(
            pid: event.process.pid,
            ppid: event.process.ppid,
            rpid: event.process.rpid,
            name: event.process.name,
            executable: event.process.executable,
            commandLine: event.process.commandLine,
            args: event.process.args,
            workingDirectory: event.process.workingDirectory,
            userId: event.process.userId,
            userName: userName,
            groupId: event.process.groupId,
            startTime: event.process.startTime,
            exitCode: event.process.exitCode,
            codeSignature: codeSignature,
            ancestors: event.process.ancestors,
            architecture: event.process.architecture,
            isPlatformBinary: event.process.isPlatformBinary,
            hashes: hashes,
            session: event.process.session,
            envVars: envVars,
            auditIdentity: event.process.auditIdentity
        )
        return Event(
            id: event.id,
            timestamp: event.timestamp,
            eventCategory: event.eventCategory,
            eventType: event.eventType,
            eventAction: event.eventAction,
            process: process,
            file: event.file,
            network: event.network,
            tcc: event.tcc,
            enrichments: enrichments,
            severity: event.severity,
            ruleMatches: event.ruleMatches
        )
    }

    /// Consumes a terminal patch whose evidence failed identity or contract
    /// validation without attaching any of its value. The heavy-plane offer
    /// has nevertheless terminated, so leaving this component `.pending`
    /// would permanently retain the Event and eventually deadlock ingestion.
    ///
    /// Event UUID is the only patch field trusted here. No evidence or binding
    /// metadata crosses into the returned Event; the component is recorded as
    /// explicit degraded coverage instead.
    public func terminalizingRejectedEvidence(in event: Event) -> Event? {
        guard binding.eventID == event.id else { return nil }
        var coverage = Self.parseCoverage(event.enrichments[Self.coverageKey])
        guard coverage[component] == .pending else { return nil }

        switch outcome {
        case .timedOut:
            coverage[component] = .timedOut
        case .cancelled:
            coverage[component] = .cancelled
        case .completed:
            coverage[component] = .unavailable
        }
        var revised = event
        Self.storeCoverage(coverage, in: &revised.enrichments)
        return revised
    }

    public static let coverageKey = "HeavyEnrichmentCoverage"

    public static func coverage(
        in event: Event
    ) -> [HeavyEnrichmentComponent: HeavyEnrichmentCoverage] {
        parseCoverage(event.enrichments[coverageKey])
    }

    public static func coverageState(
        for component: HeavyEnrichmentComponent,
        in event: Event
    ) -> HeavyEnrichmentCoverage? {
        coverage(in: event)[component]
    }

    public static func hasPendingCoverage(in event: Event) -> Bool {
        coverage(in: event).values.contains(.pending)
    }

    /// Compact deterministic marker.  Only degraded/pending components are
    /// stored, avoiding five extra strings on every high-volume event.
    public static func coverageMarker(
        _ coverage: [HeavyEnrichmentComponent: HeavyEnrichmentCoverage]
    ) -> String? {
        guard !coverage.isEmpty else { return nil }
        return HeavyEnrichmentComponent.allCases.compactMap { component in
            coverage[component].map { "\(component.rawValue):\($0.rawValue)" }
        }.joined(separator: ",")
    }

    static func parseCoverage(
        _ marker: String?
    ) -> [HeavyEnrichmentComponent: HeavyEnrichmentCoverage] {
        guard let marker else { return [:] }
        var result: [HeavyEnrichmentComponent: HeavyEnrichmentCoverage] = [:]
        for entry in marker.split(separator: ",") {
            let pieces = entry.split(separator: ":", maxSplits: 1)
            guard pieces.count == 2,
                  let component = HeavyEnrichmentComponent(rawValue: String(pieces[0])),
                  let coverage = HeavyEnrichmentCoverage(rawValue: String(pieces[1])) else { continue }
            result[component] = coverage
        }
        return result
    }

    static func storeCoverage(
        _ coverage: [HeavyEnrichmentComponent: HeavyEnrichmentCoverage],
        in enrichments: inout [String: String]
    ) {
        if let marker = coverageMarker(coverage) {
            enrichments[coverageKey] = marker
        } else {
            enrichments.removeValue(forKey: coverageKey)
        }
    }
}

/// Package-internal transfer envelope. Production moves the same aggregate
/// memory lease from the heavy plane into DeferredEnrichmentBuffer, so the
/// handoff never creates an uncharged or double-charged patch window.
package struct OwnedDeferredEventEnrichment: Sendable {
    package let patch: DeferredEventEnrichment
    package let memoryLease: EventPipelineMemoryLease

    package init(
        patch: DeferredEventEnrichment,
        memoryLease: EventPipelineMemoryLease
    ) {
        self.patch = patch
        self.memoryLease = memoryLease
    }
}

// MARK: - Plane lifecycle

public struct HeavyEnrichmentPlaneConfiguration: Sendable, Equatable {
    public let maximumConcurrentWorkers: Int
    public let maximumQueuedWorkItems: Int
    public let maximumOutstandingResults: Int
    public let maximumRetainedResultBytes: Int
    public let cacheCapacity: Int
    public let operationTimeoutSeconds: TimeInterval

    public init(
        maximumConcurrentWorkers: Int = 4,
        maximumQueuedWorkItems: Int = 128,
        maximumOutstandingResults: Int = 512,
        maximumRetainedResultBytes: Int = EventPipelineLiveMemoryBudget
            .productionMaximumBytes
                - EventPipelineLiveMemoryBudget
                    .productionForwardProgressReserveBytes,
        cacheCapacity: Int = 256,
        operationTimeoutSeconds: TimeInterval = 0.050
    ) {
        precondition(maximumConcurrentWorkers > 0)
        precondition(maximumQueuedWorkItems >= 0)
        precondition(maximumOutstandingResults > 0)
        precondition(maximumRetainedResultBytes > 0)
        precondition(cacheCapacity >= 0)
        precondition(operationTimeoutSeconds >= 0)
        self.maximumConcurrentWorkers = maximumConcurrentWorkers
        self.maximumQueuedWorkItems = maximumQueuedWorkItems
        self.maximumOutstandingResults = maximumOutstandingResults
        self.maximumRetainedResultBytes = maximumRetainedResultBytes
        self.cacheCapacity = cacheCapacity
        self.operationTimeoutSeconds = operationTimeoutSeconds
    }
}

public struct HeavyEnrichmentPlaneSnapshot: Sendable, Equatable {
    public let accepting: Bool
    public let offeredRequestsTotal: UInt64
    public let completedRequestsTotal: UInt64
    public let timedOutRequestsTotal: UInt64
    public let cancelledRequestsTotal: UInt64
    public let rejectedRequestsTotal: UInt64
    public let cacheHitsTotal: UInt64
    public let coalescedRequestsTotal: UInt64
    public let lateWorkerExitsTotal: UInt64
    public let queuedRequests: Int
    public let runningRequests: Int
    public let physicalWorkers: Int
    public let lingeringTimedOutOrCancelledWorkers: Int
    public let deferredResults: Int
    public let activeReservedResultBytes: Int
    public let deferredResultBytes: Int
    public let cacheResultBytes: Int
    public let retainedResultBytesHighWatermark: Int
    public let maximumRetainedResultBytes: Int
    public let oversizedResultValuesTotal: UInt64
    public let lingeringReservationSplitRefusalsTotal: UInt64
    public let cachedResults: Int
    public let maximumConcurrentWorkers: Int

    public var requestsConserved: Bool {
        let accounted = [
            completedRequestsTotal,
            timedOutRequestsTotal,
            cancelledRequestsTotal,
            rejectedRequestsTotal,
            UInt64(queuedRequests),
            UInt64(runningRequests),
        ].reduce(UInt64(0)) { partial, next in
            let sum = partial.addingReportingOverflow(next)
            return sum.overflow ? UInt64.max : sum.partialValue
        }
        return offeredRequestsTotal == accounted
    }

    public var physicalCapacityConserved: Bool {
        physicalWorkers <= maximumConcurrentWorkers
    }

    public var resultByteCapacityConserved: Bool {
        guard activeReservedResultBytes >= 0,
              deferredResultBytes >= 0,
              cacheResultBytes >= 0,
              activeReservedResultBytes <= maximumRetainedResultBytes,
              deferredResultBytes
                <= maximumRetainedResultBytes - activeReservedResultBytes,
              cacheResultBytes <= maximumRetainedResultBytes
                - activeReservedResultBytes - deferredResultBytes else {
            return false
        }
        return retainedResultBytesHighWatermark
                >= activeReservedResultBytes + deferredResultBytes
                    + cacheResultBytes
            && retainedResultBytesHighWatermark
                <= maximumRetainedResultBytes
    }

    public var cleanlyDrained: Bool {
        queuedRequests == 0 && runningRequests == 0 && physicalWorkers == 0
            && activeReservedResultBytes == 0
            && deferredResults == 0
            && deferredResultBytes == 0
    }
}

public enum HeavyEnrichmentOffer: Sendable, Equatable {
    case cacheHit(HeavyEnrichmentValue)
    case pending(ticket: HeavyEnrichmentTicket, coalesced: Bool)
    case rejected
}

/// Fixed-concurrency owner for every heavyweight enrichment operation.
public actor HeavyEnrichmentPlane {
    public typealias Operation = @Sendable () async -> HeavyEnrichmentValue

    private enum WorkSubject: Hashable, Sendable {
        case process(pid: Int32, started: Date, executable: String)
        case exactFileEvent(id: UUID, path: String?, size: UInt64?)
        case user(UInt32)
    }

    private struct WorkKey: Hashable, Sendable {
        let component: HeavyEnrichmentComponent
        let subject: WorkSubject

        init(component: HeavyEnrichmentComponent, binding: HeavyEnrichmentBinding) {
            self.component = component
            switch component {
            case .codeSignature, .processHashes, .environment:
                subject = .process(
                    pid: binding.processID,
                    started: binding.processStartTime,
                    executable: binding.executablePath
                )
            case .fileContent:
                // Content belongs to the one callback that proved a completed
                // write.  Never coalesce or cache it by path alone.
                subject = .exactFileEvent(
                    id: binding.eventID,
                    path: binding.filePath,
                    size: binding.eventFileSize
                )
            case .userName:
                subject = .user(binding.userID)
            }
        }
    }

    private struct Subscriber: Sendable {
        let ticket: HeavyEnrichmentTicket
        let binding: HeavyEnrichmentBinding
        let memoryLease: EventPipelineMemoryLease

        var reservedResultBytes: Int { memoryLease.bytes }
    }

    private enum WorkState: Sendable, Equatable {
        case queued
        case running
        case timedOut
        case cancelled
    }

    private struct Work: Sendable {
        let id: UInt64
        let key: WorkKey
        let component: HeavyEnrichmentComponent
        let operation: Operation
        let cacheResult: Bool
        let deadlineUptimeNanoseconds: UInt64
        var subscribers: [Subscriber]
        var state: WorkState
    }

    private struct BufferedDeferredResult: Sendable {
        let patch: DeferredEventEnrichment
        let retainedByteCharge: Int
        let memoryLease: EventPipelineMemoryLease
    }

    private struct CachedValue: Sendable {
        let value: HeavyEnrichmentValue
        let retainedByteCharge: Int
        let memoryLease: EventPipelineMemoryLease
        var accessSequence: UInt64
    }

    private let configuration: HeavyEnrichmentPlaneConfiguration
    private let liveMemoryBudget: EventPipelineLiveMemoryBudget
    private var accepting = true
    private var nextWorkID: UInt64 = 0
    private var cacheAccessSequence: UInt64 = 0
    private var works: [UInt64: Work] = [:]
    private var activeByKey: [WorkKey: UInt64] = [:]
    private var queuedWorkIDs: [UInt64] = []
    private var workerTasks: [UInt64: Task<Void, Never>] = [:]
    private var deadlineTasks: [UInt64: Task<Void, Never>] = [:]
    private var deferred: [BufferedDeferredResult] = []
    private var deferredResultBytes = 0
    private var retainedResultBytesHighWatermark = 0
    private var cache: [WorkKey: CachedValue] = [:]
    private var cacheResultBytes = 0

    private var offeredRequestsTotal: UInt64 = 0
    private var completedRequestsTotal: UInt64 = 0
    private var timedOutRequestsTotal: UInt64 = 0
    private var cancelledRequestsTotal: UInt64 = 0
    private var rejectedRequestsTotal: UInt64 = 0
    private var cacheHitsTotal: UInt64 = 0
    private var coalescedRequestsTotal: UInt64 = 0
    private var lateWorkerExitsTotal: UInt64 = 0
    private var oversizedResultValuesTotal: UInt64 = 0
    /// Times a lingering-reservation split was refused and the terminal marker
    /// had to share the subscriber's reservation instead of carving its own.
    /// Non-zero means bounded over-charging, never lost evidence — and it must
    /// stay observable, because the refusal it replaces used to be a crash.
    private var lingeringReservationSplitRefusalsTotal: UInt64 = 0

    public init(
        configuration: HeavyEnrichmentPlaneConfiguration = .init(),
        liveMemoryBudget: EventPipelineLiveMemoryBudget = .processShared
    ) {
        self.configuration = configuration
        self.liveMemoryBudget = liveMemoryBudget
    }

    /// Offers one component operation.  The call performs no supplied work;
    /// it only publishes an owned task or returns a cached/rejected decision.
    @discardableResult
    public func offer(
        component: HeavyEnrichmentComponent,
        binding: HeavyEnrichmentBinding,
        cacheResult: Bool = true,
        timeoutSeconds: TimeInterval? = nil,
        maximumResultBytes: Int? = nil,
        operation: @escaping Operation
    ) -> HeavyEnrichmentOffer {
        increment(&offeredRequestsTotal)
        let key = WorkKey(component: component, binding: binding)

        if var cached = cache[key] {
            increment(&completedRequestsTotal)
            increment(&cacheHitsTotal)
            increment(&cacheAccessSequence)
            cached.accessSequence = cacheAccessSequence
            cache[key] = cached
            return .cacheHit(cached.value)
        }

        let resultBytes = max(
            1,
            maximumResultBytes ?? component.defaultMaximumResultBytes
        )
        let baseBytes = binding.retainedByteEstimate
            .addingReportingOverflow(1_024)
        let reservationBytes: Int
        if baseBytes.overflow {
            reservationBytes = Int.max
        } else {
            let combined = baseBytes.partialValue.addingReportingOverflow(
                resultBytes
            )
            reservationBytes = combined.overflow
                ? Int.max : combined.partialValue
        }
        guard accepting,
              deferred.count + activeRequestCount
                < configuration.maximumOutstandingResults,
              canReserveResultBytes(reservationBytes) else {
            increment(&rejectedRequestsTotal)
            return .rejected
        }
        guard let memoryLease = liveMemoryBudget.tryAcquire(
            bytes: reservationBytes,
            owner: .heavyResult
        ) else {
            increment(&rejectedRequestsTotal)
            return .rejected
        }

        let ticket = HeavyEnrichmentTicket()
        if let existingID = activeByKey[key], var existing = works[existingID],
           existing.state == .queued || existing.state == .running {
            existing.subscribers.append(Subscriber(
                ticket: ticket,
                binding: binding,
                memoryLease: memoryLease
            ))
            works[existingID] = existing
            updateRetainedResultBytesHighWatermark()
            increment(&coalescedRequestsTotal)
            return .pending(ticket: ticket, coalesced: true)
        }

        let canRunNow = physicalWorkerCount < configuration.maximumConcurrentWorkers
        guard canRunNow || queuedWorkIDs.count < configuration.maximumQueuedWorkItems else {
            increment(&rejectedRequestsTotal)
            return .rejected
        }

        nextWorkID = nextWorkID == UInt64.max ? 1 : nextWorkID + 1
        let workID = nextWorkID
        let timeout = max(0, timeoutSeconds ?? configuration.operationTimeoutSeconds)
        let timeoutNanoseconds = Self.nanoseconds(timeout)
        let now = DispatchTime.now().uptimeNanoseconds
        let deadline = now.addingReportingOverflow(timeoutNanoseconds)
        let deadlineNanos = deadline.overflow ? UInt64.max : deadline.partialValue
        let work = Work(
            id: workID,
            key: key,
            component: component,
            operation: operation,
            cacheResult: cacheResult && Self.componentMayCache(component),
            deadlineUptimeNanoseconds: deadlineNanos,
            subscribers: [Subscriber(
                ticket: ticket,
                binding: binding,
                memoryLease: memoryLease
            )],
            state: canRunNow ? .running : .queued
        )
        works[workID] = work
        activeByKey[key] = workID
        updateRetainedResultBytesHighWatermark()
        scheduleDeadline(for: workID, timeoutNanoseconds: timeoutNanoseconds)
        if canRunNow {
            startWorker(for: workID)
        } else {
            queuedWorkIDs.append(workID)
        }
        return .pending(ticket: ticket, coalesced: false)
    }

    /// Removes a bounded prefix of terminal patches.  Accepted operations
    /// reserve result capacity at admission, so this queue never drops a patch.
    public func drainDeferredResults(
        limit: Int = 128,
        maximumBytes: Int = Int.max
    ) -> [DeferredEventEnrichment] {
        drainOwnedDeferredResults(
            limit: limit,
            maximumBytes: maximumBytes
        ).map(\.patch)
    }

    package func drainOwnedDeferredResults(
        limit: Int = 128,
        maximumBytes: Int = Int.max
    ) -> [OwnedDeferredEventEnrichment] {
        guard limit > 0, !deferred.isEmpty else { return [] }
        let countLimit = min(limit, deferred.count)
        let byteLimit = max(0, maximumBytes)
        var count = 0
        var bytes = 0
        for item in deferred.prefix(countLimit) {
            guard item.retainedByteCharge <= byteLimit
                    - min(bytes, byteLimit) else { break }
            bytes += item.retainedByteCharge
            count += 1
        }
        guard count > 0 else { return [] }
        let result = deferred.prefix(count).map {
            OwnedDeferredEventEnrichment(
                patch: $0.patch,
                memoryLease: $0.memoryLease
            )
        }
        deferred.removeFirst(count)
        deferredResultBytes = max(0, deferredResultBytes - bytes)
        return result
    }

    public func snapshot() -> HeavyEnrichmentPlaneSnapshot {
        let queued = works.values.reduce(into: 0) { count, work in
            if work.state == .queued { count += work.subscribers.count }
        }
        let running = works.values.reduce(into: 0) { count, work in
            if work.state == .running { count += work.subscribers.count }
        }
        let lingering = works.values.reduce(into: 0) { count, work in
            if work.state == .timedOut || work.state == .cancelled { count += 1 }
        }
        return HeavyEnrichmentPlaneSnapshot(
            accepting: accepting,
            offeredRequestsTotal: offeredRequestsTotal,
            completedRequestsTotal: completedRequestsTotal,
            timedOutRequestsTotal: timedOutRequestsTotal,
            cancelledRequestsTotal: cancelledRequestsTotal,
            rejectedRequestsTotal: rejectedRequestsTotal,
            cacheHitsTotal: cacheHitsTotal,
            coalescedRequestsTotal: coalescedRequestsTotal,
            lateWorkerExitsTotal: lateWorkerExitsTotal,
            queuedRequests: queued,
            runningRequests: running,
            physicalWorkers: physicalWorkerCount,
            lingeringTimedOutOrCancelledWorkers: lingering,
            deferredResults: deferred.count,
            activeReservedResultBytes: activeReservedResultBytes,
            deferredResultBytes: deferredResultBytes,
            cacheResultBytes: cacheResultBytes,
            retainedResultBytesHighWatermark:
                retainedResultBytesHighWatermark,
            maximumRetainedResultBytes:
                configuration.maximumRetainedResultBytes,
            oversizedResultValuesTotal: oversizedResultValuesTotal,
            lingeringReservationSplitRefusalsTotal:
                lingeringReservationSplitRefusalsTotal,
            cachedResults: cache.count,
            maximumConcurrentWorkers: configuration.maximumConcurrentWorkers
        )
    }

    /// Seals admission, terminally cancels every queued/running request, and
    /// waits up to `deadlineSeconds` for the physically owned workers to exit.
    /// Cancellation-uncooperative workers remain retained and charged after a
    /// bounded return; their later exit updates the lifecycle snapshot.
    @discardableResult
    public func shutdown(deadlineSeconds: TimeInterval = 1.0) async -> HeavyEnrichmentPlaneSnapshot {
        beginShutdown()
        let bounded = max(0, deadlineSeconds)
        let endNanos = DispatchTime.now().uptimeNanoseconds.addingReportingOverflow(
            Self.nanoseconds(bounded)
        )
        let deadline = endNanos.overflow ? UInt64.max : endNanos.partialValue
        while physicalWorkerCount > 0, DispatchTime.now().uptimeNanoseconds < deadline {
            try? await Task.sleep(nanoseconds: 1_000_000)
        }
        return snapshot()
    }

    private var activeRequestCount: Int {
        works.values.reduce(into: 0) { count, work in
            if work.state == .queued || work.state == .running {
                count += work.subscribers.count
            }
        }
    }

    private var activeReservedResultBytes: Int {
        works.values.reduce(0) { total, work in
            return work.subscribers.reduce(total) { subtotal, subscriber in
                let sum = subtotal.addingReportingOverflow(
                    subscriber.reservedResultBytes
                )
                return sum.overflow ? Int.max : sum.partialValue
            }
        }
    }

    private var retainedResultBytes: Int {
        let activeAndDeferred = activeReservedResultBytes
            .addingReportingOverflow(deferredResultBytes)
        guard !activeAndDeferred.overflow else { return Int.max }
        let total = activeAndDeferred.partialValue.addingReportingOverflow(
            cacheResultBytes
        )
        return total.overflow ? Int.max : total.partialValue
    }

    private func canReserveResultBytes(_ bytes: Int) -> Bool {
        guard bytes > 0, bytes <= configuration.maximumRetainedResultBytes else {
            return false
        }
        let retained = min(
            retainedResultBytes,
            configuration.maximumRetainedResultBytes
        )
        return bytes <= configuration.maximumRetainedResultBytes - retained
    }

    private func updateRetainedResultBytesHighWatermark() {
        retainedResultBytesHighWatermark = max(
            retainedResultBytesHighWatermark,
            retainedResultBytes
        )
    }

    /// Includes timed-out/cancelled workers that have not physically exited.
    private var physicalWorkerCount: Int { workerTasks.count }

    private func scheduleDeadline(for workID: UInt64, timeoutNanoseconds: UInt64) {
        let task = Task.detached(priority: .utility) { [self] in
            do {
                try await Task.sleep(nanoseconds: timeoutNanoseconds)
            } catch {
                return
            }
            await deadlineFired(workID: workID)
        }
        deadlineTasks[workID] = task
    }

    private func startWorker(for workID: UInt64) {
        guard var work = works[workID], work.state == .running else { return }
        if DispatchTime.now().uptimeNanoseconds >= work.deadlineUptimeNanoseconds {
            deadlineFired(workID: workID)
            return
        }
        let operation = work.operation
        // Re-publish `.running` before creating the task so a completion actor
        // hop cannot observe an unregistered work item.
        work.state = .running
        works[workID] = work
        let task = Task.detached(priority: .utility) { [self] in
            let value = await operation()
            await workerFinished(workID: workID, value: value)
        }
        workerTasks[workID] = task
    }

    private func workerFinished(workID: UInt64, value: HeavyEnrichmentValue) {
        workerTasks.removeValue(forKey: workID)
        deadlineTasks.removeValue(forKey: workID)?.cancel()
        guard let work = works.removeValue(forKey: workID) else {
            startAvailableWorkers()
            return
        }

        switch work.state {
        case .running:
            activeByKey.removeValue(forKey: work.key)
            for subscriber in work.subscribers {
                increment(&completedRequestsTotal)
                appendDeferred(
                    subscriber: subscriber,
                    component: work.component,
                    outcome: .completed,
                    value: value
                )
            }
            if work.cacheResult { insertCache(value, for: work.key) }
        case .timedOut, .cancelled:
            // Requests became terminal at deadline/shutdown.  A late value is
            // intentionally discarded and never cached or applied.
            increment(&lateWorkerExitsTotal)
        case .queued:
            // A queued operation has no worker and cannot reach this callback.
            assertionFailure("queued heavy enrichment work produced a worker result")
        }
        startAvailableWorkers()
    }

    private func deadlineFired(workID: UInt64) {
        deadlineTasks.removeValue(forKey: workID)
        guard var work = works[workID] else { return }
        switch work.state {
        case .queued:
            queuedWorkIDs.removeAll { $0 == workID }
            activeByKey.removeValue(forKey: work.key)
            works.removeValue(forKey: workID)
            terminalize(work: work, outcome: .timedOut)
            startAvailableWorkers()
        case .running:
            activeByKey.removeValue(forKey: work.key)
            guard workerTasks[workID] != nil else {
                // Deadline elapsed before a queued item could publish its
                // worker.  It is terminal, not a lingering physical worker.
                works.removeValue(forKey: workID)
                terminalize(work: work, outcome: .timedOut)
                startAvailableWorkers()
                return
            }
            work.state = .timedOut
            works[workID] = work
            workerTasks[workID]?.cancel()
            terminalize(
                work: work,
                outcome: .timedOut,
                retainLingeringReservation: true
            )
            // Do not start a replacement: the cancelled worker still owns one
            // physical slot until it actually exits.
        case .timedOut, .cancelled:
            break
        }
    }

    private func terminalize(work: Work, outcome: HeavyEnrichmentTerminalOutcome) {
        terminalize(
            work: work,
            outcome: outcome,
            retainLingeringReservation: false
        )
    }

    private func terminalize(
        work: Work,
        outcome: HeavyEnrichmentTerminalOutcome,
        retainLingeringReservation: Bool
    ) {
        var terminalSubscribers: [Subscriber] = []
        terminalSubscribers.reserveCapacity(work.subscribers.count)
        var lingeringSubscribers: [Subscriber] = []
        lingeringSubscribers.reserveCapacity(work.subscribers.count)
        for subscriber in work.subscribers {
            switch outcome {
            case .completed:
                increment(&completedRequestsTotal)
            case .timedOut:
                increment(&timedOutRequestsTotal)
            case .cancelled:
                increment(&cancelledRequestsTotal)
            }
            let marker = DeferredEventEnrichment(
                ticket: subscriber.ticket,
                binding: subscriber.binding,
                component: work.component,
                outcome: outcome,
                value: nil
            )
            let markerCharge = marker.retainedByteEstimate
            precondition(markerCharge <= subscriber.reservedResultBytes)
            let markerLease: EventPipelineMemoryLease
            if retainLingeringReservation {
                // v1.21.6-rc.45: this used to force-unwrap.
                //
                // `split` divides credit already granted to this subscriber, so
                // it succeeds in the ordinary case — but it is an Optional for
                // real reasons (a reservation released underneath us, a charge
                // larger than what the source still holds, a per-request bound).
                // A refusal here is a BOUNDED ACCOUNTING DEGRADATION: the
                // terminal marker and the lingering worker share one reservation
                // instead of two, which over-charges slightly until the worker
                // exits. That is never a reason to trap the whole engine.
                //
                // The `!` killed installed hosts 16 times between 2026-08-23 and
                // 2026-08-30 (identical EXC_BREAKPOINT, rc.43 and rc.44), reached
                // from `scheduleDeadline`'s detached utility task -> deadlineFired
                // -> terminalize(.timedOut, retainLingeringReservation: true).
                // With a 50 ms `operationTimeoutSeconds` over code-signing and
                // hashing work, that path is hot, not exotic. The refusal that
                // triggered it is fixed at its source in
                // EventPipelineLiveMemoryBudget.split; this removes the crash
                // even when a refusal is legitimate.
                if let carved = subscriber.memoryLease.split(
                    bytes: markerCharge,
                    owner: .heavyResult
                ) {
                    markerLease = carved
                } else {
                    increment(&lingeringReservationSplitRefusalsTotal)
                    // The marker and the lingering worker now SHARE one
                    // reservation (ARC copies of one lease id). Be precise about
                    // what that costs: `appendDeferred` resizes the terminal
                    // subscriber's lease down to the marker charge, and because
                    // the lingering copy is the same reservation it shrinks too.
                    // So a refusal degrades this subscriber to exactly the
                    // non-lingering accounting — the lingering worker stops being
                    // charged until it physically exits. That is an UNDER-count,
                    // bounded by one operation's reservation, and it is visible
                    // through the counter above. It is strictly better than the
                    // `!` this replaces, which trapped the whole engine.
                    markerLease = subscriber.memoryLease
                }
            } else {
                precondition(subscriber.memoryLease.resize(to: markerCharge))
                markerLease = subscriber.memoryLease
            }
            terminalSubscribers.append(Subscriber(
                ticket: subscriber.ticket,
                binding: subscriber.binding,
                memoryLease: markerLease
            ))
            if retainLingeringReservation {
                lingeringSubscribers.append(Subscriber(
                    ticket: subscriber.ticket,
                    binding: subscriber.binding,
                    memoryLease: subscriber.memoryLease
                ))
            }
        }
        if retainLingeringReservation {
            var lingering = work
            lingering.subscribers = lingeringSubscribers
            works[work.id] = lingering
        }
        for subscriber in terminalSubscribers {
            appendDeferred(
                subscriber: subscriber,
                component: work.component,
                outcome: outcome,
                value: nil
            )
        }
    }

    private func appendDeferred(
        subscriber: Subscriber,
        component: HeavyEnrichmentComponent,
        outcome: HeavyEnrichmentTerminalOutcome,
        value: HeavyEnrichmentValue?
    ) {
        var patch = DeferredEventEnrichment(
            ticket: subscriber.ticket,
            binding: subscriber.binding,
            component: component,
            outcome: outcome,
            value: value
        )
        if patch.retainedByteEstimate > subscriber.reservedResultBytes {
            increment(&oversizedResultValuesTotal)
            patch = DeferredEventEnrichment(
                ticket: subscriber.ticket,
                binding: subscriber.binding,
                component: component,
                outcome: outcome,
                value: nil
            )
        }
        let charge = patch.retainedByteEstimate
        // Admission reserved at least binding + terminal-marker ownership for
        // every subscriber. A supplied operation that exceeds its declared
        // value bound is converted to explicit unavailable coverage above.
        precondition(
            charge <= subscriber.reservedResultBytes,
            "heavy result terminal marker exceeded its admission reservation"
        )
        precondition(subscriber.memoryLease.resize(to: charge))
        deferred.append(BufferedDeferredResult(
            patch: patch,
            retainedByteCharge: charge,
            memoryLease: subscriber.memoryLease
        ))
        deferredResultBytes += charge
        updateRetainedResultBytesHighWatermark()
    }

    private func startAvailableWorkers() {
        guard accepting else { return }
        while physicalWorkerCount < configuration.maximumConcurrentWorkers,
              !queuedWorkIDs.isEmpty {
            let workID = queuedWorkIDs.removeFirst()
            guard var work = works[workID], work.state == .queued else { continue }
            if DispatchTime.now().uptimeNanoseconds >= work.deadlineUptimeNanoseconds {
                deadlineFired(workID: workID)
                continue
            }
            work.state = .running
            works[workID] = work
            startWorker(for: workID)
        }
    }

    private func beginShutdown() {
        guard accepting else { return }
        accepting = false

        let queuedIDs = queuedWorkIDs
        queuedWorkIDs.removeAll(keepingCapacity: false)
        for workID in queuedIDs {
            deadlineTasks.removeValue(forKey: workID)?.cancel()
            guard let work = works.removeValue(forKey: workID) else { continue }
            activeByKey.removeValue(forKey: work.key)
            terminalize(work: work, outcome: .cancelled)
        }

        let runningIDs = works.compactMap { id, work in
            work.state == .running ? id : nil
        }
        for workID in runningIDs {
            deadlineTasks.removeValue(forKey: workID)?.cancel()
            guard var work = works[workID] else { continue }
            activeByKey.removeValue(forKey: work.key)
            work.state = .cancelled
            works[workID] = work
            terminalize(
                work: work,
                outcome: .cancelled,
                retainLingeringReservation: true
            )
            workerTasks[workID]?.cancel()
        }
    }

    private func insertCache(_ value: HeavyEnrichmentValue, for key: WorkKey) {
        guard configuration.cacheCapacity > 0 else { return }
        let charge = value.retainedByteEstimate
        if let old = cache.removeValue(forKey: key) {
            cacheResultBytes = max(
                0,
                cacheResultBytes - old.retainedByteCharge
            )
        }
        while (!canReserveResultBytes(charge)
                || cache.count >= configuration.cacheCapacity),
              let victim = cache.min(by: {
                  $0.value.accessSequence < $1.value.accessSequence
              })?.key,
              let removed = cache.removeValue(forKey: victim) {
            cacheResultBytes = max(
                0,
                cacheResultBytes - removed.retainedByteCharge
            )
        }
        guard canReserveResultBytes(charge),
              cache.count < configuration.cacheCapacity,
              let memoryLease = liveMemoryBudget.tryAcquire(
                bytes: charge,
                owner: .heavyResult
              ) else { return }
        increment(&cacheAccessSequence)
        cache[key] = CachedValue(
            value: value,
            retainedByteCharge: charge,
            memoryLease: memoryLease,
            accessSequence: cacheAccessSequence
        )
        cacheResultBytes += charge
        updateRetainedResultBytesHighWatermark()
    }

    private func increment(_ value: inout UInt64) {
        if value < UInt64.max { value += 1 }
    }

    private nonisolated static func nanoseconds(_ seconds: TimeInterval) -> UInt64 {
        guard seconds.isFinite else { return UInt64.max }
        let bounded = min(max(0, seconds), Double(UInt64.max) / 1_000_000_000)
        return UInt64(bounded * 1_000_000_000)
    }

    /// Path-derived trust/hash/environment evidence has an external identity
    /// validator and must not acquire a second, less strict cache here.
    private nonisolated static func componentMayCache(
        _ component: HeavyEnrichmentComponent
    ) -> Bool {
        // File-content identity is one exact callback UUID, so retaining its
        // potentially large payload cannot produce a future cache hit. Keeping
        // only tiny UID->name values also prevents cache ownership from pinning
        // the reserved J headroom while no source event can release it.
        component == .userName
    }
}
