import CryptoKit
import Foundation

public struct EventJournalOverflowEvidence: Sendable, Equatable {
    public enum DigestKind: String, Sendable, Equatable {
        case canonicalJSON = "canonical_json"
        case structuralPreflight = "structural_preflight"
    }

    public let originalEventID: UUID
    public let originalBytes: Int
    public let originalSHA256: Data
    public let digestKind: DigestKind
    public let sourceIdentitySHA256: Data
}

/// The once-prepared value carried from the synchronous ingress boundary into
/// the batched journal writer. The source-identity digest is computed from the
/// raw immutable source fields before privacy sanitizing. It lets a terminal
/// revision prove that it belongs to the same source without retaining secrets.
public struct EventJournalIngressPreparation: Sendable, Equatable {
    public let event: Event
    public let canonicalJSON: Data
    public let canonicalSHA256: Data
    public let sourceIdentitySHA256: Data
    public let overflow: EventJournalOverflowEvidence?
    public let retainedByteEstimate: Int
    public let sourceRetainedByteEstimate: Int

    public init(
        event: Event,
        canonicalJSON: Data,
        canonicalSHA256: Data,
        sourceIdentitySHA256: Data? = nil,
        overflow: EventJournalOverflowEvidence?,
        retainedByteEstimate: Int = 0,
        sourceRetainedByteEstimate: Int? = nil
    ) {
        self.event = event
        self.canonicalJSON = canonicalJSON
        self.canonicalSHA256 = canonicalSHA256
        self.sourceIdentitySHA256 = sourceIdentitySHA256
            ?? EventJournalAdmissionValidator.sourceIdentityDigest(event)
        self.overflow = overflow
        self.retainedByteEstimate = max(
            canonicalJSON.count,
            retainedByteEstimate
        )
        self.sourceRetainedByteEstimate = max(
            canonicalJSON.count,
            sourceRetainedByteEstimate ?? retainedByteEstimate
        )
    }
}

/// v1.22.0 item6: bounded, lock-guarded telemetry for the real event-source
/// size distribution flowing through `preflight`/`prepare` and the sanitized
/// canonical-JSON expansion ratio. Read-only and never consulted by admission
/// logic — its sole purpose is to give a burst-time measurement pass the
/// P99/P99.9/max data needed to pick safe values for the constants flagged
/// "MEASUREMENT PENDING" below (and in DeferredEnrichmentBuffer.swift), in
/// place of guessing. O(1) per event: fixed power-of-two buckets, a running
/// max, and a fixed-size ratio reservoir — no allocation on the hot path.
public enum EventJournalSourceSizeTelemetry {
    /// Bucket[i] counts sourceBytes in (bounds[i-1], bounds[i]]; the final
    /// entry is an overflow catch-all for anything above the largest bound.
    static let bucketUpperBounds: [Int] = {
        var bounds: [Int] = []
        var value = 1_024 // 1 KiB
        let ceiling = 32 * 1_024 * 1_024 // 32 MiB
        while value <= ceiling {
            bounds.append(value)
            value <<= 1
        }
        return bounds
    }()

    private static let ratioSampleCapacity = 256

    public struct Snapshot: Sendable, Equatable {
        public let sampleCount: UInt64
        public let bucketUpperBounds: [Int]
        /// `bucketCounts.count == bucketUpperBounds.count + 1`; the trailing
        /// entry is the overflow bucket above the largest listed bound.
        public let bucketCounts: [UInt64]
        public let maximumSourceBytes: Int
        /// A bounded, most-recent sample of canonicalJSON.count / sourceBytes
        /// from the non-overflow `prepare()` path.
        public let sampledExpansionRatios: [Double]
    }

    // Guarded by `lock` — preflight()/prepare() run concurrently across the
    // priority and file lanes, matching the PowerGate/NoiseFilter pattern of
    // a lock-guarded `nonisolated(unsafe)` static cache elsewhere in this
    // module.
    private static let lock = NSLock()
    nonisolated(unsafe) private static var sampleCount: UInt64 = 0
    nonisolated(unsafe) private static var bucketCounts =
        Array(repeating: UInt64(0), count: bucketUpperBounds.count + 1)
    nonisolated(unsafe) private static var maximumSourceBytes = 0
    nonisolated(unsafe) private static var sampledExpansionRatios: [Double] = []
    nonisolated(unsafe) private static var ratioSampleCursor = 0

    static func recordSourceBytes(_ bytes: Int) {
        guard bytes >= 0 else { return }
        lock.lock()
        if sampleCount < UInt64.max { sampleCount += 1 }
        // `ExplicitEventSizer.retainedBytes` returns Int.max on arithmetic
        // overflow (not merely "large"); excluding that sentinel from the max
        // stat keeps one pathological event from permanently pinning it.
        if bytes < Int.max {
            maximumSourceBytes = max(maximumSourceBytes, bytes)
        }
        var index = bucketUpperBounds.count
        for (candidate, bound) in bucketUpperBounds.enumerated()
        where bytes <= bound {
            index = candidate
            break
        }
        bucketCounts[index] += 1
        lock.unlock()
    }

    static func recordExpansionRatio(
        canonicalJSONBytes: Int,
        sourceBytes: Int
    ) {
        guard sourceBytes > 0 else { return }
        let ratio = Double(canonicalJSONBytes) / Double(sourceBytes)
        lock.lock()
        if sampledExpansionRatios.count < ratioSampleCapacity {
            sampledExpansionRatios.append(ratio)
        } else {
            sampledExpansionRatios[ratioSampleCursor] = ratio
            ratioSampleCursor = (ratioSampleCursor + 1) % ratioSampleCapacity
        }
        lock.unlock()
    }

    public static func snapshot() -> Snapshot {
        lock.lock()
        let value = Snapshot(
            sampleCount: sampleCount,
            bucketUpperBounds: bucketUpperBounds,
            bucketCounts: bucketCounts,
            maximumSourceBytes: maximumSourceBytes,
            sampledExpansionRatios: sampledExpansionRatios
        )
        lock.unlock()
        return value
    }
}

public enum EventJournalAdmissionValidatorError: Error, LocalizedError,
    Sendable, Equatable {
    case invalidTimestamp
    case mismatchedPreflight
    case replacementEncodingFailed

    public var errorDescription: String? {
        switch self {
        case .invalidTimestamp:
            return "Event timestamp is non-finite"
        case .mismatchedPreflight:
            return "Event journal preflight does not match the event"
        case .replacementEncodingFailed:
            return "Bounded event-journal overflow record could not be encoded"
        }
    }
}

/// Allocation-light sizing and identity produced before the sanitizer or JSON
/// encoder creates another retained representation. A structural overflow also
/// carries the complete versioned source digest, computed without Mirror.
public struct EventJournalIngressPreflight: Sendable, Equatable {
    public let eventID: UUID
    public let sourceRetainedByteEstimate: Int
    public let preparationWorkspaceByteEstimate: Int
    public let structurallyOverflowed: Bool
    public let sourceIdentitySHA256: Data
    public let structuralSourceSHA256: Data?
    /// Value-semantic binding for the package's two-phase ownership seam. This
    /// is another COW reference to the caller's Event, not a deep copy. A
    /// same-UUID mutation after preflight therefore compares unequal and cannot
    /// reuse stale sizing or digests to bypass the structural gate.
    fileprivate let boundEvent: Event
}

/// Shared pre-detection boundary for the privacy-sanitized canonical journal.
///
/// The structural walk and both durable identities use explicit, versioned
/// Event-field encodings. They never depend on Mirror, compiler field layout,
/// dictionary iteration order, or String(reflecting:). Oversized input is fully
/// measured and streamed into SHA-256 in fixed-size chunks; it is never sent
/// through the sanitizer or JSONEncoder merely to produce a poison marker.
public enum EventJournalAdmissionValidator {
    public static let maximumCanonicalRecordBytes = 12 * 1_024 * 1_024
    public static let maximumPreflightStringBytes = 8 * 1_024 * 1_024
    public static let maximumPreflightElements = 131_072
    public static let maximumPreflightDepth = 64
    public static let maximumAcceptedSourceRetainedBytes = 24 * 1_024 * 1_024
    public static let maximumPreparationWorkspaceBytes =
        maximumAcceptedSourceRetainedBytes + maximumCanonicalRecordBytes + 4_096

    public static func preflight(
        _ input: Event
    ) throws -> EventJournalIngressPreflight {
        guard input.timestamp.timeIntervalSince1970.isFinite else {
            throw EventJournalAdmissionValidatorError.invalidTimestamp
        }
        var sizer = ExplicitEventSizer()
        sizer.measure(input)
        let sourceBytes = sizer.retainedBytes
        let overflowed = sizer.limitExceeded
            || sourceBytes > maximumAcceptedSourceRetainedBytes
        let sourceIdentity = sourceIdentityDigest(input)
        EventJournalSourceSizeTelemetry.recordSourceBytes(sourceBytes)
        // v1.22.0 (item 6): right-size the `.journalPrepared` acquisition from
        // the real measured source size instead of always requesting the
        // pessimistic `maximumPreparationWorkspaceBytes` (~36 MiB). Installed-host
        // measurement over 351,374 events found max sourceBytes 950,068 and a
        // sanitized-JSON expansion ratio of ~0.20–0.28 (the JSON is SMALLER than
        // the source), so `2 × sourceBytes + 64 KiB` is always ≥ the real adopt()
        // charge (retainedByteEstimate + canonicalJSON + 4096), keeping the later
        // `resize()` a shrink — never a grow that could exceed the budget. The
        // overflow path keeps the full pessimistic reserve.
        let preparationWorkspaceEstimate = overflowed
            ? maximumPreparationWorkspaceBytes
            : min(maximumPreparationWorkspaceBytes, sourceBytes * 2 + 65_536)
        return EventJournalIngressPreflight(
            eventID: input.id,
            sourceRetainedByteEstimate: sourceBytes,
            preparationWorkspaceByteEstimate: preparationWorkspaceEstimate,
            structurallyOverflowed: overflowed,
            sourceIdentitySHA256: sourceIdentity,
            structuralSourceSHA256: overflowed
                ? fullSourceDigest(input) : nil,
            boundEvent: input
        )
    }

    public static func prepare(
        _ input: Event
    ) throws -> EventJournalIngressPreparation {
        try prepare(input, preflight: preflight(input))
    }

    /// Reuses the exact sizing and source identities already produced before a
    /// caller acquired preparation workspace. This avoids re-walking a large
    /// Event at the async ownership boundary.
    public static func prepare(
        _ input: Event,
        preflight: EventJournalIngressPreflight
    ) throws -> EventJournalIngressPreparation {
        guard input.timestamp.timeIntervalSince1970.isFinite else {
            throw EventJournalAdmissionValidatorError.invalidTimestamp
        }
        guard preflight.eventID == input.id,
              preflight.boundEvent == input else {
            throw EventJournalAdmissionValidatorError.mismatchedPreflight
        }
        if preflight.structurallyOverflowed {
            return try overflowPreparation(
                input,
                originalBytes: preflight.sourceRetainedByteEstimate,
                originalDigest: preflight.structuralSourceSHA256
                    ?? fullSourceDigest(input),
                digestKind: .structuralPreflight,
                sourceIdentityDigest: preflight.sourceIdentitySHA256,
                sourceRetainedByteEstimate:
                    preflight.sourceRetainedByteEstimate
            )
        }

        let source = Event(
            id: input.id,
            timestamp: input.timestamp,
            eventCategory: input.eventCategory,
            eventType: input.eventType,
            eventAction: input.eventAction,
            process: input.process,
            file: input.file,
            network: input.network,
            tcc: input.tcc,
            enrichments: input.enrichments,
            severity: input.severity,
            ruleMatches: ReviewedRuleMatches.normalized(input.ruleMatches)
        )
        let sanitized = try EventPrivacySanitizer.sanitize(source)
        if sanitized.canonicalJSON.count <= maximumCanonicalRecordBytes {
            EventJournalSourceSizeTelemetry.recordExpansionRatio(
                canonicalJSONBytes: sanitized.canonicalJSON.count,
                sourceBytes: preflight.sourceRetainedByteEstimate
            )
            return EventJournalIngressPreparation(
                event: sanitized.event,
                canonicalJSON: sanitized.canonicalJSON,
                canonicalSHA256: Data(
                    SHA256.hash(data: sanitized.canonicalJSON)
                ),
                sourceIdentitySHA256: preflight.sourceIdentitySHA256,
                overflow: nil,
                retainedByteEstimate: max(
                    sanitized.canonicalJSON.count,
                    preflight.sourceRetainedByteEstimate
                ),
                sourceRetainedByteEstimate: max(
                    sanitized.canonicalJSON.count,
                    preflight.sourceRetainedByteEstimate
                )
            )
        }
        return try overflowPreparation(
            source,
            originalBytes: sanitized.canonicalJSON.count,
            originalDigest: Data(SHA256.hash(data: sanitized.canonicalJSON)),
            digestKind: .canonicalJSON,
            sourceIdentityDigest: preflight.sourceIdentitySHA256,
            sourceRetainedByteEstimate: max(
                preflight.sourceRetainedByteEstimate,
                sanitized.canonicalJSON.count
            )
        )
    }

    private static func overflowPreparation(
        _ source: Event,
        originalBytes: Int,
        originalDigest: Data,
        digestKind: EventJournalOverflowEvidence.DigestKind,
        sourceIdentityDigest: Data,
        sourceRetainedByteEstimate: Int
    ) throws -> EventJournalIngressPreparation {
        let digestHex = originalDigest.map {
            String(format: "%02x", $0)
        }.joined()
        let process = ProcessInfo(
            pid: source.process.pid,
            ppid: source.process.ppid,
            rpid: source.process.rpid,
            name: bounded(source.process.name, bytes: 256),
            executable: bounded(source.process.executable, bytes: 2_048),
            commandLine: "<canonical-journal-overflow>",
            args: [],
            workingDirectory: bounded(
                source.process.workingDirectory,
                bytes: 1_024
            ),
            userId: source.process.userId,
            userName: bounded(source.process.userName, bytes: 256),
            groupId: source.process.groupId,
            startTime: source.process.startTime,
            exitCode: source.process.exitCode,
            codeSignature: nil,
            ancestors: [],
            architecture: source.process.architecture.map {
                bounded($0, bytes: 64)
            },
            isPlatformBinary: source.process.isPlatformBinary,
            hashes: nil,
            session: nil,
            envVars: nil,
            auditIdentity: source.process.auditIdentity
        )
        let replacement = Event(
            id: source.id,
            timestamp: source.timestamp,
            eventCategory: source.eventCategory,
            eventType: source.eventType,
            eventAction: "journal_overflow",
            process: process,
            enrichments: [
                "journal.overflow": "true",
                "journal.original_bytes": String(originalBytes),
                "journal.original_sha256": digestHex,
                "journal.original_digest_kind": digestKind.rawValue,
            ],
            severity: source.severity,
            ruleMatches: []
        )
        let sanitized = try EventPrivacySanitizer.sanitize(replacement)
        guard !sanitized.canonicalJSON.isEmpty,
              sanitized.canonicalJSON.count <= maximumCanonicalRecordBytes else {
            throw EventJournalAdmissionValidatorError.replacementEncodingFailed
        }
        return EventJournalIngressPreparation(
            event: sanitized.event,
            canonicalJSON: sanitized.canonicalJSON,
            canonicalSHA256: Data(
                SHA256.hash(data: sanitized.canonicalJSON)
            ),
            sourceIdentitySHA256: sourceIdentityDigest,
            overflow: EventJournalOverflowEvidence(
                originalEventID: source.id,
                originalBytes: originalBytes,
                originalSHA256: originalDigest,
                digestKind: digestKind,
                sourceIdentitySHA256: sourceIdentityDigest
            ),
            retainedByteEstimate: sanitized.canonicalJSON.count + 4_096,
            sourceRetainedByteEstimate: sourceRetainedByteEstimate
        )
    }

    // MARK: Explicit structural sizing

    private struct ExplicitEventSizer {
        private(set) var escapedStringBytes = 0
        private(set) var elements = 0
        private(set) var maximumDepth = 0
        private(set) var arithmeticOverflow = false
        private(set) var stringLimitExceeded = false

        var retainedBytes: Int {
            let overhead = elements.multipliedReportingOverflow(by: 64)
            guard !overhead.overflow else { return Int.max }
            let total = escapedStringBytes.addingReportingOverflow(
                overhead.partialValue
            )
            return total.overflow ? Int.max : max(1, total.partialValue)
        }

        var limitExceeded: Bool {
            arithmeticOverflow
                || stringLimitExceeded
                || elements > maximumPreflightElements
                || maximumDepth > maximumPreflightDepth
        }

        mutating func measure(_ event: Event) {
            node(0)
            scalar(1) // id
            scalar(1) // timestamp
            string(event.eventCategory.rawValue, depth: 1)
            string(event.eventType.rawValue, depth: 1)
            string(event.eventAction, depth: 1)
            process(event.process, depth: 1)
            optionalFile(event.file, depth: 1)
            optionalNetwork(event.network, depth: 1)
            optionalTCC(event.tcc, depth: 1)
            stringMap(event.enrichments, depth: 1)
            string(event.severity.rawValue, depth: 1)
            ruleMatches(event.ruleMatches, depth: 1)
        }

        private mutating func process(_ value: ProcessInfo, depth: Int) {
            node(depth)
            scalar(depth + 1)
            scalar(depth + 1)
            scalar(depth + 1)
            string(value.name, depth: depth + 1)
            string(value.executable, depth: depth + 1)
            string(value.commandLine, depth: depth + 1)
            stringArray(value.args, depth: depth + 1)
            string(value.workingDirectory, depth: depth + 1)
            scalar(depth + 1)
            string(value.userName, depth: depth + 1)
            scalar(depth + 1)
            scalar(depth + 1)
            optionalScalar(value.exitCode, depth: depth + 1)
            optionalCodeSignature(value.codeSignature, depth: depth + 1)
            node(depth + 1)
            for ancestor in value.ancestors {
                node(depth + 2)
                scalar(depth + 3)
                string(ancestor.executable, depth: depth + 3)
                string(ancestor.name, depth: depth + 3)
            }
            optionalString(value.architecture, depth: depth + 1)
            scalar(depth + 1)
            optionalHashes(value.hashes, depth: depth + 1)
            optionalSession(value.session, depth: depth + 1)
            optionalStringMap(value.envVars, depth: depth + 1)
            optionalAudit(value.auditIdentity, depth: depth + 1)
        }

        private mutating func optionalCodeSignature(
            _ value: CodeSignatureInfo?,
            depth: Int
        ) {
            node(depth)
            guard let value else { return }
            node(depth + 1)
            string(value.signerType.rawValue, depth: depth + 2)
            optionalString(value.teamId, depth: depth + 2)
            optionalString(value.signingId, depth: depth + 2)
            stringArray(value.authorities, depth: depth + 2)
            scalar(depth + 2)
            scalar(depth + 2)
            optionalStringArray(value.issuerChain, depth: depth + 2)
            optionalStringArray(value.certHashes, depth: depth + 2)
            optionalScalar(value.isAdhocSigned, depth: depth + 2)
            optionalStringArray(value.entitlements, depth: depth + 2)
        }

        private mutating func optionalHashes(
            _ value: ProcessHashes?,
            depth: Int
        ) {
            node(depth)
            guard let value else { return }
            node(depth + 1)
            optionalString(value.sha256, depth: depth + 2)
            optionalString(value.cdhash, depth: depth + 2)
            optionalString(value.md5, depth: depth + 2)
        }

        private mutating func optionalSession(
            _ value: SessionInfo?,
            depth: Int
        ) {
            node(depth)
            guard let value else { return }
            node(depth + 1)
            optionalScalar(value.sessionId, depth: depth + 2)
            optionalString(value.tty, depth: depth + 2)
            optionalString(value.loginUser, depth: depth + 2)
            optionalString(value.sshRemoteIP, depth: depth + 2)
            node(depth + 2)
            if let launch = value.launchSource {
                string(launch.rawValue, depth: depth + 3)
            }
        }

        private mutating func optionalAudit(
            _ value: AuditIdentity?,
            depth: Int
        ) {
            node(depth)
            guard value != nil else { return }
            node(depth + 1)
            for _ in 0..<8 { scalar(depth + 2) }
        }

        private mutating func optionalFile(_ value: FileInfo?, depth: Int) {
            node(depth)
            guard let value else { return }
            node(depth + 1)
            string(value.path, depth: depth + 2)
            string(value.name, depth: depth + 2)
            string(value.directory, depth: depth + 2)
            optionalString(value.extension_, depth: depth + 2)
            optionalScalar(value.size, depth: depth + 2)
            string(value.action.rawValue, depth: depth + 2)
            optionalString(value.sourcePath, depth: depth + 2)
        }

        private mutating func optionalNetwork(
            _ value: NetworkInfo?,
            depth: Int
        ) {
            node(depth)
            guard let value else { return }
            node(depth + 1)
            string(value.sourceIp, depth: depth + 2)
            scalar(depth + 2)
            string(value.destinationIp, depth: depth + 2)
            scalar(depth + 2)
            optionalString(value.destinationHostname, depth: depth + 2)
            string(value.direction.rawValue, depth: depth + 2)
            string(value.transport, depth: depth + 2)
        }

        private mutating func optionalTCC(_ value: TCCInfo?, depth: Int) {
            node(depth)
            guard let value else { return }
            node(depth + 1)
            string(value.service, depth: depth + 2)
            string(value.client, depth: depth + 2)
            string(value.clientPath, depth: depth + 2)
            scalar(depth + 2)
            string(value.authReason, depth: depth + 2)
        }

        private mutating func ruleMatches(
            _ values: [RuleMatch],
            depth: Int
        ) {
            node(depth)
            for value in values {
                node(depth + 1)
                string(value.ruleId, depth: depth + 2)
                string(value.ruleName, depth: depth + 2)
                string(value.severity.rawValue, depth: depth + 2)
                string(value.description, depth: depth + 2)
                stringArray(value.mitreTechniques, depth: depth + 2)
                stringArray(value.tags, depth: depth + 2)
                scalar(depth + 2)
            }
        }

        private mutating func optionalStringMap(
            _ value: [String: String]?,
            depth: Int
        ) {
            node(depth)
            guard let value else { return }
            stringMap(value, depth: depth + 1)
        }

        private mutating func stringMap(
            _ value: [String: String],
            depth: Int
        ) {
            node(depth)
            for (key, child) in value {
                string(key, depth: depth + 1)
                string(child, depth: depth + 1)
            }
        }

        private mutating func optionalStringArray(
            _ value: [String]?,
            depth: Int
        ) {
            node(depth)
            guard let value else { return }
            stringArray(value, depth: depth + 1)
        }

        private mutating func stringArray(_ value: [String], depth: Int) {
            node(depth)
            for child in value { string(child, depth: depth + 1) }
        }

        private mutating func optionalString(
            _ value: String?,
            depth: Int
        ) {
            node(depth)
            if let value { string(value, depth: depth + 1) }
        }

        private mutating func optionalScalar<T>(_ value: T?, depth: Int) {
            node(depth)
            if value != nil { scalar(depth + 1) }
        }

        private mutating func scalar(_ depth: Int) { node(depth) }

        private mutating func node(_ depth: Int) {
            maximumDepth = max(maximumDepth, depth)
            let next = elements.addingReportingOverflow(1)
            if next.overflow {
                elements = Int.max
                arithmeticOverflow = true
            } else {
                elements = next.partialValue
            }
        }

        private mutating func string(_ value: String, depth: Int) {
            node(depth)
            let metrics = Self.stringMetrics(value)
            if metrics.rawBytes > maximumPreflightStringBytes {
                stringLimitExceeded = true
            }
            let next = escapedStringBytes.addingReportingOverflow(
                metrics.escapedBytes
            )
            if next.overflow {
                escapedStringBytes = Int.max
                arithmeticOverflow = true
            } else {
                escapedStringBytes = next.partialValue
            }
        }

        private static func stringMetrics(
            _ value: String
        ) -> (rawBytes: Int, escapedBytes: Int) {
            var raw = 0
            var escaped = 2
            for scalar in value.unicodeScalars {
                let utf8Bytes: Int
                switch scalar.value {
                case 0...0x7f: utf8Bytes = 1
                case 0x80...0x7ff: utf8Bytes = 2
                case 0x800...0xffff: utf8Bytes = 3
                default: utf8Bytes = 4
                }
                raw = saturatingAdd(raw, utf8Bytes)
                let encodedBytes: Int
                switch scalar.value {
                case 0x00...0x1f, 0x2028, 0x2029:
                    encodedBytes = 6
                case 0x22, 0x5c:
                    encodedBytes = 2
                default:
                    encodedBytes = utf8Bytes
                }
                escaped = saturatingAdd(escaped, encodedBytes)
            }
            return (raw, escaped)
        }

        private static func saturatingAdd(_ lhs: Int, _ rhs: Int) -> Int {
            let result = lhs.addingReportingOverflow(rhs)
            return result.overflow ? Int.max : result.partialValue
        }
    }

    // MARK: Versioned stable source hashing

    /// Streaming SHA-256 writer with unambiguous typed framing. String content
    /// is consumed once in 4 KiB chunks and no payload-sized Data is created.
    private struct StableHashWriter {
        private static let chunkSize = 4_096
        private var hash = SHA256()
        private var buffer: [UInt8] = []

        init(domain: String) {
            buffer.reserveCapacity(Self.chunkSize)
            byte(0x01)
            string(domain)
        }

        mutating func field(_ value: UInt16) {
            byte(0xf0)
            uint16(value)
        }

        mutating func object(_ schema: UInt16) {
            byte(0xa0)
            uint16(schema)
        }

        mutating func string(_ value: String) {
            byte(0x10)
            var stringChunk: [UInt8] = []
            stringChunk.reserveCapacity(Self.chunkSize)
            for valueByte in value.utf8 {
                stringChunk.append(valueByte)
                if stringChunk.count == Self.chunkSize {
                    uint32(UInt32(stringChunk.count))
                    bytes(stringChunk)
                    stringChunk.removeAll(keepingCapacity: true)
                }
            }
            if !stringChunk.isEmpty {
                uint32(UInt32(stringChunk.count))
                bytes(stringChunk)
            }
            uint32(0)
        }

        mutating func optionalString(_ value: String?) {
            optional(value != nil)
            if let value { string(value) }
        }

        mutating func stringArray(_ values: [String]) {
            byte(0x30)
            uint64(UInt64(values.count))
            for value in values { string(value) }
        }

        mutating func optionalStringArray(_ values: [String]?) {
            optional(values != nil)
            if let values { stringArray(values) }
        }

        mutating func stringMap(_ values: [String: String]) {
            byte(0x31)
            uint64(UInt64(values.count))
            var buckets = Array(
                repeating: MapBucket(),
                count: MapBucket.bucketCount
            )
            for (key, value) in values {
                var entry = StableHashWriter(
                    domain: "MacCrab.EventJournal.StringMapEntry.v1"
                )
                entry.field(1)
                entry.string(key)
                entry.field(2)
                entry.string(value)
                let digest = entry.finalize()
                let bucketIndex = Int(digest[0])
                    & (MapBucket.bucketCount - 1)
                buckets[bucketIndex].add(digest)
            }
            for index in buckets.indices {
                uint16(UInt16(index))
                buckets[index].encode(into: &self)
            }
        }

        mutating func optionalStringMap(_ values: [String: String]?) {
            optional(values != nil)
            if let values { stringMap(values) }
        }

        mutating func uuid(_ value: UUID) {
            byte(0x11)
            string(value.uuidString.lowercased())
        }

        mutating func date(_ value: Date) {
            byte(0x12)
            uint64(value.timeIntervalSince1970.bitPattern)
        }

        mutating func bool(_ value: Bool) {
            byte(0x13)
            byte(value ? 1 : 0)
        }

        mutating func optionalBool(_ value: Bool?) {
            optional(value != nil)
            if let value { bool(value) }
        }

        mutating func int32(_ value: Int32) {
            byte(0x14)
            uint32(UInt32(bitPattern: value))
        }

        mutating func optionalInt32(_ value: Int32?) {
            optional(value != nil)
            if let value { int32(value) }
        }

        mutating func uint16Value(_ value: UInt16) {
            byte(0x15)
            uint16(value)
        }

        mutating func uint32Value(_ value: UInt32) {
            byte(0x16)
            uint32(value)
        }

        mutating func optionalUInt32(_ value: UInt32?) {
            optional(value != nil)
            if let value { uint32Value(value) }
        }

        mutating func uint64Value(_ value: UInt64) {
            byte(0x17)
            uint64(value)
        }

        mutating func optionalUInt64(_ value: UInt64?) {
            optional(value != nil)
            if let value { uint64Value(value) }
        }

        mutating func optional(_ present: Bool) {
            byte(0x20)
            byte(present ? 1 : 0)
        }

        mutating func finalize() -> Data {
            flush()
            return Data(hash.finalize())
        }

        private mutating func byte(_ value: UInt8) {
            buffer.append(value)
            if buffer.count == Self.chunkSize { flush() }
        }

        private mutating func bytes(_ values: [UInt8]) {
            for value in values { byte(value) }
        }

        private mutating func uint16(_ value: UInt16) {
            byte(UInt8(truncatingIfNeeded: value >> 8))
            byte(UInt8(truncatingIfNeeded: value))
        }

        private mutating func uint32(_ value: UInt32) {
            byte(UInt8(truncatingIfNeeded: value >> 24))
            byte(UInt8(truncatingIfNeeded: value >> 16))
            byte(UInt8(truncatingIfNeeded: value >> 8))
            byte(UInt8(truncatingIfNeeded: value))
        }

        private mutating func uint64(_ value: UInt64) {
            byte(UInt8(truncatingIfNeeded: value >> 56))
            byte(UInt8(truncatingIfNeeded: value >> 48))
            byte(UInt8(truncatingIfNeeded: value >> 40))
            byte(UInt8(truncatingIfNeeded: value >> 32))
            byte(UInt8(truncatingIfNeeded: value >> 24))
            byte(UInt8(truncatingIfNeeded: value >> 16))
            byte(UInt8(truncatingIfNeeded: value >> 8))
            byte(UInt8(truncatingIfNeeded: value))
        }

        private mutating func flush() {
            guard !buffer.isEmpty else { return }
            hash.update(data: Data(buffer))
            buffer.removeAll(keepingCapacity: true)
        }
    }

    /// Fixed-memory, order-independent digest accumulator for String maps.
    /// Each key/value pair is first domain-separated with SHA-256, then folded
    /// into one of 64 deterministic buckets using both xor and modular sum.
    private struct MapBucket {
        static let bucketCount = 64
        var count: UInt64 = 0
        var xorWords = Array(repeating: UInt64(0), count: 4)
        var sumWords = Array(repeating: UInt64(0), count: 4)

        mutating func add(_ digest: Data) {
            count &+= 1
            for lane in 0..<4 {
                var word: UInt64 = 0
                for offset in 0..<8 {
                    word = (word << 8)
                        | UInt64(digest[(lane * 8) + offset])
                }
                xorWords[lane] ^= word
                sumWords[lane] &+= word
            }
        }

        func encode(into writer: inout StableHashWriter) {
            writer.uint64Value(count)
            for value in xorWords { writer.uint64Value(value) }
            for value in sumWords { writer.uint64Value(value) }
        }
    }

    private static func fullSourceDigest(_ event: Event) -> Data {
        var writer = StableHashWriter(
            domain: "MacCrab.EventJournal.FullSource.v3"
        )
        encodeFullEvent(event, into: &writer)
        return writer.finalize()
    }

    /// Versioned encoding of the immutable raw source fields. This excludes
    /// fields intentionally finalized later: userName, code signature, hashes,
    /// environment, enrichments, severity, and reviewed rule matches.
    static func sourceIdentityDigest(_ event: Event) -> Data {
        var writer = StableHashWriter(
            domain: "MacCrab.EventJournal.SourceIdentity.v2"
        )
        writer.object(1)
        writer.field(1); writer.uuid(event.id)
        writer.field(2); writer.date(event.timestamp)
        writer.field(3); writer.string(event.eventCategory.rawValue)
        writer.field(4); writer.string(event.eventType.rawValue)
        writer.field(5); writer.string(event.eventAction)
        writer.field(6)
        encodeImmutableProcess(event.process, into: &writer)
        writer.field(7)
        encodeFile(event.file, into: &writer)
        writer.field(8)
        encodeNetwork(event.network, into: &writer)
        writer.field(9)
        encodeTCC(event.tcc, into: &writer)
        return writer.finalize()
    }

    private static func encodeFullEvent(
        _ event: Event,
        into writer: inout StableHashWriter
    ) {
        writer.object(1)
        writer.field(1); writer.uuid(event.id)
        writer.field(2); writer.date(event.timestamp)
        writer.field(3); writer.string(event.eventCategory.rawValue)
        writer.field(4); writer.string(event.eventType.rawValue)
        writer.field(5); writer.string(event.eventAction)
        writer.field(6); encodeFullProcess(event.process, into: &writer)
        writer.field(7); encodeFile(event.file, into: &writer)
        writer.field(8); encodeNetwork(event.network, into: &writer)
        writer.field(9); encodeTCC(event.tcc, into: &writer)
        writer.field(10); writer.stringMap(event.enrichments)
        writer.field(11); writer.string(event.severity.rawValue)
        writer.field(12)
        writer.uint64Value(UInt64(event.ruleMatches.count))
        for match in event.ruleMatches {
            encodeRuleMatch(match, into: &writer)
        }
    }

    private static func encodeImmutableProcess(
        _ process: ProcessInfo,
        into writer: inout StableHashWriter
    ) {
        writer.object(2)
        writer.field(1); writer.int32(process.pid)
        writer.field(2); writer.int32(process.ppid)
        writer.field(3); writer.int32(process.rpid)
        writer.field(4); writer.string(process.name)
        writer.field(5); writer.string(process.executable)
        writer.field(6); writer.string(process.commandLine)
        writer.field(7); writer.stringArray(process.args)
        writer.field(8); writer.string(process.workingDirectory)
        writer.field(9); writer.uint32Value(process.userId)
        writer.field(10); writer.uint32Value(process.groupId)
        writer.field(11); writer.date(process.startTime)
        writer.field(12); writer.optionalInt32(process.exitCode)
        writer.field(13)
        writer.uint64Value(UInt64(process.ancestors.count))
        for ancestor in process.ancestors {
            encodeAncestor(ancestor, into: &writer)
        }
        writer.field(14); writer.optionalString(process.architecture)
        writer.field(15); writer.bool(process.isPlatformBinary)
        writer.field(16); encodeSession(process.session, into: &writer)
        writer.field(17); encodeAudit(process.auditIdentity, into: &writer)
    }

    private static func encodeFullProcess(
        _ process: ProcessInfo,
        into writer: inout StableHashWriter
    ) {
        writer.object(3)
        writer.field(1); writer.int32(process.pid)
        writer.field(2); writer.int32(process.ppid)
        writer.field(3); writer.int32(process.rpid)
        writer.field(4); writer.string(process.name)
        writer.field(5); writer.string(process.executable)
        writer.field(6); writer.string(process.commandLine)
        writer.field(7); writer.stringArray(process.args)
        writer.field(8); writer.string(process.workingDirectory)
        writer.field(9); writer.uint32Value(process.userId)
        writer.field(10); writer.string(process.userName)
        writer.field(11); writer.uint32Value(process.groupId)
        writer.field(12); writer.date(process.startTime)
        writer.field(13); writer.optionalInt32(process.exitCode)
        writer.field(14)
        encodeCodeSignature(process.codeSignature, into: &writer)
        writer.field(15)
        writer.uint64Value(UInt64(process.ancestors.count))
        for ancestor in process.ancestors {
            encodeAncestor(ancestor, into: &writer)
        }
        writer.field(16); writer.optionalString(process.architecture)
        writer.field(17); writer.bool(process.isPlatformBinary)
        writer.field(18); encodeHashes(process.hashes, into: &writer)
        writer.field(19); encodeSession(process.session, into: &writer)
        writer.field(20); writer.optionalStringMap(process.envVars)
        writer.field(21); encodeAudit(process.auditIdentity, into: &writer)
    }

    private static func encodeCodeSignature(
        _ value: CodeSignatureInfo?,
        into writer: inout StableHashWriter
    ) {
        writer.optional(value != nil)
        guard let value else { return }
        writer.object(4)
        writer.field(1); writer.string(value.signerType.rawValue)
        writer.field(2); writer.optionalString(value.teamId)
        writer.field(3); writer.optionalString(value.signingId)
        writer.field(4); writer.stringArray(value.authorities)
        writer.field(5); writer.uint32Value(value.flags)
        writer.field(6); writer.bool(value.isNotarized)
        writer.field(7); writer.optionalStringArray(value.issuerChain)
        writer.field(8); writer.optionalStringArray(value.certHashes)
        writer.field(9); writer.optionalBool(value.isAdhocSigned)
        writer.field(10); writer.optionalStringArray(value.entitlements)
    }

    private static func encodeHashes(
        _ value: ProcessHashes?,
        into writer: inout StableHashWriter
    ) {
        writer.optional(value != nil)
        guard let value else { return }
        writer.object(5)
        writer.field(1); writer.optionalString(value.sha256)
        writer.field(2); writer.optionalString(value.cdhash)
        writer.field(3); writer.optionalString(value.md5)
    }

    private static func encodeSession(
        _ value: SessionInfo?,
        into writer: inout StableHashWriter
    ) {
        writer.optional(value != nil)
        guard let value else { return }
        writer.object(6)
        writer.field(1); writer.optionalUInt32(value.sessionId)
        writer.field(2); writer.optionalString(value.tty)
        writer.field(3); writer.optionalString(value.loginUser)
        writer.field(4); writer.optionalString(value.sshRemoteIP)
        writer.field(5); writer.optionalString(value.launchSource?.rawValue)
    }

    private static func encodeAudit(
        _ value: AuditIdentity?,
        into writer: inout StableHashWriter
    ) {
        writer.optional(value != nil)
        guard let value else { return }
        writer.object(7)
        writer.field(1); writer.uint32Value(value.auid)
        writer.field(2); writer.uint32Value(value.euid)
        writer.field(3); writer.uint32Value(value.egid)
        writer.field(4); writer.uint32Value(value.ruid)
        writer.field(5); writer.uint32Value(value.rgid)
        writer.field(6); writer.int32(value.pid)
        writer.field(7); writer.uint32Value(value.pidversion)
        writer.field(8); writer.int32(value.asid)
    }

    private static func encodeAncestor(
        _ value: ProcessAncestor,
        into writer: inout StableHashWriter
    ) {
        writer.object(8)
        writer.field(1); writer.int32(value.pid)
        writer.field(2); writer.string(value.executable)
        writer.field(3); writer.string(value.name)
    }

    private static func encodeFile(
        _ value: FileInfo?,
        into writer: inout StableHashWriter
    ) {
        writer.optional(value != nil)
        guard let value else { return }
        writer.object(9)
        writer.field(1); writer.string(value.path)
        writer.field(2); writer.string(value.name)
        writer.field(3); writer.string(value.directory)
        writer.field(4); writer.optionalString(value.extension_)
        writer.field(5); writer.optionalUInt64(value.size)
        writer.field(6); writer.string(value.action.rawValue)
        writer.field(7); writer.optionalString(value.sourcePath)
    }

    private static func encodeNetwork(
        _ value: NetworkInfo?,
        into writer: inout StableHashWriter
    ) {
        writer.optional(value != nil)
        guard let value else { return }
        writer.object(10)
        writer.field(1); writer.string(value.sourceIp)
        writer.field(2); writer.uint16Value(value.sourcePort)
        writer.field(3); writer.string(value.destinationIp)
        writer.field(4); writer.uint16Value(value.destinationPort)
        writer.field(5); writer.optionalString(value.destinationHostname)
        writer.field(6); writer.string(value.direction.rawValue)
        writer.field(7); writer.string(value.transport)
    }

    private static func encodeTCC(
        _ value: TCCInfo?,
        into writer: inout StableHashWriter
    ) {
        writer.optional(value != nil)
        guard let value else { return }
        writer.object(11)
        writer.field(1); writer.string(value.service)
        writer.field(2); writer.string(value.client)
        writer.field(3); writer.string(value.clientPath)
        writer.field(4); writer.bool(value.allowed)
        writer.field(5); writer.string(value.authReason)
    }

    private static func encodeRuleMatch(
        _ value: RuleMatch,
        into writer: inout StableHashWriter
    ) {
        writer.object(12)
        writer.field(1); writer.string(value.ruleId)
        writer.field(2); writer.string(value.ruleName)
        writer.field(3); writer.string(value.severity.rawValue)
        writer.field(4); writer.string(value.description)
        writer.field(5); writer.stringArray(value.mitreTechniques)
        writer.field(6); writer.stringArray(value.tags)
        writer.field(7); writer.bool(value.suppressible)
    }

    private static func bounded(_ value: String, bytes: Int) -> String {
        let utf8Count = value.utf8.count
        if utf8Count <= bytes { return value }
        let marker = "…<truncated:\(utf8Count) bytes>"
        let budget = max(0, bytes - marker.utf8.count)
        var kept = 0
        var end = value.startIndex
        var index = value.startIndex
        while index < value.endIndex {
            let next = value.index(after: index)
            let characterBytes = value[index..<next].utf8.count
            if kept + characterBytes > budget { break }
            kept += characterBytes
            end = next
            index = next
        }
        return String(value[value.startIndex..<end]) + marker
    }
}
