import CryptoKit
import Foundation

/// Identity-bound receipt returned when the bounded event writer accepts the
/// trigger's immutable base revision. AlertSink uses both fields before commit:
/// a generation by itself is unsafe because it can be accidentally reused for
/// a different event after call-site refactors.
public struct EventJournalAdmission: Sendable, Equatable, Hashable {
    public let eventID: UUID
    public let generation: UInt64
    /// SHA-256 of the privacy-sanitized canonical base JSON. EventLoop carries
    /// it from the shared ingress preparation so a receipt binds value as well
    /// as UUID, and terminal work can skip byte-identical overlays.
    public let canonicalSHA256: Data?
    /// Canonical byte count is public telemetry/validation metadata; the
    /// prepared Event and bytes live in one internal ARC-shared handle.
    public let canonicalByteCount: Int
    package let preparedHandle: EventJournalPreparedHandle?

    public init(
        eventID: UUID,
        generation: UInt64,
        canonicalSHA256: Data? = nil,
        canonicalByteCount: Int = 0
    ) {
        self.eventID = eventID
        self.generation = generation
        self.canonicalSHA256 = canonicalSHA256
        self.canonicalByteCount = max(0, canonicalByteCount)
        self.preparedHandle = nil
    }

    package init(
        eventID: UUID,
        generation: UInt64,
        handle: EventJournalPreparedHandle
    ) {
        self.eventID = eventID
        self.generation = generation
        self.canonicalSHA256 = handle.canonicalSHA256
        self.canonicalByteCount = handle.canonicalByteCount
        self.preparedHandle = handle
    }

    public static func == (
        lhs: EventJournalAdmission,
        rhs: EventJournalAdmission
    ) -> Bool {
        lhs.eventID == rhs.eventID
            && lhs.generation == rhs.generation
            && lhs.canonicalSHA256 == rhs.canonicalSHA256
            && lhs.canonicalByteCount == rhs.canonicalByteCount
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(eventID)
        hasher.combine(generation)
        hasher.combine(canonicalSHA256)
        hasher.combine(canonicalByteCount)
    }
}

/// Identity-bound proof that the alert-time terminal value, rather than only
/// its earlier immutable base, reached the exact journal. Reviewed detections
/// may mutate rule matches/severity after base admission; those alerts cannot
/// claim verified context until this digest-specific terminal outcome settles.
public struct EventJournalTerminalAdmission: Sendable, Equatable {
    public let eventID: UUID
    public let baseGeneration: UInt64
    public let baseCanonicalSHA256: Data?
    public let terminalCanonicalSHA256: Data?
    public let terminalCanonicalByteCount: Int
    public let status: EventJournalContextStatus
    public let storageMutationGeneration: UInt64

    package init(
        eventID: UUID,
        baseGeneration: UInt64,
        baseCanonicalSHA256: Data?,
        terminalCanonicalSHA256: Data?,
        terminalCanonicalByteCount: Int,
        status: EventJournalContextStatus,
        storageMutationGeneration: UInt64 = 0
    ) {
        self.eventID = eventID
        self.baseGeneration = baseGeneration
        self.baseCanonicalSHA256 = baseCanonicalSHA256
        self.terminalCanonicalSHA256 = terminalCanonicalSHA256
        self.terminalCanonicalByteCount = max(0, terminalCanonicalByteCount)
        self.status = status
        self.storageMutationGeneration = storageMutationGeneration
    }
}

/// Identity-bound admission inherited by work spawned while EventLoop handles
/// one event. Swift child tasks inherit task-local values, so advisory and
/// security-decision work can carry the base-journal receipt without plumbing
/// an optional token through every detector API. Producers outside EventLoop
/// have no value and therefore take AlertSink's universal exact-admission path.
public enum EventJournalAdmissionContext {
    @TaskLocal public static var current: EventJournalAdmission?
    /// Set only after a digest-specific terminal append/poison outcome has
    /// settled. Child fanout inherits it alongside the immutable base receipt.
    @TaskLocal public static var terminalRevision:
        EventJournalTerminalAdmission?
    /// Shared source-graph ownership inherited by every structured/ordinary
    /// child task spawned while one EventLoop event is live. The Event value is
    /// COW-copied into several derived detections; inheriting the same ARC lease
    /// keeps those captures charged once until the last task exits.
    @TaskLocal public static var sourceMemoryLease:
        EventPipelineMemoryLease?
    /// Patch credits whose values have been folded into a deferred terminal
    /// Event. Replay children inherit the ARC references so terminal
    /// acknowledgement cannot uncharge enrichment strings still captured by a
    /// detection/advisory task.
    @TaskLocal public static var deferredPatchMemoryLeases:
        [EventPipelineMemoryLease] = []
    /// Explicit base-boundary failure inherited by detectors for the same raw
    /// event. This prevents AlertSink's universal ensure path from turning a
    /// pressure-rejected/poisoned boundary into an apparently healthy trigger.
    @TaskLocal public static var forcedNonverifiedStatus:
        EventJournalContextStatus?
}

/// Durable-journal truth frozen before one event-bearing alert commits.
public enum EventJournalContextStatus: String, Sendable, Equatable {
    case verified
    case poisoned
    case filtered
    case dropped
    case timedOut = "timed_out"
    case unavailable
    case repairExpired = "repair_expired"
    case mismatchedReceipt = "mismatched_receipt"
    case failed
    case prefixIncomplete = "prefix_incomplete"

    public var isVerified: Bool { self == .verified }
}

public struct AlertTriggerSnapshotTelemetry: Sendable, Equatable {
    public let completeTotal: UInt64
    public let compactedTotal: UInt64
    public let poisonTotal: UInt64
    public let journalContextGapTotal: UInt64
    public let missingJournalAdmissionTotal: UInt64
    public let mismatchedJournalAdmissionTotal: UInt64

    public init(
        completeTotal: UInt64,
        compactedTotal: UInt64,
        poisonTotal: UInt64,
        journalContextGapTotal: UInt64,
        missingJournalAdmissionTotal: UInt64,
        mismatchedJournalAdmissionTotal: UInt64
    ) {
        self.completeTotal = completeTotal
        self.compactedTotal = compactedTotal
        self.poisonTotal = poisonTotal
        self.journalContextGapTotal = journalContextGapTotal
        self.missingJournalAdmissionTotal = missingJournalAdmissionTotal
        self.mismatchedJournalAdmissionTotal = mismatchedJournalAdmissionTotal
    }
}

/// One bounded, privacy-sanitized representation of the event that directly
/// triggered an alert.
///
/// The same `eventJSON` bytes are embedded in `triggering_events_json` and
/// offered to the alert-owned evidence store. Keeping both consumers on this
/// value prevents a raw in-memory `Event` from leaking credentials through one
/// path while the other path stores a redacted copy.
public struct PreparedAlertTrigger: Sendable, Equatable {
    public enum Disposition: String, Sendable, Equatable {
        case complete
        case compacted
        case poison
    }

    public let eventID: String
    public let timestamp: Date
    public let eventJSON: String?
    public let snapshotJSON: String
    public let disposition: Disposition
    /// SHA-256 of the complete privacy-sanitized alert-time Event, even when
    /// the <=64-KiB direct representation itself had to be compacted.
    public let canonicalSHA256: Data?
    public let canonicalByteCount: Int

    public init(
        eventID: String,
        timestamp: Date,
        eventJSON: String?,
        snapshotJSON: String,
        disposition: Disposition,
        canonicalSHA256: Data? = nil,
        canonicalByteCount: Int = 0
    ) {
        self.eventID = eventID
        self.timestamp = timestamp
        self.eventJSON = eventJSON
        self.snapshotJSON = snapshotJSON
        self.disposition = disposition
        self.canonicalSHA256 = canonicalSHA256
        self.canonicalByteCount = max(0, canonicalByteCount)
    }

    public var evidenceCandidate: AlertEvidenceCandidate? {
        guard let eventJSON else { return nil }
        return AlertEvidenceCandidate(
            eventId: eventID,
            timestamp: timestamp,
            rawJSON: eventJSON
        )
    }

    /// Persist a non-verified journal state next to (not instead of) the shared
    /// trigger Event. Alert evidence continues to receive the identical event
    /// bytes; the alert row additionally carries explicit per-alert gap truth.
    public func snapshotJSON(
        journalContext status: EventJournalContextStatus
    ) -> String {
        guard !status.isVerified else { return snapshotJSON }
        let markerObject: [String: String] = [
            "eventId": eventID,
            "journalContext": "gap",
            "status": status.rawValue,
        ]
        guard let markerData = try? JSONSerialization.data(
            withJSONObject: markerObject,
            options: [.sortedKeys, .withoutEscapingSlashes]
        ) else {
            return #"[{"journalContext":"gap","status":"failed"}]"#
        }
        let marker = String(decoding: markerData, as: UTF8.self)
        let markerOnly = "[" + marker + "]"
        let baseElements = String(snapshotJSON.dropFirst().dropLast())
        let combined = "[" + baseElements + "," + marker + "]"
        if combined.utf8.count <= EventSnapshot.maximumSnapshotBytes {
            return combined
        }
        // Fail safe: never erase the context-gap truth merely because a future
        // trigger representation consumes the reserved marker budget.
        return markerOnly.utf8.count <= EventSnapshot.maximumSnapshotBytes
            ? markerOnly
            : #"[{"journalContext":"gap","status":"failed"}]"#
    }
}

/// Deterministic trigger-event encoding for durable alerts and alert evidence.
///
/// This is intentionally independent from EventStore's complete journal. Alert
/// rows live much longer than the hot event corpus and therefore own a compact,
/// privacy-safe copy capped at 64 KiB. Oversized events first receive a
/// structure-preserving compaction; a small, valid Event-shaped omission record
/// is used only if the compact form still cannot fit.
public enum EventSnapshot {
    public static let maxEvents = 8
    /// Complete JSON array bound for `triggering_events_json`.
    public static let maximumSnapshotBytes = 64 * 1_024
    /// The evidence row stores the event object without the surrounding `[]`.
    // Reserve enough room for the explicit per-alert journal-gap marker.
    public static let maxBytesPerEvent = maximumSnapshotBytes - 256

    /// Content-free fail-closed trigger used when the process-wide preparation
    /// workspace cannot be acquired. The alert is still committed and marked
    /// poisoned; pressure must never turn an attacker-shaped event into a
    /// detection bypass or force an unbudgeted sanitizer allocation.
    public static func poisonTrigger(for event: Event) -> PreparedAlertTrigger {
        let eventID = event.id.uuidString
        return PreparedAlertTrigger(
            eventID: eventID,
            timestamp: event.timestamp,
            eventJSON: nil,
            snapshotJSON: poisonMarker(
                eventID: eventID,
                timestamp: event.timestamp
            ),
            disposition: .poison
        )
    }

    private struct CompactionPolicy {
        let maximumStringBytes: Int
        let maximumGeneralArrayCount: Int
        let maximumArgumentCount: Int
        let maximumAncestorCount: Int
        let maximumRuleMatchCount: Int
        let maximumArbitraryDictionaryCount: Int
    }

    private static let firstCompaction = CompactionPolicy(
        maximumStringBytes: 2_048,
        maximumGeneralArrayCount: 32,
        maximumArgumentCount: 32,
        maximumAncestorCount: 16,
        maximumRuleMatchCount: 8,
        maximumArbitraryDictionaryCount: 24
    )

    private static let finalCompaction = CompactionPolicy(
        maximumStringBytes: 512,
        maximumGeneralArrayCount: 8,
        maximumArgumentCount: 8,
        maximumAncestorCount: 4,
        maximumRuleMatchCount: 4,
        maximumArbitraryDictionaryCount: 8
    )

    /// Prepare the direct trigger once, synchronously, before AlertStore commit.
    /// The returned value contains no raw event graph and is safe to carry on the
    /// bounded post-commit evidence lane.
    public static func prepare(_ event: Event) -> PreparedAlertTrigger {
        do {
            return prepare(try EventJournalAdmissionValidator.prepare(event))
        } catch {
            return poisonTrigger(for: event)
        }
    }

    /// Reuse the ingress boundary's sanitized Event + canonical bytes. This is
    /// the preferred path when the alert trigger is the admitted base or a
    /// prepared terminal revision.
    public static func prepare(
        _ ingress: EventJournalIngressPreparation
    ) -> PreparedAlertTrigger {
        let event = ingress.event
        let eventID = event.id.uuidString
        let timestamp = event.timestamp

        do {
            let sanitizedData = ingress.canonicalJSON
            let sanitized = try JSONSerialization.jsonObject(
                with: sanitizedData
            )

            if ingress.overflow != nil,
               validatesEvent(
                   sanitizedData,
                   eventID: eventID,
                   timestamp: timestamp
               ), sanitizedData.count <= maxBytesPerEvent {
                return prepared(
                    data: sanitizedData,
                    eventID: eventID,
                    timestamp: timestamp,
                    disposition: .poison,
                    canonicalSHA256: ingress.canonicalSHA256,
                    canonicalByteCount: ingress.canonicalJSON.count
                )
            }

            if validatesEvent(
                sanitizedData,
                eventID: eventID,
                timestamp: timestamp
            ), sanitizedData.count <= maxBytesPerEvent {
                return prepared(
                    data: sanitizedData,
                    eventID: eventID,
                    timestamp: timestamp,
                    disposition: .complete,
                    canonicalSHA256: ingress.canonicalSHA256,
                    canonicalByteCount: ingress.canonicalJSON.count
                )
            }

            for policy in [firstCompaction, finalCompaction] {
                let compacted = compact(
                    sanitized,
                    path: [],
                    policy: policy
                )
                let compactedData = try EventPrivacySanitizer
                    .canonicalJSONData(fromJSONObject: compacted)
                if compactedData.count <= maxBytesPerEvent,
                   validatesEvent(
                       compactedData,
                       eventID: eventID,
                       timestamp: timestamp
                   ) {
                    return prepared(
                        data: compactedData,
                        eventID: eventID,
                        timestamp: timestamp,
                        disposition: .compacted,
                        canonicalSHA256: ingress.canonicalSHA256,
                        canonicalByteCount: ingress.canonicalJSON.count
                    )
                }
            }

            if let omitted = omittedEvent(
                from: event,
                sanitizedBytes: sanitizedData
            ), omitted.count <= maxBytesPerEvent,
               validatesEvent(
                   omitted,
                   eventID: eventID,
                   timestamp: timestamp
               ) {
                return prepared(
                    data: omitted,
                    eventID: eventID,
                    timestamp: timestamp,
                    disposition: .compacted,
                    canonicalSHA256: ingress.canonicalSHA256,
                    canonicalByteCount: ingress.canonicalJSON.count
                )
            }
        } catch {
            // The poison record below is deliberately content-free. Never put
            // `localizedDescription` into durable JSON: an encoder error can
            // quote the rejected value and reintroduce the secret we refused.
        }

        let marker = poisonMarker(eventID: eventID, timestamp: timestamp)
        return PreparedAlertTrigger(
            eventID: eventID,
            timestamp: timestamp,
            eventJSON: nil,
            snapshotJSON: marker,
            disposition: .poison,
            canonicalSHA256: ingress.canonicalSHA256,
            canonicalByteCount: ingress.canonicalJSON.count
        )
    }

    /// Compatibility surface for sequence/campaign callers. The complete array
    /// remains under one 64-KiB bound, preserves input order, and deduplicates
    /// the direct event UUID. Every element is prepared through `prepare`.
    public static func encode(_ events: [Event]) -> String? {
        guard !events.isEmpty else { return nil }
        var seen: Set<UUID> = []
        var elements: [String] = []
        elements.reserveCapacity(min(events.count, maxEvents))
        var totalBytes = 2 // surrounding brackets

        for event in events.prefix(maxEvents) where seen.insert(event.id).inserted {
            let prepared = prepare(event)
            let element: String
            if let eventJSON = prepared.eventJSON {
                element = eventJSON
            } else {
                // `snapshotJSON` is already a one-element JSON array. Strip its
                // brackets so the poison marker remains one well-formed element.
                element = String(prepared.snapshotJSON.dropFirst().dropLast())
            }
            let separatorBytes = elements.isEmpty ? 0 : 1
            guard totalBytes + separatorBytes + element.utf8.count
                    <= maximumSnapshotBytes else {
                break
            }
            elements.append(element)
            totalBytes += separatorBytes + element.utf8.count
        }
        guard !elements.isEmpty else { return nil }
        return "[" + elements.joined(separator: ",") + "]"
    }

    private static func prepared(
        data: Data,
        eventID: String,
        timestamp: Date,
        disposition: PreparedAlertTrigger.Disposition,
        canonicalSHA256: Data,
        canonicalByteCount: Int
    ) -> PreparedAlertTrigger {
        let json = String(decoding: data, as: UTF8.self)
        return PreparedAlertTrigger(
            eventID: eventID,
            timestamp: timestamp,
            eventJSON: json,
            snapshotJSON: "[" + json + "]",
            disposition: disposition,
            canonicalSHA256: canonicalSHA256,
            canonicalByteCount: canonicalByteCount
        )
    }

    private static func validatesEvent(
        _ data: Data,
        eventID: String,
        timestamp: Date
    ) -> Bool {
        guard let decoded = try? JSONDecoder().decode(Event.self, from: data),
              decoded.id.uuidString.caseInsensitiveCompare(eventID)
                == .orderedSame,
              decoded.timestamp == timestamp else {
            return false
        }
        return true
    }

    private static func compact(
        _ value: Any,
        path: [String],
        policy: CompactionPolicy
    ) -> Any {
        if let string = value as? String {
            return boundedString(string, maximumBytes: policy.maximumStringBytes)
        }
        if let array = value as? [Any] {
            let key = path.last ?? ""
            let limit: Int
            switch key {
            case "args": limit = policy.maximumArgumentCount
            case "ancestors": limit = policy.maximumAncestorCount
            case "ruleMatches": limit = policy.maximumRuleMatchCount
            default: limit = policy.maximumGeneralArrayCount
            }
            return array.prefix(limit).map {
                compact($0, path: path + ["[]"], policy: policy)
            }
        }
        if let dictionary = value as? [String: Any] {
            let arbitrary = path.last == "enrichments"
                || path.last == "envVars"
            let sortedKeys = dictionary.keys.sorted()
            let retainedKeys = arbitrary
                ? Array(sortedKeys.prefix(policy.maximumArbitraryDictionaryCount))
                : sortedKeys
            var result: [String: Any] = [:]
            for key in retainedKeys {
                guard let child = dictionary[key] else { continue }
                result[key] = compact(
                    child,
                    path: path + [key],
                    policy: policy
                )
            }
            if arbitrary, retainedKeys.count < sortedKeys.count {
                result["_maccrab_alert_snapshot_omitted"] =
                    "\(sortedKeys.count - retainedKeys.count) entries omitted"
            }
            return result
        }
        return value
    }

    private static func boundedString(
        _ value: String,
        maximumBytes: Int
    ) -> String {
        guard value.utf8.count > maximumBytes else { return value }
        let digest = SHA256.hash(data: Data(value.utf8))
            .prefix(8)
            .map { String(format: "%02x", $0) }
            .joined()
        let marker = "...[TRUNCATED sha256=\(digest)]"
        let prefixBudget = max(0, maximumBytes - marker.utf8.count)
        var prefix = Data(value.utf8.prefix(prefixBudget))
        while !prefix.isEmpty, String(data: prefix, encoding: .utf8) == nil {
            prefix.removeLast()
        }
        return (String(data: prefix, encoding: .utf8) ?? "") + marker
    }

    private static func omittedEvent(
        from event: Event,
        sanitizedBytes: Data
    ) -> Data? {
        let digest = SHA256.hash(data: sanitizedBytes)
            .map { String(format: "%02x", $0) }
            .joined()
        let process = ProcessInfo(
            pid: event.process.pid,
            ppid: event.process.ppid,
            rpid: event.process.rpid,
            name: boundedString(
                EventPrivacySanitizer.sanitizeString(event.process.name),
                maximumBytes: 256
            ),
            executable: boundedString(
                EventPrivacySanitizer.sanitizeString(
                    event.process.executable
                ),
                maximumBytes: 1_024
            ),
            commandLine: "[OMITTED_OVERSIZE sha256=\(digest)]",
            args: [],
            workingDirectory: boundedString(
                EventPrivacySanitizer.sanitizeString(
                    event.process.workingDirectory
                ),
                maximumBytes: 1_024
            ),
            userId: event.process.userId,
            userName: boundedString(
                EventPrivacySanitizer.sanitizeString(event.process.userName),
                maximumBytes: 256
            ),
            groupId: event.process.groupId,
            startTime: event.process.startTime,
            exitCode: event.process.exitCode,
            architecture: event.process.architecture.map {
                boundedString(
                    EventPrivacySanitizer.sanitizeString($0),
                    maximumBytes: 64
                )
            },
            isPlatformBinary: event.process.isPlatformBinary,
            auditIdentity: event.process.auditIdentity
        )
        let omitted = Event(
            id: event.id,
            timestamp: event.timestamp,
            eventCategory: event.eventCategory,
            eventType: event.eventType,
            eventAction: boundedString(
                EventPrivacySanitizer.sanitizeString(event.eventAction),
                maximumBytes: 256
            ),
            process: process,
            enrichments: [
                "alert_trigger_snapshot": "omitted_oversize",
                "alert_trigger_sanitized_bytes": String(sanitizedBytes.count),
                "alert_trigger_sanitized_sha256": digest,
            ],
            severity: event.severity,
            ruleMatches: []
        )
        return try? EventPrivacySanitizer.sanitize(omitted).canonicalJSON
    }

    private static func poisonMarker(
        eventID: String,
        timestamp: Date
    ) -> String {
        let timestampValue = timestamp.timeIntervalSinceReferenceDate.isFinite
            ? timestamp.timeIntervalSinceReferenceDate : 0
        let object: [[String: Any]] = [[
            "id": eventID,
            "timestamp": timestampValue,
            "snapshot": "poison",
            "reason": "event could not be privacy-sanitized and encoded",
        ]]
        guard let data = try? JSONSerialization.data(
            withJSONObject: object,
            options: [.sortedKeys, .withoutEscapingSlashes]
        ) else {
            return #"[{"snapshot":"poison"}]"#
        }
        return String(decoding: data, as: UTF8.self)
    }
}
