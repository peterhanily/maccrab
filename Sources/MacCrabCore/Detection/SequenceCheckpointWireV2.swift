import Foundation

/// Keep the engine-facing logical model intact. The version is the actual
/// on-disk schema, not a decoder upgrade flag: v1 must reach the legacy semantic
/// validator unchanged before any legacy independent-correlation key is removed.
extension SequenceCheckpointPayload {
    private enum VersionKey: String, CodingKey { case schemaVersion }

    init(from decoder: Decoder) throws {
        let keys = try decoder.container(keyedBy: VersionKey.self)
        let version = try keys.decode(Int.self, forKey: .schemaVersion)
        switch version {
        case Self.legacySchemaVersion:
            self = try SequenceCheckpointLegacyWire(from: decoder).payload
        case Self.currentSchemaVersion:
            self = try SequenceCheckpointWireV2(from: decoder).payload
        default:
            throw SequenceCheckpointError.unsupportedSchemaVersion(version)
        }
    }

    func encode(to encoder: Encoder) throws {
        switch schemaVersion {
        case Self.legacySchemaVersion:
            try SequenceCheckpointLegacyWire(self).encode(to: encoder)
        case Self.currentSchemaVersion:
            try SequenceCheckpointWireV2(self).encode(to: encoder)
        default:
            throw SequenceCheckpointError.unsupportedSchemaVersion(schemaVersion)
        }
    }
}

/// Exact historical field layout, including duplicated membership identifiers
/// and required nonoptional ancestry fields. No v2 defaults apply to v1 input.
private struct SequenceCheckpointLegacyWire: Codable {
    let schemaVersion: Int
    let capturedAt: Date
    let ruleFingerprint: String
    let sourceGeneration: UInt64
    let partialBuckets: [SequenceCheckpointPartialBucket]
    let pendingBuckets: [SequenceCheckpointPendingBucket]
    let evictionOrder: [UUID]
    let pendingEvictionOrder: [SequenceCheckpointPendingIdentity]

    init(_ value: SequenceCheckpointPayload) {
        schemaVersion = value.schemaVersion
        capturedAt = value.capturedAt
        ruleFingerprint = value.ruleFingerprint
        sourceGeneration = value.sourceGeneration
        partialBuckets = value.partialBuckets
        pendingBuckets = value.pendingBuckets
        evictionOrder = value.evictionOrder
        pendingEvictionOrder = value.pendingEvictionOrder
    }

    var payload: SequenceCheckpointPayload {
        .init(schemaVersion: schemaVersion, capturedAt: capturedAt,
              ruleFingerprint: ruleFingerprint, sourceGeneration: sourceGeneration,
              partialBuckets: partialBuckets, pendingBuckets: pendingBuckets,
              evictionOrder: evictionOrder, pendingEvictionOrder: pendingEvictionOrder)
    }
}

/// V2 encodes bucket membership once, and omits only canonical default ancestry
/// values. All UUIDs, timestamps, paths, strings, FIFO order and non-default
/// ancestry survive exactly. An absent independent correlation key is a runtime
/// v2 invariant; it is never inferred from a string while decoding this wire.
struct SequenceCheckpointWireV2: Codable {
    let schemaVersion: Int
    let capturedAt: Date
    let ruleFingerprint: String
    let sourceGeneration: UInt64
    let partialBuckets: [PartialBucket]
    let pendingBuckets: [PendingBucket]
    let evictionOrder: [UUID]
    let pendingEvictionOrder: [SequenceCheckpointPendingIdentity]

    init(_ value: SequenceCheckpointPayload) throws {
        schemaVersion = value.schemaVersion
        capturedAt = value.capturedAt
        ruleFingerprint = value.ruleFingerprint
        sourceGeneration = value.sourceGeneration
        partialBuckets = try value.partialBuckets.map { bucket in
            guard bucket.partials.allSatisfy({ $0.ruleID == bucket.ruleID }) else {
                throw SequenceCheckpointError.invalidPayload("partial rule/bucket mismatch")
            }
            return PartialBucket(ruleID: bucket.ruleID, partials: bucket.partials.map(Partial.init))
        }
        pendingBuckets = try value.pendingBuckets.map { bucket in
            guard bucket.steps.allSatisfy({ $0.ruleID == bucket.ruleID }) else {
                throw SequenceCheckpointError.invalidPayload("pending rule/bucket mismatch")
            }
            return PendingBucket(ruleID: bucket.ruleID, steps: bucket.steps.map(Pending.init))
        }
        evictionOrder = value.evictionOrder
        pendingEvictionOrder = value.pendingEvictionOrder
    }

    var payload: SequenceCheckpointPayload {
        .init(schemaVersion: schemaVersion, capturedAt: capturedAt,
              ruleFingerprint: ruleFingerprint, sourceGeneration: sourceGeneration,
              partialBuckets: partialBuckets.map { bucket in
                  .init(ruleID: bucket.ruleID, partials: bucket.partials.map { $0.logical(ruleID: bucket.ruleID) })
              }, pendingBuckets: pendingBuckets.map { bucket in
                  .init(ruleID: bucket.ruleID, steps: bucket.steps.map { $0.logical(ruleID: bucket.ruleID) })
              }, evictionOrder: evictionOrder, pendingEvictionOrder: pendingEvictionOrder)
    }

    /// Captured time and process-local generation do not change semantic state.
    /// The schema and v2 structures do participate in its versioned digest.
    struct Semantic: Encodable {
        let schemaVersion: Int
        let ruleFingerprint: String
        let partialBuckets: [PartialBucket]
        let pendingBuckets: [PendingBucket]
        let evictionOrder: [UUID]
        let pendingEvictionOrder: [SequenceCheckpointPendingIdentity]
    }

    var semantic: Semantic {
        .init(schemaVersion: schemaVersion, ruleFingerprint: ruleFingerprint,
              partialBuckets: partialBuckets, pendingBuckets: pendingBuckets,
              evictionOrder: evictionOrder, pendingEvictionOrder: pendingEvictionOrder)
    }

    struct PartialBucket: Codable {
        let ruleID: String
        let partials: [Partial]
    }

    struct PendingBucket: Codable {
        let ruleID: String
        let steps: [Pending]
    }

    struct Partial: Codable {
        let id: UUID
        let createdAt: Date
        let matchedSteps: [Matched]
        let correlationKey: String?

        init(_ value: SequenceCheckpointPartial) {
            id = value.id
            createdAt = value.createdAt
            matchedSteps = value.matchedSteps.map(Matched.init)
            correlationKey = value.correlationKey
        }

        func logical(ruleID: String) -> SequenceCheckpointPartial {
            .init(id: id, ruleID: ruleID, createdAt: createdAt,
                  matchedSteps: matchedSteps.map(\.value), correlationKey: correlationKey)
        }
    }

    struct Pending: Codable {
        let stepID: String
        let matched: Matched
        let arrivedAt: Date

        init(_ value: SequenceCheckpointPendingStep) {
            stepID = value.stepID
            matched = Matched(value.matched)
            arrivedAt = value.arrivedAt
        }

        func logical(ruleID: String) -> SequenceCheckpointPendingStep {
            .init(ruleID: ruleID, stepID: stepID, matched: matched.value, arrivedAt: arrivedAt)
        }
    }

    struct Matched: Codable {
        let value: SequenceCheckpointMatchedStep

        init(_ value: SequenceCheckpointMatchedStep) { self.value = value }

        private enum CodingKeys: String, CodingKey {
            case stepID, eventID, timestamp, processPID, processParentPID
            case processParentWasTracked, processAncestorPIDs, filePath, networkDestination
        }

        init(from decoder: Decoder) throws {
            let keys = try decoder.container(keyedBy: CodingKeys.self)
            value = SequenceCheckpointMatchedStep(
                stepID: try keys.decode(String.self, forKey: .stepID),
                eventID: try keys.decode(UUID.self, forKey: .eventID),
                timestamp: try keys.decode(Date.self, forKey: .timestamp),
                processPID: try keys.decode(Int32.self, forKey: .processPID),
                processParentPID: keys.contains(.processParentPID)
                    ? try keys.decode(Int32.self, forKey: .processParentPID) : 0,
                processParentWasTracked: keys.contains(.processParentWasTracked)
                    ? try keys.decode(Bool.self, forKey: .processParentWasTracked) : false,
                processAncestorPIDs: keys.contains(.processAncestorPIDs)
                    ? try keys.decode([Int32].self, forKey: .processAncestorPIDs) : [],
                filePath: try keys.decodeIfPresent(String.self, forKey: .filePath),
                networkDestination: try keys.decodeIfPresent(String.self, forKey: .networkDestination)
            )
        }

        func encode(to encoder: Encoder) throws {
            var keys = encoder.container(keyedBy: CodingKeys.self)
            try keys.encode(value.stepID, forKey: .stepID)
            try keys.encode(value.eventID, forKey: .eventID)
            try keys.encode(value.timestamp, forKey: .timestamp)
            try keys.encode(value.processPID, forKey: .processPID)
            if value.processParentPID != 0 { try keys.encode(value.processParentPID, forKey: .processParentPID) }
            if value.processParentWasTracked { try keys.encode(true, forKey: .processParentWasTracked) }
            if !value.processAncestorPIDs.isEmpty { try keys.encode(value.processAncestorPIDs, forKey: .processAncestorPIDs) }
            try keys.encodeIfPresent(value.filePath, forKey: .filePath)
            try keys.encodeIfPresent(value.networkDestination, forKey: .networkDestination)
        }
    }
}
