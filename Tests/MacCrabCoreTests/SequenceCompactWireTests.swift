import Foundation
import Testing
@testable import MacCrabCore

/// Ordinary synthetic serialization compatibility cases only. These do not
/// exercise an installed carrier, hostile workload, collector or engine. Private
/// temporary checkpoint files cover the real coordinator migration boundary.
@Suite("Compact sequence wire v2 and strict legacy compatibility")
struct SequenceCompactWireTests {
    private func rule(correlation: CorrelationType = .none) -> SequenceRule {
        SequenceRule(id: "ordinary-wire", title: "Ordinary metadata",
            description: "in-memory codec fixture", level: .low, tags: [], window: 3_600,
            correlationType: correlation, ordered: true,
            steps: [SequenceStep(id: "first", logsourceCategory: "file_event", predicates: []),
                    SequenceStep(id: "later", logsourceCategory: "file_event", predicates: [], afterStep: "first")],
            trigger: .allSteps)
    }

    private func matched(step: String = "first", at time: Date, nondefaults: Bool = false,
                         path: String? = nil, destination: String? = nil) -> SequenceCheckpointMatchedStep {
        .init(stepID: step, eventID: UUID(), timestamp: time, processPID: 41,
              processParentPID: nondefaults ? 17 : 0, processParentWasTracked: nondefaults,
              processAncestorPIDs: nondefaults ? [1, 17] : [], filePath: path,
              networkDestination: destination)
    }

    private func payload(schema: Int, definition: SequenceRule, count: Int = 1,
                         at time: Date, nondefaults: Bool = false,
                         path: String? = nil, destination: String? = nil,
                         legacyNonce: Bool = true, includePending: Bool = false) throws -> SequenceCheckpointPayload {
        let partials = (0..<count).map { _ in
            SequenceCheckpointPartial(id: UUID(), ruleID: definition.id, createdAt: time,
                matchedSteps: [matched(at: time, nondefaults: nondefaults, path: path, destination: destination)],
                correlationKey: definition.correlationType == .processSame ? "41"
                    : (schema == 1 && legacyNonce ? definition.id + ":" + UUID().uuidString : nil))
        }
        let pending = includePending ? [SequenceCheckpointPendingStep(ruleID: definition.id, stepID: "later",
            matched: matched(step: "later", at: time, nondefaults: nondefaults, path: path, destination: destination),
            arrivedAt: time)] : []
        return .init(schemaVersion: schema, capturedAt: time,
            ruleFingerprint: try SequenceCheckpointCodec.ruleFingerprint([definition]), sourceGeneration: 1,
            partialBuckets: [.init(ruleID: definition.id, partials: partials)],
            pendingBuckets: pending.isEmpty ? [] : [.init(ruleID: definition.id, steps: pending)],
            evictionOrder: partials.map(\.id), pendingEvictionOrder: pending.map {
                .init(ruleID: $0.ruleID, stepID: $0.stepID, eventID: $0.matched.eventID)
            })
    }

    private func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return encoder
    }

    @Test("V2 inherits rule membership and omits only exact canonical defaults", arguments: [false, true])
    func compactShapeAndExactDefaults(nondefaults: Bool) throws {
        let original = try payload(schema: 2, definition: rule(), at: Date(), nondefaults: nondefaults,
                                   path: nondefaults ? "" : nil, destination: nondefaults ? "" : nil,
                                   includePending: true)
        let data = try encoder().encode(original)
        let parsed = try JSONSerialization.jsonObject(with: data)
        let object = try #require(parsed as? [String: Any])
        let buckets = try #require(object["partialBuckets"] as? [[String: Any]])
        let bucket = try #require(buckets.first)
        #expect(bucket["ruleID"] as? String == rule().id)
        let partial = try #require((bucket["partials"] as? [[String: Any]])?.first)
        #expect(partial["ruleID"] == nil && partial["correlationKey"] == nil)
        let matched = try #require((partial["matchedSteps"] as? [[String: Any]])?.first)
        if nondefaults {
            #expect(matched["processParentPID"] as? Int == 17)
            #expect(matched["processParentWasTracked"] as? Bool == true)
            #expect(matched["processAncestorPIDs"] as? [Int] == [1, 17])
            #expect(matched["filePath"] as? String == "" && matched["networkDestination"] as? String == "")
        } else {
            #expect(matched["processParentPID"] == nil && matched["processParentWasTracked"] == nil)
            #expect(matched["processAncestorPIDs"] == nil && matched["filePath"] == nil && matched["networkDestination"] == nil)
        }
        let pendingBucket = try #require((object["pendingBuckets"] as? [[String: Any]])?.first)
        let pending = try #require((pendingBucket["steps"] as? [[String: Any]])?.first)
        #expect(pendingBucket["ruleID"] as? String == rule().id)
        #expect(pending["ruleID"] == nil)
        let decoded = try SequenceCheckpointCodec.decode(SequenceCheckpointCodec.encode(original))
        let exactlyEqual = decoded == original
        #expect(exactlyEqual, "Omitted defaults must reconstruct exactly; empty strings are not nil")
    }

    @Test("Control escapes and Unicode preserve full logical values and remain below the wire bound")
    func escapedValuesRoundTripAndStayBounded() throws {
        let texts = ["ordinary/ascii", "quotes \" slash / backslash \\",
                     "\u{0000}\u{0001}\n\r\t\u{007F}", "é e\u{0301} 漢字 😀 🧑🏽‍💻",
                     "\u{2028}\u{2029}\u{2066}\u{2069}\u{FEFF}"]
        for text in texts {
            let original = try payload(schema: 2, definition: rule(), count: 16, at: Date(),
                                       nondefaults: true, path: text, destination: text, includePending: true)
            let estimate = SequenceCheckpointCodec.estimatedSemanticStateWeight(
                partialBuckets: original.partialBuckets, pendingBuckets: original.pendingBuckets)
            #expect(try encoder().encode(original).count <= estimate)
            let decoded = try SequenceCheckpointCodec.decode(SequenceCheckpointCodec.encode(original))
            let same = decoded == original
            #expect(same, "Escaping and compact representation must preserve all logical fields")
        }
    }

    @Test("V2 defaults apply to absent ancestry fields, not explicit nulls", arguments: [false, true])
    func explicitNullIsNotDefault(pendingRecord: Bool) throws {
        let original = try payload(schema: 2, definition: rule(), at: Date(), includePending: true)
        let data = try encoder().encode(original)
        for field in ["processParentPID", "processParentWasTracked", "processAncestorPIDs"] {
            let parsed = try JSONSerialization.jsonObject(with: data)
            var object = try #require(parsed as? [String: Any])
            let bucketKey = pendingRecord ? "pendingBuckets" : "partialBuckets"
            let recordKey = pendingRecord ? "steps" : "partials"
            var buckets = try #require(object[bucketKey] as? [[String: Any]])
            var records = try #require(buckets[0][recordKey] as? [[String: Any]])
            if pendingRecord {
                var matched = try #require(records[0]["matched"] as? [String: Any])
                matched[field] = NSNull()
                records[0]["matched"] = matched
            } else {
                var matched = try #require(records[0]["matchedSteps"] as? [[String: Any]])
                matched[0][field] = NSNull()
                records[0]["matchedSteps"] = matched
            }
            buckets[0][recordKey] = records
            object[bucketKey] = buckets
            do {
                _ = try JSONDecoder().decode(SequenceCheckpointPayload.self,
                    from: JSONSerialization.data(withJSONObject: object))
                Issue.record("Explicit null \(field) was silently defaulted in v2")
            } catch is DecodingError { }
        }
    }

    @Test("Inherited membership cannot hide a mismatched logical record during encoding", arguments: [false, true])
    func encodeRejectsMismatchedMembership(pendingRecord: Bool) throws {
        let original = try payload(schema: 2, definition: rule(), at: Date(), includePending: true)
        let candidate = SequenceCheckpointPayload(schemaVersion: 2, capturedAt: original.capturedAt,
            ruleFingerprint: original.ruleFingerprint, sourceGeneration: original.sourceGeneration,
            partialBuckets: pendingRecord ? original.partialBuckets
                : [.init(ruleID: "different-ordinary-rule", partials: original.partialBuckets[0].partials)],
            pendingBuckets: pendingRecord
                ? [.init(ruleID: "different-ordinary-rule", steps: original.pendingBuckets[0].steps)]
                : original.pendingBuckets,
            evictionOrder: original.evictionOrder, pendingEvictionOrder: original.pendingEvictionOrder)
        do {
            _ = try SequenceCheckpointCodec.encode(candidate)
            Issue.record("Compact encoding silently changed logical rule membership")
        } catch let error as SequenceCheckpointError {
            #expect(error == .invalidPayload(pendingRecord
                ? "pending rule/bucket mismatch" : "partial rule/bucket mismatch"))
        }
    }

    @Test("Legacy v1 keeps required ancestry fields and cannot borrow v2 defaults")
    func legacyRequiredFieldsRemainRequired() throws {
        let original = try payload(schema: 1, definition: rule(), at: Date())
        let data = try encoder().encode(original)
        let decoded = try SequenceCheckpointCodec.decode(SequenceCheckpointCodec.encode(original))
        #expect(decoded == original && decoded.schemaVersion == 1)
        for field in ["processParentPID", "processParentWasTracked", "processAncestorPIDs"] {
            let parsed = try JSONSerialization.jsonObject(with: data)
            var object = try #require(parsed as? [String: Any])
            var buckets = try #require(object["partialBuckets"] as? [[String: Any]])
            var partials = try #require(buckets[0]["partials"] as? [[String: Any]])
            var steps = try #require(partials[0]["matchedSteps"] as? [[String: Any]])
            let removed = steps[0].removeValue(forKey: field)
            try #require(removed != nil)
            partials[0]["matchedSteps"] = steps
            buckets[0]["partials"] = partials
            object["partialBuckets"] = buckets
            do {
                _ = try JSONDecoder().decode(SequenceCheckpointPayload.self,
                    from: JSONSerialization.data(withJSONObject: object))
                Issue.record("Legacy required field \(field) was silently defaulted")
            } catch is DecodingError { }
        }
    }

    @Test("Synthetic v1 known-answer pins the pre-RC6 canonical wire and semantic digest")
    func legacyKnownAnswer() throws {
        // Independently authored from the model and SemanticState algorithm in
        // 66baf4a23e5cabb46fbfa25284a8e952c99c8089. This is NOT a historical
        // capture, nor a rule-fingerprint validation fixture. Its ordinary data
        // pins the expanded layout, default ancestry fields and empty/nil split.
        // The expected SHA-256 was calculated with shasum over literal sorted
        // semantic JSON: this payload minus capturedAt and sourceGeneration,
        // with no prefix, whitespace or trailing newline (the v1 algorithm).
        let canonicalJSON = #"{"capturedAt":125,"evictionOrder":["11111111-1111-4111-8111-111111111111"],"partialBuckets":[{"partials":[{"correlationKey":"ordinary-wire:33333333-3333-4333-8333-333333333333","createdAt":123,"id":"11111111-1111-4111-8111-111111111111","matchedSteps":[{"eventID":"22222222-2222-4222-8222-222222222222","filePath":"/private/tmp/ordinary.txt","networkDestination":"","processAncestorPIDs":[1,17],"processPID":41,"processParentPID":17,"processParentWasTracked":true,"stepID":"first","timestamp":123}],"ruleID":"ordinary-wire"}],"ruleID":"ordinary-wire"}],"pendingBuckets":[{"ruleID":"ordinary-wire","steps":[{"arrivedAt":124,"matched":{"eventID":"44444444-4444-4444-8444-444444444444","processAncestorPIDs":[],"processPID":42,"processParentPID":0,"processParentWasTracked":false,"stepID":"later","timestamp":124},"ruleID":"ordinary-wire","stepID":"later"}]}],"pendingEvictionOrder":[{"eventID":"44444444-4444-4444-8444-444444444444","ruleID":"ordinary-wire","stepID":"later"}],"ruleFingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","schemaVersion":1,"sourceGeneration":7}"#
        let expectedDigest = "cf04d806695d34ee898de3ed2bab3533ae36ebc9111c4e853aac50a36d00bb77"
        let literalBytes = Data(canonicalJSON.utf8)
        let decoded = try JSONDecoder().decode(SequenceCheckpointPayload.self, from: literalBytes)
        let encoded = try encoder().encode(decoded)
        let exactWireBytes = encoded == literalBytes
        #expect(exactWireBytes, "The old canonical v1 JSON bytes must remain exact")
        #expect(try SequenceCheckpointCodec.semanticDigest(of: decoded) == expectedDigest)
        let envelopeDecoded = try SequenceCheckpointCodec.decode(SequenceCheckpointCodec.encode(decoded))
        #expect(envelopeDecoded == decoded)

        // These two process-local observation fields never participated in the
        // historical semantic hash; all state fields remain unchanged here.
        let recaptured = SequenceCheckpointPayload(schemaVersion: 1,
            capturedAt: Date(timeIntervalSinceReferenceDate: 999), ruleFingerprint: decoded.ruleFingerprint,
            sourceGeneration: 42, partialBuckets: decoded.partialBuckets, pendingBuckets: decoded.pendingBuckets,
            evictionOrder: decoded.evictionOrder, pendingEvictionOrder: decoded.pendingEvictionOrder)
        #expect(try SequenceCheckpointCodec.semanticDigest(of: recaptured) == expectedDigest)
    }

    @Test("Legacy nonce validation precedes migration; only validated state gains nil independent keys")
    func legacyValidationPrecedesConversion() async throws {
        let definition = rule(), time = Date()
        let legacy = try payload(schema: 1, definition: definition, count: 3, at: time)
        let decoded = try SequenceCheckpointCodec.decode(SequenceCheckpointCodec.encode(legacy))
        #expect(decoded.partialBuckets.flatMap(\.partials).allSatisfy { $0.correlationKey != nil })
        let target = SequenceEngine(lineage: ProcessLineage())
        try await target.addRule(definition)
        let result = try await target.restoreCheckpoint(decoded, now: time)
        #expect(result.partialCount == 3)
        let migrated = try await target.checkpointCapture(at: time)
        let newPartials = migrated.partialBuckets.flatMap(\.partials)
        let oldPartials = legacy.partialBuckets.flatMap(\.partials)
        #expect(newPartials.allSatisfy { $0.correlationKey == nil })
        #expect(newPartials.map(\.id) == oldPartials.map(\.id))
        #expect(newPartials.map(\.matchedSteps) == oldPartials.map(\.matchedSteps))
        #expect(migrated.evictionOrder == legacy.evictionOrder)
        #expect(try SequenceCheckpointCodec.prepare(migrated).payload.schemaVersion == 2)

        let noNonce = try payload(schema: 1, definition: definition, at: time, legacyNonce: false)
        let rejected = SequenceEngine(lineage: ProcessLineage())
        try await rejected.addRule(definition)
        do {
            _ = try await rejected.restoreCheckpoint(
                SequenceCheckpointCodec.decode(SequenceCheckpointCodec.encode(noNonce)), now: time)
            Issue.record("Legacy independent key was normalized before validation")
        } catch let error as SequenceCheckpointError {
            guard case .invalidPayload = error else { Issue.record("Unexpected compatibility error: \(error)"); return }
        }
        #expect(await rejected.checkpointWeightDiagnostics().partialCount == 0)
    }

    @Test("Legacy retains the supported deployed 10k migration ceiling when the new runtime permits 13k")
    func legacyCountBoundaryIsNotLifted() throws {
        let definition = rule(correlation: .processSame), time = Date()
        let original = try payload(schema: 1, definition: definition, count: 10_001, at: time)
        let legacyWeight = SequenceCheckpointCodec.estimatedLegacySemanticStateWeight(
            partialBuckets: original.partialBuckets, pendingBuckets: original.pendingBuckets)
        try #require(legacyWeight < 7_864_320, "Fixture must isolate count pressure from byte pressure")
        let kept = Array(original.partialBuckets[0].partials.prefix(10_000))
        let atBoundary = SequenceCheckpointPayload(schemaVersion: 1, capturedAt: time,
            ruleFingerprint: original.ruleFingerprint, sourceGeneration: 1,
            partialBuckets: [.init(ruleID: definition.id, partials: kept)], pendingBuckets: [],
            evictionOrder: kept.map(\.id), pendingEvictionOrder: [])
        let valid = try SequenceCheckpointValidator.validate(atBoundary, rules: [definition.id: definition],
            maximumPartialMatches: 13_000, maximumPendingPerRule: 8_192, now: time)
        #expect(valid.partialBuckets.flatMap(\.partials).count == 10_000)
        do {
            _ = try SequenceCheckpointValidator.validate(original, rules: [definition.id: definition],
                maximumPartialMatches: 13_000, maximumPendingPerRule: 8_192, now: time)
            Issue.record("Supported legacy migration count cap was silently raised during conversion")
        } catch let error as SequenceCheckpointError {
            guard case .invalidPayload(let reason) = error else { Issue.record("Unexpected cap error: \(error)"); return }
            #expect(reason.contains("count") && reason.contains("cap"))
        }
    }

    @Test("Legacy restore remains dirty until a v2 write, and unchanged skips validate the current carrier")
    func coordinatorMigratesLegacyAndRevalidatesCarrier() async throws {
        let definition = rule(), time = Date()
        // This migration contract covers the deployed/default v1 <=10k state,
        // not arbitrary historical engines configured above that ceiling.
        let legacy = try payload(schema: 1, definition: definition, count: 3, at: time)
        let legacyFile = try SequenceCheckpointCodec.encode(legacy)
        let legacyDigest = try SequenceCheckpointCodec.semanticDigest(of: legacy)
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-compact-migration-\(UUID())")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("ordinary.chk")
        try SequenceCheckpointFileStore.write(legacyFile, to: file)
        let engine = SequenceEngine(lineage: ProcessLineage())
        try await engine.addRule(definition)
        let coordinator = SequenceCheckpointCoordinator(checkpointURL: file)
        let restored = await coordinator.restore(into: engine, now: time)
        #expect(restored == .restored(partials: 3, pendingSteps: 0,
                                     expiredPartials: 0, expiredPendingSteps: 0))
        let before = await coordinator.telemetry(now: time)
        #expect(before.dirty && before.currentSemanticDigest == nil && before.durableCarrierValid)
        #expect(before.durableSemanticDigest == legacyDigest && before.writesTotal == 0)
        #expect(try SequenceCheckpointFileStore.read(from: file) == legacyFile)
        let canonical = try await engine.checkpointCapture(at: time)
        #expect(canonical.partialBuckets.flatMap(\.partials).allSatisfy { $0.correlationKey == nil })
        #expect(canonical.evictionOrder == legacy.evictionOrder)

        guard case .written = await coordinator.forceFlush(engine: engine, now: time) else {
            Issue.record("A validated legacy carrier must be rewritten to v2, not skipped as unchanged")
            return
        }
        let storedV2File = try SequenceCheckpointFileStore.read(from: file)
        let v2File = try #require(storedV2File)
        let migrated = try SequenceCheckpointCodec.decode(v2File)
        #expect(migrated.schemaVersion == 2)
        let recordsPreserved = migrated.partialBuckets == canonical.partialBuckets
            && migrated.pendingBuckets == canonical.pendingBuckets
            && migrated.evictionOrder == canonical.evictionOrder
            && migrated.pendingEvictionOrder == canonical.pendingEvictionOrder
        #expect(recordsPreserved, "Migration preserves every validated canonical record and both FIFO orders")
        let after = await coordinator.telemetry(now: time)
        #expect(!after.dirty && after.durableCarrierValid && after.writesTotal == 1)
        #expect(after.currentSemanticDigest == after.durableSemanticDigest)
        #expect(after.durableSemanticDigest == (try SequenceCheckpointCodec.semanticDigest(of: migrated)))
        #expect(await coordinator.forceFlush(engine: engine, now: time) == .unchanged)
        #expect(try SequenceCheckpointFileStore.read(from: file) == v2File)
        let skipped = await coordinator.telemetry(now: time)
        #expect(skipped.unchangedSkipsTotal == 1 && skipped.writesTotal == 1)

        // Re-present the ordinary, valid legacy fixture in our private file.
        // An unchanged in-memory digest cannot authorize skipping this readback.
        try SequenceCheckpointFileStore.write(legacyFile, to: file)
        guard case .written = await coordinator.forceFlush(engine: engine, now: time) else {
            Issue.record("Unchanged skip did not revalidate the actual versioned carrier")
            return
        }
        let storedRewrittenFile = try SequenceCheckpointFileStore.read(from: file)
        let rewrittenFile = try #require(storedRewrittenFile)
        let rewritten = try SequenceCheckpointCodec.decode(rewrittenFile)
        let exactRewrite = rewritten == migrated
        #expect(exactRewrite && rewritten.schemaVersion == 2)
        let revalidated = await coordinator.telemetry(now: time)
        #expect(revalidated.carrierInvalidationsTotal == 1)
        #expect(revalidated.lastCarrierInvalidationReason == .semanticMismatch)
        #expect(revalidated.writesTotal == 2 && revalidated.unchangedSkipsTotal == 1)
        #expect(!revalidated.dirty && revalidated.durableCarrierValid)
        #expect(revalidated.conservation.conservationMaintained)
    }

    @Test("Future schemas fail encode, decode and validation instead of selecting a known layout")
    func futureSchemaIsRejected() throws {
        let definition = rule(), time = Date()
        let future = try payload(schema: 3, definition: definition, at: time)
        do {
            _ = try SequenceCheckpointCodec.encode(future)
            Issue.record("Unknown schema was encoded")
        } catch let error as SequenceCheckpointError { #expect(error == .unsupportedSchemaVersion(3)) }
        let ordinary = try payload(schema: 2, definition: definition, at: time)
        let ordinaryData = try encoder().encode(ordinary)
        let parsed = try JSONSerialization.jsonObject(with: ordinaryData)
        var object = try #require(parsed as? [String: Any])
        object["schemaVersion"] = 3
        do {
            _ = try JSONDecoder().decode(SequenceCheckpointPayload.self,
                from: JSONSerialization.data(withJSONObject: object))
            Issue.record("Unknown schema borrowed a known decoder")
        } catch let error as SequenceCheckpointError { #expect(error == .unsupportedSchemaVersion(3)) }
        do {
            _ = try SequenceCheckpointValidator.validate(future, rules: [definition.id: definition],
                maximumPartialMatches: 13_000, maximumPendingPerRule: 8_192, now: time)
            Issue.record("Unknown schema was validated")
        } catch let error as SequenceCheckpointError { #expect(error == .unsupportedSchemaVersion(3)) }
    }
}
