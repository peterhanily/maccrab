// SequenceCheckpointCodec.swift
// MacCrabCore
//
// Bounded LZFSE envelope, semantic hashing, adversarial payload validation,
// and private no-follow file I/O for SequenceEngine recovery checkpoints.

import Foundation
import Compression
import CryptoKit
import Darwin

enum SequenceCheckpointCodec {
    // 8-byte magic + version/codec/reserved + two lengths + SHA-256.
    static let magic = Array("MCSEQCP1".utf8)
    static let envelopeVersion: UInt16 = 1
    static let headerBytes = 52
    static let maximumFileBytes = 8 * 1_024 * 1_024
    static let maximumUncompressedBytes = 32 * 1_024 * 1_024
    /// Conservative upper-bound budget for the canonical JSON state. Keeping
    /// this below the raw 8 MiB envelope ceiling guarantees checkpointability
    /// even when unique paths/UUIDs are incompressible.
    static let maximumSemanticStateWeight = 7 * 1_024 * 1_024 + 512 * 1_024
    static let semanticStateBaseWeight = 4_096

    private static let rawCodec: UInt8 = 0
    private static let lzfseCodec: UInt8 = 1

    private struct SemanticState: Codable {
        let schemaVersion: Int
        let ruleFingerprint: String
        let partialBuckets: [SequenceCheckpointPartialBucket]
        let pendingBuckets: [SequenceCheckpointPendingBucket]
        let evictionOrder: [UUID]
        let pendingEvictionOrder: [SequenceCheckpointPendingIdentity]
    }

    static func prepare(_ capture: SequenceCheckpointCapture) throws -> PreparedSequenceCheckpoint {
        let estimatedWeight = estimatedSemanticStateWeight(
            partialBuckets: capture.partialBuckets,
            pendingBuckets: capture.pendingBuckets
        )
        guard estimatedWeight <= maximumSemanticStateWeight else {
            throw SequenceCheckpointError.invalidPayload(
                "checkpoint semantic state weight \(estimatedWeight) exceeds \(maximumSemanticStateWeight)"
            )
        }
        let payload = SequenceCheckpointPayload(
            schemaVersion: SequenceCheckpointPayload.currentSchemaVersion,
            capturedAt: capture.capturedAt,
            ruleFingerprint: try ruleFingerprint(capture.rules),
            sourceGeneration: capture.sourceGeneration,
            partialBuckets: capture.partialBuckets,
            pendingBuckets: capture.pendingBuckets,
            evictionOrder: capture.evictionOrder,
            pendingEvictionOrder: capture.pendingEvictionOrder
        )
        let semanticDigest = try semanticDigest(of: payload)
        let payloadData = try canonicalEncoder().encode(payload)
        let encodedFile = try encodeEnvelope(payloadData)
        return PreparedSequenceCheckpoint(
            payload: payload,
            semanticDigest: semanticDigest,
            encodedFile: encodedFile
        )
    }

    static func estimatedSemanticStateWeight(
        partialBuckets: [SequenceCheckpointPartialBucket],
        pendingBuckets: [SequenceCheckpointPendingBucket]
    ) -> Int {
        var total = semanticStateBaseWeight
        for bucket in partialBuckets {
            total = saturatingWeightAdd(total, estimatedWeight(of: bucket))
        }
        for bucket in pendingBuckets {
            total = saturatingWeightAdd(total, estimatedWeight(of: bucket))
        }
        return total
    }

    static func estimatedWeight(of bucket: SequenceCheckpointPartialBucket) -> Int {
        guard !bucket.partials.isEmpty else { return 0 }
        var total = estimatedBucketOverhead(ruleID: bucket.ruleID)
        for partial in bucket.partials {
            total = saturatingWeightAdd(total, estimatedWeight(of: partial))
        }
        return total
    }

    static func estimatedWeight(of bucket: SequenceCheckpointPendingBucket) -> Int {
        guard !bucket.steps.isEmpty else { return 0 }
        var total = estimatedBucketOverhead(ruleID: bucket.ruleID)
        for pending in bucket.steps {
            total = saturatingWeightAdd(total, estimatedWeight(of: pending))
        }
        return total
    }

    static func estimatedBucketOverhead(ruleID: String) -> Int {
        saturatingWeightAdd(192, escapedJSONWeight(ruleID))
    }

    static func estimatedWeight(of partial: SequenceCheckpointPartial) -> Int {
        var total = 280 // record keys, UUIDs, dates, numbers, eviction UUID
        total = saturatingWeightAdd(total, escapedJSONWeight(partial.ruleID))
        total = saturatingWeightAdd(total, escapedJSONWeight(partial.correlationKey ?? ""))
        for matched in partial.matchedSteps {
            total = saturatingWeightAdd(total, estimatedWeight(of: matched))
        }
        return total
    }

    static func estimatedWeight(of pending: SequenceCheckpointPendingStep) -> Int {
        var total = 420 // record + global-order identity + UUID/date overhead
        let ruleWeight = escapedJSONWeight(pending.ruleID)
        let stepWeight = escapedJSONWeight(pending.stepID)
        // Both identifiers appear once in pendingBuckets and again in the
        // global pendingEvictionOrder identity.
        total = saturatingWeightAdd(total, ruleWeight)
        total = saturatingWeightAdd(total, ruleWeight)
        total = saturatingWeightAdd(total, stepWeight)
        total = saturatingWeightAdd(total, stepWeight)
        return saturatingWeightAdd(total, estimatedWeight(of: pending.matched))
    }

    private static func estimatedWeight(of matched: SequenceCheckpointMatchedStep) -> Int {
        var total = 320 + matched.processAncestorPIDs.count * 16
        total = saturatingWeightAdd(total, escapedJSONWeight(matched.stepID))
        total = saturatingWeightAdd(total, escapedJSONWeight(matched.filePath ?? ""))
        total = saturatingWeightAdd(
            total,
            escapedJSONWeight(matched.networkDestination ?? "")
        )
        return total
    }

    private static func escapedJSONWeight(_ value: String) -> Int {
        let bytes = value.utf8.count
        return bytes > Int.max / 6 ? Int.max : bytes * 6
    }

    private static func saturatingWeightAdd(_ lhs: Int, _ rhs: Int) -> Int {
        guard lhs >= 0, rhs >= 0, lhs <= Int.max - rhs else { return Int.max }
        return lhs + rhs
    }

    static func ruleFingerprint(_ rules: [SequenceRule]) throws -> String {
        guard rules.count <= SequenceCheckpointLimits.maximumRules else {
            throw SequenceCheckpointError.invalidPayload(
                "active rule count \(rules.count) exceeds \(SequenceCheckpointLimits.maximumRules)"
            )
        }
        for rule in rules { try validateRuleFingerprintShape(rule) }
        let sortedRules = rules.sorted { $0.id < $1.id }
        guard Set(sortedRules.map(\.id)).count == sortedRules.count else {
            throw SequenceCheckpointError.invalidPayload(
                "active sequence rules contain duplicate identities"
            )
        }

        // Encode and hash one structurally-bounded rule at a time. The former
        // implementation encoded the complete corpus before checking its 8 MiB
        // ceiling, so the ceiling did not bound peak allocation. Length framing
        // makes concatenation unambiguous without retaining aggregate bytes.
        var hasher = SHA256()
        hasher.update(data: Data("MacCrab.SequenceRules.v1\u{0}".utf8))
        var countFrame = Data()
        appendUInt32(UInt32(sortedRules.count), to: &countFrame)
        hasher.update(data: countFrame)
        var cumulativeBytes = 0
        for rule in sortedRules {
            let encodedRule = try canonicalEncoder().encode(rule)
            guard encodedRule.count <= SequenceCheckpointLimits.maximumSingleRuleFingerprintBytes else {
                throw SequenceCheckpointError.invalidPayload(
                    "canonical rule \(rule.id) exceeds the per-rule fingerprint byte ceiling"
                )
            }
            cumulativeBytes = try checkedAdd(
                cumulativeBytes,
                encodedRule.count,
                field: "canonical rule fingerprint bytes"
            )
            guard cumulativeBytes <= SequenceCheckpointLimits.maximumRuleFingerprintBytes else {
                throw SequenceCheckpointError.invalidPayload(
                    "canonical active rule definitions exceed the fingerprint byte ceiling"
                )
            }
            var lengthFrame = Data()
            appendUInt32(UInt32(encodedRule.count), to: &lengthFrame)
            hasher.update(data: lengthFrame)
            hasher.update(data: encodedRule)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    /// Cheap structural ceilings applied before JSONEncoder can allocate a
    /// complete per-rule representation. File-loaded rules are already bounded
    /// by RuleFileLoadingPolicy; this also closes the programmatic addRule path.
    static func validateRuleFingerprintShape(_ rule: SequenceRule) throws {
        guard rule.window.isFinite, rule.window > 0 else {
            throw SequenceCheckpointError.invalidPayload(
                "rule \(rule.id) has a non-finite or non-positive window"
            )
        }
        guard rule.steps.count <= SequenceCheckpointLimits.maximumStepsPerRule else {
            throw SequenceCheckpointError.invalidPayload(
                "rule \(rule.id) exceeds the step-count ceiling"
            )
        }
        guard rule.tags.count <= SequenceCheckpointLimits.maximumTagsPerRule else {
            throw SequenceCheckpointError.invalidPayload(
                "rule \(rule.id) exceeds the tag-count ceiling"
            )
        }

        var stringBytes = 0
        var predicateCount = 0
        var predicateValueCount = 0
        func addString(_ value: String, field: String, identifier: Bool = false) throws {
            let bytes = value.utf8.count
            let perValueLimit = identifier
                ? SequenceCheckpointLimits.maximumIdentifierBytes
                : SequenceCheckpointLimits.maximumValueBytes
            guard (!identifier || !value.isEmpty), bytes <= perValueLimit else {
                throw SequenceCheckpointError.invalidPayload(
                    "rule \(rule.id) has an empty or oversized \(field)"
                )
            }
            stringBytes = try checkedAdd(stringBytes, bytes, field: "rule string bytes")
            guard stringBytes <= SequenceCheckpointLimits.maximumSingleRuleFingerprintBytes else {
                throw SequenceCheckpointError.invalidPayload(
                    "rule \(rule.id) exceeds the pre-encoding string-byte ceiling"
                )
            }
        }

        try addString(rule.id, field: "id", identifier: true)
        try addString(rule.title, field: "title")
        try addString(rule.description, field: "description")
        for tag in rule.tags { try addString(tag, field: "tag") }
        if let status = rule.status { try addString(status, field: "status") }
        if case .steps(let triggerStepIDs) = rule.trigger {
            guard triggerStepIDs.count <= rule.steps.count else {
                throw SequenceCheckpointError.invalidPayload(
                    "rule \(rule.id) trigger exceeds its step count"
                )
            }
            for stepID in triggerStepIDs {
                try addString(stepID, field: "trigger step id", identifier: true)
            }
        }

        for step in rule.steps {
            try addString(step.id, field: "step id", identifier: true)
            try addString(step.logsourceCategory, field: "logsource category", identifier: true)
            if let after = step.afterStep {
                try addString(after, field: "after-step id", identifier: true)
            }
            if let relation = step.processRelation {
                try addString(
                    relation.relativeToStep,
                    field: "process-relation step id",
                    identifier: true
                )
            }
            predicateCount = try checkedAdd(
                predicateCount,
                step.predicates.count,
                field: "rule predicate count"
            )
            guard predicateCount <= SequenceCheckpointLimits.maximumPredicatesPerRule else {
                throw SequenceCheckpointError.invalidPayload(
                    "rule \(rule.id) exceeds the predicate-count ceiling"
                )
            }
            for predicate in step.predicates {
                try addString(predicate.field, field: "predicate field", identifier: true)
                predicateValueCount = try checkedAdd(
                    predicateValueCount,
                    predicate.values.count,
                    field: "rule predicate-value count"
                )
                guard predicateValueCount
                        <= SequenceCheckpointLimits.maximumPredicateValuesPerRule else {
                    throw SequenceCheckpointError.invalidPayload(
                        "rule \(rule.id) exceeds the predicate-value-count ceiling"
                    )
                }
                for value in predicate.values {
                    try addString(value, field: "predicate value")
                }
            }
            if let tree = step.conditionTree {
                do {
                    try tree.validate(predicateCount: step.predicates.count)
                } catch {
                    throw SequenceCheckpointError.invalidPayload(
                        "rule \(rule.id) has an invalid condition tree: \(error.localizedDescription)"
                    )
                }
            }
        }
    }

    static func semanticDigest(of payload: SequenceCheckpointPayload) throws -> String {
        let semantic = SemanticState(
            schemaVersion: payload.schemaVersion,
            ruleFingerprint: payload.ruleFingerprint,
            partialBuckets: payload.partialBuckets,
            pendingBuckets: payload.pendingBuckets,
            evictionOrder: payload.evictionOrder,
            pendingEvictionOrder: payload.pendingEvictionOrder
        )
        return sha256Hex(try canonicalEncoder().encode(semantic))
    }

    static func encode(_ payload: SequenceCheckpointPayload) throws -> Data {
        try encodeEnvelope(canonicalEncoder().encode(payload))
    }

    static func decode(_ fileData: Data) throws -> SequenceCheckpointPayload {
        guard fileData.count >= headerBytes else { throw SequenceCheckpointError.truncated }
        guard fileData.count <= maximumFileBytes else {
            throw SequenceCheckpointError.fileTooLarge(
                actual: fileData.count,
                maximum: maximumFileBytes
            )
        }

        let header = Array(fileData.prefix(headerBytes))
        guard Array(header[0..<8]) == magic else { throw SequenceCheckpointError.invalidMagic }

        let version = Int(readUInt16(header, at: 8))
        guard version == Int(envelopeVersion) else {
            throw SequenceCheckpointError.unsupportedEnvelopeVersion(version)
        }
        let codec = header[10]
        guard header[11] == 0 else { throw SequenceCheckpointError.invalidLength }
        let uncompressedCount = Int(readUInt32(header, at: 12))
        let encodedCount = Int(readUInt32(header, at: 16))
        guard uncompressedCount > 0,
              uncompressedCount <= maximumUncompressedBytes else {
            throw SequenceCheckpointError.payloadTooLarge(
                actual: uncompressedCount,
                maximum: maximumUncompressedBytes
            )
        }
        guard encodedCount > 0,
              encodedCount <= maximumFileBytes - headerBytes,
              headerBytes + encodedCount == fileData.count else {
            throw SequenceCheckpointError.invalidLength
        }

        let expectedDigest = Data(header[20..<52])
        let encodedPayload = Data(fileData[headerBytes...])
        let payloadData: Data
        switch codec {
        case rawCodec:
            guard encodedCount == uncompressedCount else {
                throw SequenceCheckpointError.invalidLength
            }
            payloadData = encodedPayload
        case lzfseCodec:
            payloadData = try decompressLZFSE(
                encodedPayload,
                exactOutputBytes: uncompressedCount
            )
        default:
            throw SequenceCheckpointError.unsupportedCodec(Int(codec))
        }

        guard Data(SHA256.hash(data: payloadData)) == expectedDigest else {
            throw SequenceCheckpointError.integrityMismatch
        }
        do {
            return try JSONDecoder().decode(SequenceCheckpointPayload.self, from: payloadData)
        } catch {
            throw SequenceCheckpointError.invalidPayload(error.localizedDescription)
        }
    }

    private static func canonicalEncoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return encoder
    }

    private static func encodeEnvelope(_ payload: Data) throws -> Data {
        guard payload.count > 0,
              payload.count <= maximumUncompressedBytes else {
            throw SequenceCheckpointError.payloadTooLarge(
                actual: payload.count,
                maximum: maximumUncompressedBytes
            )
        }

        let maximumBodyBytes = maximumFileBytes - headerBytes
        // Avoid an 8 MiB transient allocation for the common tiny/empty-state
        // checkpoint. Large payloads may still use the complete hard body cap;
        // small ones get modest incompressible-data headroom and can fall back
        // to raw bytes when LZFSE is not beneficial.
        let compressionCapacity = min(
            maximumBodyBytes,
            max(64 * 1_024, payload.count + payload.count / 8 + 64 * 1_024)
        )
        let compressed = compressLZFSE(
            payload,
            maximumOutputBytes: compressionCapacity
        )
        let codec: UInt8
        let body: Data
        if let compressed, compressed.count < payload.count {
            codec = lzfseCodec
            body = compressed
        } else if payload.count <= maximumBodyBytes {
            codec = rawCodec
            body = payload
        } else {
            throw SequenceCheckpointError.fileTooLarge(
                actual: payload.count + headerBytes,
                maximum: maximumFileBytes
            )
        }

        var output = Data()
        output.reserveCapacity(headerBytes + body.count)
        output.append(contentsOf: magic)
        appendUInt16(envelopeVersion, to: &output)
        output.append(codec)
        output.append(0)
        appendUInt32(UInt32(payload.count), to: &output)
        appendUInt32(UInt32(body.count), to: &output)
        output.append(Data(SHA256.hash(data: payload)))
        output.append(body)
        return output
    }

    private static func compressLZFSE(_ input: Data, maximumOutputBytes: Int) -> Data? {
        guard maximumOutputBytes > 0 else { return nil }
        var output = Data(count: maximumOutputBytes)
        let count = input.withUnsafeBytes { source in
            output.withUnsafeMutableBytes { destination in
                guard let sourceBase = source.bindMemory(to: UInt8.self).baseAddress,
                      let destinationBase = destination.bindMemory(to: UInt8.self).baseAddress else {
                    return 0
                }
                return compression_encode_buffer(
                    destinationBase,
                    maximumOutputBytes,
                    sourceBase,
                    input.count,
                    nil,
                    COMPRESSION_LZFSE
                )
            }
        }
        guard count > 0 else { return nil }
        output.count = count
        return output
    }

    // Internal for bounded decompressor adversarial tests. This is not API surface.
    static func decompressLZFSE(_ input: Data, exactOutputBytes: Int) throws -> Data {
        guard exactOutputBytes > 0,
              exactOutputBytes <= maximumUncompressedBytes else {
            throw SequenceCheckpointError.decompressionFailed
        }

        // Apple's Compression stream API treats the first LZFSE end marker as
        // success but may consume bytes after it. In particular, a complete
        // second LZFSE stream can be appended and `compression_stream_process`
        // still reports END, src_size == 0, and only the first stream's output.
        // Therefore src_size is not an exact-framing proof. Preflight the public,
        // stable LZFSE block container so the one end marker must be the final
        // four bytes and the block-declared raw total must match the envelope.
        // The decoder below remains authoritative for the compressed payload and
        // enforces the output bound even if hostile block metadata lies.
        try validateLZFSEStreamFraming(input, exactOutputBytes: exactOutputBytes)

        // compression_decode_buffer returning a full destination only proves
        // that a valid prefix filled that buffer. It does not prove the stream
        // ended: a tiny carrier can expand to the declared JSON prefix followed
        // by arbitrarily more bytes. Drive the streaming decoder to END in
        // modest chunks, never append beyond the declared bound, and require
        // exact output plus complete input consumption.
        let dummyPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: 1)
        defer { dummyPointer.deallocate() }
        var stream = compression_stream(
            dst_ptr: dummyPointer,
            dst_size: 0,
            src_ptr: UnsafePointer(dummyPointer),
            src_size: 0,
            state: nil
        )
        guard compression_stream_init(
            &stream,
            COMPRESSION_STREAM_DECODE,
            COMPRESSION_LZFSE
        ) != COMPRESSION_STATUS_ERROR else {
            throw SequenceCheckpointError.decompressionFailed
        }
        defer { compression_stream_destroy(&stream) }

        var output = Data()
        output.reserveCapacity(exactOutputBytes)
        var finalStatus = COMPRESSION_STATUS_OK
        var remainingInput = input.count
        var exceededDeclaredOutput = false
        var stalled = false
        let chunkBytes = 64 * 1_024
        var chunk = [UInt8](repeating: 0, count: chunkBytes)
        input.withUnsafeBytes { source in
            guard let sourceBase = source.bindMemory(to: UInt8.self).baseAddress else {
                finalStatus = COMPRESSION_STATUS_ERROR
                return
            }
            stream.src_ptr = sourceBase
            stream.src_size = input.count

            while finalStatus == COMPRESSION_STATUS_OK {
                let sourceBefore = stream.src_size
                var produced = 0
                chunk.withUnsafeMutableBytes { destination in
                    guard let destinationBase = destination.bindMemory(to: UInt8.self).baseAddress else {
                        finalStatus = COMPRESSION_STATUS_ERROR
                        return
                    }
                    stream.dst_ptr = destinationBase
                    stream.dst_size = chunkBytes
                    finalStatus = compression_stream_process(
                        &stream,
                        0
                    )
                    produced = chunkBytes - stream.dst_size
                }
                guard finalStatus != COMPRESSION_STATUS_ERROR else { break }
                guard produced <= exactOutputBytes - output.count else {
                    exceededDeclaredOutput = true
                    break
                }
                if produced > 0 {
                    output.append(contentsOf: chunk.prefix(produced))
                }
                if produced == 0, stream.src_size == sourceBefore,
                   finalStatus == COMPRESSION_STATUS_OK {
                    stalled = true
                    break
                }
            }
            remainingInput = stream.src_size
        }
        guard finalStatus == COMPRESSION_STATUS_END,
              !exceededDeclaredOutput,
              !stalled,
              remainingInput == 0,
              output.count == exactOutputBytes else {
            throw SequenceCheckpointError.decompressionFailed
        }
        return output
    }

    /// Validate only LZFSE's outer block framing. This is deliberately not a
    /// second decompressor: Apple's Compression framework still validates every
    /// entropy-coded field and produces the bytes. The walk is allocation-free,
    /// file-size bounded, and independent of compressor byte determinism, so a
    /// checkpoint remains readable across OS compressor implementation changes.
    private static func validateLZFSEStreamFraming(
        _ input: Data,
        exactOutputBytes: Int
    ) throws {
        // Little-endian ASCII block magics from Apple's published LZFSE format.
        let endOfStreamMagic: UInt32 = 0x2478_7662 // "bvx$"
        let uncompressedMagic: UInt32 = 0x2d78_7662 // "bvx-"
        let compressedV1Magic: UInt32 = 0x3178_7662 // "bvx1"
        let compressedV2Magic: UInt32 = 0x3278_7662 // "bvx2"
        let compressedLZVNMagic: UInt32 = 0x6e78_7662 // "bvxn"

        // A valid encoder uses far fewer blocks (LZFSE blocks contain up to
        // 10,000 matches). This ceiling also prevents a hostile 8 MiB stream of
        // zero-length raw blocks from turning restore into an excessive scan.
        let maximumBlocks = 4_096
        let compressedV1HeaderBytes = 772
        let compressedV2MinimumHeaderBytes = 32
        let compressedV2MaximumHeaderBytes = 752

        func invalid() throws -> Never {
            throw SequenceCheckpointError.decompressionFailed
        }

        try input.withUnsafeBytes { rawBuffer in
            guard let bytes = rawBuffer.bindMemory(to: UInt8.self).baseAddress else {
                try invalid()
            }

            func uint32LE(at offset: Int) -> UInt32 {
                UInt32(bytes[offset])
                    | (UInt32(bytes[offset + 1]) << 8)
                    | (UInt32(bytes[offset + 2]) << 16)
                    | (UInt32(bytes[offset + 3]) << 24)
            }

            func uint64LE(at offset: Int) -> UInt64 {
                UInt64(uint32LE(at: offset))
                    | (UInt64(uint32LE(at: offset + 4)) << 32)
            }

            func checkedInt(_ value: UInt32) throws -> Int {
                guard let result = Int(exactly: value) else { try invalid() }
                return result
            }

            func checkedAdd(_ lhs: Int, _ rhs: Int) throws -> Int {
                guard lhs >= 0, rhs >= 0, lhs <= Int.max - rhs else {
                    try invalid()
                }
                return lhs + rhs
            }

            var offset = 0
            var decodedBytes = 0
            var blockCount = 0
            while true {
                guard offset <= input.count - min(input.count, 4),
                      input.count - offset >= 4 else {
                    try invalid()
                }
                let magic = uint32LE(at: offset)
                if magic == endOfStreamMagic {
                    guard offset + 4 == input.count,
                          decodedBytes == exactOutputBytes else {
                        try invalid()
                    }
                    return
                }

                blockCount += 1
                guard blockCount <= maximumBlocks else { try invalid() }

                let headerBytes: Int
                let payloadBytes: Int
                let rawBytes: Int
                switch magic {
                case uncompressedMagic:
                    guard input.count - offset >= 8 else { try invalid() }
                    rawBytes = try checkedInt(uint32LE(at: offset + 4))
                    headerBytes = 8
                    payloadBytes = rawBytes

                case compressedLZVNMagic:
                    guard input.count - offset >= 12 else { try invalid() }
                    rawBytes = try checkedInt(uint32LE(at: offset + 4))
                    headerBytes = 12
                    payloadBytes = try checkedInt(uint32LE(at: offset + 8))

                case compressedV1Magic:
                    guard input.count - offset >= compressedV1HeaderBytes else {
                        try invalid()
                    }
                    rawBytes = try checkedInt(uint32LE(at: offset + 4))
                    let declaredPayload = try checkedInt(uint32LE(at: offset + 8))
                    let literalPayload = try checkedInt(uint32LE(at: offset + 20))
                    let lmdPayload = try checkedInt(uint32LE(at: offset + 24))
                    payloadBytes = try checkedAdd(literalPayload, lmdPayload)
                    guard payloadBytes == declaredPayload else { try invalid() }
                    headerBytes = compressedV1HeaderBytes

                case compressedV2Magic:
                    guard input.count - offset >= compressedV2MinimumHeaderBytes else {
                        try invalid()
                    }
                    rawBytes = try checkedInt(uint32LE(at: offset + 4))
                    let packed0 = uint64LE(at: offset + 8)
                    let packed1 = uint64LE(at: offset + 16)
                    let packed2 = uint64LE(at: offset + 24)
                    headerBytes = try checkedInt(UInt32(truncatingIfNeeded: packed2))
                    guard headerBytes >= compressedV2MinimumHeaderBytes,
                          headerBytes <= compressedV2MaximumHeaderBytes else {
                        try invalid()
                    }
                    let literalPayload = Int((packed0 >> 20) & 0x000f_ffff)
                    let lmdPayload = Int((packed1 >> 40) & 0x000f_ffff)
                    payloadBytes = try checkedAdd(literalPayload, lmdPayload)

                default:
                    try invalid()
                }

                decodedBytes = try checkedAdd(decodedBytes, rawBytes)
                guard decodedBytes <= exactOutputBytes else { try invalid() }
                let blockBytes = try checkedAdd(headerBytes, payloadBytes)
                offset = try checkedAdd(offset, blockBytes)
                guard offset <= input.count else { try invalid() }
            }
        }
    }

    private static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func checkedAdd(_ lhs: Int, _ rhs: Int, field: String) throws -> Int {
        guard rhs >= 0, lhs <= Int.max - rhs else {
            throw SequenceCheckpointError.invalidPayload("\(field) overflow")
        }
        return lhs + rhs
    }

    private static func appendUInt16(_ value: UInt16, to data: inout Data) {
        data.append(UInt8((value >> 8) & 0xff))
        data.append(UInt8(value & 0xff))
    }

    private static func appendUInt32(_ value: UInt32, to data: inout Data) {
        data.append(UInt8((value >> 24) & 0xff))
        data.append(UInt8((value >> 16) & 0xff))
        data.append(UInt8((value >> 8) & 0xff))
        data.append(UInt8(value & 0xff))
    }

    private static func readUInt16(_ bytes: [UInt8], at offset: Int) -> UInt16 {
        (UInt16(bytes[offset]) << 8) | UInt16(bytes[offset + 1])
    }

    private static func readUInt32(_ bytes: [UInt8], at offset: Int) -> UInt32 {
        (UInt32(bytes[offset]) << 24)
            | (UInt32(bytes[offset + 1]) << 16)
            | (UInt32(bytes[offset + 2]) << 8)
            | UInt32(bytes[offset + 3])
    }
}

// MARK: - Private checkpoint file carrier

enum SequenceCheckpointFileStore {
    static let temporaryNamePrefix = ".maccrab-sequence-checkpoint-"
    static let orphanMinimumAge: TimeInterval = 300

    static func cleanupOrphans(
        near url: URL,
        now: Date
    ) throws -> SecureFileIO.TemporaryCleanupReport {
        do {
            return try SecureFileIO.cleanupStaleAtomicWriteTemporaries(
                near: url.path,
                temporaryNamePrefix: temporaryNamePrefix,
                olderThan: orphanMinimumAge,
                now: now,
                maximumEntries: 4_096,
                maximumFilesToRemove: 32,
                maximumBytesToRemove: 64 * 1_024 * 1_024,
                maximumCandidateBytes: SequenceCheckpointCodec.maximumFileBytes
            )
        } catch SecureFileIO.Error.openFailed(_, let code) where code == ENOENT {
            return SecureFileIO.TemporaryCleanupReport(
                inspectedEntries: 0,
                matchingFiles: 0,
                removedFiles: 0,
                removedBytes: 0,
                remainingFiles: 0,
                remainingBytes: 0,
                scanTruncated: false
            )
        }
    }

    static func read(from url: URL) throws -> Data? {
        guard let path = BoundedRegularFileReader.normalizedAbsolutePath(url.path) else {
            throw SequenceCheckpointError.invalidPath
        }
        let components = path.dropFirst().split(separator: "/").map(String.init)
        guard let leaf = components.last, !leaf.isEmpty else {
            throw SequenceCheckpointError.invalidPath
        }

        var parent = Darwin.open(
            "/",
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        guard parent >= 0 else {
            throw SequenceCheckpointError.ioFailure("open root: errno \(errno)")
        }
        defer { Darwin.close(parent) }

        for component in components.dropLast() {
            let next = component.withCString {
                Darwin.openat(parent, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            }
            guard next >= 0 else {
                if errno == ENOENT { return nil }
                if errno == ELOOP || errno == ENOTDIR {
                    throw SequenceCheckpointError.unsafeCarrier
                }
                throw SequenceCheckpointError.ioFailure(
                    "open parent component: errno \(errno)"
                )
            }
            Darwin.close(parent)
            parent = next
        }

        let descriptor = leaf.withCString {
            Darwin.openat(
                parent,
                $0,
                O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
            )
        }
        guard descriptor >= 0 else {
            if errno == ENOENT { return nil }
            if errno == ELOOP || errno == ENOTDIR {
                throw SequenceCheckpointError.unsafeCarrier
            }
            throw SequenceCheckpointError.ioFailure("open checkpoint: errno \(errno)")
        }
        defer { Darwin.close(descriptor) }

        var before = stat()
        guard Darwin.fstat(descriptor, &before) == 0 else {
            throw SequenceCheckpointError.ioFailure("fstat checkpoint: errno \(errno)")
        }
        guard (before.st_mode & S_IFMT) == S_IFREG,
              before.st_nlink == 1,
              before.st_size >= 0 else {
            throw SequenceCheckpointError.unsafeCarrier
        }
        let expectedUID = geteuid()
        guard before.st_uid == expectedUID else {
            throw SequenceCheckpointError.foreignOwner(
                expected: expectedUID,
                actual: before.st_uid
            )
        }
        let permissions = UInt16(before.st_mode & 0o777)
        guard permissions & 0o077 == 0 else {
            throw SequenceCheckpointError.insecurePermissions(permissions)
        }
        guard before.st_size <= off_t(SequenceCheckpointCodec.maximumFileBytes) else {
            throw SequenceCheckpointError.fileTooLarge(
                actual: before.st_size > off_t(Int.max) ? Int.max : Int(before.st_size),
                maximum: SequenceCheckpointCodec.maximumFileBytes
            )
        }

        let expectedCount = Int(before.st_size)
        var data = Data(count: expectedCount)
        let actualCount = data.withUnsafeMutableBytes { buffer -> Int in
            guard expectedCount > 0, let base = buffer.baseAddress else { return 0 }
            var offset = 0
            while offset < expectedCount {
                let count = Darwin.read(
                    descriptor,
                    base.advanced(by: offset),
                    expectedCount - offset
                )
                if count < 0 {
                    if errno == EINTR { continue }
                    return -1
                }
                if count == 0 { break }
                offset += count
            }
            return offset
        }
        guard actualCount == expectedCount else {
            throw actualCount >= 0
                ? SequenceCheckpointError.truncated
                : SequenceCheckpointError.ioFailure("read checkpoint: errno \(errno)")
        }

        var after = stat()
        guard Darwin.fstat(descriptor, &after) == 0,
              before.st_dev == after.st_dev,
              before.st_ino == after.st_ino,
              before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
              before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec,
              before.st_mode == after.st_mode,
              before.st_uid == after.st_uid else {
            throw SequenceCheckpointError.ioFailure("checkpoint changed during read")
        }
        return data
    }

    static func write(_ data: Data, to url: URL) throws {
        guard data.count <= SequenceCheckpointCodec.maximumFileBytes else {
            throw SequenceCheckpointError.fileTooLarge(
                actual: data.count,
                maximum: SequenceCheckpointCodec.maximumFileBytes
            )
        }
        do {
            // SecureFileIO pins every parent component with O_NOFOLLOW, creates
            // a private same-directory O_EXCL temporary, fchmods 0600, fsyncs,
            // and atomically renames it over only a same-owner single-link file.
            try SecureFileIO.atomicReplace(
                at: url.path,
                data: data,
                mode: 0o600,
                temporaryNamePrefix: temporaryNamePrefix
            )
        } catch {
            throw SequenceCheckpointError.ioFailure(error.localizedDescription)
        }
    }
}

// MARK: - Rule-bound restore validation

enum SequenceCheckpointValidator {
    static func validate(
        _ payload: SequenceCheckpointPayload,
        rules: [String: SequenceRule],
        maximumPartialMatches: Int,
        maximumPendingPerRule: Int,
        now: Date
    ) throws -> ValidatedSequenceCheckpoint {
        guard payload.schemaVersion == SequenceCheckpointPayload.currentSchemaVersion else {
            throw SequenceCheckpointError.unsupportedSchemaVersion(payload.schemaVersion)
        }
        guard rules.count <= SequenceCheckpointLimits.maximumRules else {
            throw SequenceCheckpointError.invalidPayload("too many active rules")
        }
        guard payload.partialBuckets.count <= rules.count,
              payload.pendingBuckets.count <= rules.count else {
            throw SequenceCheckpointError.invalidPayload(
                "checkpoint has more rule buckets than active rules"
            )
        }
        if rules.isEmpty {
            guard payload.partialBuckets.isEmpty,
                  payload.pendingBuckets.isEmpty,
                  payload.evictionOrder.isEmpty,
                  payload.pendingEvictionOrder.isEmpty else {
                throw SequenceCheckpointError.invalidPayload(
                    "empty active rule corpus cannot restore sequence state"
                )
            }
        }
        let semanticWeight = SequenceCheckpointCodec.estimatedSemanticStateWeight(
            partialBuckets: payload.partialBuckets,
            pendingBuckets: payload.pendingBuckets
        )
        guard semanticWeight <= SequenceCheckpointCodec.maximumSemanticStateWeight else {
            throw SequenceCheckpointError.invalidPayload(
                "checkpoint semantic state weight exceeds the runtime cap"
            )
        }
        try validateDate(payload.capturedAt, field: "capturedAt", now: now)
        guard payload.ruleFingerprint.utf8.count == 64,
              payload.ruleFingerprint.allSatisfy({ $0.isHexDigit }) else {
            throw SequenceCheckpointError.invalidPayload("rule fingerprint is not SHA-256 hex")
        }

        let expectedFingerprint = try SequenceCheckpointCodec.ruleFingerprint(Array(rules.values))
        guard payload.ruleFingerprint == expectedFingerprint else {
            throw SequenceCheckpointError.ruleFingerprintMismatch(
                expected: expectedFingerprint,
                actual: payload.ruleFingerprint
            )
        }

        var seenPartialBuckets = Set<String>()
        var seenPartialIDs = Set<UUID>()
        var allPartialIDs = Set<UUID>()
        var survivingPartialIDs = Set<UUID>()
        var filteredPartialBuckets: [SequenceCheckpointPartialBucket] = []
        var totalPartialCount = 0
        var expiredPartialCount = 0

        for bucket in payload.partialBuckets {
            try validateIdentifier(bucket.ruleID, field: "partial rule id")
            guard seenPartialBuckets.insert(bucket.ruleID).inserted,
                  !bucket.partials.isEmpty else {
                throw SequenceCheckpointError.invalidPayload(
                    "duplicate or empty partial bucket for \(bucket.ruleID)"
                )
            }
            guard let rule = rules[bucket.ruleID], rule.enabled else {
                throw SequenceCheckpointError.invalidPayload(
                    "partial bucket references missing or disabled rule \(bucket.ruleID)"
                )
            }
            guard rule.window.isFinite, rule.window > 0 else {
                throw SequenceCheckpointError.invalidPayload(
                    "rule \(rule.id) has a non-finite or non-positive window"
                )
            }

            totalPartialCount = try checkedAdd(
                totalPartialCount,
                bucket.partials.count,
                field: "partial count"
            )
            guard totalPartialCount <= maximumPartialMatches else {
                throw SequenceCheckpointError.invalidPayload(
                    "global partial count \(totalPartialCount) exceeds cap \(maximumPartialMatches)"
                )
            }

            let ruleSteps = Dictionary(uniqueKeysWithValues: rule.steps.map { ($0.id, $0) })
            var survivors: [SequenceCheckpointPartial] = []
            survivors.reserveCapacity(bucket.partials.count)
            for partial in bucket.partials {
                guard partial.ruleID == bucket.ruleID else {
                    throw SequenceCheckpointError.invalidPayload("partial rule/bucket mismatch")
                }
                guard seenPartialIDs.insert(partial.id).inserted else {
                    throw SequenceCheckpointError.invalidPayload("duplicate partial identity \(partial.id)")
                }
                allPartialIDs.insert(partial.id)
                try validateDate(partial.createdAt, field: "partial.createdAt", now: now)
                try validateOptionalValue(partial.correlationKey, field: "correlationKey")
                guard !partial.matchedSteps.isEmpty,
                      partial.matchedSteps.count <= rule.steps.count else {
                    throw SequenceCheckpointError.invalidPayload(
                        "partial \(partial.id) has an invalid matched-step count"
                    )
                }

                var matchedStepIDs = Set<String>()
                var matchedEventIDs = Set<UUID>()
                var matchedByStepID: [String: SequenceCheckpointMatchedStep] = [:]
                for matched in partial.matchedSteps {
                    try validateMatchedStep(matched, now: now)
                    guard ruleSteps[matched.stepID] != nil else {
                        throw SequenceCheckpointError.invalidPayload(
                            "partial \(partial.id) references unknown step \(matched.stepID)"
                        )
                    }
                    guard matchedStepIDs.insert(matched.stepID).inserted else {
                        throw SequenceCheckpointError.invalidPayload(
                            "partial \(partial.id) repeats step \(matched.stepID)"
                        )
                    }
                    guard matchedEventIDs.insert(matched.eventID).inserted else {
                        throw SequenceCheckpointError.invalidPayload(
                            "partial \(partial.id) reuses event \(matched.eventID) across steps"
                        )
                    }
                    matchedByStepID[matched.stepID] = matched
                }
                try validatePartialSemantics(
                    partial,
                    rule: rule,
                    matchedByStepID: matchedByStepID
                )
                guard !triggerSatisfied(
                    rule.trigger,
                    matchedStepIDs: matchedStepIDs,
                    totalSteps: rule.steps.count
                ) else {
                    throw SequenceCheckpointError.invalidPayload(
                        "partial \(partial.id) is already complete"
                    )
                }

                if now.timeIntervalSince(partial.createdAt) > rule.window {
                    expiredPartialCount += 1
                } else {
                    survivors.append(partial)
                    survivingPartialIDs.insert(partial.id)
                }
            }
            if !survivors.isEmpty {
                filteredPartialBuckets.append(
                    SequenceCheckpointPartialBucket(ruleID: bucket.ruleID, partials: survivors)
                )
            }
        }

        guard payload.evictionOrder.count <= maximumPartialMatches else {
            throw SequenceCheckpointError.invalidPayload(
                "eviction order exceeds the global partial cap"
            )
        }
        let evictionIDs = Set(payload.evictionOrder)
        guard evictionIDs.count == payload.evictionOrder.count else {
            throw SequenceCheckpointError.invalidPayload("eviction order contains duplicate identities")
        }
        guard evictionIDs == allPartialIDs else {
            throw SequenceCheckpointError.invalidPayload(
                "eviction order does not exactly cover persisted partial identities"
            )
        }
        let filteredEvictionOrder = payload.evictionOrder.filter(survivingPartialIDs.contains)

        var seenPendingBuckets = Set<String>()
        guard payload.pendingEvictionOrder.count
                <= SequenceCheckpointLimits.maximumTotalPendingSteps else {
            throw SequenceCheckpointError.invalidPayload(
                "pending eviction order exceeds the global pending cap"
            )
        }
        var seenPendingIdentities = Set<SequenceCheckpointPendingIdentity>()
        var survivingPendingIdentities = Set<SequenceCheckpointPendingIdentity>()
        var filteredPendingBuckets: [SequenceCheckpointPendingBucket] = []
        var totalPendingCount = 0
        var expiredPendingCount = 0

        for bucket in payload.pendingBuckets {
            try validateIdentifier(bucket.ruleID, field: "pending rule id")
            guard seenPendingBuckets.insert(bucket.ruleID).inserted,
                  !bucket.steps.isEmpty else {
                throw SequenceCheckpointError.invalidPayload(
                    "duplicate or empty pending bucket for \(bucket.ruleID)"
                )
            }
            guard let rule = rules[bucket.ruleID], rule.enabled, rule.ordered else {
                throw SequenceCheckpointError.invalidPayload(
                    "pending bucket references missing, disabled, or unordered rule \(bucket.ruleID)"
                )
            }
            guard bucket.steps.count <= maximumPendingPerRule else {
                throw SequenceCheckpointError.invalidPayload(
                    "pending count for \(bucket.ruleID) exceeds cap \(maximumPendingPerRule)"
                )
            }
            totalPendingCount = try checkedAdd(
                totalPendingCount,
                bucket.steps.count,
                field: "pending count"
            )
            guard totalPendingCount <= SequenceCheckpointLimits.maximumTotalPendingSteps else {
                throw SequenceCheckpointError.invalidPayload("global pending-step count exceeds cap")
            }

            let ruleSteps = Dictionary(uniqueKeysWithValues: rule.steps.map { ($0.id, $0) })
            var survivors: [SequenceCheckpointPendingStep] = []
            survivors.reserveCapacity(bucket.steps.count)
            for pending in bucket.steps {
                guard pending.ruleID == bucket.ruleID,
                      pending.stepID == pending.matched.stepID,
                      let step = ruleSteps[pending.stepID],
                      step.id != rule.steps.first?.id else {
                    throw SequenceCheckpointError.invalidPayload(
                        "pending step has invalid rule/step membership"
                    )
                }
                try validateDate(pending.arrivedAt, field: "pending.arrivedAt", now: now)
                try validateMatchedStep(pending.matched, now: now)
                let identity = SequenceCheckpointPendingIdentity(
                    ruleID: bucket.ruleID,
                    stepID: pending.stepID,
                    eventID: pending.matched.eventID
                )
                guard seenPendingIdentities.insert(identity).inserted else {
                    throw SequenceCheckpointError.invalidPayload("duplicate pending-step identity")
                }
                if now.timeIntervalSince(pending.arrivedAt) > rule.window {
                    expiredPendingCount += 1
                } else {
                    survivors.append(pending)
                    survivingPendingIdentities.insert(identity)
                }
            }
            if !survivors.isEmpty {
                filteredPendingBuckets.append(
                    SequenceCheckpointPendingBucket(ruleID: bucket.ruleID, steps: survivors)
                )
            }
        }

        let pendingEvictionIdentities = Set(payload.pendingEvictionOrder)
        guard pendingEvictionIdentities.count == payload.pendingEvictionOrder.count else {
            throw SequenceCheckpointError.invalidPayload(
                "pending eviction order contains duplicate identities"
            )
        }
        guard pendingEvictionIdentities == seenPendingIdentities else {
            throw SequenceCheckpointError.invalidPayload(
                "pending eviction order does not exactly cover persisted pending identities"
            )
        }
        let filteredPendingEvictionOrder = payload.pendingEvictionOrder.filter(
            survivingPendingIdentities.contains
        )

        return ValidatedSequenceCheckpoint(
            payload: payload,
            partialBuckets: filteredPartialBuckets,
            pendingBuckets: filteredPendingBuckets,
            evictionOrder: filteredEvictionOrder,
            pendingEvictionOrder: filteredPendingEvictionOrder,
            expiredPartialCount: expiredPartialCount,
            expiredPendingCount: expiredPendingCount
        )
    }

    private static func validateMatchedStep(
        _ matched: SequenceCheckpointMatchedStep,
        now: Date
    ) throws {
        try validateIdentifier(matched.stepID, field: "matched step id")
        try validateDate(matched.timestamp, field: "matched timestamp", now: now)
        guard matched.processPID >= 0, matched.processParentPID >= 0 else {
            throw SequenceCheckpointError.invalidPayload("matched process PID is negative")
        }
        guard !matched.processParentWasTracked || matched.processParentPID > 0 else {
            throw SequenceCheckpointError.invalidPayload(
                "matched step claims a tracked parent without a positive parent PID"
            )
        }
        guard matched.processAncestorPIDs.count
                <= SequenceCheckpointLimits.maximumProcessAncestors,
              Set(matched.processAncestorPIDs).count == matched.processAncestorPIDs.count,
              matched.processAncestorPIDs.allSatisfy({ $0 >= 0 && $0 != matched.processPID }),
              matched.processParentPID != matched.processPID || matched.processPID == 0 else {
            throw SequenceCheckpointError.invalidPayload(
                "matched process ancestry is oversized, cyclic, or duplicated"
            )
        }
        try validateOptionalValue(matched.filePath, field: "filePath")
        try validateOptionalValue(matched.networkDestination, field: "networkDestination")
    }

    /// Validate invariants that runtime construction guarantees but ordinary
    /// Codable decoding cannot express. Without these checks, an
    /// integrity-consistent
    /// carrier could install a nil/wrong correlation key and turn file/PID
    /// correlation into allow-all, or install an impossible ordered prefix.
    private static func validatePartialSemantics(
        _ partial: SequenceCheckpointPartial,
        rule: SequenceRule,
        matchedByStepID: [String: SequenceCheckpointMatchedStep]
    ) throws {
        let matchedIDs = Set(matchedByStepID.keys)
        let initialCandidates: [SequenceCheckpointMatchedStep]

        if rule.ordered {
            guard let first = rule.steps.first,
                  matchedByStepID[first.id] != nil else {
                throw SequenceCheckpointError.invalidPayload(
                    "ordered partial \(partial.id) does not contain its first step"
                )
            }
            var encounteredGap = false
            var previousTimestamp: Date?
            for step in rule.steps {
                guard let matched = matchedByStepID[step.id] else {
                    encounteredGap = true
                    continue
                }
                guard !encounteredGap else {
                    throw SequenceCheckpointError.invalidPayload(
                        "ordered partial \(partial.id) is not a contiguous rule prefix"
                    )
                }
                if let previousTimestamp, matched.timestamp < previousTimestamp {
                    throw SequenceCheckpointError.invalidPayload(
                        "ordered partial \(partial.id) has decreasing event timestamps"
                    )
                }
                previousTimestamp = matched.timestamp
            }
            initialCandidates = [matchedByStepID[first.id]!]
        } else {
            initialCandidates = rule.steps.compactMap { step in
                guard step.afterStep == nil,
                      step.processRelation == nil else { return nil }
                return matchedByStepID[step.id]
            }
            guard !initialCandidates.isEmpty else {
                throw SequenceCheckpointError.invalidPayload(
                    "unordered partial \(partial.id) has no structurally valid seed step"
                )
            }
        }

        let ruleSteps = Dictionary(uniqueKeysWithValues: rule.steps.map { ($0.id, $0) })
        for (stepID, matched) in matchedByStepID {
            guard let definition = ruleSteps[stepID] else { continue }
            if let dependency = definition.afterStep {
                guard let reference = matchedByStepID[dependency],
                      matched.timestamp >= reference.timestamp else {
                    throw SequenceCheckpointError.invalidPayload(
                        "partial \(partial.id) violates after-step dependency for \(stepID)"
                    )
                }
            }
            if let relation = definition.processRelation {
                guard matchedIDs.contains(relation.relativeToStep),
                      let reference = matchedByStepID[relation.relativeToStep],
                      persistedRelationHolds(
                          relation.relation,
                          event: matched,
                          reference: reference
                      ) else {
                    throw SequenceCheckpointError.invalidPayload(
                        "partial \(partial.id) violates process relation for \(stepID)"
                    )
                }
            }
        }

        switch rule.correlationType {
        case .processSame:
            guard let key = partial.correlationKey,
                  initialCandidates.contains(where: { String($0.processPID) == key }),
                  matchedByStepID.values.allSatisfy({ String($0.processPID) == key }) else {
                throw SequenceCheckpointError.invalidPayload(
                    "partial \(partial.id) has an invalid process-same correlation key"
                )
            }
        case .processLineage:
            guard let key = partial.correlationKey,
                  initialCandidates.contains(where: { String($0.processPID) == key }),
                  persistedLineageHasValidAdmissionOrder(
                      rule: rule,
                      matchedByStepID: matchedByStepID,
                      seedKey: key
                  ) else {
                throw SequenceCheckpointError.invalidPayload(
                    "partial \(partial.id) has an invalid or disconnected process-lineage key"
                )
            }
        case .filePath:
            guard let key = partial.correlationKey, !key.isEmpty,
                  initialCandidates.contains(where: { $0.filePath == key }),
                  matchedByStepID.values.allSatisfy({ $0.filePath == key }) else {
                throw SequenceCheckpointError.invalidPayload(
                    "partial \(partial.id) has an invalid file-path correlation key"
                )
            }
        case .networkEndpoint:
            guard let key = partial.correlationKey, !key.isEmpty,
                  initialCandidates.contains(where: { $0.networkDestination == key }),
                  matchedByStepID.values.allSatisfy({ $0.networkDestination == key }) else {
                throw SequenceCheckpointError.invalidPayload(
                    "partial \(partial.id) has an invalid network correlation key"
                )
            }
        case .none:
            let prefix = "\(rule.id):"
            guard let key = partial.correlationKey,
                  key.hasPrefix(prefix),
                  UUID(uuidString: String(key.dropFirst(prefix.count))) != nil else {
                throw SequenceCheckpointError.invalidPayload(
                    "partial \(partial.id) has an invalid independent correlation key"
                )
            }
        }
    }

    private static func persistedLineageHasValidAdmissionOrder(
        rule: SequenceRule,
        matchedByStepID: [String: SequenceCheckpointMatchedStep],
        seedKey: String
    ) -> Bool {
        let seedIDs = rule.steps.compactMap { step -> String? in
            guard step.afterStep == nil,
                  step.processRelation == nil,
                  let matched = matchedByStepID[step.id],
                  String(matched.processPID) == seedKey else { return nil }
            return step.id
        }
        guard let seedID = seedIDs.first else { return false }
        var admitted: Set<String> = [seedID]
        var changed = true
        while changed {
            changed = false
            for step in rule.steps where !admitted.contains(step.id) {
                guard let candidate = matchedByStepID[step.id] else { continue }
                let canAdmit: Bool
                if let relation = step.processRelation,
                   admitted.contains(relation.relativeToStep),
                   let reference = matchedByStepID[relation.relativeToStep] {
                    // Explicit relations intentionally replace the broad
                    // processLineage gate; `.any` may form another component.
                    canAdmit = persistedRelationHolds(
                        relation.relation,
                        event: candidate,
                        reference: reference
                    )
                } else if step.processRelation != nil {
                    canAdmit = false
                } else {
                    canAdmit = admitted.contains { admittedID in
                        guard let reference = matchedByStepID[admittedID] else { return false }
                        return persistedRelationHolds(
                            .sameTree,
                            event: candidate,
                            reference: reference
                        )
                    }
                }
                if canAdmit {
                    admitted.insert(step.id)
                    changed = true
                }
            }
        }
        return admitted.count == matchedByStepID.count
    }

    private static func persistedRelationHolds(
        _ relation: ProcessRelation,
        event: SequenceCheckpointMatchedStep,
        reference: SequenceCheckpointMatchedStep
    ) -> Bool {
        switch relation {
        case .same, .sameProcess:
            return event.processPID == reference.processPID
        case .descendant:
            return persistedHasAncestor(event, reference.processPID)
        case .ancestor:
            return persistedHasAncestor(reference, event.processPID)
        case .sibling:
            return event.processParentWasTracked
                && reference.processParentWasTracked
                && event.processParentPID > 0
                && event.processParentPID == reference.processParentPID
        case .sameTree:
            return event.processPID == reference.processPID
                || persistedHasAncestor(event, reference.processPID)
                || persistedHasAncestor(reference, event.processPID)
        case .any:
            return true
        }
    }

    private static func persistedHasAncestor(
        _ matched: SequenceCheckpointMatchedStep,
        _ candidatePID: Int32
    ) -> Bool {
        matched.processParentPID == candidatePID
            || matched.processAncestorPIDs.contains(candidatePID)
    }

    private static func validateDate(_ date: Date, field: String, now: Date) throws {
        let value = date.timeIntervalSinceReferenceDate
        guard value.isFinite else {
            throw SequenceCheckpointError.invalidPayload("\(field) is not finite")
        }
        guard date.timeIntervalSince(now) <= SequenceCheckpointLimits.futureTimestampTolerance else {
            throw SequenceCheckpointError.invalidPayload("\(field) is too far in the future")
        }
    }

    private static func validateIdentifier(_ value: String, field: String) throws {
        guard !value.isEmpty,
              value.utf8.count <= SequenceCheckpointLimits.maximumIdentifierBytes else {
            throw SequenceCheckpointError.invalidPayload("\(field) is empty or oversized")
        }
    }

    private static func validateValue(_ value: String, field: String) throws {
        guard value.utf8.count <= SequenceCheckpointLimits.maximumValueBytes else {
            throw SequenceCheckpointError.invalidPayload("\(field) is oversized")
        }
    }

    private static func validateOptionalValue(_ value: String?, field: String) throws {
        if let value { try validateValue(value, field: field) }
    }

    private static func checkedAdd(_ lhs: Int, _ rhs: Int, field: String) throws -> Int {
        guard rhs >= 0, lhs <= Int.max - rhs else {
            throw SequenceCheckpointError.invalidPayload("\(field) overflow")
        }
        return lhs + rhs
    }

    private static func triggerSatisfied(
        _ trigger: TriggerCondition,
        matchedStepIDs: Set<String>,
        totalSteps: Int
    ) -> Bool {
        switch trigger {
        case .allSteps:
            return matchedStepIDs.count == totalSteps
        case .steps(let required):
            return required.allSatisfy(matchedStepIDs.contains)
        case .anySteps(let count):
            return matchedStepIDs.count >= count
        }
    }
}
