import Foundation
import Testing
@testable import MacCrabCore

@Suite("Conservative checkpoint string-size accounting")
struct SequenceCheckpointWeightTests {
    @Test("ASCII, JSON escapes and representative Unicode retain encoded-size upper bounds")
    func canonicalPayloadBound() throws {
        let printableASCII = String((32...126).compactMap(UnicodeScalar.init).map(Character.init))
        let controls = String((0...31).compactMap(UnicodeScalar.init).map(Character.init)) + "\u{007F}"
        let strings = ["", "ordinary-file_name.123", "/Users/fixture/Documents/report.txt",
            printableASCII, controls, "quotes \" and slash / and backslash \\",
            "é e\u{0301} Ελληνικά 漢字 한글", "😀 🧑🏽‍💻 𝄞",
            "\u{0085}\u{00A0}\u{200B}\u{2028}\u{2029}\u{2066}\u{2069}\u{FEFF}"]
        for text in strings {
            for ancestorCount in [0, 64] {
                for matchedStepCount in [1, 4] {
                    try assertPayloadBound(text: text, ancestorCount: ancestorCount,
                                           matchedStepCount: matchedStepCount)
                }
            }
        }
    }

    private func assertPayloadBound(text: String, ancestorCount: Int, matchedStepCount: Int) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let ruleID = "ordinary-" + text
        let base = Date(timeIntervalSince1970: 1_700_000_000)
        let partials = (0..<32).map { index in
            SequenceCheckpointPartial(id: UUID(), ruleID: ruleID, createdAt: base,
                matchedSteps: (0..<matchedStepCount).map { stepIndex in
                    SequenceCheckpointMatchedStep(
                        stepID: "created-\(stepIndex)-" + text, eventID: UUID(), timestamp: base,
                        processPID: Int32.max, processParentPID: Int32.max - 1,
                        processParentWasTracked: true,
                        processAncestorPIDs: (0..<ancestorCount).map { Int32.max - Int32($0) - 2 },
                        filePath: text, networkDestination: text)
                }, correlationKey: text + String(index))
        }
        let pending = partials.map {
            SequenceCheckpointPendingStep(ruleID: ruleID, stepID: "written-" + text,
                matched: $0.matchedSteps[0], arrivedAt: base)
        }
        let partialBuckets = [SequenceCheckpointPartialBucket(ruleID: ruleID, partials: partials)]
        let pendingBuckets = [SequenceCheckpointPendingBucket(ruleID: ruleID, steps: pending)]
        let payload = SequenceCheckpointPayload(schemaVersion: 1, capturedAt: base,
            ruleFingerprint: String(repeating: "a", count: 64), sourceGeneration: UInt64.max,
            partialBuckets: partialBuckets, pendingBuckets: pendingBuckets,
            evictionOrder: partials.map(\.id), pendingEvictionOrder: pending.map {
                SequenceCheckpointPendingIdentity(ruleID: $0.ruleID, stepID: $0.stepID, eventID: $0.matched.eventID)
            })
        let estimate = SequenceCheckpointCodec.estimatedSemanticStateWeight(
            partialBuckets: partialBuckets, pendingBuckets: pendingBuckets)
        #expect(try encoder.encode(payload).count <= estimate,
                "The bound must cover duplicated identifiers, order arrays, numeric and record overhead")
    }

    @Test("Ordinary ASCII avoids sixfold charging while controls and Unicode keep conservative allowance")
    func byteClassWeights() {
        let overhead = SequenceCheckpointCodec.estimatedBucketOverhead(ruleID: "")
        #expect(SequenceCheckpointCodec.estimatedBucketOverhead(ruleID: "ordinary-name") - overhead == 13)
        #expect(SequenceCheckpointCodec.estimatedBucketOverhead(ruleID: "\"/\\") - overhead == 6)
        #expect(SequenceCheckpointCodec.estimatedBucketOverhead(ruleID: "\u{0001}\u{007F}") - overhead == 12)
        let unicode = "é漢😀\u{2028}"
        #expect(SequenceCheckpointCodec.estimatedBucketOverhead(ruleID: unicode) - overhead == unicode.utf8.count * 6)
        #expect(SequenceCheckpointCodec.maximumSemanticStateWeight == 7_864_320)
        #expect(SequenceCheckpointCodec.maximumFileBytes == 8_388_608)
        #expect(SequenceCheckpointPayload.currentSchemaVersion == 1)
    }
}
