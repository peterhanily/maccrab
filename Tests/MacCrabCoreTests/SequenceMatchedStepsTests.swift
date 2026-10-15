import Foundation
import Testing
@testable import MacCrabCore

/// Pure value storage only: every retained field is compared, including fields
/// not consumed by a particular rule. No live collectors, databases or timings.
@Suite("Inline sequence bindings preserve exact value semantics")
struct SequenceMatchedStepsTests {
    private typealias Binding = SequenceEngine.MatchedStep
    private typealias Bindings = SequenceMatchedSteps<Binding>

    private func binding(_ key: String, salt: UInt8 = 1) -> Binding {
        Binding(stepId: key,
            eventId: UUID(uuid: (0, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, salt)),
            timestamp: Date(timeIntervalSince1970: 1_700_000_000 + Double(salt)),
            processPid: Int32(salt) + 100, processParentPid: Int32(salt) + 10,
            processParentWasTracked: salt.isMultiple(of: 2),
            processAncestorPids: [Int32(salt) + 9, Int32(salt) + 8],
            filePath: "/private/tmp/ordinary-\(salt)-漢字.txt",
            networkDest: "192.0.2.\(salt):443")
    }

    private func expectMatches(_ actual: Bindings, _ expected: [String: Binding]) {
        #expect(actual.count == expected.count)
        #expect(actual.isEmpty == expected.isEmpty)
        #expect(actual.isInlineSingle == (expected.count == 1))
        #expect(actual.isDictionaryBacked == (expected.count > 1))
        #expect(Set(actual.keys) == Set(expected.keys))
        #expect(Dictionary(uniqueKeysWithValues: actual.map { ($0.key, $0.value) }) == expected)
        #expect(Dictionary(uniqueKeysWithValues: actual.values.map { ($0.stepId, $0) }) == expected)
        for (key, value) in expected { #expect(actual[key] == value) }
        #expect(actual["missing"] == nil)
    }

    @Test("Empty, inline, overflow and demotion retain all binding fields")
    func transitions() {
        var actual: Bindings = [:]
        expectMatches(actual, [:])
        actual["first"] = binding("first")
        expectMatches(actual, ["first": binding("first")])
        actual["first"] = binding("first", salt: 2)
        expectMatches(actual, ["first": binding("first", salt: 2)])
        actual["second"] = binding("second", salt: 3)
        expectMatches(actual, ["first": binding("first", salt: 2), "second": binding("second", salt: 3)])
        actual["missing"] = nil
        actual["first"] = nil
        expectMatches(actual, ["second": binding("second", salt: 3)])
        actual["second"] = nil
        expectMatches(actual, [:])
    }

    @Test("Copy, advance and overflow never mutate another partial's bindings")
    func valueIsolation() {
        let first = binding("first")
        let original: Bindings = ["first": first]
        var advanced = original
        advanced["first"] = binding("first", salt: 2)
        advanced["second"] = binding("second", salt: 3)
        expectMatches(original, ["first": first])
        let saved = advanced
        advanced["second"] = binding("second", salt: 4)
        advanced["third"] = binding("third", salt: 5)
        advanced["first"] = nil
        expectMatches(saved, ["first": binding("first", salt: 2), "second": binding("second", salt: 3)])
        expectMatches(advanced, ["second": binding("second", salt: 4), "third": binding("third", salt: 5)])
        #expect(saved != advanced)
    }

    @Test("Single and overflow iterators are stable value snapshots")
    func iteratorIsolation() {
        var values: Bindings = ["first": binding("first")]
        var singleIterator = values.makeIterator()
        values["first"] = binding("first", salt: 2)
        #expect(singleIterator.next()?.value == binding("first"))
        #expect(singleIterator.next() == nil)
        values["second"] = binding("second", salt: 3)
        let snapshot = Dictionary(uniqueKeysWithValues: values.map { ($0.key, $0.value) })
        var iterator = values.makeIterator()
        var iteratorCopy = iterator
        values["third"] = binding("third", salt: 4)
        values["first"] = nil
        var read: [(String, Binding)] = []
        var copiedRead: [(String, Binding)] = []
        while let entry = iterator.next() { read.append(entry) }
        while let entry = iteratorCopy.next() { copiedRead.append(entry) }
        #expect(Dictionary(uniqueKeysWithValues: read) == snapshot)
        #expect(read.map { $0.0 } == copiedRead.map { $0.0 })
        #expect(read.map { $0.1 } == copiedRead.map { $0.1 })
        #expect(iterator.next() == nil && iteratorCopy.next() == nil)
    }

    @Test("Restored and incrementally mutated storage agree with Dictionary")
    func dictionaryEquivalence() {
        var actual = Bindings()
        var expected: [String: Binding] = [:]
        for index in 0..<64 {
            let key = "step-\(index % 7)"
            let value = binding(key, salt: UInt8(index))
            actual[key] = value
            expected[key] = value
            if index.isMultiple(of: 3) {
                let removed = "step-\((index + 2) % 7)"
                actual[removed] = nil
                expected[removed] = nil
            }
            expectMatches(actual, expected)
            let restored = Bindings(uniqueKeysWithValues: expected.map { ($0.key, $0.value) })
            #expect(restored == actual)
            expectMatches(restored, expected)
        }
    }

    @Test("The single case embeds the complete binding and owns no Dictionary")
    func structuralRepresentation() {
        let single: Bindings = ["first": binding("first")]
        #expect(single.isInlineSingle && !single.isDictionaryBacked)
        #expect(MemoryLayout<Bindings>.stride >= MemoryLayout<Binding>.stride)
        print("sequence_binding_layout binding_stride=\(MemoryLayout<Binding>.stride) "
            + "inline_container_stride=\(MemoryLayout<Bindings>.stride) "
            + "dictionary_handle_stride=\(MemoryLayout<[String: Binding]>.stride) "
            + "heap_or_footprint_measurement=false")
    }
}
