// Shared hostile-rule boundary tests for CompiledRule and SequenceRule.
// Condition trees are executable logic; malformed trees must be rejected by
// both engines, and one attacker-controlled JSON file must not allocate without
// a no-follow byte ceiling before semantic validation begins.

import Foundation
import Testing
@testable import MacCrabCore

@Suite("Shared condition-tree trust boundary")
struct RuleConditionTreeBoundaryTests {
    private func scratch(_ label: String) throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(
            "maccrab-condition-boundary-\(label)-\(UUID().uuidString)",
            isDirectory: true
        )
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
        return url
    }

    private func predicate() -> MacCrabCore.Predicate {
        MacCrabCore.Predicate(
            field: "process.executable",
            modifier: .endswith,
            values: ["/true"],
            negate: false
        )
    }

    private func compiledRule(id: String = "single-tree-boundary") -> CompiledRule {
        CompiledRule(
            id: id,
            title: id,
            description: "boundary test",
            level: .high,
            tags: ["attack.execution"],
            logsource: LogSource(category: "process_creation", product: "macos"),
            predicates: [predicate()],
            condition: .allOf,
            conditionTree: .predicate(0),
            falsepositives: [],
            enabled: true
        )
    }

    private func sequenceRule(id: String = "sequence-tree-boundary") -> SequenceRule {
        SequenceRule(
            id: id,
            title: id,
            description: "boundary test",
            level: .high,
            tags: ["attack.execution"],
            window: 60,
            correlationType: .none,
            ordered: true,
            steps: [
                SequenceStep(
                    id: "only",
                    logsourceCategory: "process_creation",
                    predicates: [predicate()],
                    condition: .allOf,
                    conditionTree: .predicate(0)
                ),
            ],
            trigger: .allSteps
        )
    }

    private func object<T: Encodable>(_ value: T) throws -> [String: Any] {
        let data = try JSONEncoder().encode(value)
        return try #require(
            JSONSerialization.jsonObject(with: data) as? [String: Any]
        )
    }

    private func writeSingleRule(
        tree: [String: Any],
        to directory: URL,
        filename: String = "rule.json"
    ) throws {
        var rule = try object(compiledRule())
        rule["condition_tree"] = tree
        let data = try JSONSerialization.data(withJSONObject: rule)
        try data.write(to: directory.appendingPathComponent(filename))
    }

    private func writeSequenceRule(
        tree: [String: Any],
        to directory: URL,
        filename: String = "sequence.json"
    ) throws {
        var rule = try object(sequenceRule())
        var steps = try #require(rule["steps"] as? [[String: Any]])
        steps[0]["condition_tree"] = tree
        rule["steps"] = steps
        let data = try JSONSerialization.data(withJSONObject: rule)
        try data.write(to: directory.appendingPathComponent(filename))
    }

    private func oversizedObject<T: Encodable>(_ value: T) throws -> Data {
        var result = try object(value)
        result["padding"] = String(
            repeating: "x",
            count: RuleFileLoadingPolicy.maximumBytes + 1
        )
        let data = try JSONSerialization.data(withJSONObject: result)
        #expect(data.count > RuleFileLoadingPolicy.maximumBytes)
        return data
    }

    @Test("decoder rejects recursive depth before descending past the shared ceiling")
    func decoderDepthGuard() throws {
        func nestedNotJSON(wrapperCount: Int) -> Data {
            var node = #"{"type":"predicate","index":0}"#
            for _ in 0..<wrapperCount {
                node = #"{"type":"not","operands":["# + node + "]}"
            }
            return Data(node.utf8)
        }

        // Leaf depth 1 + 63 NOT wrappers = the accepted depth of 64.
        let boundary = try JSONDecoder().decode(
            ConditionNode.self,
            from: nestedNotJSON(wrapperCount: ConditionNode.maximumDepth - 1)
        )
        try boundary.validate(predicateCount: 1)

        // One more wrapper enters depth 65. The direct ConditionNode decode has
        // no engine validator afterward, so this proves the decoder itself
        // stops before another recursive operands decode.
        #expect(throws: DecodingError.self) {
            _ = try JSONDecoder().decode(
                ConditionNode.self,
                from: nestedNotJSON(wrapperCount: ConditionNode.maximumDepth)
            )
        }
    }

    @Test("single-event loader rejects every malformed or oversized condition tree")
    func singleEventMalformedTreesFailClosed() async throws {
        let wideOperands: [[String: Any]] = (0..<ConditionNode.maximumNodes).map { _ in
            ["type": "predicate", "index": 0]
        }
        let malformed: [[String: Any]] = [
            ["type": "and", "operands": []],
            ["type": "or", "operands": []],
            ["type": "not", "operands": []],
            [
                "type": "not",
                "operands": [
                    ["type": "predicate", "index": 0],
                    ["type": "predicate", "index": 0],
                ],
            ],
            ["type": "xor", "operands": []],
            ["type": "predicate", "index": -1],
            ["type": "predicate", "index": 1],
            ["type": "group", "rangeStart": 0, "rangeEnd": 0, "mode": "all_of"],
            ["type": "group", "rangeStart": 0, "rangeEnd": 2, "mode": "all_of"],
            ["type": "and", "operands": wideOperands],
        ]

        let root = try scratch("single-malformed")
        defer { try? FileManager.default.removeItem(at: root) }
        for (index, tree) in malformed.enumerated() {
            let directory = root.appendingPathComponent("case-\(index)", isDirectory: true)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
            try writeSingleRule(tree: tree, to: directory)

            let engine = RuleEngine()
            let loaded = try await engine.loadRules(from: directory)
            #expect(loaded == 0, "malformed single-event tree \(index) loaded")
            #expect(await engine.ruleCount == 0,
                    "malformed single-event tree \(index) became executable")
        }
    }

    @Test("single and sequence loaders enforce the same no-follow four-MiB file boundary")
    func bothLoadersUseBoundedNoFollowReads() async throws {
        let root = try scratch("file-policy")
        defer { try? FileManager.default.removeItem(at: root) }

        let singleLinkDir = root.appendingPathComponent("single-link", isDirectory: true)
        try FileManager.default.createDirectory(at: singleLinkDir, withIntermediateDirectories: false)
        let singleTarget = singleLinkDir.appendingPathComponent("target.payload")
        try JSONEncoder().encode(compiledRule()).write(to: singleTarget)
        try FileManager.default.createSymbolicLink(
            at: singleLinkDir.appendingPathComponent("linked.json"),
            withDestinationURL: singleTarget
        )
        let linkedSingle = RuleEngine()
        #expect(try await linkedSingle.loadRules(from: singleLinkDir) == 0)
        #expect(await linkedSingle.ruleCount == 0)

        let sequenceLinkDir = root.appendingPathComponent("sequence-link", isDirectory: true)
        try FileManager.default.createDirectory(at: sequenceLinkDir, withIntermediateDirectories: false)
        let sequenceTarget = sequenceLinkDir.appendingPathComponent("target.payload")
        try JSONEncoder().encode(sequenceRule()).write(to: sequenceTarget)
        try FileManager.default.createSymbolicLink(
            at: sequenceLinkDir.appendingPathComponent("linked.json"),
            withDestinationURL: sequenceTarget
        )
        let linkedSequence = SequenceEngine(lineage: ProcessLineage())
        #expect(try await linkedSequence.loadRules(from: sequenceLinkDir) == 0)
        #expect(await linkedSequence.ruleCount == 0)

        let singleLargeDir = root.appendingPathComponent("single-large", isDirectory: true)
        try FileManager.default.createDirectory(at: singleLargeDir, withIntermediateDirectories: false)
        try oversizedObject(compiledRule()).write(
            to: singleLargeDir.appendingPathComponent("oversized.json")
        )
        let largeSingle = RuleEngine()
        #expect(try await largeSingle.loadRules(from: singleLargeDir) == 0)
        #expect(await largeSingle.ruleCount == 0)

        let sequenceLargeDir = root.appendingPathComponent("sequence-large", isDirectory: true)
        try FileManager.default.createDirectory(at: sequenceLargeDir, withIntermediateDirectories: false)
        try oversizedObject(sequenceRule()).write(
            to: sequenceLargeDir.appendingPathComponent("oversized.json")
        )
        let largeSequence = SequenceEngine(lineage: ProcessLineage())
        #expect(try await largeSequence.loadRules(from: sequenceLargeDir) == 0)
        #expect(await largeSequence.ruleCount == 0)
    }
}
