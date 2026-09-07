// Adversarial coverage for boolean conditions inside temporal sequence steps.
//
// The compiler has long emitted a faithful condition_tree for complex
// single-event rules, but the sequence compiler discarded it and left only a
// lossy flat all_of/any_of approximation. That made OR-of-AND steps match one
// field alone and made mixed `(A or B) and C` steps impossible. These tests
// pin the complete compiler -> JSON -> decoder -> SequenceEngine path.

import Foundation
import Testing
@testable import MacCrabCore

@Suite("Sequence condition-tree preservation")
struct SequenceConditionTreeTests {
    private let compiledSequenceDir = compiledRulesDirectory.appendingPathComponent("sequences")

    private struct ExpectedTreeRule {
        let filename: String
        let stepIDs: Set<String>
    }

    private let expectedCorpus: [String: ExpectedTreeRule] = [
        "e1f2a3b4-0035-4000-b000-000000000035": .init(
            filename: "clipboard_hijack_then_exfil.json", stepIDs: ["clipboard_read"]
        ),
        "e1f2a3b4-0036-4000-b000-000000000036": .init(
            filename: "archive_to_cloud_exfil.json", stepIDs: ["cloud_upload"]
        ),
        "e1f2a3b4-0001-4000-b000-000000000001": .init(
            filename: "download_persist_c2.json", stepIDs: ["persist"]
        ),
        "e1f2a3b4-3005-4000-b000-000000003005": .init(
            filename: "notarized_dropper_pattern.json", stepIDs: ["drop_binary"]
        ),
        "e1f2a3b4-0023-4000-b000-000000000023": .init(
            filename: "supply_chain_full_kill_chain.json", stepIDs: ["persist"]
        ),
        "e1f2a3b4-0021-4000-b000-000000000021": .init(
            filename: "pip_install_to_credential_harvest.json", stepIDs: ["cred_access"]
        ),
        "e1f2a3b4-0016-4000-b000-000000000016": .init(
            filename: "ransomware_kill_chain.json", stepIDs: ["initial_exec", "impact"]
        ),
    ]

    private func processInfo(
        executable: String,
        commandLine: String? = nil,
        pid: Int32 = 912,
        parentExecutable: String? = nil,
        signer: SignerType? = nil
    ) -> MacCrabCore.ProcessInfo {
        let signature = signer.map {
            CodeSignatureInfo(
                signerType: $0,
                teamId: nil,
                signingId: nil,
                authorities: [],
                flags: 0,
                isNotarized: false,
                issuerChain: nil,
                certHashes: nil,
                isAdhocSigned: nil,
                entitlements: nil
            )
        }
        let ancestors = parentExecutable.map {
            [ProcessAncestor(
                pid: pid - 1,
                executable: $0,
                name: ($0 as NSString).lastPathComponent
            )]
        } ?? []
        return MacCrabCore.ProcessInfo(
            pid: pid,
            ppid: 1,
            rpid: 1,
            name: (executable as NSString).lastPathComponent,
            executable: executable,
            commandLine: commandLine ?? executable,
            args: [executable],
            workingDirectory: "/private/tmp",
            userId: 501,
            userName: "test",
            groupId: 20,
            startTime: Date(timeIntervalSince1970: 1_700_000_000),
            codeSignature: signature,
            ancestors: ancestors,
            architecture: "arm64",
            isPlatformBinary: false
        )
    }

    private func processEvent(
        executable: String,
        commandLine: String? = nil,
        pid: Int32 = 912,
        parentExecutable: String? = nil,
        signer: SignerType? = nil
    ) -> Event {
        Event(
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: processInfo(
                executable: executable,
                commandLine: commandLine,
                pid: pid,
                parentExecutable: parentExecutable,
                signer: signer
            )
        )
    }

    private func fileEvent(_ path: String, action: FileAction) -> Event {
        Event(
            eventCategory: .file,
            eventType: .creation,
            eventAction: action.rawValue,
            process: processInfo(executable: "/private/tmp/test-reader"),
            file: FileInfo(path: path, action: action)
        )
    }

    private func singleStepRule(
        id: String,
        predicates: [MacCrabCore.Predicate],
        condition: RuleCondition = .anyOf,
        tree: ConditionNode?
    ) -> SequenceRule {
        SequenceRule(
            id: id,
            title: id,
            description: "condition-tree regression",
            level: .high,
            tags: ["attack.execution"],
            window: 60,
            correlationType: .none,
            ordered: true,
            steps: [
                SequenceStep(
                    id: "only",
                    logsourceCategory: "process_creation",
                    predicates: predicates,
                    condition: condition,
                    conditionTree: tree
                ),
            ],
            trigger: .allSteps
        )
    }

    private var onePredicate: [MacCrabCore.Predicate] {
        [
            MacCrabCore.Predicate(
                field: "process.executable",
                modifier: .endswith,
                values: ["/true"],
                negate: false
            ),
        ]
    }

    private func isolatedStepFires(_ step: SequenceStep, event: Event) async throws -> Bool {
        let ruleID = "isolated-tree-\(UUID().uuidString)"
        let isolated = SequenceStep(
            id: "only",
            logsourceCategory: step.logsourceCategory,
            predicates: step.predicates,
            condition: step.condition,
            conditionTree: step.conditionTree
        )
        let engine = SequenceEngine(lineage: ProcessLineage())
        try await engine.addRule(SequenceRule(
            id: ruleID,
            title: ruleID,
            description: "decoded corpus step",
            level: .high,
            tags: ["attack.execution"],
            window: 60,
            correlationType: .none,
            ordered: true,
            steps: [isolated],
            trigger: .allSteps
        ))
        return await engine.evaluate(event).contains { $0.ruleId == ruleID }
    }

    @Test("compiler emits and SequenceEngine decodes all eight affected corpus trees")
    func corpusTreesSurviveCompilerAndDecoder() async throws {
        try ensureRulesCompiled()

        var emittedTreeCount = 0
        for (ruleID, expected) in expectedCorpus {
            let url = compiledSequenceDir.appendingPathComponent(expected.filename)
            let data = try Data(contentsOf: url)
            guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  object["id"] as? String == ruleID,
                  let steps = object["steps"] as? [[String: Any]] else {
                Issue.record("malformed compiled sequence: \(expected.filename)")
                continue
            }
            let emittedStepIDs = Set(steps.compactMap { step -> String? in
                guard step["condition_tree"] is [String: Any] else { return nil }
                return step["id"] as? String
            })
            #expect(emittedStepIDs == expected.stepIDs,
                    "compiler lost/reassigned a tree in \(expected.filename)")
            emittedTreeCount += emittedStepIDs.count
        }
        #expect(emittedTreeCount == 8)

        let engine = SequenceEngine(lineage: ProcessLineage())
        _ = try await engine.loadRules(from: compiledSequenceDir)
        let decoded = Dictionary(uniqueKeysWithValues: await engine.listRules().map { ($0.id, $0) })

        var decodedTreeCount = 0
        for (ruleID, expected) in expectedCorpus {
            guard let rule = decoded[ruleID] else {
                Issue.record("SequenceEngine silently dropped affected rule \(ruleID)")
                continue
            }
            let decodedStepIDs = Set(rule.steps.compactMap { step in
                step.conditionTree == nil ? nil : step.id
            })
            #expect(decodedStepIDs == expected.stepIDs,
                    "decoder lost/reassigned a tree for \(ruleID)")
            decodedTreeCount += decodedStepIDs.count
        }
        #expect(decodedTreeCount == 8)
    }

    @Test("all eight decoded corpus trees execute their authored branch semantics")
    func affectedCorpusTreesExecuteExactly() async throws {
        try ensureRulesCompiled()
        let loader = SequenceEngine(lineage: ProcessLineage())
        _ = try await loader.loadRules(from: compiledSequenceDir)
        let rules = Dictionary(uniqueKeysWithValues: (await loader.listRules()).map { ($0.id, $0) })

        func step(_ ruleID: String, _ stepID: String) throws -> SequenceStep {
            try #require(rules[ruleID]?.steps.first { $0.id == stepID })
        }

        let clipboard = try step("e1f2a3b4-0035-4000-b000-000000000035", "clipboard_read")
        #expect(try await isolatedStepFires(clipboard, event: processEvent(
            executable: "/usr/bin/pbpaste", signer: .unsigned
        )))
        #expect(!(try await isolatedStepFires(clipboard, event: processEvent(
            executable: "/usr/bin/pbpaste", signer: .devId
        ))), "Image alone must not satisfy an OR-of-AND selection")
        #expect(try await isolatedStepFires(clipboard, event: processEvent(
            executable: "/usr/bin/osascript",
            commandLine: "osascript -e 'get clipboard'",
            signer: .devId
        )))

        let cloudUpload = try step("e1f2a3b4-0036-4000-b000-000000000036", "cloud_upload")
        #expect(!(try await isolatedStepFires(cloudUpload, event: processEvent(
            executable: "/usr/local/bin/rclone", commandLine: "rclone version"
        ))), "tool name alone must not satisfy the rclone+upload branch")
        #expect(try await isolatedStepFires(cloudUpload, event: processEvent(
            executable: "/usr/local/bin/rclone", commandLine: "rclone copy secrets remote:bucket"
        )))

        let downloadPersist = try step("e1f2a3b4-0001-4000-b000-000000000001", "persist")
        #expect(!(try await isolatedStepFires(downloadPersist, event: fileEvent(
            "/Users/test/Library/LaunchAgents/readme.txt", action: .create
        ))), "LaunchAgents directory alone must not satisfy directory+plist")
        #expect(try await isolatedStepFires(downloadPersist, event: fileEvent(
            "/Users/test/Library/LaunchAgents/com.evil.plist", action: .create
        )))

        let dropBinary = try step("e1f2a3b4-3005-4000-b000-000000003005", "drop_binary")
        #expect(try await isolatedStepFires(dropBinary, event: fileEvent(
            "/opt/evil.dylib", action: .write
        )))
        #expect(!(try await isolatedStepFires(dropBinary, event: fileEvent(
            "/opt/evil.dylib", action: .open
        ))), "read alone must not satisfy the write+executable branch")

        let supplyPersist = try step("e1f2a3b4-0023-4000-b000-000000000023", "persist")
        #expect(!(try await isolatedStepFires(supplyPersist, event: fileEvent(
            "/tmp/hook.pth", action: .create
        ))), ".pth alone must not satisfy the site-packages+.pth branch")
        #expect(try await isolatedStepFires(supplyPersist, event: fileEvent(
            "/tmp/site-packages/hook.pth", action: .create
        )))

        let pipCredential = try step("e1f2a3b4-0021-4000-b000-000000000021", "cred_access")
        let azureProfile = "/Users/test/.azure/azureProfile.json"
        #expect(try await isolatedStepFires(pipCredential, event: fileEvent(
            azureProfile, action: .open
        )))
        #expect(!(try await isolatedStepFires(pipCredential, event: fileEvent(
            azureProfile, action: .write
        ))), "credential path without OPEN must fail the mixed OR+AND tree")

        let ransomwareInitial = try step(
            "e1f2a3b4-0016-4000-b000-000000000016", "initial_exec"
        )
        #expect(!(try await isolatedStepFires(ransomwareInitial, event: processEvent(
            executable: "/bin/bash", parentExecutable: "/sbin/launchd", signer: .devId
        ))), "shell name alone must not satisfy shell+suspicious-parent")
        #expect(try await isolatedStepFires(ransomwareInitial, event: processEvent(
            executable: "/bin/bash", parentExecutable: "/usr/bin/curl", signer: .devId
        )))
        #expect(try await isolatedStepFires(ransomwareInitial, event: processEvent(
            executable: "/tmp/payload", signer: .unsigned
        )))

        let ransomwareImpact = try step(
            "e1f2a3b4-0016-4000-b000-000000000016", "impact"
        )
        #expect(!(try await isolatedStepFires(ransomwareImpact, event: processEvent(
            executable: "/bin/dd", commandLine: "dd --help"
        ))), "dd name alone must not satisfy dd+destructive-argument")
        #expect(try await isolatedStepFires(ransomwareImpact, event: processEvent(
            executable: "/bin/dd", commandLine: "dd if=/dev/zero of=/dev/disk9"
        )))
    }

    @Test("nested AND OR NOT and predicate groups retain exact branch semantics")
    func nestedBooleanSemantics() async throws {
        let predicates = [
            MacCrabCore.Predicate(field: "process.executable", modifier: .endswith,
                      values: ["/curl"], negate: false),
            MacCrabCore.Predicate(field: "process.commandline", modifier: .contains,
                      values: ["upload"], negate: false),
            MacCrabCore.Predicate(field: "process.executable", modifier: .endswith,
                      values: ["/aws"], negate: false),
            MacCrabCore.Predicate(field: "process.executable", modifier: .startswith,
                      values: ["/safe/"], negate: false),
        ]
        // ((curl AND command contains upload) OR aws) AND NOT /safe/*
        let tree = ConditionNode.and([
            .or([
                .predicateGroup(range: 0..<2, mode: .allOf),
                .predicate(2),
            ]),
            .not(.predicate(3)),
        ])
        let engine = SequenceEngine(lineage: ProcessLineage())
        try await engine.addRule(singleStepRule(
            id: "nested-condition-tree", predicates: predicates, tree: tree
        ))

        let partialCurl = await engine.evaluate(processEvent(
            executable: "/usr/bin/curl", commandLine: "curl https://safe.example"
        ))
        #expect(partialCurl.isEmpty,
                "flat any_of regression: curl alone must not satisfy the curl+upload branch")

        let uploadCurl = await engine.evaluate(processEvent(
            executable: "/usr/bin/curl", commandLine: "curl --upload file"
        ))
        #expect(uploadCurl.contains { $0.ruleId == "nested-condition-tree" })

        let aws = await engine.evaluate(processEvent(executable: "/usr/local/bin/aws"))
        #expect(aws.contains { $0.ruleId == "nested-condition-tree" })

        let filteredAWS = await engine.evaluate(processEvent(executable: "/safe/aws"))
        #expect(filteredAWS.isEmpty, "NOT branch must filter an otherwise matching OR branch")
    }

    @Test("malformed and pathological programmatic trees are rejected before installation")
    func invalidTreesFailClosed() async {
        var tooDeep = ConditionNode.predicate(0)
        for _ in 0..<ConditionNode.maximumDepth { tooDeep = .not(tooDeep) }

        let tooManyNodes = ConditionNode.and(
            Array(repeating: .predicate(0), count: ConditionNode.maximumNodes)
        )
        let cases: [(String, ConditionNode)] = [
            ("empty-and", .and([])),
            ("empty-or", .or([])),
            ("negative-index", .predicate(-1)),
            ("upper-index", .predicate(1)),
            ("empty-group", .predicateGroup(range: 0..<0, mode: .allOf)),
            ("oversized-group", .predicateGroup(range: 0..<2, mode: .anyOf)),
            ("too-deep", tooDeep),
            ("too-many-nodes", tooManyNodes),
        ]

        for (id, tree) in cases {
            let engine = SequenceEngine(lineage: ProcessLineage())
            await #expect(throws: SequenceEngineError.self) {
                try await engine.addRule(singleStepRule(
                    id: "invalid-\(id)", predicates: onePredicate, tree: tree
                ))
            }
            #expect(await engine.ruleCount == 0,
                    "invalid condition tree \(id) was installed")
        }
    }

    @Test("unknown nodes and malformed NOT arrays are skipped by the real loader")
    func malformedDecodedTreesFailClosed() async throws {
        let malformedNodes: [[String: Any]] = [
            ["type": "xor", "operands": []],
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
            ["type": "group", "rangeStart": 0, "rangeEnd": 0, "mode": "all_of"],
            ["type": "predicate", "index": 1],
        ]

        for (index, malformedNode) in malformedNodes.enumerated() {
            let directory = FileManager.default.temporaryDirectory.appendingPathComponent(
                "maccrab-sequence-tree-malformed-\(UUID().uuidString)",
                isDirectory: true
            )
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: directory) }

            let valid = singleStepRule(
                id: "malformed-decoder-\(index)",
                predicates: onePredicate,
                tree: .predicate(0)
            )
            let encoded = try JSONEncoder().encode(valid)
            var object = try #require(
                JSONSerialization.jsonObject(with: encoded) as? [String: Any]
            )
            var steps = try #require(object["steps"] as? [[String: Any]])
            steps[0]["condition_tree"] = malformedNode
            object["steps"] = steps
            let data = try JSONSerialization.data(withJSONObject: object)
            try data.write(to: directory.appendingPathComponent("bad.json"))

            let engine = SequenceEngine(lineage: ProcessLineage())
            let loaded = try await engine.loadRules(from: directory)
            #expect(loaded == 0, "malformed decoded tree \(index) was accepted")
            #expect(await engine.ruleCount == 0)
        }
    }

    @Test("legacy flat steps without condition_tree remain compatible")
    func legacyFlatStepStillEvaluates() async throws {
        let engine = SequenceEngine(lineage: ProcessLineage())
        try await engine.addRule(singleStepRule(
            id: "legacy-flat-step",
            predicates: onePredicate,
            condition: .allOf,
            tree: nil
        ))

        let miss = await engine.evaluate(processEvent(executable: "/usr/bin/false"))
        #expect(miss.isEmpty)
        let match = await engine.evaluate(processEvent(executable: "/usr/bin/true"))
        #expect(match.contains { $0.ruleId == "legacy-flat-step" })
    }
}
