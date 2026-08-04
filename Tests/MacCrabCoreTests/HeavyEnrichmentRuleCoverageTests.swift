import Foundation
import Testing
@testable import MacCrabCore

@Suite("Heavy enrichment rule-coverage contract")
struct HeavyEnrichmentRuleCoverageTests {
    private func scratch(_ label: String) throws -> URL {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(
            "maccrab-heavy-rule-coverage-\(label)-\(UUID().uuidString)",
            isDirectory: true
        )
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: false
        )
        return directory
    }

    private func load(_ rules: [CompiledRule], from directory: URL) async throws -> RuleEngine {
        for (index, rule) in rules.enumerated() {
            try JSONEncoder().encode(rule).write(
                to: directory.appendingPathComponent("rule-\(index).json")
            )
        }
        let engine = RuleEngine()
        #expect(try await engine.loadRules(from: directory) == rules.count)
        return engine
    }

    private func process() -> MacCrabCore.ProcessInfo {
        MacCrabCore.ProcessInfo(
            pid: 7_101,
            ppid: 1,
            rpid: 1,
            name: "writer",
            executable: "/private/tmp/writer",
            commandLine: "/private/tmp/writer",
            args: ["/private/tmp/writer"],
            workingDirectory: "/private/tmp",
            userId: 501,
            userName: "test-user",
            groupId: 20,
            startTime: Date(timeIntervalSince1970: 1_700_000_000),
            codeSignature: nil,
            ancestors: [],
            architecture: "arm64",
            isPlatformBinary: false
        )
    }

    private func coverageEnrichments(
        _ component: HeavyEnrichmentComponent,
        state: HeavyEnrichmentCoverage,
        content: String? = nil
    ) -> [String: String] {
        var enrichments: [String: String] = [:]
        if let marker = DeferredEventEnrichment.coverageMarker([component: state]) {
            enrichments[DeferredEventEnrichment.coverageKey] = marker
        }
        if let content { enrichments["FileContent"] = content }
        return enrichments
    }

    private func processEvent(
        coverage: HeavyEnrichmentCoverage? = nil
    ) -> Event {
        Event(
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: process(),
            enrichments: coverage.map {
                coverageEnrichments(.codeSignature, state: $0)
            } ?? [:]
        )
    }

    private func fileEvent(
        id: UUID = UUID(),
        timestamp: Date = Date(timeIntervalSince1970: 1_700_000_100),
        coverage: HeavyEnrichmentCoverage? = nil,
        content: String? = nil
    ) -> Event {
        Event(
            id: id,
            timestamp: timestamp,
            eventCategory: .file,
            eventType: .creation,
            eventAction: FileAction.create.rawValue,
            process: process(),
            file: FileInfo(
                path: "/private/tmp/artifact",
                size: 12,
                action: .create
            ),
            enrichments: coverage.map {
                coverageEnrichments(.fileContent, state: $0, content: content)
            } ?? content.map { ["FileContent": $0] } ?? [:]
        )
    }

    private func rule(
        id: String,
        category: String,
        predicates: [MacCrabCore.Predicate],
        condition: RuleCondition = .allOf,
        tree: ConditionNode? = nil
    ) -> CompiledRule {
        CompiledRule(
            id: id,
            title: id,
            description: "heavy coverage regression",
            level: .high,
            tags: ["attack.execution"],
            logsource: LogSource(category: category, product: "macos"),
            predicates: predicates,
            condition: condition,
            conditionTree: tree,
            falsepositives: [],
            enabled: true
        )
    }

    private func oneStepSequence(
        id: String,
        category: String,
        predicates: [MacCrabCore.Predicate],
        tree: ConditionNode? = nil
    ) -> SequenceRule {
        SequenceRule(
            id: id,
            title: id,
            description: "heavy coverage regression",
            level: .high,
            tags: ["attack.execution"],
            window: 60,
            correlationType: .none,
            ordered: true,
            steps: [SequenceStep(
                id: "only",
                logsourceCategory: category,
                predicates: predicates,
                conditionTree: tree
            )],
            trigger: .allSteps
        )
    }

    @Test("fixed field ownership covers every heavyweight rule alias")
    func fixedFieldOwnership() {
        let expected: [HeavyEnrichmentComponent: [String]] = [
            .codeSignature: [
                "process.code_signature.signer_type", "SignerType",
                "process.code_signature.team_id", "process.code_signature.signing_id",
                "process.code_signature.flags", "CodeSigningFlags",
                "process.code_signature.notarized", "process.code_signature.issuer",
                "SigningCertIssuer", "process.code_signature.cert_hash",
                "SigningCertHash", "process.code_signature.is_adhoc",
                "IsAdhocSigned", "process.is_notarized", "IsNotarized",
                "NotarizationStatus",
            ],
            .processHashes: [
                "process.hashes.sha256", "ProcessSHA256",
                "process.hashes.cdhash", "ProcessCDHash",
                "process.hashes.md5", "ProcessMD5",
            ],
            .environment: ["process.env", "EnvVarsFlat"],
            .fileContent: ["FileContent"],
            .userName: ["process.user.name", "User"],
        ]

        for (component, fields) in expected {
            for field in fields {
                #expect(
                    HeavyEnrichmentComponent.dependency(forPredicateField: field) == component,
                    "\(field) lost heavyweight ownership"
                )
            }
        }
        #expect(HeavyEnrichmentComponent.dependency(forPredicateField: "process.user.id") == nil)
        #expect(HeavyEnrichmentComponent.dependency(forPredicateField: "UserId") == nil)
        #expect(HeavyEnrichmentComponent.dependency(forPredicateField: "ParentSignerType") == nil)
    }

    @Test("flat predicate negation cannot convert unresolved coverage into a match")
    func flatNegationFailsBeforeInversion() async throws {
        let directory = try scratch("flat-negate")
        defer { try? FileManager.default.removeItem(at: directory) }
        let negatedSigner = Predicate(
            field: "SignerType",
            modifier: .equals,
            values: ["apple"],
            negate: true
        )
        let engine = try await load([
            rule(
                id: "covered-flat-negate",
                category: "process_creation",
                predicates: [negatedSigner]
            ),
        ], from: directory)
        let sequence = SequenceEngine(lineage: ProcessLineage())
        try await sequence.addRule(oneStepSequence(
            id: "covered-sequence-flat-negate",
            category: "process_creation",
            predicates: [negatedSigner]
        ))

        #expect(await engine.evaluate(processEvent()).map(\.ruleId) == ["covered-flat-negate"])
        #expect(
            await sequence.evaluate(processEvent()).map(\.ruleId)
                == ["covered-sequence-flat-negate"]
        )

        let unresolved: [HeavyEnrichmentCoverage] = [
            .pending, .rejected, .timedOut, .cancelled, .unavailable,
        ]
        for state in unresolved {
            #expect(
                await engine.evaluate(processEvent(coverage: state)).isEmpty,
                "\(state.rawValue) was inverted by predicate.negate"
            )
            #expect(
                await sequence.evaluate(processEvent(coverage: state)).isEmpty,
                "sequence \(state.rawValue) was inverted by predicate.negate"
            )
        }
    }

    @Test("condition-tree not cannot invert an unresolved predicate")
    func conditionTreeNotFailsBeforeInversion() async throws {
        let directory = try scratch("tree-not")
        defer { try? FileManager.default.removeItem(at: directory) }
        let contentPredicate = Predicate(
            field: "FileContent",
            modifier: .contains,
            values: ["malicious-marker"],
            negate: false
        )
        let engine = try await load([
            rule(
                id: "covered-tree-not",
                category: "file_event",
                predicates: [contentPredicate],
                tree: .not(.predicate(0))
            ),
        ], from: directory)
        let sequence = SequenceEngine(lineage: ProcessLineage())
        try await sequence.addRule(oneStepSequence(
            id: "covered-sequence-tree-not",
            category: "file_event",
            predicates: [contentPredicate],
            tree: .not(.predicate(0))
        ))

        #expect(await engine.evaluate(fileEvent()).map(\.ruleId) == ["covered-tree-not"])
        #expect(
            await sequence.evaluate(fileEvent()).map(\.ruleId)
                == ["covered-sequence-tree-not"]
        )
        #expect(await engine.evaluate(fileEvent(coverage: .pending)).isEmpty)
        #expect(await engine.evaluate(fileEvent(coverage: .timedOut)).isEmpty)
        #expect(await sequence.evaluate(fileEvent(coverage: .pending)).isEmpty)
        #expect(await sequence.evaluate(fileEvent(coverage: .timedOut)).isEmpty)
    }

    @Test("single-event replay evaluates only rules whose executable tree consumes the component")
    func filteredSingleEventReplay() async throws {
        let directory = try scratch("single-filter")
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = Predicate(
            field: "TargetFilename",
            modifier: .endswith,
            values: ["/artifact"],
            negate: false
        )
        let content = Predicate(
            field: "FileContent",
            modifier: .contains,
            values: ["malicious-marker"],
            negate: false
        )
        let engine = try await load([
            rule(id: "content-dependent", category: "file_event", predicates: [content]),
            rule(id: "path-independent", category: "file_event", predicates: [path]),
            // The unused content predicate must not make this executable tree
            // dependent; dependency traversal follows referenced leaves only.
            rule(
                id: "tree-independent",
                category: "file_event",
                predicates: [path, content],
                tree: .predicate(0)
            ),
        ], from: directory)

        let eventID = UUID()
        let timestamp = Date(timeIntervalSince1970: 1_700_000_100)
        let initial = fileEvent(id: eventID, timestamp: timestamp, coverage: .pending)
        #expect(Set(await engine.evaluate(initial).map(\.ruleId)) == [
            "path-independent", "tree-independent",
        ])

        let patched = fileEvent(
            id: eventID,
            timestamp: timestamp,
            content: "malicious-marker"
        )
        #expect(
            await engine.reevaluate(patched, forCompleted: [.fileContent]).map(\.ruleId)
                == ["content-dependent"]
        )
        #expect(await engine.reevaluate(patched, forCompleted: []).isEmpty)
    }

    @Test("sequence replay cannot duplicate an independent partial seed")
    func filteredSequenceReplayDoesNotDuplicatePartial() async throws {
        let path = Predicate(
            field: "TargetFilename",
            modifier: .endswith,
            values: ["/artifact"],
            negate: false
        )
        let content = Predicate(
            field: "FileContent",
            modifier: .contains,
            values: ["malicious-marker"],
            negate: false
        )
        let sequence = SequenceRule(
            id: "deferred-content-sequence",
            title: "deferred-content-sequence",
            description: "heavy coverage regression",
            level: .high,
            tags: ["attack.execution"],
            window: 60,
            correlationType: .none,
            ordered: true,
            steps: [
                SequenceStep(
                    id: "independent-seed",
                    logsourceCategory: "file_event",
                    predicates: [path]
                ),
                SequenceStep(
                    id: "content-finish",
                    logsourceCategory: "file_event",
                    predicates: [content],
                    afterStep: "independent-seed"
                ),
            ],
            trigger: .allSteps
        )

        let eventID = UUID()
        let timestamp = Date(timeIntervalSince1970: 1_700_000_100)
        let initial = fileEvent(id: eventID, timestamp: timestamp, coverage: .pending)
        let patched = fileEvent(
            id: eventID,
            timestamp: timestamp,
            content: "malicious-marker"
        )

        let filtered = SequenceEngine(lineage: ProcessLineage())
        try await filtered.addRule(sequence)
        #expect(await filtered.evaluate(initial).isEmpty)
        #expect(await filtered.activePartialMatchCount == 1)
        #expect(await filtered.reevaluate(patched, forCompleted: [.fileContent]).isEmpty)
        #expect(
            await filtered.activePartialMatchCount == 1,
            "component replay seeded the independent first step twice"
        )

        // Sensitivity proof: an ordinary full replay of the same patched event
        // does duplicate the `.none`-correlated seed, so the assertion above is
        // specifically exercising step-level dependency filtering.
        let unfiltered = SequenceEngine(lineage: ProcessLineage())
        try await unfiltered.addRule(sequence)
        _ = await unfiltered.evaluate(initial)
        _ = await unfiltered.evaluate(patched)
        #expect(await unfiltered.activePartialMatchCount == 2)
    }
}
