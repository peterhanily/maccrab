// AIResponseSafetyBoundaryTests.swift
// MacCrabCoreTests
//
// A classifier verdict is probabilistic evidence. Even a syntactically valid,
// high-confidence response can be wrong or can come from a compromised model.
// These tests pin the final response boundary so neither global defaults nor a
// per-rule configuration can turn that verdict into an automatic host mutation.

import Foundation
import Testing
@testable import MacCrabCore

private actor HostileHighConfidenceIntentBackend: LLMBackend {
    let providerName = "HostileHighConfidenceFixture"
    private var calls = 0

    func isAvailable() async -> Bool { true }

    func complete(
        systemPrompt: String,
        userPrompt: String,
        maxTokens: Int,
        temperature: Double
    ) async -> String? {
        calls += 1
        // Simulate a compromised/miscalibrated model confidently calling a
        // benign install exfiltration. The payload is deliberately valid so
        // response safety cannot rely on parser rejection.
        return #"{"label":"exfiltration","confidence":0.99,"reasons":["behavior evidence was classified as high risk"]}"#
    }

    func callCount() -> Int { calls }
}

@Suite("Model/advisory response safety boundary")
struct AIResponseSafetyBoundaryTests {
    private static let classifierRuleID =
        "d1a2b3c4-2059-4000-a000-000000002059"

    private var repositoryRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    private func installEvent(
        verdict: IntentClassifier.ClassificationResult? = nil,
        pid: Int32 = 999_999
    ) -> Event {
        let process = MacCrabCore.ProcessInfo(
            pid: pid,
            ppid: 1,
            rpid: 1,
            name: "npm",
            executable: "/opt/homebrew/bin/npm",
            commandLine: "npm install harmless-package",
            args: ["npm", "install", "harmless-package"],
            workingDirectory: "/tmp",
            userId: 501,
            userName: "test",
            groupId: 20,
            startTime: Date(timeIntervalSince1970: 1_700_000_000),
            ancestors: [
                ProcessAncestor(pid: 1, executable: "/sbin/launchd", name: "launchd"),
            ],
            architecture: "arm64",
            isPlatformBinary: false
        )
        var enrichments: [String: String] = [:]
        if let verdict {
            enrichments["IntentLabel"] = verdict.label.rawValue
            enrichments["IntentConfidence"] = String(format: "%.2f", verdict.confidence)
            enrichments["IntentHighConfidence"] = verdict.confidence >= 0.5 ? "true" : "false"
            enrichments["IntentProvider"] = verdict.provider
            enrichments["IntentRefinedBy"] = verdict.provider
        }
        return Event(
            eventCategory: .process,
            eventType: .creation,
            eventAction: "exec",
            process: process,
            enrichments: enrichments
        )
    }

    private func alert(
        ruleID: String = Self.classifierRuleID,
        severity: Severity = .high
    ) -> Alert {
        Alert(
            ruleId: ruleID,
            ruleTitle: "Intent classifier verdict",
            severity: severity,
            eventId: UUID().uuidString,
            processPath: "/opt/homebrew/bin/npm",
            processName: "npm",
            description: "Probabilistic intent evidence"
        )
    }

    @Test("Cached hostile high-confidence LLM verdict may alert and notify but global kill is refused")
    func hostileCachedVerdictCannotReachGlobalKill() async throws {
        let backend = HostileHighConfidenceIntentBackend()
        let service = LLMService(
            backend: backend,
            config: LLMConfig(),
            minInterval: 0
        )
        let classifier = IntentClassifier(llmService: service)
        let brief = IntentClassifier.BehaviorBrief(
            packageName: "harmless-package",
            packageRegistry: "npm",
            packageVersion: "1.0.0",
            installerLineage: ["npm", "node"],
            credentialsRead: [],
            networkEgress: ["registry.npmjs.org"],
            filesWritten: [],
            processesSpawned: [],
            hasObfuscatedContent: false,
            hasBundledRuntime: false,
            hasLanguageMismatch: false,
            aiAgentTriggered: true
        )

        let first = await classifier.classify(brief)
        let cached = await classifier.classify(brief)
        #expect(first.cached == false)
        #expect(cached.cached == true)
        #expect(cached.label == .exfiltration)
        #expect(cached.confidence == 0.99)
        #expect(await backend.callCount() == 1)

        // Prove the accepted cached verdict reaches the real shipping Sigma
        // rule. This is not a hand-built alert that could conceal a rule wiring
        // mismatch.
        try ensureRulesCompiled()
        let ruleEngine = RuleEngine()
        _ = try await ruleEngine.loadRules(
            from: compiledRulesDirectory
        )
        let event = installEvent(verdict: cached)
        let matches = await ruleEngine.evaluate(event)
        let match = try #require(matches.first {
            $0.ruleId == Self.classifierRuleID
        })

        let support = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-ai-response-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: support) }
        let response = ResponseEngine(supportDirectory: support.path)
        // No rule-specific config: this is the hostile global-default shape
        // from the audit. The low threshold proves severity is not what saves
        // us. Notify remains eligible so the operator still sees the finding.
        await response.setDefaultActions([
            ResponseActionConfig(action: .kill, minimumSeverity: .low),
            ResponseActionConfig(action: .notify, minimumSeverity: .low),
        ])
        let firedAlert = Alert(
            ruleId: match.ruleId,
            ruleTitle: match.ruleName,
            severity: match.severity,
            eventId: event.id.uuidString,
            processPath: event.process.executable,
            processName: event.process.name,
            description: match.description
        )
        await response.execute(alert: firedAlert, event: event)

        let audit = await response.getExecutionLog()
        let kill = try #require(audit.first { $0.action == .kill })
        #expect(kill.success == false)
        #expect(kill.target == ResponseEngine.advisoryOnlyDenialTarget)
        #expect(!audit.contains { $0.target.hasPrefix("pid:") },
                "No kill implementation may be reached for AI-derived intent")
        #expect(audit.contains {
            $0.action == .notify && $0.success && $0.target == "notification"
        })
    }

    @Test("Only explicit per-rule confirmation can create pending-only intent response")
    func confirmationMustBeExplicitAndRuleSpecific() async throws {
        let event = installEvent()
        let derivedAlert = alert()
        let support = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-ai-confirm-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: support) }

        let explicit = ResponseEngine(supportDirectory: support.path)
        await explicit.setActions(forRule: Self.classifierRuleID, actions: [
            ResponseActionConfig(
                action: .kill,
                minimumSeverity: .low,
                requireConfirmation: true
            ),
        ])
        await explicit.execute(alert: derivedAlert, event: event)
        let pending = try #require(await explicit.getExecutionLog().first)
        #expect(pending.action == .kill)
        #expect(pending.target == "pending-confirmation")
        #expect(pending.success == false)

        let global = ResponseEngine(supportDirectory: support.path)
        await global.setDefaultActions([
            ResponseActionConfig(
                action: .kill,
                minimumSeverity: .low,
                requireConfirmation: true
            ),
        ])
        await global.execute(alert: derivedAlert, event: event)
        let globalDenial = try #require(await global.getExecutionLog().first)
        #expect(globalDenial.target == ResponseEngine.advisoryOnlyDenialTarget)

        let unconfirmed = ResponseEngine(supportDirectory: support.path)
        await unconfirmed.setActions(forRule: Self.classifierRuleID, actions: [
            ResponseActionConfig(
                action: .kill,
                minimumSeverity: .low,
                requireConfirmation: false
            ),
        ])
        await unconfirmed.execute(alert: derivedAlert, event: event)
        let unconfirmedDenial = try #require(
            await unconfirmed.getExecutionLog().first
        )
        #expect(unconfirmedDenial.target == ResponseEngine.advisoryOnlyDenialTarget)

        // Compatibility guard: this detector is a deterministic composite of
        // observed behavior, not model-authored advice. Existing operator
        // response policy must continue to reach the implementation.
        let deterministic = ResponseEngine(supportDirectory: support.path)
        await deterministic.setDefaultActions([
            ResponseActionConfig(action: .kill, minimumSeverity: .low),
        ])
        await deterministic.execute(
            alert: alert(ruleID: "maccrab.behavior.composite"),
            event: event
        )
        let deterministicAttempt = try #require(
            await deterministic.getExecutionLog().first
        )
        #expect(deterministicAttempt.target == "pid:\(event.process.pid)")
    }

    @Test("Future MCP baseline review alerts remain advisory at response boundary")
    func mcpBaselineReviewCannotAuthorizeContainment() async throws {
        let support = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-mcp-response-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: support) }
        let response = ResponseEngine(supportDirectory: support.path)
        await response.setDefaultActions([
            ResponseActionConfig(action: .kill, minimumSeverity: .low),
        ])
        let event = installEvent()
        await response.execute(
            alert: alert(
                ruleID: "maccrab.mcp.baseline-anomaly.future.server.future_kind"
            ),
            event: event
        )
        let denial = try #require(await response.getExecutionLog().first)
        #expect(denial.action == .kill)
        #expect(denial.target == ResponseEngine.advisoryOnlyDenialTarget)
        #expect(denial.success == false)
    }

    @Test("Advisory rule families and response policy cannot drift apart")
    func advisoryRulePolicyDriftGuard() throws {
        let rulesRoot = repositoryRoot.appendingPathComponent("Rules")
        let enumerator = try #require(
            FileManager.default.enumerator(
                at: rulesRoot,
                includingPropertiesForKeys: nil
            )
        )
        var corpusIDs = Set<String>()
        for case let url as URL in enumerator where url.pathExtension == "yml" {
            let yaml = try String(contentsOf: url, encoding: .utf8)
            guard yaml.contains("maccrab.intent_classifier")
                    || yaml.contains("maccrab.llm_verdict")
                    || yaml.contains("IntentLabel:")
                    || yaml.contains("PromptIntentLabel:") else { continue }
            let idLine = try #require(
                yaml.split(separator: "\n").first {
                    $0.trimmingCharacters(in: .whitespaces).hasPrefix("id:")
                },
                "AI-derived rule is missing an id: \(url.path)"
            )
            let id = idLine
                .trimmingCharacters(in: .whitespaces)
                .dropFirst("id:".count)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            corpusIDs.insert(id)
        }

        #expect(!corpusIDs.isEmpty)
        for id in corpusIDs {
            #expect(ResponseEngine.isAdvisoryOnlyRuleID(id),
                    "AI-derived rule \(id) is not response-restricted")
        }
        #expect(ResponseEngine.advisoryOnlyRuleIDs.isSubset(of: corpusIDs),
                "A hard-coded boundary id no longer maps to an AI-derived rule")

        // Built-in ids do not live in YAML, so pin every advisory family. A
        // future refactor routing any of these through ResponseEngine must not
        // silently grant it containment authority.
        let advisoryBuiltins = [
            "maccrab.intent.bayesian-posterior",
            "maccrab.prompt-intent.vagueDestructive",
            "maccrab.llm.investigation-summary",
            "maccrab.llm.defense-recommendation",
            "maccrab.llm.sdr-analysis",
            "maccrab.llm.edr-context",
            "maccrab.llm.security-score",
            "maccrab.mcp.baseline-anomaly.claude.github.new_domain",
            "maccrab.counterfactual.some-observed-rule",
            "maccrab.predict.next-technique.some-observed-rule",
        ]
        for id in advisoryBuiltins {
            #expect(ResponseEngine.isAdvisoryOnlyRuleID(id),
                    "Advisory rule family lost response restriction: \(id)")
        }
        #expect(!ResponseEngine.isAdvisoryOnlyRuleID(
            "maccrab.behavior.composite"
        ))

        let expectedPrefixes: Set<String> = [
            "maccrab.intent.",
            "maccrab.prompt-intent.",
            "maccrab.llm.",
            "maccrab.mcp.baseline-anomaly.",
            "maccrab.counterfactual.",
            "maccrab.predict.",
        ]
        #expect(Set(ResponseEngine.advisoryOnlyRuleIDPrefixes) == expectedPrefixes)

        // Counterfactual and prediction remain explicit analyst/MCP tools, but
        // their automatic EventLoop alert emitters were retired. Keep their
        // response restrictions as defense in depth without falsely requiring
        // a production emitter for either family.
        let automaticEmitterPrefixes = expectedPrefixes.subtracting([
            "maccrab.counterfactual.",
            "maccrab.predict.",
        ])

        // Source-level family sweep: every currently emitted model/advisory
        // alert literal must resolve through the final response policy. This
        // catches an emitter rename that updates production but forgets the
        // boundary. Dynamic suffixes are retained as source text; only their
        // stable family prefix matters.
        let sourceRoot = repositoryRoot
            .appendingPathComponent("Sources/MacCrabAgentKit")
        let sourceEnumerator = try #require(
            FileManager.default.enumerator(
                at: sourceRoot,
                includingPropertiesForKeys: nil
            )
        )
        var observedPrefixes = Set<String>()
        for case let url as URL in sourceEnumerator where url.pathExtension == "swift" {
            let source = try String(contentsOf: url, encoding: .utf8)
            for rawLine in source.split(separator: "\n") {
                let line = String(rawLine)
                guard let marker = line.range(of: "ruleId: \"") else { continue }
                let remainder = line[marker.upperBound...]
                guard let quote = remainder.firstIndex(of: "\"") else { continue }
                let literal = String(remainder[..<quote])
                guard let family = expectedPrefixes.first(where: {
                    literal.hasPrefix($0)
                }) else { continue }
                observedPrefixes.insert(family)
                #expect(ResponseEngine.isAdvisoryOnlyRuleID(literal),
                        "Production advisory emitter bypasses policy: \(literal)")
            }
        }
        #expect(observedPrefixes == automaticEmitterPrefixes,
                "Production advisory emitters and boundary families drifted")

        // Passive visibility survives; every mutating action is denied unless
        // it takes the explicit pending-only path tested above.
        #expect(!ResponseEngine.mutatesHost(.log))
        #expect(!ResponseEngine.mutatesHost(.notify))
        #expect(!ResponseEngine.mutatesHost(.escalateNotification))
        #expect(ResponseEngine.mutatesHost(.kill))
        #expect(ResponseEngine.mutatesHost(.quarantine))
        #expect(ResponseEngine.mutatesHost(.script))
        #expect(ResponseEngine.mutatesHost(.blockNetwork))
    }
}
