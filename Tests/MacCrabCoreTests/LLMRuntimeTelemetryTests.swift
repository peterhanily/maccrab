// LLMRuntimeTelemetryTests.swift
// MacCrabCoreTests
//
// Exact conservation tests for the content-free LLM runtime ledger. These
// exercise every terminal outcome plus a live concurrency snapshot; a green
// happy-path test alone would not prove a bounded production feature.

import Foundation
import Testing
@testable import MacCrabCore

private actor TelemetryGateBackend: LLMBackend {
    let providerName = "TelemetryGate"
    private var waiters: [CheckedContinuation<String?, Never>] = []
    private(set) var calls = 0

    func isAvailable() async -> Bool { true }

    func complete(
        systemPrompt: String,
        userPrompt: String,
        maxTokens: Int,
        temperature: Double
    ) async -> String? {
        calls += 1
        return await withCheckedContinuation { continuation in
            waiters.append(continuation)
        }
    }

    func resumeAll(returning response: String?) {
        let pending = waiters
        waiters.removeAll(keepingCapacity: true)
        for continuation in pending {
            continuation.resume(returning: response)
        }
    }
}

@Suite("LLM runtime telemetry conservation")
struct LLMRuntimeTelemetryTests {
    private var repositoryRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    private func source(_ relativePath: String) throws -> String {
        try String(
            contentsOf: repositoryRoot.appendingPathComponent(relativePath),
            encoding: .utf8
        )
    }

    private func cloudConfig(strict: Bool = false) -> LLMConfig {
        var config = LLMConfig()
        config.provider = .claude
        config.sanitizeForCloud = true
        config.strictSanitize = strict
        return config
    }

    private func eventually(
        maxYields: Int = 10_000,
        _ predicate: @escaping @Sendable () async -> Bool
    ) async -> Bool {
        for _ in 0..<maxYields {
            if await predicate() { return true }
            await Task.yield()
        }
        return await predicate()
    }

    @Test("Success and cache hit conserve and attribute bytes without content labels")
    func successCacheAndFeatureAttribution() async {
        let backend = RecordingBackend(responses: ["okay"])
        let service = LLMService(
            backend: backend,
            config: cloudConfig(),
            minInterval: 0
        )

        #expect(await service.query(
            systemPrompt: "sys",
            userPrompt: "user",
            useCache: true,
            feature: .threatHunt
        )?.cached == false)
        #expect(await service.query(
            systemPrompt: "sys",
            userPrompt: "user",
            useCache: true,
            feature: .threatHunt
        )?.cached == true)

        let snapshot = await service.runtimeTelemetrySnapshot()
        let totals = snapshot.totals
        #expect(snapshot.schemaVersion == 1)
        #expect(snapshot.perFeature.map(\.feature) == LLMRuntimeFeature.allCases)
        #expect(Set(snapshot.perFeature.map(\.feature)).count == LLMRuntimeFeature.allCases.count)
        #expect(totals.requestedTotal == 2)
        #expect(totals.currentInFlight == 0)
        #expect(totals.admittedBackendTotal == 1)
        #expect(totals.backendCallsStartedTotal == 1)
        #expect(totals.outcomes.success == 1)
        #expect(totals.outcomes.cacheHit == 1)
        #expect(totals.outcomes.total == 2)
        #expect(totals.requestLatencyBuckets.map(\.completedRequests).reduce(0, +) == 2)
        #expect(totals.requestedInputUTF8BytesTotal == 14)
        #expect(totals.backendInputUTF8BytesTotal == 7)
        #expect(totals.backendOutputUTF8BytesTotal == 4)
        #expect(totals.returnedOutputUTF8BytesTotal == 8)
        #expect(totals.estimatedBackendInputTokensTotal == 2)
        #expect(totals.estimatedBackendOutputTokensTotal == 1)
        #expect(totals.estimatedReturnedOutputTokensTotal == 2)
        #expect(totals.conservationMaintained)
        #expect(totals.backendAdmissionConservationMaintained)

        let hunt = snapshot.counters(for: .threatHunt)
        #expect(hunt?.requestedTotal == 2)
        #expect(hunt?.outcomes.success == 1)
        #expect(hunt?.outcomes.cacheHit == 1)
        #expect(snapshot.counters(for: .unspecified)?.requestedTotal == 0)
        #expect(await backend.calls == 1)
    }

    @Test("Backend failures and the open-circuit rejection are distinct and conserving")
    func circuitAccounting() async {
        let backend = RecordingBackend(responses: [nil, nil, nil, "unused"])
        let service = LLMService(
            backend: backend,
            config: cloudConfig(),
            minInterval: 0
        )

        for _ in 0..<4 {
            _ = await service.query(
                systemPrompt: "system",
                userPrompt: "request",
                useCache: false,
                feature: .alertInvestigation
            )
        }

        let counters = await service.runtimeTelemetrySnapshot().totals
        #expect(counters.requestedTotal == 4)
        #expect(counters.admittedBackendTotal == 3)
        #expect(counters.backendCallsStartedTotal == 3)
        #expect(counters.outcomes.backendFailure == 3)
        #expect(counters.outcomes.circuitRejection == 1)
        #expect(counters.outcomes.total == 4)
        #expect(counters.conservationMaintained)
        #expect(counters.backendAdmissionConservationMaintained)
        #expect(await backend.calls == 3)
    }

    @Test("A half-open recovery attempt has its own conserving counters")
    func circuitRecoveryProbeAccounting() async {
        let backend = RecordingBackend(responses: [nil, nil, nil, "recovered"])
        let service = LLMService(
            backend: backend,
            config: cloudConfig(),
            minInterval: 0,
            rateLimitClock: .live,
            circuitResetInterval: 0
        )

        for index in 0..<4 {
            _ = await service.query(
                systemPrompt: "system",
                userPrompt: "request-\(index)",
                useCache: false,
                feature: .campaignInvestigation
            )
        }

        let counters = await service.runtimeTelemetrySnapshot().totals
        #expect(counters.circuitRecoveryProbesStartedTotal == 1)
        #expect(counters.currentCircuitRecoveryProbes == 0)
        #expect(counters.circuitRecoveryProbesSucceededTotal == 1)
        #expect(counters.circuitRecoveryProbesDidNotRecoverTotal == 0)
        #expect(counters.circuitRecoveryConservationMaintained)
        #expect(counters.outcomes.backendFailure == 3)
        #expect(counters.outcomes.success == 1)
    }

    @Test("Semantic validation is separate from transport outcomes and fixed by feature")
    func downstreamValidationAccounting() async {
        let service = LLMService(
            backend: RecordingBackend(responses: []),
            config: cloudConfig(),
            minInterval: 0
        )

        let investigationToken = await service.beginDownstreamValidation(
            feature: .alertInvestigation
        )
        let live = await service.runtimeTelemetrySnapshot().totals.downstreamValidation
        #expect(live.operationsStartedTotal == 1)
        #expect(live.currentOperations == 1)
        #expect(live.conservationMaintained)

        #expect(await service.recordDownstreamValidationRetry(
            token: investigationToken
        ))
        let wrongFeatureToken = LLMSemanticOperationToken(
            id: investigationToken.id,
            feature: .campaignInvestigation
        )
        #expect(await service.finishDownstreamValidation(
            token: wrongFeatureToken,
            outcome: .finalRejection
        ) == false)
        #expect(await service.finishDownstreamValidation(
            token: investigationToken,
            outcome: .accepted
        ))
        #expect(await service.finishDownstreamValidation(
            token: investigationToken,
            outcome: .finalRejection
        ) == false, "A semantic operation must finish exactly once")

        let campaignToken = await service.beginDownstreamValidation(
            feature: .campaignInvestigation
        )
        #expect(await service.finishDownstreamValidation(
            token: campaignToken,
            outcome: .finalRejection
        ))

        let snapshot = await service.runtimeTelemetrySnapshot()
        #expect(snapshot.totals.requestedTotal == 0)
        #expect(snapshot.totals.outcomes.total == 0)
        #expect(snapshot.totals.downstreamValidation.operationsStartedTotal == 2)
        #expect(snapshot.totals.downstreamValidation.currentOperations == 0)
        #expect(snapshot.totals.downstreamValidation.accepted == 1)
        #expect(snapshot.totals.downstreamValidation.retryRequested == 1)
        #expect(snapshot.totals.downstreamValidation.finalRejection == 1)
        #expect(snapshot.totals.downstreamValidation.conservationMaintained)
        let investigation = snapshot.counters(for: .alertInvestigation)
        #expect(investigation?.downstreamValidation.operationsStartedTotal == 1)
        #expect(investigation?.downstreamValidation.currentOperations == 0)
        #expect(investigation?.downstreamValidation.accepted == 1)
        #expect(investigation?.downstreamValidation.retryRequested == 1)
        #expect(investigation?.downstreamValidation.finalRejection == 0)
        #expect(snapshot.counters(for: .campaignInvestigation)?
            .downstreamValidation.finalRejection == 1)
    }

    @Test("Feature attribution is compile-required and current production calls do not drift")
    func featureAttributionDoesNotDrift() throws {
        let serviceSource = try source("Sources/MacCrabCore/LLM/LLMService.swift")
        #expect(!serviceSource.contains("feature: LLMRuntimeFeature ="),
                "Every request must choose a fixed-cardinality feature at compile time")

        let expected: [String: [String]] = [
            "Sources/MacCrabAgentKit/DaemonTimers.swift": ["securityPosture"],
            "Sources/MacCrabAgentKit/EventLoop.swift": [
                "campaignInvestigation", "activeDefense",
            ],
            "Sources/MacCrabAgentKit/MonitorTasks.swift": ["sdrContext", "edrContext"],
            "Sources/MacCrabCore/Detection/AlertClusterService.swift": ["alertClusterRationale"],
            "Sources/MacCrabCore/Detection/RuleGenerator.swift": ["ruleGeneration"],
            "Sources/MacCrabCore/Detection/ThreatHunter.swift": ["threatHunt"],
            "Sources/MacCrabCore/Enrichment/IntentClassifier.swift": ["intentClassification"],
            "Sources/MacCrabCore/LLM/LLMInvestigator.swift": [
                "alertInvestigation", "alertInvestigation", "campaignInvestigation",
            ],
            "Sources/maccrabctl/ReportCommand.swift": ["incidentReport"],
        ]

        for (path, expectedFeatures) in expected {
            let contents = try source(path)
            #expect(Self.featuresOnLLMCalls(in: contents) == expectedFeatures,
                    "LLM call attribution drifted in \(path)")
        }

        let sourcesRoot = repositoryRoot.appendingPathComponent("Sources")
        let enumerator = try #require(
            FileManager.default.enumerator(
                at: sourcesRoot,
                includingPropertiesForKeys: nil
            )
        )
        for case let file as URL in enumerator where file.pathExtension == "swift" {
            let contents = try String(contentsOf: file, encoding: .utf8)
            #expect(!contents.contains("feature: .unspecified"),
                    "Production code must not explicitly evade feature attribution: \(file.path)")
        }
    }

    private static func featuresOnLLMCalls(in source: String) -> [String] {
        let markers = [".query(", ".commentary(", ".queryWithExtendedThinking("]
        var starts: [String.Index] = []
        for marker in markers {
            var search = source.startIndex..<source.endIndex
            while let range = source.range(of: marker, range: search) {
                starts.append(range.lowerBound)
                search = range.upperBound..<source.endIndex
            }
        }
        starts.sort()
        return starts.compactMap { start in
            let nextStart = starts.first(where: { $0 > start }) ?? source.endIndex
            let segment = source[start..<nextStart]
            guard let feature = segment.range(of: "feature: .") else { return nil }
            let valueStart = feature.upperBound
            let valueEnd = segment[valueStart...].firstIndex(where: {
                !$0.isLetter && !$0.isNumber && $0 != "_"
            }) ?? segment.endIndex
            return String(segment[valueStart..<valueEnd])
        }
    }

    @Test("Strict privacy refusal and UTF-8 response oversize have explicit outcomes")
    func privacyAndOversizeAccounting() async {
        let privacyBackend = RecordingBackend(responses: ["must-not-run"])
        let privacyService = LLMService(
            backend: privacyBackend,
            config: cloudConfig(strict: true),
            minInterval: 0
        )
        let residualSecret = "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0Kk"
        #expect(LLMSanitizer.hasResidualSensitiveContent(residualSecret))
        #expect(await privacyService.query(
            systemPrompt: "system",
            userPrompt: residualSecret,
            useCache: false,
            feature: .intentClassification
        ) == nil)
        let privacy = await privacyService.runtimeTelemetrySnapshot().totals
        #expect(privacy.outcomes.privacyRejection == 1)
        #expect(privacy.admittedBackendTotal == 0)
        #expect(privacy.backendCallsStartedTotal == 0)
        #expect(privacy.conservationMaintained)
        #expect(privacy.backendAdmissionConservationMaintained)
        #expect(await privacyBackend.calls == 0)

        let oversized = String(repeating: "🦀", count: 13_000) // 52,000 UTF-8 bytes
        let oversizeBackend = RecordingBackend(responses: [oversized])
        let oversizeService = LLMService(
            backend: oversizeBackend,
            config: cloudConfig(),
            minInterval: 0
        )
        #expect(await oversizeService.query(
            systemPrompt: "s",
            userPrompt: "u",
            useCache: false,
            feature: .ruleGeneration
        ) == nil)
        let oversize = await oversizeService.runtimeTelemetrySnapshot().totals
        #expect(oversize.outcomes.responseOversize == 1)
        #expect(oversize.backendOutputUTF8BytesTotal == 52_000)
        #expect(oversize.returnedOutputUTF8BytesTotal == 0)
        #expect(oversize.conservationMaintained)
        #expect(oversize.backendAdmissionConservationMaintained)
    }

    @Test("Extended-thinking requests use the same feature and conservation ledger")
    func extendedThinkingAccounting() async {
        let backend = RecordingBackend(responses: ["deep result"])
        let service = LLMService(
            backend: backend,
            config: cloudConfig(),
            minInterval: 0
        )

        #expect(await service.queryWithExtendedThinking(
            systemPrompt: "deep system",
            userPrompt: "deep user",
            thinkingBudgetTokens: 8_000,
            maxOutputTokens: 4_096,
            feature: .campaignInvestigation
        )?.response == "deep result")

        let snapshot = await service.runtimeTelemetrySnapshot()
        #expect(snapshot.totals.requestedTotal == 1)
        #expect(snapshot.totals.outcomes.success == 1)
        #expect(snapshot.totals.conservationMaintained)
        #expect(snapshot.totals.backendAdmissionConservationMaintained)
        #expect(snapshot.counters(for: .campaignInvestigation)?.outcomes.success == 1)
    }

    @Test("A five-call burst exposes four live admissions and sheds exactly one")
    func concurrentAdmissionConservation() async {
        let backend = TelemetryGateBackend()
        let service = LLMService(
            backend: backend,
            config: cloudConfig(),
            minInterval: 0
        )

        let tasks = (0..<5).map { index in
            Task {
                await service.query(
                    systemPrompt: "system",
                    userPrompt: "request-\(index)",
                    useCache: false,
                    feature: .ruleGeneration
                )
            }
        }

        #expect(await eventually {
            let snapshot = await service.runtimeTelemetrySnapshot().totals
            return await backend.calls == 4
                && snapshot.outcomes.admissionShed == 1
                && snapshot.currentInFlight == 4
        })

        let live = await service.runtimeTelemetrySnapshot().totals
        #expect(live.requestedTotal == 5)
        #expect(live.outcomes.total == 1)
        #expect(live.currentInFlight == 4)
        #expect(live.admittedBackendTotal == 4)
        #expect(live.currentAdmittedBackendRequests == 4)
        #expect(live.backendCallsStartedTotal == 4)
        #expect(live.conservationMaintained)
        #expect(live.backendAdmissionConservationMaintained)

        await backend.resumeAll(returning: "ok")
        for task in tasks { _ = await task.value }

        let complete = await service.runtimeTelemetrySnapshot().totals
        #expect(complete.requestedTotal == 5)
        #expect(complete.currentInFlight == 0)
        #expect(complete.currentAdmittedBackendRequests == 0)
        #expect(complete.outcomes.success == 4)
        #expect(complete.outcomes.admissionShed == 1)
        #expect(complete.outcomes.total == 5)
        #expect(complete.conservationMaintained)
        #expect(complete.backendAdmissionConservationMaintained)
    }

    @Test("Cancellation while rate-limited completes the admitted-work ledger")
    func cancellationAccounting() async {
        let backend = RecordingBackend(responses: ["first"])
        let service = LLMService(
            backend: backend,
            config: cloudConfig(),
            minInterval: 60,
            rateLimitClock: LLMRateLimitClock(
                now: { 0 },
                sleep: { _ in
                    try await Task.sleep(nanoseconds: 60_000_000_000)
                }
            )
        )

        #expect(await service.query(
            systemPrompt: "system",
            userPrompt: "first",
            useCache: false,
            feature: .incidentReport
        ) != nil)

        let cancelled = Task {
            await service.query(
                systemPrompt: "system",
                userPrompt: "cancelled",
                useCache: false,
                feature: .incidentReport
            )
        }
        #expect(await eventually {
            let counters = await service.runtimeTelemetrySnapshot().totals
            return counters.currentInFlight == 1
                && counters.currentAdmittedBackendRequests == 1
        })
        cancelled.cancel()
        #expect(await cancelled.value == nil)

        let counters = await service.runtimeTelemetrySnapshot().totals
        #expect(counters.requestedTotal == 2)
        #expect(counters.admittedBackendTotal == 2)
        #expect(counters.backendCallsStartedTotal == 1)
        #expect(counters.cancellationsAfterAdmissionTotal == 1)
        #expect(counters.outcomes.success == 1)
        #expect(counters.outcomes.cancellation == 1)
        #expect(counters.outcomes.total == 2)
        #expect(counters.conservationMaintained)
        #expect(counters.backendAdmissionConservationMaintained)
        #expect(await backend.calls == 1)
    }

    @Test("LLM Sigma candidates require a concrete bounded detection policy")
    func ruleCandidateAdmissionIsStructural() {
        let valid = Self.validCandidateYAML
        #expect(RuleGenerator.validateLLMCandidate(valid))

        let commentOnly = """
        # title: fake
        # id: 00000000-0000-0000-0000-000000000001
        # status: experimental
        # logsource:
        # detection:
        # falsepositives:
        # level: high
        """
        #expect(!RuleGenerator.validateLLMCandidate(commentOnly))
        #expect(!RuleGenerator.validateLLMCandidate(valid.replacingOccurrences(
            of: "selection and not filter_system",
            with: "all of them"
        )))
        #expect(!RuleGenerator.validateLLMCandidate(valid.replacingOccurrences(
            of: "- '/tmp/stage'",
            with: "- '*'"
        )))
        #expect(!RuleGenerator.validateLLMCandidate(valid.replacingOccurrences(
            of: "Image|endswith:",
            with: "Image|re:"
        )))
        #expect(!RuleGenerator.validateLLMCandidate(valid.replacingOccurrences(
            of: "    category: process_creation",
            with: "category: process_creation"
        )))
        #expect(!RuleGenerator.validateLLMCandidate(valid.replacingOccurrences(
            of: "    selection:",
            with: "    selection: &shared"
        )))
    }

    @Test("Validated rule persistence conserves semantics and sanitizes its filename")
    func ruleCandidateSemanticAccounting() async {
        let backend = RecordingBackend(responses: [Self.validCandidateYAML])
        let service = LLMService(
            backend: backend,
            config: cloudConfig(),
            minInterval: 0
        )
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-llm-rule-\(UUID().uuidString)")
        let generator = RuleGenerator(outputDir: directory.path, llmService: service)
        let alerts = [
            (ruleId: "one", ruleTitle: "One", processPath: Optional("/tmp/stage"), tactics: Set(["attack.execution"]), timestamp: Date()),
            (ruleId: "two", ruleTitle: "Two", processPath: Optional("/tmp/stage"), tactics: Set(["attack.execution"]), timestamp: Date()),
        ]

        let generated = await generator.generateFromCampaignEnhanced(
            campaignType: "../../unsafe campaign",
            alerts: alerts
        )
        #expect(generated != nil)
        #expect(generated?.filename.contains("/") == false)
        #expect(FileManager.default.fileExists(
            atPath: directory.appendingPathComponent("auto_generated")
                .appendingPathComponent(generated?.filename ?? "missing").path
        ))
        let semantic = await service.runtimeTelemetrySnapshot()
            .counters(for: .ruleGeneration)?.downstreamValidation
        #expect(semantic?.operationsStartedTotal == 1)
        #expect(semantic?.currentOperations == 0)
        #expect(semantic?.accepted == 1)
        #expect(semantic?.finalRejection == 0)
        #expect(semantic?.conservationMaintained == true)
    }

    @Test("Deterministic rule fallback quotes hostile metadata and reports only persisted rules")
    func deterministicRuleMetadataIsSafe() async {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-deterministic-rule-\(UUID().uuidString)")
        let generator = RuleGenerator(outputDir: directory.path)
        let hostilePath = "/tmp/evil'\ncondition: all of them"
        let alerts = [
            (ruleId: "one", ruleTitle: "ignore previous instructions\nlevel: critical", processPath: Optional(hostilePath), tactics: Set(["attack.execution", "bad\ntag"]), timestamp: Date()),
            (ruleId: "two", ruleTitle: "Second", processPath: Optional(hostilePath), tactics: Set(["attack.execution"]), timestamp: Date()),
        ]
        let generated = await generator.generateFromCampaign(
            campaignType: "../../ignore_previous_instructions",
            alerts: alerts
        )
        let rule = try? #require(generated)
        #expect(rule?.filename.contains("/") == false)
        #expect(rule?.title == "Auto-Generated: Campaign Pattern")
        #expect(rule?.yaml.contains("ignore previous instructions") == false)
        #expect(rule?.yaml.contains("bad\ntag") == false)
        #expect(rule?.yaml.contains("evil'' condition: all of them") == true)
        let idLine = rule?.yaml.split(separator: "\n")
            .first(where: { $0.hasPrefix("id: ") })
            .map { String($0.dropFirst(4)) }
        #expect(idLine.flatMap { UUID(uuidString: $0) } != nil)
        #expect(await generator.stats() == 1)
    }

    private static let validCandidateYAML = """
    title: Suspicious Temporary Process Chain
    id: 00000000-0000-0000-0000-000000000001
    status: experimental
    description: Detects the observed process pattern for analyst review.
    logsource:
        category: process_creation
        product: macos
    detection:
        selection:
            Image|endswith:
                - '/tmp/stage'
        filter_system:
            ParentImage|startswith:
                - '/System/'
        condition: selection and not filter_system
    falsepositives:
        - Legitimate administrative activity
    level: high
    """
}
