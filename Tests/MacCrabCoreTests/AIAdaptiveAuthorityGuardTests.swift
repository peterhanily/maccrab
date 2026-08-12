import Foundation
import Testing

@Suite("AI adaptive-authority source guards")
struct AIAdaptiveAuthorityGuardTests {
    private var repositoryRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    @Test("Behavior scoring cannot silently learn from unversioned dismissals")
    func behaviorWeightsRemainDeterministic() throws {
        let source = try String(contentsOf: repositoryRoot
            .appendingPathComponent("Sources/MacCrabCore/Detection/BehaviorScoring.swift"))
        let catalog = try String(contentsOf: repositoryRoot
            .appendingPathComponent("Sources/MacCrabCore/ModuleStatus.swift"))
        let documentation = try String(contentsOf: repositoryRoot
            .appendingPathComponent("docs/MODULES.md"))

        #expect(!source.contains("recordSuppression(indicatorNames:"))
        #expect(!source.contains("recordInvestigation(indicatorNames:"))
        #expect(!source.contains("adjustedWeights"))
        #expect(!source.contains("indicatorFeedback"))
        #expect(!catalog.contains("feedback-adjusted weights"))
        #expect(!documentation.contains("feedback-adjusted weights"))
        #expect(source.contains("let weight = Self.weights[name] ?? 3.0"))
    }

    @Test("Alert suppression cannot mutate severity or response authority")
    func suppressionIsNotFalsePositiveTraining() throws {
        func source(_ relativePath: String) throws -> String {
            try String(contentsOf: repositoryRoot.appendingPathComponent(relativePath),
                       encoding: .utf8)
        }
        let deduplicator = try source(
            "Sources/MacCrabCore/Detection/AlertDeduplicator.swift"
        )
        let eventLoop = try source("Sources/MacCrabAgentKit/EventLoop.swift")
        let monitors = try source("Sources/MacCrabAgentKit/MonitorTasks.swift")
        let timers = try source("Sources/MacCrabAgentKit/DaemonTimers.swift")
        let catalog = try source("Sources/MacCrabCore/ModuleStatus.swift")
        let modules = try source("docs/MODULES.md")

        for text in [deduplicator, eventLoop, monitors, timers] {
            #expect(!text.contains("effectiveSeverity("))
            #expect(!text.contains("recordDismissal("))
            #expect(!text.contains("prunePrcessedDismissals("))
        }
        #expect(!deduplicator.contains("dismissalCounts"))
        #expect(!timers.contains("label: \"feedback\""))
        #expect(eventLoop.contains("let effectiveSeverity = match.severity"))
        #expect(catalog.contains("no adaptive severity authority"))
        #expect(modules.contains("no adaptive severity authority"))
    }

    @Test("Model advice cannot replace deterministic intent or fabricate forecasts")
    func advisoryInferenceCannotAcquireDetectionAuthority() throws {
        let eventLoop = try String(
            contentsOf: repositoryRoot.appendingPathComponent(
                "Sources/MacCrabAgentKit/EventLoop.swift"
            ),
            encoding: .utf8
        )
        let promptBridge = try String(
            contentsOf: repositoryRoot.appendingPathComponent(
                "Sources/MacCrabCore/Enrichment/PromptIntentBridge.swift"
            ),
            encoding: .utf8
        )

        let deterministicStamp = try #require(eventLoop.range(of:
            "enrichedEvent.enrichments[\"IntentLabel\"] ="
        ))
        #expect(eventLoop.contains("result.label.rawValue"))
        let immutableBase = try #require(eventLoop.range(of:
            "let journalBaseEvent = enrichedEvent"
        ))
        #expect(deterministicStamp.lowerBound < immutableBase.lowerBound,
                "deterministic intent must be stamped before immutable journal admission")
        #expect(eventLoop.contains("IntentModelLabel"))
        #expect(eventLoop.contains("IntentModelDisagrees"))
        #expect(!eventLoop.contains("stampedLabel = refinement.label"))
        #expect(!eventLoop.contains("stampedConfidence = refinement.confidence"))
        #expect(!eventLoop.contains("label: \"sequence-forecast\""))
        #expect(!eventLoop.contains("ruleId: \"maccrab.counterfactual.\\("))
        #expect(!eventLoop.contains("ruleId: \"maccrab.predict.next-technique.\\("))
        #expect(promptBridge.contains("label: .slopsquat, confidence: 0.0"))
        #expect(promptBridge.contains("shadow only and not a safety verdict"))
    }
}
