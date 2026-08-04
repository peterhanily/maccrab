import Foundation
import Testing
@testable import MacCrabApp

@Suite("LLM Settings application truth")
struct LLMSettingsApplicationTruthTests {
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

    @Test("Queue admission cannot reuse an older matching heartbeat")
    func queuedWriteIsPendingUntilNewerHeartbeat() {
        let requested = LLMEngineConfiguration(
            enabled: true,
            provider: "ollama",
            model: "qwen3:8b"
        )
        let queuedAt = Date(timeIntervalSince1970: 200)
        #expect(!LLMSettingsApplicationTruth.heartbeatConfirms(
            requested: requested,
            queuedAt: queuedAt,
            reported: requested,
            heartbeatWrittenAt: Date(timeIntervalSince1970: 199),
            heartbeatIsStale: false
        ))
        #expect(LLMSettingsApplicationTruth.heartbeatConfirms(
            requested: requested,
            queuedAt: queuedAt,
            reported: requested,
            heartbeatWrittenAt: Date(timeIntervalSince1970: 201),
            heartbeatIsStale: false
        ))
    }

    @Test("Fresh confirmation requires exact enabled provider and model state")
    func confirmationIsExactAndFresh() {
        let requested = LLMEngineConfiguration(
            enabled: true,
            provider: "openai",
            model: "gpt-5-mini"
        )
        let wrongModel = LLMEngineConfiguration(
            enabled: true,
            provider: "openai",
            model: "gpt-4o-mini"
        )
        #expect(!LLMSettingsApplicationTruth.heartbeatConfirms(
            requested: requested,
            queuedAt: nil,
            reported: wrongModel,
            heartbeatWrittenAt: Date(),
            heartbeatIsStale: false
        ))
        #expect(!LLMSettingsApplicationTruth.heartbeatConfirms(
            requested: requested,
            queuedAt: nil,
            reported: requested,
            heartbeatWrittenAt: Date(),
            heartbeatIsStale: true
        ))
        #expect(!LLMSettingsApplicationTruth.heartbeatConfirms(
            requested: requested,
            queuedAt: nil,
            reported: nil,
            heartbeatWrittenAt: nil,
            heartbeatIsStale: false
        ))
    }

    @Test("Disabled state is confirmed without invented provider metadata")
    func disabledConfirmationIgnoresOmittedProviderAndModel() {
        let requested = LLMEngineConfiguration(
            enabled: false,
            provider: "claude",
            model: "claude-sonnet-4-6"
        )
        let reported = LLMEngineConfiguration(enabled: false, provider: "", model: "")
        #expect(LLMSettingsApplicationTruth.heartbeatConfirms(
            requested: requested,
            queuedAt: nil,
            reported: reported,
            heartbeatWrittenAt: Date(),
            heartbeatIsStale: false
        ))
    }

    @Test("Queue failure cannot mutate applied status or become pending")
    func failureBranchReturnsBeforePendingState() throws {
        let settings = try source("Sources/MacCrabApp/Views/SettingsView.swift")
        let queueGuard = try #require(settings.range(
            of: "guard V2DaemonControl.sendLLMConfig(engineConfig) else"
        ))
        let pendingAssignment = try #require(settings.range(
            of: "llmConfigRequestQueuedAt = queuedAt",
            range: queueGuard.upperBound..<settings.endIndex
        ))
        let failureBranch = settings[queueGuard.lowerBound..<pendingAssignment.lowerBound]
        #expect(failureBranch.contains("settings.llmEngineConfigQueueFailed"))
        #expect(failureBranch.contains("return"))
        #expect(!settings.contains("appState.llmStatus.isConfigured ="))
        #expect(!settings.contains("appState.llmStatus.provider ="))
    }

    @Test("Control API documents queue-only success and UI states pending truth")
    func controlAndCopyDoNotEquateWriteWithApplication() throws {
        let control = try source("Sources/MacCrabApp/V2/V2DaemonControl.swift")
        let settings = try source("Sources/MacCrabApp/Views/SettingsView.swift")
        let appState = try source("Sources/MacCrabApp/AppState.swift")
        #expect(control.contains("It does NOT"))
        #expect(control.contains("must wait for a newer engine heartbeat"))
        #expect(settings.contains("Pending engine application"))
        #expect(settings.contains("Saved or queued settings do not prove application"))
        #expect(settings.contains("MacCrab sends no Internet egress for this loopback endpoint"))
        #expect(!settings.contains("Running locally. No data leaves your machine."))
        #expect(appState.contains("let inlineLLM = json[\"llm\"]"))
        #expect(appState.contains("richJSON[\"llm\"]"))
        #expect(!appState.contains("MACCRAB_LLM_PROVIDER"))
        #expect(!appState.contains("llmStatus.isConfigured = llmConfigured"))
    }
}
