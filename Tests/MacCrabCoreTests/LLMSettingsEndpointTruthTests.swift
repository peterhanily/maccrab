import Foundation
import Testing
@testable import MacCrabCore

@Suite("LLM Settings endpoint truth and atomic engine configuration")
struct LLMSettingsEndpointTruthTests {
    private var repositoryRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    private func source(_ relativePath: String) throws -> String {
        try String(contentsOf: repositoryRoot.appendingPathComponent(relativePath),
                   encoding: .utf8)
    }

    @Test("Privacy copy uses the same strict loopback parser as transport policy")
    func localPrivacyCannotUseSubstringHostChecks() throws {
        let settings = try source("Sources/MacCrabApp/Views/SettingsView.swift")
        #expect(settings.contains(
            "LoopbackEndpoint.isLoopback(urlString: llmOllamaURL)"
        ))
        #expect(!settings.contains("llmOllamaURL.contains(\"localhost\")"))
        #expect(!settings.contains("llmOllamaURL.contains(\"127.0.0.1\")"))
        #expect(!LoopbackEndpoint.isLoopback(
            urlString: "http://127.0.0.1.evil.com:11434"
        ))
        #expect(!LoopbackEndpoint.isLoopback(
            urlString: "http://localhost.evil.com:11434"
        ))
    }

    @Test("Remote approval is exact-endpoint-bound and reaches the root request")
    func remoteApprovalCannotFloatAcrossURLChanges() throws {
        let settings = try source("Sources/MacCrabApp/Views/SettingsView.swift")
        #expect(settings.contains("llmApprovedRemoteEndpoint == endpoint"))
        #expect(settings.contains("llmApprovedRemoteEndpoint = approved"))
        #expect(settings.contains("engineConfig[\"allow_remote_endpoint\"] = true"))
        #expect(settings.contains("guard currentRemoteEndpointIsApproved else"))
        #expect(settings.contains("guard V2DaemonControl.sendLLMConfig(engineConfig) else"))
    }

    @Test("Root rejects an unapproved remote request atomically")
    func rootCannotPartiallyApplyStaleEndpointConfiguration() throws {
        let timers = try source("Sources/MacCrabAgentKit/DaemonTimers.swift")
        let reject = try #require(timers.range(of: "let unapprovedRemoteKeys"))
        let abort = try #require(timers.range(
            of: "rejected entire request",
            range: reject.lowerBound..<timers.endIndex
        ))
        let merge = try #require(timers.range(
            of: "var sanitized: [String: Any] = [:]",
            range: abort.lowerBound..<timers.endIndex
        ))
        #expect(reject.lowerBound < abort.lowerBound)
        #expect(abort.lowerBound < merge.lowerBound)
        #expect(timers[reject.lowerBound..<merge.lowerBound].contains("return"))
    }
}
