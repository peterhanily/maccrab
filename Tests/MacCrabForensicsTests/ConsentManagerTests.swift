// ConsentManager — plan §10.5 / §10.8 policy verification.

import Foundation
import Testing
@testable import MacCrabForensics

@Suite("LoggingConsentManager — plan §10.5 policy")
struct LoggingConsentManagerTests {

    private func makeRequest(
        mode: ConsentMode,
        privacyClass: PrivacyClass = .metadata,
        aiContentAllowed: Bool = false,
        scheduledTrusted: Bool = false
    ) -> ConsentRequest {
        ConsentRequest(
            caseID: "case-test-\(UUID().uuidString.prefix(8))",
            caseName: "policy test",
            pluginID: "com.maccrab.forensics.fixture",
            pluginDisplayName: "Fixture",
            pluginType: .collector,
            mode: mode,
            caseAIContentAllowed: aiContentAllowed,
            caseScheduledTrusted: scheduledTrusted,
            highestEmittedPrivacyClass: privacyClass
        )
    }

    @Test("Interactive mode always grants (operator initiated)")
    func interactiveGrants() async throws {
        let mgr = LoggingConsentManager(sink: { _ in })
        let req = makeRequest(mode: .interactive)
        let decision = await mgr.decide(req)
        if case .granted = decision { } else { Issue.record("Expected .granted, got \(decision)") }
    }

    @Test("Scheduled default (scheduled_trusted=0) denies")
    func scheduledDefaultDenies() async throws {
        let mgr = LoggingConsentManager(sink: { _ in })
        let req = makeRequest(mode: .scheduled, scheduledTrusted: false)
        let decision = await mgr.decide(req)
        if case .denied(let reason) = decision {
            #expect(reason.contains("scheduled_trusted=0"))
        } else {
            Issue.record("Expected .denied, got \(decision)")
        }
    }

    @Test("Scheduled trusted (scheduled_trusted=1) auto-approves")
    func scheduledTrustedAutoApproves() async throws {
        let mgr = LoggingConsentManager(sink: { _ in })
        let req = makeRequest(mode: .scheduled, scheduledTrusted: true)
        let decision = await mgr.decide(req)
        if case .autoApproved = decision { } else { Issue.record("Expected .autoApproved, got \(decision)") }
    }

    @Test("MCP from agent + metadata-class plugin always grants")
    func mcpMetadataGrants() async throws {
        let mgr = LoggingConsentManager(sink: { _ in })
        let req = makeRequest(mode: .mcpFromAgent, privacyClass: .metadata)
        let decision = await mgr.decide(req)
        if case .granted = decision { } else { Issue.record("Expected .granted, got \(decision)") }
    }

    @Test("MCP from agent + non-metadata + ai_content_allowed=false denies (§10.8)")
    func mcpNonMetadataDenies() async throws {
        let mgr = LoggingConsentManager(sink: { _ in })
        let req = makeRequest(mode: .mcpFromAgent, privacyClass: .content, aiContentAllowed: false)
        let decision = await mgr.decide(req)
        if case .denied(let reason) = decision {
            #expect(reason.contains("maccrabctl case allow-ai --content"))
        } else {
            Issue.record("Expected .denied, got \(decision)")
        }
    }

    @Test("MCP from agent + non-metadata + ai_content_allowed=true grants")
    func mcpNonMetadataWithGrantGrants() async throws {
        let mgr = LoggingConsentManager(sink: { _ in })
        let req = makeRequest(mode: .mcpFromAgent, privacyClass: .personalComms, aiContentAllowed: true)
        let decision = await mgr.decide(req)
        if case .granted = decision { } else { Issue.record("Expected .granted, got \(decision)") }
    }

    @Test("Sink receives a log line per decide call")
    func sinkReceivesLog() async throws {
        var lines: [String] = []
        let mgr = LoggingConsentManager(sink: { lines.append($0) })
        let req = makeRequest(mode: .interactive)
        _ = await mgr.decide(req)
        #expect(lines.count >= 1)
        #expect(lines.first?.contains("mode=interactive") == true)
    }
}

@Suite("AlwaysAcceptConsentManager")
struct AlwaysAcceptConsentManagerTests {
    @Test("Grants any request regardless of mode / class / flags")
    func alwaysGrants() async throws {
        let mgr = AlwaysAcceptConsentManager()
        let req = ConsentRequest(
            caseID: "x",
            caseName: "x",
            pluginID: "x",
            pluginDisplayName: "x",
            pluginType: .collector,
            mode: .scheduled,
            caseAIContentAllowed: false,
            caseScheduledTrusted: false,
            highestEmittedPrivacyClass: .secret
        )
        let decision = await mgr.decide(req)
        if case .granted = decision { } else { Issue.record("Expected .granted, got \(decision)") }
    }
}
