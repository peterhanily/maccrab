// AINetworkSandboxTests.swift
// Guards the v1.18 RC live-test fix: AI-tool connections to legit APIs (Anthropic,
// GitHub) were flagged as "unapproved IP" because destinationHostname is nil at the
// connection event and the IP isn't in wellKnownCloudPrefixes. The EventLoop fix
// recovers the domain from the DNS reverse cache; these tests pin the sandbox
// property that fix relies on — a recovered approved domain clears even when its
// IP is in no prefix list, while genuine unknowns/unapproved hosts still fire.
import Testing
import Foundation
@testable import MacCrabCore

@Suite("AI Network Sandbox: DNS-correlation FP fix")
struct AINetworkSandboxDNSCorrelationTests {
    // Non-existent config path → defaults only, deterministic across machines.
    private func sandbox() -> AINetworkSandbox {
        AINetworkSandbox(customConfigPath: "/nonexistent/maccrab-test-ainetsb.json")
    }

    @Test("approved domain clears even when its IP is in no prefix list (the fix)")
    func approvedDomainClearsRegardlessOfIP() async {
        // 3.123.149.45 (AWS) is NOT in wellKnownCloudPrefixes — observed live as a
        // GitHub/Anthropic endpoint firing an 'unapproved IP' FP. With the domain
        // recovered from DNS the allowlist clears it.
        let v = await sandbox().checkConnection(
            aiToolName: "claude_code", processPid: 1234, processPath: "/usr/bin/gh",
            destinationIP: "3.123.149.45", destinationPort: 443, destinationDomain: "github.com")
        #expect(v == nil, "approved domain must clear despite a non-prefix IP")
    }

    @Test("same IP with NO domain still fires — documents why DNS recovery matters")
    func ipOnlyUnknownStillFires() async {
        let v = await sandbox().checkConnection(
            aiToolName: "claude_code", processPid: 1234, processPath: "/usr/bin/gh",
            destinationIP: "3.123.149.45", destinationPort: 443, destinationDomain: nil)
        #expect(v != nil, "an unknown IP with no domain context still violates (pre-recovery state)")
    }

    @Test("a genuinely unapproved recovered domain still fires (no blanket-allow)")
    func unapprovedDomainStillFires() async {
        let v = await sandbox().checkConnection(
            aiToolName: "claude_code", processPid: 1234, processPath: "/usr/bin/gh",
            destinationIP: "203.0.113.50", destinationPort: 443, destinationDomain: "evil-exfil.example")
        #expect(v != nil, "an unapproved recovered domain must still violate")
    }
}
