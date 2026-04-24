// AgenticInvestigatorTests.swift
//
// Coverage for the v1.6.6 Agentic Investigation Loop. Real LLM
// round-trips are deferred to the integration tests; here we lock the
// pure-function pieces that are the fragile ones: report parsing,
// tool-call parameter extraction, and campaign formatting.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("AgenticInvestigator: report parsing")
struct InvestigatorReportParsingTests {

    @Test("Well-formed block parses verdict, summary, findings, recommend")
    func wellFormed() {
        let response = """
        VERDICT: malicious
        SUMMARY: Signs of active credential theft followed by outbound exfil.
        FINDING: Unsigned process read login.keychain-db
        FINDING: Same PID opened connections to 203.0.113.4
        RECOMMEND: Quarantine the host and capture memory image.
        """
        let parsed = AgenticInvestigator.parseReport(campaignId: "c1", response: response)
        #expect(parsed.verdict == .malicious)
        #expect(parsed.summary.contains("credential theft"))
        #expect(parsed.findings.count == 2)
        #expect(parsed.recommendedAction.contains("Quarantine"))
    }

    @Test("Markdown wrappers survive the parser")
    func markdownTolerated() {
        let response = """
        **VERDICT:** benign
        **SUMMARY:** Developer running csrutil status from terminal.
        - **FINDING:** Parent process is zsh under Terminal.app
        RECOMMEND: Suppress this rule+process pair.
        """
        let parsed = AgenticInvestigator.parseReport(campaignId: "c1", response: response)
        #expect(parsed.verdict == .benign)
        #expect(parsed.findings.count == 1)
    }

    @Test("Missing sections get safe defaults, not empty strings")
    func missingSections() {
        let parsed = AgenticInvestigator.parseReport(
            campaignId: "c1",
            response: "VERDICT: inconclusive"
        )
        #expect(parsed.verdict == .inconclusive)
        #expect(!parsed.summary.isEmpty, "Missing summary must fall back to a safe default")
        #expect(!parsed.recommendedAction.isEmpty, "Missing recommend must fall back to a safe default")
    }

    @Test("No verdict at all defaults to inconclusive")
    func noVerdict() {
        let parsed = AgenticInvestigator.parseReport(
            campaignId: "c1",
            response: "FINDING: something happened"
        )
        #expect(parsed.verdict == .inconclusive)
    }

    @Test("All four verdict values round-trip through the parser")
    func allVerdictsRoundTrip() {
        for verdict in InvestigationReport.Verdict.allCases {
            let response = """
            VERDICT: \(verdict.rawValue)
            SUMMARY: test
            RECOMMEND: test
            """
            let parsed = AgenticInvestigator.parseReport(campaignId: "c", response: response)
            #expect(parsed.verdict == verdict)
        }
    }
}

@Suite("AgenticInvestigator: tool-call routing")
struct InvestigatorToolCallTests {

    @Test("describe_rule call dispatches to the rule describer")
    func describeRuleDispatches() async {
        var askedRuleIds: [String] = []
        let fetchers = InvestigationContextFetchers(
            describeRule: { id in
                askedRuleIds.append(id)
                return "description of \(id)"
            }
        )
        let result = await AgenticInvestigator.handleToolCalls(
            response: "TOOL: describe_rule RULE_ID=ruleX\n",
            fetchers: fetchers
        )
        #expect(askedRuleIds == ["ruleX"])
        #expect(result.contains("description of ruleX"))
    }

    @Test("alert_descriptions call dispatches with comma-separated IDs")
    func alertDescriptionsDispatches() async {
        var askedIds: [String] = []
        let fetchers = InvestigationContextFetchers(
            alertDescriptions: { ids in
                askedIds = ids
                return Dictionary(uniqueKeysWithValues: ids.map { ($0, "desc-of-\($0)") })
            }
        )
        let result = await AgenticInvestigator.handleToolCalls(
            response: "TOOL: alert_descriptions RULE_IDS=a,b,c",
            fetchers: fetchers
        )
        #expect(askedIds == ["a", "b", "c"])
        #expect(result.contains("desc-of-a"))
        #expect(result.contains("desc-of-c"))
    }

    @Test("process_children call dispatches with the process path")
    func processChildrenDispatches() async {
        var askedPath: String?
        let fetchers = InvestigationContextFetchers(
            recentProcessChildren: { path in
                askedPath = path
                return ["git", "curl"]
            }
        )
        let result = await AgenticInvestigator.handleToolCalls(
            response: "TOOL: process_children PROCESS_PATH=/usr/bin/ssh",
            fetchers: fetchers
        )
        #expect(askedPath == "/usr/bin/ssh")
        #expect(result.contains("git"))
        #expect(result.contains("curl"))
    }

    @Test("Tool-call cap: no more than 5 dispatches per response")
    func toolCallCap() async {
        var calls = 0
        let fetchers = InvestigationContextFetchers(
            describeRule: { _ in calls += 1; return "x" }
        )
        let response = (0..<10).map { "TOOL: describe_rule RULE_ID=r\($0)" }.joined(separator: "\n")
        _ = await AgenticInvestigator.handleToolCalls(response: response, fetchers: fetchers)
        #expect(calls == 5, "Cap of 5 calls per round must be enforced — prevents runaway fan-out")
    }

    @Test("Non-tool lines are ignored")
    func nonToolLinesIgnored() async {
        var called = false
        let fetchers = InvestigationContextFetchers(
            describeRule: { _ in called = true; return "x" }
        )
        _ = await AgenticInvestigator.handleToolCalls(
            response: "Some narrative text\nNot a tool\nVERDICT: benign",
            fetchers: fetchers
        )
        #expect(!called)
    }

    @Test("Param extraction handles quoted values")
    func paramExtraction() {
        #expect(AgenticInvestigator.extractParam("describe_rule RULE_ID=foo", key: "RULE_ID") == "foo")
        #expect(AgenticInvestigator.extractParam("describe_rule RULE_ID=\"foo\"", key: "RULE_ID") == "foo")
        #expect(AgenticInvestigator.extractParam("missing", key: "RULE_ID") == nil)
    }

    // MARK: - v1.6.9 security hardening

    @Test("Param extraction rejects values longer than 256 chars")
    func paramLengthCap() {
        let long = String(repeating: "a", count: 300)
        #expect(AgenticInvestigator.extractParam("x RULE_ID=\(long)", key: "RULE_ID") == nil,
                "Long param must be rejected to prevent unbounded downstream queries")
    }

    @Test("isSafeRuleId allows UUID and dotted identifiers, rejects junk")
    func safeRuleIdContract() {
        // Accept
        #expect(AgenticInvestigator.isSafeRuleId("d1a2b3c4-0123-4000-a000-000000000123"))
        #expect(AgenticInvestigator.isSafeRuleId("maccrab.behavior.composite"))
        #expect(AgenticInvestigator.isSafeRuleId("rule_with_underscores"))
        // Reject
        #expect(!AgenticInvestigator.isSafeRuleId(""))
        #expect(!AgenticInvestigator.isSafeRuleId("rule with spaces"))
        #expect(!AgenticInvestigator.isSafeRuleId("../etc/passwd"))
        #expect(!AgenticInvestigator.isSafeRuleId("rule\nwith\nnewlines"))
        #expect(!AgenticInvestigator.isSafeRuleId("rule;DROP TABLE alerts"))
        #expect(!AgenticInvestigator.isSafeRuleId(String(repeating: "x", count: 200)))
    }

    @Test("isSafeProcessPath rejects path traversal, non-absolute, and control chars")
    func safeProcessPathContract() {
        // Accept
        #expect(AgenticInvestigator.isSafeProcessPath("/usr/bin/ps"))
        #expect(AgenticInvestigator.isSafeProcessPath("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"))
        // Reject
        #expect(!AgenticInvestigator.isSafeProcessPath("relative/path"))
        #expect(!AgenticInvestigator.isSafeProcessPath("/tmp/../etc/passwd"))
        #expect(!AgenticInvestigator.isSafeProcessPath("/path\0with\0null"))
        #expect(!AgenticInvestigator.isSafeProcessPath("/path\nwith\nnewline"))
        #expect(!AgenticInvestigator.isSafeProcessPath(""))
    }

    @Test("alert_descriptions caps rule-id list length")
    func alertDescriptionsCapped() async {
        var askedCount = 0
        let fetchers = InvestigationContextFetchers(
            alertDescriptions: { ids in
                askedCount = ids.count
                return [:]
            }
        )
        let hugeList = (0..<100).map { "rule\($0)" }.joined(separator: ",")
        _ = await AgenticInvestigator.handleToolCalls(
            response: "TOOL: alert_descriptions RULE_IDS=\(hugeList)",
            fetchers: fetchers
        )
        #expect(askedCount <= 20,
                "alert_descriptions must cap batch size to prevent LLM-driven amplification")
    }

    @Test("Malicious path in process_children is rejected")
    func maliciousPathRejected() async {
        var askedPath: String?
        let fetchers = InvestigationContextFetchers(
            recentProcessChildren: { path in
                askedPath = path
                return []
            }
        )
        _ = await AgenticInvestigator.handleToolCalls(
            response: "TOOL: process_children PROCESS_PATH=/tmp/../etc/passwd",
            fetchers: fetchers
        )
        #expect(askedPath == nil,
                "Path containing `..` must be rejected before reaching the fetcher")
    }

    @Test("Malicious rule ID in describe_rule is rejected")
    func maliciousRuleIdRejected() async {
        var askedId: String?
        let fetchers = InvestigationContextFetchers(
            describeRule: { id in
                askedId = id
                return nil
            }
        )
        _ = await AgenticInvestigator.handleToolCalls(
            response: "TOOL: describe_rule RULE_ID=;rm -rf /",
            fetchers: fetchers
        )
        #expect(askedId == nil,
                "Rule ID with semicolon/shell meta-chars must be rejected")
    }
}

@Suite("AgenticInvestigator: campaign formatting")
struct InvestigatorCampaignFormattingTests {

    private func sampleCampaign() -> CampaignDetector.Campaign {
        let alerts = [
            CampaignDetector.AlertSummary(
                ruleId: "cred.read", ruleTitle: "Credential file read",
                severity: .high, processPath: "/usr/bin/curl", pid: 999,
                tactics: ["attack.credential_access"]
            ),
            CampaignDetector.AlertSummary(
                ruleId: "exfil.net", ruleTitle: "Outbound to public IP",
                severity: .high, processPath: "/usr/bin/curl", pid: 999,
                tactics: ["attack.exfiltration"]
            ),
        ]
        return CampaignDetector.Campaign(
            id: "campaign-1",
            type: .killChain,
            severity: .high,
            title: "Possible credential exfil",
            description: "Two alerts in under 10 seconds on same PID",
            alerts: alerts,
            tactics: ["attack.credential_access", "attack.exfiltration"],
            timeSpanSeconds: 8.0,
            detectedAt: Date()
        )
    }

    @Test("Formatted campaign carries type, severity, tactics, and alerts")
    func formatted() {
        let out = AgenticInvestigator.formatCampaign(sampleCampaign())
        #expect(out.contains("kill_chain"))
        #expect(out.contains("attack.credential_access"))
        #expect(out.contains("/usr/bin/curl"))
        #expect(out.contains("Outbound to public IP"))
        #expect(out.contains("Credential file read"))
    }
}
