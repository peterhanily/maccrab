// CampaignDetectorFPRegressionTests.swift
//
// Regression harness for the v1.6.4 field FPs: coordinated-attack
// campaigns firing on single-alert-with-multi-tactic events (csrutil
// tagged both discovery + defense_evasion), and kill-chain campaigns
// firing on Sparkle's own Autoupdate binary during a legitimate update.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("CampaignDetector FP regression")
struct CampaignDetectorFPRegressionTests {

    private func csrutilAlert(tactics: Set<String>, pid: Int = 1001) -> CampaignDetector.AlertSummary {
        .init(
            ruleId: "csrutil.status",
            ruleTitle: "SIP Status Queried via csrutil",
            severity: .medium,
            processPath: "/usr/bin/csrutil",
            pid: pid,
            tactics: tactics
        )
    }

    @Test("Single alert with two tactic tags does NOT trigger coordinated attack")
    func singleAlertTwoTacticsSilent() async {
        let detector = CampaignDetector()
        // Simulate the v1.6.3 bug: one csrutil alert carrying BOTH
        // attack.discovery AND attack.defense_evasion tags. The old
        // tactic-counter saw "2 tactics from PID 1001" and emitted a
        // "Coordinated Attack from single process" campaign. Fixed in
        // v1.6.4 by requiring ≥2 distinct ruleIds before counting.
        let campaigns = await detector.processAlert(
            csrutilAlert(tactics: ["attack.discovery", "attack.defense_evasion"])
        )
        let coordinated = campaigns.filter { $0.type == .coordinatedAttack }
        #expect(coordinated.isEmpty)
    }

    @Test("Two distinct alerts, two tactics, one PID triggers coordinated attack")
    func twoDistinctAlertsTriggerCoordinated() async {
        let detector = CampaignDetector()
        // Counter-test: two genuinely different rules firing on the same
        // process within the window SHOULD produce coordinated-attack.
        // Proves the gate doesn't make the detector useless.
        _ = await detector.processAlert(
            .init(ruleId: "discovery.rule_a", ruleTitle: "A",
                  severity: .medium, processPath: "/tmp/bad", pid: 9000,
                  tactics: ["attack.discovery"])
        )
        let campaigns = await detector.processAlert(
            .init(ruleId: "defense_evasion.rule_b", ruleTitle: "B",
                  severity: .medium, processPath: "/tmp/bad", pid: 9000,
                  tactics: ["attack.defense_evasion"])
        )
        let coordinated = campaigns.filter { $0.type == .coordinatedAttack }
        #expect(!coordinated.isEmpty)
    }

    // v1.17.4: an AI tool querying the keychain (`security find-generic-
    // password`) tripped auth_brute_force + wifi_password_extraction on the
    // same security pid → 2 tactics → a false CRITICAL/HIGH coordinated
    // attack (the live "Claude Code = coordinated_attack" FP). The campaign
    // guard suppresses it when every rule is a low keychain/sudo single-event
    // approximation AND the activity is AI-attributed.
    @Test("AI-attributed keychain breadcrumbs do NOT form a coordinated attack")
    func aiKeychainNotCoordinated() async {
        let detector = CampaignDetector()
        _ = await detector.processAlert(
            .init(ruleId: "d1a2b3c4-0448-4000-a000-000000000448", ruleTitle: "Keychain Unlock",
                  severity: .low, processPath: "/usr/bin/security", pid: 4242,
                  tactics: ["attack.credential_access"], aiTool: "claude_code"))
        let campaigns = await detector.processAlert(
            .init(ruleId: "d1a2b3c4-0501-4000-a000-000000000501", ruleTitle: "Wi-Fi Password",
                  severity: .low, processPath: "/usr/bin/security", pid: 4242,
                  tactics: ["attack.credential_access", "attack.wireless"], aiTool: "claude_code"))
        #expect(campaigns.filter { $0.type == .coordinatedAttack }.isEmpty)
    }

    @Test("Guard is scoped: same keychain rules WITHOUT AI attribution still form a campaign")
    func nonAiKeychainStillCoordinated() async {
        let detector = CampaignDetector()
        // v1.19.0: the rc.3 severity floor now excludes LOW alerts from the
        // coordinated-attack counter regardless of AI attribution (the floor
        // generalizes the older AI-only keychain-breadcrumb guard; the LOW
        // behavior is covered by devRuntimeLowMediumNotCoordinated). This test
        // keeps proving the AI-keychain guard is SCOPED to AI by lifting the
        // (non-AI) keychain rules to MEDIUM — above the floor, so absent AI
        // attribution they still correlate into a campaign.
        _ = await detector.processAlert(
            .init(ruleId: "d1a2b3c4-0448-4000-a000-000000000448", ruleTitle: "Keychain Unlock",
                  severity: .medium, processPath: "/usr/bin/security", pid: 7000,
                  tactics: ["attack.credential_access"]))
        let campaigns = await detector.processAlert(
            .init(ruleId: "d1a2b3c4-0501-4000-a000-000000000501", ruleTitle: "Wi-Fi Password",
                  severity: .medium, processPath: "/usr/bin/security", pid: 7000,
                  tactics: ["attack.credential_access", "attack.wireless"]))
        #expect(!campaigns.filter { $0.type == .coordinatedAttack }.isEmpty)
    }

    @Test("Sparkle Autoupdate path is allowlisted from coordinated attack")
    func sparkleAutoupdateSilent() async {
        let detector = CampaignDetector()
        // Even two distinct rules firing on Sparkle's Autoupdate binary
        // should not produce a coordinated-attack — legitimate updater.
        _ = await detector.processAlert(
            .init(ruleId: "defense_evasion.code_sig_check", ruleTitle: "A",
                  severity: .medium,
                  processPath: "/Users/x/Library/Caches/com.maccrab.app/org.sparkle-project.Sparkle/Installation/aB/cD/MacCrab.app/Contents/Frameworks/Sparkle.framework/Versions/B/Autoupdate",
                  pid: 8000,
                  tactics: ["attack.defense_evasion"])
        )
        let campaigns = await detector.processAlert(
            .init(ruleId: "persistence.plist_write", ruleTitle: "B",
                  severity: .medium,
                  processPath: "/Users/x/Library/Caches/com.maccrab.app/org.sparkle-project.Sparkle/Installation/aB/cD/MacCrab.app/Contents/Frameworks/Sparkle.framework/Versions/B/Autoupdate",
                  pid: 8000,
                  tactics: ["attack.persistence"])
        )
        let coordinated = campaigns.filter { $0.type == .coordinatedAttack }
        #expect(coordinated.isEmpty)
    }

    @Test("GoogleUpdater path is allowlisted from coordinated attack")
    func googleUpdaterSilent() async {
        let detector = CampaignDetector()
        _ = await detector.processAlert(
            .init(ruleId: "discovery.mdm_check", ruleTitle: "A",
                  severity: .medium,
                  processPath: "/Users/x/Library/Application Support/Google/GoogleUpdater/148.0/GoogleUpdater.app/Contents/MacOS/GoogleUpdater",
                  pid: 7001,
                  tactics: ["attack.discovery"])
        )
        let campaigns = await detector.processAlert(
            .init(ruleId: "defense_evasion.xattr", ruleTitle: "B",
                  severity: .medium,
                  processPath: "/Users/x/Library/Application Support/Google/GoogleUpdater/148.0/GoogleUpdater.app/Contents/MacOS/GoogleUpdater",
                  pid: 7001,
                  tactics: ["attack.defense_evasion"])
        )
        let coordinated = campaigns.filter { $0.type == .coordinatedAttack }
        #expect(coordinated.isEmpty)
    }

    @Test("Kill chain requires 4 tactics (raised from 3)")
    func killChainThreeTacticsSilent() async {
        let detector = CampaignDetector()
        // 3 distinct medium-severity alerts, 3 different tactics, same
        // user's machine — the pre-v1.6.4 trip pattern. With the
        // threshold at 4, this now stays silent.
        _ = await detector.processAlert(
            .init(ruleId: "credential.a", ruleTitle: "cred", severity: .medium,
                  processPath: "/usr/bin/security", pid: 100,
                  tactics: ["attack.credential_access"])
        )
        _ = await detector.processAlert(
            .init(ruleId: "discovery.a", ruleTitle: "disco", severity: .medium,
                  processPath: "/usr/bin/find", pid: 101,
                  tactics: ["attack.discovery"])
        )
        let campaigns = await detector.processAlert(
            .init(ruleId: "exfil.a", ruleTitle: "exfil", severity: .medium,
                  processPath: "/usr/bin/curl", pid: 102,
                  tactics: ["attack.exfiltration"])
        )
        let killChains = campaigns.filter { $0.type == .killChain }
        #expect(killChains.isEmpty)
    }

    // MARK: - v1.19 (S1-T4) trust-weighted campaign inputs
    //
    // LOW/MEDIUM trusted-subject or agent-lineage alerts are excluded from
    // kill-chain / coordinated-attack tactic-counting (the FP class minted on
    // swiftpm-testing-helper / Xcode helpers / agents ~every 2h). HIGH/CRITICAL
    // trusted/agent alerts STILL feed — slow-burn abuse of trusted-signed or
    // agent tooling is exactly what campaign correlation is for.

    @Test("S1-T4: LOW/MEDIUM trusted-subject alerts do NOT mint a coordinated attack")
    func lowMedTrustedNotCoordinated() async {
        let detector = CampaignDetector()
        // Two distinct MEDIUM rules on the same trusted (notarized) helper pid,
        // spanning two tactics. Pre-T4 this minted a HIGH coordinated_attack.
        _ = await detector.processAlert(
            .init(ruleId: "rule.a", ruleTitle: "A", severity: .medium,
                  processPath: "/Applications/Xcode.app/Contents/Developer/usr/bin/swiftpm-testing-helper",
                  pid: 5500, tactics: ["attack.discovery"], isTrustedSubject: true))
        let campaigns = await detector.processAlert(
            .init(ruleId: "rule.b", ruleTitle: "B", severity: .medium,
                  processPath: "/Applications/Xcode.app/Contents/Developer/usr/bin/swiftpm-testing-helper",
                  pid: 5500, tactics: ["attack.defense_evasion"], isTrustedSubject: true))
        #expect(campaigns.filter { $0.type == .coordinatedAttack }.isEmpty)
    }

    @Test("S1-T4: LOW/MEDIUM agent-lineage alerts do NOT mint a coordinated attack")
    func lowMedAgentNotCoordinated() async {
        let detector = CampaignDetector()
        _ = await detector.processAlert(
            .init(ruleId: "rule.a", ruleTitle: "A", severity: .medium,
                  processPath: "/usr/bin/curl", pid: 5600,
                  tactics: ["attack.discovery"], aiTool: "claude_code"))
        let campaigns = await detector.processAlert(
            .init(ruleId: "rule.b", ruleTitle: "B", severity: .medium,
                  processPath: "/usr/bin/curl", pid: 5600,
                  tactics: ["attack.command_and_control"], aiTool: "claude_code"))
        #expect(campaigns.filter { $0.type == .coordinatedAttack }.isEmpty)
    }

    @Test("S1-T4: HIGH trusted-subject alerts STILL feed the coordinated-attack counter")
    func highTrustedStillCoordinated() async {
        let detector = CampaignDetector()
        // Slow-burn abuse of a trusted-signed binary at HIGH severity is exactly
        // what campaign correlation is for — it must NOT be excluded.
        _ = await detector.processAlert(
            .init(ruleId: "rule.a", ruleTitle: "A", severity: .high,
                  processPath: "/Applications/Trusted.app/Contents/MacOS/tool",
                  pid: 5700, tactics: ["attack.credential_access"], isTrustedSubject: true))
        let campaigns = await detector.processAlert(
            .init(ruleId: "rule.b", ruleTitle: "B", severity: .high,
                  processPath: "/Applications/Trusted.app/Contents/MacOS/tool",
                  pid: 5700, tactics: ["attack.exfiltration"], isTrustedSubject: true))
        #expect(!campaigns.filter { $0.type == .coordinatedAttack }.isEmpty)
    }

    @Test("S1-T4: LOW/MEDIUM trusted alerts excluded from kill-chain tactic count")
    func lowMedTrustedExcludedFromKillChain() async {
        let detector = CampaignDetector()
        // 4 distinct MEDIUM tactics, ALL on trusted subjects → would reach the
        // 4-tactic kill-chain floor pre-T4, but every contributing alert is
        // LOW/MEDIUM trusted, so none count → no kill chain. (Order avoids any
        // 2-tactic combo so the only path to a campaign is the 4-tactic floor,
        // which this filter prevents.)
        let tactics = ["attack.credential_access", "attack.discovery",
                       "attack.persistence", "attack.collection"]
        var allCampaigns: [CampaignDetector.Campaign] = []
        for (i, t) in tactics.enumerated() {
            allCampaigns += await detector.processAlert(
                .init(ruleId: "trusted.\(i)", ruleTitle: "t\(i)", severity: .medium,
                      processPath: "/Applications/App.app/Contents/MacOS/helper\(i)",
                      pid: 6000 + i, tactics: [t], isTrustedSubject: true))
        }
        #expect(allCampaigns.filter { $0.type == .killChain }.isEmpty)
    }

    @Test("S1-T4: HIGH trusted alerts STILL feed the kill-chain tactic count")
    func highTrustedStillKillChain() async {
        let detector = CampaignDetector()
        // The credential+persistence+C2 chain, all HIGH trusted alerts. HIGH/
        // CRITICAL trusted alerts must still feed — slow-burn intrusion via a
        // trusted-signed binary is the whole point of campaign correlation.
        // Collect across all calls: the chain can fire as soon as the tactics
        // accumulate (and dedup then suppresses later same-type campaigns).
        let tactics = ["attack.credential_access", "attack.persistence",
                       "attack.command_and_control", "attack.discovery"]
        var allCampaigns: [CampaignDetector.Campaign] = []
        for (i, t) in tactics.enumerated() {
            allCampaigns += await detector.processAlert(
                .init(ruleId: "trusted.\(i)", ruleTitle: "t\(i)", severity: .high,
                      processPath: "/Applications/App.app/Contents/MacOS/helper\(i)",
                      pid: 6100 + i, tactics: [t], isTrustedSubject: true))
        }
        #expect(!allCampaigns.filter { $0.type == .killChain }.isEmpty)
    }

    // MARK: - v1.19.0 (rc.3 live finding): coordinated-attack severity floor
    //
    // CAMP-995FA329: a benign Cloudflare wrangler dev runtime (workerd) minted a
    // CRITICAL "Persistent Threat Actor" from a LOW "node_modules exec" + a
    // MEDIUM "curl|exec" alert spanning 3 tactics on one PID. The coordinated-
    // attack tactic counter lacked the severity floor (and benign-process /
    // usb / crypto-token excludes) that checkKillChain already has; now mirrored.

    @Test("rc.3: a benign dev runtime's LOW+MEDIUM alerts do NOT mint a CRITICAL coordinated attack (workerd FP)")
    func devRuntimeLowMediumNotCoordinated() async {
        let detector = CampaignDetector()
        let workerd = "/Users/x/node_modules/@cloudflare/workerd-darwin-arm64/bin/workerd"
        _ = await detector.processAlert(
            .init(ruleId: "exec.node_modules", ruleTitle: "Binary Executed Directly from node_modules Directory",
                  severity: .low, processPath: workerd, pid: 51409,
                  tactics: ["attack.execution", "attack.initial_access"]))
        let campaigns = await detector.processAlert(
            .init(ruleId: "exec.curl_pipe", ruleTitle: "Curl/Wget Fetch Followed By Execution From User-Writable Path",
                  severity: .medium, processPath: workerd, pid: 51409,
                  tactics: ["attack.execution", "attack.command_and_control", "attack.initial_access"]))
        // The LOW alert is below the .medium floor and drops out, leaving one
        // distinct rule → the existing >=2-ruleIds gate rejects → no campaign.
        #expect(campaigns.filter { $0.type == .coordinatedAttack }.isEmpty)
    }

    @Test("rc.3: severity floor preserves a genuine medium+ multi-rule coordinated attack")
    func genuineMediumMultiRuleStillCoordinated() async {
        let detector = CampaignDetector()
        // Two DISTINCT medium rules on one non-benign pid spanning 3 tactics —
        // a real coordinated attack must STILL mint CRITICAL after the floor.
        _ = await detector.processAlert(
            .init(ruleId: "exec.a", ruleTitle: "A", severity: .medium,
                  processPath: "/tmp/implant", pid: 52000,
                  tactics: ["attack.execution"]))
        let campaigns = await detector.processAlert(
            .init(ruleId: "c2.b", ruleTitle: "B", severity: .medium,
                  processPath: "/tmp/implant", pid: 52000,
                  tactics: ["attack.command_and_control", "attack.initial_access"]))
        let coordinated = campaigns.filter { $0.type == .coordinatedAttack }
        #expect(!coordinated.isEmpty)
        #expect(coordinated.first?.severity == .critical)  // 3 tactics → CRITICAL Persistent Threat Actor
    }
}
