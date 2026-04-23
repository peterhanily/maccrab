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
}
