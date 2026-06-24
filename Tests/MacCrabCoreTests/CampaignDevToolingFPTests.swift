// CampaignDevToolingFPTests.swift
//
// v1.19.1 (HN-audit) regression harness for two campaign false-positive
// classes the runtime audit found on the launch audience's own dev boxes:
//   1. A SINGLE alert carrying multiple MITRE tactic tags was titled a
//      multi-stage "Malware Installation Chain" / "Full Kill Chain".
//   2. Benign developer tooling (esbuild / workerd in node_modules, the
//      Swift/Xcode toolchain, Homebrew, AI coding agents) minted CRITICAL
//      "Persistent Threat Actor" coordinated-attack campaigns at HIGH severity.
// Plus the must-fire counter-tests proving the carve-outs are scoped: genuine
// multi-alert chains and CRITICAL dev-tool compromises still escalate.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("CampaignDetector dev-tooling FP regression (v1.19.1)")
struct CampaignDevToolingFPTests {

    private func alert(_ ruleId: String, _ path: String, _ tactics: Set<String>,
                       severity: Severity = .high,
                       pid: Int = 5000) -> CampaignDetector.AlertSummary {
        .init(ruleId: ruleId, ruleTitle: ruleId, severity: severity,
              processPath: path, pid: pid, tactics: tactics)
    }

    // MARK: - isDevelopmentToolingPath classifier

    @Test("isDevelopmentToolingPath matches dev runtimes, not system/temp paths")
    func devToolingClassifier() {
        #expect(CampaignDetector.isDevelopmentToolingPath("/Users/x/proj/node_modules/.bin/esbuild"))
        #expect(CampaignDetector.isDevelopmentToolingPath("/Applications/Xcode.app/Contents/Developer/usr/bin/swiftpm-testing-helper"))
        #expect(CampaignDetector.isDevelopmentToolingPath("/opt/homebrew/bin/wrangler"))
        #expect(CampaignDetector.isDevelopmentToolingPath("/Users/x/.local/share/claude/bin/claude"))
        #expect(CampaignDetector.isDevelopmentToolingPath("/Users/x/.cargo/bin/cargo"))
        // Not dev tooling:
        #expect(!CampaignDetector.isDevelopmentToolingPath("/usr/bin/curl"))
        #expect(!CampaignDetector.isDevelopmentToolingPath("/tmp/evil"))
        #expect(!CampaignDetector.isDevelopmentToolingPath(nil))
    }

    // MARK: - FP 1: single alert with many tactics is not a kill chain

    @Test("A single alert carrying 5 tactics does NOT mint a kill chain")
    func singleAlertManyTacticsNoKillChain() async {
        let detector = CampaignDetector()
        // Pre-fix: one alert tagged with credential_access+persistence+c2(+more)
        // satisfied the tactic count and was titled "Full Kill Chain" CRITICAL
        // from ONE event. A chain is multi-STAGE — it needs ≥2 contributing
        // alerts.
        let campaigns = await detector.processAlert(
            alert("malware.multi", "/tmp/evil", [
                "attack.initial_access", "attack.execution",
                "attack.persistence", "attack.credential_access",
                "attack.command_and_control",
            ])
        )
        #expect(campaigns.filter { $0.type == .killChain }.isEmpty)
        #expect(campaigns.filter { $0.type == .coordinatedAttack }.isEmpty)
    }

    @Test("Two distinct alerts spanning two tactics DO mint a kill chain (must-fire)")
    func twoAlertsStillKillChain() async {
        // Counter-test: the ≥2-contributing-alert floor must not blind the
        // detector to a genuine two-stage chain across distinct alerts.
        let detector = CampaignDetector(minTacticsForKillChain: 2)
        _ = await detector.processAlert(
            alert("cred.dump", "/tmp/evil", ["attack.credential_access"]))
        let campaigns = await detector.processAlert(
            alert("persist.plist", "/tmp/evil", ["attack.persistence"]))
        #expect(!campaigns.filter { $0.type == .killChain }.isEmpty)
    }

    // MARK: - FP 2: sub-CRITICAL dev tooling does not coordinate

    @Test("HIGH dev-tooling alerts do NOT mint a coordinated attack (esbuild/node_modules)")
    func subCriticalDevToolingSilent() async {
        let detector = CampaignDetector()
        // Two distinct HIGH rules on a node_modules binary spanning 3 tactics on
        // one PID — exactly the audit's "esbuild is a Persistent Threat Actor".
        let path = "/Users/x/proj/node_modules/.bin/esbuild"
        _ = await detector.processAlert(
            alert("exec.node_spawn", path, ["attack.execution"], pid: 6001))
        _ = await detector.processAlert(
            alert("net.curl_pipe", path, ["attack.command_and_control"], pid: 6001))
        let campaigns = await detector.processAlert(
            alert("disc.env", path, ["attack.discovery"], pid: 6001))
        #expect(campaigns.filter { $0.type == .coordinatedAttack }.isEmpty)
        #expect(campaigns.filter { $0.type == .killChain }.isEmpty)
    }

    @Test("CRITICAL dev-tooling compromise STILL escalates (safety valve, must-fire)")
    func criticalDevToolingStillFeeds() async {
        let detector = CampaignDetector()
        // A genuinely compromised dev tool (real CRITICAL alerts, not a
        // 404-package guess) must still escalate — the carve-out is scoped to
        // sub-CRITICAL severity only. The SAME three-alert esbuild scenario that
        // is silently suppressed at HIGH (subCriticalDevToolingSilent above)
        // must produce a campaign at CRITICAL. (Whether it surfaces as a
        // kill-chain or coordinated-attack depends on the pre-existing
        // dedup ordering; the point is it is NOT dropped.)
        let path = "/Users/x/proj/node_modules/.bin/esbuild"
        _ = await detector.processAlert(
            alert("cred.theft", path, ["attack.credential_access"], severity: .critical, pid: 6002))
        _ = await detector.processAlert(
            alert("persist.launchd", path, ["attack.persistence"], severity: .critical, pid: 6002))
        let campaigns = await detector.processAlert(
            alert("c2.beacon", path, ["attack.command_and_control"], severity: .critical, pid: 6002))
        #expect(!campaigns.isEmpty)
    }
}
