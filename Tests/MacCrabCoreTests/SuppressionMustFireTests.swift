// SuppressionMustFireTests.swift
// v1.20 review carve-out: a BROAD operator allowlist (.rule / .path / .host —
// "trust this rule / process / host") must NOT silence a must-fire CRITICAL
// detection (active C2 / credential theft). Only a narrow, rule-specific
// .rulePath / .ruleHash entry can, so explicit false-positive management still
// works while a general allowlist can't accidentally hide a live attack.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("Suppression: must-fire critical carve-out")
struct SuppressionMustFireTests {

    private func makeMgr() throws -> (SuppressionManager, String) {
        let dir = NSTemporaryDirectory() + "maccrab_supp_mustfire_\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        return (SuppressionManager(dataDir: dir), dir)
    }

    private func match(_ id: String, _ severity: Severity, _ techniques: [String]) -> RuleMatch {
        RuleMatch(ruleId: id, ruleName: id, severity: severity,
                  description: "test", mitreTechniques: techniques)
    }

    @Test("broad .path allowlist does NOT silence a critical C2 (t1095) detection")
    func broadPathCantSilenceC2() async throws {
        let (mgr, dir) = try makeMgr()
        defer { try? FileManager.default.removeItem(atPath: dir) }

        _ = await mgr.add(Suppression(scope: .path("/bin/bash"), source: .ui,
                                      reason: "trust this shell generally"))
        let c2 = match("reverse_shell_devtcp", .critical, ["attack.t1095"])

        // Match-aware check refuses the broad scope for a must-fire critical…
        #expect(!(await mgr.isSuppressed(match: c2, processPath: "/bin/bash")))
        // …even though the plain (scope-blind) check would have silenced it.
        #expect(await mgr.isSuppressed(ruleId: "reverse_shell_devtcp", processPath: "/bin/bash"))
    }

    @Test("broad .rule allowlist does NOT silence a critical credential-theft (t1555) detection")
    func broadRuleCantSilenceCredTheft() async throws {
        let (mgr, dir) = try makeMgr()
        defer { try? FileManager.default.removeItem(atPath: dir) }

        _ = await mgr.add(Suppression(scope: .rule("keychain_dump"), source: .cli,
                                      reason: "too noisy"))
        let theft = match("keychain_dump", .critical, ["attack.t1555.001"])
        #expect(!(await mgr.isSuppressed(match: theft, processPath: "/usr/bin/security")))
    }

    @Test("narrow .rulePath allowlist STILL silences a must-fire critical (explicit FP management)")
    func narrowRulePathStillHonored() async throws {
        let (mgr, dir) = try makeMgr()
        defer { try? FileManager.default.removeItem(atPath: dir) }

        _ = await mgr.add(Suppression(
            scope: .rulePath(ruleId: "reverse_shell_devtcp", path: "/opt/vendor/agent"),
            source: .cli, reason: "known vendor false positive"))
        let c2 = match("reverse_shell_devtcp", .critical, ["attack.t1095"])
        // Narrow, rule-specific intent is honored.
        #expect(await mgr.isSuppressed(match: c2, processPath: "/opt/vendor/agent"))
    }

    @Test("broad .path allowlist STILL silences ordinary noise (not must-fire critical)")
    func broadPathStillSilencesOrdinaryNoise() async throws {
        let (mgr, dir) = try makeMgr()
        defer { try? FileManager.default.removeItem(atPath: dir) }

        _ = await mgr.add(Suppression(scope: .path("/usr/local/bin/vendor"), source: .ui,
                                      reason: "trusted vendor agent"))
        // medium-severity C2 → carve-out is critical-only, so suppression applies.
        let medium = match("noisy_net", .medium, ["attack.t1095"])
        #expect(await mgr.isSuppressed(match: medium, processPath: "/usr/local/bin/vendor"))
        // critical but NOT a C2 / credential-theft technique → not must-fire.
        let otherCrit = match("some_persistence", .critical, ["attack.t1547"])
        #expect(await mgr.isSuppressed(match: otherCrit, processPath: "/usr/local/bin/vendor"))
    }

    @Test("scope.isBroad classifies the general vs rule-specific scopes")
    func scopeBroadnessClassification() {
        #expect(SuppressionScope.rule("x").isBroad)
        #expect(SuppressionScope.path("/x").isBroad)
        #expect(SuppressionScope.host("h").isBroad)
        #expect(!SuppressionScope.rulePath(ruleId: "x", path: "/y").isBroad)
        #expect(!SuppressionScope.ruleHash(ruleId: "x", sha256: "abc").isBroad)
    }
}
