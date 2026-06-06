// BuiltinCatalogCoverageTests.swift
// v1.18 — guards that every code-emitted maccrab.* alert id resolves to a
// BuiltinRuleCatalog entry (exact or via the longest-prefix family base used
// by AlertSink/BuiltinRuleSettings). Before v1.18 ~12 alert families
// (campaign, self-defense, pending-action, counterfactual, predict, prompt-
// intent, mcp.baseline-anomaly, correlator.network-convergence, forensic.*,
// scheduled, network beacons) emitted alerts that never appeared in the Rules
// view and couldn't be tuned. This test fails loudly if a dynamic emit family
// is added without a catalog entry, or an entry is removed.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("BuiltinRuleCatalog coverage (v1.18)")
struct BuiltinCatalogCoverageTests {

    /// Mirror of AlertSink/BuiltinRuleSettings longest-prefix resolution
    /// against the catalog: exact id, else the longest catalog id whose
    /// `id + "."` prefixes the emitted id.
    private func resolves(_ emitted: String) -> BuiltinRuleDefinition? {
        if let exact = BuiltinRuleCatalog.byId[emitted] { return exact }
        return BuiltinRuleCatalog.all
            .filter { emitted.hasPrefix($0.id + ".") }
            .max(by: { $0.id.count < $1.id.count })
    }

    /// Representative ids for every dynamic-suffix emit site in the engine.
    /// (Keep in sync with the `ruleId: "maccrab.…"` emit sites.)
    private static let emittedSamples = [
        "maccrab.campaign.kill_chain",
        "maccrab.campaign.coordinated_attack",
        "maccrab.self-defense.binary_modified",
        "maccrab.self-defense.rules_modified",
        "maccrab.pending-action.kill",
        "maccrab.counterfactual.e1f2a3b4-0001",
        "maccrab.predict.next-technique.e1f2a3b4-0001",
        "maccrab.prompt-intent.slopsquat",
        "maccrab.mcp.baseline-anomaly.cursor.server.added",
        "maccrab.correlator.network-convergence",
        "maccrab.correlator.cross-process",
        "maccrab.forensic.injected-library",
        "maccrab.forensic.hidden-process",
        "maccrab.forensic.crash-exploit-1234",
        "maccrab.forensic.power-anomaly",
        "maccrab.scheduled",
        "maccrab.deep.event-tap-keylogger",
        "maccrab.deep.crypto_token_extension",
        "maccrab.network.c2_beacon",
        "maccrab.network.doh-evasion",
        "maccrab.privacy.unexpected-camera",
        "maccrab.vuln.cve-2026-1234",
        "maccrab.usb.connected",
        "maccrab.browser.installed",
        "maccrab.ultrasonic.nuit",
        "maccrab.tempest.sdr-device",
        "maccrab.edr.remote-access",
        "maccrab.git.credential-helper",
        "maccrab.llm.behavior-analysis",
        "maccrab.llm.investigation-summary",
        // The hyphen→dot fix: the MCP family base must now govern these.
        "maccrab.ai-guard.mcp.credential",
        "maccrab.ai-guard.credential-access",
        "maccrab.threat-intel.ip-match",
    ]

    @Test("every dynamic-emit alert family resolves to a catalog entry")
    func everyEmitResolves() {
        for id in Self.emittedSamples {
            #expect(resolves(id) != nil, "no BuiltinRuleCatalog entry governs emitted id \(id)")
        }
    }

    @Test("v1.18 severity recalibration: dev-noisy AI-guard rules dropped to medium")
    func recalibratedSeverities() {
        #expect(BuiltinRuleCatalog.byId["maccrab.ai-guard.credential-access"]?.defaultSeverity == .medium)
        #expect(BuiltinRuleCatalog.byId["maccrab.ai-guard.boundary-violation"]?.defaultSeverity == .medium)
        #expect(BuiltinRuleCatalog.byId["maccrab.ai-guard.network-sandbox"]?.defaultSeverity == .medium)
        // Catalog display now matches the actual emit severity (was a stale .high).
        #expect(BuiltinRuleCatalog.byId["maccrab.clipboard.sensitive-data"]?.defaultSeverity == .medium)
        #expect(BuiltinRuleCatalog.byId["maccrab.edr"]?.defaultSeverity == .medium)
        // Confirmed-bad detections stay high.
        #expect(BuiltinRuleCatalog.byId["maccrab.notarization.cert-revoked"]?.defaultSeverity == .high)
        #expect(BuiltinRuleCatalog.byId["maccrab.threat-intel.ip-match"]?.defaultSeverity == .high)
    }

    @Test("no duplicate catalog ids")
    func noDuplicateIds() {
        let ids = BuiltinRuleCatalog.all.map(\.id)
        #expect(ids.count == Set(ids).count, "duplicate ids in BuiltinRuleCatalog")
    }
}
