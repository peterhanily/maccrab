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
        "maccrab.sdr_device.sdr_device",
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

    // MARK: - v1.19.0 (S7-8): rule-count consistency, Option A

    /// Pin the built-in detection count. The public 483 figure (Sigma rules)
    /// is a SEPARATE class; the app's Detection card and About string label
    /// the built-ins explicitly ("483 rules + 46 built-in detections") so a
    /// user never sees a bare Sigma+built-in sum (~529) contradicting 483.
    /// If a built-in is added/removed, update release.json `builtins`, the
    /// app card label, and bump this expectation — prerelease-check asserts
    /// the release.json side agrees with this catalog.
    @Test("BuiltinRuleCatalog.all.count is pinned at 46 (Option A)")
    func builtinCountPinned() {
        #expect(BuiltinRuleCatalog.all.count == 46)
    }

    /// The public Sigma total (436 single + 41 sequence + 6 graph = 483) is
    /// the composition surfaced on the website, README badge, and About
    /// string. Cross-check the pinned constants against the actual Rules/
    /// tree so a rule added without updating the published figure fails here.
    @Test("Detection-card composition math: 436 + 41 + 6 = 483 Sigma, +46 built-in")
    func sigmaCompositionMath() {
        let single = 436, sequence = 41, graph = 6
        let sigmaTotal = single + sequence + graph
        #expect(sigmaTotal == 483)
        #expect(sigmaTotal + BuiltinRuleCatalog.all.count == 529,
                "Sigma + built-in sum — the figure the app card must NOT show bare")

        // Cross-check the pinned constants against the on-disk Rules/ tree
        // (single = .yml outside sequences/ + graph/, sequence = sequences/*.yml,
        // graph = graph/*.json). Drift here means the published 483 is stale.
        let projectDir = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()   // Tests/MacCrabCoreTests
            .deletingLastPathComponent()   // Tests
            .deletingLastPathComponent()   // project root
        let rules = projectDir.appendingPathComponent("Rules")
        func count(in sub: String, ext: String, recursive: Bool) -> Int {
            let dir = rules.appendingPathComponent(sub)
            guard let en = FileManager.default.enumerator(
                at: dir, includingPropertiesForKeys: nil,
                options: recursive ? [] : [.skipsSubdirectoryDescendants]
            ) else { return 0 }
            return en.compactMap { $0 as? URL }.filter { $0.pathExtension == ext }.count
        }
        let seqOnDisk = count(in: "sequences", ext: "yml", recursive: false)
        let graphOnDisk = count(in: "graph", ext: "json", recursive: false)
        // Single = every .yml under Rules/ minus the sequence .yml files
        // (graph rules are .json, so they don't count toward the .yml total).
        let allYml = count(in: "", ext: "yml", recursive: true)
        let singleOnDisk = allYml - seqOnDisk
        #expect(singleOnDisk == single, "single-event rule count drifted: on-disk \(singleOnDisk) vs pinned \(single)")
        #expect(seqOnDisk == sequence, "sequence rule count drifted: on-disk \(seqOnDisk) vs pinned \(sequence)")
        #expect(graphOnDisk == graph, "graph rule count drifted: on-disk \(graphOnDisk) vs pinned \(graph)")
    }
}
