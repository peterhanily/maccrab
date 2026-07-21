// SequenceRuleProfileTests.swift
// v1.21.5 — F-04 rule-status PROFILE filter for SequenceEngine.loadRules(enabledStatuses:).
//
// Sequence rules previously BYPASSED the rule_profile gate entirely: DaemonSetup
// and the SIGHUP reload called loadRules(from:) with no status argument, so the
// 36 experimental sequence rules ran on default "stable" installs. loadRules
// gained an `enabledStatuses: Set<String>? = nil` parameter:
//
//   • nil (the default) → no filter: every rule loads. This is the legacy
//     behaviour, and it is what keeps the rest of the suite green.
//   • non-nil (e.g. ["stable"]) → a rule whose Sigma `status` is NOT in the set
//     is SKIPPED (not loaded). Unlike RuleEngine's present-but-disabled model,
//     SequenceEngine has no per-rule enable surface, so skipping is the filter.
//   • A rule with NO status key is grandfathered as "stable": compilers before
//     v1.21.5 didn't emit status for sequences, so a stale compiled_rules dir
//     would otherwise lose ALL sequences (including the stable ones) until the
//     operator recompiles.
//
// Fixtures are REAL compiled sequence rules (one status:stable + one
// status:experimental from /tmp/maccrab_v3/sequences) so the status field
// travels the true decode path, plus a stable rule with the status key
// stripped to model a pre-v1.21.5 compiled dir, plus a deprecated copy —
// deprecated is skipped unconditionally, under EVERY profile including nil.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("SequenceEngine: status-profile filter (F-04, v1.21.5)")
struct SequenceRuleProfileTests {

    private struct FixtureError: Error { let message: String }

    /// An isolated dir holding exactly four sequence rules: one real
    /// `status: stable`, one real `status: experimental`, a copy of the
    /// stable rule with the `status` key REMOVED (and a fresh id) to model a
    /// compiled dir produced by a pre-v1.21.5 compiler, and a copy with
    /// `status: deprecated` (a retired detection — must never load).
    private func makeProfileDir() throws -> (dir: URL, stableID: String, experimentalID: String, noStatusID: String, deprecatedID: String) {
        ensureRulesCompiled()
        let src = URL(fileURLWithPath: "/tmp/maccrab_v3/sequences")
        let files = try FileManager.default
            .contentsOfDirectory(at: src, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "json" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }

        func firstRule(status wanted: String) throws -> (url: URL, id: String, obj: [String: Any]) {
            for f in files {
                guard let obj = try? JSONSerialization.jsonObject(with: Data(contentsOf: f)) as? [String: Any],
                      (obj["status"] as? String) == wanted,
                      let id = obj["id"] as? String else { continue }
                return (f, id, obj)
            }
            throw FixtureError(message: "no compiled sequence rule with status=\(wanted) found in \(src.path)")
        }

        let stable = try firstRule(status: "stable")
        let experimental = try firstRule(status: "experimental")

        // Third fixture: the stable rule minus its status key, under a new id.
        var noStatusObj = stable.obj
        noStatusObj.removeValue(forKey: "status")
        let noStatusID = stable.id + "_no_status_key"
        noStatusObj["id"] = noStatusID

        // Fourth fixture (v1.21.5 audit): the stable rule marked deprecated.
        // A retired detection must not run under ANY profile — the engine's
        // unconditional `rule.enabled = true` would otherwise revive it when
        // the nil ("all") path skips status filtering.
        var deprecatedObj = stable.obj
        deprecatedObj["status"] = "deprecated"
        let deprecatedID = stable.id + "_deprecated"
        deprecatedObj["id"] = deprecatedID

        let dst = FileManager.default.temporaryDirectory
            .appendingPathComponent("seq-profile-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dst, withIntermediateDirectories: true)
        try FileManager.default.copyItem(at: stable.url, to: dst.appendingPathComponent(stable.url.lastPathComponent))
        try FileManager.default.copyItem(at: experimental.url, to: dst.appendingPathComponent(experimental.url.lastPathComponent))
        try JSONSerialization.data(withJSONObject: noStatusObj)
            .write(to: dst.appendingPathComponent("no_status_key.json"))
        try JSONSerialization.data(withJSONObject: deprecatedObj)
            .write(to: dst.appendingPathComponent("deprecated.json"))
        return (dst, stable.id, experimental.id, noStatusID, deprecatedID)
    }

    @Test("default (nil profile) preserves legacy behaviour — every non-deprecated rule loads")
    func defaultProfileLoadsEverything() async throws {
        let (dir, stableID, experimentalID, noStatusID, deprecatedID) = try makeProfileDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let engine = SequenceEngine(lineage: ProcessLineage())
        let loaded = try await engine.loadRules(from: dir)
        #expect(loaded == 3, "with no profile, every non-deprecated sequence rule must load")

        let ids = Set(await engine.listRules().map(\.id))
        #expect(ids == [stableID, experimentalID, noStatusID])
        // v1.21.5 audit: deprecated must NOT load even under nil ("all") —
        // pre-fix the nil path skipped status filtering entirely and the
        // engine's `rule.enabled = true` revived the compiled enabled=false.
        #expect(!ids.contains(deprecatedID), "a status:deprecated sequence must never load, even under the nil (\"all\") profile")
    }

    @Test("enabledStatuses:[stable] loads stable + grandfathers missing-status, skips experimental + deprecated")
    func stableProfileSkipsExperimental() async throws {
        let (dir, stableID, experimentalID, noStatusID, deprecatedID) = try makeProfileDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let engine = SequenceEngine(lineage: ProcessLineage())
        let loaded = try await engine.loadRules(from: dir, enabledStatuses: ["stable"])
        #expect(loaded == 2, "stable + missing-status grandfather must load; experimental + deprecated must be skipped")

        let ids = Set(await engine.listRules().map(\.id))
        #expect(ids.contains(stableID), "a status:stable sequence must load under the [stable] profile")
        #expect(ids.contains(noStatusID), "a sequence with NO status key must be grandfathered as stable (pre-v1.21.5 compiled dirs)")
        #expect(!ids.contains(experimentalID), "a status:experimental sequence must not load under the [stable] profile")
        #expect(!ids.contains(deprecatedID), "a status:deprecated sequence must never load under the [stable] profile")
    }

    @Test("decoded SequenceRule carries the compiled Sigma status")
    func decodedRuleCarriesStatus() async throws {
        let (dir, stableID, experimentalID, noStatusID, _) = try makeProfileDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let engine = SequenceEngine(lineage: ProcessLineage())
        _ = try await engine.loadRules(from: dir)

        let rules = await engine.listRules()
        #expect(rules.first { $0.id == stableID }?.status == "stable")
        #expect(rules.first { $0.id == experimentalID }?.status == "experimental")
        #expect(rules.first { $0.id == noStatusID }?.status == nil, "a missing status key must decode to nil, not a default")
    }
}
