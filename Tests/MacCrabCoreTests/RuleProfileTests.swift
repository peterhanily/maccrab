// RuleProfileTests.swift
// F-04 — rule-status PROFILE filter for RuleEngine.loadRules(enabledStatuses:).
//
// loadRules gained an `enabledStatuses: Set<String>? = nil` parameter, applied
// ONLY to the bundled base load (requireOwnerUID == nil):
//
//   • nil (the default) → no filter: every non-deprecated rule ships enabled.
//     This is the legacy behaviour, and it is what keeps the rest of the suite
//     (which loads rules with no explicit profile) green.
//   • non-nil (e.g. ["stable"]) → a decoded rule whose Sigma `status`
//     (CompiledRule.status) is NOT in the set has `enabled` flipped to false at
//     load. Deprecated rules already ship enabled=false.
//
// The profile is stashed in a private `ruleProfileStatuses` property so a SIGHUP
// reloadRules (which calls loadRules with no explicit profile) re-applies the
// same filter instead of silently re-enabling the experimental corpus.
//
// These tests exercise the REAL CompiledRule decoder against REAL compiled rule
// JSON: an isolated dir holding one `status: stable` rule + one
// `status: experimental` rule copied from the project's compiled output, so the
// status field travels the true decode path. Enabled state is inspected via the
// public `listRules()` accessor (CompiledRule.enabled / .status are public).

import Testing
import Foundation
@testable import MacCrabCore

@Suite("RuleEngine: status-profile filter (F-04)")
struct RuleProfileTests {

    private struct FixtureError: Error { let message: String }

    /// An isolated dir holding exactly two real compiled rules — one whose Sigma
    /// `status` is "stable", one "experimental" — copied verbatim from the
    /// project's compiled output (/tmp/maccrab_v3) so the real decoder runs
    /// against real content. Both ship enabled=true in the compiled JSON, so a
    /// disabled experimental rule after load can only come from the F-04 filter.
    private func makeProfileDir() throws -> (dir: URL, stableID: String, experimentalID: String) {
        ensureRulesCompiled()
        let src = URL(fileURLWithPath: "/tmp/maccrab_v3")
        let files = try FileManager.default
            .contentsOfDirectory(at: src, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "json" && $0.lastPathComponent != "manifest.json" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }

        func firstRule(status wanted: String) throws -> (url: URL, id: String) {
            for f in files {
                guard let obj = try? JSONSerialization.jsonObject(with: Data(contentsOf: f)) as? [String: Any],
                      (obj["status"] as? String) == wanted,
                      let id = obj["id"] as? String else { continue }
                return (f, id)
            }
            throw FixtureError(message: "no compiled rule with status=\(wanted) found in \(src.path)")
        }

        let stable = try firstRule(status: "stable")
        let experimental = try firstRule(status: "experimental")

        let dst = FileManager.default.temporaryDirectory
            .appendingPathComponent("profile-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dst, withIntermediateDirectories: true)
        try FileManager.default.copyItem(at: stable.url, to: dst.appendingPathComponent(stable.url.lastPathComponent))
        try FileManager.default.copyItem(at: experimental.url, to: dst.appendingPathComponent(experimental.url.lastPathComponent))
        return (dst, stable.id, experimental.id)
    }

    @Test("enabledStatuses:[stable] leaves stable enabled but disables experimental")
    func stableProfileDisablesExperimental() async throws {
        let (dir, stableID, experimentalID) = try makeProfileDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let engine = RuleEngine()
        _ = try await engine.loadRules(from: dir, enabledStatuses: ["stable"])

        let rules = await engine.listRules()
        let stable = rules.first { $0.id == stableID }
        let experimental = rules.first { $0.id == experimentalID }

        #expect(stable?.status == "stable")
        #expect(stable?.enabled == true, "a status:stable rule must stay enabled under the [stable] profile")

        // Present-but-disabled, NOT dropped — the distinction the filter promises.
        #expect(experimental != nil, "the experimental rule must still be loaded, only disabled")
        #expect(experimental?.status == "experimental")
        #expect(experimental?.enabled == false, "a status:experimental rule must be disabled under the [stable] profile")
    }

    @Test("default (nil profile) preserves legacy behaviour — experimental ships enabled")
    func defaultProfileKeepsExperimentalEnabled() async throws {
        let (dir, _, experimentalID) = try makeProfileDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        // No enabledStatuses argument at all: the legacy default path. This is the
        // invariant that keeps every other rule-loading test in the suite green.
        let engine = RuleEngine()
        _ = try await engine.loadRules(from: dir)

        let experimental = await engine.listRules().first { $0.id == experimentalID }
        #expect(experimental?.status == "experimental")
        #expect(experimental?.enabled == true, "with no profile, an experimental rule must load enabled (unchanged legacy default)")
    }

    @Test("reloadRules re-applies the stored profile — experimental stays disabled")
    func profilePersistsAcrossReload() async throws {
        let (dir, stableID, experimentalID) = try makeProfileDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let engine = RuleEngine()
        _ = try await engine.loadRules(from: dir, enabledStatuses: ["stable"])
        #expect(await engine.listRules().first { $0.id == experimentalID }?.enabled == false)

        // reloadRules calls loadRules with NO explicit profile; the stored
        // ruleProfileStatuses must be re-applied so the experimental tier does not
        // silently come back enabled.
        _ = try await engine.reloadRules(from: dir)

        let rules = await engine.listRules()
        #expect(rules.first { $0.id == stableID }?.enabled == true, "stable rule stays enabled across reload")
        #expect(rules.first { $0.id == experimentalID }?.enabled == false, "the [stable] profile must survive a reload")
    }
}
