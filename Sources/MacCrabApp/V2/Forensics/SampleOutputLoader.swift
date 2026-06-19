// SampleOutputLoader.swift
//
// Pure async helper: returns a scanner's most-recent REAL artifact
// rows (≤ limit) so the store's detail panel can preview what the
// scanner has actually produced on THIS Mac. No fake data, no
// canned samples — every row comes from a real plaintext case.
//
// No Keychain prompt: encrypted cases are skipped entirely (the
// scanner's privacy class is consulted first, and only plaintext
// cases on disk are ever opened). This is the same path the
// Findings tab walks, scoped to one scanner.
//
// Return contract:
//   nil  → no static fact for the id, OR the scanner emits only
//          encrypted-at-rest content → caller hides "Recent output".
//   []   → metadata scanner, plaintext cases scanned, no real rows
//          → never-run fallback ("Run to see output").
//   rows → real most-recent rows → render the compact preview.

import Foundation
import MacCrabForensics

enum SampleOutputLoader {

    /// Most-recent ≤`limit` real artifacts for `pluginID`, found by
    /// opening plaintext cases newest-first and querying the
    /// scanner's emitted content types. Fail-soft: any error from a
    /// case is swallowed and the scan moves on (never crashes, never
    /// blocks the UI).
    static func recentRows(
        forPluginID pluginID: String,
        caseManager: CaseManager = SampleOutputLoader.defaultCaseManager(),
        limit: Int = 3,
        maxCasesToScan: Int = 12
    ) async -> [CommittedArtifact]? {
        guard let fact = ScannerCatalog.fact(forPluginID: pluginID) else { return nil }
        // Honest no-prompt guard: encrypted-only scanners never live
        // in a plaintext case, so don't even try (and never unlock).
        guard fact.privacyClass == .metadata else { return nil }
        guard let cases = try? await caseManager.listCases() else { return [] }

        for manifest in cases.prefix(maxCasesToScan)
            where manifest.encryptionState == .plaintext {
            guard let handle = try? await caseManager.openCase(id: manifest.id) else { continue }
            let store = handle.store
            // Cheap COUNT(*) pre-check: did this plugin emit anything
            // in this case at all? Skip the row loads if not.
            let n = (try? await store.count(caseID: manifest.id, pluginID: pluginID)) ?? 0
            guard n > 0 else { continue }

            var rows: [CommittedArtifact] = []
            for ct in fact.emits {
                let q = ArtifactQuery(caseID: manifest.id, contentType: ct, limit: limit)
                if let r = try? await store.query(q) { rows.append(contentsOf: r) }
            }
            rows.sort { $0.record.observedAt > $1.record.observedAt }
            let visible = OperatorVisibilityFilter.filter(rows)
            if !visible.isEmpty { return Array(visible.prefix(limit)) }
            // The case had this plugin's content type rows but they all
            // filtered out (dev/test residue) → keep scanning older cases.
        }
        return []   // metadata scanner, no real rows → never-run fallback
    }

    /// Production case manager — same wiring the Findings/Scans tabs
    /// use (default Cases root + login-keychain DEK vault). Tests
    /// inject their own against a temp root + InMemoryDEKVault.
    static func defaultCaseManager() -> CaseManager {
        CaseManager(
            casesRoot: CaseDirectoryLayout.defaultCasesRoot,
            dekVault: KeychainDEKVault()
        )
    }
}
