// SampleOutputLoader return-contract tests.
//
// Exercises the real fake-data-free plumbing against a temp Cases/
// root + InMemoryDEKVault (no Keychain prompt in CI). Pins the
// three-tier return contract:
//   nil  → unknown id OR encrypted-only scanner (never unlocks)
//   []   → metadata scanner, no real rows (never-run fallback)
//   rows → real most-recent rows, observed_at DESC, ≤ limit,
//          dev/test residue filtered out

import Testing
import Foundation
@testable import MacCrabApp
@testable import MacCrabForensics

@Suite("SampleOutputLoader — store sample-output return contract")
struct SampleOutputLoaderTests {

    private func tempRoot() -> URL {
        URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-sampleoutput-\(UUID().uuidString)")
    }

    /// tcc-lite is a metadata scanner that emits `tcc.grant`.
    private let tccLite = "com.maccrab.forensics.tcc-lite"

    private func tccGrantRecord(
        caseID: String,
        pluginID: String,
        summary: String,
        observedAt: Date,
        sha: String
    ) -> ArtifactRecord {
        ArtifactRecord(
            caseID: caseID,
            pluginID: pluginID,
            pluginVersion: "1.0.0",
            schemaVersion: 1,
            contentType: "tcc.grant",
            sha256: sha,
            observedAt: observedAt,
            summary: summary,
            privacyClass: .metadata,
            data: ["service": .string("kTCCServiceCamera")]
        )
    }

    @Test("unknown plugin id → nil (no static fact)")
    func unknownIDReturnsNil() async {
        let mgr = CaseManager(casesRoot: tempRoot(), dekVault: InMemoryDEKVault())
        let rows = await SampleOutputLoader.recentRows(
            forPluginID: "com.example.does-not-exist",
            caseManager: mgr
        )
        #expect(rows == nil)
    }

    @Test("encrypted-only scanner → nil without ever opening a case")
    func encryptedOnlyScannerReturnsNil() async {
        // mail is .personalComms in ScannerCatalog — must never reach the store.
        let mgr = CaseManager(casesRoot: tempRoot(), dekVault: InMemoryDEKVault())
        let rows = await SampleOutputLoader.recentRows(
            forPluginID: "com.maccrab.forensics.mail",
            caseManager: mgr
        )
        #expect(rows == nil)
    }

    @Test("metadata scanner with no cases → [] (never-run fallback, not nil)")
    func metadataScannerNoCasesReturnsEmpty() async {
        let mgr = CaseManager(casesRoot: tempRoot(), dekVault: InMemoryDEKVault())
        let rows = await SampleOutputLoader.recentRows(forPluginID: tccLite, caseManager: mgr)
        #expect(rows != nil)
        #expect(rows?.isEmpty == true)
    }

    @Test("metadata scanner with real rows → newest-first, capped at limit")
    func returnsNewestRowsObservedAtDesc() async throws {
        let root = tempRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let mgr = CaseManager(casesRoot: root, dekVault: InMemoryDEKVault())
        let handle = try await mgr.createCase(name: "tuesday review", encrypted: false)

        let base = Date(timeIntervalSince1970: 1_700_000_000)
        // Commit 4 rows with ascending observed_at; loader caps at 3 and sorts DESC.
        for i in 0..<4 {
            try await handle.store.commit(tccGrantRecord(
                caseID: handle.caseID,
                pluginID: tccLite,
                summary: "grant-\(i)",
                observedAt: base.addingTimeInterval(Double(i) * 60),
                sha: "sha-\(i)"
            ))
        }

        let rows = try #require(await SampleOutputLoader.recentRows(forPluginID: tccLite, caseManager: mgr))
        #expect(rows.count == 3)
        // Newest-first: grant-3, grant-2, grant-1.
        #expect(rows.map { $0.record.summary } == ["grant-3", "grant-2", "grant-1"])
        // Strictly descending observed_at.
        for i in 1..<rows.count {
            #expect(rows[i - 1].record.observedAt >= rows[i].record.observedAt)
        }
    }

    @Test("OperatorVisibilityFilter drops dev/test residue, keeps the real row")
    func operatorFilterDropsTestResidue() async throws {
        let root = tempRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let mgr = CaseManager(casesRoot: root, dekVault: InMemoryDEKVault())
        let handle = try await mgr.createCase(name: "review", encrypted: false)
        let base = Date(timeIntervalSince1970: 1_700_000_000)

        // A real tcc.grant + a test-residue tcc.grant (same content type, hidden id).
        try await handle.store.commit(tccGrantRecord(
            caseID: handle.caseID, pluginID: tccLite,
            summary: "real", observedAt: base, sha: "real-sha"
        ))
        try await handle.store.commit(tccGrantRecord(
            caseID: handle.caseID, pluginID: "com.test.daemon",
            summary: "residue", observedAt: base.addingTimeInterval(120), sha: "residue-sha"
        ))

        let rows = try #require(await SampleOutputLoader.recentRows(forPluginID: tccLite, caseManager: mgr))
        #expect(rows.count == 1)
        #expect(rows.first?.record.summary == "real")
    }
}
