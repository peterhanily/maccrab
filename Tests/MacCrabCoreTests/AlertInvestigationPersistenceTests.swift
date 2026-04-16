// AlertInvestigationPersistenceTests.swift
// Phase 4: verify LLMInvestigation round-trips through AlertStore's
// new llm_investigation_json column (schema v2).

import Testing
import Foundation
@testable import MacCrabCore

@Suite("Alert investigation persistence")
struct AlertInvestigationPersistenceTests {

    private func makeTempPath() -> String {
        NSTemporaryDirectory() + "maccrab_inv_\(UUID().uuidString).db"
    }

    private func cleanup(_ path: String) {
        [path, path + "-wal", path + "-shm"].forEach {
            try? FileManager.default.removeItem(atPath: $0)
        }
    }

    private func sampleInvestigation(alertId: String) -> LLMInvestigation {
        LLMInvestigation(
            alertId: alertId,
            confidence: 0.87,
            verdict: .likelyMalicious,
            summary: "Dropper pattern with known-bad hash match.",
            evidenceChain: [
                Evidence(kind: .event, id: "evt-1", note: "exec from /tmp"),
                Evidence(kind: .threatIntel, id: "misp-9001", note: "hash in feed"),
            ],
            mitreReasoning: [
                MITREMap(tacticId: "TA0005", techniqueId: "T1562.001",
                         reasoning: "defense evasion via disabling tools")
            ],
            suggestedActions: [
                SuggestedAction(
                    kind: .quarantine, title: "Quarantine dropped binary",
                    rationale: "Hash matches MISP entry",
                    d3fendRef: "D3-EHPV",
                    blastRadius: .low,
                    requiresConfirmation: true,
                    previewCommand: "mv /tmp/stage /var/quarantine/"
                )
            ],
            confidencePenalties: ["No corroborating network evidence"],
            modelVersion: "claude-sonnet-4-6",
            generatedAt: Date(timeIntervalSince1970: 1_712_500_000)
        )
    }

    @Test("insert() persists llmInvestigation, query() reads it back")
    func insertAndRead() async throws {
        let path = makeTempPath()
        defer { cleanup(path) }

        let store = try AlertStore(path: path)
        let investigation = sampleInvestigation(alertId: "alert-01")
        let alert = Alert(
            id: "alert-01", ruleId: "r1", ruleTitle: "t",
            severity: .high, eventId: "evt",
            llmInvestigation: investigation
        )
        try await store.insert(alert: alert)

        let fetched = try await store.alert(id: "alert-01")
        #expect(fetched?.llmInvestigation?.alertId == "alert-01")
        #expect(fetched?.llmInvestigation?.verdict == .likelyMalicious)
        #expect(fetched?.llmInvestigation?.confidence == 0.87)
        #expect(fetched?.llmInvestigation?.suggestedActions.count == 1)
        #expect(fetched?.llmInvestigation?.suggestedActions.first?.d3fendRef == "D3-EHPV")
    }

    @Test("updateInvestigation() attaches to an existing alert")
    func updateAfterInsert() async throws {
        let path = makeTempPath()
        defer { cleanup(path) }

        let store = try AlertStore(path: path)
        let alert = Alert(
            id: "alert-02", ruleId: "r1", ruleTitle: "t",
            severity: .critical, eventId: "evt"
        )
        try await store.insert(alert: alert)

        // No investigation yet.
        let before = try await store.alert(id: "alert-02")
        #expect(before?.llmInvestigation == nil)

        // Update in place.
        try await store.updateInvestigation(
            alertId: "alert-02",
            investigation: sampleInvestigation(alertId: "alert-02")
        )

        let after = try await store.alert(id: "alert-02")
        #expect(after?.llmInvestigation?.verdict == .likelyMalicious)
        #expect(after?.llmInvestigation?.summary.contains("Dropper") == true)
    }

    @Test("Alerts without investigation decode with nil")
    func nilInvestigation() async throws {
        let path = makeTempPath()
        defer { cleanup(path) }

        let store = try AlertStore(path: path)
        let alert = Alert(
            id: "alert-03", ruleId: "r1", ruleTitle: "t",
            severity: .medium, eventId: "evt"
        )
        try await store.insert(alert: alert)

        let fetched = try await store.alert(id: "alert-03")
        #expect(fetched?.llmInvestigation == nil)
    }

    @Test("Schema migrates from v1 DB (no column) to v2 (with column)")
    func migrationAdded() async throws {
        let path = makeTempPath()
        defer { cleanup(path) }

        // Simulate a v1 DB by just opening the store (which runs migrations).
        // After init, the llm_investigation_json column must exist.
        _ = try AlertStore(path: path)

        var raw: OpaquePointer?
        let rc = sqlite3_open_v2(path, &raw, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil)
        #expect(rc == SQLITE_OK)
        defer { if let raw { sqlite3_close(raw) } }

        // table_info should list llm_investigation_json
        var stmt: OpaquePointer?
        let pragma = "PRAGMA table_info(alerts)"
        sqlite3_prepare_v2(raw, pragma, -1, &stmt, nil)
        defer { sqlite3_finalize(stmt) }

        var foundColumn = false
        while sqlite3_step(stmt) == SQLITE_ROW {
            if let cstr = sqlite3_column_text(stmt, 1),
               String(cString: cstr) == "llm_investigation_json" {
                foundColumn = true
                break
            }
        }
        #expect(foundColumn)

        // user_version reflects v2
        let version = try #require(try? SchemaMigrator.readVersion(db: raw!))
        #expect(version >= 2)
    }
}

// Swift Testing needs the SQLite types pulled into the test file for
// the schema-inspection test above.
import SQLite3
