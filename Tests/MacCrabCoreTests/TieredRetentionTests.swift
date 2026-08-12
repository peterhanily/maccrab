// TieredRetentionTests.swift
//
// Coverage for the schema-v8 retention split between the exact event journal,
// aggregate history, and alert-owned evidence.
//
// The contract under test:
//   1. EventStore selects bounded backward context; AlertStore owns the copy.
//   2. Alert-owned capture is idempotent and evicts oldest context first.
//   3. Source timestamps cannot prematurely prune newly admitted journal rows.
//   4. Whole expired journal blocks roll up exact events atomically.
//   5. Journal expiry and aggregate maintenance are idempotent.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("Tiered retention (schema v8)")
struct TieredRetentionTests {

    private func makeTempStore() throws -> (EventStore, URL) {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-tiers-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        let store = try EventStore(directory: tmp.path)
        return (store, tmp)
    }

    private func sampleEvent(
        at date: Date,
        name: String = "sample",
        path: String = "/bin/sample",
        padding: Int = 0
    ) -> Event {
        let command = path + String(repeating: "x", count: padding)
        let proc = ProcessInfo(
            pid: 1000, ppid: 1, rpid: 1,
            name: name, executable: path,
            commandLine: command, args: padding > 0 ? [command] : [],
            workingDirectory: "/",
            userId: 501, userName: "t", groupId: 20,
            startTime: date,
            ancestors: [],
            isPlatformBinary: false
        )
        return Event(
            timestamp: date,
            eventCategory: .process, eventType: .start,
            eventAction: "exec", process: proc
        )
    }

    private func evidenceCandidate(
        _ event: Event
    ) throws -> AlertEvidenceCandidate {
        let data = try JSONEncoder().encode(event)
        return AlertEvidenceCandidate(
            eventId: event.id.uuidString,
            timestamp: event.timestamp,
            rawJSON: String(decoding: data, as: UTF8.self)
        )
    }

    private func sampleAlert(id: String, event: Event) -> Alert {
        Alert(
            id: id,
            timestamp: event.timestamp,
            ruleId: "test.tiered-retention",
            ruleTitle: "Tiered retention test",
            severity: .high,
            eventId: event.id.uuidString
        )
    }

    private func expireFreshJournal(_ store: EventStore) async throws -> Int {
        try await store.expireJournalBlocks(
            retainedThrough: Date().addingTimeInterval(16 * 60),
            maximumBlocks: 256
        )
    }

    // MARK: - Alert evidence

    @Test("alert-owned evidence captures the backward window")
    func evidenceCapturesSurroundingEvents() async throws {
        let (events, tmp) = try makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }
        let alerts = try AlertStore(directory: tmp.path)

        // This value rounds one ULP upward through the alerts.db Unix-seconds
        // representation. Date-epoch arithmetic used to exclude the event at
        // the inclusive -30-second boundary deterministically.
        let alertTime = Date(
            timeIntervalSinceReferenceDate: 800_000_000.1234568
        )
        let alertId = UUID().uuidString
        var expectedIDs: [UUID] = []
        var trigger: Event?

        for offset in [-120.0, -30.0, 0.0, 30.0, 120.0] {
            let event = sampleEvent(at: alertTime.addingTimeInterval(offset))
            try await events.insert(event: event)
            if offset == -30 { expectedIDs.append(event.id) }
            if offset == 0 {
                expectedIDs.append(event.id)
                trigger = event
            }
        }

        let parent = sampleAlert(id: alertId, event: try #require(trigger))
        try await alerts.insert(alert: parent)
        let candidates = try await events.alertEvidenceCandidates(
            alertTimestamp: alertTime
        )
        let result = try await alerts.captureEvidence(
            alertId: alertId,
            candidates: candidates,
            maxBytes: 100 * 1_048_576
        )
        let evidence = try await alerts.evidenceFor(alertId: alertId)
        #expect(result.insertedRows == 2)
        #expect(evidence.map(\.id) == expectedIDs)
    }

    @Test("alert-owned evidence capture is idempotent")
    func evidenceRecordingIsIdempotent() async throws {
        let (_, tmp) = try makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }
        let store = try AlertStore(directory: tmp.path)

        // This value rounds one ULP downward through alerts.db, which used to
        // make the exact trigger appear later than its own parent alert.
        let alertTime = Date(
            timeIntervalSinceReferenceDate: 807_000_000.1
        )
        let alertId = UUID().uuidString
        let event = sampleEvent(at: alertTime)
        try await store.insert(alert: sampleAlert(id: alertId, event: event))
        let candidate = try evidenceCandidate(event)

        let first = try await store.captureEvidence(
            alertId: alertId,
            candidates: [candidate],
            maxBytes: 100 * 1_048_576
        )
        let second = try await store.captureEvidence(
            alertId: alertId,
            candidates: [candidate],
            maxBytes: 100 * 1_048_576
        )
        let third = try await store.captureEvidence(
            alertId: alertId,
            candidates: [candidate],
            maxBytes: 100 * 1_048_576
        )

        let evidence = try await store.evidenceFor(alertId: alertId)
        #expect(first.insertedRows == 1)
        #expect(second.insertedRows == 0 && second.duplicateRows == 1)
        #expect(third.insertedRows == 0 && third.duplicateRows == 1)
        #expect(evidence.count == 1)
    }

    @Test("alert-owned evidence budget evicts oldest context first")
    func evidenceSizeCapEvictsOldest() async throws {
        let (_, tmp) = try makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }
        let store = try AlertStore(directory: tmp.path)

        let base = Date(timeIntervalSince1970: 1_700_000_000)
        var ids: [String] = []
        var tenRowCap: Int64 = 0
        for i in 0..<30 {
            let t = base.addingTimeInterval(Double(i) * 60)
            let event = sampleEvent(at: t, padding: 20_000)
            let id = "alert-\(i)"
            ids.append(id)
            try await store.insert(alert: sampleAlert(id: id, event: event))
            let result = try await store.captureEvidence(
                alertId: id,
                candidates: [try evidenceCandidate(event)],
                maxBytes: 100 * 1_048_576
            )
            #expect(result.insertedRows == 1)
            if i == 9 {
                tenRowCap = try await store.refreshEvidenceBudgetSnapshot(
                    maxBytes: .max
                ).chargedBytes
            }
        }
        #expect(try await store.evidenceFor(alertId: ids[0]).count == 1)

        let full = try await store.refreshEvidenceBudgetSnapshot(
            maxBytes: tenRowCap
        )
        #expect(full.overBudget)
        let noop = try await store.pruneAlertEvidenceToBudget(
            maxBytes: 100_000_000
        )
        #expect(noop == 0)
        #expect(try await store.pruneAlertEvidenceToBudget(maxBytes: -1) == 0)

        // Bound each maintenance transaction so the test observes the
        // oldest-first ordering instead of a deliberate whole-batch overshoot.
        _ = try await store.updateStorageAdmission(
            SQLitePersistentStorePolicy(
                maxFootprintBytes: 200 * 1_048_576,
                freeSpaceFloorBytes: 0,
                transactionReserveBytes: 512 * 1_024,
                storageVolumePath: tmp.path
            )
        )
        let deleted = try await store.pruneAlertEvidenceToBudget(
            maxBytes: tenRowCap
        )
        #expect(deleted > 0)
        #expect(try await store.evidenceFor(alertId: ids[0]).isEmpty)
        #expect(try await store.evidenceFor(alertId: ids[29]).count == 1)
        let final = try await store.refreshEvidenceBudgetSnapshot(
            maxBytes: tenRowCap
        )
        #expect(!final.overBudget)
    }

    @Test("evidenceFor returns empty for unknown alert id")
    func evidenceForUnknownAlertEmpty() async throws {
        let (_, tmp) = try makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }
        let store = try AlertStore(directory: tmp.path)

        let evidence = try await store.evidenceFor(alertId: UUID().uuidString)
        #expect(evidence.isEmpty)
    }

    // MARK: - Journal expiry + aggregate retention

    @Test("source time cannot prune fresh journal rows; whole-block expiry rolls them up")
    func rollUpDeletesAndAggregates() async throws {
        let (store, tmp) = try makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let now = Date()
        let oldDay = now.addingTimeInterval(-3 * 86400)   // 3 days old
        let recent = now.addingTimeInterval(-1 * 3600)    // 1 hour old

        var ids: [UUID] = []
        for _ in 0..<5 {
            let event = sampleEvent(at: oldDay)
            ids.append(event.id)
            try await store.insert(event: event)
        }
        for _ in 0..<2 {
            let event = sampleEvent(at: recent)
            ids.append(event.id)
            try await store.insert(event: event)
        }

        let cutoff = now.addingTimeInterval(-86400) // 24h ago
        let deleted = try await store.rollUpAndPrune(olderThan: cutoff)
        #expect(deleted == 0)
        #expect(try await store.aggregateCount() == 0)
        for id in ids {
            let snapshot = try await store.exactEventSnapshot(id: id)
            #expect(snapshot.event?.id == id)
        }

        // A journal block is admitted for 15 minutes regardless of an
        // attacker-controlled source timestamp.
        #expect(try await store.expireJournalBlocks(
            retainedThrough: now.addingTimeInterval(14 * 60)
        ) == 0)
        #expect(try await expireFreshJournal(store) == 7)
        #expect(try await expireFreshJournal(store) == 0)
        for id in ids {
            let snapshot = try await store.exactEventSnapshot(id: id)
            #expect(snapshot.event == nil)
        }
        let aggregates = try await store.aggregates(sinceDay: "2000-01-01")
        #expect(aggregates.count == 2)
        #expect(aggregates.reduce(0) { $0 + $1.count } == 7)
    }

    @Test("whole-block journal expiry is idempotent")
    func rollUpIsIdempotent() async throws {
        let (store, tmp) = try makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let oldDay = Date().addingTimeInterval(-3 * 86400)
        for _ in 0..<10 {
            try await store.insert(event: sampleEvent(at: oldDay))
        }

        #expect(try await expireFreshJournal(store) == 10)
        #expect(try await expireFreshJournal(store) == 0)
        #expect(try await expireFreshJournal(store) == 0)

        let agg = try await store.aggregates(sinceDay: "2000-01-01")
        let total = agg.reduce(0) { $0 + $1.count }
        #expect(total == 10)
    }

    @Test("aggregates(sinceDay:category:) filters by day and category")
    func aggregatesFilterCorrectly() async throws {
        let (store, tmp) = try makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let oldDay = Date().addingTimeInterval(-2 * 86400)
        for _ in 0..<3 {
            try await store.insert(event: sampleEvent(at: oldDay))
        }
        #expect(try await expireFreshJournal(store) == 3)

        // Future day → empty.
        let futureDay = "2099-01-01"
        let none = try await store.aggregates(sinceDay: futureDay)
        #expect(none.isEmpty)

        // Beginning of time → finds our row.
        let all = try await store.aggregates(sinceDay: "2000-01-01")
        #expect(!all.isEmpty)

        // Wrong category → empty.
        let networkOnly = try await store.aggregates(sinceDay: "2000-01-01", category: .network)
        #expect(networkOnly.isEmpty)

        // Right category → finds our row.
        let processOnly = try await store.aggregates(sinceDay: "2000-01-01", category: .process)
        #expect(!processOnly.isEmpty)
    }

    @Test("rollUpAndPrune trims aggregate rows older than 30 days")
    func rollUpTrimsOldAggregates() async throws {
        let (store, tmp) = try makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let veryOld = Date().addingTimeInterval(-60 * 86400)
        let recentlyOld = Date().addingTimeInterval(-5 * 86400)
        try await store.insert(event: sampleEvent(at: veryOld))
        try await store.insert(event: sampleEvent(at: recentlyOld, name: "recent", path: "/bin/recent"))

        #expect(try await expireFreshJournal(store) == 2)
        #expect(try await store.aggregateCount() == 2)

        // Legacy-row maintenance also retains the 30-day aggregate trim.
        #expect(try await store.rollUpAndPrune(
            olderThan: Date().addingTimeInterval(-86400)
        ) == 0)

        let agg = try await store.aggregates(sinceDay: "2000-01-01")
        #expect(agg.count == 1)
        #expect(agg.first?.processPath == "/bin/recent")
    }
}
