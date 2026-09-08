import Foundation
import Testing
@testable import MacCrabCore

@Suite("AlertStore sustained physical pressure", .serialized)
struct AlertStoreSustainedPressureTests {
    private let mib: Int64 = 1_048_576
    private let reserve: Int64 = 8 * 1_048_576
    private let evidenceBudget: Int64 = 64 * 1_048_576

    private func event(at timestamp: Date, padding: Int) -> Event {
        let process = MacCrabCore.ProcessInfo(
            pid: 123, ppid: 1, rpid: 1, name: "fixture-tool", executable: "/usr/bin/fixture-tool",
            commandLine: "/usr/bin/fixture-tool", args: ["/usr/bin/fixture-tool"],
            workingDirectory: "/private/tmp", userId: 501, userName: "fixture", groupId: 20,
            startTime: timestamp, exitCode: nil, codeSignature: nil, ancestors: [],
            architecture: "arm64", isPlatformBinary: false
        )
        return Event(timestamp: timestamp, eventCategory: .process, eventType: .creation,
                     eventAction: "exec", process: process,
                     enrichments: ["fixture_detail": String(repeating: "x", count: padding)], severity: .high)
    }

    private func alert(id: String, event: Event, history: Bool = false) -> Alert {
        Alert(id: id, timestamp: event.timestamp,
              ruleId: history ? "test.alert-pressure.history" : "test.alert-pressure.current",
              ruleTitle: "Ordinary fixture detection", severity: .high, eventId: event.id.uuidString,
              processPath: event.process.executable, processName: event.process.name,
              description: String(repeating: "d", count: 16 * 1_024))
    }

    private func candidate(_ event: Event) throws -> AlertEvidenceCandidate {
        let data = try JSONEncoder().encode(event)
        #expect(data.count <= AlertEvidencePolicy.maximumRawPayloadBytes)
        return AlertEvidenceCandidate(eventId: event.id.uuidString, timestamp: event.timestamp,
                                      rawJSON: String(decoding: data, as: UTF8.self))
    }

    private func complete(_ id: String) -> AlertEvidenceContextRecord {
        .init(alertId: id, status: .complete, sourceMutationGeneration: 1,
              poisonRecordCount: 0, corruptRecordCount: 0)
    }

    private func policy(cap: Int64, directory: URL) -> SQLitePersistentStorePolicy {
        .init(maxFootprintBytes: cap, freeSpaceFloorBytes: 0,
              transactionReserveBytes: reserve, storageVolumePath: directory.path)
    }

    @Test("Repeated alert and evidence writes reclaim completed history within one fixed physical cap")
    func sustainedWritesPreserveCurrentEvidence() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-alert-sustained-\(UUID())")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("alerts.db").path
        // Enough for one ordinary recovery workspace, but never two nested
        // maximum workspaces. This is isolated from unrelated test fixtures.
        let memory = EventPipelineLiveMemoryBudget(
            maximumBytes: 12 * 1_048_576,
            forwardProgressReserveBytes: EventJournalCodec.maximumWorkspaceBytes,
            eventStoreWorkspaceReserveBytes: EventJournalCodec.maximumWorkspaceBytes
        )
        let store = try AlertStore(path: path,
            storagePolicy: policy(cap: 64 * mib, directory: directory), liveMemoryBudget: memory)
        #expect(await store.autoVacuumMode() == 2)
        let base = Date(timeIntervalSince1970: 1_780_000_000)

        // The oldest parent is deliberately pending, with real evidence
        // already attached. Neither its age nor its pages make it eligible.
        let pendingEvent = event(at: base.addingTimeInterval(-1_000), padding: 8 * 1_024)
        let pending = alert(id: "pending-old-parent", event: pendingEvent)
        try await store.insert(alert: pending)
        let pendingCapture = try await store.captureEvidence(alertId: pending.id,
            candidates: [candidate(pendingEvent)], maxBytes: evidenceBudget)
        #expect(pendingCapture.insertedRows == 1)
        #expect(try await store.evidenceContext(alertId: pending.id)?.status == .pending)

        // More than one 256-parent retention window: the first recovery must
        // have both eligible older rows and newer completed history to retain.
        for index in 0..<300 {
            let seedEvent = event(at: base.addingTimeInterval(Double(index)), padding: 1_024)
            let seed = alert(id: "history-\(index)", event: seedEvent, history: true)
            try await store.insert(alert: seed)
            if index % 64 == 0 {
                let capture = try await store.captureEvidence(alertId: seed.id,
                    candidates: [candidate(seedEvent)], maxBytes: evidenceBudget)
                #expect(capture.insertedRows == 1)
            }
            try await store.recordEvidenceContext(complete(seed.id))
        }
        #expect(try await store.count() == 301)
        #expect(await store.walCheckpointTruncate())
        let seededBytes = try SQLitePersistentStoreAdmission.measureFamily(path)
        #expect(seededBytes >= 4 * mib, "The fixture must contain real allocated SQLite pages")
        #expect(seededBytes < 12 * mib, "Keep this test's physical fixture bounded")
        // Fix the real cap once, below the headroom needed for the upcoming
        // ordinary transactions. No measured-footprint override or later cap
        // adjustment is used; only production recovery can make room.
        let fixedCap = seededBytes + reserve + 64 * 1_024
        let fixedPolicy = policy(cap: fixedCap, directory: directory)
        _ = try await store.updateStorageAdmission(fixedPolicy)
        var maximumObservedBytes = seededBytes
        func observeCap() throws {
            let actual = try SQLitePersistentStoreAdmission.measureFamily(path)
            maximumObservedBytes = max(maximumObservedBytes, actual)
            #expect(actual <= fixedCap, "Every observed SQLite main+WAL+SHM family must respect its unchanged cap")
        }

        for index in 0..<96 {
            let current = event(at: base.addingTimeInterval(1_000 + Double(index)), padding: 48 * 1_024)
            let parent = alert(id: "current-\(index)", event: current)
            let prepared = try candidate(current)
            #expect(prepared.rawJSON.utf8.count > 48 * 1_024)
            try await store.insert(alert: parent)
            try observeCap()
            #expect(try await store.evidenceContext(alertId: parent.id)?.status == .pending)
            let captured = try await store.captureEvidence(alertId: parent.id,
                candidates: [prepared], maxBytes: evidenceBudget)
            #expect(captured.insertedRows == 1 && captured.prunedRows == 0)
            try observeCap()
            try await store.recordEvidenceContext(complete(parent.id))
            try observeCap()
            #expect(try await store.alert(id: parent.id)?.eventId == current.id.uuidString)
            #expect(try await store.evidenceFor(alertId: parent.id) == [current])
            #expect(try await store.evidenceContext(alertId: parent.id)?.isComplete == true)
            #expect(try await store.alert(id: pending.id) != nil)
            #expect(try await store.evidenceFor(alertId: pending.id) == [pendingEvent])
            if index == 0 {
                let retained = try await store.alerts(since: base, ruleId: "test.alert-pressure.history", limit: 301)
                #expect(!retained.isEmpty && retained.count < 300,
                        "Actual pressure must retire some completed history while retaining newer history")
                #expect(try await store.alert(id: "history-0") == nil)
                #expect(try await store.evidenceFor(alertId: "history-0").isEmpty,
                        "Retired completed history must cascade its owned evidence")
                #expect(try await store.alert(id: "history-299") != nil)
            }
        }
        let counts = try await store.evidenceContextCounts()
        #expect(counts.reconciles && counts.pending == 1)
        #expect(counts.complete == counts.alertRows - 1)
        #expect(counts.incomplete == 0 && counts.captureFailed == 0 && counts.legacyUnverified == 0)
        #expect(try await store.count() < 397, "Writes must have reclaimed real completed parents")
        #expect(try await store.evidenceContext(alertId: pending.id)?.status == .pending)

        // A subsequent ordinary insert succeeds under the same cap after the
        // sustained sequence, and a fresh read-only handle sees durable rows.
        let final = event(at: base.addingTimeInterval(2_000), padding: 48 * 1_024)
        let later = alert(id: "later-parent", event: final)
        try await store.insert(alert: later)
        try observeCap()
        let laterCapture = try await store.captureEvidence(alertId: later.id,
            candidates: [candidate(final)], maxBytes: evidenceBudget)
        #expect(laterCapture.insertedRows == 1)
        try observeCap()
        try await store.recordEvidenceContext(complete(later.id))
        try observeCap()
        #expect(try await store.alert(id: later.id) != nil)
        let reopened = try AlertStore(path: path, forceReadOnly: true, liveMemoryBudget: memory)
        #expect(try await reopened.alert(id: later.id) != nil)
        #expect(try await reopened.evidenceFor(alertId: later.id) == [final])
        #expect(try await reopened.evidenceContext(alertId: later.id)?.isComplete == true)
        #expect(try await reopened.evidenceFor(alertId: pending.id) == [pendingEvent])
        let admission = try #require(await store.storageAdmissionSnapshot())
        #expect(admission.maxFootprintBytes == fixedCap && admission.latchedFailure == nil)
        #expect(!admission.pageLimitPending && maximumObservedBytes <= fixedCap)
        let ownership = memory.snapshot()
        #expect(ownership.withinCapacity && ownership.leasesConserved)
        #expect(ownership.currentBytes == 0 && ownership.activeLeases == 0)
        #expect(ownership.acquisitionTotal > 0, "Real recovery must have acquired its bounded workspace")
    }

    @Test("Capture-owned evidence pruning preserves current evidence and the ordinary transaction reserve")
    func captureSubcapPruningPreservesReserve() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-alert-subcap-\(UUID())")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("alerts.db").path
        let fixedCap = 16 * mib
        let subcap: Int64 = 128 * 1_024
        let memory = EventPipelineLiveMemoryBudget(
            maximumBytes: 12 * 1_048_576,
            forwardProgressReserveBytes: EventJournalCodec.maximumWorkspaceBytes,
            eventStoreWorkspaceReserveBytes: EventJournalCodec.maximumWorkspaceBytes
        )
        let store = try AlertStore(path: path,
            storagePolicy: policy(cap: fixedCap, directory: directory), liveMemoryBudget: memory)
        let base = Date(timeIntervalSince1970: 1_780_010_000)
        let pending = alert(id: "subcap-pending-parent",
                            event: event(at: base.addingTimeInterval(-1_000), padding: 0))
        try await store.insert(alert: pending)
        func observeReserve() throws {
            let actual = try SQLitePersistentStoreAdmission.measureFamily(path)
            #expect(actual + reserve <= fixedCap,
                    "Capture and its size-prune/context writes must leave the next ordinary reserve intact")
        }
        var prunedRows = 0
        var latestEvent: Event?
        var latestID = ""
        for index in 0..<20 {
            let current = event(at: base.addingTimeInterval(Double(index)), padding: 16 * 1_024)
            let parent = alert(id: "subcap-current-\(index)", event: current)
            try await store.insert(alert: parent)
            try observeReserve()
            let result = try await store.captureEvidence(alertId: parent.id,
                candidates: [candidate(current)], maxBytes: subcap)
            #expect(result.insertedRows == 1)
            prunedRows += result.prunedRows
            try observeReserve()
            #expect(try await store.alert(id: parent.id) != nil)
            #expect(try await store.evidenceFor(alertId: parent.id) == [current],
                    "An older-evidence batch must not erase the just-captured evidence that fits the subcap")
            try await store.recordEvidenceContext(complete(parent.id))
            try observeReserve()
            #expect(try await store.evidenceContext(alertId: parent.id)?.isComplete == true)
            #expect(try await store.alert(id: pending.id) != nil)
            #expect(try await store.evidenceContext(alertId: pending.id)?.status == .pending)
            let evidence = try await store.refreshEvidenceBudgetSnapshot(maxBytes: subcap)
            #expect(!evidence.overBudget && evidence.rowCount > 0)
            latestEvent = current
            latestID = parent.id
        }
        #expect(prunedRows > 0, "This fixture must exercise actual capture-owned evidence DELETEs")
        #expect(try await store.evidenceFor(alertId: "subcap-current-0").isEmpty)
        #expect(try await store.alert(id: "subcap-current-0") != nil,
                "Evidence subcap pruning preserves the parent alert")
        #expect(try await store.count() == 21)
        let latest = try #require(latestEvent)
        let reopened = try AlertStore(path: path, forceReadOnly: true, liveMemoryBudget: memory)
        #expect(try await reopened.evidenceFor(alertId: latestID) == [latest])
        #expect(try await reopened.evidenceContext(alertId: latestID)?.isComplete == true)
        #expect(try await reopened.evidenceContext(alertId: pending.id)?.status == .pending)
        let admission = try #require(await store.storageAdmissionSnapshot())
        #expect(admission.maxFootprintBytes == fixedCap && admission.latchedFailure == nil)
        let ownership = memory.snapshot()
        #expect(ownership.withinCapacity && ownership.leasesConserved)
        #expect(ownership.currentBytes == 0 && ownership.activeLeases == 0)
    }
}
