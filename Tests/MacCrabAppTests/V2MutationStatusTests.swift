import Foundation
import Testing
@testable import MacCrabApp
@testable import MacCrabCore

@Suite("Mutation submission and saved-state confirmation")
struct V2MutationStatusTests {
    private func request(_ operation: V2MutationRequest.Operation, id: String = "alert-1") -> V2MutationRequest {
        .init(operation: operation, targetID: id, title: "Fixture")
    }

    @Test("legacy enqueue success is queued; an unavailable provider is failed")
    @MainActor
    func acceptedIsNotApplied() async {
        let accepted = await V2MockDataProvider().submitMutation(request(.suppressAlert))
        #expect(accepted == .queued)
        let failed = await V2OfflineDataProvider().submitMutation(request(.deleteAlert))
        if case .failed = failed { } else { Issue.record("offline mutation must fail") }
    }

    @Test("a request becomes applied only after confirmation and blocks conflicting pending actions")
    func queuedTransitions() {
        let suppress = request(.suppressAlert)
        let restore = request(.unsuppressAlert)
        var tracker = V2MutationTracker()
        let suppressionStarted = tracker.begin(suppress)
        #expect(suppressionStarted)
        #expect(tracker.entries.first?.status == .submitting)
        tracker.submitted(suppress, result: .queued)
        #expect(tracker.entries.first?.status == .queued)
        let conflictingRestoreStarted = tracker.begin(restore)
        #expect(!conflictingRestoreStarted)
        tracker.observed(suppress, confirmation: .pending)
        #expect(!tracker.allApplied([suppress]))
        tracker.observed(suppress, confirmation: .applied)
        #expect(tracker.allApplied([suppress]))
        let restoreStarted = tracker.begin(restore)
        #expect(restoreStarted)
    }

    @Test("rejected, timed-out, and reconnected requests never become success")
    func failureAndExpiry() {
        let now = Date(timeIntervalSince1970: 1_000)
        let failed = request(.suppressAlert, id: "failed")
        let timeout = request(.deleteAlert, id: "timeout")
        let reconnect = request(.unsuppressAlert, id: "reconnect")
        var tracker = V2MutationTracker()
        let rejectedRequestStarted = tracker.begin(failed, now: now)
        #expect(rejectedRequestStarted)
        tracker.submitted(failed, result: .failed("Permission denied"))
        #expect(tracker.entries.first?.status == .failed("Permission denied"))
        let timeoutRequestStarted = tracker.begin(timeout, now: now)
        #expect(timeoutRequestStarted)
        tracker.submitted(timeout, result: .queued)
        tracker.observed(timeout, confirmation: .unavailable("Read failed"), now: now.addingTimeInterval(30))
        #expect(tracker.queued.count == 1)
        tracker.expire(now: now.addingTimeInterval(V2MutationTracker.confirmationTimeout))
        #expect(tracker.entries.last?.status == .unconfirmed)
        #expect(!tracker.allApplied([timeout]))
        let reconnectRequestStarted = tracker.begin(reconnect, now: now)
        #expect(reconnectRequestStarted)
        tracker.submitted(reconnect, result: .queued)
        tracker.invalidatePending()
        tracker.observed(reconnect, confirmation: .applied)
        #expect(tracker.entries.last?.status == .unconfirmed)
        #expect(tracker.pending.isEmpty)
    }

    @Test("bulk Undo waits for every requested row and confirmation visits later pending work")
    func bulkConfirmation() {
        let now = Date(timeIntervalSince1970: 1_000)
        var tracker = V2MutationTracker()
        let batch = (0..<101).map { request(.suppressAlert, id: "alert-\($0)") }
        for item in batch {
            let requestStarted = tracker.begin(item, now: now)
            #expect(requestStarted)
            tracker.submitted(item, result: .queued)
        }
        let firstIDs = Set(tracker.confirmationBatch.map(\.id))
        #expect(firstIDs.count == 100)
        for item in tracker.confirmationBatch {
            tracker.observed(item.request, confirmation: .pending, now: now.addingTimeInterval(5))
        }
        #expect(tracker.confirmationBatch.first.map { !firstIDs.contains($0.id) } == true)
        for item in batch.dropLast() {
            tracker.observed(item, confirmation: .applied, now: now.addingTimeInterval(10))
        }
        #expect(!tracker.allApplied(batch))
        tracker.observed(batch.last!, confirmation: .applied, now: now.addingTimeInterval(10))
        #expect(tracker.allApplied(batch))
    }

    @Test("a filtered-out row cannot confirm deletion; a successful point read can")
    func deletionUsesPointRead() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("maccrab-mutation-\(UUID())")
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try AlertStore(directory: directory.path)
        let alert = Alert(id: "retained", timestamp: Date(timeIntervalSince1970: 100),
                          ruleId: "fixture", ruleTitle: "Fixture", severity: .low, eventId: "event")
        try await store.insert(alert: alert)
        let delete = request(.deleteAlert, id: alert.id)
        #expect(try await store.alerts(since: Date(), limit: 1).isEmpty)
        #expect(await V2MutationConfirmationReader.confirm(delete, alertStore: store,
                    campaignStore: nil, dataDir: directory.path) == .pending)
        #expect(try await store.delete(alertId: alert.id))
        #expect(await V2MutationConfirmationReader.confirm(delete, alertStore: store,
                    campaignStore: nil, dataDir: directory.path) == .applied)
        let unavailable = await V2MutationConfirmationReader.confirm(delete, alertStore: nil,
                    campaignStore: nil, dataDir: directory.path)
        if case .unavailable = unavailable { } else { Issue.record("No store must not confirm deletion") }
    }

    @Test("saved suppression and restore are confirmed without optimistic row changes")
    func alertSavedState() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("maccrab-mutation-\(UUID())")
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try AlertStore(directory: directory.path)
        let alert = Alert(id: "retained", ruleId: "fixture", ruleTitle: "Fixture", severity: .low, eventId: "event")
        try await store.insert(alert: alert)
        let suppress = request(.suppressAlert, id: alert.id)
        #expect(await V2MutationConfirmationReader.confirm(suppress, alertStore: store,
                    campaignStore: nil, dataDir: directory.path) == .pending)
        #expect(try await store.alert(id: alert.id)?.suppressed == false)
        try await store.suppress(alertId: alert.id)
        #expect(await V2MutationConfirmationReader.confirm(suppress, alertStore: store,
                    campaignStore: nil, dataDir: directory.path) == .applied)
        let restore = request(.unsuppressAlert, id: alert.id)
        #expect(await V2MutationConfirmationReader.confirm(restore, alertStore: store,
                    campaignStore: nil, dataDir: directory.path) == .pending)
        try await store.unsuppress(alertId: alert.id)
        #expect(await V2MutationConfirmationReader.confirm(restore, alertStore: store,
                    campaignStore: nil, dataDir: directory.path) == .applied)
    }

    @Test("campaign confirmation waits for the campaign row, self alert and complete contributor fan-out")
    func campaignFanOut() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("maccrab-mutation-\(UUID())")
        defer { try? FileManager.default.removeItem(at: directory) }
        let alerts = try AlertStore(directory: directory.path)
        let campaigns = try CampaignStore(directory: directory.path)
        let campaignID = "campaign"
        try await campaigns.insert(.init(id: campaignID, type: "fixture", severity: .low,
            title: "Fixture", description: "Fixture", tactics: [], timeSpanSeconds: 1,
            detectedAt: Date()))
        try await alerts.insert(alert: .init(id: campaignID, ruleId: "fixture", ruleTitle: "Fixture",
                                           severity: .low, eventId: "self"))
        try await alerts.insert(alert: .init(id: "contributor", ruleId: "fixture", ruleTitle: "Fixture",
                                           severity: .low, eventId: "child", campaignId: campaignID))
        let suppress = request(.suppressCampaign, id: campaignID)
        try await campaigns.setSuppressed(id: campaignID, true)
        #expect(await V2MutationConfirmationReader.confirm(suppress, alertStore: alerts,
                    campaignStore: campaigns, dataDir: directory.path) == .pending)
        try await alerts.suppress(alertId: campaignID)
        #expect(await V2MutationConfirmationReader.confirm(suppress, alertStore: alerts,
                    campaignStore: campaigns, dataDir: directory.path) == .pending)
        _ = try await alerts.suppress(campaignId: campaignID)
        #expect(await V2MutationConfirmationReader.confirm(suppress, alertStore: alerts,
                    campaignStore: campaigns, dataDir: directory.path) == .applied)
        let restore = request(.unsuppressCampaign, id: campaignID)
        try await campaigns.setSuppressed(id: campaignID, false)
        #expect(await V2MutationConfirmationReader.confirm(restore, alertStore: alerts,
                    campaignStore: campaigns, dataDir: directory.path) == .pending)
        try await alerts.unsuppress(alertId: campaignID)
        _ = try await alerts.unsuppress(campaignId: campaignID)
        #expect(await V2MutationConfirmationReader.confirm(restore, alertStore: alerts,
                    campaignStore: campaigns, dataDir: directory.path) == .applied)
    }

    @Test("missing or malformed suppression data is not an empty valid state")
    func suppressionReadTruth() throws {
        let entry = Suppression(scope: .rulePath(ruleId: "fixture", path: "/fixture/app"), source: .ui, reason: "Fixture")
        let other = Suppression(scope: .rule("fixture"), source: .cli, reason: "Other scope")
        let lift = V2MutationRequest(operation: .liftSuppression, targetID: entry.id,
                                     title: "Fixture", scope: entry.scope.summary)
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        func data(_ entries: [Suppression]) throws -> Data {
            try encoder.encode(SuppressionFile(version: 2, entries: entries))
        }
        #expect(V2MutationConfirmationReader.confirmSuppression(lift,
                    data: try data([entry, other])) == .pending)
        #expect(V2MutationConfirmationReader.confirmSuppression(lift,
                    data: try data([other])) == .applied)
        let row = V2SuppressionEntry(entry)
        #expect(row.id == entry.id)
        #expect(row.ruleId == "fixture")
        #expect(row.scope == entry.scope.summary)
        #expect(row.addedBy == "ui")
        for value in ["{}", "invalid", #"{"entries":[{}]}"#] {
            let result = V2MutationConfirmationReader.confirmSuppression(lift, data: Data(value.utf8))
            if case .unavailable = result { } else { Issue.record("Invalid data must not confirm a lift") }
        }
    }
}
