// AlertStoreCountByCampaignTests.swift
// v1.18 — countByCampaign is the pre-flight for the MCP suppress_campaign
// fan-out confirmation. It MUST agree exactly with suppress(campaignId:)
// (same predicate) so the "would suppress N" count the agent is asked to
// confirm equals what the subsequent UPDATE actually touches.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("AlertStore.countByCampaign (v1.18)")
struct AlertStoreCountByCampaignTests {

    private func makeStore() throws -> (AlertStore, URL) {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-count-campaign-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        return (try AlertStore(directory: tmp.path), tmp)
    }

    private func alert(campaign: String?, suppressed: Bool) -> Alert {
        Alert(ruleId: "test.rule", ruleTitle: "T", severity: .high,
              eventId: UUID().uuidString, suppressed: suppressed, campaignId: campaign)
    }

    @Test("countByCampaign equals what suppress(campaignId:) affects (predicate lock)")
    func countLocksToSuppress() async throws {
        let (store, tmp) = try makeStore()
        defer { try? FileManager.default.removeItem(at: tmp) }
        // 3 unsuppressed + 1 already-suppressed in camp-1; 2 in another campaign.
        for _ in 0..<3 { try await store.insert(alert: alert(campaign: "camp-1", suppressed: false)) }
        try await store.insert(alert: alert(campaign: "camp-1", suppressed: true))
        for _ in 0..<2 { try await store.insert(alert: alert(campaign: "camp-2", suppressed: false)) }

        let pre = try await store.countByCampaign(campaignId: "camp-1")
        #expect(pre == 3)                                   // only the unsuppressed in camp-1
        let affected = try await store.suppress(campaignId: "camp-1")
        #expect(affected == pre)                            // count and UPDATE agree exactly
        #expect(try await store.countByCampaign(campaignId: "camp-1") == 0)  // none left
        #expect(try await store.countByCampaign(campaignId: "camp-2") == 2)  // untouched
    }
}
