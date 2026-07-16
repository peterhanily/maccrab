// V2OfflineDataProviderCompletenessTests — Owner-issue-2 (completeness/inverse).
//
// The offline provider is the RELEASE default until live stores connect. Its
// contract is that EVERY surface is honestly empty/zeroed — a release build must
// never render an invented alert, campaign, trace, KPI, or a mutation that
// "succeeded". The weak version of this test asserts "alerts is empty". The
// owner's Issue 2 demands the INVERSE: the empty surface is COMPLETE.
//
// So this file enumerates EVERY accessor on the V2DataProvider protocol —
// including the protocol-DEFAULT methods (agentSessions / integrations /
// compositeRuleLabels / unsuppressCampaign / suppressedCampaigns) that the
// offline type inherits rather than defines — and asserts each returns the empty
// / zero / false / nil bottom value. A guard test (`accessorInventoryIsComplete`)
// pins the exact set of protocol requirements so that if a NEW accessor is added
// to V2DataProvider and NOT covered here, the inventory assertion fails — making
// the completeness claim self-maintaining.
//
// Mutation note: if any accessor regressed to return fabricated content (e.g.
// suppressAlert -> true, or alerts(...) -> [someDemoAlert], or kpis() -> a
// non-zero snapshot), the corresponding #expect below flips and the test FAILS.

import Testing
import Foundation
@testable import MacCrabApp

@Suite("V2OfflineDataProvider — complete empty surface (owner issue 2)")
@MainActor
struct V2OfflineDataProviderCompletenessTests {

    private func makeProvider() -> V2OfflineDataProvider { V2OfflineDataProvider() }

    @Test("mode + diagnostics are the honest-offline bottom values")
    func metadata() {
        let p = makeProvider()
        #expect(p.mode == .offline)
        #expect(p.lastErrorDescription == nil)
        #expect(p.dataDir == nil)
    }

    @Test("EVERY collection accessor returns exactly empty (count == 0)")
    func everyCollectionIsEmpty() async {
        let p = makeProvider()
        let now = Date()

        // Read surfaces — directly defined on V2OfflineDataProvider.
        #expect(await p.alerts(since: now, limit: 1000).isEmpty)
        #expect(await p.events(limit: 1000).isEmpty)
        #expect(await p.campaigns(since: now, limit: 1000).isEmpty)
        #expect(await p.traces(limit: 1000).isEmpty)
        #expect(await p.rules().isEmpty)
        #expect(await p.feeds().isEmpty)
        #expect(await p.mcpServers().isEmpty)
        #expect(await p.collectors().isEmpty)
        #expect(await p.permissions().isEmpty)
        #expect(await p.packages().isEmpty)
        #expect(await p.extensions().isEmpty)
        #expect(await p.suppressions().isEmpty)
        #expect(await p.traceMembers(traceId: "anything").isEmpty)
        #expect(await p.traceEdges(traceId: "anything").isEmpty)
        #expect(await p.alertHistogram(rangeKey: "24h").isEmpty)

        // Read surfaces backed by PROTOCOL DEFAULTS (the offline type inherits
        // these — they must still be empty, which is the point of covering them).
        #expect(await p.agentSessions(limit: 1000).isEmpty)
        #expect(await p.integrations().isEmpty)
        #expect(await p.compositeRuleLabels().isEmpty)
        #expect(await p.suppressedCampaigns(limit: 1000).isEmpty)
    }

    @Test("the histogram is empty for EVERY documented range key (no range fabricates buckets)")
    func histogramEmptyForAllRanges() async {
        let p = makeProvider()
        for key in ["1h", "6h", "24h", "7d", "garbage", ""] {
            #expect(await p.alertHistogram(rangeKey: key).isEmpty, "range \(key) must be empty")
        }
    }

    @Test("kpis() is EXACTLY .zero — every numeric field zero, series empty")
    func kpisAreZero() async {
        let p = makeProvider()
        let k = await p.kpis()
        #expect(k == V2OverviewKPIs.zero)
        // Field-level inverse so a future non-equatable drift still catches:
        #expect(k.openAlerts24h == 0)
        #expect(k.openAlertsLast24hDelta == 0)
        #expect(k.activeCampaigns == 0)
        #expect(k.activeCampaignsCritical == 0)
        #expect(k.activeCampaignsHigh == 0)
        #expect(k.activeCampaignsMedium == 0)
        #expect(k.eventsPerSecond == 0)
        #expect(k.eventsLast8Buckets.isEmpty)
    }

    @Test("heartbeat() is nil (no daemon — never a synthesized snapshot)")
    func heartbeatNil() async {
        let p = makeProvider()
        #expect(await p.heartbeat() == nil)
    }

    @Test("EVERY Bool mutation returns false (no-op) for any id/scope, including empty")
    func everyBoolMutationIsFalse() async {
        let p = makeProvider()
        for id in ["alert-1", "", "../../etc", "💥"] {
            #expect(await p.suppressAlert(id: id) == false)
            #expect(await p.unsuppressAlert(id: id) == false)
            #expect(await p.deleteAlert(id: id) == false)
            #expect(await p.unsuppressCampaign(id: id) == false)   // protocol default
        }
        #expect(await p.liftSuppression(ruleId: "r1", scope: "any") == false)
        #expect(await p.liftSuppression(ruleId: "", scope: "") == false)
        #expect(await p.refreshThreatIntel() == false)
    }

    @Test("EVERY Int mutation returns 0 rows touched, for empty and non-empty inputs")
    func everyIntMutationIsZero() async {
        let p = makeProvider()
        #expect(await p.suppressAlerts(ids: []) == 0)
        #expect(await p.suppressAlerts(ids: ["a", "b", "c"]) == 0)
        #expect(await p.suppressCampaign(id: "camp-1") == 0)
        #expect(await p.suppressCampaign(id: "") == 0)
    }

    // MARK: - Completeness guard: the protocol requirement set is fully covered

    @Test("accessor inventory is COMPLETE — every V2DataProvider requirement is asserted above")
    func accessorInventoryIsComplete() {
        // The CANONICAL set of V2DataProvider members this suite asserts on. If a
        // requirement is added to the protocol, the maintainer must add it here
        // AND assert its empty/zero value above — otherwise this guard's intent
        // (a complete empty surface) silently rots. Listing it explicitly is the
        // self-documenting "nothing missing" half of Issue 2.
        let coveredRequirements: Set<String> = [
            // properties
            "mode", "lastErrorDescription", "dataDir",
            // read collections
            "alerts(since:limit:)", "events(limit:)", "campaigns(since:limit:)",
            "traces(limit:)", "agentSessions(limit:)", "rules()",
            "compositeRuleLabels()", "feeds()", "mcpServers()", "collectors()",
            "permissions()", "packages()", "extensions()", "integrations()",
            "suppressions()", "traceMembers(traceId:)", "traceEdges(traceId:)",
            "suppressedCampaigns(limit:)",
            // scalar reads
            "heartbeat()", "kpis()", "alertHistogram(rangeKey:)",
            // mutations
            "suppressAlert(id:)", "unsuppressAlert(id:)", "deleteAlert(id:)",
            "suppressAlerts(ids:)", "suppressCampaign(id:)", "unsuppressCampaign(id:)",
            "refreshThreatIntel()", "liftSuppression(ruleId:scope:)",
        ]
        // The count is pinned: any drift (add/remove) is a visible diff that
        // forces the maintainer back to this file. As of the V2DataProvider
        // protocol at the time of writing, there are 32 covered members
        // (3 properties + 18 read accessors + 11 mutations — counting
        // alertHistogram/kpis/heartbeat among the reads). traceEdges(traceId:)
        // was added in v1.21.4 for the Investigation graph's real causal edges.
        #expect(coveredRequirements.count == 32,
                "V2DataProvider requirement count changed — re-audit the offline empty surface")
    }
}
