import Foundation
import Testing
@testable import MacCrabCore

/// A work plane's protection verdict means losing work now. An earlier shed
/// stays in the totals as history; it no longer keeps the warning on for the
/// rest of the engine's life. Engines without the recency flag keep the
/// lifetime verdict, so an older engine never reads healthier than it is.
@Suite("Work-plane loss is judged by recency")
struct WorkPlaneLossRecencyTests {
    private func plane(
        shed: Int,
        recent: Bool?,
        conservesOffered: Bool = true
    ) throws -> HeartbeatSnapshot.TimerLifecycle {
        var raw: [String: Any] = [
            "accepting": true,
            "offered_handlers_total": 100 + shed,
            "accepted_handlers_total": 100,
            "completed_handlers_total": 100,
            "rejected_handlers_total": shed,
            "closed_rejected_handlers_total": 0,
            "overload_shed_handlers_total": shed,
            "coalesced_handlers_total": 0,
            "coalesced_by_label": [String: Int](),
            "rejected_by_label": shed > 0 ? ["file-injection-scan": shed] : [String: Int](),
            "inline_fallback_handlers_total": 0,
            "inline_fallbacks_by_label": [String: Int](),
            "in_flight_handlers": 0,
            "maximum_in_flight_handlers": 4096,
            "conserves_accepted_handlers": true,
            "conserves_offered_handlers": conservesOffered,
        ]
        if let recent { raw["loss_recent"] = recent }
        raw["loss_last_at_unix"] = shed > 0 ? 1_793_300_000.0 as Any : NSNull()
        let data = try JSONSerialization.data(withJSONObject: raw)
        return try JSONDecoder().decode(HeartbeatSnapshot.TimerLifecycle.self, from: data)
    }

    @Test("an earlier shed outside the window is history, not degradation")
    func earlierShedIsHistory() throws {
        let lifecycle = try plane(shed: 2181, recent: false)
        #expect(lifecycle.lossSinceStartObserved)
        #expect(lifecycle.lossLastAtUnix == 1_793_300_000)
        #expect(!lifecycle.degraded)
        #expect(!lifecycle.detectionProtectionDegraded)
        #expect(!lifecycle.featureDegraded)
    }

    @Test("a shed inside the window degrades protection")
    func recentShedDegrades() throws {
        let lifecycle = try plane(shed: 1, recent: true)
        #expect(lifecycle.degradedWhileRunning)
        #expect(lifecycle.detectionProtectionDegraded)
        #expect(lifecycle.featureDegraded)
    }

    @Test("an engine without the recency flag is judged on lifetime totals")
    func legacyEngineKeepsLifetimeVerdict() throws {
        let lifecycle = try plane(shed: 1, recent: nil)
        #expect(lifecycle.lossRecent == nil)
        #expect(lifecycle.detectionProtectionDegraded)
        #expect(lifecycle.featureDegraded)
    }

    @Test("broken conservation degrades whatever the loss recency says")
    func brokenConservationAlwaysDegrades() throws {
        let lifecycle = try plane(shed: 0, recent: false, conservesOffered: false)
        #expect(lifecycle.detectionProtectionDegraded)
        #expect(lifecycle.featureDegraded)
    }

    @Test("a plane that never lost work is healthy")
    func cleanPlaneIsHealthy() throws {
        let lifecycle = try plane(shed: 0, recent: false)
        #expect(!lifecycle.lossSinceStartObserved)
        #expect(lifecycle.lossLastAtUnix == nil)
        #expect(!lifecycle.detectionProtectionDegraded)
    }

    @Test("the content-scan plane decodes from the rich heartbeat")
    func contentScanPlaneDecodes() throws {
        let data = try JSONSerialization.data(withJSONObject: [
            "content_scan_work_lifecycle": [
                "accepting": true, "offered_handlers_total": 7,
                "accepted_handlers_total": 5, "completed_handlers_total": 5,
                "rejected_handlers_total": 0, "closed_rejected_handlers_total": 0,
                "overload_shed_handlers_total": 0, "coalesced_handlers_total": 2,
                "inline_fallback_handlers_total": 0, "in_flight_handlers": 0,
                "maximum_in_flight_handlers": 4096,
                "conserves_accepted_handlers": true, "conserves_offered_handlers": true,
                "loss_recent": false,
            ] as [String: Any],
        ])
        let heartbeat = try JSONDecoder().decode(HeartbeatSnapshot.self, from: data)
        let scans = try #require(heartbeat.contentScanWorkLifecycle)
        #expect(scans.maximumInFlightHandlers == 4096)
        #expect(scans.coalescedHandlersTotal == 2)
        #expect(!scans.detectionProtectionDegraded)
        #expect(scans.losslessPressureObserved)
    }
}
