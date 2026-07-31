import Testing
import Foundation
@testable import MacCrabAgentKit

/// Regression guard for the audit finding that 15 of 17 collectors reported
/// `healthy: true` forever. `healthy` for an event-driven collector was
/// `errorCount == 0`, and the only mutator of `errorCount` — `recordError` —
/// had zero call sites, so two entirely dead sensors (UnifiedLogCollector,
/// DNSCollector) sat green on a shipped install for months.
@Suite("CollectorRegistry: liveness of continuous-traffic collectors")
struct CollectorRegistryLivenessTests {

    private func status(_ snap: [CollectorRegistry.Status], _ name: String)
        -> CollectorRegistry.Status? {
        snap.first { $0.name == name }
    }

    @Test("a continuous-traffic collector that never ticks goes unhealthy after the grace window")
    func continuousNeverTicksGoesUnhealthy() async {
        let reg = CollectorRegistry()
        await reg.register(
            name: "DNSCollector", expectedIntervalSeconds: 30,
            eventDriven: true, expectsContinuousTraffic: true)

        // Inside the grace window (10 x 30s = 300s) it is still healthy.
        let early = await reg.snapshot(now: Date().addingTimeInterval(100))
        #expect(status(early, "DNSCollector")?.healthy == true,
                "a freshly registered streaming collector gets a grace window")

        // Past it, never having emitted a single event is a fault.
        let late = await reg.snapshot(now: Date().addingTimeInterval(600))
        #expect(status(late, "DNSCollector")?.healthy == false,
                "a streaming collector with no events past the grace window must go red")
    }

    @Test("a bursty event-driven collector may idle indefinitely and stays healthy")
    func burstyIdleStaysHealthy() async {
        let reg = CollectorRegistry()
        // USB genuinely sees nothing for days — it must keep the benefit of the doubt.
        await reg.register(name: "USBMonitor", expectedIntervalSeconds: 10, eventDriven: true)

        let snap = await reg.snapshot(now: Date().addingTimeInterval(7 * 24 * 3600))
        #expect(status(snap, "USBMonitor")?.healthy == true,
                "a bursty collector idling for a week is idle, not dead")
    }

    @Test("a continuous-traffic collector that goes silent after ticking goes unhealthy")
    func continuousGoesSilentAfterTicking() async {
        let reg = CollectorRegistry()
        await reg.register(
            name: "UnifiedLogCollector", expectedIntervalSeconds: 30,
            eventDriven: true, expectsContinuousTraffic: true)
        await reg.recordTick(name: "UnifiedLogCollector")

        let fresh = await reg.snapshot(now: Date().addingTimeInterval(60))
        #expect(status(fresh, "UnifiedLogCollector")?.healthy == true)

        let stale = await reg.snapshot(now: Date().addingTimeInterval(600))
        #expect(status(stale, "UnifiedLogCollector")?.healthy == false,
                "a streaming collector silent for 10x its interval must go red")
    }

    @Test("recordError marks an event-driven collector unhealthy")
    func recordErrorMarksUnhealthy() async {
        let reg = CollectorRegistry()
        await reg.register(name: "TCCMonitor", expectedIntervalSeconds: 60, eventDriven: true)
        await reg.recordTick(name: "TCCMonitor")
        #expect(status(await reg.snapshot(), "TCCMonitor")?.healthy == true)

        await reg.recordError(name: "TCCMonitor", message: "BIOCSETIF failed")
        let snap = await reg.snapshot()
        #expect(status(snap, "TCCMonitor")?.healthy == false)
        #expect(status(snap, "TCCMonitor")?.lastError == "BIOCSETIF failed")
    }
}
