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

    @Test("intentionally disabled collectors remain distinct from a failed enabled start")
    func disabledAndFailedStart() async {
        let registry = CollectorRegistry()
        await registry.register(name: "Optional", expectedIntervalSeconds: 30,
                                started: false, enabled: false,
                                disabledReason: "Turned off in settings")
        await registry.register(name: "Required", expectedIntervalSeconds: 30, started: false)
        let early = await registry.snapshot()
        #expect(status(early, "Optional")?.state == .disabled)
        #expect(status(early, "Optional")?.enabled == false)
        #expect(status(early, "Optional")?.reason == "Turned off in settings")
        #expect(status(early, "Required")?.state == .starting)
        let late = await registry.snapshot(now: Date().addingTimeInterval(600))
        #expect(status(late, "Optional")?.state == .disabled)
        #expect(status(late, "Required")?.state == .failed)
    }

    @Test("polling startup, normal operation, error, and silence have distinct states")
    func pollingTransitions() async {
        let registry = CollectorRegistry()
        await registry.register(name: "Polling", expectedIntervalSeconds: 10)
        #expect(status(await registry.snapshot(), "Polling")?.state == .starting)
        #expect(status(await registry.snapshot(now: Date().addingTimeInterval(60)), "Polling")?.state == .stalled)
        await registry.recordTick(name: "Polling")
        #expect(status(await registry.snapshot(), "Polling")?.state == .healthy)
        await registry.recordError(name: "Polling", message: "Poll failed")
        #expect(status(await registry.snapshot(), "Polling")?.state == .failed)
    }

    @Test("a real event lazily registers its source as started")
    func lazyRegistrationIsStarted() async {
        let registry = CollectorRegistry()
        await registry.recordTick(name: "NewSource")
        #expect(status(await registry.snapshot(), "NewSource")?.state == .healthy)
    }

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

    @Test("only verified capture recovery clears a fault and preserves its lifetime history")
    func verifiedRecoveryPreservesHistory() async {
        let registry = CollectorRegistry()
        await registry.register(name: "DNSCollector", expectedIntervalSeconds: 30,
                                eventDriven: true, expectsContinuousTraffic: true)
        await registry.recordTick(name: "DNSCollector")
        await registry.recordError(name: "DNSCollector", message: "BPF read failed")
        // A buffered event can arrive after capture failed. It is not proof
        // that the descriptor was reconfigured successfully.
        await registry.recordTick(name: "DNSCollector")
        let failed = status(await registry.snapshot(), "DNSCollector")
        #expect(failed?.state == .failed)
        #expect(failed?.errorCount == 1)

        let recoveredAt = Date().addingTimeInterval(600)
        await registry.recordRecovery(name: "DNSCollector", at: recoveredAt)
        let recovered = status(await registry.snapshot(now: recoveredAt), "DNSCollector")
        #expect(recovered?.state == .healthy)
        #expect(recovered?.reason == "reconfigured, awaiting events")
        #expect(recovered?.errorCount == 1)
        #expect(recovered?.lastError == "BPF read failed")
        #expect(recovered?.eventCount == failed?.eventCount)
        #expect(recovered?.lastTick == failed?.lastTick)
        let silent = status(await registry.snapshot(
            now: recoveredAt.addingTimeInterval(600)
        ), "DNSCollector")
        #expect(silent?.state == .stalled)

        await registry.recordError(name: "DNSCollector", message: "BPF bind failed")
        let failedAgain = status(await registry.snapshot(now: recoveredAt), "DNSCollector")
        #expect(failedAgain?.state == .failed)
        #expect(failedAgain?.errorCount == 2)
        #expect(failedAgain?.lastError == "BPF bind failed")
    }

    @Test("verified setup without traffic starts a bounded grace without inventing events")
    func recoveryBeforeFirstEvent() async {
        let registry = CollectorRegistry()
        await registry.register(name: "DNSCollector", expectedIntervalSeconds: 30,
                                eventDriven: true, expectsContinuousTraffic: true)
        await registry.recordError(name: "DNSCollector", message: "BPF unavailable")
        let recoveredAt = Date().addingTimeInterval(600)
        await registry.recordRecovery(name: "DNSCollector", at: recoveredAt)
        let recovered = status(await registry.snapshot(now: recoveredAt), "DNSCollector")
        #expect(recovered?.state == .healthy)
        #expect(recovered?.lastTick == nil)
        #expect(recovered?.eventCount == 0)
        #expect(recovered?.errorCount == 1)
        let silent = status(await registry.snapshot(
            now: recoveredAt.addingTimeInterval(600)
        ), "DNSCollector")
        #expect(silent?.state == .stalled)
    }

    @Test("verified setup cannot revive an ended stream or enable a disabled collector")
    func recoveryDoesNotReviveTerminalStates() async {
        let registry = CollectorRegistry()
        await registry.register(name: "Ended", expectedIntervalSeconds: 30, eventDriven: true)
        await registry.recordStreamEnded(name: "Ended")
        await registry.recordRecovery(name: "Ended")
        let ended = status(await registry.snapshot(), "Ended")
        #expect(ended?.state == .failed)
        #expect(ended?.reason == "stream ended")
        #expect(ended?.errorCount == 1)
        await registry.register(name: "Disabled", expectedIntervalSeconds: 30,
                                started: false, enabled: false)
        await registry.recordRecovery(name: "Disabled")
        let disabled = status(await registry.snapshot(), "Disabled")
        #expect(disabled?.state == .disabled)
        #expect(disabled?.eventCount == 0)
    }
}
