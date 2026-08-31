// CollectorStartedHealthTests.swift
//
// v1.21.6-rc.45: "registered" is not "running".
//
// WHAT THIS PINS. On every release install, FSEventsCollector and
// UltrasonicMonitor were registered in the CollectorRegistry and rendered
// **Healthy** in the dashboard while never being started at all:
//   - FSEventsCollector starts only `if !isRoot`, and the shipped System
//     Extension IS root (DaemonSetup: `if !isRoot { await fsEventsCollector.start() }`).
//   - UltrasonicMonitor's consumer task starts unconditionally, but the monitor
//     behind it starts only under the `ultrasonicEnabled` opt-in.
// A never-ticked event-driven collector was judged solely on
// `errorCount == 0`, and `recordError` has no production call site — so the
// verdict was permanently `true`. Absence of evidence rendered as health.
//
// The fix is deliberately narrow for a release: `started` defaults to TRUE, so
// the thirteen collectors that start unconditionally are untouched and cannot
// gain a false RED. Only a registration whose start is genuinely gated declares
// `started: false`, and flips when the gate opens.

import Testing
import Foundation
@testable import MacCrabAgentKit

@Suite("Collector started-vs-registered health (v1.21.6-rc.45)")
struct CollectorStartedHealthTests {

    @Test("a registered-but-never-started collector is not healthy, and says why")
    func neverStartedIsNotHealthy() async {
        let registry = CollectorRegistry()
        await registry.register(
            name: "FSEventsCollector", expectedIntervalSeconds: 30,
            eventDriven: true, started: false
        )
        let status = await registry.snapshot().first { $0.name == "FSEventsCollector" }
        let s = try? #require(status)
        #expect(s?.healthy == false, "a collector that was never started must not report healthy")
        #expect(s?.reason == "not started")
    }

    @Test("opening the gate flips it to a real health verdict")
    func recordStartedFlipsTheVerdict() async {
        let registry = CollectorRegistry()
        await registry.register(
            name: "UltrasonicMonitor", expectedIntervalSeconds: 60,
            eventDriven: true, started: false
        )
        await registry.recordStarted(name: "UltrasonicMonitor")
        let s = await registry.snapshot().first { $0.name == "UltrasonicMonitor" }
        #expect(s?.healthy == true, "once actually started, a quiet event-driven collector keeps the benefit of the doubt")
        #expect(s?.reason == "started, no events yet")
    }

    @Test("the default is unchanged, so no collector gains a false red")
    func defaultRegistrationStaysHealthy() async {
        let registry = CollectorRegistry()
        await registry.register(
            name: "USBMonitor", expectedIntervalSeconds: 10, eventDriven: true
        )
        let s = await registry.snapshot().first { $0.name == "USBMonitor" }
        #expect(s?.healthy == true)
        #expect(s?.reason == "started, no events yet")
    }

    @Test("every status explains itself")
    func everyStatusHasAReason() async {
        let registry = CollectorRegistry()
        await registry.register(name: "ESCollector", expectedIntervalSeconds: 5)
        await registry.register(
            name: "DNSCollector", expectedIntervalSeconds: 30,
            eventDriven: true, expectsContinuousTraffic: true
        )
        await registry.register(
            name: "FSEventsCollector", expectedIntervalSeconds: 30,
            eventDriven: true, started: false
        )
        await registry.recordTick(name: "DNSCollector")
        for status in await registry.snapshot() {
            #expect(
                !status.reason.isEmpty,
                "\(status.name) reported healthy=\(status.healthy) with no explanation"
            )
        }
    }

    @Test("the two gated collectors declare their gate at registration")
    func gatedCollectorsDeclareTheirGate() throws {
        let root = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        let setup = try String(
            contentsOf: root.appendingPathComponent("Sources/MacCrabAgentKit/DaemonSetup.swift"),
            encoding: .utf8
        )
        #expect(
            setup.contains("name: \"FSEventsCollector\", expectedIntervalSeconds: 30,\n            eventDriven: true, started: false"),
            "FSEventsCollector is the non-root fallback; on the shipped root sysext it never starts"
        )
        #expect(
            setup.contains("name: \"UltrasonicMonitor\", expectedIntervalSeconds: 60,\n            eventDriven: true, started: false"),
            "UltrasonicMonitor is opt-in and must not claim health before its gate opens"
        )
        // ...and both must flip when their gate actually opens.
        #expect(setup.contains("recordStarted(name: \"FSEventsCollector\")"))
        #expect(setup.contains("recordStarted(name: \"UltrasonicMonitor\")"))
    }
}
