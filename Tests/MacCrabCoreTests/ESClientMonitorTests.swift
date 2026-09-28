// ESClientMonitorTests.swift
// v1.22.2: endpointsecurityd and syspolicyd are launched on demand and
// idle-exit, so their absence is not an alert (field: a CRITICAL
// "Endpointsecurityd Down" whose launchd exit reason was
// JETSAM_REASON_MEMORY_IDLE_EXIT while ES kept delivering). The monitor's
// registry health comes from completed polls, not from the alerts it emits.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("ESClientMonitor: on-demand daemons and poll liveness")
struct ESClientMonitorTests {

    final class Probe: @unchecked Sendable {
        private let lock = NSLock()
        private var running: Set<String>
        init(_ running: Set<String>) { self.running = running }
        func set(_ name: String, running up: Bool) {
            lock.lock(); defer { lock.unlock() }
            if up { running.insert(name) } else { running.remove(name) }
        }
        func isRunning(_ name: String) -> Bool {
            lock.lock(); defer { lock.unlock() }
            return running.contains(name)
        }
    }

    private func drain(_ monitor: ESClientMonitor) async -> [ESClientMonitor.ESHealthEvent.EventType] {
        await monitor.stop()
        var types: [ESClientMonitor.ESHealthEvent.EventType] = []
        for await event in monitor.events { types.append(event.type) }
        return types
    }

    @Test("endpointsecurityd and syspolicyd idle-exiting raise nothing and stay healthy")
    func onDemandDaemonsAreNotAlerted() async {
        let probe = Probe(["xprotectd", "syspolicyd", "endpointsecurityd"])
        let monitor = ESClientMonitor(pollInterval: 60, isRunning: { probe.isRunning($0) })
        await monitor.checkHealth()
        probe.set("endpointsecurityd", running: false)
        probe.set("syspolicyd", running: false)
        await monitor.checkHealth()
        #expect(await monitor.currentStatus().isHealthy)
        #expect(await drain(monitor).isEmpty)
    }

    @Test("xprotectd going down and coming back still alerts")
    func xprotectdTransitionsAlert() async {
        let probe = Probe(["xprotectd"])
        let monitor = ESClientMonitor(pollInterval: 60, isRunning: { probe.isRunning($0) })
        await monitor.checkHealth()
        probe.set("xprotectd", running: false)
        await monitor.checkHealth()
        #expect(await monitor.currentStatus().isHealthy == false)
        probe.set("xprotectd", running: true)
        await monitor.checkHealth()
        #expect(await drain(monitor) == [.xprotectdDown, .securityDaemonRestarted])
    }

    @Test("every completed poll is liveness, even when nothing changed")
    func pollsRecordLiveness() async throws {
        let monitor = ESClientMonitor(pollInterval: 60, isRunning: { _ in true })
        #expect(monitor.pollingHealth.snapshot().started == false)
        await monitor.start()
        let deadline = Date().addingTimeInterval(5)
        while monitor.pollingHealth.snapshot().completedPollCount == 0, Date() < deadline {
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        #expect(monitor.pollingHealth.snapshot().completedPollCount == 1)
        _ = await monitor.stopAndJoin()
        #expect(monitor.pollingHealth.snapshot().stopped)
    }
}
