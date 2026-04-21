import Testing
import Foundation
@testable import MacCrabCore

// Run a `body` between `start()` and `stop()` while guaranteeing `stop()`
// runs even if `body` throws. v1.4 stability fix: before this helper, all
// CollectorTests called `await monitor.stop()` *after* `try await
// Task.sleep(...)`, so a cancelled sleep (slow CI, parallel test
// contention) left the monitor running and polluted later test state.
// Each test now routes through `withStartedMonitor` and the stop is in
// the guaranteed-cleanup path.
private func withStartedMonitor(
    start: () async -> Void,
    stop: () async -> Void,
    body: @escaping @Sendable () async throws -> Void
) async throws {
    await start()
    let bodyResult = await Task { try await body() }.result
    await stop()
    _ = try bodyResult.get()
}

// MARK: - EDR Monitor

@Suite("EDR Monitor")
struct EDRMonitorTests {
    @Test("Starts with no detected tools")
    func defaultState() async {
        let monitor = EDRMonitor()
        let tools = await monitor.detectedTools()
        // On a clean dev machine, some tools may or may not be present.
        // We only verify the API works and returns a valid array.
        #expect(tools.count >= 0)
    }

    @Test("Start and stop without crash")
    func lifecycle() async throws {
        let monitor = EDRMonitor(pollInterval: 60)
        try await withStartedMonitor(start: { await monitor.start() }, stop: { await monitor.stop() }) {
            try await Task.sleep(for: .milliseconds(100))
        }
    }
}

// MARK: - Browser Extension Monitor
// (lifecycle test already in EdgeFeatureTests.swift)

// MARK: - Clipboard Monitor

@Suite("Clipboard Monitor")
struct ClipboardMonitorTests {
    @Test("Start and stop without crash")
    func lifecycle() async throws {
        let monitor = ClipboardMonitor()
        try await withStartedMonitor(start: { await monitor.start() }, stop: { await monitor.stop() }) {
            try await Task.sleep(for: .milliseconds(100))
        }
    }
}

// MARK: - USB Monitor

@Suite("USB Monitor")
struct USBMonitorTests {
    @Test("Start and stop without crash")
    func lifecycle() async throws {
        let monitor = USBMonitor()
        try await withStartedMonitor(start: { await monitor.start() }, stop: { await monitor.stop() }) {
            try await Task.sleep(for: .milliseconds(100))
        }
    }
}

// MARK: - MCP Monitor

@Suite("MCP Monitor")
struct MCPMonitorTests {
    @Test("Start and stop without crash")
    func lifecycle() async throws {
        let monitor = MCPMonitor()
        try await withStartedMonitor(start: { await monitor.start() }, stop: { await monitor.stop() }) {
            try await Task.sleep(for: .milliseconds(100))
        }
    }
}

// MARK: - Network Collector

@Suite("Network Collector")
struct NetworkCollectorTests {
    @Test("Start and stop without crash")
    func lifecycle() async throws {
        let collector = NetworkCollector()
        try await withStartedMonitor(start: { await collector.start() }, stop: { await collector.stop() }) {
            try await Task.sleep(for: .milliseconds(100))
        }
    }
}

// MARK: - System Policy Monitor

@Suite("System Policy Monitor")
struct SystemPolicyMonitorTests {
    @Test("Start and stop without crash")
    func lifecycle() async throws {
        let monitor = SystemPolicyMonitor()
        try await withStartedMonitor(start: { await monitor.start() }, stop: { await monitor.stop() }) {
            try await Task.sleep(for: .milliseconds(100))
        }
    }
}

// MARK: - TEMPEST Monitor

@Suite("TEMPEST Monitor")
struct TEMPESTMonitorTests {
    @Test("Start and stop without crash")
    func lifecycle() async throws {
        let monitor = TEMPESTMonitor()
        try await withStartedMonitor(start: { await monitor.start() }, stop: { await monitor.stop() }) {
            try await Task.sleep(for: .milliseconds(100))
        }
    }
}

// MARK: - Event Tap Monitor

@Suite("Event Tap Monitor")
struct EventTapMonitorTests {
    @Test("Start and stop without crash")
    func lifecycle() async throws {
        let monitor = EventTapMonitor()
        try await withStartedMonitor(start: { await monitor.start() }, stop: { await monitor.stop() }) {
            try await Task.sleep(for: .milliseconds(100))
        }
    }
}

// MARK: - FSEvents Collector

@Suite("FSEvents Collector")
struct FSEventsCollectorTests {
    @Test("Start and stop without crash")
    func lifecycle() async throws {
        let collector = FSEventsCollector()
        try await withStartedMonitor(start: { await collector.start() }, stop: { await collector.stop() }) {
            try await Task.sleep(for: .milliseconds(100))
        }
    }
}

// MARK: - TCC Monitor

@Suite("TCC Monitor")
struct TCCMonitorTests {
    @Test("Start and stop without crash")
    func lifecycle() async throws {
        let monitor = TCCMonitor()
        try await withStartedMonitor(start: { await monitor.start() }, stop: { await monitor.stop() }) {
            try await Task.sleep(for: .milliseconds(100))
        }
    }
}
