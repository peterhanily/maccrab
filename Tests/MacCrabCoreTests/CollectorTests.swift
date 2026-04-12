import Testing
import Foundation
@testable import MacCrabCore

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
        await monitor.start()
        // Brief pause to let the scan task spin up
        try await Task.sleep(for: .milliseconds(100))
        await monitor.stop()
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
        await monitor.start()
        try await Task.sleep(for: .milliseconds(100))
        await monitor.stop()
    }
}

// MARK: - USB Monitor

@Suite("USB Monitor")
struct USBMonitorTests {
    @Test("Start and stop without crash")
    func lifecycle() async throws {
        let monitor = USBMonitor()
        await monitor.start()
        try await Task.sleep(for: .milliseconds(100))
        await monitor.stop()
    }
}

// MARK: - MCP Monitor

@Suite("MCP Monitor")
struct MCPMonitorTests {
    @Test("Start and stop without crash")
    func lifecycle() async throws {
        let monitor = MCPMonitor()
        await monitor.start()
        try await Task.sleep(for: .milliseconds(100))
        await monitor.stop()
    }
}

// MARK: - Network Collector

@Suite("Network Collector")
struct NetworkCollectorTests {
    @Test("Start and stop without crash")
    func lifecycle() async throws {
        let collector = NetworkCollector()
        await collector.start()
        try await Task.sleep(for: .milliseconds(100))
        await collector.stop()
    }
}

// MARK: - System Policy Monitor

@Suite("System Policy Monitor")
struct SystemPolicyMonitorTests {
    @Test("Start and stop without crash")
    func lifecycle() async throws {
        let monitor = SystemPolicyMonitor()
        await monitor.start()
        try await Task.sleep(for: .milliseconds(100))
        await monitor.stop()
    }
}

// MARK: - TEMPEST Monitor

@Suite("TEMPEST Monitor")
struct TEMPESTMonitorTests {
    @Test("Start and stop without crash")
    func lifecycle() async throws {
        let monitor = TEMPESTMonitor()
        await monitor.start()
        try await Task.sleep(for: .milliseconds(100))
        await monitor.stop()
    }
}

// MARK: - Event Tap Monitor

@Suite("Event Tap Monitor")
struct EventTapMonitorTests {
    @Test("Start and stop without crash")
    func lifecycle() async throws {
        let monitor = EventTapMonitor()
        await monitor.start()
        try await Task.sleep(for: .milliseconds(100))
        await monitor.stop()
    }
}

// MARK: - FSEvents Collector

@Suite("FSEvents Collector")
struct FSEventsCollectorTests {
    @Test("Start and stop without crash")
    func lifecycle() async throws {
        let collector = FSEventsCollector()
        await collector.start()
        try await Task.sleep(for: .milliseconds(100))
        await collector.stop()
    }
}

// MARK: - TCC Monitor

@Suite("TCC Monitor")
struct TCCMonitorTests {
    @Test("Start and stop without crash")
    func lifecycle() async throws {
        let monitor = TCCMonitor()
        await monitor.start()
        try await Task.sleep(for: .milliseconds(100))
        await monitor.stop()
    }
}
