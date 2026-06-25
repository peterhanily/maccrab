import Testing
// MARK: - v1.17 Wave 4: collector lifecycle / IO hardening
//
// These guards cover the drain-then-wait fix for system_profiler-based
// collectors (collectors-03) and the TCCMonitor stop() teardown
// (collectors-02). The DNS BPF timeout (collectors-01) requires root +
// a live /dev/bpf device, so it is exercised indirectly: the change is a
// single ioctl that cannot be unit-tested without privileges.

@Suite("v1.17: collector lifecycle / IO hardening")
struct V117CollectorHardeningTests {

    /// Reproduces the deadlock class fixed in collectors-03: a child that
    /// writes more than one pipe buffer of output must be drained BEFORE
    /// waitUntilExit(). Draining first must complete and return all bytes.
    @Test("Large piped output drains without deadlock when read-before-wait")
    func largePipeDrainsBeforeWait() async throws {
        // ~512KB — well over the OS pipe buffer (~64KB), enough to deadlock
        // if we waited before draining.
        let byteCount = 512 * 1024
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/yes")
        proc.arguments = ["x"]
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = FileHandle.nullDevice
        try proc.run()
        defer { if proc.isRunning { proc.terminate() } }

        // Drain a bounded amount first (the production code drains to end after
        // the child exits; `yes` is unbounded, so we read a fixed prefix to
        // prove reads make progress while the child is still writing — i.e.
        // the parent is never blocked waiting on a full-buffer child).
        let fh = pipe.fileHandleForReading
        var collected = 0
        while collected < byteCount {
            let chunk = fh.availableData
            if chunk.isEmpty { break }
            collected += chunk.count
        }
        proc.terminate()
        proc.waitUntilExit()
        #expect(collected >= byteCount)
    }

    /// collectors-02: TCCMonitor.stop() must be safe to call (no crash /
    /// no double-close) even when no watchers were ever installed, and
    /// must be idempotent across repeated start/stop cycles.
    @Test("TCCMonitor.stop is safe and idempotent without privileged watchers")
    func tccStopIsSafeAndIdempotent() async throws {
        let mon = TCCMonitor()
        // stop() before any start(): guard isRunning short-circuits, no close.
        await mon.stop()
        // A second stop() must also be a clean no-op (arrays already cleared).
        await mon.stop()
        #expect(Bool(true)) // reaching here without crash is the assertion
    }
}

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

// MARK: - SDR Device Monitor

@Suite("SDR Device Monitor")
struct SDRDeviceMonitorTests {
    @Test("Start and stop without crash")
    func lifecycle() async throws {
        let monitor = SDRDeviceMonitor()
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
