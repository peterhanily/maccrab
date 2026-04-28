// CollectorRegistry.swift
// MacCrabAgentKit
//
// v1.7.2: central registry of collector liveness. Each collector
// (16 of them at the time of writing) calls `recordTick(name:)`
// from its event-stream consumer in `MonitorTasks` whenever it
// produces an event. The heartbeat writer queries `snapshot()`
// every 30 s and embeds the result so the dashboard's ES Health
// panel can show "which collectors are alive" without hardcoding
// the list.
//
// Why one centralised registry rather than touching each
// collector actor: the monitor consumers in MonitorTasks already
// loop over `for await event in state.<collector>.events`. Adding
// one `await state.collectorRegistry.recordTick(...)` call per
// loop is the smallest possible change that preserves each
// collector's existing API and isolation.

import Foundation
import os.log
import MacCrabCore

public actor CollectorRegistry {

    // MARK: - Public types

    public struct Status: Codable, Sendable, Hashable {
        public let name: String
        /// Wall-clock time of the most recent event from this collector.
        /// Nil before the first event.
        public let lastTick: Date?
        /// Total events observed from this collector since daemon start.
        public let eventCount: UInt64
        /// Number of times the collector reported an internal error.
        public let errorCount: UInt64
        /// Most recent error message (last 200 chars), nil if none.
        public let lastError: String?
        /// Operator-meaningful expected tick interval — used by the
        /// dashboard to decide whether a missing tick is "normal idle"
        /// (e.g. USBMonitor between hotplug events) or "stalled".
        public let expectedIntervalSeconds: Int
        /// Derived health: true when `lastTick` is within 5× the
        /// expected interval (or `lastTick` is nil because the
        /// collector is event-driven and quiet by default).
        public let healthy: Bool

        public init(name: String, lastTick: Date?, eventCount: UInt64,
                    errorCount: UInt64, lastError: String?,
                    expectedIntervalSeconds: Int, healthy: Bool) {
            self.name = name
            self.lastTick = lastTick
            self.eventCount = eventCount
            self.errorCount = errorCount
            self.lastError = lastError
            self.expectedIntervalSeconds = expectedIntervalSeconds
            self.healthy = healthy
        }
    }

    // MARK: - Internal mutable state

    private struct InternalEntry {
        var lastTick: Date?
        var eventCount: UInt64 = 0
        var errorCount: UInt64 = 0
        var lastError: String?
        let expectedIntervalSeconds: Int
        /// Event-driven collectors (USB, BrowserExtension, etc.) can be
        /// idle for hours without that being unhealthy. Mark them
        /// `eventDriven` so the health computation tolerates long idle
        /// gaps when no events have been produced.
        let eventDriven: Bool
    }

    private var entries: [String: InternalEntry] = [:]
    /// v1.7.3 hotfix: cap on `entries`. The 16 known collectors plus
    /// generous headroom for lazy-registers from misconfigured paths.
    /// Without this cap, any code path that calls `recordTick` with a
    /// novel name string (e.g. a name that includes a PID, timestamp,
    /// or path component) would grow the dictionary unbounded — one
    /// of the three causes of the v1.7.2 → v1.7.3 memory regression
    /// observed at 2.31 GB resident.
    private let maxEntries: Int
    /// Aggregate count of events the daemon dropped (queue full,
    /// AsyncStream backpressure, parse error). Bumped from anywhere
    /// via `recordDrop(reason:)`.
    private var droppedEvents: UInt64 = 0

    private let logger = Logger(subsystem: "com.maccrab.agentkit", category: "collector-registry")

    public init(maxEntries: Int = 64) {
        self.maxEntries = max(16, maxEntries)
    }

    // MARK: - Registration

    /// Seed the registry with a known collector. Call once at daemon
    /// startup before the collector's event loop runs. Idempotent —
    /// re-registering with the same name just refreshes the
    /// `expectedIntervalSeconds` and clears any pre-existing error.
    public func register(name: String, expectedIntervalSeconds: Int, eventDriven: Bool = false) {
        entries[name] = InternalEntry(
            lastTick: nil,
            eventCount: 0,
            errorCount: 0,
            lastError: nil,
            expectedIntervalSeconds: max(1, expectedIntervalSeconds),
            eventDriven: eventDriven
        )
    }

    // MARK: - Tick / error / drop

    /// Record one event tick from a collector. Increments the event
    /// counter and refreshes `lastTick`.
    public func recordTick(name: String) {
        if var entry = entries[name] {
            entry.lastTick = Date()
            entry.eventCount &+= 1
            entries[name] = entry
            return
        }
        // v1.7.3: enforce the cap before lazy-registering. If full,
        // evict the least-recently-active entry (tiebreak: never-
        // ticked entries first, then oldest lastTick). This keeps
        // memory bounded under name-string variance — a buggy
        // collector that emits with PID-suffixed names can no
        // longer grow the dictionary unbounded.
        if entries.count >= maxEntries {
            let victimKey: String? = {
                // Prefer evicting an entry that has never ticked.
                if let neverTicked = entries.first(where: { $0.value.lastTick == nil })?.key {
                    return neverTicked
                }
                // Otherwise oldest-lastTick.
                return entries.min(by: { (a, b) in
                    (a.value.lastTick ?? .distantPast) < (b.value.lastTick ?? .distantPast)
                })?.key
            }()
            if let key = victimKey {
                entries.removeValue(forKey: key)
                logger.warning("CollectorRegistry: cap (\(self.maxEntries, privacy: .public)) reached — evicted '\(key, privacy: .public)' to make room for '\(name, privacy: .public)'")
            }
        }
        // Lazy-register on first tick — collectors that started
        // without explicit registration still appear in the panel.
        // v1.7.2 review fix: default `eventDriven: false` and a
        // generous 300 s expected interval. If a future polling
        // collector forgets explicit `register()` in DaemonSetup,
        // it now appears as a polling-class entry that goes
        // unhealthy after a stall (instead of silently passing
        // health checks as event-driven). The warning logs
        // surface the missing registration to operators.
        logger.warning("CollectorRegistry: lazy-registering unknown collector '\(name, privacy: .public)' — add an explicit register() call in DaemonSetup")
        entries[name] = InternalEntry(
            lastTick: Date(), eventCount: 1,
            errorCount: 0, lastError: nil,
            expectedIntervalSeconds: 300,
            eventDriven: false
        )
    }

    public func recordError(name: String, message: String) {
        guard var entry = entries[name] else { return }
        entry.errorCount &+= 1
        entry.lastError = String(message.prefix(200))
        entries[name] = entry
    }

    public func recordDrop(reason: String) {
        droppedEvents &+= 1
        if droppedEvents <= 10 || droppedEvents.isMultiple(of: 100) {
            logger.warning("Collector drop #\(self.droppedEvents): \(reason, privacy: .public)")
        }
    }

    // MARK: - Snapshot

    /// Snapshot for the heartbeat writer. Computes `healthy` per entry:
    ///   - event-driven collectors are healthy unless `errorCount > 0`
    ///     and `lastError` is recent
    ///   - polling collectors are unhealthy if `lastTick` is nil after
    ///     2× expected interval has elapsed (computed against first
    ///     tick), OR if `lastTick` is older than 5× expected interval.
    public func snapshot(now: Date = Date()) -> [Status] {
        entries.map { (name, entry) in
            let healthy: Bool
            if let last = entry.lastTick {
                let age = now.timeIntervalSince(last)
                healthy = entry.eventDriven
                    ? entry.errorCount == 0
                    : age < Double(entry.expectedIntervalSeconds) * 5
            } else {
                // No tick yet — event-driven collectors get the benefit
                // of the doubt; polling ones are pending.
                healthy = entry.eventDriven
            }
            return Status(
                name: name,
                lastTick: entry.lastTick,
                eventCount: entry.eventCount,
                errorCount: entry.errorCount,
                lastError: entry.lastError,
                expectedIntervalSeconds: entry.expectedIntervalSeconds,
                healthy: healthy
            )
        }
        .sorted { $0.name < $1.name }
    }

    public func droppedEventsTotal() -> UInt64 {
        droppedEvents
    }
}
