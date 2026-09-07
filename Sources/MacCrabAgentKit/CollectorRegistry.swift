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
        /// v1.21.6-rc.45: WHY the collector is in this state, in operator
        /// words. `healthy` alone cannot distinguish "running and quiet" from
        /// "never started" — and an install shipped both
        /// FSEventsCollector and UltrasonicMonitor registered, never started,
        /// and rendered Healthy. A boolean that cannot express "I was never
        /// asked to run" is not a health signal.
        public let reason: String
        public let state: CollectorHealthState
        public let enabled: Bool

        public init(name: String, lastTick: Date?, eventCount: UInt64,
                    errorCount: UInt64, lastError: String?,
                    expectedIntervalSeconds: Int, healthy: Bool,
                    reason: String = "", state: CollectorHealthState? = nil,
                    enabled: Bool = true) {
            self.name = name
            self.lastTick = lastTick
            self.eventCount = eventCount
            self.errorCount = errorCount
            self.lastError = lastError
            self.expectedIntervalSeconds = expectedIntervalSeconds
            self.healthy = healthy
            self.reason = reason
            self.enabled = enabled
            self.state = state ?? .resolve(
                state: nil, enabled: enabled, healthy: healthy,
                reason: reason, lastError: lastError)
        }
    }

    // MARK: - Internal mutable state

    private struct InternalEntry {
        var lastTick: Date?
        var eventCount: UInt64 = 0
        var errorCount: UInt64 = 0
        var lastError: String?
        /// Cleared only by verified recovery, never by an unrelated event tick.
        var activeError: String?
        var lastVerifiedRecovery: Date?
        let expectedIntervalSeconds: Int
        /// Event-driven collectors (USB, BrowserExtension, etc.) can be
        /// idle for hours without that being unhealthy. Mark them
        /// `eventDriven` so the health computation tolerates long idle
        /// gaps when no events have been produced.
        let eventDriven: Bool
        /// Event-driven collectors that see CONTINUOUS traffic on any active
        /// Mac — unified log, DNS, FSEvents. For these, prolonged silence is
        /// evidence of death, not idleness, so they lose the never-ticked
        /// benefit of the doubt after a grace window. Without this, an
        /// event-driven collector that has never emitted anything reports
        /// healthy forever: `healthy` was `errorCount == 0` and the only
        /// mutator of `errorCount` (`recordError`) had no call sites, which is
        /// how two entirely dead sensors sat green on a shipped install.
        let expectsContinuousTraffic: Bool
        /// When `register()` (or lazy-registration) first saw this collector —
        /// the baseline for the never-ticked grace window.
        let registeredAt: Date
        /// v1.21.6 (RES-11): the collector's consumer loop RETURNED — its
        /// AsyncStream finished outside daemon shutdown. Nothing restarts these
        /// loops (only 6 of 17 sources go through `driveSource`), so this is a
        /// terminal state, not idleness.
        ///
        /// Deliberately a THIRD signal rather than reusing
        /// `expectsContinuousTraffic`: 11 of the 13 unsupervised collectors are
        /// legitimately bursty (USB hotplug, clipboard change, browser-extension
        /// install, MCP config edit, EDR discovery, rootkit scan, SDR, BTM,
        /// ultrasonic, event tap, system policy), and marking them
        /// continuous-traffic to get liveness coverage would ship false reds on
        /// every quiet machine.
        var streamEnded: Bool = false
        /// v1.21.6-rc.45: `start()` was actually called for this collector.
        /// Registration is not evidence of running: FSEventsCollector starts
        /// only `if !isRoot` (the shipped sysext IS root) and UltrasonicMonitor
        /// only under an opt-in flag, so both were registered and never started
        /// on every release install — and reported Healthy throughout, because
        /// a never-ticked event-driven collector was judged solely on
        /// `errorCount == 0` and `recordError` had no call sites.
        var started: Bool = false
        var enabled: Bool = true
        var disabledReason: String? = nil
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
    /// - Parameter started: whether this collector is actually started for this
    ///   boot. Defaults to `true` because most collectors start
    ///   unconditionally; pass `false` at a registration whose start is GATED
    ///   (platform check, opt-in flag, missing permission) and call
    ///   `recordStarted` where the gate opens. A gated collector that reports
    ///   `healthy` is worse than one that reports nothing.
    public func register(
        name: String,
        expectedIntervalSeconds: Int,
        eventDriven: Bool = false,
        expectsContinuousTraffic: Bool = false,
        started: Bool = true,
        enabled: Bool = true,
        disabledReason: String? = nil
    ) {
        entries[name] = InternalEntry(
            lastTick: nil,
            eventCount: 0,
            errorCount: 0,
            lastError: nil,
            expectedIntervalSeconds: max(1, expectedIntervalSeconds),
            eventDriven: eventDriven,
            expectsContinuousTraffic: expectsContinuousTraffic,
            registeredAt: Date(),
            started: started,
            enabled: enabled,
            disabledReason: disabledReason
        )
    }

    // MARK: - Tick / error / drop

    /// Mark that this collector's `start()` was actually invoked. Callers that
    /// register a collector but then skip starting it (platform gate, opt-in
    /// flag, missing permission) must NOT call this — that is exactly the state
    /// the operator needs to see.
    public func recordStarted(name: String) {
        guard var entry = entries[name] else { return }
        guard entry.enabled else { return }
        entry.started = true
        entries[name] = entry
    }

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
            eventDriven: false,
            expectsContinuousTraffic: false,
            registeredAt: Date(), started: true
        )
    }

    /// v1.21.6 (RES-11): a collector's consumer loop returned — its event stream
    /// finished — while the daemon was still running. Every collector's
    /// `continuation.finish()` lives only in its `stop()`, so outside shutdown
    /// this means the source is dead: no event can ever arrive again, and no
    /// restart is attempted for the 13 collectors that are not routed through
    /// `DaemonState.driveSource`. Terminal and unconditional — a dead sensor is
    /// not "idle", regardless of how bursty it normally is.
    ///
    /// Callers must not invoke this during shutdown; `MonitorSupervisor.start`
    /// gates on `!Task.isCancelled` for exactly that reason.
    public func recordStreamEnded(name: String) {
        guard var entry = entries[name] else { return }
        guard !entry.streamEnded else { return }   // idempotent: fault once
        entry.streamEnded = true
        entry.errorCount &+= 1
        entry.lastError = "event stream ended while the daemon was running — this collector is dead and nothing restarts it"
        entries[name] = entry
        logger.fault("CollectorRegistry: '\(name, privacy: .public)' event stream ENDED — sensor is dead, no restart is attempted. Coverage from this collector is lost until the engine restarts.")
    }

    public func recordError(name: String, message: String) {
        guard var entry = entries[name] else { return }
        entry.errorCount &+= 1
        entry.lastError = String(message.prefix(200))
        entry.activeError = entry.lastError
        entries[name] = entry
    }

    /// Report a successfully reconfigured source after checking its setup. This
    /// clears the current fault while preserving lifetime error history. It
    /// starts a new liveness grace period without inventing an event tick and
    /// cannot revive an ended consumer stream or an intentionally disabled one.
    public func recordRecovery(name: String, at date: Date = Date()) {
        guard var entry = entries[name], entry.enabled, !entry.streamEnded else { return }
        entry.activeError = nil
        entry.lastVerifiedRecovery = date
        entry.started = true
        entries[name] = entry
    }

    public func recordSetupStatus(name: String, status: CollectorSetupStatus) {
        switch status {
        case .configured: recordRecovery(name: name)
        case .unavailable(let reason): recordError(name: name, message: reason)
        }
    }

    public func recordDrop(reason: String) {
        droppedEvents &+= 1
        if droppedEvents <= 10 || droppedEvents.isMultiple(of: 100) {
            logger.warning("Collector drop #\(self.droppedEvents): \(reason, privacy: .public)")
        }
    }

    // MARK: - Snapshot

    /// Snapshot for the heartbeat writer. Explicit disablement is separate from
    /// health. Polling collectors get five intervals to tick; continuous event
    /// sources get ten. Reported errors remain failed until verified recovery;
    /// ended streams remain terminal. Lifetime error counts never reset here.
    public func snapshot(now: Date = Date()) -> [Status] {
        entries.map { (name, entry) in
            let state: CollectorHealthState
            let reason: String
            let silenceBudget = Double(entry.expectedIntervalSeconds) * 10
            if !entry.enabled {
                state = .disabled
                reason = entry.disabledReason ?? "disabled by configuration"
            } else if entry.streamEnded {
                state = .failed
                reason = "stream ended"
            } else if entry.activeError != nil {
                // Polling errors are failures too; a recent tick must not hide
                // an explicit collector error on the same heartbeat.
                state = .failed
                reason = "errors reported"
            } else if !entry.started {
                state = now.timeIntervalSince(entry.registeredAt) < silenceBudget
                    ? .starting : .failed
                reason = "not started"
            } else if let recovery = entry.lastVerifiedRecovery,
                      entry.lastTick.map({ $0 < recovery }) ?? true {
                let withinGrace = entry.eventDriven
                    ? (!entry.expectsContinuousTraffic
                        || now.timeIntervalSince(recovery) < silenceBudget)
                    : now.timeIntervalSince(recovery)
                        < Double(entry.expectedIntervalSeconds) * 5
                state = withinGrace ? (entry.eventDriven ? .healthy : .starting) : .stalled
                reason = withinGrace
                    ? "reconfigured, awaiting events"
                    : "no events after verified recovery"
            } else if let last = entry.lastTick {
                let age = now.timeIntervalSince(last)
                let receiving = entry.eventDriven
                    ? (!entry.expectsContinuousTraffic || age < silenceBudget)
                    : age < Double(entry.expectedIntervalSeconds) * 5
                state = receiving ? .healthy : .stalled
                reason = receiving
                    ? (entry.eventDriven ? "receiving events" : "ticking")
                    : (entry.eventDriven ? "silent past grace window" : "no tick within 5x its interval")
            } else if entry.eventDriven {
                let withinGrace = !entry.expectsContinuousTraffic
                    || now.timeIntervalSince(entry.registeredAt) < silenceBudget
                state = withinGrace ? .healthy : .stalled
                reason = withinGrace ? "started, no events yet" : "no events past grace window"
            } else {
                let withinGrace = now.timeIntervalSince(entry.registeredAt)
                    < Double(entry.expectedIntervalSeconds) * 5
                state = withinGrace ? .starting : .stalled
                reason = withinGrace ? "started, awaiting first tick" : "no tick within 5x its interval"
            }
            return Status(
                name: name,
                lastTick: entry.lastTick,
                eventCount: entry.eventCount,
                errorCount: entry.errorCount,
                lastError: entry.lastError,
                expectedIntervalSeconds: entry.expectedIntervalSeconds,
                healthy: state == .healthy,
                reason: reason,
                state: state,
                enabled: entry.enabled
            )
        }
        .sorted { $0.name < $1.name }
    }

    public func droppedEventsTotal() -> UInt64 {
        droppedEvents
    }
}
