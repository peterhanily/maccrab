// AppState.swift
// MacCrabApp
//
// Central state object for the MacCrab dashboard app.
// Reads real data from the daemon's SQLite database.

import Foundation
import AppKit
import Combine
import CSQLCipher
import MacCrabCore
import os.log

// MARK: - AppState

@MainActor
final class AppState: ObservableObject {

    // MARK: Published state

    @Published var isConnected: Bool = false
    @Published var eventsPerSecond: Int = 0
    @Published var rulesLoaded: Int = 0
    @Published var totalAlerts: Int = 0

    // MARK: Health signals (v1.4.3 "fail loud" surfaces)

    /// Snapshot of sysext-side storage errors, written by
    /// `StorageErrorTracker.writeSnapshot()` to
    /// `/Library/Application Support/MacCrab/storage_errors.json` and
    /// polled by `refreshStorageHealth()`. Nil when no errors have
    /// been recorded yet.
    struct StorageErrorSnapshot {
        var alertInsertErrors: Int
        var eventInsertErrors: Int
        var lastErrorMessage: String
        var lastErrorKind: String      // "alert_insert" | "event_insert"
        var lastErrorAt: Date?
    }
    @Published var storageErrors: StorageErrorSnapshot?

    /// Snapshot of sysext heartbeat. Sysext writes this every 30s via
    /// the heartbeatTimer. Dashboard considers it "stale" (detection
    /// silent) if age exceeds `heartbeatStaleThreshold`.
    struct HeartbeatSnapshot {
        var writtenAt: Date
        var uptimeSeconds: Int
        var eventsProcessed: UInt64
        var alertsEmitted: UInt64

        /// Sysext-reported Full Disk Access state. Nil means the heartbeat
        /// predates schema v2 (older sysext) so we fall back to the
        /// TCC.db / WAL heuristics. Non-nil is authoritative — the sysext
        /// runs as root and directly tests FDA by opening the
        /// TCC-protected system TCC.db; the app cannot do that because
        /// Unix perms + TCC both apply to a user-process probe.
        var sysextHasFDA: Bool?

        /// v1.7.1 schema v3: per-event-category counts over the last
        /// hour, queried by the daemon from the events table on each
        /// heartbeat tick. Nil for v1 / v2 heartbeats. Used by the
        /// rebuilt ES Health panel for the event-type breakdown matrix.
        var eventTypeCounts1h: [String: Int]?

        /// v1.7.2 schema v4: per-collector liveness snapshot. Replaces
        /// the hardcoded collector list in ESHealthView with daemon-
        /// driven status. Each entry carries name, last-tick, event
        /// count, error count, healthy bool, and the expected polling
        /// interval. Nil for v1–v3 heartbeats.
        var collectorHealth: [CollectorHealthEntry]?

        /// v1.7.2 schema v4: aggregate count of events the daemon has
        /// dropped (queue full, AsyncStream backpressure, parse error).
        /// Nil for v1–v3 heartbeats.
        var eventsDropped: UInt64?

        /// v1.21.4 Phase-1 D2: the ES sensor is in a degraded state — a
        /// file-event flood is spiking above baseline while the kernel is
        /// dropping messages (possible telemetry-drop evasion). Nil for
        /// pre-v1.21.4 heartbeats. Advisory only. Drives the menu-bar
        /// "protection degraded" flag + the ES Health banner.
        var esSensorDegraded: Bool?
        /// Human-readable D2 detail (drop counts + rates) for the ES Health
        /// banner. Empty/nil when not degraded.
        var esSensorDegradedDetail: String?

        /// Ages past this are considered stale → detection engine is
        /// either hung, crashed, or replaced by a silent no-op. 120s
        /// is ~4× the 30s write cadence: tolerates one missed tick and
        /// common IO hiccups without false-positive banner.
        static let staleThreshold: TimeInterval = 120
        var isStale: Bool { Date().timeIntervalSince(writtenAt) > Self.staleThreshold }

        /// v1.12.0 RC15: boot-phase tracker. The daemon writes phase
        /// updates at milestones during DaemonSetup.initialize: a
        /// "starting" heartbeat fires immediately at T+~0 s so the
        /// dashboard can show "Daemon: Starting (loading rules)..."
        /// instead of "Not running" for the 15-20 s of init work.
        /// Phase progression: starting → stores_ready → rules_loaded →
        /// ready. `nil` for v1.11.x and earlier daemons (treated as
        /// "ready" if liveness:true).
        var bootPhase: String?
        /// Wall-clock time at which the daemon started its boot. Used
        /// to display elapsed time in the dashboard's "starting" banner.
        var startedAt: Date?
        /// True when the daemon has finished initialising. Falls back
        /// to liveness for older daemons that don't write boot_phase.
        var isReady: Bool {
            if let phase = bootPhase { return phase == "ready" }
            // No boot_phase field → pre-RC15 daemon. Fall back to the
            // legacy liveness signal.
            return true
        }
    }

    public struct CollectorHealthEntry: Hashable, Codable {
        public let name: String
        public let lastTickUnix: TimeInterval?
        public let eventCount: UInt64
        public let errorCount: UInt64
        public let lastError: String?
        public let expectedIntervalSeconds: Int
        public let healthy: Bool
    }
    @Published var heartbeat: HeartbeatSnapshot?

    /// Rule-tampering state. Written by `RuleBundleInstaller` when the
    /// installed compiled_rules directory's SHA-256 hashes don't
    /// match the bundled manifest.json — either because an attacker
    /// modified the installed tree post-sync, OR because the shipped
    /// .app bundle itself was tampered with.
    struct RuleTamperSnapshot {
        var bundledTampered: Bool
        var installedTampered: Bool
        var mismatchedFileCount: Int
        var detectedAt: Date
    }
    @Published var ruleTamper: RuleTamperSnapshot?

    /// Callback MacCrabApp wires up so AppState's poll loop can
    /// trigger a sysext reactivation when the heartbeat goes stale.
    /// Returns true if the activation request was submitted. Without
    /// this, a crashed or deadlocked sysext required the user to
    /// notice the banner and relaunch manually. Watchdog respects a
    /// cooldown (`sysextWatchdogRetryAfter`) so we don't pound
    /// sysextd with activation requests on a persistently-failing
    /// install.
    var sysextWatchdogActivate: (() -> Void)?
    private var lastSysextWatchdogAt: Date?
    private let sysextWatchdogCooldown: TimeInterval = 300  // 5 min

    /// True when detection is in a degraded state — zero rules loaded,
    /// heartbeat stale, storage-write errors accumulating, or rule
    /// tampering detected. The statusbar icon swaps to a warning
    /// variant and the Overview shows a `DetectionHealthBanner`.
    /// Aggregate in one place so new health signals are a one-line
    /// change instead of sweeping every UI surface.
    var isProtectionDegraded: Bool {
        if isConnected && rulesLoaded == 0 { return true }
        if let snap = storageErrors, hasConcerningStorageError(snap) { return true }
        if let hb = heartbeat, hb.isStale { return true }
        if ruleTamper != nil { return true }
        // v1.21.4 Phase-1 D2: the ES sensor is losing telemetry to a
        // possible-evasion file-flood — surface it as degraded protection.
        if let hb = heartbeat, hb.esSensorDegraded == true { return true }
        return false
    }

    /// True if storage errors are accumulating — not just a single
    /// transient failure. v1.4.3 was too sensitive: one event insert
    /// returning SQLITE_BUSY (a routine consequence of WAL
    /// checkpoint contention, now fixed by busy_timeout=5000 in
    /// v1.4.4) fired the red banner. Require both: the most recent
    /// error within 2 minutes AND ≥ `storageErrorBannerThreshold`
    /// total failures. Below the threshold, single transients are
    /// logged but don't nag the user.
    private static let storageErrorBannerThreshold = 5
    func hasConcerningStorageError(_ s: StorageErrorSnapshot) -> Bool {
        guard let at = s.lastErrorAt else { return false }
        guard Date().timeIntervalSince(at) < 120 else { return false }
        return (s.alertInsertErrors + s.eventInsertErrors) >= Self.storageErrorBannerThreshold
    }

    /// Read the storage-errors snapshot file that the sysext writes.
    /// Called from `refresh()`; low cost (tiny file, no parsing on the
    /// hot path). Silent if file is absent — no errors yet recorded.
    func refreshStorageHealth() {
        let path = "/Library/Application Support/MacCrab/storage_errors.json"
        // v1.7.11: skip re-parse when file hasn't changed since last poll.
        let mtime = (try? FileManager.default.attributesOfItem(atPath: path)[.modificationDate]) as? Date
        if let mtime, let last = lastStorageHealthMtime, mtime <= last {
            return
        }
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return
        }
        lastStorageHealthMtime = mtime
        let alertErrs = json["alert_insert_errors"] as? Int ?? 0
        let eventErrs = json["event_insert_errors"] as? Int ?? 0
        let msg = json["last_error_message"] as? String ?? ""
        let kind = json["last_error_kind"] as? String ?? ""
        let at = (json["last_error_at_unix"] as? TimeInterval).flatMap {
            $0 > 0 ? Date(timeIntervalSince1970: $0) : nil
        }
        storageErrors = StorageErrorSnapshot(
            alertInsertErrors: alertErrs,
            eventInsertErrors: eventErrs,
            lastErrorMessage: msg,
            lastErrorKind: kind,
            lastErrorAt: at
        )
    }

    /// Read the rule-tamper snapshot that RuleBundleInstaller writes
    /// when verifyManifest finds a SHA-256 mismatch. Absent file →
    /// healthy (no tamper); any present file is a live tamper
    /// indicator the Overview banner surfaces.
    func refreshRuleTamper() {
        let path = "/Library/Application Support/MacCrab/rule_tamper.json"
        // v1.7.11: skip re-parse when file hasn't changed since last poll.
        let mtime = (try? FileManager.default.attributesOfItem(atPath: path)[.modificationDate]) as? Date
        if let mtime, let last = lastRuleTamperMtime, mtime <= last {
            return
        }
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            // No file → no tamper detected. Clear any stale state.
            if ruleTamper != nil { ruleTamper = nil }
            return
        }
        lastRuleTamperMtime = mtime
        ruleTamper = RuleTamperSnapshot(
            bundledTampered: json["bundled_tampered"] as? Bool ?? false,
            installedTampered: json["installed_tampered"] as? Bool ?? false,
            mismatchedFileCount: json["mismatched_file_count"] as? Int ?? 0,
            detectedAt: Date(timeIntervalSince1970: json["detected_at_unix"] as? TimeInterval ?? 0)
        )
    }

    /// Read the heartbeat snapshot the sysext writes every 30s. An
    /// absent file (first run) or a stale timestamp (>120s) both
    /// indicate the detection engine is silent — the dashboard
    /// surfaces a banner and the statusbar icon flips.
    ///
    /// v1.7.5: heartbeat is split into TWO files. `heartbeat.json` is
    /// the minimal liveness file written synchronously by the daemon's
    /// dispatch-thread livenessTimer (cannot deadlock). `heartbeat_rich.
    /// json` carries the per-event-category counts, collector health,
    /// and drop counter — written async by the heartbeat Task.
    /// Liveness gating reads only the first file; the rich fields are
    /// merged in if the second file exists. Pre-v1.7.5 daemons wrote
    /// everything to heartbeat.json — those fields still decode if
    /// present (backward-compatible).
    func refreshHeartbeat() {
        let path = "/Library/Application Support/MacCrab/heartbeat.json"
        // v1.7.11: skip re-parse when neither heartbeat.json nor
        // heartbeat_rich.json have changed since the last successful
        // refresh. The daemon writes heartbeat every 30 s; the dashboard
        // polls every 5 s; without this guard 5 of every 6 polls do a
        // full Foundation autorelease cycle (Data + JSONSerialization +
        // dict downcasts) AND an unconditional `heartbeat = ...` @Published
        // mutation that triggers SwiftUI body re-evaluation across every
        // view bound to AppState. The Events tab in particular re-binds
        // its NSTableView, which inflates Auto Layout constraints that
        // never release until the view is dismantled. Field-reproduced:
        // ~333 constraints/sec, ~1.5 GB/day on a parked dashboard.
        let richPathForMtime = "/Library/Application Support/MacCrab/heartbeat_rich.json"
        let mtime = (try? FileManager.default.attributesOfItem(atPath: path)[.modificationDate]) as? Date
        let richMtime = (try? FileManager.default.attributesOfItem(atPath: richPathForMtime)[.modificationDate]) as? Date
        let combined = [mtime, richMtime].compactMap { $0 }.max()
        if let combined, let last = lastHeartbeatMtime, combined <= last {
            return
        }
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let writtenAtUnix = json["written_at_unix"] as? TimeInterval else {
            // No file yet — cold start, mark as stale so the user sees
            // the banner until the first write arrives. Without this
            // the banner would never appear for a hung-from-start
            // sysext because `heartbeat` stays nil.
            if heartbeat == nil && isConnected {
                heartbeat = HeartbeatSnapshot(
                    writtenAt: .distantPast,
                    uptimeSeconds: 0,
                    eventsProcessed: 0,
                    alertsEmitted: 0,
                    sysextHasFDA: nil
                )
            }
            return
        }
        // v1.7.2 schema v4 — collector_health array of dicts.
        // Pre-ship review fix: don't silently drop malformed entries —
        // log a warning so operators see "the daemon sent garbage in
        // its heartbeat" instead of just "fewer collectors than
        // expected." Bug-shaped daemons surface; truncated dashboards
        // don't.
        var collectorHealth: [CollectorHealthEntry]? = nil
        if let arr = json["collector_health"] as? [[String: Any]] {
            var decoded: [CollectorHealthEntry] = []
            decoded.reserveCapacity(arr.count)
            var droppedCount = 0
            for d in arr {
                guard let name = d["name"] as? String,
                      let healthy = d["healthy"] as? Bool,
                      let interval = d["expected_interval_seconds"] as? Int else {
                    droppedCount += 1
                    continue
                }
                decoded.append(CollectorHealthEntry(
                    name: name,
                    lastTickUnix: d["last_tick_unix"] as? TimeInterval,
                    eventCount: (d["event_count"] as? UInt64)
                        ?? UInt64(d["event_count"] as? Int ?? 0),
                    errorCount: (d["error_count"] as? UInt64)
                        ?? UInt64(d["error_count"] as? Int ?? 0),
                    lastError: d["last_error"] as? String,
                    expectedIntervalSeconds: interval,
                    healthy: healthy
                ))
            }
            if droppedCount > 0 {
                Logger(subsystem: "com.maccrab.app", category: "heartbeat")
                    .warning("Dropped \(droppedCount, privacy: .public) malformed collector_health entries from heartbeat — daemon may be writing inconsistent payload")
            }
            collectorHealth = decoded
        }

        // v1.7.5: rich fields may live in a separate file if the
        // daemon is v1.7.5+. Pre-v1.7.5 daemons wrote them inline to
        // heartbeat.json; we still decode them from there as a
        // fallback. This makes the dashboard backward-compatible
        // with any v1.7.0–v1.7.4 sysext.
        var richEventTypeCounts: [String: Int]? = json["event_type_counts_1h"] as? [String: Int]
        var richCollectorHealth: [CollectorHealthEntry]? = collectorHealth
        var richDropped: UInt64? = (json["events_dropped"] as? UInt64)
            ?? UInt64(json["events_dropped"] as? Int ?? 0)
        // v1.21.4 Phase-1 D2: sensor-degraded advisory (rich-file only).
        var richSensorDegraded: Bool? = json["es_sensor_degraded"] as? Bool
        var richSensorDegradedDetail: String? = json["es_sensor_degraded_detail"] as? String
        let richPath = "/Library/Application Support/MacCrab/heartbeat_rich.json"
        if let richData = try? Data(contentsOf: URL(fileURLWithPath: richPath)),
           let richJSON = try? JSONSerialization.jsonObject(with: richData) as? [String: Any] {
            if let counts = richJSON["event_type_counts_1h"] as? [String: Int] {
                richEventTypeCounts = counts
            }
            if let arr = richJSON["collector_health"] as? [[String: Any]] {
                var decoded: [CollectorHealthEntry] = []
                decoded.reserveCapacity(arr.count)
                for d in arr {
                    guard let name = d["name"] as? String,
                          let healthy = d["healthy"] as? Bool,
                          let interval = d["expected_interval_seconds"] as? Int else { continue }
                    decoded.append(CollectorHealthEntry(
                        name: name,
                        lastTickUnix: d["last_tick_unix"] as? TimeInterval,
                        eventCount: (d["event_count"] as? UInt64)
                            ?? UInt64(d["event_count"] as? Int ?? 0),
                        errorCount: (d["error_count"] as? UInt64)
                            ?? UInt64(d["error_count"] as? Int ?? 0),
                        lastError: d["last_error"] as? String,
                        expectedIntervalSeconds: interval,
                        healthy: healthy
                    ))
                }
                richCollectorHealth = decoded
            }
            if let dropped = richJSON["events_dropped"] as? UInt64 {
                richDropped = dropped
            } else if let dropped = richJSON["events_dropped"] as? Int {
                richDropped = UInt64(dropped)
            }
            if let degraded = richJSON["es_sensor_degraded"] as? Bool {
                richSensorDegraded = degraded
            }
            if let detail = richJSON["es_sensor_degraded_detail"] as? String, !detail.isEmpty {
                richSensorDegradedDetail = detail
            }
        }

        var snapshot = HeartbeatSnapshot(
            writtenAt: Date(timeIntervalSince1970: writtenAtUnix),
            uptimeSeconds: json["uptime_seconds"] as? Int ?? 0,
            eventsProcessed: (json["events_processed"] as? UInt64)
                ?? UInt64(json["events_processed"] as? Int ?? 0),
            alertsEmitted: (json["alerts_emitted"] as? UInt64)
                ?? UInt64(json["alerts_emitted"] as? Int ?? 0),
            sysextHasFDA: json["sysext_has_fda"] as? Bool,
            eventTypeCounts1h: richEventTypeCounts,
            collectorHealth: richCollectorHealth,
            eventsDropped: richDropped
        )
        snapshot.esSensorDegraded = richSensorDegraded
        snapshot.esSensorDegradedDetail = richSensorDegradedDetail
        // v1.12.0 RC15: pull the boot-phase tracker out of the payload
        // when it's there. Older daemons (v1.11.x and earlier) won't
        // write this field; snapshot.isReady falls back to liveness for
        // those.
        snapshot.bootPhase = json["boot_phase"] as? String
        if let startedAt = json["started_at_unix"] as? TimeInterval {
            snapshot.startedAt = Date(timeIntervalSince1970: startedAt)
        }
        heartbeat = snapshot
        // Record successful parse so the next call short-circuits when
        // neither heartbeat.json nor heartbeat_rich.json have been
        // re-written by the daemon.
        lastHeartbeatMtime = combined
    }

    /// v1.7.11: mtime tracking for the three refresh paths that previously
    /// re-parsed and re-published their snapshot every 5 s regardless of
    /// whether the underlying file had changed. Each unconditional
    /// @Published write triggered a SwiftUI body re-eval across every
    /// view bound to AppState (it's @ObservedObject, not a derived
    /// projection), which on Events drove ~333 Auto Layout
    /// constraints/sec via NSTableView rebinds. Mirroring the
    /// `lastLineageMtime` / `lastMCPBaselineMtime` / `lastTCCSnapshotMtime`
    /// pattern that already gates the AI/MCP/TCC paths.
    private var lastHeartbeatMtime: Date?
    private var lastStorageHealthMtime: Date?
    private var lastRuleTamperMtime: Date?

    /// Path to the daemon-written security-tool integrations snapshot.
    /// `IntegrationsView` reads this instead of re-running its own
    /// scan, so the dashboard picks up the daemon's enriched results
    /// (`isRunning` queries done at root privilege catch launchds the
    /// user-side actor can't reliably enumerate).
    func integrationsSnapshotPath() -> String {
        dataDir + "/integrations_snapshot.json"
    }

    /// mtime of the lineage snapshot the last time we successfully
    /// decoded it. Used by `refreshAgentLineage` to skip the JSON
    /// decode when the daemon hasn't rewritten the file since last
    /// poll. Dashboard polls every 10 s; daemon writes every 30 s, so
    /// 2 of every 3 polls would otherwise re-decode an unchanged file.
    /// Worst-case payload is ~38 MB at theoretical caps and we don't
    /// want to burn UI thread time decoding it twice for nothing.
    private var lastLineageMtime: Date?

    /// mtime of the rule-telemetry snapshot. v1.7.1.
    private var lastRuleTelemetryMtime: Date?

    /// Refresh per-rule fire counts + exec time stats from the daemon
    /// snapshot at `<dataDir>/rule_telemetry.json`. The rebuilt
    /// `RuleBrowser` reads these to show fire-count, last-fired, and
    /// mean-exec-ms columns on each rule row.
    func refreshRuleTelemetry() {
        let path = dataDir + "/rule_telemetry.json"
        let mtime = (try? FileManager.default.attributesOfItem(atPath: path)[.modificationDate]) as? Date
        if let mtime, let last = lastRuleTelemetryMtime, mtime <= last {
            return
        }
        guard let snapshot = RuleEngine.readTelemetrySnapshot(at: path) else { return }
        var dict: [String: RuleEngine.RuleStats] = [:]
        dict.reserveCapacity(snapshot.stats.count)
        for s in snapshot.stats { dict[s.ruleId] = s }
        ruleTelemetry = dict
        ruleTelemetryLastRefresh = snapshot.writtenAt
        lastRuleTelemetryMtime = mtime
    }

    /// Refresh the AI agent-lineage timeline from the daemon-written
    /// snapshot at `<dataDir>/agent_lineage.json`. The daemon refreshes
    /// every 30 s on the heartbeat tick. We `stat()` first and skip
    /// the decode entirely when the mtime hasn't advanced — cheap
    /// path for the common case.
    func refreshAgentLineage() async {
        let path = dataDir + "/agent_lineage.json"
        let mtime = (try? FileManager.default.attributesOfItem(atPath: path)[.modificationDate]) as? Date
        if let mtime, let last = lastLineageMtime, mtime <= last {
            return
        }
        // APPCORE-03: the Data(contentsOf:) + JSON decode here can be up
        // to ~38 MB at the writer's caps. Keep the mtime gate and the
        // @Published publish on @MainActor; run only the read+decode
        // off-main (returns a Sendable LineageSnapshot?), mirroring
        // warmUpStoresOffMain. No @Published var is touched off-actor.
        let path_ = path
        let snapshot = await Task.detached(priority: .userInitiated) {
            AgentLineageService.readSnapshot(at: path_)
        }.value
        guard let snapshot else {
            // Silently keep the previous list — flickering to "no
            // sessions" between polls is worse than slightly-stale data.
            return
        }
        aiSessions = snapshot.sessions
        aiSessionsLastRefresh = snapshot.writtenAt
        lastLineageMtime = mtime
    }

    /// Refresh threat-intelligence IOC counts AND the full IOC set
    /// from the daemon-written cache file at
    /// `<dataDir>/threat_intel/feed_cache.json`. Surfaces both the
    /// counts (in the metrics row) and the actual lists (in the
    /// browser sections) of `ThreatIntelView`. Read-only — the
    /// daemon's `ThreatIntelFeed` is the producer; we just decode
    /// the cache it writes.
    ///
    /// Gated by mtime: the daemon-side feed updater runs on a 4-hour
    /// cadence so the file rarely changes, and decoding a 100K-hash
    /// set on every 10 s poll would burn UI thread time for nothing.
    func refreshThreatIntelStats() async {
        let cacheDir = dataDir + "/threat_intel"
        let cachePath = cacheDir + "/feed_cache.json"
        let mtime = (try? FileManager.default.attributesOfItem(atPath: cachePath)[.modificationDate]) as? Date
        if let mtime, let last = lastThreatIntelMtime, mtime <= last {
            return
        }

        // APPCORE-03: cachedIOCs decodes the full IOC cache (a ~100K-hash
        // set per the gating comment above). Keep the mtime gate and the
        // @Published publish on @MainActor; run only the read+decode
        // off-main (returns a Sendable IOCSet?), mirroring
        // warmUpStoresOffMain. No @Published var is touched off-actor.
        let cacheDir_ = cacheDir
        guard let iocs = await Task.detached(priority: .userInitiated, operation: {
            ThreatIntelFeed.cachedIOCs(at: cacheDir_)
        }).value else {
            // Daemon not running, file not yet written, or cache empty —
            // leave the previous values so the UI doesn't flicker to
            // zero between polls.
            return
        }
        threatIntelIOCs = iocs
        threatIntelStats = ThreatIntelStats(
            hashes: iocs.hashes.count,
            ips: iocs.ips.count,
            domains: iocs.domains.count,
            urls: iocs.urls.count,
            lastUpdate: iocs.lastUpdate
        )
        lastThreatIntelMtime = mtime
    }

    /// Alerts whose `ruleId` indicates an IOC match — the dashboard
    /// renders these in the ThreatIntelView "Recent Matches" section
    /// so the analyst can see what the IOC list is actually catching.
    /// Pure derived state; no extra DB query needed.
    var threatIntelMatches: [AlertViewModel] {
        dashboardAlerts.filter { alert in
            // Part A writes all IOC matches under the
            // `maccrab.threat-intel.` prefix; keep the legacy DNS id
            // for pre-existing alerts that used the old naming.
            alert.ruleId.hasPrefix("maccrab.threat-intel.")
                || alert.ruleId == "maccrab.dns.threat-intel-match"
        }
    }

    /// Trigger a one-shot threat-intel feed refresh on the daemon and
    /// re-pull the local cache view as soon as the daemon writes the
    /// new file. Sends SIGUSR1 to the sysext (preferred) and to the
    /// legacy `maccrabd` standalone daemon (dev fallback). Force-
    /// invalidates the mtime gate so the next poll picks up the new
    /// snapshot regardless of timestamps.
    func refreshThreatIntelNow() async {
        // v1.17: drop a `refresh-intel` request into the root daemon's
        // inbox (the file-IPC channel the sysext polls every 5s). The
        // pkill -USR1 below fails EPERM against a uid-0 sysext, so the
        // inbox request is the real release-path trigger; pkill stays
        // ONLY as the same-uid `maccrabd` dev fallback.
        _ = V2LiveDataProvider.writeInboxRefreshRequest(inboxDir: dataDir + "/inbox")
        // SIGUSR1 to the dev daemon — pkill is silent when the named
        // process doesn't exist, so this is safe in either context.
        _ = runShell(["/usr/bin/pkill", "-USR1", "-x", "maccrabd"])

        // Drop the mtime gate so the next refresh re-decodes even if
        // the daemon writes the file with the same mtime second.
        lastThreatIntelMtime = nil

        // Wait briefly for the daemon to fetch + write, then re-pull.
        // Real-world abuse.ch CSV download is ~2-5s; we sleep 6s to
        // give it headroom, but we also keep polling on the regular
        // 10s pollTimer so a slow refresh resolves on its own.
        try? await Task.sleep(nanoseconds: 6 * 1_000_000_000)
        await refreshThreatIntelStats()
    }

    /// Run a shell command and return its exit status. Used for the
    /// SIGUSR1 refresh path. Errors are swallowed because both pkill
    /// targets may be absent (sysext not yet activated or maccrabd
    /// not running) and that's not an error condition.
    @discardableResult
    private func runShell(_ argv: [String]) -> Int32 {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: argv[0])
        p.arguments = Array(argv.dropFirst())
        p.standardOutput = nil
        p.standardError = nil
        do {
            try p.run()
            p.waitUntilExit()
            return p.terminationStatus
        } catch {
            return -1
        }
    }

    /// Lazily construct (or rebuild on config drift) the user-side LLM
    /// stack: `LLMService` + `TriageService`. The config lives in
    /// `~/Library/Application Support/MacCrab/llm_config.json` and is
    /// owned by `SettingsView.syncLLMConfig`. We re-check at most once
    /// per `llmConfigCheckInterval` to avoid re-decoding the file on
    /// every triage call.
    ///
    /// Returns nil when LLM is disabled, when the chosen provider has
    /// no API key, or when the backend reports unavailable. Callers
    /// should surface "LLM not configured" UI when nil.
    private func ensureLLMService() async -> LLMService? {
        if let svc = llmService,
           Date().timeIntervalSince(lastLLMConfigCheckedAt) < llmConfigCheckInterval {
            return svc
        }
        lastLLMConfigCheckedAt = Date()

        let configPath = NSHomeDirectory() + "/Library/Application Support/MacCrab/llm_config.json"
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: configPath)),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            llmService = nil
            triageService = nil
            return nil
        }

        var cfg = LLMConfig()
        if let v = json["enabled"] as? Bool { cfg.enabled = v }
        if let v = json["provider"] as? String, let p = LLMProvider(rawValue: v) { cfg.provider = p }
        if let v = json["ollama_url"] as? String { cfg.ollamaURL = v }
        if let v = json["ollama_model"] as? String { cfg.ollamaModel = v }
        if let v = json["ollama_api_key"] as? String { cfg.ollamaAPIKey = v }
        if let v = json["claude_api_key"] as? String { cfg.claudeAPIKey = v }
        if let v = json["claude_model"] as? String { cfg.claudeModel = v }
        if let v = json["openai_url"] as? String { cfg.openaiURL = v }
        if let v = json["openai_api_key"] as? String { cfg.openaiAPIKey = v }
        if let v = json["openai_model"] as? String { cfg.openaiModel = v }
        if let v = json["mistral_api_key"] as? String { cfg.mistralAPIKey = v }
        if let v = json["mistral_model"] as? String { cfg.mistralModel = v }
        if let v = json["gemini_api_key"] as? String { cfg.geminiAPIKey = v }
        if let v = json["gemini_model"] as? String { cfg.geminiModel = v }
        // Off-by-default operator opt-in for the multi-round agentic
        // campaign investigator (multiplies LLM cost/latency).
        if let v = json["agentic_investigation_enabled"] as? Bool { cfg.agenticInvestigationEnabled = v }

        let svc = await LLMService.makeFromConfig(cfg)
        llmService = svc
        triageService = svc.map { TriageService(llm: $0) }
        // Build the agentic investigator only when both a backend is
        // available AND the operator opted in. Stays nil otherwise so
        // `investigateCampaign` cleanly no-ops.
        agenticInvestigator = (svc != nil && cfg.agenticInvestigationEnabled)
            ? svc.map { AgenticInvestigator(llm: $0) }
            : nil
        return svc
    }

    /// Operator-initiated multi-round agentic investigation of a
    /// detected campaign. Gated behind `agentic_investigation_enabled`
    /// (default OFF) — no-ops with a cleared placeholder when the flag
    /// is unset, no backend is configured, or the loop yields no report.
    /// Result lands in `campaignInvestigations[campaign.id]` for the
    /// campaign-detail UI. Advisory only; the report's recommendations
    /// are never auto-executed.
    func investigateCampaign(_ campaign: CampaignDetector.Campaign) async {
        // Mark "investigating"
        campaignInvestigations[campaign.id] = .some(nil)

        guard await ensureLLMService() != nil, let investigator = agenticInvestigator else {
            campaignInvestigations[campaign.id] = .none
            return
        }

        // Wire describe_rule against the dashboard's already-loaded rule
        // set. The other two fetchers keep their safe no-op defaults —
        // the dashboard holds no live event-store actor to query.
        let loadedRules = rules
        let fetchers = InvestigationContextFetchers(
            describeRule: { ruleId in
                loadedRules.first { $0.id == ruleId }?.title
            }
        )

        let report = await investigator.investigate(campaign: campaign, fetchers: fetchers)
        campaignInvestigations[campaign.id] = .some(report)
    }

    /// Ask the user-side TriageService for a disposition recommendation
    /// on the alert under the cursor in `AlertDetailView`. Result lands
    /// in `triageRecommendations[alertId]` so the view can re-render
    /// with the verdict + rationale next to the alert.
    ///
    /// Marks the entry as `nil` (placeholder) before the LLM call
    /// returns so the UI can show "Triage in progress" without races.
    func triageAlert(_ alert: AlertViewModel) async {
        // Mark "thinking"
        triageRecommendations[alert.id] = .some(nil)

        guard await ensureLLMService() != nil, let triage = triageService else {
            triageRecommendations[alert.id] = .none
            return
        }

        // Hydrate a minimal `Alert` from the view model — we only need
        // the fields TriageService.buildPrompt reads. The app-side
        // `Severity` mirror and the core enum share rawValue strings,
        // so convert via that. Default to `.medium` if a future
        // value lands in one but not the other.
        let coreSeverity = MacCrabCore.Severity(rawValue: alert.severity.rawValue) ?? .medium
        let coreAlert = Alert(
            id: alert.id,
            timestamp: alert.timestamp,
            ruleId: alert.ruleId,
            ruleTitle: alert.ruleTitle,
            severity: coreSeverity,
            eventId: alert.eventId,
            processPath: alert.processPath.isEmpty ? nil : alert.processPath,
            processName: alert.processName.isEmpty ? nil : alert.processName,
            description: alert.description.isEmpty ? nil : alert.description,
            mitreTactics: nil,
            mitreTechniques: alert.mitreTechniques.isEmpty ? nil : alert.mitreTechniques,
            suppressed: alert.suppressed
        )

        // Cluster size approximation: count alerts in `dashboardAlerts`
        // that share rule + process. Cheap O(n) over the visible set.
        let similarCount = dashboardAlerts.filter {
            $0.ruleId == alert.ruleId && $0.processName == alert.processName
        }.count

        let recommendation = await triage.recommend(
            for: coreAlert,
            similarCount: similarCount,
            dailyTotal: dashboardAlerts.count
        )
        triageRecommendations[alert.id] = .some(recommendation)
    }

    /// Drop any cached LLM stack so the next triage call rebuilds from
    /// the latest `llm_config.json`. Called by SettingsView whenever
    /// the user changes provider, model, or API key — guarantees the
    /// next triage uses the new config without waiting for the 30 s
    /// re-check window.
    func invalidateLLMConfigCache() {
        llmService = nil
        triageService = nil
        lastLLMConfigCheckedAt = .distantPast
    }

    /// Full Disk Access state.
    ///
    /// macOS treats `com.maccrab.app` (this process) and `com.maccrab.agent`
    /// (the sysext) as SEPARATE TCC principals — each needs its own FDA
    /// grant. `fullDiskAccessGranted` is the conjunction: both must be
    /// allowed for the banner to clear. The separate booleans let the
    /// banner say which one is missing so the user doesn't go hunting.
    ///
    /// Defaults to true so the dashboard doesn't flash a warning on launch
    /// before the first probe runs.
    @Published var fullDiskAccessGranted: Bool = true
    /// The app itself can read TCC.db — means Settings → Privacy & Security
    /// → Full Disk Access has MacCrab.app allowed.
    @Published var appHasFDA: Bool = true
    /// The sysext has FDA for "MacCrab Endpoint Security Extension". The
    /// primary signal is `heartbeat.sysextHasFDA` (the sysext probes its
    /// own FDA as root and writes the result). Falls back to a user TCC.db
    /// query when the heartbeat pre-dates schema v2, and to a 30-minute
    /// WAL mtime window when no FDA data is available at all.
    @Published var sysextHasFDA: Bool = true

    /// User explicitly dismissed the FDA banner via the "Dismiss" button.
    /// An escape hatch for when our detection is wrong and the banner
    /// persists despite FDA actually being granted. Persisted to
    /// UserDefaults; auto-cleared when detection confirms both principals
    /// are granted so future revocations re-surface the banner.
    @Published var fdaBannerDismissedByUser: Bool = UserDefaults.standard.bool(forKey: "fdaBannerDismissedByUser")
    @Published var recentAlerts: [AlertViewModel] = []
    @Published var dashboardAlerts: [AlertViewModel] = []
    @Published var events: [EventViewModel] = []
    /// True when the keyset cursor for the alerts/events list still has older
    /// rows behind it. Drives the "Load older" affordance in `AlertDashboard`
    /// and `EventStream`. Set when an initial load returns a full page; cleared
    /// when a paged fetch comes back short (end-of-table).
    @Published var hasMoreAlerts: Bool = false
    @Published var hasMoreEvents: Bool = false
    /// True while the Events tab is showing FTS5 search results rather than
    /// the live time-ordered window. Used by `loadEventsIncremental` to skip
    /// its prepend so a relevance-ordered search isn't clobbered by newer
    /// rows arriving on the poll tick.
    @Published var eventSearchActive: Bool = false
    /// Mirror flag for the Alerts tab — same reasoning as `eventSearchActive`
    /// but the underlying query is LIKE-based (no FTS5 on the alerts table).
    @Published var alertSearchActive: Bool = false
    /// Guards against rapid double-clicks on "Load older". Two concurrent
    /// `loadOlderAlerts` calls would both read the same cursor, fire the
    /// same SQL, and rely on the dedup `Set` to discard one — correct but
    /// wasted DB + memory churn. Set on entry, cleared on exit.
    /// v1.8.0 audit fix: published so the UI can disable the button + show
    /// a "Loading…" label while the keyset fetch is in flight.
    @Published var isLoadingOlderAlerts: Bool = false
    @Published var isLoadingOlderEvents: Bool = false
    @Published var rules: [RuleViewModel] = []

    /// Threat intel stats for the dashboard
    struct ThreatIntelStats {
        var hashes: Int = 0
        var ips: Int = 0
        var domains: Int = 0
        var urls: Int = 0
        var lastUpdate: Date?
    }
    @Published var threatIntelStats = ThreatIntelStats()

    /// Full IOC set the daemon currently holds — surfaces the actual
    /// hash / IP / domain / URL strings to the dashboard browser
    /// rather than just the counts. Refreshed on the same path as
    /// `threatIntelStats` (single decoder call) and gated by mtime.
    @Published var threatIntelIOCs: ThreatIntelFeed.IOCSet?
    private var lastThreatIntelMtime: Date?

    /// Fleet telemetry connection status
    struct FleetStatus {
        var isConfigured: Bool = false
        var fleetURL: String = ""
    }
    @Published var fleetStatus = FleetStatus()

    /// LLM backend status
    struct LLMStatus {
        var isConfigured: Bool = false
        var provider: String = ""
    }
    @Published var llmStatus = LLMStatus()

    /// AI analysis alerts (investigation summaries + defense recommendations)
    @Published var aiAnalysisAlerts: [AlertViewModel] = []

    /// Per-AI-tool session timelines, populated from the daemon-written
    /// `agent_lineage.json` snapshot. Most-recently-active session first.
    /// Empty until either the daemon is running and has detected an AI
    /// tool, or a snapshot from a previous run is present on disk.
    @Published var aiSessions: [AgentSessionSnapshot] = []
    /// When the lineage snapshot was last refreshed from disk. Used by
    /// the timeline view to render a "Updated <relative time>" caption.
    @Published var aiSessionsLastRefresh: Date?

    /// Per-rule runtime telemetry, populated from `rule_telemetry.json`
    /// (v1.7.1). Keyed by ruleId for O(1) lookup when rendering rows.
    @Published var ruleTelemetry: [String: RuleEngine.RuleStats] = [:]
    @Published var ruleTelemetryLastRefresh: Date?

    // MARK: - LLM-orchestration services (v1.6.10 "move out of sysext")
    //
    // Three services that previously lived as orphan vars in DaemonState
    // (declared, never wired) — outbound HTTPS with vendor API keys does
    // not belong at ES-entitlement root privilege. Now hosted on the
    // user-side AppState alongside the LLM config that the dashboard
    // already owns. Constructed lazily from `llm_config.json` on first
    // use; reset whenever Settings rewrites the config.

    private var llmService: LLMService?
    private var triageService: TriageService?
    /// Built lazily by `ensureLLMService` ONLY when the operator has
    /// opted in via `agentic_investigation_enabled` in llm_config.json.
    /// nil otherwise — `investigateCampaign` no-ops when nil.
    private var agenticInvestigator: AgenticInvestigator?
    private var lastLLMConfigCheckedAt: Date = .distantPast
    private let llmConfigCheckInterval: TimeInterval = 30  // seconds

    /// In-flight / completed InvestigationReport per campaign, keyed by
    /// campaign ID, surfaced inline in the campaign-detail UI. `nil`
    /// value = "still investigating" placeholder; entry absent = "not
    /// yet requested".
    @Published var campaignInvestigations: [String: InvestigationReport?] = [:]

    /// In-flight TriageRecommendation per alert, surfaced inline in
    /// `AlertDetailView`. Keyed by alert ID. `nil` value = "still
    /// thinking" placeholder; entry absent = "not yet requested".
    @Published var triageRecommendations: [String: TriageRecommendation?] = [:]

    /// Security posture score (0-100) and letter grade.
    /// Computed by SecurityScorer on first load and refreshed every 5 minutes.
    @Published var securityScore: Int = 0
    @Published var securityGrade: String = ""
    /// v1.8.0-rc7: per-factor breakdown so the Overview tab can explain
    /// the grade on hover (which checks earned how many points, what's
    /// dragging the score down). Populated alongside score / grade in
    /// the same SecurityScorer.calculate() pass.
    @Published var securityFactors: [SecurityScorer.Factor] = []

    // MARK: Private

    private var pollTimer: AnyCancellable?
    /// nil until the first `updateStats()` sample primes it — see
    /// `eventsPerSecondFrom` (deep-audit fix for the first-poll rate spike).
    private var previousEventCount: Int? = nil
    private var lastStatsUpdate: Date = Date()
    private var rulesLoaded_cached = false
    /// v1.11.1 (audit perf MEDIUM): mtime gate ported from
    /// V2LiveDataProvider.rules(). Lets `loadRules()` short-circuit on
    /// repeat calls when the compiled-rules dir hasn't changed —
    /// previously the `rulesLoaded_cached` gate skipped the function
    /// entirely, but a dashboard re-launch (or any manual call after
    /// a SIGHUP-driven recompile) re-parsed all compiled JSON files
    /// regardless. Tracks the dir mtime of whichever candidate path
    /// won the load.
    private var rulesCacheDirMtime: Date?
    private var rulesCacheDirPath: String?
    private var lastAlertTimestamp: Date = .distantPast
    private var lastEventTimestamp: Date = .distantPast
    private var lastSecurityScoreUpdate: Date = .distantPast
    /// Keyset cursor pointing at the oldest row currently in `dashboardAlerts`
    /// / `events`. `loadOlderAlerts()` / `loadOlderEvents()` advance from here.
    /// Refreshed by every initial load or paged fetch.
    private var alertCursor: PaginationCursor?
    private var eventCursor: PaginationCursor?

    /// Authoritative set of alert IDs the user has manually suppressed this session.
    /// Published so SwiftUI views (filteredAlerts) re-render whenever it changes,
    /// guaranteeing suppression state is never overwritten by a DB reload.
    @Published var suppressedIDs: Set<String> = []

    /// Cached DB connections — avoid reopening on every poll cycle.
    /// v1.9.0 (audit Stab-H4): each store has its OWN `lastChecked`
    /// timestamp. Pre-fix the three stores shared a single
    /// `dbLastChecked` field — after any one was probed, the others
    /// skipped their freshness check for 30 s and could keep serving
    /// a stale handle pinned to the wrong dir.
    private var cachedAlertStore: AlertStore?
    private var cachedEventStore: EventStore?
    private var cachedTraceStore: TraceStore?
    /// v1.9 PR-5 audit (B3): the dashboard owns attribution_overrides.db
    /// at the user-writable support path. Daemon reads it for stats.
    private var cachedOverrideStore: AttributionOverrideStore?
    private var traceDbLastChecked: Date = .distantPast
    /// Path the trace store was opened against. When the mtime probe
    /// resolves a different path (user-dir flipped to system-dir or
    /// vice versa) we drop the cache so the next call rebuilds.
    private var cachedTraceStorePath: String?
    /// v1.12.0 fix: path-tracking caches for alerts.db / events.db.
    /// Replaces the prior 30-second TTL which paid SchemaMigrator.
    /// quickCheck() cost on every reopen — on a 962 MB events.db with
    /// FTS5 that's multi-second main-thread blocking. WAL mode handles
    /// fresh-read natively; the only legitimate reason to reopen is a
    /// path change (rare — daemon dir migration).
    private var cachedAlertStorePath: String?
    private var cachedEventStorePath: String?

    // MARK: - v1.9 PR-4: Agent traces dashboard surface

    /// Recent trace IDs seen in `traces.db`, sorted by most-recent activity
    /// first. Empty when the feature isn't enabled or no spans have been
    /// ingested yet.
    @Published var recentTraceIds: [String] = []
    /// Spans for the currently-selected trace. Refreshed on selection
    /// change in AgentTracesView; cleared when nothing is selected.
    @Published var selectedTraceSpans: [SpanRecord] = []
    /// Currently-selected trace_id, or nil when the trace list shows no
    /// detail pane.
    @Published var selectedTraceId: String?
    /// Aggregate stats for the dashboard's reattribute-quality metric.
    /// Always reflects the current EventStore snapshot.
    @Published var attributionStats: AttributionOverrideStats = AttributionOverrideStats(
        ratedCount: 0, confirmedCount: 0,
        wrongToolCount: 0, noAgentCount: 0, unknownVerdictCount: 0,
        totalEventsWithMachineAttribution: 0
    )

    // v1.9 audit Phase-1.7: mtime-skip state for refreshAgentTraces.
    // Pre-fix the comment promised mtime-skip but unconditionally
    // queried both stores every 5 s tick. Now we re-poll only when
    // traces.db, events.db, or attribution_overrides.db have been
    // re-written since the last successful poll. Pattern mirrors
    // refreshStorageHealth / refreshRuleTamper.
    private var lastTracesDbMtime: Date?
    private var lastEventsDbMtimeForAgent: Date?
    private var lastOverridesDbMtime: Date?

    // MARK: - v1.9 Phase-3: agent-traces receiver toggle

    /// Operator-controlled toggle. When changed, AppState writes the
    /// config file and SIGHUPs the daemon so the receiver lifecycle
    /// matches. Initialised from disk so a UI restart preserves the
    /// last setting.
    @Published var agentTracesReceiverEnabled: Bool = AgentTracesConfigStore.read(
        from: NSHomeDirectory() + "/Library/Application Support/MacCrab/" + AgentTracesConfigStore.filename
    )?.receiverEnabled ?? false

    /// Daemon-published receiver health snapshot. Polled on the
    /// regular refresh tick.
    @Published var agentTracesStatus: AgentTracesStatus?

    /// Wall-clock time of the most recent toggle-on event (or AppState
    /// init when the toggle was already on at launch). The view uses
    /// `now - this` to decide when to flip "Awaiting daemon" (orange)
    /// → "Daemon not responding" (red). Nil when the toggle is off.
    /// v1.9.0 (audit UX-H5).
    @Published var agentTracesEnableRequestedAt: Date?

    /// Threshold after which the dashboard considers the daemon
    /// non-responsive. 30 s comfortably covers the worst-case
    /// SIGHUP-debounce + signal-deliver + status-write round-trip
    /// (typically <2 s).
    public static let agentTracesAwaitingTimeoutSeconds: Double = 30.0

    /// Daemon-published last-flush status. Refreshed by
    /// `refreshStorageFlushStatus` on the same tick that
    /// `refreshAgentTracesStatus` runs.
    @Published var storageFlushStatus: StorageFlushStatus?

    /// Whether the dashboard is mid-flush (signal sent, awaiting the
    /// daemon's status write to come back).
    @Published var storageFlushInFlight: Bool = false

    /// Current events.db on-disk footprint (db + wal + shm), in bytes.
    /// Updated alongside storage flush status. Surfaces in Settings
    /// so the operator can see whether the sweep actually reclaimed
    /// space.
    @Published var eventsDbBytes: UInt64 = 0

    /// Pending debounced sync task — cancelled and rescheduled on
    /// every toggle change so a flick on/off/on doesn't write three
    /// configs in 50 ms.
    private var pendingAgentTracesSync: Task<Void, Never>?

    /// Resolve the MacCrab data directory.
    /// Prefers the system dir (root daemon) when its DB exists and is newer
    /// than the user dir DB, which may contain stale data from a previous
    /// non-root run. v1.4: use *readable* checks (not just `fileExists`),
    /// log the chosen path so operators can diagnose, and do not fall
    /// through to an unreadable path silently.
    private let dataDir: String = {
        let fm = FileManager.default
        let logger = Logger(subsystem: "com.maccrab.app", category: "data-dir")
        // v1.21.4 (UI-test seam): honor MACCRAB_DATA_DIR so UI / integration
        // tests can point the whole dashboard at a SEEDED fixture directory
        // instead of the live daemon DB — making data-driven UI tests
        // deterministic without a running root daemon. Gated on the
        // `-ui-testing` launch arg AND the dir existing, so it can never affect
        // a production launch. (Foundation.ProcessInfo — MacCrabCore defines its
        // own ProcessInfo type.)
        if CommandLine.arguments.contains("-ui-testing"),
           let override = Foundation.ProcessInfo.processInfo.environment["MACCRAB_DATA_DIR"],
           fm.fileExists(atPath: override) {
            logger.info("dataDir=override (MACCRAB_DATA_DIR + -ui-testing)")
            return override
        }
        let userDir = fm.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first.map { $0.appendingPathComponent("MacCrab").path }
            ?? NSHomeDirectory() + "/Library/Application Support/MacCrab"
        let systemDir = "/Library/Application Support/MacCrab"

        let userDB = userDir + "/events.db"
        let systemDB = systemDir + "/events.db"
        let userReadable = fm.isReadableFile(atPath: userDB)
        let systemReadable = fm.isReadableFile(atPath: systemDB)

        // If both are readable, prefer whichever was modified more recently.
        if userReadable && systemReadable {
            let userMod = (try? fm.attributesOfItem(atPath: userDB))?[.modificationDate] as? Date
            let sysMod = (try? fm.attributesOfItem(atPath: systemDB))?[.modificationDate] as? Date
            if let s = sysMod, let u = userMod, s >= u {
                logger.info("dataDir=system (system DB newer than user DB)")
                return systemDir
            }
            logger.info("dataDir=user (user DB newer than system DB)")
            return userDir
        }
        if systemReadable {
            logger.info("dataDir=system (only system DB readable)")
            return systemDir
        }
        if userReadable {
            logger.info("dataDir=user (only user DB readable)")
            return userDir
        }
        // Neither is readable. That's either a first-run (no DB yet) or a
        // filesystem-level problem (both DBs exist but permissions deny
        // us — e.g. system DB is root-600 and we're non-root). The former
        // is normal, the latter is an install/upgrade bug. Warn and
        // return systemDir as the "expected" location so the sysext's DB
        // gets picked up as soon as it's first readable.
        let systemExists = fm.fileExists(atPath: systemDB)
        let userExists = fm.fileExists(atPath: userDB)
        if systemExists || userExists {
            logger.warning("dataDir fallback to system: system-exists=\(systemExists, privacy: .public) user-exists=\(userExists, privacy: .public) but neither is readable — possible permissions issue")
        } else {
            logger.info("dataDir=system (first-run: no DB at either location yet)")
        }
        return systemDir
    }()

    // MARK: Initialization

    init() {
        startPolling()
        // v1.11.1 (audit launch-perf): suppression file reads
        // deferred to a Task so init() returns immediately. Pre-fix
        // these two ran sync on @MainActor at init time, contributing
        // ~10-30ms of pre-first-frame blocking. The Published
        // suppressionPatterns / suppressedIDs default to empty, so a
        // brief window where the dashboard renders before
        // suppressions populate is benign — by the time the user
        // can interact (clicks > 50ms), the Task has completed.
        Task { @MainActor [weak self] in
            self?.loadSuppressPatterns()
            self?.loadSuppressedIDs()
        }
        // v1.9.0 (audit UX-H5): if the receiver was already toggled
        // on at launch (config from disk), treat the dashboard's
        // open as the "request" so the awaiting-daemon pill has a
        // timeout even on cold start.
        if agentTracesReceiverEnabled {
            agentTracesEnableRequestedAt = Date()
        }
        // v1.12.0 fix: open the SQLite stores off-MainActor BEFORE
        // the first refresh() runs. Pre-fix, init's `Task { await
        // refresh() }` hopped to @MainActor and called alertStore() /
        // eventStore() synchronously — each runs AlertStore.init /
        // EventStore.init + SchemaMigrator.quickCheck on @MainActor.
        // On a 962 MB events.db with FTS5 that's multi-second beachball
        // before the dashboard window can paint or accept input.
        Task.detached(priority: .userInitiated) { [weak self] in
            guard let self else { return }
            await self.warmUpStoresOffMain()
            await self.refresh()
        }
    }

    /// Construct AlertStore + EventStore on a background Task so the
    /// SQLite open / schema migration / quick_check don't block main.
    /// Once cached, all subsequent `alertStore()` / `eventStore()`
    /// calls on @MainActor short-circuit on the cache (path-change
    /// detection only).
    private func warmUpStoresOffMain() async {
        let userDir = FileManager.default.urls(
            for: .applicationSupportDirectory, in: .userDomainMask
        ).first?.appendingPathComponent("MacCrab").path
            ?? NSHomeDirectory() + "/Library/Application Support/MacCrab"
        let systemDir = "/Library/Application Support/MacCrab"
        let alertDir = Self.pickFreshestDir(
            candidates: [dataDir, userDir, systemDir],
            fileName: "alerts.db",
            defaultDir: dataDir
        )
        let eventDir = Self.pickFreshestDir(
            candidates: [dataDir, userDir, systemDir],
            fileName: "events.db",
            defaultDir: dataDir
        )
        // Wave 9A.1 (v1.12.6 RC2): dashboard opens both stores read-only.
        // Mutation paths (suppress / unsuppress / delete) route through
        // the inbox file-IPC channel per v1.10.1; the direct
        // store.suppress/unsuppress/prune calls below have always been
        // marked "Best-effort DB write (fails silently on read-only DB)"
        // in their existing comments. Pre-9A.1 the RW open held shared+
        // upgrade locks on events.db/alerts.db that blocked the sysext's
        // VACUUM (field-confirmed via lsof showing two RW fds on the
        // dashboard process). Same fix shape as the v1.6.22 perf-audit-
        // pattern lesson, re-applied here.
        async let alertResult: AlertStore? = Task.detached(priority: .userInitiated) {
            try? AlertStore(directory: alertDir, forceReadOnly: true)
        }.value
        async let eventResult: EventStore? = Task.detached(priority: .userInitiated) {
            try? EventStore(directory: eventDir, forceReadOnly: true)
        }.value
        let (alert, event) = await (alertResult, eventResult)
        if let store = alert {
            cachedAlertStore = store
            cachedAlertStorePath = alertDir
        }
        if let store = event {
            cachedEventStore = store
            cachedEventStorePath = eventDir
        }
    }

    /// Path-probe helper used by warmUpStoresOffMain (and matches the
    /// shape of the alertStore() / eventStore() probe). `nonisolated`
    /// so the background Task can call it without hopping to main.
    nonisolated private static func pickFreshestDir(
        candidates rawCandidates: [String],
        fileName: String,
        defaultDir: String
    ) -> String {
        let candidates = Array(Set(rawCandidates))
        return candidates
            .map { (dir: String) -> (String, Date) in
                let mtime = (try? FileManager.default
                    .attributesOfItem(atPath: dir + "/" + fileName))?[.modificationDate] as? Date
                return (dir, mtime ?? .distantPast)
            }
            .max(by: { $0.1 < $1.1 })?.0
            ?? defaultDir
    }

    /// Start the 10-second poll. Idempotent: safe to call when the
    /// dashboard comes back to foreground from a background state. Views
    /// invoke `stopPolling()` in `.onChange(of: scenePhase)` when the
    /// dashboard window is hidden, so a background MacCrab app isn't
    /// hammering SQLite for updates nobody is looking at.
    func startPolling() {
        guard pollTimer == nil else { return }
        // Deep-audit fix: honor the "Poll detection engine every N seconds"
        // setting (pollIntervalSeconds) rather than a hardcoded 10 s, so the
        // menubar/notifier DB poll matches the cadence the V2 dashboard already
        // drives from the same key (V2DashboardState.refreshIntervalSeconds).
        // 2 s floor mirrors the dashboard clamp. Read at (re)start — a scene
        // toggle or setting change re-arms the timer at the new interval.
        let interval = Double(max(2, UserDefaults.standard.object(forKey: "pollIntervalSeconds") as? Int ?? 5))
        pollTimer = Timer.publish(every: interval, on: .main, in: .common)
            .autoconnect()
            .sink { [weak self] _ in
                guard let self else { return }
                Task { @MainActor in await self.refresh() }
            }
    }

    // MARK: - ClickFix clipboard bridge (v1.18)
    //
    // The root System Extension cannot read the GUI pasteboard (no Aqua session),
    // so the user-context app polls it and forwards delivery-shaped payloads
    // (curl|bash, etc.) to the sysext's ClickFixDetector via the inbox IPC, where
    // the exec-correlation half raises the paste-and-run alert. Tied to the poll
    // lifecycle (foreground only). 3 s cadence so a fast copy→paste→run is caught
    // well inside the detector's 60 s window. The `changeCount` gate makes the
    // common case (clipboard unchanged) a single cheap integer read.
    private var clipboardTimer: AnyCancellable?
    private var lastClipboardChangeCount: Int = -1

    /// Process-lifetime: started once at launch by the AppDelegate (NOT gated on
    /// the dashboard window's scenePhase), so ClickFix records delivery-shaped
    /// clipboard payloads whenever the LSUIElement menubar app is running.
    func startClipboardBridge() {
        guard clipboardTimer == nil else { return }
        lastClipboardChangeCount = NSPasteboard.general.changeCount
        clipboardTimer = Timer.publish(every: 3.0, on: .main, in: .common)
            .autoconnect()
            .sink { [weak self] _ in self?.pollClipboardForClickFix() }
    }

    private func stopClipboardBridge() {
        clipboardTimer?.cancel()
        clipboardTimer = nil
    }

    private func pollClipboardForClickFix() {
        let pb = NSPasteboard.general
        let count = pb.changeCount
        guard count != lastClipboardChangeCount else { return }
        lastClipboardChangeCount = count
        guard let text = pb.string(forType: .string), !text.isEmpty,
              ClickFixDetector.looksLikeShellDelivery(text) else { return }
        writeClickFixPayloadToInbox(String(text.prefix(8192)))
    }

    private func writeClickFixPayloadToInbox(_ payload: String) {
        let obj: [String: Any] = [
            "schema_version": 1,
            "payload": payload,
            "timestamp": Date().timeIntervalSince1970,
            "source": "MacCrabApp"
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: obj) else { return }
        let inboxDir = "/Library/Application Support/MacCrab/inbox"
        let userInboxDir = NSHomeDirectory() + "/Library/Application Support/MacCrab/inbox"
        for dir in [inboxDir, userInboxDir] {
            try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
            let path = "\(dir)/record-clipboard-\(Int(Date().timeIntervalSince1970))-\(getpid())-\(UUID().uuidString.prefix(8)).json"
            try? data.write(to: URL(fileURLWithPath: path))
        }
    }

    // MARK: - Built-in rule overrides (v1.18)
    //
    // The hardcoded maccrab.* rules are tunable via builtin_rules_settings.json,
    // which the ROOT daemon owns (the app can't write the system support dir).
    // Route the change through the inbox IPC; the daemon writes the file and
    // AlertSink applies it at the submit chokepoint.
    func setBuiltinRuleEnabled(ruleId: String, enabled: Bool) {
        dropBuiltinRuleSetting(["ruleId": ruleId, "enabled": enabled])
    }
    /// `severityRaw == nil` clears the override (revert to the catalog default).
    func setBuiltinRuleSeverity(ruleId: String, severityRaw: String?) {
        dropBuiltinRuleSetting(["ruleId": ruleId, "severityOverride": severityRaw ?? NSNull()])
    }
    private func dropBuiltinRuleSetting(_ fields: [String: Any]) {
        var obj = fields
        obj["schema_version"] = 1
        obj["requester"] = "MacCrabApp"
        guard let data = try? JSONSerialization.data(withJSONObject: obj) else { return }
        let inboxDir = "/Library/Application Support/MacCrab/inbox"
        let userInboxDir = NSHomeDirectory() + "/Library/Application Support/MacCrab/inbox"
        for dir in [inboxDir, userInboxDir] {
            try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
            let path = "\(dir)/builtin-rule-setting-\(Int(Date().timeIntervalSince1970))-\(getpid())-\(UUID().uuidString.prefix(8)).json"
            try? data.write(to: URL(fileURLWithPath: path))
        }
    }

    /// Stop the poll timer and release its subscription. Called from the
    /// dashboard window's `.onChange(of: scenePhase)` when the window is
    /// hidden / the app is backgrounded. Saves one SQLite sweep every
    /// 10 s plus the downstream view invalidation work.
    func stopPolling() {
        pollTimer?.cancel()
        pollTimer = nil
        // NOTE: the ClickFix clipboard bridge is deliberately NOT stopped here.
        // It's process-lifetime (started once at launch by the AppDelegate), so
        // ClickFix keeps watching the clipboard whenever the menubar app is
        // alive — not only while the dashboard window is foregrounded.
    }

    /// Get or create cached alert store.
    /// v1.9 hot-fix: probe both system + user paths and pick whichever
    /// alerts.db has the freshest mtime so we don't pin to a stale
    /// system-dir copy left over by a prior sysext install.
    /// v1.12.0 fix: removed 30-second TTL reopen. The reopen paid
    /// AlertStore.init's full schema migration + quick_check cost on
    /// every cycle — fine on small DBs, multi-second on the 962 MB
    /// events.db field-observed. Reopen only when the chosen path
    /// actually changed; SQLite WAL handles fresh reads natively.
    private func alertStore() throws -> AlertStore {
        let userDir = FileManager.default.urls(
            for: .applicationSupportDirectory, in: .userDomainMask
        ).first?.appendingPathComponent("MacCrab").path
            ?? NSHomeDirectory() + "/Library/Application Support/MacCrab"
        let systemDir = "/Library/Application Support/MacCrab"
        let candidates = Array(Set([dataDir, userDir, systemDir]))
        let chosen: String = candidates
            .map { (dir: String) -> (String, Date) in
                let mtime = (try? FileManager.default
                    .attributesOfItem(atPath: dir + "/alerts.db"))?[.modificationDate] as? Date
                return (dir, mtime ?? .distantPast)
            }
            .max(by: { $0.1 < $1.1 })?.0
            ?? dataDir
        if let store = cachedAlertStore, cachedAlertStorePath == chosen {
            return store
        }
        // Wave 9A.1 (v1.12.6 RC2): dashboard alert store is read-only.
        let store = try AlertStore(directory: chosen, forceReadOnly: true)
        cachedAlertStore = store
        cachedAlertStorePath = chosen
        return store
    }

    /// Get or create cached event store.
    ///
    /// v1.9 hot-fix: probe both system + user paths and use whichever
    /// `events.db` was modified most RECENTLY at call time, not at
    /// AppState init time. Pre-fix `dataDir` was a `let` computed
    /// once at init (the user kept opening the app while events.db
    /// at /Library/.../events.db was a stale 5GB blob from a prior
    /// v1.8.x sysext, so the dashboard pinned to system-dir while
    /// the running non-root daemon wrote to user-dir → no events
    /// visible). Same shape as the traces.db fix.
    private func eventStore() throws -> EventStore {
        let userDir = FileManager.default.urls(
            for: .applicationSupportDirectory, in: .userDomainMask
        ).first?.appendingPathComponent("MacCrab").path
            ?? NSHomeDirectory() + "/Library/Application Support/MacCrab"
        let systemDir = "/Library/Application Support/MacCrab"
        let candidates = Array(Set([dataDir, userDir, systemDir]))
        // Pick the directory whose events.db was modified most
        // recently. Empty dirs / missing files yield distantPast
        // and lose to any concrete file.
        let chosen: String = candidates
            .map { (dir: String) -> (String, Date) in
                let mtime = (try? FileManager.default
                    .attributesOfItem(atPath: dir + "/events.db"))?[.modificationDate] as? Date
                return (dir, mtime ?? .distantPast)
            }
            .max(by: { $0.1 < $1.1 })?.0
            ?? dataDir
        // v1.12.0 fix: see alertStore() — reopen only on path change,
        // not every 30s. FTS5 quick_check on a 962 MB events.db blocks
        // main thread for seconds.
        if let store = cachedEventStore, cachedEventStorePath == chosen {
            return store
        }
        // Wave 9A.1 (v1.12.6 RC2): dashboard event store is read-only.
        let store = try EventStore(directory: chosen, forceReadOnly: true)
        cachedEventStore = store
        cachedEventStorePath = chosen
        return store
    }

    /// v1.9 Phase-2.3: shared DatabaseEncryption. Looks up the same
    /// keychain item as the daemon (v1.8.1 access-groups make this
    /// cross-bundle), so attributes_json encrypted by the daemon
    /// decrypts cleanly here. Lazy + cached.
    private var cachedDbEncryption: DatabaseEncryption?
    private func dbEncryption() -> DatabaseEncryption {
        if let e = cachedDbEncryption { return e }
        let e = DatabaseEncryption(enabled: true)
        cachedDbEncryption = e
        return e
    }

    /// v1.9 PR-5 audit (B3): override store always lives at the
    /// **user-writable** support path so the dashboard can record
    /// verdicts without sudo. (events.db is root-owned 0640 in
    /// production installs; the dashboard's prepare-fallback opened
    /// read-only there and silently swallowed write failures.)
    private func overrideStore() throws -> AttributionOverrideStore {
        if let s = cachedOverrideStore { return s }
        let userDir = FileManager.default.urls(
            for: .applicationSupportDirectory, in: .userDomainMask
        ).first?.appendingPathComponent("MacCrab").path
            ?? NSHomeDirectory() + "/Library/Application Support/MacCrab"
        let store = try AttributionOverrideStore(directory: userDir)
        cachedOverrideStore = store
        return store
    }

    /// Get or create cached trace store. Returns nil (and a logged
    /// warning) when traces.db doesn't exist — that's the steady state
    /// for daemons running without the OTLP receiver enabled.
    ///
    /// PR-4 (post-ship hotfix): probe BOTH the resolved `dataDir`
    /// (events.db wins by mtime) AND the user dir independently —
    /// `traces.db` may live in a different dir than `events.db` when a
    /// stale root-owned events.db at /Library/... is keeping `dataDir`
    /// pinned to the system path while the running non-root daemon
    /// writes traces.db to the user dir. Same shape as the
    /// maccrabctl StatusCommand fix.
    ///
    /// v1.9.0 (audit Stab-M5): pick the dir with the freshest
    /// `traces.db` mtime, NOT the first-readable one. Matches
    /// `eventStore()` / `alertStore()`. Pre-fix asymmetry meant a
    /// stale traces.db at the system path could pin the dashboard to
    /// the wrong file when both existed.
    ///
    /// v1.9.0 (audit Stab-H4): per-store TTL. The cache also drops
    /// when the resolved path changes (user-dir/system-dir flip) so a
    /// stale handle never wins after a daemon restart.
    private func traceStoreOrNil() -> TraceStore? {
        let userDir = FileManager.default.urls(
            for: .applicationSupportDirectory, in: .userDomainMask
        ).first?.appendingPathComponent("MacCrab").path
            ?? NSHomeDirectory() + "/Library/Application Support/MacCrab"
        let candidates = Array(Set([
            dataDir + "/traces.db",
            userDir + "/traces.db",
        ]))
        let chosenPath: String? = candidates
            .compactMap { (path: String) -> (String, Date)? in
                guard FileManager.default.isReadableFile(atPath: path),
                      let mtime = (try? FileManager.default
                          .attributesOfItem(atPath: path))?[.modificationDate] as? Date
                else { return nil }
                return (path, mtime)
            }
            .max(by: { $0.1 < $1.1 })?.0
        guard let path = chosenPath else { return nil }

        // Cache hit: same path AND under TTL.
        if let store = cachedTraceStore,
           cachedTraceStorePath == path,
           Date().timeIntervalSince(traceDbLastChecked) < 30 {
            return store
        }

        // Path flip or expired TTL — rebuild. Pass the shared
        // encryption instance so the dashboard can decrypt
        // attributes_json written by the daemon.
        let store = try? TraceStore(path: path, encryption: dbEncryption())
        cachedTraceStore = store
        cachedTraceStorePath = path
        traceDbLastChecked = Date()
        return store
    }

    // MARK: - PR-4: trace queries surfaced for AgentTracesView

    /// Refresh `recentTraceIds` + `attributionStats` from disk.
    /// v1.9 audit Phase-1.7: real mtime-skip across all three sources.
    /// Pre-fix the comment claimed the pattern but the code re-queried
    /// every poll. Now: if none of {traces.db, events.db,
    /// attribution_overrides.db} has changed since last successful
    /// read, skip the SQLite roundtrips entirely.
    @MainActor
    func refreshAgentTraces(limit: Int = 200, force: Bool = false) async {
        let userDir = FileManager.default.urls(
            for: .applicationSupportDirectory, in: .userDomainMask
        ).first?.appendingPathComponent("MacCrab").path
            ?? NSHomeDirectory() + "/Library/Application Support/MacCrab"

        // Resolve the most recent mtime across user + system paths for
        // each file (whichever side wrote last is the one we care about).
        func newestMtime(for filename: String) -> Date? {
            let paths = [dataDir + "/" + filename, userDir + "/" + filename]
            let mtimes = paths.compactMap {
                (try? FileManager.default.attributesOfItem(atPath: $0)[.modificationDate]) as? Date
            }
            return mtimes.max()
        }

        let tracesMtime = newestMtime(for: "traces.db")
        let eventsMtime = newestMtime(for: "events.db")
        let overridesMtime = newestMtime(for: "attribution_overrides.db")

        // Skip when nothing changed AND we have at least one prior good read.
        if !force,
           let _ = lastEventsDbMtimeForAgent ?? lastTracesDbMtime ?? lastOverridesDbMtime,
           tracesMtime == lastTracesDbMtime,
           eventsMtime == lastEventsDbMtimeForAgent,
           overridesMtime == lastOverridesDbMtime {
            return
        }

        // v1.9 PR-5 audit (B3): stats roll up from TWO sources — the
        // dashboard's user-writable override store (verdict counts)
        // and the daemon's events.db (total events with machine
        // attribution).
        var total = 0
        if let es = try? eventStore() {
            total = (try? await es.eventCountWithMachineAttribution()) ?? 0
        }
        if let overrides = try? overrideStore() {
            if let stats = try? await overrides.stats(totalEventsWithMachineAttribution: total) {
                self.attributionStats = stats
            }
        }
        if let store = traceStoreOrNil() {
            if let ids = try? await store.recentTraceIds(limit: limit) {
                self.recentTraceIds = ids
            }
        } else {
            self.recentTraceIds = []
        }

        lastTracesDbMtime = tracesMtime
        lastEventsDbMtimeForAgent = eventsMtime
        lastOverridesDbMtime = overridesMtime
    }

    /// Load all spans for a given trace into `selectedTraceSpans`. Sets
    /// `selectedTraceId` so the detail pane re-renders when the user
    /// clicks a different row.
    @MainActor
    func loadTrace(_ traceId: String) async {
        self.selectedTraceId = traceId
        guard let store = traceStoreOrNil() else {
            self.selectedTraceSpans = []
            return
        }
        if let spans = try? await store.spansForTrace(traceId) {
            self.selectedTraceSpans = spans
        } else {
            self.selectedTraceSpans = []
        }
    }

    /// Persist a reattribute verdict for a given event. Refreshes
    /// `attributionStats` afterwards so the metric updates live.
    /// v1.9 PR-5 audit (B3): writes go through the dashboard's
    /// user-writable AttributionOverrideStore so root-owned events.db
    /// no longer silently fails the click.
    @MainActor
    func recordAttributionOverride(
        eventId: String,
        machineConfidence: String?,
        verdict: AttributionOverride.Verdict,
        note: String?
    ) async {
        guard let overrides = try? overrideStore() else {
            Logger(subsystem: "com.maccrab.app", category: "agent-traces")
                .error("recordAttributionOverride: override store unavailable")
            return
        }
        let now = Date()
        let override = AttributionOverride(
            eventId: eventId,
            machineConfidence: machineConfidence,
            verdict: verdict,
            userNote: note,
            createdAt: now,
            updatedAt: now
        )
        do {
            try await overrides.record(override)
            // Force-refresh: the override write just bumped
            // attribution_overrides.db's mtime but the mtime-skip
            // pattern would only catch it on the next tick if we
            // happened to be milliseconds slow. `force: true` makes
            // the dashboard reflect the verdict instantly.
            await refreshAgentTraces(force: true)
        } catch {
            Logger(subsystem: "com.maccrab.app", category: "agent-traces")
                .error("recordAttributionOverride failed: \(String(describing: error), privacy: .public)")
        }
    }

    /// Read the operator verdict for a given event id. Returns nil when
    /// none has been recorded yet.
    func attributionOverride(for eventId: String) async -> AttributionOverride? {
        guard let overrides = try? overrideStore() else { return nil }
        return try? await overrides.fetch(eventId: eventId)
    }

    // MARK: - v1.9 Phase-3: receiver toggle sync

    /// Debounced wrapper for `syncAgentTracesConfig`. 500 ms debounce
    /// matches the webhook-config sync pattern.
    @MainActor
    func scheduleAgentTracesSync() {
        // v1.9.0 (audit UX-H5): record (or clear) the request
        // timestamp synchronously at the toggle moment — debounce
        // delay shouldn't push the awaiting-pill timeout out by half
        // a second.
        if agentTracesReceiverEnabled {
            agentTracesEnableRequestedAt = Date()
        } else {
            agentTracesEnableRequestedAt = nil
        }

        pendingAgentTracesSync?.cancel()
        pendingAgentTracesSync = Task {
            do {
                try await Task.sleep(nanoseconds: 500_000_000)
            } catch {
                return
            }
            guard !Task.isCancelled else { return }
            await MainActor.run { self.syncAgentTracesConfig() }
        }
    }

    /// Write the operator's agent-traces config to the user-home path
    /// and SIGHUP the daemon so it reloads + starts/stops the
    /// receiver. Mirrors syncWebhookConfig.
    @MainActor
    func syncAgentTracesConfig() {
        let configDir = NSHomeDirectory() + "/Library/Application Support/MacCrab"
        let path = configDir + "/" + AgentTracesConfigStore.filename
        // v1.21.4 Phase-6 6A: the single "Receive agent traces" toggle
        // drives the whole stack — set the master (agent_traces_enabled)
        // and receiverEnabled together. The master is what the shipped
        // sysext gates the producer + receiver on; without it the toggle
        // would write receiverEnabled=true but the daemon's master stays
        // off and nothing starts.
        let cfg = AgentTracesConfig(
            enabled: agentTracesReceiverEnabled,
            receiverEnabled: agentTracesReceiverEnabled,
            port: 4318
        )
        // Dev path: the user-owned maccrabd reads this config file directly and
        // responds to the SIGHUP below.
        guard AgentTracesConfigStore.write(cfg, to: path) else { return }

        // Deep-audit fix (1695): the RELEASE sysext runs as root and owns the
        // system-side agent_traces_config.json; `pkill -HUP com.maccrab.agent`
        // is EPERM cross-uid, so the toggle was a silent no-op on release.
        // Route it through the privileged inbox file-drop IPC every other
        // dashboard→sysext control already uses. The daemon handler writes the
        // system-side config and (re)starts the receiver lifecycle.
        _ = dropAgentTracesRequest(receiverEnabled: agentTracesReceiverEnabled, port: 4318)

        // Dev only: SIGHUP the maccrabd binary (same-uid, so this works). The
        // release sysext is driven by the inbox request above, not this pkill.
        let devTask = Process()
        devTask.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
        devTask.arguments = ["-HUP", "maccrabd"]
        devTask.standardOutput = Pipe()
        devTask.standardError = Pipe()
        try? devTask.run()
    }

    /// Drop an `apply-agent-traces-<token>.json` request into the daemon's
    /// inbox (both system + user support dirs) so the root sysext applies the
    /// receiver toggle it can't be pkill'd for cross-uid. Returns true if at
    /// least one write landed.
    ///
    /// DAEMON-SIDE HANDLER REQUIRED (residual): add an `apply-agent-traces-`
    /// verb to the inbox poller in DaemonTimers.swift (partition +
    /// handleApplyAgentTracesRequests) that reads `receiverEnabled`/`port`,
    /// writes `<systemSupportDir>/agent_traces_config.json` via
    /// AgentTracesConfigStore (setting agent_traces_enabled + receiverEnabled),
    /// (re)starts the OTLP receiver, and applies the same uid/symlink auth gate
    /// + audit as the reload-rules / llm-config verbs.
    private func dropAgentTracesRequest(receiverEnabled: Bool, port: Int) -> Bool {
        let dirs = ["/Library/Application Support/MacCrab/inbox",
                    NSHomeDirectory() + "/Library/Application Support/MacCrab/inbox"]
        var wrote = false
        for dir in dirs where Self.writeAgentTracesRequest(inboxDir: dir, receiverEnabled: receiverEnabled, port: port) {
            wrote = true
        }
        return wrote
    }

    /// Write one `apply-agent-traces-*.json` into `inboxDir`. Static + pure so
    /// it's unit-testable against a temp dir (mirrors writeInboxRefreshRequest).
    nonisolated static func writeAgentTracesRequest(inboxDir: String, receiverEnabled: Bool, port: Int) -> Bool {
        let fm = FileManager.default
        if !fm.fileExists(atPath: inboxDir) {
            try? fm.createDirectory(atPath: inboxDir, withIntermediateDirectories: true)
        }
        let obj: [String: Any] = [
            "schema_version": 1,
            "receiverEnabled": receiverEnabled,
            "port": port,
            "requester": "MacCrabApp",
            "queuedAt": ISO8601DateFormatter().string(from: Date())
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: obj) else { return false }
        let token = "\(Int(Date().timeIntervalSince1970))-\(getpid())-\(UUID().uuidString.prefix(8))"
        let path = inboxDir + "/apply-agent-traces-\(token).json"
        do {
            try data.write(to: URL(fileURLWithPath: path), options: .atomic)
            return true
        } catch {
            return false
        }
    }

    /// Trigger an immediate events.db size-cap sweep on the daemon.
    /// Sends BOTH SIGUSR2 (the v1.9 dedicated handler) and SIGHUP
    /// (which the v1.6.14+ enforcer also reacts to) to maximise
    /// reach — older sysext binaries that pre-date the SIGUSR2
    /// handler will still respond to SIGHUP. Targets both
    /// `com.maccrab.agent` (sysext) and `maccrabd` (dev daemon).
    /// Sets `storageFlushInFlight` so the UI can show a spinner; the
    /// status JSON the daemon writes when done flips it back off.
    @MainActor
    func requestStorageFlush() {
        storageFlushInFlight = true

        // v1.10.0 audit fix (second pass): write the marker file to
        // <supportDir>/inbox/ which the daemon creates with mode
        // 1777 on boot. The first attempt used /tmp/ but sysextd's
        // sandbox profile for ES extensions doesn't expose the same
        // /private/tmp the dashboard sees — sysext's
        // contentsOfDirectory("/tmp") returned nothing even when a
        // marker was sitting there. The inbox dir is rooted under
        // the daemon's known support path so there's no sandbox
        // translation, and the sticky+world-write bits let either UID
        // drop a file. We still send the pkill as a fallback for the
        // dev `swift run maccrabd` path where UIDs match.
        let inboxDir = "/Library/Application Support/MacCrab/inbox"
        let userInboxDir = NSHomeDirectory() + "/Library/Application Support/MacCrab/inbox"
        let payload: [String: Any] = [
            "schema_version": 1,
            "requested_at_unix": Date().timeIntervalSince1970,
            "requester": "MacCrabApp dashboard",
            "requester_pid": getpid()
        ]
        if let data = try? JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted]) {
            // Try system inbox first (where the sysext polls). Fall
            // back to user-home inbox for dev `swift run maccrabd`
            // installs that write to the user data dir.
            for dir in [inboxDir, userInboxDir] {
                try? FileManager.default.createDirectory(
                    atPath: dir, withIntermediateDirectories: true
                )
                let path = "\(dir)/flush-request-\(Int(Date().timeIntervalSince1970))-\(getpid()).json"
                try? data.write(to: URL(fileURLWithPath: path))
            }
        }

        // Fallback signal path — no-op on the sysext (UID mismatch)
        // but does the right thing on dev `swift run maccrabd`.
        for sig in ["-USR2", "-HUP"] {
            for processName in ["com.maccrab.agent", "maccrabd"] {
                let task = Process()
                task.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
                task.arguments = [sig, processName]
                task.standardOutput = Pipe()
                task.standardError = Pipe()
                try? task.run()
            }
        }
        // Auto-clear the in-flight flag after 180 s in case the daemon
        // doesn't write a status JSON (e.g. an older sysext that
        // honored SIGHUP but doesn't know to write our status file,
        // or the daemon is dead). v1.9.0 (audit Stab-M12) extended
        // from 90 s → 180 s: multi-GB DBs on slow disks have been
        // observed to take 60-120 s for the prune+VACUUM phase, and
        // the prior 90 s window flipped the button back active while
        // the daemon was still working — letting the operator click
        // again and double-fire the size-cap sweep.
        Task { [weak self] in
            try? await Task.sleep(nanoseconds: 180_000_000_000)
            await MainActor.run {
                self?.storageFlushInFlight = false
            }
        }
    }

    /// Pull the latest flush snapshot from disk. Returns false if no
    /// snapshot file exists yet (daemon hasn't run a sweep on this
    /// install). Updates `storageFlushStatus`, `eventsDbBytes`, and
    /// clears `storageFlushInFlight` if the snapshot is fresher than
    /// when we last sent SIGUSR2.
    @MainActor
    func refreshStorageFlushStatus() {
        let userDir = NSHomeDirectory() + "/Library/Application Support/MacCrab"
        let systemDir = "/Library/Application Support/MacCrab"
        let candidates = Array(Set([systemDir, userDir]))

        // Newest snapshot wins (across user + system dirs, mirroring
        // the eventStore() path probe).
        var newest: StorageFlushStatus?
        for dir in candidates {
            if let s = StorageFlushStatus.read(from: dir),
               (newest == nil || (s.lastRunAt ?? .distantPast) > (newest!.lastRunAt ?? .distantPast)) {
                newest = s
            }
        }
        if newest != storageFlushStatus {
            storageFlushStatus = newest
            if newest?.inProgress == false {
                storageFlushInFlight = false
            }
        }

        // Refresh on-disk footprint so the Settings UI can display
        // current size next to "Reduce now".
        var maxBytes: UInt64 = 0
        for dir in candidates {
            let bytes = StorageFlushStatus.fileSize(at: dir + "/events.db")
            if bytes > maxBytes { maxBytes = bytes }
        }
        if maxBytes != eventsDbBytes {
            eventsDbBytes = maxBytes
        }
    }

    /// Pull the daemon-published status snapshot. Polled on the
    /// regular refresh tick alongside refreshAgentTraces.
    @MainActor
    func refreshAgentTracesStatus() {
        // Probe both system and user dirs (the running daemon may be
        // root-deployed sysext or non-root dev build).
        let userDir = NSHomeDirectory() + "/Library/Application Support/MacCrab"
        let systemDir = "/Library/Application Support/MacCrab"
        let candidates = [systemDir, userDir]
        var newest: AgentTracesStatus?
        for dir in candidates {
            if let s = AgentTracesStatusStore.read(from: dir),
               (newest == nil || s.updatedAt > newest!.updatedAt) {
                newest = s
            }
        }
        if newest != agentTracesStatus {
            agentTracesStatus = newest
        }
    }

    // MARK: Public interface

    /// Hide the FDA banner. Called from the banner's "Dismiss" button as
    /// an escape hatch when our automatic detection is wrong. The flag
    /// is persisted to UserDefaults so the banner stays hidden across
    /// launches, and is automatically cleared in `refresh()` if/when our
    /// detection confirms both principals have FDA (so future FDA loss
    /// still re-raises the banner).
    func dismissFDABanner() {
        fdaBannerDismissedByUser = true
        UserDefaults.standard.set(true, forKey: "fdaBannerDismissedByUser")
    }

    func refresh() async {
        // Check daemon connectivity: DB exists + has data = connected
        // Also check for WAL file which indicates active writer (daemon)
        let dbPath = dataDir + "/events.db"
        let fm = FileManager.default
        let dbExists = fm.isReadableFile(atPath: dbPath)
        let walExists = fm.fileExists(atPath: dbPath + "-wal")
        // v1.7.11: equality-checked @Published writes. These three Bools
        // change at most once per session in normal operation (daemon
        // up/down, FDA grant/revoke). Pre-fix the unconditional assign
        // fired @Published every poll, triggering SwiftUI body re-eval
        // across every view bound to AppState — driving NSTableView
        // rebinds in EventStream that inflated Auto Layout constraints.
        let newIsConnected = dbExists && (walExists || fm.fileExists(atPath: dbPath + "-shm"))
        if isConnected != newIsConnected { isConnected = newIsConnected }

        // FDA probe for the APP principal — readability of the user TCC.db
        // requires Full Disk Access granted to MacCrab.app.
        let tccPath = NSHomeDirectory() + "/Library/Application Support/com.apple.TCC/TCC.db"
        let newAppHasFDA = fm.isReadableFile(atPath: tccPath)
        if appHasFDA != newAppHasFDA { appHasFDA = newAppHasFDA }

        // FDA probe for the SYSEXT principal — three-tier detection.
        //
        // Tier 1 (authoritative, schema v2+ sysext): the sysext writes
        // its own `has_fda` into heartbeat.json every 30 s. It runs as
        // root and opens the TCC-protected system TCC.db to test —
        // successful open means FDA, EPERM means no FDA. This is the
        // only reliable signal because the app process cannot read the
        // system TCC.db itself (Unix perms: 600 root:wheel plus TCC).
        //
        // Tier 2 (legacy sysext or pre-first-heartbeat): try the app's
        // own user TCC.db for a sysext row. Works sometimes — grants
        // land here on some macOS builds. Requires app FDA to open.
        //
        // Tier 3 (cold dashboard, pre-heartbeat, no app FDA): WAL mtime
        // within 30 minutes — an active sysext implies FDA because ES
        // subscription requires it.
        //
        // Read the heartbeat FIRST so the downstream decision uses the
        // latest value. The existing `refreshHeartbeat()` call later in
        // this method will also refresh, but ordering it here lets us
        // gate Tier 1.
        refreshHeartbeat()

        // v1.7.11: compute new sysextHasFDA into a local, then apply with
        // equality check. Same rationale as the isConnected/appHasFDA
        // pattern above — the value rarely changes per-poll, but the
        // unconditional @Published write fired SwiftUI body re-evals on
        // every poll cycle.
        let newSysextHasFDA: Bool
        if let hb = heartbeat, !hb.isStale, let hbFDA = hb.sysextHasFDA {
            newSysextHasFDA = hbFDA
        } else {
            let systemTCCPath = "/Library/Application Support/com.apple.TCC/TCC.db"
            let foundInTCC = Self.querySysextFDA(userTCC: appHasFDA ? tccPath : nil,
                                                  systemTCC: systemTCCPath)
            if foundInTCC {
                newSysextHasFDA = true
            } else if appHasFDA {
                newSysextHasFDA = false
            } else {
                let walPath = dbPath + "-wal"
                if let attrs = try? fm.attributesOfItem(atPath: walPath),
                   let mtime = attrs[.modificationDate] as? Date {
                    newSysextHasFDA = Date().timeIntervalSince(mtime) < 1800
                } else {
                    newSysextHasFDA = !isConnected ? false : sysextHasFDA
                }
            }
        }
        if sysextHasFDA != newSysextHasFDA { sysextHasFDA = newSysextHasFDA }
        let newFDAGranted = appHasFDA && sysextHasFDA
        if fullDiskAccessGranted != newFDAGranted { fullDiskAccessGranted = newFDAGranted }

        // User override: once both principals are detected as granted,
        // clear any prior "dismiss banner" flag so future FDA-revocation
        // reliably raises the banner again.
        if fullDiskAccessGranted && fdaBannerDismissedByUser {
            fdaBannerDismissedByUser = false
            UserDefaults.standard.set(false, forKey: "fdaBannerDismissedByUser")
        }

        // Check fleet configuration
        let fleetURL = ProcessInfo.processInfo.environment["MACCRAB_FLEET_URL"] ?? ""
        fleetStatus.isConfigured = !fleetURL.isEmpty
        fleetStatus.fleetURL = fleetURL

        // Check LLM configuration (from config file or env vars)
        var detectedLLMProvider = ProcessInfo.processInfo.environment["MACCRAB_LLM_PROVIDER"] ?? ""
        var llmConfigured = !detectedLLMProvider.isEmpty
        if !llmConfigured {
            // AIAnalysisView/SettingsView write llm_config.json to user-home;
            // read from the same place, not dataDir (which may flip to the
            // system dir after a sysext upgrade — see uiStateDir comment).
            if let data = readUIState("llm_config.json"),
               let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let enabled = json["enabled"] as? Bool, enabled,
               let provider = json["provider"] as? String {
                detectedLLMProvider = provider
                llmConfigured = true
            }
        }
        llmStatus.isConfigured = llmConfigured
        llmStatus.provider = detectedLLMProvider

        guard dbExists else {
            eventsPerSecond = 0
            // Drop the baseline so a DB that (re)appears re-primes on its next
            // sample instead of spiking off a stale count (see eventsPerSecondFrom).
            previousEventCount = nil
            return
        }

        // Incremental: only fetch new data since last poll
        await loadAlertsIncremental()
        await loadEventsIncremental()
        await updateStats()
        // v1.4.3 fail-loud: refresh storage-error and heartbeat state
        // from sysext-written snapshot files so the Overview banners
        // and statusbar icon react within one poll cycle.
        refreshStorageHealth()
        refreshHeartbeat()
        refreshRuleTamper()
        await refreshThreatIntelStats()
        await refreshAgentLineage()
        refreshRuleTelemetry()
        maybeKickWatchdog()

        // Rules rarely change — load once, BUT only latch on a SUCCESSFUL load.
        // If the first poll reads the compiled_rules dir mid-install / mid-OTA
        // (transiently empty), rulesLoaded would be 0; latching that for the
        // session made isProtectionDegraded true forever (a permanent false
        // "Protection degraded"). Retry each poll until rules actually load.
        if !rulesLoaded_cached {
            await loadRules()
            if rulesLoaded > 0 { rulesLoaded_cached = true }
        }
    }

    /// If the heartbeat has been stale for long enough AND we haven't
    /// tried to reactivate the sysext within the cooldown window,
    /// invoke the watchdog callback. Doesn't replace the user-facing
    /// banner — both fire. The goal is to self-heal transient sysext
    /// crashes without user intervention; if reactivation doesn't
    /// restore the heartbeat, the banner stays up and the user takes
    /// over.
    private func maybeKickWatchdog() {
        guard let hb = heartbeat, hb.isStale else { return }
        guard let callback = sysextWatchdogActivate else { return }
        if let last = lastSysextWatchdogAt,
           Date().timeIntervalSince(last) < sysextWatchdogCooldown {
            return
        }
        lastSysextWatchdogAt = Date()
        Self.uiStateLogger.notice("Sysext heartbeat stale — kicking watchdog reactivation")
        callback()
    }

    func loadAlerts(limit: Int = 500, filter: String? = nil) async {
        do {
            let store = try alertStore()
            let isSearch = filter.map { !$0.isEmpty } ?? false
            let alerts: [Alert]
            if let query = filter, isSearch {
                alerts = try await store.search(text: query, limit: limit)
            } else {
                alerts = try await store.alerts(since: Date.distantPast, limit: limit)
            }
            // Apply suppressedIDs overlay: if the user suppressed an alert this session,
            // keep it suppressed regardless of what the DB says (handles read-only DB case).
            let overlay = suppressedIDs
            dashboardAlerts = alerts.map { alert in
                var vm = alertToViewModel(alert)
                if overlay.contains(vm.id) { vm.suppressed = true }
                return vm
            }
            refreshAlertBadges()
            // Sync cursor so the next incremental poll doesn't re-fetch these alerts
            // and insert them as unsuppressed duplicates.
            if let mostRecent = dashboardAlerts.first?.timestamp {
                lastAlertTimestamp = mostRecent
            }
            // Gate the live poll while a search is active — same reasoning as
            // events. LIKE search results aren't a contiguous time window.
            alertSearchActive = isSearch
            // Park a keyset cursor at the oldest row so "Load older" can pick
            // up from here. Treat a full page as "more available"; a short
            // page means we already have everything. Searches don't get a
            // cursor — they aren't time-ordered windows.
            if !isSearch, alerts.count == limit, let oldest = alerts.last {
                alertCursor = PaginationCursor(timestamp: oldest.timestamp, id: oldest.id)
                hasMoreAlerts = true
            } else {
                alertCursor = nil
                hasMoreAlerts = false
            }
        } catch {
            // DB may not exist yet
        }
    }

    func loadEvents(
        limit: Int = 500,
        filter: String? = nil,
        since: Date = .distantPast,
        until: Date = .distantFuture,
        category: MacCrabCore.EventCategory? = nil
    ) async {
        do {
            let store = try eventStore()
            let raw: [Event]
            let isSearch = filter.map { !$0.isEmpty } ?? false
            if let query = filter, isSearch {
                // Pass [since, until] through to FTS5/LIKE so an
                // "Investigate in Events" navigation can narrow to
                // the alert's firing window (e.g. ±30 min around the
                // alert timestamp). Without an upper bound, a search
                // from an alert 30 days ago still surfaced today's
                // events that matched the same process — which
                // wasn't what the user clicked Investigate to see.
                //
                // EventStore.search has no category predicate, so a
                // search + category combo is narrowed by the caller's
                // in-memory pass (EventStream.recomputeFilter) rather
                // than DB-side. That path is limit-capped, so on a busy
                // host it undercounts the same way the non-search path
                // used to — the hot-tier fix below is the primary one.
                raw = try await store.search(text: query, since: since, until: until, limit: limit)
            } else {
                // EventStore.events doesn't yet take an upper bound;
                // narrow client-side after the fetch. The result set
                // for non-search queries is already small (`limit`
                // capped) so this is fine. `category` IS pushed DB-side
                // so the picker filters the whole hot tier, not just the
                // ~500-row loaded window (which undercounts on busy hosts).
                let all = try await store.events(since: since, category: category, limit: limit)
                raw = all.filter { $0.timestamp <= until }
            }
            events = raw.map { eventToViewModel($0) }
            // Gate the live poll: while a search is active, the events array
            // holds FTS-ranked results; the live prepend would mix unrelated
            // newer rows in at the top.
            eventSearchActive = isSearch
            // FTS5 search is ordered by relevance, not time, so its tail isn't
            // a meaningful cursor — disable "Load older" while a search is
            // active. The non-search path orders by (timestamp DESC, id DESC),
            // matching the keyset cursor contract.
            if !isSearch, raw.count == limit, let oldest = raw.last {
                eventCursor = PaginationCursor(
                    timestamp: oldest.timestamp,
                    id: oldest.id.uuidString
                )
                hasMoreEvents = true
            } else {
                eventCursor = nil
                hasMoreEvents = false
            }
        } catch {
            // DB may not exist yet
        }
    }

    /// Append the next page of older alerts to `dashboardAlerts`. Backed by
    /// the keyset cursor so the call is constant-time at any depth and stable
    /// under concurrent inserts (the incremental newer-poll prepends, so its
    /// rows never collide with a paged fetch). No-op when `hasMoreAlerts` is
    /// false. Errors are swallowed — UI just stops offering "Load older".
    func loadOlderAlerts(pageSize: Int = 100) async {
        guard hasMoreAlerts, let cursor = alertCursor else { return }
        if isLoadingOlderAlerts { return }
        isLoadingOlderAlerts = true
        defer { isLoadingOlderAlerts = false }
        do {
            let store = try alertStore()
            let page = try await store.alerts(before: cursor, pageSize: pageSize)
            let overlay = suppressedIDs
            // Dedup against what we already have. The cursor's strict-less-than
            // predicate means duplicates only happen if a fetch overlapped a
            // trim — cheap to defend regardless.
            let existing = Set(dashboardAlerts.map { $0.id })
            let appended = page.items
                .filter { !existing.contains($0.id) }
                .map { alert -> AlertViewModel in
                    var vm = alertToViewModel(alert)
                    if overlay.contains(vm.id) { vm.suppressed = true }
                    return vm
                }
            if !appended.isEmpty {
                dashboardAlerts.append(contentsOf: appended)
            }
            alertCursor = page.nextCursor
            hasMoreAlerts = page.nextCursor != nil
        } catch {}
    }

    /// Mirror of `loadOlderAlerts` for the Events tab.
    func loadOlderEvents(pageSize: Int = 200, category: MacCrabCore.EventCategory? = nil) async {
        guard hasMoreEvents, let cursor = eventCursor else { return }
        if isLoadingOlderEvents { return }
        isLoadingOlderEvents = true
        defer { isLoadingOlderEvents = false }
        do {
            let store = try eventStore()
            let page = try await store.events(before: cursor, category: category, pageSize: pageSize)
            let existing = Set(events.map { $0.id })
            let appended = page.items
                .filter { !existing.contains($0.id) }
                .map { eventToViewModel($0) }
            if !appended.isEmpty {
                events.append(contentsOf: appended)
            }
            eventCursor = page.nextCursor
            hasMoreEvents = page.nextCursor != nil
        } catch {}
    }

    func loadRules() async {
        // Search for compiled rules in multiple locations
        let candidates = [
            dataDir + "/compiled_rules",
            // User-specific directory (populated by `make compile-rules`)
            FileManager.default.urls(
                for: .applicationSupportDirectory,
                in: .userDomainMask
            ).first.map { $0.appendingPathComponent("MacCrab/compiled_rules").path }
                ?? NSHomeDirectory() + "/Library/Application Support/MacCrab/compiled_rules",
            // System dir the ROOT daemon enforces from — unconditional fallback so
            // the app never reads 0 rules (→ false "degraded") when dataDir
            // resolved to the user side but the engine runs system-side.
            "/Library/Application Support/MacCrab/compiled_rules",
            // Development: next to the maccrabd binary
            URL(fileURLWithPath: CommandLine.arguments[0])
                .deletingLastPathComponent()
                .deletingLastPathComponent() // out of .app bundle
                .deletingLastPathComponent()
                .appendingPathComponent("debug/compiled_rules").path,
            // Direct build dir
            FileManager.default.currentDirectoryPath + "/.build/debug/compiled_rules",
        ]

        for dir in candidates {
            if let files = try? FileManager.default.contentsOfDirectory(atPath: dir),
               files.contains(where: { $0.hasSuffix(".json") }) {
                // v1.11.1 (audit perf MEDIUM): mtime gate. If the
                // dir we'd load from is the same one we last loaded
                // AND its mtime is unchanged, the parsed `rules`
                // array is still authoritative — skip the full-directory
                // contentsOfDirectory + JSONDecoder.decode pass.
                let mtime = (try? FileManager.default.attributesOfItem(atPath: dir))?[.modificationDate] as? Date
                if dir == rulesCacheDirPath, let mtime, mtime == rulesCacheDirMtime, !rules.isEmpty {
                    return
                }
                rules = loadRulesFromDir(dir, files: files)
                rulesLoaded = rules.count
                rulesCacheDirPath = dir
                rulesCacheDirMtime = mtime
                return
            }
        }
        rulesLoaded = 0
    }

    func unsuppressAlert(_ alertId: String) async {
        // Update authoritative set and in-memory state immediately
        suppressedIDs.remove(alertId)
        saveSuppressedIDs()
        if let idx = dashboardAlerts.firstIndex(where: { $0.id == alertId }) {
            dashboardAlerts[idx].suppressed = false
        }
        refreshAlertBadges()
        // Best-effort DB write
        do {
            let store = try alertStore()
            try await store.unsuppress(alertId: alertId)
        } catch {}
    }

    /// Suppression rules: (ruleTitle, processName) patterns to auto-hide.
    @Published var suppressionPatterns: [(ruleTitle: String, processName: String)] = []

    func suppressAlert(_ alertId: String) async {
        // Update authoritative set and in-memory state immediately — no loadAlerts() needed.
        // suppressedIDs survives any DB reload, so tab-switching can never undo a suppression.
        suppressedIDs.insert(alertId)
        saveSuppressedIDs()
        Self.uiStateLogger.info("suppressAlert \(alertId, privacy: .public) — total suppressed=\(self.suppressedIDs.count, privacy: .public)")
        if let idx = dashboardAlerts.firstIndex(where: { $0.id == alertId }) {
            dashboardAlerts[idx].suppressed = true
        }
        refreshAlertBadges()
        // Best-effort DB write (fails silently on read-only DB)
        do {
            let store = try alertStore()
            try await store.suppress(alertId: alertId)
        } catch {}
    }

    /// Bulk version of `suppressAlert`. Single authoritative-set update,
    /// single `refreshAlertBadges()`, and a serialised DB loop. The batched
    /// form exists so campaign / alert multi-select UIs don't produce N
    /// badge flickers when dismissing 20 items.
    func suppressAlerts(_ alertIds: Set<String>) async {
        guard !alertIds.isEmpty else { return }
        suppressedIDs.formUnion(alertIds)
        saveSuppressedIDs()
        for i in dashboardAlerts.indices where alertIds.contains(dashboardAlerts[i].id) {
            dashboardAlerts[i].suppressed = true
        }
        refreshAlertBadges()
        do {
            let store = try alertStore()
            for id in alertIds {
                try? await store.suppress(alertId: id)
            }
        } catch {}
    }

    /// Suppress ALL alerts matching this rule + process pattern, now and in the future.
    func suppressPattern(ruleTitle: String, processName: String) async {
        suppressionPatterns.append((ruleTitle, processName))
        saveSuppressPatterns()

        // Suppress all matching alerts in DB
        do {
            let store = try alertStore()
            for alert in dashboardAlerts where alert.ruleTitle == ruleTitle && alert.processName == processName && !alert.suppressed {
                try await store.suppress(alertId: alert.id)
            }
        } catch {}

        // Mark as suppressed in display and in the authoritative set
        for i in dashboardAlerts.indices {
            if dashboardAlerts[i].ruleTitle == ruleTitle && dashboardAlerts[i].processName == processName {
                suppressedIDs.insert(dashboardAlerts[i].id)
                dashboardAlerts[i].suppressed = true
            }
        }
        saveSuppressedIDs()
        refreshAlertBadges()
    }

    /// Remove a suppression pattern.
    func unsuppressPattern(ruleTitle: String, processName: String) {
        suppressionPatterns.removeAll { $0.ruleTitle == ruleTitle && $0.processName == processName }
        saveSuppressPatterns()
    }

    /// Check if an alert matches a suppression pattern.
    func isPatternSuppressed(_ alert: AlertViewModel) -> Bool {
        suppressionPatterns.contains { $0.ruleTitle == alert.ruleTitle && $0.processName == alert.processName }
    }

    /// Sidebar-count and "recent" list share a filter: unsuppressed, not in
    /// the overlay, not pattern-suppressed, and NOT a campaign alert.
    /// Campaigns ship as alerts with `ruleId` prefixed `maccrab.campaign.`
    /// and have their own sidebar badge — counting them in both totals was
    /// the v1.3.10 sidebar double-count bug.
    private func visibleAlertsForBadges() -> [AlertViewModel] {
        dashboardAlerts.filter {
            !$0.suppressed
            && !suppressedIDs.contains($0.id)
            && !isPatternSuppressed($0)
            && !$0.ruleId.hasPrefix("maccrab.campaign.")
        }
    }

    /// Refresh `recentAlerts` (top 5 for Overview) and `totalAlerts` (sidebar
    /// badge). Keep this as the single source of truth for those derived
    /// fields so adding a new filter term (like the campaign-exclusion
    /// above) only requires editing one place.
    private func refreshAlertBadges() {
        let visible = visibleAlertsForBadges()
        recentAlerts = Array(visible.prefix(5))
        totalAlerts = visible.count
    }

    /// Check the user TCC.db and/or system TCC.db for the sysext's FDA row.
    /// `userTCC` is nil when the app itself doesn't have FDA (file unreadable).
    /// The system TCC.db open silently fails without root — that's expected.
    private static func querySysextFDA(userTCC: String?, systemTCC: String) -> Bool {
        if let path = userTCC, querySysextFDAInDB(path) { return true }
        if querySysextFDAInDB(systemTCC) { return true }
        return false
    }

    /// Open one TCC.db and look for an authorized sysext FDA entry.
    /// Matches a closed set of known client identifiers — the plain bundle
    /// ID and the `.systemextension` suffix variant seen on some macOS
    /// builds. A prior revision used `LIKE 'com.maccrab.agent%'` which
    /// matched too broadly (any future `com.maccrab.agent.*` would collide).
    private static func querySysextFDAInDB(_ tccPath: String) -> Bool {
        // `sqlite3_open_v2` follows symlinks. A privileged attacker who can
        // swap the TCC.db path for a symlink pointing at a malicious DB could
        // steer our probe. Reject symlinks up front; regular files only.
        // Mirrors the pattern used in EventStore / AlertStore.
        guard !Self.isSymlink(tccPath) else { return false }
        var db: OpaquePointer?
        guard sqlite3_open_v2(tccPath, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, nil) == SQLITE_OK else { return false }
        defer { sqlite3_close(db) }
        let sql = "SELECT auth_value FROM access WHERE service='kTCCServiceSystemPolicyAllFiles' AND client IN ('com.maccrab.agent', 'com.maccrab.agent.systemextension')"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return false }
        defer { sqlite3_finalize(stmt) }
        while sqlite3_step(stmt) == SQLITE_ROW {
            if sqlite3_column_int(stmt, 0) == 2 { return true }
        }
        return false
    }

    /// Return true if `path` is a symbolic link (lstat does NOT follow).
    /// Missing files return false — the caller's sqlite3_open_v2 will handle
    /// the not-found case.
    private static func isSymlink(_ path: String) -> Bool {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: path) else {
            return false
        }
        return (attrs[.type] as? FileAttributeType) == .typeSymbolicLink
    }

    // MARK: - UI-state storage
    //
    // v1.3.12 bug fix: dashboard state (suppression IDs, suppression
    // patterns) used to live inside `dataDir`, which resolves to either
    // the user-home MacCrab dir or the system-wide one depending on
    // which `events.db` was modified most recently. After every
    // upgrade the sysext writes fresh events to the system DB, flipping
    // `dataDir` to `/Library/Application Support/MacCrab/` — a
    // directory the non-root dashboard can't write to. Result:
    // `try? json.write(...)` silently fails, the next launch's
    // `loadSuppressedIDs()` reads from the new empty system location,
    // and every user suppression disappears.
    //
    // Fix: anchor UI-state writes to the stable user-home path. Dashboard
    // state belongs to the user, not to the detection engine.
    //
    // Migration: when loading, fall back to the old dataDir copy if the
    // user-home copy doesn't exist. First successful save under the new
    // path makes the fallback unnecessary going forward.

    // v1.4.1 diagnostic logging: users reported suppressions still
    // resetting after the v1.3.12/v1.4.0 fix was supposed to anchor them
    // to user-home. These logger calls make save/load paths visible under
    // `sudo log show --subsystem com.maccrab.app --predicate
    // 'category == "ui-state"' --last 1h` so a future repro leaves a
    // trail. Values are file paths and counts, never user secrets, so
    // `.public` is safe.
    private static let uiStateLogger = Logger(subsystem: "com.maccrab.app", category: "ui-state")

    private var uiStateDir: String {
        let home = NSHomeDirectory()
        let dir = "\(home)/Library/Application Support/MacCrab"
        do {
            try FileManager.default.createDirectory(
                atPath: dir,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        } catch {
            Self.uiStateLogger.error("Failed to create uiStateDir \(dir, privacy: .public): \(error.localizedDescription, privacy: .public)")
        }
        return dir
    }

    /// Read a UI-state JSON blob, preferring `uiStateDir` with a
    /// fallback to the legacy `dataDir` location so pre-v1.3.12 users
    /// don't lose their suppressions on upgrade.
    private func readUIState(_ filename: String) -> Data? {
        let newPath = "\(uiStateDir)/\(filename)"
        if let data = try? Data(contentsOf: URL(fileURLWithPath: newPath)) {
            Self.uiStateLogger.info("Read \(filename, privacy: .public) from uiStateDir (\(data.count) bytes)")
            return data
        }
        let oldPath = "\(dataDir)/\(filename)"
        if oldPath != newPath, let data = try? Data(contentsOf: URL(fileURLWithPath: oldPath)) {
            Self.uiStateLogger.notice("Read \(filename, privacy: .public) from legacy dataDir fallback \(self.dataDir, privacy: .public) (\(data.count) bytes)")
            return data
        }
        Self.uiStateLogger.info("No \(filename, privacy: .public) found at uiStateDir or dataDir — using defaults")
        return nil
    }

    /// Write a UI-state JSON blob under `uiStateDir` via temp + rename so a
    /// crash between calls cannot leave a half-written file that the next
    /// readback would fail to decode (silently wiping user suppressions).
    private func writeUIState(_ filename: String, data: Data) {
        let path = "\(uiStateDir)/\(filename)"
        let tmp = path + ".tmp"
        do {
            try data.write(to: URL(fileURLWithPath: tmp))
            // moveItem fails if the destination exists — remove first on the
            // second+ write. Not atomic with respect to a crash between
            // remove and rename, but the temp file remains and the next
            // write recovers cleanly.
            if FileManager.default.fileExists(atPath: path) {
                try FileManager.default.removeItem(atPath: path)
            }
            try FileManager.default.moveItem(atPath: tmp, toPath: path)
            Self.uiStateLogger.info("Wrote \(filename, privacy: .public) (\(data.count) bytes) to \(path, privacy: .public)")
        } catch {
            try? FileManager.default.removeItem(atPath: tmp)
            Self.uiStateLogger.error("Failed to write \(filename, privacy: .public) to \(path, privacy: .public): \(error.localizedDescription, privacy: .public)")
        }
    }

    private func saveSuppressPatterns() {
        let data = suppressionPatterns.map { ["ruleTitle": $0.ruleTitle, "processName": $0.processName] }
        if let json = try? JSONSerialization.data(withJSONObject: data) {
            writeUIState("ui_suppressions.json", data: json)
        }
    }

    func loadSuppressPatterns() {
        guard let data = readUIState("ui_suppressions.json"),
              let arr = try? JSONSerialization.jsonObject(with: data) as? [[String: String]] else { return }
        suppressionPatterns = arr.compactMap { dict in
            guard let r = dict["ruleTitle"], let p = dict["processName"] else { return nil }
            return (r, p)
        }
        Self.uiStateLogger.info("Loaded \(self.suppressionPatterns.count, privacy: .public) suppression pattern(s)")
    }

    /// Persist the current `suppressedIDs` set to disk so suppressions survive app restarts.
    private func saveSuppressedIDs() {
        let arr = Array(suppressedIDs)
        if let json = try? JSONSerialization.data(withJSONObject: arr) {
            writeUIState("ui_suppressed_ids.json", data: json)
        }
    }

    /// Load previously persisted `suppressedIDs` on startup. Also migrates
    /// the state forward: if we found the file only at the legacy
    /// `dataDir` location (not at `uiStateDir`), rewrite it immediately so
    /// future launches hit the stable path on the first try.
    func loadSuppressedIDs() {
        guard let data = readUIState("ui_suppressed_ids.json"),
              let arr = try? JSONSerialization.jsonObject(with: data) as? [String] else { return }
        suppressedIDs = Set(arr)
        Self.uiStateLogger.info("Loaded \(self.suppressedIDs.count, privacy: .public) suppressed alert id(s)")

        // Migration: if the file only exists at legacy dataDir, rewrite
        // it at uiStateDir so the stable location is authoritative.
        let newPath = "\(uiStateDir)/ui_suppressed_ids.json"
        if !FileManager.default.fileExists(atPath: newPath) {
            saveSuppressedIDs()
        }
    }

    func reloadDaemonRules() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
        task.arguments = ["-HUP", "maccrabd"]
        try? task.run()
    }

    /// Human-readable result of the last `pruneAlerts` call — shown next to
    /// the "Clear Now" button so users see confirmation without a modal.
    @Published var lastPruneResult: String?

    /// Delete alerts older than `olderThanDays`. Wraps `AlertStore.prune`,
    /// refreshes the dashboard afterwards, and records a user-facing
    /// summary string. Failures are caught and surfaced via the same
    /// `lastPruneResult` field so the UI has exactly one feedback surface.
    func pruneAlerts(olderThanDays days: Int) async {
        guard days > 0 else { return }
        let cutoff = Date().addingTimeInterval(-Double(days) * 86_400)
        do {
            let store = try alertStore()
            let deleted = try await store.prune(olderThan: cutoff)
            await refresh()
            lastPruneResult = deleted == 0
                ? "No alerts older than \(days) days"
                : "Deleted \(deleted) alerts older than \(days) days"
        } catch {
            // Deep-audit fix (2568): the dashboard opens alerts.db read-only
            // (the root daemon owns it), so a direct prune always throws
            // "attempt to write a readonly database" on a release install —
            // "Clear Now" never worked. Route the bulk delete through the
            // privileged inbox the same way alert suppress/delete already do;
            // the daemon owns the writable handle and applies it on its next
            // poll. We can't report an exact count synchronously, so the
            // feedback becomes "requested".
            if Self.isReadOnlyError(error), dropPruneAlertsRequest(olderThanDays: days) {
                lastPruneResult = "Requested cleanup of alerts older than \(days) days — the engine will apply it shortly."
            } else {
                lastPruneResult = "Prune failed: \(error.localizedDescription)"
            }
        }
    }

    /// True when a SQLite write failed because the dashboard holds a
    /// read-only handle on a root-owned DB (the common release case).
    /// Mirrors V2LiveDataProvider.isReadOnlyError.
    nonisolated static func isReadOnlyError(_ error: Error) -> Bool {
        let s = "\(error)".lowercased()
        return s.contains("readonly") || s.contains("read-only")
            || s.contains("permission denied") || s.contains("operation not permitted")
    }

    /// Drop a `prune-alerts-<token>.json` request into the daemon's inbox so
    /// the root engine (which owns alerts.db) performs the retention delete.
    /// Written to BOTH the system and user support dirs — whichever daemon is
    /// running polls its own inbox (matches writeClickFixPayloadToInbox /
    /// dropBuiltinRuleSetting). Returns true if at least one write landed.
    ///
    /// DAEMON-SIDE HANDLER REQUIRED (residual): add a `prune-alerts-` verb to
    /// the inbox poller in DaemonTimers.swift (partition + handlePruneAlertsRequests)
    /// that reads `olderThanDays`, opens alerts.db read-write, calls
    /// AlertStore.prune(olderThan:), and applies the same uid/symlink auth gate
    /// + audit as the delete-alert verb.
    private func dropPruneAlertsRequest(olderThanDays days: Int) -> Bool {
        let dirs = ["/Library/Application Support/MacCrab/inbox",
                    NSHomeDirectory() + "/Library/Application Support/MacCrab/inbox"]
        var wrote = false
        for dir in dirs where Self.writePruneAlertsRequest(inboxDir: dir, olderThanDays: days) {
            wrote = true
        }
        return wrote
    }

    /// Write one `prune-alerts-*.json` into `inboxDir`. Static + pure so it's
    /// unit-testable against a temp dir (mirrors writeInboxRefreshRequest).
    /// Returns false on an unwritable path (honest failure, no fake success).
    nonisolated static func writePruneAlertsRequest(inboxDir: String, olderThanDays days: Int) -> Bool {
        let fm = FileManager.default
        if !fm.fileExists(atPath: inboxDir) {
            try? fm.createDirectory(atPath: inboxDir, withIntermediateDirectories: true)
        }
        let obj: [String: Any] = [
            "schema_version": 1,
            "olderThanDays": days,
            "requester": "MacCrabApp",
            "queuedAt": ISO8601DateFormatter().string(from: Date())
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: obj) else { return false }
        let token = "\(Int(Date().timeIntervalSince1970))-\(getpid())-\(UUID().uuidString.prefix(8))"
        let path = inboxDir + "/prune-alerts-\(token).json"
        do {
            try data.write(to: URL(fileURLWithPath: path), options: .atomic)
            return true
        } catch {
            return false
        }
    }

    // MARK: Incremental Loading

    private func loadAlertsIncremental() async {
        // Mirror loadEventsIncremental: skip the prepend during search so the
        // relevance-ordered LIKE results stay intact between poll ticks.
        if alertSearchActive { return }
        do {
            let store = try alertStore()
            let newAlerts = try await store.alerts(since: lastAlertTimestamp, limit: 100)
            let existingIDs = Set(dashboardAlerts.map { $0.id })
            let overlay = suppressedIDs
            let newViewModels = newAlerts
                .filter { $0.timestamp > lastAlertTimestamp && !existingIDs.contains($0.id) }
                .map { alert -> AlertViewModel in
                    var vm = alertToViewModel(alert)
                    if overlay.contains(vm.id) { vm.suppressed = true }
                    return vm
                }
            if !newViewModels.isEmpty {
                dashboardAlerts.insert(contentsOf: newViewModels, at: 0)
                // Soft cap to bound memory while leaving "Load older" room.
                // 5000 alerts is plenty (a busy day rarely exceeds 1-2k); the
                // 500-trim that lived here pre-v1.8 silently discarded any
                // alerts the user had paged in.
                if dashboardAlerts.count > 5000 { dashboardAlerts = Array(dashboardAlerts.prefix(5000)) }
                refreshAlertBadges()
                lastAlertTimestamp = newViewModels.first?.timestamp ?? lastAlertTimestamp

                // v1.21.4: the in-app alert popover is NO LONGER triggered here.
                // It is owned solely by AlertNotifier (OS banner, with the
                // popover as its auth-denied fallback). This independent
                // per-poll trigger fired the popover in ADDITION to the banner
                // for the same critical alert — the double-notification bug.

                // Extract AI analysis alerts
                aiAnalysisAlerts = dashboardAlerts.filter {
                    $0.ruleTitle.hasPrefix("Investigation Summary:") ||
                    $0.ruleTitle.hasPrefix("Defense Recommendation:")
                }
            }
        } catch {}
    }

    private func loadEventsIncremental() async {
        // Don't trample search results with newer rows the user didn't ask for.
        if eventSearchActive { return }
        do {
            let store = try eventStore()
            let newEvents = try await store.events(since: lastEventTimestamp, limit: 200)
            let newViewModels = newEvents
                .filter { $0.timestamp > lastEventTimestamp }
                .map { eventToViewModel($0) }
            if !newViewModels.isEmpty {
                events.insert(contentsOf: newViewModels, at: 0)
                // Soft cap matches the alerts list — see loadAlertsIncremental.
                if events.count > 5000 { events = Array(events.prefix(5000)) }
                lastEventTimestamp = newViewModels.first?.timestamp ?? lastEventTimestamp
            }
        } catch {}
    }

    // MARK: Private — Data Mapping

    /// internal (not private) so AppDelegate can convert a
    /// MacCrabCore.Alert to the popover's view model in the
    /// notification deny-fallback path.
    func alertToViewModel(_ a: Alert) -> AlertViewModel {
        AlertViewModel(
            id: a.id,
            timestamp: a.timestamp,
            ruleId: a.ruleId,
            ruleTitle: a.ruleTitle,
            severity: mapSeverity(a.severity),
            processName: a.processName ?? "unknown",
            processPath: a.processPath ?? "",
            description: a.description ?? "",
            mitreTechniques: a.mitreTechniques ?? "",
            suppressed: a.suppressed,
            eventId: a.eventId,
            llmInvestigation: a.llmInvestigation,
            triggeringEventsJson: a.triggeringEventsJson
        )
    }

    /// Fetch the originating Event for an alert so the detail view can
    /// render command line, parent, signer, file path, network endpoint,
    /// and ancestors. Returns nil for alerts without a backing Event
    /// (USB, clipboard, tamper) or when the event has already been
    /// pruned from the DB.
    func fetchEvent(id: String) async -> Event? {
        guard let uuid = UUID(uuidString: id) else { return nil }
        do {
            let store = try eventStore()
            return try await store.event(id: uuid)
        } catch {
            return nil
        }
    }

    /// v1.8.0: read the surrounding ±60s window of events that the daemon
    /// snapshotted into `alert_evidence` when this alert fired. The list
    /// is empty for alerts predating v1.8 evidence capture, and for any
    /// alert where the snapshot transaction failed (best-effort by design).
    func fetchEvidence(alertId: String) async -> [Event] {
        do {
            let store = try eventStore()
            return try await store.evidenceFor(alertId: alertId)
        } catch {
            return []
        }
    }

    /// v1.8.0: read aggregate counts (day, category, signer, path) from the
    /// warm-tier rollup table. Backs the Overview trends widget and the
    /// Events tab "summarized" indicator when the user picks a range >24h.
    func fetchAggregates(sinceDay: String, category: MacCrabCore.EventCategory? = nil) async -> [EventStore.AggregateRow] {
        do {
            let store = try eventStore()
            return try await store.aggregates(sinceDay: sinceDay, category: category)
        } catch {
            return []
        }
    }

    /// v1.8.0 polish: SQL-side histogram bin counts. The Events-tab chart
    /// was previously built from the 500-row in-memory cache, which on a
    /// 264 events/sec host covered ~2 seconds of activity — every bin
    /// collapsed into one regardless of window size. This fetches counts
    /// straight from the events table via GROUP BY on a stepped bucket
    /// expression so the chart accurately reflects the full window.
    func fetchHistogramBins(
        spanSeconds: TimeInterval,
        stepSeconds: Int,
        endingAt: Date = Date(),
        category: MacCrabCore.EventCategory? = nil
    ) async -> [(Date, Int)] {
        do {
            let store = try eventStore()
            return try await store.histogramBins(
                spanSeconds: spanSeconds,
                stepSeconds: stepSeconds,
                endingAt: endingAt,
                category: category
            )
        } catch {
            return []
        }
    }

    private func eventToViewModel(_ e: Event) -> EventViewModel {
        let detail: String
        if let file = e.file {
            detail = file.path
        } else if let net = e.network {
            detail = "\(net.destinationIp):\(net.destinationPort)"
        } else if let tcc = e.tcc {
            detail = "\(tcc.service) → \(tcc.client)"
        } else {
            detail = e.process.executable
        }

        // v1.12.6 Wave 9H: surface Wave-2 schema additions in the
        // detail pane. ai_tool reads `ai_tool` first then `agent_tool`
        // (Wave 9C's enrichment-key writer fallback) so we display
        // whichever key the producing path chose. is_notarized is
        // optional — codeSignature may be nil (e.g. ad-hoc / unsigned
        // bin); only show it when we have signature info.
        let parent = e.process.ancestors.first
        let aiToolValue = e.enrichments["ai_tool"]
            ?? e.enrichments["agent_tool"] ?? ""
        return EventViewModel(
            id: e.id,
            timestamp: e.timestamp,
            action: e.eventAction,
            category: mapCategory(e.eventCategory),
            processName: e.process.name,
            pid: e.process.pid,
            detail: detail,
            signerType: e.process.codeSignature?.signerType.rawValue ?? "",
            executablePath: e.process.executable,
            commandLine: e.process.commandLine,
            userName: e.process.userName,
            workingDirectory: e.process.workingDirectory,
            architecture: e.process.architecture ?? "",
            isNotarized: e.process.codeSignature.map { $0.isNotarized },
            aiTool: aiToolValue,
            parentName: parent?.name ?? "",
            parentExecutable: parent?.executable ?? "",
            processSHA256: e.process.hashes?.sha256 ?? ""
        )
    }

    private func mapSeverity(_ s: MacCrabCore.Severity) -> Severity {
        switch s {
        case .informational: return .informational
        case .low: return .low
        case .medium: return .medium
        case .high: return .high
        case .critical: return .critical
        }
    }

    private func mapCategory(_ c: MacCrabCore.EventCategory) -> EventCategory {
        switch c {
        case .process: return .process
        case .file: return .file
        case .network: return .network
        case .authentication: return .authentication
        case .tcc: return .tcc
        case .registry: return .registry
        }
    }

    private func loadRulesFromDir(_ dir: String, files: [String]) -> [RuleViewModel] {
        let decoder = JSONDecoder()
        return files.compactMap { file -> RuleViewModel? in
            guard file.hasSuffix(".json") else { return nil }
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: dir + "/" + file)),
                  let rule = try? decoder.decode(CompiledRule.self, from: data) else { return nil }
            return RuleViewModel(
                id: rule.id,
                title: rule.title,
                level: rule.level.rawValue,
                tags: rule.tags,
                description: rule.description,
                enabled: rule.enabled
            )
        }
    }

    /// Compute events/sec from two count samples. Returns nil for the very
    /// first sample (previousCount == nil) so the caller primes the baseline
    /// without publishing a spurious spike equal to the entire event backlog.
    /// Static + pure for unit testing.
    nonisolated static func eventsPerSecondFrom(previousCount: Int?, currentCount: Int, elapsedSeconds: Int) -> Int? {
        guard let previous = previousCount else { return nil }
        let delta = currentCount - previous
        let elapsed = max(1, elapsedSeconds)
        return delta > 0 ? max(1, delta / elapsed) : 0
    }

    private func updateStats() async {
        do {
            let store = try eventStore()
            let currentCount = try await store.count()
            let now = Date()
            let elapsed = max(1, Int(now.timeIntervalSince(lastStatsUpdate)))
            // Deep-audit fix (2814): skip the FIRST sample. With no baseline the
            // delta is the entire backlog, which published a spurious events/sec
            // spike on the first poll. `eventsPerSecondFrom` returns nil until
            // primed. Only publish when the displayed value actually changes —
            // every @Published assignment invalidates every SwiftUI view that
            // subscribes to AppState (OverviewDashboard, StatusBarMenu,
            // ESHealthView read eventsPerSecond), and re-publishing the same 0
            // every tick forced a full-dashboard redraw with no visible change.
            if let rate = Self.eventsPerSecondFrom(previousCount: previousEventCount,
                                                   currentCount: currentCount,
                                                   elapsedSeconds: elapsed),
               rate != eventsPerSecond {
                eventsPerSecond = rate
            }
            previousEventCount = currentCount
            lastStatsUpdate = now
        } catch {}

        // Recompute security score at most every 5 minutes (scorer
        // calls system APIs). v1.11.1 (audit perf LOW): the audit
        // flagged this as "could be a dedicated DispatchSource", but
        // a `timeIntervalSince()` comparison per 5-s refresh tick is
        // essentially free (sub-microsecond), and the alternative
        // (background Task with sleep) introduces lifecycle complexity
        // around AppState teardown without a measurable win. Keeping
        // the elapsed-time gate; revisit if profiling ever shows it
        // matters.
        let now = Date()
        if now.timeIntervalSince(lastSecurityScoreUpdate) >= 300 {
            let result = await SecurityScorer().calculate()
            securityScore = result.totalScore
            securityGrade = result.grade
            securityFactors = result.factors
            lastSecurityScoreUpdate = now
        }
    }
}
