// AppState.swift
// MacCrabApp
//
// Central state object for the MacCrab dashboard app.
// Reads real data from the daemon's SQLite database.

import Foundation
import Combine
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

        /// Ages past this are considered stale → detection engine is
        /// either hung, crashed, or replaced by a silent no-op. 120s
        /// is ~4× the 30s write cadence: tolerates one missed tick and
        /// common IO hiccups without false-positive banner.
        static let staleThreshold: TimeInterval = 120
        var isStale: Bool { Date().timeIntervalSince(writtenAt) > Self.staleThreshold }
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
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return
        }
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
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            // No file → no tamper detected. Clear any stale state.
            if ruleTamper != nil { ruleTamper = nil }
            return
        }
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
    func refreshHeartbeat() {
        let path = "/Library/Application Support/MacCrab/heartbeat.json"
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
                    alertsEmitted: 0
                )
            }
            return
        }
        heartbeat = HeartbeatSnapshot(
            writtenAt: Date(timeIntervalSince1970: writtenAtUnix),
            uptimeSeconds: json["uptime_seconds"] as? Int ?? 0,
            eventsProcessed: (json["events_processed"] as? UInt64)
                ?? UInt64(json["events_processed"] as? Int ?? 0),
            alertsEmitted: (json["alerts_emitted"] as? UInt64)
                ?? UInt64(json["alerts_emitted"] as? Int ?? 0)
        )
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
    /// The sysext can read TCC-protected paths — means FDA is granted to
    /// "MacCrab Endpoint Security Extension". We can't probe this directly
    /// from the app (separate process), so we infer from the presence of a
    /// healthy events.db with recent writes: if the sysext is writing TCC
    /// events to disk, it has FDA. Otherwise we assume it doesn't.
    @Published var sysextHasFDA: Bool = true
    @Published var recentAlerts: [AlertViewModel] = []
    @Published var dashboardAlerts: [AlertViewModel] = []
    @Published var events: [EventViewModel] = []
    @Published var rules: [RuleViewModel] = []
    @Published var tccEvents: [TCCEventViewModel] = []

    enum Tab: String, CaseIterable { case overview, alerts, events, rules, tcc, aiGuard, prevention, threatIntel, integrations, docs }

    /// Threat intel stats for the dashboard
    struct ThreatIntelStats {
        var hashes: Int = 0
        var ips: Int = 0
        var domains: Int = 0
        var urls: Int = 0
        var lastUpdate: Date?
    }
    @Published var threatIntelStats = ThreatIntelStats()

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

    @Published var selectedTab: Tab = .overview

    /// Security posture score (0-100) and letter grade.
    /// Computed by SecurityScorer on first load and refreshed every 5 minutes.
    @Published var securityScore: Int = 0
    @Published var securityGrade: String = ""

    // MARK: Private

    /// Callback for showing critical alert popovers in the menu bar
    var onCriticalAlert: ((AlertViewModel) -> Void)?

    private var pollTimer: AnyCancellable?
    private var previousEventCount: Int = 0
    private var lastStatsUpdate: Date = Date()
    private var rulesLoaded_cached = false
    private var lastAlertTimestamp: Date = .distantPast
    private var lastEventTimestamp: Date = .distantPast
    private var lastSecurityScoreUpdate: Date = .distantPast

    /// Authoritative set of alert IDs the user has manually suppressed this session.
    /// Published so SwiftUI views (filteredAlerts) re-render whenever it changes,
    /// guaranteeing suppression state is never overwritten by a DB reload.
    @Published var suppressedIDs: Set<String> = []

    /// Cached DB connections — avoid reopening on every poll cycle
    private var cachedAlertStore: AlertStore?
    private var cachedEventStore: EventStore?
    private var dbLastChecked: Date = .distantPast

    /// Resolve the MacCrab data directory.
    /// Prefers the system dir (root daemon) when its DB exists and is newer
    /// than the user dir DB, which may contain stale data from a previous
    /// non-root run. v1.4: use *readable* checks (not just `fileExists`),
    /// log the chosen path so operators can diagnose, and do not fall
    /// through to an unreadable path silently.
    private let dataDir: String = {
        let fm = FileManager.default
        let logger = Logger(subsystem: "com.maccrab.app", category: "data-dir")
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
        // Poll every 10 seconds (not 5 — reduces CPU by 50%)
        pollTimer = Timer.publish(every: 10.0, on: .main, in: .common)
            .autoconnect()
            .sink { [weak self] _ in
                guard let self else { return }
                Task { @MainActor in await self.refresh() }
            }
        loadSuppressPatterns()
        loadSuppressedIDs()
        Task { await refresh() }
    }

    /// Get or create cached alert store.
    /// Reopens every 30 seconds to pick up new WAL data from the daemon.
    private func alertStore() throws -> AlertStore {
        if let store = cachedAlertStore,
           Date().timeIntervalSince(dbLastChecked) < 30 { return store }
        let store = try AlertStore(directory: dataDir)
        cachedAlertStore = store
        dbLastChecked = Date()
        return store
    }

    /// Get or create cached event store
    private func eventStore() throws -> EventStore {
        if let store = cachedEventStore,
           Date().timeIntervalSince(dbLastChecked) < 30 { return store }
        let store = try EventStore(directory: dataDir)
        cachedEventStore = store
        return store
    }

    // MARK: Public interface

    func refresh() async {
        // Check daemon connectivity: DB exists + has data = connected
        // Also check for WAL file which indicates active writer (daemon)
        let dbPath = dataDir + "/events.db"
        let fm = FileManager.default
        let dbExists = fm.isReadableFile(atPath: dbPath)
        let walExists = fm.fileExists(atPath: dbPath + "-wal")
        isConnected = dbExists && (walExists || fm.fileExists(atPath: dbPath + "-shm"))

        // FDA probe for the APP principal — readability of the user TCC.db
        // requires Full Disk Access granted to MacCrab.app.
        let tccPath = NSHomeDirectory() + "/Library/Application Support/com.apple.TCC/TCC.db"
        appHasFDA = fm.isReadableFile(atPath: tccPath)

        // FDA probe for the SYSEXT principal — we can't call an API from
        // here that directly tells us the sysext's TCC state, but we can
        // infer it: if events.db WAL has been written to recently, the
        // sysext is flowing ES events, which requires it to have FDA for
        // protected paths. If the WAL hasn't been touched in the last 5
        // minutes, assume it's missing FDA (or the sysext is wedged).
        let walPath = dbPath + "-wal"
        if let attrs = try? fm.attributesOfItem(atPath: walPath),
           let mtime = attrs[.modificationDate] as? Date {
            sysextHasFDA = Date().timeIntervalSince(mtime) < 300
        } else {
            // No WAL yet → sysext hasn't written anything → assume missing FDA
            // until proven otherwise.
            sysextHasFDA = !isConnected ? false : sysextHasFDA
        }
        fullDiskAccessGranted = appHasFDA && sysextHasFDA

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
        maybeKickWatchdog()

        // Rules rarely change — only load once
        if !rulesLoaded_cached {
            await loadRules()
            await loadTCCEvents()
            rulesLoaded_cached = true
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

    func loadAlerts(limit: Int = 500) async {
        do {
            let store = try alertStore()
            let alerts = try await store.alerts(since: Date.distantPast, limit: limit)
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
        } catch {
            // DB may not exist yet
        }
    }

    func loadEvents(limit: Int = 500, filter: String? = nil) async {
        do {
            let store = try eventStore()
            let raw: [Event]
            if let query = filter, !query.isEmpty {
                raw = try await store.search(text: query, limit: limit)
            } else {
                raw = try await store.events(since: Date.distantPast, limit: limit)
            }
            events = raw.map { eventToViewModel($0) }
        } catch {
            // DB may not exist yet
        }
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
                rules = loadRulesFromDir(dir, files: files)
                rulesLoaded = rules.count
                return
            }
        }
        rulesLoaded = 0
    }

    func loadTCCEvents() async {
        do {
            let store = try eventStore()
            let tccRaw = try await store.events(since: Date.distantPast, category: .tcc, limit: 200)
            tccEvents = tccRaw.compactMap { event -> TCCEventViewModel? in
                guard let tcc = event.tcc else { return nil }
                return TCCEventViewModel(
                    id: event.id.uuidString,
                    timestamp: event.timestamp,
                    serviceName: tcc.service,
                    clientName: tcc.client,
                    clientPath: tcc.clientPath,
                    allowed: tcc.allowed,
                    authReason: tcc.authReason
                )
            }
        } catch {
            // DB may not exist yet
        }
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

    /// Write a UI-state JSON blob under `uiStateDir`.
    private func writeUIState(_ filename: String, data: Data) {
        let path = "\(uiStateDir)/\(filename)"
        do {
            try data.write(to: URL(fileURLWithPath: path))
            Self.uiStateLogger.info("Wrote \(filename, privacy: .public) (\(data.count) bytes) to \(path, privacy: .public)")
        } catch {
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
            lastPruneResult = "Prune failed: \(error.localizedDescription)"
        }
    }

    // MARK: Incremental Loading

    private func loadAlertsIncremental() async {
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
                // Cap at 500
                if dashboardAlerts.count > 500 { dashboardAlerts = Array(dashboardAlerts.prefix(500)) }
                refreshAlertBadges()
                lastAlertTimestamp = newViewModels.first?.timestamp ?? lastAlertTimestamp

                // Trigger crab speech bubble for critical/high alerts
                if let newest = newViewModels.first,
                   (newest.severity == .critical || newest.severity == .high),
                   !newest.suppressed, !isPatternSuppressed(newest) {
                    onCriticalAlert?(newest)
                }

                // Extract AI analysis alerts
                aiAnalysisAlerts = dashboardAlerts.filter {
                    $0.ruleTitle.hasPrefix("Investigation Summary:") ||
                    $0.ruleTitle.hasPrefix("Defense Recommendation:")
                }
            }
        } catch {}
    }

    private func loadEventsIncremental() async {
        do {
            let store = try eventStore()
            let newEvents = try await store.events(since: lastEventTimestamp, limit: 200)
            let newViewModels = newEvents
                .filter { $0.timestamp > lastEventTimestamp }
                .map { eventToViewModel($0) }
            if !newViewModels.isEmpty {
                events.insert(contentsOf: newViewModels, at: 0)
                if events.count > 500 { events = Array(events.prefix(500)) }
                lastEventTimestamp = newViewModels.first?.timestamp ?? lastEventTimestamp
            }
        } catch {}
    }

    // MARK: Private — Data Mapping

    private func alertToViewModel(_ a: Alert) -> AlertViewModel {
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
            llmInvestigation: a.llmInvestigation
        )
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

        return EventViewModel(
            id: e.id,
            timestamp: e.timestamp,
            action: e.eventAction,
            category: mapCategory(e.eventCategory),
            processName: e.process.name,
            pid: e.process.pid,
            detail: detail,
            signerType: e.process.codeSignature?.signerType.rawValue ?? ""
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

    private func updateStats() async {
        do {
            let store = try eventStore()
            let currentCount = try await store.count()
            let now = Date()
            let elapsed = max(1, Int(now.timeIntervalSince(lastStatsUpdate)))
            let delta = currentCount - previousEventCount
            eventsPerSecond = delta > 0 ? max(1, delta / elapsed) : 0
            previousEventCount = currentCount
            lastStatsUpdate = now
        } catch {}

        // Recompute security score at most every 5 minutes (scorer calls system APIs)
        let now = Date()
        if now.timeIntervalSince(lastSecurityScoreUpdate) >= 300 {
            let result = await SecurityScorer().calculate()
            securityScore = result.totalScore
            securityGrade = result.grade
            lastSecurityScoreUpdate = now
        }
    }
}
