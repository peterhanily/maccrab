// AppState.swift
// MacCrabApp
//
// Central state object for the MacCrab dashboard app.
// Reads real data from the daemon's SQLite database.

import Foundation
import Combine
import MacCrabCore

// MARK: - AppState

@MainActor
final class AppState: ObservableObject {

    // MARK: Published state

    @Published var isConnected: Bool = false
    @Published var eventsPerSecond: Int = 0
    @Published var rulesLoaded: Int = 0
    @Published var totalAlerts: Int = 0

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
    /// non-root run.
    private let dataDir: String = {
        let fm = FileManager.default
        let userDir = fm.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first.map { $0.appendingPathComponent("MacCrab").path }
            ?? NSHomeDirectory() + "/Library/Application Support/MacCrab"
        let systemDir = "/Library/Application Support/MacCrab"

        let userDB = userDir + "/events.db"
        let systemDB = systemDir + "/events.db"
        let userExists = fm.fileExists(atPath: userDB)
        let systemReadable = fm.isReadableFile(atPath: systemDB)

        // If both exist, prefer whichever was modified more recently.
        if userExists && systemReadable {
            let userMod = (try? fm.attributesOfItem(atPath: userDB))?[.modificationDate] as? Date
            let sysMod = (try? fm.attributesOfItem(atPath: systemDB))?[.modificationDate] as? Date
            if let s = sysMod, let u = userMod, s >= u {
                return systemDir
            }
            return userDir
        }
        if systemReadable { return systemDir }
        if userExists { return userDir }
        // Neither exists yet — default to system dir so we pick it up when
        // the root daemon creates it.
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
            let llmConfigPath = dataDir + "/llm_config.json"
            if let data = try? Data(contentsOf: URL(fileURLWithPath: llmConfigPath)),
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

        // Rules rarely change — only load once
        if !rulesLoaded_cached {
            await loadRules()
            await loadTCCEvents()
            rulesLoaded_cached = true
        }
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
            recentAlerts = Array(dashboardAlerts.filter { !$0.suppressed && !suppressedIDs.contains($0.id) && !isPatternSuppressed($0) }.prefix(5))
            totalAlerts = dashboardAlerts.filter { !$0.suppressed && !suppressedIDs.contains($0.id) && !isPatternSuppressed($0) }.count
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
        recentAlerts = Array(dashboardAlerts.filter { !$0.suppressed && !suppressedIDs.contains($0.id) && !isPatternSuppressed($0) }.prefix(5))
        totalAlerts = dashboardAlerts.filter { !$0.suppressed && !suppressedIDs.contains($0.id) && !isPatternSuppressed($0) }.count
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
        if let idx = dashboardAlerts.firstIndex(where: { $0.id == alertId }) {
            dashboardAlerts[idx].suppressed = true
        }
        recentAlerts = Array(dashboardAlerts.filter { !$0.suppressed && !suppressedIDs.contains($0.id) && !isPatternSuppressed($0) }.prefix(5))
        totalAlerts = dashboardAlerts.filter { !$0.suppressed && !suppressedIDs.contains($0.id) && !isPatternSuppressed($0) }.count
        // Best-effort DB write (fails silently on read-only DB)
        do {
            let store = try alertStore()
            try await store.suppress(alertId: alertId)
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
        recentAlerts = Array(dashboardAlerts.filter { !$0.suppressed && !suppressedIDs.contains($0.id) && !isPatternSuppressed($0) }.prefix(5))
        totalAlerts = dashboardAlerts.filter { !$0.suppressed && !suppressedIDs.contains($0.id) && !isPatternSuppressed($0) }.count
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

    private func saveSuppressPatterns() {
        let data = suppressionPatterns.map { ["ruleTitle": $0.ruleTitle, "processName": $0.processName] }
        if let json = try? JSONSerialization.data(withJSONObject: data) {
            try? json.write(to: URL(fileURLWithPath: dataDir + "/ui_suppressions.json"))
        }
    }

    func loadSuppressPatterns() {
        let path = dataDir + "/ui_suppressions.json"
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let arr = try? JSONSerialization.jsonObject(with: data) as? [[String: String]] else { return }
        suppressionPatterns = arr.compactMap { dict in
            guard let r = dict["ruleTitle"], let p = dict["processName"] else { return nil }
            return (r, p)
        }
    }

    /// Persist the current `suppressedIDs` set to disk so suppressions survive app restarts.
    private func saveSuppressedIDs() {
        let arr = Array(suppressedIDs)
        if let json = try? JSONSerialization.data(withJSONObject: arr) {
            try? json.write(to: URL(fileURLWithPath: dataDir + "/ui_suppressed_ids.json"))
        }
    }

    /// Load previously persisted `suppressedIDs` on startup.
    func loadSuppressedIDs() {
        let path = dataDir + "/ui_suppressed_ids.json"
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let arr = try? JSONSerialization.jsonObject(with: data) as? [String] else { return }
        suppressedIDs = Set(arr)
    }

    func reloadDaemonRules() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
        task.arguments = ["-HUP", "maccrabd"]
        try? task.run()
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
                recentAlerts = Array(dashboardAlerts.filter { !$0.suppressed && !suppressedIDs.contains($0.id) && !isPatternSuppressed($0) }.prefix(5))
                totalAlerts = dashboardAlerts.filter { !$0.suppressed && !suppressedIDs.contains($0.id) && !isPatternSuppressed($0) }.count
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
