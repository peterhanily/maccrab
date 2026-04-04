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
    @Published var recentAlerts: [AlertViewModel] = []
    @Published var dashboardAlerts: [AlertViewModel] = []
    @Published var events: [EventViewModel] = []
    @Published var rules: [RuleViewModel] = []
    @Published var tccEvents: [TCCEventViewModel] = []

    enum Tab: String, CaseIterable { case alerts, events, rules, tcc, docs, settings }
    @Published var selectedTab: Tab = .alerts

    // MARK: Private

    private var pollTimer: AnyCancellable?
    private var previousEventCount: Int = 0
    private var rulesLoaded_cached = false
    private var lastAlertTimestamp: Date = .distantPast
    private var lastEventTimestamp: Date = .distantPast

    /// Resolve the MacCrab data directory.
    private let dataDir: String = {
        let userDir = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first!.appendingPathComponent("MacCrab").path
        if FileManager.default.fileExists(atPath: userDir + "/events.db") {
            return userDir
        }
        let systemDir = "/Library/Application Support/MacCrab"
        if FileManager.default.isReadableFile(atPath: systemDir + "/events.db") {
            return systemDir
        }
        return userDir
    }()

    // MARK: Initialization

    init() {
        pollTimer = Timer.publish(every: 5.0, on: .main, in: .common)
            .autoconnect()
            .sink { [weak self] _ in
                guard let self else { return }
                Task { @MainActor in await self.refresh() }
            }
        Task { await refresh() }
    }

    // MARK: Public interface

    func refresh() async {
        // Check daemon connectivity (lightweight check)
        let daemonRunning = FileManager.default.fileExists(atPath: "/proc/\(getpid())") || {
            let t = Process()
            t.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
            t.arguments = ["-x", "maccrabd"]
            t.standardOutput = FileHandle.nullDevice
            t.standardError = FileHandle.nullDevice
            try? t.run()
            t.waitUntilExit()
            return t.terminationStatus == 0
        }()
        let dbExists = FileManager.default.fileExists(atPath: dataDir + "/events.db")
        isConnected = daemonRunning || dbExists

        guard isConnected else {
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
            let store = try AlertStore(directory: dataDir)
            let alerts = try await store.alerts(since: Date.distantPast, limit: limit)
            dashboardAlerts = alerts.map { alertToViewModel($0) }
            recentAlerts = Array(dashboardAlerts.prefix(5))
            totalAlerts = dashboardAlerts.filter { !$0.suppressed }.count
        } catch {
            // DB may not exist yet
        }
    }

    func loadEvents(limit: Int = 500, filter: String? = nil) async {
        do {
            let store = try EventStore(directory: dataDir)
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
            let store = try EventStore(directory: dataDir)
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

    func suppressAlert(_ alertId: String) async {
        do {
            let store = try AlertStore(directory: dataDir)
            try await store.suppress(alertId: alertId)
            await loadAlerts()
        } catch {
            // Mark locally
            if let idx = dashboardAlerts.firstIndex(where: { $0.id == alertId }) {
                dashboardAlerts[idx].suppressed = true
            }
        }
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
            let store = try AlertStore(directory: dataDir)
            let newAlerts = try await store.alerts(since: lastAlertTimestamp, limit: 100)
            let newViewModels = newAlerts
                .filter { $0.timestamp > lastAlertTimestamp }
                .map { alertToViewModel($0) }
            if !newViewModels.isEmpty {
                dashboardAlerts.insert(contentsOf: newViewModels, at: 0)
                // Cap at 500
                if dashboardAlerts.count > 500 { dashboardAlerts = Array(dashboardAlerts.prefix(500)) }
                recentAlerts = Array(dashboardAlerts.prefix(5))
                totalAlerts = dashboardAlerts.filter { !$0.suppressed }.count
                lastAlertTimestamp = newViewModels.first?.timestamp ?? lastAlertTimestamp
            }
        } catch {}
    }

    private func loadEventsIncremental() async {
        do {
            let store = try EventStore(directory: dataDir)
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
            ruleTitle: a.ruleTitle,
            severity: mapSeverity(a.severity),
            processName: a.processName ?? "unknown",
            processPath: a.processPath ?? "",
            description: a.description ?? "",
            mitreTechniques: a.mitreTechniques ?? "",
            suppressed: a.suppressed
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
            let store = try EventStore(directory: dataDir)
            let currentCount = try await store.count()
            eventsPerSecond = max(0, (currentCount - previousEventCount) / 5)
            previousEventCount = currentCount
        } catch {}
    }
}
