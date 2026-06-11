// V2LiveDataProvider.swift
// MacCrabApp — Dashboard v2
//
// Phase 4: best-effort reads from MacCrabCore stores. Each surface
// degrades independently: if the alerts.db isn't there, alerts()
// returns empty + records the error, while events() can still work.
//
// The store-init pattern matches AppState.swift's path-probe: pick
// the directory whose .db is most recently modified, so we don't
// pin to a stale system-dir copy from a prior sysext install.

import Foundation
import MacCrabCore

@MainActor
public final class V2LiveDataProvider: V2DataProvider {

    public let mode: V2DataSourceMode = .live
    public private(set) var lastErrorDescription: String? = nil
    public let dataDir: String?

    private let alertStore: AlertStore?
    private let eventStore: EventStore?
    private let campaignStore: CampaignStore?
    private let causalStore: SQLiteCausalGraphStore?

    /// Cached V2-shape rules + the directory mtime used to compute
    /// the cache. Pre-fix `rules()` re-loaded all compiled JSON files +
    /// re-decoded them on every 5s refresh tick — even when nothing
    /// in `compiled_rules/` had changed. The compiled_rules dir is
    /// only mutated when the daemon recompiles or an operator drops
    /// a custom YAML, both rare. Now: stat the directory's
    /// mtime, return the cache if it matches, only re-load on
    /// change. Cache is per-instance (one V2LiveDataProvider lives
    /// for the dashboard's lifetime), so the cache survives
    /// workspace switches but resets on reconnect / app launch.
    private var rulesCache: [V2MockRule] = []
    private var rulesCacheDirMtime: Date? = nil
    private var rulesCacheTelemetryMtime: Date? = nil
    /// v1.12.0 RC20: track user_rules dir mtime so the dashboard
    /// rule-list refreshes after the user saves a YAML edit. Pre-fix,
    /// rulesCache wasn't invalidated when user_rules changed, so the
    /// inspector kept showing the bundled severity even after the
    /// user-override JSON landed on disk.
    private var rulesCacheUserRulesMtime: Date? = nil

    /// Cached sequence + graph (composite) rule id→title map, gated on
    /// the compiled_rules dir mtime — the same invalidation signal as
    /// `rulesCache`. Composite rules only change on recompile / app
    /// upgrade, so a per-launch cache is plenty.
    private var compositeLabelsCache: [String: String] = [:]
    private var compositeLabelsCacheMtime: Date? = nil

    /// Returns nil if no candidate directory exists at all (fresh dev
    /// machine where the daemon has never run). Caller should fall
    /// back to V2MockDataProvider.
    public init?() async {
        // Pick a single canonical data directory rather than a mix
        // of system + user-home per-file: if a user previously ran
        // `swift run maccrabd` (writes to user-home) then later
        // installed the sysext (writes to system), the dev leftovers
        // outranked the production data on per-file mtime. Now we
        // prefer the system dir whenever it has *any* canonical file,
        // and fall back to user-home only when system is empty.
        let dir = V2LiveDataProvider.pickDataDirectory()
        let alertsDir   = dir.flatMap { Self.fileExists(at: $0 + "/alerts.db")     ? $0 : nil }
        let eventsDir   = dir.flatMap { Self.fileExists(at: $0 + "/events.db")     ? $0 : nil }
        let campaignDir = dir.flatMap { Self.fileExists(at: $0 + "/campaigns.db")  ? $0 : nil }
        let traceDir    = dir.flatMap { Self.fileExists(at: $0 + "/tracegraph.db") ? $0 : nil }

        guard alertsDir != nil || eventsDir != nil
                || campaignDir != nil || traceDir != nil else {
            return nil
        }

        self.dataDir = dir

        // v1.11.1 (audit launch-perf): the class is @MainActor, so
        // pre-fix the four SQLite opens (each running schema migration
        // checks + WAL setup + pragma application) ran serially on the
        // main thread, beachballing the dashboard for 50-300ms on cold
        // open + further on schema-v4 ALTER. Now: run all four opens
        // in parallel on background threads via Task.detached + async-
        // let, then assign the results back on @MainActor (the actor
        // types are Sendable so this is safe). Net: cold open drops
        // from serial sum to ~max(individual open) + actor hop.
        // Wave 9A (v1.12.6 RC2): all four dashboard-side stores open
        // read-only. The dashboard never writes — alert suppress /
        // unsuppress / delete route through the inbox file-IPC channel
        // per v1.10.1. Pre-9A the RW open held shared/upgrade locks
        // that blocked the sysext's VACUUM (field-confirmed via lsof
        // showing two RW fds on the dashboard process) — the v1.6.22
        // perf-audit-pattern recurring in a new actor.
        async let alertStoreT: AlertStore? = Task.detached { () -> AlertStore? in
            guard let dir = alertsDir else { return nil }
            return try? AlertStore(directory: dir, forceReadOnly: true)
        }.value
        async let eventStoreT: EventStore? = Task.detached { () -> EventStore? in
            guard let dir = eventsDir else { return nil }
            return try? EventStore(directory: dir, forceReadOnly: true)
        }.value
        async let campaignStoreT: CampaignStore? = Task.detached { () -> CampaignStore? in
            guard let dir = campaignDir else { return nil }
            return try? CampaignStore(directory: dir, forceReadOnly: true)
        }.value
        // SQLiteCausalGraphStore's init is already async (its own actor
        // hop), so it doesn't need a Task.detached wrapper — but we
        // still want it to run in parallel with the other three.
        async let causalStoreT: SQLiteCausalGraphStore? = {
            guard let dir = traceDir else { return nil }
            return try? await SQLiteCausalGraphStore(databasePath: dir + "/tracegraph.db", forceReadOnly: true)
        }()

        self.alertStore = await alertStoreT
        self.eventStore = await eventStoreT
        self.campaignStore = await campaignStoreT
        self.causalStore = await causalStoreT

        // Surface a generic "one or more stores failed to open" error
        // when any store is nil despite its dir existing. The previous
        // per-store error string was rarely consumed by the dashboard
        // (just logged) — the simpler signal is enough.
        let allOpened = (alertsDir == nil   || self.alertStore != nil)
                     && (eventsDir == nil   || self.eventStore != nil)
                     && (campaignDir == nil || self.campaignStore != nil)
                     && (traceDir == nil    || self.causalStore != nil)
        self.lastErrorDescription = allOpened ? nil
            : "one or more on-disk stores failed to open — see daemon log"
    }

    // MARK: - V2DataProvider

    // MARK: - Heavy queries (off-main decode)
    //
    // These four are the hottest surfaces — alerts/events/campaigns/
    // traces — each potentially returning hundreds of rows whose
    // mappers (toV2Alert, toV2Event, ...) decode optional JSON
    // payloads (LLM investigation, MITRE lists). Pre-fix the .map ran
    // on @MainActor and caused 100-400 ms beachballs on every refresh
    // tick. Now: the store call hops to its own actor (free), and the
    // decode loop runs in a Task.detached at .userInitiated priority,
    // so the main thread stays free for SwiftUI re-render.

    public func alerts(since: Date, limit: Int) async -> [V2MockAlert] {
        guard let alertStore else { return [] }
        do {
            // v1.18 (audit): honour the caller's time range. Pre-this the fetch
            // was hardcoded to -7d, so the Alerts 30d / All-time chips filtered a
            // 7-day subset and 77% of history was unreachable no matter the chip.
            let raw = try await alertStore.alerts(
                since: since,
                severity: nil, suppressed: nil, limit: limit
            )
            return await Task.detached(priority: .userInitiated) {
                raw.map(V2LiveDataProvider.toV2Alert)
            }.value
        } catch {
            lastErrorDescription = "alerts read: \(error)"
            return []
        }
    }

    public func events(limit: Int) async -> [V2MockEvent] {
        guard let eventStore else { return [] }
        do {
            let raw = try await eventStore.events(
                since: Date().addingTimeInterval(-60 * 60),
                category: nil, severity: nil, limit: limit
            )
            return await Task.detached(priority: .userInitiated) {
                raw.map(V2LiveDataProvider.toV2Event)
            }.value
        } catch {
            lastErrorDescription = "events read: \(error)"
            return []
        }
    }

    public func campaigns(since: Date, limit: Int) async -> [V2MockCampaign] {
        guard let campaignStore else { return [] }
        do {
            let raw = try await campaignStore.list(
                since: since,
                includeSuppressed: false,
                limit: limit
            )
            return await Task.detached(priority: .userInitiated) {
                raw.map(V2LiveDataProvider.toV2Campaign)
            }.value
        } catch {
            lastErrorDescription = "campaigns read: \(error)"
            return []
        }
    }

    public func traces(limit: Int) async -> [V2MockTrace] {
        guard let causalStore else { return [] }
        do {
            let raw = try await causalStore.listTraces(limit: limit)
            return await Task.detached(priority: .userInitiated) {
                raw.map(V2LiveDataProvider.toV2Trace)
            }.value
        } catch {
            lastErrorDescription = "traces read: \(error)"
            return []
        }
    }

    /// Wave-3 recorder: durable AI-agent sessions from events.db.
    public func agentSessions(limit: Int) async -> [V2AgentSession] {
        guard let eventStore else { return [] }
        do {
            let raw = try await eventStore.agentSessions(limit: limit)
            return raw.map { s in
                V2AgentSession(
                    id: s.sessionId,
                    tool: s.tool ?? "unknown",
                    projectDir: s.projectDir,
                    eventCount: s.eventCount,
                    firstSeen: s.firstSeen,
                    lastSeen: s.lastSeen
                )
            }
        } catch {
            lastErrorDescription = "agent sessions read: \(error)"
            return []
        }
    }

    // The remaining surfaces don't have a 1:1 store yet — return mock
    // until phase 4.5 wires the appropriate scanners / monitors / config
    // readers. Marked clearly so consumers can label them as such.

    public func rules() async -> [V2MockRule] {
        guard let dir = dataDir else { return [] }
        let rulesPath = dir + "/compiled_rules"
        let telemetryPath = dir + "/rule_telemetry.json"
        let fm = FileManager.default

        // mtime gate — return the cache unchanged if neither the
        // compiled_rules directory, the rule_telemetry.json file, NOR
        // the user_rules dir has been touched since the last call.
        // v1.12.0 RC20: user_rules mtime added so Edit-YAML saves
        // invalidate the cache and the dashboard re-renders with the
        // new severity.
        let userRulesPath = dir + "/user_rules"
        let dirMtime  = (try? fm.attributesOfItem(atPath: rulesPath))?[.modificationDate] as? Date
        let teleMtime = (try? fm.attributesOfItem(atPath: telemetryPath))?[.modificationDate] as? Date
        let userMtime = (try? fm.attributesOfItem(atPath: userRulesPath))?[.modificationDate] as? Date
        if !rulesCache.isEmpty,
           dirMtime == rulesCacheDirMtime,
           teleMtime == rulesCacheTelemetryMtime,
           userMtime == rulesCacheUserRulesMtime {
            return rulesCache
        }

        let rulesURL = URL(fileURLWithPath: rulesPath)
        let engine = RuleEngine()
        do { _ = try await engine.loadRules(from: rulesURL) }
        catch {
            lastErrorDescription = "rules read: \(error)"
            return []
        }
        // v1.12.0 RC20: overlay user_rules on top of bundled rules so
        // the dashboard's Detection → Rules list reflects user edits
        // (severity changes, disabled flags) the same way the daemon
        // does. Pre-fix the dashboard read ONLY the bundled compiled_
        // rules tree, so when a user lowered a rule's severity via
        // Edit YAML the displayed severity stayed at the bundled
        // default — even though the daemon was firing the user's
        // version. RuleEngine.loadRules does last-write-wins on
        // rule.id, so the user_rules load that runs second wins.
        if fm.fileExists(atPath: userRulesPath) {
            _ = try? await engine.loadRules(from: URL(fileURLWithPath: userRulesPath))
        }
        let rules = await engine.listRules()

        let mapped = await Task.detached(priority: .userInitiated) {
            var telemetry: [String: RuleEngine.RuleStats] = [:]
            if let snapshot = RuleEngine.readTelemetrySnapshot(at: telemetryPath) {
                for s in snapshot.stats { telemetry[s.ruleId] = s }
            }
            return rules.map { rule in
                V2LiveDataProvider.toV2Rule(rule, stats: telemetry[rule.id])
            }
        }.value

        // v1.18: surface the hardcoded maccrab.* built-in detections in the
        // Rules view (read-only content) with their operator overrides applied.
        // Settings are written by the daemon (root) via the inbox IPC; the
        // dashboard reads the same file for display.
        let builtinSettings = dataDir.map { BuiltinRuleSettings.load(fromDir: $0) } ?? BuiltinRuleSettings()
        let builtins: [V2MockRule] = BuiltinRuleCatalog.all.map { def in
            let s = builtinSettings.setting(forRuleId: def.id)
            return V2MockRule(
                id: def.id,
                title: def.title,
                category: def.category,
                severity: V2LiveDataProvider.toV2Severity(s?.severityOverride ?? def.defaultSeverity),
                mitre: def.techniques.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty },
                isEnabled: s?.enabled ?? true,
                lastFired: nil,
                firesLastWeek: 0,
                isCustom: false,
                description: def.description,
                severityOverrideRaw: s?.severityOverride?.rawValue
            )
        }
        // v1.18: surface multi-step sequence rules and multi-entity graph
        // rules as their own rows. They are compiled to single-object JSON
        // under compiled_rules/{sequences,graph}/ and loaded by the
        // SequenceEngine / TraceGraph engine (not RuleEngine), so they were
        // previously only used for alert title lookup (compositeRuleLabels)
        // and never appeared in the Rules list.
        let composite = await Task.detached(priority: .userInitiated) {
            V2LiveDataProvider.loadCompositeRules(
                sequencesDir: rulesPath + "/sequences",
                graphDir: rulesPath + "/graph")
        }.value
        let merged = mapped + composite + builtins
        rulesCache = merged
        rulesCacheDirMtime = dirMtime
        rulesCacheTelemetryMtime = teleMtime
        rulesCacheUserRulesMtime = userMtime
        return merged
    }

    public func compositeRuleLabels() async -> [String: String] {
        guard let dir = dataDir else { return [:] }
        let rulesPath = dir + "/compiled_rules"
        let dirMtime = (try? FileManager.default
            .attributesOfItem(atPath: rulesPath))?[.modificationDate] as? Date
        if !compositeLabelsCache.isEmpty, dirMtime == compositeLabelsCacheMtime {
            return compositeLabelsCache
        }
        // Each compiled sequence/graph file is a single object with a
        // top-level `id` + `title` (41 sequence files, 6 graph files).
        // Read off-main; these are tiny but it keeps file I/O off the
        // MainActor like the rules()/haystack paths.
        let sequencesDir = rulesPath + "/sequences"
        let graphDir = rulesPath + "/graph"
        let labels = await Task.detached(priority: .userInitiated) {
            V2LiveDataProvider.loadCompositeRuleLabels(
                sequencesDir: sequencesDir, graphDir: graphDir)
        }.value
        compositeLabelsCache = labels
        compositeLabelsCacheMtime = dirMtime
        return labels
    }

    /// Pure file→map reader for `compositeRuleLabels()`, extracted so it
    /// is unit-testable against a temp dir (the codebase convention for
    /// the V2 provider — see `toV2Rule`/`toV2Alert`). Each compiled
    /// sequence/graph file is a single object with a top-level `id` +
    /// `title`. Returns `[lowercasedId: title]`. Missing dirs / unreadable
    /// or malformed files are skipped silently.
    nonisolated static func loadCompositeRuleLabels(
        sequencesDir: String, graphDir: String
    ) -> [String: String] {
        struct Stub: Decodable { let id: String; let title: String }
        let fm = FileManager.default
        let dec = JSONDecoder()
        var out: [String: String] = [:]
        for sub in [sequencesDir, graphDir] {
            guard let urls = try? fm.contentsOfDirectory(
                at: URL(fileURLWithPath: sub),
                includingPropertiesForKeys: nil,
                options: [.skipsHiddenFiles]
            ) else { continue }
            for url in urls where url.pathExtension == "json" {
                guard let data = try? Data(contentsOf: url),
                      let stub = try? dec.decode(Stub.self, from: data) else { continue }
                out[stub.id.lowercased()] = stub.title
            }
        }
        return out
    }

    /// v1.18: read the compiled sequence + graph rules into full Rules-list
    /// rows (id / title / severity / MITRE / enabled / description), so the
    /// dashboard's Rules view lists the multi-step ("time sequence") and
    /// multi-entity detections alongside single-event YAML rules and the
    /// built-in detections. Read-only display; the engine loads the same
    /// files. Missing dirs / malformed files are skipped silently.
    nonisolated static func loadCompositeRules(
        sequencesDir: String, graphDir: String
    ) -> [V2MockRule] {
        struct Stub: Decodable {
            let id: String
            let title: String
            let level: String?
            let tags: [String]?
            let description: String?
            let enabled: Bool?
        }
        let fm = FileManager.default
        let dec = JSONDecoder()
        var out: [V2MockRule] = []
        for (sub, category) in [(sequencesDir, "Sequence"), (graphDir, "Graph")] {
            guard let urls = try? fm.contentsOfDirectory(
                at: URL(fileURLWithPath: sub),
                includingPropertiesForKeys: nil,
                options: [.skipsHiddenFiles]
            ) else { continue }
            for url in urls where url.pathExtension == "json" {
                guard let data = try? Data(contentsOf: url),
                      let stub = try? dec.decode(Stub.self, from: data) else { continue }
                let mitre = (stub.tags ?? [])
                    .filter { $0.hasPrefix("attack.t") }
                    .map { String($0.dropFirst("attack.".count)).uppercased() }
                out.append(V2MockRule(
                    id: stub.id,
                    title: stub.title,
                    category: category,
                    severity: severityFromString(stub.level ?? "medium"),
                    mitre: mitre,
                    isEnabled: stub.enabled ?? true,
                    lastFired: nil,
                    firesLastWeek: 0,
                    isCustom: false,
                    description: stub.description ?? ""
                ))
            }
        }
        return out
    }

    public func heartbeat() async -> V2HeartbeatSnapshot? {
        // `readFreshest` does two synchronous `attributesOfItem` +
        // `Data(contentsOf:)` + `JSONSerialization.jsonObject` calls.
        // ~3-15 ms per call on cold cache. Detach so a System / Overview
        // refresh tick doesn't block main.
        await Task.detached(priority: .userInitiated) {
            V2HeartbeatSnapshot.readFreshest()
        }.value
    }

    public func alertHistogram(rangeKey: String) async -> [V2OverviewBucket] {
        guard let alertStore else { return [] }
        let now = Date()
        let (totalSpan, bucketSpan): (TimeInterval, TimeInterval) = {
            switch rangeKey {
            case "1h":  return (3_600,    300)
            case "6h":  return (21_600,   1_800)
            case "24h": return (86_400,   7_200)
            case "7d":  return (604_800,  43_200)
            default:    return (21_600,   1_800)
            }
        }()
        let alerts = (try? await alertStore.alerts(
            since: now.addingTimeInterval(-totalSpan),
            severity: nil, suppressed: false, limit: 10_000
        )) ?? []
        let count = Int(totalSpan / bucketSpan)
        return (0..<count).map { i in
            let end = now.addingTimeInterval(-bucketSpan * Double(count - i - 1))
            let start = end.addingTimeInterval(-bucketSpan)
            let inBucket = alerts.filter { $0.timestamp >= start && $0.timestamp < end }
            return V2OverviewBucket(
                start: start, end: end,
                critical: inBucket.filter { $0.severity == .critical }.count,
                high:     inBucket.filter { $0.severity == .high     }.count,
                medium:   inBucket.filter { $0.severity == .medium   }.count,
                low:      inBucket.filter { $0.severity == .low      }.count
            )
        }
    }

    public func kpis() async -> V2OverviewKPIs {
        let now = Date()
        let day: TimeInterval = 86_400
        // Open alerts in last 24h (suppressed filtered out).
        var openAlerts = 0
        var prevAlerts = 0
        if let alertStore {
            let recent = (try? await alertStore.alerts(
                since: now.addingTimeInterval(-day),
                severity: nil, suppressed: false, limit: 5000
            )) ?? []
            openAlerts = recent.count
            let previous = (try? await alertStore.alerts(
                since: now.addingTimeInterval(-2 * day),
                severity: nil, suppressed: false, limit: 5000
            )) ?? []
            prevAlerts = previous.count - openAlerts
        }
        // Active campaigns + severity breakdown.
        var campCount = 0
        var critCount = 0, highCount = 0, medCount = 0
        if let campaignStore {
            let recent = (try? await campaignStore.list(
                since: now.addingTimeInterval(-7 * day),
                includeSuppressed: false, limit: 200
            )) ?? []
            campCount = recent.count
            for c in recent {
                switch c.severity {
                case .critical: critCount += 1
                case .high:     highCount += 1
                case .medium:   medCount += 1
                default: break
                }
            }
        }
        // Events/sec from last 1m bucket count.
        var eventsPerSec: Double = 0
        var sparkBuckets: [Double] = []
        if let eventStore {
            let counts = (try? await eventStore.eventCountsByCategory(since: now.addingTimeInterval(-60))) ?? [:]
            let totalLastMin = counts.values.reduce(0, +)
            eventsPerSec = Double(totalLastMin) / 60.0
            // 8 × 1-minute buckets for the sparkline.
            let bins = (try? await eventStore.histogramBins(
                spanSeconds: 8 * 60, stepSeconds: 60, endingAt: now, category: nil
            )) ?? []
            sparkBuckets = bins.map { Double($0.1) }
        }
        return V2OverviewKPIs(
            openAlerts24h: openAlerts,
            openAlertsLast24hDelta: openAlerts - prevAlerts,
            activeCampaigns: campCount,
            activeCampaignsCritical: critCount,
            activeCampaignsHigh: highCount,
            activeCampaignsMedium: medCount,
            eventsPerSecond: eventsPerSec,
            eventsLast8Buckets: sparkBuckets
        )
    }

    public func feeds() async -> [V2MockFeed] {
        // The IOC cache file can be multi-MB (abuse.ch full feed
        // dumps). Pre-fix this synchronous read + Codable-decode +
        // sort + per-feed-row build all ran on @MainActor — typically
        // 10-50 ms, sometimes 100+ ms on cold cache. Detach the
        // entire body off-main; only `dataDir` capture is needed.
        //
        // v1.12.6 Wave 9E: route through `loadFeedsFromCache(preferring:)`
        // so a `dataDir` that resolved to one directory still finds the
        // cache when the sysext wrote it to the other (system vs user-
        // home). Pre-fix this only read `dataDir + "/threat_intel"` and
        // silently returned [] on path mismatch until the user clicked
        // Refresh and the daemon re-wrote the cache. The helper falls
        // back to the canonical system + user-home paths so the threat-
        // intel surface populates on first appear.
        let resolvedDir = dataDir
        return await Task.detached(priority: .userInitiated) {
            return V2LiveDataProvider.loadFeedsFromCache(preferring: resolvedDir)
        }.value
    }

    /// Read the threat-intel feed cache from disk, trying the optional
    /// `preferred` directory first and then each canonical path returned
    /// by `candidateThreatIntelCacheDirs(preferring:)`. Returns the
    /// first cache that decodes cleanly, mapped into the V2 row shape.
    /// Empty when no cache exists anywhere.
    ///
    /// Marked `nonisolated` so callers can invoke it off the MainActor
    /// (e.g. inside `Task.detached` in `feeds()`), and `static` so the
    /// V2IntelligenceWorkspace can read the cache directly on first
    /// appear without waiting for `connectLiveData()` to flip the
    /// provider to live mode.
    nonisolated public static func loadFeedsFromCache(preferring preferred: String? = nil) -> [V2MockFeed] {
        let dirs = candidateThreatIntelCacheDirs(preferring: preferred)
        guard let iocs = dirs.lazy.compactMap({ ThreatIntelFeed.cachedIOCs(at: $0) }).first else {
            return []
        }
        let totalHashes = iocs.hashes.count
        let totalIPs = iocs.ips.count
        let totalDomains = iocs.domains.count
        let totalURLs = iocs.urls.count
        let now = Date()
        var rows: [V2MockFeed] = []
        for (name, lastUpdate) in iocs.perFeedLastUpdate.sorted(by: { $0.key < $1.key }) {
            let staleness = now.timeIntervalSince(lastUpdate)
            let kind = V2LiveDataProvider.feedKindHint(name: name)
            let entries: Int = {
                switch kind {
                case "Hashes":   return totalHashes
                case "IPs":      return totalIPs
                case "Domains":  return totalDomains
                case "URLs":     return totalURLs
                default:         return totalHashes + totalIPs + totalDomains + totalURLs
                }
            }()
            // Surface the per-feed last-error reason (HTTP non-2xx,
            // exception, or a 200 with 0 parsed records). When a feed
            // last failed it reads as .warning even if its prior
            // successful fetch is still inside the 6h window — a frozen
            // count must look like a problem, not "healthy".
            let lastError = iocs.perFeedLastError[name]?.reason
            let status: V2StatusLevel = (staleness > 6 * 60 * 60 || lastError != nil)
                ? .warning : .info
            rows.append(V2MockFeed(
                id: "feed-\(name)",
                name: name, kind: kind,
                entries: entries, lastFetch: lastUpdate,
                status: status, staleness: staleness,
                lastError: lastError
            ))
        }
        return rows
    }

    /// Last time ANY threat-intel feed actually pulled fresh records,
    /// read from the same cache the feed rows come from. nil when no
    /// cache exists or no successful pull has happened yet. Lets the
    /// Intelligence workspace show a top-level "last successful pull"
    /// line so the operator can SEE the feeds working.
    nonisolated public static func lastSuccessfulPull(preferring preferred: String? = nil) -> Date? {
        let dirs = candidateThreatIntelCacheDirs(preferring: preferred)
        return dirs.lazy
            .compactMap { ThreatIntelFeed.cachedIOCs(at: $0) }
            .first?.lastSuccessfulPull
    }

    /// Canonical threat-intel cache directory candidates, in priority
    /// order. The optional `preferred` directory wins first; the system
    /// path (sysext-written) is tried next; the user-home path
    /// (`swift run maccrabd` dev workflow) is tried last. Duplicates
    /// are de-duplicated so the same dir isn't probed twice.
    nonisolated public static func candidateThreatIntelCacheDirs(preferring preferred: String? = nil) -> [String] {
        var dirs: [String] = []
        if let preferred {
            dirs.append(preferred + "/threat_intel")
        }
        let systemDir = "/Library/Application Support/MacCrab/threat_intel"
        let userDir = (FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)
            .first?.appendingPathComponent("MacCrab/threat_intel").path)
            ?? NSHomeDirectory() + "/Library/Application Support/MacCrab/threat_intel"
        if !dirs.contains(systemDir) { dirs.append(systemDir) }
        if !dirs.contains(userDir) { dirs.append(userDir) }
        return dirs
    }

    nonisolated private static func feedKindHint(name: String) -> String {
        let n = name.lowercased()
        if n.contains("urlhaus") || n.contains("phish")  { return "URLs" }
        if n.contains("threatfox") || n.contains("ioc") { return "IPs" }
        if n.contains("spamhaus") || n.contains("drop") { return "IPs" }
        if n.contains("hash") || n.contains("malware")  { return "Hashes" }
        if n.contains("domain")                          { return "Domains" }
        return "Mixed"
    }


    public func mcpServers() async -> [V2MockMCP] {
        // 6 synchronous file reads + JSON parses on @MainActor before
        // the perf audit. Detach the entire scan off-main: only the
        // `configs` list needs capture and it's pure data.
        let configs: [(tool: String, path: String)] = [
            ("Claude Code", "~/.claude/claude_desktop_config.json"),
            ("Claude Code", "~/.claude.json"),
            ("Cursor",      "~/.cursor/mcp.json"),
            ("Continue",    "~/.continue/config.json"),
            ("VS Code",     "~/.vscode/mcp.json"),
            ("Windsurf",    "~/.windsurf/mcp.json"),
        ]
        return await Task.detached(priority: .userInitiated) {
            var byKey: [String: V2MockMCP] = [:]
            for cfg in configs {
                let path = (cfg.path as NSString).expandingTildeInPath
                guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
                      let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                      let servers = json["mcpServers"] as? [String: [String: Any]] else { continue }
                let mtime = (try? FileManager.default.attributesOfItem(atPath: path))?[.modificationDate] as? Date ?? Date()
                for (name, spec) in servers {
                    let key = "\(cfg.tool)::\(name)"
                    let cmd = spec["command"] as? String ?? ""
                    let args = spec["args"] as? [String] ?? []
                    let toolCount = args.count + 1   // proxy until we can introspect
                    let trust: V2StatusLevel = cmd.contains("/tmp/")
                        || cmd.contains("/var/tmp/") ? .warning : .info
                    if let existing = byKey[key] {
                        var knownTo = existing.knownTo
                        if !knownTo.contains(cfg.tool) { knownTo.append(cfg.tool) }
                        byKey[key] = V2MockMCP(
                            id: existing.id, name: existing.name, host: existing.host,
                            toolCount: existing.toolCount, knownTo: knownTo,
                            trust: existing.trust, lastUsed: max(existing.lastUsed, mtime)
                        )
                    } else {
                        byKey[key] = V2MockMCP(
                            id: key, name: name, host: "localhost",
                            toolCount: toolCount, knownTo: [cfg.tool],
                            trust: trust, lastUsed: mtime
                        )
                    }
                }
            }
            return Array(byKey.values).sorted { $0.name < $1.name }
        }.value
    }

    // v1.11.0: collectors + permissions wired from existing daemon
    // snapshots (heartbeat_rich.json + tcc_snapshot.json). Packages
    // remains empty pending the v1.11.x PackageScanner; integrations
    // remains empty pending DaemonConfig integration list exposure.

    public func collectors() async -> [V2MockCollector] {
        // Reuse the heartbeat the System workspace already reads.
        // Each collector entry: name, eventCount, healthy, lastTickUnix.
        // Map to V2MockCollector — throughput is best-effort
        // (eventCount / uptime), errors not yet tracked in heartbeat.
        guard let snap = V2HeartbeatSnapshot.readFreshest() else { return [] }
        let uptimeSeconds = max(snap.uptimeSeconds, 1)
        return snap.collectors.map { c -> V2MockCollector in
            V2MockCollector(
                id: c.name,
                name: c.name,
                status: c.healthy ? .healthy : .warning,
                throughput: Double(c.eventCount) / Double(uptimeSeconds),
                lag: c.lastTick.map { Date().timeIntervalSince($0) } ?? 0,
                errors: 0,
                lastEvent: c.lastTick ?? Date.distantPast
            )
        }
    }

    public func permissions() async -> [V2MockPermission] {
        // The daemon writes <supportDir>/tcc_snapshot.json on each
        // TCCMonitor change; readSnapshot decodes it.
        //
        // v1.11.0 RC2 ship-blocker fix (audit perf MEDIUM): detach
        // off-MainActor. V2LiveDataProvider is @MainActor so the
        // sync `Data(contentsOf:)` + JSONDecoder() inside
        // `readSnapshot` previously ran on main, producing 1-3ms
        // jitter per dashboard refresh tick (worse on cold cache /
        // FDA-snapshot scan storms). Mirrors the existing `heartbeat`
        // detach pattern.
        guard let dir = dataDir else { return [] }
        let path = dir + "/tcc_snapshot.json"
        let snap = await Task.detached(priority: .userInitiated) {
            TCCMonitor.readSnapshot(at: path)
        }.value
        guard let snap else { return [] }
        return snap.entries.map { e -> V2MockPermission in
            V2MockPermission(
                id: "\(e.service)|\(e.client)",
                service: prettyTCCService(e.service),
                granted: e.authValue == 2,                          // 2 = allowed
                required: Self.requiredTCCServices.contains(e.service), // FDA + ES are load-bearing
                description: "\(e.client) (\(authValueLabel(e.authValue)))"
            )
        }
    }

    private static let requiredTCCServices: Set<String> = [
        "kTCCServiceSystemPolicyAllFiles",  // Full Disk Access
        "kTCCServiceEndpointSecurityClient",
    ]

    private nonisolated func prettyTCCService(_ raw: String) -> String {
        // Strip the kTCCService prefix; insert spaces ahead of capitals
        // for a readable label ("Full Disk Access" instead of
        // "SystemPolicyAllFiles").
        let stripped = raw.hasPrefix("kTCCService")
            ? String(raw.dropFirst("kTCCService".count))
            : raw
        var out = ""
        for ch in stripped {
            if ch.isUppercase && !out.isEmpty { out.append(" ") }
            out.append(ch)
        }
        // A few hand-tuned overrides for the common services so they
        // match Apple's UI labels rather than the raw enum spelling.
        switch raw {
        case "kTCCServiceSystemPolicyAllFiles": return "Full Disk Access"
        case "kTCCServiceScreenCapture":        return "Screen Recording"
        case "kTCCServiceListenEvent":          return "Input Monitoring"
        case "kTCCServicePostEvent":            return "Accessibility"
        case "kTCCServiceMicrophone":           return "Microphone"
        case "kTCCServiceCamera":               return "Camera"
        case "kTCCServiceContactsFull":         return "Contacts"
        case "kTCCServiceCalendar":             return "Calendar"
        case "kTCCServicePhotos":               return "Photos"
        case "kTCCServiceLocation":             return "Location Services"
        default: return out
        }
    }

    private nonisolated func authValueLabel(_ v: Int) -> String {
        switch v {
        case 0: return "denied"
        case 2: return "allowed"
        default: return "unknown"
        }
    }

    public func packages() async -> [V2MockPackage] {
        // v1.11.1 (M2 backlog): wired to PackageScanner. brew + npm +
        // pip3 inventory; per-instance 5-min cache so the 5-s
        // dashboard refresh doesn't re-shell each tick. Latest-version
        // + vulnCount stay at placeholder defaults — registry API
        // wiring is a v1.11.x follow-up.
        //
        // v1.12.0 post-audit (H-Int1): the bulk scan() output only
        // includes the pure-local typosquat score. Attestation +
        // content-flag fields require registry HTTP and an installed-
        // tree walk — too expensive for every refresh tick. We
        // kick off background enrichment of the top-3 typosquat-flagged
        // packages on each tick; those are the highest-risk entries
        // and the Supply chain inspector renders the result once it
        // lands. The 5-min cache absorbs repeated enrichment calls.
        let infos = await Self.packageScanner.scan()
        await Self.kickOffBackgroundEnrichment(infos: infos)
        let enrichedInfos = await Self.enrichmentResults.snapshot()
        return infos.map { info in
            let merged = enrichedInfos[info.id] ?? info
            return V2MockPackage(
                id: merged.id,
                name: merged.name,
                installed: merged.installedVersion,
                latest: merged.latestVersion,
                manager: merged.manager,
                vulnCount: merged.vulnCount,
                staleness: merged.stalenessSeconds,
                typosquatScore: merged.typosquatScore,
                typosquatSimilarTo: merged.typosquatSimilarTo,
                attestationStatus: merged.attestationStatus,
                contentRedFlags: merged.contentRedFlags
            )
        }
    }

    /// Shared across V2LiveDataProvider instances so the 5-min cache
    /// doesn't reset on every dashboard reconnect.
    private static let packageScanner = PackageScanner()

    /// v1.12.0 post-audit (H-Int1): shared analyzers + per-package
    /// enrichment-result map for background dashboard hydration.
    private static let attestationEnricher = AttestationEnricher()
    private static let metadataAnalyzer = PackageMetadataAnalyzer()
    private static let contentAnalyzer = PackageContentAnalyzer()
    private static let enrichmentResults = EnrichmentResultCache()

    /// Spawn at most one background enrichment per tick. Picks the
    /// highest-typosquat-score packages first since those are the
    /// rows the analyst will click on. The actor's `snapshot()`
    /// returns whatever has landed so far.
    private static func kickOffBackgroundEnrichment(infos: [PackageInfo]) async {
        let candidates = infos
            .filter { ($0.typosquatScore ?? 0) >= 50 }
            .sorted { ($0.typosquatScore ?? 0) > ($1.typosquatScore ?? 0) }
            .prefix(3)
        let pending = await enrichmentResults.pending()
        for info in candidates where !pending.contains(info.id) {
            await enrichmentResults.markPending(info.id)
            Task.detached(priority: .utility) {
                let enriched = await packageScanner.enrich(
                    info,
                    metadataAnalyzer: metadataAnalyzer,
                    attestationEnricher: attestationEnricher,
                    contentAnalyzer: nil,
                    installedPath: nil
                )
                await enrichmentResults.record(enriched)
            }
        }
    }

    public func integrations() async -> [V2MockIntegration] {
        // v1.11.1 (M2 backlog): read the daemon's configured external
        // sinks from on-disk JSON. Three files contribute:
        //
        //   daemon_config.json.outputs[]  → file / splunk / elastic /
        //                                    datadog / wazuh / s3 / sftp
        //   notifications.json            → slack / teams / discord /
        //                                    pagerduty webhooks (v1.6.19)
        //   alert_notifications.json      → OS notification severity gate
        //                                    (v1.11.0 wire-the-orphans)
        //
        // Status stays at "configured" until per-sink health reporting
        // lands; for v1.11.1 the panel simply surfaces what's wired so
        // operators can confirm their config reached the daemon.
        //
        // v1.11.0 RC2 follow-up (perf HIGH from RC2 audit): detach the
        // sync file I/O off-MainActor. V2LiveDataProvider is @MainActor
        // and `.task(id: refreshTick)` in V2IntelligenceWorkspace fires
        // this every 5s while ANY Intelligence sub-tab is active —
        // 3 × Data(contentsOf:) + JSONSerialization on the main queue
        // produced 1-3ms jitter per tick (worse on cold cache). Same
        // detach pattern as the freshly-fixed `permissions()`.
        guard let dir = dataDir else { return [] }
        return await Task.detached(priority: .userInitiated) {
            return Self._loadIntegrations(dataDir: dir)
        }.value
    }

    /// Pure file-I/O helper invoked from the detached Task above.
    /// `nonisolated` so the Task body can call it without bouncing
    /// back onto the MainActor.
    nonisolated private static func _loadIntegrations(dataDir dir: String) -> [V2MockIntegration] {
        var out: [V2MockIntegration] = []

        // daemon_config.json outputs[]
        let dcPath = dir + "/daemon_config.json"
        if let data = try? Data(contentsOf: URL(fileURLWithPath: dcPath)),
           let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let outputs = json["outputs"] as? [[String: Any]] {
            for (idx, entry) in outputs.enumerated() {
                let type = (entry["type"] as? String) ?? "unknown"
                let detail: String = {
                    switch type {
                    case "file":         return (entry["path"] as? String) ?? "—"
                    case "splunk_hec":   return (entry["url"] as? String) ?? "—"
                    case "elastic_bulk": return (entry["url"] as? String) ?? "—"
                    case "datadog_logs": return (entry["url"] as? String) ?? "—"
                    case "wazuh_api":    return (entry["url"] as? String) ?? "—"
                    case "s3":           return [(entry["bucket"] as? String).map { "s3://\($0)" }, entry["region"] as? String].compactMap { $0 }.joined(separator: " · ")
                    case "sftp":         return [(entry["user"] as? String), (entry["host"] as? String)].compactMap { $0 }.joined(separator: "@")
                    case "otlp":         return (entry["url"] as? String) ?? "—"
                    default:             return "—"
                    }
                }()
                let kind: String = {
                    switch type {
                    case "file":      return "file"
                    case "s3", "sftp": return "object-store"
                    case "otlp":      return "telemetry"
                    default:          return "siem"
                    }
                }()
                let name: String = {
                    switch type {
                    case "splunk_hec":   return "Splunk HEC"
                    case "elastic_bulk": return "Elasticsearch Bulk"
                    case "datadog_logs": return "Datadog Logs"
                    case "wazuh_api":    return "Wazuh API"
                    case "s3":           return "S3 / object store"
                    case "sftp":         return "SFTP"
                    case "file":         return "File output"
                    case "otlp":         return "OTLP"
                    default:             return type
                    }
                }()
                out.append(V2MockIntegration(
                    id: "output:\(type):\(idx)",
                    name: name,
                    kind: kind,
                    status: .info,    // "configured" — per-sink health is v1.11.x
                    detail: detail
                ))
            }
        }

        // notifications.json webhooks
        let notifPath = dir + "/notifications.json"
        if let data = try? Data(contentsOf: URL(fileURLWithPath: notifPath)),
           let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            if let slack = json["slack"] as? [String: Any], let url = slack["webhookURL"] as? String, !url.isEmpty {
                out.append(V2MockIntegration(
                    id: "webhook:slack", name: "Slack", kind: "webhook",
                    status: .info, detail: redactedWebhookURL(url)
                ))
            }
            if let teams = json["teams"] as? [String: Any], let url = teams["webhookURL"] as? String, !url.isEmpty {
                out.append(V2MockIntegration(
                    id: "webhook:teams", name: "Microsoft Teams", kind: "webhook",
                    status: .info, detail: redactedWebhookURL(url)
                ))
            }
            if let discord = json["discord"] as? [String: Any], let url = discord["webhookURL"] as? String, !url.isEmpty {
                out.append(V2MockIntegration(
                    id: "webhook:discord", name: "Discord", kind: "webhook",
                    status: .info, detail: redactedWebhookURL(url)
                ))
            }
            if let pd = json["pagerduty"] as? [String: Any], let key = pd["routingKey"] as? String, !key.isEmpty {
                out.append(V2MockIntegration(
                    id: "webhook:pagerduty", name: "PagerDuty", kind: "webhook",
                    status: .info, detail: "routing key configured"
                ))
            }
        }

        // alert_notifications.json — OS notification gate (v1.11.0)
        let alertNotifPath = dir + "/alert_notifications.json"
        if let data = try? Data(contentsOf: URL(fileURLWithPath: alertNotifPath)),
           let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            let enabled = json["enabled"] as? Bool ?? true
            let sev = json["min_severity"] as? String ?? "high"
            out.append(V2MockIntegration(
                id: "notification:macos",
                name: "macOS notifications",
                kind: "notification",
                status: enabled ? .info : .warning,
                detail: enabled ? "min severity: \(sev)" : "disabled"
            ))
        }

        // v1.12.5 fix: surface DETECTED third-party security tools
        // (Objective-See, Little Snitch, CrowdStrike, etc.) alongside
        // configured OUTPUT SINKS. Pre-fix the panel only read the
        // three config files above, so a user running BlockBlock /
        // LuLu / KnockKnock / OverSight saw "No integrations
        // configured" even when MacCrab's SecurityToolIntegrations
        // actor had already detected them. The daemon writes
        // `integrations_snapshot.json` periodically (DaemonTimers tick
        // + at boot) with the enriched `isRunning`-checked tool list;
        // we just read what it left behind.
        let snapshotPath = dir + "/integrations_snapshot.json"
        if let snap = SecurityToolIntegrations.readSnapshot(at: snapshotPath) {
            for tool in snap.tools {
                let status: V2StatusLevel = tool.isRunning ? .healthy : .info
                let detail: String = {
                    var parts: [String] = []
                    if let v = tool.version, !v.isEmpty { parts.append("v\(v)") }
                    parts.append(tool.isRunning ? "running" : "installed")
                    if !tool.capabilities.isEmpty {
                        parts.append(tool.capabilities.prefix(2).joined(separator: " · "))
                    }
                    return parts.joined(separator: " — ")
                }()
                out.append(V2MockIntegration(
                    id: "tool:\(tool.name.replacingOccurrences(of: " ", with: "-").lowercased())",
                    name: tool.name,
                    kind: "detected-tool",
                    status: status,
                    detail: detail
                ))
            }
        }

        return out
    }

    /// Hide the path / token portion of a webhook URL so the integration
    /// panel doesn't leak secrets when the dashboard is screenshotted.
    /// v1.11.0 RC2 follow-up: now `static` so the off-MainActor
    /// `_loadIntegrations` helper can invoke it without bouncing back
    /// onto the actor.
    nonisolated private static func redactedWebhookURL(_ url: String) -> String {
        guard let comps = URLComponents(string: url), let host = comps.host else { return "configured" }
        return "https://\(host)/…"
    }

    public func extensions() async -> [V2MockExtension] {
        // Off-main: BrowserExtensionMonitor.snapshot does ~5
        // contentsOfDirectory walks + N JSON parses (manifest reads)
        // — synchronous file I/O. Don't run it on @MainActor.
        await Task.detached(priority: .userInitiated) {
            BrowserExtensionMonitor.snapshot().map { snap -> V2MockExtension in
                // Pretty browser label.
                let browserLabel: String = {
                    switch snap.browser.lowercased() {
                    case "chrome":   return "Chrome"
                    case "firefox":  return "Firefox"
                    case "brave":    return "Brave"
                    case "edge":     return "Edge"
                    case "arc":      return "Arc"
                    default:         return snap.browser.capitalized
                    }
                }()
                // Combine permissions + host_permissions; dedupe.
                var allPerms = snap.permissions
                for h in snap.hostPermissions where !allPerms.contains(h) {
                    allPerms.append(h)
                }
                if snap.isDevMode { allPerms.append("⚠ dev mode") }
                // installedAt: best-effort — manifest mtime is the
                // closest signal we have without scanning the
                // browser's own metadata DB. Falls back to
                // distantPast so the field is non-nil but obviously
                // not-yet-populated.
                let installedAt = (try? FileManager.default.attributesOfItem(
                    atPath: snap.extensionPath + "/manifest.json"
                ))?[.modificationDate] as? Date ?? Date.distantPast
                return V2MockExtension(
                    id: snap.id,
                    name: snap.extensionName,
                    browser: browserLabel,
                    version: snap.version ?? "—",
                    permissions: allPerms,
                    signed: !snap.isDevMode,
                    riskScore: snap.riskScore,
                    installedAt: installedAt
                )
            }
        }.value
    }

    // MARK: - Mutations

    public func suppressAlert(id: String) async -> Bool {
        guard let alertStore else {
            lastErrorDescription = "no alert store"
            return false
        }
        do {
            try await alertStore.suppress(alertId: id)
            return true
        } catch {
            if isReadOnlyError(error), queueInboxMutation(prefix: "suppress-alert", id: id) {
                lastErrorDescription = nil
                return true
            }
            lastErrorDescription = describeMutationError(error)
            return false
        }
    }

    public func unsuppressAlert(id: String) async -> Bool {
        guard let alertStore else {
            lastErrorDescription = "no alert store"
            return false
        }
        do {
            try await alertStore.unsuppress(alertId: id)
            return true
        } catch {
            if isReadOnlyError(error), queueInboxMutation(prefix: "unsuppress-alert", id: id) {
                lastErrorDescription = nil
                return true
            }
            lastErrorDescription = describeMutationError(error)
            return false
        }
    }

    public func deleteAlert(id: String) async -> Bool {
        guard let alertStore else {
            lastErrorDescription = "no alert store"
            return false
        }
        do {
            return try await alertStore.delete(alertId: id)
        } catch {
            if isReadOnlyError(error), queueInboxMutation(prefix: "delete-alert", id: id) {
                lastErrorDescription = nil
                // Return true to flip UI optimistically — the daemon
                // applies the delete within ~5 s. The row will simply
                // be gone on the next alerts() refresh.
                return true
            }
            lastErrorDescription = describeMutationError(error)
            return false
        }
    }

    public func suppressAlerts(ids: [String]) async -> Int {
        guard let alertStore else {
            lastErrorDescription = "no alert store"
            return 0
        }
        var count = 0
        for (idx, id) in ids.enumerated() {
            do {
                try await alertStore.suppress(alertId: id)
                count += 1
            } catch {
                if isReadOnlyError(error) {
                    // First read-only error → switch the rest of the
                    // batch (including the failing id) to IPC. If the
                    // first id is read-only every subsequent one will
                    // be too — no point trying each one.
                    var queued = 0
                    for rem in ids[idx...] {
                        if queueInboxMutation(prefix: "suppress-alert", id: rem) {
                            queued += 1
                        }
                    }
                    lastErrorDescription = queued == 0
                        ? describeMutationError(error)
                        : nil
                    return count + queued
                }
                lastErrorDescription = describeMutationError(error)
            }
        }
        return count
    }

    /// Suppress a campaign + every contributing alert.
    ///
    /// The campaign itself is stored as an alert with rule_id
    /// `maccrab.campaign.*`, so suppressing it requires hitting BOTH
    /// the alert-side row (so the campaign card greys out) AND every
    /// alert with `campaignId == id` (so the contributors stop firing).
    /// The CampaignStore row is also flipped so the dashboard's
    /// campaigns list reflects state across restarts.
    ///
    /// In dev (user-owned DB), the loop runs client-side. In release
    /// (root-owned DB), we drop a single `suppress-campaign-*` request
    /// and let the daemon do the fan-out — one round-trip over file
    /// IPC instead of N.
    public func suppressCampaign(id: String) async -> Int {
        guard let alertStore else {
            lastErrorDescription = "no alert store"
            return 0
        }
        var count = 0
        // 1. Suppress the campaign alert itself (best-effort — the
        //    campaign may not have a self-row if it was created from a
        //    sequence rule that never wrote an alert).
        do {
            try await alertStore.suppress(alertId: id)
            count += 1
        } catch {
            if isReadOnlyError(error) {
                if queueInboxMutation(prefix: "suppress-campaign", id: id) {
                    lastErrorDescription = nil
                    // Daemon does the fan-out + the campaigns.db flip.
                    // Return 1 so the caller knows the request landed.
                    return 1
                }
                lastErrorDescription = describeMutationError(error)
                return 0
            }
        }
        // 2. Fan out: every alert tagged with this campaign id.
        // v1.11.0 RC2 (audit functionality MEDIUM): use the new
        // single-SQL `AlertStore.suppress(campaignId:)` method
        // instead of pulling 10K rows + per-row UPDATE in a loop.
        // The MCP path adopted this in v1.11.0; the dashboard path
        // should match. Avoids the 30s wedge under storm conditions.
        do {
            let n = try await alertStore.suppress(campaignId: id)
            count += n
        } catch {
            if isReadOnlyError(error) {
                lastErrorDescription = describeMutationError(error)
            } else {
                lastErrorDescription = "campaign fan-out: \(error)"
            }
        }
        // 3. Flip the persistent campaign row so the dashboard's
        //    campaigns list reflects suppressed state. Best-effort.
        if let campaignStore {
            do {
                try await campaignStore.setSuppressed(id: id, true)
            } catch {
                // Don't fail the operation just because the
                // campaign-side flag didn't take.
            }
        }
        return count
    }

    /// Reverse of ``suppressCampaign(id:)``: lift the campaign's own suppression
    /// + the suppression on its contributing alerts, and flip the persistent
    /// campaign row back to active. Read-only DB → queue an unsuppress-campaign
    /// inbox mutation. Returns true if the restore (or its inbox request) landed.
    public func unsuppressCampaign(id: String) async -> Bool {
        guard let alertStore else {
            lastErrorDescription = "no alert store"
            return false
        }
        do {
            try await alertStore.unsuppress(alertId: id)
        } catch {
            if isReadOnlyError(error) {
                if queueInboxMutation(prefix: "unsuppress-campaign", id: id) {
                    lastErrorDescription = nil
                    return true
                }
                lastErrorDescription = describeMutationError(error)
                return false
            }
        }
        do {
            _ = try await alertStore.unsuppress(campaignId: id)
        } catch {
            lastErrorDescription = "campaign restore fan-out: \(error)"
        }
        if let campaignStore {
            try? await campaignStore.setSuppressed(id: id, false)
        }
        return true
    }

    /// Fetch currently-suppressed campaigns for the restore surface.
    public func suppressedCampaigns(limit: Int) async -> [V2MockCampaign] {
        guard let campaignStore else { return [] }
        do {
            let raw = try await campaignStore.list(
                since: Date.distantPast, includeSuppressed: true, limit: limit)
            return await Task.detached(priority: .userInitiated) {
                raw.map(V2LiveDataProvider.toV2Campaign).filter { $0.suppressed }
            }.value
        } catch {
            lastErrorDescription = "suppressed campaigns read: \(error)"
            return []
        }
    }

    /// Drop a JSON mutation request into <dataDir>/inbox/ for the
    /// root daemon to pick up. Files are named `<prefix>-<id>.json` so
    /// re-clicking a suppress button coalesces into one file (idempotent).
    /// The daemon polls every 5 s; UI flips optimistically and the
    /// next 5 s refresh tick observes the actual flipped row.
    ///
    /// Pre-v1.10.1, mutations against a root-owned alerts.db just
    /// failed with SQLITE_READONLY and the user was told to "use
    /// `maccrabctl alerts suppress`" — a subcommand that does not
    /// exist. This is the real fix.
    private func queueInboxMutation(prefix: String, id: String) -> Bool {
        guard let dir = dataDir else { return false }
        let inboxDir = dir + "/inbox"
        let fm = FileManager.default
        // The daemon creates the inbox dir at boot with mode 1777, so
        // typically it exists. If we got here on a fresh install whose
        // sysext hasn't booted yet, try to create it ourselves (will
        // succeed in dev, fail under <Library/Application Support>
        // without elevation — in which case the request can't ship).
        if !fm.fileExists(atPath: inboxDir) {
            try? fm.createDirectory(
                atPath: inboxDir, withIntermediateDirectories: true
            )
        }
        // Sanitize the id for use as a filename. Alert ids are UUIDs
        // in practice but defense-in-depth in case a future id format
        // contains path separators.
        let safeId = id.replacingOccurrences(of: "/", with: "_")
                       .replacingOccurrences(of: "..", with: "_")
        let path = inboxDir + "/\(prefix)-\(safeId).json"
        let payload: [String: Any] = [
            "id": id,
            "queuedAt": ISO8601DateFormatter().string(from: Date()),
            "source": "MacCrabApp"
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: payload) else {
            return false
        }
        do {
            try data.write(to: URL(fileURLWithPath: path), options: .atomic)
            return true
        } catch {
            // If the inbox dir doesn't exist + we couldn't create it,
            // we end up here. Surface in lastErrorDescription so the
            // UI can show something more useful than silent failure.
            return false
        }
    }

    /// Trigger a one-shot refresh of all threat-intel feeds by dropping
    /// a `refresh-intel` request into the root daemon's inbox channel
    /// (the same file-IPC path alert suppress/delete use). The pre-v1.17
    /// path shelled out to `maccrabctl intel refresh` which `pkill
    /// -USR1`'d the sysext — that fails EPERM (user → uid-0 sysext), so
    /// refreshNow() never fired yet the UI still showed success. Now we
    /// write the request the daemon already polls, and report success
    /// ONLY if the file was actually written.
    public func refreshThreatIntel() async -> Bool {
        guard let dir = dataDir else {
            lastErrorDescription = "intel refresh: no data directory (daemon not yet run)"
            return false
        }
        let inboxDir = dir + "/inbox"
        // File write is small + atomic; detach so the click never
        // beachballs even if the inbox dir needs creating.
        let ok = await Task.detached(priority: .userInitiated) {
            V2LiveDataProvider.writeInboxRefreshRequest(inboxDir: inboxDir)
        }.value
        if !ok {
            lastErrorDescription = "intel refresh: could not queue request in \(inboxDir) (is the engine running?)"
            return false
        }
        return true
    }

    /// Drop a parameterless `refresh-intel-<token>.json` into the
    /// daemon's inbox. Static + pure so it's unit-testable against a
    /// temp dir without a DB-backed provider. The daemon coalesces
    /// multiple files into a single refreshNow(), so the filename uses
    /// a random token (no need to de-dup by id like the alert verbs).
    nonisolated static func writeInboxRefreshRequest(inboxDir: String) -> Bool {
        let fm = FileManager.default
        if !fm.fileExists(atPath: inboxDir) {
            // Typically the sysext already created this at boot (mode
            // 1777). On a fresh install whose sysext hasn't booted, this
            // create succeeds in dev but fails under <Library/Application
            // Support> without elevation — in which case we honestly
            // report failure rather than a fake success.
            try? fm.createDirectory(atPath: inboxDir, withIntermediateDirectories: true)
        }
        let token = UUID().uuidString
        let path = inboxDir + "/refresh-intel-\(token).json"
        let payload: [String: Any] = [
            "queuedAt": ISO8601DateFormatter().string(from: Date()),
            "source": "MacCrabApp"
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: payload) else {
            return false
        }
        do {
            try data.write(to: URL(fileURLWithPath: path), options: .atomic)
            return true
        } catch {
            return false
        }
    }

    /// Read live suppression entries from `<dataDir>/suppressions.json`.
    /// SuppressionManager writes this on every change; we just decode
    /// off-main so a refresh tick doesn't block the UI on disk read +
    /// JSONDecoder.
    public func suppressions() async -> [V2SuppressionEntry] {
        guard let dir = dataDir else { return [] }
        let path = dir + "/suppressions.json"
        return await Task.detached(priority: .userInitiated) {
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { return [] }
            struct OnDisk: Codable {
                let entries: [Entry]?
                struct Entry: Codable {
                    let id: String?
                    let ruleId: String
                    let scope: String?
                    let addedBy: String?
                    let createdAt: Date?
                    let expiresAt: Date?
                }
            }
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            guard let parsed = try? decoder.decode(OnDisk.self, from: data) else { return [] }
            return (parsed.entries ?? []).map {
                V2SuppressionEntry(
                    id: $0.id ?? UUID().uuidString,
                    ruleId: $0.ruleId,
                    scope: $0.scope ?? "any",
                    addedBy: $0.addedBy ?? "—",
                    createdAt: $0.createdAt ?? Date.distantPast,
                    expiresAt: $0.expiresAt
                )
            }
        }.value
    }

    public func liftSuppression(ruleId: String, scope: String) async -> Bool {
        var args = ["unsuppress", ruleId]
        if !scope.isEmpty, scope != "any" {
            args.append(scope)
        }
        // Detach the subprocess spawn off-main; same rationale as
        // refreshThreatIntel above.
        let argsCopy = args
        let result = await Task.detached(priority: .userInitiated) {
            V2LiveDataProvider.runMaccrabctl(arguments: argsCopy)
        }.value
        if result.exitCode != 0 {
            lastErrorDescription = "lift suppression: \(result.stderr.split(separator: "\n").first.map(String.init) ?? "exit \(result.exitCode)")"
            return false
        }
        return true
    }

    /// Resolve a trace's member entities. Walks the causal graph
    /// store's loadTrace + per-entity lookups. Empty when the trace
    /// is unknown or the store isn't reachable.
    public func traceMembers(traceId: String) async -> [V2TraceMember] {
        guard let causalStore else { return [] }
        let outer: (trace: Trace, members: [TraceMembership])??
        outer = try? await causalStore.loadTrace(id: traceId)
        guard let unwrapped = outer, let result = unwrapped else {
            return []
        }
        var members: [V2TraceMember] = []
        for membership in result.members {
            guard let entityId = membership.entityId else { continue }
            if let entity = try? await causalStore.entity(id: entityId) {
                members.append(V2TraceMember(
                    id: entity.id,
                    entityType: entity.entityType,
                    displayName: entity.displayName,
                    firstSeen: entity.firstSeen,
                    isAnchor: membership.role == "anchor"
                ))
            }
        }
        // Anchor first, then by first-seen ascending — matches the
        // chronological-then-importance ordering operators expect.
        return members.sorted { lhs, rhs in
            if lhs.isAnchor && !rhs.isAnchor { return true }
            if !lhs.isAnchor && rhs.isAnchor { return false }
            return lhs.firstSeen < rhs.firstSeen
        }
    }

    /// Locate maccrabctl across common install paths and run it.
    nonisolated private static func runMaccrabctl(arguments: [String])
        -> (exitCode: Int32, stdout: String, stderr: String)
    {
        let candidates = [
            Bundle.main.path(forResource: "maccrabctl", ofType: nil, inDirectory: "bin"),
            Bundle.main.path(forResource: "maccrabctl", ofType: nil),
            "/usr/local/bin/maccrabctl",
            "/opt/homebrew/bin/maccrabctl",
            FileManager.default.currentDirectoryPath + "/.build/debug/maccrabctl",
        ].compactMap { $0 }
        guard let binPath = candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else {
            return (127, "", "maccrabctl binary not found")
        }
        let task = Process()
        task.executableURL = URL(fileURLWithPath: binPath)
        task.arguments = arguments
        let outPipe = Pipe(); let errPipe = Pipe()
        task.standardOutput = outPipe
        task.standardError = errPipe
        do {
            try task.run()
            task.waitUntilExit()
            let outData = (try? outPipe.fileHandleForReading.readToEnd()) ?? Data()
            let errData = (try? errPipe.fileHandleForReading.readToEnd()) ?? Data()
            return (
                task.terminationStatus,
                String(data: outData, encoding: .utf8) ?? "",
                String(data: errData, encoding: .utf8) ?? ""
            )
        } catch {
            return (-1, "", "spawn failed: \(error)")
        }
    }

    /// SQLite "attempt to write a readonly database" surfaces when the
    /// daemon owns alerts.db as root and the dashboard runs as a
    /// non-privileged user — the common case for a notarized release
    /// build. Detect explicitly so the UI can show a clear hint
    /// rather than a raw error string.
    private func isReadOnlyError(_ error: Error) -> Bool {
        let s = "\(error)".lowercased()
        return s.contains("readonly") || s.contains("read-only")
            || s.contains("permission denied") || s.contains("operation not permitted")
    }

    private func describeMutationError(_ error: Error) -> String {
        if isReadOnlyError(error) {
            // We only land here when the IPC fallback ALSO failed —
            // i.e. the inbox dir doesn't exist or isn't writable.
            // Likely cause: fresh install where the sysext hasn't
            // booted, or a corrupted Application Support tree.
            return "Could not apply mutation: alerts.db is read-only and the daemon's IPC inbox at `/Library/Application Support/MacCrab/inbox/` isn't writable. Restart the daemon (re-open MacCrab.app and reactivate the System Extension) to re-create the inbox directory."
        }
        return "mutation failed: \(error)"
    }

    // MARK: - Path probing

    /// Pick the canonical data directory. System-installed sysext
    /// always wins when it has any of the canonical files; the user-
    /// home directory is only considered when the system dir is empty
    /// (dev workflow with `swift run maccrabd` and no sysext).
    private static func pickDataDirectory() -> String? {
        let systemDir = "/Library/Application Support/MacCrab"
        let userDir = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)
            .first?.appendingPathComponent("MacCrab").path
            ?? NSHomeDirectory() + "/Library/Application Support/MacCrab"
        let canonical = ["/alerts.db", "/events.db", "/campaigns.db", "/tracegraph.db"]
        if canonical.contains(where: { fileExists(at: systemDir + $0) }) {
            return systemDir
        }
        if canonical.contains(where: { fileExists(at: userDir + $0) }) {
            return userDir
        }
        return nil
    }

    private static func fileExists(at path: String) -> Bool {
        FileManager.default.fileExists(atPath: path)
    }

    // MARK: - Mappers
    //
    // Marked `nonisolated` so the off-main decode in alerts() / events()
    // / campaigns() / traces() actually runs off-main. Without this,
    // the static funcs inherit the enclosing class's @MainActor and
    // Task.detached silently bounces back onto main — defeats the
    // beachball fix.

    nonisolated private static func toV2Severity(_ s: MacCrabCore.Severity) -> V2Severity {
        switch s {
        case .critical:      return .critical
        case .high:          return .high
        case .medium:        return .medium
        case .low:           return .low
        case .informational: return .info
        }
    }

    nonisolated internal static func toV2Alert(_ a: Alert) -> V2MockAlert {
        let mitre = a.mitreTechniquesList
        // v1.12.6 Wave 9H: parent / user / ai_tool / working_directory /
        // process_sha256 / host_name now ARE stored on Alert (Wave 2's
        // alerts.db v4 → v5 ALTER TABLE). Pre-9H the comment claimed
        // these were only on the originating Event — true before Wave 2,
        // not after. Inspector still hides empty fields so legacy
        // pre-v1.12.6 alerts that have NULL in these columns render
        // identically to the pre-9H path.
        return V2MockAlert(
            id: a.id,
            title: a.ruleTitle,
            severity: toV2Severity(a.severity),
            ruleId: a.ruleId,
            process: a.processName ?? "—",
            processPath: a.processPath ?? "",
            pid: 0,
            parent: a.parentExecutable ?? "",
            user: a.userName ?? "",
            aiTool: a.aiTool ?? "",
            workingDirectory: a.workingDirectory ?? "",
            processSHA256: a.processSha256 ?? "",
            hostName: a.hostName ?? "",
            triggeringEventsJson: a.triggeringEventsJson ?? "",
            timestamp: a.timestamp,
            mitre: mitre,
            category: (a.mitreTactics ?? "uncategorised").components(separatedBy: ",").first ?? "—",
            description: a.description ?? "",
            actionsTaken: [],
            suppressed: a.suppressed,
            remediationHint: a.remediationHint,
            d3fendTechniques: a.d3fendTechniques ?? [],
            llmVerdict: a.llmInvestigation?.verdict.rawValue,
            llmConfidence: a.llmInvestigation?.confidence,
            llmSummary: a.llmInvestigation?.summary,
            llmModel: a.llmInvestigation?.modelVersion,
            llmSuggestedActions: (a.llmInvestigation?.suggestedActions ?? []).map { $0.title },
            analystNote: a.analyst?.notes,
            analystOwner: a.analyst?.owner,
            analystStatus: a.analyst?.status?.rawValue,
            analystTicketRef: a.analyst?.ticketRef
        )
    }

    nonisolated internal static func toV2Event(_ e: Event) -> V2MockEvent {
        let detail: String = {
            if let n = e.network { return "\(n.transport) \(n.destinationIp):\(n.destinationPort)" }
            if let f = e.file    { return "\(f.action.rawValue) \(f.path)" }
            return e.eventType.rawValue
        }()
        return V2MockEvent(
            id: e.id.uuidString,
            timestamp: e.timestamp,
            category: e.eventCategory.rawValue,
            process: e.process.executable,
            pid: e.process.pid,
            detail: detail,
            scoring: e.severity == .informational ? nil : toV2Severity(e.severity)
        )
    }

    nonisolated internal static func toV2Campaign(_ r: CampaignStore.Record) -> V2MockCampaign {
        // v1.12.6 Wave 9J: surface Wave-2 campaigns.db schema columns
        // (affectedUsers, affectedExecutables, processTreeDepth,
        // techniques, aiTools) plus prefer the persisted firstSeen /
        // lastSeen over the pre-Wave-2 synthetic
        // `detectedAt - timeSpanSeconds`. `entities` was previously
        // hardcoded to 0 — now derives from
        // `affectedUsers + affectedExecutables` count.
        let users = r.affectedUsers ?? []
        let execs = r.affectedExecutables ?? []
        let entitiesCount = users.count + execs.count
        return V2MockCampaign(
            id: r.id,
            name: r.title,
            severity: toV2Severity(r.severity),
            firstSeen: r.firstSeen ?? r.detectedAt.addingTimeInterval(-r.timeSpanSeconds),
            lastSeen: r.lastSeen ?? r.detectedAt,
            alertCount: r.alerts.count,
            tactics: r.tactics,
            entities: entitiesCount,
            killChainStages: r.tactics,
            summary: r.description,
            affectedUsers: users,
            affectedExecutables: execs,
            techniques: r.techniques ?? [],
            aiTools: r.aiTools ?? [],
            processTreeDepth: r.processTreeDepth ?? 0,
            suppressed: r.suppressed
        )
    }

    nonisolated internal static func toV2Trace(_ t: Trace) -> V2MockTrace {
        return V2MockTrace(
            id: t.id,
            title: t.title,
            rootProcess: t.rootEntityId ?? "—",
            nodeCount: 0,
            edgeCount: 0,
            anchorVerdict: t.status,
            firstSeen: t.createdAt,
            lastUpdated: t.updatedAt,
            isDemo: t.title.hasPrefix("[DEMO]"),
            severityHint: severityFromString(t.severity)
        )
    }

    nonisolated private static func toV2Rule(_ r: CompiledRule, stats: RuleEngine.RuleStats? = nil) -> V2MockRule {
        // MITRE-shaped tags look like "attack.t1059" / "attack.execution".
        let mitre = r.tags
            .filter { $0.hasPrefix("attack.t") }
            .map { String($0.dropFirst("attack.".count)).uppercased() }
        // Heuristic: rule ids prefixed with "custom_" or living under
        // a Custom logsource category are user-authored.
        let isCustom = r.id.hasPrefix("custom_")
            || r.logsource.category.lowercased() == "custom"
        return V2MockRule(
            id: r.id,
            title: r.title,
            category: r.logsource.category,
            severity: toV2Severity(r.level),
            mitre: mitre.isEmpty ? [] : mitre,
            isEnabled: r.enabled,
            lastFired: stats?.lastFiredAt,
            firesLastWeek: Int(stats?.fireCount ?? 0),
            isCustom: isCustom,
            description: r.description,
            status: r.status
        )
    }

    nonisolated private static func severityFromString(_ s: String) -> V2Severity {
        switch s.lowercased() {
        case "critical":      return .critical
        case "high":          return .high
        case "medium":        return .medium
        case "low":           return .low
        case "informational", "info": return .info
        default: return .info
        }
    }
}

/// v1.12.0 post-audit (H-Int1): small actor that holds the most
/// recent deep-enrichment result per package id and tracks which
/// packages have an in-flight enrichment so we don't double-fire.
private actor EnrichmentResultCache {
    private var results: [String: PackageInfo] = [:]
    private var inFlight: Set<String> = []

    func snapshot() -> [String: PackageInfo] { results }

    func pending() -> Set<String> { inFlight }

    func markPending(_ id: String) { inFlight.insert(id) }

    func record(_ info: PackageInfo) {
        results[info.id] = info
        inFlight.remove(info.id)
    }
}


