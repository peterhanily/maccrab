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
    /// the cache. Pre-fix `rules()` re-loaded all 427 JSON files +
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

        var firstErr: String? = nil

        self.alertStore = {
            guard let dir = alertsDir else { return nil }
            do { return try AlertStore(directory: dir) }
            catch { if firstErr == nil { firstErr = "alerts: \(error)" }; return nil }
        }()
        self.eventStore = {
            guard let dir = eventsDir else { return nil }
            do { return try EventStore(directory: dir) }
            catch { if firstErr == nil { firstErr = "events: \(error)" }; return nil }
        }()
        self.campaignStore = {
            guard let dir = campaignDir else { return nil }
            do { return try CampaignStore(directory: dir) }
            catch { if firstErr == nil { firstErr = "campaigns: \(error)" }; return nil }
        }()
        self.causalStore = await {
            guard let dir = traceDir else { return nil }
            do { return try await SQLiteCausalGraphStore(databasePath: dir + "/tracegraph.db") }
            catch { if firstErr == nil { firstErr = "tracegraph: \(error)" }; return nil }
        }()

        self.lastErrorDescription = firstErr
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

    public func alerts(limit: Int) async -> [V2MockAlert] {
        guard let alertStore else { return [] }
        do {
            let raw = try await alertStore.alerts(
                since: Date().addingTimeInterval(-7 * 24 * 60 * 60),
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

    public func campaigns(limit: Int) async -> [V2MockCampaign] {
        guard let campaignStore else { return [] }
        do {
            let raw = try await campaignStore.list(
                since: Date().addingTimeInterval(-7 * 24 * 60 * 60),
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

    // The remaining surfaces don't have a 1:1 store yet — return mock
    // until phase 4.5 wires the appropriate scanners / monitors / config
    // readers. Marked clearly so consumers can label them as such.

    public func rules() async -> [V2MockRule] {
        guard let dir = dataDir else { return [] }
        let rulesPath = dir + "/compiled_rules"
        let telemetryPath = dir + "/rule_telemetry.json"
        let fm = FileManager.default

        // mtime gate — return the cache unchanged if neither the
        // compiled_rules directory nor the rule_telemetry.json file
        // has been touched since the last call.
        let dirMtime  = (try? fm.attributesOfItem(atPath: rulesPath))?[.modificationDate] as? Date
        let teleMtime = (try? fm.attributesOfItem(atPath: telemetryPath))?[.modificationDate] as? Date
        if !rulesCache.isEmpty,
           dirMtime == rulesCacheDirMtime,
           teleMtime == rulesCacheTelemetryMtime {
            return rulesCache
        }

        let rulesURL = URL(fileURLWithPath: rulesPath)
        let engine = RuleEngine()
        do { _ = try await engine.loadRules(from: rulesURL) }
        catch {
            lastErrorDescription = "rules read: \(error)"
            return []
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

        rulesCache = mapped
        rulesCacheDirMtime = dirMtime
        rulesCacheTelemetryMtime = teleMtime
        return mapped
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
        guard let dir = dataDir else { return [] }
        let cacheDir = dir + "/threat_intel"
        return await Task.detached(priority: .userInitiated) {
            guard let iocs = ThreatIntelFeed.cachedIOCs(at: cacheDir) else { return [] }
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
                let status: V2StatusLevel = staleness > 6 * 60 * 60 ? .warning : .info
                rows.append(V2MockFeed(
                    id: "feed-\(name)",
                    name: name, kind: kind,
                    entries: entries, lastFetch: lastUpdate,
                    status: status, staleness: staleness
                ))
            }
            return rows
        }.value
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

    // No backing implementation yet — return empty so the workspace
    // shows an honest empty state. Demo data is gone in v1.10.0.
    public func collectors() async -> [V2MockCollector]    { [] }
    public func permissions() async -> [V2MockPermission]  { [] }
    public func packages() async -> [V2MockPackage]        { [] }

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
        for id in ids {
            do {
                try await alertStore.suppress(alertId: id)
                count += 1
            } catch {
                lastErrorDescription = describeMutationError(error)
                // First read-only error = abort the loop. Repeating
                // for every id would just spam the same error.
                if isReadOnlyError(error) { break }
            }
        }
        return count
    }

    /// Suppress a campaign + every contributing alert. The campaign
    /// itself is stored as an alert with rule_id `maccrab.campaign.*`,
    /// so suppressing it requires hitting BOTH the alert-side row
    /// (so the campaign card greys out) AND every alert with
    /// `campaignId == id` (so the contributors stop firing). The
    /// CampaignStore.Record is also flipped to suppressed so the
    /// dashboard's campaigns list reflects state across restarts.
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
            // Read-only DB — give up early; subsequent calls would
            // re-error anyway.
            if isReadOnlyError(error) {
                lastErrorDescription = describeMutationError(error)
                return 0
            }
        }
        // 2. Find contributing alerts and suppress each.
        do {
            let raw = try await alertStore.alerts(
                since: Date.distantPast,
                severity: nil, suppressed: false, limit: 10_000
            )
            let contributors = raw.filter { $0.campaignId == id }
            for alert in contributors {
                do {
                    try await alertStore.suppress(alertId: alert.id)
                    count += 1
                } catch {
                    if isReadOnlyError(error) {
                        lastErrorDescription = describeMutationError(error)
                        break
                    }
                }
            }
        } catch {
            lastErrorDescription = "campaign contributors lookup: \(error)"
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

    /// Trigger a one-shot refresh of all threat-intel feeds. Shells out
    /// to `maccrabctl intel refresh` which signals the daemon's
    /// ThreatIntelFeed actor. We don't talk to the actor directly from
    /// the dashboard because the actor lives in the sysext process.
    public func refreshThreatIntel() async -> Bool {
        // `runMaccrabctl` does `Process.run() + waitUntilExit()` which
        // blocks main for 50-300 ms. Detach so the user's click
        // doesn't beachball.
        let result = await Task.detached(priority: .userInitiated) {
            V2LiveDataProvider.runMaccrabctl(arguments: ["intel", "refresh"])
        }.value
        if result.exitCode != 0 {
            lastErrorDescription = "intel refresh: \(result.stderr.split(separator: "\n").first.map(String.init) ?? "exit \(result.exitCode)")"
            return false
        }
        return true
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
            return "Database is read-only. The daemon owns this file as root, so the dashboard can't mutate it directly. Use `maccrabctl alerts suppress <id>` instead, or run the dashboard with elevated privileges."
        }
        return "suppress: \(error)"
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

    nonisolated private static func toV2Alert(_ a: Alert) -> V2MockAlert {
        let mitre = a.mitreTechniquesList
        // Process-side metadata (pid/parent/user) isn't stored on Alert
        // — only on the originating Event. Surface defaults here and
        // the inspector hides those rows when empty rather than
        // showing fake "PID: 0" data. actionsTaken is left empty for
        // the same reason: alerts that DID trigger a response action
        // get tagged later when prevention is wired through.
        return V2MockAlert(
            id: a.id,
            title: a.ruleTitle,
            severity: toV2Severity(a.severity),
            ruleId: a.ruleId,
            process: a.processName ?? "—",
            processPath: a.processPath ?? "",
            pid: 0,
            parent: "",
            user: "",
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

    nonisolated private static func toV2Event(_ e: Event) -> V2MockEvent {
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

    nonisolated private static func toV2Campaign(_ r: CampaignStore.Record) -> V2MockCampaign {
        return V2MockCampaign(
            id: r.id,
            name: r.title,
            severity: toV2Severity(r.severity),
            firstSeen: r.detectedAt.addingTimeInterval(-r.timeSpanSeconds),
            lastSeen: r.detectedAt,
            alertCount: r.alerts.count,
            tactics: r.tactics,
            entities: 0,
            killChainStages: r.tactics,
            summary: r.description
        )
    }

    nonisolated private static func toV2Trace(_ t: Trace) -> V2MockTrace {
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
            description: r.description
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


