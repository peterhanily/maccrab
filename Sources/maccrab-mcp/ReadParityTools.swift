// ReadParityTools.swift
// maccrab-mcp
//
// v1.21.6 (audit PAR-09): the read half of the capability matrix.
//
// The audit found the CLI↔MCP matrix one-sided in both directions. The
// dashboard side was closed by the System › Health audit card; this file closes
// the agent side. Before it, an agent could `create_rule` and `delete_rule` but
// could not ENUMERATE the corpus it was editing — `list_builtin_rules` returns
// only the 46 `maccrab.*` built-ins, so the 438-rule Sigma corpus was invisible.
// Four more human-only surfaces (`why`, `vulns`, `privacy`, `extensions`) had no
// MCP equivalent at all.
//
// Every tool here is READ-ONLY: each appears in the explicit
// `agentUngatedStaticTools` registry, and none writes anything. They deliberately
// re-read the same stores the CLI reads rather than shelling out to `maccrabctl` — a subprocess would
// inherit the agent's environment and re-parse formatted text.

import Foundation
import MacCrabCore

// MARK: - list_rules

/// Mirror of `maccrabctl rules list` over the compiled Sigma corpus.
///
/// Carries the same two annotations the CLI gained in v1.21.6, because without
/// them a listing cannot distinguish "quiet because nothing attacked me" from
/// "quiet because it never ran" — the distinction that decides whether the
/// corpus is worth anything:
///   * `rule_profile` — 351 of 438 rules are `experimental` and are NOT LOADED
///     under the default `stable` profile, yet every one of them carries
///     `enabled: true` on disk.
///   * `rule_telemetry.json` — per-rule evaluation and fire counts, so a loaded
///     rule that was never evaluated once (a dead logsource) is visible.
func handleListRules(_ args: [String: Any]) -> Any {
    let compiledDir = dataDir + "/compiled_rules"
    let fm = FileManager.default
    guard let files = try? fm.contentsOfDirectory(atPath: compiledDir) else {
        return toolError("No compiled rules readable at \(compiledDir). The engine writes them at startup; if MacCrab is running, this process may lack read access.")
    }

    let levelFilter = (args["level"] as? String)?.lowercased()
    let search = (args["search"] as? String)?.lowercased()
    let tacticFilter = (args["tactic"] as? String)?.lowercased()
    let limit = min(max(args["limit"] as? Int ?? 100, 1), 500)

    // Prefer the heartbeat's published profile: daemon_config.json is 0600
    // root-owned, so reading it as this uid silently yields the "stable"
    // default and would mislabel an `all`-profile install as gating rules it
    // actually loads.
    var heartbeatProfile: String?
    if let data = try? Data(contentsOf: URL(fileURLWithPath: dataDir + "/heartbeat_rich.json")),
       let hb = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
        heartbeatProfile = hb["rule_profile"] as? String
    }
    let profile = heartbeatProfile ?? "stable"
    let profileEnablesAll = profile.lowercased() == "all"

    var telemetryByID: [String: RuleEngine.RuleStats] = [:]
    if let snapshot = RuleEngine.readTelemetrySnapshot(at: dataDir + "/rule_telemetry.json") {
        for stat in snapshot.stats { telemetryByID[stat.ruleId] = stat }
    }

    // manifest.json is the rule-bundle manifest, not a rule — it has no `level`
    // and would show up as a phantom entry.
    let jsonFiles = files.filter { $0.hasSuffix(".json") && $0 != "manifest.json" }.sorted()

    var rows: [String] = []
    var total = 0, loaded = 0, matchedEver = 0, dark = 0
    for file in jsonFiles {
        guard let data = fm.contents(atPath: compiledDir + "/" + file),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { continue }
        total += 1

        let title = json["title"] as? String ?? "Unknown"
        let level = (json["level"] as? String ?? "informational").lowercased()
        let ruleId = json["id"] as? String ?? ""
        let tags = (json["tags"] as? [String]) ?? []
        let status = (json["status"] as? String)?.lowercased() ?? "experimental"

        let isLoaded = status != "deprecated" && (profileEnablesAll || status == "stable")
        if isLoaded { loaded += 1 }

        // State, computed exactly as the CLI computes it.
        let state: String
        if status == "deprecated" {
            state = "DEPRECATED (retained but never loaded)"
        } else if !isLoaded {
            state = "OFF: not loaded under rule_profile=\(profile) (status=\(status))"
        } else if let stats = telemetryByID[ruleId] {
            if stats.fireCount > 0 {
                matchedEver += 1
                state = "matched \(stats.fireCount)x over \(stats.evaluationCount) evals"
            } else {
                state = "quiet: \(stats.evaluationCount) evals, 0 matches"
            }
        } else if telemetryByID.isEmpty {
            // No snapshot at all — the daemon may not be running. Saying
            // nothing beats labelling every rule dark.
            state = "state unknown (no rule_telemetry.json)"
        } else {
            // Loaded, telemetry exists for OTHER rules, none for this one: it
            // was never evaluated once, i.e. its logsource has no live
            // producer. This is the state that made the tcc_event rules look
            // identical to healthy quiet rules.
            dark += 1
            state = "DARK: never evaluated — its logsource has no live producer"
        }

        if let levelFilter, level != levelFilter { continue }
        if let tacticFilter, !tags.contains(where: { $0.lowercased().contains(tacticFilter) }) { continue }
        if let search, !title.lowercased().contains(search), !ruleId.lowercased().contains(search) { continue }

        rows.append("[\(level.uppercased())] \(title)\n  id: \(ruleId)\n  tags: \(tags.prefix(4).joined(separator: ", "))\n  state: \(state)")
    }

    var lines = [
        "\(total) compiled rule(s); \(loaded) loaded under rule_profile=\(profile).",
    ]
    if !telemetryByID.isEmpty {
        lines.append("Of the loaded rules, \(matchedEver) have ever matched and \(dark) were never evaluated at all (current daemon boot only).")
    } else {
        lines.append("No rule_telemetry.json — per-rule evaluation state is unavailable (is the engine running?).")
    }
    lines.append("These are the Sigma corpus rules; the built-in maccrab.* detections are a separate set — use list_builtin_rules.")
    if rows.count > limit {
        lines.append("Showing \(limit) of \(rows.count) matching rules — narrow with level / tactic / search, or raise limit (max 500).")
        rows = Array(rows.prefix(limit))
    } else {
        lines.append("\(rows.count) matching:")
    }
    lines.append("")
    lines.append(contentsOf: rows)
    return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
}

// MARK: - explain_alert  (mirror of `maccrabctl why`)

/// Explain which rule fired and what is known about the match.
///
/// The CLI's `why` re-reads the rule's compiled predicate and prints the
/// matched clauses. That detail is only available when the rule JSON is
/// readable; when it is not, this says so rather than implying the alert had no
/// rule behind it.
func handleExplainAlert(_ args: [String: Any]) async -> Any {
    guard let alertId = args["alert_id"] as? String, !alertId.isEmpty else {
        return toolError("'alert_id' is required (get it from get_alerts).")
    }
    do {
        let store = try AlertStore(directory: dataDir)
        // No id-lookup on the store protocol; scan a bounded recent window, the
        // same way the CLI does.
        let recent = try await store.alerts(since: Date.distantPast, limit: 2000)
        guard let alert = recent.first(where: { $0.id == alertId }) else {
            return toolError("No alert with id '\(alertId)' in the most recent 2000. It may have been pruned by the alert-retention sweep.")
        }

        var lines: [String] = []
        lines.append("[\(alert.severity.rawValue.uppercased())] \(alert.ruleTitle)")
        lines.append("  rule_id: \(alert.ruleId)")
        lines.append("  time:    \(isoFormatter.string(from: alert.timestamp))")
        if let proc = alert.processName { lines.append("  process: \(proc)") }
        if let path = alert.processPath { lines.append("  path:    \(LLMSanitizer.sanitize(path))") }
        if let desc = alert.description { lines.append("  detail:  \(LLMSanitizer.sanitize(desc))") }
        if let techs = alert.mitreTechniques, !techs.isEmpty { lines.append("  mitre:   \(techs)") }
        lines.append("  suppressed: \(alert.suppressed)")

        // maccrab.* alerts are synthetic — behavioral scoring, campaign
        // roll-ups, self-defense. They have no compiled predicate to show, and
        // hunting for one would report a misleading "rule file not found".
        if alert.ruleId.hasPrefix("maccrab.") {
            lines.append("")
            lines.append("This is a built-in maccrab.* detection, not a Sigma rule: it has no compiled predicate.")
            lines.append("Its verdict comes from the engine's own scoring/correlation, described above and in list_builtin_rules.")
            return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
        }

        // Sigma rule: surface the compiled predicate so the agent can see what
        // the match actually required.
        let compiledDir = dataDir + "/compiled_rules"
        let fm = FileManager.default
        var ruleJSON: [String: Any]?
        if let files = try? fm.contentsOfDirectory(atPath: compiledDir) {
            for file in files where file.hasSuffix(".json") && file != "manifest.json" {
                guard let data = fm.contents(atPath: compiledDir + "/" + file),
                      let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                      (json["id"] as? String) == alert.ruleId else { continue }
                ruleJSON = json
                break
            }
        }
        lines.append("")
        guard let ruleJSON else {
            lines.append("The compiled rule for \(alert.ruleId) is not readable from this process, so the")
            lines.append("matching predicate cannot be shown. The alert itself is unaffected.")
            return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
        }
        lines.append("Rule definition:")
        if let desc = ruleJSON["description"] as? String { lines.append("  description: \(desc)") }
        if let status = ruleJSON["status"] as? String { lines.append("  status: \(status)") }
        if let ls = ruleJSON["logsource"] { lines.append("  logsource: \(ls)") }
        if let det = ruleJSON["detection"],
           let data = try? JSONSerialization.data(withJSONObject: det, options: [.prettyPrinted, .sortedKeys]),
           let text = String(data: data, encoding: .utf8) {
            lines.append("  detection:")
            for l in text.components(separatedBy: "\n") { lines.append("    " + l) }
        }
        return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
    } catch {
        return toolError("Error reading alerts: \(error.localizedDescription)")
    }
}

// MARK: - get_vulns / get_privacy_alerts

/// Shared body for the two rule-prefix views. Both are thin filters over the
/// alert store — the same rows `get_alerts` returns, narrowed to one family.
private func alertsWithPrefix(
    _ prefix: String, hours: Double, limit: Int, emptyHint: String
) async -> Any {
    do {
        let store = try AlertStore(directory: dataDir)
        let since = Date().addingTimeInterval(-hours * 3600)
        // Over-fetch then filter: the store has no rule-prefix predicate, and a
        // limit applied before filtering would return a near-empty page
        // whenever the family is a small share of recent alerts.
        let all = try await store.alerts(since: since, limit: 2000)
        let matched = Array(all.filter { $0.ruleId.hasPrefix(prefix) }.prefix(limit))
        guard !matched.isEmpty else {
            return ["content": [["type": "text", "text":
                "No \(prefix)* alerts in the last \(Int(hours))h.\n\(emptyHint)"]]]
        }
        var lines = ["\(matched.count) \(prefix)* alert(s) from the last \(Int(hours))h:"]
        for a in matched {
            lines.append("")
            lines.append("[\(a.severity.rawValue.uppercased())] \(a.ruleTitle)\(a.suppressed ? " [SUPPRESSED]" : "")")
            lines.append("  time: \(isoFormatter.string(from: a.timestamp))")
            lines.append("  id:   \(a.id)")
            if let p = a.processName { lines.append("  process: \(p)") }
            if let d = a.description { lines.append("  detail: \(LLMSanitizer.sanitize(String(d.prefix(400))))") }
        }
        if all.count == 2000 {
            lines.append("")
            lines.append("(Scanned the 2000 most recent alerts; older \(prefix)* rows in this window are not shown.)")
        }
        return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
    } catch {
        return toolError("Error reading alerts: \(error.localizedDescription)")
    }
}

func handleGetVulns(_ args: [String: Any]) async -> Any {
    await alertsWithPrefix(
        "maccrab.vuln.",
        hours: args["hours"] as? Double ?? 168,
        limit: min(max(args["limit"] as? Int ?? 50, 1), 200),
        emptyHint: "Vulnerability lookups are OFF by default and require `vuln_scan_enabled` — with it off there is nothing to report, which is not the same as a clean bill of health."
    )
}

func handleGetPrivacyAlerts(_ args: [String: Any]) async -> Any {
    await alertsWithPrefix(
        "maccrab.privacy.",
        hours: args["hours"] as? Double ?? 168,
        limit: min(max(args["limit"] as? Int ?? 50, 1), 200),
        emptyHint: "The privacy auditor runs hourly and surfaces bulk egress, domain spikes and high-frequency tracker contacts."
    )
}

// MARK: - get_browser_extensions

/// Mirror of `maccrabctl extensions`.
///
/// Calls `BrowserExtensionMonitor.snapshotResult()` — the same live scan the
/// dashboard uses, including its completeness diagnostics — rather than reading
/// a persisted inventory, because the monitor does
/// not persist one: it emits events into the store and the UI re-scans on
/// demand. The scan walks THIS process's `NSHomeDirectory()`, so it reports the
/// extensions of the account the MCP server runs as, which is the same scope
/// `maccrabctl extensions` reports and the same scope the agent already has.
func handleGetBrowserExtensions(_ args: [String: Any]) -> Any {
    let suspiciousOnly = args["suspicious_only"] as? Bool ?? false
    let limit = min(max(args["limit"] as? Int ?? 100, 1), 300)

    // riskScore is 0-100 from the monitor's dangerous-permission weighting.
    // 40 is the CLI's own "worth a look" line; keep the two surfaces answering
    // the same question the same way.
    let riskyFloor = 40
    let inventory = BrowserExtensionMonitor.snapshotResult()
    let all = inventory.extensions
    let flagged = all.filter { $0.riskScore >= riskyFloor || !$0.dangerousPermissions.isEmpty }

    var shown = suspiciousOnly ? flagged : all
    var lines = ["\(all.count) installed browser extension(s); \(flagged.count) at or above risk \(riskyFloor) (or holding a dangerous permission)."]
    if inventory.coverage.wasTruncated {
        lines.insert(
            "WARNING: browser inventory is PARTIAL — the bounded scan exhausted its directory-entry budget in \(inventory.coverage.truncatedHomeCount) home(s). Absence from this output is not evidence that an extension is not installed.",
            at: 0
        )
    }
    if all.isEmpty {
        if inventory.coverage.wasTruncated {
            lines.append("No extension rows were discovered before bounded coverage ended; this is not a clean empty result.")
        } else {
            lines.append("No extension directories were readable. On a release install the MCP server runs as your user, so this reflects your own browser profiles; a sandboxed or headless context may see none.")
        }
        return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
    }
    if shown.count > limit {
        lines.append("Showing the \(limit) highest-risk of \(shown.count) (already sorted by risk).")
        shown = Array(shown.prefix(limit))
    }
    if shown.isEmpty {
        lines.append("None flagged.")
    }
    lines.append("")
    for e in shown {
        let mark = (e.riskScore >= riskyFloor || !e.dangerousPermissions.isEmpty) ? "[RISK \(e.riskScore)] " : "[risk \(e.riskScore)] "
        lines.append("\(mark)\(e.extensionName)  (\(e.browser)\(e.isDevMode ? ", DEV-MODE/unpacked" : ""))")
        lines.append("  id: \(e.extensionId)\(e.version.map { " v\($0)" } ?? "")")
        if !e.dangerousPermissions.isEmpty {
            lines.append("  dangerous: \(e.dangerousPermissions.joined(separator: ", "))")
        }
        if !e.hostPermissions.isEmpty {
            lines.append("  hosts: \(e.hostPermissions.prefix(6).joined(separator: ", "))")
        }
    }
    return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
}
