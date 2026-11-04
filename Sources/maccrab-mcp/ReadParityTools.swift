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
    mcpRuleInventory(directory: dataDir, arguments: args)
}

// MARK: - explain_alert  (short form of `maccrabctl why`)

/// Explain which rule fired and what is known about the match.
///
/// Shows the alert, then the rule the engine applies for its id, as
/// CompiledRuleFileIndex resolves it: a user rule the engine would load, else
/// the bundled rule. Of that rule it shows the description, status and
/// logsource, not the matching logic; a closing line points to
/// `maccrabctl why <alert id>`, which prints the rule's predicates and how they
/// combine on this Mac (long value lists are shortened). When this process
/// cannot read all of user_rules, a note says the engine, which runs as root
/// when installed, may apply a user rule from there instead, unless the rule
/// is a sequence or graph rule, which user rules do not replace. The rule
/// definition is shown only when the rule JSON is readable; when it is not,
/// this says so rather than implying the alert had no rule behind it.
func handleExplainAlert(_ args: [String: Any]) async -> Any {
    guard let alertId = args["alert_id"] as? String, !alertId.isEmpty else {
        return toolError("'alert_id' is required (get it from get_alerts).")
    }
    do {
        let store = try openMCPAlertStoreForReading(directory: dataDir)
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

        // Sigma rule: show the definition of the rule the engine applies for
        // this id.
        let compiledDir = dataDir + "/compiled_rules"
        let ruleJSON = CompiledRuleFileIndex.shared.rule(id: alert.ruleId, in: compiledDir)
        lines.append("")
        guard let ruleJSON else {
            lines.append("The compiled rule for \(alert.ruleId) is not readable from this process, so its")
            lines.append("definition cannot be shown. The alert itself is unaffected.")
            return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
        }
        lines += explainRuleDefinitionLines(
            ruleJSON, alertID: alert.id,
            duplicateUserRules: CompiledRuleFileIndex.shared.hasDuplicateUserRules(id: alert.ruleId, in: compiledDir),
            unreadableUserRules: CompiledRuleFileIndex.shared.hasUnreadableUserRules(id: alert.ruleId, in: compiledDir))
        return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
    } catch {
        return toolError("Error reading alerts: \(error.localizedDescription)")
    }
}

/// The "Rule definition:" part of explain_alert: the rule's description,
/// status and logsource, then where to see its matching logic. That is left
/// to `maccrabctl why`, which prints the rule's predicates and how they
/// combine on this Mac (long value lists are shortened); this server's
/// responses pass through the privacy sanitizer, which rewrites paths, host
/// names and addresses in rule values.
func explainRuleDefinitionLines(_ rule: [String: Any], alertID: String, duplicateUserRules: Bool, unreadableUserRules: Bool) -> [String] {
    var lines = ["Rule definition:"]
    if duplicateUserRules && !unreadableUserRules {
        lines.append("  note: several user rules have this id. The engine applies one of them, in an order MacCrab does not define; this is the first by file name.")
    } else if duplicateUserRules {
        lines.append("  note: at least two user rules have this id. The engine applies one of them or one this process cannot read, in an order MacCrab does not define; this is the first by file name of those this process can read.")
    }
    if unreadableUserRules {
        lines.append("  note: this process cannot read all of user_rules (the folder cannot be listed or inspected, or a file in it cannot be inspected or opened). The engine runs as root when installed, so it may apply a user rule from there for this id instead of the rule shown; to check, run `sudo maccrabctl why \(alertID)` on this Mac.")
    }
    if let desc = rule["description"] as? String { lines.append("  description: \(desc)") }
    if let status = rule["status"] as? String { lines.append("  status: \(status)") }
    if let ls = rule["logsource"] as? [String: Any] {
        let pairs: [String] = ls.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }
        lines.append("  logsource: " + pairs.joined(separator: ", "))
    }
    lines.append("  matching logic: run `maccrabctl why \(alertID)` on this Mac; it prints the rule's predicates and how they combine (long value lists are shortened).")
    return lines
}

// MARK: - get_vulns / get_privacy_alerts

/// Shared body for the two rule-prefix views. Both are thin filters over the
/// alert store — the same rows `get_alerts` returns, narrowed to one family.
private func alertsWithPrefix(
    _ prefix: String, hours: Double, limit: Int, emptyHint: String
) async -> Any {
    do {
        let store = try openMCPAlertStoreForReading(directory: dataDir)
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

/// Rule id -> compiled file. Built on first use, then rebuilt when a rule
/// directory's stamp (the bundled folders: stat mtime; user_rules: lstat
/// mtime, ctime, mode and owner) or a rule file's lstat stamp changes
/// (checked on every lookup), or a cached entry stops resolving. Every
/// explain_alert call used to open and parse each compiled rule (about 480
/// files) to find one id. Launched by an AI agent, this server is an
/// attributed agent child, so each of those opens was admitted, journaled and
/// scanned as agent activity: MacCrab amplifying itself.
final class CompiledRuleFileIndex: @unchecked Sendable {
    static let shared = CompiledRuleFileIndex()

    /// The rule directories as they were at the last build. A compile adds,
    /// removes or renames files, which moves a directory's mtime. A chmod or
    /// chown of user_rules, which decides whether the engine trusts the
    /// overlay and whether this process can list it, leaves its mtime alone,
    /// so its ctime, mode and owner count too. A rule file edited in place
    /// moves none of these; its FileStamp does.
    private struct Stamp: Equatable {
        let bundled: [Time?]
        let user: UserRulesState?
    }

    /// lstat metadata of one rule file. An edit in place moves the file's mtime
    /// and ctime but not its directory's; a replacement changes its inode. A
    /// chmod, which decides whether this process can open it, moves its ctime.
    private struct FileStamp: Equatable {
        let path: String
        let inode: UInt64
        let size: Int64
        let modified: Time
        let changed: Time
    }

    private struct Time: Equatable {
        let seconds: Int
        let nanoseconds: Int

        init(_ value: timespec) {
            seconds = value.tv_sec
            nanoseconds = value.tv_nsec
        }
    }

    private struct UserRulesState: Equatable {
        let modified: Time
        let changed: Time
        let mode: mode_t
        let owner: uid_t
    }

    /// The bundled corpus in the order an id resolves: single-event,
    /// sequence, graph and auto-generated rules.
    private static func bundledDirectories(_ compiledDir: String) -> [String] {
        [compiledDir, compiledDir + "/sequences", compiledDir + "/graph", compiledDir + "/auto_generated"]
    }

    static func userRulesDirectory(_ compiledDir: String) -> String {
        (compiledDir as NSString).deletingLastPathComponent + "/user_rules"
    }

    private let lock = NSLock()
    private var directory: String?
    private var stamp: Stamp?
    private var files: [FileStamp] = []
    private var paths: [String: String] = [:]
    private var duplicateUserRuleIDs: Set<String> = []
    private var unreadableUserRules = false
    private var builds = 0

    /// Index builds so far. Tests use it to show that a miss opens no rule file.
    var rebuildCount: Int {
        lock.lock(); defer { lock.unlock() }
        return builds
    }

    /// The rule the engine applies for `id`: a user rule only while the engine
    /// would load it (the UserRuleOverlayTrust checks, then
    /// RuleEngine.decodeLoadableRule), else the bundled rule, so an agent is
    /// never handed rule text the engine refused.
    func rule(id: String, in compiledDir: String) -> [String: Any]? {
        rule(id: id, in: compiledDir, engineUID: UserRuleOverlayTrust.engineUID(
            forSupportDirectory: (compiledDir as NSString).deletingLastPathComponent))
    }

    func rule(id: String, in compiledDir: String, engineUID: uid_t) -> [String: Any]? {
        let userDir = Self.userRulesDirectory(compiledDir)
        // A user rule is used only while the engine would still load it.
        func resolve(_ path: String) -> [String: Any]? {
            let json: [String: Any]?
            if path.hasPrefix(userDir + "/") {
                guard UserRuleOverlayTrust.trustsDirectory(atPath: userDir, engineUID: engineUID),
                      UserRuleOverlayTrust.trustsFile(atPath: path, engineUID: engineUID) else { return nil }
                json = Self.loadUserRule(path).rule
            } else {
                json = Self.load(path)
            }
            return (json?["id"] as? String) == id ? json : nil
        }
        // The server lives for a whole agent session, while the engine installs
        // overrides and an operator may fix user_rules' mode or edit a rule in
        // place: an entry is used only while the directories and their rule
        // files are as they were when it was indexed.
        let current = Self.stamp(compiledDir)
        let unchanged = isCurrent(compiledDir, stamp: current)
            && filesUnchanged(Self.fileStamps(compiledDir, engineUID: engineUID))
        let cached = cachedPath(id: id, in: compiledDir)
        if unchanged, let cached, let json = resolve(cached) {
            return json
        }
        // A stale entry means the rules changed: rebuild. An id with no entry
        // rebuilds only when the directories or their files changed, so an
        // alert whose rule is no longer in the corpus does not reopen every
        // file on each call.
        guard cached != nil || !unchanged else { return nil }
        rebuild(compiledDir, stamp: current, engineUID: engineUID)
        return cachedPath(id: id, in: compiledDir).flatMap(resolve)
    }

    /// Whether more than one loadable user rule claims `id` in the current index.
    func hasDuplicateUserRules(id: String, in compiledDir: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return directory == compiledDir && duplicateUserRuleIDs.contains(id)
    }

    /// Whether the engine may apply, for `id`, a user rule this process cannot
    /// read: at the last build, this process was refused lstat of user_rules
    /// or of a file in it, could not list user_rules, or could not open a file
    /// in it that the engine's uid owns, and `id` is not a sequence or graph
    /// rule's, which user rules do not replace.
    func hasUnreadableUserRules(id: String, in compiledDir: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard directory == compiledDir, unreadableUserRules, let path = paths[id] else { return false }
        return !path.hasPrefix(compiledDir + "/sequences/") && !path.hasPrefix(compiledDir + "/graph/")
    }

    private func cachedPath(id: String, in compiledDir: String) -> String? {
        lock.lock(); defer { lock.unlock() }
        guard directory == compiledDir else { return nil }
        return paths[id]
    }

    private func isCurrent(_ compiledDir: String, stamp current: Stamp) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return directory == compiledDir && stamp == current
    }

    private func filesUnchanged(_ current: [FileStamp]) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return files == current
    }

    private func rebuild(_ compiledDir: String, stamp current: Stamp, engineUID: uid_t) {
        // Stamped before they are read: a file that changes during the build
        // no longer matches its stamp, so the next lookup rebuilds again.
        let currentFiles = Self.fileStamps(compiledDir, engineUID: engineUID)
        var next: [String: String] = [:]
        for dir in Self.bundledDirectories(compiledDir) {
            for path in Self.ruleFiles(in: dir) ?? [] {
                if let id = Self.load(path)?["id"] as? String, next[id] == nil {
                    next[id] = path
                }
            }
        }
        // The engine overlays the user rules it would load on its single-event
        // rules: one replaces a single-event id or adds a new one. A user file
        // with a sequence or graph id does not replace that rule. The
        // single-event engine loads it next to that rule, and the index keeps
        // showing the sequence or graph definition.
        let userDir = Self.userRulesDirectory(compiledDir)
        var duplicated: Set<String> = []
        var unreadable = false
        // A folder this process may not lstat or cannot list, a file in it
        // that it may not lstat, or a file the engine's uid owns that it may
        // not open, need not be one the engine refuses: an engine running as
        // root is not held to file modes or ACL entries, and may load a rule
        // from there.
        if UserRuleOverlayTrust.trustsDirectory(atPath: userDir, engineUID: engineUID) {
            let otherEngines = [compiledDir + "/sequences/", compiledDir + "/graph/"]
            var overridden: Set<String> = []
            let userFiles = Self.ruleFiles(in: userDir)
            if userFiles == nil { unreadable = true }
            for path in userFiles ?? [] {
                guard UserRuleOverlayTrust.trustsFile(atPath: path, engineUID: engineUID) else {
                    if UserRuleOverlayTrust.lstatIsRefused(atPath: path) { unreadable = true }
                    continue
                }
                let (rule, inaccessible) = Self.loadUserRule(path)
                if inaccessible { unreadable = true }
                guard let id = rule?["id"] as? String else { continue }
                // The engine loads each of these and keeps the last it enumerates,
                // an order it does not define: show the first by name, note the rest.
                if overridden.contains(id) { duplicated.insert(id); continue }
                if let bundled = next[id], otherEngines.contains(where: { bundled.hasPrefix($0) }) { continue }
                next[id] = path
                overridden.insert(id)
            }
        } else if UserRuleOverlayTrust.lstatIsRefused(atPath: userDir) {
            unreadable = true
        }
        lock.lock()
        directory = compiledDir
        stamp = current
        files = currentFiles
        paths = next
        duplicateUserRuleIDs = duplicated
        unreadableUserRules = unreadable
        builds += 1
        lock.unlock()
    }

    /// A directory's rule files, sorted, selected as RuleEngine.loadRules
    /// selects them: `.json` files other than the build manifest, skipping
    /// the files .skipsHiddenFiles treats as hidden, a leading dot or the
    /// UF_HIDDEN flag. The paths are built from `dir`, because the listed URLs
    /// resolve /tmp and /var to /private and a user rule is recognised by its
    /// `dir` prefix. nil when the directory cannot be listed.
    private static func ruleFiles(in dir: String) -> [String]? {
        guard let listed: [URL] = try? FileManager.default.contentsOfDirectory(
            at: URL(fileURLWithPath: dir), includingPropertiesForKeys: nil, options: [.skipsHiddenFiles]) else { return nil }
        let jsonFiles: [URL] = listed.filter { $0.pathExtension == "json" && $0.lastPathComponent != "manifest.json" }
        return jsonFiles.map { dir + "/" + $0.lastPathComponent }.sorted()
    }

    private static func stamp(_ compiledDir: String) -> Stamp {
        let bundled = bundledDirectories(compiledDir).map { path -> Time? in
            var st = stat()
            return stat(path, &st) == 0 ? Time(st.st_mtimespec) : nil
        }
        // lstat, as the trust check does: a symlink swapped in changes it.
        var st = stat()
        let user = lstat(userRulesDirectory(compiledDir), &st) == 0
            ? UserRulesState(modified: Time(st.st_mtimespec), changed: Time(st.st_ctimespec),
                             mode: st.st_mode, owner: st.st_uid)
            : nil
        return Stamp(bundled: bundled, user: user)
    }

    /// The rule files the index reads: those of the bundled directories and,
    /// while the engine trusts it, of user_rules. Listing and lstat only: no
    /// rule file is opened.
    private static func fileStamps(_ compiledDir: String, engineUID: uid_t) -> [FileStamp] {
        var directories = bundledDirectories(compiledDir)
        let userDir = userRulesDirectory(compiledDir)
        if UserRuleOverlayTrust.trustsDirectory(atPath: userDir, engineUID: engineUID) { directories.append(userDir) }
        return directories.flatMap { ruleFiles(in: $0) ?? [] }.map { path in
            var st = stat()
            guard lstat(path, &st) == 0 else {
                return FileStamp(path: path, inode: 0, size: -1, modified: Time(timespec()), changed: Time(timespec()))
            }
            return FileStamp(path: path, inode: UInt64(st.st_ino), size: Int64(st.st_size),
                             modified: Time(st.st_mtimespec), changed: Time(st.st_ctimespec))
        }
    }

    /// A regular file only, read through the bounded reader: a FIFO or a
    /// symlink planted among the rules is skipped, not followed or waited on.
    private static func load(_ path: String) -> [String: Any]? {
        guard let data = BoundedRegularFileReader.read(at: path, maximumBytes: RuleEngine.maximumRuleFileBytes) else { return nil }
        return try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    }

    /// A user rule only if the engine would load it: RuleEngine.decodeLoadableRule,
    /// the decode and condition-tree validation loadRules applies.
    /// `inaccessible` is whether this process was refused permission to open it.
    private static func loadUserRule(_ path: String) -> (rule: [String: Any]?, inaccessible: Bool) {
        let outcome = BoundedRegularFileReader.readOutcome(at: path, maximumBytes: RuleEngine.maximumRuleFileBytes)
        guard case .success(let snapshot) = outcome,
              (try? RuleEngine.decodeLoadableRule(snapshot.data)) != nil else {
            return (nil, outcome == .rejected(.inaccessible))
        }
        return (try? JSONSerialization.jsonObject(with: snapshot.data) as? [String: Any], false)
    }
}
