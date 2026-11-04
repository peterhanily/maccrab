// RuleMutateCommands.swift -- `maccrabctl rule delete|severity` (PARITY-05).
//
// Headless mirror of the MCP rule-mutation handlers in
// maccrab-mcp/AgentControl.swift:
//   • rule delete <id>          → handleDeleteRule (verb "remove-rule")
//   • rule severity <id> <lvl>  → handleSetBuiltinRuleSetting for maccrab.*
//                                 (verb "builtin-rule-setting"); for a
//                                 user-authored rule, set the JSON `level`
//                                 and re-install (verb "install-rule").
//
// Both route through the privileged inbox the engine polls; the daemon
// authorizes by file-owner uid and re-sanitizes the rule id
// (DaemonTimers.swift). The CLI is NOT trusted — it only queues. Built-in
// maccrab.* rules cannot be DELETED (mirroring the MCP: tune them with
// severity instead). Sequence + graph rules cannot have their severity set
// here (they aren't single-event level rules).

import Foundation
import MacCrabCore

/// Dispatch the `delete` / `severity` sub-verbs of `maccrabctl rule`. Wired
/// in from the EXISTING `case "rule"` in MacCrabCtl.main (see sharedEdits) —
/// args here are the tokens AFTER `rule` (i.e. args.dropFirst(2)).
func dispatchRuleMutate(args: [String]) {
    guard let sub = args.first else {
        printRuleMutateUsage()
        exit(1)
    }
    let rest = Array(args.dropFirst())
    switch sub {
    case "delete":
        ruleDelete(args: rest)
    case "severity":
        ruleSeverity(args: rest)
    default:
        printRuleMutateUsage()
        exit(1)
    }
}

private func printRuleMutateUsage() {
    print("""
    Usage:
      maccrabctl rule delete <id>             Remove a user-authored rule. Built-in
                                              maccrab.* rules cannot be deleted — tune
                                              them with `rule severity` instead.
      maccrabctl rule severity <id> <level>   Override a rule's severity.
                                              level: critical|high|medium|low|informational
                                              (or 'default' to clear an override).
                                              Sequence and graph rules are not supported.
    """)
}

// MARK: - rule delete

private func ruleDelete(args: [String]) {
    guard let ruleId = args.first, !ruleId.isEmpty else {
        print("Usage: maccrabctl rule delete <id>")
        exit(1)
    }
    // Path-traversal guard — mirrors handleDeleteRule exactly.
    guard ruleId.count <= 128, !ruleId.contains("/"), !ruleId.contains("..") else {
        print("Invalid rule id (no '/' or '..', max 128 chars).")
        exit(1)
    }
    // Built-in detections cannot be deleted (same refusal the MCP gives).
    guard !ruleId.hasPrefix("maccrab.") else {
        print("Built-in maccrab.* rules cannot be deleted. Tune them instead:")
        print("  maccrabctl rule severity \(ruleId) <level>")
        print("  maccrabctl rule disable \(ruleId)")
        exit(1)
    }
    switch ruleDeletePlan(ruleId: ruleId, supportDir: maccrabDataDir()) {
    case .refuse(let lines):
        lines.forEach { print($0) }
        exit(1)
    case .queue(let reply):
        if let err = dropCtlInboxRequest(verb: "remove-rule", payload: ["ruleId": ruleId]) {
            print("Could not queue rule removal: \(err)")
            print("(The engine may not be running, or this shell can't write its inbox.)")
            exit(1)
        }
        print(reply)
    }
}

/// What `rule delete` does with an id that passed its argument checks.
enum RuleDeletePlan: Equatable {
    /// Print these lines and exit 1, queueing nothing.
    case refuse([String])
    /// Queue remove-rule, then print this line.
    case queue(String)
}

/// The engine's remove-rule handler deletes user_rules/<basename>.yml and
/// user_rules/<basename>.json, so without that JSON file nothing is queued.
/// When a top-level compiled_rules rule has the "id" of that file's rule (or
/// `ruleId`, if the file has none), the reply says the engine uses that
/// bundled rule after the reload.
func ruleDeletePlan(ruleId: String, supportDir: String) -> RuleDeletePlan {
    let userRuleFile = safeUserRuleBasename(ruleId).map { "user_rules/\($0).json" }
    guard let userRuleFile, FileManager.default.fileExists(atPath: supportDir + "/" + userRuleFile) else {
        return .refuse([
            "No user rule has the id \(ruleId)" + (userRuleFile.map { " (there is no \($0))" } ?? "")
                + ", so nothing was queued.",
            "Bundled rules cannot be deleted. To turn one off, use Disable rule in the dashboard's"
                + " Detection › Rules, or maccrabctl rule disable \(ruleId), which on a release install"
                + " lasts until the engine restarts.",
        ])
    }
    // The engine replaces the bundled rule whose id is the user rule's "id".
    let userRuleID = (try? Data(contentsOf: URL(fileURLWithPath: supportDir + "/" + userRuleFile)))
        .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }?["id"] as? String
    if locateRuleJSON(byId: userRuleID ?? ruleId, inDir: supportDir + "/compiled_rules") != nil {
        return .queue("Queued removal of user rule \(ruleId), which has the same id as a bundled rule."
            + " After the next reload (~5 s) the engine uses the bundled rule instead.")
    }
    return .queue("Queued removal of user rule \(ruleId). The engine drops it on the next reload (~5 s).")
}

// MARK: - rule severity

private func ruleSeverity(args: [String]) {
    guard args.count >= 2 else {
        print("Usage: maccrabctl rule severity <id> <level>")
        print("  level: critical | high | medium | low | informational | default")
        exit(1)
    }
    let ruleId = args[0]
    let levelRaw = args[1].lowercased()

    guard ruleId.count <= 128, !ruleId.contains("/"), !ruleId.contains("..") else {
        print("Invalid rule id (no '/' or '..', max 128 chars).")
        exit(1)
    }

    // "default" clears any override (only meaningful for built-ins).
    let clearing = (levelRaw == "default" || levelRaw == "clear")
    if !clearing, Severity(rawValue: levelRaw) == nil {
        print("'\(args[1])' is not a valid level. Use one of: critical, high, medium, low, informational (or 'default' to clear).")
        exit(1)
    }

    if ruleId.hasPrefix("maccrab.") {
        ruleSeverityBuiltin(ruleId: ruleId, levelRaw: levelRaw, clearing: clearing)
    } else {
        guard !clearing else {
            print("'default' only applies to built-in maccrab.* rules. For a user rule, set an explicit level.")
            exit(1)
        }
        ruleSeverityUser(ruleId: ruleId, level: levelRaw)
    }
}

/// Built-in path — mirror handleSetBuiltinRuleSetting: queue a
/// `builtin-rule-setting` request with `severityOverride` (NSNull clears).
private func ruleSeverityBuiltin(ruleId: String, levelRaw: String, clearing: Bool) {
    var payload: [String: Any] = ["ruleId": ruleId]
    payload["severityOverride"] = clearing ? NSNull() : levelRaw
    if let err = dropCtlInboxRequest(verb: "builtin-rule-setting", payload: payload) {
        print("Could not queue severity override: \(err)")
        exit(1)
    }
    if clearing {
        print("Queued severity override clear for \(ruleId) (reverts to catalog default).")
    } else {
        print("Queued severity override for \(ruleId): \(levelRaw).")
    }
    print("The engine applies it within ~5 s; detection still runs as before.")
}

/// User-rule path — read the rule's compiled JSON, refuse sequence/graph,
/// set its `level`, and re-install via the `install-rule` inbox verb
/// (json-only is accepted by the daemon's install handler).
private func ruleSeverityUser(ruleId: String, level: String) {
    let fm = FileManager.default
    let supportDir = maccrabDataDir()

    // The daemon sanitizes the install/remove id to a [a-z0-9-_] basename
    // (DaemonTimers.safeRuleBasename); the on-disk file is named accordingly.
    let basename = safeUserRuleBasename(ruleId)
    guard let basename else {
        print("Invalid user rule id.")
        exit(1)
    }

    // Locate the rule JSON: user_rules/<basename>.json (where the engine
    // writes installed user rules), else scan compiled_rules/ for a rule
    // whose "id" matches (handles ids that aren't a clean basename).
    let userRuleJSON = supportDir + "/user_rules/\(basename).json"
    var jsonPath: String? = fm.fileExists(atPath: userRuleJSON) ? userRuleJSON : nil
    if jsonPath == nil {
        jsonPath = locateRuleJSON(byId: ruleId, inDir: supportDir + "/compiled_rules")
            ?? locateRuleJSON(byId: ruleId, inDir: supportDir + "/user_rules")
    }
    guard let jsonPath else {
        print("User rule '\(ruleId)' not found under \(supportDir)/user_rules or compiled_rules.")
        print("Use `maccrabctl rules list` to find the rule id. (Built-in maccrab.* rules use the same command.)")
        exit(1)
    }

    guard let data = try? Data(contentsOf: URL(fileURLWithPath: jsonPath)),
          var json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        print("Could not read rule JSON at \(jsonPath).")
        exit(1)
    }

    // Refuse multi-step (sequence) and multi-entity (graph) rules — they are
    // not single-event `level` rules; severity is set in their own YAML.
    if isSequenceOrGraphRule(json) {
        print("Rule '\(ruleId)' is a sequence or graph rule — its severity can't be set with this command.")
        print("Edit the rule's YAML in Rules/sequences or Rules/graph and recompile.")
        exit(1)
    }

    let previous = (json["level"] as? String) ?? "?"
    json["level"] = level

    guard JSONSerialization.isValidJSONObject(json),
          let rewritten = try? JSONSerialization.data(withJSONObject: json, options: [.sortedKeys]),
          let jsonText = String(data: rewritten, encoding: .utf8) else {
        print("Could not serialize updated rule JSON.")
        exit(1)
    }

    // Re-install via the privileged inbox (json-only). The daemon overwrites
    // user_rules/<basename>.json and bumps the reload tick.
    let payload: [String: Any] = ["ruleId": ruleId, "json": jsonText]
    if let err = dropCtlInboxRequest(verb: "install-rule", payload: payload) {
        print("Could not queue severity change: \(err)")
        exit(1)
    }
    print("Queued severity change for user rule \(ruleId): \(previous) → \(level).")
    print("The engine reloads it within ~5 s.")
}

// MARK: - helpers

/// Find a rule JSON in `dir` whose top-level "id" == ruleId. Returns the
/// full path or nil. Skips manifest.json.
private func locateRuleJSON(byId ruleId: String, inDir dir: String) -> String? {
    let fm = FileManager.default
    guard let files = try? fm.contentsOfDirectory(atPath: dir) else { return nil }
    for file in files where file.hasSuffix(".json") && file != "manifest.json" {
        let path = dir + "/" + file
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              (json["id"] as? String) == ruleId else { continue }
        return path
    }
    return nil
}

/// A sequence rule carries `steps`; a graph rule carries graph structure
/// (`nodes` / `entities` / `graph`) or a `type` of sequence/graph.
private func isSequenceOrGraphRule(_ json: [String: Any]) -> Bool {
    if json["steps"] != nil { return true }
    if json["nodes"] != nil || json["entities"] != nil || json["graph"] != nil { return true }
    if let t = (json["type"] as? String)?.lowercased(), t == "sequence" || t == "graph" {
        return true
    }
    return false
}

/// Mirror DaemonTimers.safeRuleBasename: lowercased, [a-z0-9-_] only,
/// non-empty, ≤128. Returns nil if nothing survives.
func safeUserRuleBasename(_ raw: String) -> String? {
    let allowed = Set("abcdefghijklmnopqrstuvwxyz0123456789-_")
    let s = String(raw.lowercased().filter { allowed.contains($0) })
    guard !s.isEmpty, s.count <= 128 else { return nil }
    return s
}

// MARK: - shared inbox drop (used by ConfigCommands + RuleMutateCommands)

/// Drop a request into the privileged inbox the engine polls. Mirrors
/// AgentControl.swift::dropInboxRequest (atomic temp-then-rename so the
/// daemon's lstat gate never races a partial file). Returns nil on success
/// or an error string. The daemon authorizes by file-owner uid and
/// re-validates the payload — this is a queue, not a trusted command.
func dropCtlInboxRequest(verb: String, payload: [String: Any]) -> String? {
    let inboxDir: String
    do {
        inboxDir = try requestInboxDirectory()
    } catch {
        return error.localizedDescription
    }
    let fm = FileManager.default
    guard JSONSerialization.isValidJSONObject(payload),
          let data = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]) else {
        return "could not serialize request payload"
    }
    let reqId = UUID().uuidString
    let finalPath = inboxDir + "/\(verb)-\(reqId).json"
    let tmpPath = inboxDir + "/.\(verb)-\(reqId).tmp"
    do {
        try data.write(to: URL(fileURLWithPath: tmpPath))
    } catch {
        return "could not write request: \(error.localizedDescription)"
    }
    let ok = tmpPath.withCString { src in finalPath.withCString { dst in rename(src, dst) == 0 } }
    guard ok else {
        try? fm.removeItem(atPath: tmpPath)
        return "could not place request in inbox: \(String(cString: strerror(errno)))"
    }
    return nil
}
