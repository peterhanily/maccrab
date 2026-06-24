// ResponseCommands.swift
// maccrabctl
//
// `maccrabctl actions list | set | delete` — operator-facing CLI to view and
// configure per-rule (and default) response actions. SECURITY-CRITICAL: these
// edits steer what the ROOT engine does when a rule fires (kill / quarantine /
// blockNetwork / script). This command reads and writes the SAME `actions.json`
// the dashboard's Response Actions tab uses, and after a mutating change drops
// a `reload-rules` request into the privileged inbox (the file-IPC channel the
// System Extension polls) — NOT pkill, because a uid-501 user process cannot
// signal the uid-0 sysext (EPERM). The inbox `reload-rules` verb raises SIGHUP
// to the engine, whose SIGHUP handler re-reads actions.json.
//
// Schema parity: the file is { "defaults": [Entry], "rules": { ruleId: [Entry] } }
// where Entry = { action, minimumSeverity, scriptPath?, requireConfirmation?,
// blockDurationSeconds? }. This mirrors the dashboard's ActionEntry / ActionConfig
// (ResponseActionsView.swift) and decodes against MacCrabCore's ActionConfigFile.
//
// requireConfirmation defaults TRUE for the destructive actions
// (kill / quarantine / blockNetwork) — the safer default you opt OUT of with
// --no-confirm, matching the dashboard editor's DEFAULT_REQUIRE_CONFIRM.

import Foundation
import os
import MacCrabCore

/// Audit sink for state-modifying response-action operations. Same os.log
/// `.notice`/"AUDIT" convention the case + MCP suppress handlers use.
private let actionsAuditLogger = Logger(subsystem: "com.maccrab.ctl", category: "actions-audit")

/// Actions whose auto-execution is destructive — default requireConfirmation to
/// true on `set` unless the operator passes --no-confirm. Mirrors the dashboard's
/// DEFAULT_REQUIRE_CONFIRM.
private let actionsRequireConfirmByDefault: Set<String> = ["kill", "quarantine", "blockNetwork"]

/// All accepted action verbs (== ResponseActionType raw values).
private let actionsValidActions: Set<String> = [
    "log", "notify", "kill", "quarantine", "script", "blockNetwork", "escalateNotification",
]

private let actionsValidSeverities: Set<String> = ["critical", "high", "medium", "low", "informational"]

// MARK: - JSON model (mirrors the dashboard's ActionEntry / ActionConfig)

/// One response action. `Codable`; nil optionals are omitted on encode so the
/// file stays byte-compatible with what the dashboard writes.
private struct ActionEntryJSON: Codable {
    var action: String
    var minimumSeverity: String
    var scriptPath: String?
    var requireConfirmation: Bool?
    var blockDurationSeconds: Int?
}

private struct ActionConfigJSON: Codable {
    var defaults: [ActionEntryJSON]
    var rules: [String: [ActionEntryJSON]]

    init(defaults: [ActionEntryJSON] = [], rules: [String: [ActionEntryJSON]] = [:]) {
        self.defaults = defaults
        self.rules = rules
    }
}

// MARK: - Dispatch

/// Dispatch `maccrabctl actions <subcommand> ...`. Called from MacCrabCtl.main
/// when args[1] == "actions".
func dispatchActions(args: [String]) async {
    guard let sub = args.first else {
        printActionsUsage()
        exit(0)
    }
    let rest = Array(args.dropFirst())
    do {
        switch sub {
        case "list":
            try actionsList(args: rest)
        case "set":
            try actionsSet(args: rest)
        case "delete":
            try actionsDelete(args: rest)
        case "help", "-h", "--help":
            printActionsUsage()
        default:
            print("Unknown actions subcommand: \(sub)")
            printActionsUsage()
            exit(1)
        }
    } catch let CaseCommandError.usage(msg) {
        print(msg)
        exit(1)
    } catch let CaseCommandError.underlying(msg) {
        print("Error: \(msg)")
        exit(1)
    } catch {
        print("Error: \(error)")
        exit(1)
    }
}

func printActionsUsage() {
    print("""
    Usage: maccrabctl actions <subcommand>

    View and configure response actions — what the engine does when a rule fires
    (kill / quarantine / blockNetwork / script / notify / escalateNotification).
    Edits the same actions.json the dashboard's Response Actions tab uses, then
    queues a rule reload so the engine picks it up within ~5 s.

    Subcommands:
      list                                List default + per-rule response actions.

      set [--rule <ruleId>] --action <a> [--min-severity <sev>]
          [--script <path>] [--confirm | --no-confirm]
          [--block-duration <seconds>]
                                          Add a response action. Omit --rule to add
                                          a DEFAULT action (applies to all rules).
                                          Re-running with the same --rule + --action
                                          replaces that action's settings.
                                          Destructive actions (kill, quarantine,
                                          blockNetwork) default to requiring operator
                                          confirmation; use --no-confirm to opt out.

      delete [--rule <ruleId>] [--action <a>]
                                          Remove actions. With --rule + --action,
                                          removes just that action. With --rule only,
                                          removes all actions for that rule. With
                                          --action only, removes that action from the
                                          defaults. With neither, errors.

    Action verbs:    log, notify, kill, quarantine, script, blockNetwork, escalateNotification
    Severities:      critical, high, medium, low, informational  (default: high)

    SECURITY: kill / quarantine / blockNetwork auto-execute against the process
    or file that tripped the rule. Default to confirmation-gated unless you pass
    --no-confirm. Edits take effect on the engine's next reload (~5 s).
    """)
}

// MARK: - Paths

/// READ path: prefer the system-installed actions.json when it is readable and
/// at least as recent as the user-home copy (the engine prefers the most-recent
/// of the two), else the user-home copy. Mirrors the dashboard + ResponseEngine
/// loader so `list` reflects what the engine actually loaded.
private func actionsReadPath() -> String {
    let fm = FileManager.default
    let userPath = maccrabUserWritableDataDir() + "/actions.json"
    let systemPath = "/Library/Application Support/MacCrab/actions.json"
    let systemReadable = fm.isReadableFile(atPath: systemPath)
    let userExists = fm.fileExists(atPath: userPath)
    if systemReadable && userExists {
        let s = (try? fm.attributesOfItem(atPath: systemPath))?[.modificationDate] as? Date
        let u = (try? fm.attributesOfItem(atPath: userPath))?[.modificationDate] as? Date
        if let s, let u, s >= u { return systemPath }
        return userPath
    }
    if systemReadable { return systemPath }
    return userPath
}

/// WRITE path: ALWAYS the user-home data dir. The CLI runs as uid 501 and cannot
/// write the root-owned system dir (the try? would silently swallow EPERM). The
/// engine overlays user-home on top of system on reload, so user writes activate.
private func actionsWritePath() -> String {
    maccrabUserWritableDataDir() + "/actions.json"
}

// MARK: - Load / save

private func loadActionsConfig() throws -> ActionConfigJSON {
    let path = actionsReadPath()
    guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
        // No file yet — start from empty (engine falls back to its built-in
        // defaults when actions.json is absent).
        return ActionConfigJSON()
    }
    do {
        return try JSONDecoder().decode(ActionConfigJSON.self, from: data)
    } catch {
        throw CaseCommandError.underlying("could not parse \(path): \(error.localizedDescription)")
    }
}

/// Atomic write to the user-home actions.json, then queue a reload. Mirrors the
/// dashboard's tmp-write + move, but reloads via the inbox (uid-501 can't HUP
/// the root sysext).
private func saveActionsConfig(_ config: ActionConfigJSON) throws {
    let path = actionsWritePath()
    let dir = (path as NSString).deletingLastPathComponent
    let fm = FileManager.default
    try? fm.createDirectory(atPath: dir, withIntermediateDirectories: true)

    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    let data: Data
    do {
        data = try encoder.encode(config)
    } catch {
        throw CaseCommandError.underlying("could not encode config: \(error.localizedDescription)")
    }
    let tmp = path + ".tmp"
    do {
        try data.write(to: URL(fileURLWithPath: tmp))
        _ = try? fm.removeItem(atPath: path)
        try fm.moveItem(atPath: tmp, toPath: path)
    } catch {
        try? fm.removeItem(atPath: tmp)
        throw CaseCommandError.underlying("could not write \(path): \(error.localizedDescription)")
    }
}

/// Drop a `reload-rules` request into the engine's privileged inbox. The inbox
/// poller authorizes by file-owner uid and raises SIGHUP to the engine, whose
/// SIGHUP handler re-reads actions.json (and rules). Same channel `intel refresh`
/// uses. Returns true if the request was queued.
@discardableResult
private func queueActionsReload() -> Bool {
    let inboxDir = maccrabDataDir() + "/inbox"
    let fm = FileManager.default
    if !fm.fileExists(atPath: inboxDir) {
        try? fm.createDirectory(atPath: inboxDir, withIntermediateDirectories: true)
    }
    let path = inboxDir + "/reload-rules-\(UUID().uuidString).json"
    let payload: [String: Any] = [
        "requestedAt": ISO8601DateFormatter().string(from: Date()),
        "source": "maccrabctl-actions",
    ]
    guard let data = try? JSONSerialization.data(withJSONObject: payload) else { return false }
    return (try? data.write(to: URL(fileURLWithPath: path), options: .atomic)) != nil
}

// MARK: - Subcommands

private func actionsList(args: [String]) throws {
    let config = try loadActionsConfig()

    if config.defaults.isEmpty && config.rules.isEmpty {
        print("No actions.json found (or it is empty). The engine is using its built-in defaults.")
        print("Add one with: maccrabctl actions set --action notify --min-severity high")
        return
    }

    print("Default actions (apply to all rules unless a per-rule entry overrides):")
    if config.defaults.isEmpty {
        print("  (none)")
    } else {
        for e in config.defaults { print("  " + formatActionLine(e)) }
    }
    print("")
    print("Per-rule actions:")
    if config.rules.isEmpty {
        print("  (none)")
    } else {
        for ruleId in config.rules.keys.sorted() {
            print("  \(ruleId):")
            for e in config.rules[ruleId] ?? [] { print("    " + formatActionLine(e)) }
        }
    }
}

private func formatActionLine(_ e: ActionEntryJSON) -> String {
    var parts = ["\(e.action) (min=\(e.minimumSeverity))"]
    if let sp = e.scriptPath { parts.append("script=\(sp)") }
    if let d = e.blockDurationSeconds { parts.append("block-duration=\(d)s") }
    // Show the EFFECTIVE confirmation gate: nil decodes as false in the engine,
    // so an unset flag means auto-execute.
    let confirm = e.requireConfirmation ?? false
    parts.append(confirm ? "confirm=required" : "confirm=no (auto-executes)")
    return parts.joined(separator: "  ")
}

private func actionsSet(args: [String]) throws {
    var ruleId: String? = nil
    var action: String? = nil
    var minSeverity = "high"
    var scriptPath: String? = nil
    var blockDuration: Int? = nil
    var confirmExplicit: Bool? = nil  // nil = use per-action default

    var i = 0
    while i < args.count {
        switch args[i] {
        case "--rule" where i + 1 < args.count:
            ruleId = args[i + 1]; i += 2
        case "--action" where i + 1 < args.count:
            action = args[i + 1]; i += 2
        case "--min-severity" where i + 1 < args.count:
            minSeverity = args[i + 1]; i += 2
        case "--script" where i + 1 < args.count:
            scriptPath = args[i + 1]; i += 2
        case "--block-duration" where i + 1 < args.count:
            blockDuration = Int(args[i + 1]); i += 2
        case "--confirm":
            confirmExplicit = true; i += 1
        case "--no-confirm":
            confirmExplicit = false; i += 1
        default:
            i += 1
        }
    }

    guard let action else {
        throw CaseCommandError.usage("Usage: maccrabctl actions set [--rule <ruleId>] --action <a> [--min-severity <sev>] [--script <path>] [--confirm | --no-confirm] [--block-duration <s>]")
    }
    guard actionsValidActions.contains(action) else {
        throw CaseCommandError.underlying("invalid --action '\(action)'. Valid: \(actionsValidActions.sorted().joined(separator: ", "))")
    }
    guard actionsValidSeverities.contains(minSeverity) else {
        throw CaseCommandError.underlying("invalid --min-severity '\(minSeverity)'. Valid: \(actionsValidSeverities.sorted().joined(separator: ", "))")
    }
    if action == "script" && (scriptPath == nil || scriptPath?.isEmpty == true) {
        throw CaseCommandError.underlying("--action script requires --script <path>")
    }

    // requireConfirmation: explicit flag wins; otherwise destructive actions
    // default to TRUE (the safer default), everything else to nil (omitted).
    let requireConfirmation: Bool?
    if let explicit = confirmExplicit {
        requireConfirmation = explicit ? true : nil
    } else {
        requireConfirmation = actionsRequireConfirmByDefault.contains(action) ? true : nil
    }

    let entry = ActionEntryJSON(
        action: action,
        minimumSeverity: minSeverity,
        scriptPath: scriptPath,
        requireConfirmation: requireConfirmation,
        blockDurationSeconds: blockDuration
    )

    var config = try loadActionsConfig()
    // Replace-by-(rule,action): editing the same action's settings is idempotent
    // rather than appending duplicates.
    if let ruleId {
        var list = config.rules[ruleId] ?? []
        list.removeAll { $0.action == action }
        list.append(entry)
        config.rules[ruleId] = list
    } else {
        config.defaults.removeAll { $0.action == action }
        config.defaults.append(entry)
    }

    try saveActionsConfig(config)
    actionsAuditLogger.notice("CTL AUDIT: actions_set — user=\(NSUserName(), privacy: .public) pid=\(getpid()) rule=\(ruleId ?? "(default)", privacy: .public) action=\(action, privacy: .public) confirm=\(requireConfirmation ?? false)")

    let target = ruleId.map { "rule \($0)" } ?? "default actions"
    let confirmNote = (requireConfirmation ?? false)
        ? "  (operator confirmation REQUIRED — will not auto-execute)"
        : (actionsRequireConfirmByDefault.contains(action) ? "  (auto-executes — confirmation explicitly disabled)" : "")
    print("Set \(action) (min=\(minSeverity)) on \(target).\(confirmNote)")
    if queueActionsReload() {
        print("Queued a rule reload — the engine applies it within ~5 s.")
    } else {
        print("Saved, but could not queue a reload (the engine may not be running, or this shell can't write its inbox).")
        print("The engine will pick it up on its next start or SIGHUP.")
    }
}

private func actionsDelete(args: [String]) throws {
    var ruleId: String? = nil
    var action: String? = nil
    var i = 0
    while i < args.count {
        switch args[i] {
        case "--rule" where i + 1 < args.count:
            ruleId = args[i + 1]; i += 2
        case "--action" where i + 1 < args.count:
            action = args[i + 1]; i += 2
        default:
            i += 1
        }
    }
    guard ruleId != nil || action != nil else {
        throw CaseCommandError.usage("Usage: maccrabctl actions delete [--rule <ruleId>] [--action <a>] (need at least one of --rule / --action)")
    }

    var config = try loadActionsConfig()
    var removed = 0
    let describe: String

    if let ruleId, let action {
        var list = config.rules[ruleId] ?? []
        let before = list.count
        list.removeAll { $0.action == action }
        removed = before - list.count
        if list.isEmpty { config.rules.removeValue(forKey: ruleId) }
        else { config.rules[ruleId] = list }
        describe = "\(action) from rule \(ruleId)"
    } else if let ruleId {
        removed = config.rules[ruleId]?.count ?? 0
        config.rules.removeValue(forKey: ruleId)
        describe = "all actions for rule \(ruleId)"
    } else {
        let action = action!
        let before = config.defaults.count
        config.defaults.removeAll { $0.action == action }
        removed = before - config.defaults.count
        describe = "\(action) from default actions"
    }

    guard removed > 0 else {
        print("Nothing to delete (\(describe) not found).")
        return
    }

    try saveActionsConfig(config)
    actionsAuditLogger.notice("CTL AUDIT: actions_delete — user=\(NSUserName(), privacy: .public) pid=\(getpid()) rule=\(ruleId ?? "(default)", privacy: .public) action=\(action ?? "(all)", privacy: .public) removed=\(removed)")

    print("Removed \(describe) (\(removed) entr\(removed == 1 ? "y" : "ies")).")
    if queueActionsReload() {
        print("Queued a rule reload — the engine applies it within ~5 s.")
    } else {
        print("Saved, but could not queue a reload (the engine may not be running).")
    }
}
