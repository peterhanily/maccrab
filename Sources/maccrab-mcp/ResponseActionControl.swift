// ResponseActionControl.swift
// maccrab-mcp
//
// MCP parity for `maccrabctl actions`: read + tune the response-action config
// (actions.json) that steers what the ROOT engine does when a rule fires.
//
// SECURITY-CRITICAL. `set_response_action` is a DEFENSE-AFFECTING mutation —
// it can arm kill / quarantine / blockNetwork against the process or file that
// trips a rule — so it is gated at the top `.response` tier in
// AgentControl.swift's agentToolCapability map. (The map FAILS OPEN, so a
// missing entry would silently bypass the gate; the fail-open guard test pins
// the gated set.) `list_response_actions` is read-only and ungated.
//
// Like the dashboard + CLI, we WRITE the user-home actions.json (the MCP runs
// as uid 501 and cannot write the root-owned system dir) and queue a reload via
// the privileged inbox `reload-rules` verb — whose handler raises SIGHUP to the
// engine, which re-reads actions.json. We never write engine state directly.

import Foundation

// MARK: - JSON model (mirrors the dashboard's ActionEntry / ActionConfig)

private struct MCPActionEntry: Codable {
    var action: String
    var minimumSeverity: String
    var scriptPath: String?
    var requireConfirmation: Bool?
    var blockDurationSeconds: Int?
}

private struct MCPActionConfig: Codable {
    var defaults: [MCPActionEntry]
    var rules: [String: [MCPActionEntry]]

    init(defaults: [MCPActionEntry] = [], rules: [String: [MCPActionEntry]] = [:]) {
        self.defaults = defaults
        self.rules = rules
    }
}

private let mcpResponseValidActions: Set<String> = [
    "log", "notify", "kill", "quarantine", "script", "blockNetwork", "escalateNotification",
]
private let mcpResponseValidSeverities: Set<String> = ["critical", "high", "medium", "low", "informational"]
/// Destructive actions default requireConfirmation to true (the safer default).
private let mcpResponseConfirmByDefault: Set<String> = ["kill", "quarantine", "blockNetwork"]

/// The root-managed dirs the ROOT engine will execute response scripts from
/// (mirrors ResponseAction.scriptAllowlistedDirs). A script anywhere else is
/// rejected by the engine at exec time; we reject it here at WRITE time too so
/// the MCP never persists an actions.json the engine would silently refuse.
private let mcpScriptAllowlistedDirs: [String] = [
    "/Library/Application Support/MacCrab/scripts/",
    "/usr/local/maccrab/scripts/",
]

/// Belt-and-suspenders server-side validation for `set_response_action`'s
/// `script_path`. The tool wrote whatever the client sent and relied entirely on
/// the engine's downstream enforcement (client-honesty). Reject here anything
/// the engine would never run: a non-absolute path, or a path outside the two
/// root-managed script dirs. We deliberately do NOT check ownership / existence
/// / symlink here — the script may be installed after this config is written,
/// and only the ROOT engine (ResponseAction.validateScriptPath, which also
/// enforces root:owner + no group/world-write + no-symlink at exec time) can
/// authoritatively lstat it. Standardizes first to defeat `..` traversal.
private func mcpValidateScriptPath(_ path: String) -> Bool {
    guard path.hasPrefix("/") else { return false }            // absolute only
    let canonical = URL(fileURLWithPath: path).standardizedFileURL.path  // defeat ..
    return mcpScriptAllowlistedDirs.contains { canonical.hasPrefix($0) }
}

// MARK: - Paths

/// READ path: prefer the system actions.json when readable + at least as recent
/// as the user copy (mirrors the engine's loader), else the user copy.
private func mcpActionsReadPath() -> String {
    let fm = FileManager.default
    let userPath = mcpUserWritableDataDir() + "/actions.json"
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

/// WRITE path: ALWAYS the user-home data dir (uid 501 cannot write the root dir).
private func mcpActionsWritePath() -> String {
    mcpUserWritableDataDir() + "/actions.json"
}

/// The user-domain MacCrab dir, ALWAYS. `dataDir` (resolveDataDir) prefers the
/// root system dir when its events.db is newer — correct for READING engine
/// state, wrong for client-owned writes that would silently EPERM there.
private func mcpUserWritableDataDir() -> String {
    FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)
        .first.map { $0.appendingPathComponent("MacCrab").path }
        ?? NSHomeDirectory() + "/Library/Application Support/MacCrab"
}

// MARK: - Load / save

/// Error wrapper so the load result's failure type conforms to `Error`
/// (Swift's Result requires it; a bare String does not conform).
private struct MCPActionConfigError: Error { let message: String }

private func mcpLoadActionsConfig() -> Result<MCPActionConfig, MCPActionConfigError> {
    let path = mcpActionsReadPath()
    guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
        return .success(MCPActionConfig())  // absent → engine uses built-in defaults
    }
    do { return .success(try JSONDecoder().decode(MCPActionConfig.self, from: data)) }
    catch { return .failure(MCPActionConfigError(message: "could not parse \(path): \(error.localizedDescription)")) }
}

private func mcpSaveActionsConfig(_ config: MCPActionConfig) -> String? {
    let path = mcpActionsWritePath()
    let dir = (path as NSString).deletingLastPathComponent
    let fm = FileManager.default
    try? fm.createDirectory(atPath: dir, withIntermediateDirectories: true)
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    guard let data = try? encoder.encode(config) else { return "could not encode config" }
    let tmp = path + ".tmp"
    do {
        try data.write(to: URL(fileURLWithPath: tmp))
        _ = try? fm.removeItem(atPath: path)
        try fm.moveItem(atPath: tmp, toPath: path)
    } catch {
        try? fm.removeItem(atPath: tmp)
        return "could not write \(path): \(error.localizedDescription)"
    }
    return nil
}

// MARK: - Read-only: list_response_actions

func handleListResponseActions() -> Any {
    switch mcpLoadActionsConfig() {
    case .failure(let err):
        return toolError(err.message)
    case .success(let config):
        if config.defaults.isEmpty && config.rules.isEmpty {
            return ["content": [["type": "text", "text": "No actions.json configured; the engine is using its built-in default response actions. Add one with set_response_action."]]]
        }
        var lines = ["Response actions (what the engine does when a rule fires):", "", "Default actions (apply to all rules unless overridden):"]
        if config.defaults.isEmpty { lines.append("  (none)") }
        else { for e in config.defaults { lines.append("  " + mcpFormatActionLine(e)) } }
        lines.append("")
        lines.append("Per-rule actions:")
        if config.rules.isEmpty { lines.append("  (none)") }
        else {
            for ruleId in config.rules.keys.sorted() {
                lines.append("  \(ruleId):")
                for e in config.rules[ruleId] ?? [] { lines.append("    " + mcpFormatActionLine(e)) }
            }
        }
        return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
    }
}

private func mcpFormatActionLine(_ e: MCPActionEntry) -> String {
    var parts = ["\(e.action) (min=\(e.minimumSeverity))"]
    if let sp = e.scriptPath { parts.append("script=\(sp)") }
    if let d = e.blockDurationSeconds { parts.append("block-duration=\(d)s") }
    let confirm = e.requireConfirmation ?? false
    parts.append(confirm ? "confirm=required" : "confirm=no (auto-executes)")
    return parts.joined(separator: "  ")
}

// MARK: - Mutating: set_response_action (.response tier)

func handleSetResponseAction(_ args: [String: Any]) -> Any {
    guard let action = args["action"] as? String, mcpResponseValidActions.contains(action) else {
        return toolError("'action' is required and must be one of: \(mcpResponseValidActions.sorted().joined(separator: ", "))")
    }
    let minSeverity = (args["min_severity"] as? String) ?? "high"
    guard mcpResponseValidSeverities.contains(minSeverity) else {
        return toolError("'min_severity' must be one of: \(mcpResponseValidSeverities.sorted().joined(separator: ", "))")
    }
    let scriptPath = args["script_path"] as? String
    if action == "script" && (scriptPath == nil || scriptPath?.isEmpty == true) {
        return toolError("action 'script' requires 'script_path'")
    }
    // Server-side validation (don't trust the client / rely solely on the engine):
    // any script_path we persist must be an absolute path under a root-managed
    // script dir the engine will actually execute from — otherwise the arming is
    // a silent no-op at best and a misdirection at worst.
    if let sp = scriptPath, !sp.isEmpty, !mcpValidateScriptPath(sp) {
        return toolError("'script_path' must be an absolute path under a root-managed scripts dir (\(mcpScriptAllowlistedDirs.joined(separator: " or "))). The ROOT engine only executes scripts that live there and are owned by root with no group/world-write, so a path elsewhere would never run.")
    }
    let blockDuration = args["block_duration_seconds"] as? Int
    let ruleId = (args["rule_id"] as? String).flatMap { $0.isEmpty ? nil : $0 }

    // requireConfirmation: explicit 'require_confirmation' wins; else destructive
    // actions default to true. Encoded as nil (omitted) when false, matching the
    // dashboard's on-disk shape (the engine treats absent as false).
    let requireConfirmation: Bool?
    if let explicit = args["require_confirmation"] as? Bool {
        requireConfirmation = explicit ? true : nil
    } else {
        requireConfirmation = mcpResponseConfirmByDefault.contains(action) ? true : nil
    }

    let entry = MCPActionEntry(
        action: action,
        minimumSeverity: minSeverity,
        scriptPath: scriptPath,
        requireConfirmation: requireConfirmation,
        blockDurationSeconds: blockDuration
    )

    var config: MCPActionConfig
    switch mcpLoadActionsConfig() {
    case .failure(let err): return toolError(err.message)
    case .success(let c): config = c
    }
    // Replace-by-(rule,action) so editing settings is idempotent.
    if let ruleId {
        var list = config.rules[ruleId] ?? []
        list.removeAll { $0.action == action }
        list.append(entry)
        config.rules[ruleId] = list
    } else {
        config.defaults.removeAll { $0.action == action }
        config.defaults.append(entry)
    }

    if let err = mcpSaveActionsConfig(config) { return toolError(err) }
    auditLog("set_response_action", details: "rule=\(ruleId ?? "(default)") action=\(action) confirm=\(requireConfirmation ?? false) ppid=\(getppid())")

    // Reload via the inbox reload-rules verb (uid-501 can't HUP the root sysext).
    if let err = dropInboxRequest(verb: "reload-rules", payload: ["requestedAt": isoFormatter.string(from: Date()), "source": "mcp-set-response-action"]) {
        return ["content": [["type": "text", "text": "Saved \(action) on \(ruleId ?? "default actions"), but could not queue a reload: \(err). The engine will pick it up on its next start / SIGHUP."]]]
    }
    let confirmNote = (requireConfirmation ?? false)
        ? " Operator confirmation is REQUIRED — it will not auto-execute."
        : (mcpResponseConfirmByDefault.contains(action) ? " Confirmation was explicitly disabled — this auto-executes." : "")
    return ["content": [["type": "text", "text": "Set \(action) (min=\(minSeverity)) on \(ruleId.map { "rule \($0)" } ?? "default actions").\(confirmNote) Queued a rule reload; the engine applies it within ~5 s."]]]
}
