// AgentControl.swift
// maccrab-mcp
//
// v1.18: the agent control-plane that turns MacCrab's MCP server into a
// customizable "skill" — a Claude/Codex session can tune detection, author
// rules, and adjust defense-affecting config.
//
// SAFETY MODEL — everything here is OFF BY DEFAULT.
//   Capabilities live in the ROOT-OWNED
//   `/Library/Application Support/MacCrab/mcp_capabilities.json`:
//     { "config": false, "authoring": false, "response": false }
//   A missing / non-root-owned file (the default) means ALL mutation is denied;
//   the agent can still read. The human sets grants in the dashboard (Settings →
//   Agent Control), which routes the choice through the privileged inbox so the
//   ROOT engine writes the file. The MCP trusts the file ONLY because it is
//   root-owned — an agent runs as the console user and cannot create a
//   root-owned file, so it can never grant itself power, and there is no MCP
//   tool that enables a capability.
//
//   Three tiers, escalating:
//     • config    — tune detection: built-in rule settings, reload, refresh
//                   intel, safe daemon tunables (thresholds / poll intervals).
//     • authoring — create / delete detection rules.
//     • response  — flip DEFENSE-AFFECTING config (ES introspection / file-open
//                   subscriptions, ultrasonic). Disabling these reduces
//                   coverage, so they require the top tier.
//
//   Every mutation goes through the privileged inbox IPC (uid + symlink/
//   hardlink gated, audit-logged by the daemon) — the same path the dashboard
//   uses. Nothing here writes engine state directly. Response actions are
//   untouched: they still never auto-execute.

import Foundation
import MacCrabCore

enum AgentCapability: String {
    case config
    case authoring
    case response
}

/// Read the human-set capability grants. Missing / unreadable / malformed /
/// not-root-owned → all-denied (safe default). Never cached: each call re-reads
/// so a human revoking a tier takes effect immediately.
///
/// SECURITY (the load-bearing invariant): the grants file is trusted ONLY when
/// it is a regular file owned by root (uid 0) at the system support dir. The
/// human enables tiers in the dashboard, which routes through the privileged
/// inbox so the ROOT engine writes this file. An agent runs as the console user
/// (uid 501) and CANNOT create a root-owned file anywhere, so it cannot grant
/// itself a capability — even though it can write into its own user-home dir.
/// We `lstat` (rejecting a symlink an agent could point at a root file) and
/// require st_uid == 0.
func loadAgentCapabilities() -> Set<AgentCapability> {
    let path = "/Library/Application Support/MacCrab/mcp_capabilities.json"
    var st = stat()
    guard lstat(path, &st) == 0,
          (st.st_mode & S_IFMT) == S_IFREG,   // a regular file, not a symlink/dir
          st.st_uid == 0                       // written by the root engine only
    else { return [] }
    guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
          let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    else { return [] }
    var granted: Set<AgentCapability> = []
    for cap in [AgentCapability.config, .authoring, .response] {
        if (json[cap.rawValue] as? Bool) == true { granted.insert(cap) }
    }
    return granted
}

/// Tool → required capability. Tools not listed are read-only and always
/// allowed (subject to the MCP transport's own scoping).
///
/// NOTE (the load-bearing trap): this map FAILS OPEN — `agentCapabilityDenial`
/// returns nil (allow) for any tool not listed here. So EVERY new mutating MCP
/// tool MUST be added below, or it silently bypasses the capability gate.
let agentToolCapability: [String: AgentCapability] = [
    "set_builtin_rule_setting": .config,
    "reload_rules": .config,
    "refresh_threat_intel": .config,
    "set_daemon_config": .config,        // defense-affecting keys re-checked → .response
    "create_rule": .authoring,
    "delete_rule": .authoring,
    // Suppressing an alert/campaign hides findings — a defense-degrading
    // action — so it requires the top tier, like other coverage-reducing
    // changes. Without this, an agent with ZERO granted tiers (the secure
    // default) could still suppress up to the per-session budget.
    "suppress_alert": .response,
    "suppress_campaign": .response,
    // Arming a response action (kill / quarantine / blockNetwork) is the most
    // defense-affecting agent mutation, so it sits at the top tier. The map
    // FAILS OPEN — any set_-prefixed tool absent here bypasses the gate — so
    // this entry is load-bearing (and pinned by mutatingToolsAreGated).
    "set_response_action": .response,
    // Updating an installed plugin replaces executable code on disk (via the
    // verified install path). Forward-only + signer-pinned, but still
    // code-changing, so it sits at the top tier. (The read-only
    // forensics_check_plugin_updates is intentionally absent — it never mutates.)
    "forensics_install_plugin_update": .response,
    // Plugin lifecycle (parity with the CLI). Install/uninstall change executable
    // scanner code on disk; pin changes update policy. All code/config-changing,
    // so the top tier — matching forensics_install_plugin_update. Install +
    // uninstall additionally require confirm:true in their handlers.
    "forensics_install_plugin": .response,
    "forensics_uninstall_plugin": .response,
    "forensics_pin_plugin": .response,
]

/// Drop a request into the privileged inbox the daemon polls (same dir +
/// verb-prefix contract as the dashboard). Atomic create-exclusive write so
/// the daemon's lstat gate never races a partial file. Returns nil on success
/// or an error string.
func dropInboxRequest(verb: String, payload: [String: Any]) -> String? {
    let inboxDir = dataDir + "/inbox"
    try? FileManager.default.createDirectory(atPath: inboxDir, withIntermediateDirectories: true)
    let reqId = UUID().uuidString
    let finalPath = inboxDir + "/\(verb)-\(reqId).json"
    guard JSONSerialization.isValidJSONObject(payload),
          let data = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]) else {
        return "could not serialize request payload"
    }
    // Write to a temp file in the same dir, then rename into place (atomic on
    // the same filesystem) so the poller never sees a half-written request.
    let tmpPath = inboxDir + "/.\(verb)-\(reqId).tmp"
    do {
        try data.write(to: URL(fileURLWithPath: tmpPath))
    } catch {
        return "could not write request: \(error.localizedDescription)"
    }
    let ok = tmpPath.withCString { src in finalPath.withCString { dst in rename(src, dst) == 0 } }
    guard ok else {
        try? FileManager.default.removeItem(atPath: tmpPath)
        return "could not place request in inbox: \(String(cString: strerror(errno)))"
    }
    return nil
}

// MARK: - Capability gate (called from handleToolCall before dispatch)

/// Returns a toolError dict if `name` is a mutating tool whose tier isn't
/// granted; nil if the call may proceed. `set_daemon_config` is special-cased:
/// defense-affecting keys require the `response` tier even though the tool's
/// base tier is `config`.
func agentCapabilityDenial(forTool name: String, args: [String: Any]) -> [String: Any]? {
    guard let base = agentToolCapability[name] else { return nil }  // read-only tool
    let granted = loadAgentCapabilities()
    // Escalate set_daemon_config to .response when the key is defense-affecting.
    var required = base
    if name == "set_daemon_config", let key = args["key"] as? String,
       daemonConfigResponseKeys.contains(key) {
        required = .response
    }
    if granted.contains(required) { return nil }
    return toolError("MacCrab agent capability '\(required.rawValue)' is not enabled. A human must turn it on in the dashboard (Settings → Agent Control); the grant is stored in a root-owned file that agents cannot write. All agent-control tiers are off by default.")
}

// MARK: - Read-only: capabilities + built-in rule catalog + audit log

func handleAgentCapabilities() -> Any {
    let granted = loadAgentCapabilities()
    var lines = ["MacCrab agent control capabilities (all off by default; human-set only):"]
    for cap in [AgentCapability.config, .authoring, .response] {
        let on = granted.contains(cap)
        let desc: String
        switch cap {
        case .config:    desc = "tune detection — built-in rule settings, reload rules, refresh intel, safe daemon tunables"
        case .authoring: desc = "create / delete detection rules"
        case .response:  desc = "change DEFENSE-AFFECTING config (ES introspection / file-open subscriptions, ultrasonic)"
        }
        lines.append("  [\(on ? "ON " : "off")] \(cap.rawValue) — \(desc)")
    }
    lines.append("")
    lines.append("Enable a tier in the dashboard (Settings → Agent Control). Grants are stored in a root-owned file that agents cannot write. Every change an agent makes is routed through the privileged inbox and audit-logged by the engine.")
    return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
}

func handleListBuiltinRules() -> Any {
    let settings = BuiltinRuleSettings.load(fromDir: dataDir)
    var lines = ["Built-in MacCrab detections (\(BuiltinRuleCatalog.all.count)). 'eff' = effective severity after any override; muted rules are recorded but post no alert:"]
    for def in BuiltinRuleCatalog.all.sorted(by: { $0.id < $1.id }) {
        let s = settings.setting(forRuleId: def.id)
        let enabled = s?.enabled ?? true
        let eff = (s?.severityOverride ?? def.defaultSeverity).rawValue
        let muted = enabled ? "" : " [MUTED]"
        lines.append("• \(def.id) — \(def.title) (\(def.category)) eff=\(eff)\(muted)")
    }
    return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
}

func handleGetAuditLog(_ args: [String: Any]) -> Any {
    let limit = min(max((args["limit"] as? Int) ?? 50, 1), 500)
    let path = dataDir + "/dashboard_audit.log"
    guard let text = try? String(contentsOfFile: path, encoding: .utf8) else {
        return ["content": [["type": "text", "text": "No audit log found at \(path) yet (no privileged mutations have been recorded)."]]]
    }
    let tail = text.split(separator: "\n", omittingEmptySubsequences: true).suffix(limit)
    return ["content": [["type": "text", "text": tail.isEmpty ? "(audit log empty)" : tail.joined(separator: "\n")]]]
}

// MARK: - Tier "config": built-in rule settings / reload / refresh / tunables

func handleSetBuiltinRuleSetting(_ args: [String: Any]) -> Any {
    guard let ruleId = args["rule_id"] as? String, ruleId.hasPrefix("maccrab."), ruleId.count <= 128 else {
        return toolError("'rule_id' must be a maccrab.* built-in rule id (see list_builtin_rules)")
    }
    var payload: [String: Any] = ["ruleId": ruleId]
    if let enabled = args["enabled"] as? Bool { payload["enabled"] = enabled }
    if args.keys.contains("severity") {
        if let raw = args["severity"] as? String {
            guard Severity(rawValue: raw) != nil else {
                return toolError("'severity' must be one of: critical, high, medium, low, informational (or omit / null to clear)")
            }
            payload["severityOverride"] = raw
        } else {
            payload["severityOverride"] = NSNull()  // clear to catalog default
        }
    }
    guard payload.count > 1 else { return toolError("provide 'enabled' and/or 'severity'") }
    auditLog("set_builtin_rule_setting", details: "rule_id=\(ruleId) ppid=\(getppid())")
    if let err = dropInboxRequest(verb: "builtin-rule-setting", payload: payload) { return toolError(err) }
    return ["content": [["type": "text", "text": "Queued built-in rule update for \(ruleId). The engine applies it within ~5 s; detection still runs even when an alert is muted."]]]
}

func handleReloadRules() -> Any {
    auditLog("reload_rules", details: "ppid=\(getppid())")
    if let err = dropInboxRequest(verb: "reload-rules", payload: ["requestedAt": isoFormatter.string(from: Date())]) {
        return toolError(err)
    }
    return ["content": [["type": "text", "text": "Queued a rule reload. The engine re-reads compiled_rules + user_rules within ~5 s."]]]
}

func handleRefreshThreatIntel() -> Any {
    auditLog("refresh_threat_intel", details: "ppid=\(getppid())")
    if let err = dropInboxRequest(verb: "refresh-intel", payload: ["requestedAt": isoFormatter.string(from: Date())]) {
        return toolError(err)
    }
    return ["content": [["type": "text", "text": "Queued a threat-intel feed refresh."]]]
}

/// Safe (config-tier) tunables → {key: kind}. snake_case matches daemon_config.json.
let daemonConfigSafeKeys: [String: String] = [
    "behavior_alert_threshold": "double",
    "behavior_critical_threshold": "double",
    "statistical_z_threshold": "double",
    "statistical_min_samples": "int",
    "usb_poll_interval": "double",
    "clipboard_poll_interval": "double",
    "browser_extension_poll_interval": "double",
    "rootkit_poll_interval": "double",
    "event_tap_poll_interval": "double",
    "system_policy_poll_interval": "double",
    "prompt_injection_confidence": "int",
    "intent_posterior_threshold": "double",
]

/// Defense-affecting (response-tier) keys → {key: kind}. Turning these off
/// REDUCES detection coverage, so they require the top capability tier.
let daemonConfigResponseKeysTyped: [String: String] = [
    "subscribe_file_open_events": "bool",
    "subscribe_introspection_events": "bool",
    "ultrasonic_enabled": "bool",
]
let daemonConfigResponseKeys = Set(daemonConfigResponseKeysTyped.keys)

func handleSetDaemonConfig(_ args: [String: Any]) -> Any {
    guard let key = args["key"] as? String else { return toolError("'key' is required") }
    let kind = daemonConfigSafeKeys[key] ?? daemonConfigResponseKeysTyped[key]
    guard let kind else {
        let allowed = (daemonConfigSafeKeys.keys.sorted() + daemonConfigResponseKeysTyped.keys.sorted()).joined(separator: ", ")
        return toolError("'\(key)' is not a settable key. Allowed: \(allowed)")
    }
    // Coerce + validate the value to the declared kind. Reject anything else.
    var coerced: Any
    switch kind {
    case "bool":
        guard let b = args["value"] as? Bool else { return toolError("'\(key)' expects a boolean value") }
        coerced = b
    case "int":
        guard let i = args["value"] as? Int else { return toolError("'\(key)' expects an integer value") }
        coerced = i
    default: // double
        if let d = args["value"] as? Double { coerced = d }
        else if let i = args["value"] as? Int { coerced = Double(i) }
        else { return toolError("'\(key)' expects a number value") }
    }
    auditLog("set_daemon_config", details: "key=\(key) ppid=\(getppid())")
    if let err = dropInboxRequest(verb: "set-daemon-config", payload: ["key": key, "value": coerced]) {
        return toolError(err)
    }
    return ["content": [["type": "text", "text": "Queued daemon_config update: \(key) = \(coerced). Takes effect on the engine's next config reload / restart."]]]
}

// MARK: - Tier "authoring": create / delete rules

func handleCreateRule(_ args: [String: Any]) async -> Any {
    guard let yaml = args["yaml"] as? String, !yaml.isEmpty, yaml.utf8.count <= 64 * 1024 else {
        return toolError("'yaml' is required (a single Sigma YAML rule, ≤64 KB)")
    }
    // The rule needs a stable lowercase-UUID id; derive it from the YAML if it
    // declares one, else mint one and prepend it (the engine keys overrides on id).
    let ruleId: String
    var yamlToCompile = yaml
    if let m = yaml.range(of: #"(?m)^id:\s*([0-9a-fA-F-]{8,})\s*$"#, options: .regularExpression),
       let idMatch = yaml[m].range(of: #"[0-9a-fA-F-]{8,}"#, options: .regularExpression) {
        ruleId = yaml[idMatch].lowercased()
    } else {
        ruleId = UUID().uuidString.lowercased()
        yamlToCompile = "id: \(ruleId)\n" + yaml
    }
    // Compile via a located bundled compiler so we never ship un-compiled YAML.
    let compiled = compileRuleYAML(ruleId: ruleId, yaml: yamlToCompile)
    switch compiled {
    case .failure(let msg):
        return toolError("rule did not compile: \(msg)")
    case .success(let jsonText):
        auditLog("create_rule", details: "rule_id=\(ruleId) ppid=\(getppid())")
        if let err = dropInboxRequest(verb: "install-rule", payload: [
            "ruleId": ruleId, "yaml": yamlToCompile, "json": jsonText,
        ]) { return toolError(err) }
        return ["content": [["type": "text", "text": "Compiled and queued rule \(ruleId) for install. The engine loads it within ~5 s; it then appears in Detection → Rules and fires."]]]
    }
}

func handleDeleteRule(_ args: [String: Any]) -> Any {
    guard let ruleId = args["rule_id"] as? String, !ruleId.isEmpty, ruleId.count <= 128,
          !ruleId.contains("/"), !ruleId.contains("..") else {
        return toolError("'rule_id' is required (the id of a user-authored rule; built-in maccrab.* rules are tuned with set_builtin_rule_setting, not deleted)")
    }
    auditLog("delete_rule", details: "rule_id=\(ruleId) ppid=\(getppid())")
    if let err = dropInboxRequest(verb: "remove-rule", payload: ["ruleId": ruleId]) { return toolError(err) }
    return ["content": [["type": "text", "text": "Queued removal of user rule \(ruleId). The engine drops it on the next reload."]]]
}

private enum CompileOutcome { case success(String); case failure(String) }

/// Locate a bundled compile_rules.py and run it on a single staged rule.
/// Probes: $MACCRAB_COMPILER, the installed app, then ./Compiler (dev/repo cwd).
private func compileRuleYAML(ruleId: String, yaml: String) -> CompileOutcome {
    let fm = FileManager.default
    let candidates = [
        ProcessInfo.processInfo.environment["MACCRAB_COMPILER"],
        "/Applications/MacCrab.app/Contents/Resources/Compiler/compile_rules.py",
        fm.currentDirectoryPath + "/Compiler/compile_rules.py",
    ].compactMap { $0 }
    guard let compiler = candidates.first(where: { fm.fileExists(atPath: $0) }) else {
        return .failure("could not locate compile_rules.py (set MACCRAB_COMPILER, or install MacCrab.app, or run the server from the repo root)")
    }
    let pyDir = (compiler as NSString).deletingLastPathComponent
    let tmp = NSTemporaryDirectory() + "maccrab-mcp-rule-\(UUID().uuidString)"
    defer { try? fm.removeItem(atPath: tmp) }
    guard (try? fm.createDirectory(atPath: tmp, withIntermediateDirectories: true)) != nil,
          (try? yaml.data(using: .utf8)?.write(to: URL(fileURLWithPath: tmp + "/\(ruleId).yml"))) != nil else {
        return .failure("could not stage YAML for compilation")
    }
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
    task.arguments = [compiler, "--input-dir", tmp, "--output-dir", tmp]
    var env = ProcessInfo.processInfo.environment
    env["PYTHONPATH"] = pyDir
    task.environment = env
    let errPipe = Pipe()
    task.standardError = errPipe
    task.standardOutput = Pipe()
    do { try task.run() } catch { return .failure("could not run python3: \(error.localizedDescription)") }
    task.waitUntilExit()
    let jsonPath = tmp + "/\(ruleId).json"
    if task.terminationStatus != 0 || !fm.fileExists(atPath: jsonPath) {
        let err = (try? errPipe.fileHandleForReading.readToEnd()).flatMap { String(data: $0, encoding: .utf8) } ?? ""
        let detail = err.split(separator: "\n").suffix(6).joined(separator: " ")
        return .failure(detail.isEmpty ? "compiler exited \(task.terminationStatus) (rule may be malformed or product != macos)" : detail)
    }
    guard let jsonText = try? String(contentsOfFile: jsonPath, encoding: .utf8) else {
        return .failure("compiled JSON was unreadable")
    }
    return .success(jsonText)
}
