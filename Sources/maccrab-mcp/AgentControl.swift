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
//   the agent can still read. A human grants a tier through the explicit
//   root-authorized CLI (`sudo maccrabctl agent-capabilities set … on`). The
//   dashboard may revoke tiers but its console-user request cannot create a new
//   grant. The MCP trusts only a tightly validated root-owned state file, so an
//   agent cannot grant itself power, and there is no MCP tool that enables a
//   capability.
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
//   hardlink gated, audit-logged by the daemon). Response actions are
//   untouched: they still never auto-execute.
//
//   EXCEPTION (audit #15): `set_response_action` does NOT write through the
//   inbox — it writes the user-home `actions.json` directly, and the root engine
//   honors that file ONLY when its owner is an admin (ResponseEngine.isAdminUID).
//   A non-admin write therefore succeeds on disk but never arms; the tool now
//   says so explicitly. The reload is still queued through the inbox.

import Foundation
import Darwin
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
/// it is a regular, single-link, non-group/world-writable file owned by root
/// (uid 0) at the system support dir. A human enables tiers through the
/// root-authorized CLI; the root engine writes this file. An agent runs as the
/// console user and cannot create or modify a file meeting that trust policy.
func loadAgentCapabilities() -> Set<AgentCapability> {
    readTrustedAgentCapabilities(
        at: "/Library/Application Support/MacCrab/mcp_capabilities.json",
        expectedOwnerUID: 0
    )
}

/// Bounded, descriptor-validated capability load. Root ownership alone is not
/// sufficient: a root-owned file accidentally left group/world-writable can be
/// modified in place by an unprivileged process without changing `st_uid`.
/// Opening no-follow, comparing the opened inode with lstat, requiring a single
/// link and rejecting writable-by-others closes that bypass and the path/read
/// TOCTOU. `expectedOwnerUID` is an internal test seam; production always uses 0.
func readTrustedAgentCapabilities(
    at path: String,
    expectedOwnerUID: uid_t
) -> Set<AgentCapability> {
    let maximumBytes: off_t = 64 * 1024
    var pathInfo = stat()
    guard lstat(path, &pathInfo) == 0,
          (pathInfo.st_mode & S_IFMT) == S_IFREG,
          pathInfo.st_uid == expectedOwnerUID,
          pathInfo.st_nlink == 1,
          (pathInfo.st_mode & (S_IWGRP | S_IWOTH)) == 0,
          pathInfo.st_size >= 0,
          pathInfo.st_size <= maximumBytes
    else { return [] }

    let fd = open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
    guard fd >= 0 else { return [] }
    defer { close(fd) }
    var openedInfo = stat()
    guard fstat(fd, &openedInfo) == 0,
          (openedInfo.st_mode & S_IFMT) == S_IFREG,
          openedInfo.st_uid == expectedOwnerUID,
          openedInfo.st_nlink == 1,
          openedInfo.st_dev == pathInfo.st_dev,
          openedInfo.st_ino == pathInfo.st_ino,
          (openedInfo.st_mode & (S_IWGRP | S_IWOTH)) == 0,
          openedInfo.st_size >= 0,
          openedInfo.st_size <= maximumBytes
    else { return [] }

    var data = Data()
    data.reserveCapacity(Int(openedInfo.st_size))
    var buffer = [UInt8](repeating: 0, count: 4 * 1024)
    while true {
        let remaining = Int(maximumBytes) - data.count + 1
        guard remaining > 0 else { return [] }
        let requested = min(buffer.count, remaining)
        let count = buffer.withUnsafeMutableBytes {
            Darwin.read(fd, $0.baseAddress, requested)
        }
        if count == 0 { break }
        if count < 0 {
            if errno == EINTR { continue }
            return []
        }
        data.append(contentsOf: buffer[0..<count])
        if data.count > Int(maximumBytes) { return [] }
    }

    guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
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
    // Network EGRESS, not mutation — but gated for the same reason
    // refresh_threat_intel is. Both handlers reach out to npm / PyPI from this
    // host's IP (PackageMetadataAnalyzer → HardenedRegistrySession;
    // AttestationEnricher → registry.npmjs.org/-/npm/v1/security/attestations
    // and pypi.org/integrity). Ungated, any connected agent — including one
    // steered by prompt injection in content MacCrab itself ingested — could
    // emit an arbitrary sequence of package-name lookups, which is both an
    // undisclosed egress channel and a low-bandwidth exfil primitive. The
    // documented `packageFreshnessEnabled` switch does NOT cover this path and
    // cannot: daemon_config.json is root-owned 0600, so this uid-501 process
    // can never read it (see ConfigCommands.swift's EACCES branch). A
    // human-granted capability tier is the gate that actually works here.
    "analyze_package_metadata": .config,
    "verify_package_attestation": .config,
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
    // Running a forensic scan EXECUTES plugin scanner code and can sweep
    // sensitive local data (messages, mail, browser history, TCC state) into a
    // case. create_case opens the container; run_collector / run_analyzer /
    // run_all execute the scanner/analyzer plugins. Previously ALL of these were
    // absent here, so the fail-open default let an agent with ZERO granted tiers
    // run arbitrary forensic collection. Gated at the top tier to match the other
    // code-executing plugin tools above (this is a read/scan of local state, not
    // a defense-config change, but .response is the tightest existing tier and
    // the correct home for code execution + sensitive-data collection). NOTE:
    // gating create_case only closes the fresh-case path — an agent can still
    // target a case_id from forensics_list_cases — so run_collector /
    // run_analyzer / run_all are gated DIRECTLY, and run_all (the "run all
    // collectors" superset of run_collector) is included so it can't be a bypass.
    "forensics_create_case": .response,
    "forensics_run_collector": .response,
    "forensics_run_analyzer": .response,
    "forensics_run_all": .response,
    // forensics_enrich EXECUTES enricher plugin code against an operator-named
    // path — the same code-execution class as run_collector / run_analyzer — so
    // it sits at the top tier too. Previously absent: the map's fail-open
    // default let an agent with ZERO granted tiers run arbitrary enricher code.
    "forensics_enrich": .response,
    // Reading COLLECTED forensic artifacts back out of a case (Safari visits,
    // TCC grants, quarantine downloads, app-usage, per-content-type / posture
    // rollups) is the exfil half of the collection the operator gated behind
    // .response. Collection is .response-gated (above); gate the read-back at
    // the same tier so the forensic surface is one coherent .response-tier
    // capability and a zero-tier agent cannot extract sensitive local metadata
    // that a prior scan committed. Plugin / case ENUMERATION
    // (forensics_list_plugins / list_cases / list_installed_plugins /
    // search_catalog / check_plugin_updates / verify_installed_plugins) stays
    // ungated — it reveals no collected personal data.
    "forensics_search_artifacts": .response,
    "forensics_get_artifact": .response,
    "forensics_timeline": .response,
    "forensics_explain_case": .response,
    "forensics_posture_findings": .response,
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
    return toolError("MacCrab agent capability '\(required.rawValue)' is not enabled. A human must explicitly grant it with: sudo maccrabctl agent-capabilities set \(required.rawValue) on. The grant is stored in root-owned state that agents cannot write. All agent-control tiers are off by default.")
}

/// Fail-CLOSED gate for the dynamically-registered per-plugin collector tools
/// (imessage_*, mail_*, safari_*, knowledgec_*, quarantine_*, launchd_*, tcc_*,
/// macho_analyze_path, pkg_analyze_path, …). These names are declared by
/// installed collector manifests and advertised via `pluginMCPTools()`, so they
/// can NEVER appear in the static `agentToolCapability` map — and that map FAILS
/// OPEN. Each one executes plugin scanner code and commits (often sensitive:
/// messages / mail / browser history / TCC state) artifacts into a case, i.e.
/// exactly what forensics_run_collector does, so it requires the top `.response`
/// tier. Called at the single plugin-dispatch chokepoint (handlePluginMCPTool);
/// without it a zero-capability agent could run arbitrary personal-data
/// collection by naming a per-plugin tool directly. Returns a toolError dict
/// when `.response` isn't granted; nil to proceed.
func perPluginCollectorCapabilityDenial(forTool name: String) -> [String: Any]? {
    if loadAgentCapabilities().contains(.response) { return nil }
    return toolError("MacCrab agent capability 'response' is not enabled. The per-plugin collector tool '\(name)' executes plugin scanner code and commits forensic artifacts (sensitive local data) into a case, so it requires the top 'response' tier — the same gate as forensics_run_collector. A human must explicitly grant it with: sudo maccrabctl agent-capabilities set response on. The grant is stored in root-owned state that agents cannot write. All agent-control tiers are off by default.")
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
    lines.append("A human can grant a tier with `sudo maccrabctl agent-capabilities set <tier> on`. Grants are stored in root-owned state that agents cannot write. Every change an agent makes is routed through the privileged inbox and audit-logged by the engine.")
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

/// v1.21.6 (audit DOC-11): network-enrichment switches an agent may set to
/// `false` but never to `true`. Mirrors DaemonTimers.agentDisableOnlyConfigKeys
/// and ConfigCommands.configEgressDisableOnlyKeys — the daemon re-checks this
/// independently, so a divergence here is a usability bug, not a hole.
/// Disabling reduces egress and is safe for anything holding the config tier to
/// call; enabling would let an agent turn on outbound calls that publish the
/// host's resolved domains (cert transparency) and installed software inventory
/// (osv.dev), so that direction stays a human action in the dashboard.
let daemonConfigEgressDisableOnlyKeys: Set<String> = [
    "threat_intel_enabled",
    "vuln_scan_enabled",
    "package_freshness_enabled",
    "cert_transparency_enabled",
]

func handleSetDaemonConfig(_ args: [String: Any]) -> Any {
    guard let key = args["key"] as? String else { return toolError("'key' is required") }
    let kind = daemonConfigSafeKeys[key] ?? daemonConfigResponseKeysTyped[key]
        ?? (daemonConfigEgressDisableOnlyKeys.contains(key) ? "bool" : nil)
    guard let kind else {
        let allowed = (daemonConfigSafeKeys.keys.sorted()
                       + daemonConfigResponseKeysTyped.keys.sorted()
                       + daemonConfigEgressDisableOnlyKeys.sorted().map { "\($0) (false only)" })
            .joined(separator: ", ")
        return toolError("'\(key)' is not a settable key. Allowed: \(allowed)")
    }
    // Disable-only: refuse the enabling direction here so the agent gets a
    // reason instead of a silent daemon-side rejection.
    if daemonConfigEgressDisableOnlyKeys.contains(key), (args["value"] as? Bool) == true {
        return toolError("'\(key)' can only be set to false. Enabling it turns on outbound network calls, which is a human action: Settings > Network enrichment in MacCrab.app.")
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
/// Probes: $MACCRAB_COMPILER, then the installed app. The repo-relative
/// ./Compiler candidate is DEBUG-only (see below).
private func compileRuleYAML(ruleId: String, yaml: String) -> CompileOutcome {
    let fm = FileManager.default
    var candidates = [
        ProcessInfo.processInfo.environment["MACCRAB_COMPILER"],
        "/Applications/MacCrab.app/Contents/Resources/Compiler/compile_rules.py",
    ].compactMap { $0 }
    // The cwd-relative candidate is DEBUG-only, matching the trust-root probes in
    // RuleChannelFetch.loadRulesPublicKey / PluginCatalogFetch.loadCatalogPublicKey.
    // maccrab-mcp is launched by an agent client with cwd = whatever repository the
    // session happens to be in, so on a release build any checkout that merely
    // CONTAINS a file at Compiler/compile_rules.py would have that file handed to
    // /usr/bin/python3 the first time an agent called create_rule — arbitrary code
    // execution sourced from an attacker-chosen working directory. Release builds
    // now resolve only $MACCRAB_COMPILER (explicit operator opt-in) or the
    // code-signed app bundle; the dev loop is unaffected because .mcp.json points
    // at .build/debug/maccrab-mcp, which is a debug build run from the repo root.
    #if DEBUG
    candidates.append(fm.currentDirectoryPath + "/Compiler/compile_rules.py")
    #endif
    guard let compiler = candidates.first(where: { fm.fileExists(atPath: $0) }) else {
        return .failure("could not locate compile_rules.py (set MACCRAB_COMPILER, or install MacCrab.app)")
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
