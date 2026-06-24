// ConfigCommands.swift -- `maccrabctl config get|set` (PARITY-04).
//
// Headless mirror of the MCP `set_daemon_config` handler
// (maccrab-mcp/AgentControl.swift::handleSetDaemonConfig). Same SAFE
// allow-list, same type coercion, and the SAME privileged-inbox drop
// (`set-daemon-config` verb) the daemon authorizes by file-owner uid and
// re-validates against its own whitelist (DaemonTimers.swift). The CLI is
// NOT trusted — it only queues; the root engine is the authority.
//
// `get` reads daemon_config.json directly (read-only), so an operator can
// see the current value before/after a `set`.
//
// NOTE ON THE ALLOW-LIST: ideally this list would be shared with the MCP
// server (AgentControl.swift::daemonConfigSafeKeys / …ResponseKeysTyped)
// and the daemon (DaemonTimers). It is NOT factored into DaemonConfig.swift
// because that type lives in the MacCrabAgentKit target, which neither
// maccrabctl nor maccrab-mcp link (both depend only on MacCrabCore +
// MacCrabForensics). A truly shared list would have to move to MacCrabCore;
// see the kit's sharedEdits note. Until then this mirrors the MCP's keys
// verbatim — keep the three lists in lockstep when adding a tunable.

import Foundation
import MacCrabCore

/// Safe (config-tier) tunables → declared kind. Mirrors
/// AgentControl.swift::daemonConfigSafeKeys (snake_case = daemon_config.json).
private let configSafeKeys: [String: String] = [
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

/// Defense-affecting (response-tier in the MCP) keys → declared kind.
/// Turning these off REDUCES coverage. Mirrors
/// AgentControl.swift::daemonConfigResponseKeysTyped. The CLI doesn't gate
/// on agent capability tiers (a human at a terminal is already the
/// authority), but we keep the set so `set` can warn before queueing.
private let configResponseKeys: [String: String] = [
    "subscribe_file_open_events": "bool",
    "subscribe_introspection_events": "bool",
    "ultrasonic_enabled": "bool",
]

/// Dispatch `maccrabctl config <get|set> ...`. Called from MacCrabCtl.main
/// when args[1] == "config" (rest == args.dropFirst(2)).
func dispatchConfig(args: [String]) {
    guard let sub = args.first else {
        printConfigUsage()
        exit(0)
    }
    let rest = Array(args.dropFirst())
    switch sub {
    case "get":
        configGet(args: rest)
    case "set":
        configSet(args: rest)
    case "help", "-h", "--help":
        printConfigUsage()
    default:
        print("Unknown config subcommand: \(sub)")
        printConfigUsage()
        exit(1)
    }
}

func printConfigUsage() {
    let safe = configSafeKeys.keys.sorted().joined(separator: ", ")
    let resp = configResponseKeys.keys.sorted().joined(separator: ", ")
    print("""
    Usage: maccrabctl config <subcommand>

    Subcommands:
      get [<key>]            Show the current value of <key> from daemon_config.json,
                             or the whole file when no key is given.
      set <key> <value>      Queue a daemon_config update via the privileged inbox.
                             The engine applies it on its next config reload / restart.

    Settable keys (safe tunables — thresholds / poll intervals):
      \(safe)

    Defense-affecting keys (turning these off reduces detection coverage):
      \(resp)
    """)
}

// MARK: - get

private func configGet(args: [String]) {
    let path = maccrabDataDir() + "/daemon_config.json"

    // Distinguish "no config file" (genuine all-defaults) from "config file
    // exists but this uid can't read it" (release builds write a root-owned
    // 0600 daemon_config.json under /Library/Application Support/MacCrab/; a
    // uid-501 CLI gets EACCES). Reporting "all defaults" in the unreadable
    // case is misleading — the engine may be running a very different config.
    let fileExists = FileManager.default.fileExists(atPath: path)
    let data: Data
    do {
        data = try Data(contentsOf: URL(fileURLWithPath: path))
    } catch {
        if fileExists {
            // Present but unreadable (typically EACCES on a root-owned 0600 file).
            print("A daemon_config.json exists at \(path) but is not readable by this user (likely root-owned).")
            print("Run via the app or with sudo to inspect it; values below cannot be shown.")
        } else {
            print("No daemon_config.json found at \(path) (using defaults — no config file).")
            if let key = args.first {
                print("Key '\(key)' is therefore at its default value.")
            }
        }
        return
    }
    guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        print("daemon_config.json at \(path) is present but could not be parsed as JSON.")
        return
    }
    if let key = args.first {
        if let value = json[key] {
            print("\(key) = \(value)")
        } else if configSafeKeys[key] != nil || configResponseKeys[key] != nil {
            print("\(key) is not set in daemon_config.json (using its built-in default).")
        } else {
            print("'\(key)' is not present in daemon_config.json.")
            print("Settable keys: \(allowedKeyList())")
        }
        return
    }
    // No key: dump the whole file, sorted for stable output.
    print("daemon_config.json (\(path)):")
    for k in json.keys.sorted() {
        print("  \(k) = \(json[k]!)")
    }
}

// MARK: - set

private func configSet(args: [String]) {
    guard args.count >= 2 else {
        print("Usage: maccrabctl config set <key> <value>")
        print("Settable keys: \(allowedKeyList())")
        exit(1)
    }
    let key = args[0]
    let raw = args[1]

    let kind = configSafeKeys[key] ?? configResponseKeys[key]
    guard let kind else {
        print("'\(key)' is not a settable key.")
        print("Allowed: \(allowedKeyList())")
        exit(1)
    }

    // Coerce + validate the string argument to the declared kind, mirroring
    // the MCP handler's per-kind validation.
    let coerced: Any
    switch kind {
    case "bool":
        guard let b = parseBool(raw) else {
            print("'\(key)' expects a boolean value (true / false).")
            exit(1)
        }
        coerced = b
    case "int":
        guard let i = Int(raw) else {
            print("'\(key)' expects an integer value.")
            exit(1)
        }
        coerced = i
    default: // double
        guard let d = Double(raw) else {
            print("'\(key)' expects a number value.")
            exit(1)
        }
        coerced = d
    }

    // Mirror the MCP's capability framing for operators: defense-affecting
    // keys are coverage-reducing. The CLI doesn't enforce a tier (a local
    // operator is the authority), but it warns so the impact is explicit.
    if configResponseKeys[key] != nil, parseBool(raw) == false {
        print("⚠️  '\(key)' is defense-affecting — setting it false REDUCES detection coverage.")
    }

    // Drop a `set-daemon-config` request into the privileged inbox the engine
    // polls (same dir + verb-prefix + payload contract as the MCP handler and
    // the dashboard). The daemon re-validates the key against its own
    // whitelist and authorizes by file-owner uid; the CLI only queues.
    let payload: [String: Any] = ["key": key, "value": coerced]
    if let err = dropCtlInboxRequest(verb: "set-daemon-config", payload: payload) {
        print("Could not queue config update: \(err)")
        print("(The engine may not be running, or this shell can't write its inbox.)")
        exit(1)
    }
    print("Queued daemon_config update: \(key) = \(coerced).")
    print("The engine applies it on its next config reload / restart.")
}

// MARK: - helpers

private func allowedKeyList() -> String {
    (configSafeKeys.keys.sorted() + configResponseKeys.keys.sorted()).joined(separator: ", ")
}

private func parseBool(_ s: String) -> Bool? {
    switch s.lowercased() {
    case "true", "1", "yes", "on": return true
    case "false", "0", "no", "off": return false
    default: return nil
    }
}
