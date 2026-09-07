// Configuration reads and mutation submission use the shared runtime contract.
import Foundation
import MacCrabCore

func dispatchConfig(args: [String]) {
    let command = args.first ?? "help"
    let rest = Array(args.dropFirst())
    do {
        switch command {
        case "get": try configGet(args: rest)
        case "effective": try configEffective(args: rest)
        case "schema":
            guard rest.isEmpty || rest == ["--json"] else { throw RuntimeConfigContractError("Usage: maccrabctl config schema [--json]") }
            try printCLIJSON(RuntimeConfigurationContract.definitions)
        case "status": try configRequestStatus(args: rest)
        case "set": try configSet(args: rest)
        case "help", "-h", "--help": printConfigUsage()
        default: throw RuntimeConfigContractError("Unknown config subcommand: \(command)")
        }
    } catch { cliFailure("config \(command): \(error.localizedDescription)") }
}

func printConfigUsage() {
    print("""
    Usage: maccrabctl config <subcommand>

      get [key] [--json]         Configured file values and defaults; not an applied-state claim.
      effective [key] [--json]   Runtime values, source, adjustments and applied generation.
      schema [--json]            Shared key/type/bounds/application contract.
      set <key> <value> [--json] Submit a request; returns its ID without claiming it applied.
      status <request-id> [--json] Read the daemon's durable request outcome.

    Effective output covers the shared runtime-tunable catalog. Other configuration
    remains visible through get. Numeric values use the documented bounds. Network
    enrichment switches can only be disabled here; the app enables them.
    Request outcomes are retained for up to 30 days and the newest 4096 requests.
    """)
}

private func readArguments(_ args: [String]) throws -> (key: String?, json: Bool) {
    let positional = args.filter { $0 != "--json" }
    guard positional.count <= 1, !positional.contains(where: { $0.hasPrefix("--") }) else {
        throw RuntimeConfigContractError("Expected at most one key and optional --json")
    }
    return (positional.first, args.contains("--json"))
}

func configuredConfigDocument(directory: String, key: String?) throws -> [String: Any] {
    let path = directory + "/daemon_config.json"
    let configured = try RuntimeConfigurationFiles.readConfigured(at: path)
    var values = configured ?? [:]
    for definition in RuntimeConfigurationContract.definitions {
        values[definition.key] = values[definition.property] ?? values[definition.key]
            ?? definition.defaultValue.foundationValue
        values.removeValue(forKey: definition.property)
    }
    if let key {
        guard let value = values[key] else { throw RuntimeConfigContractError("Unknown configuration key '\(key)'") }
        values = [key: value]
    }
    return ["schema_version": 1, "view": "configured", "source_directory": directory,
            "file_present": configured != nil, "values": values]
}

private func configGet(args: [String]) throws {
    let options = try readArguments(args)
    let document = try configuredConfigDocument(directory: maccrabDataDir(), key: options.key)
    if options.json { try printCLIJSONObject(document); return }
    print("Configured values (runtime application is shown by `config effective`):")
    let values = document["values"] as? [String: Any] ?? [:]
    for key in values.keys.sorted() {
        guard let value = values[key] else { continue }
        print("  \(key) = \(value)")
    }
}

private func configEffective(args: [String]) throws {
    let options = try readArguments(args)
    let directory = maccrabDataDir()
    var snapshot = try RuntimeConfigurationFiles.readEffective(directory: directory)
    if let key = options.key {
        guard let entry = snapshot.values[key] else { throw RuntimeConfigContractError("'\(key)' is not in the runtime-tunable catalog") }
        snapshot.values = [key: entry]
    }
    let heartbeat = try RuntimeConfigurationFiles.readConfigured(at: directory + "/heartbeat.json")
    let written = heartbeat?["written_at_unix"] as? Double
    let age = written.map { Date().timeIntervalSince1970 - $0 }
    let current = heartbeat.flatMap(EngineTelemetryIdentity.init(heartbeat:)) == snapshot.engineIdentity
        && (age.map { $0 >= 0 && $0 <= 120 } ?? false)
    if options.json {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        encoder.dateEncodingStrategy = .iso8601
        var object = try JSONSerialization.jsonObject(with: encoder.encode(snapshot)) as? [String: Any] ?? [:]
        object["view"] = "effective_runtime_tunables"
        object["current"] = current
        object["source_directory"] = directory
        try printCLIJSONObject(object)
        return
    }
    print("\(current ? "Current" : "Historical / unverified") runtime configuration; generation \(snapshot.generation):")
    for key in snapshot.values.keys.sorted() {
        guard let entry = snapshot.values[key] else { continue }
        print("  \(key) = \(entry.value?.description ?? "unsupported") [\(entry.source)]")
        if let adjustment = entry.adjustment { print("    \(adjustment); configured: \(entry.configuredValue)") }
    }
}

private func configRequestStatus(args: [String]) throws {
    let options = try readArguments(args)
    guard let raw = options.key, let id = UUID(uuidString: raw) else {
        throw RuntimeConfigContractError("Usage: maccrabctl config status <request-UUID> [--json]")
    }
    let directory = maccrabDataDir()
    if let receipt = try RuntimeConfigurationFiles.readReceipt(directory: directory, requestID: id) {
        if options.json { try printCLIJSON(receipt) }
        else { print("\(receipt.requestID.uuidString): \(receipt.state.rawValue) — \(receipt.reason)") }
        return
    }
    let pending = ["set-daemon-config", "reload-rules", "remove-suppression"].contains {
        FileManager.default.fileExists(atPath: directory + "/inbox/" + $0 + "-" + id.uuidString + ".json")
    }
    if options.json {
        try printCLIJSONObject(["schema_version": 1, "request_id": id.uuidString,
                                "state": pending ? "pending" : "unknown"])
    } else { print("\(id.uuidString): \(pending ? "pending daemon acknowledgement" : "unknown or expired request")") }
    if !pending { cliFailure("No retained outcome exists for this request", code: 4) }
}

private func configSet(args: [String]) throws {
    let positional = args.filter { $0 != "--json" }
    guard positional.count == 2 else { throw RuntimeConfigContractError("Usage: maccrabctl config set <key> <value> [--json]") }
    let key = positional[0]
    guard let definition = RuntimeConfigurationContract.byKey[key] else {
        throw RuntimeConfigContractError("'\(key)' is not a settable key; see config schema")
    }
    let requested = try definition.parse(positional[1])
    let normalized = try definition.normalized(requested)
    let id = try RuntimeConfigurationFiles.submit(
        operation: "set-daemon-config", payload: ["key": key, "value": requested.foundationValue], directory: maccrabDataDir()
    )
    if args.contains("--json") {
        try printCLIJSONObject(["schema_version": 1, "state": "pending", "request_id": id.uuidString,
                                "operation": "set-daemon-config", "key": key,
                                "requested_value": requested.foundationValue,
                                "normalized_value": normalized.foundationValue,
                                "application": definition.application.rawValue])
    } else {
        print("Submitted \(key) = \(requested); request \(id.uuidString).")
        if requested != normalized { print("The documented bounds normalize this to \(normalized).") }
        print("Application: \(definition.application.rawValue). Check: maccrabctl config status \(id.uuidString)")
    }
}

// MARK: - audit

/// `maccrabctl audit [N]` — tail the privileged-mutation audit trail.
///
/// PARITY: the MCP surface has `get_audit_log`, but neither the CLI nor the
/// dashboard could read it, so the record of what an AGENT changed was legible
/// only through the agent's own tooling — which inverts the trust relationship
/// the agent-capability tiers exist to establish. Reads both rails the writers
/// use: `dashboard_audit.log` (engine request acceptance, rejection and application,
/// written by DaemonTimers.auditLogInbox) and `mcp_mutations.jsonl` (what an
/// MCP client REQUESTED, written by maccrab-mcp's auditLog into the USER
/// app-support dir, which is a different directory from the engine's).
func dispatchAudit(args: [String]) {
    let limit = args.first.flatMap { Int($0) }.map { max(1, min($0, 1000)) } ?? 50

    func tail(_ path: String, label: String) {
        guard FileManager.default.fileExists(atPath: path) else {
            print("\(label): none recorded yet (\(path))")
            print("")
            return
        }
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else {
            // Present but unreadable. Never print "none" here — that would read
            // as "nothing was changed", which is the opposite of what we know.
            print("\(label): present but not readable by this user (\(path)) — retry with sudo.")
            print("")
            return
        }
        let all = text.components(separatedBy: .newlines).filter { !$0.isEmpty }
        let shown = all.suffix(limit)
        print("\(label) — last \(shown.count) of \(all.count) (\(path)):")
        print(String(repeating: "─", count: 60))
        for line in shown { print("  \(line)") }
        print("")
    }

    tail(maccrabDataDir() + "/dashboard_audit.log", label: "Engine request audit")
    let userDir = FileManager.default
        .urls(for: .applicationSupportDirectory, in: .userDomainMask)
        .first.map { $0.appendingPathComponent("MacCrab").path }
        ?? NSHomeDirectory() + "/Library/Application Support/MacCrab"
    tail(userDir + "/mcp_mutations.jsonl", label: "Requested via MCP")
}
