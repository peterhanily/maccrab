// maccrab-mcp — MacCrab MCP Server
//
// Model Context Protocol server that exposes MacCrab's detection data
// to AI agents. Communicates via JSON-RPC 2.0 over stdio.
//
// Tools exposed:
//   get_alerts      — Query recent alerts with severity/time filtering
//   get_events      — Query recent events with category filtering
//   get_campaigns   — List detected attack campaigns
//   get_status      — Daemon status, rule count, event stats
//   hunt            — Natural language threat hunting (SQL generation)
//   get_security_score — System security posture score with factors
//   get_edr_tools   — List detected EDR/RMM/insider threat tools
//   suppress_alert  — Suppress an alert by ID
//
// Usage:
//   Register in Claude Code settings:
//   { "mcpServers": { "maccrab": { "command": "/path/to/maccrab-mcp" } } }

import Foundation
import MacCrabCore

// Force unbuffered stdout for reliable pipe output
setbuf(stdout, nil)

// MARK: - Data Directory Resolution

func resolveDataDir() -> String {
    let fm = FileManager.default
    let userDir = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)
        .first.map { $0.appendingPathComponent("MacCrab").path }
        ?? NSHomeDirectory() + "/Library/Application Support/MacCrab"
    let systemDir = "/Library/Application Support/MacCrab"
    let userDB = userDir + "/events.db"
    let systemDB = systemDir + "/events.db"

    if fm.isReadableFile(atPath: systemDB) {
        let sysMod = (try? fm.attributesOfItem(atPath: systemDB))?[.modificationDate] as? Date
        let userMod = fm.fileExists(atPath: userDB)
            ? (try? fm.attributesOfItem(atPath: userDB))?[.modificationDate] as? Date
            : nil
        if let s = sysMod, userMod == nil || s >= userMod! { return systemDir }
    }
    if fm.fileExists(atPath: userDB) { return userDir }
    return systemDir
}

// MARK: - JSON-RPC Types

struct JSONRPCRequest: Decodable {
    let jsonrpc: String
    let id: RequestId?
    let method: String
    let params: AnyCodable?
}

enum RequestId: Decodable, Encodable {
    case int(Int)
    case string(String)

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let v = try? container.decode(Int.self) { self = .int(v); return }
        if let v = try? container.decode(String.self) { self = .string(v); return }
        throw DecodingError.typeMismatch(RequestId.self, .init(codingPath: [], debugDescription: "Expected int or string"))
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .int(let v): try container.encode(v)
        case .string(let v): try container.encode(v)
        }
    }
}

struct AnyCodable: Decodable {
    let value: Any
    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let v = try? container.decode([String: AnyCodable].self) {
            value = v.mapValues { $0.value }
        } else if let v = try? container.decode([AnyCodable].self) {
            value = v.map { $0.value }
        } else if let v = try? container.decode(String.self) { value = v }
        else if let v = try? container.decode(Int.self) { value = v }
        else if let v = try? container.decode(Double.self) { value = v }
        else if let v = try? container.decode(Bool.self) { value = v }
        else { value = NSNull() }
    }
}

// MARK: - Response Helpers

func sendResponse(id: RequestId?, result: Any) {
    var response: [String: Any] = ["jsonrpc": "2.0"]
    if let id = id {
        switch id {
        case .int(let v): response["id"] = v
        case .string(let v): response["id"] = v
        }
    }
    response["result"] = result
    writeJSON(response)
}

func sendError(id: RequestId?, code: Int, message: String) {
    var response: [String: Any] = ["jsonrpc": "2.0"]
    if let id = id {
        switch id {
        case .int(let v): response["id"] = v
        case .string(let v): response["id"] = v
        }
    }
    response["error"] = ["code": code, "message": message] as [String: Any]
    writeJSON(response)
}

let stdoutHandle = FileHandle.standardOutput

func writeJSON(_ obj: Any) {
    guard let data = try? JSONSerialization.data(withJSONObject: obj),
          let str = String(data: data, encoding: .utf8) else { return }
    let output = "Content-Length: \(data.count)\r\n\r\n\(str)"
    // Use POSIX write() for reliable unbuffered output
    let outputData = Array(output.utf8)
    outputData.withUnsafeBufferPointer { ptr in
        _ = Darwin.write(STDOUT_FILENO, ptr.baseAddress!, ptr.count)
    }
}

// MARK: - Tool Definitions

let tools: [[String: Any]] = [
    [
        "name": "get_alerts",
        "description": "Get recent security alerts from MacCrab. Returns alert details including rule name, severity, process info, MITRE techniques, and AI analysis if available.",
        "inputSchema": [
            "type": "object",
            "properties": [
                "limit": ["type": "integer", "description": "Max alerts to return (default 20, max 100)", "default": 20],
                "severity": ["type": "string", "description": "Filter by minimum severity: critical, high, medium, low, informational", "enum": ["critical", "high", "medium", "low", "informational"]],
                "hours": ["type": "number", "description": "Only alerts from the last N hours (default: 24)", "default": 24],
                "include_suppressed": ["type": "boolean", "description": "Include suppressed alerts (default false)", "default": false],
            ],
        ] as [String: Any],
    ],
    [
        "name": "get_events",
        "description": "Get recent security events (process executions, file operations, network connections, TCC changes) from MacCrab.",
        "inputSchema": [
            "type": "object",
            "properties": [
                "limit": ["type": "integer", "description": "Max events to return (default 20, max 100)", "default": 20],
                "category": ["type": "string", "description": "Filter by category: process, file, network, auth, tcc, dns", "enum": ["process", "file", "network", "auth", "tcc", "dns"]],
                "search": ["type": "string", "description": "Full-text search query"],
                "hours": ["type": "number", "description": "Only events from the last N hours (default: 24)", "default": 24],
            ],
        ] as [String: Any],
    ],
    [
        "name": "get_campaigns",
        "description": "Get detected attack campaigns — kill chains, alert storms, AI compromise attempts, coordinated attacks, and lateral movement patterns.",
        "inputSchema": [
            "type": "object",
            "properties": [
                "limit": ["type": "integer", "description": "Max campaigns to return (default 10)", "default": 10],
            ],
        ] as [String: Any],
    ],
    [
        "name": "get_status",
        "description": "Get MacCrab daemon status: running state, rule count, event/alert counts, database size, security score, and active monitors.",
        "inputSchema": ["type": "object", "properties": [:] as [String: Any]] as [String: Any],
    ],
    [
        "name": "hunt",
        "description": "Search for threats using a natural language query or SQL. Examples: 'show unsigned processes with network connections', 'find critical alerts from the last hour', 'processes connecting to unusual ports'.",
        "inputSchema": [
            "type": "object",
            "properties": [
                "query": ["type": "string", "description": "Natural language threat hunting query or SQL SELECT"],
            ],
            "required": ["query"],
        ] as [String: Any],
    ],
    [
        "name": "get_security_score",
        "description": "Get the system security posture score (0-100) with individual factors (SIP, FileVault, Firewall, etc.), grades, and specific recommendations.",
        "inputSchema": ["type": "object", "properties": [:] as [String: Any]] as [String: Any],
    ],
    [
        "name": "suppress_alert",
        "description": "Suppress an alert by ID so it no longer appears in the active alerts list. Use when an alert is a known false positive.",
        "inputSchema": [
            "type": "object",
            "properties": [
                "alert_id": ["type": "string", "description": "The alert ID to suppress"],
            ],
            "required": ["alert_id"],
        ] as [String: Any],
    ],
]

// MARK: - Tool Handlers

let dataDir = resolveDataDir()

func handleToolCall(name: String, args: [String: Any]) async -> Any {
    switch name {
    case "get_alerts":
        return await handleGetAlerts(args)
    case "get_events":
        return await handleGetEvents(args)
    case "get_campaigns":
        return await handleGetCampaigns(args)
    case "get_status":
        return await handleGetStatus()
    case "hunt":
        return await handleHunt(args)
    case "get_security_score":
        return await handleGetSecurityScore()
    case "suppress_alert":
        return await handleSuppressAlert(args)
    default:
        return ["content": [["type": "text", "text": "Unknown tool: \(name)"]]]
    }
}

func handleGetAlerts(_ args: [String: Any]) async -> Any {
    let limit = min(args["limit"] as? Int ?? 20, 100)
    let hours = args["hours"] as? Double ?? 24
    let severityFilter = (args["severity"] as? String).flatMap { Severity(rawValue: $0) }
    let includeSuppressed = args["include_suppressed"] as? Bool ?? false

    do {
        let store = try AlertStore(directory: dataDir)
        let since = Date().addingTimeInterval(-hours * 3600)
        let alerts = try await store.alerts(since: since, severity: severityFilter, suppressed: includeSuppressed ? nil : false, limit: limit)

        var lines: [String] = ["\(alerts.count) alert(s) from last \(Int(hours))h:"]
        for alert in alerts {
            let time = ISO8601DateFormatter().string(from: alert.timestamp)
            lines.append("")
            lines.append("[\(alert.severity.rawValue.uppercased())] \(alert.ruleTitle)")
            lines.append("  Time: \(time)")
            lines.append("  ID: \(alert.id)")
            if let proc = alert.processName { lines.append("  Process: \(proc)") }
            if let path = alert.processPath { lines.append("  Path: \(path)") }
            if let desc = alert.description { lines.append("  Detail: \(desc.prefix(300))") }
            if let techs = alert.mitreTechniques, !techs.isEmpty { lines.append("  MITRE: \(techs)") }
        }

        return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
    } catch {
        return ["content": [["type": "text", "text": "Error reading alerts: \(error.localizedDescription)"]]]
    }
}

func handleGetEvents(_ args: [String: Any]) async -> Any {
    let limit = min(args["limit"] as? Int ?? 20, 100)
    let hours = args["hours"] as? Double ?? 24
    let search = args["search"] as? String
    let category = args["category"] as? String

    do {
        let store = try EventStore(directory: dataDir)
        let since = Date().addingTimeInterval(-hours * 3600)
        let events: [Event]
        if let q = search {
            events = try await store.search(text: q, limit: limit)
        } else {
            let cat = category.flatMap { EventCategory(rawValue: $0) }
            events = try await store.events(since: since, category: cat, limit: limit)
        }

        var lines: [String] = ["\(events.count) event(s):"]
        for event in events {
            let time = ISO8601DateFormatter().string(from: event.timestamp)
            lines.append("")
            lines.append("\(time) [\(event.eventCategory.rawValue)] \(event.eventAction)")
            lines.append("  Process: \(event.process.name) (PID \(event.process.pid))")
            lines.append("  Path: \(event.process.executable)")
            if !event.process.commandLine.isEmpty { lines.append("  Cmd: \(event.process.commandLine.prefix(200))") }
            if let file = event.file { lines.append("  File: \(file.path)") }
            if let net = event.network {
                lines.append("  Network: \(net.destinationIp ?? "?"):\(net.destinationPort)")
            }
        }

        return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
    } catch {
        return ["content": [["type": "text", "text": "Error reading events: \(error.localizedDescription)"]]]
    }
}

func handleGetCampaigns(_ args: [String: Any]) async -> Any {
    let limit = min(args["limit"] as? Int ?? 10, 50)

    do {
        let store = try AlertStore(directory: dataDir)
        let all = try await store.alerts(since: Date.distantPast, limit: 1000)
        let campaigns = all.filter { $0.ruleId.hasPrefix("maccrab.campaign.") }.prefix(limit)

        if campaigns.isEmpty {
            return ["content": [["type": "text", "text": "No campaigns detected. This is good — no multi-stage attacks identified."]]]
        }

        var lines: [String] = ["\(campaigns.count) campaign(s) detected:"]
        for c in campaigns {
            let time = ISO8601DateFormatter().string(from: c.timestamp)
            let type = c.ruleId.replacingOccurrences(of: "maccrab.campaign.", with: "")
            lines.append("")
            lines.append("[\(c.severity.rawValue.uppercased())] \(c.ruleTitle)")
            lines.append("  Type: \(type)")
            lines.append("  Time: \(time)")
            if let desc = c.description { lines.append("  Detail: \(desc.prefix(300))") }
            if let tactics = c.mitreTactics { lines.append("  Tactics: \(tactics)") }
        }

        return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
    } catch {
        return ["content": [["type": "text", "text": "Error reading campaigns: \(error.localizedDescription)"]]]
    }
}

func handleGetStatus() async -> Any {
    let fm = FileManager.default
    let dbPath = dataDir + "/events.db"
    let dbExists = fm.fileExists(atPath: dbPath)
    let walExists = fm.fileExists(atPath: dbPath + "-wal")
    let daemonRunning = walExists  // WAL file = active writer

    var lines: [String] = ["MacCrab Status"]
    lines.append("═══════════════════════════════════")
    lines.append("Daemon: \(daemonRunning ? "Running" : "Offline")")
    lines.append("Database: \(dbExists ? dbPath : "Not found")")

    if dbExists {
        let size = (try? fm.attributesOfItem(atPath: dbPath))?[.size] as? UInt64 ?? 0
        lines.append("DB Size: \(ByteCountFormatter.string(fromByteCount: Int64(size), countStyle: .file))")
    }

    do {
        let eventStore = try EventStore(directory: dataDir)
        let alertStore = try AlertStore(directory: dataDir)
        let eventCount = try await eventStore.count()
        let alertCount = try await alertStore.count()
        lines.append("Total Events: \(eventCount)")
        lines.append("Total Alerts: \(alertCount)")
    } catch {}

    // Count compiled rules
    let rulesDir = dataDir + "/compiled_rules"
    let ruleCount = (try? fm.contentsOfDirectory(atPath: rulesDir))?.filter { $0.hasSuffix(".json") }.count ?? 0
    lines.append("Rules Loaded: \(ruleCount)")

    return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
}

func handleHunt(_ args: [String: Any]) async -> Any {
    guard let query = args["query"] as? String, !query.isEmpty else {
        return ["content": [["type": "text", "text": "Error: 'query' parameter is required"]]]
    }

    do {
        let store = try EventStore(directory: dataDir)
        let results = try await store.search(text: query, limit: 50)

        if results.isEmpty {
            return ["content": [["type": "text", "text": "No results for: \(query)\n\nTry broader terms or check different time ranges."]]]
        }

        var lines: [String] = ["\(results.count) result(s) for: \(query)"]
        for event in results.prefix(20) {
            let time = ISO8601DateFormatter().string(from: event.timestamp)
            lines.append("")
            lines.append("\(time) [\(event.eventCategory.rawValue)] \(event.process.name)")
            lines.append("  Path: \(event.process.executable)")
            if !event.process.commandLine.isEmpty { lines.append("  Cmd: \(event.process.commandLine.prefix(200))") }
        }

        return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
    } catch {
        return ["content": [["type": "text", "text": "Hunt error: \(error.localizedDescription)"]]]
    }
}

func handleGetSecurityScore() async -> Any {
    let scorer = SecurityScorer()
    let score = await scorer.calculate()

    var lines: [String] = [
        "Security Score: \(score.totalScore)/100 (Grade: \(score.grade))",
        "═══════════════════════════════════",
    ]

    for factor in score.factors {
        let icon = factor.status == "pass" ? "PASS" : (factor.status == "warn" ? "WARN" : "FAIL")
        lines.append("[\(icon)] \(factor.name): \(factor.score)/\(factor.maxScore) — \(factor.detail)")
    }

    if !score.recommendations.isEmpty {
        lines.append("")
        lines.append("Recommendations:")
        for rec in score.recommendations {
            lines.append("  - \(rec)")
        }
    }

    return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
}

func handleSuppressAlert(_ args: [String: Any]) async -> Any {
    guard let alertId = args["alert_id"] as? String, !alertId.isEmpty else {
        return ["content": [["type": "text", "text": "Error: 'alert_id' parameter is required"]]]
    }

    do {
        let store = try AlertStore(directory: dataDir)
        try await store.suppress(alertId: alertId)
        return ["content": [["type": "text", "text": "Alert \(alertId) suppressed successfully."]]]
    } catch {
        return ["content": [["type": "text", "text": "Error suppressing alert: \(error.localizedDescription)"]]]
    }
}

// MARK: - Main Loop (stdio JSON-RPC)

let decoder = JSONDecoder()

// Read JSON-RPC messages from stdin.
// MCP uses Content-Length framing, but many clients also send bare JSON lines.
// Support both: if a line starts with "Content-Length:", read the framed message.
// Otherwise, try to parse the line as a JSON-RPC request directly.
let stdinHandle = FileHandle.standardInput

// Disable stdout buffering for reliable pipe output
setbuf(stdout, nil)

while let line = readLine(strippingNewline: true) {
    let trimmed = line.trimmingCharacters(in: .whitespaces)
    guard !trimmed.isEmpty else { continue }

    var body: Data

    if trimmed.lowercased().hasPrefix("content-length:") {
        let lengthStr = trimmed.dropFirst("content-length:".count).trimmingCharacters(in: .whitespaces)
        guard let length = Int(lengthStr), length > 0 else { continue }

        // Read until blank line (end of headers)
        while let headerLine = readLine(strippingNewline: true), !headerLine.trimmingCharacters(in: .whitespaces).isEmpty {}

        // Read exactly `length` bytes
        body = stdinHandle.readData(ofLength: length)
    } else if trimmed.hasPrefix("{") {
        // Bare JSON line
        body = trimmed.data(using: .utf8) ?? Data()
    } else {
        continue
    }

    guard let request = try? decoder.decode(JSONRPCRequest.self, from: body) else {
        // Parse failed — send error response
        writeJSON(["jsonrpc": "2.0", "id": NSNull(), "error": ["code": -32700, "message": "Parse error: \(String(data: body, encoding: .utf8)?.prefix(100) ?? "nil")"]] as [String: Any])
        continue
    }

    // Handle synchronous methods inline, async methods via runloop spin
    switch request.method {
    case "initialize":
        sendResponse(id: request.id, result: [
            "protocolVersion": "2024-11-05",
            "capabilities": ["tools": [:] as [String: Any]] as [String: Any],
            "serverInfo": ["name": "maccrab", "version": "1.0.0"] as [String: Any],
        ] as [String: Any])
    case "notifications/initialized":
        break
    case "tools/list":
        sendResponse(id: request.id, result: ["tools": tools])
    case "ping":
        sendResponse(id: request.id, result: ["status": "ok"])
    case "tools/call":
        guard let params = request.params?.value as? [String: Any],
              let toolName = params["name"] as? String else {
            sendError(id: request.id, code: -32602, message: "Missing tool name")
            continue
        }
        let args = params["arguments"] as? [String: Any] ?? [:]
        let reqId = request.id

        // Use a semaphore on a background queue (not main) to avoid deadlock
        let sem = DispatchSemaphore(value: 0)
        var result: Any = ["content": [["type": "text", "text": "Internal error"]]]
        DispatchQueue.global().async {
            Task {
                result = await handleToolCall(name: toolName, args: args)
                sem.signal()
            }
        }
        sem.wait()
        sendResponse(id: reqId, result: result)
    default:
        sendError(id: request.id, code: -32601, message: "Method not found: \(request.method)")
    }
}
