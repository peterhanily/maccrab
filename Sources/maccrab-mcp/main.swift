// maccrab-mcp — MacCrab MCP Server
//
// Model Context Protocol server that exposes MacCrab's detection data
// to AI agents. Communicates via JSON-RPC 2.0 over stdio.
//
// Tools exposed:
//   get_alerts         — Query recent alerts with severity/time filtering
//   get_events         — Query recent events with category filtering
//   get_campaigns      — List detected attack campaigns
//   get_status         — Daemon status, rule count, event stats
//   hunt               — Full-text threat hunting (FTS over events)
//   get_security_score — System security posture score with factors
//   suppress_alert     — Suppress an alert by ID
//   get_alert_detail   — Full alert detail: description, LLM investigation, D3FEND, ancestry
//   suppress_campaign  — Suppress a campaign and all its contributing alerts
//   get_ai_alerts      — AI Guard alert stream (credential fence, boundary, injection, MCP)
//   scan_text          — Prompt injection scan via Forensicate.ai (self-protection for AI agents)
//
// Usage:
//   Register in Claude Code settings:
//   { "mcpServers": { "maccrab": { "command": "/path/to/maccrab-mcp" } } }

import Foundation
import MacCrabCore
import os.log

// Force unbuffered stdout for reliable pipe output
setbuf(stdout, nil)

private let logger = Logger(subsystem: "com.maccrab.mcp", category: "server")

// v1.11.1 (audit perf LOW): hoist ISO8601DateFormatter — pre-fix the
// MCP request handlers instantiated a new formatter per timestamp
// inside every loop. ~0.5 ms init cost each; at 100-row response
// sizes that was 50 ms wasted per request, before any actual data
// formatting. The formatter is stateless once configured, safe to
// share file-wide.
let isoFormatter = ISO8601DateFormatter()

// MARK: - Security: Parent Process Validation

/// Verify the MCP server was launched by a trusted parent process.
/// MCP stdio transport is inherently scoped to the launching process,
/// but this check adds defense-in-depth against unexpected invocations.
func validateParentProcess() {
    let ppid = getppid()
    var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
    let result = proc_pidpath(ppid, &buffer, UInt32(buffer.count))
    if result > 0 {
        let parentPath = String(cString: buffer)
        logger.info("MCP server started by PID \(ppid): \(parentPath)")
    } else {
        logger.warning("Could not resolve parent process path (PID \(ppid))")
    }
}

/// Audit log for state-modifying operations.
///
/// v1.18 Wave-3 P2b: besides the os.log line, append a durable JSON record
/// to a user-writable mutation log so an agent session's mutations survive
/// the process and can be surfaced in get_agent_session. We capture only
/// the caller's `ppid` here (sync path); the ppid→session join happens at
/// read time. Best-effort: a write failure never blocks the mutation.
func auditLog(_ operation: String, details: String) {
    logger.notice("MCP AUDIT: \(operation) — \(details)")
    appendJSONLine([
        "ts": ISO8601DateFormatter().string(from: Date()),
        "operation": operation,
        "details": details,
        "ppid": Int(getppid()),
    ], to: mcpMutationLogPath())
}

/// v1.18 Wave-3 P5: record EVERY MCP tool call (not just mutations) to a
/// durable per-call log, tagged with the caller's ppid (the session join
/// happens at read time). The complete agent-interaction rail.
func recordToolCall(_ tool: String, result: Any) {
    let isError = ((result as? [String: Any])?["isError"] as? Bool) ?? false
    appendJSONLine([
        "ts": ISO8601DateFormatter().string(from: Date()),
        "tool": tool,
        "is_error": isError,
        "ppid": Int(getppid()),
    ], to: mcpToolCallLogPath())
}

/// User app-support dir (uid-501-writable even when the engine's data dir
/// is the root-owned system dir).
func mcpUserDir() -> String {
    let fm = FileManager.default
    let dir = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)
        .first.map { $0.appendingPathComponent("MacCrab").path }
        ?? NSHomeDirectory() + "/Library/Application Support/MacCrab"
    try? fm.createDirectory(atPath: dir, withIntermediateDirectories: true)
    return dir
}

func mcpMutationLogPath() -> String { mcpUserDir() + "/mcp_mutations.jsonl" }
func mcpToolCallLogPath() -> String { mcpUserDir() + "/mcp_tool_calls.jsonl" }

/// Best-effort append of one JSON line to a durable log. Never throws —
/// a write failure must not block the operation being recorded.
func appendJSONLine(_ obj: [String: Any], to path: String) {
    guard JSONSerialization.isValidJSONObject(obj),
          let data = try? JSONSerialization.data(withJSONObject: obj),
          let text = String(data: data, encoding: .utf8) else { return }
    let bytes = Data((text + "\n").utf8)
    if let fh = FileHandle(forWritingAtPath: path) {
        defer { try? fh.close() }
        _ = try? fh.seekToEnd()
        try? fh.write(contentsOf: bytes)
    } else {
        try? bytes.write(to: URL(fileURLWithPath: path))
    }
}

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

/// Walk an MCP tool response dict and run every `content[].text` value
/// through `LLMSanitizer.sanitize`. Other fields pass through untouched
/// so structured ids (alert UUIDs, campaign ids, trace ids) are not
/// scrambled — but free-form text the agent will render to the user is
/// scrubbed of usernames, paths, IPs, hostnames, and credential shapes.
func sanitizeContent(_ result: Any) -> Any {
    guard var dict = result as? [String: Any] else { return result }
    if let content = dict["content"] as? [[String: Any]] {
        let scrubbed: [[String: Any]] = content.map { block in
            var b = block
            if (b["type"] as? String) == "text", let t = b["text"] as? String {
                b["text"] = LLMSanitizer.sanitize(t)
            }
            return b
        }
        dict["content"] = scrubbed
    }
    return dict
}

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
    // v1.17.4: MCP stdio transport is newline-delimited JSON (one compact
    // object per line), NOT LSP Content-Length framing. Compact
    // JSONSerialization (no .prettyPrinted) escapes any embedded newline, so
    // `str` contains none — appending "\n" is a safe single-line frame.
    let output = str + "\n"
    // Use POSIX write() for reliable unbuffered output
    let outputData = Array(output.utf8)
    outputData.withUnsafeBufferPointer { ptr in
        _ = Darwin.write(STDOUT_FILENO, ptr.baseAddress!, ptr.count)
    }
}

/// MCP CallToolResult failure shape. Validation failures, not-found, and
/// thrown exceptions set `isError: true` so an agent reads them as errors,
/// not as data. (Empty result SETS and successful verdicts stay
/// success-shaped — they are not tool failures.) The dispatcher merges this
/// dict into the JSON-RPC `result` envelope and only rewrites `content[].text`,
/// so the `isError` key rides through untouched, per the MCP schema.
func toolError(_ message: String) -> [String: Any] {
    ["isError": true, "content": [["type": "text", "text": message]]]
}

// MARK: - Tool Definitions

let tools: [[String: Any]] = [
    [
        "name": "get_alerts",
        "description": "Get recent security alerts from MacCrab. Returns alert details including rule name, severity, process info, MITRE techniques, and AI analysis if available. For result sets larger than `limit`, the response ends with `[next_cursor: <token>]` — pass that opaque token back as `cursor` to fetch the next page. Cursor pagination is keyset-based (constant-time at any depth) and ignores the `hours` filter.",
        "inputSchema": [
            "type": "object",
            "properties": [
                "limit": ["type": "integer", "description": "Max alerts to return (default 20, max 100)", "default": 20],
                "severity": ["type": "string", "description": "Filter by minimum severity: critical, high, medium, low, informational", "enum": ["critical", "high", "medium", "low", "informational"]],
                "hours": ["type": "number", "description": "Only alerts from the last N hours (default: 24). Ignored when `cursor` is set.", "default": 24],
                "include_suppressed": ["type": "boolean", "description": "Include suppressed alerts (default false)", "default": false],
                "cursor": ["type": "string", "description": "Opaque pagination token from a previous response's `next_cursor`. Returns alerts strictly older than the token's position."],
            ],
        ] as [String: Any],
    ],
    [
        "name": "get_events",
        "description": "Get recent security events (process executions, file operations, network connections, TCC changes) from MacCrab. For result sets larger than `limit`, the response ends with `[next_cursor: <token>]` — pass that opaque token back as `cursor` to fetch the next page. Cursor pagination is keyset-based and ignores the `hours` and `search` filters.",
        "inputSchema": [
            "type": "object",
            "properties": [
                "limit": ["type": "integer", "description": "Max events to return (default 20, max 100)", "default": 20],
                "category": ["type": "string", "description": "Filter by EventCategory rawValue. Note: DNS lookups themselves are NOT stored in the events table — DNSCollector emits to the alert path, not EventStore — so DNS observability comes via `get_alerts` matching DNS-pattern rules, not via this tool. Process-injection / TCC / file / authentication events all surface here.", "enum": ["process", "file", "network", "authentication", "tcc", "registry"]],
                "search": ["type": "string", "description": "Full-text search query. Ignored when `cursor` is set."],
                "hours": ["type": "number", "description": "Only events from the last N hours (default: 24). Ignored when `cursor` is set.", "default": 24],
                "cursor": ["type": "string", "description": "Opaque pagination token from a previous response's `next_cursor`. Returns events strictly older than the token's position."],
            ],
        ] as [String: Any],
    ],
    [
        "name": "get_campaigns",
        "description": "Get detected attack campaigns — kill chains, alert storms, AI compromise attempts, coordinated attacks, and lateral movement patterns. For result sets larger than `limit`, the response ends with `[next_cursor: <token>]` — pass that opaque token back as `cursor` to fetch the next page. Cursor pagination is keyset-based and queries the full alerts table (no in-process pre-filter cap).",
        "inputSchema": [
            "type": "object",
            "properties": [
                "limit": ["type": "integer", "description": "Max campaigns to return (default 10, max 100)", "default": 10],
                "cursor": ["type": "string", "description": "Opaque pagination token from a previous response's `next_cursor`. Returns campaigns strictly older than the token's position."],
            ],
        ] as [String: Any],
    ],
    [
        "name": "get_status",
        "description": "Get MacCrab daemon status: running state, rule count, event/alert counts, database size, security score, and active monitors.",
        "inputSchema": ["type": "object", "properties": [:] as [String: Any]] as [String: Any],
    ],
    [
        "name": "list_agent_sessions",
        "description": "List recent AI-coding-agent sessions observed on this Mac (Claude Code, Cursor, etc.): tool, project dir, first/last activity, and event count. Each carries a durable session id — pass it to get_agent_session for the full timeline.",
        "inputSchema": [
            "type": "object",
            "properties": [
                "limit": ["type": "integer", "description": "Max sessions (default 50, max 500)."],
            ],
        ] as [String: Any],
    ],
    [
        "name": "get_agent_session",
        "description": "Return one agent session's chronological timeline — the process / file / network events attributed to that AI tool and its descendants, keyed by the durable session id from list_agent_sessions.",
        "inputSchema": [
            "type": "object",
            "properties": [
                "session_id": ["type": "string", "description": "Durable agent session id (from list_agent_sessions)."],
                "limit": ["type": "integer", "description": "Max timeline events (default 500, max 2000)."],
            ],
            "required": ["session_id"],
        ] as [String: Any],
    ],
    [
        "name": "export_session_bundle",
        "description": "Export one agent session as a signed, Merkle-rooted, tamper-evident bundle (events + alerts + mutations) — a replayable black box for the session. Returns the bundle path, Merkle root, and signing status.",
        "inputSchema": [
            "type": "object",
            "properties": [
                "session_id": ["type": "string", "description": "Durable agent session id (from list_agent_sessions)."],
            ],
            "required": ["session_id"],
        ] as [String: Any],
    ],
    [
        "name": "verify_session_bundle",
        "description": "Verify a .maccrabsession bundle exported by export_session_bundle: recomputes the Merkle root over the content (detects any tamper) and verifies the signature. Returns merkle_ok, signed, signature_ok.",
        "inputSchema": [
            "type": "object",
            "properties": [
                "path": ["type": "string", "description": "Path to the .maccrabsession bundle directory (from export_session_bundle)."],
            ],
            "required": ["path"],
        ] as [String: Any],
    ],
    [
        "name": "hunt",
        "description": "Full-text threat hunting across events (FTS phrase / substring search over the event stream). Examples: 'ssh', 'launchctl', 'unsigned'. Note: this is a text search, not a natural-language or SQL interpreter.",
        "inputSchema": [
            "type": "object",
            "properties": [
                "query": ["type": "string", "description": "Full-text threat-hunting query (FTS phrase / substring match over events)"],
                "limit": ["type": "integer", "description": "Max results to return (default 50, max 100)", "default": 50],
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
    [
        "name": "get_alert_detail",
        "description": "Get full detail for a single alert by ID: complete description (no truncation), LLM investigation verdict and suggested actions, MITRE D3FEND mitigations, parent process ancestry, and remediation hints. Use after get_alerts to deep-dive a specific alert.",
        "inputSchema": [
            "type": "object",
            "properties": [
                "alert_id": ["type": "string", "description": "The alert ID to look up (from get_alerts)"],
            ],
            "required": ["alert_id"],
        ] as [String: Any],
    ],
    [
        "name": "suppress_campaign",
        "description": "Suppress a campaign alert and all of its contributing alerts in one operation. Use the campaign ID from get_campaigns. Audit-logged.",
        "inputSchema": [
            "type": "object",
            "properties": [
                "campaign_id": ["type": "string", "description": "The campaign alert ID to suppress (from get_campaigns)"],
                "confirm": ["type": "boolean", "description": "Set true to proceed when the campaign would suppress more than 50 contributing alerts (required for large fan-outs)"],
            ],
            "required": ["campaign_id"],
        ] as [String: Any],
    ],
    [
        "name": "get_ai_alerts",
        "description": "Get AI Guard specific alerts: credential fence violations, project boundary crossings, prompt injection detections, and MCP tool poisoning attempts. Useful for an AI coding tool to check whether MacCrab has flagged its own recent activity.",
        "inputSchema": [
            "type": "object",
            "properties": [
                "limit": ["type": "integer", "description": "Max alerts to return (default 20, max 100)", "default": 20],
                "hours": ["type": "number", "description": "Only alerts from the last N hours (default: 24)", "default": 24],
            ],
        ] as [String: Any],
    ],
    [
        "name": "scan_text",
        "description": "Scan text for prompt injection attacks using MacCrab's built-in Forensicate.ai scanner (87+ rules). An AI agent can call this before processing untrusted input — e.g. file contents, web pages, user-supplied prompts — to check for jailbreaks, DAN personas, encoded payloads, and multi-vector attacks. Returns verdict, confidence score, and matched rule names.",
        "inputSchema": [
            "type": "object",
            "properties": [
                "text": ["type": "string", "description": "Text to scan for prompt injection (max 10000 characters)"],
            ],
            "required": ["text"],
        ] as [String: Any],
    ],
    [
        "name": "cluster_alerts",
        "description": "Group recent alerts into clusters by shared rule and process. Reduces an N-alert triage view to a handful of fingerprints that the analyst can suppress, escalate, or explain one at a time. Each cluster carries size, max severity, MITRE tactics union, first/last seen timestamps, and a stable id so the client can track expand/collapse state. Pass `hours` to bound the window (default 24). Pass `min_severity` to drop low-severity noise (values: low/medium/high/critical).",
        "inputSchema": [
            "type": "object",
            "properties": [
                "hours": ["type": "integer", "description": "Hours of history to cluster (default 24, max 168)"],
                "min_severity": ["type": "string", "description": "Minimum severity to include (low/medium/high/critical)"],
            ],
        ] as [String: Any],
    ],

    // ─── v1.10 TraceGraph tools ────────────────────────────────────
    [
        "name": "get_traces",
        "description": "List recent causal traces from the v1.10 TraceGraph engine. Each trace is a materialized provenance graph anchored on a critical event (loader spawn, honeyfile read, etc.) with its full process / file / network ancestry. Returns id, title, anchor verdict, severity, status, node + edge counts, and timestamps. Pair with get_trace_detail to drill into one.",
        "inputSchema": [
            "type": "object",
            "properties": [
                "limit": ["type": "integer", "description": "Max traces to return (default 25, max 200)", "default": 25],
                "status": ["type": "string", "description": "Filter by status: open / closed / suppressed (default: any)"],
            ],
        ] as [String: Any],
    ],
    [
        "name": "get_trace_detail",
        "description": "Fetch one TraceGraph trace by id with its anchor verdict, member entities (process / file / network nodes), and the latest hash-chain entry. Use this after get_traces to inspect what the daemon decided about a specific incident.",
        "inputSchema": [
            "type": "object",
            "properties": [
                "trace_id": ["type": "string", "description": "Trace id (from get_traces)"],
            ],
            "required": ["trace_id"],
        ] as [String: Any],
    ],
    [
        "name": "hunt_trace",
        "description": "Substring search across trace titles and anchor verdicts. Returns matching traces with a one-line summary. Useful for an agent investigating a known process or path — pass `query: \"loader\"` or `query: \".aws/credentials\"`.",
        "inputSchema": [
            "type": "object",
            "properties": [
                "query": ["type": "string", "description": "Substring to match (case-insensitive)"],
                "limit": ["type": "integer", "description": "Max matches to return (default 25, max 100)", "default": 25],
            ],
            "required": ["query"],
        ] as [String: Any],
    ],
    [
        "name": "verify_bundle",
        "description": "Verify a .maccrabtrace bundle file: schema, Merkle root, signature, and replay determinism. Use to confirm a bundle hasn't been tampered with before forwarding it to a SOC or legal hold. Returns per-check pass/fail + the trace id + signing key fingerprint.",
        "inputSchema": [
            "type": "object",
            "properties": [
                "path": ["type": "string", "description": "Absolute path to the .maccrabtrace bundle"],
            ],
            "required": ["path"],
        ] as [String: Any],
    ],
    [
        "name": "trace_from_event",
        "description": "Pivot from an event id to the trace that contains it (if any). Returns the trace summary + the event's role within it (anchor / member / external).",
        "inputSchema": [
            "type": "object",
            "properties": [
                "event_id": ["type": "string", "description": "Event id (from get_events)"],
            ],
            "required": ["event_id"],
        ] as [String: Any],
    ],
    // v1.12.0 — Package Intelligence + Intent Classification tools.
    [
        "name": "check_typosquat_score",
        "description": "Score a package name against a curated, operator-replaceable corpus of popular npm/PyPI package names using Damerau-Levenshtein distance and Unicode TR39 confusable folding. Catches AI-hallucinated names (slopsquatting), homoglyph attacks (Cyrillic a vs Latin a), and adjacent-key transpositions. Returns nearest popular name + distance + score 0-100.",
        "inputSchema": [
            "type": "object",
            "properties": [
                "name": ["type": "string", "description": "Package name to check"],
                "registry": ["type": "string", "description": "Registry: npm or pypi", "enum": ["npm", "pypi"]],
            ],
            "required": ["name", "registry"],
        ] as [String: Any],
    ],
    [
        "name": "scan_package_content",
        "description": "Walk an installed package directory and compute content-anomaly score: size, language-fingerprint census, single-line >100KB bundle detection, Mach-O magic-byte detection, obfuscator markers (PyArmor, _0x identifiers, Mini Shai-Hulud signatures, webpack), bundled-runtime drop. Returns 0-100 score plus per-factor reasons.",
        "inputSchema": [
            "type": "object",
            "properties": [
                "path": ["type": "string", "description": "Absolute path to an installed package directory (e.g., /Users/me/node_modules/foo)"],
                "ecosystem": ["type": "string", "description": "Ecosystem: npm / pypi / homebrew", "enum": ["npm", "pypi", "homebrew"]],
            ],
            "required": ["path", "ecosystem"],
        ] as [String: Any],
    ],
    [
        "name": "analyze_package_metadata",
        "description": "Fetch one JSON metadata document from the registry (npm registry / PyPI JSON API) and score description length, boilerplate clone, homepage host class (free-host vs corporate), version-history burst, top-version-squat (99.x.x first-publish), and maintainer signals (noreply emails). One HTTP GET per package per 24h. Returns 0-100 score + per-factor reasons.",
        "inputSchema": [
            "type": "object",
            "properties": [
                "name": ["type": "string", "description": "Package name"],
                "registry": ["type": "string", "description": "Registry: npm or pypi", "enum": ["npm", "pypi"]],
            ],
            "required": ["name", "registry"],
        ] as [String: Any],
    ],
    [
        "name": "verify_package_attestation",
        "description": "Verify cryptographic provenance via npm Sigstore + GitHub Actions OIDC, or PyPI PEP 740 attestations. Optional prior_builder argument enables publishing-method-mismatch detection — the defining stolen-token republish signal. Returns status (.verified / .absent / .mismatched / .fetchFailed) + builder identity + source repo + warnings.",
        "inputSchema": [
            "type": "object",
            "properties": [
                "name": ["type": "string", "description": "Package name"],
                "version": ["type": "string", "description": "Version string (semver for npm, PEP 440 for PyPI)"],
                "registry": ["type": "string", "description": "Registry: npm or pypi", "enum": ["npm", "pypi"]],
                "prior_builder": ["type": "string", "description": "Optional: builder identity from a prior version to compare against for mismatch detection"],
            ],
            "required": ["name", "version", "registry"],
        ] as [String: Any],
    ],
    [
        "name": "classify_package_intent",
        "description": "LLM-driven structured-intent classifier. Takes a behavior brief (package name + installer lineage + credential reads + network egress + content anomaly flags + AI-agent attribution) and returns a calibrated IntentLabel (benign / credentialHarvest / exfiltration / persistence / destructive / reconnaissance / lateralMovement / unknown) + confidence + ranked reasons. Falls back to a deterministic heuristic classifier when no LLM is configured.",
        "inputSchema": [
            "type": "object",
            "properties": [
                "package_name": ["type": "string", "description": "Package name"],
                "registry": ["type": "string", "description": "npm / pypi / brew"],
                "version": ["type": "string", "description": "Optional version"],
                "installer_lineage": ["type": "array", "description": "Process basenames in install lineage", "items": ["type": "string"]],
                "credentials_read": ["type": "array", "description": "Paths of credential files read during install", "items": ["type": "string"]],
                "network_egress": ["type": "array", "description": "Hosts contacted during install", "items": ["type": "string"]],
                "files_written": ["type": "array", "description": "Up to 8 representative file paths written", "items": ["type": "string"]],
                "processes_spawned": ["type": "array", "description": "Process basenames spawned during install", "items": ["type": "string"]],
                "has_obfuscated_content": ["type": "boolean"],
                "has_bundled_runtime": ["type": "boolean"],
                "has_language_mismatch": ["type": "boolean"],
                "ai_agent_triggered": ["type": "boolean"],
            ],
            "required": ["package_name", "registry"],
        ] as [String: Any],
    ],
    [
        "name": "predict_next_technique",
        "description": "Given a sequence of MITRE ATT&CK tactic IDs already observed for a process tree, return the top-N most-likely next tactics from MacCrab's shipped kill-chain transition prior. Inspired by KillChainGraph (arXiv 2508.18230) but local-only, no GPU, no online training.",
        "inputSchema": [
            "type": "object",
            "properties": [
                "tactic_prefix": ["type": "array", "description": "ATT&CK tactic IDs (TA0001 etc.) in chronological order", "items": ["type": "string"]],
                "top_n": ["type": "integer", "description": "Number of predictions to return (default 3, max 14)"],
            ],
            "required": ["tactic_prefix"],
        ] as [String: Any],
    ],
    [
        "name": "score_text_style",
        "description": "Compute stylometric + LLM-text + urgency scores for a text blob (commit message / PR description / README). Used for: maintainer style-drift detection (mockingbird / persona takeover), LLM-generated text detection (em-dash density + hedge phrases + sentence variance), urgency-lexicon scoring (XZ-Utils Jia Tan / polyfill.io social-engineering pattern).",
        "inputSchema": [
            "type": "object",
            "properties": [
                "text": ["type": "string", "description": "Text to analyse (max 100KB)"],
                "author": ["type": "string", "description": "Optional author identifier — if provided and a baseline exists, returns a drift result"],
            ],
            "required": ["text"],
        ] as [String: Any],
    ],
    [
        "name": "get_intent_posterior",
        "description": "Return the Bayesian-intent-engine posterior for a process tree (by tree key, typically the installer PID). NOTE: the MCP server holds its own process-local BayesianIntentEngine — this is NOT the daemon's posterior. Use this tool to feed evidence (via observe_intent_evidence in the future) and read it back inside an MCP session. For the daemon's per-tree posterior, query the alerts emitted by `maccrab.intent.bayesian-posterior` via get_alerts.",
        "inputSchema": [
            "type": "object",
            "properties": [
                "tree_key": ["type": "string", "description": "Process tree key (anchor PID or lineage identifier)"],
            ],
            "required": ["tree_key"],
        ] as [String: Any],
    ],
    // ===================================================================
    // Mac Context Plugin Platform (v1.13a / v1.13b)
    // ===================================================================
    [
        "name": "forensics.list_plugins",
        "description": "List every forensic plugin registered in MacCrabForensics. Optional `category` filters by plugin type (collector / enricher / fingerprinter / analyzer).",
        "inputSchema": [
            "type": "object",
            "properties": [
                "category": ["type": "string", "description": "Optional. One of: collector, enricher, fingerprinter, analyzer."],
            ],
        ] as [String: Any],
    ],
    [
        "name": "forensics.create_case",
        "description": "Create a new forensic case to hold collected artifacts, and return its case_id. Plaintext (unencrypted) so an agent can reopen it headlessly. Run a collector against the returned case_id, then read results with forensics.search_artifacts / forensics.timeline.",
        "inputSchema": [
            "type": "object",
            "properties": [
                "name": ["type": "string", "description": "Short case label (≤200 chars)."],
                "notes": ["type": "string", "description": "Optional free-text notes."],
                "window_seconds": ["type": "integer", "description": "Optional time window (seconds back from now) recorded on the case."],
            ],
            "required": ["name"],
        ] as [String: Any],
    ],
    [
        "name": "forensics.run_collector",
        "description": "Invoke a Collector plugin against a case. Optional `inputs` (e.g. {\"path\": \"/usr/bin/codesign\"}) targets path-driven analyzers; see each plugin's declared inputs via forensics.list_plugins. Returns the CollectionResult (artifacts committed / rejected / status).",
        "inputSchema": [
            "type": "object",
            "properties": [
                "plugin_id": ["type": "string", "description": "Plugin id, e.g. com.maccrab.forensics.tcc-lite."],
                "case_id": ["type": "string", "description": "Target case UUID."],
                "inputs": ["type": "object", "description": "Optional operator-supplied inputs declared by the plugin (e.g. {\"path\": \"/full/path/to/binary\"})."],
            ],
            "required": ["plugin_id", "case_id"],
        ] as [String: Any],
    ],
    [
        "name": "forensics.search_artifacts",
        "description": "Search a case's committed artifacts. Filters: contentType, observedAfter (ISO8601), observedBefore (ISO8601), limit. Returns metadata-class artifacts unconditionally; higher classes require case.ai_content_allowed=1.",
        "inputSchema": [
            "type": "object",
            "properties": [
                "case_id": ["type": "string"],
                "content_type": ["type": "string"],
                "observed_after": ["type": "string"],
                "observed_before": ["type": "string"],
                "limit": ["type": "integer"],
            ],
            "required": ["case_id"],
        ] as [String: Any],
    ],
    [
        "name": "forensics.get_artifact",
        "description": "Fetch a single artifact by id within a case.",
        "inputSchema": [
            "type": "object",
            "properties": [
                "case_id": ["type": "string"],
                "artifact_id": ["type": "integer"],
            ],
            "required": ["case_id", "artifact_id"],
        ] as [String: Any],
    ],
    [
        "name": "forensics.timeline",
        "description": "Return a case's artifacts ordered by observed_at across all content types. Default 200 entries. (v1.13b extended meta-tool.)",
        "inputSchema": [
            "type": "object",
            "properties": [
                "case_id": ["type": "string"],
                "limit": ["type": "integer"],
            ],
            "required": ["case_id"],
        ] as [String: Any],
    ],
    [
        "name": "forensics.explain_case",
        "description": "Summarize a case for an operator: name + creation date + encryption state + plugin invocation count + artifact totals by content type. (v1.13b extended meta-tool.)",
        "inputSchema": [
            "type": "object",
            "properties": [
                "case_id": ["type": "string"],
            ],
            "required": ["case_id"],
        ] as [String: Any],
    ],
    [
        "name": "forensics.posture_findings",
        "description": "Return findings emitted by the v1.15 posture Analyzer. v1.13b: returns an empty array — the Analyzer ships at v1.15, this tool reserves the surface.",
        "inputSchema": [
            "type": "object",
            "properties": [
                "case_id": ["type": "string"],
            ],
            "required": ["case_id"],
        ] as [String: Any],
    ],
    // ===================================================================
    // Forensics plugins — third-party scanners installed by the
    // operator. The on-the-wire MCP names use the customer-shaped
    // `forensics.*` namespace; the legacy `tierb.*` names from
    // v1.16 are kept as silent aliases through v1.18 so existing
    // AI-agent integrations don't break.
    // ===================================================================
    [
        "name": "forensics.list_installed_plugins",
        "description": "List installed third-party scanners with their verification status. Returns plugins_root, trusted_key_count, revoked_key_count, verified + failed buckets. Verified plugins include manifest version + publisher key prefix; failed plugins include reason (e.g. revoked key).",
        "inputSchema": [
            "type": "object",
            "properties": [:] as [String: Any],
        ] as [String: Any],
    ],
    [
        "name": "forensics.verify_installed_plugins",
        "description": "Force re-verification of every installed third-party scanner against the current trust + revocation lists. Same payload as forensics.list_installed_plugins but bypasses the bootstrap cache.",
        "inputSchema": [
            "type": "object",
            "properties": [:] as [String: Any],
        ] as [String: Any],
    ],
    // ===================================================================
    // v1.18 — Agent control-plane (customizable skill). All mutating tools
    // are OFF BY DEFAULT and require a human-enabled capability tier (config
    // / authoring / response). See AgentControl.swift.
    // ===================================================================
    [
        "name": "agent_capabilities",
        "description": "Report which MacCrab agent-control capability tiers (config / authoring / response) the human has enabled, and how to enable them. Read-only. Call this first — every other control tool is denied unless its tier is on.",
        "inputSchema": ["type": "object", "properties": [:] as [String: Any]] as [String: Any],
    ],
    [
        "name": "list_builtin_rules",
        "description": "List the built-in maccrab.* detections with their category and effective severity (after any operator override), and whether each is muted. Read-only.",
        "inputSchema": ["type": "object", "properties": [:] as [String: Any]] as [String: Any],
    ],
    [
        "name": "get_audit_log",
        "description": "Return the tail of the privileged-mutation audit log (every config/rule/suppression change the engine applied). Read-only.",
        "inputSchema": [
            "type": "object",
            "properties": ["limit": ["type": "integer", "description": "max lines (1-500, default 50)"]],
        ] as [String: Any],
    ],
    [
        "name": "set_builtin_rule_setting",
        "description": "Mute/enable a built-in maccrab.* detection or override its severity. Requires the 'config' capability. Detection + any protective action still run when an alert is muted; only the alert is suppressed.",
        "inputSchema": [
            "type": "object",
            "properties": [
                "rule_id": ["type": "string", "description": "a maccrab.* rule id (see list_builtin_rules)"],
                "enabled": ["type": "boolean", "description": "false mutes the alert"],
                "severity": ["type": "string", "description": "critical|high|medium|low|informational; null clears to default"],
            ],
            "required": ["rule_id"],
        ] as [String: Any],
    ],
    [
        "name": "reload_rules",
        "description": "Ask the engine to reload its compiled rules + user rules. Requires the 'config' capability.",
        "inputSchema": ["type": "object", "properties": [:] as [String: Any]] as [String: Any],
    ],
    [
        "name": "refresh_threat_intel",
        "description": "Ask the engine to refresh its threat-intel feeds. Requires the 'config' capability.",
        "inputSchema": ["type": "object", "properties": [:] as [String: Any]] as [String: Any],
    ],
    [
        "name": "set_daemon_config",
        "description": "Set one allowed daemon_config key. Safe tunables (thresholds, poll intervals) require the 'config' capability; defense-affecting keys (subscribe_introspection_events, subscribe_file_open_events, ultrasonic_enabled) require the higher 'response' capability because turning them off reduces detection coverage.",
        "inputSchema": [
            "type": "object",
            "properties": [
                "key": ["type": "string", "description": "an allowed daemon_config key (call with an invalid key to see the allow-list)"],
                "value": ["description": "number or boolean matching the key's type"],
            ],
            "required": ["key", "value"],
        ] as [String: Any],
    ],
    [
        "name": "create_rule",
        "description": "Compile and install a new detection rule from a single Sigma YAML document. Requires the 'authoring' capability. The rule is validated by the bundled compiler before install; on success it appears in Detection → Rules and fires. Returns a compile error if the YAML is malformed.",
        "inputSchema": [
            "type": "object",
            "properties": ["yaml": ["type": "string", "description": "one Sigma YAML rule (≤64 KB). An 'id:' is minted if absent."]],
            "required": ["yaml"],
        ] as [String: Any],
    ],
    [
        "name": "delete_rule",
        "description": "Remove a user-authored rule by id. Requires the 'authoring' capability. Built-in maccrab.* detections cannot be deleted — tune them with set_builtin_rule_setting instead.",
        "inputSchema": [
            "type": "object",
            "properties": ["rule_id": ["type": "string", "description": "the id of a user-authored rule"]],
            "required": ["rule_id"],
        ] as [String: Any],
    ],
]

// MARK: - Tool Handlers

let dataDir = resolveDataDir()

/// v1.18: per-process suppression budget — defense-in-depth over the audit
/// log so a misbehaving agent can't mass-suppress across a session. Shared
/// by suppress_alert AND suppress_campaign so the campaign path can't bypass
/// the per-alert cap. Per-process (an agent restarting the server resets it,
/// hence the separate fan-out confirm on suppress_campaign for bulk hits).
actor SuppressBudget {
    private var used = 0
    let limit = 50
    func tryConsume() -> Bool {
        if used >= limit { return false }
        used += 1
        return true
    }
}
let suppressBudget = SuppressBudget()

// v1.18: resolve the trace store path ONCE (writer-aware) instead of per
// handler, so the chosen dir can't flip between calls.
let traceGraphPath = resolveTraceGraphPath()

func handleToolCall(name: String, args: [String: Any]) async -> Any {
    // v1.18 agent control-plane: deny mutating tools whose capability tier the
    // human hasn't enabled (all tiers off by default). Read-only tools pass.
    if let denial = agentCapabilityDenial(forTool: name, args: args) { return denial }
    switch name {
    // v1.18 agent control-plane (see AgentControl.swift).
    case "agent_capabilities":
        return handleAgentCapabilities()
    case "list_builtin_rules":
        return handleListBuiltinRules()
    case "get_audit_log":
        return handleGetAuditLog(args)
    case "set_builtin_rule_setting":
        return handleSetBuiltinRuleSetting(args)
    case "reload_rules":
        return handleReloadRules()
    case "refresh_threat_intel":
        return handleRefreshThreatIntel()
    case "set_daemon_config":
        return handleSetDaemonConfig(args)
    case "create_rule":
        return await handleCreateRule(args)
    case "delete_rule":
        return handleDeleteRule(args)
    case "get_alerts":
        return await handleGetAlerts(args)
    case "get_events":
        return await handleGetEvents(args)
    case "get_campaigns":
        return await handleGetCampaigns(args)
    case "get_status":
        return await handleGetStatus()
    case "list_agent_sessions":
        return await handleListAgentSessions(args)
    case "get_agent_session":
        return await handleGetAgentSession(args)
    case "export_session_bundle":
        return await handleExportSessionBundle(args)
    case "verify_session_bundle":
        return await handleVerifySessionBundle(args)
    case "hunt":
        return await handleHunt(args)
    case "get_security_score":
        return await handleGetSecurityScore()
    case "suppress_alert":
        return await handleSuppressAlert(args)
    case "get_alert_detail":
        return await handleGetAlertDetail(args)
    case "suppress_campaign":
        return await handleSuppressCampaign(args)
    case "get_ai_alerts":
        return await handleGetAIAlerts(args)
    case "scan_text":
        return await handleScanText(args)
    case "cluster_alerts":
        return await handleClusterAlerts(args)
    case "get_traces":
        return await handleGetTraces(args)
    case "get_trace_detail":
        return await handleGetTraceDetail(args)
    case "hunt_trace":
        return await handleHuntTrace(args)
    case "verify_bundle":
        return await handleVerifyBundle(args)
    case "trace_from_event":
        return await handleTraceFromEvent(args)
    // v1.12.0 — Package Intelligence + Intent Classification.
    case "check_typosquat_score":
        return await handleCheckTyposquatScore(args)
    case "scan_package_content":
        return await handleScanPackageContent(args)
    case "analyze_package_metadata":
        return await handleAnalyzePackageMetadata(args)
    case "verify_package_attestation":
        return await handleVerifyPackageAttestation(args)
    case "classify_package_intent":
        return await handleClassifyPackageIntent(args)
    case "predict_next_technique":
        return await handlePredictNextTechnique(args)
    case "score_text_style":
        return await handleScoreTextStyle(args)
    case "get_intent_posterior":
        return await handleGetIntentPosterior(args)
    // v1.13a / v1.13b — Mac Context Plugin Platform meta-tools.
    case "forensics.list_plugins":
        return await handleForensicsListPlugins(args)
    case "forensics.create_case":
        return await handleForensicsCreateCase(args)
    case "forensics.run_collector":
        return await handleForensicsRunCollector(args)
    case "forensics.search_artifacts":
        return await handleForensicsSearchArtifacts(args)
    case "forensics.get_artifact":
        return await handleForensicsGetArtifact(args)
    case "forensics.timeline":
        return await handleForensicsTimeline(args)
    case "forensics.explain_case":
        return await handleForensicsExplainCase(args)
    case "forensics.posture_findings":
        return await handleForensicsPostureFindings(args)
    case "forensics.list_installed_plugins":
        return await handleTierBListPlugins()
    case "forensics.verify_installed_plugins":
        return await handleTierBVerify()
    // v1.17 rc.7 — legacy aliases (silent, no warning). Keep
    // through v1.18; remove in v1.19.
    case "tierb.list_plugins":
        return await handleTierBListPlugins()
    case "tierb.verify":
        return await handleTierBVerify()
    default:
        // Dynamically-registered per-plugin tools (manifest-declared
        // mcpTools on collector plugins). Forward-compatible: future
        // installed collector plugins route here automatically.
        try? await ForensicsMCPBootstrapper.shared.ensure()
        if let manifest = await pluginForMCPTool(name) {
            return await handlePluginMCPTool(name: name, manifest: manifest, args: args)
        }
        return toolError("Unknown tool: \(name)")
    }
}

// MARK: - Tier B MCP handlers

private let sharedTierBBootstrap = TierBBootstrap()

func handleTierBListPlugins() async -> Any {
    let status = await sharedTierBBootstrap.status(force: false)
    return ["content": [["type": "text", "text": jsonStringify(tierBStatusPayload(status))]]]
}

func handleTierBVerify() async -> Any {
    let status = await sharedTierBBootstrap.refresh()
    return ["content": [["type": "text", "text": jsonStringify(tierBStatusPayload(status))]]]
}

// tierb.run_installed (subprocess spawn) is research-only and
// remains on the `research/post-v15` branch. v1.16 ships
// tierb.list_plugins + tierb.verify (the discovery surface);
// spawn ships when NSXPCConnection + XPC service bundling lands.

private func tierBStatusPayload(_ status: TierBBootstrap.Status) -> [String: Any] {
    let isoFmt = ISO8601DateFormatter()
    return [
        "plugins_root": status.pluginsRoot,
        "verified_at": isoFmt.string(from: status.verifiedAt),
        "trusted_key_count": status.trustedKeyCount,
        "revoked_key_count": status.revokedKeyCount,
        "verified": status.verified.map { v -> [String: Any] in
            [
                "plugin_id": v.pluginID,
                "version": v.version,
                "bundle_root": v.bundleRoot,
                "publisher_key_hex": v.publicKeyHex,
                // v1.19.0: "store" (signed rave-catalog receipt) vs "third-party"
                // (operator-trusted sideload). Built-ins are listed separately.
                "provenance": v.provenance.rawValue,
            ]
        },
        "failed": status.failed.map { f -> [String: Any] in
            [
                "plugin_id": f.pluginID,
                "reason": f.reason,
            ]
        },
        // O2: installed plugins quarantined by a signed revocation. On disk
        // (evidence preserved) but refused load.
        "quarantined": status.quarantined.map { q -> [String: Any] in
            var entry: [String: Any] = [
                "plugin_id": q.pluginID,
                "installed_version": q.installedVersion,
                "reason": q.reason,
                "code": q.code,
                "quarantined_at": q.quarantinedAt,
            ]
            if let s = q.revocationsSerial { entry["revocations_serial"] = s }
            if let u = q.advisoryURL { entry["advisory_url"] = u }
            return entry
        },
    ]
}

// MARK: - v1.12.0 Package Intelligence + Intent handlers

/// Shared intent engine instance for posterior queries within the
/// MCP server lifetime. Initialised on first use.
private let sharedIntentEngine = BayesianIntentEngine()
private let sharedTyposquatDB = TyposquatDatabase()
private let sharedNextPredictor = NextTechniquePredictor()
private let sharedStylometric = StylometricFingerprinter()

/// Resolve an LLM backend for the MCP server (currently only
/// classify_package_intent uses it). Builds an LLMConfig from the
/// dashboard-written `llm_config.json` + env overrides — the same
/// non-entitled-reader path the sysext uses — and lets
/// `LLMService.makeFromConfig` run its bounded 3 s availability probe.
/// Returns nil (→ heuristic fallback) when nothing is configured or the
/// backend is unreachable. Keychain is intentionally NOT read here to
/// avoid any interactive prompt in an agent-driven server process.
private func resolveMCPLLMService() async -> LLMService? {
    var config = LLMConfig()
    var hasConfig = false
    let configPath = dataDir + "/llm_config.json"
    if let data = try? Data(contentsOf: URL(fileURLWithPath: configPath)),
       let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
        if let enabled = json["enabled"] as? Bool { config.enabled = enabled }
        if let provider = json["provider"] as? String {
            config.provider = LLMProvider(rawValue: provider) ?? config.provider
        }
        if let v = json["ollama_url"] as? String { config.ollamaURL = v }
        if let v = json["ollama_model"] as? String { config.ollamaModel = v }
        if let v = json["ollama_api_key"] as? String { config.ollamaAPIKey = v }
        if let v = json["claude_api_key"] as? String { config.claudeAPIKey = v }
        if let v = json["claude_model"] as? String { config.claudeModel = v }
        if let v = json["openai_url"] as? String { config.openaiURL = v }
        if let v = json["openai_api_key"] as? String { config.openaiAPIKey = v }
        if let v = json["openai_model"] as? String { config.openaiModel = v }
        if let v = json["mistral_api_key"] as? String { config.mistralAPIKey = v }
        if let v = json["mistral_model"] as? String { config.mistralModel = v }
        if let v = json["gemini_api_key"] as? String { config.geminiAPIKey = v }
        if let v = json["gemini_model"] as? String { config.geminiModel = v }
        hasConfig = config.enabled
    }
    let env = ProcessInfo.processInfo.environment
    if let p = env["MACCRAB_LLM_PROVIDER"] {
        config.provider = LLMProvider(rawValue: p) ?? config.provider
        hasConfig = true
    }
    if let v = env["MACCRAB_LLM_OLLAMA_URL"] { config.ollamaURL = v }
    if let v = env["MACCRAB_LLM_OLLAMA_MODEL"] { config.ollamaModel = v }
    if let v = env["MACCRAB_LLM_CLAUDE_KEY"] { config.claudeAPIKey = v }
    if let v = env["MACCRAB_LLM_OPENAI_URL"] { config.openaiURL = v }
    if let v = env["MACCRAB_LLM_OPENAI_KEY"] { config.openaiAPIKey = v }
    guard hasConfig else { return nil }
    return await LLMService.makeFromConfig(config)
}

/// Probe-once cache so classify_package_intent doesn't re-resolve (and
/// re-probe) the backend on every call.
private let sharedMCPLLMService = Task<LLMService?, Never> { await resolveMCPLLMService() }

func handleCheckTyposquatScore(_ args: [String: Any]) async -> Any {
    guard let name = args["name"] as? String,
          let registryRaw = args["registry"] as? String,
          let registry = TyposquatDatabase.Registry(rawValue: registryRaw) else {
        return toolError("Error: 'name' and 'registry' (npm|pypi) required")
    }
    let result = await sharedTyposquatDB.score(candidate: name, registry: registry)
    var lines: [String] = ["Typosquat scan: \(name) (\(registry.rawValue))"]
    lines.append("Score: \(result.score)/100")
    if let similar = result.similarTo, let distance = result.distance {
        lines.append("Closest popular: '\(similar)' (Damerau-Levenshtein \(distance))")
    } else {
        lines.append("No nearby popular name in the bundled package-name corpus")
    }
    lines.append("Homoglyph: \(result.isHomoglyph ? "YES" : "no")")
    for reason in result.reasons { lines.append("- \(reason)") }
    return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
}

func handleScanPackageContent(_ args: [String: Any]) async -> Any {
    guard let path = args["path"] as? String,
          let ecosystemRaw = args["ecosystem"] as? String,
          let ecosystem = PackageContentAnalyzer.Ecosystem(rawValue: ecosystemRaw) else {
        return toolError("Error: 'path' and 'ecosystem' (npm|pypi|homebrew) required")
    }
    let analyzer = PackageContentAnalyzer()
    let result = await analyzer.analyze(packagePath: URL(fileURLWithPath: path), ecosystem: ecosystem)
    var lines: [String] = ["Content scan: \(path)"]
    lines.append("Score: \(result.score)/100")
    lines.append("Total bytes: \(result.totalBytes)")
    lines.append("File count: \(result.fileCount)")
    if !result.singleLineLargeFiles.isEmpty {
        lines.append("Single-line large files: \(result.singleLineLargeFiles.joined(separator: ", "))")
    }
    if !result.nativeBinaryFiles.isEmpty {
        lines.append("Native binaries: \(result.nativeBinaryFiles.joined(separator: ", "))")
    }
    if !result.obfuscatorMatches.isEmpty {
        lines.append("Obfuscator markers: \(result.obfuscatorMatches.joined(separator: "; "))")
    }
    if !result.bundledRuntimeFiles.isEmpty {
        lines.append("Bundled runtime drops: \(result.bundledRuntimeFiles.joined(separator: ", "))")
    }
    for reason in result.reasons { lines.append("- \(reason)") }
    return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
}

func handleAnalyzePackageMetadata(_ args: [String: Any]) async -> Any {
    guard let name = args["name"] as? String,
          let registryRaw = args["registry"] as? String,
          let registry = PackageMetadataAnalyzer.Registry(rawValue: registryRaw) else {
        return toolError("Error: 'name' and 'registry' (npm|pypi) required")
    }
    let analyzer = PackageMetadataAnalyzer()
    guard let result = await analyzer.analyze(packageName: name, registry: registry) else {
        return toolError("Failed to fetch metadata for \(name) on \(registry.rawValue)")
    }
    var lines: [String] = ["Metadata scan: \(name) (\(registry.rawValue))"]
    lines.append("Score: \(result.score)/100")
    lines.append("Description length: \(result.descriptionLength)")
    lines.append("Homepage: \(result.homepage ?? "(missing)") [\(result.homepageHostClass.rawValue)]")
    lines.append("Repo: \(result.repositoryURL ?? "(missing)")")
    lines.append("First version: \(result.firstVersion ?? "?")  Latest: \(result.latestVersion ?? "?")")
    lines.append("Maintainer emails: \(result.maintainerEmails.joined(separator: ", "))")
    for reason in result.reasons { lines.append("- \(reason)") }
    return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
}

func handleVerifyPackageAttestation(_ args: [String: Any]) async -> Any {
    guard let name = args["name"] as? String,
          let version = args["version"] as? String,
          let registryRaw = args["registry"] as? String,
          let registry = AttestationEnricher.Registry(rawValue: registryRaw) else {
        return toolError("Error: 'name', 'version', and 'registry' (npm|pypi) required")
    }
    let priorBuilder = args["prior_builder"] as? String
    let enricher = AttestationEnricher()
    let result = await enricher.verify(packageName: name, version: version, registry: registry, priorBuilder: priorBuilder)
    var lines: [String] = ["Attestation: \(name)@\(version) (\(registry.rawValue))"]
    lines.append("Status: \(result.status.rawValue)")
    if let builder = result.builder { lines.append("Builder: \(builder)") }
    if let repo = result.sourceRepo { lines.append("Source repo: \(repo)") }
    if let prior = result.priorBuilder { lines.append("Compared against prior builder: \(prior)") }
    for warning in result.warnings { lines.append("⚠ \(warning)") }
    return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
}

func handleClassifyPackageIntent(_ args: [String: Any]) async -> Any {
    guard let packageName = args["package_name"] as? String,
          let registry = args["registry"] as? String else {
        return toolError("Error: 'package_name' and 'registry' required")
    }
    let brief = IntentClassifier.BehaviorBrief(
        packageName: packageName,
        packageRegistry: registry,
        packageVersion: args["version"] as? String,
        installerLineage: (args["installer_lineage"] as? [String]) ?? [],
        credentialsRead: (args["credentials_read"] as? [String]) ?? [],
        networkEgress: (args["network_egress"] as? [String]) ?? [],
        filesWritten: (args["files_written"] as? [String]) ?? [],
        processesSpawned: (args["processes_spawned"] as? [String]) ?? [],
        hasObfuscatedContent: (args["has_obfuscated_content"] as? Bool) ?? false,
        hasBundledRuntime: (args["has_bundled_runtime"] as? Bool) ?? false,
        hasLanguageMismatch: (args["has_language_mismatch"] as? Bool) ?? false,
        aiAgentTriggered: (args["ai_agent_triggered"] as? Bool) ?? false
    )
    // Use a configured LLM backend when one is available (resolved +
    // availability-probed once per process); IntentClassifier falls back
    // to its deterministic heuristic when this is nil.
    let classifier = IntentClassifier(llmService: await sharedMCPLLMService.value)
    let result = await classifier.classify(brief)
    var lines: [String] = ["Intent classification: \(packageName)"]
    lines.append("Label: \(result.label.rawValue)")
    lines.append("Confidence: \(String(format: "%.2f", result.confidence))")
    lines.append("Provider: \(result.provider)")
    lines.append("Abstained: \(result.abstained)")
    for reason in result.reasons { lines.append("- \(reason)") }
    return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
}

func handlePredictNextTechnique(_ args: [String: Any]) async -> Any {
    guard let prefix = args["tactic_prefix"] as? [String], !prefix.isEmpty else {
        return toolError("Error: 'tactic_prefix' (array of ATT&CK TA00xx ids) required")
    }
    let topN = min(14, max(1, (args["top_n"] as? Int) ?? 3))
    let tactics = prefix.compactMap { NextTechniquePredictor.Tactic(rawValue: $0) }
    guard !tactics.isEmpty else {
        return toolError("Error: no recognised ATT&CK tactic IDs in prefix")
    }
    let predictions = await sharedNextPredictor.predictNext(after: tactics, topN: topN)
    var lines: [String] = ["Next-tactic predictions after \(prefix.joined(separator: " → "))"]
    for pred in predictions {
        lines.append("  \(pred.tactic.rawValue): \(String(format: "%.2f", pred.probability))")
    }
    return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
}

func handleScoreTextStyle(_ args: [String: Any]) async -> Any {
    guard let text = args["text"] as? String, !text.isEmpty else {
        return toolError("Error: 'text' required")
    }
    guard text.count <= 100_000 else {
        return toolError("Error: text too long (max 100KB)")
    }
    let llmScore = await sharedStylometric.llmTextScore(text)
    let urgency = await sharedStylometric.urgencyScore(text)
    var lines: [String] = ["Stylometric scan"]
    lines.append("LLM-text score: \(llmScore)/100")
    lines.append("Urgency score: \(urgency.score)/100")
    if !urgency.matchedTerms.isEmpty {
        lines.append("Urgency terms matched: \(urgency.matchedTerms.joined(separator: ", "))")
    }
    if let author = args["author"] as? String, !author.isEmpty {
        if let drift = await sharedStylometric.checkDrift(author: author, text: text) {
            lines.append("Author '\(author)' drift cosine distance: \(String(format: "%.3f", drift.cosineDistance))")
            lines.append("Flagged: \(drift.flagged ? "YES" : "no")")
            for reason in drift.reasons { lines.append("  - \(reason)") }
        } else {
            lines.append("No baseline yet for author '\(author)' — call again to start the rolling baseline")
        }
    }
    return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
}

func handleGetIntentPosterior(_ args: [String: Any]) async -> Any {
    guard let treeKey = args["tree_key"] as? String, !treeKey.isEmpty else {
        return toolError("Error: 'tree_key' required")
    }
    guard let posterior = await sharedIntentEngine.posterior(treeKey: treeKey) else {
        return ["content": [["type": "text", "text": "No posterior found for tree '\(treeKey)' — no evidence has been observed yet"]]]
    }
    var lines: [String] = ["Intent posterior for tree \(treeKey)"]
    lines.append("Top goal: \(posterior.topGoal.rawValue) (\(String(format: "%.3f", posterior.topProbability)))")
    let sorted = posterior.probabilities.sorted { $0.value > $1.value }
    lines.append("Full distribution:")
    for (goal, prob) in sorted {
        lines.append("  \(goal.rawValue): \(String(format: "%.3f", prob))")
    }
    lines.append("Evidence log (last \(min(posterior.evidenceLog.count, 8))):")
    for ev in posterior.evidenceLog.suffix(8) {
        lines.append("  - \(ev.rawValue)")
    }
    return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
}

// MARK: - cluster_alerts (v1.6.7)

/// Group recent alerts by rule+process fingerprint so the triage view
/// collapses to clusters instead of individual events.
func handleClusterAlerts(_ args: [String: Any]) async -> Any {
    let hours = max(1, min((args["hours"] as? Int) ?? 24, 168))
    let minSevString = (args["min_severity"] as? String)?.lowercased() ?? ""
    let minSeverity: Severity? = {
        switch minSevString {
        case "low": return .low
        case "medium": return .medium
        case "high": return .high
        case "critical": return .critical
        default: return nil
        }
    }()

    let store: AlertStore
    do {
        // Alerts live in alerts.db, not events.db. Use the directory:
        // initializer (which appends the canonical alerts.db filename)
        // exactly like handleGetAlerts and every other alert handler —
        // opening events.db here bound this to a dormant/empty `alerts`
        // table, so cluster_alerts always reported "0 alerts → 0 clusters".
        store = try AlertStore(directory: dataDir)
    } catch {
        return toolError("Failed to open AlertStore: \(error.localizedDescription)")
    }

    let since = Date().addingTimeInterval(-Double(hours) * 3600)
    let alerts: [Alert]
    do {
        // v1.11.1 (audit perf HIGH): push minSeverity into SQL so we
        // don't fetch up to 5000 rows just to discard most of them.
        // AlertStore.alerts already accepts a severity floor.
        alerts = try await store.alerts(since: since, severity: minSeverity, suppressed: false, limit: 5000)
    } catch {
        return toolError("Failed to query alerts: \(error.localizedDescription)")
    }

    let svc = AlertClusterService()
    let clusters = await svc.cluster(alerts: alerts)
    let filtered = alerts // alias retained for the summary line below

    let payload = clusters.map { c -> [String: Any] in
        [
            "id": c.id,
            "fingerprint": c.fingerprint,
            "rule_id": c.ruleId,
            "rule_title": c.ruleTitle,
            "process_name": c.processName,
            "process_path": c.processPath as Any,
            "severity": c.severity.rawValue,
            "size": c.size,
            "tactics": Array(c.tactics).sorted(),
            "first_seen": isoFormatter.string(from: c.firstSeen),
            "last_seen": isoFormatter.string(from: c.lastSeen),
            "member_alert_ids": c.memberAlertIds,
        ]
    }

    let summary = "Window: last \(hours)h — \(filtered.count) alerts → \(clusters.count) clusters"
    let data = try? JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys])
    let jsonText = data.flatMap { String(data: $0, encoding: .utf8) } ?? "[]"
    return [
        "content": [
            ["type": "text", "text": summary],
            ["type": "text", "text": jsonText],
        ]
    ]
}

// MARK: - Cursor encoding (v1.8.0)
//
// MCP responses are textual, so we serialize the keyset cursor as
// "<epoch>:<id>". The id portion is a UUID string for events and a
// UUID string for alerts — neither contains a colon, so a single-split
// is unambiguous. Token is opaque to callers; they pass it back unchanged.

private func encodeCursor(_ cursor: PaginationCursor) -> String {
    return "\(cursor.timestamp.timeIntervalSince1970):\(cursor.id)"
}

private func decodeCursor(_ raw: String) -> PaginationCursor? {
    guard let colon = raw.firstIndex(of: ":") else { return nil }
    let tsPart = raw[..<colon]
    let idPart = raw[raw.index(after: colon)...]
    guard let ts = Double(tsPart), !idPart.isEmpty else { return nil }
    return PaginationCursor(
        timestamp: Date(timeIntervalSince1970: ts),
        id: String(idPart)
    )
}

func handleGetAlerts(_ args: [String: Any]) async -> Any {
    let limit = min(max(args["limit"] as? Int ?? 20, 1), 100)
    let hours = args["hours"] as? Double ?? 24
    let severityFilter = (args["severity"] as? String).flatMap { Severity(rawValue: $0) }
    let includeSuppressed = args["include_suppressed"] as? Bool ?? false
    let cursor = (args["cursor"] as? String).flatMap(decodeCursor)

    do {
        let store = try AlertStore(directory: dataDir)
        let alerts: [Alert]
        let nextCursor: PaginationCursor?
        let header: String

        if cursor != nil {
            // Cursor path: keyset-paginated. The hours filter doesn't compose
            // with cursor pagination — the cursor IS the upper bound. Caller
            // can stop paging when results get older than they want.
            let page = try await store.alerts(
                before: cursor,
                severity: severityFilter,
                suppressed: includeSuppressed ? nil : false,
                pageSize: limit
            )
            alerts = page.items
            nextCursor = page.nextCursor
            header = "\(alerts.count) alert(s) (cursor page):"
        } else {
            let since = Date().addingTimeInterval(-hours * 3600)
            alerts = try await store.alerts(
                since: since,
                severity: severityFilter,
                suppressed: includeSuppressed ? nil : false,
                limit: limit
            )
            // Hand back a cursor only when the caller hit the page cap —
            // shorter result sets mean there's nothing more to read.
            if alerts.count == limit, let oldest = alerts.last {
                nextCursor = PaginationCursor(timestamp: oldest.timestamp, id: oldest.id)
            } else {
                nextCursor = nil
            }
            header = "\(alerts.count) alert(s) from last \(Int(hours))h:"
        }

        var lines: [String] = [header]
        for alert in alerts {
            let time = isoFormatter.string(from: alert.timestamp)
            lines.append("")
            lines.append("[\(alert.severity.rawValue.uppercased())] \(alert.ruleTitle)")
            lines.append("  Time: \(time)")
            lines.append("  ID: \(alert.id)")
            if let proc = alert.processName { lines.append("  Process: \(proc)") }
            // v1.12.0 RC25 (privacy): redact /Users/<name>/ paths
            // before handing the line to the LLM. LLMSanitizer covers
            // username, private IPs, SSH/AWS/JWT credential shapes.
            if let path = alert.processPath { lines.append("  Path: \(LLMSanitizer.sanitize(path))") }
            if let desc = alert.description { lines.append("  Detail: \(LLMSanitizer.sanitize(String(desc.prefix(300))))") }
            if let techs = alert.mitreTechniques, !techs.isEmpty { lines.append("  MITRE: \(techs)") }
        }
        if let next = nextCursor {
            lines.append("")
            lines.append("[next_cursor: \(encodeCursor(next))]")
        }

        return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
    } catch {
        return toolError("Error reading alerts: \(error.localizedDescription)")
    }
}

func handleGetEvents(_ args: [String: Any]) async -> Any {
    let limit = min(max(args["limit"] as? Int ?? 20, 1), 100)
    let hours = args["hours"] as? Double ?? 24
    let search = args["search"] as? String
    let category = args["category"] as? String
    let cursor = (args["cursor"] as? String).flatMap(decodeCursor)
    let cat = category.flatMap { EventCategory(rawValue: $0) }

    do {
        let store = try EventStore(directory: dataDir)
        let events: [Event]
        let nextCursor: PaginationCursor?

        if cursor != nil {
            // Cursor takes precedence over `search` and `hours` — same reasoning
            // as alerts, plus FTS search is relevance-ordered (incompatible
            // with keyset cursor's time ordering).
            let page = try await store.events(
                before: cursor,
                category: cat,
                pageSize: limit
            )
            events = page.items
            nextCursor = page.nextCursor
        } else if let q = search, !q.isEmpty {
            events = try await store.search(text: q, limit: limit)
            nextCursor = nil
        } else {
            let since = Date().addingTimeInterval(-hours * 3600)
            events = try await store.events(since: since, category: cat, limit: limit)
            if events.count == limit, let oldest = events.last {
                nextCursor = PaginationCursor(
                    timestamp: oldest.timestamp,
                    id: oldest.id.uuidString
                )
            } else {
                nextCursor = nil
            }
        }

        var lines: [String] = ["\(events.count) event(s):"]
        for event in events {
            let time = isoFormatter.string(from: event.timestamp)
            lines.append("")
            lines.append("\(time) [\(event.eventCategory.rawValue)] \(event.eventAction)")
            lines.append("  Process: \(event.process.name) (PID \(event.process.pid))")
            lines.append("  Path: \(event.process.executable)")
            if !event.process.commandLine.isEmpty { lines.append("  Cmd: \(event.process.commandLine.prefix(200))") }
            if let file = event.file { lines.append("  File: \(file.path)") }
            if let net = event.network {
                lines.append("  Network: \(net.destinationIp):\(net.destinationPort)")
            }
        }
        if let next = nextCursor {
            lines.append("")
            lines.append("[next_cursor: \(encodeCursor(next))]")
        }

        return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
    } catch {
        return toolError("Error reading events: \(error.localizedDescription)")
    }
}

func handleGetCampaigns(_ args: [String: Any]) async -> Any {
    let limit = min(max(args["limit"] as? Int ?? 10, 1), 100)
    let cursor = (args["cursor"] as? String).flatMap(decodeCursor)

    do {
        let store = try AlertStore(directory: dataDir)
        // Pre-fix this fetched 1000 alerts and filtered in-process — any
        // campaign older than the most-recent 1000 alerts was silently
        // dropped. Now the SQL filter (`rule_id LIKE 'maccrab.campaign.%'`)
        // is the only filter applied; pagination is keyset-based.
        let page = try await store.campaigns(before: cursor, pageSize: limit)
        let campaigns = page.items

        if campaigns.isEmpty && cursor == nil {
            return ["content": [["type": "text", "text": "No campaigns detected. This is good — no multi-stage attacks identified."]]]
        }

        var lines: [String] = ["\(campaigns.count) campaign(s) detected:"]
        for c in campaigns {
            let time = isoFormatter.string(from: c.timestamp)
            let type = c.ruleId.replacingOccurrences(of: "maccrab.campaign.", with: "")
            lines.append("")
            lines.append("[\(c.severity.rawValue.uppercased())] \(c.ruleTitle)")
            lines.append("  Type: \(type)")
            lines.append("  Time: \(time)")
            if let desc = c.description { lines.append("  Detail: \(desc.prefix(300))") }
            if let tactics = c.mitreTactics { lines.append("  Tactics: \(tactics)") }
        }
        if let next = page.nextCursor {
            lines.append("")
            lines.append("[next_cursor: \(encodeCursor(next))]")
        }

        return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
    } catch {
        return toolError("Error reading campaigns: \(error.localizedDescription)")
    }
}

func handleListAgentSessions(_ args: [String: Any]) async -> Any {
    let limit = min(max((args["limit"] as? Int) ?? 50, 1), 500)
    do {
        let store = try EventStore(directory: dataDir)
        // Fail-soft on the query: this is a READ tool, so an empty / young
        // store must return an empty list, not isError. On a fresh install
        // the `ai_tool_session_id` column is added by a SchemaMigrator step
        // that EventStore.openDatabase swallows-and-logs if it loses a
        // create-time lock race (e.g. WAL/checkpoint BUSY on a load-saturated
        // CI runner) — leaving the column absent so the SELECT throws
        // "no such column". Treat any such query failure as "nothing recorded
        // yet", mirroring get_traces' empty-store path.
        let sessions = (try? await store.agentSessions(limit: limit)) ?? []
        let iso = ISO8601DateFormatter()
        let payload = sessions.map { s -> [String: Any] in
            [
                "session_id": s.sessionId,
                "tool": s.tool as Any,
                "project_dir": s.projectDir as Any,
                "first_seen": iso.string(from: s.firstSeen),
                "last_seen": iso.string(from: s.lastSeen),
                "event_count": s.eventCount,
            ]
        }
        let note = payload.isEmpty
            ? "No agent sessions recorded yet. Sessions populate once the running engine includes the Wave-3 session stamping (ai_tool_session_id)."
            : ""
        return ["content": [["type": "text", "text": jsonStringify(["sessions": payload, "note": note])]]]
    } catch {
        // READ tool: a store that can't be opened — no engine has created it
        // (fresh box), or a create-time lock race lost it under load — means
        // "no sessions yet" for the caller, not isError. Mutation tools still
        // surface store-open failures.
        let note = "No agent sessions recorded yet (no engine store available)."
        return ["content": [["type": "text", "text": jsonStringify(["sessions": [Any](), "note": note])]]]
    }
}

/// Read the durable MCP mutation log and return the mutations whose ppid
/// resolves to `sessionId` (ppid-correlated, medium confidence). Bounded
/// to the most recent lines so an unbounded log can't blow up the call.
/// Read a durable ppid-tagged JSONL log and return the entries whose ppid
/// resolves (medium-confidence, ppid-correlated) to `sessionId`. Shared by
/// the mutation rail (P2b) and the tool-call rail (P5). `keep` picks the
/// fields surfaced per entry.
func logEntriesForSession(
    logPath: String, sessionId: String, store: EventStore, max: Int = 5000,
    keep: ([String: Any]) -> [String: Any]
) async -> [[String: Any]] {
    guard let text = try? String(contentsOfFile: logPath, encoding: .utf8) else { return [] }
    var pidToSession: [Int32: String?] = [:]
    var out: [[String: Any]] = []
    for raw in text.split(separator: "\n").suffix(max) {
        guard let data = raw.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let ppid = obj["ppid"] as? Int else { continue }
        let key = Int32(ppid)
        let resolved: String?
        if let cached = pidToSession[key] {
            resolved = cached
        } else {
            resolved = (try? await store.agentSessionForPid(key)) ?? nil
            pidToSession[key] = resolved
        }
        if resolved == sessionId { out.append(keep(obj)) }
    }
    return out
}

func mutationsForSession(_ sessionId: String, store: EventStore) async -> [[String: Any]] {
    await logEntriesForSession(logPath: mcpMutationLogPath(), sessionId: sessionId, store: store) { obj in
        [
            "ts": obj["ts"] ?? "",
            "operation": obj["operation"] ?? "",
            "details": obj["details"] ?? "",
            "confidence": "ppid-correlated",
        ]
    }
}

/// P5 tool-call rail for a session.
func toolCallsForSession(_ sessionId: String, store: EventStore) async -> [[String: Any]] {
    await logEntriesForSession(logPath: mcpToolCallLogPath(), sessionId: sessionId, store: store) { obj in
        [
            "ts": obj["ts"] ?? "",
            "tool": obj["tool"] ?? "",
            "is_error": obj["is_error"] ?? false,
            "confidence": "ppid-correlated",
        ]
    }
}

func handleGetAgentSession(_ args: [String: Any]) async -> Any {
    guard let sessionId = args["session_id"] as? String, !sessionId.isEmpty else {
        return toolError("'session_id' is required (see list_agent_sessions)")
    }
    let limit = min(max((args["limit"] as? Int) ?? 500, 1), 2000)
    do {
        let store = try EventStore(directory: dataDir)
        // Fail-soft on the event query: a READ tool against an empty / young
        // store (or an unknown session id) must return an empty timeline, not
        // isError. The `ai_tool_session_id` column is migration-added and can
        // be absent on a fresh store whose migration lost a create-time lock
        // race (see handleListAgentSessions / EventStore.openDatabase). The
        // alert / mutation / tool-call rails below are already best-effort.
        let events = (try? await store.eventsForAgentSession(sessionId, limit: limit)) ?? []
        let iso = ISO8601DateFormatter()
        let timeline = events.map { e -> [String: Any] in
            var row: [String: Any] = [
                "ts": iso.string(from: e.timestamp),
                "category": e.eventCategory.rawValue,
                "action": e.eventAction,
                "process": e.process.name,
                "pid": Int(e.process.pid),
                "path": e.process.executable,
            ]
            if let f = e.file?.path { row["file"] = f }
            if let n = e.network {
                row["dest"] = (n.destinationHostname ?? "").isEmpty
                    ? "\(n.destinationPort)" : "\(n.destinationHostname!):\(n.destinationPort)"
            }
            return row
        }
        // Wave-3 P2: the alert rail — what this session's activity tripped.
        // Best-effort: the alert rail is supplementary, so a fresh-store
        // alerts.db open/query failure must not turn this read into isError.
        let alertStore = try? AlertStore(directory: dataDir)
        let sessionAlerts = (try? await alertStore?.alerts(forAgentSession: sessionId)) ?? []
        let alerts = sessionAlerts.map { a -> [String: Any] in
            [
                "ts": iso.string(from: a.timestamp),
                "alert_id": a.id,
                "rule_id": a.ruleId,
                "rule_title": a.ruleTitle,
                "severity": a.severity.rawValue,
                "suppressed": a.suppressed,
            ]
        }
        // Wave-3 P2b: the mutation rail — what the agent changed. Read the
        // durable MCP mutation log and keep the lines whose ppid resolves
        // (medium-confidence, ppid-correlated) to THIS session.
        let mutations = await mutationsForSession(sessionId, store: store)
        // Wave-3 P5: the per-tool-call rail — the agent's full MCP interaction.
        let toolCalls = await toolCallsForSession(sessionId, store: store)
        return ["content": [["type": "text", "text": jsonStringify([
            "session_id": sessionId,
            "event_count": events.count,
            "alert_count": alerts.count,
            "mutation_count": mutations.count,
            "tool_call_count": toolCalls.count,
            "timeline": timeline,
            "alerts": alerts,
            "mutations": mutations,
            "tool_calls": toolCalls,
        ] as [String: Any])]]]
    } catch {
        // READ tool: a store that can't be opened (fresh box / create-time
        // lock race under load) means an empty timeline for the caller, not
        // isError. Mutation tools still surface store-open failures.
        return ["content": [["type": "text", "text": jsonStringify([
            "session_id": sessionId,
            "event_count": 0,
            "alert_count": 0,
            "mutation_count": 0,
            "tool_call_count": 0,
            "timeline": [Any](),
            "alerts": [Any](),
            "mutations": [Any](),
            "tool_calls": [Any](),
        ] as [String: Any])]]]
    }
}

func handleExportSessionBundle(_ args: [String: Any]) async -> Any {
    guard let sessionId = args["session_id"] as? String, !sessionId.isEmpty else {
        return toolError("'session_id' is required (see list_agent_sessions)")
    }
    // SEC-3: session_id becomes a path component below; a real session id is a
    // UUID. Reject anything else so a crafted '../'-style id can't write the
    // bundle outside the session_bundles dir.
    guard UUID(uuidString: sessionId) != nil else {
        return toolError("'session_id' must be a session UUID (from list_agent_sessions)")
    }
    do {
        let store = try EventStore(directory: dataDir)
        let events = try await store.eventsForAgentSession(sessionId, limit: 10000)
        let encoder = JSONEncoder()
        let eventsJsonl: [String] = events.compactMap { e in
            (try? encoder.encode(e)).flatMap { String(data: $0, encoding: .utf8) }
        }
        let alertStore = try AlertStore(directory: dataDir)
        let alerts = (try? await alertStore.alerts(forAgentSession: sessionId)) ?? []
        let alertsJson = (try? encoder.encode(alerts)).flatMap { String(data: $0, encoding: .utf8) } ?? "[]"
        let mutations = await mutationsForSession(sessionId, store: store)
        let mutationsJson = (try? JSONSerialization.data(withJSONObject: mutations, options: [.sortedKeys]))
            .flatMap { String(data: $0, encoding: .utf8) } ?? "[]"
        let toolCalls = await toolCallsForSession(sessionId, store: store)
        let toolCallsJson = (try? JSONSerialization.data(withJSONObject: toolCalls, options: [.sortedKeys]))
            .flatMap { String(data: $0, encoding: .utf8) } ?? "[]"

        let metadata: [String: Any] = [
            "session_id": sessionId,
            "exported_at": ISO8601DateFormatter().string(from: Date()),
            "event_count": events.count,
            "alert_count": alerts.count,
            "mutation_count": mutations.count,
            "tool_call_count": toolCalls.count,
            "maccrab_version": MacCrabVersion.current,
        ]
        let metadataJson = (try? JSONSerialization.data(withJSONObject: metadata, options: [.sortedKeys]))
            .flatMap { String(data: $0, encoding: .utf8) } ?? "{}"

        // Write to a user-writable exports dir; unique name avoids clobber.
        let fm = FileManager.default
        let base = (fm.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            .map { $0.appendingPathComponent("MacCrab/session_bundles") }
            ?? URL(fileURLWithPath: NSHomeDirectory() + "/Library/Application Support/MacCrab/session_bundles"))
        try? fm.createDirectory(at: base, withIntermediateDirectories: true)
        let target = base.appendingPathComponent("\(sessionId)-\(UUID().uuidString.prefix(8)).maccrabsession")

        // WAVE3-02: force .filesystemDegraded (pure CryptoKit, no Secure-
        // Enclave entitlement) because the MCP server is unentitled — the SE
        // path fails with -34018 and yields an unsigned, forgeable bundle. A
        // dedicated keys dir avoids inheriting any SE-mode state from the
        // shared trace-signing keys dir.
        let ts = TrustSubstrate(
            storage: FilesystemTrustSubstrateStorage(baseDirectory: URL(fileURLWithPath: mcpUserDir() + "/session_keys/")),
            modeOverride: .filesystemDegraded
        )

        let res = try await AgentSessionBundle.export(
            sessionId: sessionId,
            eventsJsonl: eventsJsonl,
            alertsJson: alertsJson,
            mutationsJson: mutationsJson,
            metadataJson: metadataJson,
            toolCallsJson: toolCallsJson,
            to: target,
            trustSubstrate: ts
        )
        var payload: [String: Any] = [
            "session_id": sessionId,
            "bundle_path": res.bundleDir.path,
            "merkle_root": res.merkleRoot,
            "signed": res.signed,
            "key_mode": res.keyMode,
            "event_count": events.count,
            "alert_count": alerts.count,
            "mutation_count": mutations.count,
            "verify_with": "verify_session_bundle { path: \"\(res.bundleDir.path)\" }",
        ]
        if let err = res.signError {
            // Honest warning: an unsigned bundle detects accidental corruption
            // (Merkle) but is forgeable (no signature binds the root).
            payload["sign_error"] = err
            payload["warning"] = "UNSIGNED bundle — signature failed; content is hash-rooted but not tamper-proof."
        }
        return ["content": [["type": "text", "text": jsonStringify(payload)]]]
    } catch {
        return toolError("export_session_bundle failed: \(error)")
    }
}

func handleVerifySessionBundle(_ args: [String: Any]) async -> Any {
    guard let path = args["path"] as? String, !path.isEmpty else {
        return toolError("'path' is required (a .maccrabsession bundle dir from export_session_bundle)")
    }
    // Same substrate the export path uses, so the public key matches.
    let ts = TrustSubstrate(
        storage: FilesystemTrustSubstrateStorage(baseDirectory: URL(fileURLWithPath: mcpUserDir() + "/session_keys/")),
        modeOverride: .filesystemDegraded
    )
    do {
        let v = try await AgentSessionBundle.verify(at: URL(fileURLWithPath: path), trustSubstrate: ts)
        let verdict = (v.merkleOk && v.signed && v.signatureOk) ? "verified"
            : (v.merkleOk && !v.signed) ? "unsigned (content hash-rooted only — forgeable)"
            : "TAMPERED / invalid"
        return ["content": [["type": "text", "text": jsonStringify([
            "path": path,
            "merkle_ok": v.merkleOk,
            "signed": v.signed,
            "signature_ok": v.signatureOk,
            "verdict": verdict,
        ] as [String: Any])]]]
    } catch {
        return toolError("verify_session_bundle failed: \(error)")
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

    // Count compiled single-event rules (exclude manifest.json — it is
    // build-time metadata, not a rule; counting it reported 437 vs the true
    // 436 the engine loads).
    let rulesDir = dataDir + "/compiled_rules"
    let ruleCount = (try? fm.contentsOfDirectory(atPath: rulesDir))?
        .filter { $0.hasSuffix(".json") && $0 != "manifest.json" }.count ?? 0
    lines.append("Rules Loaded: \(ruleCount)")

    return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
}

func handleHunt(_ args: [String: Any]) async -> Any {
    guard let query = args["query"] as? String, !query.isEmpty else {
        return toolError("Error: 'query' parameter is required")
    }

    // Input validation: cap query length to prevent FTS abuse
    guard query.count <= 1000 else {
        return toolError("Error: query too long (max 1000 characters)")
    }

    let limit = min(max(args["limit"] as? Int ?? 50, 1), 100)

    do {
        let store = try EventStore(directory: dataDir)
        let results = try await store.search(text: query, limit: limit)

        if results.isEmpty {
            return ["content": [["type": "text", "text": "No results for: \(query)\n\nTry broader terms or check different time ranges."]]]
        }

        var lines: [String] = ["\(results.count) result(s) for: \(query)"]
        for event in results {
            let time = isoFormatter.string(from: event.timestamp)
            lines.append("")
            lines.append("\(time) [\(event.eventCategory.rawValue)] \(event.process.name)")
            lines.append("  Path: \(event.process.executable)")
            if !event.process.commandLine.isEmpty { lines.append("  Cmd: \(event.process.commandLine.prefix(200))") }
        }

        return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
    } catch {
        return toolError("Hunt error: \(error.localizedDescription)")
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
        return toolError("'alert_id' parameter is required")
    }

    // Input validation: alert IDs are UUIDs
    guard alertId.count <= 64 else {
        return toolError("invalid alert_id format")
    }

    // v1.18: per-session suppression budget (defense-in-depth over the audit log).
    guard await suppressBudget.tryConsume() else {
        return toolError("suppress budget exhausted (max \(suppressBudget.limit) per server session) — restart the MCP session or use the dashboard for bulk suppression")
    }

    // Audit log: state-modifying operation
    auditLog("suppress_alert", details: "alert_id=\(alertId) ppid=\(getppid())")

    do {
        let store = try AlertStore(directory: dataDir)
        try await store.suppress(alertId: alertId)
        return ["content": [["type": "text", "text": "Alert \(alertId) suppressed successfully."]]]
    } catch {
        return toolError("suppressing alert: \(error.localizedDescription)")
    }
}

func handleGetAlertDetail(_ args: [String: Any]) async -> Any {
    guard let alertId = args["alert_id"] as? String, !alertId.isEmpty else {
        return toolError("Error: 'alert_id' parameter is required")
    }
    guard alertId.count <= 64 else {
        return toolError("Error: invalid alert_id format")
    }

    do {
        let store = try AlertStore(directory: dataDir)
        guard let alert = try await store.alert(id: alertId) else {
            return toolError("Alert \(alertId) not found.")
        }

        var lines: [String] = []
        lines.append("[\(alert.severity.rawValue.uppercased())] \(alert.ruleTitle)")
        lines.append("ID:     \(alert.id)")
        lines.append("Time:   \(isoFormatter.string(from: alert.timestamp))")
        lines.append("Status: \(alert.suppressed ? "Suppressed" : "Active")")
        if let proc = alert.processName { lines.append("Process: \(proc)") }
        // v1.12.0 RC25 (privacy): redact paths before yielding to LLM.
        if let path = alert.processPath  { lines.append("Path:    \(LLMSanitizer.sanitize(path))") }
        if let tactics = alert.mitreTactics    { lines.append("Tactics:    \(tactics)") }
        if let techs   = alert.mitreTechniques { lines.append("Techniques: \(techs)") }
        if let d3 = alert.d3fendTechniques, !d3.isEmpty {
            lines.append("D3FEND Mitigations: \(d3.joined(separator: ", "))")
        }
        if let hint = alert.remediationHint { lines.append("Remediation: \(hint)") }
        if let cid = alert.campaignId { lines.append("Campaign ID: \(cid)") }

        if let desc = alert.description {
            lines.append("")
            lines.append("Description:")
            lines.append(desc)
        }

        if let inv = alert.llmInvestigation {
            lines.append("")
            lines.append("AI Investigation:")
            lines.append("  Verdict:    \(inv.verdict.rawValue)")
            lines.append("  Confidence: \(Int(inv.confidence * 100))%")
            lines.append("  Summary:    \(inv.summary)")
            if !inv.suggestedActions.isEmpty {
                lines.append("  Suggested Actions:")
                for action in inv.suggestedActions.prefix(5) {
                    let risk = action.requiresConfirmation ? " [requires confirmation]" : ""
                    lines.append("    • \(action.title)\(risk): \(action.rationale)")
                }
            }
            if !inv.confidencePenalties.isEmpty {
                lines.append("  Uncertainty: \(inv.confidencePenalties.joined(separator: "; "))")
            }
        }

        lines.append("")
        lines.append("Use get_events with search='\(alert.eventId)' to see the triggering event and full process ancestry.")

        return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
    } catch {
        return toolError("Error: \(error.localizedDescription)")
    }
}

func handleSuppressCampaign(_ args: [String: Any]) async -> Any {
    guard let campaignId = args["campaign_id"] as? String, !campaignId.isEmpty else {
        return toolError("'campaign_id' parameter is required")
    }
    guard campaignId.count <= 64 else {
        return toolError("invalid campaign_id format")
    }

    do {
        let store = try AlertStore(directory: dataDir)

        // v1.18: fan-out confirmation. A campaign can suppress many alerts;
        // require an explicit confirm for large fan-outs so an agent can't
        // mass-suppress in one call. The pre-count uses the SAME predicate as
        // suppress(campaignId:) so the gate and the mutation agree exactly.
        let pending = (try? await store.countByCampaign(campaignId: campaignId)) ?? 0
        let confirmed = (args["confirm"] as? Bool) == true
        if pending > 50 && !confirmed {
            return toolError("suppress_campaign would suppress \(pending) contributing alerts — re-call with confirm:true to proceed, or use the dashboard for bulk suppression.")
        }

        // v1.18 / F1: consume the per-session budget (shared with suppress_alert)
        // only once the call will actually suppress. The confirm-required bounce
        // above suppressed nothing, so it must not debit the budget — otherwise
        // one intended large suppression costs two units.
        guard await suppressBudget.tryConsume() else {
            return toolError("suppress budget exhausted (max \(suppressBudget.limit) per server session) — restart the MCP session or use the dashboard for bulk suppression")
        }

        auditLog("suppress_campaign", details: "campaign_id=\(campaignId) pending=\(pending) confirm=\(confirmed) ppid=\(getppid())")

        // Suppress the campaign alert itself.
        try await store.suppress(alertId: campaignId)

        // v1.11.1 (audit perf HIGH): single SQL UPDATE for the fan-out
        // instead of a 10K-row pull + N-serial-write loop. Pre-fix the
        // worst case wedged the handler ~30s on 5K matching alerts.
        let count = try await store.suppress(campaignId: campaignId)

        let extra = count == 0 ? "" : " Also suppressed \(count) contributing alert(s)."
        return ["content": [["type": "text", "text": "Campaign \(campaignId) suppressed.\(extra)"]]]
    } catch {
        return toolError("\(error.localizedDescription)")
    }
}

func handleGetAIAlerts(_ args: [String: Any]) async -> Any {
    let limit = min(max(args["limit"] as? Int ?? 20, 1), 100)
    let hours = args["hours"] as? Double ?? 24

    do {
        let store = try AlertStore(directory: dataDir)
        let since = Date().addingTimeInterval(-hours * 3600)
        // v1.11.1 (audit perf HIGH): SQL-side rule_id LIKE prefix
        // filter instead of "pull 10K + Swift substring match across
        // 8 keywords on every row".
        let aiAlerts = try await store.aiAlerts(since: since, limit: limit)

        if aiAlerts.isEmpty {
            return ["content": [["type": "text", "text": "No AI safety alerts in the last \(Int(hours))h. AI tools are operating within safe boundaries."]]]
        }

        var lines: [String] = ["\(aiAlerts.count) AI safety alert(s) — last \(Int(hours))h:"]
        for alert in aiAlerts {
            lines.append("")
            lines.append("[\(alert.severity.rawValue.uppercased())] \(alert.ruleTitle)")
            lines.append("  Time:    \(isoFormatter.string(from: alert.timestamp))")
            lines.append("  ID:      \(alert.id)")
            if let proc = alert.processName { lines.append("  Process: \(proc)") }
            if let desc = alert.description { lines.append("  Detail:  \(desc)") }
        }

        return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
    } catch {
        return toolError("Error: \(error.localizedDescription)")
    }
}

func handleScanText(_ args: [String: Any]) async -> Any {
    guard let text = args["text"] as? String, !text.isEmpty else {
        return toolError("Error: 'text' parameter is required")
    }
    guard text.count <= 10_000 else {
        return toolError("Error: text too long (max 10000 characters)")
    }

    let scanner = PromptInjectionScanner()
    guard await scanner.isAvailable else {
        return toolError("Prompt injection scanner not available. Install forensicate to enable this tool:\n  pip install forensicate-ai")
    }

    guard let result = await scanner.scan(text) else {
        return toolError("Scan returned no result (possible timeout or parse error).")
    }

    var lines: [String] = ["Prompt Injection Scan"]
    lines.append("═══════════════════════════════════")
    lines.append("Safe:       \(!result.isPositive)")
    lines.append("Confidence: \(result.confidence)%")

    if result.isPositive {
        lines.append("⚠️  INJECTION DETECTED")
        if !result.reasons.isEmpty {
            lines.append("Reasons:")
            // v1.12.0 RC25 (privacy): Forensicate's reason strings can
            // echo portions of the scanned text. Route through
            // LLMSanitizer so paths / credential shapes / private IPs
            // never round-trip back into the AI agent's context.
            for r in result.reasons { lines.append("  - \(LLMSanitizer.sanitize(r))") }
        }
        if !result.matchedRules.isEmpty {
            lines.append("Matched Rules:")
            for rule in result.matchedRules.prefix(10) {
                lines.append("  [\(rule.severity.uppercased())] \(rule.ruleName)")
            }
        }
        if !result.compoundThreats.isEmpty {
            lines.append("Compound Threats: \(result.compoundThreats.joined(separator: ", "))")
        }
    } else {
        lines.append("✓ No injection patterns detected")
    }

    return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
}

// MARK: - v1.10 TraceGraph handlers

/// Probe likely paths for the tracegraph.db. Same logic as
/// `resolveDataDir()` for events/alerts but checks both system and
/// user app-support locations.
private func resolveTraceGraphPath() -> String {
    let userDir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)
        .first?.appendingPathComponent("MacCrab").path
        ?? NSHomeDirectory() + "/Library/Application Support/MacCrab"
    let systemDir = "/Library/Application Support/MacCrab"
    // v1.18: deterministic, writer-aware resolution. A `-wal` sidecar means
    // the daemon is actively writing that store; prefer it (system/root dir
    // first, then user/dev dir) instead of racing on newest mtime, which
    // could flip the chosen store between calls. Newest-mtime is only the
    // fallback when no live writer is detectable.
    let fm = FileManager.default
    for dir in [systemDir, userDir] where fm.fileExists(atPath: dir + "/tracegraph.db-wal") {
        return dir + "/tracegraph.db"
    }
    let candidates = [dataDir, userDir, systemDir]
    let chosen = candidates
        .map { dir -> (String, Date) in
            let mtime = (try? fm
                .attributesOfItem(atPath: dir + "/tracegraph.db"))?[.modificationDate] as? Date
            return (dir, mtime ?? .distantPast)
        }
        .max { $0.1 < $1.1 }?.0 ?? dataDir
    return chosen + "/tracegraph.db"
}

func handleGetTraces(_ args: [String: Any]) async -> Any {
    let limit = min(max(args["limit"] as? Int ?? 25, 1), 200)
    let statusFilter = args["status"] as? String
    do {
        let store = try await SQLiteCausalGraphStore(databasePath: traceGraphPath)
        // v1.11.1 (audit perf HIGH): push status filter into SQL so a
        // caller asking for `limit:25 status:open` actually gets up
        // to 25 matching rows (pre-fix the filter ran AFTER the limit,
        // capping returned matches at whatever fraction of the first
        // 25 happened to match).
        let traces = try await store.listTraces(limit: limit, status: statusFilter)
        if traces.isEmpty {
            return ["content": [["type": "text", "text":
                "No traces found. Either the daemon hasn't materialized any yet (it anchors a trace once it correlates a multi-step chain of activity), or the tracegraph.db isn't on this machine."]]]
        }
        var lines = ["\(traces.count) trace(s):"]
        for t in traces {
            // v1.11.1 (audit perf HIGH): O(1) memberCount via dedicated
            // SQL query instead of a full loadTrace round-trip per row.
            // Pre-fix this was an N+1 — 200 traces × 2 SQL queries each
            // + full member-set deserialization just to read .count.
            let nodes = (try? await store.memberCount(traceId: t.id)) ?? 0
            lines.append("")
            lines.append("[\(t.severity.uppercased())] \(t.title)  (id: \(t.id))")
            lines.append("  Status:    \(t.status)")
            lines.append("  Anchor:    \(t.anchorEventId)")
            lines.append("  Nodes:     \(nodes)")
            lines.append("  Updated:   \(isoFormatter.string(from: t.updatedAt))")
        }
        return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
    } catch {
        return toolError("Error reading traces: \(error.localizedDescription)")
    }
}

func handleGetTraceDetail(_ args: [String: Any]) async -> Any {
    guard let traceId = args["trace_id"] as? String, !traceId.isEmpty else {
        return toolError("Missing required argument: trace_id")
    }
    do {
        let store = try await SQLiteCausalGraphStore(databasePath: traceGraphPath)
        guard let pair = try await store.loadTrace(id: traceId) else {
            return toolError("Trace \(traceId) not found.")
        }
        let (trace, members) = pair
        let chainEntry = try? await store.latestHashChainEntry(for: traceId)
        var lines = ["Trace \(trace.id)"]
        lines.append("═══════════════════════════════════")
        lines.append("Title:     \(trace.title)")
        lines.append("Severity:  \(trace.severity)")
        lines.append("Status:    \(trace.status)")
        lines.append("Anchor:    \(trace.anchorEventId)")
        if let root = trace.rootEntityId { lines.append("Root:      \(root)") }
        lines.append("Created:   \(isoFormatter.string(from: trace.createdAt))")
        lines.append("Updated:   \(isoFormatter.string(from: trace.updatedAt))")
        lines.append("")
        lines.append("Members (\(members.count)):")
        for m in members.prefix(50) {
            let entityLabel = m.entityId ?? (m.edgeId.map { "edge \($0)" } ?? "—")
            lines.append("  · \(entityLabel) [\(m.role)]")
        }
        if members.count > 50 { lines.append("  … +\(members.count - 50) more") }
        if let entry = chainEntry {
            lines.append("")
            lines.append("Latest hash-chain entry:")
            lines.append("  Sequence:  \(entry.sequenceNumber)")
            lines.append("  Recorded:  \(isoFormatter.string(from: entry.createdAt))")
            lines.append("  Hash:      \(entry.currentHash.prefix(16))…")
        }
        return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
    } catch {
        return toolError("Error reading trace: \(error.localizedDescription)")
    }
}

func handleHuntTrace(_ args: [String: Any]) async -> Any {
    guard let query = args["query"] as? String, !query.isEmpty else {
        return toolError("Missing required argument: query")
    }
    let limit = min(max(args["limit"] as? Int ?? 25, 1), 100)
    do {
        let store = try await SQLiteCausalGraphStore(databasePath: traceGraphPath)
        // v1.11.1 (audit perf LOW): SQL-side LIKE instead of pulling
        // 500 candidates + Swift substring scan. Lets SQLite skip
        // deserializing non-matches.
        let matches = try await store.huntTraces(query: query, limit: limit)
        if matches.isEmpty {
            return ["content": [["type": "text", "text": "No traces match `\(query)`."]]]
        }
        var lines = ["\(matches.count) trace(s) match `\(query)`:"]
        for t in matches {
            lines.append("  · [\(t.severity.uppercased())] \(t.title)  (\(t.id))")
        }
        return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
    } catch {
        return toolError("Error hunting traces: \(error.localizedDescription)")
    }
}

func handleVerifyBundle(_ args: [String: Any]) async -> Any {
    guard let path = args["path"] as? String, !path.isEmpty else {
        return toolError("Missing required argument: path")
    }
    let url = URL(fileURLWithPath: (path as NSString).expandingTildeInPath)
    var isDir: ObjCBool = false
    let exists = FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir)
    guard exists else {
        return toolError("Path not found: \(url.path)")
    }
    // For files (assumed .maccrabtrace archives), extract to a tmp
    // directory before verifying. For directories, verify in place.
    let bundleDir: URL
    var tmpDir: URL?
    if isDir.boolValue {
        bundleDir = url
    } else {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-mcp-verify-\(UUID().uuidString)")
        do {
            try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/bin/tar")
            p.currentDirectoryURL = tmp
            p.arguments = ["-xzf", url.path]
            try p.run(); p.waitUntilExit()
            guard p.terminationStatus == 0 else {
                try? FileManager.default.removeItem(at: tmp)
                return toolError("Failed to extract bundle archive: \(url.lastPathComponent)")
            }
            let inner = (try? FileManager.default.contentsOfDirectory(at: tmp, includingPropertiesForKeys: nil)) ?? []
            bundleDir = inner.count == 1 ? inner[0] : tmp
            tmpDir = tmp
        } catch {
            return toolError("Failed to extract bundle archive: \(error.localizedDescription)")
        }
    }
    // storage-01 parity: wire the same TOFU pin store maccrabctl uses so an
    // agent verifying a bundle via MCP also gets pin-on-first / reject-on-
    // key-change. Pinned by trace_id; first verify of an unseen trace_id is
    // trusted, a later rewrite-and-resign with a swapped key then fails.
    // The pin store lives next to the trace data this server already reads.
    var options = BundleVerifier.Options()
    let pinStore = TraceKeyPinStore(directory: dataDir)
    let traceId = (try? Data(contentsOf: bundleDir.appendingPathComponent("manifest.json")))
        .flatMap { try? canonicalJSONDecoder().decode(BundleManifest.self, from: $0) }?
        .traceId
    if let traceId, let pinned = pinStore.pinnedFingerprint(forTraceId: traceId) {
        options.pinnedKeyFingerprint = pinned
    }
    let outcome = await BundleVerifier.verify(at: bundleDir, options: options)
    // TOFU: on a clean first verify, record the key we just trusted.
    if outcome.exitCode == 0, let traceId,
       let sigData = try? Data(contentsOf: bundleDir.appendingPathComponent("integrity/chain_head_signature.json")),
       let sig = try? canonicalJSONDecoder().decode(ChainHeadSignatureArtifact.self, from: sigData) {
        pinStore.pinIfAbsent(traceId: traceId, fingerprint: sig.signingKeyFingerprint)
    }
    if let tmpDir { try? FileManager.default.removeItem(at: tmpDir) }
    var lines = ["Bundle verification — exit \(outcome.exitCode)"]
    lines.append("═══════════════════════════════════")
    lines.append("Path:    \(url.lastPathComponent)")
    if outcome.exitCode == 0 {
        lines.append("Result:  ✓ Verified")
    } else {
        lines.append("Result:  ✗ Failed")
        lines.append("Reason:  \(String(describing: outcome.kind))")
    }
    if !outcome.messages.isEmpty {
        lines.append("")
        for m in outcome.messages.prefix(20) { lines.append("  · \(m)") }
    }
    return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
}

func handleTraceFromEvent(_ args: [String: Any]) async -> Any {
    guard let eventId = args["event_id"] as? String, !eventId.isEmpty else {
        return toolError("Missing required argument: event_id")
    }
    do {
        let store = try await SQLiteCausalGraphStore(databasePath: traceGraphPath)
        // v1.11.1 (audit perf HIGH): single SQL UNION across the
        // membership index AND the anchor_event_id column instead of
        // listing 200 traces + linearly scanning each one's members.
        // Pre-fix worst case: 200 × 2 SQL queries + 200 × M
        // deserializations. Now: one query.
        guard let trace = try await store.traceContaining(entityId: eventId) else {
            return ["content": [["type": "text", "text":
                "Event \(eventId) is not a member of any trace. Either it pre-dates the trace materialiser's window, or it didn't qualify as a trace anchor / member."]]]
        }
        var lines = ["Event \(eventId) belongs to trace \(trace.id)"]
        lines.append("═══════════════════════════════════")
        lines.append("Title:    \(trace.title)")
        lines.append("Severity: \(trace.severity)")
        lines.append("Anchor:   \(trace.anchorEventId)")
        lines.append("Role:     \(trace.anchorEventId == eventId ? "anchor" : "member")")
        lines.append("Status:   \(trace.status)")
        lines.append("Updated:  \(isoFormatter.string(from: trace.updatedAt))")
        return ["content": [["type": "text", "text": lines.joined(separator: "\n")]]]
    } catch {
        return toolError("Error looking up trace: \(error.localizedDescription)")
    }
}

// MARK: - v1.13a / v1.13b — Mac Context Plugin Platform meta-tool handlers

import MacCrabForensics

/// Lazy registry bootstrap shared across all forensics MCP tools.
/// Subsequent calls are idempotent.
// MUST NOT be @MainActor. The tools/call dispatch parks the MAIN THREAD on a
// DispatchSemaphore (sem.wait), so a MainActor-isolated ensure() can never run
// — it deadlocks every forensics tool (list_plugins / run_collector /
// search_artifacts / get_artifact / timeline / explain_case / posture_findings)
// while non-forensics tools work fine. An actor runs ensure() on its own
// cooperative executor, off the (parked) main thread. (RC H1: was @MainActor.)
actor ForensicsMCPBootstrapper {
    static let shared = ForensicsMCPBootstrapper()
    private var bootstrapped = false
    private init() {}
    func ensure() async throws {
        if !bootstrapped {
            try await MacCrabForensicsBootstrap.registerBuiltins()
            bootstrapped = true
        }
    }
}

private func forensicsCaseManager() -> CaseManager {
    CaseManager(
        casesRoot: CaseDirectoryLayout.defaultCasesRoot,
        dekVault: KeychainDEKVault()
    )
}

// MARK: - Plugin input coercion + dynamic per-plugin MCP tools

/// Build PluginInvocationInputs from MCP call args, coercing each value
/// to the type its InputSpec declares. Trusting the manifest's declared
/// type sidesteps the NSNumber Bool-vs-Int ambiguity that a guess-the-
/// type coercion would hit. The `caseID` input is resolved separately
/// from `case_id`, so it's skipped here.
private func buildPluginInputs(from args: [String: Any], specs: [InputSpec]) -> PluginInvocationInputs {
    var values: [String: InputValue] = [:]
    for spec in specs where spec.type != .caseID {
        guard let raw = args[spec.name] else { continue }
        switch spec.type {
        case .bool:
            if let b = raw as? Bool { values[spec.name] = .bool(b) }
        case .integer:
            if let i = raw as? Int { values[spec.name] = .integer(i) }
        case .string, .path, .timeWindow, .caseID:
            if let s = raw as? String { values[spec.name] = .string(s) }
        }
    }
    return PluginInvocationInputs(values: values)
}

private func jsonSchemaType(for type: InputType) -> String {
    switch type {
    case .bool: return "boolean"
    case .integer: return "integer"
    case .string, .path, .timeWindow, .caseID: return "string"
    }
}

/// Project each registered COLLECTOR plugin's declared mcpTools into MCP
/// tool definitions, appended to the static `tools` list. Manifest-
/// driven: a future installed collector plugin's declared mcpTools light
/// up here automatically with no server code change. Non-collector
/// plugin tools (enricher/analyzer) are omitted until their run-path
/// returns case-committable output — we don't advertise what can't run.
private func pluginMCPTools() async -> [[String: Any]] {
    var out: [[String: Any]] = []
    for m in await PluginRegistry.shared.manifests() where m.type == .collector {
        for t in m.mcpTools {
            var props: [String: Any] = [
                "case_id": ["type": "string", "description": "Target case UUID. Create one with forensics.create_case."],
            ]
            for spec in m.inputs where spec.type != .caseID {
                props[spec.name] = ["type": jsonSchemaType(for: spec.type), "description": spec.description]
            }
            out.append([
                "name": t.name,
                "description": "\(t.description) [plugin \(m.id); commits \(t.exposesPrivacyClass.rawValue)-class artifacts into the case — read them with forensics.search_artifacts]",
                "inputSchema": [
                    "type": "object",
                    "properties": props,
                    "required": ["case_id"],
                ] as [String: Any],
            ])
        }
    }
    return out
}

/// Resolve a dynamic plugin-tool name to its declaring collector plugin.
private func pluginForMCPTool(_ name: String) async -> PluginManifest? {
    for m in await PluginRegistry.shared.manifests() where m.type == .collector {
        if m.mcpTools.contains(where: { $0.name == name }) { return m }
    }
    return nil
}

/// Run a dynamically-registered plugin tool. It maps to the declaring
/// collector plugin's run, with the tool's declared inputs threaded
/// through. Requires `case_id` (the artifact destination); the artifacts
/// are then read via forensics.search_artifacts / forensics.timeline.
func handlePluginMCPTool(name: String, manifest: PluginManifest, args: [String: Any]) async -> Any {
    guard let caseID = args["case_id"] as? String else {
        let optional = manifest.inputs.filter { $0.type != .caseID }.map { $0.name }
        let extra = optional.isEmpty ? "" : " Inputs: \(optional.joined(separator: ", "))."
        return toolError("'\(name)' requires 'case_id' (create one with forensics.create_case).\(extra)")
    }
    do {
        try await ForensicsMCPBootstrapper.shared.ensure()
        let mgr = forensicsCaseManager()
        let handle = try await mgr.openCase(id: caseID)
        let inputs = buildPluginInputs(from: args, specs: manifest.inputs)
        let runner = PluginRunner()
        let (result, invocationID) = try await runner.runCollector(
            id: manifest.id,
            handle: handle,
            inputs: inputs
        )
        return ["content": [["type": "text", "text": jsonStringify([
            "tool": name,
            "plugin_id": manifest.id,
            "case_id": caseID,
            "invocation_id": Int(invocationID),
            "status": result.status.rawValue,
            "artifacts_committed": result.artifactsCommitted,
            "artifacts_rejected": result.artifactsRejected,
            "notes": result.notes,
        ] as [String: Any])]]]
    } catch {
        return toolError("\(name) failed: \(error)")
    }
}

func handleForensicsCreateCase(_ args: [String: Any]) async -> Any {
    guard let name = (args["name"] as? String).map({ $0.trimmingCharacters(in: .whitespacesAndNewlines) }),
          !name.isEmpty, name.count <= 200 else {
        return toolError("'name' is required (a short case label, ≤200 chars)")
    }
    // Plaintext by default: an encrypted case wraps its DEK to the app's
    // keychain, whose retrieval needs an interactive Touch ID/passcode
    // prompt the headless MCP process can't satisfy — the agent could
    // create it but never reopen it. Notes optional.
    let notes = (args["notes"] as? String).map { String($0.prefix(2000)) }
    let window: MacCrabForensics.TimeWindow? = (args["window_seconds"] as? Int).flatMap { secs in
        secs > 0 ? MacCrabForensics.TimeWindow.relative(TimeInterval(secs)) : nil
    }
    do {
        try await ForensicsMCPBootstrapper.shared.ensure()
        let mgr = forensicsCaseManager()
        let handle = try await mgr.createCase(name: name, timeWindow: window, notes: notes, encrypted: false)
        return ["content": [["type": "text", "text": jsonStringify([
            "case_id": handle.caseID,
            "name": name,
            "encryption": "plaintext",
            "next_steps": "Run a collector against this case — forensics.run_collector{plugin_id, case_id, inputs} or a per-plugin tool like macho_analyze_path{case_id, path} — then read results with forensics.search_artifacts / forensics.timeline.",
        ] as [String: Any])]]]
    } catch {
        return toolError("create_case failed: \(error)")
    }
}

/// Encode a CommittedArtifact as the dict shape MCP tools return.
private func encodeArtifact(_ a: CommittedArtifact) -> [String: Any] {
    var out: [String: Any] = [
        "id": Int(a.id),
        "case_id": a.record.caseID,
        "plugin_id": a.record.pluginID,
        "plugin_version": a.record.pluginVersion,
        "schema_version": a.record.schemaVersion,
        "content_type": a.record.contentType,
        "sha256": a.record.sha256,
        "observed_at": ISO8601DateFormatter().string(from: a.record.observedAt),
        "captured_at": ISO8601DateFormatter().string(from: a.record.capturedAt),
        "size_bytes": Int(a.record.sizeBytes),
        "confidence": a.record.confidence.rawValue,
        "privacy_class": a.record.privacyClass.rawValue,
    ]
    if let s = a.record.summary { out["summary"] = s }
    if let actor = a.record.actor { out["actor"] = actor }
    return out
}

/// Block non-metadata exposure unless ai_content_allowed is set.
/// Plan §10.8: returns a structured error naming the case, the
/// privacy class, and the CLI command the operator runs to grant.
private func aiContentBlockedError(
    caseID: String, caseName: String, tool: String, classRaw: String
) -> [String: Any] {
    let text = "This tool exposes \(classRaw)-class artifacts. The case '\(caseName)' (id: \(caseID)) has not been granted AI content access. To enable, the operator can run:\n\n  maccrabctl case allow-ai --content \(caseID)\n\nor open the case in the MacCrab dashboard → Case Settings → 'Allow AI access to content'.\n\nThis tool will not proceed until access is granted."
    return [
        "isError": true,
        "content": [["type": "text", "text": text]],
        "structuredContent": [
            "error": "case_content_access_denied",
            "case_id": caseID,
            "case_name": caseName,
            "tool": tool,
            "exposesPrivacyClass": classRaw,
            "ai_action_required": "operator_grants_content_access",
        ] as [String: Any],
    ]
}

func handleForensicsListPlugins(_ args: [String: Any]) async -> Any {
    do {
        try await ForensicsMCPBootstrapper.shared.ensure()
    } catch {
        return toolError("bootstrap failed: \(error)")
    }
    let category = args["category"] as? String
    let manifests: [PluginManifest]
    if let cat = category.flatMap({ PluginType(rawValue: $0) }) {
        manifests = await PluginRegistry.shared.manifests(ofType: cat)
    } else {
        manifests = await PluginRegistry.shared.manifests()
    }
    let payload = manifests.map { m -> [String: Any] in
        return [
            "id": m.id,
            "version": m.version,
            "display_name": m.displayName,
            "type": m.type.rawValue,
            "runtime": m.runtime.rawValue,
            "stability": m.stability.rawValue,
            "description": m.description,
            "inputs": m.inputs.map { spec -> [String: Any] in
                ["name": spec.name, "type": spec.type.rawValue, "description": spec.description, "required": spec.required]
            },
            "mcp_tools": m.mcpTools.map { t -> [String: Any] in
                ["name": t.name, "description": t.description, "privacy_class": t.exposesPrivacyClass.rawValue]
            },
            // Only collector plugins are runnable via the dynamic per-tool
            // MCP surface today (their declared mcpTools appear in tools/list);
            // other types declare tools that ship when their run-path lands.
            "runnable_via_mcp": m.type == .collector,
            // v1.19.0: forensics.list_plugins enumerates the Tier A first-party
            // catalog shipped inside the app — all built-in by definition.
            "provenance": PluginProvenance.builtIn.rawValue,
        ]
    }
    return ["content": [["type": "text", "text": jsonStringify(["plugins": payload])]]]
}

func handleForensicsRunCollector(_ args: [String: Any]) async -> Any {
    guard let pluginID = args["plugin_id"] as? String,
          let caseID = args["case_id"] as? String else {
        return toolError("missing required arguments: plugin_id, case_id")
    }
    do {
        try await ForensicsMCPBootstrapper.shared.ensure()
        let mgr = forensicsCaseManager()
        let handle = try await mgr.openCase(id: caseID)
        // Thread operator-supplied inputs (e.g. {"path": "/usr/bin/codesign"})
        // so path-driven analyzers target a chosen file instead of their
        // dogfood default. Coerced by the plugin's declared InputSpec types.
        let inputsArg = args["inputs"] as? [String: Any] ?? [:]
        let specs = await PluginRegistry.shared.registration(forID: pluginID)?.manifest.inputs ?? []
        let inputs = buildPluginInputs(from: inputsArg, specs: specs)
        let runner = PluginRunner()
        let (result, invocationID) = try await runner.runCollector(
            id: pluginID,
            handle: handle,
            inputs: inputs
        )
        return ["content": [["type": "text", "text": jsonStringify([
            "plugin_id": pluginID,
            "case_id": caseID,
            "invocation_id": Int(invocationID),
            "status": result.status.rawValue,
            "artifacts_committed": result.artifactsCommitted,
            "artifacts_rejected": result.artifactsRejected,
            "notes": result.notes,
        ] as [String: Any])]]]
    } catch {
        return toolError("run_collector failed: \(error)")
    }
}

func handleForensicsSearchArtifacts(_ args: [String: Any]) async -> Any {
    guard let caseID = args["case_id"] as? String else {
        return toolError("missing required argument: case_id")
    }
    let contentType = args["content_type"] as? String
    let limit = (args["limit"] as? Int) ?? 100
    let observedAfter = (args["observed_after"] as? String).flatMap { ISO8601DateFormatter().date(from: $0) }
    let observedBefore = (args["observed_before"] as? String).flatMap { ISO8601DateFormatter().date(from: $0) }
    do {
        try await ForensicsMCPBootstrapper.shared.ensure()
        let mgr = forensicsCaseManager()
        let handle = try await mgr.openCase(id: caseID)
        guard let row = try await handle.store.fetchCase(id: caseID) else {
            return toolError("case not found")
        }
        // Apply privacy gate: cap result class at metadata unless the
        // case has granted AI content access, in which case raise the
        // ceiling only to .content. The grant is `allow-ai --content`
        // (non-metadata); personalComms / credentialAdjacent / secret
        // stay blocked from MCP per PluginTypes class semantics.
        let ceiling: PrivacyClass = row.aiContentAllowed ? .content : .metadata
        let q = ArtifactQuery(
            caseID: caseID,
            contentType: contentType,
            observedAfter: observedAfter,
            observedBefore: observedBefore,
            privacyClassAtMost: ceiling,
            limit: limit
        )
        let rows = try await handle.store.query(q)
        let payload = rows.map(encodeArtifact)
        return ["content": [["type": "text", "text": jsonStringify(["artifacts": payload])]]]
    } catch {
        return toolError("search_artifacts failed: \(error)")
    }
}

func handleForensicsGetArtifact(_ args: [String: Any]) async -> Any {
    guard let caseID = args["case_id"] as? String,
          let artifactID = args["artifact_id"] as? Int else {
        return toolError("missing required arguments: case_id, artifact_id")
    }
    do {
        try await ForensicsMCPBootstrapper.shared.ensure()
        let mgr = forensicsCaseManager()
        let handle = try await mgr.openCase(id: caseID)
        guard let row = try await handle.store.fetchCase(id: caseID) else {
            return toolError("case not found")
        }
        let ceiling: PrivacyClass = row.aiContentAllowed ? .content : .metadata
        // Cheap path: query by case + take the artifact id locally.
        // (A future store-side getByID would be more efficient.)
        let rows = try await handle.store.query(ArtifactQuery(
            caseID: caseID,
            privacyClassAtMost: ceiling,
            limit: 10_000
        ))
        if let found = rows.first(where: { $0.id == Int64(artifactID) }) {
            return ["content": [["type": "text", "text": jsonStringify(encodeArtifact(found))]]]
        }
        // Miss under the current ceiling. Disambiguate genuinely-absent
        // vs blocked-by-privacy: an unfiltered (privacyClassAtMost: nil)
        // lookup, scoped to the same case + bound, sees every class. If
        // the id exists there it is above the ceiling — name the case,
        // its privacy class, and the operator grant via the structured
        // aiContentBlockedError. The Wave-3 ceiling query above is
        // untouched, so visible artifacts are unaffected.
        let unfiltered = try await handle.store.query(ArtifactQuery(
            caseID: caseID,
            privacyClassAtMost: nil,
            limit: 10_000
        ))
        if let blocked = unfiltered.first(where: { $0.id == Int64(artifactID) }) {
            return aiContentBlockedError(
                caseID: row.id,
                caseName: row.name,
                tool: "forensics.get_artifact",
                classRaw: blocked.record.privacyClass.rawValue
            )
        }
        return toolError("artifact not found in case")
    } catch {
        return toolError("get_artifact failed: \(error)")
    }
}

func handleForensicsTimeline(_ args: [String: Any]) async -> Any {
    guard let caseID = args["case_id"] as? String else {
        return toolError("missing required argument: case_id")
    }
    let limit = (args["limit"] as? Int) ?? 200
    do {
        try await ForensicsMCPBootstrapper.shared.ensure()
        let mgr = forensicsCaseManager()
        let handle = try await mgr.openCase(id: caseID)
        guard let row = try await handle.store.fetchCase(id: caseID) else {
            return toolError("case not found")
        }
        let ceiling: PrivacyClass = row.aiContentAllowed ? .content : .metadata
        let q = ArtifactQuery(
            caseID: caseID,
            privacyClassAtMost: ceiling,
            limit: limit
        )
        let rows = try await handle.store.query(q)
        let payload = rows.map(encodeArtifact)
        return ["content": [["type": "text", "text": jsonStringify(["timeline": payload])]]]
    } catch {
        return toolError("timeline failed: \(error)")
    }
}

func handleForensicsExplainCase(_ args: [String: Any]) async -> Any {
    guard let caseID = args["case_id"] as? String else {
        return toolError("missing required argument: case_id")
    }
    do {
        try await ForensicsMCPBootstrapper.shared.ensure()
        let mgr = forensicsCaseManager()
        let handle = try await mgr.openCase(id: caseID)
        guard let row = try await handle.store.fetchCase(id: caseID) else {
            return toolError("case not found")
        }
        // Aggregate artifact counts by content type.
        // Cheap: pull everything and bucket. Future iteration can
        // do this server-side with COUNT GROUP BY.
        // Apply the same privacy ceiling as the read handlers so the
        // per-content-type counts don't leak the existence of blocked
        // (personalComms / credentialAdjacent / secret) artifacts.
        let ceiling: PrivacyClass = row.aiContentAllowed ? .content : .metadata
        let rows = try await handle.store.query(ArtifactQuery(caseID: caseID, privacyClassAtMost: ceiling, limit: 100_000))
        var byContentType: [String: Int] = [:]
        for r in rows {
            byContentType[r.record.contentType, default: 0] += 1
        }
        let summary: [String: Any] = [
            "case_id": row.id,
            "case_name": row.name,
            "created_at": ISO8601DateFormatter().string(from: row.createdAt),
            "encryption_state": row.encryptionState.rawValue,
            "ai_content_allowed": row.aiContentAllowed,
            "scheduled_trusted": row.scheduledTrusted,
            "artifact_total": rows.count,
            "artifacts_by_content_type": byContentType,
        ]
        return ["content": [["type": "text", "text": jsonStringify(summary)]]]
    } catch {
        return toolError("explain_case failed: \(error)")
    }
}

func handleForensicsPostureFindings(_ args: [String: Any]) async -> Any {
    guard let caseID = args["case_id"] as? String else {
        return toolError("missing required argument: case_id")
    }
    // v1.13b: stub. The v1.15 posture Analyzer emits posture.*
    // findings; until that lands, the tool returns an empty array
    // with a note. Tool surface is reserved so consumers can wire
    // against it now.
    do {
        try await ForensicsMCPBootstrapper.shared.ensure()
        let mgr = forensicsCaseManager()
        let handle = try await mgr.openCase(id: caseID)
        // Query any committed `posture.*` artifacts — the v1.15
        // Analyzer commits findings as artifacts with content_type
        // posture.<finding_type>. v1.13b finds none; the response
        // shape is forward-compatible.
        let rows = try await handle.store.query(ArtifactQuery(
            caseID: caseID,
            limit: 10_000
        ))
        let findings = rows.filter { $0.record.contentType.hasPrefix("posture.") }.map(encodeArtifact)
        return ["content": [["type": "text", "text": jsonStringify([
            "findings": findings,
            "note": findings.isEmpty
                ? "No findings yet. The v1.15 posture Analyzer emits posture.* artifacts; until v1.15 ships, this returns an empty array."
                : "Findings emitted by the v1.15 posture Analyzer.",
        ] as [String: Any])]]]
    } catch {
        return toolError("posture_findings failed: \(error)")
    }
}

/// Tiny JSON stringifier. Matches the existing handlers' habit of
/// returning a JSON-encoded string as the tool result's text body.
private func jsonStringify(_ obj: Any) -> String {
    guard let data = try? JSONSerialization.data(
        withJSONObject: obj,
        options: [.prettyPrinted, .sortedKeys]
    ) else {
        return "{}"
    }
    let text = String(data: data, encoding: .utf8) ?? "{}"
    // SEC-1: JSONSerialization escapes '/' as '\/', which defeats
    // LLMSanitizer's /Users/<name>/ regex (it matches literal slashes) — so
    // usernames/home paths flowed UN-redacted to the agent. Unescape slashes
    // (JSONSerialization only emits '\/' for a real '/', so this stays valid
    // JSON) so the downstream sanitizeContent pass can redact paths before
    // they reach the agent / a cloud LLM.
    return text.replacingOccurrences(of: "\\/", with: "/")
}

// MARK: - Main Loop (stdio JSON-RPC)

let decoder = JSONDecoder()

// Security: validate parent process at startup
validateParentProcess()

// maccrab-mcp is meant to run as the logged-in user (launched by an AI
// agent like Claude Code). It never needs root. Warn — not refuse — when
// run as euid 0 (refusing could break an unforeseen flow). Written to
// STDERR so it never corrupts the stdout JSON-RPC stream.
if geteuid() == 0 {
    FileHandle.standardError.write(Data(
        "warning: maccrab-mcp is running as root (euid 0); it is meant to run as the logged-in user. Running a user-writable bundled binary as root is an unnecessary privilege-escalation surface. Continuing.\n".utf8))
}

// Read newline-delimited JSON-RPC messages from stdin (MCP stdio transport).
//
// v1.17.4: the prior build also tried to accept LSP Content-Length framing,
// but interleaving readLine() (buffered) with FileHandle.readData on the
// same fd buffer-stole bytes and corrupted framed messages (a spurious
// -32700 parse error plus a dropped message per frame). We now read ONLY
// newline-delimited JSON, matching the corrected newline-delimited output.

// Disable stdout buffering for reliable pipe output
setbuf(stdout, nil)

while let line = readLine(strippingNewline: true) {
    let trimmed = line.trimmingCharacters(in: .whitespaces)
    guard trimmed.hasPrefix("{") else { continue }
    let body = trimmed.data(using: .utf8) ?? Data()

    guard let request = try? decoder.decode(JSONRPCRequest.self, from: body) else {
        // Parse failed — send generic error (don't leak request body which may contain secrets)
        writeJSON(["jsonrpc": "2.0", "id": NSNull(), "error": ["code": -32700, "message": "Parse error: invalid JSON-RPC request"]] as [String: Any])
        continue
    }

    // Handle synchronous methods inline, async methods via runloop spin
    switch request.method {
    case "initialize":
        sendResponse(id: request.id, result: [
            "protocolVersion": "2024-11-05",
            "capabilities": ["tools": [:] as [String: Any]] as [String: Any],
            "serverInfo": ["name": "maccrab", "version": MacCrabVersion.current] as [String: Any],
        ] as [String: Any])
    case "notifications/initialized":
        break
    case "tools/list":
        // Static tools + dynamically-projected per-plugin tools. The
        // forensics bootstrap + registry read are async, so spin the
        // runloop like tools/call does.
        let listSem = DispatchSemaphore(value: 0)
        var allTools = tools
        DispatchQueue.global().async {
            Task {
                try? await ForensicsMCPBootstrapper.shared.ensure()
                allTools.append(contentsOf: await pluginMCPTools())
                listSem.signal()
            }
        }
        listSem.wait()
        sendResponse(id: request.id, result: ["tools": allTools])
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
        // Whether this tool's output is forensic evidence (exempt from
        // sanitization, below). True for the forensics.* meta-tools AND
        // for dynamically-registered per-plugin tools (macho_analyze_path,
        // …), whose names lack the forensics. prefix but return the same
        // chain-of-custody-sensitive run results.
        // The session-bundle tools RETURN a functional bundle path the
        // operator must use (export → verify); redacting the username in that
        // path (SEC-1) would break the round-trip. The path is the operator's
        // own bundle location, so it's exempt — unlike get_agent_session,
        // whose timeline is observability data that stays sanitized.
        var isForensicTool = toolName.hasPrefix("forensics.")
            || toolName == "export_session_bundle"
            || toolName == "verify_session_bundle"
        DispatchQueue.global().async {
            Task {
                result = await handleToolCall(name: toolName, args: args)
                if !isForensicTool { isForensicTool = await pluginForMCPTool(toolName) != nil }
                sem.signal()
            }
        }
        sem.wait()
        // Wave-3 P5: record the call on the durable per-call rail.
        recordToolCall(toolName, result: result)
        // Sanitize before sending to the MCP client (typically an AI
        // agent like Claude Code). Without this, raw /Users/<name>/...
        // paths, private IPs, hostnames, and any leaked API keys flow
        // straight to the agent every call. README documents
        // automatic sanitization for cloud LLM calls — this is the
        // missing half of that promise for MCP responses.
        //
        // Exception: forensic artifact reads are integrity reads consumed
        // as evidence — their source paths, summaries and hashes must NOT
        // be scrubbed or chain-of-custody breaks. The privacy ceiling
        // already bounds what those tools return (metadata by default;
        // content only with an explicit `allow-ai --content` grant).
        let response = isForensicTool ? result : sanitizeContent(result)
        sendResponse(id: reqId, result: response)
    default:
        sendError(id: request.id, code: -32601, message: "Method not found: \(request.method)")
    }
}
