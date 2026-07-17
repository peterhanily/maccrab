// `maccrabctl session` subcommands — headless-operator parity with the
// MCP server's agent-session tools (list_agent_sessions, get_agent_session,
// export_session_bundle, verify_session_bundle).
//
// Wave-3 recorder surface. The CLI is unentitled (uid 501, no Secure-Enclave
// access), so signing forces `.filesystemDegraded` — the same mode the MCP
// server uses — with a dedicated `session_keys/` dir under the user-writable
// data tree so the public key matches across export and verify.
//
// Substrate choice mirrors maccrab-mcp's handlers exactly: pure-CryptoKit
// filesystem keys. The mutation and tool-call rails the MCP server stitches in
// come from MCP-server-private JSONL logs (mcp_mutations.jsonl /
// mcp_tool_calls.jsonl) that the CLI does not own, so CLI exports carry EMPTY
// mutation/tool-call rails and say so out loud.

import Foundation
import os
import MacCrabCore

private let sessionAuditLogger = Logger(subsystem: "com.maccrab.ctl", category: "session-audit")

enum SessionCommandError: Error, CustomStringConvertible {
    case usage(String)
    case underlying(String)

    var description: String {
        switch self {
        case .usage(let msg): return msg
        case .underlying(let msg): return msg
        }
    }
}

/// Dispatch `maccrabctl session <subcommand> ...`. Called from
/// MacCrabCtl.main when args[1] == "session".
func dispatchSession(args: [String]) async {
    guard let sub = args.first else {
        printSessionUsage()
        exit(0)
    }
    let rest = Array(args.dropFirst())

    do {
        switch sub {
        case "list":
            try await sessionList(args: rest)
        case "show":
            try await sessionShow(args: rest)
        case "export":
            try await sessionExport(args: rest)
        case "verify":
            try await sessionVerify(args: rest)
        case "help", "-h", "--help":
            printSessionUsage()
        default:
            print("Unknown session subcommand: \(sub)")
            printSessionUsage()
            exit(1)
        }
    } catch let SessionCommandError.usage(msg) {
        print(msg)
        exit(1)
    } catch {
        print("Error: \(error)")
        exit(1)
    }
}

func printSessionUsage() {
    print("""
    Usage: maccrabctl session <subcommand>

    Subcommands:
      list                                List recent AI-agent sessions
                                          (tool, project dir, first/last seen,
                                          event count, durable session id).
      show <session-id>                   Show one session's chronological
                                          timeline (events) + the alerts its
                                          activity tripped.
      export <session-id> [--out <dir>]   Export a signed .maccrabsession bundle
                                          (events + alerts, Merkle-rooted +
                                          ECDSA-P256 signed). Default out dir:
                                          <user-support>/MacCrab/session_bundles.
      verify <bundle>                     Verify a .maccrabsession bundle:
                                          recompute the Merkle root (detects
                                          tamper) + verify the signature.

    Note: <session-id> must be a session UUID (from `session list`).
    CLI exports carry EMPTY mutation/tool-call rails — those come from the MCP
    server's private logs; only the MCP `export_session_bundle` includes them.
    """)
}

// MARK: - SEC-3 id guard

/// Reject anything that isn't a session UUID. In `export` the id becomes a path
/// component, so a crafted '../'-style id must not escape the bundles dir; the
/// other subcommands keep the same guard for a consistent contract.
private func requireSessionUUID(_ id: String) throws {
    guard UUID(uuidString: id) != nil else {
        throw SessionCommandError.usage("'\(id)' is not a session UUID. Run `maccrabctl session list` to find a valid id.")
    }
}

// MARK: - Subcommand implementations

private func sessionList(args: [String]) async throws {
    var limit = 50
    var i = 0
    while i < args.count {
        if args[i] == "--limit", i + 1 < args.count { limit = Int(args[i+1]) ?? 50; i += 2 }
        else { i += 1 }
    }
    limit = min(max(limit, 1), 500)

    let store = try EventStore(directory: maccrabDataDir())
    // READ surface: an empty / young store (or an absent migration-added
    // ai_tool_session_id column on a fresh box) means "nothing recorded yet",
    // mirroring the MCP handler's fail-soft path — not an error.
    let sessions = (try? await store.agentSessions(limit: limit)) ?? []
    guard !sessions.isEmpty else {
        print("No agent sessions recorded yet.")
        print("Sessions populate once the running engine observes a coding agent (Claude Code, Cursor, …) and its descendant activity.")
        return
    }

    let fmt = ISO8601DateFormatter()
    let widthID = max(sessions.map { $0.sessionId.count }.max() ?? 36, "Session ID".count)
    let widthTool = max(sessions.map { ($0.tool ?? "?").count }.max() ?? 8, "Tool".count)
    print(rowAligned([
        ("Session ID", widthID), ("Tool", widthTool),
        ("Events", 7), ("Last seen", 25),
    ]))
    print(String(repeating: "-", count: widthID + widthTool + 7 + 25 + 6))
    for s in sessions {
        print(rowAligned([
            (s.sessionId, widthID),
            (s.tool ?? "?", widthTool),
            (String(s.eventCount), 7),
            (fmt.string(from: s.lastSeen), 25),
        ]))
        if let proj = s.projectDir, !proj.isEmpty {
            print("    dir: \(proj)")
        }
    }
}

private func sessionShow(args: [String]) async throws {
    guard let id = args.first, !id.hasPrefix("--") else {
        throw SessionCommandError.usage("Usage: maccrabctl session show <session-id>")
    }
    try requireSessionUUID(id)
    var limit = 500
    var i = 1
    while i < args.count {
        if args[i] == "--limit", i + 1 < args.count { limit = Int(args[i+1]) ?? 500; i += 2 }
        else { i += 1 }
    }
    limit = min(max(limit, 1), 2000)

    let store = try EventStore(directory: maccrabDataDir())
    // Fail-soft on the event query (fresh store / unknown id / absent
    // migration column) — same contract as the MCP handler.
    let events = (try? await store.eventsForAgentSession(id, limit: limit)) ?? []
    let alertStore = try? AlertStore(directory: maccrabDataDir())
    let alerts = (try? await alertStore?.alerts(forAgentSession: id)) ?? []

    let fmt = ISO8601DateFormatter()
    print("Session \(id)")
    print("  events: \(events.count)   alerts: \(alerts.count)")
    if events.isEmpty && alerts.isEmpty {
        print("  (no recorded activity for this session id yet)")
        return
    }

    if !events.isEmpty {
        print("\nTimeline (\(events.count)):")
        for e in events {
            var line = "  \(fmt.string(from: e.timestamp))  \(e.eventCategory.rawValue)/\(e.eventAction)  \(e.process.name) (pid \(e.process.pid))"
            if let f = e.file?.path { line += "  file=\(f)" }
            if let n = e.network {
                let host = (n.destinationHostname ?? "").isEmpty
                    ? "\(n.destinationPort)" : "\(n.destinationHostname!):\(n.destinationPort)"
                line += "  dest=\(host)"
            }
            print(line)
        }
    }

    if !alerts.isEmpty {
        print("\nAlerts (\(alerts.count)):")
        for a in alerts {
            print("  \(fmt.string(from: a.timestamp))  [\(a.severity.rawValue.uppercased())] \(a.ruleId) — \(a.ruleTitle)\(a.suppressed ? " (suppressed)" : "")")
        }
    }
}

private func sessionExport(args: [String]) async throws {
    guard let id = args.first, !id.hasPrefix("--") else {
        throw SessionCommandError.usage("Usage: maccrabctl session export <session-id> [--out <dir>]")
    }
    // SEC-3: id becomes a path component below — UUID-only.
    try requireSessionUUID(id)
    var outDir: String? = nil
    var i = 1
    while i < args.count {
        if args[i] == "--out", i + 1 < args.count { outDir = args[i+1]; i += 2 }
        else { i += 1 }
    }

    let store = try EventStore(directory: maccrabDataDir())
    let events = try await store.eventsForAgentSession(id, limit: 10_000)
    let encoder = JSONEncoder()
    let eventsJsonl: [String] = events.compactMap { e in
        (try? encoder.encode(e)).flatMap { String(data: $0, encoding: .utf8) }
    }
    let alertStore = try AlertStore(directory: maccrabDataDir())
    let alerts = (try? await alertStore.alerts(forAgentSession: id)) ?? []
    let alertsJson = (try? encoder.encode(alerts)).flatMap { String(data: $0, encoding: .utf8) } ?? "[]"

    // CLI does NOT own the MCP server's private mutation/tool-call JSONL logs,
    // so these rails are intentionally empty for CLI exports.
    let mutationsJson = "[]"
    let toolCallsJson = "[]"

    let metadata: [String: Any] = [
        "session_id": id,
        "exported_at": ISO8601DateFormatter().string(from: Date()),
        "event_count": events.count,
        "alert_count": alerts.count,
        "mutation_count": 0,
        "tool_call_count": 0,
        "exported_by": "maccrabctl",
        "maccrab_version": MacCrabVersion.current,
    ]
    let metadataJson = (try? JSONSerialization.data(withJSONObject: metadata, options: [.sortedKeys]))
        .flatMap { String(data: $0, encoding: .utf8) } ?? "{}"

    // Target dir: --out, else <user-writable-support>/MacCrab/session_bundles.
    // Always write under the user-WRITABLE tree (uid 501); the daemon's root
    // dir read by maccrabDataDir() is not writable by the CLI.
    let fm = FileManager.default
    let baseDir: URL = outDir.map { URL(fileURLWithPath: $0) }
        ?? URL(fileURLWithPath: maccrabUserWritableDataDir()).appendingPathComponent("session_bundles")
    try? fm.createDirectory(at: baseDir, withIntermediateDirectories: true)
    let target = baseDir.appendingPathComponent("\(id)-\(UUID().uuidString.prefix(8)).maccrabsession")

    // WAVE3-02: force .filesystemDegraded — the unentitled CLI cannot reach the
    // Secure Enclave (would fail -34018 and yield an unsigned, forgeable
    // bundle). A dedicated keys dir keeps this independent of trace-signing keys.
    let ts = TrustSubstrate(
        storage: FilesystemTrustSubstrateStorage(
            baseDirectory: URL(fileURLWithPath: maccrabUserWritableDataDir()).appendingPathComponent("session_keys")
        ),
        modeOverride: .filesystemDegraded
    )

    let res = try await AgentSessionBundle.export(
        sessionId: id,
        eventsJsonl: eventsJsonl,
        alertsJson: alertsJson,
        mutationsJson: mutationsJson,
        metadataJson: metadataJson,
        toolCallsJson: toolCallsJson,
        to: target,
        trustSubstrate: ts
    )

    // Audit: an export materializes session evidence to a new file. Same
    // os.log .notice/"AUDIT" sink the case commands use.
    sessionAuditLogger.notice("CTL AUDIT: session_export — user=\(NSUserName(), privacy: .public) pid=\(getpid()) session=\(id, privacy: .public) path=\(res.bundleDir.path, privacy: .public)")

    print("Exported session bundle for \(id)")
    print("  Path:        \(res.bundleDir.path)")
    print("  Merkle root: \(res.merkleRoot)")
    print("  Signed:      \(res.signed ? "yes" : "no")  (key mode: \(res.keyMode))")
    print("  Events:      \(events.count)   Alerts: \(alerts.count)")
    print("  Rails:       mutations=0 tool_calls=0 (empty for CLI exports — those come from the MCP server's private logs)")
    if let err = res.signError {
        print("  ⚠️  UNSIGNED — signature failed: \(err)")
        print("      Content is hash-rooted (Merkle) but NOT tamper-proof.")
    }
    print("\nVerify with: maccrabctl session verify \(res.bundleDir.path)")
}

private func sessionVerify(args: [String]) async throws {
    guard let path = args.first, !path.hasPrefix("--") else {
        throw SessionCommandError.usage("Usage: maccrabctl session verify <bundle>")
    }
    // Same substrate the export path uses, so the public key matches.
    let ts = TrustSubstrate(
        storage: FilesystemTrustSubstrateStorage(
            baseDirectory: URL(fileURLWithPath: maccrabUserWritableDataDir()).appendingPathComponent("session_keys")
        ),
        modeOverride: .filesystemDegraded
    )
    let v = try await AgentSessionBundle.verify(at: URL(fileURLWithPath: path), trustSubstrate: ts)
    let verdict = (v.merkleOk && v.signed && v.signatureOk) ? "verified"
        : (v.merkleOk && !v.signed) ? "unsigned (content hash-rooted only — forgeable)"
        : "TAMPERED / invalid"
    print("Bundle: \(path)")
    print("  merkle_ok:    \(v.merkleOk)")
    print("  signed:       \(v.signed)")
    print("  signature_ok: \(v.signatureOk)")
    print("  verdict:      \(verdict)")
    // The exit code must be trustworthy for gating: return 0 ONLY for a
    // genuinely signed-and-verified (authenticated) bundle. An UNSIGNED
    // (forgeable, content-hash-rooted-only) bundle and a TAMPERED/invalid one
    // BOTH exit non-zero, so a caller can't mistake a merely well-formed file
    // for authenticated evidence. Distinct codes let a caller tell them apart:
    //   0 = authenticated, 2 = unsigned, 1 = tampered/invalid.
    let authenticated = v.merkleOk && v.signed && v.signatureOk
    if !authenticated {
        exit(v.merkleOk && !v.signed ? 2 : 1)
    }
}
