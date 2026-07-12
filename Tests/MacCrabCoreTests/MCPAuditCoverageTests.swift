// MCPAuditCoverageTests.swift
// MacCrabCoreTests
//
// G-05: prove 1:1 audit coverage for the mutating control surface.
//
// The audit report flagged that it was UNPROVEN that every mutating MCP tool
// and every privileged-inbox verb emits an audit-log line. A mutation with no
// audit trail is invisible to `dashboard_audit.log` / get_agent_session, so a
// forgotten `auditLog(...)` silently erases the "who changed what" record — the
// same failure class as the v1.18 capability-bypass, but for accountability
// instead of authorization.
//
// These are SOURCE-SCANNING tests (they read the shipped .swift files, not the
// running binary) so they can assert the structural invariant directly and,
// critically, FAIL when a FUTURE mutating tool/verb is added without an audit
// line:
//
//   1. everyGatedMcpToolAuditLogs — the canonical mutating MCP surface is the
//      key set of `agentToolCapability` (AgentControl.swift); it is DERIVED from
//      source here, so any new gated tool is automatically in scope. Each must
//      have an `auditLog("<tool>"` call somewhere in Sources/maccrab-mcp/.
//
//   2. everyMutatingInboxVerbAuditLogs — each privileged-inbox verb is drained
//      by a `handle<Verb>Requests` function in DaemonTimers.swift; every such
//      handler must call `auditLogInbox(`. Handler names are DERIVED from source,
//      so a new verb handler is automatically in scope.
//
// This pairs with `mutatingToolsAreGated` (MCPProtocolHarnessTests.swift), which
// pins the same surface to the CAPABILITY gate. Gate + audit together: a new
// mutator must be both gated AND audited, or a test fails.

import Testing
import Foundation

@Suite("MCP audit coverage")
struct MCPAuditCoverageTests {

    /// Package root, resolved from this file's location (mirrors the harness).
    static func packageRoot() -> URL {
        URL(fileURLWithPath: #filePath)   // .../Tests/MacCrabCoreTests/<this>.swift
            .deletingLastPathComponent()  // MacCrabCoreTests
            .deletingLastPathComponent()  // Tests
            .deletingLastPathComponent()  // package root
    }

    private static func read(_ relativePath: String) -> String {
        (try? String(contentsOf: packageRoot().appendingPathComponent(relativePath), encoding: .utf8)) ?? ""
    }

    /// All regex capture-group-1 matches for `pattern` in `text`.
    private static func matches(_ pattern: String, in text: String) -> [String] {
        guard let re = try? NSRegularExpression(pattern: pattern) else { return [] }
        let ns = text as NSString
        return re.matches(in: text, range: NSRange(location: 0, length: ns.length)).compactMap { m in
            m.numberOfRanges > 1 ? ns.substring(with: m.range(at: 1)) : nil
        }
    }

    /// Concatenate every .swift file under Sources/maccrab-mcp/ so an audit call
    /// counts no matter which file the handler lives in.
    private static func mcpServerSource() -> String {
        let dir = packageRoot().appendingPathComponent("Sources/maccrab-mcp")
        let files = (try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? []
        return files
            .filter { $0.pathExtension == "swift" }
            .compactMap { try? String(contentsOf: $0, encoding: .utf8) }
            .joined(separator: "\n")
    }

    // MARK: - MCP tools

    @Test("every capability-gated MCP tool emits an audit-log line")
    func everyGatedMcpToolAuditLogs() {
        let agentControl = Self.read("Sources/maccrab-mcp/AgentControl.swift")
        #expect(!agentControl.isEmpty, "could not read AgentControl.swift")

        // Isolate the `agentToolCapability` dictionary literal, then pull its
        // string keys (`"tool": .config|.authoring|.response`). Deriving the set
        // from source is the load-bearing part: a tool added to the gate is
        // automatically required to audit, with no second list to update.
        let block: String = {
            guard let start = agentControl.range(of: "let agentToolCapability") else { return agentControl }
            let rest = agentControl[start.lowerBound...]
            if let end = rest.range(of: "\n]") { return String(rest[..<end.upperBound]) }
            return String(rest)
        }()
        let gatedTools = Set(Self.matches(#""([a-z0-9_]+)"\s*:\s*\.(?:config|authoring|response)"#, in: block))

        // Sanity: the parse worked and found the known surface (guards against a
        // silently-empty regex that would make the loop below vacuously pass).
        #expect(gatedTools.count >= 15, "parsed only \(gatedTools.count) gated tools from agentToolCapability — parser likely broke")
        for known in ["set_daemon_config", "create_rule", "suppress_alert", "set_response_action",
                      "forensics_run_collector", "forensics_run_all"] {
            #expect(gatedTools.contains(known), "expected gated tool '\(known)' not parsed from agentToolCapability")
        }

        let source = Self.mcpServerSource()
        #expect(!source.isEmpty, "could not read Sources/maccrab-mcp/*.swift")
        for tool in gatedTools.sorted() {
            #expect(source.contains("auditLog(\"\(tool)\""),
                    "gated MCP tool '\(tool)' has no auditLog(\"\(tool)\", …) call — a mutation with no audit trail (G-05). Add an auditLog line to its handler.")
        }
    }

    // MARK: - Privileged-inbox verbs

    @Test("every mutating inbox-verb handler emits an audit-log line")
    func everyMutatingInboxVerbAuditLogs() {
        let timers = Self.read("Sources/MacCrabAgentKit/DaemonTimers.swift")
        #expect(!timers.isEmpty, "could not read DaemonTimers.swift")

        // Each privileged-inbox verb is drained by a `handle<Verb>Requests`
        // function. Derive the handler names from source so a new verb handler
        // is automatically in scope.
        let handlerNames = Set(Self.matches(#"private static func (handle\w+Requests)\("#, in: timers))
        #expect(handlerNames.count >= 12, "parsed only \(handlerNames.count) inbox-verb handlers — parser likely broke")
        for known in ["handleSuppressAlertRequests", "handleInstallRuleRequests",
                      "handleSetDaemonConfigRequests", "handleSuppressCampaignRequests"] {
            #expect(handlerNames.contains(known), "expected inbox handler '\(known)' not parsed from DaemonTimers.swift")
        }

        // Every handler function body must contain an auditLogInbox( call. Body
        // = from the function's declaration to the next handler declaration.
        for name in handlerNames.sorted() {
            guard let declStart = timers.range(of: "func \(name)(") else {
                Issue.record("could not locate body of \(name)")
                continue
            }
            let after = timers[declStart.upperBound...]
            let body: Substring
            if let next = after.range(of: "\n    private static func ") {
                body = after[..<next.lowerBound]
            } else {
                body = after
            }
            #expect(body.contains("auditLogInbox("),
                    "inbox-verb handler '\(name)' has no auditLogInbox( call — a mutating verb with no audit trail (G-05).")
        }
    }
}
