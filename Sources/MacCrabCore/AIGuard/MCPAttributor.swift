// MCPAttributor.swift
// MacCrabCore
//
// Producer half of MCPBaselineService (v1.7.0). At event time, walks
// the firing process's ancestry to identify whether one of its
// ancestors is a running MCP server and, if so, returns the server
// name + AI-tool host that owns it. Tags are written into
// `Event.enrichments` and fed into `MCPBaselineService.observe(...)`.
//
// The attribution job is two questions:
//
//   1. "Does this event's process descend from an AI-tool host?"
//      Already answered by `AIProcessTracker.isAIChild`. The attributor
//      only runs when isAIChild returns true with a known toolType, so
//      non-AI events pay zero cost.
//
//   2. "If yes, which configured MCP server was the boundary process?"
//      Answered here. The attributor cross-references the event's
//      ancestor chain against `MCPMonitor.serversForTool(...)` — the
//      static configured-server list — and matches via cmdline /
//      executable shape. The first ancestor that matches a configured
//      server *is* the MCP-server-boundary process; that's the
//      attribution.
//
// Hot-path cost: O(1) cache hit by PID for events under an MCP server
// we've already attributed; O(ancestors × configured_servers) on first
// encounter (typically <50 work units).

import Foundation
import os.log

public actor MCPAttributor {

    // MARK: - Public types

    /// The result of attributing one event to an MCP server.
    public struct Attribution: Sendable, Hashable {
        /// The configured server name (key from the AI tool's config
        /// file, e.g. "filesystem", "github", "brave-search").
        public let serverName: String

        /// Best-effort category derived from the server's package name
        /// or the server name itself. Used for grouping in the
        /// dashboard. e.g. "filesystem", "github", "fetch", "memory".
        public let serverCategory: String

        /// Tool key matching `MCPMonitor` taxonomy: "claude", "cursor",
        /// "continue", "vscode", "windsurf".
        public let tool: String

        /// PID of the boundary process we identified as the running
        /// instance of this configured server. Useful for later
        /// telemetry (drift between attributed PID and event PID
        /// depth ⇒ deeper subprocess chains).
        public let boundaryPid: Int32

        /// How confident we are in the match.
        public enum Confidence: String, Sendable, Hashable, Codable {
            /// Cmdline contained the configured server's distinctive
            /// package token (`@modelcontextprotocol/server-foo`,
            /// `mcp-server-fetch`, etc.).
            case high
            /// Executable basename matched the configured `command`
            /// AND at least one configured arg appeared in cmdline.
            case medium
            /// Match was inferred from descending an AI-tool host
            /// without a stronger signal — kept for telemetry but
            /// not fed to the baseline.
            case low
        }
        public let confidence: Confidence
    }

    // MARK: - Dependencies

    private let mcpMonitor: MCPMonitor
    private let lineage: ProcessLineage

    // MARK: - State

    /// PID-keyed cache of attributions. `nil` value means "we walked
    /// this PID's ancestry and decided there's no MCP attribution" —
    /// caching the negative result keeps the hot path O(1) on the
    /// many AI-child events that aren't actually under an MCP server.
    private var cache: [pid_t: Attribution?] = [:]
    private let cacheCap: Int

    private let logger = Logger(subsystem: "com.maccrab.aiguard", category: "mcp-attributor")

    public init(
        mcpMonitor: MCPMonitor,
        lineage: ProcessLineage,
        cacheCap: Int = 5_000
    ) {
        self.mcpMonitor = mcpMonitor
        self.lineage = lineage
        self.cacheCap = max(64, cacheCap)
    }

    // MARK: - API

    /// Attribute an event to an MCP server, if any of its ancestors
    /// looks like one of the AI-tool's configured servers.
    ///
    /// Caller is responsible for first checking `aiTracker.isAIChild`
    /// — this method assumes the caller already knows the event is
    /// under an AI-tool host.
    ///
    /// - Parameters:
    ///   - pid: Event PID.
    ///   - ancestors: Ancestor chain (parent first → root last).
    ///     Pass through what `ProcessLineage.ancestors(of:)` returned.
    ///   - aiTool: AI-tool host classification (claude_code, cursor, …).
    /// - Returns: Attribution if any ancestor matches a configured MCP
    ///   server for `aiTool`; `nil` otherwise. Negative results are
    ///   cached under the PID so subsequent events from the same
    ///   process don't repeat the walk.
    public func attribute(
        pid: Int32,
        ancestors: [ProcessAncestor],
        aiTool: AIToolType
    ) async -> Attribution? {
        if let cached = cache[pid] { return cached }

        let toolKey = Self.mcpToolKey(for: aiTool)
        let configured = await mcpMonitor.serversForTool(toolKey)
        guard !configured.isEmpty else {
            recordMiss(pid: pid)
            return nil
        }

        // Build the search list: the firing process itself plus its
        // ancestor chain. We try each one against every configured
        // server and stop at the strongest match. Ordering walk-out
        // (event PID first, root last) means a tightly-nested
        // subprocess gets attributed to its nearest MCP boundary, not
        // to a far-up ancestor that happens to share a token.
        var firstAncestorCmd = await lineage.commandLine(of: pid) ?? ""
        var bestMatch: (Attribution, score: Int)? = nil

        for (index, candidate) in ([SearchTarget(pid: pid, executable: nil, cmd: firstAncestorCmd)] + ancestors.map { SearchTarget(pid: $0.pid, executable: $0.executable, cmd: nil) }).enumerated() {
            let cmdline: String
            if let pre = candidate.cmd { cmdline = pre }
            else { cmdline = await lineage.commandLine(of: candidate.pid) ?? "" }
            // The first iteration's cmdline doubles as the closure
            // input above; reuse to keep the actor hop count down on
            // hot path.
            if index == 0 { firstAncestorCmd = cmdline }

            for server in configured {
                let score = matchScore(server: server, executable: candidate.executable, cmdline: cmdline)
                guard score > 0 else { continue }
                let confidence: Attribution.Confidence = score >= 3 ? .high : score == 2 ? .medium : .low
                let attribution = Attribution(
                    serverName: server.name,
                    serverCategory: Self.categorize(server: server),
                    tool: server.tool,
                    boundaryPid: candidate.pid,
                    confidence: confidence
                )
                if let existing = bestMatch {
                    if score > existing.score {
                        bestMatch = (attribution, score)
                    }
                } else {
                    bestMatch = (attribution, score)
                }
                // High-confidence match at the nearest ancestor wins
                // outright; no need to keep walking. Saves work on
                // typical event traffic.
                if confidence == .high { break }
            }
            if bestMatch?.0.confidence == .high { break }
        }

        if let best = bestMatch {
            recordHit(pid: pid, attribution: best.0)
            return best.0
        }
        recordMiss(pid: pid)
        return nil
    }

    /// Evict cached entry for an exited PID. Optional — the cache
    /// also caps itself at `cacheCap` with LRU-by-insertion eviction —
    /// but calling this on every ES exit event keeps the cache lean.
    public func processExited(pid: Int32) {
        cache.removeValue(forKey: pid)
    }

    // MARK: - Internals

    private struct SearchTarget {
        let pid: Int32
        let executable: String?
        let cmd: String?
    }

    private func recordHit(pid: pid_t, attribution: Attribution) {
        if cache.count >= cacheCap, let evict = cache.keys.first {
            cache.removeValue(forKey: evict)
        }
        cache[pid] = attribution
    }

    private func recordMiss(pid: pid_t) {
        if cache.count >= cacheCap, let evict = cache.keys.first {
            cache.removeValue(forKey: evict)
        }
        cache[pid] = .some(nil)
    }

    /// Score how strongly a process matches a configured server.
    ///   3 — cmdline contains the server's package token (e.g.
    ///       `@modelcontextprotocol/server-filesystem`,
    ///       `mcp-server-fetch`).
    ///   2 — executable basename matches `command` AND at least one
    ///       configured arg appears in cmdline.
    ///   1 — executable basename matches `command` (weak).
    ///   0 — no match.
    private func matchScore(
        server: MCPMonitor.ConfiguredServer,
        executable: String?,
        cmdline: String
    ) -> Int {
        // Strong: package token in cmdline
        for arg in server.args {
            if Self.looksLikePackageToken(arg), cmdline.contains(arg) {
                return 3
            }
        }

        // Medium / weak: command match
        if let exe = executable, !server.command.isEmpty {
            let exeBasename = (exe as NSString).lastPathComponent
            if exeBasename == (server.command as NSString).lastPathComponent || exe == server.command {
                if server.args.contains(where: { cmdline.contains($0) && $0.count > 1 }) {
                    return 2
                }
                return 1
            }
        }

        return 0
    }

    private static func looksLikePackageToken(_ s: String) -> Bool {
        // "@modelcontextprotocol/server-filesystem", "mcp-server-fetch",
        // "firecrawl-mcp", etc. — distinctive multi-word tokens that
        // are unlikely to appear unrelated in a cmdline.
        if s.hasPrefix("@modelcontextprotocol/") { return true }
        if s.hasPrefix("mcp-server-") { return true }
        if s.hasSuffix("-mcp") && s.count >= 8 { return true }
        // v1.7.2 — additional tokens for Aider + Codex MCP shapes:
        // - aider plugins ship as `aider_mcp_*` Python modules
        // - OpenAI Codex CLI uses `@openai/codex-cli` and
        //   `openai-codex-mcp-*` Node packages
        if s.hasPrefix("aider_mcp_") { return true }
        if s.hasPrefix("@openai/codex") { return true }
        if s.hasPrefix("openai-codex-mcp") { return true }
        return false
    }

    private static func categorize(server: MCPMonitor.ConfiguredServer) -> String {
        // Try the package-token form first — it carries the canonical
        // suffix (filesystem, github, brave-search, …).
        for arg in server.args {
            if arg.hasPrefix("@modelcontextprotocol/server-") {
                return String(arg.dropFirst("@modelcontextprotocol/server-".count))
            }
            if arg.hasPrefix("mcp-server-") {
                return String(arg.dropFirst("mcp-server-".count))
            }
            if arg.hasSuffix("-mcp") {
                return String(arg.dropLast("-mcp".count))
            }
            // v1.7.2 — additional category extractors:
            if arg.hasPrefix("aider_mcp_") {
                return String(arg.dropFirst("aider_mcp_".count))
            }
            if arg.hasPrefix("openai-codex-mcp-") {
                return String(arg.dropFirst("openai-codex-mcp-".count))
            }
        }
        // Fall back to the configured server name.
        return server.name
    }

    /// Map an `AIToolType` (used by AIProcessTracker) to the tool key
    /// that `MCPMonitor` indexes its config under. The two enums grew
    /// independently; this is the bridge.
    private static func mcpToolKey(for tool: AIToolType) -> String {
        switch tool {
        case .claudeCode, .openClaw: return "claude"
        case .cursor:                return "cursor"
        case .continuedev:           return "continue"
        case .windsurf:              return "windsurf"
        case .copilot:               return "vscode"
        case .codex, .aider, .unknown: return tool.rawValue
        }
    }
}
