// MCPMonitor.swift
// MacCrabCore
//
// Monitors MCP (Model Context Protocol) server configurations used by AI
// coding tools (Claude Code, Cursor, Continue.dev, VS Code, Windsurf).
// MCP servers extend AI tool capabilities but malicious ones can inject
// prompt poisoning, exfiltrate data, or gain unauthorized access.

import Foundation
import os.log

/// Watches MCP config files for changes and flags suspicious server entries.
///
/// Detects:
/// - Newly added MCP servers (configuration drift)
/// - Servers with suspicious command paths (/tmp/, /Downloads/, etc.)
/// - Servers with base64-encoded arguments (potential payload obfuscation)
/// - Servers with suspicious names indicating malicious intent
/// - Servers running unknown packages via npx
public actor MCPMonitor {

    private let logger = Logger(subsystem: "com.maccrab", category: "mcp-monitor")

    public nonisolated let events: AsyncStream<MCPServerEvent>
    private var continuation: AsyncStream<MCPServerEvent>.Continuation?
    private var watchTask: Task<Void, Never>?
    private var pollTask: Task<Void, Never>?
    private var dispatchSources: [DispatchSourceFileSystemObject] = []

    /// Baseline of known servers keyed by "configFile::serverName".
    private var knownServers: [String: MCPServerEntry] = [:]
    private var baselined = false

    private let pollInterval: TimeInterval

    // MARK: - Types

    /// An event emitted when an MCP server configuration changes.
    public struct MCPServerEvent: Sendable {
        public let configFile: String
        public let serverName: String
        public let command: String
        public let args: [String]
        public let eventType: EventType
        public let reason: String
        public let tool: String
    }

    public enum EventType: String, Sendable {
        case added = "mcp_server_added"
        case modified = "mcp_server_modified"
        case suspicious = "mcp_server_suspicious"
        case removed = "mcp_server_removed"
    }

    /// Internal representation of a parsed MCP server entry.
    private struct MCPServerEntry: Sendable, Equatable {
        let name: String
        let command: String
        let args: [String]
        let configFile: String
        let tool: String
    }

    // MARK: - Config Paths

    private static let configPaths: [(tool: String, path: String)] = [
        ("claude", "~/.claude/claude_desktop_config.json"),
        ("claude", "~/.claude.json"),
        ("cursor", "~/.cursor/mcp.json"),
        ("continue", "~/.continue/config.json"),
        ("vscode", "~/.vscode/mcp.json"),
        ("windsurf", "~/.windsurf/mcp.json"),
    ]

    // MARK: - Suspicious Patterns

    /// Path components that indicate a suspicious command location.
    private static let suspiciousPathComponents: [String] = [
        "/tmp/",
        "/private/tmp/",
        "/var/tmp/",
        "/Downloads/",
        "/Users/Shared/",
    ]

    /// Server names that suggest malicious intent.
    private static let suspiciousNameKeywords: [String] = [
        "inject", "exfil", "steal", "hack", "exploit", "payload",
        "backdoor", "reverse", "shell", "keylog", "dump", "scrape",
    ]

    /// Known-good MCP packages commonly used with npx.
    private static let knownGoodNpxPackages: Set<String> = [
        "@modelcontextprotocol/server-filesystem",
        "@modelcontextprotocol/server-github",
        "@modelcontextprotocol/server-gitlab",
        "@modelcontextprotocol/server-google-maps",
        "@modelcontextprotocol/server-memory",
        "@modelcontextprotocol/server-postgres",
        "@modelcontextprotocol/server-puppeteer",
        "@modelcontextprotocol/server-sequential-thinking",
        "@modelcontextprotocol/server-slack",
        "@modelcontextprotocol/server-sqlite",
        "@modelcontextprotocol/server-brave-search",
        "@modelcontextprotocol/server-everything",
        "@modelcontextprotocol/server-fetch",
        "mcp-server-fetch",
        "firecrawl-mcp",
    ]

    // MARK: - Initialization

    public init(pollInterval: TimeInterval = 60.0) {
        self.pollInterval = pollInterval
        var capturedContinuation: AsyncStream<MCPServerEvent>.Continuation!
        self.events = AsyncStream(bufferingPolicy: .bufferingNewest(64)) { continuation in
            capturedContinuation = continuation
        }
        self.continuation = capturedContinuation
    }

    // MARK: - Lifecycle

    public func start() {
        guard watchTask == nil else { return }
        logger.info("MCP monitor starting")

        // Perform initial baseline scan
        scanAllConfigs()
        baselined = true

        // Set up file watchers for each config that exists
        setupFileWatchers()

        // Also poll periodically in case file watchers miss events
        pollTask = Task { [weak self] in
            guard let self else { return }
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: UInt64(self.pollInterval * 1_000_000_000))
                guard !Task.isCancelled else { break }
                await self.scanAllConfigs()
            }
        }
    }

    public func stop() {
        watchTask?.cancel()
        watchTask = nil
        pollTask?.cancel()
        pollTask = nil

        for source in dispatchSources {
            source.cancel()
        }
        dispatchSources.removeAll()

        continuation?.finish()
    }

    // MARK: - File Watchers

    private func setupFileWatchers() {
        for (tool, rawPath) in Self.configPaths {
            let path = Self.expandTilde(rawPath)
            guard FileManager.default.fileExists(atPath: path) else { continue }

            let fd = open(path, O_EVTONLY)
            guard fd >= 0 else {
                logger.warning("MCP monitor: cannot open \(path) for watching")
                continue
            }

            let source = DispatchSource.makeFileSystemObjectSource(
                fileDescriptor: fd,
                eventMask: [.write, .rename, .delete, .extend],
                queue: DispatchQueue.global(qos: .utility)
            )

            let capturedPath = path
            let capturedTool = tool

            source.setEventHandler { [weak self] in
                guard let self else { return }
                Task {
                    await self.handleConfigChange(tool: capturedTool, path: capturedPath)
                }
            }

            source.setCancelHandler {
                close(fd)
            }

            source.resume()
            dispatchSources.append(source)

            logger.info("MCP monitor: watching \(path) for \(tool)")
        }
    }

    private func handleConfigChange(tool: String, path: String) {
        logger.info("MCP config changed: \(path)")
        scanConfig(tool: tool, path: path)
    }

    // MARK: - Scanning

    private func scanAllConfigs() {
        for (tool, rawPath) in Self.configPaths {
            let path = Self.expandTilde(rawPath)
            scanConfig(tool: tool, path: path)
        }
    }

    private func scanConfig(tool: String, path: String) {
        guard FileManager.default.fileExists(atPath: path) else { return }

        let servers = parseConfig(tool: tool, path: path)

        // Build set of current server keys for this config
        let currentKeys = Set(servers.map { Self.serverKey(configFile: path, name: $0.name) })

        // Detect removed servers
        let removedKeys = knownServers.keys.filter { key in
            key.hasPrefix(path + "::") && !currentKeys.contains(key)
        }
        for key in removedKeys {
            if let entry = knownServers[key] {
                emitEvent(
                    configFile: path,
                    serverName: entry.name,
                    command: entry.command,
                    args: entry.args,
                    eventType: .removed,
                    reason: "MCP server '\(entry.name)' was removed from \(path)",
                    tool: tool
                )
                knownServers.removeValue(forKey: key)
            }
        }

        // Check each current server
        for server in servers {
            let key = Self.serverKey(configFile: path, name: server.name)
            let existing = knownServers[key]

            if existing == nil {
                // New server
                knownServers[key] = server

                if baselined {
                    emitEvent(
                        configFile: path,
                        serverName: server.name,
                        command: server.command,
                        args: server.args,
                        eventType: .added,
                        reason: "New MCP server '\(server.name)' added to \(path)",
                        tool: tool
                    )
                }
            } else if existing != server {
                // Modified server
                knownServers[key] = server

                emitEvent(
                    configFile: path,
                    serverName: server.name,
                    command: server.command,
                    args: server.args,
                    eventType: .modified,
                    reason: "MCP server '\(server.name)' configuration changed in \(path)",
                    tool: tool
                )
            }

            // Always check for suspicious patterns (even on baseline)
            checkSuspicious(server: server)
        }
    }

    // MARK: - Config Parsing

    private func parseConfig(tool: String, path: String) -> [MCPServerEntry] {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return []
        }

        var servers: [MCPServerEntry] = []

        // Extract mcpServers dict -- different tools use different structures
        let mcpServers: [String: Any]?
        switch tool {
        case "claude":
            // Claude uses {"mcpServers": {...}} at top level
            mcpServers = json["mcpServers"] as? [String: Any]
        case "cursor", "vscode", "windsurf":
            // These use {"mcpServers": {...}} at top level
            mcpServers = json["mcpServers"] as? [String: Any]
        case "continue":
            // Continue.dev uses {"mcpServers": [...]} or {"models": [...], "mcpServers": [...]}
            mcpServers = json["mcpServers"] as? [String: Any]
        default:
            mcpServers = json["mcpServers"] as? [String: Any]
        }

        guard let serversDict = mcpServers else { return [] }

        for (name, value) in serversDict {
            guard let config = value as? [String: Any] else { continue }

            let command = config["command"] as? String ?? ""
            let args: [String]
            if let argsArray = config["args"] as? [String] {
                args = argsArray
            } else if let argsArray = config["args"] as? [Any] {
                args = argsArray.map { "\($0)" }
            } else {
                args = []
            }

            servers.append(MCPServerEntry(
                name: name,
                command: command,
                args: args,
                configFile: path,
                tool: tool
            ))
        }

        return servers
    }

    // MARK: - Suspicious Pattern Detection

    private func checkSuspicious(server: MCPServerEntry) {
        // 1. Suspicious command path
        for component in Self.suspiciousPathComponents {
            if server.command.contains(component) {
                emitEvent(
                    configFile: server.configFile,
                    serverName: server.name,
                    command: server.command,
                    args: server.args,
                    eventType: .suspicious,
                    reason: "MCP server '\(server.name)' command path contains suspicious location '\(component)': \(server.command)",
                    tool: server.tool
                )
                break
            }
        }

        // 2. Base64-encoded arguments
        for arg in server.args {
            if looksLikeBase64(arg) {
                emitEvent(
                    configFile: server.configFile,
                    serverName: server.name,
                    command: server.command,
                    args: server.args,
                    eventType: .suspicious,
                    reason: "MCP server '\(server.name)' has base64-encoded argument (potential obfuscated payload): \(arg.prefix(60))...",
                    tool: server.tool
                )
                break
            }
        }

        // 3. Suspicious server name
        let lowerName = server.name.lowercased()
        for keyword in Self.suspiciousNameKeywords {
            if lowerName.contains(keyword) {
                emitEvent(
                    configFile: server.configFile,
                    serverName: server.name,
                    command: server.command,
                    args: server.args,
                    eventType: .suspicious,
                    reason: "MCP server name '\(server.name)' contains suspicious keyword '\(keyword)'",
                    tool: server.tool
                )
                break
            }
        }

        // 4. npx running unknown package
        if server.command.hasSuffix("/npx") || server.command == "npx" {
            let packageArg = server.args.first { !$0.hasPrefix("-") }
            if let pkg = packageArg, !Self.knownGoodNpxPackages.contains(pkg) {
                emitEvent(
                    configFile: server.configFile,
                    serverName: server.name,
                    command: server.command,
                    args: server.args,
                    eventType: .suspicious,
                    reason: "MCP server '\(server.name)' runs unknown npx package '\(pkg)' — verify this is a legitimate MCP server package",
                    tool: server.tool
                )
            }
        }

        // 5. Tool description injection patterns in args
        let injectionPatterns = [
            "ignore all previous",
            "ignore your instructions",
            "you are now",
            "system prompt",
            "<tool_result>",
            "</tool_result>",
            "<result>",
            "IMPORTANT:",
        ]
        let allArgs = server.args.joined(separator: " ").lowercased()
        for pattern in injectionPatterns {
            if allArgs.contains(pattern.lowercased()) {
                emitEvent(
                    configFile: server.configFile,
                    serverName: server.name,
                    command: server.command,
                    args: server.args,
                    eventType: .suspicious,
                    reason: "MCP server '\(server.name)' args contain prompt injection pattern: '\(pattern)'",
                    tool: server.tool
                )
                break
            }
        }
    }

    // MARK: - Helpers

    /// Check if a string looks like a base64-encoded payload.
    /// Requires at least 40 chars of valid base64 characters with padding.
    private nonisolated func looksLikeBase64(_ string: String) -> Bool {
        guard string.count >= 40 else { return false }
        let base64Chars = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "+/="))
        return string.unicodeScalars.allSatisfy { base64Chars.contains($0) }
    }

    private static func serverKey(configFile: String, name: String) -> String {
        "\(configFile)::\(name)"
    }

    private nonisolated static func expandTilde(_ path: String) -> String {
        if path.hasPrefix("~/") {
            return NSHomeDirectory() + String(path.dropFirst(1))
        }
        return path
    }

    private func emitEvent(
        configFile: String,
        serverName: String,
        command: String,
        args: [String],
        eventType: EventType,
        reason: String,
        tool: String
    ) {
        let event = MCPServerEvent(
            configFile: configFile,
            serverName: serverName,
            command: command,
            args: args,
            eventType: eventType,
            reason: reason,
            tool: tool
        )
        continuation?.yield(event)

        switch eventType {
        case .suspicious:
            logger.warning("MCP suspicious: \(reason)")
        case .added:
            logger.notice("MCP server added: \(serverName) in \(configFile)")
        case .modified:
            logger.notice("MCP server modified: \(serverName) in \(configFile)")
        case .removed:
            logger.notice("MCP server removed: \(serverName) from \(configFile)")
        }
    }
}
