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
    private var pollTask: Task<Void, Never>?
    private var dispatchSources: [DispatchSourceFileSystemObject] = []
    private var lifecyclePhase: CollectorLifecyclePhase = .initialized
    private let callbackTasks = CollectorCallbackTaskLifecycle(maximumInFlight: 16)
    private let sourceCancellationGroup = DispatchGroup()

    /// Baseline of known servers keyed by "configFile::serverName".
    private var knownServers: [String: MCPServerEntry] = [:]
    /// Last read failure per path. The 60-second poll reports each stable
    /// failure state once, then re-arms after the file becomes readable or its
    /// failure class changes.
    private var reportedConfigFailures: [String: ConfigReadFailure] = [:]
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

    private enum ConfigReadFailure: Sendable, Equatable {
        case malformedJSON
        case carrier(BoundedRegularFileReader.Rejection)

        static func == (lhs: Self, rhs: Self) -> Bool {
            switch (lhs, rhs) {
            case (.malformedJSON, .malformedJSON):
                return true
            case (.carrier(.oversized), .carrier(.oversized)):
                // A growing poison file remains one failure class; do not emit
                // a fresh alert every poll merely because its byte count rose.
                return true
            case (.carrier(let left), .carrier(let right)):
                return left == right
            default:
                return false
            }
        }
    }

    private enum ConfigParseResult: Sendable {
        case success([MCPServerEntry])
        case failure(ConfigReadFailure)
    }

    // MARK: - Public snapshot for MCPAttributor (v1.7.0)

    /// Public, copy-by-value snapshot of one configured MCP server. Used
    /// by `MCPAttributor` (and any other consumer that needs to match a
    /// running process against the configured-server set) without having
    /// to re-parse the JSON config files itself.
    public struct ConfiguredServer: Sendable, Hashable {
        public let name: String
        public let command: String
        public let args: [String]
        public let tool: String
    }

    /// Returns every currently-known MCP server configured for the given
    /// AI-tool key (`"claude"`, `"cursor"`, `"vscode"`, `"continue"`,
    /// `"windsurf"`). Empty when no config has been parsed yet (the
    /// monitor performs its first scan inside `start()`).
    public func serversForTool(_ tool: String) -> [ConfiguredServer] {
        knownServers.values
            .filter { $0.tool == tool }
            .map { ConfiguredServer(name: $0.name, command: $0.command, args: $0.args, tool: $0.tool) }
    }

    /// Returns every currently-known MCP server across all tools.
    /// Useful for the dashboard's MCP Server Activity panel.
    public func allConfiguredServers() -> [ConfiguredServer] {
        knownServers.values.map {
            ConfiguredServer(name: $0.name, command: $0.command, args: $0.args, tool: $0.tool)
        }
    }

    /// Test-only helper: inject a configured server without going
    /// through the file-watcher path. Used by `MCPAttributorTests`.
    /// Underscore prefix marks the SPI nature; we don't strip it
    /// from production builds because the file-write side effect
    /// would require a real config file otherwise — and the seed
    /// itself is harmless (it's just a dictionary insert).
    public func _testInjectServer(_ server: ConfiguredServer) {
        let key = "\(server.tool)::\(server.name)"
        knownServers[key] = MCPServerEntry(
            name: server.name,
            command: server.command,
            args: server.args,
            configFile: "(test-injected)",
            tool: server.tool
        )
    }

    // MARK: - Config Paths

    private static let configPaths: [(tool: String, path: String)] = [
        ("claude", "~/.claude/claude_desktop_config.json"),
        // Claude Desktop's real config location (the ~/.claude/ path above is the
        // CLI's directory and does not hold the desktop config).
        ("claude", "~/Library/Application Support/Claude/claude_desktop_config.json"),
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

    /// AI-05: markers looked for inside a LOCAL MCP server's own source file.
    /// ONLY the zero-FP-by-construction set. The looser `injectionPatterns`
    /// used against `args` in check 5 ("system prompt", "IMPORTANT:",
    /// "you are now") occur throughout legitimate MCP server source and would
    /// turn the 60 s poll into an alert storm.
    private static let toolPoisoningStrongMarkers: [String] = [
        "ignore your instructions",
        "do not tell the user",
        "hidden instruction",
        "system prompt override",
    ]

    /// Extensions whose contents ARE the server's tool definitions. Compiled
    /// binaries are deliberately absent: MacCrab's own `maccrab-mcp` embeds the
    /// Forensicate injection-rule corpus as string literals, so scanning Mach-O
    /// would self-trip on every poll.
    private static let scannableServerSourceExtensions: Set<String> = [
        "js", "mjs", "cjs", "ts", "py", "rb", "sh", "json",
    ]

    /// Hard cap on how much of a server source file is read.
    private static let maxServerSourceScanBytes = 512 * 1024

    /// MCP clients accumulate project history in their JSON config (notably
    /// `~/.claude.json`), so this is deliberately larger than the small
    /// toggle/config caps elsewhere. It is still finite: these files live in
    /// user-writable homes and are read by the root daemon during startup and
    /// every poll.
    static let maxConfigBytes = 4 * 1024 * 1024

    /// Descriptor-identity/change-time fingerprints already scanned, so the
    /// 60 s poll does not re-parse or re-emit on an unchanged file. The bounded
    /// descriptor read still occurs to bind all fingerprint fields to the same
    /// inode. Cleared wholesale past the cap: this is cheap parse avoidance,
    /// not a correctness cache.
    private var scannedServerSources: Set<String> = []

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
        guard lifecyclePhase == .initialized, callbackTasks.open() else {
            logger.warning("MCP monitor start rejected after its one-shot lifecycle advanced")
            return
        }
        lifecyclePhase = .running
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
                try? await Task.sleep(nanoseconds: UInt64(PowerGate.adjustedInterval(base: self.pollInterval) * 1_000_000_000))
                guard !Task.isCancelled else { break }
                await self.scanAllConfigs()
            }
        }
    }

    public func stop() {
        _ = beginStop()
    }

    @discardableResult
    public func stopAndJoin(deadline: TimeInterval = 1.0) async -> Bool {
        let tasks = beginStop()
        async let tasksJoined = CollectorBoundedTaskJoin.waitForAll(tasks, deadline: deadline)
        async let sourcesJoined = CollectorDispatchGroupJoin.wait(sourceCancellationGroup, deadline: deadline)
        let (taskResult, sourceResult) = await (tasksJoined, sourcesJoined)
        let clean = taskResult && sourceResult
        if clean {
            pollTask = nil
            lifecyclePhase = .stopped
            logger.info("MCP monitor stopped cleanly")
        } else {
            logger.error("MCP monitor stop deadline expired with poll, callback, or source teardown active")
        }
        return clean
    }

    private func beginStop() -> [Task<Void, Never>] {
        if lifecyclePhase == .stopped { return [] }
        lifecyclePhase = .stopping
        var tasks = callbackTasks.sealAndCancel()
        if let pollTask { tasks.append(pollTask) }
        pollTask?.cancel()

        for source in dispatchSources {
            source.cancel()
        }
        dispatchSources.removeAll()

        continuation?.finish()
        continuation = nil
        return tasks
    }

    deinit {
        _ = callbackTasks.sealAndCancel()
        pollTask?.cancel()
        for source in dispatchSources { source.cancel() }
        continuation?.finish()
    }

    // MARK: - File Watchers

    private func setupFileWatchers() {
        for (tool, path) in Self.resolvedConfigPaths() {
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
            let callbackTasks = self.callbackTasks

            source.setEventHandler { [weak self] in
                callbackTasks.submit { [weak self] in
                    await self?.handleConfigChange(tool: capturedTool, path: capturedPath)
                }
            }

            sourceCancellationGroup.enter()
            let sourceCancellationGroup = self.sourceCancellationGroup
            source.setCancelHandler {
                close(fd)
                sourceCancellationGroup.leave()
            }

            source.resume()
            dispatchSources.append(source)

            logger.info("MCP monitor: watching \(path) for \(tool)")
        }
    }

    private func handleConfigChange(tool: String, path: String) {
        guard lifecyclePhase == .running, !Task.isCancelled else { return }
        logger.info("MCP config changed: \(path)")
        scanConfig(tool: tool, path: path)
    }

    // MARK: - Scanning

    private func scanAllConfigs() {
        for (tool, path) in Self.resolvedConfigPaths() {
            scanConfig(tool: tool, path: path)
        }
    }

    private func scanConfig(tool: String, path: String) {
        guard FileManager.default.fileExists(atPath: path) else {
            reportedConfigFailures.removeValue(forKey: path)
            return
        }

        let servers: [MCPServerEntry]
        switch parseConfig(tool: tool, path: path) {
        case .success(let parsed):
            reportedConfigFailures.removeValue(forKey: path)
            servers = parsed
        case .failure(let failure):
            reportConfigFailure(failure, tool: tool, path: path)
            // A rejected or malformed carrier says nothing about whether the
            // previously parsed servers were removed. Preserve the last known
            // baseline instead of emitting false removals and erasing it.
            return
        }

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

    private func parseConfig(tool: String, path: String) -> ConfigParseResult {
        let snapshot: BoundedRegularFileReader.Snapshot
        switch BoundedRegularFileReader.readOutcome(
            at: path,
            maximumBytes: Self.maxConfigBytes
        ) {
        case .success(let read):
            snapshot = read
        case .rejected(let reason):
            return .failure(.carrier(reason))
        }
        guard let json = try? JSONSerialization.jsonObject(
            with: snapshot.data
        ) as? [String: Any] else {
            return .failure(.malformedJSON)
        }

        var servers: [MCPServerEntry] = []

        // Every supported tool uses {"mcpServers": {...}} at the top level, so
        // there is one common extraction. (This replaced a four-arm switch whose
        // arms were all identical.)
        var merged = json["mcpServers"] as? [String: Any] ?? [:]

        // Claude Code ALSO scopes servers per project under
        // `projects["<cwd>"].mcpServers`, and reading only the top level found
        // nothing: on a host with a server configured, `~/.claude.json`'s
        // top-level `mcpServers` is literally null while the real entry sits under
        // `projects`. That is why MCP attribution was 0-for-47,087 and both
        // MCPAttributor and MCPBehavioralBaseline never executed.
        if tool == "claude", let projects = json["projects"] as? [String: Any] {
            for (_, projectValue) in projects {
                guard let project = projectValue as? [String: Any],
                      let servers = project["mcpServers"] as? [String: Any] else { continue }
                // Top-level entries win on a name collision — a globally
                // configured server is the more authoritative record.
                for (name, cfg) in servers where merged[name] == nil {
                    merged[name] = cfg
                }
            }
        }

        guard !merged.isEmpty else { return .success([]) }
        let serversDict = merged

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

        return .success(servers)
    }

    private func reportConfigFailure(
        _ failure: ConfigReadFailure,
        tool: String,
        path: String
    ) {
        guard reportedConfigFailures[path] != failure else { return }
        reportedConfigFailures[path] = failure

        switch failure {
        case .malformedJSON:
            logger.warning("MCP config malformed JSON: \(path, privacy: .public)")
        case .carrier(.notFound):
            // Expected when a watched file is atomically replaced between the
            // directory scan and descriptor open.
            break
        case .carrier(.inaccessible):
            logger.warning("MCP config inaccessible: \(path, privacy: .public)")
        case .carrier(.ioFailure):
            logger.warning("MCP config read failed: \(path, privacy: .public)")
        case .carrier(.invalidRequest):
            logger.error("MCP config path rejected as invalid: \(path, privacy: .public)")
        case .carrier(.unsafeCarrier):
            emitRejectedConfigEvent(
                tool: tool,
                path: path,
                detail: "unsafe non-regular, linked, or symlinked carrier"
            )
        case .carrier(.changedDuringRead):
            emitRejectedConfigEvent(
                tool: tool,
                path: path,
                detail: "carrier changed during the descriptor read"
            )
        case .carrier(.oversized(let actual, let maximum)):
            emitRejectedConfigEvent(
                tool: tool,
                path: path,
                detail: "oversized carrier (\(actual) bytes; maximum \(maximum))"
            )
        }
    }

    private func emitRejectedConfigEvent(tool: String, path: String, detail: String) {
        emitEvent(
            configFile: path,
            serverName: "(config)",
            command: "",
            args: [],
            eventType: .suspicious,
            reason: "MCP \(tool) configuration rejected: \(detail)",
            tool: tool
        )
    }

    /// Internal runtime seam used to verify rejection observability without
    /// depending on a real user's MCP configuration directory.
    func _testScanConfig(tool: String, path: String) {
        scanConfig(tool: tool, path: path)
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

        // 6. Tool-poisoning markers in a LOCAL server's own source (AI-05).
        scanServerSourceForToolPoisoning(server: server)
    }

    /// AI-05: the canonical MCP "tool poisoning" attack hides agent directives
    /// in a tool's `description` / `inputSchema`. Those travel in the JSON-RPC
    /// `tools/list` RESPONSE over the client's stdio pipe, which MacCrab never
    /// sees — so neither check 5 above nor
    /// `Rules/ai_safety/mcp_server_tool_poisoning.yml` (both argv-only) can
    /// detect the attack they are named for. For a server whose config points
    /// at a LOCAL script those descriptions are string literals in a file we
    /// CAN read, and that is the one place the attack is observable today.
    /// Remote and compiled servers, and rug pulls that change the manifest
    /// without changing the file, remain undetected — that needs a broker-
    /// mediated `tools/list` baseline, which does not exist yet.
    ///
    /// Deliberately conservative, because this runs as root against
    /// user-writable paths on a 60 s poll:
    ///   * four zero-FP markers only (see `toolPoisoningStrongMarkers`);
    ///   * text extensions only, so we never scan our own MCP binary;
    ///   * one descriptor-relative `BoundedRegularFileReader` snapshot, so a
    ///     symlink / FIFO / device or parent/leaf replacement cannot redirect,
    ///     block, or separate the fingerprint metadata from the scanned bytes;
    ///   * a descriptor identity + ctime fingerprint so same-size replacement
    ///     with a restored mtime cannot inherit an earlier clean decision.
    private func scanServerSourceForToolPoisoning(server: MCPServerEntry) {
        for path in ([server.command] + server.args) where path.hasPrefix("/") {
            let ext = (path as NSString).pathExtension.lowercased()
            guard Self.scannableServerSourceExtensions.contains(ext),
                  case .success(let snapshot) = BoundedRegularFileReader.readOutcome(
                      at: path,
                      maximumBytes: Self.maxServerSourceScanBytes
                  ), !snapshot.data.isEmpty else { continue }

            let fingerprint = [
                path,
                String(snapshot.deviceID),
                String(snapshot.inodeNumber),
                String(snapshot.statusChangeSeconds),
                String(snapshot.statusChangeNanoseconds),
                String(snapshot.sizeBytes),
            ].joined(separator: "|")
            guard !scannedServerSources.contains(fingerprint) else { continue }
            if scannedServerSources.count >= 512 {
                scannedServerSources.removeAll(keepingCapacity: true)
            }
            scannedServerSources.insert(fingerprint)

            let text = String(decoding: snapshot.data, as: UTF8.self)

            let reason: String?
            if let marker = Self.toolPoisoningStrongMarkers.first(where: {
                text.range(of: $0, options: .caseInsensitive) != nil
            }) {
                reason = "MCP server '\(server.name)' source \(path) contains tool-poisoning instruction text: '\(marker)'"
            } else if text.unicodeScalars.contains(where: { $0.value >= 0xE0000 && $0.value <= 0xE007F }) {
                reason = "MCP server '\(server.name)' source \(path) contains invisible Unicode TAG characters (U+E0000-U+E007F), the standard carrier for instructions hidden inside a tool description"
            } else {
                reason = nil
            }

            if let reason {
                emitEvent(
                    configFile: server.configFile,
                    serverName: server.name,
                    command: server.command,
                    args: server.args,
                    eventType: .suspicious,
                    reason: reason,
                    tool: server.tool
                )
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

    /// Expand a `~/…` config path to a CONCRETE path per real user home.
    ///
    /// FF-10: this used to return a single `NSHomeDirectory() + …` path.
    /// MCPMonitor is instantiated by DaemonSetup inside the ROOT System
    /// Extension, where `NSHomeDirectory()` is `/var/root` — a home that holds
    /// none of these files. So EVERY entry in `configPaths` missed, no watcher
    /// was ever installed, and `scanAllConfigs` found nothing: MCP tool-poisoning
    /// detection had zero input on a release install. That is also why the
    /// `projects[*].mcpServers` walk in `parseConfig` could not help — the file
    /// it needs was never opened. (The `maccrabctl mcp` subcommand runs as the
    /// user, which is why the CLI listed servers the daemon could not see.)
    ///
    /// Use the shared uid/passwd/no-symlink home contract. A privileged caller
    /// must not trust a bare `/Users/*` directory walk or append `/var/root`.
    private nonisolated static func expandTildeForAllHomes(_ path: String) -> [String] {
        guard path.hasPrefix("~/") else { return [path] }
        let suffix = String(path.dropFirst(1))   // keeps the leading "/"
        return RealUserHomeResolver.all().map { $0.path + suffix }
    }

    /// `configPaths` expanded across every real user home — the concrete list
    /// both the watcher installer and the scanner iterate.
    private nonisolated static func resolvedConfigPaths() -> [(tool: String, path: String)] {
        configPaths.flatMap { entry in
            expandTildeForAllHomes(entry.path).map { (tool: entry.tool, path: $0) }
        }
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
