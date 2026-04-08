// MCPCommand.swift
// maccrabctl
//
// Lists MCP (Model Context Protocol) server configurations across all AI
// coding tools installed on the system (Claude Code, Cursor, Continue.dev,
// VS Code, Windsurf).  Flags suspicious entries matching the same heuristics
// used by the daemon's MCPMonitor.

import Foundation
import MacCrabCore

extension MacCrabCtl {
    static func listMCPServers(suspiciousOnly: Bool) {
        let configPaths: [(tool: String, path: String)] = [
            ("claude",   ("~/.claude/claude_desktop_config.json" as NSString).expandingTildeInPath),
            ("claude",   ("~/.claude.json" as NSString).expandingTildeInPath),
            ("cursor",   ("~/.cursor/mcp.json" as NSString).expandingTildeInPath),
            ("continue", ("~/.continue/config.json" as NSString).expandingTildeInPath),
            ("vscode",   ("~/.vscode/mcp.json" as NSString).expandingTildeInPath),
            ("windsurf", ("~/.windsurf/mcp.json" as NSString).expandingTildeInPath),
        ]

        var totalServers = 0
        var suspiciousCount = 0

        print("MacCrab MCP Server Inventory")
        print("══════════════════════════════════════════")

        let fm = FileManager.default
        var foundAny = false

        for (tool, path) in configPaths {
            guard fm.fileExists(atPath: path) else { continue }
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let mcpServers = json["mcpServers"] as? [String: Any],
                  !mcpServers.isEmpty
            else { continue }

            let servers = mcpServers.compactMap { (name, value) -> MCPServerInfo? in
                guard let config = value as? [String: Any] else { return nil }
                let command = config["command"] as? String ?? ""
                let args: [String]
                if let a = config["args"] as? [String] { args = a }
                else if let a = config["args"] as? [Any] { args = a.map { "\($0)" } }
                else { args = [] }
                let (susp, reason) = checkSuspicious(name: name, command: command, args: args)
                return MCPServerInfo(
                    tool: tool, configFile: path, name: name,
                    command: command, args: args,
                    isSuspicious: susp, suspicionReason: reason
                )
            }
            .sorted { $0.name < $1.name }

            let visible = suspiciousOnly ? servers.filter { $0.isSuspicious } : servers
            guard !visible.isEmpty else { continue }

            foundAny = true
            print("\n\(tool.capitalized)  (\(path))")
            print(String(repeating: "─", count: 60))

            for server in visible {
                totalServers += 1
                let indicator = server.isSuspicious ? "⚠️ " : "   "
                print("\(indicator)\(server.name)")
                print("     cmd:  \(server.command)")
                if !server.args.isEmpty {
                    let argsPreview = server.args.prefix(4).joined(separator: " ")
                    print("     args: \(argsPreview)")
                }
                if let reason = server.suspicionReason {
                    suspiciousCount += 1
                    print("     ⚠️  \(reason)")
                }
            }
        }

        if !foundAny {
            print("\nNo MCP server configurations found.")
            print("Checked: Claude Code, Cursor, Continue.dev, VS Code, Windsurf")
            return
        }

        print("\n══════════════════════════════════════════")
        print("Total: \(totalServers) server(s)", terminator: "")
        if suspiciousCount > 0 {
            print("  |  ⚠️  \(suspiciousCount) suspicious", terminator: "")
        }
        print()

        if totalServers == 0 {
            print("No MCP servers configured.")
        }
    }

    // MARK: - Suspicious Pattern Detection

    private static let suspiciousPathComponents = [
        "/tmp/", "/private/tmp/", "/var/tmp/", "/Downloads/", "/Users/Shared/",
    ]

    private static let suspiciousNameKeywords = [
        "inject", "exfil", "steal", "hack", "exploit", "payload",
        "backdoor", "reverse", "shell", "keylog", "dump", "scrape",
    ]

    private static let knownGoodNpxPackages: Set<String> = [
        "@modelcontextprotocol/server-filesystem",
        "@modelcontextprotocol/server-github",
        "@modelcontextprotocol/server-gitlab",
        "@modelcontextprotocol/server-memory",
        "@modelcontextprotocol/server-postgres",
        "@modelcontextprotocol/server-puppeteer",
        "@modelcontextprotocol/server-sequential-thinking",
        "@modelcontextprotocol/server-slack",
        "@modelcontextprotocol/server-sqlite",
        "@modelcontextprotocol/server-brave-search",
        "@modelcontextprotocol/server-fetch",
        "mcp-server-fetch",
        "firecrawl-mcp",
    ]

    private static let promptInjectionPatterns = [
        "ignore all previous", "ignore your instructions", "you are now",
        "system prompt", "<tool_result>", "</tool_result>",
    ]

    private static func checkSuspicious(
        name: String, command: String, args: [String]
    ) -> (Bool, String?) {
        // Suspicious path
        for component in suspiciousPathComponents where command.contains(component) {
            return (true, "Command path in suspicious location: \(command)")
        }
        // Suspicious name keyword
        let lower = name.lowercased()
        for kw in suspiciousNameKeywords where lower.contains(kw) {
            return (true, "Server name contains suspicious keyword '\(kw)'")
        }
        // Base64-encoded argument
        for arg in args where arg.count >= 40 {
            let base64 = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "+/="))
            if arg.unicodeScalars.allSatisfy({ base64.contains($0) }) {
                return (true, "Argument looks like base64-encoded payload: \(arg.prefix(40))…")
            }
        }
        // npx unknown package
        if command.hasSuffix("/npx") || command == "npx" {
            if let pkg = args.first(where: { !$0.hasPrefix("-") }),
               !knownGoodNpxPackages.contains(pkg) {
                return (true, "Unknown npx package '\(pkg)' — verify before trusting")
            }
        }
        // Prompt injection in args
        let allArgs = args.joined(separator: " ").lowercased()
        for pattern in promptInjectionPatterns where allArgs.contains(pattern) {
            return (true, "Args contain prompt injection pattern: '\(pattern)'")
        }
        return (false, nil)
    }
}

private struct MCPServerInfo {
    let tool: String
    let configFile: String
    let name: String
    let command: String
    let args: [String]
    let isSuspicious: Bool
    let suspicionReason: String?
}
