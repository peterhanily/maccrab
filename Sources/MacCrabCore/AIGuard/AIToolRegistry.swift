// AIToolRegistry.swift
// MacCrabCore
//
// Registry of known AI coding tools. Identifies processes belonging to
// Claude Code, Codex, OpenClaw, Cursor, and other AI agents by matching
// executable paths and process ancestry against known patterns.

import Foundation

/// Types of AI coding tools that MacCrab monitors.
public enum AIToolType: String, Codable, Sendable, CaseIterable {
    case claudeCode = "claude_code"
    case codex = "codex"
    case openClaw = "openclaw"
    case cursor = "cursor"
    case aider = "aider"
    case copilot = "copilot"
    case continuedev = "continue"
    case windsurf = "windsurf"
    case kiro = "kiro"
    case unknown = "unknown_ai_tool"

    public var displayName: String {
        switch self {
        case .claudeCode: return "Claude Code"
        case .codex: return "Codex"
        case .openClaw: return "OpenClaw"
        case .cursor: return "Cursor"
        case .aider: return "Aider"
        case .copilot: return "GitHub Copilot"
        case .continuedev: return "Continue.dev"
        case .windsurf: return "Windsurf"
        case .kiro: return "Kiro IDE"
        case .unknown: return "Unknown AI Tool"
        }
    }
}

/// Per-tool ownership metadata: the config/state directories a tool legitimately
/// reads/writes, and the API endpoints it legitimately talks to. Used to tell a
/// tool touching ITS OWN store / backend (benign, down-weighted) apart from
/// cross-tool / shared-credential access or beaconing to an unknown host
/// (must-fire). Directory entries use a leading "~" expanded to the current
/// user's home at lookup time.
///
/// IMPORTANT (must-fire safety): `ownDirs` deliberately lists ONLY each tool's
/// own config/state directories. Shared or system credential locations
/// (~/.aws, ~/.ssh, ~/.npmrc, .env, ~/Library/Keychains/login.keychain-db,
/// browser login stores) are NEVER listed here, so an AI tool reading those
/// still fires. The Sigma cred-theft rules (NoiseFilter Gate-8) are unaffected
/// by this metadata regardless.
public struct AIToolMetadata: Sendable {
    public let ownDirs: [String]
    public let knownEndpoints: [String]
    public init(ownDirs: [String] = [], knownEndpoints: [String] = []) {
        self.ownDirs = ownDirs
        self.knownEndpoints = knownEndpoints
    }
}

/// Identifies AI coding tools from executable paths and process ancestry.
///
/// Uses pattern matching against known binary paths, directory structures,
/// and process names. Extensible via custom patterns in config.
public struct AIToolRegistry: Sendable {

    /// Patterns for identifying AI tools. Each tuple: (tool type, path substrings to match).
    private static let builtinPatterns: [(AIToolType, [String])] = [
        // Claude Code
        (.claudeCode, [
            "/.local/bin/claude",
            "/.local/share/claude/versions/",
            "/claude-code",
            "claude-desktop",
        ]),
        // Codex (OpenAI)
        (.codex, [
            "Codex.app/Contents/",
            "/codex app-server",
            "codex-cli",
        ]),
        // OpenClaw
        (.openClaw, [
            "openclaw-gateway",
            "/openclaw",
            "/.openclaw/",
        ]),
        // Cursor
        (.cursor, [
            "Cursor.app/Contents/",
            "cursor-helper",
            "/Cursor Helper",
        ]),
        // Aider
        (.aider, [
            "/aider",
            "aider-chat",
        ]),
        // GitHub Copilot (standalone CLI)
        (.copilot, [
            "github-copilot",
            "copilot-agent",
            "copilot-language-server",
        ]),
        // Continue.dev — VS Code / JetBrains plugin; config at
        // ~/.continue/. Wave 7A.5 added the explicit config-dir path
        // because the SANDWORM_MODE supply-chain payload targets
        // Continue's MCP config (~/.continue/config.json).
        (.continuedev, [
            "continue-binary",
            ".continue/",
            "/.continue/config.json",
        ]),
        // Windsurf (Codeium) — IDE app + Codeium support dir + plugin
        // MCP config path. Wave 7A.5 added ~/Library/Application
        // Support/Codeium/Windsurf/ and ~/.windsurf/mcp.json — both
        // surfaced as compromise targets by the same SANDWORM_MODE
        // payload that targets Continue.
        (.windsurf, [
            "Windsurf.app/Contents/",
            "windsurf-helper",
            "/Library/Application Support/Codeium/Windsurf/",
            "/.windsurf/",
            "/Codeium/Windsurf/",
        ]),
        // Kiro IDE (Amazon) — agent-based IDE. Wave 7A.5 added because
        // the node-ipc supply-chain compromise (2025) listed Kiro
        // settings dirs as a primary target. App lives at
        // /Applications/Kiro.app and the per-user state lives in
        // ~/Library/Application Support/Kiro/ + ~/.kiro/.
        (.kiro, [
            "Kiro.app/Contents/",
            "/Library/Application Support/Kiro/",
            "/.kiro/",
            "kiro-helper",
        ]),
    ]

    /// Per-tool own config/state dirs + known API endpoints (v1.19.0, D1 FP
    /// tuning). Each tool's OWN store only — shared/system credential locations
    /// are intentionally absent (see `AIToolMetadata`).
    private static let toolMetadata: [AIToolType: AIToolMetadata] = [
        .claudeCode: .init(
            ownDirs: ["~/.claude", "~/.config/claude", "~/.local/share/claude", "~/.local/state/claude"],
            knownEndpoints: ["api.anthropic.com", "anthropic.com", "claude.ai", "statsig.anthropic.com"]),
        .codex: .init(
            ownDirs: ["~/.codex", "~/.config/codex"],
            knownEndpoints: ["api.openai.com", "openai.com", "chatgpt.com"]),
        .openClaw: .init(
            ownDirs: ["~/.openclaw", "~/.config/openclaw"],
            knownEndpoints: []),
        .cursor: .init(
            ownDirs: ["~/.cursor", "~/Library/Application Support/Cursor", "~/.config/cursor"],
            knownEndpoints: ["api.cursor.com", "cursor.sh", "api2.cursor.sh"]),
        .aider: .init(
            ownDirs: ["~/.aider", "~/.config/aider"],
            knownEndpoints: ["aider.chat"]),
        .copilot: .init(
            ownDirs: ["~/.config/github-copilot", "~/.config/gh-copilot"],
            knownEndpoints: ["api.githubcopilot.com", "copilot.github.com", "copilot-proxy.githubusercontent.com"]),
        .continuedev: .init(
            ownDirs: ["~/.continue", "~/.config/continue"],
            knownEndpoints: ["continue.dev", "api.continue.dev"]),
        .windsurf: .init(
            ownDirs: ["~/.windsurf", "~/Library/Application Support/Codeium/Windsurf", "~/.codeium", "~/.config/codeium"],
            knownEndpoints: ["codeium.com", "api.codeium.com", "server.codeium.com"]),
        .kiro: .init(
            ownDirs: ["~/.kiro", "~/Library/Application Support/Kiro", "~/.config/kiro"],
            knownEndpoints: ["kiro.dev"]),
    ]

    /// Metadata (own dirs / endpoints) for a recognized tool, if modeled.
    public static func metadata(for tool: AIToolType) -> AIToolMetadata? {
        toolMetadata[tool]
    }

    /// True if `filePath` lies within `toolType`'s OWN config/state directory.
    /// Conservative by construction: only the tool's own dirs are matched, so
    /// shared/system credential reads (~/.aws, ~/.ssh, ~/.npmrc, login.keychain-db,
    /// browser stores) never count as "own store" and are not down-weighted here.
    public static func isOwnedByTool(filePath: String, toolType: AIToolType) -> Bool {
        guard let meta = toolMetadata[toolType], !meta.ownDirs.isEmpty else { return false }
        let home = NSHomeDirectory()
        let file = (filePath as NSString).standardizingPath
        for dir in meta.ownDirs {
            let expanded = dir.hasPrefix("~") ? home + String(dir.dropFirst()) : dir
            let normDir = (expanded as NSString).standardizingPath
            if file == normDir || file.hasPrefix(normDir + "/") {
                return true
            }
        }
        return false
    }

    /// True if `hostname` is one of `toolType`'s known API endpoints. Suffix
    /// match so subdomains (`foo.api.anthropic.com`) count, but lookalikes
    /// (`evilanthropic.com`) do not.
    public static func isKnownEndpoint(hostname: String, toolType: AIToolType) -> Bool {
        guard let meta = toolMetadata[toolType], !meta.knownEndpoints.isEmpty else { return false }
        let host = hostname.lowercased()
        return meta.knownEndpoints.contains { ep in
            host == ep || host.hasSuffix("." + ep)
        }
    }

    /// Custom patterns loaded from config (user-extensible).
    private let customPatterns: [(AIToolType, [String])]

    public init(customPatterns: [(AIToolType, [String])] = []) {
        self.customPatterns = customPatterns
    }

    /// Check if an executable path belongs to a known AI coding tool.
    public func isAITool(executablePath: String) -> AIToolType? {
        let path = executablePath.lowercased()

        // Check builtin patterns
        for (toolType, patterns) in Self.builtinPatterns {
            for pattern in patterns {
                if path.contains(pattern.lowercased()) {
                    return toolType
                }
            }
        }

        // Check custom patterns
        for (toolType, patterns) in customPatterns {
            for pattern in patterns {
                if path.contains(pattern.lowercased()) {
                    return toolType
                }
            }
        }

        return nil
    }

    /// Check if a process is a child of an AI tool by examining its ancestors.
    public func isAIChildProcess(ancestors: [ProcessAncestor]) -> (isChild: Bool, toolType: AIToolType?) {
        for ancestor in ancestors {
            if let toolType = isAITool(executablePath: ancestor.executable) {
                return (true, toolType)
            }
        }
        return (false, nil)
    }

    /// Check if a process name matches common AI tool process names.
    public func isAIToolByName(_ processName: String) -> AIToolType? {
        let name = processName.lowercased()
        let namePatterns: [(AIToolType, [String])] = [
            (.claudeCode, ["claude"]),
            (.codex, ["codex"]),
            (.openClaw, ["openclaw"]),
            (.cursor, ["cursor"]),
            (.aider, ["aider"]),
            (.continuedev, ["continue"]),
            (.windsurf, ["windsurf"]),
            (.kiro, ["kiro"]),
        ]
        for (tool, patterns) in namePatterns {
            for p in patterns where name == p || name.hasPrefix(p + " ") {
                return tool
            }
        }
        return nil
    }
}
