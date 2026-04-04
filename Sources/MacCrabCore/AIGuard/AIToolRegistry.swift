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
        case .unknown: return "Unknown AI Tool"
        }
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
        // Continue.dev
        (.continuedev, [
            "continue-binary",
            ".continue/",
        ]),
        // Windsurf
        (.windsurf, [
            "Windsurf.app/Contents/",
            "windsurf-helper",
        ]),
    ]

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
        ]
        for (tool, patterns) in namePatterns {
            for p in patterns where name == p || name.hasPrefix(p + " ") {
                return tool
            }
        }
        return nil
    }
}
