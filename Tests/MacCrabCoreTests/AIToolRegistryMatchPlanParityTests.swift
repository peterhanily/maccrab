import Foundation
import Testing
@testable import MacCrabCore

/// The precomputed registry must resolve every path exactly as the former
/// per-call matcher did. The reference below is that matcher, kept verbatim
/// (including Foundation `contains`) as an independent oracle.
@Suite("AI tool registry precomputed match parity")
struct AIToolRegistryMatchPlanParityTests {
    private static let referenceExecutableNames: [(AIToolType, [String])] = [
        (.codex, ["codex", "codex-cli"]),
    ]
    private static let referencePatterns: [(AIToolType, [String])] = [
        (.claudeCode, ["/.local/bin/claude", "/.local/share/claude/versions/", "/claude-code", "claude-desktop"]),
        (.codex, ["Codex.app/Contents/"]),
        (.openClaw, ["openclaw-gateway", "/openclaw", "/.openclaw/"]),
        (.cursor, ["Cursor.app/Contents/", "cursor-helper", "/Cursor Helper"]),
        (.aider, ["/aider", "aider-chat"]),
        (.copilot, ["github-copilot", "copilot-agent", "copilot-language-server"]),
        (.continuedev, ["continue-binary", ".continue/", "/.continue/config.json"]),
        (.windsurf, ["Windsurf.app/Contents/", "windsurf-helper",
                     "/Library/Application Support/Codeium/Windsurf/", "/.windsurf/", "/Codeium/Windsurf/"]),
        (.kiro, ["Kiro.app/Contents/", "/Library/Application Support/Kiro/", "/.kiro/", "kiro-helper"]),
    ]

    private static func referenceMatches(path: String, basename: String, pattern: String) -> Bool {
        if pattern.hasPrefix("/"), !pattern.dropFirst().contains("/") {
            let name = String(pattern.dropFirst())
            return basename == name || path.contains("/\(name)/")
        }
        return path.contains(pattern)
    }

    private static func reference(
        _ executablePath: String,
        custom: [(AIToolType, [String])]
    ) -> AIToolType? {
        let path = executablePath.lowercased()
        let basename = (path as NSString).lastPathComponent
        for (toolType, names) in referenceExecutableNames where names.contains(basename) {
            return toolType
        }
        for (toolType, patterns) in referencePatterns + custom {
            for pattern in patterns
            where referenceMatches(path: path, basename: basename, pattern: pattern.lowercased()) {
                return toolType
            }
        }
        return nil
    }

    private static let corpus: [String] = [
        "/Users/dev/.local/bin/claude", "/Users/dev/.local/share/claude/versions/2.1.0/claude",
        "/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/cli.js",
        "/Applications/Claude.app/Contents/MacOS/claude-desktop",
        "/Applications/Codex.app/Contents/Resources/codex", "/Users/dev/.codex/packages/standalone/x/bin/codex",
        "/usr/local/bin/codex-cli", "/Users/dev/projects/codex/build-helper",
        "/usr/local/bin/openclaw", "/opt/openclaw-sandbox/node", "/Users/dev/.openclaw/bin/run",
        "/Applications/Cursor.app/Contents/Frameworks/Cursor Helper (Plugin).app/Contents/MacOS/Cursor Helper (Plugin)",
        "/usr/local/bin/aider", "/Users/x/projects/aider-clone/bin/python", "/opt/homebrew/Cellar/aider/0.1/bin/python",
        "/usr/local/lib/node_modules/github-copilot/bin/copilot-language-server",
        "/Users/dev/.continue/config.json", "/Applications/Windsurf.app/Contents/MacOS/Windsurf",
        "/Users/dev/Library/Application Support/Codeium/Windsurf/bin/x", "/Applications/Kiro.app/Contents/MacOS/Kiro",
        "/bin/zsh", "/usr/bin/git", "/System/Library/Frameworks/x.framework/x", "", "/", "claude", "/AIDER",
        "/Users/dev/CLAUDE-CODE/bin", "/Users/d\u{e9}v/.local/bin/claude", "/Users/de\u{301}v/aider/x",
        "/tmp/a\r\n/aider/b", "/tmp/kiro-helper\u{301}", "/usr/local/bin/aider/", "//aider//",
    ]

    @Test("builtin plans resolve every corpus path exactly like the per-call matcher")
    func builtinParity() {
        let registry = AIToolRegistry()
        for path in Self.corpus {
            #expect(registry.isAITool(executablePath: path) == Self.reference(path, custom: []),
                    "\(path.debugDescription)")
        }
    }

    @Test("custom patterns keep their order and AI-12 component semantics")
    func customParity() {
        let custom: [(AIToolType, [String])] = [
            (.unknown, ["/MyAgent", "agent-runner/", "/Weird\u{301}", "/a/b", "X"]),
            (.cursor, ["/myagent"]),
        ]
        let registry = AIToolRegistry(customPatterns: custom)
        let paths = Self.corpus + [
            "/usr/local/bin/myagent", "/opt/myagent/bin/x", "/opt/myagent-old/bin/x", "/srv/agent-runner/run",
            "/tmp/weird\u{301}", "/tmp/weird\u{301}/x", "/a/b/c", "/tmp/x", "/MYAGENT",
        ]
        for path in paths {
            #expect(registry.isAITool(executablePath: path) == Self.reference(path, custom: custom),
                    "\(path.debugDescription)")
        }
    }
}
