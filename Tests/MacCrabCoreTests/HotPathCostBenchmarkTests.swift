import CryptoKit
import Foundation
import Testing
@testable import MacCrabCore

/// Report-only CPU cost of the per-event hot paths the RC12 engine profile
/// attributed most time to, over inert developer-workstation file events
/// from an AI agent's descendants. Uses only long-standing APIs so the same
/// file measures earlier sources for an old-versus-new comparison. Verdicts
/// are digested so a faster path that changed an answer is visible.
@Suite("Per-event hot path cost", .serialized)
struct HotPathCostBenchmarkTests {
    private struct Shape {
        let name: String
        let executable: String
        let commandLine: String
    }

    private static let shapes: [Shape] = [
        Shape(name: "node", executable: "/opt/homebrew/Cellar/node/22.3.0/bin/node",
              commandLine: "node /Users/dev/Documents/claude_code/webapp/node_modules/.bin/vite build --mode production --outDir dist"),
        Shape(name: "git", executable: "/Applications/Xcode.app/Contents/Developer/usr/bin/git",
              commandLine: "git -C /Users/dev/Documents/claude_code/webapp status --porcelain=v2 --branch"),
        Shape(name: "swift-frontend", executable: "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/swift-frontend",
              commandLine: "swift-frontend -frontend -c -primary-file Sources/App/Model.swift -emit-module-path .build/debug/App.build/Model.swiftmodule -target arm64-apple-macosx13.0"),
        Shape(name: "python3", executable: "/Users/dev/.pyenv/versions/3.12.2/bin/python3.12",
              commandLine: "python3 -m pytest tests/unit -q --maxfail=1 -p no:cacheprovider"),
        Shape(name: "zsh", executable: "/bin/zsh", commandLine: "/bin/zsh -c -l source ~/.zshrc && npm run lint"),
    ]

    private static let paths: [String] = [
        "/Users/dev/Documents/claude_code/webapp/src/components/Button.tsx",
        "/Users/dev/Documents/claude_code/webapp/node_modules/react-dom/cjs/react-dom.development.js",
        "/Users/dev/Documents/claude_code/webapp/.git/objects/4f/1c2e9a7b3d5f6e8a0b1c2d3e4f5a6b7c8d9e0f",
        "/Users/dev/Documents/claude_code/webapp/dist/assets/index-8f3a2b1c.js",
        "/private/var/folders/xy/abcdef123456/T/vite-tmp-91827/chunk-22.mjs",
        "/Users/dev/Library/Caches/pip/http-v2/a/b/c/d/e/0123456789abcdef.body",
        "/Users/dev/Documents/claude_code/webapp/README.md",
        "/Users/dev/Documents/claude_code/webapp/package-lock.json",
        "/Users/dev/.npm/_cacache/index-v5/3a/7f/0e5d9c1b2a3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d",
        "/opt/homebrew/lib/node_modules/npm/lib/commands/run-script.js",
        "/Users/dev/Documents/claude_code/service/Sources/Service/Handlers/Session.swift",
        "/Users/dev/Documents/claude_code/service/.build/arm64-apple-macosx/debug/Service.build/Session.swift.o",
    ]

    private static let actions: [(String, FileAction, EventType)] = [
        ("open", .open, .info), ("write", .write, .change), ("close_modified", .close, .change),
        ("create", .create, .creation), ("rename", .rename, .change), ("unlink", .delete, .deletion),
    ]

    private static let ancestors: [ProcessAncestor] = [
        ProcessAncestor(pid: 4_100, executable: "/bin/zsh", name: "zsh"),
        ProcessAncestor(pid: 4_000, executable: "/Users/dev/.local/share/claude/versions/2.1.0/claude", name: "claude"),
        ProcessAncestor(pid: 3_900, executable: "/Applications/Ghostty.app/Contents/MacOS/ghostty", name: "ghostty"),
        ProcessAncestor(pid: 1, executable: "/sbin/launchd", name: "launchd"),
    ]

    private static func events(count: Int) -> [Event] {
        // Fixed identities and times keep the verdict digest reproducible.
        let now = Date(timeIntervalSince1970: 1_792_400_000)
        return (0..<count).map { index in
            let shape = shapes[index % shapes.count]
            let path = paths[(index / shapes.count) % paths.count]
            let action = actions[index % actions.count]
            let process = MacCrabCore.ProcessInfo(
                pid: Int32(5_000 + index % 40), ppid: 4_100, rpid: 4_100, name: shape.name,
                executable: shape.executable, commandLine: shape.commandLine,
                args: shape.commandLine.split(separator: " ").map(String.init),
                workingDirectory: "/Users/dev/Documents/claude_code/webapp", userId: 501, userName: "dev",
                groupId: 20, startTime: now.addingTimeInterval(-30), ancestors: ancestors,
                isPlatformBinary: false
            )
            return Event(
                id: UUID(uuidString: String(format: "00000000-0000-4000-a000-%012x", index + 1))!,
                timestamp: now.addingTimeInterval(Double(index) / 1_000), eventCategory: .file,
                eventType: action.2, eventAction: action.0, process: process,
                file: FileInfo(path: path, action: action.1),
                enrichments: ["ai_tool": "claude_code", "ai_tool_child": "true", "ai_root_pid": "4000",
                              "ai_project_dir": "/Users/dev/Documents/claude_code/webapp"]
            )
        }
    }

    private static func nanos(_ duration: Duration) -> Double {
        Double(duration.components.seconds) * 1e9 + Double(duration.components.attoseconds) / 1e9
    }

    @Test("per-event cost of the profiled hot paths, with a verdict digest")
    func hotPathCost() async throws {
        let root = try ensureRulesCompiled()
        let rules = RuleEngine()
        let sequences = SequenceEngine(lineage: ProcessLineage())
        _ = try await rules.loadRules(from: root, enabledStatuses: ["stable"])
        _ = try await sequences.loadRules(from: root.appendingPathComponent("sequences"), enabledStatuses: ["stable"])
        let registry = AIToolRegistry()
        let fence = CredentialFence()
        let corpus = Self.events(count: 2_400)
        let clock = ContinuousClock()
        var cost: [String: Double] = [:]
        var digest = SHA256()
        func record(_ name: String, _ verdicts: String) { digest.update(data: Data((name + ":" + verdicts + "\n").utf8)) }

        for pass in 0..<2 {  // pass 0 warms caches and code; pass 1 is reported
            var local: [String: Double] = [:]
            var start = clock.now
            var answers: [String] = []
            for event in corpus {
                answers.append(String(describing: registry.isAITool(executablePath: event.process.executable)))
                for ancestor in event.process.ancestors {
                    answers.append(String(describing: registry.isAITool(executablePath: ancestor.executable)))
                }
            }
            local["ai_tool_registry"] = Self.nanos(start.duration(to: clock.now)); if pass == 1 { record("ai", answers.joined(separator: ",")) }

            start = clock.now; answers = []
            for event in corpus {
                let path = event.file!.path
                answers.append(String(describing: fence.checkAccessDetailed(filePath: path, aiToolName: "Claude Code",
                                                                          aiToolType: .claudeCode,
                                                                          accessingBinary: event.process.name)?.type))
                answers.append(String(describing: AgentLineageService.materializedFileEventKind(path: path, eventAction: event.eventAction)))
            }
            local["credential_and_lineage"] = Self.nanos(start.duration(to: clock.now)); if pass == 1 { record("cred", answers.joined(separator: ",")) }

            start = clock.now; answers = []
            for event in corpus {
                let path = event.file!.path
                answers.append("\(ESCollector.isCredentialReadPath(path))\(ESCollector.isAgentContentReadPath(path))")
                answers.append("\(CrossProcessCorrelator.shouldIgnoreFilePath(path))")
                answers.append("\(CampaignDetector.isDevelopmentToolingPath(event.process.executable))")
                for ancestor in event.process.ancestors {
                    answers.append(String(describing: SessionEnricher.classifyAncestor(name: ancestor.name, executable: ancestor.executable)))
                }
            }
            local["path_policies"] = Self.nanos(start.duration(to: clock.now)); if pass == 1 { record("paths", answers.joined(separator: ",")) }

            start = clock.now; answers = []
            for event in corpus {
                let prepared = try EventJournalAdmissionValidator.prepare(event)
                answers.append(String(prepared.canonicalJSON.count))
            }
            local["journal_prepare"] = Self.nanos(start.duration(to: clock.now)); if pass == 1 { record("journal", answers.joined(separator: ",")) }

            start = clock.now; answers = []
            for event in corpus {
                answers.append((await rules.evaluate(event)).map(\.ruleId).sorted().joined(separator: "+"))
            }
            local["rules"] = Self.nanos(start.duration(to: clock.now)); if pass == 1 { record("rules", answers.joined(separator: ",")) }

            start = clock.now; answers = []
            for event in corpus {
                answers.append((await sequences.evaluate(event)).map(\.ruleId).sorted().joined(separator: "+"))
            }
            local["sequences"] = Self.nanos(start.duration(to: clock.now)); if pass == 1 { record("sequences", answers.joined(separator: ",")) }
            if pass == 1 { cost = local }
        }
        var report: [String: Any] = ["schema": "hot-path-cost-v1", "events": corpus.count]
        var total = 0.0
        for (name, ns) in cost {
            report[name + "_ns_per_event"] = (ns / Double(corpus.count)).rounded()
            total += ns
        }
        report["total_ns_per_event"] = (total / Double(corpus.count)).rounded()
        report["verdict_digest"] = digest.finalize().map { String(format: "%02x", $0) }.joined()
        let data = try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys])
        print("BENCH_HOT_PATH " + String(decoding: data, as: UTF8.self))
        #expect(total > 0)
    }
}
