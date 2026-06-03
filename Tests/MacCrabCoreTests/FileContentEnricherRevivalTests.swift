// FileContentEnricherRevivalTests.swift
// v1.17.4 — locks BOTH halves of the FileContent desync that left all 14
// `FileContent|contains` rules dead: (1) EventEnricher gated on bare
// "close" while collectors emit "close_modified"; (2) shouldScan returned
// false for the agent skill/config/hook/CI roots those rules target.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("FileContentEnricher: revival (v1.17.4)")
struct FileContentEnricherRevivalTests {

    @Test("shouldScan allows the AI-agent skill/config/hook/CI roots the dead rules target")
    func allowsAgentRoots() {
        let yes = [
            "/Users/x/.claude/skills/foo/SKILL.md",
            "/Users/x/.codex/skills/bar/SKILL.md",
            "/Users/x/.cursor/skills/baz/SKILL.md",
            "/Users/x/.claude/scripts/run.sh",
            "/Users/x/.claude/hooks/pre.sh",
            "/Users/x/.claude/agents/agent.md",
            "/repo/.github/workflows/ci.yml",
            "/Users/x/.claude/claude_desktop_config.json",
            "/Users/x/.claude.json",
            "/Users/x/.cursor/mcp.json",
            "/Users/x/.claude/settings.json",
            "/Users/x/.claude/project.json",
            "/Users/x/.claude/local.json",
        ]
        for p in yes { #expect(FileContentEnricher.shouldScan(targetPath: p), "expected scan: \(p)") }
    }

    @Test("shouldScan keeps the pre-existing roots and rejects unrelated paths")
    func existingAndNegative() {
        #expect(FileContentEnricher.shouldScan(targetPath: "/Applications/Foo.app/Contents/Info.plist"))
        #expect(FileContentEnricher.shouldScan(targetPath: "/Users/x/node_modules/evil/index.js"))
        #expect(!FileContentEnricher.shouldScan(targetPath: "/Users/x/Documents/notes.txt"))
        #expect(!FileContentEnricher.shouldScan(targetPath: "/tmp/random.bin"))
        // contains "/.claude/" but is NOT one of the allowlisted subpaths —
        // proves we did not blanket-allow the high-volume .claude tree.
        #expect(!FileContentEnricher.shouldScan(targetPath: "/Users/x/.claude/todos/foo.json"))
    }

    @Test("close-class file event is content-enriched; a non-close action is not (gate fix)")
    func closeGateEnriches() async throws {
        let base = FileManager.default.temporaryDirectory.appendingPathComponent("fce-\(UUID().uuidString)")
        let wfDir = base.appendingPathComponent(".github/workflows", isDirectory: true)
        try FileManager.default.createDirectory(at: wfDir, withIntermediateDirectories: true)
        let wf = wfDir.appendingPathComponent("ci.yml")
        try "runs-on: self-hosted\nuses: shai-hulud\n".write(to: wf, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: base) }

        let enricher = EventEnricher(fileContentEnricher: FileContentEnricher())
        func fileEvent(action: String) -> Event {
            let proc = MacCrabCore.ProcessInfo(
                pid: 4242, ppid: 1, rpid: 4242, name: "curl", executable: "/usr/bin/curl",
                commandLine: "curl", args: [], workingDirectory: "/",
                userId: 501, userName: "t", groupId: 20, startTime: Date(), codeSignature: nil)
            return Event(eventCategory: .file, eventType: .creation, eventAction: action,
                         process: proc, file: FileInfo(path: wf.path, action: .create))
        }

        let enrichedClose = await enricher.enrich(fileEvent(action: "close_modified"))
        #expect(enrichedClose.enrichments["FileContent"] != nil)

        let enrichedOpen = await enricher.enrich(fileEvent(action: "open"))
        #expect(enrichedOpen.enrichments["FileContent"] == nil)
    }
}
