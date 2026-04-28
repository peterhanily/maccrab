// MCPAttributorTests.swift
//
// Tests for the v1.7.0 MCP attribution producer half. The attributor
// walks an event's process ancestry and matches each ancestor's
// commandline against the AI tool's configured MCP servers (parsed by
// `MCPMonitor` from the user's claude/cursor/etc. config files).

import Testing
import Foundation
@testable import MacCrabCore

@Suite("MCPAttributor: package-token match")
struct MCPAttributorPackageTokenTests {

    /// Build a fully-populated test stack: an MCPMonitor with a
    /// pre-seeded server config (we bypass the file-watcher path by
    /// using the public `serversForTool` accessor we just added — the
    /// test injects via reflection or via a prepared config file).
    /// For Phase 1 we simulate the parsed-config state by writing a
    /// real config file the monitor will pick up on `start()`.

    @Test("High-confidence match when ancestor cmdline contains @modelcontextprotocol/server-filesystem")
    func highConfidenceFilesystem() async throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-mcp-attributor-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        // Stage a fake claude config in a temp dir layout the monitor
        // reads from (~/.claude/claude_desktop_config.json). For unit
        // testing we drive the public API directly by constructing the
        // monitor and calling `serversForTool` after seeding via a
        // crafted config — since `parseConfig` is private, we exercise
        // the matcher by constructing `ConfiguredServer` values
        // directly instead and confirming MCPAttributor's match logic
        // against them.
        let configured = MCPMonitor.ConfiguredServer(
            name: "filesystem",
            command: "npx",
            args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
            tool: "claude"
        )

        // Construct an attributor whose mcpMonitor returns this single
        // server. We use the monitor with no started watch and inject
        // via the test-only `_seedKnownServers` if available — fall
        // back to verifying the score function via a mirror.
        let monitor = MCPMonitor()
        await monitor._testInjectServer(configured)
        let lineage = ProcessLineage()
        // Seed the lineage with two processes: a shell parent and a
        // child node process whose cmdline carries the package token.
        await lineage.recordProcess(
            pid: 1001, ppid: 0,
            path: "/bin/zsh", name: "zsh",
            startTime: Date(),
            commandLine: "/bin/zsh -l"
        )
        await lineage.recordProcess(
            pid: 1002, ppid: 1001,
            path: "/usr/local/bin/node", name: "node",
            startTime: Date(),
            commandLine: "node /usr/local/lib/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js /tmp"
        )

        let attributor = MCPAttributor(mcpMonitor: monitor, lineage: lineage)
        let ancestors = await lineage.ancestors(of: 1002)
        let attribution = await attributor.attribute(
            pid: 1002,
            ancestors: ancestors,
            aiTool: .claudeCode
        )
        #expect(attribution != nil)
        #expect(attribution?.serverName == "filesystem")
        #expect(attribution?.tool == "claude")
        #expect(attribution?.confidence == .high)
        #expect(attribution?.serverCategory == "filesystem")
    }

    @Test("Returns nil when no configured server matches")
    func noMatch() async throws {
        let monitor = MCPMonitor()
        let lineage = ProcessLineage()
        await lineage.recordProcess(
            pid: 2001, ppid: 0,
            path: "/usr/bin/git", name: "git",
            startTime: Date(),
            commandLine: "git status"
        )
        let attributor = MCPAttributor(mcpMonitor: monitor, lineage: lineage)
        let ancestors = await lineage.ancestors(of: 2001)
        let attribution = await attributor.attribute(
            pid: 2001,
            ancestors: ancestors,
            aiTool: .claudeCode
        )
        #expect(attribution == nil)
    }

    @Test("Negative results are cached (no rewalk)")
    func negativeCacheHit() async throws {
        let monitor = MCPMonitor()
        let lineage = ProcessLineage()
        await lineage.recordProcess(
            pid: 3001, ppid: 0,
            path: "/usr/bin/git", name: "git",
            startTime: Date(),
            commandLine: "git status"
        )
        let attributor = MCPAttributor(mcpMonitor: monitor, lineage: lineage)
        let ancestors = await lineage.ancestors(of: 3001)
        // First call: walks ancestry, decides nil.
        let first = await attributor.attribute(pid: 3001, ancestors: ancestors, aiTool: .claudeCode)
        #expect(first == nil)
        // Second call should hit the negative cache (same pid).
        // We can't directly verify the cache hit without instrumentation
        // but the call should still return nil and not blow up.
        let second = await attributor.attribute(pid: 3001, ancestors: ancestors, aiTool: .claudeCode)
        #expect(second == nil)
    }

    @Test("Aider aider_mcp_* package token attributes correctly (v1.7.2)")
    func aiderShapeAttribution() async throws {
        let aider = MCPMonitor.ConfiguredServer(
            name: "filesystem",
            command: "python3",
            args: ["-m", "aider_mcp_filesystem", "/tmp"],
            tool: "claude"
        )
        let monitor = MCPMonitor()
        await monitor._testInjectServer(aider)
        let lineage = ProcessLineage()
        await lineage.recordProcess(
            pid: 5001, ppid: 0,
            path: "/usr/bin/python3", name: "python3",
            startTime: Date(),
            commandLine: "python3 -m aider_mcp_filesystem /tmp"
        )
        let attributor = MCPAttributor(mcpMonitor: monitor, lineage: lineage)
        let ancestors = await lineage.ancestors(of: 5001)
        let attribution = await attributor.attribute(
            pid: 5001, ancestors: ancestors, aiTool: .claudeCode
        )
        #expect(attribution != nil)
        #expect(attribution?.confidence == .high)
        #expect(attribution?.serverCategory == "filesystem")
    }

    @Test("Codex @openai/codex-cli package token attributes correctly (v1.7.2)")
    func codexShapeAttribution() async throws {
        let codex = MCPMonitor.ConfiguredServer(
            name: "github",
            command: "npx",
            args: ["-y", "openai-codex-mcp-github"],
            tool: "claude"
        )
        let monitor = MCPMonitor()
        await monitor._testInjectServer(codex)
        let lineage = ProcessLineage()
        await lineage.recordProcess(
            pid: 5101, ppid: 0,
            path: "/usr/local/bin/node", name: "node",
            startTime: Date(),
            commandLine: "node /opt/openai-codex-mcp-github/dist/index.js"
        )
        let attributor = MCPAttributor(mcpMonitor: monitor, lineage: lineage)
        let ancestors = await lineage.ancestors(of: 5101)
        let attribution = await attributor.attribute(
            pid: 5101, ancestors: ancestors, aiTool: .claudeCode
        )
        #expect(attribution != nil)
        #expect(attribution?.confidence == .high)
        #expect(attribution?.serverCategory == "github")
    }

    @Test("Server category derived from package token")
    func categoryFromPackageToken() async throws {
        let github = MCPMonitor.ConfiguredServer(
            name: "github",
            command: "npx",
            args: ["-y", "@modelcontextprotocol/server-github"],
            tool: "claude"
        )
        let fetch = MCPMonitor.ConfiguredServer(
            name: "myfetch",
            command: "npx",
            args: ["-y", "mcp-server-fetch"],
            tool: "claude"
        )
        let monitor = MCPMonitor()
        await monitor._testInjectServer(github)
        await monitor._testInjectServer(fetch)
        let lineage = ProcessLineage()
        await lineage.recordProcess(
            pid: 4001, ppid: 0,
            path: "/usr/local/bin/node", name: "node",
            startTime: Date(),
            commandLine: "node /opt/@modelcontextprotocol/server-github/dist/index.js"
        )
        await lineage.recordProcess(
            pid: 4002, ppid: 0,
            path: "/usr/bin/python3", name: "python3",
            startTime: Date(),
            commandLine: "python3 -m mcp-server-fetch"
        )

        let attributor = MCPAttributor(mcpMonitor: monitor, lineage: lineage)
        let ancestorsA = await lineage.ancestors(of: 4001)
        let ancestorsB = await lineage.ancestors(of: 4002)
        let attrA = await attributor.attribute(pid: 4001, ancestors: ancestorsA, aiTool: .claudeCode)
        let attrB = await attributor.attribute(pid: 4002, ancestors: ancestorsB, aiTool: .claudeCode)
        #expect(attrA?.serverCategory == "github")
        #expect(attrB?.serverCategory == "fetch")
    }
}

@Suite("MCPBaselineService: snapshot round-trip (v1.7.0)")
struct MCPBaselineSnapshotTests {

    @Test("writeSnapshot then readSnapshot returns equivalent baselines")
    func roundTrip() async throws {
        let svc = MCPBaselineService(learningObservations: 1, learningWindow: 0.0)
        _ = await svc.observe(.init(tool: "claude", serverName: "fs", filePath: "/tmp/a"))
        _ = await svc.observe(.init(tool: "claude", serverName: "fs", filePath: "/tmp/b"))
        _ = await svc.observe(.init(tool: "claude", serverName: "fs", domain: "api.github.com"))

        let path = NSTemporaryDirectory() + "maccrab-mcp-snapshot-\(UUID().uuidString).json"
        defer { try? FileManager.default.removeItem(atPath: path) }
        await svc.writeSnapshot(to: path)

        let snapshot = MCPBaselineService.readSnapshot(at: path)
        #expect(snapshot != nil)
        #expect(snapshot?.baselines.count == 1)
        let b = snapshot!.baselines[0]
        #expect(b.serverName == "fs")
        #expect(b.tool == "claude")
        #expect(b.fileBasenames.contains("a"))
        #expect(b.fileBasenames.contains("b"))
        // MCPBaselineService normalizes domains to their registrable form
        // (api.github.com → github.com). Match the normalized form.
        #expect(b.domains.contains("github.com"))
    }

    @Test("Empty service writes a snapshot with zero baselines")
    func emptyRoundTrip() async throws {
        let svc = MCPBaselineService()
        let path = NSTemporaryDirectory() + "maccrab-mcp-snapshot-empty-\(UUID().uuidString).json"
        defer { try? FileManager.default.removeItem(atPath: path) }
        await svc.writeSnapshot(to: path)
        let snapshot = MCPBaselineService.readSnapshot(at: path)
        #expect(snapshot?.baselines.isEmpty == true)
    }
}
