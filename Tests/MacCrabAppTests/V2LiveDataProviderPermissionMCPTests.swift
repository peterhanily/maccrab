// V2LiveDataProviderPermissionMCPTests.swift
// MacCrabAppTests
//
// Deep-audit reconciliation (2026-07-16):
//  - permissions() finding (768): "Blocking missing" showed a false red
//    "investigate" alarm because `required` was keyed on the TCC SERVICE
//    across ALL clients — any unrelated app with a denied FDA row inflated
//    the count. Fix scopes `required` to MacCrab's OWN identities.
//  - mcpServers() finding (710): "Host" was hardcoded "localhost" even for
//    remote (SSE / streamable-HTTP) servers that declare a `url`. Fix reads
//    the real host from the url field.

import Testing
import Foundation
@testable import MacCrabApp
@testable import MacCrabCore

@Suite("V2LiveDataProvider — permission scoping + MCP host")
struct V2LiveDataProviderPermissionMCPTests {

    // MARK: - isRequiredMacCrabPermission (finding 768)

    @Test("FDA + ES granted to a MacCrab identity are required")
    func requiredForMacCrabClients() {
        // Full Disk Access on the engine, the .systemextension variant, and the app.
        #expect(V2LiveDataProvider.isRequiredMacCrabPermission(
            service: "kTCCServiceSystemPolicyAllFiles", client: "com.maccrab.agent"))
        #expect(V2LiveDataProvider.isRequiredMacCrabPermission(
            service: "kTCCServiceSystemPolicyAllFiles", client: "com.maccrab.agent.systemextension"))
        #expect(V2LiveDataProvider.isRequiredMacCrabPermission(
            service: "kTCCServiceSystemPolicyAllFiles", client: "com.maccrab.app"))
        // Endpoint Security client (agent only).
        #expect(V2LiveDataProvider.isRequiredMacCrabPermission(
            service: "kTCCServiceEndpointSecurityClient", client: "com.maccrab.agent"))
    }

    @Test("a load-bearing service for a NON-MacCrab client is NOT required (the false-alarm case)")
    func notRequiredForOtherClients() {
        // Pre-fix, a denied FDA row for Terminal (or any app) counted toward
        // "Blocking missing" and lit a red "investigate" on a healthy Mac.
        #expect(!V2LiveDataProvider.isRequiredMacCrabPermission(
            service: "kTCCServiceSystemPolicyAllFiles", client: "com.apple.Terminal"))
        #expect(!V2LiveDataProvider.isRequiredMacCrabPermission(
            service: "kTCCServiceSystemPolicyAllFiles", client: "com.googlecode.iterm2"))
        #expect(!V2LiveDataProvider.isRequiredMacCrabPermission(
            service: "kTCCServiceEndpointSecurityClient", client: "com.crowdstrike.falcon"))
    }

    @Test("a non-load-bearing service is never required, even for a MacCrab client")
    func notRequiredForOtherServices() {
        #expect(!V2LiveDataProvider.isRequiredMacCrabPermission(
            service: "kTCCServiceMicrophone", client: "com.maccrab.agent"))
        #expect(!V2LiveDataProvider.isRequiredMacCrabPermission(
            service: "kTCCServiceScreenCapture", client: "com.maccrab.app"))
    }

    // MARK: - mcpHost (finding 710)

    @Test("stdio server (command/args, no url) resolves to localhost")
    func stdioHostIsLocalhost() {
        let spec: [String: Any] = ["command": "npx", "args": ["-y", "some-mcp-server"]]
        #expect(V2LiveDataProvider.mcpHost(for: spec) == "localhost")
    }

    @Test("remote server surfaces the real url host, not localhost")
    func remoteHostFromURL() {
        let spec: [String: Any] = ["url": "https://mcp.example.com/sse", "type": "sse"]
        #expect(V2LiveDataProvider.mcpHost(for: spec) == "mcp.example.com")
    }

    @Test("Continue's serverUrl spelling is also honored")
    func remoteHostFromServerURL() {
        let spec: [String: Any] = ["serverUrl": "https://api.acme.dev:8443/mcp"]
        #expect(V2LiveDataProvider.mcpHost(for: spec) == "api.acme.dev")
    }

    @Test("an empty url falls back to localhost")
    func emptyURLFallsBack() {
        let spec: [String: Any] = ["url": "", "command": "node"]
        #expect(V2LiveDataProvider.mcpHost(for: spec) == "localhost")
    }

    @Test("Only a current versioned MCP baseline snapshot counts as live profiling")
    func baselineSnapshotFreshness() {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let baseline = MCPServerBaseline(
            serverKey: "Claude Code::github",
            tool: "Claude Code",
            serverName: "github"
        )
        let fresh = MCPBaselineService.BaselineSnapshot(
            writtenAt: now.addingTimeInterval(-30),
            baselines: [baseline]
        )
        #expect(V2LiveDataProvider.liveMCPBaselineKeys(
            from: fresh, now: now
        ) == ["Claude Code::github"])

        let stale = MCPBaselineService.BaselineSnapshot(
            writtenAt: now.addingTimeInterval(-121),
            baselines: [baseline]
        )
        #expect(V2LiveDataProvider.liveMCPBaselineKeys(
            from: stale, now: now
        ).isEmpty)

        let legacy = MCPBaselineService.BaselineSnapshot(
            schemaVersion: 1,
            writtenAt: now,
            baselines: [baseline]
        )
        #expect(V2LiveDataProvider.liveMCPBaselineKeys(
            from: legacy, now: now
        ).isEmpty)

        let unknownFuture = MCPBaselineService.BaselineSnapshot(
            schemaVersion: MCPBaselineService.BaselineSnapshot.currentSchemaVersion + 1,
            writtenAt: now,
            baselines: [baseline]
        )
        #expect(V2LiveDataProvider.liveMCPBaselineKeys(
            from: unknownFuture, now: now
        ).isEmpty)

        let futureDated = MCPBaselineService.BaselineSnapshot(
            writtenAt: now.addingTimeInterval(6),
            baselines: [baseline]
        )
        #expect(V2LiveDataProvider.liveMCPBaselineKeys(
            from: futureDated, now: now
        ).isEmpty)
    }
}
