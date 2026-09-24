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

    // MARK: - Engine access and ownership (v1.22.2)

    private func row(_ service: String, _ client: String, granted: Bool) -> V2MockPermission {
        V2MockPermission(
            id: "\(service)|\(client)", service: V2LiveDataProvider.prettyTCCService(service),
            granted: granted,
            required: V2LiveDataProvider.isRequiredMacCrabPermission(service: service, client: client),
            description: client, owner: V2LiveDataProvider.permissionOwner(client: client),
            serviceKey: service)
    }

    @Test("TCC rows are attributed to the engine, the app, or another app")
    func ownerAttribution() {
        #expect(V2LiveDataProvider.permissionOwner(client: "com.maccrab.agent") == .engine)
        #expect(V2LiveDataProvider.permissionOwner(client: "com.maccrab.agent.systemextension") == .engine)
        #expect(V2LiveDataProvider.permissionOwner(client: "com.maccrab.app") == .app)
        #expect(V2LiveDataProvider.permissionOwner(client: "com.apple.Safari") == .other)
        #expect(V2LiveDataProvider.permissionOwner(client: "com.maccrab.agent.helper") == .other)
    }

    @Test("a stale denied engine FDA row is satisfied by the engine's verified live access")
    func engineProbeSatisfiesDeniedRow() {
        // The field shape: the ES extension's grant sits in
        // EndpointSecurityClient while an old SystemPolicyAllFiles row is denied.
        let rows = [
            row("kTCCServiceSystemPolicyAllFiles", "com.maccrab.agent", granted: false),
            row("kTCCServiceEndpointSecurityClient", "com.maccrab.agent", granted: true),
            row("kTCCServiceSystemPolicyAllFiles", "com.maccrab.app", granted: false),
            row("kTCCServiceSystemPolicyAllFiles", "com.apple.Terminal", granted: false),
        ]
        let verified = V2LiveDataProvider.resolvingEngineAccess(rows, engineAccessVerified: true)
        #expect(verified[0].granted)
        #expect(verified[0].required)
        // Only the engine's rows change: the app and other apps keep their TCC state.
        #expect(!verified[2].granted)
        #expect(!verified[3].granted)
        #expect(verified.filter { $0.owner != .other && $0.required && !$0.granted }.map(\.id)
                == ["kTCCServiceSystemPolicyAllFiles|com.maccrab.app"])

        let unverified = V2LiveDataProvider.resolvingEngineAccess(rows, engineAccessVerified: false)
        #expect(unverified == rows)
    }

    @Test("internal TCC service keys get readable labels")
    func readableServiceLabels() {
        #expect(V2LiveDataProvider.prettyTCCService("kTCCServiceLiverpool") == "iCloud (CloudKit)")
        #expect(V2LiveDataProvider.prettyTCCService("kTCCServiceUbiquity") == "iCloud Drive")
        #expect(V2LiveDataProvider.prettyTCCService("kTCCServiceSystemPolicyDocumentsFolder") == "Documents Folder")
        #expect(V2LiveDataProvider.prettyTCCService("kTCCServiceEndpointSecurityClient") == "Endpoint Security Client")
    }

    @Test("diagnostics export lists only MacCrab's own permission rows, with owner and raw service")
    func exportScopesPermissionsToMacCrab() throws {
        let rows = [
            row("kTCCServiceEndpointSecurityClient", "com.maccrab.agent", granted: true),
            row("kTCCServiceSystemPolicyAllFiles", "com.maccrab.app", granted: true),
            row("kTCCServiceLiverpool", "com.apple.Maps", granted: true),
            row("kTCCServiceLiverpool", "com.apple.Safari", granted: true),
        ]
        let export = try V2DiagnosticsExport.make(
            source: .init(directory: "/Library/Application Support/MacCrab"), mode: "Live",
            heartbeat: nil, failure: nil, permissions: rows, providerReadFailed: false)
        let object = try #require(JSONSerialization.jsonObject(with: export.data) as? [String: Any])
        let exported = try #require(object["permissions"] as? [[String: Any]])
        #expect(exported.count == 2)
        #expect(exported.map { $0["owner"] as? String } == ["engine", "app"])
        #expect(exported.map { $0["service"] as? String }
                == ["kTCCServiceEndpointSecurityClient", "kTCCServiceSystemPolicyAllFiles"])
        let text = String(decoding: export.data, as: UTF8.self)
        #expect(!text.contains("com.apple.Maps"))
        #expect(!text.contains("Liverpool"))
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
