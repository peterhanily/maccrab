import Darwin
import Foundation
import Testing
@testable import MacCrabApp

@Suite("Dashboard MCP capability authority")
struct AgentCapabilityDashboardTests {
    private func temporaryDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-dashboard-capability-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        return directory
    }

    @Test("OFF to ON is denied with the exact root-authorized instruction")
    func grantRequiresRootCLI() {
        let state = DashboardAgentCapabilities()
        for tier in DashboardAgentCapabilityTier.allCases {
            #expect(V2DaemonControl.dashboardAgentCapabilityChange(
                tier: tier,
                currentState: state,
                requestedEnabled: true
            ) == .rootGrantRequired(
                command: "sudo maccrabctl agent-capabilities set \(tier.rawValue) on"
            ))
        }
    }

    @Test("display state comes from a descriptor-validated authoritative file")
    func loadsTrustedStateForDisplay() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("mcp_capabilities.json")
        try Data(#"{"config":true,"authoring":false,"response":true}"#.utf8)
            .write(to: file)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: file.path
        )

        let loaded = try V2DaemonControl.loadAgentCapabilities(
            atPath: file.path,
            expectedOwnerUID: getuid()
        )
        #expect(loaded == DashboardAgentCapabilities(
            config: true,
            authoring: false,
            response: true
        ))

        // Ownership alone is insufficient if another uid can rewrite bytes.
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o666],
            ofItemAtPath: file.path
        )
        #expect(throws: (any Error).self) {
            _ = try V2DaemonControl.loadAgentCapabilities(
                atPath: file.path,
                expectedOwnerUID: getuid()
            )
        }
    }

    @Test("revocation request turns only the selected installed tier off")
    func revocationPreservesOtherTiers() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let current = DashboardAgentCapabilities(
            config: true,
            authoring: true,
            response: true
        )

        #expect(V2DaemonControl.dashboardAgentCapabilityChange(
            tier: .authoring,
            currentState: current,
            requestedEnabled: false
        ) == .revoke)
        #expect(V2DaemonControl.writeAgentCapabilityRevocationRequest(
            inboxDir: directory.path,
            tier: .authoring,
            currentState: current
        ))

        let names = try FileManager.default.contentsOfDirectory(atPath: directory.path)
        let name = try #require(names.only)
        #expect(name.hasPrefix("set-agent-capabilities-"))
        #expect(name.hasSuffix(".json"))
        let data = try Data(contentsOf: directory.appendingPathComponent(name))
        let payload = try #require(
            JSONSerialization.jsonObject(with: data) as? [String: Any]
        )
        #expect(payload["config"] as? Bool == true)
        #expect(payload["authoring"] as? Bool == false)
        #expect(payload["response"] as? Bool == true)
        #expect(payload["requestedTransition"] as? String == "revoke")
    }

    @Test("source guard keeps Settings root-state driven and grant-incapable")
    func sourceDriftGuard() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let settings = try String(
            contentsOf: root.appendingPathComponent("Sources/MacCrabApp/Views/SettingsView.swift"),
            encoding: .utf8
        )
        let appState = try String(
            contentsOf: root.appendingPathComponent("Sources/MacCrabApp/AppState.swift"),
            encoding: .utf8
        )

        #expect(settings.contains("appState.agentCapabilities"))
        #expect(settings.contains("dashboardAgentCapabilityChange"))
        #expect(settings.contains("queueAgentCapabilityRevocation"))
        #expect(!settings.contains("@AppStorage(\"agentCap"))
        #expect(!settings.contains("syncAgentCapabilities"))
        #expect(!settings.contains("confirmAgentResponseTier"))
        #expect(!settings.contains("Grant — I control this agent"))
        #expect(appState.contains("V2DaemonControl.loadAgentCapabilities"))
    }
}

private extension Collection {
    var only: Element? { count == 1 ? first : nil }
}
