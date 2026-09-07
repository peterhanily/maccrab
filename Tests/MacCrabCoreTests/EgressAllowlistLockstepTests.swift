// The CLI, MCP server and daemon share the request contract in MacCrabCore.
// Verify the privacy behavior and keep every client wired to that validator.
import Testing
import Foundation
import MacCrabCore

@Suite("Shared disable-only network configuration")
struct EgressAllowlistLockstepTests {
    static let expected: Set<String> = [
        "threat_intel_enabled", "vuln_scan_enabled",
        "package_freshness_enabled", "cert_transparency_enabled",
    ]

    @Test("Exactly the four outbound enrichment switches are disable-only")
    func exactNetworkScope() {
        let actual = Set(RuntimeConfigurationContract.definitions
            .filter(\.disableOnly).map(\.key))
        #expect(actual == Self.expected)
    }

    @Test("Client requests can disable enrichment but cannot enable network access",
          arguments: Self.expected.sorted())
    func disableOnlyRequest(key: String) throws {
        let definition = try #require(RuntimeConfigurationContract.byKey[key])
        #expect(definition.kind == .bool)
        #expect(definition.defaultValue == .boolean(false))
        #expect(definition.application == .live)
        #expect(try definition.normalized(.boolean(false)) == .boolean(false))
        #expect(throws: RuntimeConfigContractError.self) {
            try definition.normalized(.boolean(true))
        }
        #expect(throws: RuntimeConfigContractError.self) {
            try definition.typed(NSNumber(value: 0))
        }
        // Reading an administrator's existing enabled configuration is distinct
        // from granting a new enable request through CLI/MCP.
        #expect(try definition.normalized(.boolean(true), forRequest: false) == .boolean(true))
    }

    @Test("Each request handler checks shared membership and normalizes the value",
          arguments: [
            "Sources/maccrabctl/ConfigCommands.swift",
            "Sources/maccrab-mcp/AgentControl.swift",
            "Sources/MacCrabAgentKit/DaemonTimers.swift",
          ])
    func sharedClientValidation(path: String) throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let source = try String(contentsOf: root.appendingPathComponent(path), encoding: .utf8)
        #expect(source.contains("RuntimeConfigurationContract.byKey[key]"))
        #expect(source.contains("try definition.normalized(requested)"))
    }
}
