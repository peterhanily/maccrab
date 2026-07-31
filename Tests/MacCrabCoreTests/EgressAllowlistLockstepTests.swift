// EgressAllowlistLockstepTests.swift
// The daemon_config allowlist is maintained in THREE places — the CLI
// (maccrabctl/ConfigCommands), the MCP server (maccrab-mcp/AgentControl) and the
// daemon itself (MacCrabAgentKit/DaemonTimers). ConfigCommands' own header says
// "keep the three lists in lockstep"; they cannot be factored into one type
// because the CLI and MCP targets do not link MacCrabAgentKit.
//
// A source-scanning guard is therefore the only mechanism available. It matters
// most for the v1.21.6 disable-only egress keys: if the daemon list gains a key
// the other two lack, the CLI rejects something the engine would accept; if the
// CLI or MCP gains one the DAEMON lacks, a user is told their egress switch was
// queued when the engine will drop it as `rejected_key` — a privacy control that
// silently does nothing.
import Testing
import Foundation

@Suite("Egress disable-only allowlist stays in lockstep across CLI / MCP / daemon")
struct EgressAllowlistLockstepTests {

    static let repoRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()   // MacCrabCoreTests
        .deletingLastPathComponent()   // Tests
        .deletingLastPathComponent()   // repo root

    /// The four network-enrichment switches. Every one performs outbound HTTP.
    static let expected: Set<String> = [
        "threat_intel_enabled",
        "vuln_scan_enabled",
        "package_freshness_enabled",
        "cert_transparency_enabled",
    ]

    /// Pull the string literals out of a named Swift `Set<String>` / dictionary
    /// literal, from its declaration to the closing bracket.
    static func keys(inFile path: String, afterDeclaration decl: String) throws -> Set<String> {
        let src = try String(contentsOf: repoRoot.appendingPathComponent(path), encoding: .utf8)
        guard let declRange = src.range(of: decl) else {
            Issue.record("declaration '\(decl)' not found in \(path)")
            return []
        }
        let tail = src[declRange.upperBound...]
        guard let close = tail.range(of: "]") else { return [] }
        let body = tail[..<close.lowerBound]
        let re = try NSRegularExpression(pattern: #""([a-z_]+)""#)
        let s = String(body)
        return Set(re.matches(in: s, range: NSRange(s.startIndex..., in: s)).compactMap {
            Range($0.range(at: 1), in: s).map { String(s[$0]) }
        })
    }

    @Test("the CLI list is exactly the four egress switches")
    func cliList() throws {
        let found = try Self.keys(inFile: "Sources/maccrabctl/ConfigCommands.swift",
                                  afterDeclaration: "configEgressDisableOnlyKeys: Set<String> = [")
        #expect(found == Self.expected, "CLI egress allowlist drifted: \(found.sorted())")
    }

    @Test("the MCP list is exactly the four egress switches")
    func mcpList() throws {
        let found = try Self.keys(inFile: "Sources/maccrab-mcp/AgentControl.swift",
                                  afterDeclaration: "daemonConfigEgressDisableOnlyKeys: Set<String> = [")
        #expect(found == Self.expected, "MCP egress allowlist drifted: \(found.sorted())")
    }

    @Test("the daemon list is exactly the four egress switches")
    func daemonList() throws {
        let found = try Self.keys(inFile: "Sources/MacCrabAgentKit/DaemonTimers.swift",
                                  afterDeclaration: "agentDisableOnlyConfigKeys: Set<String> = [")
        #expect(found == Self.expected, "daemon egress allowlist drifted: \(found.sorted())")
    }

    /// The daemon rejects any key absent from `agentSettableConfigKeys` BEFORE it
    /// ever consults the disable-only set, so an egress key missing from the
    /// settable map would be dropped as `rejected_key` while the CLI happily
    /// reported the request queued.
    @Test("every egress key is also in the daemon's settable-key map")
    func daemonSettableIncludesEgress() throws {
        let found = try Self.keys(inFile: "Sources/MacCrabAgentKit/DaemonTimers.swift",
                                  afterDeclaration: "agentSettableConfigKeys: [String: String] = [")
        for key in Self.expected {
            #expect(found.contains(key),
                    "'\(key)' is disable-only but not settable — the daemon would reject it as an unknown key")
        }
    }
}
