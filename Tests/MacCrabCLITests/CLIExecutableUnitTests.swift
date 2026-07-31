// CLIExecutableUnitTests.swift
// MacCrabCLITests
//
// CI-14: `maccrab-mcp` (4.3k LOC) and `maccrabctl` (10.2k LOC) are both
// SHIPPED, user-facing executables and neither had a test target. The only MCP
// coverage was MCPProtocolHarnessTests — a black box that spawns the binary
// against a deliberately EMPTY hermetic store, so by construction it cannot
// tell a handler whose SQL targets the wrong table from a correct one, and it
// cannot reach any pure helper at all.
//
// SPM has allowed a test target to depend on an executable target since
// tools-version 5.5, and both executables use top-level code in `main.swift`,
// which is the supported shape. ONE CAVEAT bounds what may be tested here:
// globals DECLARED IN main.swift (maccrab-mcp's `tools`, `dataDir`,
// `isoFormatter`) are initialised by the entry point, which the test runner
// never calls — reading one traps. Globals in every OTHER file of the module
// (AgentControl.swift's `agentToolCapability`, Helpers.swift's `isTerminal`)
// are ordinary lazy globals and are safe, as are all functions.
//
// So: functions and non-main.swift state only, and nothing with a side effect —
// no dropInboxRequest / auditLog, which write into the real support directory.

import Testing
import Foundation
@testable import maccrabctl
@testable import maccrab_mcp

@Suite("maccrabctl: unit")
struct MacCrabCtlUnitTests {

    /// The v1/v2 suppression-store discriminator. `suppressRule` /
    /// `unsuppressRule` encode a FLAT `[ruleId: [path]]` document over the very
    /// same suppressions.json the daemon rewrites in v2 shape
    /// (`{"version":2,"entries":[…]}`), so a v1 write onto a v2 document
    /// destroys the entire TTL/audit allowlist. This one predicate is what
    /// stands between those two encodings, and it had no coverage.
    @Test("suppressionStoreIsV2 recognises both v2 shapes and never mistakes a v1 document for one")
    func suppressionStoreShapeDetection() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrabctl-suppress-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        func write(_ json: String, _ name: String) throws -> String {
            let p = dir.appendingPathComponent(name).path
            try json.write(toFile: p, atomically: true, encoding: .utf8)
            return p
        }

        // v2 by explicit version, and v2 by entries array. The daemon writes
        // both keys, but EITHER alone must be enough to stop a v1 overwrite.
        #expect(MacCrabCtl.suppressionStoreIsV2(try write(#"{"version":2,"entries":[]}"#, "a.json")))
        #expect(MacCrabCtl.suppressionStoreIsV2(try write(#"{"version":2}"#, "b.json")))
        #expect(MacCrabCtl.suppressionStoreIsV2(try write(#"{"entries":[{"ruleId":"r"}]}"#, "c.json")))

        // A genuine v1 flat map, an absent file, and non-JSON must all read as
        // "not v2" so the v1 path stays usable on a real v1 store.
        #expect(!MacCrabCtl.suppressionStoreIsV2(try write(#"{"csrutil_status":["/usr/bin/csrutil"]}"#, "d.json")))
        #expect(!MacCrabCtl.suppressionStoreIsV2(dir.appendingPathComponent("nope.json").path))
        #expect(!MacCrabCtl.suppressionStoreIsV2(try write("not json at all", "e.json")))
    }

    /// CLI-5 contract: the research verbs are dispatched only under
    /// MACCRAB_DEV=1 and must never be advertised in shipped help. Asserted on
    /// the LEADING TOKEN of each help line, not a substring — "MCFP v1 static
    /// process fingerprint" is legitimate prose on the `fingerprint` line, and a
    /// naive `contains("mcfp")` would fail on it.
    @Test("usageText never advertises a dev-hidden command")
    func hiddenCommandsStayHidden() {
        #expect(!MacCrabCtl.hiddenCommands.isEmpty)
        let advertised = Set(MacCrabCtl.usageText()
            .components(separatedBy: "\n")
            .compactMap { $0.trimmingCharacters(in: .whitespaces).components(separatedBy: " ").first }
            .filter { !$0.isEmpty })
        for hidden in MacCrabCtl.hiddenCommands {
            #expect(!advertised.contains(hidden),
                    "'\(hidden)' is a MACCRAB_DEV-only verb but appears as a documented command in `maccrabctl help`")
        }
    }
}

@Suite("maccrab-mcp: unit")
struct MCPHandlerUnitTests {

    /// `sanitizeContent` runs over EVERY tool response on the way out. It must
    /// rewrite `content[].text` and touch nothing else — in particular
    /// `isError`, which is the only thing an agent reads to tell a tool failure
    /// from data. A rewrite that rebuilt the dict instead of mutating it would
    /// launder every error into a success, and the black-box harness (which only
    /// checks that SOME isError appears somewhere) would not notice.
    @Test("sanitizeContent scrubs text blocks and preserves isError + non-text blocks")
    func sanitizePreservesEnvelope() throws {
        let input: [String: Any] = [
            "isError": true,
            "content": [
                ["type": "text", "text": "outbound to 192.168.7.31 from the alerting process"],
                ["type": "resource", "uri": "maccrab://alert/9f3c"],
            ],
        ]
        let out = try #require(maccrab_mcp.sanitizeContent(input) as? [String: Any])
        #expect(out["isError"] as? Bool == true)
        let blocks = try #require(out["content"] as? [[String: Any]])
        #expect(blocks.count == 2)
        // The text block was scrubbed. 192.168/16 is an unconditional RFC-1918
        // match in LLMSanitizer.privateIPRegex, so this does not depend on the
        // running user's name (the CI `runner` account sits in the sanitizer's
        // reserved set and would make a username-based assertion flaky).
        let text = try #require(blocks[0]["text"] as? String)
        #expect(!text.contains("192.168.7.31"))
        // The non-text block rode through untouched.
        #expect(blocks[1]["uri"] as? String == "maccrab://alert/9f3c")
        #expect(blocks[1]["text"] == nil)
    }

    /// `set_daemon_config`'s base tier is `.config`, but the three
    /// defence-affecting keys escalate to `.response` because turning them off
    /// REDUCES detection coverage. That escalation is a single `if` inside
    /// `agentCapabilityDenial` with no unit coverage; the protocol harness can
    /// only observe that *some* denial happened, never which tier was demanded.
    @Test("set_daemon_config escalates defence-affecting keys to the response tier")
    func defenceAffectingKeysEscalate() {
        // The grants file is root-owned so a test cannot fabricate one. Assert
        // against whatever this host actually has: honest on CI (no grants) and
        // on a dev box where the operator granted a tier.
        let granted = maccrab_mcp.loadAgentCapabilities()
        let defenceKey = "subscribe_file_open_events"
        #expect(maccrab_mcp.daemonConfigResponseKeys.contains(defenceKey))

        let denial = maccrab_mcp.agentCapabilityDenial(
            forTool: "set_daemon_config", args: ["key": defenceKey, "value": false])
        if granted.contains(.response) {
            #expect(denial == nil, "response tier is granted on this host, so the call must be allowed")
        } else {
            #expect(denial?["isError"] as? Bool == true)
            let text = ((denial?["content"] as? [[String: Any]])?.first?["text"] as? String) ?? ""
            #expect(text.contains("'response'"),
                    "a defence-affecting key must be denied at the RESPONSE tier, not the base config tier — got: \(text)")
        }

        // A safe tunable stays at the base tier.
        let safeDenial = maccrab_mcp.agentCapabilityDenial(
            forTool: "set_daemon_config", args: ["key": "behavior_alert_threshold", "value": 12.0])
        if granted.contains(.config) {
            #expect(safeDenial == nil)
        } else {
            let text = ((safeDenial?["content"] as? [[String: Any]])?.first?["text"] as? String) ?? ""
            #expect(text.contains("'config'"))
        }

        // A read-only tool is absent from the map entirely and is never denied.
        #expect(maccrab_mcp.agentCapabilityDenial(forTool: "get_alerts", args: [:]) == nil)
    }
}
