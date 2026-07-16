// MCPProtocolHarnessTests.swift
// MacCrabCoreTests
//
// Black-box protocol contract for the maccrab-mcp server. Spawns the built
// binary and drives it over its newline-delimited JSON-RPC stdio transport.
// Locks three things that have no other coverage:
//   1. The initialize handshake + tools/list shape.
//   2. SINGLE-LINE framing — the v1.17.3→.4 regressor (LSP Content-Length
//      framing once buffer-stole bytes); every response must be exactly one
//      line even when it carries multi-line tool descriptions.
//   3. The isError contract — forensics/not-found handlers must set
//      isError:true (the fix made this round) and JSON-RPC error codes
//      (-32601 / -32602 / -32700) for protocol-level failures.

import Testing
import Foundation

// CI-robustness (three mutually-reinforcing mitigations; the suite is a
// black-box harness that spawns a real binary under full-suite load):
//   1. .serialized — one spawn at a time within the suite (other suites still
//      run parallel). Originally added to stop a 7-way concurrent
//      `swift build --product maccrab-mcp` thundering herd; CI now pre-builds
//      the binary (swift build links maccrab-mcp), so binaryURL() finds it and
//      never builds in-test, but serialization still bounds spawn concurrency.
//   2. hermetic HOME (see `hermeticHome`) — the spawned server's store is an
//      isolated temp dir, so a slow first-spawn migration can't half-write a
//      shared DB that a later test then reads (the intermittent isError flake).
//   3. a 60s read watchdog (see `drive`) — generous enough that a load-starved
//      first spawn's DB-create/migrate completes instead of being killed →
//      empty response. A healthy server still answers in milliseconds.
@Suite("MCP protocol contract", .serialized)
struct MCPProtocolHarnessTests {

    /// Locate the built maccrab-mcp binary, building it once if absent.
    static func binaryURL() -> URL? {
        let root = URL(fileURLWithPath: #filePath)   // .../Tests/MacCrabCoreTests/<this>.swift
            .deletingLastPathComponent()             // MacCrabCoreTests
            .deletingLastPathComponent()             // Tests
            .deletingLastPathComponent()             // package root
        let fm = FileManager.default
        let candidates = [
            root.appendingPathComponent(".build/debug/maccrab-mcp"),
            root.appendingPathComponent(".build/release/maccrab-mcp"),
        ]
        for c in candidates where fm.isExecutableFile(atPath: c.path) { return c }
        // Fallback: build the product once (deps are already compiled by the
        // test build, so this is the maccrab-mcp link only — fast).
        let build = Process()
        build.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        build.arguments = ["swift", "build", "--product", "maccrab-mcp"]
        build.currentDirectoryURL = root
        build.standardOutput = FileHandle.nullDevice
        build.standardError = FileHandle.nullDevice
        try? build.run()
        build.waitUntilExit()
        let debug = root.appendingPathComponent(".build/debug/maccrab-mcp")
        return fm.isExecutableFile(atPath: debug.path) ? debug : nil
    }

    /// A hermetic, per-process app-support root for the spawned server. The
    /// server resolves its store under HOME (`~/Library/Application Support/
    /// MacCrab`, `main.swift` resolveDataDir/mcpUserDir). Pointing HOME here
    /// means the harness (a) never reads or writes the developer/CI MacCrab
    /// store — so the suite tests the real empty-store contract rather than
    /// whatever happens to be on the machine — and (b) a slow first-spawn
    /// SQLite migration on a load-saturated CI runner cannot half-write the
    /// shared store and poison a later test (the intermittent isError flakes).
    static let hermeticHome: URL = {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-mcp-harness-\(ProcessInfo.processInfo.globallyUniqueString)",
                                    isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }()

    /// Feed newline-delimited request lines and return the parsed responses,
    /// retrying on an EMPTY result. A CI runner building 442 suites in parallel
    /// can starve the first cold 28MB-binary spawn (dyld load + Swift runtime
    /// init + first DB open) past the read watchdog → no output. Later spawns
    /// in the serialized suite are fast (binary + store warm in the page cache),
    /// so a retry of the cold first call almost always succeeds. A genuinely
    /// broken server returns empty on every attempt → the test still fails.
    func drive(_ requestLines: [String]) -> [[String: Any]] {
        var objs: [[String: Any]] = []
        for _ in 0..<3 {
            objs = driveOnce(requestLines)
            if !objs.isEmpty { break }
        }
        if objs.isEmpty {
            Issue.record("maccrab-mcp produced no parseable response after 3 attempts (missing binary, spawn failure, or starved past the watchdog)")
        }
        return objs
    }

    /// One spawn → write → read attempt. A 60s read watchdog guarantees a
    /// misbehaving (or fatally starved) server can't hang the suite. Returns
    /// [] on any failure — the caller (`drive`) decides whether to retry or
    /// record an issue, so a transient first-attempt failure isn't a test fail.
    private func driveOnce(_ requestLines: [String]) -> [[String: Any]] {
        guard let bin = Self.binaryURL() else { return [] }
        let proc = Process()
        proc.executableURL = bin
        var env = ProcessInfo.processInfo.environment
        env["HOME"] = Self.hermeticHome.path
        proc.environment = env
        let inPipe = Pipe(), outPipe = Pipe()
        proc.standardInput = inPipe
        proc.standardOutput = outPipe
        proc.standardError = FileHandle.nullDevice
        do { try proc.run() } catch { return [] }
        let payload = (requestLines.joined(separator: "\n") + "\n").data(using: .utf8)!
        inPipe.fileHandleForWriting.write(payload)
        try? inPipe.fileHandleForWriting.close()

        var outData = Data()
        let group = DispatchGroup()
        group.enter()
        DispatchQueue.global().async {
            outData = outPipe.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }
        if group.wait(timeout: .now() + 60) == .timedOut {
            proc.terminate()
            _ = group.wait(timeout: .now() + 2)
        }
        proc.waitUntilExit()

        let text = String(data: outData, encoding: .utf8) ?? ""
        var objs: [[String: Any]] = []
        for raw in text.split(separator: "\n") {
            let t = raw.trimmingCharacters(in: .whitespaces)
            guard t.hasPrefix("{"), let d = t.data(using: .utf8),
                  let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any] else { continue }
            objs.append(o)
        }
        return objs
    }

    private func byId(_ objs: [[String: Any]], _ id: Int) -> [String: Any]? {
        objs.first { ($0["id"] as? Int) == id }
    }

    @Test("initialize handshake + tools/list shape, single-line framed")
    func handshakeAndToolsList() {
        let objs = drive([
            #"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
            #"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        ])
        // Framing: exactly two well-formed JSON lines, despite tools/list
        // carrying long, possibly newline-containing tool descriptions.
        #expect(objs.count == 2)

        let initResult = byId(objs, 1)?["result"] as? [String: Any]
        #expect(initResult?["protocolVersion"] as? String == "2024-11-05")
        #expect((initResult?["serverInfo"] as? [String: Any])?["name"] as? String == "maccrab")

        let tools = (byId(objs, 2)?["result"] as? [String: Any])?["tools"] as? [[String: Any]]
        let names = Set((tools ?? []).compactMap { $0["name"] as? String })
        // Floor sized to the static tool surface (~49 + dynamically-registered
        // plugin tools; ~78 live). The prior >=30 floor was so far below the
        // real surface that a whole category could vanish undetected — the
        // golden set below pins the load-bearing tools across categories so a
        // dropped registration fails this test.
        #expect(names.count >= 45)
        for required in [
            "get_alerts", "get_status", "get_events", "get_campaigns",
            "suppress_alert", "suppress_campaign", "hunt", "get_security_score",
            "get_traces", "get_trace_detail",
            "export_session_bundle", "verify_session_bundle", "get_agent_session",
            "forensics_search_artifacts",   // MCP-3: advertised with underscore now
        ] {
            #expect(names.contains(required), "MCP tool missing from tools/list: \(required)")
        }
        // MCP-3: strict MCP clients require ^[a-zA-Z0-9_-]+$ — NO advertised
        // tool name may contain a dot.
        for n in names {
            #expect(!n.contains("."), "advertised tool name contains a dot (strict-client incompatible): \(n)")
        }
    }

    @Test("Forensics/unknown errors set isError:true (the contract fix)")
    func isErrorContract() {
        let objs = drive([
            #"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"forensics.search_artifacts","arguments":{}}}"#,
            #"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"forensics.get_artifact","arguments":{}}}"#,
            #"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"definitely_not_a_tool","arguments":{}}}"#,
        ])
        for id in 1...3 {
            let result = byId(objs, id)?["result"] as? [String: Any]
            #expect(result?["isError"] as? Bool == true, "id \(id) should be isError")
        }
    }

    /// Extract the first text block from a tools/call result payload.
    private func resultText(_ objs: [[String: Any]], _ id: Int) -> String {
        let result = byId(objs, id)?["result"] as? [String: Any]
        let content = result?["content"] as? [[String: Any]]
        return content?.first?["text"] as? String ?? ""
    }

    @Test("tools/list exposes forensics_create_case + dynamically-registered plugin tools")
    func dynamicToolSurface() {
        let objs = drive([
            #"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
            #"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        ])
        let tools = (byId(objs, 2)?["result"] as? [String: Any])?["tools"] as? [[String: Any]]
        let names = Set((tools ?? []).compactMap { $0["name"] as? String })
        // The create-case meta-tool (MCP-3: underscore name; dotted still accepted as an alias).
        #expect(names.contains("forensics_create_case"))
        // Per-plugin tools projected from collector manifests' mcpTools.
        #expect(names.contains("macho_analyze_path"))
        #expect(names.contains("tcc_grants_for_service"))
        // The lone enricher-declared tool is NOT runnable yet → not advertised.
        #expect(!names.contains("codesign_resolve"))
        // A dynamic tool requires case_id and surfaces its plugin inputs.
        if let macho = (tools ?? []).first(where: { $0["name"] as? String == "macho_analyze_path" }) {
            let schema = macho["inputSchema"] as? [String: Any]
            let props = schema?["properties"] as? [String: Any]
            let required = schema?["required"] as? [String]
            #expect(props?["case_id"] != nil)
            #expect(props?["path"] != nil)
            #expect(required?.contains("case_id") == true)
        } else {
            Issue.record("macho_analyze_path missing from tools/list")
        }
    }

    @Test("SEC-1: agent-session output is slash-unescaped + never leaks the raw username")
    func sessionOutputSanitized() {
        let objs = drive([
            #"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
            #"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_agent_session","arguments":{"session_id":"00000000-0000-0000-0000-000000000000"}}}"#,
            #"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_agent_sessions","arguments":{}}}"#,
        ])
        for id in [2, 3] {
            let text = resultText(objs, id)
            // jsonStringify must unescape '/' so the sanitizer's /Users/<name>/
            // regex can match (the escaped '\/' form defeated it — SEC-1).
            #expect(!text.contains(#"\/"#), "id \(id): output still has escaped slashes — sanitizer can't redact paths")
            // The agent must never see the raw operator username; any /Users/
            // path must be redacted to /Users/[USER]/.
            #expect(!text.contains("/Users/\(NSUserName())/"), "id \(id): raw home path leaked to the agent")
        }
    }

    @Test("suppress_alert / suppress_campaign are gated by the response tier")
    func suppressGating() {
        let objs = drive([
            #"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
            #"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"agent_capabilities","arguments":{}}}"#,
            #"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"suppress_alert","arguments":{"alert_id":"00000000-0000-0000-0000-000000000000"}}}"#,
            #"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"suppress_campaign","arguments":{"campaign_id":"does-not-exist"}}}"#,
        ])
        // Adaptive to the host's real grant file (root-owned, can't be
        // faked in-test): if the response tier is OFF (the secure default /
        // CI), both suppress calls must be capability-denied. If it's ON
        // (a granted dev box), the denial reason must NOT be 'capability'
        // (any error is then a not-found, not a bypassed gate).
        let responseGranted = resultText(objs, 2).contains("[ON ] response")
        for id in [3, 4] {
            let text = resultText(objs, id).lowercased()
            if responseGranted {
                #expect(!text.contains("capability is not enabled"),
                        "id \(id): with response granted, suppress must not be capability-denied")
            } else {
                let result = byId(objs, id)?["result"] as? [String: Any]
                #expect(result?["isError"] as? Bool == true, "id \(id) should be isError when ungranted")
                #expect(text.contains("capability"),
                        "id \(id): ungranted suppress must be denied for a capability reason")
            }
        }
    }

    /// v1.19.0 (D6): fail-open guard for the capability gate. `agentToolCapability`
    /// (AgentControl.swift) returns nil → ALLOW for any tool not in the map, so a
    /// new engine-mutating tool added to `handleToolCall` but forgotten in the map
    /// silently bypasses the gate — the exact class of the v1.18 capability-bypass.
    /// This pins the set of mutating-verb-prefixed tools advertised by tools/list
    /// to the known gated surface, so a NEW ungated mutator fails the build. It
    /// executes nothing (safe on any host). The forensics.* / dotted plugin
    /// namespace is local-evidence/analysis, intentionally outside the
    /// engine-mutation tier, and is excluded.
    @Test("every engine-mutating tool stays in the capability gate (fail-open guard)")
    func mutatingToolsAreGated() {
        let objs = drive([
            #"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
            #"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        ])
        let names = Set(((byId(objs, 2)?["result"] as? [String: Any])?["tools"] as? [[String: Any]] ?? [])
            .compactMap { $0["name"] as? String })
        #expect(!names.isEmpty, "tools/list returned no tools")

        // Engine mutators follow a verb-prefix convention. The forensics PLUGIN
        // mutators (underscore-named since v1.19.1) carry no verb prefix but ARE
        // gated (.response tier) — install/uninstall/pin replace executable
        // scanner code / change pin state on disk — so pin them explicitly: a
        // forgotten agentToolCapability entry (or a new forensics mutator) then
        // fails the build instead of failing OPEN (the v1.18 bypass class).
        let mutatingPrefixes = ["create_", "delete_", "set_", "suppress_", "reload_", "refresh_"]
        let forensicsMutators: Set<String> = [
            "forensics_install_plugin", "forensics_uninstall_plugin",
            "forensics_pin_plugin", "forensics_install_plugin_update",
            // v1.21.4 (audit): these execute plugin/enricher code or read back
            // collected sensitive data and are now .response-gated — pin them so
            // a future ungate fails the build (the v1.18 fail-open bypass class).
            "forensics_run_collector", "forensics_run_analyzer",
            "forensics_run_all", "forensics_create_case", "forensics_enrich",
        ]
        let observed = names.filter { n in
            !n.contains(".") && (mutatingPrefixes.contains { n.hasPrefix($0) } || forensicsMutators.contains(n))
        }

        // The canonical gated engine-mutation surface (mirrors agentToolCapability
        // in AgentControl.swift). Adding a mutating tool to handleToolCall means
        // adding it to agentToolCapability AND here — otherwise it fails OPEN.
        let expectedGated: Set<String> = [
            "create_rule", "delete_rule",
            "set_builtin_rule_setting", "set_daemon_config",
            "reload_rules", "refresh_threat_intel",
            "suppress_alert", "suppress_campaign",
            "set_response_action",
            "forensics_install_plugin", "forensics_uninstall_plugin",
            "forensics_pin_plugin", "forensics_install_plugin_update",
            // v1.21.4 (audit): code-executing / case-mutating forensics tools now
            // .response-gated (the v1.18 fail-open bypass class).
            "forensics_run_collector", "forensics_run_analyzer",
            "forensics_run_all", "forensics_create_case", "forensics_enrich",
        ]
        for n in observed {
            #expect(expectedGated.contains(n),
                    "mutating-verb tool '\(n)' is advertised but not in the known capability-gated set — add it to agentToolCapability (AgentControl.swift) AND this test, or it fails OPEN (the v1.18 bypass class)")
        }
        for n in expectedGated {
            #expect(names.contains(n), "expected gated tool missing from tools/list: \(n)")
        }
    }

    @Test("JSON-RPC error codes for protocol-level failures")
    func jsonRpcErrorCodes() {
        let objs = drive([
            #"{"jsonrpc":"2.0","id":1,"method":"bogus/method"}"#,
            #"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"arguments":{}}}"#,  // no name
            #"{bad json"#,                                                                  // -32700
        ])
        #expect((byId(objs, 1)?["error"] as? [String: Any])?["code"] as? Int == -32601)
        #expect((byId(objs, 2)?["error"] as? [String: Any])?["code"] as? Int == -32602)
        // The parse-error response carries a null id — find it by code.
        let parseErr = objs.contains { ($0["error"] as? [String: Any])?["code"] as? Int == -32700 }
        #expect(parseErr)
    }

    @Test("agent-session read tools are advertised and return well-formed (non-error) results")
    func agentSessionTools() {
        let objs = drive([
            #"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
            #"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
            #"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_agent_sessions","arguments":{}}}"#,
            #"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_agent_session","arguments":{"session_id":"no-such-session"}}}"#,
        ])
        let names = Set(((byId(objs, 2)?["result"] as? [String: Any])?["tools"] as? [[String: Any]] ?? [])
            .compactMap { $0["name"] as? String })
        #expect(names.contains("list_agent_sessions"))
        #expect(names.contains("get_agent_session"))
        // Read tools must succeed (not isError) even with an empty store /
        // unknown session — they return an empty list / empty timeline.
        #expect((byId(objs, 3)?["result"] as? [String: Any])?["isError"] as? Bool != true)
        #expect((byId(objs, 4)?["result"] as? [String: Any])?["isError"] as? Bool != true)
    }
}
