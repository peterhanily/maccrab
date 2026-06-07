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

@Suite("MCP protocol contract")
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

    /// Feed newline-delimited request lines, close stdin (EOF ends the server
    /// loop), and return the parsed response objects. A 15s read watchdog
    /// guarantees a misbehaving server can't hang the suite.
    func drive(_ requestLines: [String]) -> [[String: Any]] {
        guard let bin = Self.binaryURL() else {
            Issue.record("maccrab-mcp binary not found and could not be built")
            return []
        }
        let proc = Process()
        proc.executableURL = bin
        let inPipe = Pipe(), outPipe = Pipe()
        proc.standardInput = inPipe
        proc.standardOutput = outPipe
        proc.standardError = FileHandle.nullDevice
        do { try proc.run() } catch {
            Issue.record("failed to spawn maccrab-mcp: \(error)")
            return []
        }
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
        if group.wait(timeout: .now() + 15) == .timedOut {
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
        #expect(names.count >= 30)   // 34 tools
        #expect(names.contains("get_alerts"))
        #expect(names.contains("get_status"))
        #expect(names.contains("forensics.search_artifacts"))
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
