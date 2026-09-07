import Foundation
import Testing
@testable import MacCrabCore
@testable import maccrabctl
@testable import maccrab_mcp

@Suite("CLI and MCP runtime read contracts")
struct RuntimeReadContractTests {
    private func directory() throws -> URL {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("maccrab-client-contract-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        return root
    }

    private func runCLI(_ arguments: [String], directory: URL) throws -> (status: Int32, stdout: String, stderr: String) {
        let project = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let binary = Foundation.ProcessInfo.processInfo.environment["MACCRAB_CTL_BINARY"]
            .map { URL(fileURLWithPath: $0) } ?? project.appendingPathComponent(".build/debug/maccrabctl")
        try #require(FileManager.default.isExecutableFile(atPath: binary.path), "The current CLI executable must be built for its contract tests")
        let output = directory.appendingPathComponent("stdout-\(UUID().uuidString)")
        let errors = directory.appendingPathComponent("stderr-\(UUID().uuidString)")
        FileManager.default.createFile(atPath: output.path, contents: nil)
        FileManager.default.createFile(atPath: errors.path, contents: nil)
        let stdout = try FileHandle(forWritingTo: output)
        let stderr = try FileHandle(forWritingTo: errors)
        defer { try? stdout.close(); try? stderr.close() }
        let process = Process()
        process.executableURL = binary
        process.arguments = arguments
        var environment = Foundation.ProcessInfo.processInfo.environment
        environment["MACCRAB_DATA_DIR"] = directory.path
        process.environment = environment
        process.standardOutput = stdout
        process.standardError = stderr
        let completed = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in completed.signal() }
        try process.run()
        guard completed.wait(timeout: .now() + 20) == .success else {
            if process.isRunning { process.terminate() }
            if completed.wait(timeout: .now() + 1) != .success, process.isRunning {
                kill(process.processIdentifier, SIGKILL)
                _ = completed.wait(timeout: .now() + 1)
            }
            throw RuntimeConfigContractError("Read-only CLI contract command exceeded its deadline")
        }
        return (process.terminationStatus,
                try String(contentsOf: output, encoding: .utf8),
                try String(contentsOf: errors, encoding: .utf8))
    }

    private func object(_ text: String) throws -> [String: Any] {
        try #require(JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any])
    }
    private func mcpObject(_ result: Any) throws -> [String: Any] {
        let envelope = try #require(result as? [String: Any])
        #expect(envelope["isError"] as? Bool != true)
        let content = try #require(envelope["content"] as? [[String: Any]])
        return try object(try #require(content.first?["text"] as? String))
    }

    @Test("CLI optional configuration defaults, successful reads and read failures have distinct exits")
    func configurationReadExits() throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let missing = try runCLI(["config", "get", "usb_poll_interval", "--json"], directory: root)
        #expect(missing.status == 0)
        let missingObject = try object(missing.stdout)
        #expect(missingObject["file_present"] as? Bool == false)
        #expect((missingObject["values"] as? [String: Any])?["usb_poll_interval"] as? Double == 10)
        try Data(#"{"usb_poll_interval":10,"usbPollInterval":20}"#.utf8).write(to: root.appendingPathComponent("daemon_config.json"))
        let configured = try runCLI(["config", "get", "usb_poll_interval", "--json"], directory: root)
        #expect(configured.status == 0)
        #expect((try object(configured.stdout)["values"] as? [String: Any])?["usb_poll_interval"] as? Double == 20)
        let unknown = try runCLI(["config", "get", "no_such_setting", "--json"], directory: root)
        #expect(unknown.status != 0)
        #expect(unknown.stdout.isEmpty)
        #expect(!unknown.stderr.isEmpty)
        // Ordinary incomplete configuration from an interrupted manual edit.
        try Data("{\n".utf8).write(to: root.appendingPathComponent("daemon_config.json"))
        let incomplete = try runCLI(["config", "get", "--json"], directory: root)
        #expect(incomplete.status != 0)
        #expect(incomplete.stdout.isEmpty)
        #expect(!incomplete.stderr.isEmpty)
    }

    @Test("CLI rule reads distinguish absent corpus from an empty readable corpus")
    func rulesReadExits() throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let missing = try runCLI(["rules", "list", "--json"], directory: root)
        #expect(missing.status != 0)
        #expect(missing.stdout.isEmpty)
        try FileManager.default.createDirectory(at: root.appendingPathComponent("compiled_rules"), withIntermediateDirectories: true)
        let empty = try runCLI(["rules", "list", "--json"], directory: root)
        #expect(empty.status == 0)
        #expect((try object(empty.stdout)["rules"] as? [Any])?.isEmpty == true)
    }

    @Test("ordinary retained data returns matching bounded CLI and MCP status counts")
    func populatedStatus() async throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let now = Date()
        let event = Event(eventCategory: .process, eventType: .start, eventAction: "exec", process: .init(
            pid: 7000, ppid: 1, rpid: 1, name: "ordinary", executable: "/usr/bin/true",
            commandLine: "/usr/bin/true", args: [], workingDirectory: "/tmp", userId: 501,
            userName: "fixture", groupId: 20, startTime: now
        ))
        do {
            let events = try EventStore(directory: root.path)
            try await events.insert(event: event)
            let alerts = try AlertStore(directory: root.path)
            try await alerts.insert(alert: .init(ruleId: "fixture.ordinary", ruleTitle: "Ordinary fixture",
                severity: .informational, eventId: event.id.uuidString))
        }
        let cli = try runCLI(["status", "--json"], directory: root)
        #expect(cli.status == 0)
        let cliObject = try object(cli.stdout)
        let mcp = try mcpObject(await mcpRuntimeStatus(directory: root.path, now: now))
        #expect(cliObject["retained_event_count"] as? Int == 1)
        #expect(cliObject["retained_alert_count"] as? Int == 1)
        let mcpEvents = mcp["retained_event_count"] as? Int
        let cliEvents = cliObject["retained_event_count"] as? Int
        let mcpAlerts = mcp["retained_alert_count"] as? Int
        let cliAlerts = cliObject["retained_alert_count"] as? Int
        #expect(mcpEvents == cliEvents)
        #expect(mcpAlerts == cliAlerts)
        #expect(cliObject["liveness"] as? String == "unavailable")
        #expect(mcp["current_health"] == nil)
    }

    @Test("MCP inventory pagination and CLI coverage share current snapshot identity and timestamps")
    func ruleReadParity() async throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let compiled = root.appendingPathComponent("compiled_rules")
        try FileManager.default.createDirectory(at: compiled, withIntermediateDirectories: true)
        for id in ["a", "b"] {
            try JSONSerialization.data(withJSONObject: ["id": id, "title": "Ordinary \(id)", "level": "low",
                "status": "stable", "enabled": true, "tags": ["fixture.ordinary"]])
                .write(to: compiled.appendingPathComponent(id + ".json"))
        }
        let now = Date()
        let identity = EngineTelemetryIdentity(pid: 42, startedAtUnix: now.timeIntervalSince1970 - 10,
                                               version: "1.22.0", build: "fixture")
        let heartbeat: [String: Any] = ["engine_pid": identity.pid, "engine_started_at_unix": identity.startedAtUnix,
            "engine_version": identity.version, "engine_build": identity.build,
            "written_at_unix": now.timeIntervalSince1970, "rule_profile": "stable"]
        let heartbeatData = try JSONSerialization.data(withJSONObject: heartbeat)
        try heartbeatData.write(to: root.appendingPathComponent("heartbeat.json"))
        try heartbeatData.write(to: root.appendingPathComponent("heartbeat_rich.json"))
        let snapshot = RuleEngine.TelemetrySnapshot(writtenAt: now,
            stats: [.init(ruleId: "a", evaluationCount: 3)], engineIdentity: identity,
            loadedRuleIds: ["a", "b"], enabledRuleIds: ["a", "b"])
        try JSONEncoder().encode(snapshot).write(to: root.appendingPathComponent("rule_telemetry.json"))
        let cli = try runCLI(["rules", "list", "--json"], directory: root)
        #expect(cli.status == 0)
        let cliObject = try object(cli.stdout)
        // Observe after writing, as a real client does. A zero-age boundary
        // can round forward by a fraction of a microsecond when a Unix Double
        // is decoded into Foundation's different reference epoch.
        let observedAt = now.addingTimeInterval(1)
        let first = try mcpObject(mcpRuleInventory(directory: root.path, arguments: ["limit": 1], now: observedAt))
        let second = try mcpObject(mcpRuleInventory(directory: root.path, arguments: ["limit": 1, "offset": 1], now: observedAt))
        #expect(first["matching"] as? Int == 2)
        #expect(first["next_offset"] as? Int == 1)
        #expect(second["next_offset"] is NSNull)
        let cliWrittenAt = cliObject["telemetry_written_at"] as? String
        let mcpWrittenAt = first["telemetry_written_at"] as? String
        #expect(cliWrittenAt == mcpWrittenAt)
        #expect(cliObject["telemetry_freshness"] as? String == "current")
        #expect(first["telemetry_freshness"] as? String == "current")
        #expect(second["telemetry_freshness"] as? String == "current")
        let firstRows = try #require(first["rules"] as? [[String: Any]])
        let secondRows = try #require(second["rules"] as? [[String: Any]])
        #expect(firstRows.first?["coverage"] as? String == "quiet")
        #expect(secondRows.first?["coverage"] as? String == "unobserved")
    }
}
