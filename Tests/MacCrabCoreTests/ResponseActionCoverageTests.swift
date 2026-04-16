// ResponseActionCoverageTests.swift
// Fills the gaps the pre-existing EngineTests ResponseEngineTests left
// uncovered: blockNetwork, script, and escalateNotification. The first
// two run their real implementations (pfctl fails gracefully without
// root; script uses /bin/echo in a temp dir). The third is verified at
// the config-load layer so we don't pop real system notifications mid-
// test run.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("Response action coverage")
struct ResponseActionCoverageTests {

    // MARK: - Helpers

    private func makeAlert(
        ruleId: String = "test.rule",
        severity: Severity = .high,
        processName: String = "curl"
    ) -> Alert {
        Alert(
            ruleId: ruleId, ruleTitle: "Coverage rule",
            severity: severity, eventId: UUID().uuidString,
            processPath: "/usr/bin/\(processName)", processName: processName,
            description: "test", mitreTactics: "TA0011", mitreTechniques: "T1071"
        )
    }

    private func makeNetworkEvent(destinationIp: String = "203.0.113.99") -> Event {
        let proc = MacCrabCore.ProcessInfo(
            pid: 9999, ppid: 1, rpid: 1,
            name: "curl", executable: "/usr/bin/curl",
            commandLine: "/usr/bin/curl https://\(destinationIp)",
            args: [], workingDirectory: "/tmp",
            userId: 501, userName: "alice", groupId: 20,
            startTime: Date()
        )
        let net = NetworkInfo(
            sourceIp: "10.0.0.5", sourcePort: 54321,
            destinationIp: destinationIp, destinationPort: 443,
            destinationHostname: "canary.invalid",
            direction: .outbound, transport: "tcp"
        )
        return Event(
            eventCategory: .network, eventType: .connection,
            eventAction: "connect", process: proc, network: net
        )
    }

    private func makeProcEvent() -> Event {
        let proc = MacCrabCore.ProcessInfo(
            pid: 9998, ppid: 1, rpid: 1,
            name: "bash", executable: "/bin/bash",
            commandLine: "/bin/bash -c whoami",
            args: [], workingDirectory: "/tmp",
            userId: 501, userName: "alice", groupId: 20,
            startTime: Date()
        )
        return Event(
            eventCategory: .process, eventType: .start,
            eventAction: "exec", process: proc
        )
    }

    private func tempDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-rac-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    // MARK: - blockNetwork

    @Test("blockNetwork logs an attempt keyed on the event's destination IP")
    func blockNetworkLogs() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let engine = ResponseEngine(
            quarantineDir: dir.appendingPathComponent("quarantine").path
        )
        await engine.setActions(forRule: "test.rule", actions: [
            ResponseActionConfig(
                action: .blockNetwork,
                minimumSeverity: .high,
                blockDurationSeconds: 60
            )
        ])

        let alert = makeAlert()
        let event = makeNetworkEvent(destinationIp: "203.0.113.42")
        await engine.execute(alert: alert, event: event)

        let log = await engine.getExecutionLog()
        #expect(log.count == 1)
        #expect(log[0].action == .blockNetwork)
        #expect(log[0].target == "203.0.113.42")
        // Success is environment-dependent (pfctl needs root) — what we
        // care about is that the attempt was logged at all.
    }

    @Test("blockNetwork with no destination IP is recorded as failed")
    func blockNetworkMissingIP() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let engine = ResponseEngine(
            quarantineDir: dir.appendingPathComponent("quarantine").path
        )
        await engine.setActions(forRule: "test.rule", actions: [
            ResponseActionConfig(action: .blockNetwork, minimumSeverity: .high)
        ])

        // Process event has no network block — destination IP is absent.
        let alert = makeAlert()
        let event = makeProcEvent()
        await engine.execute(alert: alert, event: event)

        let log = await engine.getExecutionLog()
        #expect(log.count == 1)
        #expect(log[0].action == .blockNetwork)
        #expect(log[0].target == "unknown")
        #expect(log[0].success == false)
    }

    // MARK: - script

    @Test("script action executes the configured script path")
    func scriptRuns() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        // Marker file proves the script actually executed.
        let markerPath = dir.appendingPathComponent("marker.txt").path
        let scriptPath = dir.appendingPathComponent("test_script.sh").path
        let script = "#!/bin/sh\necho \"$MACCRAB_ALERT_ID\" > \(markerPath)\n"
        try script.write(toFile: scriptPath, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o755], ofItemAtPath: scriptPath
        )

        let engine = ResponseEngine(
            quarantineDir: dir.appendingPathComponent("quarantine").path
        )
        await engine.setActions(forRule: "test.rule", actions: [
            ResponseActionConfig(
                action: .script,
                scriptPath: scriptPath,
                minimumSeverity: .high
            )
        ])

        let alert = makeAlert()
        let event = makeProcEvent()
        await engine.execute(alert: alert, event: event)

        let log = await engine.getExecutionLog()
        #expect(log.count == 1)
        #expect(log[0].action == .script)
        #expect(log[0].target == scriptPath)
        #expect(log[0].success == true)

        // Marker file exists → the script body ran.
        #expect(FileManager.default.fileExists(atPath: markerPath))
    }

    @Test("script action without scriptPath is skipped with a warning")
    func scriptMissingPath() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let engine = ResponseEngine(
            quarantineDir: dir.appendingPathComponent("quarantine").path
        )
        await engine.setActions(forRule: "test.rule", actions: [
            ResponseActionConfig(action: .script, scriptPath: nil)
        ])

        let alert = makeAlert()
        let event = makeProcEvent()
        await engine.execute(alert: alert, event: event)

        // No log entry: the engine `continue`s past a script with no path.
        let log = await engine.getExecutionLog()
        #expect(log.isEmpty)
    }

    @Test("script action fails when script is non-executable")
    func scriptNonExecutable() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let scriptPath = dir.appendingPathComponent("nonexec.sh").path
        try "echo hi".write(toFile: scriptPath, atomically: true, encoding: .utf8)
        // Deliberately NOT setting executable bit.

        let engine = ResponseEngine(
            quarantineDir: dir.appendingPathComponent("quarantine").path
        )
        await engine.setActions(forRule: "test.rule", actions: [
            ResponseActionConfig(action: .script, scriptPath: scriptPath)
        ])

        let alert = makeAlert()
        let event = makeProcEvent()
        await engine.execute(alert: alert, event: event)

        let log = await engine.getExecutionLog()
        #expect(log.count == 1)
        #expect(log[0].success == false)
    }

    // MARK: - escalateNotification (config-only)

    /// We intentionally don't run the full osascript path — firing real
    /// macOS notifications during tests is hostile to developer flow.
    /// Here we verify that escalateNotification is a recognizable action
    /// type that can be loaded from JSON and selected by rule.
    @Test("escalateNotification action round-trips through JSON config")
    func escalateConfigLoads() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let configPath = dir.appendingPathComponent("actions.json").path
        let json = """
        {
            "rules": {
                "test.rule": [
                    {"action": "escalateNotification", "minimumSeverity": "critical", "requireConfirmation": false}
                ]
            }
        }
        """
        try json.write(toFile: configPath, atomically: true, encoding: .utf8)

        let engine = ResponseEngine(
            quarantineDir: dir.appendingPathComponent("quarantine").path
        )
        try await engine.loadConfig(from: configPath)

        // Drive with a .high alert — below the .critical threshold, so
        // the action is skipped and no notification fires.
        let alert = makeAlert(severity: .high)
        let event = makeProcEvent()
        await engine.execute(alert: alert, event: event)

        let log = await engine.getExecutionLog()
        #expect(log.isEmpty, "escalate is critical-only; .high alert should be skipped")
    }

    // MARK: - All action types are valid JSON values

    @Test("Every ResponseActionType round-trips through Codable")
    func allActionTypesCodable() throws {
        let kinds: [ResponseActionType] = [
            .log, .notify, .kill, .quarantine, .script,
            .blockNetwork, .escalateNotification,
        ]
        for kind in kinds {
            let config = ResponseActionConfig(action: kind, minimumSeverity: .medium)
            let data = try JSONEncoder().encode(config)
            let decoded = try JSONDecoder().decode(ResponseActionConfig.self, from: data)
            #expect(decoded.action == kind)
        }
    }
}
