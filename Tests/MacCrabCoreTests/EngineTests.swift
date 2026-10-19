// EngineTests.swift
// Unit tests for ResponseEngine, IncidentGrouper, and CertTransparency.

import Testing
import Foundation
@testable import MacCrabCore

// MARK: - Local Test Helpers

/// Minimal event builder for engine tests (mirrors the one in MacCrabCoreTests.swift).
private func makeTestEvent(
    category: EventCategory = .process,
    type: EventType = .creation,
    action: String = "exec",
    processName: String = "test",
    processPath: String = "/usr/bin/test",
    commandLine: String = "/usr/bin/test",
    pid: Int32 = 100,
    ppid: Int32 = 1,
    parentPath: String = "/sbin/launchd",
    file: FileInfo? = nil,
    network: NetworkInfo? = nil
) -> Event {
    let process = ProcessInfo(
        pid: pid,
        ppid: ppid,
        rpid: ppid,
        name: processName,
        executable: processPath,
        commandLine: commandLine,
        args: commandLine.split(separator: " ").map(String.init),
        workingDirectory: "/",
        userId: 501,
        userName: "testuser",
        groupId: 20,
        startTime: Date(),
        exitCode: nil,
        codeSignature: nil,
        ancestors: [ProcessAncestor(pid: ppid, executable: parentPath, name: URL(fileURLWithPath: parentPath).lastPathComponent)],
        architecture: "arm64",
        isPlatformBinary: false
    )
    return Event(
        eventCategory: category,
        eventType: type,
        eventAction: action,
        process: process,
        file: file,
        network: network,
        tcc: nil
    )
}

/// Minimal alert builder for engine tests.
private func makeTestAlert(
    ruleId: String = "test-rule-001",
    ruleTitle: String = "Test Rule",
    severity: Severity = .high,
    processName: String = "curl"
) -> Alert {
    Alert(
        ruleId: ruleId,
        ruleTitle: ruleTitle,
        severity: severity,
        eventId: UUID().uuidString,
        processPath: "/usr/bin/\(processName)",
        processName: processName,
        description: "Test alert",
        mitreTactics: "attack.execution",
        mitreTechniques: "attack.t1059.004",
        suppressed: false
    )
}

// MARK: - Response Engine Tests

@Suite("Response Engine")
struct ResponseEngineTests {

    @Test("Config loads from JSON file")
    func configLoadsFromJSON() async throws {
        let tmpDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        let configPath = tmpDir.appendingPathComponent("actions.json").path
        let json = """
        {
            "defaults": [
                {"action": "log", "minimumSeverity": "low", "requireConfirmation": false}
            ],
            "rules": {
                "rule-abc": [
                    {"action": "notify", "minimumSeverity": "high", "requireConfirmation": false}
                ]
            }
        }
        """
        try json.write(toFile: configPath, atomically: true, encoding: .utf8)

        let recorder = ResponseActionTestRecorder()
        let engine = makeInertResponseEngine(recording: recorder)
        try await engine.loadConfig(from: configPath)

        // Verify real file decoding and routing, without consulting an admin's
        // live actions.json or allowing any action to address a host resource.
        let alert = makeTestAlert(ruleId: "rule-abc", severity: .high)
        let event = makeTestEvent()
        await engine.execute(alert: alert, event: event)

        let log = await engine.getExecutionLog()
        #expect(log.count == 1)
        #expect(log[0].action == .notify)
        #expect(log[0].ruleId == "rule-abc")
        #expect(log[0].target == "fixture:notify")
        #expect(await recorder.invocations == [.init(
            action: .notify, eventID: event.id, processID: event.process.pid,
            ruleID: alert.ruleId)])
    }

    @Test("Owned user snapshot wins only when newer than the explicit config", arguments: [-1.0, 0.0, 1.0])
    func configSelectsNewestSnapshot(userAgeOffset: TimeInterval) async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-action-selection-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let system = dir.appendingPathComponent("system.json")
        let user = dir.appendingPathComponent("user.json")
        try #"{"defaults":[{"action":"notify","minimumSeverity":"low"}]}"#
            .write(to: system, atomically: true, encoding: .utf8)
        try #"{"defaults":[{"action":"kill","minimumSeverity":"low"}]}"#
            .write(to: user, atomically: true, encoding: .utf8)
        let baseDate = Date(timeIntervalSince1970: 1_700_000_000)
        try FileManager.default.setAttributes([.modificationDate: baseDate], ofItemAtPath: system.path)
        try FileManager.default.setAttributes(
            [.modificationDate: baseDate.addingTimeInterval(userAgeOffset)], ofItemAtPath: user.path)
        let snapshot = try ownedActionsSnapshot(user)
        let recorder = ResponseActionTestRecorder()
        let engine = makeInertResponseEngine(recording: recorder, userConfigSnapshotProvider: { snapshot })
        try await engine.loadConfig(from: system.path)
        let event = makeTestEvent(pid: 42)
        let alert = makeTestAlert()
        await engine.execute(alert: alert, event: event)

        let expected: ResponseActionType = userAgeOffset > 0 ? .kill : .notify
        #expect(await recorder.invocations == [.init(
            action: expected, eventID: event.id, processID: event.process.pid,
            ruleID: alert.ruleId)])
        let log = await engine.getExecutionLog()
        #expect(log.count == 1)
        #expect(log.first?.target == "fixture:\(expected.rawValue)")
    }

    @Test("Missing config sources do not discover live policy or discard the existing policy",
          arguments: [true, false], [true, false])
    func configMissingSnapshots(systemPresent: Bool, userPresent: Bool) async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-action-absence-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let system = dir.appendingPathComponent("system.json")
        let user = dir.appendingPathComponent("user.json")
        if systemPresent {
            try #"{"defaults":[{"action":"notify","minimumSeverity":"low"}]}"#
                .write(to: system, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes(
                [.modificationDate: Date(timeIntervalSince1970: 1_700_000_000)], ofItemAtPath: system.path)
        }
        let userSnapshot: BoundedRegularFileReader.Snapshot?
        if userPresent {
            try #"{"defaults":[{"action":"kill","minimumSeverity":"low"}]}"#
                .write(to: user, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes(
                [.modificationDate: Date(timeIntervalSince1970: 1_700_000_001)], ofItemAtPath: user.path)
            userSnapshot = try ownedActionsSnapshot(user)
        } else {
            userSnapshot = nil
        }
        let recorder = ResponseActionTestRecorder()
        let engine = makeInertResponseEngine(recording: recorder, userConfigSnapshotProvider: { userSnapshot })
        await engine.setDefaultActions([ResponseActionConfig(action: .escalateNotification, minimumSeverity: .low)])
        try await engine.loadConfig(from: system.path)
        let event = makeTestEvent(pid: 42)
        let alert = makeTestAlert()
        await engine.execute(alert: alert, event: event)
        let expected: ResponseActionType = userPresent ? .kill : (systemPresent ? .notify : .escalateNotification)
        #expect(await recorder.invocations == [.init(
            action: expected, eventID: event.id, processID: event.process.pid,
            ruleID: alert.ruleId)])
    }

    @Test("Malformed newest policy is rejected without partially replacing active actions")
    func malformedNewestConfigKeepsExistingPolicy() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-action-malformed-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let system = dir.appendingPathComponent("system.json")
        let user = dir.appendingPathComponent("user.json")
        try #"{"defaults":[{"action":"kill"}]}"#
            .write(to: system, atomically: true, encoding: .utf8)
        try "{broken".write(to: user, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.modificationDate: Date(timeIntervalSince1970: 1_700_000_000)], ofItemAtPath: system.path)
        try FileManager.default.setAttributes(
            [.modificationDate: Date(timeIntervalSince1970: 1_700_000_001)], ofItemAtPath: user.path)
        let snapshot = try ownedActionsSnapshot(user)
        let recorder = ResponseActionTestRecorder()
        let engine = makeInertResponseEngine(recording: recorder, userConfigSnapshotProvider: { snapshot })
        await engine.setDefaultActions([ResponseActionConfig(action: .notify, minimumSeverity: .low)])
        await #expect(throws: DecodingError.self) { try await engine.loadConfig(from: system.path) }
        let event = makeTestEvent(pid: 42)
        let alert = makeTestAlert()
        await engine.execute(alert: alert, event: event)
        #expect(await recorder.invocations == [.init(
            action: .notify, eventID: event.id, processID: event.process.pid,
            ruleID: alert.ruleId)])
    }

    private func ownedActionsSnapshot(_ path: URL) throws -> BoundedRegularFileReader.Snapshot {
        let outcome = BoundedRegularFileReader.readOutcome(
            at: path.path, maximumBytes: ResponseEngine.maxActionConfigBytes)
        guard case .success(let snapshot) = outcome else {
            Issue.record("owned action fixture was rejected: \(outcome)")
            throw CocoaError(.fileReadUnknown)
        }
        return snapshot
    }

    @Test("Default actions apply when no rule-specific config")
    func defaultActionsApply() async throws {
        let tmpDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        let engine = ResponseEngine(quarantineDir: tmpDir.appendingPathComponent("quarantine").path)

        // Set defaults: a notify action at medium severity.
        await engine.setDefaultActions([
            ResponseActionConfig(action: .notify, minimumSeverity: .medium)
        ])

        // Fire with an unmatched rule ID — should fall through to defaults.
        let alert = makeTestAlert(ruleId: "no-such-rule", severity: .high)
        let event = makeTestEvent()
        await engine.execute(alert: alert, event: event)

        let log = await engine.getExecutionLog()
        #expect(log.count == 1)
        #expect(log[0].action == .notify)
        #expect(log[0].ruleId == "no-such-rule")
    }

    @Test("Execution log tracks actions")
    func executionLogTracksActions() async throws {
        let tmpDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        let engine = ResponseEngine(quarantineDir: tmpDir.appendingPathComponent("quarantine").path)
        await engine.setActions(forRule: "log-test", actions: [
            ResponseActionConfig(action: .notify, minimumSeverity: .low)
        ])

        let alert = makeTestAlert(ruleId: "log-test", severity: .high)
        let event = makeTestEvent()
        await engine.execute(alert: alert, event: event)

        let log = await engine.getExecutionLog()
        #expect(!log.isEmpty)
        let entry = log[0]
        #expect(entry.ruleId == "log-test")
        #expect(entry.action == .notify)
        #expect(entry.success == true)
        #expect(entry.target == "notification")
        // Timestamp should be recent
        #expect(entry.timestamp.timeIntervalSinceNow > -5)
    }

    @Test("Kill policy routes the exact event and records the executor outcome", arguments: [true, false])
    func killActionTargetsCorrectPID(success: Bool) async throws {
        let recorder = ResponseActionTestRecorder(success: success)
        let engine = makeInertResponseEngine(recording: recorder)
        await engine.setActions(forRule: "kill-test", actions: [
            ResponseActionConfig(action: .kill, minimumSeverity: .high)
        ])

        // PID is fixture data, never a host target. Admission and audit must
        // preserve the event identity for both executor success and failure.
        let alert = makeTestAlert(ruleId: "kill-test", severity: .critical)
        let event = makeTestEvent(pid: 42)
        await engine.execute(alert: alert, event: event)

        let log = await engine.getExecutionLog()
        #expect(log.count == 1)
        #expect(log[0].action == .kill)
        #expect(log[0].target == "fixture:kill")
        #expect(log[0].ruleId == "kill-test")
        #expect(log[0].success == success)
        #expect(await recorder.invocations == [.init(
            action: .kill, eventID: event.id, processID: event.process.pid,
            ruleID: alert.ruleId)])
    }

    @Test("Quarantine moves file to quarantine dir")
    func quarantineMovesFile() async throws {
        // Use /tmp/ rather than FileManager.temporaryDirectory (which on
        // macOS returns /var/folders/...): the v1.6.19.1
        // SafeQuarantinePathValidator correctly rejects /var/folders/ as a
        // protected per-user runtime location, so the test fixture must
        // live somewhere the validator allows.
        let tmpDir = URL(fileURLWithPath: "/tmp/maccrab-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        let quarantineDir = tmpDir.appendingPathComponent("quarantine").path
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        // Create a temp file to quarantine.
        let suspiciousFile = tmpDir.appendingPathComponent("malware.sh").path
        try "#!/bin/bash\necho pwned".write(toFile: suspiciousFile, atomically: true, encoding: .utf8)
        #expect(FileManager.default.fileExists(atPath: suspiciousFile))

        let engine = ResponseEngine(quarantineDir: quarantineDir)
        await engine.setActions(forRule: "quarantine-test", actions: [
            ResponseActionConfig(action: .quarantine, minimumSeverity: .medium)
        ])

        // Build an event whose file path points at our temp file.
        let fileInfo = FileInfo(
            path: suspiciousFile,
            name: "malware.sh",
            directory: tmpDir.path,
            extension_: "sh",
            size: 24,
            action: .create
        )
        let alert = makeTestAlert(ruleId: "quarantine-test", severity: .high)
        let event = makeTestEvent(file: fileInfo)
        await engine.execute(alert: alert, event: event)

        // Original file should be gone.
        #expect(!FileManager.default.fileExists(atPath: suspiciousFile))

        // Quarantine directory should contain the moved file and its sidecar.
        let quarantineContents = try FileManager.default.contentsOfDirectory(atPath: quarantineDir)
        let dataFiles = quarantineContents.filter { !$0.hasSuffix(".json") }
        let sidecarFiles = quarantineContents.filter { $0.hasSuffix(".json") }
        #expect(dataFiles.count >= 1)
        #expect(sidecarFiles.count >= 1)

        // Verify sidecar has expected metadata.
        let sidecarPath = (quarantineDir as NSString).appendingPathComponent(sidecarFiles[0])
        let sidecarData = try Data(contentsOf: URL(fileURLWithPath: sidecarPath))
        let metadata = try JSONSerialization.jsonObject(with: sidecarData) as? [String: Any]
        #expect(metadata?["original_path"] as? String == suspiciousFile)
        #expect(metadata?["rule_id"] as? String == "quarantine-test")

        // Verify execution log.
        let log = await engine.getExecutionLog()
        #expect(log.count == 1)
        #expect(log[0].action == .quarantine)
        #expect(log[0].success == true)
    }
}

// MARK: - Incident Grouper Tests

@Suite("Incident Grouper")
struct IncidentGrouperTests {

    @Test("Groups related alerts into single incident")
    func groupsRelatedAlerts() async {
        let grouper = IncidentGrouper(correlationWindow: 300, staleWindow: 600)
        let now = Date()

        // Two alerts from the same process within the correlation window.
        let id1 = await grouper.processAlert(
            alertId: "alert-1",
            timestamp: now,
            ruleTitle: "Suspicious exec",
            severity: .medium,
            processPath: "/usr/bin/curl",
            parentPath: "/bin/bash",
            tactics: ["execution"]
        )

        let id2 = await grouper.processAlert(
            alertId: "alert-2",
            timestamp: now.addingTimeInterval(30), // 30 seconds later
            ruleTitle: "Data exfiltration",
            severity: .high,
            processPath: "/usr/bin/curl",
            parentPath: "/bin/bash",
            tactics: ["exfiltration"]
        )

        // Both should be in the same incident.
        #expect(id1 == id2)

        let incident = await grouper.incident(id: id1)
        #expect(incident != nil)
        #expect(incident!.alerts.count == 2)
        #expect(incident!.tactics.contains("execution"))
        #expect(incident!.tactics.contains("exfiltration"))
    }

    @Test("Separates unrelated alerts into different incidents")
    func separatesUnrelatedAlerts() async {
        let grouper = IncidentGrouper(correlationWindow: 300, staleWindow: 600)
        let now = Date()

        let id1 = await grouper.processAlert(
            alertId: "alert-a",
            timestamp: now,
            ruleTitle: "Curl activity",
            severity: .medium,
            processPath: "/usr/bin/curl",
            parentPath: "/bin/bash",
            tactics: ["execution"]
        )

        // Different process, different parent — should be a separate incident.
        let id2 = await grouper.processAlert(
            alertId: "alert-b",
            timestamp: now.addingTimeInterval(10),
            ruleTitle: "Python activity",
            severity: .medium,
            processPath: "/usr/bin/python3",
            parentPath: "/usr/local/bin/cron",
            tactics: ["persistence"]
        )

        #expect(id1 != id2)

        let incidents = await grouper.allIncidents()
        #expect(incidents.count == 2)
    }

    @Test("Stale incidents are cleaned up")
    func staleIncidentsCleanedUp() async {
        // Use a tiny stale window so we can test without real delays.
        let grouper = IncidentGrouper(correlationWindow: 5, staleWindow: 1)

        // Create an incident in the past (well beyond the stale window).
        let pastTime = Date().addingTimeInterval(-10)
        let id = await grouper.processAlert(
            alertId: "stale-alert",
            timestamp: pastTime,
            ruleTitle: "Old alert",
            severity: .low,
            processPath: "/usr/bin/old",
            parentPath: nil,
            tactics: ["discovery"]
        )

        // Verify the incident was created.
        let incidentBeforeSweep = await grouper.incident(id: id)
        #expect(incidentBeforeSweep != nil)

        // activeIncidents() calls sweepStale() internally.
        let active = await grouper.activeIncidents()
        #expect(active.isEmpty)

        // The incident should now be marked stale.
        let stats = await grouper.stats()
        #expect(stats.active == 0)
        #expect(stats.stale == 1)
    }

    @Test("Returns incident summary with alert count")
    func incidentSummary() async {
        let grouper = IncidentGrouper(correlationWindow: 300, staleWindow: 600)
        let now = Date()

        await grouper.processAlert(
            alertId: "sum-1",
            timestamp: now,
            ruleTitle: "Recon scan",
            severity: .medium,
            processPath: "/usr/bin/nmap",
            parentPath: "/bin/bash",
            tactics: ["reconnaissance"]
        )

        await grouper.processAlert(
            alertId: "sum-2",
            timestamp: now.addingTimeInterval(20),
            ruleTitle: "Privilege escalation",
            severity: .high,
            processPath: "/usr/bin/nmap",
            parentPath: "/bin/bash",
            tactics: ["privilege-escalation"]
        )

        let incidents = await grouper.activeIncidents()
        #expect(incidents.count == 1)

        let inc = incidents[0]
        #expect(inc.alerts.count == 2)
        #expect(inc.severity == .high) // Escalated from medium
        #expect(inc.processTree.contains("/usr/bin/nmap"))
        #expect(inc.processTree.contains("/bin/bash"))
        #expect(inc.tactics.count == 2)

        // Verify narrative contains meaningful info
        let narrative = inc.narrative
        #expect(narrative.contains("2 alerts"))
    }
}

// MARK: - Certificate Transparency Tests

@Suite("Certificate Transparency")
struct CertTransparencyTests {

    @Test("Known safe domains pass check")
    func knownSafeDomainsPass() async {
        // The CT checker with no watch patterns should not flag well-known
        // domains via the typosquat detector.
        let ct = CertTransparency(watchPatterns: [])
        let (isSuspicious1, _) = await ct.isTyposquat("google.com")
        let (isSuspicious2, _) = await ct.isTyposquat("apple.com")
        #expect(isSuspicious1 == false)
        #expect(isSuspicious2 == false)
    }

    @Test("Typosquatting detection flags similar domains")
    func typosquattingDetection() async {
        let ct = CertTransparency(watchPatterns: ["google", "apple"])

        // "gooogle" is edit distance 1 from "google"
        let (flagged1, reason1) = await ct.isTyposquat("gooogle.com")
        #expect(flagged1 == true)
        #expect(reason1 != nil)

        // "appple" is edit distance 1 from "apple"
        let (flagged2, reason2) = await ct.isTyposquat("appple.com")
        #expect(flagged2 == true)
        #expect(reason2 != nil)

        // Exact matches should NOT be flagged as typosquats.
        let (flaggedExact, _) = await ct.isTyposquat("google.com")
        #expect(flaggedExact == false)

        // Homoglyph: "g00g1e" (zeros for o's, 1 for l) — edit distance 3
        // so only the homoglyph normalizer catches it.
        let (flaggedHomoglyph, reasonH) = await ct.isTyposquat("g00g1e.com")
        #expect(flaggedHomoglyph == true)
        #expect(reasonH?.contains("Homoglyph") == true)
    }

    @Test("Check returns nil for unchecked domains")
    func checkReturnsNilForUncheckedDomains() async {
        // With no network access and no cache, checkDomain should either
        // return nil (network failure) or a non-suspicious result.
        // We use a domain that won't resolve via crt.sh — a .invalid TLD.
        let ct = CertTransparency(watchPatterns: [])
        let result = await ct.checkDomain("this-domain-does-not-exist.invalid")

        // The crt.sh query will fail or return empty — either nil or
        // a result with certificateCount == 0 and isSuspicious == false.
        if let result = result {
            #expect(result.certificateCount == 0)
            #expect(result.isSuspicious == false)
        }
        // nil is also acceptable — the method returns nil on network error.
    }
}
