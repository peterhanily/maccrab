// OCSFMapperTests.swift
// Verifies MacCrab → OCSF 1.x mapping for the four emitted classes.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("OCSF Mapper")
struct OCSFMapperTests {

    // MARK: - Fixtures

    private func makeProcess(
        name: String = "curl",
        executable: String = "/usr/bin/curl",
        pid: Int32 = 1234,
        ppid: Int32 = 1,
        hashes: ProcessHashes? = nil
    ) -> MacCrabCore.ProcessInfo {
        MacCrabCore.ProcessInfo(
            pid: pid,
            ppid: ppid,
            rpid: ppid,
            name: name,
            executable: executable,
            commandLine: "\(executable) https://example.com",
            args: [executable, "https://example.com"],
            workingDirectory: "/tmp",
            userId: 501,
            userName: "alice",
            groupId: 20,
            startTime: Date(timeIntervalSince1970: 1_712_345_600),
            ancestors: [
                ProcessAncestor(pid: 1, executable: "/sbin/launchd", name: "launchd"),
            ],
            hashes: hashes
        )
    }

    private func makeProcessEvent(
        action: String = "exec",
        severity: Severity = .medium,
        hashes: ProcessHashes? = nil
    ) -> Event {
        Event(
            id: UUID(uuidString: "11111111-2222-3333-4444-555555555555")!,
            timestamp: Date(timeIntervalSince1970: 1_712_345_700),
            eventCategory: .process,
            eventType: .start,
            eventAction: action,
            process: makeProcess(hashes: hashes),
            severity: severity
        )
    }

    // MARK: - Process Activity (1007)

    @Test("Process exec event maps to OCSF Process Activity class_uid 1007 / Launch")
    func processExecLaunch() {
        let event = makeProcessEvent(action: "exec")
        guard case .process(let p) = OCSFMapper.mapEvent(event) else {
            Issue.record("Expected .process case")
            return
        }

        #expect(p.classUid == 1007)
        #expect(p.categoryUid == 1)
        #expect(p.className == "Process Activity")
        #expect(p.activityId == 1)               // Launch
        #expect(p.activityName == "Launch")
        #expect(p.typeUid == 1007 * 100 + 1)     // 100701
        #expect(p.process.pid == 1234)
        #expect(p.process.cmdLine?.contains("example.com") == true)
        #expect(p.process.parentProcess?.name == "launchd")
        #expect(p.process.parentProcess?.pid == 1)
    }

    @Test("Process exit event maps to activity_id 2 (Terminate)")
    func processExitTerminate() {
        let event = makeProcessEvent(action: "exit")
        guard case .process(let p) = OCSFMapper.mapEvent(event) else {
            Issue.record("Expected .process case")
            return
        }
        #expect(p.activityId == 2)
        #expect(p.activityName == "Terminate")
        #expect(p.typeUid == 1007 * 100 + 2)
    }

    @Test("ProcessHashes surface as OCSF hashes array")
    func hashesPopulate() {
        let hashes = ProcessHashes(
            sha256: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            cdhash: "0123456789abcdef0123456789abcdef01234567",
            md5: nil
        )
        let event = makeProcessEvent(hashes: hashes)
        guard case .process(let p) = OCSFMapper.mapEvent(event) else {
            Issue.record("Expected .process case")
            return
        }
        let fileHashes = try! #require(p.process.file?.hashes)
        #expect(fileHashes.contains(where: { $0.algorithm == "sha-256" && $0.value == hashes.sha256 }))
        #expect(fileHashes.contains(where: { $0.algorithm == "cdhash" }))
    }

    @Test("Severity maps to OCSF severity_id 1–5")
    func severityMapping() {
        let cases: [(Severity, Int, String)] = [
            (.informational, 1, "Informational"),
            (.low, 2, "Low"),
            (.medium, 3, "Medium"),
            (.high, 4, "High"),
            (.critical, 5, "Critical"),
        ]
        for (input, expectedId, expectedName) in cases {
            let event = makeProcessEvent(severity: input)
            guard case .process(let p) = OCSFMapper.mapEvent(event) else {
                Issue.record("Expected .process case")
                continue
            }
            #expect(p.severityId == expectedId)
            #expect(p.severity == expectedName)
        }
    }

    // MARK: - File Activity (1001)

    @Test("File create maps to activity_id 1 (Create)")
    func fileCreate() {
        let event = Event(
            eventCategory: .file,
            eventType: .creation,
            eventAction: "create",
            process: makeProcess(),
            file: FileInfo(
                path: "/tmp/evil.bin",
                name: "evil.bin",
                directory: "/tmp",
                extension_: "bin",
                size: 4096,
                action: .create
            )
        )
        guard case .file(let f) = OCSFMapper.mapEvent(event) else {
            Issue.record("Expected .file case")
            return
        }
        #expect(f.classUid == 1001)
        #expect(f.activityId == 1)
        #expect(f.file.path == "/tmp/evil.bin")
        #expect(f.file.parentFolder == "/tmp")
        #expect(f.file.size == 4096)
    }

    @Test("File delete maps to activity_id 4 (Delete)")
    func fileDelete() {
        let event = Event(
            eventCategory: .file,
            eventType: .deletion,
            eventAction: "delete",
            process: makeProcess(),
            file: FileInfo(
                path: "/tmp/a", name: "a", directory: "/tmp",
                extension_: nil, size: nil, action: .delete
            )
        )
        guard case .file(let f) = OCSFMapper.mapEvent(event) else {
            Issue.record("Expected .file case")
            return
        }
        #expect(f.activityId == 4)
    }

    // MARK: - Network Activity (4001)

    @Test("Network event maps to OCSF Network Activity with src/dst endpoints")
    func networkActivity() {
        let event = Event(
            eventCategory: .network,
            eventType: .connection,
            eventAction: "connect",
            process: makeProcess(),
            network: NetworkInfo(
                sourceIp: "10.0.0.5",
                sourcePort: 54321,
                destinationIp: "203.0.113.42",
                destinationPort: 443,
                destinationHostname: "example.com",
                direction: .outbound,
                transport: "tcp"
            )
        )
        guard case .network(let n) = OCSFMapper.mapEvent(event) else {
            Issue.record("Expected .network case")
            return
        }
        #expect(n.classUid == 4001)
        #expect(n.srcEndpoint.ip == "10.0.0.5")
        #expect(n.srcEndpoint.port == 54321)
        #expect(n.dstEndpoint.ip == "203.0.113.42")
        #expect(n.dstEndpoint.port == 443)
        #expect(n.dstEndpoint.hostname == "example.com")
        #expect(n.connectionInfo?.protocolName == "tcp")
        #expect(n.connectionInfo?.direction == "outbound")
    }

    // MARK: - Security Finding (2004)

    @Test("Alert maps to Security Finding with MITRE attack")
    func alertSecurityFinding() {
        let alert = Alert(
            id: "alert-99",
            ruleId: "rule.credential_access",
            ruleTitle: "Suspicious keychain access",
            severity: .high,
            eventId: "evt-1",
            processPath: "/tmp/badness",
            processName: "badness",
            description: "Process accessed keychain",
            mitreTactics: "TA0006",
            mitreTechniques: "T1555.001",
            remediationHint: "Investigate credential access"
        )
        let finding = OCSFMapper.mapAlert(alert)

        #expect(finding.classUid == 2004)
        #expect(finding.categoryUid == 2)
        #expect(finding.typeUid == 2004 * 100 + 1)
        #expect(finding.severity == "High")
        #expect(finding.severityId == 4)
        #expect(finding.finding.uid == "alert-99")
        #expect(finding.finding.title == "Suspicious keychain access")
        #expect(finding.attacks?.first?.tactic?.uid == "TA0006")
        #expect(finding.attacks?.first?.technique?.uid == "T1555.001")
        #expect(finding.remediation?.desc == "Investigate credential access")
    }

    @Test("Suppressed alert state maps to id 3 (Suppressed)")
    func suppressedState() {
        let alert = Alert(
            ruleId: "r",
            ruleTitle: "t",
            severity: .low,
            eventId: "e",
            suppressed: true
        )
        let finding = OCSFMapper.mapAlert(alert)
        #expect(finding.stateId == 3)
        #expect(finding.state == "Suppressed")
    }

    @Test("Investigating analyst status maps to state_id 2 (In Progress)")
    func investigatingState() {
        let alert = Alert(
            ruleId: "r",
            ruleTitle: "t",
            severity: .medium,
            eventId: "e",
            analyst: AnalystMetadata(status: .investigating)
        )
        let finding = OCSFMapper.mapAlert(alert)
        #expect(finding.stateId == 2)
        #expect(finding.state == "In Progress")
    }

    // MARK: - JSON serialization

    @Test("OCSF record encodes to snake_case JSON")
    func snakeCaseJSON() throws {
        let event = makeProcessEvent()
        let record = OCSFMapper.mapEvent(event)
        let json = try OCSFMapper.encodeJSON(record)

        #expect(json.contains("\"class_uid\":1007"))
        #expect(json.contains("\"category_uid\":1"))
        #expect(json.contains("\"activity_id\":1"))
        #expect(json.contains("\"type_uid\":100701"))
        #expect(json.contains("\"cmd_line\""))
        #expect(json.contains("\"parent_process\""))
        #expect(!json.contains("\"classUid\""))   // camelCase should be converted
        #expect(!json.contains("\"cmdLine\""))
    }

    @Test("Security finding JSON contains attack and finding blocks")
    func findingJSON() throws {
        let alert = Alert(
            id: "a1",
            ruleId: "r",
            ruleTitle: "Test rule",
            severity: .critical,
            eventId: "e1",
            mitreTactics: "TA0005",
            mitreTechniques: "T1562.001"
        )
        let json = try OCSFMapper.encodeJSON(OCSFMapper.mapAlert(alert))

        #expect(json.contains("\"class_uid\":2004"))
        #expect(json.contains("\"severity\":\"Critical\""))
        #expect(json.contains("\"attacks\""))
        #expect(json.contains("TA0005"))
        #expect(json.contains("T1562.001"))
        #expect(json.contains("\"finding\""))
    }

    @Test("Metadata block contains product name and schema version")
    func metadataBlock() throws {
        let event = makeProcessEvent()
        let json = try OCSFMapper.encodeJSON(OCSFMapper.mapEvent(event))
        #expect(json.contains("\"vendor_name\":\"MacCrab\""))
        #expect(json.contains("\"version\":\"1.3.0\""))
    }
}
