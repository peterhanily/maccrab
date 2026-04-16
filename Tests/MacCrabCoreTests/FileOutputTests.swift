// FileOutputTests.swift
// NDJSON writer + size/age rotation + retention.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("FileOutput")
struct FileOutputTests {

    private func makeTempPath() -> String {
        NSTemporaryDirectory() + "maccrab_fileoutput_\(UUID().uuidString)/alerts.jsonl"
    }

    private func cleanup(_ path: String) {
        let dir = (path as NSString).deletingLastPathComponent
        try? FileManager.default.removeItem(atPath: dir)
    }

    private func alertAndEvent() -> (Alert, Event) {
        let proc = MacCrabCore.ProcessInfo(
            pid: 1234, ppid: 1, rpid: 1,
            name: "curl", executable: "/usr/bin/curl",
            commandLine: "curl https://example.com",
            args: ["/usr/bin/curl", "https://example.com"],
            workingDirectory: "/tmp",
            userId: 501, userName: "alice", groupId: 20,
            startTime: Date()
        )
        let event = Event(
            eventCategory: .process, eventType: .start,
            eventAction: "exec", process: proc
        )
        let alert = Alert(
            id: "alert-x", ruleId: "rule.test", ruleTitle: "Test",
            severity: .high, eventId: event.id.uuidString,
            processPath: "/usr/bin/curl", processName: "curl",
            description: "Test alert",
            mitreTactics: "TA0005", mitreTechniques: "T1562.001"
        )
        return (alert, event)
    }

    // MARK: - Write + format

    @Test("OCSF format writes one JSON object per line with class_uid 2004")
    func ocsfOutput() async throws {
        let path = makeTempPath()
        defer { cleanup(path) }

        let out = FileOutput(path: path, format: .ocsf)
        let (a, e) = alertAndEvent()
        await out.send(alert: a, event: e)
        await out.send(alert: a, event: e)
        await out.flush()

        let content = try String(contentsOfFile: path, encoding: .utf8)
        let lines = content.split(separator: "\n").map(String.init)
        #expect(lines.count == 2)
        for line in lines {
            #expect(line.contains("\"class_uid\":2004"))
            #expect(line.contains("\"category_uid\":2"))
        }
    }

    @Test("Native format writes MacCrab envelope with alert + event")
    func nativeOutput() async throws {
        let path = makeTempPath()
        defer { cleanup(path) }

        let out = FileOutput(path: path, format: .native)
        let (a, e) = alertAndEvent()
        await out.send(alert: a, event: e)
        await out.flush()

        let content = try String(contentsOfFile: path, encoding: .utf8)
        #expect(content.contains("\"schema\":\"maccrab.alert.v1\""))
        #expect(content.contains("\"rule_id\":\"rule.test\""))
        #expect(content.contains("\"severity\":\"high\""))
        #expect(content.contains("\"mitre_tactics\":[\"TA0005\"]"))
    }

    @Test("Parent directory is created on first write")
    func createsParentDir() async throws {
        let nestedPath = NSTemporaryDirectory() + "maccrab_fo_\(UUID().uuidString)/sub/deep/alerts.jsonl"
        defer { try? FileManager.default.removeItem(
            atPath: NSTemporaryDirectory() + "maccrab_fo_")
        }

        let out = FileOutput(path: nestedPath)
        let (a, e) = alertAndEvent()
        await out.send(alert: a, event: e)
        await out.flush()

        #expect(FileManager.default.fileExists(atPath: nestedPath))
    }

    @Test("File permissions are 0o600 (owner-only)")
    func filePermissions() async throws {
        let path = makeTempPath()
        defer { cleanup(path) }

        let out = FileOutput(path: path)
        let (a, e) = alertAndEvent()
        await out.send(alert: a, event: e)
        await out.flush()

        let attrs = try FileManager.default.attributesOfItem(atPath: path)
        let perms = (attrs[.posixPermissions] as? NSNumber)?.intValue ?? 0
        #expect(perms == 0o600, "Expected 0o600, got \(String(perms, radix: 8))")
    }

    // MARK: - Stats

    @Test("Stats track sent + lastSentAt")
    func statsIncrement() async {
        let path = makeTempPath()
        defer { cleanup(path) }

        let out = FileOutput(path: path)
        let (a, e) = alertAndEvent()
        await out.send(alert: a, event: e)
        await out.send(alert: a, event: e)
        await out.send(alert: a, event: e)

        let s = await out.outputStats()
        #expect(s.sent == 3)
        #expect(s.failed == 0)
        #expect(s.lastSentAt != nil)
    }

    // MARK: - Rotation

    @Test("Rotates when size cap exceeded and creates .1 archive")
    func sizeRotation() async throws {
        let path = makeTempPath()
        defer { cleanup(path) }

        // Tiny cap (256 bytes) — one OCSF line (~1-2 KB) triggers rotation.
        let out = FileOutput(path: path, maxBytes: 256)
        let (a, e) = alertAndEvent()
        await out.send(alert: a, event: e)
        await out.send(alert: a, event: e)
        await out.flush()

        #expect(FileManager.default.fileExists(atPath: path + ".1"),
                "Expected rotated archive at \(path).1")
        #expect(FileManager.default.fileExists(atPath: path))
    }

    @Test("Retains only maxArchives rotated files")
    func retention() async throws {
        let path = makeTempPath()
        defer { cleanup(path) }

        // Aggressive: rotate after every write, keep only 2 archives.
        let out = FileOutput(path: path, maxBytes: 64, maxArchives: 2)
        let (a, e) = alertAndEvent()

        // Four writes → three rotations → four archives with retention=2
        // means .1, .2 survive; .3 / older are dropped.
        for _ in 0..<5 {
            await out.send(alert: a, event: e)
        }
        await out.flush()

        let fm = FileManager.default
        #expect(fm.fileExists(atPath: path),       "live file should exist")
        #expect(fm.fileExists(atPath: path + ".1"), ".1 should exist")
        #expect(fm.fileExists(atPath: path + ".2"), ".2 should exist")
        #expect(!fm.fileExists(atPath: path + ".3"), ".3 should have fallen off")
    }

    // MARK: - Output protocol conformance

    @Test("Conforms to Output protocol with name 'file'")
    func protocolConformance() async {
        let path = makeTempPath()
        defer { cleanup(path) }

        let out: any Output = FileOutput(path: path)
        #expect(out.name == "file")
        let h = await out.health()
        #expect(h == .unknown) // no sends yet
    }

    @Test("Health is .healthy after successful sends")
    func healthReportsSuccess() async {
        let path = makeTempPath()
        defer { cleanup(path) }

        let out = FileOutput(path: path)
        let (a, e) = alertAndEvent()
        await out.send(alert: a, event: e)

        let h = await out.health()
        #expect(h == .healthy)
    }
}
