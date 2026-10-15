import Foundation
import Testing
@testable import MacCrabApp
import MacCrabCore

/// Inert scalar heartbeat dictionaries and test-owned temporary files only.
/// No installed heartbeat, process sampling, reader/store or network access.
@Suite("Events reader current engine identity eligibility")
struct EventReaderEngineIdentityTests {
    private let now = Date(timeIntervalSince1970: 1_000)

    private func heartbeat() -> [String: Any] {
        ["boot_phase": "ready", "liveness": true, "written_at_unix": 1_000.0,
         "engine_pid": 41, "engine_started_at_unix": 100.0,
         "engine_version": "fixture", "engine_build": "fixture.1"]
    }

    private func jsonObject(_ raw: [String: Any]) throws -> [String: Any] {
        let bytes = try JSONSerialization.data(withJSONObject: raw)
        let parsed = try JSONSerialization.jsonObject(with: bytes)
        return try #require(parsed as? [String: Any])
    }

    @Test("Fresh ready JSON has exact identity and the 120-second boundary is inclusive")
    func currentIdentityAndFreshnessBoundary() throws {
        let raw = try jsonObject(heartbeat())
        let expected = EngineTelemetryIdentity(pid: 41, startedAtUnix: 100,
                                               version: "fixture", build: "fixture.1")
        #expect(EventReaderEngineIdentity.decode(raw, now: now) == expected)
        #expect(EventReaderEngineIdentity.decode(raw, now: now.addingTimeInterval(120)) == expected)
        #expect(EventReaderEngineIdentity.decode(raw, now: now.addingTimeInterval(120.001)) == nil)
        #expect(EventReaderEngineIdentity.decode(raw, now: now.addingTimeInterval(-0.001)) == nil)
        for invalid in [Double.nan, Double.infinity, -Double.infinity] {
            #expect(EventReaderEngineIdentity.decode(raw, now: Date(timeIntervalSince1970: invalid)) == nil)
        }
    }

    @Test("Missing readiness, liveness and identity fields never establish reusable identity")
    func requiredFieldsAndReadiness() throws {
        let baseline = heartbeat()
        for key in baseline.keys {
            var candidate = baseline
            candidate.removeValue(forKey: key)
            #expect(EventReaderEngineIdentity.decode(candidate, now: now) == nil)
        }
        for phase in ["", "starting", "stopping"] {
            var candidate = baseline
            candidate["boot_phase"] = phase
            #expect(EventReaderEngineIdentity.decode(candidate, now: now) == nil)
        }
        var notLive = baseline
        notLive["liveness"] = false
        #expect(EventReaderEngineIdentity.decode(notLive, now: now) == nil)
        for key in ["engine_version", "engine_build"] {
            for invalid in (["", 1, NSNull()] as [Any]) {
                var candidate = baseline
                candidate[key] = invalid
                #expect(EventReaderEngineIdentity.decode(candidate, now: now) == nil)
            }
        }
    }

    @Test("Boolean numbers and numeric liveness do not cross JSON type boundaries")
    func strictBooleanAndNumberTypes() throws {
        for key in ["written_at_unix", "engine_pid", "engine_started_at_unix"] {
            for invalid in ([true, false, "41", NSNull()] as [Any]) {
                var candidate = heartbeat()
                candidate[key] = invalid
                let parsed = try jsonObject(candidate)
                #expect(EventReaderEngineIdentity.decode(parsed, now: now) == nil)
            }
        }
        for invalid in ([1, 0, "true", NSNull()] as [Any]) {
            var candidate = heartbeat()
            candidate["liveness"] = invalid
            let parsed = try jsonObject(candidate)
            #expect(EventReaderEngineIdentity.decode(parsed, now: now) == nil)
        }
    }

    @Test("Nonfinite times and invalid PID or epoch numbers cannot establish identity")
    func numericValidity() {
        for key in ["written_at_unix", "engine_pid", "engine_started_at_unix"] {
            for invalid in [Double.nan, Double.infinity, -Double.infinity] {
                var candidate = heartbeat()
                candidate[key] = invalid
                #expect(EventReaderEngineIdentity.decode(candidate, now: now) == nil)
            }
        }
        for invalidPID in [-1.0, 0, 1.25, Double.greatestFiniteMagnitude] {
            var candidate = heartbeat()
            candidate["engine_pid"] = invalidPID
            #expect(EventReaderEngineIdentity.decode(candidate, now: now) == nil)
        }
        for invalidStart in [-1.0, 0, 1_001] {
            var candidate = heartbeat()
            candidate["engine_started_at_unix"] = invalidStart
            #expect(EventReaderEngineIdentity.decode(candidate, now: now) == nil)
        }
    }

    @Test("A restart or artifact change changes the exact epoch while freshness-only writes do not")
    func restartAndArtifactIdentity() throws {
        let initial = EventReaderEngineIdentity.decode(heartbeat(), now: now)
        let baseline = try #require(initial)
        let changes: [(String, Any)] = [("engine_pid", 42), ("engine_started_at_unix", 101.0),
                                       ("engine_version", "fixture-next"), ("engine_build", "fixture.2")]
        for (key, value) in changes {
            var candidate = heartbeat()
            candidate[key] = value
            let changed = EventReaderEngineIdentity.decode(candidate, now: now)
            let identity = try #require(changed)
            #expect(identity != baseline)
        }
        var newer = heartbeat()
        newer["written_at_unix"] = 1_001.0
        #expect(EventReaderEngineIdentity.decode(newer, now: now.addingTimeInterval(1)) == baseline)
    }

    @Test("Task-owned control reads honor 64KiB exactly and do not cache old identity")
    func boundedFileAndFreshRead() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-reader-identity-\(UUID())")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("heartbeat.json")
        #expect(EventReaderEngineIdentity.read(directory: root.path, now: now) == nil)
        let bytes = try JSONSerialization.data(withJSONObject: heartbeat(), options: [.sortedKeys])
        let limit = 64 * 1_024
        try #require(bytes.count < limit)
        let atLimit = bytes + Data(repeating: 0x20, count: limit - bytes.count)
        try atLimit.write(to: file)
        let initialRead = EventReaderEngineIdentity.read(directory: root.path, now: now)
        let initial = try #require(initialRead)
        try (atLimit + Data([0x20])).write(to: file)
        #expect(EventReaderEngineIdentity.read(directory: root.path, now: now) == nil)
        var nextEpoch = heartbeat()
        nextEpoch["engine_started_at_unix"] = 101.0
        let replacement = try JSONSerialization.data(withJSONObject: nextEpoch, options: [.sortedKeys])
        try replacement.write(to: file)
        let replacedRead = EventReaderEngineIdentity.read(directory: root.path, now: now)
        let replaced = try #require(replacedRead)
        #expect(replaced != initial && replaced.startedAtUnix == 101)
        try Data("[]".utf8).write(to: file)
        #expect(EventReaderEngineIdentity.read(directory: root.path, now: now) == nil)
    }
}
