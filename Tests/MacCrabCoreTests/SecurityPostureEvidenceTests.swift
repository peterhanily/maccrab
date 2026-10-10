import Foundation
import Testing
@testable import MacCrabCore

@Suite("Security posture evidence truthfulness")
struct SecurityPostureEvidenceTests {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)

    private func heartbeat(ready: Bool = true) -> [String: Any] {
        [
            "engine_pid": 1234,
            "engine_started_at_unix": now.timeIntervalSince1970 - 300,
            "engine_version": "fixture-version",
            "engine_build": "fixture-build",
            "written_at_unix": now.timeIntervalSince1970 - 1,
            "boot_phase": ready ? "ready" : "upgrading_store",
            "es_mode": "native client",
            "es_sensor_degraded": false,
            "es_client_split_degraded": false,
            "sysext_has_fda": true,
        ]
    }

    private func data(_ object: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }

    private func expectUnknown(_ factor: SecurityScorer.Factor) {
        #expect(factor.status == "unknown")
        #expect(factor.score == 0)
        #expect(factor.maxScore > 0)
    }

    @Test("Missing, failed and unsupported screen-lock observations never pass")
    func unknownScreenLock() {
        let observations: [String?] = [nil, "", "  \n", "2", "true", "unavailable"]
        for raw in observations {
            let factor = SecurityScorer.screenLockFactor(rawPreference: raw)
            expectUnknown(factor)
            #expect(factor.detail.contains("unknown"))
        }
    }

    @Test("Known screen-lock preference states remain distinct and do not attest delay")
    func knownScreenLock() {
        let enabled = SecurityScorer.screenLockFactor(rawPreference: "1\n")
        #expect(enabled.status == "pass")
        #expect(enabled.score == enabled.maxScore)
        #expect(enabled.detail.contains("delay not assessed"))
        let disabled = SecurityScorer.screenLockFactor(rawPreference: "0")
        #expect(disabled.status == "warn")
        #expect(disabled.score == 0)
        #expect(disabled.detail.contains("disabled"))
    }

    @Test("XProtect installation does not establish definition currency")
    func xprotectCurrencyUnknown() {
        for installed in [true, false, nil] as [Bool?] {
            let factor = SecurityScorer.xprotectFactor(installed: installed)
            expectUnknown(factor)
            #expect(!factor.detail.contains("up to date"))
        }
        #expect(SecurityScorer.xprotectFactor(installed: true).detail.contains("not verified"))
    }

    @Test("Fresh matching ready native-sensor telemetry can earn readiness credit")
    func freshEngineReadiness() throws {
        let bytes = try data(heartbeat())
        let factor = SecurityScorer.engineReadinessFactor(lite: bytes, rich: bytes, now: now)
        #expect(factor.status == "pass")
        #expect(factor.score == 7)
        #expect(factor.detail.contains("reports ready"))
        #expect(factor.detail.contains("efficacy is not assessed"))
    }

    @Test("Stale, future, unidentified and malformed liveness remains unknown")
    func invalidLiveness() throws {
        let rich = try data(heartbeat())
        for offset in [-121.0, 1.0] {
            var lite = heartbeat()
            lite["written_at_unix"] = now.timeIntervalSince1970 + offset
            expectUnknown(SecurityScorer.engineReadinessFactor(lite: try data(lite), rich: rich, now: now))
        }
        for key in ["engine_pid", "engine_started_at_unix", "engine_version", "engine_build", "written_at_unix", "boot_phase"] {
            var lite = heartbeat()
            lite.removeValue(forKey: key)
            expectUnknown(SecurityScorer.engineReadinessFactor(lite: try data(lite), rich: rich, now: now))
        }
        for key in ["engine_version", "engine_build"] {
            var lite = heartbeat()
            lite[key] = ""
            expectUnknown(SecurityScorer.engineReadinessFactor(lite: try data(lite), rich: rich, now: now))
        }
        var impossibleStart = heartbeat()
        impossibleStart["engine_started_at_unix"] = now.timeIntervalSince1970 + 1
        expectUnknown(SecurityScorer.engineReadinessFactor(lite: try data(impossibleStart), rich: rich, now: now))
        expectUnknown(SecurityScorer.engineReadinessFactor(lite: Data("not-json".utf8), rich: rich, now: now))
    }

    @Test("A pre-ready engine cannot inherit a healthy readiness verdict")
    func preReadyEngine() throws {
        let factor = SecurityScorer.engineReadinessFactor(
            lite: try data(heartbeat(ready: false)), rich: try data(heartbeat()), now: now
        )
        #expect(factor.status == "warn")
        #expect(factor.score == 0)
    }

    @Test("Missing, stale, mismatched and incomplete rich health never passes")
    func unknownSensorCoverage() throws {
        let lite = try data(heartbeat())
        expectUnknown(SecurityScorer.engineReadinessFactor(lite: lite, rich: nil, now: now))
        expectUnknown(SecurityScorer.engineReadinessFactor(lite: lite, rich: Data("[]".utf8), now: now))
        for key in ["es_mode", "es_sensor_degraded", "es_client_split_degraded", "sysext_has_fda"] {
            var rich = heartbeat()
            rich.removeValue(forKey: key)
            expectUnknown(SecurityScorer.engineReadinessFactor(lite: lite, rich: try data(rich), now: now))
        }
        for key in ["engine_version", "engine_build"] {
            var rich = heartbeat()
            rich[key] = "other-epoch"
            expectUnknown(SecurityScorer.engineReadinessFactor(lite: lite, rich: try data(rich), now: now))
        }
        for (key, value) in [
            ("engine_pid", 4321.0),
            ("engine_started_at_unix", now.timeIntervalSince1970 - 400),
            ("written_at_unix", now.timeIntervalSince1970 - 121),
            ("written_at_unix", now.timeIntervalSince1970 + 1),
        ] {
            var rich = heartbeat()
            rich[key] = value
            expectUnknown(SecurityScorer.engineReadinessFactor(lite: lite, rich: try data(rich), now: now))
        }
        var wrongType = heartbeat()
        wrongType["es_sensor_degraded"] = "false"
        expectUnknown(SecurityScorer.engineReadinessFactor(lite: lite, rich: try data(wrongType), now: now))
    }

    @Test("Fresh degraded, fallback or FDA-denied sensor states earn no readiness credit")
    func knownDegradedSensor() throws {
        let lite = try data(heartbeat())
        for key in ["es_sensor_degraded", "es_client_split_degraded", "sysext_has_fda"] {
            var rich = heartbeat()
            rich[key] = key != "sysext_has_fda"
            let factor = SecurityScorer.engineReadinessFactor(lite: lite, rich: try data(rich), now: now)
            #expect(factor.status == "warn")
            #expect(factor.score == 0)
        }
        var fallback = heartbeat()
        fallback["es_mode"] = "eslogger"
        let factor = SecurityScorer.engineReadinessFactor(lite: lite, rich: try data(fallback), now: now)
        #expect(factor.status == "warn")
        #expect(factor.score == 0)
    }

    @Test("Unreadable system telemetry cannot fall through to a healthy dev store")
    func unreadableSystemDoesNotFallback() throws {
        let healthy = try data(heartbeat())
        let factor = SecurityScorer.engineReadinessFactor(
            directories: ["/fixture/system", "/fixture/user"], now: now
        ) { path, _ in
            if path.hasPrefix("/fixture/system/") { throw CocoaError(.fileReadNoPermission) }
            return healthy
        }
        expectUnknown(factor)
    }

    @Test("A stale selected system epoch cannot borrow healthy user telemetry")
    func staleSystemDoesNotFallback() throws {
        var stale = heartbeat()
        stale["written_at_unix"] = now.timeIntervalSince1970 - 121
        let staleBytes = try data(stale)
        let healthy = try data(heartbeat())
        let factor = SecurityScorer.engineReadinessFactor(
            directories: ["/fixture/system", "/fixture/user"], now: now
        ) { path, _ in
            path.hasPrefix("/fixture/system/") ? staleBytes : healthy
        }
        expectUnknown(factor)
    }

    @Test("Missing telemetry is unknown and reader byte budgets stay explicit")
    func missingEngineAndReaderBudgets() throws {
        let absent = SecurityScorer.engineReadinessFactor(directories: ["/fixture"], now: now) { _, limit in
            #expect(limit == 64 * 1024)
            return nil
        }
        expectUnknown(absent)
        let healthy = try data(heartbeat())
        let present = SecurityScorer.engineReadinessFactor(directories: ["/fixture"], now: now) { path, limit in
            #expect(limit == (path.hasSuffix("heartbeat_rich.json") ? 4 * 1024 * 1024 : 64 * 1024))
            return healthy
        }
        #expect(present.status == "pass")
    }

    @Test("Production bounded reader assesses a private fixture without writing or opening stores")
    func readOnlyHeartbeatFixture() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-posture-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let bytes = try data(heartbeat())
        let names = ["heartbeat.json", "heartbeat_rich.json"]
        for name in names { try bytes.write(to: directory.appendingPathComponent(name)) }
        let factor = SecurityScorer.engineReadinessFactor(directories: [directory.path], now: now)
        #expect(factor.status == "pass")
        #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted() == names.sorted())
        for name in names { #expect(try Data(contentsOf: directory.appendingPathComponent(name)) == bytes) }
    }
}
