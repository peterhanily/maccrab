import Foundation
import Testing
@testable import MacCrabApp

@Suite("Protection readiness and collector presentation")
struct V2ProtectionStatusTests {
    @Test("upgrade telemetry counts processed, expired and preserved rows without claiming protection")
    func upgradeProgress() throws {
        var raw: [String: Any] = [
            "boot_phase": "upgrading_store", "liveness": false,
            "upgrade_source_events": 100, "upgrade_migrated_events": 60,
            "upgrade_remaining_events": 25, "upgrade_expired_events": 10,
            "upgrade_corrupt_preserved_events": 5,
        ]
        let snapshot = V2HeartbeatSnapshot.decode(raw: raw)
        let progress = try #require(snapshot.storeUpgradeProgress)
        #expect(snapshot.readiness == .starting)
        #expect(!snapshot.isReady)
        #expect(progress.processedEvents == 75)
        #expect(progress.migratedEvents == 60)
        #expect(progress.expiredEvents == 10)
        #expect(progress.corruptPreservedEvents == 5)
        raw["boot_phase"] = "ready"
        #expect(V2HeartbeatSnapshot.decode(raw: raw).storeUpgradeProgress == nil)
        raw["boot_phase"] = "upgrading_store"
        raw["upgrade_remaining_events"] = -1
        #expect(V2HeartbeatSnapshot.decode(raw: raw).storeUpgradeProgress == nil)
        raw.removeValue(forKey: "upgrade_remaining_events")
        #expect(V2HeartbeatSnapshot.decode(raw: raw).readiness == .starting)
        raw["upgrade_source_events"] = 5
        raw["upgrade_migrated_events"] = 5
        raw["upgrade_remaining_events"] = 5
        #expect(V2HeartbeatSnapshot.decode(raw: raw).storeUpgradeProgress == nil)
        raw["upgrade_source_events"] = 100
        raw["upgrade_migrated_events"] = 60
        raw["upgrade_remaining_events"] = 25
        raw["upgrade_corrupt_preserved_events"] = 6
        #expect(V2HeartbeatSnapshot.decode(raw: raw).storeUpgradeProgress == nil)
    }

    @Test("the menu bar warns about upgrade, failure, stale and absent engines without AppState")
    func windowlessMenuBarHealth() {
        // An exact Unix second avoids a round-trip rounding the encoded
        // heartbeat a fraction of a microsecond ahead of the test clock.
        let now = Date(timeIntervalSince1970: 1_780_000_000)
        func snapshot(_ phase: String, age: Double = 0) -> V2HeartbeatSnapshot {
            V2HeartbeatSnapshot.decode(raw: [
                "written_at_unix": now.addingTimeInterval(-age).timeIntervalSince1970,
                "engine_pid": 101, "engine_started_at_unix": now.addingTimeInterval(-300).timeIntervalSince1970,
                "engine_version": "1.22.1", "engine_build": "test",
                "boot_phase": phase, "liveness": phase == "ready", "rules_loaded": 10,
                "collector_health": [["name": "ESCollector", "healthy": true,
                                      "state": "healthy", "enabled": true]],
            ])
        }
        #expect(V2MenuBarProtectionStatus.resolve(heartbeat: nil, now: now) == .unavailable)
        var identityless = snapshot("ready")
        identityless.engineIdentity = nil
        #expect(V2MenuBarProtectionStatus.resolve(heartbeat: identityless, now: now) == .unavailable)
        #expect(V2MenuBarProtectionStatus.resolve(heartbeat: snapshot("starting"), now: now) == .starting)
        #expect(V2MenuBarProtectionStatus.resolve(heartbeat: snapshot("upgrading_store"), now: now) == .upgrading)
        #expect(V2MenuBarProtectionStatus.resolve(heartbeat: snapshot("storage_not_ready"), now: now) == .unavailable)
        #expect(V2MenuBarProtectionStatus.resolve(heartbeat: snapshot("ready"), now: now) == .active)
        #expect(V2MenuBarProtectionStatus.resolve(heartbeat: snapshot("ready", age: 121), now: now) == .unavailable)
        #expect(V2MenuBarProtectionStatus.resolve(heartbeat: snapshot("ready", age: -1), now: now) == .unavailable)
        #expect(V2MenuBarProtectionStatus.resolve(heartbeat: snapshot("ready"), additionalDegradation: true, now: now) == .degraded)
        for status in [V2MenuBarProtectionStatus.starting, .upgrading, .degraded, .unavailable] {
            #expect(status.title != V2MenuBarProtectionStatus.active.title)
        }
    }

    @Test("normal boot, storage failure, recovery, and stale transitions stay truthful")
    func readinessTransitions() {
        func status(_ phase: String?, live: Bool? = false, stale: Bool = false) -> V2ProtectionStatus {
            .resolve(providerLive: true, heartbeatPresent: true, heartbeatStale: stale,
                     readiness: .init(bootPhase: phase, liveness: live), degraded: false)
        }
        for phase in ["starting", "upgrading_store", "stores_ready", "rules_loaded", "collectors_started"] {
            #expect(status(phase) == .starting)
        }
        #expect(status("storage_not_ready") == .unavailable)
        #expect(status("unknown_future_failure") == .unavailable)
        #expect(status("ready", live: false) == .starting)
        #expect(status("ready", live: true) == .active)
        #expect(status("ready", live: true, stale: true) == .degraded)
        #expect(status(nil, live: true) == .active)
        #expect(status(nil, live: nil) == .unavailable)
    }

    @Test("a boot heartbeat is visible before the database connects")
    func readinessBeforeDatabaseConnection() {
        #expect(V2ProtectionStatus.resolve(
            providerLive: false, heartbeatPresent: true, heartbeatStale: false,
            readiness: .starting, degraded: true) == .starting)
        #expect(V2ProtectionStatus.resolve(
            providerLive: false, heartbeatPresent: false, heartbeatStale: true,
            readiness: .unavailable, degraded: true) == .inactive)
    }

    @Test("optional disablement is neutral, while enabled sensor failure loses protection")
    func sensorAggregation() {
        let normal = V2CollectorSummary(states: [.healthy, .healthy, .disabled, .disabled])
        #expect(normal.enabledCount == 2)
        #expect(normal.disabledCount == 2)
        #expect(normal.allEnabledHealthy)
        #expect(!V2CollectorSummary(states: [.disabled]).allEnabledHealthy)
        #expect(!V2CollectorSummary(states: []).allEnabledHealthy)
        for sensor in [V2CollectorState.starting, .failed, .stalled] {
            let impaired = V2CollectorSummary(states: [.healthy, sensor, .disabled])
            #expect(!impaired.allEnabledHealthy)
            #expect(V2ProtectionStatus.resolve(
                providerLive: true, heartbeatPresent: true, heartbeatStale: false,
                readiness: .ready, degraded: !impaired.allEnabledHealthy) == .degraded)
        }
    }

    @Test("collector decoder preserves structured status and explains optional disablement")
    func collectorDecoding() throws {
        let snapshot = V2HeartbeatSnapshot.decode(raw: [
            "collector_health": [
                ["name": "FSEventsCollector", "healthy": false, "state": "disabled",
                 "enabled": false, "reason": "Endpoint Security provides file monitoring"],
                ["name": "DNSCollector", "healthy": false, "state": "failed", "enabled": true,
                 "reason": "errors reported", "last_error": "Capture unavailable"],
            ],
        ])
        let disabled = try #require(snapshot.collectors.first)
        #expect(disabled.resolvedState == .disabled)
        #expect(disabled.reason == "Endpoint Security provides file monitoring")
        let failed = try #require(snapshot.collectors.last)
        #expect(failed.resolvedState == .failed)
        #expect(failed.lastError == "Capture unavailable")
        #expect(V2CollectorState.resolve(state: nil, enabled: nil, healthy: false,
            reason: "not started", lastError: nil) == .failed)
        #expect(V2CollectorState.resolve(state: "unknown", enabled: true, healthy: true,
            reason: nil, lastError: nil) == .failed)
    }

    @Test("current startup cannot inherit healthy sensors from the previous process")
    func heartbeatEpochTransitions() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-ui-boot-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let now = Date(timeIntervalSince1970: 1_780_000_000)
        let written = now.timeIntervalSince1970
        func write(_ value: [String: Any], _ name: String) throws {
            try JSONSerialization.data(withJSONObject: value).write(to: directory.appendingPathComponent(name))
        }
        func minimal(_ phase: String, _ live: Bool) -> [String: Any] {
            ["written_at_unix": written, "engine_pid": 42,
             "engine_version": "1.22.0", "engine_build": "fixture",
             "engine_started_at_unix": written - 5, "boot_phase": phase, "liveness": live]
        }
        var rich: [String: Any] = [
            "written_at_unix": written - 10, "engine_pid": 41,
            "engine_version": "1.22.0", "engine_build": "fixture",
            "engine_started_at_unix": written - 100,
            "collector_health": [["name": "DNSCollector", "healthy": true]],
        ]
        try write(rich, "heartbeat_rich.json")
        try write(minimal("starting", false), "heartbeat.json")
        let starting = try #require(V2HeartbeatSnapshot.read(directory: directory.path, now: now))
        #expect(starting.readiness == .starting)
        #expect(starting.collectors.isEmpty)
        #expect(V2MenuBarProtectionStatus.resolve(heartbeat: starting, now: now) == .starting)
        var upgrading = minimal("upgrading_store", false)
        upgrading["upgrade_source_events"] = 100
        upgrading["upgrade_migrated_events"] = 25
        upgrading["upgrade_remaining_events"] = 75
        try write(upgrading, "heartbeat.json")
        let upgrade = try #require(V2HeartbeatSnapshot.read(directory: directory.path, now: now))
        #expect(upgrade.collectors.isEmpty)
        #expect(upgrade.storeUpgradeProgress?.processedEvents == 25)
        #expect(V2MenuBarProtectionStatus.resolve(heartbeat: upgrade, now: now) == .upgrading)
        try write(minimal("storage_not_ready", false), "heartbeat.json")
        #expect(V2HeartbeatSnapshot.read(directory: directory.path, now: now)?.readiness == .unavailable)
        rich["written_at_unix"] = written
        rich["engine_pid"] = 42
        rich["engine_started_at_unix"] = written - 5
        try write(rich, "heartbeat_rich.json")
        try write(minimal("ready", true), "heartbeat.json")
        let ready = try #require(V2HeartbeatSnapshot.read(directory: directory.path, now: now))
        #expect(ready.isReady)
        #expect(ready.collectors.count == 1)
        var unmatched = rich
        unmatched["engine_build"] = "previous-build"
        #expect(!V2HeartbeatPayload.currentRich(unmatched, minimal: minimal("ready", true), now: now))
        unmatched = rich
        unmatched.removeValue(forKey: "engine_pid")
        #expect(!V2HeartbeatPayload.currentRich(unmatched, minimal: minimal("ready", true), now: now))
        unmatched = rich
        unmatched["written_at_unix"] = written + 1
        #expect(!V2HeartbeatPayload.currentRich(unmatched, minimal: minimal("ready", true), now: now))
        #expect(!V2HeartbeatPayload.currentRich(rich, minimal: minimal("ready", true),
                                              now: now.addingTimeInterval(121)))
        #expect(V2HeartbeatSnapshot.read(directory: directory.path,
                                        now: now.addingTimeInterval(301)) == nil)
    }
}
