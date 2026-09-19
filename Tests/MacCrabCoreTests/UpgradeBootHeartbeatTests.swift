import Foundation
import Testing
@testable import MacCrabAgentKit

@Suite("Database upgrade boot heartbeat")
struct UpgradeBootHeartbeatTests {
    @Test("Progress is readable before collectors start and cannot override engine identity")
    func progressRemainsUnready() throws {
        let directory = FileManager.default.temporaryDirectory
            .resolvingSymlinksInPath()
            .appendingPathComponent("upgrade-heartbeat-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let startedAt = Date()
        DaemonSetup.writeBootPhase(
            supportDir: directory.path, phase: "upgrading_store", startedAt: startedAt,
            detail: [
                "upgrade_source_events": 128,
                "upgrade_migrated_events": 60,
                "upgrade_remaining_events": 64,
                "upgrade_expired_events": 3,
                "upgrade_corrupt_preserved_events": 1,
                "liveness": true,
                "engine_pid": -1,
            ]
        )
        let path = directory.appendingPathComponent("heartbeat.json")
        let payload = try #require(JSONSerialization.jsonObject(
            with: Data(contentsOf: path)
        ) as? [String: Any])
        #expect(payload["boot_phase"] as? String == "upgrading_store")
        #expect(payload["liveness"] as? Bool == false)
        #expect(payload["engine_pid"] as? Int == DaemonProcessIdentity.current.pid)
        #expect(payload["upgrade_source_events"] as? Int == 128)
        #expect(payload["upgrade_remaining_events"] as? Int == 64)
        #expect(payload["upgrade_corrupt_preserved_events"] as? Int == 1)

        // A subsequent phase replaces the whole progress payload.
        DaemonSetup.writeBootPhase(
            supportDir: directory.path, phase: "stores_ready", startedAt: startedAt
        )
        let next = try #require(JSONSerialization.jsonObject(
            with: Data(contentsOf: path)
        ) as? [String: Any])
        #expect(next["boot_phase"] as? String == "stores_ready")
        #expect(next["upgrade_source_events"] == nil)
        #expect(next["liveness"] as? Bool == false)
    }
}
