import Foundation
import Testing
@testable import MacCrabApp

@Suite("Rule reload readiness and queue semantics")
struct V2DaemonControlReloadTests {
    @Test("an inbox without a fresh ready engine cannot report a queued reload")
    func reloadRequiresReadyEngine() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-reload-\(UUID())")
        let inbox = directory.appendingPathComponent("inbox")
        try FileManager.default.createDirectory(at: inbox, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let source = V2EngineSource(directory: directory.path)
        let now = Date(timeIntervalSince1970: 1_780_000_000)
        func write(phase: String, age: Double = 0, identified: Bool = true) throws {
            var raw: [String: Any] = [
                "written_at_unix": now.addingTimeInterval(-age).timeIntervalSince1970,
                "boot_phase": phase, "liveness": phase == "ready",
            ]
            if identified {
                raw["engine_pid"] = 101
                raw["engine_started_at_unix"] = now.addingTimeInterval(-300).timeIntervalSince1970
                raw["engine_version"] = "1.22.1"
                raw["engine_build"] = "test"
            }
            try JSONSerialization.data(withJSONObject: raw)
                .write(to: directory.appendingPathComponent("heartbeat.json"), options: .atomic)
        }
        #expect(!V2DaemonControl.reloadDetectionRules(source: source, now: now))
        for phase in ["starting", "upgrading_store", "storage_not_ready", "unknown"] {
            try write(phase: phase)
            #expect(!V2DaemonControl.reloadDetectionRules(source: source, now: now))
        }
        for age in [121.0, -1.0] {
            try write(phase: "ready", age: age)
            #expect(!V2DaemonControl.reloadDetectionRules(source: source, now: now))
        }
        try write(phase: "ready", identified: false)
        #expect(!V2DaemonControl.reloadDetectionRules(source: source, now: now))
        #expect(try FileManager.default.contentsOfDirectory(atPath: inbox.path).isEmpty)
        try write(phase: "ready")
        #expect(V2DaemonControl.reloadDetectionRules(source: source, now: now))
        let requests = try FileManager.default.contentsOfDirectory(atPath: inbox.path)
        #expect(requests.count == 1)
        #expect(requests.first?.hasPrefix("reload-rules-") == true)
        #expect(requests.first?.hasSuffix(".json") == true)
    }
}
