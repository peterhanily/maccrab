import Foundation
import Testing
@testable import MacCrabCore
@testable import MacCrabAgentKit

@Suite("Pre-ingestion failure support report")
struct PreIngestionFailureReportTests {
    @Test("typed capacity failure publishes a current report and unavailable heartbeat without raw diagnostics")
    func typedCapacityFailure() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-startup-report-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let detail = "private-fixture-marker /Users/fixture/private-event.json"
        let started = Date()
        do {
            try DaemonBootstrap.failPreIngestionStorage(
                supportDir: directory.path, startedAt: started,
                component: "EventStore", reason: detail,
                failure: SQLitePersistentStoreAdmissionError.footprintLimit(
                    footprintBytes: 399, reserveBytes: 32, maxFootprintBytes: 420
                )
            )
        } catch let failure as DaemonBootstrapError {
            #expect(failure == .preIngestionStorageNotReady(
                component: "EventStore", reason: detail
            ))
        }
        let reportURL = directory.appendingPathComponent("last_crash.json")
        // pass-c: actual user-context read of the support file published by
        // the same production boundary, including its dashboard-readable mode.
        #expect(FileManager.default.isReadableFile(atPath: reportURL.path))
        let bytes = try Data(contentsOf: reportURL)
        #expect(bytes.count < 2048)
        #expect(!String(decoding: bytes, as: UTF8.self).contains(detail))
        let report = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        #expect(report["schema_version"] as? Int == 2)
        #expect(report["database"] as? String == "events.db")
        #expect(report["reason"] as? String == "storage_pressure")
        #expect(report["preservation_outcome"] as? String == "unverified")
        let occurred = try #require(report["occurred_at_unix"] as? Double)
        #expect(occurred >= started.timeIntervalSince1970)
        let attributes = try FileManager.default.attributesOfItem(atPath: reportURL.path)
        #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o644)
        let heartbeat = try #require(JSONSerialization.jsonObject(with:
            Data(contentsOf: directory.appendingPathComponent("heartbeat.json"))) as? [String: Any])
        #expect(heartbeat["boot_phase"] as? String == "storage_not_ready")
        #expect(heartbeat["liveness"] as? Bool == false)
        #expect(report["engine_pid"] as? Int == heartbeat["engine_pid"] as? Int)
        #expect(report["engine_started_at_unix"] as? Double
            == heartbeat["engine_started_at_unix"] as? Double)
        #expect(Set(try FileManager.default.contentsOfDirectory(atPath: directory.path))
            == ["heartbeat.json", "last_crash.json"])
    }

    @Test("generic readiness failures replace stale reports without inferring a cause or exposing component text")
    func genericFailureRemainsUnclassified() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-startup-report-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let reportURL = directory.appendingPathComponent("last_crash.json")
        try Data("{\"reason\":\"integrity_failure\"}".utf8).write(to: reportURL)
        let detail = "storage_pressure integrity_failure private-fixture-marker"
        do {
            try DaemonBootstrap.failPreIngestionStorage(
                supportDir: directory.path, startedAt: Date(),
                component: "/private/custom-component", reason: detail
            )
        } catch let failure as DaemonBootstrapError {
            #expect(failure == .preIngestionStorageNotReady(
                component: "/private/custom-component", reason: detail
            ))
        }
        let bytes = try Data(contentsOf: reportURL)
        let text = String(decoding: bytes, as: UTF8.self)
        #expect(!text.contains(detail))
        #expect(!text.contains("/private/custom-component"))
        let report = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        #expect(report["database"] as? String == "unknown")
        #expect(report["reason"] as? String == "initialization_failed")
        #expect(report["preservation_outcome"] as? String == "unverified")
    }
}
