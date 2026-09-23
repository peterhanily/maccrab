// RuntimeStatusReadinessTests.swift
// The strict post-boot coverage check reads `es_client_split_degraded` and
// `es_sensor_degraded` out of heartbeat_rich.json as literal booleans right
// after `boot_phase == "ready"`. The engine writes that file only from its
// rich-heartbeat timer, which starts AFTER `ready` is published, so until the
// first tick the file is whatever the previous engine left behind (or absent).
// These tests pin the reader contract that keeps that window honest: a rich
// heartbeat is this engine's health only when its engine identity matches the
// liveness heartbeat, and once it does, both coverage flags decode as concrete
// booleans rather than honest-absent nil.

import Foundation
import Testing
@testable import MacCrabCore

@Suite("Runtime status: ES coverage flags across boot readiness")
struct RuntimeStatusReadinessTests {

    private func directory() throws -> URL {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-readiness-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: path, withIntermediateDirectories: true)
        return path
    }

    private func write(_ object: [String: Any], as name: String, in directory: URL) throws {
        let data = try JSONSerialization.data(withJSONObject: object)
        try data.write(to: directory.appendingPathComponent(name))
    }

    private func identity(pid: Int, startedAt: Date) -> [String: Any] {
        [
            "engine_pid": pid,
            "engine_started_at_unix": startedAt.timeIntervalSince1970,
            "engine_version": "1.22.1",
            "engine_build": "fixture",
        ]
    }

    /// The boot-phase liveness heartbeat `DaemonSetup.writeBootPhase` publishes
    /// during boot and the liveness timer keeps publishing after `ready`.
    private func lite(pid: Int, startedAt: Date, writtenAt: Date, phase: String) -> [String: Any] {
        identity(pid: pid, startedAt: startedAt).merging([
            "schema_version": 4,
            "written_at_unix": writtenAt.timeIntervalSince1970,
            "boot_phase": phase,
            "liveness": phase == "ready",
        ]) { current, _ in current }
    }

    /// The rich heartbeat's ES coverage surface as the rich timer writes it:
    /// both flags are always present as booleans, never null.
    private func rich(pid: Int, startedAt: Date, writtenAt: Date,
                      sensorDegraded: Bool, splitDegraded: Bool) -> [String: Any] {
        identity(pid: pid, startedAt: startedAt).merging([
            "schema_version": 5,
            "written_at_unix": writtenAt.timeIntervalSince1970,
            "es_mode": "native client",
            "es_sensor_degraded": sensorDegraded,
            "es_sensor_degraded_severity": sensorDegraded ? "high" : "",
            "es_sensor_degraded_detail": sensorDegraded ? "ES sensor degraded (fixture)" : "",
            "es_client_split_degraded": splitDegraded,
            "collector_health": [[
                "name": "ESCollector",
                "enabled": true,
                "healthy": true,
                "state": "healthy",
                "reason": "native callbacks active",
            ]],
        ]) { current, _ in current }
    }

    @Test("pre-ready: the previous engine's rich heartbeat is never this engine's health")
    func preReadyDoesNotInheritPredecessorFlags() async throws {
        let path = try directory()
        defer { try? FileManager.default.removeItem(at: path) }
        let now = Date(timeIntervalSince1970: 1_790_091_330)
        // The candidate is mid-upgrade; its liveness heartbeat is fresh.
        let candidateStart = now.addingTimeInterval(-8)
        try write(lite(pid: 1349, startedAt: candidateStart, writtenAt: now.addingTimeInterval(-1),
                       phase: "upgrading_store"),
                  as: "heartbeat.json", in: path)
        // The predecessor's last rich tick is still on disk — and still fresh
        // enough to pass an age check — carrying an advisory flag that fired
        // in ITS epoch.
        try write(rich(pid: 1200, startedAt: now.addingTimeInterval(-600),
                       writtenAt: now.addingTimeInterval(-20),
                       sensorDegraded: true, splitDegraded: false),
                  as: "heartbeat_rich.json", in: path)

        let document = try await RuntimeStatusDocument.read(directory: path.path, now: now)
        #expect(document.liveness == "fresh")
        #expect(document.bootPhase == "upgrading_store")
        #expect(document.engineIdentity?.pid == 1349)
        #expect(document.currentHealth == nil,
                "a rich heartbeat from another engine identity is not current health, however fresh")
    }

    @Test("ready: the engine's own rich heartbeat carries both coverage flags as concrete booleans")
    func readyCarriesConcreteCoverageFlags() async throws {
        let path = try directory()
        defer { try? FileManager.default.removeItem(at: path) }
        let now = Date(timeIntervalSince1970: 1_790_091_470)
        let candidateStart = now.addingTimeInterval(-150)
        try write(lite(pid: 1349, startedAt: candidateStart, writtenAt: now.addingTimeInterval(-3),
                       phase: "ready"),
                  as: "heartbeat.json", in: path)
        try write(rich(pid: 1349, startedAt: candidateStart, writtenAt: now.addingTimeInterval(-2),
                       sensorDegraded: false, splitDegraded: false),
                  as: "heartbeat_rich.json", in: path)

        let document = try await RuntimeStatusDocument.read(directory: path.path, now: now)
        #expect(document.liveness == "fresh")
        #expect(document.bootPhase == "ready")
        let health = try #require(document.currentHealth)
        // Concrete `false`, not honest-absent nil: the writer always emits both.
        #expect(health.esSensorDegraded == false)
        #expect(health.esClientSplitDegraded == false)
        #expect(health.esSensorDegradedDetail == "")
        let es = try #require(health.collectorHealth?.first { $0.name == "ESCollector" })
        #expect(es.healthy)
    }
}
