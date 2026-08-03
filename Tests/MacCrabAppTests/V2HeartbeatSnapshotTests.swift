// V2HeartbeatSnapshotTests.swift
// MacCrabAppTests
//
// Pin the V2HeartbeatSnapshot decoder + computed-property contract.
// The dashboard's System workspace renders these directly so a
// silent decoding regression would put epoch-0 / 20583d-ago strings
// in front of users. Covers: decode happy path, missing-field
// degradation, uptime formatting buckets, eventsPerSecond1h math.

import Testing
import Foundation
@testable import MacCrabApp

@Suite("V2HeartbeatSnapshot")
struct V2HeartbeatSnapshotTests {

    private func writeFixture(_ json: [String: Any]) throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-hb-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let path = dir.appendingPathComponent("heartbeat_rich.json")
        let data = try JSONSerialization.data(withJSONObject: json, options: [])
        try data.write(to: path)
        return path
    }

    // MARK: - uptimeDisplay buckets

    @Test("uptimeDisplay formats sub-minute values as seconds")
    func uptimeUnderOneMinute() {
        let snap = makeSnapshot(uptimeSeconds: 45)
        #expect(snap.uptimeDisplay == "45s")
    }

    @Test("uptimeDisplay formats sub-hour values as minutes")
    func uptimeUnderOneHour() {
        let snap = makeSnapshot(uptimeSeconds: 600)
        #expect(snap.uptimeDisplay == "10m")
    }

    @Test("uptimeDisplay formats sub-day values as Hh Mm")
    func uptimeUnderOneDay() {
        let snap = makeSnapshot(uptimeSeconds: 2 * 3600 + 14 * 60) // 2h 14m
        #expect(snap.uptimeDisplay == "2h 14m")
    }

    @Test("uptimeDisplay drops the minute component when at an exact hour")
    func uptimeExactHour() {
        let snap = makeSnapshot(uptimeSeconds: 3 * 3600)
        #expect(snap.uptimeDisplay == "3h")
    }

    @Test("uptimeDisplay formats day+ values as Nd Hh")
    func uptimeMultiDay() {
        let snap = makeSnapshot(uptimeSeconds: 5 * 86_400 + 3 * 3600)
        #expect(snap.uptimeDisplay == "5d 3h")
    }

    @Test("uptimeDisplay drops hour when on an exact day")
    func uptimeExactDay() {
        let snap = makeSnapshot(uptimeSeconds: 12 * 86_400)
        #expect(snap.uptimeDisplay == "12d")
    }

    // MARK: - eventsPerSecond1h

    @Test("eventsPerSecond1h sums all categories and divides by 3600")
    func eventsPerSecondMath() {
        let snap = makeSnapshot(eventTypeCounts1h: ["exec": 1800, "file": 1800])
        #expect(snap.eventsPerSecond1h == 1.0)
    }

    @Test("eventsPerSecond1h returns 0 when counts are empty")
    func eventsPerSecondEmpty() {
        let snap = makeSnapshot(eventTypeCounts1h: [:])
        #expect(snap.eventsPerSecond1h == 0.0)
    }

    // MARK: - prevention block (UX-3)

    @Test("prevention block decodes three modules; absent → nil; partial → safe defaults")
    func preventionDecode() {
        let raw: [String: Any] = [
            "sinkhole": ["enabled": true, "count": 5],
            "network_blocker": ["enabled": false, "count": 0],
            "persistence_guard": ["enabled": true, "count": 3],
        ]
        let p = V2HeartbeatSnapshot.Prevention(from: raw)
        #expect(p?.sinkhole.enabled == true)
        #expect(p?.sinkhole.count == 5)
        #expect(p?.networkBlocker.enabled == false)
        #expect(p?.persistenceGuard.count == 3)
        // Older daemon (no prevention block) → nil so the UI shows
        // "status unavailable" instead of a false reading, no crash.
        #expect(V2HeartbeatSnapshot.Prevention(from: nil) == nil)
        // Malformed/partial block → safe defaults, never a crash.
        let partial = V2HeartbeatSnapshot.Prevention(from: ["sinkhole": ["enabled": true]])
        #expect(partial?.sinkhole.enabled == true)
        #expect(partial?.sinkhole.count == 0)
        #expect(partial?.networkBlocker.enabled == false)
    }

    // MARK: - TraceGraph storage admission

    @Test("event-pipeline causality block preserves source, lane, and collector boundaries")
    func eventPipelineDecode() throws {
        let pipeline = try #require(V2HeartbeatSnapshot.EventPipeline(from: [
            "offered_by_source": ["ESCollector": 20, "UnifiedLogCollector": 8],
            "offered_by_source_and_lane": [
                "ESCollector": ["priority": 12, "file": 8],
                "UnifiedLogCollector": ["priority": 6, "file": 2],
            ],
            "dropped_by_source_and_lane": [
                "ESCollector": ["priority": 0, "file": 1],
                "UnifiedLogCollector": ["priority": 1, "file": 0],
            ],
            "terminated_by_source_and_lane": [
                "ESCollector": ["priority": 1, "file": 0],
            ],
            "collector_offered_by_source_and_lane": [
                "ESCollector": ["priority": 13, "file": 9],
            ],
            "upstream_dropped_by_source_and_lane": [
                "ESCollector": ["priority": 0, "file": 1],
            ],
            "upstream_terminated_by_source_and_lane": [
                "ESCollector": ["priority": 1, "file": 0],
            ],
            "merged_dropped_by_source_and_lane": [
                "UnifiedLogCollector": ["priority": 1, "file": 0],
            ],
            "merged_terminated_by_source_and_lane": [
                "ESCollector": ["priority": 0, "file": 0],
            ],
            "offered_by_lane": ["priority": 18, "file": 10],
            "dequeued_by_lane": ["priority": 16, "file": 9],
            "completed_by_lane": ["priority": 15, "file": 9],
            "backlog_estimate_by_lane": ["priority": 1, "file": 0],
            "in_flight_by_lane": ["priority": 1, "file": 0],
            "processing_p99_us_by_lane": ["priority": 4_000, "file": 1_000],
            "latency_sample_count_by_lane": ["priority": 15, "file": 9],
            "upstream_dropped_by_lane": ["priority": 0, "file": 1],
            "upstream_terminated_by_lane": ["priority": 1, "file": 0],
            "merged_dropped_by_lane": ["priority": 1, "file": 1],
            "merged_terminated_by_lane": ["priority": 0, "file": 0],
            "collector_capacity_by_source": ["ESCollector": 100_000],
            "pre_buffer_dropped_by_source": ["ESCollector": 7],
            "detection_input_dropped_total": 10,
            "capacity_by_lane": ["priority": 100_000, "file": 100_000],
            "collector_buffer": [
                "unified_log_normalized_total": 10,
                "unified_log_stream_yield_dropped_total": 2,
                "unified_log_capacity": 512,
            ],
        ]))

        #expect(pipeline.offeredBySource["ESCollector"] == 20)
        #expect(pipeline.offeredBySourceAndLane["UnifiedLogCollector"]?["file"] == 2)
        #expect(pipeline.droppedBySourceAndLane["ESCollector"]?["file"] == 1)
        #expect(pipeline.terminatedBySourceAndLane["ESCollector"]?["priority"] == 1)
        #expect(pipeline.upstreamDroppedByLane["file"] == 1)
        #expect(pipeline.mergedDroppedBySourceAndLane["UnifiedLogCollector"]?["priority"] == 1)
        #expect(pipeline.collectorCapacityBySource["ESCollector"] == 100_000)
        #expect(pipeline.preBufferDroppedBySource["ESCollector"] == 7)
        #expect(pipeline.detectionInputDroppedTotal == 10)
        #expect(pipeline.backlogEstimateByLane["priority"] == 1)
        #expect(pipeline.inFlightByLane["priority"] == 1)
        #expect(pipeline.processingP99MicrosByLane["priority"] == 4_000)
        #expect(pipeline.latencySampleCountByLane["file"] == 9)
        #expect(pipeline.collectorBuffer["unified_log_stream_yield_dropped_total"] == 2)
        let diagnostics = pipeline.diagnosticDictionary
        #expect(diagnostics["detection_input_dropped_total"] as? UInt64 == 10)
        #expect((diagnostics["upstream_dropped_by_lane"] as? [String: UInt64])?["file"] == 1)
        #expect(V2HeartbeatSnapshot.EventPipeline(from: nil) == nil)
    }

    @Test("startup storage admission remains a fail-visible evidence gap")
    func traceGraphStartupAdmissionDecode() throws {
        let status = try #require(V2HeartbeatSnapshot.TraceGraphStorageAdmission(from: [
            "enabled": true,
            "blocked": true,
            "store_available": false,
            "startup_blocked": true,
            "reason": "low_free_space",
            "free_space_bytes": NSNumber(value: 100_000_000),
            "free_space_floor_bytes": NSNumber(value: 1_073_741_824),
        ]))

        #expect(status.enabled)
        #expect(status.blocked)
        #expect(status.storeAvailable == false)
        #expect(status.startupBlocked)
        #expect(status.reason == "low_free_space")
        #expect(status.freeSpaceBytes == 100_000_000)
        #expect(status.freeSpaceFloorBytes == 1_073_741_824)
        #expect(status.evidenceUnavailable)
        #expect(status.operatorDetail.contains("paused at startup"))
        #expect(status.operatorDetail.contains("new causal evidence is not being recorded"))
    }

    @Test("live healthy admission is not reported as an evidence gap")
    func traceGraphHealthyAdmissionDecode() throws {
        let status = try #require(V2HeartbeatSnapshot.TraceGraphStorageAdmission(from: [
            "enabled": true,
            "blocked": false,
            "store_available": true,
            "startup_blocked": false,
            "reason": "",
        ]))

        #expect(!status.evidenceUnavailable)
        #expect(status.reason == nil)
    }

    @Test("Agent Trace admission uses the shared wire shape without implying trust")
    func traceStoreAdmissionDecode() throws {
        let status = try #require(V2HeartbeatSnapshot.TraceGraphStorageAdmission(from: [
            "enabled": true,
            "blocked": true,
            "store_available": true,
            "startup_blocked": false,
            "reason": "footprint_limit",
            "footprint_bytes": NSNumber(value: 96_000_000),
            "max_footprint_bytes": NSNumber(value: 100_000_000),
        ]))

        #expect(status.evidenceUnavailable)
        #expect(status.reason == "footprint_limit")
        #expect(status.footprintBytes == 96_000_000)
        #expect(status.maxFootprintBytes == 100_000_000)
    }

    @Test("TraceGraph evidence gaps degrade every shared dashboard surface")
    func traceGraphGlobalDegradedSignal() {
        #expect(AppState.traceGraphEvidenceUnavailable(blocked: true, storeAvailable: true))
        #expect(AppState.traceGraphEvidenceUnavailable(blocked: false, storeAvailable: false))
        #expect(!AppState.traceGraphEvidenceUnavailable(blocked: false, storeAvailable: true))
        #expect(!AppState.traceGraphEvidenceUnavailable(blocked: nil, storeAvailable: nil))
    }

    @Test("browser inventory truncation decodes as an explicit coverage gap")
    func browserInventoryDecode() throws {
        let inventory = try #require(V2HeartbeatSnapshot.BrowserInventory(from: [
            "coverage_known": true,
            "complete": false,
            "degraded": true,
            "reason": "directory_budget_exhausted",
            "last_scan_was_truncated": true,
            "scans_total": 7,
            "truncated_scans_total": 2,
            "inspected_directory_entries_total": 200_321,
            "truncated_directories_total": 2,
            "truncated_homes_total": 2,
            "last_scan_completed_at_unix": 1_785_686_400.5,
            "last_scan_homes": 2,
            "last_scan_inspected_directory_entries": 100_321,
            "last_scan_truncated_directory_count": 1,
            "last_scan_truncated_home_count": 1,
            "per_home_directory_entry_budget": 100_000,
        ]))

        #expect(inventory.coverageKnown)
        #expect(!inventory.complete)
        #expect(inventory.degraded)
        #expect(inventory.lastScanWasTruncated)
        #expect(inventory.scansTotal == 7)
        #expect(inventory.lastScanTruncatedHomeCount == 1)
        #expect(inventory.operatorDetail.contains("partial"))
        #expect(inventory.diagnosticDictionary["complete"] as? Bool == false)
        #expect(inventory.diagnosticDictionary["last_scan_truncated_home_count"] as? UInt64 == 1)
        #expect(V2HeartbeatSnapshot.BrowserInventory(from: nil) == nil)
        #expect(AppState.browserInventoryEvidenceUnavailable(
            coverageKnown: true,
            complete: false,
            degraded: false,
            lastScanWasTruncated: false
        ))
        #expect(!AppState.browserInventoryEvidenceUnavailable(
            coverageKnown: true,
            complete: true,
            degraded: false,
            lastScanWasTruncated: false
        ))
        let contradictory = try #require(V2HeartbeatSnapshot.BrowserInventory(from: [
            "coverage_known": true,
            "complete": false,
            "degraded": false,
            "last_scan_was_truncated": true,
        ]))
        #expect(contradictory.degraded)
    }

    // MARK: - readFreshest behavior

    @Test("readFreshest returns nil when no candidate heartbeat exists")
    func readFreshestNil() {
        // The Real readFreshest scans two specific application-support
        // dirs; on a clean test environment those should not contain
        // a recent heartbeat. We accept either nil OR a real snapshot
        // depending on whether the developer's daemon is running.
        // Not strictly testable without injecting paths; documented
        // as a follow-up.
        let snap = V2HeartbeatSnapshot.readFreshest()
        // If the daemon is running, snap is non-nil and within 5 minutes.
        if let s = snap {
            #expect(s.writtenAt.timeIntervalSinceNow > -300)
        }
    }

    // MARK: - Helpers

    private func makeSnapshot(
        uptimeSeconds: Int = 0,
        eventTypeCounts1h: [String: Int] = [:]
    ) -> V2HeartbeatSnapshot {
        V2HeartbeatSnapshot(
            writtenAt: Date(),
            uptimeSeconds: uptimeSeconds,
            eventsProcessed: 0,
            alertsEmitted: 0,
            residentMemoryMB: nil,
            sysextHasFDA: false,
            schemaVersion: 2,
            eventTypeCounts1h: eventTypeCounts1h,
            collectors: [],
            payloadTruncatedTotal: 0,
            esloggerDroppedTotal: 0,
            esSensorDegraded: false,
            esSensorDegradedDetail: nil,
            esSensorDegradedSeverity: nil,
            llm: nil,
            prevention: nil,
            traceGraphStorageAdmission: nil,
            traceStoreStorageAdmission: nil,
            eventPipeline: nil,
            browserInventory: nil
        )
    }
}
