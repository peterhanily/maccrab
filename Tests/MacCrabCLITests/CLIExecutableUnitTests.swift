// CLIExecutableUnitTests.swift
// MacCrabCLITests
//
// CI-14: `maccrab-mcp` (4.3k LOC) and `maccrabctl` (10.2k LOC) are both
// SHIPPED, user-facing executables and neither had a test target. The only MCP
// coverage was MCPProtocolHarnessTests — a black box that spawns the binary
// against a deliberately EMPTY hermetic store, so by construction it cannot
// tell a handler whose SQL targets the wrong table from a correct one, and it
// cannot reach any pure helper at all.
//
// SPM has allowed a test target to depend on an executable target since
// tools-version 5.5, and both executables use top-level code in `main.swift`,
// which is the supported shape. ONE CAVEAT bounds what may be tested here:
// globals DECLARED IN main.swift (maccrab-mcp's `tools`, `dataDir`,
// `isoFormatter`) are initialised by the entry point, which the test runner
// never calls — reading one traps. Globals in every OTHER file of the module
// (AgentControl.swift's `agentToolCapability`, Helpers.swift's `isTerminal`)
// are ordinary lazy globals and are safe, as are all functions.
//
// So: functions and non-main.swift state only, and nothing with a side effect —
// no dropInboxRequest / auditLog, which write into the real support directory.

import Testing
import Foundation
@testable import maccrabctl
@testable import maccrab_mcp
@testable import MacCrabCore

@Suite("maccrabctl: unit")
struct MacCrabCtlUnitTests {

    @Test("trace export treats --out as the documented parent directory")
    func traceExportTargetUsesOutputDirectory() throws {
        #expect(MacCrabCtl.traceExportStoreOpenFailureExitCode == 1)
        let outputDirectory = URL(fileURLWithPath: "/private/tmp/trace-exports")
        #expect(try MacCrabCtl.traceExportTarget(
            traceId: "trace-123",
            outputDirectory: outputDirectory
        ).path == "/private/tmp/trace-exports/trace-123.maccrabtrace")
        #expect(try MacCrabCtl.traceExportTarget(
            traceId: "trace-123",
            outputDirectory: nil,
            currentDirectoryPath: "/private/tmp/cwd"
        ).path == "/private/tmp/cwd/trace-123.maccrabtrace")
        #expect(throws: MacCrabCtl.TraceExportTargetError.self) {
            _ = try MacCrabCtl.traceExportTarget(
                traceId: "../../redirected",
                outputDirectory: outputDirectory
            )
        }
    }

    /// The v1/v2 suppression-store discriminator. `suppressRule` /
    /// `unsuppressRule` encode a FLAT `[ruleId: [path]]` document over the very
    /// same suppressions.json the daemon rewrites in v2 shape
    /// (`{"version":2,"entries":[…]}`), so a v1 write onto a v2 document
    /// destroys the entire TTL/audit allowlist. This one predicate is what
    /// stands between those two encodings, and it had no coverage.
    @Test("suppressionStoreIsV2 recognises both v2 shapes and never mistakes a v1 document for one")
    func suppressionStoreShapeDetection() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrabctl-suppress-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        func write(_ json: String, _ name: String) throws -> String {
            let p = dir.appendingPathComponent(name).path
            try json.write(toFile: p, atomically: true, encoding: .utf8)
            return p
        }

        // v2 by explicit version, and v2 by entries array. The daemon writes
        // both keys, but EITHER alone must be enough to stop a v1 overwrite.
        #expect(MacCrabCtl.suppressionStoreIsV2(try write(#"{"version":2,"entries":[]}"#, "a.json")))
        #expect(MacCrabCtl.suppressionStoreIsV2(try write(#"{"version":2}"#, "b.json")))
        #expect(MacCrabCtl.suppressionStoreIsV2(try write(#"{"entries":[{"ruleId":"r"}]}"#, "c.json")))

        // A genuine v1 flat map, an absent file, and non-JSON must all read as
        // "not v2" so the v1 path stays usable on a real v1 store.
        #expect(!MacCrabCtl.suppressionStoreIsV2(try write(#"{"csrutil_status":["/usr/bin/csrutil"]}"#, "d.json")))
        #expect(!MacCrabCtl.suppressionStoreIsV2(dir.appendingPathComponent("nope.json").path))
        #expect(!MacCrabCtl.suppressionStoreIsV2(try write("not json at all", "e.json")))
    }

    /// CLI-5 contract: the research verbs are dispatched only under
    /// MACCRAB_DEV=1 and must never be advertised in shipped help. Asserted on
    /// the LEADING TOKEN of each help line, not a substring — "MCFP v1 static
    /// process fingerprint" is legitimate prose on the `fingerprint` line, and a
    /// naive `contains("mcfp")` would fail on it.
    @Test("usageText never advertises a dev-hidden command")
    func hiddenCommandsStayHidden() {
        #expect(!MacCrabCtl.hiddenCommands.isEmpty)
        let advertised = Set(MacCrabCtl.usageText()
            .components(separatedBy: "\n")
            .compactMap { $0.trimmingCharacters(in: .whitespaces).components(separatedBy: " ").first }
            .filter { !$0.isEmpty })
        for hidden in MacCrabCtl.hiddenCommands {
            #expect(!advertised.contains(hidden),
                    "'\(hidden)' is a MACCRAB_DEV-only verb but appears as a documented command in `maccrabctl help`")
        }
    }

    @Test("status makes a TraceGraph startup-admission evidence gap explicit")
    func traceGraphStartupAdmissionStatus() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrabctl-tracegraph-status-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let fixture = """
        {
          "schema_version": 5,
          "written_at_unix": 1700000000,
          "tracegraph_storage_admission": {
            "enabled": true,
            "blocked": true,
            "store_available": false,
            "startup_blocked": true,
            "reason": "low_free_space"
          }
        }
        """
        try fixture.write(
            to: dir.appendingPathComponent("heartbeat_rich.json"),
            atomically: true,
            encoding: .utf8
        )

        let lines = MacCrabCtl.traceGraphStorageStatusLines(supportDir: dir.path)
        #expect(lines.first == "TraceGraph:      Paused at startup ⚠")
        #expect(lines.joined(separator: "\n").contains("new causal evidence is not being recorded"))
        #expect(lines.joined(separator: "\n").contains("low_free_space"))
        #expect(lines.last?.contains("restart MacCrab") == true)
    }

    @Test("status reports a live admitted TraceGraph as active")
    func traceGraphHealthyStatus() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrabctl-tracegraph-healthy-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        try """
        {"schema_version":5,"written_at_unix":1700000000,
         "tracegraph_storage_admission":{"enabled":true,"blocked":false,
         "store_available":true,"startup_blocked":false,"reason":""}}
        """.write(
            to: dir.appendingPathComponent("heartbeat_rich.json"),
            atomically: true,
            encoding: .utf8
        )

        #expect(MacCrabCtl.traceGraphStorageStatusLines(supportDir: dir.path)
            == ["TraceGraph:      Active ✓"])
    }

    @Test("status refuses false-green Active after a failed TraceGraph batch")
    func traceGraphFailedBatchStatus() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrabctl-tracegraph-failed-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        try """
        {"schema_version":5,"written_at_unix":1700000000,
         "tracegraph_storage_admission":{"enabled":true,"blocked":false,
         "store_available":true,"startup_blocked":false,"reason":"",
         "ingest_events_total":2,"ingest_events_committed_total":0,
         "ingest_events_failed_total":2,"ingest_events_in_flight":0,
         "ingest_events_pending":0,"entity_observations_total":2,
         "edge_observations_total":0,"write_attempts_total":1,
         "write_batches_committed_total":0,"write_batches_failed_total":1,
         "write_batches_in_flight":0,"write_rows_attempted_total":1,
         "write_rows_committed_total":0,"write_rows_failed_total":1,
         "write_rows_in_flight":0,"coalesced_noop_rows_total":1,
         "pending_entity_rows":0,"pending_edge_rows":0}}
        """.write(
            to: dir.appendingPathComponent("heartbeat_rich.json"),
            atomically: true,
            encoding: .utf8
        )

        let cli = MacCrabCtl.traceGraphStorageStatusLines(supportDir: dir.path)
        #expect(cli.first == "TraceGraph:      Evidence writes degraded ⚠")
        #expect(cli.joined(separator: "\n").contains("events=2"))
        #expect(!cli.joined(separator: "\n").contains("Active ✓"))

        let heartbeat = try #require(HeartbeatSnapshot.readFreshest(supportDirs: [dir.path]))
        let storage = try #require(heartbeat.traceGraphStorageAdmission)
        let mcp = maccrab_mcp.traceGraphPersistenceStatusLines(storage)
        #expect(mcp.first == "TraceGraph: Evidence writes degraded")
        #expect(mcp.joined(separator: "\n").contains("batches=1"))
    }

    @Test("status treats a non-accepting TraceGraph recovery barrier as a live fault")
    func traceGraphRecoveryBarrierStatus() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrabctl-tracegraph-barrier-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        try """
        {"schema_version":5,"written_at_unix":1700000000,
         "tracegraph_storage_admission":{"enabled":true,"blocked":false,
         "store_available":true,"startup_blocked":false,"reason":"",
         "accepting_mutations":false,"recovering":true,
         "recovery_mutation_waiters":0,"recovery_mutation_waiter_limit":256,
         "recovery_mutation_queue_saturated":false,
         "recovery_mutation_waiter_high_watermark":0,
         "recovery_mutation_waits_total":0,
         "recovery_mutation_wait_releases_total":0,
         "recovery_mutation_wait_cancellations_total":0,
         "recovery_mutation_wait_closed_total":0,
         "recovery_mutation_wait_saturations_total":0,
         "recovery_mutation_wait_nanoseconds_total":0,
         "recovery_mutation_max_wait_nanoseconds":0,
         "recovery_mutation_oldest_wait_nanoseconds":0,
         "recovery_writer_preemptions_total":0,
         "ingest_events_total":1,"ingest_events_committed_total":1,
         "ingest_events_failed_total":0,"ingest_events_in_flight":0,
         "ingest_events_pending":0,"entity_observations_total":1,
         "edge_observations_total":0,"relevance_suppressed_file_events_total":0,
         "relevance_suppressed_rows_total":0,"write_attempts_total":1,
         "write_batches_committed_total":1,"write_batches_failed_total":0,
         "write_batches_in_flight":0,"write_rows_attempted_total":1,
         "write_rows_committed_total":1,"write_rows_failed_total":0,
         "write_rows_in_flight":0,"coalesced_noop_rows_total":0,
         "pending_entity_rows":0,"pending_edge_rows":0}}
        """.write(
            to: dir.appendingPathComponent("heartbeat_rich.json"),
            atomically: true,
            encoding: .utf8
        )

        let lines = MacCrabCtl.traceGraphStorageStatusLines(supportDir: dir.path)
        let output = lines.joined(separator: "\n")
        #expect(lines.first == "TraceGraph:      Evidence writes degraded ⚠")
        #expect(output.contains("Recovery handoff is not healthy now"))
        #expect(output.contains("accepting=false"))
        #expect(!output.contains("earlier this boot"))
    }

    @Test("CLI and MCP expose conserving fixed-cardinality AI runtime quality")
    func llmRuntimeStatus() throws {
        func counters(
            requested: Int = 0,
            cache: Int = 0,
            retries: Int = 0,
            finalRejections: Int = 0
        ) -> [String: Any] {
            [
                "requestedTotal": requested,
                "currentInFlight": 0,
                "admittedBackendTotal": 0,
                "currentAdmittedBackendRequests": 0,
                "backendCallsStartedTotal": 0,
                "cancellationsAfterAdmissionTotal": 0,
                "outcomes": [
                    "success": 0, "cacheHit": cache,
                    "backendFailure": 0, "circuitRejection": 0,
                    "privacyRejection": 0, "admissionShed": 0,
                    "cancellation": 0, "responseOversize": 0,
                ],
                "circuitRecoveryProbesStartedTotal": 0,
                "currentCircuitRecoveryProbes": 0,
                "circuitRecoveryProbesSucceededTotal": 0,
                "circuitRecoveryProbesDidNotRecoverTotal": 0,
                "downstreamValidation": [
                    "operationsStartedTotal": finalRejections,
                    "currentOperations": 0,
                    "accepted": 0,
                    "retryRequested": retries,
                    "finalRejection": finalRejections,
                ],
                "requestLatencyBuckets": [["completedRequests": requested]],
                "requestedInputUTF8BytesTotal": 0,
                "backendInputUTF8BytesTotal": 0,
                "backendOutputUTF8BytesTotal": 0,
                "returnedOutputUTF8BytesTotal": 0,
                "estimatedBackendInputTokensTotal": 0,
                "estimatedBackendOutputTokensTotal": 0,
                "estimatedReturnedOutputTokensTotal": 0,
                "conservationMaintained": true,
                "backendAdmissionConservationMaintained": true,
                "circuitRecoveryConservationMaintained": true,
            ]
        }
        let features: [[String: Any]] = LLMRuntimeFeature.allCases.map { feature in
            let value: [String: Any]
            switch feature {
            case .unspecified:
                value = counters(requested: 1, cache: 1)
            case .alertInvestigation:
                value = counters(retries: 1, finalRejections: 1)
            default:
                value = counters()
            }
            return ["feature": feature.rawValue, "counters": value]
        }
        let rejectionReasons: [[String: Any]] =
            LLMAlertInvestigationRejectionReason.allCases.map { reason in
                [
                    "reason": reason.rawValue,
                    "observedAttempts": reason == .evidenceGrounding ? 2 : 0,
                    "terminalRejections": reason == .evidenceGrounding ? 1 : 0,
                ]
            }
        let heartbeat: [String: Any] = [
            "schema_version": 5,
            "written_at_unix": 1_700_000_000.0,
            "llm": [
                "configured": true,
                "provider": "fixture",
                "model": "content-free",
                "healthy": true,
                "runtime_telemetry": [
                    "schemaVersion": 2,
                    "capturedAtUnix": 1_700_000_000.0,
                    "totals": counters(
                        requested: 1, cache: 1, retries: 1, finalRejections: 1
                    ),
                    "perFeature": features,
                    "alertInvestigationRejections": [
                        "observedAttemptsTotal": 2,
                        "terminalRejectionsTotal": 1,
                        "byReason": rejectionReasons,
                    ],
                ],
            ],
        ]
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrabctl-llm-runtime-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        try JSONSerialization.data(withJSONObject: heartbeat).write(
            to: dir.appendingPathComponent("heartbeat_rich.json")
        )

        let cli = MacCrabCtl.llmRuntimeStatusLines(supportDir: dir.path)
        let cliText = cli.joined(separator: "\n")
        #expect(cli.first?.contains("requested=1") == true)
        #expect(cliText.contains("unspecified=1 ⚠"))
        #expect(cliText.contains("retries=1"))
        #expect(cliText.contains("final_rejection=1 ⚠"))
        #expect(cliText.contains("evidence_grounding=2/1"))
        #expect(!cliText.contains("prompt"))

        let typed = try #require(HeartbeatSnapshot.readFreshest(supportDirs: [dir.path]))
        let llm = try #require(typed.llm)
        let mcp = maccrab_mcp.llmRuntimeOperatorStatusLines(llm)
            .joined(separator: "\n")
        #expect(mcp.contains("accounting=conserving"))
        #expect(mcp.contains("unspecified=1"))
        #expect(mcp.contains("final_rejection=1"))
        #expect(mcp.contains("evidence_grounding=2/1"))
        #expect(!mcp.contains("prompt"))
    }

    @Test("CLI and MCP distinguish live transition storage and timer conservation")
    func transitionStorageAndTimerStatus() throws {
        let heartbeat: [String: Any] = [
            "written_at_unix": 1_700_000_000.0,
            "alert_evidence_budget": [
                "events_family_effective_cap_bytes": 440_401_920,
                "events_family_steady_state_cap_bytes": 335_544_320,
                "alerts_family_combined_cap_bytes": 209_715_200,
                "events_and_alerts_total_cap_bytes": 650_117_120,
                "events_and_alerts_steady_state_total_cap_bytes": 545_259_520,
                "legacy_transition_reserve_bytes": 104_857_600,
                "legacy_transition_max_bytes": 104_857_600,
                "legacy_transition_measurement_failed": true,
                "legacy_row_count": 42,
                "legacy_charged_bytes": 73_400_320,
                "capture_offered_total": 4,
                "capture_completed_total": 2,
                "capture_failures_total": 1,
                "capture_shed_total": 0,
                "capture_pending": 0,
                "capture_in_flight": 1,
                "capture_queue_capacity": 256,
                "capture_accepting": true,
                "capture_conserved": true,
                "allocated_bytes_exact": false,
                "mutation_generation": 19,
                "full_refreshes_total": 3,
            ],
            "timer_lifecycle": [
                "accepting": true,
                "offered_handlers_total": 11,
                "accepted_handlers_total": 10,
                "completed_handlers_total": 8,
                "rejected_handlers_total": 1,
                "closed_rejected_handlers_total": 0,
                "overload_shed_handlers_total": 1,
                "coalesced_handlers_total": 0,
                "inline_fallback_handlers_total": 0,
                "in_flight_handlers": 1,
                "maximum_in_flight_handlers": 256,
                "conserves_accepted_handlers": false,
                "conserves_offered_handlers": true,
            ],
            "liveness_timer_lifecycle": [
                "accepting": true,
                "offered_handlers_total": 2,
                "accepted_handlers_total": 1,
                "completed_handlers_total": 0,
                "rejected_handlers_total": 0,
                "closed_rejected_handlers_total": 0,
                "overload_shed_handlers_total": 0,
                "coalesced_handlers_total": 1,
                "inline_fallback_handlers_total": 0,
                "in_flight_handlers": 1,
                "maximum_in_flight_handlers": 1,
                "conserves_accepted_handlers": true,
                "conserves_offered_handlers": true,
            ],
            "detection_work_lifecycle": [
                "accepting": false,
                "offered_handlers_total": 4,
                "accepted_handlers_total": 3,
                "completed_handlers_total": 3,
                "rejected_handlers_total": 1,
                "closed_rejected_handlers_total": 1,
                "overload_shed_handlers_total": 0,
                "coalesced_handlers_total": 0,
                "inline_fallback_handlers_total": 0,
                "in_flight_handlers": 0,
                "maximum_in_flight_handlers": 256,
                "conserves_accepted_handlers": true,
                "conserves_offered_handlers": true,
            ],
            "advisory_work_lifecycle": [
                "accepting": true,
                "offered_handlers_total": 2,
                "accepted_handlers_total": 1,
                "completed_handlers_total": 1,
                "rejected_handlers_total": 1,
                "closed_rejected_handlers_total": 0,
                "overload_shed_handlers_total": 1,
                "coalesced_handlers_total": 0,
                "inline_fallback_handlers_total": 0,
                "in_flight_handlers": 0,
                "maximum_in_flight_handlers": 64,
                "conserves_accepted_handlers": true,
                "conserves_offered_handlers": true,
            ],
            "output_work_lifecycle": [
                "accepting": true,
                "offered_handlers_total": 2,
                "accepted_handlers_total": 1,
                "completed_handlers_total": 1,
                "rejected_handlers_total": 0,
                "closed_rejected_handlers_total": 0,
                "overload_shed_handlers_total": 0,
                "coalesced_handlers_total": 0,
                "inline_fallback_handlers_total": 1,
                "in_flight_handlers": 0,
                "maximum_in_flight_handlers": 128,
                "conserves_accepted_handlers": true,
                "conserves_offered_handlers": true,
            ],
            "otlp_receiver_lifecycle": [
                "accepting_listeners": false,
                "listeners_accepted_total": 2,
                "listeners_completed_total": 1,
                "listeners_rejected_after_seal_total": 1,
                "active_listeners": 1,
                "ready_listeners": 1,
                "listeners_conserved": true,
                "accepting_connections": false,
                "connections_accepted_total": 2,
                "connections_completed_total": 1,
                "connections_rejected_after_seal_total": 1,
                "connections_rejected_at_capacity_total": 0,
                "active_connections": 1,
                "connections_conserved": true,
                "accepting_body_tasks": false,
                "body_tasks_accepted_total": 1,
                "body_tasks_completed_total": 0,
                "body_tasks_cancelled_total": 0,
                "body_tasks_rejected_total": 1,
                "body_task_cancellation_requests_total": 1,
                "body_tasks_in_flight": 1,
                "maximum_body_tasks": 64,
                "body_tasks_conserved": true,
                "accepting_callback_tasks": false,
                "callback_tasks_accepted_total": 2,
                "callback_tasks_completed_total": 1,
                "callback_tasks_cancelled_total": 0,
                "callback_tasks_rejected_total": 1,
                "callback_task_cancellation_requests_total": 1,
                "callback_tasks_in_flight": 1,
                "maximum_callback_tasks": 256,
                "callback_tasks_conserved": true,
                "lifecycle_operations_in_progress": 1,
                "shutdown_timeouts_total": 1,
                "cleanly_stopped": false,
                "last_shutdown_clean": false,
            ],
        ]
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrabctl-transition-status-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        try JSONSerialization.data(withJSONObject: heartbeat).write(
            to: dir.appendingPathComponent("heartbeat_rich.json")
        )

        let storage = MacCrabCtl.alertEvidenceStorageStatusLines(supportDir: dir.path)
            .joined(separator: "\n")
        #expect(storage.contains("LIVE transition-aware"))
        #expect(storage.contains("combined 620 MiB"))
        #expect(storage.contains("STEADY STATE"))
        #expect(storage.contains("combined 520 MiB"))
        #expect(storage.contains("Evidence Worker"))
        #expect(storage.contains("accepting=yes"))
        #expect(storage.contains("allocated_exact=no"))
        #expect(storage.contains("full_refreshes=3"))
        #expect(storage.contains("capture is degraded"))
        let timers = MacCrabCtl.timerLifecycleStatusLines(supportDir: dir.path)
        #expect(timers.first?.contains("Degraded") == true)
        #expect(timers.first?.contains("accepted_conserves=false") == true)
        #expect(timers.first?.contains("offered_conserves=true") == true)
        #expect(timers.joined(separator: "\n").contains("maintenance guarantee is degraded"))
        let work = MacCrabCtl.workLifecycleStatusLines(supportDir: dir.path)
            .joined(separator: "\n")
        #expect(work.contains("Liveness:       Conserving"))
        #expect(work.contains("Capacity pressure was handled without measured loss"))
        #expect(work.contains("Detection Work: Degraded"))
        #expect(work.contains("PROTECTION DEGRADED"))
        #expect(work.contains("AI Advisory:    Degraded"))
        #expect(work.contains("deterministic detection"))
        #expect(work.contains("Alert Outputs:  Conserving"))
        let otlp = MacCrabCtl.otlpReceiverLifecycleStatusLines(supportDir: dir.path)
            .joined(separator: "\n")
        #expect(otlp.contains("Agent OTLP:     Feature degraded"))
        #expect(otlp.contains("listeners accepted=2"))
        #expect(otlp.contains("callbacks accepted=2"))
        #expect(otlp.contains("lifecycle_operations=1"))
        #expect(otlp.contains("conserves=true"))
        #expect(otlp.contains("cleanly_stopped=false"))
        #expect(otlp.contains("last_shutdown_clean=false"))
        #expect(otlp.contains("kernel detection continues"))

        let typed = try #require(HeartbeatSnapshot.readFreshest(supportDirs: [dir.path]))
        let mcpStorage = maccrab_mcp.alertEvidenceBudgetStatusLines(
            try #require(typed.alertEvidenceBudget)
        ).joined(separator: "\n")
        #expect(mcpStorage.contains("live transition-aware"))
        #expect(mcpStorage.contains("steady state"))
        #expect(mcpStorage.contains("DEGRADED measurement"))
        #expect(mcpStorage.contains("accepting=yes"))
        #expect(mcpStorage.contains("allocated_exact=no"))
        let mcpTimers = maccrab_mcp.timerLifecycleOperatorStatusLines(
            try #require(typed.timerLifecycle)
        ).joined(separator: "\n")
        #expect(mcpTimers.contains("Maintenance: DEGRADED"))
        #expect(mcpTimers.contains("accepted_conserves=false"))
        let mcpWork = maccrab_mcp.workLifecycleOperatorStatusLines(typed)
            .joined(separator: "\n")
        #expect(mcpWork.contains("Detection Work: DEGRADED"))
        #expect(mcpWork.contains("PROTECTION DEGRADED"))
        #expect(mcpWork.contains("AI Advisory: DEGRADED"))
        #expect(mcpWork.contains("Alert Outputs: conserving"))
        let mcpOTLP = maccrab_mcp.otlpReceiverLifecycleOperatorStatusLines(
            try #require(typed.otlpReceiverLifecycle)
        ).joined(separator: "\n")
        #expect(mcpOTLP.contains("FEATURE DEGRADED"))
        #expect(mcpOTLP.contains("listeners accepted=2"))
        #expect(mcpOTLP.contains("callbacks accepted=2"))
        #expect(mcpOTLP.contains("lifecycle_operations=1"))
        #expect(mcpOTLP.contains("cleanly_stopped=false"))
        #expect(mcpOTLP.contains("kernel detection continues"))
    }

    @Test("heartbeat producers and every shipped operator surface cannot drift")
    func operatorHealthSourceWiring() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        func source(_ path: String) throws -> String {
            try String(
                contentsOf: root.appendingPathComponent(path),
                encoding: .utf8
            )
        }
        let timers = try source("Sources/MacCrabAgentKit/DaemonTimers.swift")
        let dto = try source("Sources/MacCrabCore/Assessment/HeartbeatSnapshot.swift")
        let v2 = try source("Sources/MacCrabApp/V2/Data/V2HeartbeatSnapshot.swift")
        let appState = try source("Sources/MacCrabApp/AppState.swift")
        let workspace = try source("Sources/MacCrabApp/V2/Workspaces/V2SystemWorkspace.swift")
        let cli = try source("Sources/maccrabctl/StatusCommand.swift")
        let mcp = try source("Sources/maccrab-mcp/main.swift")

        let graphKeys = [
            "ingest_events_total", "ingest_events_committed_total",
            "ingest_events_failed_total", "ingest_events_in_flight",
            "ingest_events_pending", "entity_observations_total",
            "edge_observations_total",
            "relevance_suppressed_file_events_total",
            "relevance_suppressed_rows_total", "write_attempts_total",
            "write_batches_committed_total", "write_batches_failed_total",
            "write_batches_in_flight", "write_rows_attempted_total",
            "write_rows_committed_total", "write_rows_failed_total",
            "write_rows_in_flight", "coalesced_noop_rows_total",
            "pending_entity_rows", "pending_edge_rows",
        ]
        for key in graphKeys {
            #expect(timers.contains("d[\"\(key)\"]"), "producer lost \(key)")
            #expect(dto.contains("\"\(key)\""), "shared DTO lost \(key)")
        }
        for surface in [v2, workspace, cli, mcp] {
            #expect(surface.contains("graphWriteDegraded"),
                    "a shipped operator surface stopped checking writer health")
        }

        #expect(timers.contains("llmDict[\"runtime_telemetry\"]"))
        #expect(dto.contains("runtimeTelemetry = \"runtime_telemetry\""))
        #expect(v2.contains("runtimeConservationMaintained"))
        #expect(workspace.contains("llmRuntimeDegradedBanner"))
        #expect(cli.contains("llmRuntimeStatusLines"))
        #expect(mcp.contains("llmRuntimeOperatorStatusLines"))
        for semanticField in ["retryRequested", "finalRejection"] {
            #expect(dto.contains(semanticField))
            #expect(v2.contains(semanticField))
            #expect(cli.contains(semanticField))
            #expect(mcp.contains(semanticField))
        }

        let evidenceKeys = [
            "events_family_steady_state_cap_bytes",
            "events_and_alerts_steady_state_total_cap_bytes",
            "legacy_transition_reserve_bytes",
            "legacy_transition_max_bytes",
            "legacy_transition_measurement_failed",
            "capture_offered_total", "capture_completed_total",
            "capture_failures_total", "capture_shed_total",
            "capture_pending", "capture_in_flight",
            "capture_queue_capacity", "capture_accepting",
            "capture_conserved", "allocated_bytes_exact",
            "mutation_generation", "full_refreshes_total",
        ]
        for key in evidenceKeys {
            #expect(timers.contains("\"\(key)\""), "producer lost \(key)")
            #expect(dto.contains("\"\(key)\""), "shared DTO lost \(key)")
        }
        for surface in [workspace, cli, mcp] {
            #expect(surface.contains("legacyTransitionReserveBytes"))
            #expect(surface.contains("captureDegraded"))
            #expect(surface.contains("captureAccepting"))
            #expect(surface.contains("allocatedBytesExact"))
            #expect(surface.contains("mutationGeneration"))
            #expect(surface.contains("fullRefreshesTotal"))
        }

        let lifecycleObjects = [
            "timer_lifecycle", "liveness_timer_lifecycle",
            "startup_work_lifecycle", "detection_work_lifecycle",
            "advisory_work_lifecycle", "output_work_lifecycle",
        ]
        for object in lifecycleObjects {
            #expect(timers.contains("\"\(object)\""))
            #expect(dto.contains("\"\(object)\""))
        }
        let lifecycleKeys = [
            "offered_handlers_total", "accepted_handlers_total",
            "completed_handlers_total", "rejected_handlers_total",
            "closed_rejected_handlers_total", "overload_shed_handlers_total",
            "coalesced_handlers_total", "coalesced_by_label",
            "rejected_by_label", "inline_fallback_handlers_total",
            "inline_fallbacks_by_label", "in_flight_handlers",
            "maximum_in_flight_handlers", "conserves_accepted_handlers",
            "conserves_offered_handlers",
        ]
        for key in lifecycleKeys {
            #expect(timers.contains("\"\(key)\""), "producer lost \(key)")
            #expect(dto.contains("\"\(key)\""), "shared DTO lost \(key)")
        }
        for surface in [v2, appState, workspace, cli, mcp] {
            #expect(surface.contains("detectionWorkLifecycle"))
            #expect(surface.contains("advisoryWorkLifecycle"))
            #expect(surface.contains("outputWorkLifecycle"))
            #expect(surface.contains("otlpReceiverLifecycle"))
        }
        #expect(appState.contains("detectionWorkProtectionUnavailable"))
        #expect(workspace.contains("lifecycleDegradedBanner"))
        #expect(workspace.contains("Protection degraded"))
        #expect(cli.contains("workLifecycleStatusLines"))
        #expect(cli.contains("otlpReceiverLifecycleStatusLines"))
        #expect(mcp.contains("workLifecycleOperatorStatusLines"))
        #expect(mcp.contains("otlpReceiverLifecycleOperatorStatusLines"))

        let otlpKeys = [
            "accepting_listeners", "listeners_accepted_total",
            "listeners_completed_total", "listeners_rejected_after_seal_total",
            "active_listeners", "ready_listeners", "listeners_conserved",
            "accepting_connections", "connections_accepted_total",
            "connections_completed_total",
            "connections_rejected_after_seal_total",
            "connections_rejected_at_capacity_total", "active_connections",
            "connections_conserved", "accepting_body_tasks",
            "body_tasks_accepted_total", "body_tasks_completed_total",
            "body_tasks_cancelled_total", "body_tasks_rejected_total",
            "body_task_cancellation_requests_total", "body_tasks_in_flight",
            "maximum_body_tasks", "body_tasks_conserved",
            "accepting_callback_tasks", "callback_tasks_accepted_total",
            "callback_tasks_completed_total", "callback_tasks_cancelled_total",
            "callback_tasks_rejected_total",
            "callback_task_cancellation_requests_total",
            "callback_tasks_in_flight", "maximum_callback_tasks",
            "callback_tasks_conserved", "lifecycle_operations_in_progress",
            "shutdown_timeouts_total", "cleanly_stopped",
            "last_shutdown_clean",
        ]
        #expect(timers.contains("\"otlp_receiver_lifecycle\""))
        #expect(dto.contains("\"otlp_receiver_lifecycle\""))
        for key in otlpKeys {
            #expect(timers.contains("\"\(key)\""), "producer lost OTLP \(key)")
            #expect(dto.contains("\"\(key)\""), "shared DTO lost OTLP \(key)")
        }
        for field in [
            "listenersAcceptedTotal", "listenersConserved",
            "callbackTasksAcceptedTotal", "callbackTasksConserved",
            "lifecycleOperationsInProgress",
        ] {
            #expect(workspace.contains(field), "dashboard lost OTLP \(field)")
            #expect(cli.contains(field), "CLI lost OTLP \(field)")
            #expect(mcp.contains(field), "MCP lost OTLP \(field)")
        }
    }

    @Test("status distinguishes restart-safe sequence state from a continuity gap")
    func sequenceCheckpointStatus() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrabctl-sequence-status-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        try """
        {"schema_version":5,"written_at_unix":1700000000,
         "sequence_checkpoint":{"restore_status":"restored","dirty":false,
         "configured_crash_rpo_seconds":30,
         "crash_rpo_bound_currently_maintained":true}}
        """.write(
            to: dir.appendingPathComponent("heartbeat_rich.json"),
            atomically: true,
            encoding: .utf8
        )
        #expect(MacCrabCtl.sequenceCheckpointStatusLines(supportDir: dir.path)
            == ["Sequence State:  Restart-safe ✓ (≤30s partial-state RPO)"])

        try """
        {"schema_version":5,"written_at_unix":1700000001,
         "sequence_checkpoint":{"restore_status":"rejected","dirty":true,
         "crash_rpo_bound_currently_maintained":false}}
        """.write(
            to: dir.appendingPathComponent("heartbeat_rich.json"),
            atomically: true,
            encoding: .utf8
        )
        let rejected = MacCrabCtl.sequenceCheckpointStatusLines(supportDir: dir.path)
        #expect(rejected.first == "Sequence State:  Previous checkpoint rejected ⚠")
        #expect(rejected.joined(separator: "\n").contains("could not be recovered"))

        try """
        {"schema_version":5,"written_at_unix":1700000002,
         "sequence_partials_evicted_total":0,"sequence_partials_in_flight":4,
         "sequence_pending_steps_current":9,"sequence_pending_steps_evicted_total":3,
         "sequence_state_continuity_maintained":false,
         "sequence_state_continuity_detail":"pending_step_eviction",
         "sequence_checkpoint":{"restore_status":"recovered","dirty":false,
         "durable_carrier_valid":true,"carrier_invalidations_total":1,
         "last_carrier_invalidation_reason":"integrity_mismatch",
         "crash_rpo_bound_currently_maintained":true}}
        """.write(
            to: dir.appendingPathComponent("heartbeat_rich.json"),
            atomically: true,
            encoding: .utf8
        )
        let evicted = MacCrabCtl.sequenceCheckpointStatusLines(supportDir: dir.path)
        #expect(evicted.first == "Sequence State:  Runtime continuity degraded ⚠")
        #expect(evicted.joined(separator: "\n").contains("pending_step_eviction"))
        #expect(evicted.joined(separator: "\n").contains("pending_evictions=3"))
    }

    @Test("status makes traces.db shedding and untrusted provenance explicit")
    func traceStorePressureStatus() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrabctl-traces-status-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        try """
        {"schema_version":5,"written_at_unix":1700000000,
         "traces_storage_admission":{"enabled":true,"blocked":true,
         "store_available":true,"startup_blocked":false,"reason":"footprint_limit"}}
        """.write(
            to: dir.appendingPathComponent("heartbeat_rich.json"),
            atomically: true,
            encoding: .utf8
        )

        let lines = MacCrabCtl.traceStoreStorageStatusLines(supportDir: dir.path)
        #expect(lines.first == "Agent Trace DB:  Persistence paused ⚠")
        #expect(lines.joined(separator: "\n").contains("Unauthenticated/self-reported OTLP spans"))
        #expect(lines.joined(separator: "\n").contains("kernel detection continues"))
        #expect(lines.joined(separator: "\n").contains("footprint_limit"))
    }

    @Test("status treats an intentionally disabled trace receiver as non-pressure")
    func traceStoreDisabledStatus() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrabctl-traces-disabled-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        try """
        {"schema_version":5,"written_at_unix":1700000000,
         "traces_storage_admission":{"enabled":false,"blocked":false,
         "store_available":false,"reason":"receiver_disabled"}}
        """.write(
            to: dir.appendingPathComponent("heartbeat_rich.json"),
            atomically: true,
            encoding: .utf8
        )

        #expect(MacCrabCtl.traceStoreStorageStatusLines(supportDir: dir.path)
            == ["Agent Trace DB:  Receiver disabled"])
    }
}

@Suite("maccrab-mcp: unit")
struct MCPHandlerUnitTests {

    /// `sanitizeContent` runs over every ordinary response and every ERROR on
    /// the way out (authorized forensic-evidence successes are intentionally
    /// exempt). It must rewrite `content[].text`, recursively scrub structured
    /// ERROR strings, and preserve the envelope/non-text blocks. A rewrite that
    /// rebuilt the dict could launder every error into a success.
    @Test("sanitizeContent scrubs text + structured errors and preserves the envelope")
    func sanitizePreservesEnvelope() throws {
        let input: [String: Any] = [
            "isError": true,
            "content": [
                ["type": "text", "text": "outbound to 192.168.7.31 from the alerting process"],
                ["type": "resource", "uri": "maccrab://alert/9f3c"],
            ],
            "structuredContent": [
                "error": "fixture_error",
                "nested": [
                    "host": "192.168.7.31",
                    "values": ["safe-fixed-id", "Bearer ABCDEFGHIJKLMNOPQRSTUV123456"],
                ] as [String: Any],
            ] as [String: Any],
        ]
        let out = try #require(maccrab_mcp.sanitizeContent(input) as? [String: Any])
        #expect(out["isError"] as? Bool == true)
        let blocks = try #require(out["content"] as? [[String: Any]])
        #expect(blocks.count == 2)
        // The text block was scrubbed. 192.168/16 is an unconditional RFC-1918
        // match in LLMSanitizer.privateIPRegex, so this does not depend on the
        // running user's name (the CI `runner` account sits in the sanitizer's
        // reserved set and would make a username-based assertion flaky).
        let text = try #require(blocks[0]["text"] as? String)
        #expect(!text.contains("192.168.7.31"))
        // The non-text block rode through untouched.
        #expect(blocks[1]["uri"] as? String == "maccrab://alert/9f3c")
        #expect(blocks[1]["text"] == nil)

        let structured = try #require(out["structuredContent"] as? [String: Any])
        #expect(structured["error"] as? String == "fixture_error")
        let nested = try #require(structured["nested"] as? [String: Any])
        #expect((nested["host"] as? String)?.contains("192.168.7.31") == false)
        let values = try #require(nested["values"] as? [String])
        #expect(values.first == "safe-fixed-id")
        #expect(values.last?.contains("ABCDEFGHIJKLMNOPQRSTUV123456") == false)
    }

    @Test("MCP rejects global or confirmation-disabled host mutations before any write")
    func destructiveResponseActionsArePendingPerRuleOnly() throws {
        for action in ["kill", "quarantine", "script", "blockNetwork"] {
            var base: [String: Any] = ["action": action]
            if action == "script" {
                base["script_path"] = "/Library/Application Support/MacCrab/scripts/review-only.sh"
            }

            let global = try #require(maccrab_mcp.handleSetResponseAction(base) as? [String: Any])
            #expect(global["isError"] as? Bool == true)
            let globalText = ((global["content"] as? [[String: Any]])?.first?["text"] as? String) ?? ""
            #expect(globalText.contains("cannot create a global default"), "\(action): \(globalText)")

            var automatic = base
            automatic["rule_id"] = "fixture.exact-rule"
            automatic["require_confirmation"] = false
            let denied = try #require(maccrab_mcp.handleSetResponseAction(automatic) as? [String: Any])
            #expect(denied["isError"] as? Bool == true)
            let deniedText = ((denied["content"] as? [[String: Any]])?.first?["text"] as? String) ?? ""
            #expect(deniedText.contains("cannot disable operator confirmation"), "\(action): \(deniedText)")
        }
    }

    /// `set_daemon_config`'s base tier is `.config`, but the three
    /// defence-affecting keys escalate to `.response` because turning them off
    /// REDUCES detection coverage. That escalation is a single `if` inside
    /// `agentCapabilityDenial` with no unit coverage; the protocol harness can
    /// only observe that *some* denial happened, never which tier was demanded.
    @Test("set_daemon_config escalates defence-affecting keys to the response tier")
    func defenceAffectingKeysEscalate() {
        // The grants file is root-owned so a test cannot fabricate one. Assert
        // against whatever this host actually has: honest on CI (no grants) and
        // on a dev box where the operator granted a tier.
        let granted = maccrab_mcp.loadAgentCapabilities()
        let defenceKey = "subscribe_file_open_events"
        #expect(maccrab_mcp.daemonConfigResponseKeys.contains(defenceKey))

        let denial = maccrab_mcp.agentCapabilityDenial(
            forTool: "set_daemon_config", args: ["key": defenceKey, "value": false])
        if granted.contains(.response) {
            #expect(denial == nil, "response tier is granted on this host, so the call must be allowed")
        } else {
            #expect(denial?["isError"] as? Bool == true)
            let text = ((denial?["content"] as? [[String: Any]])?.first?["text"] as? String) ?? ""
            #expect(text.contains("'response'"),
                    "a defence-affecting key must be denied at the RESPONSE tier, not the base config tier — got: \(text)")
        }

        // A safe tunable stays at the base tier.
        let safeDenial = maccrab_mcp.agentCapabilityDenial(
            forTool: "set_daemon_config", args: ["key": "behavior_alert_threshold", "value": 12.0])
        if granted.contains(.config) {
            #expect(safeDenial == nil)
        } else {
            let text = ((safeDenial?["content"] as? [[String: Any]])?.first?["text"] as? String) ?? ""
            #expect(text.contains("'config'"))
        }

        // An explicitly ungated read tool is never denied.
        #expect(maccrab_mcp.agentCapabilityDenial(forTool: "get_alerts", args: [:]) == nil)

        // Unknown/new names have no inherited authority. They fail closed even
        // if their spelling looks read-only; adding a switch case requires an
        // explicit classification in AgentControl.swift.
        let unknown = maccrab_mcp.agentCapabilityDenial(
            forTool: "get_future_unclassified_tool", args: [:])
        #expect(unknown?["isError"] as? Bool == true)
        let unknownText = ((unknown?["content"] as? [[String: Any]])?.first?["text"] as? String) ?? ""
        #expect(unknownText.contains("Denied unclassified MCP tool"))

        #expect(maccrab_mcp.agentToolCapability["classify_package_intent"] == .config)
        #expect(maccrab_mcp.agentToolCapability["forensics_check_plugin_updates"] == .config)
        #expect(maccrab_mcp.agentToolCapability["forensics_search_catalog"] == .config)
        #expect(maccrab_mcp.agentToolCapability["export_session_bundle"] == .response)
    }
}
