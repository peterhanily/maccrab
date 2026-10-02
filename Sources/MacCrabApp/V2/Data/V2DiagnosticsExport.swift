import Foundation

/// A single inspectable support file assembled from explicit status fields.
/// No source files, raw errors, event bodies, paths, inventory, keys or audit
/// records are copied into the default export.
struct V2DiagnosticsExport: Identifiable, Sendable {
    let id = UUID()
    let data: Data
    let filename: String

    static func make(source: V2EngineSource, mode: String, heartbeat: V2HeartbeatSnapshot?,
                     failure: V2StartupFailure?, permissions: [V2MockPermission],
                     providerReadFailed: Bool, now: Date = Date()) throws -> V2DiagnosticsExport {
        var result: [String: Any] = [
            "schema_version": 4,
            "generated_at_unix": now.timeIntervalSince1970,
            "app_version": Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "unknown",
            "provider_mode": mode,
            "engine_source": source.directory == "/Library/Application Support/MacCrab" ? "installed_system" : "user_or_custom",
            "provider_read_failed": providerReadFailed,
            "redaction": "status_only_no_raw_errors_events_paths_inventory_or_secrets",
        ]
        if let heartbeat {
            var status: [String: Any] = [
                "written_at_unix": heartbeat.writtenAt.timeIntervalSince1970,
                "is_ready": heartbeat.isReady,
                "is_stale": heartbeat.isStale,
                "uptime_seconds": heartbeat.uptimeSeconds,
                "events_processed": heartbeat.eventsProcessed,
                "alerts_emitted": heartbeat.alertsEmitted,
                "sysext_has_fda": heartbeat.sysextHasFDA,
                "payload_truncated_total": heartbeat.payloadTruncatedTotal,
                "eslogger_dropped_total": heartbeat.esloggerDroppedTotal,
                "es_sensor_degraded": heartbeat.esSensorDegraded,
            ]
            if let phase = heartbeat.bootPhase {
                status["readiness"] = heartbeat.readiness.rawValue
                // The raw phase can change across versions. Preserve known
                // phases only; readiness still describes an unknown phase.
                let known = ["starting", "upgrading_store", "stores_ready", "storage_not_ready", "rules_loaded", "collectors_started", "ready"]
                status["boot_phase"] = known.contains(phase) ? phase : "other"
            }
            if let identity = heartbeat.engineIdentity {
                status["engine_pid"] = identity.pid
                status["engine_started_at_unix"] = identity.startedAtUnix
                status["engine_version"] = identity.version
                status["engine_build"] = identity.build
            }
            if let count = heartbeat.rulesLoaded { status["rules_loaded"] = count }
            if let progress = heartbeat.storeUpgradeProgress {
                status["upgrade_source_events"] = progress.sourceEvents
                status["upgrade_migrated_events"] = progress.migratedEvents
                status["upgrade_remaining_events"] = progress.remainingEvents
                if let expired = progress.expiredEvents { status["upgrade_expired_events"] = expired }
                if let corrupt = progress.corruptPreservedEvents { status["upgrade_corrupt_preserved_events"] = corrupt }
            }
            if let memory = heartbeat.residentMemoryMB { status["resident_memory_mb"] = memory }
            result["heartbeat"] = status
            if let dns = heartbeat.dnsCapture { result["dns_capture"] = dns.diagnosticDictionary }
            result["protection"] = protection(heartbeat)
            result["collectors"] = heartbeat.collectors.map { collector -> [String: Any] in
                ["name": collector.name, "state": collector.resolvedState.rawValue,
                 "event_count": collector.eventCount, "reported_error_present": collector.lastError != nil]
            }
        }
        if let failure {
            var report = failure.diagnosticDictionary
            report["historical"] = failure.isHistorical(heartbeat: heartbeat)
            result["startup_failure"] = report
        }
        // MacCrab's own rows only. The snapshot also holds every other app's
        // grants: that is inventory, and without the client names those rows
        // read as duplicates and contradictions.
        result["permissions"] = permissions.filter { $0.owner != .other }.map { permission -> [String: Any] in
            ["service": permission.serviceKey.isEmpty ? permission.service : permission.serviceKey,
             "owner": permission.owner.rawValue,
             "granted": permission.granted, "required": permission.required]
        }
        let data = try JSONSerialization.data(withJSONObject: result, options: [.prettyPrinted, .sortedKeys])
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd-HHmm"
        return .init(data: data, filename: "maccrab-diagnostics-\(formatter.string(from: now)).json")
    }
}

extension V2DiagnosticsExport {
    /// Every input behind the sidebar and Overview protection verdict, so a
    /// report of "Protection degraded" explains itself. Values are the same
    /// closed-vocabulary flags the app evaluates; free-text details stay out.
    static func protection(_ heartbeat: V2HeartbeatSnapshot) -> [String: Any] {
        func flag(_ value: Bool?) -> Any { value.map { $0 } ?? NSNull() }
        func text(_ value: String?) -> Any { value.map { $0 } ?? NSNull() }
        func number(_ value: Double?) -> Any { value.map { $0 } ?? NSNull() }
        func count(_ value: Int?) -> Any { value.map { $0 } ?? NSNull() }

        let collectors = V2CollectorSummary(states: heartbeat.collectors.map(\.resolvedState))
        let detectionWorkDegraded = heartbeat.detectionWorkLifecycle?.detectionProtectionDegraded
            ?? heartbeat.legacyDerivedWorkLifecycle?.featureDegraded
        var reasons: [String] = []
        if heartbeat.isStale { reasons.append("heartbeat_stale") }
        if heartbeat.readiness != .ready { reasons.append("engine_not_ready") }
        if !collectors.allEnabledHealthy { reasons.append("enabled_collector_unhealthy") }
        if heartbeat.rulesLoaded == 0 { reasons.append("no_rules_loaded") }
        if heartbeat.esSensorDegraded { reasons.append("es_sensor_degraded") }
        if heartbeat.traceGraphStorageAdmission?.evidenceUnavailable == true { reasons.append("tracegraph_evidence_unavailable") }
        if heartbeat.browserInventory?.degraded == true { reasons.append("browser_inventory_degraded") }
        if heartbeat.sequenceCheckpoint?.degraded == true { reasons.append("sequence_checkpoint_degraded") }
        if heartbeat.timerLifecycle?.featureDegraded == true { reasons.append("maintenance_timer_degraded") }
        if detectionWorkDegraded == true { reasons.append("detection_work_degraded") }
        if heartbeat.alertEvidenceBudget?.captureDegraded == true { reasons.append("alert_evidence_capture_degraded") }
        if heartbeat.alertEvidenceBudget?.transitionDegraded == true { reasons.append("alert_evidence_transition_degraded") }
        if heartbeat.alertWritesRequireAttention { reasons.append("alert_write_failure_recent") }

        var block: [String: Any] = [
            "resolved_from_heartbeat": String(describing: V2MenuBarProtectionStatus.resolve(heartbeat: heartbeat)),
            "reasons": reasons,
            "not_included": ["storage_errors_recent_window", "rule_tamper"],
            "readiness": heartbeat.readiness.rawValue,
            "heartbeat_stale": heartbeat.isStale,
            "rules_loaded": count(heartbeat.rulesLoaded),
            "collectors_enabled": collectors.enabledCount,
            "collectors_healthy": collectors.healthyCount,
            "collectors_not_healthy": heartbeat.collectors
                .filter { $0.resolvedState != .healthy && $0.resolvedState != .disabled }
                .map(\.name).sorted(),
            "es_sensor_degraded": heartbeat.esSensorDegraded,
            "browser_inventory_degraded": flag(heartbeat.browserInventory?.degraded),
            "maintenance_timer_degraded": flag(heartbeat.timerLifecycle?.featureDegraded),
            "detection_work_degraded": flag(detectionWorkDegraded),
            "alert_evidence_capture_degraded": flag(heartbeat.alertEvidenceBudget?.captureDegraded),
            "alert_evidence_transition_degraded": flag(heartbeat.alertEvidenceBudget?.transitionDegraded),
            "alert_insert_errors_total": count(heartbeat.alertInsertErrorsTotal),
            "alert_insert_failure_recent": flag(heartbeat.alertInsertFailureRecent),
            "alert_insert_last_error_at_unix": number(heartbeat.alertInsertLastErrorAt?.timeIntervalSince1970),
            "alert_write_failure_current": heartbeat.alertWritesRequireAttention,
        ]
        if let storage = heartbeat.traceGraphStorageAdmission {
            let telemetry = storage.writeTelemetry
            block["tracegraph"] = [
                "enabled": storage.enabled,
                "blocked": storage.blocked,
                "startup_blocked": storage.startupBlocked,
                "store_available": flag(storage.storeAvailable),
                "accepting_mutations": flag(storage.acceptingMutations),
                "reason": text(storage.reason),
                "write_telemetry_present": telemetry?.writeTelemetryPresent ?? false,
                "write_telemetry_complete": telemetry?.writeTelemetryComplete ?? false,
                "write_failed_totals_nonzero": flag(telemetry?.hasStickyWriteFailure),
                "write_failure_recent": flag(telemetry?.writeFailureRecent),
                "write_last_failure_at_unix": number(telemetry?.writeLastFailureAtUnix),
                "write_failure_current": flag(telemetry?.hasCurrentWriteFailure),
                "outstanding_backlog": flag(telemetry?.hasOutstandingBacklog),
                "write_conservation_maintained": flag(telemetry?.writeConservationMaintained),
                "recovery_mutation_barrier_degraded": telemetry?.recoveryMutationBarrierDegraded ?? false,
                "graph_write_degraded": storage.graphWriteDegraded,
                "evidence_unavailable": storage.evidenceUnavailable,
            ] as [String: Any]
        }
        if let checkpoint = heartbeat.sequenceCheckpoint {
            block["sequence_checkpoint"] = [
                "degraded": checkpoint.degraded,
                "restore_status": text(checkpoint.restoreStatus),
                "crash_rpo_bound_currently_maintained": flag(checkpoint.crashRPOBoundCurrentlyMaintained),
                "durable_carrier_valid": flag(checkpoint.durableCarrierValid),
                "orphan_cleanup_scan_truncated": flag(checkpoint.orphanCleanupScanTruncated),
                "state_continuity_maintained": flag(checkpoint.stateContinuityMaintained),
            ] as [String: Any]
        }
        return block
    }
}
