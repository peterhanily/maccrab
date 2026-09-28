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
            "schema_version": 3,
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
