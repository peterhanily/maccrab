import Foundation
import MacCrabCore

extension MacCrabCtl {
    static func showStatus() async {
        let supportDir = maccrabDataDir()
        let dbPath = supportDir + "/events.db"

        // LOCALIZE: "MacCrab Status"
        print("MacCrab Status")
        print("══════════════════════════════════════════════════════════════")

        // ── Daemon ────────────────────────────────────────────────────────
        let daemonRunning = isDaemonRunning()
        print("Daemon:          \(daemonRunning ? "Running ✓" : "Not running ✗")")
        if !daemonRunning {
            print("                 Release: open MacCrab.app → Enable Protection")
            print("                 Dev:     sudo maccrabd  (or: make run-root)")
        }

        // ── Kernel sensor ─────────────────────────────────────────────────
        // Without this the CLI/MCP surfaces were strictly less informative than
        // the dashboard: a total loss of the ES client left "Daemon: Running ✓"
        // as the only status line while no kernel event was being collected at
        // all. es_mode is the live result of the ES → eslogger → kdebug →
        // nothing fallback chain; the two degradation flags already existed in
        // the heartbeat but no CLI surface read them.
        if daemonRunning, let sensor = sensorHealthFromHeartbeat(supportDir: supportDir) {
            let native = sensor.mode == "native client"
            let healthy = native && !sensor.splitDegraded && !sensor.sensorDegraded
            print("Kernel Sensor:   \(sensor.mode) \(healthy ? "✓" : "⚠")")
            if !native {
                print("                 ⚠  Not using the native Endpoint Security client — kernel coverage is degraded or absent")
                print("                    Check the ES entitlement and Full Disk Access, and whether another EDR holds the ES client slots")
            }
            if sensor.splitDegraded {
                print("                 ⚠  ES file/exec client split degraded — a file-write flood can starve exec events")
            }
            if sensor.sensorDegraded {
                print("                 ⚠  Sensor degraded: \(sensor.degradedDetail)")
            }
            if sensor.backpressureDropped > 0 {
                print("                 ⚠  \(sensor.backpressureDropped) ES message(s) dropped at the worker in-flight cap since boot")
            }
        }

        // ── Database ──────────────────────────────────────────────────────
        if FileManager.default.fileExists(atPath: dbPath) {
            let attrs = try? FileManager.default.attributesOfItem(atPath: dbPath)
            let size = attrs?[.size] as? UInt64 ?? 0
            print("Database:        \(dbPath)")
            print("DB Size:         \(formatBytes(size))")
        } else {
            print("Database:        Not found (daemon has not run yet)")
        }

        // TraceGraph can be storage-shed while the daemon, collectors and main
        // events database stay healthy. Surface the forensic-evidence gap next
        // to storage instead of rendering an empty graph as "no activity".
        if daemonRunning {
            for line in alertEvidenceStorageStatusLines(
                supportDir: supportDir
            ) {
                print(line)
            }
            for line in traceGraphStorageStatusLines(supportDir: supportDir) {
                print(line)
            }
            for line in traceStoreStorageStatusLines(supportDir: supportDir) {
                print(line)
            }
            for line in sequenceCheckpointStatusLines(supportDir: supportDir) {
                print(line)
            }
            for line in llmRuntimeStatusLines(supportDir: supportDir) {
                print(line)
            }
            for line in workLifecycleStatusLines(supportDir: supportDir) {
                print(line)
            }
            for line in otlpReceiverLifecycleStatusLines(supportDir: supportDir) {
                print(line)
            }
        }

        // ── Events ────────────────────────────────────────────────────────
        do {
            let eventStore = try EventStore(directory: supportDir)
            let eventCount = (try? await eventStore.count()) ?? 0
            let recentEvents = (try? await eventStore.events(since: Date.distantPast, limit: 1)) ?? []
            print("Events:          \(eventCount) stored")
            if let latest = recentEvents.first {
                print("Last Event:      \(formatDate(latest.timestamp))")

                // Warn if last event is more than 5 minutes old and daemon is running
                if daemonRunning && Date().timeIntervalSince(latest.timestamp) > 300 {
                    let minutes = Int(Date().timeIntervalSince(latest.timestamp) / 60)
                    print("                 ⚠  No new events for \(minutes)m — collectors may have stalled")
                    print("                    Check: log stream --predicate 'subsystem==\"com.maccrab.agent\"'")
                }
            } else {
                print("Last Event:      None recorded")
            }
        } catch {
            print("Events:          (error reading: \(error))")
        }

        // ── Alerts ────────────────────────────────────────────────────────
        do {
            let alertStore = try AlertStore(directory: supportDir)
            let alertCount = (try? await alertStore.count()) ?? 0

            // Campaign count: alerts whose rule_id starts with "maccrab.campaign."
            // FF-04: counted SQL-side. Deriving it from the newest-500 sample
            // below reported "0 campaign(s)" on any host whose most recent 500
            // alerts hold no campaign row, while hundreds sat in the table.
            let recentAlerts = (try? await alertStore.alerts(since: Date.distantPast, limit: 500)) ?? []
            let campaignCount = (try? await alertStore.campaignCount()) ?? 0

            // Unsuppressed critical/high in last 24h
            let cutoff = Date().addingTimeInterval(-86400)
            let urgentAlerts = recentAlerts.filter {
                $0.timestamp >= cutoff
                && ($0.severity == .critical || $0.severity == .high)
                && !$0.suppressed
                && !$0.ruleId.hasPrefix("maccrab.campaign.")
            }

            print("Alerts:          \(alertCount) total, \(campaignCount) campaign(s)")
            if !urgentAlerts.isEmpty {
                print("                 ⚠  \(urgentAlerts.count) critical/high alert(s) in last 24h")
            }
            if let latestAlert = recentAlerts.filter({ !$0.ruleId.hasPrefix("maccrab.campaign.") }).first {
                print("Last Alert:      \(formatDate(latestAlert.timestamp))  \(latestAlert.ruleTitle)")
            }
        } catch {
            print("Alerts:          (error reading: \(error))")
        }

        // ── Rules ─────────────────────────────────────────────────────────
        let compiledDir = supportDir + "/compiled_rules"
        if FileManager.default.fileExists(atPath: compiledDir) {
            let files = try? FileManager.default.contentsOfDirectory(atPath: compiledDir)
            // Exclude manifest.json (and any non-rule sidecars) so the count
            // matches ground truth — mirrors build-release.sh's rule count.
            let ruleCount = files?.filter { $0.hasSuffix(".json") && $0 != "manifest.json" }.count ?? 0
            let seqDir = compiledDir + "/sequences"
            // v1.21.5: sequence rules are profile-gated at LOAD (skipped, not
            // present-but-disabled), so the shipped file count read as if every
            // sequence runs. Decode each compiled rule's `status` + the
            // configured rule_profile and report effective coverage.
            let profile = ruleProfileFromConfig(supportDir: supportDir)
            let seq = sequenceRuleCounts(seqDir: seqDir, ruleProfile: profile)
            let seqDisabled = seq.shipped - seq.active
            let seqLabel = seqDisabled > 0
                ? "\(seq.active) active / \(seq.shipped) shipped sequence rule(s) (\(seqDisabled) disabled by rule profile)"
                : "\(seq.active) sequence rule(s)"
            // v1.21.4 (F3): prefer the daemon's live active/loaded counts from
            // the heartbeat so we report EFFECTIVE coverage. The on-disk file
            // count counts every rule PRESENT; under the F-04 stable rule
            // profile many ship disabled, so the file count overstates how many
            // rules actually evaluate. Fall back to the file count when the
            // daemon isn't running (no fresh heartbeat) or on an older daemon
            // build that doesn't publish the keys.
            if daemonRunning, let hb = ruleCoverageFromHeartbeat(supportDir: supportDir), hb.loaded > 0 {
                if hb.active < hb.loaded {
                    print("Rules:           \(hb.active) active / \(hb.loaded) loaded standard, \(seqLabel)")
                    print("                 \(hb.loaded - hb.active) disabled by rule profile — set rule_profile: all to enable")
                } else {
                    print("Rules:           \(hb.active) standard, \(seqLabel)")
                }
            } else {
                print("Rules:           \(ruleCount) standard, \(seqLabel)")
            }
        } else {
            print("Rules:           No compiled rules found")
            print("                 Run: make compile-rules")
        }

        // ── Agent Traces (v1.9 PR-4) ──────────────────────────────────────
        // The trace store lives in `traces.db` next to events.db, but
        // the user-vs-system support-dir resolution in maccrabDataDir()
        // is keyed on events.db modification time — a stale
        // /Library/Application Support/MacCrab/events.db from a prior
        // root run can win even when the current daemon is writing to
        // ~/Library/.../traces.db. So we probe BOTH paths
        // independently and surface whichever has data.
        let userSupport = (FileManager.default.urls(
            for: .applicationSupportDirectory, in: .userDomainMask
        ).first?.appendingPathComponent("MacCrab").path)
            ?? NSHomeDirectory() + "/Library/Application Support/MacCrab"
        let candidatePaths = Array(Set([
            supportDir + "/traces.db",
            userSupport + "/traces.db",
        ]))
        var anyTraceLine = false
        for tracesPath in candidatePaths {
            guard FileManager.default.fileExists(atPath: tracesPath) else { continue }
            do {
                let traceStore = try TraceStore(
                    path: tracesPath,
                    forceReadOnly: true
                )
                let spanCount = (try? await traceStore.count()) ?? 0
                if spanCount > 0 {
                    print("Agent Traces:    \(spanCount) unauthenticated/self-reported span(s) ingested  (\(tracesPath))")
                    anyTraceLine = true
                }
            } catch {
                print("Agent Traces:    (error reading \(tracesPath): \(error))")
                anyTraceLine = true
            }
        }
        // Quality metric line — Plan v3 review #11 fixed label format.
        // v1.9 PR-5 audit (B3): rated counts now live in
        // attribution_overrides.db at the user-writable path; total
        // count of machine-attributed events comes from events.db.
        // Probe both at user + system paths.
        let candidateDirs = Array(Set([supportDir, userSupport]))
        var total = 0
        for dir in candidateDirs {
            guard FileManager.default.fileExists(atPath: dir + "/events.db") else { continue }
            if let es = try? EventStore(directory: dir),
               let n = try? await es.eventCountWithMachineAttribution() {
                total = max(total, n)
            }
        }
        for dir in candidateDirs {
            guard FileManager.default.fileExists(atPath: dir + "/attribution_overrides.db") else { continue }
            if let store = try? AttributionOverrideStore(directory: dir),
               let stats = try? await store.stats(totalEventsWithMachineAttribution: total),
               (stats.ratedCount > 0 || total > 0) {
                print("                 \(stats.formattedAccuracyLine)")
                anyTraceLine = true
                break
            }
        }
        // Even with no overrides, surface the total if non-zero.
        if !anyTraceLine, total > 0 {
            let zero = AttributionOverrideStats(
                ratedCount: 0, confirmedCount: 0,
                wrongToolCount: 0, noAgentCount: 0, unknownVerdictCount: 0,
                totalEventsWithMachineAttribution: total
            )
            print("                 \(zero.formattedAccuracyLine)")
            anyTraceLine = true
        }
        if !anyTraceLine {
            if isDaemonRunning() {
                print("Agent Traces:    Disabled (enable via the dashboard toggle / agent_traces_config.json, or MACCRAB_AGENT_TRACES=1 for dev)")
            }
        }

        // ── Suppressions ──────────────────────────────────────────────────
        let suppressFile = (supportDir as NSString).appendingPathComponent("suppressions.json")
        let suppressData = try? Data(contentsOf: URL(fileURLWithPath: suppressFile))
        if let data = suppressData,
           let suppressions = try? JSONDecoder().decode([String: [String]].self, from: data),
           !suppressions.isEmpty {
            let totalPaths = suppressions.values.reduce(0) { $0 + $1.count }
            print("Suppressions:    \(suppressions.count) rule(s), \(totalPaths) path(s)")
        } else if let data = suppressData,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let entries = json["entries"] as? [[String: Any]] {
            // v2 store (SuppressionManager's `{"version": 2, "entries": [...]}`).
            // The daemon rewrites the file into this shape on first load, so the
            // v1 decode above fails on every running install and status reported
            // "None configured" while the allowlist was in force.
            print("Suppressions:    \(entries.count) allowlist entry(ies) — see 'maccrabctl allow list'")
        } else {
            print("Suppressions:    None configured")
        }

        // ── Security Posture ──────────────────────────────────────────────
        let scoreResult = await SecurityScorer().calculate()
        let grade = scoreResult.grade
        let scoreStr = "\(scoreResult.totalScore)/100"
        let gradeIndicator = scoreResult.totalScore >= 80 ? "✓" : scoreResult.totalScore >= 60 ? "⚠" : "✗"
        print("Security Score:  \(grade) (\(scoreStr))  \(gradeIndicator)")
        let failedFactors = scoreResult.factors.filter { $0.status == "fail" }
        if !failedFactors.isEmpty {
            for factor in failedFactors.prefix(3) {
                print("                 ✗ \(factor.name): \(factor.detail)")
            }
            if failedFactors.count > 3 {
                print("                   … \(failedFactors.count - 3) more (run: maccrabctl security)")
            }
        }

        print("══════════════════════════════════════════════════════════════")
    }

    static func isDaemonRunning() -> Bool {
        // Probe both names: the v1.3+ system extension binary
        // (`com.maccrab.agent`) is the production engine; `maccrabd` is
        // the dev-mode standalone daemon used by `swift run maccrabd`.
        // Either being live means MacCrab is actively monitoring.
        for name in ["com.maccrab.agent", "maccrabd"] {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
            process.arguments = ["-x", name]
            process.standardOutput = FileHandle.nullDevice
            process.standardError = FileHandle.nullDevice
            try? process.run()
            process.waitUntilExit()
            if process.terminationStatus == 0 { return true }
        }
        return false
    }

    /// v1.21.5: the effective `rule_profile`, used to compute sequence-rule
    /// coverage. Prefer the heartbeat: on a release install daemon_config.json
    /// is root-0600, so this uid-501 process can NEVER read it and always fell
    /// back to "stable". That is right by accident on a default install and
    /// wrong for any operator who followed this command's own hint and set
    /// `rule_profile: all` — the sequence count would keep reporting the stable
    /// subset while the heartbeat-derived single-event count jumped. The daemon
    /// publishes its own effective profile into the 0644 heartbeat_rich.json
    /// (DaemonTimers), which is exactly what V2LiveDataProvider.ruleProfile
    /// already reads; keep the config read as a dev fallback for a non-root
    /// `swift run maccrabd` install where the config IS readable.
    static func ruleProfileFromConfig(supportDir: String) -> String {
        let heartbeat = supportDir + "/heartbeat_rich.json"
        if let data = try? Data(contentsOf: URL(fileURLWithPath: heartbeat)),
           let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let profile = json["rule_profile"] as? String, !profile.isEmpty {
            return profile
        }
        let path = supportDir + "/daemon_config.json"
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let profile = json["rule_profile"] as? String else {
            return "stable"
        }
        return profile
    }

    /// v1.21.5: effective sequence coverage — decode each compiled sequence
    /// rule's `status` and apply the same semantics as SequenceEngine.loadRules:
    /// deprecated never loads under any profile; a missing status key is
    /// grandfathered "stable"; profile "all" loads every non-deprecated rule,
    /// anything else (incl. unknown values) loads only "stable".
    static func sequenceRuleCounts(seqDir: String, ruleProfile: String) -> (active: Int, shipped: Int) {
        struct Stub: Decodable { let status: String? }
        let files = (try? FileManager.default.contentsOfDirectory(atPath: seqDir))?
            .filter { $0.hasSuffix(".json") } ?? []
        let loadAll = ruleProfile.lowercased() == "all"
        var active = 0
        for file in files {
            var status = "stable" // unreadable/undecodable ≈ missing key: grandfathered
            if let data = try? Data(contentsOf: URL(fileURLWithPath: seqDir + "/" + file)),
               let stub = try? JSONDecoder().decode(Stub.self, from: data) {
                status = (stub.status ?? "stable").lowercased()
            }
            if status == "deprecated" { continue }
            if loadAll || status == "stable" { active += 1 }
        }
        return (active, files.count)
    }

    /// v1.21.4 (F3): read the daemon's live single-event rule coverage from the
    /// rich heartbeat — `rules_active` (rules that will actually evaluate) vs
    /// `rules_loaded` (rules present on disk). Returns nil when the heartbeat is
    /// missing or predates these keys (older daemon), in which case the caller
    /// falls back to counting compiled rule files.
    static func ruleCoverageFromHeartbeat(supportDir: String) -> (active: Int, loaded: Int)? {
        let path = supportDir + "/heartbeat_rich.json"
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let active = json["rules_active"] as? Int,
              let loaded = json["rules_loaded"] as? Int else {
            return nil
        }
        return (active, loaded)
    }

    /// Kernel-sensor health from the rich heartbeat: which event source the
    /// boot-time fallback chain settled on, plus the degradation flags the
    /// daemon already tracked but no CLI surface read. Returns nil when the
    /// heartbeat is missing or predates the `es_mode` key (older daemon), in
    /// which case the caller prints nothing rather than a misleading red.
    static func sensorHealthFromHeartbeat(supportDir: String)
        -> (mode: String, splitDegraded: Bool, sensorDegraded: Bool,
            degradedDetail: String, backpressureDropped: UInt64)? {
        let path = supportDir + "/heartbeat_rich.json"
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let mode = json["es_mode"] as? String else {
            return nil
        }
        return (
            mode,
            (json["es_client_split_degraded"] as? Bool) ?? false,
            (json["es_sensor_degraded"] as? Bool) ?? false,
            (json["es_sensor_degraded_detail"] as? String) ?? "",
            (json["es_copy_backpressure_dropped_total"] as? NSNumber)?.uint64Value ?? 0
        )
    }

    /// Effective post-split caps from the running engine. Never re-label the
    /// legacy 420 MiB event+evidence envelope as an event-only database cap.
    static func alertEvidenceStorageStatusLines(
        supportDir: String
    ) -> [String] {
        guard let budget = HeartbeatSnapshot
            .readFreshest(supportDirs: [supportDir])?
            .alertEvidenceBudget,
              let events = budget.eventsFamilyEffectiveCapBytes,
              let alerts = budget.alertsFamilyCombinedCapBytes,
              let total = budget.eventsAndAlertsTotalCapBytes else {
            return []
        }
        func mib(_ bytes: Int64) -> Int64 {
            bytes / SQLitePersistentStorePolicy.bytesPerMiB
        }
        var lines = [
            "Storage Caps:    LIVE transition-aware: events.db \(mib(events)) MiB; alerts.db \(mib(alerts)) MiB incl. evidence; combined \(mib(total)) MiB"
        ]
        if let steadyEvents = budget.eventsFamilySteadyStateCapBytes,
           let steadyTotal = budget.eventsAndAlertsSteadyStateTotalCapBytes {
            lines.append("                 STEADY STATE after legacy evidence ages out: events.db \(mib(steadyEvents)) MiB; combined \(mib(steadyTotal)) MiB")
        }
        if let reserve = budget.legacyTransitionReserveBytes, reserve > 0 {
            let maximum = budget.legacyTransitionMaxBytes.map { mib($0) } ?? -1
            var transition = "                 Legacy evidence reserve: \(mib(reserve)) MiB live (maximum \(maximum) MiB)"
            if let rows = budget.legacyRowCount { transition += "; rows=\(rows)" }
            if let charged = budget.legacyChargedBytes {
                transition += "; charged=\(mib(charged)) MiB"
            }
            lines.append(transition)
        }
        if budget.legacyTransitionMeasurementFailed == true {
            lines.append("                 ⚠  Legacy evidence measurement failed; the bounded maximum transition reserve is retained fail-closed.")
        }
        if let offered = budget.captureOfferedTotal {
            let accepting = budget.captureAccepting.map { $0 ? "yes" : "no" }
                ?? "unknown"
            let conserving = budget.captureConservationMaintained
                .map { $0 ? "yes" : "NO" } ?? "unknown"
            lines.append("Evidence Worker: offered=\(offered), completed=\(budget.captureCompletedTotal ?? -1), failed=\(budget.captureFailuresTotal ?? -1), shed=\(budget.captureShedTotal ?? -1), pending=\(budget.capturePending ?? -1), in_flight=\(budget.captureInFlight ?? -1), capacity=\(budget.captureQueueCapacity ?? -1), accepting=\(accepting), conserving=\(conserving)")
            if budget.captureDegraded {
                lines.append("                 ⚠  Alert evidence capture is degraded; a single in-flight job is normal, but failure/shedding/accounting drift or pending work is not.")
            }
        }
        if budget.allocatedBytesExact != nil
            || budget.mutationGeneration != nil
            || budget.fullRefreshesTotal != nil {
            let exact = budget.allocatedBytesExact.map { $0 ? "yes" : "no" }
                ?? "unknown"
            let generation = budget.mutationGeneration.map { String($0) }
                ?? "unknown"
            let refreshes = budget.fullRefreshesTotal.map { String($0) }
                ?? "unknown"
            lines.append("Evidence Budget: allocated_exact=\(exact), mutation_generation=\(generation), full_refreshes=\(refreshes)")
        }
        if budget.allocatedBytesExact == false {
            lines.append("                 Evidence allocation is a conservative upper bound pending an exact DBSTAT refresh.")
        }
        if budget.overBudget == true || budget.alertsFamilyBlocked == true {
            let reason = budget.alertsFamilyReason
                .flatMap { $0.isEmpty ? nil : $0 }
                ?? "evidence or alerts family budget exceeded"
            lines.append("                 ⚠  Alert evidence persistence degraded (\(reason))")
        }
        return lines
    }

    static func timerLifecycleStatusLines(supportDir: String) -> [String] {
        guard let timers = HeartbeatSnapshot
            .readFreshest(supportDirs: [supportDir])?
            .timerLifecycle else { return [] }
        return lifecycleStatusLines(
            label: "Maintenance:",
            lifecycle: timers,
            degraded: timers.featureDegraded,
            degradedDetail: "A maintenance/retention operation was lost, did not join cleanly, or has incomplete accounting; live detection may continue, but that maintenance guarantee is degraded."
        )
    }

    static func workLifecycleStatusLines(supportDir: String) -> [String] {
        guard let heartbeat = HeartbeatSnapshot
            .readFreshest(supportDirs: [supportDir]) else { return [] }
        var lines: [String] = []
        if let timers = heartbeat.timerLifecycle {
            lines.append(contentsOf: lifecycleStatusLines(
                label: "Maintenance:",
                lifecycle: timers,
                degraded: timers.featureDegraded,
                degradedDetail: "A maintenance/retention operation was lost, did not join cleanly, or has incomplete accounting; live detection may continue, but that maintenance guarantee is degraded."
            ))
        }
        func append(
            _ label: String,
            _ lifecycle: HeartbeatSnapshot.TimerLifecycle?,
            degraded: (HeartbeatSnapshot.TimerLifecycle) -> Bool,
            detail: String
        ) {
            guard let lifecycle else { return }
            lines.append(contentsOf: lifecycleStatusLines(
                label: label,
                lifecycle: lifecycle,
                degraded: degraded(lifecycle),
                degradedDetail: detail
            ))
        }
        append(
            "Liveness:", heartbeat.livenessTimerLifecycle,
            degraded: { $0.featureDegraded },
            detail: "The independent liveness heartbeat lost work, did not join cleanly, or has incomplete accounting; external process-health observations may be incomplete."
        )
        append(
            "Startup Work:", heartbeat.startupWorkLifecycle,
            degraded: { $0.featureDegraded },
            detail: "A boot hydration or startup worker was lost, did not join cleanly, or has incomplete accounting; startup feature completeness is degraded."
        )
        append(
            "Detection Work:", heartbeat.detectionWorkLifecycle,
            degraded: { $0.detectionProtectionDegraded },
            detail: "PROTECTION DEGRADED: a security decision was rejected, shed, left unjoined, or could not be accounted for completely. Lossless inline overload fallback and intentional coalescing are not loss."
        )
        append(
            "AI Advisory:", heartbeat.advisoryWorkLifecycle,
            degraded: { $0.featureDegraded },
            detail: "AI/advisory features shed work or reported incomplete ownership; deterministic detection and locally persisted alerts continue."
        )
        append(
            "Alert Outputs:", heartbeat.outputWorkLifecycle,
            degraded: { $0.featureDegraded },
            detail: "Notification or external delivery shed work or reported incomplete ownership; detection and local alert persistence continue."
        )

        let splitPresent = heartbeat.livenessTimerLifecycle != nil
            || heartbeat.startupWorkLifecycle != nil
            || heartbeat.detectionWorkLifecycle != nil
            || heartbeat.advisoryWorkLifecycle != nil
            || heartbeat.outputWorkLifecycle != nil
        if !splitPresent {
            append(
                "Legacy Derived:", heartbeat.legacyDerivedWorkLifecycle,
                degraded: { $0.featureDegraded },
                detail: "This older aggregate cannot attribute loss to detection, AI advisory, or output delivery; upgrade for exact lane health."
            )
        }
        return lines
    }

    private static func lifecycleStatusLines(
        label: String,
        lifecycle: HeartbeatSnapshot.TimerLifecycle,
        degraded: Bool,
        degradedDetail: String
    ) -> [String] {
        let status = degraded ? "Degraded ⚠" : "Conserving ✓"
        let paddedLabel = label.padding(toLength: 16, withPad: " ", startingAt: 0)
        var lines = [
            "\(paddedLabel)\(status) (offered=\(lifecycle.offeredHandlersTotal ?? 0), accepted=\(lifecycle.acceptedHandlersTotal ?? 0), completed=\(lifecycle.completedHandlersTotal ?? 0), in_flight=\(lifecycle.inFlightHandlers ?? 0)/\(lifecycle.maximumInFlightHandlers ?? 0), rejected=\(lifecycle.rejectedHandlersTotal ?? 0), closed=\(lifecycle.closedRejectedHandlersTotal ?? 0), overload_shed=\(lifecycle.overloadShedHandlersTotal ?? 0), coalesced=\(lifecycle.coalescedHandlersTotal ?? 0), inline_fallback=\(lifecycle.inlineFallbackHandlersTotal ?? 0), accepted_conserves=\(lifecycle.conservesAcceptedHandlers.map { String($0) } ?? "unknown"), offered_conserves=\(lifecycle.conservesOfferedHandlers.map { String($0) } ?? "unknown"))"
        ]
        if degraded {
            lines.append("                 ⚠  \(degradedDetail)")
        } else if lifecycle.losslessPressureObserved {
            lines.append("                 Capacity pressure was handled without measured loss (coalesced or run inline).")
        }
        return lines
    }

    static func otlpReceiverLifecycleStatusLines(
        supportDir: String
    ) -> [String] {
        guard let lifecycle = HeartbeatSnapshot
            .readFreshest(supportDirs: [supportDir])?
            .otlpReceiverLifecycle else { return [] }
        let state = lifecycle.featureDegraded
            ? "Feature degraded ⚠" : "Conserving ✓"
        var lines = [
            "Agent OTLP:     \(state) (listeners accepted=\(lifecycle.listenersAcceptedTotal ?? 0), completed=\(lifecycle.listenersCompletedTotal ?? 0), active=\(lifecycle.activeListeners ?? 0), ready=\(lifecycle.readyListeners ?? 0), rejected_after_seal=\(lifecycle.listenersRejectedAfterSealTotal ?? 0), conserves=\(lifecycle.listenersConserved.map { String($0) } ?? "unknown"); connections accepted=\(lifecycle.connectionsAcceptedTotal ?? 0), completed=\(lifecycle.connectionsCompletedTotal ?? 0), active=\(lifecycle.activeConnections ?? 0), rejected_after_seal=\(lifecycle.connectionsRejectedAfterSealTotal ?? 0), rejected_at_capacity=\(lifecycle.connectionsRejectedAtCapacityTotal ?? 0), conserves=\(lifecycle.connectionsConserved.map { String($0) } ?? "unknown"); body accepted=\(lifecycle.bodyTasksAcceptedTotal ?? 0), completed=\(lifecycle.bodyTasksCompletedTotal ?? 0), cancelled=\(lifecycle.bodyTasksCancelledTotal ?? 0), rejected=\(lifecycle.bodyTasksRejectedTotal ?? 0), in_flight=\(lifecycle.bodyTasksInFlight ?? 0)/\(lifecycle.maximumBodyTasks ?? 0), conserves=\(lifecycle.bodyTasksConserved.map { String($0) } ?? "unknown"); callbacks accepted=\(lifecycle.callbackTasksAcceptedTotal ?? 0), completed=\(lifecycle.callbackTasksCompletedTotal ?? 0), cancelled=\(lifecycle.callbackTasksCancelledTotal ?? 0), rejected=\(lifecycle.callbackTasksRejectedTotal ?? 0), in_flight=\(lifecycle.callbackTasksInFlight ?? 0)/\(lifecycle.maximumCallbackTasks ?? 0), conserves=\(lifecycle.callbackTasksConserved.map { String($0) } ?? "unknown"); lifecycle_operations=\(lifecycle.lifecycleOperationsInProgress ?? 0), cleanly_stopped=\(lifecycle.cleanlyStopped.map { String($0) } ?? "unknown"), last_shutdown_clean=\(lifecycle.lastShutdownClean.map { String($0) } ?? "not_attempted"), shutdown_timeouts=\(lifecycle.shutdownTimeoutsTotal ?? 0))"
        ]
        if lifecycle.featureDegraded {
            lines.append("                 ⚠  Unauthenticated/self-reported OTLP input was rejected, ownership was incomplete/non-conserving, sealed work remains, a lifecycle operation is still in progress, or shutdown was unclean; kernel detection continues.")
        } else if lifecycle.acceptingListeners == true {
            lines.append("                 Receiver is open; active listeners/connections/callbacks/body tasks and cleanly_stopped=false are normal while all ownership ledgers conserve.")
        }
        return lines
    }

    /// Operator-facing TraceGraph persistence status from the shared heartbeat
    /// DTO. Kept pure apart from the bounded heartbeat read so the shipped CLI
    /// output can be pinned with a fixture in `MacCrabCLITests`.
    static func traceGraphStorageStatusLines(supportDir: String) -> [String] {
        guard let storage = HeartbeatSnapshot
            .readFreshest(supportDirs: [supportDir])?
            .traceGraphStorageAdmission
        else { return [] }

        let unavailable = storage.blocked == true
            || storage.storeAvailable == false
            || storage.enabled == false
        guard unavailable || storage.graphWriteDegraded else {
            return ["TraceGraph:      Active ✓"]
        }

        if !unavailable, storage.graphWriteDegraded {
            var lines = ["TraceGraph:      Evidence writes degraded ⚠"]
            if storage.hasStickyWriteFailure == true {
                lines.append(
                    "                 Failed since boot: events=\(storage.ingestEventsFailedTotal ?? -1), batches=\(storage.writeBatchesFailedTotal ?? -1), rows=\(storage.writeRowsFailedTotal ?? -1)."
                )
            }
            if storage.writeConservationMaintained == false {
                lines.append("                 ⚠  Ingest/write accounting does not conserve; persisted evidence totals are not trustworthy.")
            }
            if storage.writeTelemetryPresent && !storage.writeTelemetryComplete {
                lines.append("                 ⚠  TraceGraph write accounting is incomplete; missing counters cannot be treated as healthy.")
            }
            if storage.hasOutstandingBacklog == true {
                let rows = (storage.pendingEntityRows ?? 0) + (storage.pendingEdgeRows ?? 0)
                lines.append("                 ⚠  Outstanding backlog: \(storage.ingestEventsPending ?? -1) event(s), \(rows) row(s); repeated heartbeats mean the writer is stuck.")
            }
            return lines
        }

        let state: String
        if storage.startupBlocked == true {
            state = "Paused at startup ⚠"
        } else if storage.storeAvailable == false || storage.enabled == false {
            state = "Persistence unavailable ⚠"
        } else {
            state = "Persistence paused ⚠"
        }

        let reason = storage.reason.flatMap { $0.isEmpty ? nil : $0 }
            ?? "reason not reported"
        var lines = [
            "TraceGraph:      \(state)",
            "                 Detection continues, but new causal evidence is not being recorded (\(reason)).",
        ]
        if storage.startupBlocked == true {
            lines.append("                 Free disk space or adjust the TraceGraph storage limit, then restart MacCrab.")
        }
        if storage.hasStickyWriteFailure == true {
            lines.append(
                "                 Failed since boot: events=\(storage.ingestEventsFailedTotal ?? -1), batches=\(storage.writeBatchesFailedTotal ?? -1), rows=\(storage.writeRowsFailedTotal ?? -1)."
            )
        }
        if storage.writeConservationMaintained == false {
            lines.append("                 ⚠  Ingest/write accounting does not conserve; persisted evidence totals are not trustworthy.")
        }
        if storage.writeTelemetryPresent && !storage.writeTelemetryComplete {
            lines.append("                 ⚠  TraceGraph write accounting is incomplete; missing counters cannot be treated as healthy.")
        }
        if storage.hasOutstandingBacklog == true {
            let rows = (storage.pendingEntityRows ?? 0) + (storage.pendingEdgeRows ?? 0)
            lines.append("                 ⚠  Outstanding backlog: \(storage.ingestEventsPending ?? -1) event(s), \(rows) row(s); repeated heartbeats mean the writer is stuck.")
        }
        return lines
    }

    /// Content-free, fixed-cardinality AI request accounting. Transport health
    /// alone is insufficient: feature attribution, semantic fail-closed
    /// rejection, and all three exact conservation ledgers stay visible.
    static func llmRuntimeStatusLines(supportDir: String) -> [String] {
        guard let llm = HeartbeatSnapshot
            .readFreshest(supportDirs: [supportDir])?
            .llm else { return [] }
        guard llm.configured == true else {
            return ["AI Runtime:      Not configured"]
        }
        guard let runtime = llm.runtimeTelemetry else {
            if llm.runtimeTelemetryEncodingFailed == true {
                return [
                    "AI Runtime:      Telemetry unavailable ⚠",
                    "                 The engine could not encode its content-free request ledger; AI accounting is unknown.",
                ]
            }
            return ["AI Runtime:      Accounting unavailable (older engine)"]
        }

        let totals = runtime.totals
        let outcomes = totals.outcomes
        let semantic = totals.downstreamValidation
        let conserving = llm.runtimeConservationMaintained == true
        let unspecified = llm.unspecifiedRequestsTotal ?? 0
        let attributionMark = unspecified == 0 ? "✓" : "⚠"
        let semanticMark = semantic.finalRejection == 0 ? "✓" : "⚠"
        let featureTotals = runtime.perFeature.map {
            "\($0.feature.rawValue)=\($0.counters.requestedTotal)"
        }.joined(separator: ", ")

        return [
            "AI Runtime:      requested=\(totals.requestedTotal), in_flight=\(totals.currentInFlight), backend_calls=\(totals.backendCallsStartedTotal) \(conserving ? "✓" : "⚠ accounting drift")",
            "                 outcomes: success=\(outcomes.success), cache_hit=\(outcomes.cacheHit), backend_failure=\(outcomes.backendFailure), circuit_rejection=\(outcomes.circuitRejection), privacy_rejection=\(outcomes.privacyRejection), admission_shed=\(outcomes.admissionShed), cancellation=\(outcomes.cancellation), response_oversize=\(outcomes.responseOversize)",
            "AI Attribution:  unspecified=\(unspecified) \(attributionMark); features: \(featureTotals)",
            "AI Validation:   operations=\(semantic.operationsStartedTotal), current=\(semantic.currentOperations), accepted=\(semantic.accepted), retries=\(semantic.retryRequested), final_rejection=\(semantic.finalRejection) \(semanticMark)",
        ]
    }

    /// Restart continuity for in-flight multi-event detections. A missing block
    /// means an older daemon and remains unknown; it must not be fabricated as
    /// healthy. Digests are intentionally omitted from the operator surface.
    static func sequenceCheckpointStatusLines(supportDir: String) -> [String] {
        guard let snapshot = HeartbeatSnapshot
            .readFreshest(supportDirs: [supportDir]),
              let checkpoint = snapshot.sequenceCheckpoint
        else { return [] }

        let status = checkpoint.restoreStatus ?? "unknown"
        if snapshot.sequenceStateContinuityMaintained == false {
            let reason = snapshot.sequenceStateContinuityDetail
                .flatMap { $0.isEmpty ? nil : $0 }
                ?? "runtime state loss or accounting drift"
            return [
                "Sequence State:  Runtime continuity degraded ⚠",
                "                 Some in-flight multi-event detections were lost or cannot be accounted for exactly (\(reason)).",
                "                 partials=\(snapshot.sequencePartialsInFlight ?? -1), partial_evictions=\(snapshot.sequencePartialsEvictedTotal ?? -1), pending=\(snapshot.sequencePendingStepsCurrent ?? -1), pending_evictions=\(snapshot.sequencePendingStepsEvictedTotal ?? -1)",
            ]
        }
        if checkpoint.durableCarrierValid == false {
            return [
                "Sequence State:  Durable checkpoint unavailable ⚠",
                "                 Detection continues, but in-flight multi-event state cannot currently survive a restart.",
            ]
        }
        if checkpoint.orphanCleanupScanTruncated == true {
            return [
                "Sequence State:  Checkpoint disk accounting incomplete ⚠",
                "                 The bounded temporary-file cleanup scan was truncated; checkpoint storage use is not fully verified.",
            ]
        }
        if status == "rejected" {
            return [
                "Sequence State:  Previous checkpoint rejected ⚠",
                "                 In-flight multi-event detections from before this engine start could not be recovered.",
            ]
        }
        if checkpoint.crashRPOBoundCurrentlyMaintained == false {
            let reason = checkpoint.lastFailure
                .flatMap { $0.isEmpty ? nil : $0 }
                ?? "configured crash-recovery window is not currently guaranteed"
            return [
                "Sequence State:  Restart continuity degraded ⚠",
                "                 Detection continues, but a crash could lose partial sequence state (\(reason)).",
            ]
        }
        if checkpoint.crashRPOBoundCurrentlyMaintained == true {
            var lines: [String]
            if let seconds = checkpoint.configuredCrashRPOSeconds {
                lines = [
                    "Sequence State:  Restart-safe ✓ (≤\(Int(seconds.rounded()))s partial-state RPO)"
                ]
            } else {
                lines = ["Sequence State:  Restart-safe ✓"]
            }
            if let invalidations = checkpoint.carrierInvalidationsTotal,
               invalidations > 0 {
                let reason = checkpoint.lastCarrierInvalidationReason
                    .flatMap { $0.isEmpty ? nil : $0 }
                    ?? "reason unavailable"
                lines.append("                 Recovered carrier invalidations: \(invalidations) (last: \(reason)).")
            }
            return lines
        }
        return ["Sequence State:  Status unavailable"]
    }

    /// Operator-facing traces.db persistence state. A disabled receiver is an
    /// intentional configuration, while an enabled-but-blocked store means new
    /// unauthenticated/self-reported OTLP spans are being shed.
    static func traceStoreStorageStatusLines(supportDir: String) -> [String] {
        guard let storage = HeartbeatSnapshot
            .readFreshest(supportDirs: [supportDir])?
            .traceStoreStorageAdmission
        else { return [] }

        if storage.reason == "receiver_disabled",
           storage.blocked != true {
            return ["Agent Trace DB:  Receiver disabled"]
        }

        let unavailable = storage.blocked == true
            || (storage.enabled == true && storage.storeAvailable == false)
        guard unavailable else {
            return ["Agent Trace DB:  Active ✓ (unauthenticated/self-reported OTLP)"]
        }

        let state: String
        if storage.startupBlocked == true {
            state = "Paused at startup ⚠"
        } else if storage.storeAvailable == false || storage.enabled == false {
            state = "Persistence unavailable ⚠"
        } else {
            state = "Persistence paused ⚠"
        }

        let reason = storage.reason.flatMap { $0.isEmpty ? nil : $0 }
            ?? "reason not reported"
        var lines = [
            "Agent Trace DB:  \(state)",
            "                 Unauthenticated/self-reported OTLP spans are not being recorded (\(reason)); kernel detection continues.",
        ]
        if storage.startupBlocked == true {
            lines.append("                 Free disk space or adjust the traces storage limit, then restart MacCrab.")
        }
        return lines
    }
}
