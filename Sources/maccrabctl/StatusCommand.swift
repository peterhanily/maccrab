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
                let traceStore = try TraceStore(path: tracesPath)
                let spanCount = (try? await traceStore.count()) ?? 0
                if spanCount > 0 {
                    print("Agent Traces:    \(spanCount) span(s) ingested  (\(tracesPath))")
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
}
