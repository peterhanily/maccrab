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
            let recentAlerts = (try? await alertStore.alerts(since: Date.distantPast, limit: 500)) ?? []
            let campaignCount = recentAlerts.filter { $0.ruleId.hasPrefix("maccrab.campaign.") }.count

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
            let ruleCount = files?.filter { $0.hasSuffix(".json") }.count ?? 0
            let seqDir = compiledDir + "/sequences"
            let seqFiles = try? FileManager.default.contentsOfDirectory(atPath: seqDir)
            let seqCount = seqFiles?.filter { $0.hasSuffix(".json") }.count ?? 0
            print("Rules:           \(ruleCount) standard, \(seqCount) sequence rule(s) loaded")
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
                print("Agent Traces:    Disabled (set MACCRAB_AGENT_TRACES=1 + MACCRAB_OTLP_RECEIVER=1 to enable)")
            }
        }

        // ── Suppressions ──────────────────────────────────────────────────
        let suppressFile = (supportDir as NSString).appendingPathComponent("suppressions.json")
        if let data = try? Data(contentsOf: URL(fileURLWithPath: suppressFile)),
           let suppressions = try? JSONDecoder().decode([String: [String]].self, from: data),
           !suppressions.isEmpty {
            let totalPaths = suppressions.values.reduce(0) { $0 + $1.count }
            print("Suppressions:    \(suppressions.count) rule(s), \(totalPaths) path(s)")
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
}
