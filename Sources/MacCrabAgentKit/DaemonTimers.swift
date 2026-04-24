import Foundation
import MacCrabCore
import SQLite3
import os.log

/// Creates and starts all periodic timers (forensic scans, hourly tasks,
/// stats logging, retention pruning, maintenance sweeps).
/// Returns the timer sources so they stay alive.
enum DaemonTimers {
    struct Handles {
        let forensicTimer: DispatchSourceTimer
        let hourlyTimer: DispatchSourceTimer
        let statsTimer: DispatchSourceTimer
        let pruneTimer: DispatchSourceTimer
        let sizeCapTimer: DispatchSourceTimer
        let maintenanceTimer: DispatchSourceTimer
        let feedbackTimer: DispatchSourceTimer
        let heartbeatTimer: DispatchSourceTimer
    }

    static func start(state: DaemonState, eventCount: @escaping () -> UInt64, alertCount: @escaping () -> UInt64, startTime: Date) -> Handles {
        // Periodic forensic scans (crash reports, power anomalies, library inventory)
        let forensicTimer = DispatchSource.makeTimerSource(queue: .global())
        forensicTimer.schedule(deadline: .now() + 120, repeating: 300) // First at 2min, then every 5min
        forensicTimer.setEventHandler {
            Task {
                // Crash report mining.
                // Route every synthetic alert here through the shared
                // AlertDeduplicator. Without it, a single long-lived process
                // (lldb-rpc-server, WindowServer, etc.) emitting the same
                // finding on successive scans produces a fresh alert every
                // tick — observed in production as 19 identical alerts per
                // 48 h for a single Xcode debug session.
                let exploits = await state.crashReportMiner.scan()
                for exploit in exploits {
                    let ruleId = "maccrab.forensic.crash-exploit-\(exploit.indicator)"
                    if await state.deduplicator.shouldSuppress(ruleId: ruleId, processPath: exploit.reportPath) { continue }
                    let alert = Alert(
                        ruleId: ruleId,
                        ruleTitle: "Exploitation Indicator in Crash Report: \(exploit.processName)",
                        severity: exploit.severity,
                        eventId: UUID().uuidString,
                        processPath: exploit.reportPath, processName: exploit.processName,
                        description: "\(exploit.indicator): \(exploit.excerpt)",
                        mitreTactics: "attack.execution", mitreTechniques: "attack.t1203",
                        suppressed: false
                    )
                    do { try await state.alertStore.insert(alert: alert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                    await state.deduplicator.recordAlert(ruleId: ruleId, processPath: exploit.reportPath)
                    if exploit.severity >= .high { await state.notifier.notify(alert: alert) }
                    print("[CRASH] \(exploit.indicator) in \(exploit.processName)")
                }

                // Power anomaly detection.
                let anomalies = await state.powerAnomalyDetector.scan()
                for anomaly in anomalies {
                    let ruleId = "maccrab.forensic.power-\(anomaly.type.rawValue)"
                    let key = anomaly.processName  // processPath is nil for power events
                    if await state.deduplicator.shouldSuppress(ruleId: ruleId, processPath: key) { continue }
                    let alert = Alert(
                        ruleId: ruleId,
                        ruleTitle: "Power Anomaly: \(anomaly.processName) \(anomaly.type.rawValue)",
                        severity: anomaly.severity,
                        eventId: UUID().uuidString,
                        processPath: nil, processName: anomaly.processName,
                        description: anomaly.detail,
                        mitreTactics: "attack.execution", mitreTechniques: "attack.t1496",
                        suppressed: false
                    )
                    do { try await state.alertStore.insert(alert: alert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                    await state.deduplicator.recordAlert(ruleId: ruleId, processPath: key)
                }

                // Library inventory scan (every other cycle -- resource intensive).
                // LibraryInventory also does its own (pid, libraryPath) dedup
                // internally so the same loaded dylib doesn't re-alert across
                // scans even if the surrounding AlertDeduplicator window expires.
                let injected = await state.libraryInventory.scanAllProcesses()
                for lib in injected {
                    let ruleId = "maccrab.forensic.injected-library"
                    if await state.deduplicator.shouldSuppress(ruleId: ruleId, processPath: lib.processPath) { continue }
                    let alert = Alert(
                        ruleId: ruleId,
                        ruleTitle: "Injected Library: \(lib.processName) loaded \((lib.libraryPath as NSString).lastPathComponent)",
                        severity: lib.severity,
                        eventId: UUID().uuidString,
                        processPath: lib.processPath, processName: lib.processName,
                        description: "\(lib.reason). Library: \(lib.libraryPath)",
                        mitreTactics: "attack.defense_evasion", mitreTechniques: "attack.t1574.006",
                        suppressed: false
                    )
                    do { try await state.alertStore.insert(alert: alert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                    await state.deduplicator.recordAlert(ruleId: ruleId, processPath: lib.processPath)
                    if lib.severity >= .high { await state.notifier.notify(alert: alert) }
                    print("[INJECT] \(lib.processName) <- \(lib.libraryPath)")
                }
            }
        }
        forensicTimer.resume()

        // Hourly: security score refresh, vuln scan, privacy audit purge, digest
        let hourlyTimer = DispatchSource.makeTimerSource(queue: .global())
        hourlyTimer.schedule(deadline: .now() + 3600, repeating: 3600)
        hourlyTimer.setEventHandler {
            Task {
                // Refresh security score
                let score = await state.securityScorer.calculate()
                logger.info("Security score: \(score.totalScore)/100 (\(score.grade))")

                // LLM security posture analysis (non-blocking, hourly, only if score < 90)
                if let llm = state.llmService, score.totalScore < 90 {
                    let totalScore = score.totalScore
                    let grade = score.grade
                    let factors = score.factors.map { ($0.name, $0.category, $0.score, $0.maxScore, $0.status, $0.detail) }
                    let recs = score.recommendations
                    Task {
                        if let analysis = await llm.query(
                            systemPrompt: LLMPrompts.securityScoreSystem,
                            userPrompt: LLMPrompts.securityScoreUser(
                                totalScore: totalScore, grade: grade,
                                factors: factors, recommendations: recs
                            ),
                            maxTokens: 512, temperature: 0.3
                        ) {
                            let scoreAlert = Alert(
                                ruleId: "maccrab.llm.security-score",
                                ruleTitle: "AI Security Recommendations (\(grade) — \(totalScore)/100)",
                                severity: .informational,
                                eventId: UUID().uuidString,
                                processPath: nil, processName: "maccrabd",
                                description: analysis.response,
                                mitreTactics: nil, mitreTechniques: nil,
                                suppressed: false
                            )
                            do { try await state.alertStore.insert(alert: scoreAlert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                            print("[LLM] Security score analysis: \(grade) (\(totalScore)/100)")
                        }
                    }
                }

                // Vulnerability scan — emit alerts for critical/high CVEs.
                // Alert ID = "vuln-<cveId>" so INSERT OR REPLACE deduplicates
                // at the DB level: same CVE updates the existing alert rather
                // than creating duplicates on every hourly scan.
                let vulns = await state.vulnScanner.scanInstalledApps()
                for vuln in vulns {
                    for v in vuln.vulnerabilities where v.severity == "critical" || v.severity == "high" {
                        logger.warning("Vulnerable app: \(vuln.appName) v\(vuln.installedVersion) -- \(v.cveId)")
                        let sev: Severity = v.severity == "critical" ? .critical : .high
                        let fixNote = v.fixedInVersion.map { " Fixed in \($0)." } ?? ""
                        let desc = "\(vuln.appName) \(vuln.installedVersion) contains \(v.cveId) (\(v.severity.uppercased())).\(fixNote) Update immediately."
                        let vulnAlert = Alert(
                            id: "vuln-\(v.cveId)",
                            ruleId: "maccrab.vuln.\(v.cveId)",
                            ruleTitle: "\(v.cveId) in \(vuln.appName) \(vuln.installedVersion)",
                            severity: sev,
                            eventId: "vuln-\(v.cveId)",
                            processPath: vuln.appPath,
                            processName: vuln.appName,
                            description: desc,
                            mitreTactics: nil,
                            mitreTechniques: nil,
                            suppressed: false
                        )
                        do { try await state.alertStore.insert(alert: vulnAlert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                    }
                }

                // Privacy egress anomaly alerts. Alert ID keyed on process +
                // anomaly kind so each unique (app, kind) pair produces one
                // alert regardless of scan frequency.
                let privacyAnomalies = await state.appPrivacyAuditor.checkForAnomalies()
                for anomaly in privacyAnomalies {
                    logger.warning("Privacy anomaly [\(anomaly.kind.rawValue)]: \(anomaly.detail)")
                    let alertId = "privacy-\(anomaly.processName)-\(anomaly.kind.rawValue)"
                    let privAlert = Alert(
                        id: alertId,
                        ruleId: "maccrab.privacy.\(anomaly.kind.rawValue)",
                        ruleTitle: "Privacy: \(anomaly.kind.rawValue.replacingOccurrences(of: "_", with: " ").capitalized) — \(anomaly.processName)",
                        severity: .medium,
                        eventId: alertId,
                        processPath: anomaly.processPath,
                        processName: anomaly.processName,
                        description: anomaly.detail,
                        mitreTactics: nil,
                        mitreTechniques: nil,
                        suppressed: false
                    )
                    do { try await state.alertStore.insert(alert: privAlert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                }

                // Purge old privacy audit data
                await state.appPrivacyAuditor.purge(olderThan: 86400)

                // MISP sync (if configured)
                if await state.mispClient.isConfigured {
                    let iocs = await state.mispClient.fetchCategorized(lastDays: 1)
                    if !iocs.ips.isEmpty || !iocs.domains.isEmpty {
                        await state.threatIntel.addCustomIOCs(hashes: iocs.hashes, ips: iocs.ips, domains: iocs.domains)
                    }
                }

                // Scheduled reports -- daily digest + weekly HTML report
                let recentAlerts = (try? await state.alertStore.alerts(
                    since: Date().addingTimeInterval(-7 * 86400),
                    limit: 10000
                )) ?? []
                let alertTuples = recentAlerts.map { a in
                    (ruleTitle: a.ruleTitle, severity: a.severity.rawValue,
                     processName: a.processName ?? "unknown", timestamp: a.timestamp)
                }
                let alertTotal = (try? await state.alertStore.count()) ?? 0
                await state.scheduledReports.checkAndGenerate(
                    alerts: alertTuples,
                    eventCount: alertTotal,
                    securityScore: score.totalScore,
                    reportGenerator: state.reportGenerator,
                    digestGenerator: state.securityDigest,
                    notificationIntegrations: state.notificationIntegrations
                )
            }
        }
        hourlyTimer.resume()

        // Keep references alive for on-demand use
        _ = state.cdhashExtractor
        _ = state.panicButton
        _ = state.travelMode
        _ = state.securityDigest
        _ = state.vulnScanner
        _ = state.toolIntegrations
        _ = state.alertExporter
        _ = state.scheduledReports

        // Periodic stats logging
        let statsTimer = DispatchSource.makeTimerSource(queue: .global())
        statsTimer.schedule(deadline: .now() + 60, repeating: 60)
        statsTimer.setEventHandler {
            let ec = eventCount()
            let ac = alertCount()
            let uptime = Int(Date().timeIntervalSince(startTime))
            let hours = uptime / 3600
            let minutes = (uptime % 3600) / 60
            logger.info("Stats: \(ec) events processed, \(ac) alerts, uptime \(hours)h\(minutes)m")

            // Report eslogger sequence-gap drops (buffer overflow indicator)
            if let eslogger = state.esloggerCollector {
                Task {
                    let dropped = await eslogger.getDroppedEventCount()
                    if dropped > 0 {
                        logger.warning("eslogger: \(dropped) events dropped (sequence gaps)")
                    }
                }
            }

            // Event flow health check: warn if no new events stored in the last 5 minutes.
            // Skips the first 2 minutes of uptime to allow collectors to start up.
            guard uptime > 120 else { return }
            Task {
                if let latestEvent = try? await state.eventStore.events(since: Date.distantPast, limit: 1).first {
                    let staleness = Date().timeIntervalSince(latestEvent.timestamp)
                    if staleness > 300 {
                        let staleMinutes = Int(staleness / 60)
                        logger.warning("Event flow stalled: no new events stored for \(staleMinutes)m — collectors may need restart")
                        logger.warning("Check: log stream --predicate 'subsystem==\"com.maccrab.agent\" AND category==\"EventStream\"'")
                    }
                }
            }
        }
        statsTimer.resume()

        // Retention pruning (daily). Clamp retentionDays to [1, 3650] so a
        // misconfigured value can't delete everything on the next tick or
        // overflow the TimeInterval math.
        let retentionDays = max(1, min(state.retentionDays, 3650))
        let pruneTimer = DispatchSource.makeTimerSource(queue: .global())
        pruneTimer.schedule(deadline: .now() + 3600, repeating: 86400) // First at 1h, then daily
        pruneTimer.setEventHandler {
            Task {
                let cutoff = Date().addingTimeInterval(-Double(retentionDays) * 86400)
                let prunedEvents = (try? await state.eventStore.prune(olderThan: cutoff)) ?? 0
                let prunedAlerts = (try? await state.alertStore.prune(olderThan: cutoff)) ?? 0
                logger.info("Retention sweep: \(prunedEvents) events + \(prunedAlerts) alerts older than \(retentionDays)d pruned")
            }
        }
        pruneTimer.resume()

        // v1.6.12: DB size-cap enforcement (hourly). The retention
        // timer above only deletes events older than `retentionDays`,
        // which on a high-event-rate machine lets the SQLite file
        // grow past the configured `maxDatabaseSizeMB` cap anyway.
        // Field case: 30d retention, ~50 events/s → DB grew to
        // 18.95 GB (38× the 500 MB cap) before the discrepancy was
        // noticed. This timer checks file size every hour and
        // iteratively prunes the oldest events + VACUUMs until the
        // file drops below 80% of the cap.
        let maxSizeMB = max(50, state.maxDatabaseSizeMB)
        let targetSizeMB = Int(Double(maxSizeMB) * 0.8)
        let dbFilePath = state.supportDir + "/events.db"

        // Startup log so operators can verify the cap is armed by
        // grepping the first 15 minutes of daemon logs. Measures
        // current size too, so "why is this taking so long to
        // prune?" has an immediate answer (big starting DB).
        let startupSizeMB: Int = {
            let attrs = try? FileManager.default.attributesOfItem(atPath: dbFilePath)
            let bytes = (attrs?[.size] as? UInt64) ?? 0
            return Int(bytes / 1_000_000)
        }()
        if startupSizeMB > maxSizeMB {
            logger.notice("Size-cap timer armed: cap=\(maxSizeMB) MB, target=\(targetSizeMB) MB, currently \(startupSizeMB) MB (OVER CAP — first sweep in 15 min, hourly thereafter)")
        } else {
            logger.info("Size-cap timer armed: cap=\(maxSizeMB) MB, target=\(targetSizeMB) MB, currently \(startupSizeMB) MB (under cap)")
        }

        let sizeCapTimer = DispatchSource.makeTimerSource(queue: .global())
        // v1.6.13: first sweep at 15 min (up from 10) so collectors
        // + inventory warm-up settle before we compete for IO.
        // Hourly thereafter.
        sizeCapTimer.schedule(deadline: .now() + 900, repeating: 3600)
        sizeCapTimer.setEventHandler {
            Task {
                await enforceDatabaseSizeCap(
                    dbPath: dbFilePath,
                    maxSizeMB: maxSizeMB,
                    targetSizeMB: targetSizeMB,
                    eventStore: state.eventStore
                )
            }
        }
        sizeCapTimer.resume()

        // Periodic baseline save + dedup sweep (every 5 minutes)
        let maintenanceTimer = DispatchSource.makeTimerSource(queue: .global())
        maintenanceTimer.schedule(deadline: .now() + 300, repeating: 300)
        maintenanceTimer.setEventHandler {
            Task {
                try? await state.baselineEngine.save()
                try? await state.processTreeAnalyzer.save()
                await state.deduplicator.sweep()
                await state.crossProcessCorrelator.purgeStale()
                await state.topologyAnomalyDetector.purgeStale()
                await state.campaignDetector.sweep()
                await state.tlsFingerprinter.sweep()
                // Allowlist v2: prune expired suppressions. The sweep
                // appends an audit entry per expired row, so operators
                // can reconstruct when each allow lapsed.
                let expired = await state.suppressionManager.sweepExpired()
                if !expired.isEmpty {
                    logger.info("Allowlist sweep expired \(expired.count) suppression(s)")
                }
                await state.deduplicator.prunePrcessedDismissals()
            }
        }
        maintenanceTimer.resume()

        // Feedback sweep: every 60s, pull IDs of alerts the user has marked
        // suppressed in the dashboard and feed them into the deduplicator's
        // dismissal tracker. The deduplicator uses this signal to auto-
        // downgrade severity for rules with a high dismissal rate on future
        // firings. Small sweep interval so the feedback feels responsive.
        let feedbackTimer = DispatchSource.makeTimerSource(queue: .global())
        feedbackTimer.schedule(deadline: .now() + 60, repeating: 60)
        feedbackTimer.setEventHandler {
            Task {
                do {
                    let dismissed = try await state.alertStore.listSuppressed(limit: 500)
                    for (alertId, ruleId) in dismissed {
                        await state.deduplicator.recordDismissal(alertId: alertId, ruleId: ruleId)
                    }
                } catch {
                    logger.error("Feedback sweep failed: \(error.localizedDescription)")
                }
            }
        }
        feedbackTimer.resume()

        // v1.4.3 fail-loud: write a heartbeat snapshot every 30s so
        // the dashboard can detect a silently-replaced or hung sysext.
        // If an attacker drops in a no-op sysext binary, the dashboard
        // still sees the old heartbeat file aging past the threshold
        // and raises a DetectionHealthBanner. The snapshot includes
        // event/alert counters + uptime so the dashboard can also
        // show rich debugging info on the ES Health page.
        let heartbeatTimer = DispatchSource.makeTimerSource(queue: .global())
        heartbeatTimer.schedule(deadline: .now() + 5, repeating: 30)
        heartbeatTimer.setEventHandler {
            // Probe sysext Full Disk Access authoritatively. The sysext
            // runs as root but TCC still gates its access to the user and
            // system TCC databases. If we can open + query the system
            // TCC.db, FDA is granted (TCC bypasses the service). If TCC
            // denies us, sqlite3_open / sqlite3_prepare will fail.
            // The dashboard reads this field and uses it as the primary
            // sysext-FDA signal — way more reliable than inferring from
            // WAL mtime or trying to read TCC.db from the non-root app
            // (where Unix perms + TCC both apply).
            let sysextHasFDA = probeSysextFDA()

            let nowUnix = Date().timeIntervalSince1970
            let uptime = Int(Date().timeIntervalSince(startTime))
            let events = eventCount()
            let alerts = alertCount()

            let payload: [String: Any] = [
                "written_at_unix": nowUnix,
                "uptime_seconds": uptime,
                "events_processed": events,
                "alerts_emitted": alerts,
                "sysext_has_fda": sysextHasFDA,
                "fda_checked_at_unix": nowUnix,
                "schema_version": 2,
            ]

            // Metrics export — Prometheus-textfile-style JSON at a world-
            // readable path. Counter-style semantics: scrapers compute
            // rates from deltas. Using /var/tmp (survives reboots, no
            // privilege boundary to cross) so external collectors can
            // read without special entitlements.
            let metricsPayload: [String: Any] = [
                "schema": 1,
                "written_at_unix": nowUnix,
                "uptime_seconds": uptime,
                "events_total": events,
                "alerts_total": alerts,
                "sysext_has_fda": sysextHasFDA,
                "power_state": PowerGate.stateDescription,
            ]
            if let metricsData = try? JSONSerialization.data(
                withJSONObject: metricsPayload,
                options: [.sortedKeys]
            ) {
                let metricsPath = "/var/tmp/maccrab.metrics.json"
                let metricsTmp = metricsPath + ".tmp"
                do {
                    try metricsData.write(to: URL(fileURLWithPath: metricsTmp))
                    _ = try? FileManager.default.removeItem(atPath: metricsPath)
                    try FileManager.default.moveItem(atPath: metricsTmp, toPath: metricsPath)
                } catch {
                    // Metrics writes are best-effort — no alert if /var/tmp
                    // is unreadable for some reason; next tick will retry.
                }
            }
            guard let data = try? JSONSerialization.data(
                withJSONObject: payload,
                options: [.prettyPrinted, .sortedKeys]
            ) else { return }
            let path = "/Library/Application Support/MacCrab/heartbeat.json"
            // Write via temp + rename so the dashboard never catches a
            // half-written file. Silent on failure — the next 30s tick
            // will try again.
            let tmp = path + ".tmp"
            do {
                try data.write(to: URL(fileURLWithPath: tmp))
                try FileManager.default.moveItem(atPath: tmp, toPath: path)
            } catch {
                // File may already exist; retry as overwrite.
                try? FileManager.default.removeItem(atPath: path)
                try? FileManager.default.moveItem(atPath: tmp, toPath: path)
            }
        }
        heartbeatTimer.resume()

        return Handles(
            forensicTimer: forensicTimer,
            hourlyTimer: hourlyTimer,
            statsTimer: statsTimer,
            pruneTimer: pruneTimer,
            sizeCapTimer: sizeCapTimer,
            maintenanceTimer: maintenanceTimer,
            feedbackTimer: feedbackTimer,
            heartbeatTimer: heartbeatTimer
        )
    }
}

// MARK: - Size-cap enforcement (hardened in v1.6.13)

/// Hardened size-cap enforcer. Runs on the hourly timer and from
/// any on-demand entry point. Design goals (v1.6.13):
///
/// - **Bounded blast radius.** Delete at most 50% of rows per sweep;
///   if still over cap, next tick does another 50%. Converges to the
///   target across a few hours instead of wiping in one pass.
/// - **Never crash on out-of-disk.** VACUUM needs ~= DB size of
///   scratch space. Pre-flight statvfs check; skip VACUUM if free <
///   1.3× current DB size. The row deletion still happened (pages
///   are freed internally), so the cap will close over subsequent
///   ticks as disk frees up.
/// - **Single VACUUM per sweep.** Prune everything first, then
///   VACUUM once at the end. Previous v1.6.12 code called VACUUM
///   per iteration — up to 8× full-file rewrites on a big DB.
/// - **WAL-aware.** Checkpoint the WAL (PASSIVE → RESTART
///   fallback) before and after VACUUM so the main .db file (what
///   the Settings UI measures) actually reflects the shrink.
/// - **Reentrancy-safe.** Hourly timer + on-demand "prune now"
///   can collide; guard via `EventStore.beginSizeCapPrune()`.
/// - **Structured log output.** Every sweep emits one line with
///   starting/ending sizes, rows pruned, disk-space decision, and
///   vacuum result. Operators can `log show --predicate 'subsystem
///   == "com.maccrab.agent"'` and see exactly what the enforcer
///   did.
private func enforceDatabaseSizeCap(
    dbPath: String,
    maxSizeMB: Int,
    targetSizeMB: Int,
    eventStore: EventStore
) async {
    let fm = FileManager.default

    // Reentrancy: if another sweep is already running (hourly timer
    // + on-demand invocation can race), exit cleanly.
    guard await eventStore.beginSizeCapPrune() else {
        logger.info("Size-cap enforcer: another sweep already active, skipping")
        return
    }
    defer { Task { await eventStore.endSizeCapPrune() } }

    func currentSizeMB() -> Int {
        let attrs = try? fm.attributesOfItem(atPath: dbPath)
        let bytes = (attrs?[.size] as? UInt64) ?? 0
        return Int(bytes / 1_000_000)
    }

    /// Free space on the volume holding the DB, in MB. Returns
    /// UInt64.max on error so that a statvfs failure doesn't
    /// mistakenly skip VACUUM (we fall back to "try it and let
    /// SQLite fail gracefully").
    func freeDiskMB() -> Int {
        let url = URL(fileURLWithPath: dbPath).deletingLastPathComponent()
        let values = try? url.resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey])
        if let bytes = values?.volumeAvailableCapacityForImportantUsage, bytes > 0 {
            return Int(bytes / 1_000_000)
        }
        return Int.max
    }

    let initialMB = currentSizeMB()
    guard initialMB > maxSizeMB else {
        // Quiet no-op. Normal hourly tick on a well-sized DB.
        return
    }

    logger.warning("Size-cap enforcer armed: DB \(initialMB) MB exceeds cap \(maxSizeMB) MB; target \(targetSizeMB) MB.")

    // --- Phase 1: prune rows (bounded at 50% of total per sweep) ---
    //
    // Deleting more than half the rows in one go is almost always a
    // bug: either the overage estimate is wrong, or the cap changed
    // radically. Cap per-sweep deletion so a misestimate never
    // wipes the whole store.

    let totalEventsBefore = (try? await eventStore.count()) ?? 0
    let maxPerSweep = totalEventsBefore / 2
    let overageFraction = Double(initialMB - targetSizeMB) / Double(initialMB)
    let estimatedPrune = max(10_000, Int(Double(totalEventsBefore) * min(0.6, overageFraction + 0.1)))
    let pruneCount = min(estimatedPrune, maxPerSweep)

    let pruned = (try? await eventStore.pruneOldest(count: pruneCount)) ?? 0
    let sizeAfterPruneMB = currentSizeMB()
    logger.notice("Size-cap phase 1: pruned \(pruned) rows (estimated \(estimatedPrune), cap \(maxPerSweep)); logical size now \(sizeAfterPruneMB) MB")

    // --- Phase 2: VACUUM if we have the disk headroom ---
    //
    // VACUUM needs ~= current DB size of scratch space. We require
    // 1.3× as buffer. If the volume is tight, we skip VACUUM
    // entirely — the `.db` file won't shrink this pass, but pages
    // are freed internally so the DB won't grow again until the
    // freed pages are reused. On the next hourly tick (or once
    // disk frees), we'll revisit.

    let needMB = Int(Double(sizeAfterPruneMB) * 1.3)
    let freeMB = freeDiskMB()
    let canVacuum = freeMB >= needMB

    if !canVacuum {
        logger.warning("Size-cap phase 2: skipping VACUUM — need \(needMB) MB free, have \(freeMB) MB. File size unchanged; will retry next tick.")
        let endMB = currentSizeMB()
        logger.notice("Size-cap sweep complete: \(initialMB) MB → \(endMB) MB (rows pruned: \(pruned), vacuum: skipped)")
        return
    }

    // Checkpoint the WAL first so VACUUM sees all committed pages
    // consolidated in the main file.
    let checkpointBefore = await eventStore.walCheckpoint()
    do {
        try await eventStore.vacuum()
    } catch {
        logger.error("Size-cap phase 2: VACUUM failed (\(error.localizedDescription)). File size likely unchanged; will retry next tick.")
        let endMB = currentSizeMB()
        logger.notice("Size-cap sweep complete: \(initialMB) MB → \(endMB) MB (rows pruned: \(pruned), vacuum: failed)")
        return
    }

    // Second checkpoint drains any WAL left by the VACUUM itself.
    _ = await eventStore.walCheckpoint()

    let finalMB = currentSizeMB()
    logger.notice("Size-cap sweep complete: \(initialMB) MB → \(finalMB) MB (rows pruned: \(pruned), vacuum: success, checkpoint_before_drained: \(checkpointBefore))")
}

/// Probe whether this sysext process currently has Full Disk Access.
///
/// Strategy: try to open `/Library/Application Support/com.apple.TCC/TCC.db`
/// and execute a trivial query. That database is TCC-protected under the
/// `kTCCServiceSystemPolicyAllFiles` (FDA) service, so:
///   • With FDA → TCC allows the open → query succeeds → return true
///   • Without FDA → TCC denies (EPERM) → sqlite3_open_v2 or the first
///     prepare fails → return false
///
/// This is authoritative for the sysext because it runs as root (so Unix
/// permissions are not the gate — TCC is). It's cheap (< 1 ms) and is run
/// every 30 s inside the heartbeat timer.
///
/// Intentionally file-scope (not inside the enum) so it remains callable
/// from the DispatchSource closure without `self.` captures.
private func probeSysextFDA() -> Bool {
    let systemTCC = "/Library/Application Support/com.apple.TCC/TCC.db"
    guard FileManager.default.fileExists(atPath: systemTCC) else { return false }
    var db: OpaquePointer?
    guard sqlite3_open_v2(
        systemTCC,
        &db,
        SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX,
        nil
    ) == SQLITE_OK else { return false }
    defer { sqlite3_close(db) }
    // A bare SELECT on the access table confirms real read access —
    // on older macOS versions, sqlite3_open might return OK for a
    // path the process can't actually read, with prepare being the
    // real gate.
    var stmt: OpaquePointer?
    guard sqlite3_prepare_v2(
        db,
        "SELECT 1 FROM access LIMIT 1",
        -1,
        &stmt,
        nil
    ) == SQLITE_OK else { return false }
    defer { sqlite3_finalize(stmt) }
    let rc = sqlite3_step(stmt)
    return rc == SQLITE_ROW || rc == SQLITE_DONE
}
