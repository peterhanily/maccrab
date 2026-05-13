import Foundation
import MacCrabCore
import SQLite3
import os.log
import SystemConfiguration

// v1.7.3 added a HeartbeatInFlight class that wrapped the heartbeat
// body in an outer overlap guard. Combined with serial `await` of
// the snapshot writers it created a deadlock: any single guard-less
// snapshot writer (MCPBaseline / RuleEngine / TCCMonitor in v1.7.3)
// could block the heartbeat indefinitely, holding the lock,
// preventing any further heartbeat ticks. Dashboard would then show
// "Detection engine appears silent" after 120 s.
//
// v1.7.4 reverts the outer guard. Each snapshot writer now has its
// own per-writer `snapshotWriteInFlight` guard (matching
// AgentLineageService.swift), so fire-and-forget Tasks at the
// heartbeat level are safe — concurrent writeSnapshot calls no-op
// instead of queueing on the actor. The heartbeat write itself
// stays on the critical fast path.

/// Creates and starts all periodic timers (forensic scans, hourly tasks,
/// stats logging, retention pruning, maintenance sweeps).
/// Returns the timer sources so they stay alive.
enum DaemonTimers {
    struct Handles {
        let forensicTimer: DispatchSourceTimer
        let hourlyTimer: DispatchSourceTimer
        let statsTimer: DispatchSourceTimer
        /// v1.8.0: split from one shared `pruneTimer` so events / alerts /
        /// campaigns each have their own retention cadence + size cap.
        let alertsPruneTimer: DispatchSourceTimer
        let alertsSizeCapTimer: DispatchSourceTimer
        let campaignsPruneTimer: DispatchSourceTimer?
        let campaignsSizeCapTimer: DispatchSourceTimer?
        let sizeCapTimer: DispatchSourceTimer
        let maintenanceTimer: DispatchSourceTimer
        let feedbackTimer: DispatchSourceTimer
        let heartbeatTimer: DispatchSourceTimer
        /// v1.7.5: minimal liveness heartbeat decoupled from the rich
        /// payload. Synchronous dispatch-thread file write of
        /// `heartbeat.json`. Cannot deadlock on actor work.
        let livenessTimer: DispatchSourceTimer
        /// v1.10.0: daily retention sweeps for the v1.10 stores. Pre-fix
        /// these were declared as local lets inside start() and went
        /// out of scope on return — DispatchSourceTimer ARC-deallocates
        /// without retention, silently breaking pruning. Now retained.
        let tracegraphPruneTimer: DispatchSourceTimer?
        let tracesPruneTimer: DispatchSourceTimer?
        /// v1.10.0: file-based IPC poller. Polls
        /// /Library/Application Support/MacCrab/inbox/*.json every 5 s
        /// so the dashboard (running as the user) can request mutations
        /// on a root-owned DB without needing signal-delivery permission.
        /// Handles: flush-request-*, suppress-alert-*, unsuppress-alert-*,
        /// delete-alert-*, suppress-campaign-* (v1.10.1).
        let inboxPoller: DispatchSourceTimer
    }

    static func start(state: DaemonState, eventCount: @escaping () -> UInt64, alertCount: @escaping () -> UInt64, startTime: Date) -> Handles {
        // Periodic forensic scans (crash reports, power anomalies, library inventory)
        let forensicTimer = DispatchSource.makeTimerSource(queue: .global())
        forensicTimer.schedule(deadline: .now() + 120, repeating: 300) // First at 2min, then every 5min
        // v1.6.22: counter so the library-inventory scan runs only every
        // other forensic tick (10 min cadence) instead of every tick (5 min).
        // The pre-v1.6.22 inline comment claimed "every other cycle" but no
        // skip logic existed, so it ran on every fire. Tally is bumped on
        // every fire and the scan only runs on odd values.
        let libraryInventoryTickCounter = LockedCounter()
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
                    let inserted: Bool
                    do { inserted = try await state.alertSink.submit(alert: alert) }
                    catch { await StorageErrorTracker.shared.recordAlertError(error); continue }
                    guard inserted else { continue }
                    if exploit.severity >= .high { await state.notifier.notify(alert: alert) }
                    print("[CRASH] \(exploit.indicator) in \(exploit.processName)")
                }

                // Power anomaly detection.
                let anomalies = await state.powerAnomalyDetector.scan()
                for anomaly in anomalies {
                    let ruleId = "maccrab.forensic.power-\(anomaly.type.rawValue)"
                    // processPath is nil for power events; use processName as
                    // the dedup-fallback key so AlertSink partitions by app.
                    let alert = Alert(
                        ruleId: ruleId,
                        ruleTitle: "Power Anomaly: \(anomaly.processName) \(anomaly.type.rawValue)",
                        severity: anomaly.severity,
                        eventId: UUID().uuidString,
                        processPath: anomaly.processName,
                        processName: anomaly.processName,
                        description: anomaly.detail,
                        mitreTactics: "attack.execution", mitreTechniques: "attack.t1496",
                        suppressed: false
                    )
                    do { _ = try await state.alertSink.submit(alert: alert) }
                    catch { await StorageErrorTracker.shared.recordAlertError(error) }
                }

                // Library inventory scan (every other cycle — resource intensive).
                // v1.6.22 made the every-other-cycle skip real (it had been a
                // promise without an implementation). LibraryInventory also
                // does its own (pid, libraryPath) dedup internally so the same
                // loaded dylib doesn't re-alert across scans even if the
                // surrounding AlertDeduplicator window expires.
                let tick = libraryInventoryTickCounter.increment()
                guard tick.isMultiple(of: 2) else { return }
                let injected = await state.libraryInventory.scanAllProcesses()
                for lib in injected {
                    let ruleId = "maccrab.forensic.injected-library"
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
                    let inserted: Bool
                    do { inserted = try await state.alertSink.submit(alert: alert) }
                    catch { await StorageErrorTracker.shared.recordAlertError(error); continue }
                    guard inserted else { continue }
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
                            do { _ = try await state.alertSink.submit(alert: scoreAlert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
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
                        do { _ = try await state.alertSink.submit(alert: vulnAlert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
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
                    do { _ = try await state.alertSink.submit(alert: privAlert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
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

                // v1.6.15: refresh the on-disk integrations snapshot so
                // the dashboard's IntegrationsView shows the daemon's
                // enriched results (running-state checks done at root
                // privilege) instead of re-scanning from user context.
                let integrationsSnapshotPath = state.supportDir + "/integrations_snapshot.json"
                await state.toolIntegrations.writeSnapshot(to: integrationsSnapshotPath)

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

        // v1.8.0 storage redesign: per-tier retention, decoupled timers.
        // Pre-v1.8 used one daily timer to prune both events and alerts
        // with the same cutoff, so a heavy event firehose evicted alerts
        // as collateral damage. The redesign:
        //
        //   - Events are governed by the adaptive rollup below (1h hot
        //     tier by default). No separate daily timer for events.
        //   - Alerts and campaigns each get their own daily prune timer
        //     reading their own retentionDays — typically 365d, fully
        //     independent of event churn.
        //   - Each store also has an hourly size-cap timer for defense
        //     in depth: alertsMaxSizeMB / campaignsMaxSizeMB.
        //
        // All knobs read live from state.storage so a SIGHUP-driven
        // config reload is honored on the next tick.

        let alertsPruneTimer = DispatchSource.makeTimerSource(queue: .global())
        alertsPruneTimer.schedule(deadline: .now() + 3600, repeating: 86400)
        alertsPruneTimer.setEventHandler {
            Task {
                let days = max(1, min(state.storage.alertsRetentionDays, 3650))
                let cutoff = Date().addingTimeInterval(-Double(days) * 86400)
                let pruned = (try? await state.alertStore.prune(olderThan: cutoff)) ?? 0
                if pruned > 0 {
                    logger.info("Alerts retention sweep: \(pruned) alerts older than \(days)d pruned")
                }
            }
        }
        alertsPruneTimer.resume()

        let campaignsPruneTimer: DispatchSourceTimer?
        if let campaignStore = state.campaignStore {
            let t = DispatchSource.makeTimerSource(queue: .global())
            t.schedule(deadline: .now() + 3600, repeating: 86400)
            t.setEventHandler {
                Task {
                    let days = max(1, min(state.storage.campaignsRetentionDays, 3650))
                    let cutoff = Date().addingTimeInterval(-Double(days) * 86400)
                    let pruned = (try? await campaignStore.prune(olderThan: cutoff)) ?? 0
                    if pruned > 0 {
                        logger.info("Campaigns retention sweep: \(pruned) campaigns older than \(days)d pruned")
                    }
                }
            }
            t.resume()
            campaignsPruneTimer = t
        } else {
            campaignsPruneTimer = nil
        }

        // v1.10.0 audit fix: tracegraph.db + traces.db both shipped
        // in v1.9/v1.10 with no retention. On a dev machine running
        // Claude Code daily this grew several GB / month indefinitely.
        // Default 90d retention + size cap (250 MB tracegraph, 100 MB
        // traces). One daily timer drives both stores; size-cap
        // fallback applies pruneOldest if a 90d cut alone can't fit
        // the budget.
        let tracegraphPruneTimer: DispatchSourceTimer?
        if let causalStore = state.causalStore {
            let t = DispatchSource.makeTimerSource(queue: .global())
            t.schedule(deadline: .now() + 3600, repeating: 86400)
            t.setEventHandler {
                Task {
                    let days = 90
                    let capBytes: Int64 = 250 * 1024 * 1024
                    let cutoff = Date().addingTimeInterval(-Double(days) * 86400)
                    let pruned = (try? await causalStore.pruneTraces(olderThan: cutoff)) ?? 0
                    if pruned > 0 {
                        logger.info("TraceGraph retention sweep: \(pruned) traces older than \(days)d pruned")
                    }
                    let size = await causalStore.databaseSizeBytes()
                    if size > capBytes {
                        // Drop 10% of trace rows oldest-first; keep
                        // looping until under cap or zero rows pruned.
                        for _ in 0..<5 {
                            let count = (try? await causalStore.traceCount()) ?? 0
                            let dropTarget = max(50, count / 10)
                            let dropped = (try? await causalStore.pruneOldestTraces(count: dropTarget)) ?? 0
                            logger.warning("TraceGraph size cap: pruned \(dropped) oldest traces (\(size / 1024 / 1024) MB > \(capBytes / 1024 / 1024) MB cap)")
                            if dropped == 0 { break }
                            let nowSize = await causalStore.databaseSizeBytes()
                            if nowSize < capBytes { break }
                        }
                    }
                }
            }
            t.resume()
            tracegraphPruneTimer = t
        } else {
            tracegraphPruneTimer = nil
        }

        let tracesPruneTimer: DispatchSourceTimer?
        if let traceStore = state.traceStore {
            let t = DispatchSource.makeTimerSource(queue: .global())
            t.schedule(deadline: .now() + 3600, repeating: 86400)
            t.setEventHandler {
                Task {
                    let days = 90
                    let capBytes: Int64 = 100 * 1024 * 1024
                    let cutoff = Date().addingTimeInterval(-Double(days) * 86400)
                    let pruned = (try? await traceStore.prune(olderThan: cutoff)) ?? 0
                    if pruned > 0 {
                        logger.info("OTLP traces retention sweep: \(pruned) spans older than \(days)d pruned")
                    }
                    let size = await traceStore.databaseSizeBytes()
                    if size > capBytes {
                        for _ in 0..<5 {
                            let count = (try? await traceStore.count()) ?? 0
                            let dropTarget = max(500, count / 10)
                            let dropped = (try? await traceStore.pruneOldest(count: dropTarget)) ?? 0
                            logger.warning("OTLP traces size cap: pruned \(dropped) oldest spans (\(size / 1024 / 1024) MB > \(capBytes / 1024 / 1024) MB cap)")
                            if dropped == 0 { break }
                            let nowSize = await traceStore.databaseSizeBytes()
                            if nowSize < capBytes { break }
                        }
                    }
                }
            }
            t.resume()
            tracesPruneTimer = t
        } else {
            tracesPruneTimer = nil
        }

        // v1.8.0 tiered storage with adaptive retention + size-cap fallback.
        //
        // First-cut design assumed ~5-10k events/hour. Field measurement on
        // production data showed ~950k events/hour on a busy dev/AI machine
        // — 13× higher. The 24h hot tier alone produces 4.4 GB at that
        // rate, which a 200 MB cap couldn't hold. v1.8.0-final defaults the
        // hot tier to 1h instead of 24h.
        //
        // Layered fix:
        //   - Layer 1 (EventInsertFilter): drop self-monitoring + dev-tool
        //     scratch at insert time. Closes ~17%+ of volume.
        //   - Layer 2 (this code): adaptive retention. Default cutoff =
        //     state.storage.eventsHotTierHours (1h); if DB > targetSizeMB,
        //     tighten progressively (h, h/2, h/4, h/8) until it fits.
        //   - Layer 3 (this code): hard cap fallback. If even the tightest
        //     cutoff can't bring the DB under cap, force pruneOldest() so
        //     we never exceed the user's disk-budget intent.
        //
        // Configurable via state.storage.{eventsHotTierHours, eventsMaxSizeMB}.
        // Defaults: 1h / 200 MB. Target = 80% of cap.
        let dbFilePath = state.supportDir + "/events.db"
        let startupSizeMB = measureDatabaseFootprintMB(dbPath: dbFilePath)
        let startupCapMB = max(100, state.storage.eventsMaxSizeMB)
        let startupHotMinutes = max(15, state.storage.eventsHotTierMinutes)
        logger.notice("Tier-rollup timer armed: hot-tier=\(startupHotMinutes)m adaptive, cap=\(startupCapMB) MB, currently \(startupSizeMB) MB (db+wal+shm). First sweep in 15 min, every 6h thereafter.")

        // v1.10.0 audit fix: first sweep at .now() + 60 s instead of
        // + 900 s. If the user is booting into a sysext that
        // inherited a 1+ GB events.db from a previous run, waiting
        // 15 min before the first prune is far too long — most
        // users assume the daemon isn't working. 60 s gives the rest
        // of startup time to settle while still firing fast enough
        // for the user to see "DB shrunk from X to Y" within 1-2
        // minutes of launching the dashboard.
        let sizeCapTimer = DispatchSource.makeTimerSource(queue: .global())
        sizeCapTimer.schedule(deadline: .now() + 60, repeating: 6 * 3600)
        sizeCapTimer.setEventHandler {
            Task {
                let capMB = max(100, state.storage.eventsMaxSizeMB)
                let targetMB = Int(Double(capMB) * 0.8)
                let hotMinutes = max(15, state.storage.eventsHotTierMinutes)
                let aggregateDays = max(1, state.storage.aggregateDays)
                let alertsRetention = max(1, state.storage.alertsRetentionDays)
                await runAdaptiveRollupSweep(
                    eventStore: state.eventStore,
                    dbPath: dbFilePath,
                    targetSizeMB: targetMB,
                    capSizeMB: capMB,
                    hotTierMinutes: hotMinutes,
                    aggregateDays: aggregateDays,
                    alertsRetentionDays: alertsRetention
                )
            }
        }
        sizeCapTimer.resume()

        // Hourly size-cap defense for alerts.db. Alert volume is orders of
        // magnitude lower than events, so this rarely fires — but if a
        // pathological rule-author commits an alert-spamming rule, the cap
        // bounds the blast radius.
        let alertsSizeCapTimer = DispatchSource.makeTimerSource(queue: .global())
        alertsSizeCapTimer.schedule(deadline: .now() + 1800, repeating: 3600)
        alertsSizeCapTimer.setEventHandler {
            Task {
                let capMB = max(50, state.storage.alertsMaxSizeMB)
                let alertsPath = state.supportDir + "/alerts.db"
                let nowMB = measureDatabaseFootprintMB(dbPath: alertsPath)
                guard nowMB > capMB else { return }
                let total = (try? await state.alertStore.count()) ?? 0
                let overFraction = Double(nowMB - capMB) / Double(max(1, nowMB))
                let dropTarget = max(1_000, Int(Double(total) * (overFraction + 0.1)))
                let dropped = (try? await state.alertStore.pruneOldest(count: dropTarget)) ?? 0
                logger.warning("Alerts size cap: pruned \(dropped) oldest alerts (\(nowMB) MB > \(capMB) MB cap, target drop \(dropTarget))")
            }
        }
        alertsSizeCapTimer.resume()

        // Same hourly defense for campaigns.db when present.
        let campaignsSizeCapTimer: DispatchSourceTimer?
        if let campaignStore = state.campaignStore {
            let t = DispatchSource.makeTimerSource(queue: .global())
            t.schedule(deadline: .now() + 1800, repeating: 3600)
            t.setEventHandler {
                Task {
                    let capMB = max(50, state.storage.campaignsMaxSizeMB)
                    let cPath = state.supportDir + "/campaigns.db"
                    let nowMB = measureDatabaseFootprintMB(dbPath: cPath)
                    guard nowMB > capMB else { return }
                    let total = (try? await campaignStore.count()) ?? 0
                    let overFraction = Double(nowMB - capMB) / Double(max(1, nowMB))
                    let dropTarget = max(100, Int(Double(total) * (overFraction + 0.1)))
                    let dropped = (try? await campaignStore.pruneOldest(count: dropTarget)) ?? 0
                    logger.warning("Campaigns size cap: pruned \(dropped) oldest campaigns (\(nowMB) MB > \(capMB) MB cap, target drop \(dropTarget))")
                }
            }
            t.resume()
            campaignsSizeCapTimer = t
        } else {
            campaignsSizeCapTimer = nil
        }

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
                // v1.11.1 (audit scalability HIGH): drain ProcessLineage's
                // pendingPromotions buffer so under PID-recycle storms
                // skeleton records aren't silently truncated by the
                // 1024-cap removeFirst at evictLRUProcess(). v1.11.1
                // surfaces them as a count + log; v1.11.2+ will forward
                // to CompactPersistentLineage / SQLiteCausalGraphStore
                // per the §6.3.1 invariant ("silent ancestry loss is not
                // allowed"). Currently the surfaced count is enough to
                // observe whether the cap is actively saturated.
                let drained = await state.enricher.lineage.drainPendingPromotions()
                if !drained.isEmpty {
                    logger.info("ProcessLineage maintenance drain: \(drained.count) skeleton(s) released from pendingPromotions cap")
                }
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

        // v1.7.5 design split: TWO heartbeat-related timers.
        //
        // 1. **Liveness heartbeat** — synchronous dispatch-thread
        //    write of a minimal `heartbeat.json`. NO actor hops, NO
        //    EventStore queries, NO snapshot writes. Just a fast
        //    file write of {written_at_unix, uptime_seconds,
        //    sysext_has_fda, schema_version}. The dashboard's
        //    "Detection engine appears silent" banner is gated on
        //    THIS file. Cannot deadlock because there's nothing
        //    async to deadlock on.
        // 2. **Rich heartbeat** — the v1.7.0–v1.7.4 payload, now
        //    written to `heartbeat_rich.json` and consumed by the
        //    ES Health panel for the per-event-category breakdown,
        //    collector liveness array, drop count. Can stall
        //    indefinitely without affecting liveness detection.
        //
        // This separation cures the v1.7.3 silent-heartbeat class
        // architecturally — liveness is decoupled from any heavyweight
        // work. Future regressions in the rich payload (slow query,
        // stuck actor, full disk for snapshot writes) can NEVER cause
        // the dashboard to think the daemon is dead when it isn't.
        let livenessTimer = DispatchSource.makeTimerSource(queue: .global())
        livenessTimer.schedule(deadline: .now() + 5, repeating: 30)
        livenessTimer.setEventHandler {
            // Synchronous on the dispatch queue. No Task wrapper, no
            // actor hops. The probeSysextFDA call is itself sync —
            // it opens TCC.db directly via sqlite3_open_v2 + close.
            //
            // v1.8.0 audit: wrap JSONSerialization in autoreleasepool.
            // DispatchSource timer event handlers run on a long-lived
            // global queue with no Swift Task scope, so autoreleased
            // NSDictionary / NSString temporaries created by
            // JSONSerialization survive until the queue thread exits
            // (effectively forever). Same shape as the v1.7.7-v1.7.9
            // EsloggerCollector / FileHasher leak chain that put
            // ~1 GB of NSConcreteData into long-running daemons.
            autoreleasepool {
                let sysextHasFDA = probeSysextFDA()
                let nowUnix = Date().timeIntervalSince1970
                let uptime = Int(Date().timeIntervalSince(startTime))
                let payload: [String: Any] = [
                    "written_at_unix": nowUnix,
                    "uptime_seconds": uptime,
                    "sysext_has_fda": sysextHasFDA,
                    "fda_checked_at_unix": nowUnix,
                    "events_processed": eventCount(),
                    "alerts_emitted": alertCount(),
                    "schema_version": 4,
                    "liveness": true,
                ]
                guard let data = try? JSONSerialization.data(
                    withJSONObject: payload,
                    options: [.sortedKeys]
                ) else { return }
                let path = state.supportDir + "/heartbeat.json"
                let tmp = path + ".tmp"
                do {
                    try data.write(to: URL(fileURLWithPath: tmp))
                    try FileManager.default.moveItem(atPath: tmp, toPath: path)
                } catch {
                    try? FileManager.default.removeItem(atPath: path)
                    try? FileManager.default.moveItem(atPath: tmp, toPath: path)
                }
            }
        }
        livenessTimer.resume()

        // v1.4.3 fail-loud: write a heartbeat snapshot every 30s so
        // the dashboard can detect a silently-replaced or hung sysext.
        // If an attacker drops in a no-op sysext binary, the dashboard
        // still sees the old heartbeat file aging past the threshold
        // and raises a DetectionHealthBanner. The snapshot includes
        // event/alert counters + uptime so the dashboard can also
        // show rich debugging info on the ES Health page.
        //
        // v1.7.4 design: heartbeat write is the critical fast path.
        // Snapshot writers live behind their own per-writer
        // snapshotWriteInFlight guards, so fire-and-forget Tasks at
        // this level are safe — concurrent calls no-op instead of
        // queueing on the actor (which is what caused the v1.7.0–
        // v1.7.3 leak class). No outer overlap guard: if a tick takes
        // longer than 30 s the next tick simply runs in parallel, and
        // since each writeSnapshot guards itself, no actor backlog
        // forms.
        let heartbeatTimer = DispatchSource.makeTimerSource(queue: .global())
        heartbeatTimer.schedule(deadline: .now() + 5, repeating: 30)
        heartbeatTimer.setEventHandler {
            // v1.7.1: heartbeat body wrapped in Task to allow the
            // EventStore query for per-category counts to await across
            // actor isolation. The dispatch-timer event handler itself
            // is synchronous; spawning a Task lets the body run async
            // without blocking the timer queue.
            Task {
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

            // v1.7.1: per-event-category counts over the last hour. Empty
            // dict on a fresh DB; populated as soon as events accumulate.
            // Best-effort — never blocks the heartbeat write.
            let oneHourAgo = Date().addingTimeInterval(-3600)
            var eventTypeCounts: [String: Int] = [:]
            do {
                eventTypeCounts = try await state.eventStore.eventCountsByCategory(since: oneHourAgo)
            } catch {
                // Heartbeat write must succeed even when the EventStore
                // query fails (db locked under contention, etc.).
            }

            // v1.7.2: collector liveness + drop counter.
            let collectorStatuses = await state.collectorRegistry.snapshot()
            let droppedTotal = await state.collectorRegistry.droppedEventsTotal()
            // Encode collectors as plain dicts for JSONSerialization
            // compatibility (it can't take a [Codable] directly).
            let collectorDicts: [[String: Any]] = collectorStatuses.map { s in
                var d: [String: Any] = [
                    "name": s.name,
                    "event_count": s.eventCount,
                    "error_count": s.errorCount,
                    "expected_interval_seconds": s.expectedIntervalSeconds,
                    "healthy": s.healthy,
                ]
                if let lt = s.lastTick { d["last_tick_unix"] = lt.timeIntervalSince1970 }
                if let le = s.lastError { d["last_error"] = le }
                return d
            }

            let payload: [String: Any] = [
                "written_at_unix": nowUnix,
                "uptime_seconds": uptime,
                "events_processed": events,
                "alerts_emitted": alerts,
                "sysext_has_fda": sysextHasFDA,
                "fda_checked_at_unix": nowUnix,
                "event_type_counts_1h": eventTypeCounts,
                "collector_health": collectorDicts,
                "events_dropped": droppedTotal,
                "schema_version": 4,
            ]

            // Metrics export — Prometheus-textfile-style JSON at a world-
            // readable path. Counter-style semantics: scrapers compute
            // rates from deltas. Using /var/tmp (survives reboots, no
            // privilege boundary to cross) so external collectors can
            // read without special entitlements.
            // v1.7.9: include resident memory in MB so scrapers + the
            // dashboard's diagnostic surface can plot daemon RSS over
            // time. Field-driven addition after v1.7.6→v1.7.7→v1.7.9
            // memory leak iterations: we want continuous RSS visibility
            // so the next leak shape is caught before user reports
            // climb to 1+ GB. mach_task_basic_info reads our own RSS
            // without sudo or external tools.
            var taskInfo = mach_task_basic_info()
            var taskInfoCount = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info_data_t>.size / MemoryLayout<integer_t>.size)
            let kr = withUnsafeMutablePointer(to: &taskInfo) {
                $0.withMemoryRebound(to: integer_t.self, capacity: Int(taskInfoCount)) {
                    task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), $0, &taskInfoCount)
                }
            }
            let residentMB: Int = kr == KERN_SUCCESS ? Int(taskInfo.resident_size / 1_048_576) : -1

            let metricsPayload: [String: Any] = [
                "schema": 2,
                "written_at_unix": nowUnix,
                "uptime_seconds": uptime,
                "events_total": events,
                "alerts_total": alerts,
                "events_dropped_total": droppedTotal,
                "events_per_sec_lifetime": uptime > 0 ? Double(events) / Double(uptime) : 0,
                "resident_memory_mb": residentMB,
                "sysext_has_fda": sysextHasFDA,
                "power_state": PowerGate.stateDescription,
            ]
            // v1.8.0 audit: autoreleasepool wrap. The Task scope drains on
            // completion, but inside a long-running per-tick body the
            // JSONSerialization temporaries persist across suspension points
            // (FileManager I/O is synchronous but the Foundation API
            // returns autoreleased Data). Match the livenessTimer pattern.
            autoreleasepool {
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
            }
            guard let data = autoreleasepool(invoking: { () -> Data? in
                try? JSONSerialization.data(
                    withJSONObject: payload,
                    options: [.prettyPrinted, .sortedKeys]
                )
            }) else { return }
            // v1.7.5: rich heartbeat goes to a SEPARATE file. Liveness
            // detection (heartbeat.json) is the synchronous fast path
            // above. This file carries the rich payload (per-event-
            // category counts, collector health, drop counter) for the
            // ES Health panel. If the rich payload stalls, the
            // dashboard's "engine alive" check still works.
            let path = state.supportDir + "/heartbeat_rich.json"
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

            // v1.7.4: snapshot writes back to fire-and-forget Tasks.
            // Each writer's per-instance `snapshotWriteInFlight`
            // guard drops concurrent calls to that writer specifically
            // — the v1.7.0 actor-queue leak is closed at the writer,
            // not at the heartbeat. The heartbeat itself stays fast.
            let lineagePath = state.supportDir + "/agent_lineage.json"
            Task { await state.agentLineageService.writeSnapshot(to: lineagePath) }

            let mcpBaselinePath = state.supportDir + "/mcp_baselines.json"
            Task { await state.mcpBaseline.writeSnapshot(to: mcpBaselinePath) }

            let ruleTelemetryPath = state.supportDir + "/rule_telemetry.json"
            Task { await state.ruleEngine.writeTelemetrySnapshot(to: ruleTelemetryPath) }

            let tccSnapshotPath = state.supportDir + "/tcc_snapshot.json"
            Task { await state.tccMonitor.writeSnapshot(to: tccSnapshotPath) }
            } // end outer Task wrapper around heartbeat body
        }
        heartbeatTimer.resume()

        // v1.10.0 audit fix: file-based IPC for dashboard → root sysext.
        // The dashboard runs as the logged-in user; the sysext owns
        // alerts.db / events.db / campaigns.db as root 0600. Mutations
        // (suppress, unsuppress, delete, flush) can't be issued directly
        // from the dashboard because:
        //   - direct DB write fails with SQLITE_READONLY
        //   - POSIX signals from user → root sysext return EPERM
        //   - /tmp doesn't share namespace between user and the sysext
        //     sandbox (first attempt in v1.10.0)
        // Solution: <supportDir>/inbox/ mode 1777 (world-write + sticky;
        // sticky prevents cross-user file deletion). The sysext (this
        // poller, running as root) drains the dir every 5 s.
        //
        // v1.10.1 extended the file types accepted beyond flush requests
        // — alert suppress/unsuppress/delete + campaign suppress all
        // route through this same channel.
        let inboxDir = state.supportDir + "/inbox"
        do {
            try FileManager.default.createDirectory(
                atPath: inboxDir, withIntermediateDirectories: true
            )
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o1777], ofItemAtPath: inboxDir
            )
        } catch {
            print("[inbox] failed to ensure inbox dir at \(inboxDir): \(error.localizedDescription)")
        }

        let inboxPoller = DispatchSource.makeTimerSource(queue: .global())
        // 5 s tick: a directory listing of an empty dir is cheap, and
        // dashboard users expect a suppress click to settle quickly.
        // The original 30 s value was sized for flush requests only,
        // which are infrequent and slow to run anyway. Alert mutations
        // are interactive — keep them snappy.
        inboxPoller.schedule(deadline: .now() + 5, repeating: 5)
        inboxPoller.setEventHandler {
            Task {
                // v1.11.0 (audit stability HIGH): skip this tick if a
                // previous Task is still draining (campaign suppress
                // fan-out can take tens of seconds at 5-10K alerts).
                // Without the guard, parallel Tasks raced for the same
                // request files + doubled DB write load.
                let acquired: Bool = state.inboxPollerLock.withLock { inFlight in
                    if inFlight { return false }
                    inFlight = true
                    return true
                }
                guard acquired else { return }
                defer { state.inboxPollerLock.withLock { $0 = false } }

                let fm = FileManager.default
                guard let files = try? fm.contentsOfDirectory(atPath: inboxDir),
                      !files.isEmpty else { return }

                // Partition by request type so we drain in a defined order
                // (mutations first, flush last — flush can take seconds).
                let suppressAlertReqs = files.filter { $0.hasPrefix("suppress-alert-") && $0.hasSuffix(".json") }
                let unsuppressAlertReqs = files.filter { $0.hasPrefix("unsuppress-alert-") && $0.hasSuffix(".json") }
                let deleteAlertReqs = files.filter { $0.hasPrefix("delete-alert-") && $0.hasSuffix(".json") }
                let suppressCampaignReqs = files.filter { $0.hasPrefix("suppress-campaign-") && $0.hasSuffix(".json") }
                let flushRequests = files.filter { $0.hasPrefix("flush-request-") && $0.hasSuffix(".json") }

                await handleSuppressAlertRequests(suppressAlertReqs, inboxDir: inboxDir, state: state)
                await handleUnsuppressAlertRequests(unsuppressAlertReqs, inboxDir: inboxDir, state: state)
                await handleDeleteAlertRequests(deleteAlertReqs, inboxDir: inboxDir, state: state)
                await handleSuppressCampaignRequests(suppressCampaignReqs, inboxDir: inboxDir, state: state)
                await handleFlushRequests(flushRequests, inboxDir: inboxDir, state: state)
            }
        }
        inboxPoller.resume()

        return Handles(
            forensicTimer: forensicTimer,
            hourlyTimer: hourlyTimer,
            statsTimer: statsTimer,
            alertsPruneTimer: alertsPruneTimer,
            alertsSizeCapTimer: alertsSizeCapTimer,
            campaignsPruneTimer: campaignsPruneTimer,
            campaignsSizeCapTimer: campaignsSizeCapTimer,
            sizeCapTimer: sizeCapTimer,
            maintenanceTimer: maintenanceTimer,
            feedbackTimer: feedbackTimer,
            heartbeatTimer: heartbeatTimer,
            livenessTimer: livenessTimer,
            tracegraphPruneTimer: tracegraphPruneTimer,
            tracesPruneTimer: tracesPruneTimer,
            inboxPoller: inboxPoller
        )
    }

    // MARK: - Inbox request handlers (v1.10.1)
    //
    // Each request file is a JSON object with a single `id` field,
    // optionally accompanied by `reason` for audit-log context. The
    // handler reads it, applies the mutation through the appropriate
    // store, then removes the file (always — leaving it would
    // re-trigger on the next 5 s tick). Failures are logged but
    // don't block subsequent requests in the same tick.

    private static func handleFlushRequests(
        _ names: [String], inboxDir: String, state: DaemonState
    ) async {
        guard !names.isEmpty else { return }
        let fm = FileManager.default
        print("[inbox] flush: \(names.count) request(s) — running enforceDatabaseSizeCapNow")
        let beforeBytes = StorageFlushStatus.fileSize(at: state.supportDir + "/events.db")
        let started = Date()
        let didRun = await enforceDatabaseSizeCapNow(state: state)
        for name in names {
            try? fm.removeItem(atPath: inboxDir + "/" + name)
        }
        if didRun {
            let afterBytes = StorageFlushStatus.fileSize(at: state.supportDir + "/events.db")
            let status = StorageFlushStatus(
                inProgress: false, lastRunAt: started,
                bytesBefore: beforeBytes, bytesAfter: afterBytes, note: nil
            )
            StorageFlushStatus.write(status, to: state.supportDir)
            print("[inbox] flush sweep done: \(beforeBytes / 1_000_000) MB → \(afterBytes / 1_000_000) MB")
        } else {
            print("[inbox] flush sweep skipped — another already in progress")
        }
    }

    private static func handleSuppressAlertRequests(
        _ names: [String], inboxDir: String, state: DaemonState
    ) async {
        let fm = FileManager.default
        for name in names {
            let path = inboxDir + "/" + name
            defer { try? fm.removeItem(atPath: path) }
            guard let id = readIdRequest(at: path) else {
                print("[inbox] suppress-alert \(name): malformed payload (expected {\"id\":\"…\"})")
                continue
            }
            let uid = requestOwnerUID(at: path)
            guard isAuthorizedInboxRequest(uid: uid) else {
                print("[inbox] suppress-alert id=\(id) REJECTED uid=\(uid) (not console-user or root)")
                auditLogInbox(state: state, prefix: "suppress-alert", id: id, uid: uid, result: "rejected_uid")
                continue
            }
            do {
                try await state.alertStore.suppress(alertId: id)
                print("[inbox] suppress-alert id=\(id) uid=\(uid) ok")
                auditLogInbox(state: state, prefix: "suppress-alert", id: id, uid: uid, result: "ok")
            } catch {
                print("[inbox] suppress-alert id=\(id) uid=\(uid) failed: \(error)")
                auditLogInbox(state: state, prefix: "suppress-alert", id: id, uid: uid, result: "failed:\(error)")
            }
        }
    }

    private static func handleUnsuppressAlertRequests(
        _ names: [String], inboxDir: String, state: DaemonState
    ) async {
        let fm = FileManager.default
        for name in names {
            let path = inboxDir + "/" + name
            defer { try? fm.removeItem(atPath: path) }
            guard let id = readIdRequest(at: path) else {
                print("[inbox] unsuppress-alert \(name): malformed payload")
                continue
            }
            let uid = requestOwnerUID(at: path)
            guard isAuthorizedInboxRequest(uid: uid) else {
                print("[inbox] unsuppress-alert id=\(id) REJECTED uid=\(uid) (not console-user or root)")
                auditLogInbox(state: state, prefix: "unsuppress-alert", id: id, uid: uid, result: "rejected_uid")
                continue
            }
            do {
                try await state.alertStore.unsuppress(alertId: id)
                print("[inbox] unsuppress-alert id=\(id) uid=\(uid) ok")
                auditLogInbox(state: state, prefix: "unsuppress-alert", id: id, uid: uid, result: "ok")
            } catch {
                print("[inbox] unsuppress-alert id=\(id) uid=\(uid) failed: \(error)")
                auditLogInbox(state: state, prefix: "unsuppress-alert", id: id, uid: uid, result: "failed:\(error)")
            }
        }
    }

    private static func handleDeleteAlertRequests(
        _ names: [String], inboxDir: String, state: DaemonState
    ) async {
        let fm = FileManager.default
        for name in names {
            let path = inboxDir + "/" + name
            defer { try? fm.removeItem(atPath: path) }
            guard let id = readIdRequest(at: path) else {
                print("[inbox] delete-alert \(name): malformed payload")
                continue
            }
            let uid = requestOwnerUID(at: path)
            guard isAuthorizedInboxRequest(uid: uid) else {
                print("[inbox] delete-alert id=\(id) REJECTED uid=\(uid) (not console-user or root)")
                auditLogInbox(state: state, prefix: "delete-alert", id: id, uid: uid, result: "rejected_uid")
                continue
            }
            do {
                let removed = try await state.alertStore.delete(alertId: id)
                print("[inbox] delete-alert id=\(id) uid=\(uid) removed=\(removed)")
                auditLogInbox(state: state, prefix: "delete-alert", id: id, uid: uid, result: "removed=\(removed)")
            } catch {
                print("[inbox] delete-alert id=\(id) uid=\(uid) failed: \(error)")
                auditLogInbox(state: state, prefix: "delete-alert", id: id, uid: uid, result: "failed:\(error)")
            }
        }
    }

    private static func handleSuppressCampaignRequests(
        _ names: [String], inboxDir: String, state: DaemonState
    ) async {
        let fm = FileManager.default
        for name in names {
            let path = inboxDir + "/" + name
            defer { try? fm.removeItem(atPath: path) }
            guard let id = readIdRequest(at: path) else {
                print("[inbox] suppress-campaign \(name): malformed payload")
                continue
            }
            let uid = requestOwnerUID(at: path)
            guard isAuthorizedInboxRequest(uid: uid) else {
                print("[inbox] suppress-campaign id=\(id) REJECTED uid=\(uid) (not console-user or root)")
                auditLogInbox(state: state, prefix: "suppress-campaign", id: id, uid: uid, result: "rejected_uid")
                continue
            }
            // Suppress the campaign-as-alert row (campaigns have a
            // `maccrab.campaign.*` rule_id and live alongside regular
            // alerts in alerts.db). Best-effort — pre-v1.8 campaigns
            // exist only in campaigns.db and have no alerts.db row.
            try? await state.alertStore.suppress(alertId: id)

            // Fan out: every alert whose campaignId matches this
            // campaign also gets suppressed. The dashboard used to
            // do this loop itself; moving it server-side means one
            // round trip instead of N over file IPC.
            var fanOut = 0
            do {
                let alerts = try await state.alertStore.alerts(
                    since: Date.distantPast,
                    severity: nil, suppressed: false, limit: 10_000
                )
                for a in alerts where a.campaignId == id {
                    do {
                        try await state.alertStore.suppress(alertId: a.id)
                        fanOut += 1
                    } catch {
                        // One bad row shouldn't abort the rest.
                        print("[inbox] suppress-campaign fan-out id=\(a.id) failed: \(error)")
                    }
                }
            } catch {
                print("[inbox] suppress-campaign contributors lookup failed: \(error)")
            }

            // Flip the persistent campaigns.db row so the dashboard's
            // campaigns list reflects suppressed state across restarts.
            if let cs = state.campaignStore {
                try? await cs.setSuppressed(id: id, true)
            }
            print("[inbox] suppress-campaign id=\(id) uid=\(uid) fanOut=\(fanOut)")
            auditLogInbox(state: state, prefix: "suppress-campaign", id: id, uid: uid, result: "ok fanOut=\(fanOut)")
        }
    }

    /// Read a `{"id":"…"}` request file. Returns nil for missing /
    /// malformed / empty-id payloads so the caller can log + skip.
    private static func readIdRequest(at path: String) -> String? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let id = json["id"] as? String,
              !id.isEmpty
        else { return nil }
        return id
    }

    /// Stat the request file to get the UID of whoever dropped it.
    /// Used by `isAuthorizedInboxRequest(uid:)` below.
    ///
    /// **v1.11.0 RC2 ship-blocker fix:** uses `lstat()` (not `stat()`)
    /// so a symlink in the 1777 inbox dir CANNOT be used to forge a
    /// root UID — pre-fix `stat()` followed symlinks, so an attacker
    /// could symlink `suppress-alert-X.json → /Library/Application
    /// Support/MacCrab/agent_lineage.json` (root-owned) and the gate
    /// authorised the request as root. Now: lstat returns the symlink
    /// owner (the attacker's uid), and the additional S_IFLNK check
    /// rejects symlinks outright before the request is processed.
    /// Hardlinks are also rejected (st_nlink > 1) so an attacker can't
    /// hardlink a root-owned file into the inbox either.
    /// Returns -1 on stat failure or any rejection condition — that
    /// value never satisfies the gate.
    private static func requestOwnerUID(at path: String) -> Int {
        var st = stat()
        guard lstat(path, &st) == 0 else { return -1 }
        // Refuse symlinks outright — too easy to forge root ownership.
        if (st.st_mode & S_IFMT) == S_IFLNK { return -1 }
        // Refuse hardlinked files: st_nlink > 1 means the inode also
        // exists elsewhere in the filesystem; the attacker may have
        // hardlinked a root-owned file into the world-writable inbox.
        if st.st_nlink > 1 { return -1 }
        return Int(st.st_uid)
    }

    /// Returns the UID of the user logged in at the macOS GUI console.
    /// `loginwindow` (or nil result) means no user is logged in — e.g.
    /// during early boot. Returns nil in that case so the gate falls
    /// back to root-only.
    private static func consoleUserUID() -> uid_t? {
        var uid: uid_t = 0
        var gid: gid_t = 0
        let store = SCDynamicStoreCreate(nil, "MacCrabInboxGate" as CFString, nil, nil)
        guard let user = SCDynamicStoreCopyConsoleUser(store, &uid, &gid) else { return nil }
        let userStr = user as String
        if userStr.isEmpty || userStr == "loginwindow" { return nil }
        return uid
    }

    /// v1.10.2 (audit BLOCKER): the inbox dir at
    /// `/Library/Application Support/MacCrab/inbox/` is mode 1777 so
    /// any local user can drop request files. Without a UID gate at
    /// the handler level, a logged-in standard / guest / kiosk user
    /// could blind the EDR by suppressing or deleting alerts (or
    /// fan-out-suppressing whole campaigns). We accept requests only
    /// from:
    ///   - root (uid 0): launchd / sudo flows + the daemon itself
    ///   - the GUI console user: the human at the keyboard, who is
    ///     also the user running MacCrab.app
    /// Anything else is rejected and audit-logged.
    private static func isAuthorizedInboxRequest(uid: Int) -> Bool {
        if uid < 0 { return false }                  // stat failed
        if uid == 0 { return true }                  // root
        if let console = consoleUserUID(), Int(console) == uid { return true }
        return false
    }

    /// Append a single line to the inbox audit log. Format is
    /// space-separated `key=value` pairs, ISO 8601 timestamp first.
    /// The MCP path uses a similar `dashboard_audit.log` in
    /// `<supportDir>` — keep them in the same file so operators have
    /// a single tail target for "who changed alert state".
    nonisolated(unsafe) private static let _inboxAuditFmt: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    /// Sanitize an attacker-controlled string before it lands in the
    /// audit log. v1.11.0 RC2 ship-blocker fix: a request id like
    /// `valid-uuid\nresult=ok uid=0` would have forged a fake "ok"
    /// audit line, since the audit format is one line-per-mutation
    /// space-separated key=value pairs. Reject newlines / carriage
    /// returns / non-printable ASCII; cap length at 128 (alert ids
    /// are UUIDs, well under that). Replacement makes the truncation
    /// visible to operators tailing the log.
    private static func sanitizeAuditField(_ s: String, max: Int = 128) -> String {
        let scrubbed = String(s.unicodeScalars.prefix(max).map { scalar -> Character in
            if scalar == "\n" || scalar == "\r" { return "_" }
            if !scalar.isASCII { return "?" }
            if scalar.value < 0x20 { return "_" }
            return Character(scalar)
        })
        return scrubbed
    }

    private static func auditLogInbox(
        state: DaemonState, prefix: String, id: String, uid: Int, result: String
    ) {
        let logPath = state.supportDir + "/dashboard_audit.log"
        // Sanitize all attacker-controlled fields so log-injection
        // attempts (newlines, ANSI escapes, control chars in the id
        // / result string) can't forge subsequent log lines.
        let safeId = sanitizeAuditField(id)
        let safeResult = sanitizeAuditField(result, max: 256)
        let line = "\(_inboxAuditFmt.string(from: Date())) source=inbox prefix=\(prefix) id=\(safeId) uid=\(uid) result=\(safeResult)\n"
        guard let data = line.data(using: .utf8) else { return }
        let url = URL(fileURLWithPath: logPath)
        if let handle = try? FileHandle(forWritingTo: url) {
            _ = try? handle.seekToEnd()
            try? handle.write(contentsOf: data)
            try? handle.close()
        } else {
            // First-time write (file doesn't exist yet).
            try? data.write(to: url, options: .atomic)
        }
    }
}

// MARK: - DB footprint measurement (v1.6.14)

/// Return the SQLite database footprint in MB, summing the main
/// `.db` file plus its `-wal` and `-shm` sidecars. v1.6.14: earlier
/// releases measured only the main `.db`, so a 480 MB main file
/// plus a 40 MB WAL presented as "under cap" despite consuming
/// 520 MB on disk. Operators setting a tight cap were surprised
/// when `du` and the daemon's cap disagreed; now they match.
///
/// Returns 0 on stat failure — downstream callers already treat
/// 0 as "skip enforcement" via the `> maxSizeMB` guard.
func measureDatabaseFootprintMB(dbPath: String) -> Int {
    let fm = FileManager.default
    func size(_ p: String) -> UInt64 {
        guard let attrs = try? fm.attributesOfItem(atPath: p),
              let b = attrs[.size] as? UInt64 else { return 0 }
        return b
    }
    let total = size(dbPath) + size(dbPath + "-wal") + size(dbPath + "-shm")
    return Int(total / 1_000_000)
}

// MARK: - Adaptive rollup sweep (v1.8.0)

/// Three-layer storage discipline: pre-insert filter (Layer 1) → adaptive
/// retention (this function, Layer 2) → defense-in-depth size cap (also
/// here, Layer 3).
///
/// Tries the configured `hotTierMinutes` cutoff first. If the DB is still
/// over `targetSizeMB` afterwards, tightens the cutoff progressively
/// (hotTier, /2, /4) — but never below 15 minutes (the SequenceEngine
/// rebuild floor; the longest sequence rule has a 10-minute window).
///
/// If after the tightest cutoff the DB STILL exceeds `capSizeMB`, Layer 3
/// kicks in: pruneOldest() to bring file size under cap by sheer row
/// count, followed by VACUUM if disk has the headroom.
///
/// All steps are best-effort; failures log + continue. The next 6-hourly
/// tick retries the same logic from scratch — idempotent by design.
func runAdaptiveRollupSweep(
    eventStore: EventStore,
    dbPath: String,
    targetSizeMB: Int,
    capSizeMB: Int,
    hotTierMinutes: Int = 30,
    aggregateDays: Int = 90,
    alertsRetentionDays: Int = 365,
    evidencePerAlertCap: Int = 50
) async {
    // v1.8.0-rc6: Prune oversized alert_evidence FIRST. On the field test
    // host, a single sweep found 802K evidence rows / 2.4 GB — the storage
    // split decoupled evidence (in events.db) from its parent alerts (now
    // in alerts.db) without any retention bridging the two. Two prune steps:
    //   - Per-alert row cap (existing oversize from pre-rc6 captures)
    //   - Time-based prune (orphans whose parent alert was deleted from alerts.db)
    do {
        let evidenceCutoff = Date().addingTimeInterval(-Double(alertsRetentionDays) * 86400)
        let evictedByAge = (try? await eventStore.pruneAlertEvidence(olderThan: evidenceCutoff)) ?? 0
        let evictedByCap = (try? await eventStore.pruneAlertEvidenceCap(perAlertMax: evidencePerAlertCap)) ?? 0
        if evictedByAge > 0 || evictedByCap > 0 {
            logger.notice("alert_evidence prune: \(evictedByAge) by age (>\(alertsRetentionDays)d), \(evictedByCap) by per-alert cap (>\(evidencePerAlertCap) rows)")
        }
    }

    // Build a progressively-tightening cutoff ladder from the configured
    // hot-tier window. Floors at 15 min (sequence-rebuild safety).
    let raw = [hotTierMinutes, hotTierMinutes / 2, hotTierMinutes / 4]
    let cutoffsMinutes: [Double] = Array(NSOrderedSet(array: raw.map { max(15, $0) }))
        .compactMap { ($0 as? Int).map(Double.init) }
    let startSizeMB = measureDatabaseFootprintMB(dbPath: dbPath)
    var totalPruned = 0

    for minutes in cutoffsMinutes {
        let beforeMB = measureDatabaseFootprintMB(dbPath: dbPath)
        if beforeMB <= targetSizeMB && minutes != cutoffsMinutes.first {
            // Don't tighten further than needed. Only the first cutoff
            // (the configured hot tier) always runs; tighter cutoffs only
            // kick in if the DB is still over target.
            break
        }
        do {
            let cutoff = Date().addingTimeInterval(-minutes * 60)
            let pruned = try await eventStore.rollUpAndPrune(
                olderThan: cutoff,
                aggregateRetentionDays: aggregateDays
            )
            totalPruned += pruned
            if pruned > 0 {
                logger.notice("Adaptive rollup: cutoff \(Int(minutes))m pruned \(pruned) events")
            }
            if minutes == cutoffsMinutes.first {
                continue   // always do the configured pass; the loop's guard checks AFTER
            }
            // Re-check size after each tighter pass.
            let afterMB = measureDatabaseFootprintMB(dbPath: dbPath)
            if afterMB <= targetSizeMB {
                logger.notice("Adaptive rollup: DB \(beforeMB) MB → \(afterMB) MB at \(Int(minutes))m cutoff (target \(targetSizeMB) MB) — done.")
                break
            }
        } catch {
            logger.error("Adaptive rollup at cutoff \(Int(minutes))m failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    // Layer 3: defense-in-depth cap. After all the time-based cutoffs, if
    // the DB still exceeds the hard ceiling, prune by row count until it
    // fits. Last-resort guarantee that the user's disk-budget is honored.
    let sizeAfterAdaptiveMB = measureDatabaseFootprintMB(dbPath: dbPath)
    if sizeAfterAdaptiveMB > capSizeMB {
        logger.warning("Adaptive rollup left DB at \(sizeAfterAdaptiveMB) MB (cap \(capSizeMB) MB) — engaging Layer 3 row-count cap.")
        do {
            // Estimate how many rows to drop: the over-cap fraction × row count.
            let total = (try? await eventStore.count()) ?? 0
            let overFraction = Double(sizeAfterAdaptiveMB - capSizeMB) / Double(sizeAfterAdaptiveMB)
            let dropTarget = max(10_000, Int(Double(total) * (overFraction + 0.1)))
            let dropped = (try? await eventStore.pruneOldest(count: dropTarget)) ?? 0
            logger.notice("Layer 3 cap: pruned \(dropped) oldest events (target \(dropTarget))")
            // v1.10.0 audit fix: feed Layer 3's drop count into the
            // shared totalPruned counter so the VACUUM gate below
            // ("if totalPruned > 0") fires. Pre-fix Layer 3 deleted
            // millions of rows but the gate stayed false (because
            // the adaptive loop hadn't pruned anything — table
            // already inside hot tier), so VACUUM was skipped and
            // the file stayed at the high-water mark. Field-
            // observed: a manual flush at 2.3 GB returned 2.5 GB
            // afterAfter (the difference being inserts that
            // accumulated during the no-op-VACUUM sweep window).
            totalPruned += dropped
        }
    }

    // Single VACUUM at the end of the sweep to actually reclaim the
    // pages freed by the prune steps. Without this, DELETE marks pages
    // free for future reuse but the file size on disk stays at the
    // high-water mark — so the adaptive logic above sees the file as
    // still over target on every subsequent tick and keeps tightening
    // pointlessly. Matches the v1.6.13 legacy design ("prune everything
    // first, then VACUUM once at the end").
    //
    // Skipped if no rows were pruned (no freed pages to reclaim) or if
    // free disk is too tight (VACUUM rebuilds into a parallel temp
    // file ≈ DB size; needs at least 1.3× headroom). On skip we also
    // run a wal_checkpoint(TRUNCATE) so any drained pages migrate from
    // the WAL into the main file — a cheap partial cleanup.
    if totalPruned > 0 {
        let dbSizeBeforeVacuum = measureDatabaseFootprintMB(dbPath: dbPath)
        let freeMB = freeDiskMB(forPath: dbPath)
        if freeMB >= Int(Double(dbSizeBeforeVacuum) * 1.3) {
            do {
                try await eventStore.vacuum()
            } catch {
                logger.warning("Tier-rollup VACUUM failed: \(error.localizedDescription, privacy: .public)")
            }
        } else {
            logger.warning("Tier-rollup: skipping VACUUM (free disk \(freeMB) MB < 1.3× DB size \(dbSizeBeforeVacuum) MB) — running checkpoint(TRUNCATE) instead")
            await eventStore.walCheckpoint()
        }
    }

    let endMB = measureDatabaseFootprintMB(dbPath: dbPath)
    if startSizeMB != endMB || totalPruned > 0 {
        logger.notice("Tier-rollup sweep complete: DB \(startSizeMB) MB → \(endMB) MB, pruned \(totalPruned) events total.")
    }
}

/// Free disk space at the volume containing `path`, in megabytes.
/// Returns 0 on stat failure (caller treats 0 as "not enough headroom").
private func freeDiskMB(forPath path: String) -> Int {
    var stat = statvfs()
    guard statvfs((path as NSString).utf8String, &stat) == 0 else { return 0 }
    let bytes = UInt64(stat.f_bavail) * UInt64(stat.f_frsize)
    return Int(bytes / 1_000_000)
}

// MARK: - On-demand sweep entry point (v1.6.14)

/// Trigger a size-cap sweep immediately, outside the hourly timer.
/// Used by the SIGHUP handler so operators can lower the cap in
/// Settings, send SIGHUP, and see the DB shrink in seconds instead
/// of waiting up to an hour for the next tick. Reads cap + target
/// from `state` so the freshly-reloaded `DaemonConfig` is honored.
///
/// v1.9.0 (audit Stab-M1): returns `true` when the sweep actually
/// ran, `false` when it was skipped because another sweep was
/// already in progress (`EventStore.beginSizeCapPrune` returned
/// false). Callers (SIGUSR2 handler) use the return value to avoid
/// overwriting the running sweep's pending status snapshot with a
/// stale "after" measurement.
@discardableResult
func enforceDatabaseSizeCapNow(state: DaemonState) async -> Bool {
    let maxSizeMB = max(50, state.storage.eventsMaxSizeMB)
    let targetSizeMB = Int(Double(maxSizeMB) * 0.8)
    let dbFilePath = state.supportDir + "/events.db"
    return await enforceDatabaseSizeCap(
        dbPath: dbFilePath,
        maxSizeMB: maxSizeMB,
        targetSizeMB: targetSizeMB,
        eventStore: state.eventStore
    )
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
) async -> Bool {
    // Reentrancy: if another sweep is already running (hourly timer
    // + on-demand invocation can race), exit cleanly. v1.9.0
    // (audit Stab-M1): return false so the SIGUSR2 caller can skip
    // the status-snapshot write — pre-fix the second SIGUSR2 within
    // ~2 s of the first wrote a stale `bytesAfter` mid-sweep.
    guard await eventStore.beginSizeCapPrune() else {
        logger.info("Size-cap enforcer: another sweep already active, skipping")
        return false
    }
    defer { Task { await eventStore.endSizeCapPrune() } }

    func currentSizeMB() -> Int {
        // v1.6.14: sum db + wal + shm so the cap reflects total
        // on-disk footprint, not just the main file.
        return measureDatabaseFootprintMB(dbPath: dbPath)
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
        // Quiet no-op. Normal hourly tick on a well-sized DB. We did
        // acquire the lock — that counts as "ran" for SIGUSR2's
        // purposes (the dashboard sees the under-cap measurement).
        return true
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
        return true
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
        return true
    }

    // Second checkpoint drains any WAL left by the VACUUM itself.
    _ = await eventStore.walCheckpoint()

    let finalMB = currentSizeMB()
    logger.notice("Size-cap sweep complete: \(initialMB) MB → \(finalMB) MB (rows pruned: \(pruned), vacuum: success, checkpoint_before_drained: \(checkpointBefore))")
    return true
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
