import Foundation
import MacCrabCore
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
        let maintenanceTimer: DispatchSourceTimer
        let feedbackTimer: DispatchSourceTimer
    }

    static func start(state: DaemonState, eventCount: @escaping () -> UInt64, alertCount: @escaping () -> UInt64, startTime: Date) -> Handles {
        // Periodic forensic scans (crash reports, power anomalies, library inventory)
        let forensicTimer = DispatchSource.makeTimerSource(queue: .global())
        forensicTimer.schedule(deadline: .now() + 120, repeating: 300) // First at 2min, then every 5min
        forensicTimer.setEventHandler {
            Task {
                // Crash report mining
                let exploits = await state.crashReportMiner.scan()
                for exploit in exploits {
                    let alert = Alert(
                        ruleId: "maccrab.forensic.crash-exploit-\(exploit.indicator)",
                        ruleTitle: "Exploitation Indicator in Crash Report: \(exploit.processName)",
                        severity: exploit.severity,
                        eventId: UUID().uuidString,
                        processPath: exploit.reportPath, processName: exploit.processName,
                        description: "\(exploit.indicator): \(exploit.excerpt)",
                        mitreTactics: "attack.execution", mitreTechniques: "attack.t1203",
                        suppressed: false
                    )
                    do { try await state.alertStore.insert(alert: alert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                    if exploit.severity >= .high { await state.notifier.notify(alert: alert) }
                    print("[CRASH] \(exploit.indicator) in \(exploit.processName)")
                }

                // Power anomaly detection
                let anomalies = await state.powerAnomalyDetector.scan()
                for anomaly in anomalies {
                    let alert = Alert(
                        ruleId: "maccrab.forensic.power-\(anomaly.type.rawValue)",
                        ruleTitle: "Power Anomaly: \(anomaly.processName) \(anomaly.type.rawValue)",
                        severity: anomaly.severity,
                        eventId: UUID().uuidString,
                        processPath: nil, processName: anomaly.processName,
                        description: anomaly.detail,
                        mitreTactics: "attack.execution", mitreTechniques: "attack.t1496",
                        suppressed: false
                    )
                    do { try await state.alertStore.insert(alert: alert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                }

                // Library inventory scan (every other cycle -- resource intensive)
                let injected = await state.libraryInventory.scanAllProcesses()
                for lib in injected {
                    let alert = Alert(
                        ruleId: "maccrab.forensic.injected-library",
                        ruleTitle: "Injected Library: \(lib.processName) loaded \((lib.libraryPath as NSString).lastPathComponent)",
                        severity: lib.severity,
                        eventId: UUID().uuidString,
                        processPath: lib.processPath, processName: lib.processName,
                        description: "\(lib.reason). Library: \(lib.libraryPath)",
                        mitreTactics: "attack.defense_evasion", mitreTechniques: "attack.t1574.006",
                        suppressed: false
                    )
                    do { try await state.alertStore.insert(alert: alert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
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

                // Vulnerability scan
                let vulns = await state.vulnScanner.scanInstalledApps()
                for vuln in vulns {
                    for v in vuln.vulnerabilities where v.severity == "critical" || v.severity == "high" {
                        logger.warning("Vulnerable app: \(vuln.appName) v\(vuln.installedVersion) -- \(v.cveId)")
                    }
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

        // Periodic baseline save + dedup sweep (every 5 minutes)
        let maintenanceTimer = DispatchSource.makeTimerSource(queue: .global())
        maintenanceTimer.schedule(deadline: .now() + 300, repeating: 300)
        maintenanceTimer.setEventHandler {
            Task {
                try? await state.baselineEngine.save()
                try? await state.processTreeAnalyzer.save()
                await state.deduplicator.sweep()
                await state.crossProcessCorrelator.purgeStale()
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

        return Handles(
            forensicTimer: forensicTimer,
            hourlyTimer: hourlyTimer,
            statsTimer: statsTimer,
            pruneTimer: pruneTimer,
            maintenanceTimer: maintenanceTimer,
            feedbackTimer: feedbackTimer
        )
    }
}
