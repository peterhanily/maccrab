import Foundation
import MacCrabCore
import os.log

/// Installs SIGHUP (rule reload), SIGTERM, and SIGINT (shutdown) handlers.
/// Returns the dispatch sources so they stay alive.
enum SignalHandlers {
    struct Handles {
        let sigHupSource: DispatchSourceSignal
        let sigTermSource: DispatchSourceSignal
        let sigIntSource: DispatchSourceSignal
        let sigUsr1Source: DispatchSourceSignal
    }

    static func install(state: DaemonState, supervisor: MonitorSupervisor) -> Handles {
        // Handle SIGHUP for rule reload
        let sigHupSource = DispatchSource.makeSignalSource(signal: SIGHUP, queue: .main)
        signal(SIGHUP, SIG_IGN) // Ignore default handler
        sigHupSource.setEventHandler {
            Task {
                do {
                    print("[SIGHUP] Reloading rules from: \(state.rulesURL.path)")
                    let singleCount = try await state.ruleEngine.reloadRules(from: state.rulesURL)
                    print("[SIGHUP] Single-event rules: \(singleCount)")
                    let seqCount = try await state.sequenceEngine.loadRules(from: URL(fileURLWithPath: state.sequenceRulesDir))
                    print("[SIGHUP] Reloaded \(singleCount) single + \(seqCount) sequence rules")
                    await state.suppressionManager.load()
                    let stats = await state.suppressionManager.stats()
                    print("[SIGHUP] Suppressions: \(stats.pathCount) paths across \(stats.ruleCount) rules")

                    // Retroactive detection: scan last 6 hours of events against new rules
                    let retroSince = Date().addingTimeInterval(-6 * 3600)
                    let recentEvents = try await state.eventStore.events(since: retroSince, limit: 10_000)
                    var retroMatches = 0
                    for event in recentEvents {
                        var matches = await state.ruleEngine.evaluate(event)
                        NoiseFilter.apply(&matches, event: event, isWarmingUp: state.isWarmingUp)
                        for match in matches {
                            let alert = Alert(
                                ruleId: match.ruleId,
                                ruleTitle: "[Retroactive] \(match.ruleName)",
                                severity: match.severity,
                                eventId: event.id.uuidString,
                                processPath: event.process.executable,
                                processName: event.process.name,
                                description: "Retroactive detection: \(match.description)",
                                mitreTactics: match.tags.filter { $0.hasPrefix("attack.") && !$0.contains("t1") }.joined(separator: ","),
                                mitreTechniques: match.tags.filter { $0.contains("t1") }.joined(separator: ","),
                                suppressed: false
                            )
                            // AlertSink applies dedup + insert in one call; the
                            // retroactive scan's earlier manual dedup folded in.
                            let inserted: Bool
                            do {
                                inserted = try await state.alertSink.submit(alert: alert, event: event)
                            } catch {
                                await StorageErrorTracker.shared.recordAlertError(error)
                                continue
                            }
                            if inserted { retroMatches += 1 }
                        }
                    }
                    if retroMatches > 0 {
                        print("[SIGHUP] Retroactive scan: \(retroMatches) new detections from \(recentEvents.count) events")
                    } else {
                        print("[SIGHUP] Retroactive scan: no new detections in \(recentEvents.count) events")
                    }

                    // v1.6.14: reload storage config so the operator's
                    // Settings slider value (written to daemon_config.json
                    // by the dashboard) takes effect without a daemon
                    // restart. v1.8.0 expanded this from a single (cap, ret)
                    // pair to per-tier {events, alerts, campaigns} budgets.
                    let freshConfig = DaemonConfig.load(from: state.supportDir)
                    let old = state.storage
                    var newStorage = freshConfig.storage
                    newStorage.eventsHotTierHours    = max(1, newStorage.eventsHotTierHours)
                    newStorage.eventsMaxSizeMB       = max(50, newStorage.eventsMaxSizeMB)
                    newStorage.aggregateDays         = max(1, newStorage.aggregateDays)
                    newStorage.alertsRetentionDays   = max(1, newStorage.alertsRetentionDays)
                    newStorage.alertsMaxSizeMB       = max(50, newStorage.alertsMaxSizeMB)
                    newStorage.campaignsRetentionDays = max(1, newStorage.campaignsRetentionDays)
                    newStorage.campaignsMaxSizeMB    = max(50, newStorage.campaignsMaxSizeMB)
                    state.storage = newStorage

                    let eventsCapChanged = old.eventsMaxSizeMB != newStorage.eventsMaxSizeMB
                    let anyChange = old.eventsHotTierHours    != newStorage.eventsHotTierHours
                                 || old.eventsMaxSizeMB       != newStorage.eventsMaxSizeMB
                                 || old.aggregateDays         != newStorage.aggregateDays
                                 || old.alertsRetentionDays   != newStorage.alertsRetentionDays
                                 || old.alertsMaxSizeMB       != newStorage.alertsMaxSizeMB
                                 || old.campaignsRetentionDays != newStorage.campaignsRetentionDays
                                 || old.campaignsMaxSizeMB    != newStorage.campaignsMaxSizeMB
                    if anyChange {
                        print("[SIGHUP] Storage config reloaded: events=\(newStorage.eventsHotTierHours)h/\(newStorage.eventsMaxSizeMB)MB, alerts=\(newStorage.alertsRetentionDays)d/\(newStorage.alertsMaxSizeMB)MB, campaigns=\(newStorage.campaignsRetentionDays)d/\(newStorage.campaignsMaxSizeMB)MB, aggregates=\(newStorage.aggregateDays)d")
                        if eventsCapChanged {
                            // Lowered events cap: kick an immediate sweep so the
                            // operator sees the DB shrink in seconds instead of
                            // waiting up to 6h for the next rollup tick.
                            await enforceDatabaseSizeCapNow(state: state)
                        }
                    } else {
                        print("[SIGHUP] Storage config unchanged")
                    }

                    // v1.6.19: pick up dashboard-written notifications.json
                    // so Slack / Teams / Discord / PagerDuty webhooks edited
                    // in Settings start firing without a daemon restart.
                    await state.notificationIntegrations.reloadConfig()
                    let services = await state.notificationIntegrations.configuredServices()
                    print("[SIGHUP] Notification services: \(services.isEmpty ? "none" : services.joined(separator: ", "))")

                    // v1.6.19.1: pick up dashboard-written actions.json so
                    // Response Actions tab edits (per-rule kill / quarantine
                    // / blockNetwork / script / notify configs) take effect
                    // without a daemon restart. Writes from the user app
                    // land in ~/Library/.../actions.json; the loader probes
                    // both that path and the system path and prefers the
                    // most recent.
                    let actionsPath = state.supportDir + "/actions.json"
                    if FileManager.default.fileExists(atPath: actionsPath) {
                        do {
                            try await state.responseEngine.loadConfig(from: actionsPath)
                            print("[SIGHUP] Response actions reloaded from \(actionsPath)")
                        } catch {
                            print("[SIGHUP] Response action reload failed: \(error)")
                        }
                    }
                } catch {
                    print("[SIGHUP] ERROR: \(error)")
                }
            }
        }
        sigHupSource.resume()

        // Handle SIGTERM/SIGINT for graceful shutdown.
        //
        // The OS will SIGKILL us anyway if we dawdle (sysextd has its own
        // termination deadline, launchd has `ExitTimeOut`, Sparkle's
        // installer doesn't wait forever), so we race supervisor.shutdown
        // against our own 3-second deadline. If every supervised task
        // unwinds in time, great; if not, we still exit cleanly so the
        // OS never has to resort to SIGKILL and leave state half-written.
        let shutdownHandler: @Sendable () -> Void = {
            logger.info("MacCrab daemon shutting down...")
            print("\nShutting down MacCrab daemon...")
            Task {
                await supervisor.shutdown(deadline: 3.0)
                exit(0)
            }
            // Hard fallback: if the Task above gets stuck (supervisor
            // actor deadlocked, scheduler starved), make sure we still
            // exit within ~4s of the signal. exit() from any thread is
            // fine once we're past the graceful window.
            DispatchQueue.global().asyncAfter(deadline: .now() + 4.0) {
                logger.warning("MacCrab daemon shutdown deadline exceeded — forcing exit")
                exit(0)
            }
        }

        let sigTermSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        signal(SIGTERM, SIG_IGN)
        sigTermSource.setEventHandler { shutdownHandler() }
        sigTermSource.resume()

        let sigIntSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
        signal(SIGINT, SIG_IGN)
        sigIntSource.setEventHandler { shutdownHandler() }
        sigIntSource.resume()

        // v1.6.17: SIGUSR1 triggers a one-shot threat-intel feed
        // refresh. Used by the dashboard's "Refresh Now" button so
        // operators don't have to wait the full 4 h cadence after
        // editing custom IOCs or after a feed outage.
        let sigUsr1Source = DispatchSource.makeSignalSource(signal: SIGUSR1, queue: .main)
        signal(SIGUSR1, SIG_IGN)
        sigUsr1Source.setEventHandler {
            print("[SIGUSR1] Threat intel feed refresh requested by dashboard")
            Task {
                await state.threatIntel.refreshNow()
                print("[SIGUSR1] Threat intel refresh complete")
            }
        }
        sigUsr1Source.resume()

        return Handles(
            sigHupSource: sigHupSource,
            sigTermSource: sigTermSource,
            sigIntSource: sigIntSource,
            sigUsr1Source: sigUsr1Source
        )
    }
}
