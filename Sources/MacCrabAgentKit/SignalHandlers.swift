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
        /// v1.9 hot-fix: manual events.db size-cap sweep on demand.
        let sigUsr2Source: DispatchSourceSignal
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
                    // v1.19.1 (rc.9 review): re-apply the user_rules override overlay
                    // after the base reload. reloadRules() FULLY REPLACES the ruleset,
                    // so without this a `pkill -HUP` (the documented reload path) would
                    // DROP operator overrides until the next file-watch tick / restart.
                    // Same per-file daemon-owner gate as the startup + watcher load.
                    let overlayDir = state.supportDir + "/user_rules"
                    if FileManager.default.fileExists(atPath: overlayDir), isOverlayDirSecure(overlayDir),
                       let overlaid = try? await state.ruleEngine.loadRules(from: URL(fileURLWithPath: overlayDir), requireOwnerUID: geteuid()), overlaid > 0 {
                        print("[SIGHUP] Re-applied \(overlaid) user rule override(s)")
                    }
                    // Re-apply pushed (detection-only) rules — reloadRules cleared
                    // the pushed set; load them additive-only and refresh the
                    // response-engine detection-only gate.
                    let pushedDir = URL(fileURLWithPath: state.rulesURL.path + "/pushed")
                    if let pushed = try? await state.ruleEngine.loadPushedRules(from: pushedDir), pushed > 0 {
                        print("[SIGHUP] Re-applied \(pushed) pushed (detection-only) rule(s)")
                    }
                    let reloadedPushedIDs = await state.ruleEngine.pushedRuleIDs
                    await state.responseEngine.setDetectionOnlyRuleIDs(reloadedPushedIDs)
                    let seqCount = try await state.sequenceEngine.loadRules(from: URL(fileURLWithPath: state.sequenceRulesDir))
                    print("[SIGHUP] Reloaded \(singleCount) single + \(seqCount) sequence rules")

                    // v1.12.0 RC3 (Int-HSig1): also reload graph rules so
                    // an operator can edit Rules/graph/*.json and have
                    // them picked up without a daemon restart. The
                    // evaluator holds its rules immutably, so swap in a
                    // freshly-constructed instance.
                    let graphRulesDir = URL(fileURLWithPath: state.supportDir + "/compiled_rules/graph")
                    var graphRules = GraphRuleLoader.loadRules(from: graphRulesDir)
                    if graphRules.isEmpty {
                        let cwd = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
                        graphRules = GraphRuleLoader.loadFromProjectSource(projectRoot: cwd)
                    }
                    // v1.12.0 RC4 fix (Sec-R4-N3): always swap the
                    // evaluator, even when the new ruleset is empty.
                    // Pre-fix an operator who deleted all graph rules
                    // and SIGHUPed would still see the old rules
                    // fire silently — inconsistent with
                    // ruleEngine.reloadRules which fully replaces.
                    state.setGraphEvaluator(GraphRuleEvaluator(rules: graphRules))
                    print("[SIGHUP] Graph rules: \(graphRules.count)")
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
                    // v1.11.0: reload OS-notification config so the
                    // SettingsView toggle/picker takes effect on the
                    // next notification without a daemon restart.
                    // v1.11.0 RC2: pass `enabled` through as its own
                    // flag (was previously folded into a `.critical`
                    // sentinel which didn't actually mute critical
                    // alerts).
                    let notifConfig = loadAlertNotificationConfig(supportDir: state.supportDir)
                    await state.notifier.setMinimumSeverity(notifConfig.minSeverity)
                    await state.notifier.setEnabled(notifConfig.enabled)
                    print("[SIGHUP] Alert-notification config reloaded: enabled=\(notifConfig.enabled), minSeverity=\(notifConfig.minSeverity.rawValue)")

                    let freshConfig = DaemonConfig.load(from: state.supportDir)
                    let old = state.storage
                    var newStorage = freshConfig.storage
                    newStorage.eventsHotTierMinutes  = max(15, newStorage.eventsHotTierMinutes)
                    newStorage.eventsMaxSizeMB       = max(50, newStorage.eventsMaxSizeMB)
                    newStorage.aggregateDays         = max(1, newStorage.aggregateDays)
                    newStorage.alertsRetentionDays   = max(1, newStorage.alertsRetentionDays)
                    newStorage.alertsMaxSizeMB       = max(50, newStorage.alertsMaxSizeMB)
                    newStorage.campaignsRetentionDays = max(1, newStorage.campaignsRetentionDays)
                    newStorage.campaignsMaxSizeMB    = max(50, newStorage.campaignsMaxSizeMB)
                    state.storage = newStorage

                    // v1.19.1: re-apply the opt-in network-enrichment switches
                    // live. vuln-scan + package-freshness are read from state on
                    // the next sweep/event; the threat-intel feed needs its
                    // network loop started/stopped explicitly so a toggle halts
                    // (or resumes) egress without a daemon restart.
                    state.vulnScanEnabled = freshConfig.vulnScanEnabled
                    state.packageFreshnessEnabled = freshConfig.packageFreshnessEnabled
                    state.certTransparencyEnabled = freshConfig.certTransparencyEnabled
                    if state.threatIntelEnabled != freshConfig.threatIntelEnabled {
                        state.threatIntelEnabled = freshConfig.threatIntelEnabled
                        await state.threatIntel.setNetworkRefresh(freshConfig.threatIntelEnabled)
                        print("[SIGHUP] Threat-intel network refresh \(freshConfig.threatIntelEnabled ? "ENABLED" : "disabled (egress stopped)")")
                    }

                    let eventsCapChanged = old.eventsMaxSizeMB != newStorage.eventsMaxSizeMB
                    let anyChange = old.eventsHotTierMinutes  != newStorage.eventsHotTierMinutes
                                 || old.eventsMaxSizeMB       != newStorage.eventsMaxSizeMB
                                 || old.aggregateDays         != newStorage.aggregateDays
                                 || old.alertsRetentionDays   != newStorage.alertsRetentionDays
                                 || old.alertsMaxSizeMB       != newStorage.alertsMaxSizeMB
                                 || old.campaignsRetentionDays != newStorage.campaignsRetentionDays
                                 || old.campaignsMaxSizeMB    != newStorage.campaignsMaxSizeMB
                    if anyChange {
                        print("[SIGHUP] Storage config reloaded: events=\(newStorage.eventsHotTierMinutes)m/\(newStorage.eventsMaxSizeMB)MB, alerts=\(newStorage.alertsRetentionDays)d/\(newStorage.alertsMaxSizeMB)MB, campaigns=\(newStorage.campaignsRetentionDays)d/\(newStorage.campaignsMaxSizeMB)MB, aggregates=\(newStorage.aggregateDays)d")
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
                    // loadConfig probes BOTH this system path AND the user-home
                    // actions.json and no-ops when neither exists, so call it
                    // unconditionally. Gating on the SYSTEM file's existence
                    // (the prior behavior) skipped reloads of CLI/MCP/dashboard
                    // writes that land only in the user-home file on a clean
                    // machine (P1 — the new `actions` feature's activation path).
                    let actionsPath = state.supportDir + "/actions.json"
                    do {
                        try await state.responseEngine.loadConfig(from: actionsPath)
                        print("[SIGHUP] Response actions reloaded")
                    } catch {
                        print("[SIGHUP] Response action reload failed: \(error)")
                    }

                    // v1.9 Phase-3.4: pick up dashboard-written
                    // agent_traces_config.json so the operator's
                    // toggle takes effect without a daemon restart.
                    // Idempotent: same-port enabled→enabled is a
                    // no-op. Port change stops + restarts.
                    await DaemonSetup.applyAgentTracesConfig(
                        state: state,
                        supportDir: state.supportDir,
                        dbEncryption: state.dbEncryption
                    )

                    // v1.10.0: SIGHUP also triggers a one-shot threat-intel
                    // refresh. The dashboard's "Refresh feeds" button signals
                    // SIGHUP via maccrabctl rather than waiting on the 4-hour
                    // auto-refresh cadence.
                    //
                    // v1.19.1 (privacy): ONLY when threat-intel enrichment is
                    // opted in. Without this gate every reload — enabling a
                    // DIFFERENT feed, or even a storage-slider edit (which now
                    // SIGHUPs) — fired an abuse.ch fetch the user never enabled.
                    // refreshNow() is also self-guarding (no-op when the network
                    // loop isn't running), so this is defense in depth.
                    if freshConfig.threatIntelEnabled {
                        print("[SIGHUP] Refreshing threat intel feeds…")
                        await state.threatIntel.refreshNow()
                        print("[SIGHUP] Threat intel refresh complete")
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
                // v1.9 PR-5: drain the OTLP receiver first so the
                // NWListener is closed before launchd respawns the
                // daemon. Avoids leaving the kernel socket in
                // TIME_WAIT, which would make the next start fail to
                // bind 4318. Cheap (no new actor hops) and idempotent.
                await state.otlpReceiver?.stop()
                // v1.21.4 (audit): flush the batched events writer BEFORE exit —
                // the F2/A1 writer buffers up to flushThreshold/250ms of events,
                // and the driveSource tasks never end on their own, so
                // runEventLoop's post-stream shutdown flush is unreachable on a
                // signal. Without this, the last partial batch is lost on every
                // graceful SIGTERM/SIGINT (a regression vs the pre-F2 sync write).
                await state.eventWriter.shutdown()
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

        // v1.9 hot-fix: SIGUSR2 triggers immediate enforcement of the
        // events.db size cap. Workaround for hosts where the
        // periodic enforcer hasn't been keeping up (regression class
        // first seen on the v1.8.0 sysext: 5GB+ events.db growing
        // unchecked). Dashboard's "Reduce events.db now" button in
        // Settings sends this signal and reads the status snapshot.
        let sigUsr2Source = DispatchSource.makeSignalSource(signal: SIGUSR2, queue: .main)
        signal(SIGUSR2, SIG_IGN)
        sigUsr2Source.setEventHandler {
            print("[SIGUSR2] Manual events.db size-cap sweep requested by dashboard")
            Task {
                let beforeBytes = StorageFlushStatus.fileSize(at: state.supportDir + "/events.db")
                let started = Date()
                let didRun = await enforceDatabaseSizeCapNow(state: state)
                // v1.9.0 (audit Stab-M1): only persist a status
                // snapshot when WE actually ran the sweep. Pre-fix,
                // a second SIGUSR2 within ~2 s of the first would
                // hit the reentrancy guard, then still write its own
                // (stale) `bytesAfter` measurement on top of the
                // running sweep's pending state. Now the running
                // sweep's own final write wins.
                if didRun {
                    let afterBytes = StorageFlushStatus.fileSize(at: state.supportDir + "/events.db")
                    let status = StorageFlushStatus(
                        inProgress: false,
                        lastRunAt: started,
                        bytesBefore: beforeBytes,
                        bytesAfter: afterBytes,
                        note: nil
                    )
                    StorageFlushStatus.write(status, to: state.supportDir)
                    print("[SIGUSR2] events.db sweep done: \(beforeBytes / 1_000_000) MB → \(afterBytes / 1_000_000) MB")
                } else {
                    print("[SIGUSR2] events.db sweep skipped — another sweep is already in progress; preserving its pending status")
                }
            }
        }
        sigUsr2Source.resume()

        return Handles(
            sigHupSource: sigHupSource,
            sigTermSource: sigTermSource,
            sigIntSource: sigIntSource,
            sigUsr1Source: sigUsr1Source,
            sigUsr2Source: sigUsr2Source
        )
    }
}
