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
                            // Skip if already deduplicated
                            if await state.deduplicator.shouldSuppress(ruleId: match.ruleId, processPath: event.process.executable) {
                                continue
                            }
                            await state.deduplicator.recordAlert(ruleId: match.ruleId, processPath: event.process.executable)

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
                            do { try await state.alertStore.insert(alert: alert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                            retroMatches += 1
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
                    // restart. Before this change, `maxDatabaseSizeMB`
                    // and `retentionDays` were captured into the timer
                    // closures at setup time and a SIGHUP only reloaded
                    // rules — so lowering the cap in Settings required
                    // a full reinstall or reboot to land.
                    let freshConfig = DaemonConfig.load(from: state.supportDir)
                    let oldCap = state.maxDatabaseSizeMB
                    let oldRet = state.retentionDays
                    let newCap = max(50, freshConfig.maxDatabaseSizeMB)
                    let newRet = freshConfig.retentionDays
                    state.maxDatabaseSizeMB = newCap
                    state.retentionDays = newRet
                    if oldCap != newCap || oldRet != newRet {
                        print("[SIGHUP] Storage config reloaded: maxDatabaseSizeMB \(oldCap)->\(newCap), retentionDays \(oldRet)->\(newRet)")
                        // Kick an immediate size-cap sweep so a lowered
                        // cap visibly prunes without waiting up to an
                        // hour. No-op if currently under the new cap.
                        await enforceDatabaseSizeCapNow(state: state)
                    } else {
                        print("[SIGHUP] Storage config unchanged (cap=\(newCap) MB, retention=\(newRet)d)")
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

        return Handles(
            sigHupSource: sigHupSource,
            sigTermSource: sigTermSource,
            sigIntSource: sigIntSource
        )
    }
}
