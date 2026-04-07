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

    static func install(state: DaemonState) -> Handles {
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
                        let matches = await state.ruleEngine.evaluate(event)
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
                } catch {
                    print("[SIGHUP] ERROR: \(error)")
                }
            }
        }
        sigHupSource.resume()

        // Handle SIGTERM/SIGINT for graceful shutdown
        let shutdownHandler = {
            logger.info("MacCrab daemon shutting down...")
            print("\nShutting down MacCrab daemon...")
            exit(0)
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
