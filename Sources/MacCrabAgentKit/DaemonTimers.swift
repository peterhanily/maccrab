import Foundation
import MacCrabCore
import CSQLCipher
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

// MARK: - v1.21.4 Phase-1 D2 — sensor-degraded / possible-evasion evaluator
//
// A file-write flood that spikes above baseline WHILE the kernel is dropping
// ES messages (or the process/exec channel collapses) is the "cross-channel
// blind-spot" signature: a benign-looking storm starving MacCrab's exec
// attribution. This evaluator is PURE + deterministic (baseline in → decision
// + baseline out) so it can be unit-tested with synthetic heartbeat inputs
// without a live daemon. The rolling EWMA baseline is held LOCALLY by the
// heartbeat closure in `DaemonTimers.start` (a locked box), NOT on DaemonState.
//
// Evasion advisory ONLY — nothing here auto-throttles or auto-mutes in
// response (owner decision). It emits a HIGH meta-alert (LOW when the dominant
// high-I/O writer is a known-benign signer, so coverage loss is never fully
// silent).
enum SensorDegradationEvaluator {

    // Tunables — NEEDS-ON-DEVICE calibration against real host baselines.
    /// EWMA smoothing factor over 30 s ticks (~3-4 tick memory).
    static let ewmaAlpha = 0.3
    /// A tick's file-event rate must exceed baseline × this to count as a spike.
    static let fileSpikeMultiplier = 3.0
    /// Absolute floor: below this many file events in a tick, no spike (guards
    /// the divide-by-tiny-baseline FP on an idle box / at daemon start).
    static let minFileEventsForSpike = 2000.0
    /// Process/exec events collapse when they fall below baseline × this.
    static let processCollapseRatio = 0.5
    /// The process/exec baseline must have been at least this busy for a
    /// "collapse" to mean anything — stops a near-idle box (trivial exec rate)
    /// from tripping the collapse branch on ordinary noise. The kernel-drop
    /// branch is unaffected.
    static let minProcessBaselineForCollapse = 50.0

    /// Rolling baseline carried tick-to-tick. `degradedActive` is the latch
    /// that makes a sustained flood fire exactly once (rising-edge only).
    struct Baseline: Equatable {
        var fileEventEwma: Double = 0
        var processEventEwma: Double = 0
        var seeded: Bool = false
        var degradedActive: Bool = false
    }

    /// Per-tick inputs, all derived from the D1/D4 monotonic counters' deltas.
    struct Input {
        /// File write-family events processed this tick (CREATE/WRITE/CLOSE/
        /// RENAME/UNLINK delta).
        var fileEventsThisTick: Double
        /// Process/exec events reached-at-callback this tick (EXEC/FORK/EXIT
        /// delta). Collapses precisely when the kernel drops exec messages.
        var processEventsThisTick: Double
        /// `es_kernel_dropped_total` delta over this tick.
        var kernelDropDelta: UInt64
        /// ES-collector-stage userspace drops over this tick:
        /// `es_copy_backpressure_dropped_total` + `es_stream_yield_dropped_total`.
        /// After Phase-3 (async retain-worker) and Phase-4 (file/exec client
        /// split), a flood no longer produces KERNEL drops — the message is
        /// retained off the kernel queue and then lost when the bounded worker
        /// queue or the collector's AsyncStream buffer overflows. Those are the
        /// dominant coverage-loss signal now, so D2 must gate on them too, not
        /// just `kernelDropDelta` (else a real flood degrades the sensor
        /// silently). NOT the merged-stream `events_dropped` — that is a
        /// downstream consumer stage, deliberately kept out of the ES-sensor
        /// verdict.
        var collectorDropDelta: UInt64
        /// The dominant high-I/O writer this window is a known-benign signer.
        var benignHighIOSigner: Bool
    }

    enum Outcome: Equatable {
        case noAlert
        /// Fire. `severity` is HIGH normally, LOW when attributed to a
        /// benign signer; `benignAttribution` echoes the input for the
        /// "(benign attribution)" wording.
        case degraded(severity: Severity, benignAttribution: Bool)
    }

    struct Result: Equatable {
        var outcome: Outcome
        var newBaseline: Baseline
        // Diagnostics for the alert description.
        var fileRate: Double
        var fileBaseline: Double
        var processRate: Double
        var processBaseline: Double
        var kernelDropDelta: UInt64
        var collectorDropDelta: UInt64
    }

    /// Pure evaluation: given this tick's inputs and the prior baseline,
    /// decide whether the sensor is degraded and return the advanced baseline.
    static func evaluate(input: Input, baseline: Baseline) -> Result {
        var b = baseline

        // First observation: seed the baseline; a spike needs history.
        guard b.seeded else {
            b.fileEventEwma = input.fileEventsThisTick
            b.processEventEwma = input.processEventsThisTick
            b.seeded = true
            return Result(
                outcome: .noAlert, newBaseline: b,
                fileRate: input.fileEventsThisTick, fileBaseline: input.fileEventsThisTick,
                processRate: input.processEventsThisTick, processBaseline: input.processEventsThisTick,
                kernelDropDelta: input.kernelDropDelta,
                collectorDropDelta: input.collectorDropDelta
            )
        }

        let spike = input.fileEventsThisTick >= minFileEventsForSpike
            && input.fileEventsThisTick > b.fileEventEwma * fileSpikeMultiplier
        let processCollapse = b.processEventEwma >= minProcessBaselineForCollapse
            && input.processEventsThisTick < b.processEventEwma * processCollapseRatio
        // Any coverage-loss signal — kernel drops OR the ES-collector-stage
        // userspace drops (backpressure / stream-yield) OR an exec-channel
        // collapse — while the file rate is spiking is a degraded sensor.
        // collectorDropDelta is the signal that survives Phase-3/4 (which drove
        // kernelDropDelta to ~0); without it the meta-alert never fires on a
        // real flood.
        let conjunction = spike
            && (input.kernelDropDelta > 0 || input.collectorDropDelta > 0 || processCollapse)

        var outcome: Outcome = .noAlert
        if conjunction && !b.degradedActive {
            // Rising edge — fire once. Benign signer downgrades HIGH → LOW.
            let severity: Severity = input.benignHighIOSigner ? .low : .high
            outcome = .degraded(severity: severity, benignAttribution: input.benignHighIOSigner)
            b.degradedActive = true
        }
        // Re-arm only when the file-rate spike subsides (not merely when drops
        // pause), so a sustained flood stays latched at exactly one fire.
        if !spike { b.degradedActive = false }

        // Don't learn from anomalies: freeze the baseline while spiking so a
        // flood can't poison it (which would blind the next episode).
        if !spike {
            b.fileEventEwma = ewmaAlpha * input.fileEventsThisTick + (1 - ewmaAlpha) * b.fileEventEwma
            b.processEventEwma = ewmaAlpha * input.processEventsThisTick + (1 - ewmaAlpha) * b.processEventEwma
        }

        return Result(
            outcome: outcome, newBaseline: b,
            fileRate: input.fileEventsThisTick, fileBaseline: baseline.fileEventEwma,
            processRate: input.processEventsThisTick, processBaseline: baseline.processEventEwma,
            kernelDropDelta: input.kernelDropDelta,
            collectorDropDelta: input.collectorDropDelta
        )
    }
}

/// Thread-safe holder for the D2 EWMA baseline + the previous cumulative
/// counters (for the per-tick delta) — LOCAL to `DaemonTimers.start` (captured
/// by the heartbeat closure), so overlapping heartbeat ticks (the design
/// permits parallel ticks when one runs > 30 s) can't race the
/// read-modify-write. NOT a DaemonState field.
final class SensorDegradationState: @unchecked Sendable {
    private let lock = NSLock()
    private var baseline = SensorDegradationEvaluator.Baseline()
    private var lastFileCumulative: UInt64 = 0
    private var lastProcessCumulative: UInt64 = 0
    private var lastKernelDropCumulative: UInt64 = 0
    private var lastCollectorDropCumulative: UInt64 = 0
    private var haveLastCumulative = false

    /// Fold this tick's CUMULATIVE counters (monotonic since the last ES
    /// client (re)create) into per-tick deltas, then evaluate. A client
    /// reconnect resets the kernel counters to a lower value; a negative delta
    /// is clamped to 0 so a restart isn't miscounted as a giant burst.
    func step(
        fileCumulative: UInt64,
        processCumulative: UInt64,
        kernelDropCumulative: UInt64,
        collectorDropCumulative: UInt64,
        benignHighIOSigner: Bool
    ) -> SensorDegradationEvaluator.Result {
        lock.lock(); defer { lock.unlock() }

        // First call: no prior cumulative, so no real delta exists yet. Record
        // and skip the evaluator so its baseline is seeded from the first REAL
        // delta (next tick) rather than a fake zero — which would otherwise let
        // any first delta ≥ minFileEventsForSpike spike against a zero baseline.
        guard haveLastCumulative else {
            lastFileCumulative = fileCumulative
            lastProcessCumulative = processCumulative
            lastKernelDropCumulative = kernelDropCumulative
            lastCollectorDropCumulative = collectorDropCumulative
            haveLastCumulative = true
            return SensorDegradationEvaluator.Result(
                outcome: .noAlert, newBaseline: baseline,
                fileRate: 0, fileBaseline: 0, processRate: 0, processBaseline: 0,
                kernelDropDelta: 0, collectorDropDelta: 0
            )
        }

        func delta(_ cur: UInt64, _ last: UInt64) -> UInt64 { cur >= last ? cur &- last : 0 }
        let fileDelta = delta(fileCumulative, lastFileCumulative)
        let processDelta = delta(processCumulative, lastProcessCumulative)
        let dropDelta = delta(kernelDropCumulative, lastKernelDropCumulative)
        let collectorDropDelta = delta(collectorDropCumulative, lastCollectorDropCumulative)

        lastFileCumulative = fileCumulative
        lastProcessCumulative = processCumulative
        lastKernelDropCumulative = kernelDropCumulative
        lastCollectorDropCumulative = collectorDropCumulative

        let input = SensorDegradationEvaluator.Input(
            fileEventsThisTick: Double(fileDelta),
            processEventsThisTick: Double(processDelta),
            kernelDropDelta: dropDelta,
            collectorDropDelta: collectorDropDelta,
            benignHighIOSigner: benignHighIOSigner
        )
        let result = SensorDegradationEvaluator.evaluate(input: input, baseline: baseline)
        baseline = result.newBaseline
        return result
    }
}

// MARK: - v1.21.4 Phase-2 D3 — coverage-canary two-point verdict
//
// The watchdog spawns `/usr/bin/true` with a per-run nonce, then checks two
// independent points: (1) did the ES callback SEE the exec, and (2) did it
// land in `events.db`. This PURE evaluator turns those two booleans into a
// verdict that NAMES the failing stage — so a coverage gap is attributed to
// the kernel/ingest path vs the store/eviction path, not reported as an
// undifferentiated "we lost it". Deterministic → unit-tested without a spawn.
enum CoverageCanaryEvaluator {
    enum Verdict: Equatable {
        /// Seen at the callback AND present in the DB — full coverage.
        case healthy
        /// Missing at the ES callback ⇒ the kernel/ingest stage dropped it
        /// (per-client-queue backpressure — the D1 blind-spot made visible).
        case kernelGap
        /// Seen at the callback but absent from the DB ⇒ the store/eviction
        /// stage lost it (retention sweep evicted the row, or an insert gap).
        case evictionGap

        /// Human-readable stage name for the alert (nil when healthy).
        var stageLabel: String? {
            switch self {
            case .healthy:     return nil
            case .kernelGap:   return "kernel/ingest"
            case .evictionGap: return "store/eviction"
            }
        }
    }

    /// Two-point verdict. A miss at the callback dominates: if the exec never
    /// reached us, the DB result is moot (and a lone DB hit without a callback
    /// sighting would be a timing artifact of the recognizer window, not real
    /// coverage), so `seenAtCallback == false` is always a kernel gap.
    static func verdict(seenAtCallback: Bool, foundInDB: Bool) -> Verdict {
        guard seenAtCallback else { return .kernelGap }
        return foundInDB ? .healthy : .evictionGap
    }
}

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
        /// v1.12.6: early-fire watchdog (60 s cadence) for the events.db
        /// size cap. Defense-in-depth for the configurable scheduled
        /// `sizeCapTimer` — catches sudden growth bursts (DB > 1.5× cap)
        /// between scheduled sweeps. Retained here so the DispatchSourceTimer
        /// isn't ARC-deallocated on return from `start()` (mirrors the
        /// v1.10.0 fix for the trace/tracegraph prune timers).
        let sizeCapWatchdogTimer: DispatchSourceTimer
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
        /// v1.18.0: daily sweep for generated-artifact directories that
        /// previously had no retention — `reports/` (age-based) and
        /// `compiled_rules/auto_generated/` (count cap, oldest-first).
        let artifactsPruneTimer: DispatchSourceTimer?
        /// v1.10.0: file-based IPC poller. Polls
        /// /Library/Application Support/MacCrab/inbox/*.json every 5 s
        /// so the dashboard (running as the user) can request mutations
        /// on a root-owned DB without needing signal-delivery permission.
        /// Handles: flush-request-*, suppress-alert-*, unsuppress-alert-*,
        /// delete-alert-*, suppress-campaign-* (v1.10.1).
        let inboxPoller: DispatchSourceTimer
        /// v1.21.4 Phase-2 (D3): jittered coverage-canary watchdog. Self-
        /// reschedules ~5-15 min out on each fire (see start()). Retained here
        /// so the DispatchSourceTimer isn't ARC-deallocated on return from
        /// start() (same reason as the prune timers above).
        let coverageCanaryTimer: DispatchSourceTimer
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
                //
                // v1.19.1: the osv.dev lookup POSTs the installed-software
                // inventory, so it is opt-in (off by default). Read the flag
                // live from state so a SIGHUP toggle takes effect next sweep.
                let vulns = state.vulnScanEnabled ? await state.vulnScanner.scanInstalledApps() : []
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
            // v1.18: first sweep at +180 s (not +3600), then hourly (not daily).
            // tracegraph.db is the per-event-growing "worst offender" and was the
            // only size-capped store still on a 1h-first / daily cadence — so a
            // sysext that inherited an over-cap substrate from the previous
            // session sat at 438 MB+ for a full hour every boot, and on a busy
            // host drifted back over the 250 MB cap between daily sweeps. Match
            // the events.db size-cap philosophy (+60 s / hourly). Now cheap:
            // auto_vacuum=INCREMENTAL (set in openDatabase) makes the post-prune
            // incremental_vacuum a real freelist reclaim, so full VACUUM only
            // runs on the rare occasion incremental can't fit the budget.
            t.schedule(deadline: .now() + 180, repeating: 3600)
            t.setEventHandler {
                Task {
                    // v1.18: retention + size cap are now operator-tunable
                    // (storage.tracegraphRetentionDays / tracegraphMaxSizeMB),
                    // replacing the hardcoded 90d / 250 MB.
                    let days = max(1, min(state.storage.tracegraphRetentionDays, 3650))
                    let capBytes = Int64(max(50, state.storage.tracegraphMaxSizeMB)) * 1024 * 1024
                    let cutoff = Date().addingTimeInterval(-Double(days) * 86400)
                    let pruned = (try? await causalStore.pruneTraces(olderThan: cutoff)) ?? 0
                    if pruned > 0 {
                        logger.info("TraceGraph retention sweep: \(pruned) traces older than \(days)d pruned")
                    }
                    // v1.18: bound the global entity/edge substrate — the
                    // dominant (and, pre-v1.18, never-reclaimed) tenant of
                    // tracegraph.db. Orphan-guarded so surviving traces are
                    // never corrupted.
                    //
                    // The substrate is NOT subject to the 90-day TRACE retention:
                    // an entity/edge that hasn't joined a trace within the ±300s
                    // materialization window is dead and never will, so pruning it
                    // by the trace cutoff (90d) let orphans pile up to 91%+ of the
                    // file on a young DB (audit: 207k orphan entities / 7 traces,
                    // ~179 MB). Reclaim orphans older than a short window instead;
                    // the orphan guard keeps surviving traces safe at any window.
                    let orphanCutoff = Date().addingTimeInterval(-3600)  // 1h ≫ the 5-min trace window
                    let orphans = (try? await causalStore.pruneOrphanedGraph(olderThan: orphanCutoff)) ?? (edges: 0, entities: 0)
                    if orphans.edges > 0 || orphans.entities > 0 {
                        logger.info("TraceGraph substrate sweep: pruned \(orphans.edges) orphan edges + \(orphans.entities) orphan entities (>1h, unreferenced)")
                    }
                    // v1.19: TRUNCATE the WAL every tick so tracegraph.db-wal
                    // can't sit pinned at the 64 MiB journal_size_limit ceiling.
                    // RESTART (the old walCheckpoint) drains the WAL but leaves
                    // the sidecar file at its high-water mark; under a busy
                    // upsert stream that's a steady 64 MiB of invisible footprint.
                    _ = await causalStore.walCheckpointTruncate()
                    // v1.19: trip on the FOOTPRINT (db + WAL + shm), not the
                    // bare db file. databaseSizeBytes() saw only the .db file, so
                    // a 213 MB db + a 64 MiB WAL (= 281 MB real footprint) never
                    // tripped the 250 MB cap and the freelist was never reclaimed
                    // — matching the events/alerts/campaigns gates that already
                    // measure footprint via measureDatabaseFootprintMB (MB == 10^6).
                    let cgPath = state.supportDir + "/tracegraph.db"
                    let capMB = Int(capBytes / (1024 * 1024))
                    let footprintMB = measureDatabaseFootprintMB(dbPath: cgPath)
                    if footprintMB > capMB {
                        // Over cap: drop oldest traces AND evict the oldest
                        // unreferenced substrate (the bulk). Keep looping
                        // until under cap or nothing more can be pruned.
                        for _ in 0..<5 {
                            let count = (try? await causalStore.traceCount()) ?? 0
                            let dropTarget = max(50, count / 10)
                            let droppedTraces = (try? await causalStore.pruneOldestTraces(count: dropTarget)) ?? 0
                            let droppedGraph = (try? await causalStore.pruneOldestGraph(count: 50_000)) ?? (edges: 0, entities: 0)
                            if droppedTraces == 0 && droppedGraph.edges == 0 && droppedGraph.entities == 0 { break }
                            // Break on LIVE data size (page_count − freelist), NOT the
                            // file footprint: DELETEs free pages onto the freelist but
                            // the file doesn't shrink until the post-loop
                            // incremental_vacuum, so a databaseSizeBytes() check never
                            // tripped and this loop over-pruned ~10× past the cap
                            // (field-observed 476 MB → 36 MB at a 250 MB cap). liveSize
                            // tracks the prune in real time, so we stop near the cap and
                            // let the vacuum below shrink the file to match.
                            let liveSize = await causalStore.liveDataSizeBytes()
                            logger.warning("TraceGraph size cap: pruned \(droppedTraces) oldest traces + \(droppedGraph.edges) edges + \(droppedGraph.entities) entities (live \(liveSize / 1024 / 1024) MB vs \(capBytes / 1024 / 1024) MB cap)")
                            if liveSize < capBytes { break }
                        }

                        // Wave 9B (v1.12.6): tracegraph.db is the
                        // worst offender — field-observed 11 GB on a
                        // long-running install. Try incremental_vacuum
                        // first (no scratch disk needed), then full
                        // VACUUM only if disk has 1.3× headroom.
                        //
                        // auto_vacuum=INCREMENTAL is set in openDatabase
                        // (Wave 9B.1), so incremental_vacuum is a real
                        // freelist reclaim here; full VACUUM below is the
                        // rare fallback for when incremental can't fit the
                        // budget (or a pre-Wave-9B.1 mode-0 file).
                        let postPruneMB = measureDatabaseFootprintMB(dbPath: cgPath)
                        let mode = await causalStore.autoVacuumMode()
                        let reclaimed = (try? await causalStore.incrementalVacuum(maxPages: 200_000)) ?? 0
                        let postIncrementalMB = measureDatabaseFootprintMB(dbPath: cgPath)
                        if reclaimed > 0 {
                            logger.notice("TraceGraph size cap: incremental_vacuum reclaimed \(reclaimed) pages, \(postPruneMB) MB → \(postIncrementalMB) MB")
                        } else if mode != 2 {
                            logger.warning("TraceGraph size cap: incremental_vacuum unavailable (auto_vacuum mode=\(mode), need 2/INCREMENTAL). Run `maccrabctl maintenance vacuum tracegraph` once to convert.")
                        }

                        let freeMB = freeDiskMB(forPath: cgPath)
                        let needMB = Int(Double(postIncrementalMB) * 1.3)
                        if freeMB >= needMB {
                            do {
                                try await causalStore.vacuum()
                                let finalMB = measureDatabaseFootprintMB(dbPath: cgPath)
                                logger.notice("TraceGraph size cap: full VACUUM complete — \(postIncrementalMB) MB → \(finalMB) MB")
                            } catch {
                                logger.warning("TraceGraph size cap: full VACUUM failed (\(error.localizedDescription)). incremental_vacuum reclaimed \(reclaimed) pages.")
                            }
                        } else {
                            logger.warning("TraceGraph size cap: full VACUUM skipped — need \(needMB) MB free, have \(freeMB) MB. incremental_vacuum reclaimed \(reclaimed) pages.")
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
            // v1.18: first sweep at +180 s so an inherited over-cap traces.db
            // reconciles shortly after boot instead of an hour in. OTLP spans
            // aren't a per-event offender like the graph substrate, so the
            // steady cadence stays daily.
            t.schedule(deadline: .now() + 180, repeating: 86400)
            t.setEventHandler {
                Task {
                    // v1.18: operator-tunable (storage.tracesRetentionDays /
                    // tracesMaxSizeMB), replacing the hardcoded 90d / 100 MB.
                    let days = max(1, min(state.storage.tracesRetentionDays, 3650))
                    let capBytes = Int64(max(50, state.storage.tracesMaxSizeMB)) * 1024 * 1024
                    let cutoff = Date().addingTimeInterval(-Double(days) * 86400)
                    let pruned = (try? await traceStore.prune(olderThan: cutoff)) ?? 0
                    if pruned > 0 {
                        logger.info("OTLP traces retention sweep: \(pruned) spans older than \(days)d pruned")
                    }
                    // v1.19: TRUNCATE the WAL every tick so traces.db-wal can't
                    // sit pinned at the 64 MiB journal_size_limit ceiling.
                    _ = await traceStore.walCheckpointTruncate()
                    // v1.19: TRIP on the FOOTPRINT (db + WAL + shm), not the live
                    // data size. The prior trip used liveDataSizeBytes() — correct
                    // for the loop BREAK (avoids over-prune; see comment in loop),
                    // but as the trip GATE it ignored a 64 MiB pinned WAL, so a
                    // live-data-just-under-cap + full-WAL footprint never tripped
                    // and the freelist/WAL were never reclaimed. Mirrors the
                    // events/alerts/campaigns gates (measureDatabaseFootprintMB).
                    let tsPath = state.supportDir + "/traces.db"
                    let capMB = Int(capBytes / (1024 * 1024))
                    let footprintMB = measureDatabaseFootprintMB(dbPath: tsPath)
                    if footprintMB > capMB {
                        // Loop BREAK still keys on LIVE data size, not the file
                        // footprint. traces.db is auto_vacuum=INCREMENTAL, so
                        // DELETEs go to the freelist and the file doesn't shrink
                        // until the post-loop vacuum — keying the break on file
                        // size ran all 5 iterations and over-pruned ~41% of spans.
                        for _ in 0..<5 {
                            let count = (try? await traceStore.count()) ?? 0
                            let dropTarget = max(500, count / 10)
                            let dropped = (try? await traceStore.pruneOldest(count: dropTarget)) ?? 0
                            let liveMB = await traceStore.liveDataSizeBytes() / 1024 / 1024
                            logger.warning("OTLP traces size cap: pruned \(dropped) oldest spans (footprint \(footprintMB) MB > \(capMB) MB cap, live \(liveMB) MB)")
                            if dropped == 0 { break }
                            let nowSize = await traceStore.liveDataSizeBytes()
                            if nowSize < capBytes { break }
                        }

                        // Wave 9B (v1.12.6): incremental_vacuum +
                        // low-disk-safe full VACUUM. Same pattern as
                        // the tracegraph.db enforcer above. traces.db
                        // is auto_vacuum=INCREMENTAL (since v1.12.6 RC2),
                        // so incrementalVacuum reclaims freed pages.
                        let postPruneMB = measureDatabaseFootprintMB(dbPath: tsPath)
                        let mode = await traceStore.autoVacuumMode()
                        let reclaimed = (try? await traceStore.incrementalVacuum(maxPages: 200_000)) ?? 0
                        let postIncrementalMB = measureDatabaseFootprintMB(dbPath: tsPath)
                        if reclaimed > 0 {
                            logger.notice("OTLP traces size cap: incremental_vacuum reclaimed \(reclaimed) pages, \(postPruneMB) MB → \(postIncrementalMB) MB")
                        } else if mode != 2 {
                            logger.warning("OTLP traces size cap: incremental_vacuum unavailable (auto_vacuum mode=\(mode), need 2/INCREMENTAL). Run `maccrabctl maintenance vacuum traces` once to convert.")
                        }

                        let freeMB = freeDiskMB(forPath: tsPath)
                        let needMB = Int(Double(postIncrementalMB) * 1.3)
                        if freeMB >= needMB {
                            do {
                                try await traceStore.vacuum()
                                let finalMB = measureDatabaseFootprintMB(dbPath: tsPath)
                                logger.notice("OTLP traces size cap: full VACUUM complete — \(postIncrementalMB) MB → \(finalMB) MB")
                            } catch {
                                logger.warning("OTLP traces size cap: full VACUUM failed (\(error.localizedDescription)). incremental_vacuum reclaimed \(reclaimed) pages.")
                            }
                        } else {
                            logger.warning("OTLP traces size cap: full VACUUM skipped — need \(needMB) MB free, have \(freeMB) MB. incremental_vacuum reclaimed \(reclaimed) pages.")
                        }
                    }
                }
            }
            t.resume()
            tracesPruneTimer = t
        } else {
            tracesPruneTimer = nil
        }

        // v1.18.0: generated-artifact retention. Daily, cheap, independent
        // of the DB stores. reports/ pruned by age (storage.reportsRetentionDays);
        // compiled_rules/auto_generated/ capped to the newest N files
        // (storage.autoGeneratedRulesMax, oldest pruned first). 0 disables
        // either sweep.
        let artifactsPruneTimer: DispatchSourceTimer
        let artifactsTimer = DispatchSource.makeTimerSource(queue: .global())
        artifactsTimer.schedule(deadline: .now() + 3600, repeating: 86400)
        let artifactsSupportDir = state.supportDir
        let reportsRetentionDays = state.storage.reportsRetentionDays
        let autoGeneratedRulesMax = state.storage.autoGeneratedRulesMax
        artifactsTimer.setEventHandler {
            let fm = FileManager.default
            if reportsRetentionDays > 0 {
                let dir = artifactsSupportDir + "/reports"
                let cutoff = Date().addingTimeInterval(-Double(reportsRetentionDays) * 86400)
                var removed = 0
                if let names = try? fm.contentsOfDirectory(atPath: dir) {
                    for name in names {
                        let p = dir + "/" + name
                        let mtime = (try? fm.attributesOfItem(atPath: p))?[.modificationDate] as? Date
                        if let m = mtime, m < cutoff, (try? fm.removeItem(atPath: p)) != nil { removed += 1 }
                    }
                }
                if removed > 0 {
                    logger.info("Reports retention sweep: \(removed) report(s) older than \(reportsRetentionDays)d pruned")
                }
            }
            if autoGeneratedRulesMax > 0 {
                let dir = artifactsSupportDir + "/compiled_rules/auto_generated"
                if let names = try? fm.contentsOfDirectory(atPath: dir), names.count > autoGeneratedRulesMax {
                    let byAge = names.compactMap { name -> (String, Date)? in
                        let p = dir + "/" + name
                        let m = (try? fm.attributesOfItem(atPath: p))?[.modificationDate] as? Date
                        return m.map { (p, $0) }
                    }.sorted { $0.1 < $1.1 }   // oldest first
                    let dropCount = byAge.count - autoGeneratedRulesMax
                    var removed = 0
                    for (p, _) in byAge.prefix(dropCount) where (try? fm.removeItem(atPath: p)) != nil { removed += 1 }
                    if removed > 0 {
                        logger.info("Auto-generated rules cap: pruned \(removed) oldest rule file(s) (kept newest \(autoGeneratedRulesMax))")
                    }
                }
            }
        }
        artifactsTimer.resume()
        artifactsPruneTimer = artifactsTimer

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
        // v1.12.6: cadence is now user-configurable via
        // storage.eventsSizeCapIntervalMinutes. The default (60 min)
        // replaces the v1.10.0 hardcoded 6h interval that left field
        // hosts wedged with up to ~17 GB of unswept growth on busy
        // workloads. Operators on heavier workloads can drop the
        // interval (e.g. 5 min); idle hosts can lift it to save CPU.
        let configuredSweepMinutes = state.storage.eventsSizeCapIntervalMinutes
        let sweepIntervalMinutes: Int
        if configuredSweepMinutes > 0 {
            sweepIntervalMinutes = configuredSweepMinutes
        } else {
            sweepIntervalMinutes = 60
            logger.warning("eventsSizeCapIntervalMinutes=\(configuredSweepMinutes) is non-positive — falling back to default 60 min cadence.")
        }
        logger.notice("Tier-rollup timer armed: hot-tier=\(startupHotMinutes)m adaptive, cap=\(startupCapMB) MB, sweep cadence=\(sweepIntervalMinutes)m, currently \(startupSizeMB) MB (db+wal+shm). First sweep in 60 s.")

        // v1.10.0 audit fix: first sweep at .now() + 60 s instead of
        // + 900 s. If the user is booting into a sysext that
        // inherited a 1+ GB events.db from a previous run, waiting
        // 15 min before the first prune is far too long — most
        // users assume the daemon isn't working. 60 s gives the rest
        // of startup time to settle while still firing fast enough
        // for the user to see "DB shrunk from X to Y" within 1-2
        // minutes of launching the dashboard.
        //
        // v1.12.6: repeat interval pulled from
        // `state.storage.eventsSizeCapIntervalMinutes` (default 60 min,
        // configurable via daemon_config.json or user_overrides.json).
        // The hardcoded 6h interval that this replaces let a busy host's
        // events.db overrun a 300 MB cap by ~17 GB between sweeps.
        let sizeCapTimer = DispatchSource.makeTimerSource(queue: .global())
        sizeCapTimer.schedule(
            deadline: .now() + 60,
            repeating: .seconds(sweepIntervalMinutes * 60)
        )
        sizeCapTimer.setEventHandler {
            Task {
                let capMB = max(100, state.storage.eventsMaxSizeMB)
                let targetMB = Int(Double(capMB) * 0.8)
                let hotMinutes = max(15, state.storage.eventsHotTierMinutes)
                let aggregateDays = max(1, state.storage.aggregateDays)
                let alertsRetention = max(1, state.storage.alertsRetentionDays)
                // v1.12.6: serialize scheduled sweeps with the early-fire
                // watchdog (and any inbox flush-request) via the shared
                // beginSizeCapPrune guard on EventStore. Without this,
                // a watchdog burst on a wedged host could stack on top
                // of an in-flight scheduled sweep, doubling the I/O
                // load just when the disk is most pressured.
                guard await state.eventStore.beginSizeCapPrune() else {
                    logger.info("Tier-rollup scheduled sweep: another sweep already in flight, skipping.")
                    return
                }
                defer { Task { await state.eventStore.endSizeCapPrune() } }
                await runAdaptiveRollupSweep(
                    eventStore: state.eventStore,
                    dbPath: dbFilePath,
                    targetSizeMB: targetMB,
                    capSizeMB: capMB,
                    hotTierMinutes: hotMinutes,
                    aggregateDays: aggregateDays,
                    alertsRetentionDays: alertsRetention,
                    evidenceMaxSizeMB: max(10, state.storage.evidenceMaxSizeMB),
                    processFloorMinutes: max(0, state.storage.processEventsFloorMinutes)
                )
            }
        }
        sizeCapTimer.resume()

        // v1.12.6: early-fire size-cap watchdog. Defense-in-depth for the
        // configurable scheduled cadence above — if the DB blows past
        // 1.5× the cap between scheduled sweeps (sustained event-firehose
        // burst, runaway rule write-amplification, etc.), fire a sweep
        // immediately rather than letting growth continue unchecked.
        //
        // Cadence: 60 s. Cheap — three stat() calls (db + wal + shm)
        // and a numeric compare; only schedules a sweep on the cold
        // path (over-threshold).
        //
        // Reentrancy: shares the EventStore `beginSizeCapPrune` guard
        // with the scheduled sweep + inbox flush-request handler, so
        // the watchdog cannot stack on top of an in-flight sweep.
        let sizeCapWatchdogTimer = DispatchSource.makeTimerSource(queue: .global())
        sizeCapWatchdogTimer.schedule(deadline: .now() + 120, repeating: 60)
        sizeCapWatchdogTimer.setEventHandler {
            Task {
                let capMB = max(100, state.storage.eventsMaxSizeMB)
                let nowMB = measureDatabaseFootprintMB(dbPath: dbFilePath)
                // 1.5× cap is the "this should never happen on a healthy
                // host" line. Picked so normal jitter around the cap
                // (the scheduled sweep prunes to 80% of cap, then the
                // hot tier refills) doesn't trip the watchdog every
                // minute. The 0.5× margin gives the scheduled sweep
                // headroom to do its job.
                let watchdogThresholdMB = Int(Double(capMB) * 1.5)
                guard nowMB > watchdogThresholdMB else { return }
                guard await state.eventStore.beginSizeCapPrune() else {
                    // A scheduled sweep is already running. The
                    // scheduled sweep will bring us back under the cap
                    // — no need to queue another.
                    return
                }
                defer { Task { await state.eventStore.endSizeCapPrune() } }
                let targetMB = Int(Double(capMB) * 0.8)
                let hotMinutes = max(15, state.storage.eventsHotTierMinutes)
                let aggregateDays = max(1, state.storage.aggregateDays)
                let alertsRetention = max(1, state.storage.alertsRetentionDays)
                logger.warning("Tier-rollup early-fire watchdog: DB \(nowMB) MB exceeds 1.5× cap (\(watchdogThresholdMB) MB) — running sweep now.")
                await runAdaptiveRollupSweep(
                    eventStore: state.eventStore,
                    dbPath: dbFilePath,
                    targetSizeMB: targetMB,
                    capSizeMB: capMB,
                    hotTierMinutes: hotMinutes,
                    aggregateDays: aggregateDays,
                    alertsRetentionDays: alertsRetention,
                    evidenceMaxSizeMB: max(10, state.storage.evidenceMaxSizeMB),
                    processFloorMinutes: max(0, state.storage.processEventsFloorMinutes)
                )
            }
        }
        sizeCapWatchdogTimer.resume()

        // Hourly size-cap defense for alerts.db. Alert volume is orders of
        // magnitude lower than events, so this rarely fires — but if a
        // pathological rule-author commits an alert-spamming rule, the cap
        // bounds the blast radius.
        //
        // Wave 9B (v1.12.6): on a low-disk host the post-prune VACUUM
        // would skip silently. We now run incremental_vacuum first
        // (free, in-place truncate) and only fall through to full
        // VACUUM if the volume has 1.3× headroom.
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

                // Phase 2a: incremental_vacuum first — free, in-place
                // truncate of end-of-file freelist pages. No-op if the
                // DB isn't in INCREMENTAL mode.
                let postPruneMB = measureDatabaseFootprintMB(dbPath: alertsPath)
                let reclaimed = (try? await state.alertStore.incrementalVacuum(maxPages: 200_000)) ?? 0
                let postIncrementalMB = measureDatabaseFootprintMB(dbPath: alertsPath)
                if reclaimed > 0 {
                    logger.notice("Alerts size cap: incremental_vacuum reclaimed \(reclaimed) pages, \(postPruneMB) MB → \(postIncrementalMB) MB")
                }

                // Phase 2b: full VACUUM only if 1.3× headroom available.
                let freeMB = freeDiskMB(forPath: alertsPath)
                let needMB = Int(Double(postIncrementalMB) * 1.3)
                if freeMB >= needMB {
                    do {
                        try await state.alertStore.vacuum()
                        let finalMB = measureDatabaseFootprintMB(dbPath: alertsPath)
                        logger.notice("Alerts size cap: full VACUUM complete — \(postIncrementalMB) MB → \(finalMB) MB")
                    } catch {
                        logger.warning("Alerts size cap: full VACUUM failed (\(error.localizedDescription)). incremental_vacuum reclaimed \(reclaimed) pages.")
                    }
                } else if reclaimed == 0 {
                    logger.warning("Alerts size cap: full VACUUM skipped (need \(needMB) MB free, have \(freeMB) MB) AND incremental_vacuum was no-op. File size unchanged.")
                } else {
                    logger.warning("Alerts size cap: full VACUUM skipped (need \(needMB) MB free, have \(freeMB) MB). incremental_vacuum still reclaimed \(reclaimed) pages.")
                }
            }
        }
        alertsSizeCapTimer.resume()

        // Same hourly defense for campaigns.db when present.
        //
        // Wave 9B (v1.12.6): incremental_vacuum + low-disk-safe full
        // VACUUM mirror the alerts.db enforcer above. Campaigns table
        // is tiny in practice, but the consistent shape keeps the
        // structured-log output uniform across stores so operators
        // grep one predicate to see all four.
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

                    let postPruneMB = measureDatabaseFootprintMB(dbPath: cPath)
                    let reclaimed = (try? await campaignStore.incrementalVacuum(maxPages: 200_000)) ?? 0
                    let postIncrementalMB = measureDatabaseFootprintMB(dbPath: cPath)
                    if reclaimed > 0 {
                        logger.notice("Campaigns size cap: incremental_vacuum reclaimed \(reclaimed) pages, \(postPruneMB) MB → \(postIncrementalMB) MB")
                    }

                    let freeMB = freeDiskMB(forPath: cPath)
                    let needMB = Int(Double(postIncrementalMB) * 1.3)
                    if freeMB >= needMB {
                        do {
                            try await campaignStore.vacuum()
                            let finalMB = measureDatabaseFootprintMB(dbPath: cPath)
                            logger.notice("Campaigns size cap: full VACUUM complete — \(postIncrementalMB) MB → \(finalMB) MB")
                        } catch {
                            logger.warning("Campaigns size cap: full VACUUM failed (\(error.localizedDescription)). incremental_vacuum reclaimed \(reclaimed) pages.")
                        }
                    } else if reclaimed == 0 {
                        logger.warning("Campaigns size cap: full VACUUM skipped (need \(needMB) MB free, have \(freeMB) MB) AND incremental_vacuum was no-op.")
                    } else {
                        logger.warning("Campaigns size cap: full VACUUM skipped (need \(needMB) MB free, have \(freeMB) MB). incremental_vacuum still reclaimed \(reclaimed) pages.")
                    }
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
        // v1.12.0 fix: first heartbeat fires at +0.5 s, not +5 s, so the
        // dashboard's 10-second poll cadence has a fresh heartbeat to
        // read on its first tick. Pre-fix, the +5 s timer delay stacked
        // with the dashboard poll lag to produce a 15-25 s "Daemon:
        // starting…" window before "Daemon: Running ✓" appeared, even
        // though the daemon process was up and serving events in ~3 s.
        let livenessTimer = DispatchSource.makeTimerSource(queue: .global())
        livenessTimer.schedule(deadline: .now() + 0.5, repeating: 30)
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
                    // v1.12.0 RC15: keep boot_phase populated even after
                    // boot completes so the dashboard's interpretation
                    // logic ({phase == "ready"} → "Running") doesn't have
                    // to fall back to inferring from liveness alone.
                    "boot_phase": "ready",
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
        // v1.21.4 Phase-1 D2: rolling baseline for the sensor-degraded
        // meta-alert. Captured by the heartbeat closure below; lives here (not
        // on DaemonState) and is lock-guarded so overlapping ticks are safe.
        let sensorDegradation = SensorDegradationState()

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
            // Fold the merged-stream buffer drops (bufferingNewest cap →
            // oldest evicted) into the registry total. recordDrop keeps its
            // other callers; the merged-stream yield path is a separate drop
            // source that must also show up in the heartbeat. v1.21.4 (A2): the
            // merged stream is split priority/file, so BOTH detection-input drop
            // counters are folded here. The batched writer's storage-write drops
            // are NOT folded — they are a storage-layer loss, not a detection
            // gap (the event was fully processed), surfaced under their own key.
            let priorityDropped = UInt64(state.mergedStreamDropCount)
            let fileDropped = UInt64(state.fileStreamDropCount)
            let eventWriterDropped = UInt64(state.eventWriter.droppedCount)
            let droppedTotal = await state.collectorRegistry.droppedEventsTotal()
                &+ priorityDropped &+ fileDropped
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

            // v1.12.6 Wave 9D: surface event-insert error counts + rate +
            // last-kind into the rich heartbeat so the dashboard can
            // render a "storage degraded" banner without having to
            // poll storage_errors.json as a second source. Reads
            // through the StorageErrorTracker actor — strictly off the
            // hot insert path (30 s cadence).
            let insertErrorSnapshot = await StorageErrorTracker.shared.eventInsertErrorSnapshot()

            // v1.12.6 Wave 9K: previously-orphaned operator counters
            // wired into the rich heartbeat:
            //  - `payload_truncated_total`: how many events have hit
            //    EventStore's 64 KB raw_json cap since boot. Pre-9K
            //    the counter incremented on every truncation but was
            //    never surfaced — Wave 1's cap could fire 10⁴× per
            //    minute without operator visibility.
            //  - `eslogger_dropped_total`: `global_seq_num` gaps observed by
            //    the dev-fallback `EsloggerCollector` subprocess (nil in the
            //    release sysext, so 0 there). This is the *eslogger fallback's*
            //    own drop counter — NOT the native ES client's kernel drops,
            //    which are surfaced separately below as `es_kernel_dropped_total`
            //    / `es_kernel_dropped_by_type` (v1.21.4 Phase-0 D1). Pre-9K it
            //    was only logged as a warning every 30 s.
            let payloadTruncatedTotal = await state.eventStore.payloadTruncatedTotal()
            let esloggerDroppedTotal = await state.esloggerCollector?.getDroppedEventCount() ?? 0

            // v1.21.4 Phase-0 (D1 + D4): native ES kernel-drop accounting +
            // hot-path gauges, read straight off the ESCollector (synchronous,
            // lock-guarded — no actor hop). nil collector (dev eslogger/kdebug
            // fallback path, no ES entitlement) → zeros, so the keys are always
            // present. `events_dropped` is deliberately NOT folded with these —
            // the kernel ingest-drop vs userspace-eviction distinction is the
            // whole point of the D1 methodology correction. By-type maps are
            // re-keyed to readable event-type names for the heartbeat surface.
            let esGlobalDropped = state.collector?.esGlobalDropped() ?? 0
            let esKernelDroppedByType: [String: UInt64] =
                (state.collector?.esKernelDroppedByType() ?? [:])
                    .reduce(into: [:]) { $0[ESCollector.eventTypeName($1.key)] = $1.value }
            let esProcessedByType: [String: UInt64] =
                (state.collector?.esProcessedByType() ?? [:])
                    .reduce(into: [:]) { $0[ESCollector.eventTypeName($1.key)] = $1.value }
            let esHandlerP99Micros = state.collector?.esHandlerP99Micros() ?? 0
            let esStreamYieldDropped = state.collector?.esStreamYieldDropped() ?? 0
            let esCopyBackpressureDropped = state.collector?.esCopyBackpressureDropped() ?? 0
            let esClientSplitDegraded = state.collector?.esClientSplitDegraded() ?? false

            // v1.21.4 Phase-1 D2: sensor-degraded / possible-evasion meta-alert.
            // Fold the D1/D4 cumulative counters into per-tick deltas and gate on
            // the conjunction (file-event spike above rolling baseline AND
            // (kernel drops > 0 OR process/exec channel collapse)). Advisory
            // ONLY — never auto-throttles/auto-mutes (owner decision).
            let fileEventsCumulative = Self.esFileEventTypeNames
                .reduce(UInt64(0)) { $0 &+ (esProcessedByType[$1] ?? 0) }
            let processEventsCumulative = Self.esProcessEventTypeNames
                .reduce(UInt64(0)) { $0 &+ (esProcessedByType[$1] ?? 0) }
            // Best-effort FP control: is the dominant recent file writer a
            // known-benign high-I/O signer (Time Machine / Spotlight / Xcode /
            // MacCrab)? Bounded query (off the hot path, 30 s cadence). Only
            // downgrades severity — never silences the alert.
            let benignHighIOSigner = await Self.dominantFileWriterIsBenign(state: state)
            let sensorResult = sensorDegradation.step(
                fileCumulative: fileEventsCumulative,
                processCumulative: processEventsCumulative,
                kernelDropCumulative: esGlobalDropped,
                // ES-collector-stage userspace drops (Phase-3 worker queue +
                // Phase-4/collector AsyncStream). These, not kernel drops, are
                // what a real flood produces after the retain-worker + client
                // split — so D2 gates on them too (see Input.collectorDropDelta).
                collectorDropCumulative: esCopyBackpressureDropped &+ esStreamYieldDropped,
                benignHighIOSigner: benignHighIOSigner
            )
            var esSensorDegraded = false
            var esSensorDegradedSeverity = ""
            var esSensorDegradedDetail = ""
            if case let .degraded(severity, benignAttribution) = sensorResult.outcome {
                esSensorDegraded = true
                esSensorDegradedSeverity = severity.rawValue
                let attribution = benignAttribution ? " (benign attribution)" : ""
                // Plain interpolation (no String(format:) — avoids the CVarArg
                // %@/%llu pitfalls this codebase has been bitten by).
                esSensorDegradedDetail =
                    "ES sensor degraded\(attribution) — file-event rate \(Int(sensorResult.fileRate))/tick spiked above baseline \(Int(sensorResult.fileBaseline)) while \(sensorResult.kernelDropDelta) ES messages were kernel-dropped, \(sensorResult.collectorDropDelta) were dropped at the collector stage (backpressure/stream-yield), and process/exec throughput fell to \(Int(sensorResult.processRate))/tick (baseline \(Int(sensorResult.processBaseline))). Possible telemetry-drop evasion; verify what is generating the file storm."
                let alert = Alert(
                    ruleId: "maccrab.self-defense.\(ESClientMonitor.ESHealthEvent.EventType.sensorDegraded.rawValue)",
                    ruleTitle: "Sensor Degraded: possible telemetry-drop evasion",
                    severity: severity,
                    eventId: UUID().uuidString,
                    processPath: nil,
                    processName: "maccrabd",
                    description: esSensorDegradedDetail,
                    mitreTactics: "attack.defense_evasion",
                    mitreTechniques: "attack.t1562.001",
                    suppressed: false
                )
                // Route through AlertSink (not the raw alertStore.insert) so the
                // meta-alert inherits dedup/suppression — the sink dedups on the
                // shared ruleId, backstopping the evaluator's rising-edge latch.
                _ = try? await state.alertSink.submit(alert: alert)
            }

            // v1.18: engine LLM health — surfaces "enabled but unreachable /
            // misconfigured model" instead of failing silently. nil service
            // → not configured for the engine.
            let llmHealthDict: [String: Any]
            if let h = await state.llmService?.healthSnapshot() {
                llmHealthDict = [
                    "configured": true,
                    "provider": h.provider,
                    "model": h.model,
                    "last_success_unix": h.lastSuccessAtUnix ?? 0,
                    "consecutive_failures": h.consecutiveFailures,
                    "circuit_open": h.circuitOpen,
                    "healthy": h.lastSuccessAtUnix != nil && !h.circuitOpen,
                ]
            } else {
                llmHealthDict = ["configured": false]
            }

            // UX-3: live prevention-module state so the dashboard's Prevention
            // tab can show real sinkhole / network-blocker / persistence-guard
            // status instead of "unavailable". Each .stats() is a cheap actor read.
            let sinkholeStats = await state.dnsSinkhole.stats()
            let blockerStats = await state.networkBlocker.stats()
            let guardStats = await state.persistenceGuard.stats()
            let preventionDict: [String: Any] = [
                "sinkhole": ["enabled": sinkholeStats.enabled, "count": sinkholeStats.domainCount],
                "network_blocker": ["enabled": blockerStats.enabled, "count": blockerStats.blockedCount],
                "persistence_guard": ["enabled": guardStats.enabled, "count": guardStats.protectedCount],
            ]

            // v1.21.4 (F3): honest single-event rule coverage. `rules_loaded` =
            // every rule the engine loaded from disk; `rules_active` = the subset
            // that will actually EVALUATE (enabled). Under the F-04 stable rule
            // profile these diverge sharply (e.g. ~438 loaded / ~87 active), so
            // the dashboard + `maccrabctl status` can report effective coverage
            // rather than the on-disk file count that overstates protection.
            // Cheap actor reads, off the hot path (30 s cadence).
            let rulesLoaded = await state.ruleEngine.ruleCount
            // v1.21.4 (audit): surface DB tamper-evidence — an AES-GCM
            // authenticated-decrypt failure means an encrypted DB column/row was
            // modified. Previously only fault-logged; now visible so the operator
            // (and the dashboard) can see + act on it. Monotonic since boot.
            let dbTamperFailures = state.dbEncryption.authenticatedDecryptFailures
            let rulesActive = await state.ruleEngine.enabledRuleCount

            let payload: [String: Any] = [
                "written_at_unix": nowUnix,
                "llm": llmHealthDict,
                "prevention": preventionDict,
                "uptime_seconds": uptime,
                "events_processed": events,
                "alerts_emitted": alerts,
                "sysext_has_fda": sysextHasFDA,
                "fda_checked_at_unix": nowUnix,
                "event_type_counts_1h": eventTypeCounts,
                "collector_health": collectorDicts,
                "events_dropped": droppedTotal,
                // v1.21.4 Phase-0 D1: honest kernel-drop counters (per-client
                // global + per-event-type), separate from `events_dropped`
                // (userspace AsyncStream eviction). Names via ESCollector.eventTypeName.
                "es_kernel_dropped_total": esGlobalDropped,
                "es_kernel_dropped_by_type": esKernelDroppedByType,
                // v1.21.4 Phase-0 D4: leading-indicator gauges.
                "es_handler_p99_us": esHandlerP99Micros,
                "es_processed_by_type": esProcessedByType,
                "es_stream_yield_dropped_total": esStreamYieldDropped,
                "es_copy_backpressure_dropped_total": esCopyBackpressureDropped,
                "es_client_split_degraded": esClientSplitDegraded,
                // v1.21.4 Phase-1 D2: sensor-degraded advisory state for the
                // ES Health surface + the menu-bar "protection degraded" flag.
                "es_sensor_degraded": esSensorDegraded,
                "es_sensor_degraded_severity": esSensorDegradedSeverity,
                "es_sensor_degraded_detail": esSensorDegradedDetail,
                // Wave 9D additions. `last_event_insert_error_kind` is
                // an empty string when no event-insert error has been
                // recorded since boot — JSONSerialization can't carry
                // Swift `nil` so we elide-by-empty-string. Dashboard
                // consumers should treat `""` and missing key
                // identically.
                "event_insert_errors_total": insertErrorSnapshot.total,
                "event_insert_error_rate_per_min": insertErrorSnapshot.ratePerMin,
                "last_event_insert_error_kind": insertErrorSnapshot.lastKind ?? "",
                // Wave 9K additions.
                "payload_truncated_total": payloadTruncatedTotal,
                "eslogger_dropped_total": esloggerDroppedTotal,
                // v1.21.4 (F3): effective vs on-disk single-event rule coverage.
                "rules_loaded": rulesLoaded,
                "db_tamper_decrypt_failures": dbTamperFailures,
                "rules_active": rulesActive,
                // v1.21.4 (F2/A2): split merged-stream drop attribution. Both are
                // detection-input drops folded into `events_dropped`; surfaced
                // distinctly so a file-noise flood (file) is not read as a lost
                // exec (priority). `events_storage_write_dropped_total` is the
                // batched writer's storage-layer drop — NOT a detection gap.
                "merged_priority_dropped_total": priorityDropped,
                "merged_file_dropped_total": fileDropped,
                "events_storage_write_dropped_total": eventWriterDropped,
                "schema_version": 5,
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
                // v1.21.4 Phase-0 D1/D4 scalar counters (Prometheus-style; the
                // per-type maps live in heartbeat_rich.json only).
                "es_kernel_dropped_total": esGlobalDropped,
                "es_handler_p99_us": esHandlerP99Micros,
                "es_stream_yield_dropped_total": esStreamYieldDropped,
                "es_copy_backpressure_dropped_total": esCopyBackpressureDropped,
                "es_client_split_degraded": esClientSplitDegraded,
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
                let refreshIntelReqs = files.filter { $0.hasPrefix("refresh-intel-") && $0.hasSuffix(".json") }
                let reloadRulesReqs = files.filter { $0.hasPrefix("reload-rules-") && $0.hasSuffix(".json") }
                let llmConfigReqs = files.filter { $0.hasPrefix("llm-config-") && $0.hasSuffix(".json") }
                let flushRequests = files.filter { $0.hasPrefix("flush-request-") && $0.hasSuffix(".json") }
                // v1.18: ClickFix clipboard payloads recorded in USER context (the
                // menubar app can read the GUI pasteboard; the root sysext cannot)
                // and dropped here for the exec-correlation half to use.
                let recordClipboardReqs = files.filter { $0.hasPrefix("record-clipboard-") && $0.hasSuffix(".json") }
                // v1.18: per-built-in-rule enable/disable + severity override.
                let builtinRuleReqs = files.filter { $0.hasPrefix("builtin-rule-setting-") && $0.hasSuffix(".json") }
                // v1.18 agent control-plane (MCP skill): set a whitelisted
                // daemon_config key, install a compiled user rule, remove a
                // user rule. Same uid/symlink auth gate + audit as every verb.
                let setDaemonConfigReqs = files.filter { $0.hasPrefix("set-daemon-config-") && $0.hasSuffix(".json") }
                let installRuleReqs = files.filter { $0.hasPrefix("install-rule-") && $0.hasSuffix(".json") }
                let removeRuleReqs = files.filter { $0.hasPrefix("remove-rule-") && $0.hasSuffix(".json") }
                // v1.18: the human's agent-control grants. The root engine owns
                // mcp_capabilities.json so an agent (console user) can't grant
                // itself power; the dashboard routes the human's choice here.
                let agentCapReqs = files.filter { $0.hasPrefix("set-agent-capabilities-") && $0.hasSuffix(".json") }

                await handleSuppressAlertRequests(suppressAlertReqs, inboxDir: inboxDir, state: state)
                await handleUnsuppressAlertRequests(unsuppressAlertReqs, inboxDir: inboxDir, state: state)
                await handleDeleteAlertRequests(deleteAlertReqs, inboxDir: inboxDir, state: state)
                await handleSuppressCampaignRequests(suppressCampaignReqs, inboxDir: inboxDir, state: state)
                await handleRefreshIntelRequests(refreshIntelReqs, inboxDir: inboxDir, state: state)
                await handleReloadRulesRequests(reloadRulesReqs, inboxDir: inboxDir, state: state)
                await handleLLMConfigRequests(llmConfigReqs, inboxDir: inboxDir, state: state)
                await handleRecordClipboardRequests(recordClipboardReqs, inboxDir: inboxDir, state: state)
                await handleBuiltinRuleSettingRequests(builtinRuleReqs, inboxDir: inboxDir, state: state)
                await handleSetDaemonConfigRequests(setDaemonConfigReqs, inboxDir: inboxDir, state: state)
                await handleInstallRuleRequests(installRuleReqs, inboxDir: inboxDir, state: state)
                await handleRemoveRuleRequests(removeRuleReqs, inboxDir: inboxDir, state: state)
                await handleSetAgentCapabilitiesRequests(agentCapReqs, inboxDir: inboxDir, state: state)
                await handleFlushRequests(flushRequests, inboxDir: inboxDir, state: state)
            }
        }
        inboxPoller.resume()

        // v1.21.4 Phase-2 (D3): coverage-canary watchdog. On a jittered ~5-15 min
        // interval, spawn a benign probe exec and verify it reaches both the ES
        // callback and events.db (see runCoverageCanary). Jitter (a fresh random
        // deadline re-armed on each fire, one-shot repeating: .never) so the
        // probe cadence isn't predictable and doesn't phase-lock with other
        // sweeps. First fire is already 5-15 min out, clear of the 60 s warm-up.
        let coverageCanaryTimer = DispatchSource.makeTimerSource(queue: .global())
        // One-shot (repeating: .never), re-armed to a fresh random deadline on
        // each fire — this is the jitter. `canaryJitterSeconds()` returns 5-15 min.
        coverageCanaryTimer.schedule(deadline: .now() + canaryJitterSeconds(), repeating: .never)
        coverageCanaryTimer.setEventHandler {
            // Re-arm for the next jittered fire immediately; the probe itself
            // runs off-timer in a Task (spawn NEVER happens in the ES callback).
            coverageCanaryTimer.schedule(deadline: .now() + canaryJitterSeconds(), repeating: .never)
            Task { await runCoverageCanary(state: state) }
        }
        coverageCanaryTimer.resume()

        return Handles(
            forensicTimer: forensicTimer,
            hourlyTimer: hourlyTimer,
            statsTimer: statsTimer,
            alertsPruneTimer: alertsPruneTimer,
            alertsSizeCapTimer: alertsSizeCapTimer,
            campaignsPruneTimer: campaignsPruneTimer,
            campaignsSizeCapTimer: campaignsSizeCapTimer,
            sizeCapTimer: sizeCapTimer,
            sizeCapWatchdogTimer: sizeCapWatchdogTimer,
            maintenanceTimer: maintenanceTimer,
            feedbackTimer: feedbackTimer,
            heartbeatTimer: heartbeatTimer,
            livenessTimer: livenessTimer,
            tracegraphPruneTimer: tracegraphPruneTimer,
            tracesPruneTimer: tracesPruneTimer,
            artifactsPruneTimer: artifactsPruneTimer,
            inboxPoller: inboxPoller,
            coverageCanaryTimer: coverageCanaryTimer
        )
    }

    // MARK: - v1.21.4 Phase-1 D2 helpers

    /// ES event-type names (as re-keyed in the heartbeat's `esProcessedByType`)
    /// that make up the file write-family — the D2 flood numerator.
    static let esFileEventTypeNames: [String] = [
        "NOTIFY_CREATE", "NOTIFY_WRITE", "NOTIFY_CLOSE", "NOTIFY_RENAME", "NOTIFY_UNLINK",
    ]

    /// Process/exec event-type names — the channel a file flood can starve.
    static let esProcessEventTypeNames: [String] = [
        "NOTIFY_EXEC", "NOTIFY_FORK", "NOTIFY_EXIT",
    ]

    /// Known-benign high-I/O signing identifiers. When the dominant recent
    /// file writer matches one of these, a sensor-degraded episode is
    /// downgraded HIGH → LOW (still emitted). Matched as a substring of the
    /// process's `signingId` so bundle-id variants (e.g. `com.apple.mdworker`,
    /// `com.apple.mdworker_shared`) are covered.
    static let benignHighIOSignerIDs: [String] = [
        "com.apple.backupd",        // Time Machine
        "com.apple.mdworker",       // Spotlight indexing
        "com.apple.mds",            // Spotlight metadata server
        "com.apple.Spotlight",
        "com.apple.dt.Xcode",       // Xcode builds
        "com.apple.CloudDocs",      // iCloud Drive sync
        "com.apple.bird",           // CloudKit / iCloud daemon
        "com.maccrab",              // MacCrab's own copies (belt-and-braces vs Mitigation A)
    ]

    /// Best-effort: is the dominant writer across the most recent file events a
    /// known-benign high-I/O signer? Bounded (≤200 rows), off the hot path.
    /// Returns false on any query error or when no signer dominates — the
    /// safe default is "not benign" (keeps the alert at HIGH).
    static func dominantFileWriterIsBenign(state: DaemonState) async -> Bool {
        let recent = try? await state.eventStore.events(
            before: nil, category: .file, pageSize: 200
        )
        guard let items = recent?.items, !items.isEmpty else { return false }
        var counts: [String: Int] = [:]
        for event in items {
            let signer = event.process.codeSignature?.signingId ?? "(unsigned)"
            counts[signer, default: 0] += 1
        }
        guard let (topSigner, topCount) = counts.max(by: { $0.value < $1.value }) else { return false }
        // Require a clear majority so a benign signer that merely appears
        // alongside the real flood-writer doesn't downgrade the alert.
        guard Double(topCount) >= Double(items.count) * 0.5 else { return false }
        return benignHighIOSignerIDs.contains { topSigner.contains($0) }
    }

    // MARK: - v1.21.4 Phase-2 (D3) coverage-canary watchdog

    /// Jittered probe interval bounds (seconds): 5-15 min, like the sweep timers.
    static let canaryMinIntervalSeconds: Double = 300
    static let canaryMaxIntervalSeconds: Double = 900

    /// A fresh random interval in [min, max]. The unpredictable cadence keeps the
    /// probe from phase-locking with other sweeps and from being trivially timed
    /// around by an adversary. First fire is already ≥5 min out, clear of warm-up.
    static func canaryJitterSeconds() -> Double {
        Double.random(in: canaryMinIntervalSeconds...canaryMaxIntervalSeconds)
    }

    /// Seconds to wait after the probe spawn before checking coverage — long
    /// enough for the ES callback to latch and the async DB insert to flush.
    static let canarySettleSeconds: UInt64 = 20
    /// Extra DB re-checks (spaced by canaryDBRecheckSeconds) before concluding a
    /// store/eviction gap — tolerates insert-batch latency without crying wolf.
    static let canaryDBRecheckAttempts = 3
    static let canaryDBRecheckSeconds: UInt64 = 5

    /// One coverage-canary cycle: spawn a benign probe exec, then verify it
    /// reached BOTH the ES callback and events.db, and on a gap emit a
    /// stage-naming health alert via AlertSink (advisory — nothing auto-acts).
    ///
    /// Safety invariants (see CoverageCanary): the probe is `/usr/bin/true` +
    /// a neutral marker, so it trips no rule and no self-defense check; the
    /// exec is suppressed in NoiseFilter as belt-and-braces; and the spawn
    /// happens HERE (the timer task), never in the ES callback.
    static func runCoverageCanary(state: DaemonState) async {
        // No ES client (dev non-root fallback) ⇒ nothing to probe.
        guard let collector = state.collector else { return }

        let nonce = CoverageCanary.makeNonce()
        collector.armCanaryNonce(nonce)
        defer { collector.disarmCanaryNonce(nonce) }

        let spawnedAt = Date()
        guard spawnCanaryProbe(nonce: nonce) else {
            // A failed spawn is a local error, not a coverage gap — don't alert.
            print("[D3] coverage-canary spawn failed")
            return
        }

        // Point 1: settle, then read the callback sighting.
        try? await Task.sleep(nanoseconds: canarySettleSeconds * 1_000_000_000)
        let seenAtCallback = collector.canarySeenAtCallback(nonce)

        // Point 2: look for the exec in events.db (command line carries the
        // nonce). Re-check a few times so a slow insert batch isn't misread as
        // an eviction gap. Window starts slightly before the spawn.
        let since = spawnedAt.addingTimeInterval(-30)
        var foundInDB = await canaryPresentInDB(state: state, nonce: nonce, since: since)
        var attempt = 0
        while !foundInDB && attempt < canaryDBRecheckAttempts {
            try? await Task.sleep(nanoseconds: canaryDBRecheckSeconds * 1_000_000_000)
            foundInDB = await canaryPresentInDB(state: state, nonce: nonce, since: since)
            attempt += 1
        }

        let verdict = CoverageCanaryEvaluator.verdict(
            seenAtCallback: seenAtCallback, foundInDB: foundInDB
        )
        guard verdict != .healthy, let stage = verdict.stageLabel else { return }

        // A kernel/ingest gap is active telemetry loss (possible evasion); an
        // eviction gap is retention pressure — surface both, weighted accordingly.
        let severity: Severity = (verdict == .kernelGap) ? .high : .medium
        let description =
            "Coverage canary lost at the \(stage) stage: a self-generated probe exec "
            + (verdict == .kernelGap
               ? "never reached the ES callback — the kernel/ingest path dropped it (per-client-queue backpressure; the same blind-spot a file-write flood exploits). "
               : "was seen at the ES callback but is absent from events.db — the store/eviction path lost it (retention sweep or insert gap). ")
            + "MacCrab's own telemetry coverage is degraded; verify what is generating load or storage pressure."

        let alert = Alert(
            // Synthetic self-defense ruleId (same convention as the D2
            // sensor-degraded meta-alert). NOT a Rules/ entry.
            ruleId: "maccrab.self-defense.coverage_gap",
            ruleTitle: "Coverage Gap: telemetry canary lost at \(stage)",
            severity: severity,
            eventId: UUID().uuidString,
            processPath: CoverageCanary.spawnBinaryPath,
            processName: "maccrabd",
            description: description,
            mitreTactics: "attack.defense_evasion",
            mitreTechniques: "attack.t1562.001",
            suppressed: false
        )
        // Route via AlertSink so it inherits dedup/suppression (backstops the
        // per-cycle cadence if a gap persists across several probes).
        _ = try? await state.alertSink.submit(alert: alert)
    }

    /// Store-side half of the two-point check: is an event carrying `nonce`
    /// present in events.db? Uses the FTS/command-line search the hunt tool
    /// uses. Any query error ⇒ treated as "not found" (the recheck loop covers
    /// transient errors; a persistent one degrades to an eviction-gap report).
    static func canaryPresentInDB(state: DaemonState, nonce: String, since: Date) async -> Bool {
        let hits = try? await state.eventStore.search(text: nonce, since: since, limit: 1)
        return (hits?.isEmpty == false)
    }

    /// posix_spawn the benign probe as `/usr/bin/env /usr/bin/true <nonce>`,
    /// detached, with a minimal environment. The `env` layer is the muteSelf
    /// work-around (see CoverageCanary): it makes the OBSERVED `/usr/bin/true`
    /// exec be initiated by `env` (unmuted) rather than the daemon (muted).
    /// Reaps the child so it can't linger as a zombie. Returns whether the
    /// spawn itself succeeded.
    static func spawnCanaryProbe(nonce: String) -> Bool {
        let spawnPath = CoverageCanary.intermediaryBinaryPath   // /usr/bin/env
        guard let cEnv = strdup(spawnPath),
              let cTrue = strdup(CoverageCanary.spawnBinaryPath),   // /usr/bin/true
              let cNonce = strdup(nonce) else { return false }
        defer { free(cEnv); free(cTrue); free(cNonce) }
        var pid: pid_t = 0
        // env <true> <nonce> → env execs /usr/bin/true with argv[1] = nonce.
        let argv: [UnsafeMutablePointer<CChar>?] = [cEnv, cTrue, cNonce, nil]
        // Empty environment — the probe needs nothing and this avoids leaking
        // the daemon's env (API keys etc.) into a child exec.
        let envp: [UnsafeMutablePointer<CChar>?] = [nil]
        let rc = argv.withUnsafeBufferPointer { aBuf in
            envp.withUnsafeBufferPointer { eBuf in
                posix_spawn(&pid, spawnPath, nil, nil,
                            UnsafeMutablePointer(mutating: aBuf.baseAddress!),
                            UnsafeMutablePointer(mutating: eBuf.baseAddress!))
            }
        }
        guard rc == 0 else { return false }
        // Best-effort reap — the probe exits immediately. ECHILD (SIGCHLD
        // auto-reaped elsewhere) is fine; we only need to avoid a zombie.
        var status: Int32 = 0
        _ = waitpid(pid, &status, 0)
        return true
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
        // Authorization gate (parity with every other inbox verb). The inbox dir
        // is mode 1777 — any local user can drop a file — and a flush DELETES the
        // oldest events (anti-forensics value to an attacker erasing early-
        // intrusion telemetry). Flush carries no id and is a single global sweep,
        // so we run it iff at least one request is from an authorized uid (root or
        // the GUI console user); symlink/hardlink-forged files resolve to uid -1
        // and are rejected. Every request is audit-logged; all files are removed.
        var anyAuthorized = false
        for name in names {
            let path = inboxDir + "/" + name
            let uid = requestOwnerUID(at: path)
            if isAuthorizedInboxRequest(uid: uid) {
                anyAuthorized = true
                auditLogInbox(state: state, prefix: "flush", id: name, uid: uid, result: "ok")
            } else {
                print("[inbox] flush \(name) REJECTED uid=\(uid) (not console-user or root)")
                auditLogInbox(state: state, prefix: "flush", id: name, uid: uid, result: "rejected_uid")
            }
            try? fm.removeItem(atPath: path)
        }
        guard anyAuthorized else {
            print("[inbox] flush: no authorized request — sweep skipped")
            return
        }
        print("[inbox] flush: running enforceDatabaseSizeCapNow")
        let beforeBytes = StorageFlushStatus.fileSize(at: state.supportDir + "/events.db")
        let started = Date()
        let didRun = await enforceDatabaseSizeCapNow(state: state)
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

    /// v1.18: ClickFix clipboard payloads from the user-context app. The root
    /// sysext cannot read the GUI pasteboard (no Aqua session), so the menubar
    /// app records delivery-shaped clipboard text (curl|bash, etc.) and drops it
    /// here; we feed it into the shared ClickFixDetector whose exec-correlation
    /// half runs in the event loop. Same uid/symlink auth gate as every verb.
    private static func handleRecordClipboardRequests(
        _ names: [String], inboxDir: String, state: DaemonState
    ) async {
        guard !names.isEmpty else { return }
        let fm = FileManager.default
        for name in names {
            let path = inboxDir + "/" + name
            defer { try? fm.removeItem(atPath: path) }
            let uid = requestOwnerUID(at: path)   // lstat — rejects symlink/hardlink forgery
            guard isAuthorizedInboxRequest(uid: uid) else {
                print("[inbox] record-clipboard REJECTED uid=\(uid) (not console-user or root)")
                auditLogInbox(state: state, prefix: "record-clipboard", id: "-", uid: uid, result: "rejected_uid")
                continue
            }
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let payload = json["payload"] as? String, !payload.isEmpty else {
                print("[inbox] record-clipboard \(name): malformed payload")
                continue
            }
            // Cap so a giant clipboard can't bloat the detector buffer.
            let capped = String(payload.prefix(8192))
            if let clickFix = state.clickFix {
                let recorded = await clickFix.recordClipboard(capped, at: Date())
                auditLogInbox(state: state, prefix: "record-clipboard", id: "-", uid: uid,
                              result: recorded ? "recorded" : "filtered_by_shape")
            } else {
                auditLogInbox(state: state, prefix: "record-clipboard", id: "-", uid: uid, result: "clickfix_disabled")
            }
        }
    }

    /// v1.18: per-built-in-rule operator overrides (enable/disable + severity)
    /// written by the user-context app. The root daemon owns the support dir, so
    /// it (not the unprivileged app) writes `builtin_rules_settings.json`, which
    /// AlertSink reads at the submit chokepoint. Same auth gate as every verb.
    private static func handleBuiltinRuleSettingRequests(
        _ names: [String], inboxDir: String, state: DaemonState
    ) async {
        guard !names.isEmpty else { return }
        let fm = FileManager.default
        for name in names {
            let path = inboxDir + "/" + name
            defer { try? fm.removeItem(atPath: path) }
            let uid = requestOwnerUID(at: path)
            guard isAuthorizedInboxRequest(uid: uid) else {
                print("[inbox] builtin-rule-setting REJECTED uid=\(uid)")
                auditLogInbox(state: state, prefix: "builtin-rule-setting", id: "-", uid: uid, result: "rejected_uid")
                continue
            }
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let ruleId = json["ruleId"] as? String, ruleId.hasPrefix("maccrab.") else {
                print("[inbox] builtin-rule-setting \(name): malformed")
                continue
            }
            var settings = BuiltinRuleSettings.load(fromDir: state.supportDir)
            var entry = settings.rules[ruleId] ?? BuiltinRuleSetting()
            if let enabled = json["enabled"] as? Bool { entry.enabled = enabled }
            if json.keys.contains("severityOverride") {
                if let raw = json["severityOverride"] as? String, let sev = Severity(rawValue: raw) {
                    entry.severityOverride = sev
                } else {
                    entry.severityOverride = nil   // explicit null = clear to default
                }
            }
            settings.rules[ruleId] = entry
            do {
                try settings.save(toDir: state.supportDir)
                auditLogInbox(state: state, prefix: "builtin-rule-setting", id: sanitizeAuditField(ruleId), uid: uid,
                              result: "enabled=\(entry.enabled) sev=\(entry.severityOverride?.rawValue ?? "default")")
            } catch {
                print("[inbox] builtin-rule-setting \(ruleId) save failed: \(error)")
            }
        }
    }

    // v1.18 agent control-plane: whitelisted daemon_config keys settable from
    // the MCP skill. Re-stated here (NOT trusting the MCP) so the daemon is the
    // authority. Safe tunables vs defense-affecting kill-switches — the MCP
    // gates the latter behind the higher 'response' tier; the daemon enforces
    // type + membership regardless.
    private static let agentSettableConfigKeys: [String: String] = [
        "behavior_alert_threshold": "double", "behavior_critical_threshold": "double",
        "statistical_z_threshold": "double", "statistical_min_samples": "int",
        "usb_poll_interval": "double", "clipboard_poll_interval": "double",
        "browser_extension_poll_interval": "double", "rootkit_poll_interval": "double",
        "event_tap_poll_interval": "double", "system_policy_poll_interval": "double",
        "prompt_injection_confidence": "int", "intent_posterior_threshold": "double",
        "subscribe_file_open_events": "bool", "subscribe_introspection_events": "bool",
        "ultrasonic_enabled": "bool",
    ]

    /// v1.19.1 (audit): detection-preserving safe ranges for agent-settable
    /// NUMERIC config. Without clamping, an agent (or any console user via the
    /// inbox) could set a threshold to a value that effectively DISABLES a tier
    /// — the live audit caught `statistical_z_threshold` pushed to 99 (anomaly
    /// tier off) with only an audit line, no alert. Requested values outside the
    /// range are CLAMPED to the nearest bound AND raise a self-protection alert.
    private static let agentConfigSafeRange: [String: (min: Double, max: Double)] = [
        "behavior_alert_threshold":        (1, 50),
        "behavior_critical_threshold":     (1, 100),
        "statistical_z_threshold":         (1.0, 6.0),
        "statistical_min_samples":         (10, 1000),
        "prompt_injection_confidence":     (1, 95),
        "intent_posterior_threshold":      (0.5, 0.99),
        "usb_poll_interval":               (1, 300),
        "clipboard_poll_interval":         (1, 60),
        "browser_extension_poll_interval": (5, 600),
        "rootkit_poll_interval":           (10, 600),
        "event_tap_poll_interval":         (1, 300),
        "system_policy_poll_interval":     (10, 1800),
    ]

    private static func handleSetDaemonConfigRequests(
        _ names: [String], inboxDir: String, state: DaemonState
    ) async {
        guard !names.isEmpty else { return }
        let fm = FileManager.default
        for name in names {
            let path = inboxDir + "/" + name
            defer { try? fm.removeItem(atPath: path) }
            let uid = requestOwnerUID(at: path)
            guard isAuthorizedInboxRequest(uid: uid) else {
                auditLogInbox(state: state, prefix: "set-daemon-config", id: "-", uid: uid, result: "rejected_uid")
                continue
            }
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let key = json["key"] as? String,
                  let kind = agentSettableConfigKeys[key] else {
                auditLogInbox(state: state, prefix: "set-daemon-config", id: "-", uid: uid, result: "rejected_key")
                continue
            }
            // Coerce + validate the value to the declared kind; reject mismatches.
            var value: Any
            switch kind {
            case "bool":
                guard let b = json["value"] as? Bool else {
                    auditLogInbox(state: state, prefix: "set-daemon-config", id: sanitizeAuditField(key), uid: uid, result: "rejected_type")
                    continue
                }
                value = b
            case "int":
                guard let i = json["value"] as? Int else {
                    auditLogInbox(state: state, prefix: "set-daemon-config", id: sanitizeAuditField(key), uid: uid, result: "rejected_type")
                    continue
                }
                value = i
            default:
                if let d = json["value"] as? Double { value = d }
                else if let i = json["value"] as? Int { value = Double(i) }
                else {
                    auditLogInbox(state: state, prefix: "set-daemon-config", id: sanitizeAuditField(key), uid: uid, result: "rejected_type")
                    continue
                }
            }
            // v1.19.1 (audit): clamp numeric thresholds to a detection-preserving
            // range so an agent / console user can't disable a tier (e.g. the
            // live-caught statistical_z_threshold=99). A clamp means the request
            // tried to weaken detection past the safe bound — make it LOUD.
            if let range = agentConfigSafeRange[key] {
                let requested = (value as? Double) ?? Double(value as? Int ?? 0)
                let clamped = Swift.min(Swift.max(requested, range.min), range.max)
                if clamped != requested {
                    value = (kind == "int") ? (Int(clamped.rounded()) as Any) : (clamped as Any)
                    auditLogInbox(state: state, prefix: "set-daemon-config",
                                  id: sanitizeAuditField(key), uid: uid,
                                  result: "clamped \(requested)->\(clamped)")
                    await emitSelfProtectionAlert(
                        state: state, action: "Detection threshold clamped",
                        detail: "Config '\(key)' was requested as \(requested), outside the detection-preserving range [\(range.min), \(range.max)] — clamped to \(clamped). A value past this bound weakens or disables a detection tier.")
                }
            }
            // Merge into daemon_config.json (root-owned). Effect on next config
            // reload / restart — these keys are read at startup.
            let cfgPath = state.supportDir + "/daemon_config.json"
            var cfg: [String: Any] = (try? Data(contentsOf: URL(fileURLWithPath: cfgPath)))
                .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] } ?? [:]
            cfg[key] = value
            do {
                let out = try JSONSerialization.data(withJSONObject: cfg, options: [.prettyPrinted, .sortedKeys])
                let tmp = cfgPath + ".tmp"
                try out.write(to: URL(fileURLWithPath: tmp))
                _ = try? fm.removeItem(atPath: cfgPath)
                try fm.moveItem(atPath: tmp, toPath: cfgPath)
                try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: cfgPath)
                auditLogInbox(state: state, prefix: "set-daemon-config",
                              id: sanitizeAuditField(key), uid: uid, result: "set=\(value)")
                // Self-protection: disabling an ES event subscription blinds a
                // class of kernel telemetry — rare-legitimate, high-impact.
                if (key == "subscribe_file_open_events" || key == "subscribe_introspection_events"),
                   (value as? Bool) == false {
                    await emitSelfProtectionAlert(
                        state: state, action: "Endpoint Security subscription disabled",
                        detail: "ES event subscription '\(key)' was set to false (disables a class of kernel telemetry on the next daemon restart)")
                }
            } catch {
                print("[inbox] set-daemon-config \(key) write failed: \(error)")
            }
        }
    }

    /// v1.18 security hardening (self-protection): record an alert when an
    /// inbox request makes a high-impact change to MacCrab's OWN detection
    /// posture — granting an MCP capability tier, disabling an ES event
    /// subscription, or enabling a remote LLM endpoint. Post-compromise,
    /// malware running as the console user can drive these (uid-gated) verbs;
    /// we cannot PREVENT that without user-presence, but we can make it LOUD.
    /// Inserted directly into the alert store (recorded, dashboard/CLI/MCP-
    /// visible, bypasses the noise filter); NOT OS-notified, to avoid spamming
    /// the operator on their own legitimate changes. Observe-only — the verb
    /// itself already executed; this never blocks it.
    private static func emitSelfProtectionAlert(state: DaemonState, action: String, detail: String) async {
        let alert = Alert(
            ruleId: "maccrab.self-defense.config_modified",
            ruleTitle: "MacCrab Self-Protection: \(action)",
            severity: .high,
            eventId: UUID().uuidString,
            processPath: nil,
            processName: "maccrabd",
            description: "\(detail) via the privileged inbox. If you did not just make this change in the MacCrab dashboard, a process running as your user may be weakening MacCrab — investigate.",
            mitreTactics: "attack.defense_evasion",
            mitreTechniques: "attack.t1562.001",
            suppressed: false
        )
        do { try await state.alertStore.insert(alert: alert) }
        catch { print("[self-protection] failed to record '\(action)' alert: \(error)") }
    }

    /// v1.18: write the human's agent-control capability grants to a ROOT-owned
    /// mcp_capabilities.json. This is the ONLY writer of that file — the MCP
    /// server trusts it solely because it's root-owned, so an agent (console
    /// user) can never grant itself a tier. The dashboard (uid 501) drops the
    /// request here; only the console user / root may (the standard inbox gate).
    private static func handleSetAgentCapabilitiesRequests(
        _ names: [String], inboxDir: String, state: DaemonState
    ) async {
        guard !names.isEmpty else { return }
        let fm = FileManager.default
        for name in names {
            let path = inboxDir + "/" + name
            defer { try? fm.removeItem(atPath: path) }
            let uid = requestOwnerUID(at: path)
            guard isAuthorizedInboxRequest(uid: uid) else {
                auditLogInbox(state: state, prefix: "set-agent-capabilities", id: "-", uid: uid, result: "rejected_uid")
                continue
            }
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                auditLogInbox(state: state, prefix: "set-agent-capabilities", id: "-", uid: uid, result: "rejected_malformed")
                continue
            }
            let grants: [String: Bool] = [
                "config": (json["config"] as? Bool) ?? false,
                "authoring": (json["authoring"] as? Bool) ?? false,
                "response": (json["response"] as? Bool) ?? false,
            ]
            let capPath = state.supportDir + "/mcp_capabilities.json"
            // Read the prior grants so a tier going false->true (a GRANT) can
            // raise a self-protection alert below.
            let prevGrants: [String: Bool] = (try? Data(contentsOf: URL(fileURLWithPath: capPath)))
                .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Bool] } ?? [:]
            do {
                let out = try JSONSerialization.data(withJSONObject: grants, options: [.prettyPrinted, .sortedKeys])
                let tmp = capPath + ".tmp"
                try out.write(to: URL(fileURLWithPath: tmp))
                _ = try? fm.removeItem(atPath: capPath)
                try fm.moveItem(atPath: tmp, toPath: capPath)
                // 0644 root-owned (the daemon runs as root): world-readable so the
                // uid-501 MCP can READ it, but only root can write it.
                try? fm.setAttributes([.posixPermissions: 0o644], ofItemAtPath: capPath)
                auditLogInbox(state: state, prefix: "set-agent-capabilities", id: "-", uid: uid,
                              result: "config=\(grants["config"]!) authoring=\(grants["authoring"]!) response=\(grants["response"]!)")
                // Self-protection: a tier going false->true is a capability GRANT
                // (the sharpest edge in the security review — this verb is gated
                // only by uid). Fire only on a NEW grant, so re-writes/revokes
                // stay quiet.
                let newlyGranted = grants.filter { $0.value && !(prevGrants[$0.key] ?? false) }
                    .keys.sorted()
                if !newlyGranted.isEmpty {
                    await emitSelfProtectionAlert(
                        state: state, action: "MCP agent capability granted",
                        detail: "MCP agent capability tier(s) [\(newlyGranted.joined(separator: ", "))] were GRANTED")
                }
            } catch {
                print("[inbox] set-agent-capabilities write failed: \(error)")
            }
        }
    }

    /// Sanitize an agent-supplied rule id to a safe user_rules basename:
    /// lowercased, only [a-z0-9-_], no path traversal. Returns nil if empty.
    private static func safeRuleBasename(_ raw: String) -> String? {
        let allowed = Set("abcdefghijklmnopqrstuvwxyz0123456789-_")
        let s = String(raw.lowercased().filter { allowed.contains($0) })
        guard !s.isEmpty, s.count <= 128 else { return nil }
        return s
    }

    private static func handleInstallRuleRequests(
        _ names: [String], inboxDir: String, state: DaemonState
    ) async {
        guard !names.isEmpty else { return }
        let fm = FileManager.default
        for name in names {
            let path = inboxDir + "/" + name
            defer { try? fm.removeItem(atPath: path) }
            let uid = requestOwnerUID(at: path)
            guard isAuthorizedInboxRequest(uid: uid) else {
                auditLogInbox(state: state, prefix: "install-rule", id: "-", uid: uid, result: "rejected_uid")
                continue
            }
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let rawId = json["ruleId"] as? String, let ruleId = safeRuleBasename(rawId),
                  let jsonText = json["json"] as? String,
                  jsonText.utf8.count <= 256 * 1024,
                  ((json["yaml"] as? String) ?? "").utf8.count <= 64 * 1024 else {
                auditLogInbox(state: state, prefix: "install-rule", id: "-", uid: uid, result: "rejected_malformed")
                continue
            }
            // yaml optional: rule INSTALLS carry source yaml (write both .yml +
            // .json), but a built-in DISABLE/severity OVERRIDE is json-only.
            let yaml = (json["yaml"] as? String) ?? ""
            let userRulesDir = state.supportDir + "/user_rules"
            do {
                try fm.createDirectory(atPath: userRulesDir, withIntermediateDirectories: true)
                // v1.18: enforce secure perms (0755, daemon-owned). The engine's
                // secure-dir gate (DaemonSetup.isSecureDirectory) REFUSES a
                // group/world-writable rules dir, so a legacy app-created
                // root:admin 0775 dir meant "rule installed but never loads".
                // Routing installs through this root handler + clamping the dir to
                // 0755 makes the gate accept it — and migrates any legacy 0775 dir
                // in place on the next install.
                try? fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: userRulesDir)
                if !yaml.isEmpty {
                    try yaml.data(using: .utf8)?.write(to: URL(fileURLWithPath: userRulesDir + "/\(ruleId).yml"))
                }
                try jsonText.data(using: .utf8)?.write(to: URL(fileURLWithPath: userRulesDir + "/\(ruleId).json"))
                let tick = "\(Date().timeIntervalSince1970)\n"
                try? tick.data(using: .utf8)?.write(to: URL(fileURLWithPath: userRulesDir + "/.reload_tick"))
                auditLogInbox(state: state, prefix: "install-rule", id: sanitizeAuditField(ruleId), uid: uid, result: "installed")
            } catch {
                print("[inbox] install-rule \(ruleId) failed: \(error)")
                auditLogInbox(state: state, prefix: "install-rule", id: sanitizeAuditField(ruleId), uid: uid, result: "error")
            }
        }
    }

    private static func handleRemoveRuleRequests(
        _ names: [String], inboxDir: String, state: DaemonState
    ) async {
        guard !names.isEmpty else { return }
        let fm = FileManager.default
        for name in names {
            let path = inboxDir + "/" + name
            defer { try? fm.removeItem(atPath: path) }
            let uid = requestOwnerUID(at: path)
            guard isAuthorizedInboxRequest(uid: uid) else {
                auditLogInbox(state: state, prefix: "remove-rule", id: "-", uid: uid, result: "rejected_uid")
                continue
            }
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let rawId = json["ruleId"] as? String, let ruleId = safeRuleBasename(rawId) else {
                auditLogInbox(state: state, prefix: "remove-rule", id: "-", uid: uid, result: "rejected_malformed")
                continue
            }
            let userRulesDir = state.supportDir + "/user_rules"
            _ = try? fm.removeItem(atPath: userRulesDir + "/\(ruleId).yml")
            _ = try? fm.removeItem(atPath: userRulesDir + "/\(ruleId).json")
            let tick = "\(Date().timeIntervalSince1970)\n"
            try? tick.data(using: .utf8)?.write(to: URL(fileURLWithPath: userRulesDir + "/.reload_tick"))
            auditLogInbox(state: state, prefix: "remove-rule", id: sanitizeAuditField(ruleId), uid: uid, result: "removed")
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

    /// v1.17: threat-intel refresh over the inbox channel. The
    /// dashboard "Refresh now" button and `maccrabctl intel refresh`
    /// used to `pkill -USR1` the sysext, which fails EPERM (user →
    /// uid-0 sysext) and never fired refreshNow(). Now they drop a
    /// `refresh-intel-<token>.json` here. Unlike the alert verbs this
    /// request is parameterless (no `id`) — we authorize by file owner
    /// uid and ignore the body. Multiple files in one tick COALESCE:
    /// refreshNow() runs once regardless of how many landed, so rapid
    /// re-clicking can't stack redundant URLhaus/MalwareBazaar/Feodo
    /// fetches. Every file is removed each tick so it can't re-trigger.
    private static func handleRefreshIntelRequests(
        _ names: [String], inboxDir: String, state: DaemonState
    ) async {
        guard !names.isEmpty else { return }
        let fm = FileManager.default
        var anyAuthorized = false
        for name in names {
            let path = inboxDir + "/" + name
            defer { try? fm.removeItem(atPath: path) }
            let uid = requestOwnerUID(at: path)
            guard isAuthorizedInboxRequest(uid: uid) else {
                print("[inbox] refresh-intel \(name) REJECTED uid=\(uid) (not console-user or root)")
                auditLogInbox(state: state, prefix: "refresh-intel", id: "-", uid: uid, result: "rejected_uid")
                continue
            }
            anyAuthorized = true
            auditLogInbox(state: state, prefix: "refresh-intel", id: "-", uid: uid, result: "ok")
        }
        guard anyAuthorized else { return }
        print("[inbox] refresh-intel: \(names.count) request(s) — running ThreatIntelFeed.refreshNow (coalesced)")
        await state.threatIntel.refreshNow()
        print("[inbox] refresh-intel: refreshNow complete")
    }

    /// Handle `reload-rules-<token>.json` requests. The app can't pkill
    /// the root sysext cross-uid (and a sandboxed app can't spawn pkill
    /// at all), so the dashboard's Reload button drops a request here
    /// instead. We reuse the existing SIGHUP rule-reload path in-process
    /// by raising SIGHUP to ourselves — no logic duplication: the
    /// SignalHandlers SIGHUP DispatchSource does the full single /
    /// sequence / graph reload + suppression refresh. Coalesced: many
    /// requests in one tick raise a single SIGHUP.
    private static func handleReloadRulesRequests(
        _ names: [String], inboxDir: String, state: DaemonState
    ) async {
        guard !names.isEmpty else { return }
        let fm = FileManager.default
        var anyAuthorized = false
        for name in names {
            let path = inboxDir + "/" + name
            defer { try? fm.removeItem(atPath: path) }
            let uid = requestOwnerUID(at: path)
            guard isAuthorizedInboxRequest(uid: uid) else {
                print("[inbox] reload-rules \(name) REJECTED uid=\(uid) (not console-user or root)")
                auditLogInbox(state: state, prefix: "reload-rules", id: "-", uid: uid, result: "rejected_uid")
                continue
            }
            anyAuthorized = true
            auditLogInbox(state: state, prefix: "reload-rules", id: "-", uid: uid, result: "ok")
        }
        guard anyAuthorized else { return }
        print("[inbox] reload-rules: \(names.count) request(s) — raising SIGHUP to self")
        kill(getpid(), SIGHUP)
    }

    /// v1.17.4: apply a dashboard-pushed LLM backend config. The app writes
    /// the uid-501 user-dir llm_config.json, which the ROOT sysext never
    /// reads (it reads <support>/llm_config.json). This bridges the
    /// NON-SECRET fields over the privileged inbox so engine-side LLM
    /// features become reachable. Security posture: a uid-501 file steering
    /// a root process's outbound URL is an SSRF/exfil surface, so any
    /// non-loopback ollama_url/openai_url is DEFAULT-DENIED unless the
    /// payload sets allow_remote_endpoint=true. Cloud API keys never travel
    /// this channel (keychain leg). Takes effect on the next engine restart.
    private static func handleLLMConfigRequests(
        _ names: [String], inboxDir: String, state: DaemonState
    ) async {
        guard !names.isEmpty else { return }
        let fm = FileManager.default
        // Coalesce: apply only the newest authorized request.
        var newest: (mtime: Date, payload: [String: Any], uid: Int)?
        for name in names {
            let path = inboxDir + "/" + name
            defer { try? fm.removeItem(atPath: path) }
            let uid = requestOwnerUID(at: path)
            guard isAuthorizedInboxRequest(uid: uid) else {
                auditLogInbox(state: state, prefix: "llm-config", id: "-", uid: uid, result: "rejected_uid")
                continue
            }
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                auditLogInbox(state: state, prefix: "llm-config", id: "-", uid: uid, result: "malformed")
                continue
            }
            let mtime = (try? fm.attributesOfItem(atPath: path))?[.modificationDate] as? Date
                ?? Date(timeIntervalSince1970: 0)
            if newest == nil || mtime > newest!.mtime { newest = (mtime, json, uid) }
            auditLogInbox(state: state, prefix: "llm-config", id: "-", uid: uid, result: "ok")
        }
        guard let chosen = newest else { return }

        // Whitelist NON-SECRET keys; default-deny non-loopback endpoints.
        let allowRemote = (chosen.payload["allow_remote_endpoint"] as? Bool) ?? false
        let urlKeys: Set<String> = ["ollama_url", "openai_url"]
        let allowedKeys = ["enabled", "provider", "ollama_url", "ollama_model",
                           "openai_url", "openai_model", "claude_model",
                           "mistral_model", "gemini_model", "agentic_investigation_enabled"]
        var sanitized: [String: Any] = [:]
        for key in allowedKeys {
            guard let value = chosen.payload[key] else { continue }
            if urlKeys.contains(key), let urlStr = value as? String,
               !isLoopbackEndpoint(urlStr), !allowRemote {
                print("[inbox] llm-config: rejected non-loopback \(key)=\(urlStr) (set allow_remote_endpoint to override)")
                auditLogInbox(state: state, prefix: "llm-config", id: key, uid: chosen.uid, result: "url_rejected_nonloopback")
                continue
            }
            sanitized[key] = value
        }
        guard !sanitized.isEmpty else { return }

        // Merge onto the existing root config (preserve fields/keys not in
        // this payload), write 0600 root-owned.
        let rootPath = state.supportDir + "/llm_config.json"
        var merged: [String: Any] = {
            if let data = try? Data(contentsOf: URL(fileURLWithPath: rootPath)),
               let existing = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                return existing
            }
            return [:]
        }()
        for (k, v) in sanitized { merged[k] = v }
        if let out = try? JSONSerialization.data(withJSONObject: merged, options: [.sortedKeys, .prettyPrinted]) {
            try? out.write(to: URL(fileURLWithPath: rootPath), options: .atomic)
            try? fm.setAttributes([.posixPermissions: NSNumber(value: Int16(0o600))], ofItemAtPath: rootPath)
            print("[inbox] llm-config: applied \(sanitized.count) field(s) → \(rootPath) (effective next engine restart)")
            // Self-protection: a non-loopback endpoint accepted under
            // allow_remote_endpoint=true means future engine LLM prompt traffic
            // may leave the host — surface it (rare-legitimate, exfil-relevant).
            let remoteApplied = sanitized.contains { (k, v) in
                urlKeys.contains(k) && ((v as? String).map { !isLoopbackEndpoint($0) } ?? false)
            }
            if allowRemote && remoteApplied {
                await emitSelfProtectionAlert(
                    state: state, action: "Remote LLM endpoint enabled",
                    detail: "A non-loopback LLM endpoint was configured with allow_remote_endpoint=true (engine prompt traffic may leave the host)")
            }
        }
    }

    /// A URL string whose host is genuinely loopback (localhost / ::1 /
    /// an IPv4 literal in 127.0.0.0/8). Default-deny gate for engine-side
    /// LLM endpoints (SSRF/exfil guard). Delegates to the shared strict
    /// validator so a hostname like `127.0.0.1.evil.com` is rejected — a
    /// textual `hasPrefix("127.")` test would have let it through.
    private static func isLoopbackEndpoint(_ urlString: String) -> Bool {
        return LoopbackEndpoint.isLoopback(urlString: urlString)
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
    // `internal` (not private) so the symlink/hardlink forgery rejection is
    // unit-tested against real on-disk files — this is the gate that stops a
    // local user from forging root ownership of an inbox request.
    static func requestOwnerUID(at path: String) -> Int {
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

    /// v1.19.1 (audit): true if `uid` belongs to the macOS `admin` group
    /// (gid 80). The control plane must accept mutating verbs only from an
    /// ADMIN console user (or root) — on a shared / managed / kiosk Mac a
    /// standard, non-admin user at the keyboard must not be able to suppress
    /// alerts, install rules, or weaken config via the 1777 inbox.
    static func isAdminUID(_ uid: uid_t) -> Bool {   // internal for @testable
        guard let pw = getpwuid(uid) else { return false }
        let name = String(cString: pw.pointee.pw_name)
        let baseGID = Int32(bitPattern: pw.pointee.pw_gid)
        var ngroups: Int32 = 64
        var groups = [Int32](repeating: 0, count: Int(ngroups))
        if getgrouplist(name, baseGID, &groups, &ngroups) == -1 {
            // Buffer was too small; ngroups now holds the needed size — retry.
            groups = [Int32](repeating: 0, count: Int(ngroups))
            guard getgrouplist(name, baseGID, &groups, &ngroups) != -1 else { return false }
        }
        return groups.prefix(Int(ngroups)).contains(80)   // gid 80 == admin
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
    static func isAuthorizedInboxRequest(uid: Int) -> Bool {
        if uid < 0 { return false }                  // stat failed
        if uid == 0 { return true }                  // root
        // v1.19.1 (audit): the console user must ALSO be an admin to issue
        // control verbs. Pre-fix any foreground console user — incl. a standard
        // non-admin user on a shared/managed Mac — could suppress/delete alerts,
        // suppress campaigns, install rules, or weaken config. Now: root, or the
        // GUI console user AND that user is in the admin group.
        if let console = consoleUserUID(), Int(console) == uid, isAdminUID(console) { return true }
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
    static func sanitizeAuditField(_ s: String, max: Int = 128) -> String {
        let scrubbed = String(s.unicodeScalars.prefix(max).map { scalar -> Character in
            if scalar == "\n" || scalar == "\r" { return "_" }
            if !scalar.isASCII { return "?" }
            if scalar.value < 0x20 { return "_" }
            return Character(scalar)
        })
        return scrubbed
    }

    /// v1.21.4 (G-04): size-based rotation for `dashboard_audit.log`. The log
    /// is plain-appended one line per privileged mutation and previously had no
    /// cap, so it grew without bound. When the live file passes `maxBytes`,
    /// shift `.N → .(N+1)` (oldest falls off the end) and move the live file to
    /// `.1`, mirroring the FileOutput rotation idiom. `maxArchives` rotated
    /// generations are kept.
    ///
    /// Best-effort and intentionally NON-tamper-evident: this is a forensic
    /// breadcrumb (a single tail target for "who changed alert state"), not a
    /// hash-chained ledger — rotation discards the oldest generation. Operators
    /// needing durable retention should export via the daemon's syslog/SIEM
    /// sinks.
    static func rotateAuditLogIfNeeded(
        path: String, maxBytes: UInt64 = 5 * 1024 * 1024, maxArchives: Int = 3
    ) {
        let fm = FileManager.default
        guard maxArchives >= 1,
              let attrs = try? fm.attributesOfItem(atPath: path),
              let size = attrs[.size] as? UInt64, size > maxBytes else { return }
        // Shift .N → .(N+1) from the oldest so nothing is overwritten.
        for i in stride(from: maxArchives, to: 0, by: -1) {
            let src = "\(path).\(i)"
            guard fm.fileExists(atPath: src) else { continue }
            if i == maxArchives {
                try? fm.removeItem(atPath: src)          // oldest falls off the end
            } else {
                try? fm.moveItem(atPath: src, toPath: "\(path).\(i + 1)")
            }
        }
        try? fm.moveItem(atPath: path, toPath: "\(path).1")
    }

    private static func auditLogInbox(
        state: DaemonState, prefix: String, id: String, uid: Int, result: String
    ) {
        let logPath = state.supportDir + "/dashboard_audit.log"
        rotateAuditLogIfNeeded(path: logPath)
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
    evidencePerAlertCap: Int = 50,
    evidenceMaxSizeMB: Int = 100,
    processFloorMinutes: Int = 0
) async {
    // v1.21.4 per-category retention floor. When > 0, spare process/exec rows
    // newer than this cutoff from BOTH the time-based rollup (Layer 2) and the
    // oldest-first row-count fallback (Layer 3) so a cheap file-write flood
    // can't collapse the low-volume process channel as collateral. Layer 3's
    // pruneOldest carries a soft-floor valve, so the cap still converges even
    // when the protected rows alone exceed it. 0 = category-blind (unchanged).
    let processFloorCategory: EventCategory? = processFloorMinutes > 0 ? .process : nil
    let processFloorCutoff: Date? = processFloorMinutes > 0
        ? Date().addingTimeInterval(-Double(processFloorMinutes) * 60)
        : nil
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
        // RC H2: total-size cap. Age + per-alert-cap don't bound total size,
        // so on a busy host alert_evidence outgrew the events cap (194 MB).
        let evidenceCapBytes = Int64(max(10, evidenceMaxSizeMB)) * 1_048_576
        let evictedBySize = (try? await eventStore.pruneAlertEvidenceBySize(maxBytes: evidenceCapBytes)) ?? 0
        if evictedByAge > 0 || evictedByCap > 0 || evictedBySize > 0 {
            logger.notice("alert_evidence prune: \(evictedByAge) by age (>\(alertsRetentionDays)d), \(evictedByCap) by per-alert cap (>\(evidencePerAlertCap) rows), \(evictedBySize) by size (>\(evidenceMaxSizeMB) MB)")
        }
    }

    // Build a progressively-tightening cutoff ladder from the configured
    // hot-tier window. Floors at 15 min (sequence-rebuild safety: the
    // longest single sequence rule has a 10-minute window; below 15 we'd
    // risk dropping events mid-sequence on rule reload).
    //
    // v1.12.6 fix: the prior implementation built `[hot, hot/2, hot/4]`,
    // applied `max(15, …)` to each, then `NSOrderedSet` dedup'd. When
    // `hotTierMinutes ≤ 15`, all three rungs collapsed to 15 and the
    // dedup left a single-entry ladder — meaning the Layer-2 adaptive
    // pass had no progressively-tighter cutoffs to try, and Layer 3
    // (the row-count fallback) had to do all the work alone. On a host
    // already running with a 15 min hot tier (a deliberate "minimum
    // safe" setting), this defeated the adaptive design entirely.
    //
    // New ladder construction: explicit fractional cutoffs with strict
    // monotonic decrease enforced via `min(prev - 1, candidate)` before
    // the 15-minute floor is applied. At `hotTierMinutes == 15` this
    // yields `[15, 14, 13]` (still adaptive, still above the 10-minute
    // sequence-window). At `hotTierMinutes == 30` it yields
    // `[30, 15, 13]`. The minimum floor of 13 (15 − 2) was picked so
    // even the pathological-floor case retains *some* tightening room;
    // the Layer-3 row-count fallback below still handles any overflow.
    let hotMinutes = hotTierMinutes
    let rung1 = hotMinutes
    let rung2 = min(rung1 - 1, max(15, hotMinutes / 2))
    let rung3 = min(rung2 - 1, max(15, hotMinutes / 4))
    let rawLadder = [rung1, rung2, rung3]
    // Filter to strictly-positive cutoffs (rung2/rung3 can dip if the
    // operator sets a 1-minute hot tier — defense against bogus config
    // rather than expected operation).
    let cutoffsMinutes: [Double] = rawLadder
        .filter { $0 > 0 }
        .map(Double.init)
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
                aggregateRetentionDays: aggregateDays,
                protecting: processFloorCategory,
                newerThan: processFloorCutoff
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
            let dropped = (try? await eventStore.pruneOldest(
                count: dropTarget,
                protecting: processFloorCategory,
                newerThan: processFloorCutoff
            )) ?? 0
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
    // Wave 9B (v1.12.6): incremental_vacuum first so we (a) shrink
    // the file even when disk is too tight for full VACUUM, and (b)
    // reduce the headroom requirement for the full VACUUM below by
    // pre-truncating end-of-file freelist pages.
    //
    // Full VACUUM skipped if no rows were pruned, if free disk is too
    // tight (VACUUM rebuilds into a parallel temp file ≈ DB size;
    // needs at least 1.3× headroom), or both. On skip we still run a
    // wal_checkpoint(TRUNCATE) so any drained pages migrate from the
    // WAL into the main file — a cheap partial cleanup.
    if totalPruned > 0 {
        let dbSizeBeforePrune = measureDatabaseFootprintMB(dbPath: dbPath)
        let reclaimed = (try? await eventStore.incrementalVacuum(maxPages: 200_000)) ?? 0
        let dbSizeAfterIncremental = measureDatabaseFootprintMB(dbPath: dbPath)
        if reclaimed > 0 {
            logger.notice("Tier-rollup: incremental_vacuum reclaimed \(reclaimed) pages, \(dbSizeBeforePrune) MB → \(dbSizeAfterIncremental) MB")
        }

        let freeMB = freeDiskMB(forPath: dbPath)
        // v1.18 (audit): incremental_vacuum (above) already returns freed pages to
        // the OS, so a DB that is now under target needs no full-file rebuild.
        // Reserve the expensive full VACUUM (whole-file copy — ~3 min + a pinned
        // CPU core on a ~400MB DB, and it trips the macOS disk-writes monitor) for
        // the genuinely-still-over-target case; otherwise just checkpoint the WAL.
        // This ends the hourly full-VACUUM write-amplification the audit found
        // (which was driven by the evidence-cap bug keeping the DB permanently
        // over cap → Layer-3 firing every tick → totalPruned>0 → VACUUM every tick).
        // v1.19.1 (audit): also defer the heavy full VACUUM under battery /
        // thermal pressure. A whole-file rewrite (~3 min, a pinned core, hundreds
        // of MB of writes) is non-urgent maintenance that shouldn't run on
        // battery or while thermally throttled — incremental_vacuum already
        // reclaimed pages above and the WAL is checkpointed below, so the cap
        // still trends down; the full rebuild waits for AC / nominal thermal.
        let underPowerPressure = PowerGate.pollIntervalMultiplier > 1.0
        if dbSizeAfterIncremental > targetSizeMB && freeMB >= Int(Double(dbSizeAfterIncremental) * 1.3) && !underPowerPressure {
            do {
                // B-03: dedicated connection, off the actor — see the phase-2b
                // caller. Keeps the multi-minute rewrite off the ingestion path.
                try await EventStore.vacuumOnDedicatedConnection(at: dbPath)
            } catch {
                logger.warning("Tier-rollup VACUUM failed: \(error.localizedDescription, privacy: .public)")
            }
        } else if dbSizeAfterIncremental > targetSizeMB && underPowerPressure {
            logger.notice("Tier-rollup: deferring full VACUUM under power/thermal pressure (poll-multiplier \(PowerGate.pollIntervalMultiplier)); incremental_vacuum reclaimed \(reclaimed) pages → \(dbSizeAfterIncremental) MB. Checkpointing WAL; full rebuild will run on AC / nominal thermal.")
            await eventStore.walCheckpoint()
        } else {
            logger.notice("Tier-rollup: incremental_vacuum reclaimed \(reclaimed) pages → \(dbSizeAfterIncremental) MB (target \(targetSizeMB) MB); full VACUUM not needed, running checkpoint(TRUNCATE) for WAL cleanup.")
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
        eventStore: state.eventStore,
        processFloorMinutes: max(0, state.storage.processEventsFloorMinutes)
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
    eventStore: EventStore,
    processFloorMinutes: Int = 0
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

    // v1.21.4 per-category floor: spare recent process/exec rows, spilling
    // into them only when the eligible (file) rows can't satisfy the drop
    // count (pruneOldest's soft-floor valve — keeps the cap converging).
    let processFloorCutoff: Date? = processFloorMinutes > 0
        ? Date().addingTimeInterval(-Double(processFloorMinutes) * 60)
        : nil
    let pruned = (try? await eventStore.pruneOldest(
        count: pruneCount,
        protecting: processFloorMinutes > 0 ? .process : nil,
        newerThan: processFloorCutoff
    )) ?? 0
    let sizeAfterPruneMB = currentSizeMB()
    logger.notice("Size-cap phase 1: pruned \(pruned) rows (estimated \(estimatedPrune), cap \(maxPerSweep)); logical size now \(sizeAfterPruneMB) MB")

    // --- Phase 2a: incremental_vacuum pre-flight (Wave 9B, v1.12.6) ---
    //
    // BEFORE attempting a full VACUUM, run incremental_vacuum to
    // trim end-of-file freelist pages in place. This is free
    // (no scratch disk) and:
    //   1. On a 7 GB events.db with 1.7M freelist pages, this can
    //      drop the file to ~500 MB BEFORE the full VACUUM runs,
    //      making the subsequent full-rewrite cheap.
    //   2. If disk is too tight for full VACUUM, this is our only
    //      path to actually shrinking the file. Without it, the
    //      `.db` file grew unbounded between sweeps because every
    //      VACUUM attempt failed the headroom check.
    //
    // 200K-page cap (set in StoragePragmas.incrementalVacuumHardCap)
    // bounds the wall-clock so a runaway freelist on a huge file
    // doesn't stall the actor for minutes. At ~4 KB/page that's up
    // to ~800 MB of file truncation per call, which on commodity SSDs
    // takes ~5-30 s. The next scheduled sweep continues if more
    // pages remain.
    let preVacuumMB = sizeAfterPruneMB
    let preReclaimed: Int
    do {
        preReclaimed = try await eventStore.incrementalVacuum(maxPages: 200_000)
    } catch {
        logger.warning("Size-cap phase 2a: incremental_vacuum threw \(error.localizedDescription) — continuing")
        preReclaimed = 0
    }
    let sizeAfterIncrementalMB = currentSizeMB()
    if preReclaimed > 0 {
        logger.notice("Size-cap phase 2a: incremental_vacuum reclaimed \(preReclaimed) pages, \(preVacuumMB) MB → \(sizeAfterIncrementalMB) MB")
    } else {
        let mode = await eventStore.autoVacuumMode()
        if mode != 2 {
            logger.warning("Size-cap phase 2a: incremental_vacuum unavailable (auto_vacuum mode=\(mode), need 2/INCREMENTAL). Run `maccrabctl maintenance vacuum events` once to convert.")
        }
    }

    // --- Phase 2b: full VACUUM if we have the disk headroom ---
    //
    // VACUUM needs ~= current DB size of scratch space. We require
    // 1.3× as buffer, recomputed AFTER phase 2a so the incremental
    // truncate shrinks our headroom requirement. If the volume is
    // still tight, we skip VACUUM entirely — the file has been
    // partially shrunk by phase 2a (or by no-op if INCREMENTAL is
    // off), and the next hourly tick (or once disk frees) revisits.

    let needMB = Int(Double(sizeAfterIncrementalMB) * 1.3)
    let freeMB = freeDiskMB()
    let canVacuum = freeMB >= needMB

    if !canVacuum {
        logger.warning("Size-cap phase 2b: skipping full VACUUM — need \(needMB) MB free, have \(freeMB) MB. Phase 2a reclaimed \(preReclaimed) pages; will retry next tick.")
        let endMB = currentSizeMB()
        logger.notice("Size-cap sweep complete: \(initialMB) MB → \(endMB) MB (rows pruned: \(pruned), incremental_vacuum: \(preReclaimed) pages, full vacuum: skipped)")
        return true
    }

    // Checkpoint the WAL first so VACUUM sees all committed pages
    // consolidated in the main file.
    let checkpointBefore = await eventStore.walCheckpoint()
    do {
        // B-03: run the full VACUUM on a dedicated connection off the actor so
        // it can't head-of-line-block event ingestion for the rewrite's duration.
        try await EventStore.vacuumOnDedicatedConnection(at: dbPath)
    } catch {
        logger.error("Size-cap phase 2b: VACUUM failed (\(error.localizedDescription)). Phase 2a reclaimed \(preReclaimed) pages; will retry next tick.")
        let endMB = currentSizeMB()
        logger.notice("Size-cap sweep complete: \(initialMB) MB → \(endMB) MB (rows pruned: \(pruned), incremental_vacuum: \(preReclaimed) pages, full vacuum: failed)")
        return true
    }

    // Second checkpoint drains any WAL left by the VACUUM itself.
    _ = await eventStore.walCheckpoint()

    let finalMB = currentSizeMB()
    logger.notice("Size-cap sweep complete: \(initialMB) MB → \(finalMB) MB (rows pruned: \(pruned), incremental_vacuum: \(preReclaimed) pages, full vacuum: success, checkpoint_before_drained: \(checkpointBefore))")
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
