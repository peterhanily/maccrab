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

    static func install(
        state: DaemonState,
        supervisor: MonitorSupervisor,
        timerLifecycle: DaemonTimerLifecycle,
        livenessLifecycle: DaemonTimerLifecycle
    ) -> Handles {
        // Handle SIGHUP for rule reload
        let sigHupSource = DispatchSource.makeSignalSource(signal: SIGHUP, queue: .main)
        signal(SIGHUP, SIG_IGN) // Ignore default handler
        sigHupSource.setEventHandler {
            let accepted = timerLifecycle.submit(label: "signal.rule-reload") {
                guard await state.daemonLifecycle.beginRuleReload() else {
                    let reason = await state.daemonLifecycle.isShuttingDown()
                        ? "daemon shutdown is in progress"
                        : "rule reload is already in progress"
                    print("[SIGHUP] Ignoring reload: \(reason)")
                    return
                }
                let reloadRequestIDs = await state.runtimeConfigurationReporter.takeReloadRequests()
                var reloadSucceeded = false
                var reloadFailureReason = "Rule reload did not complete"
                var retroactiveScanNote = ""

                do {
                    try Task.checkCancellation()
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
                    // The out-of-band rule channel is release-disabled. Preserve
                    // any pushed corpus on disk, but do not read or evaluate it.
                    await state.responseEngine.setDetectionOnlyRuleIDs([])
                    // v1.21.5: sequence + graph rules honor the F-04 rule
                    // profile on reload too. RuleEngine re-applies its stored
                    // profile internally, but SequenceEngine/GraphRuleLoader
                    // take the statuses per call — without this a SIGHUP
                    // silently re-enabled the experimental sequence corpus.
                    // Re-derived from a fresh config load (state doesn't keep
                    // the config; the same load also feeds the storage/
                    // enrichment reloads below).
                    let freshConfig = DaemonConfig.load(from: state.supportDir)
                    let ruleStatuses = DaemonConfig.enabledRuleStatuses(forProfile: freshConfig.ruleProfile)
                    // reloadRules (not loadRules): full-replace so a sequence now
                    // deprecated / outside the tightened profile / deleted actually
                    // STOPS firing. loadRules is additive and would keep the stale
                    // enabled copy alive until restart (mother-of-all-audits #6).
                    // Treat the active sequence corpus and its durable
                    // checkpoint as one reload transaction. Join any in-flight
                    // periodic write before replacing rules so an old-corpus
                    // checkpoint cannot race the new fingerprint. If reload
                    // fails, the engine retains its last-known-good corpus and
                    // the old durable checkpoint remains valid.
                    await state.sequenceCheckpointCoordinator.stopPeriodicCheckpointing()
                    let seqCount: Int
                    do {
                        seqCount = try await state.sequenceEngine.reloadRules(
                            from: URL(fileURLWithPath: state.sequenceRulesDir),
                            enabledStatuses: ruleStatuses
                        )
                    } catch {
                        await state.sequenceCheckpointCoordinator.startPeriodicCheckpointing(
                            engine: state.sequenceEngine
                        )
                        throw error
                    }
                    let sequenceCheckpointResult = await state.sequenceCheckpointCoordinator
                        .forceFlush(engine: state.sequenceEngine)
                    let sequenceCheckpointTelemetry = await state.sequenceCheckpointCoordinator
                        .telemetry(engine: state.sequenceEngine)
                    DaemonBootstrap.reportSequenceCheckpointFlush(
                        sequenceCheckpointResult,
                        context: "SIGHUP sequence-rule reload",
                        requiresCleanBoundary: false,
                        ingestionQuiesced: false,
                        dirtyAfterFlush: sequenceCheckpointTelemetry.dirty
                    )
                    await state.sequenceCheckpointCoordinator.startPeriodicCheckpointing(
                        engine: state.sequenceEngine
                    )
                    // v1.21.5 (audit): the fresh profile governs ONLY the
                    // sequence/graph reload — RuleEngine.reloadRules re-applies
                    // its boot-stored profile internally (pre-existing,
                    // accepted). Say so instead of implying the fresh profile
                    // covered the single-event reload too, and warn loudly when
                    // the two diverge.
                    print("[SIGHUP] Reloaded \(singleCount) single + \(seqCount) sequence rules (rule_profile \(freshConfig.ruleProfile) governs the sequence/graph reload)")
                    // v1.22.0: ALSO emit through os.log.
                    //
                    // A System Extension's stdout is discarded — nothing in this
                    // process's `print` output reaches the unified log. Proven on
                    // an installed host: DaemonSetup emits every BOOT_TIMING label
                    // via BOTH print and logger.notice, and only the os.log copies
                    // appear in the log store.
                    //
                    // That made the operator-facing record of a live rule reload
                    // invisible: an admin who sends SIGHUP had no way to confirm
                    // from the logs that anything reloaded, or how many rules are
                    // now active. It also made the release gate's live-reload
                    // evidence unsatisfiable by construction, so a run could burn
                    // its full 900-second epoch and then fail assembling a
                    // transcript the product could never have written.
                    //
                    // Deliberately mirrors the existing line rather than replacing
                    // it: `print` remains the transcript for a foreground
                    // `swift run maccrabd`, where there is no os_log subsystem to
                    // read. Counts only — no paths, no rule content.
                    logger.notice(
                        "[SIGHUP] Reloaded \(singleCount, privacy: .public) single + \(seqCount, privacy: .public) sequence rules (rule_profile \(freshConfig.ruleProfile, privacy: .public) governs the sequence/graph reload)"
                    )
                    if freshConfig.ruleProfile != state.bootRuleProfile {
                        print("[SIGHUP] WARNING: rule_profile changed '\(state.bootRuleProfile)' → '\(freshConfig.ruleProfile)' since boot — single-event rules keep the boot profile until the daemon restarts")
                        logger.warning(
                            "[SIGHUP] rule_profile changed '\(state.bootRuleProfile, privacy: .public)' -> '\(freshConfig.ruleProfile, privacy: .public)' since boot — single-event rules keep the boot profile until the daemon restarts"
                        )
                    }

                    // v1.12.0 RC3 (Int-HSig1): also reload graph rules so
                    // an operator can edit Rules/graph/*.json and have
                    // them picked up without a daemon restart. The
                    // evaluator holds its rules immutably, so swap in a
                    // freshly-constructed instance.
                    // Flush the bounded rolling batch first: a newly loaded
                    // graph rule must never begin against a substrate that is
                    // still only resident in the old ingestion epoch.
                    if let bridge = state.causalGraphBridge {
                        do {
                            try await bridge.flushPending()
                        } catch {
                            print("[SIGHUP] TraceGraph pending-write flush failed: \(error.localizedDescription)")
                        }
                    }
                    let graphRulesDir = URL(fileURLWithPath: state.supportDir + "/compiled_rules/graph")
                    var graphRules = GraphRuleLoader.loadRules(from: graphRulesDir, enabledStatuses: ruleStatuses)
                    if graphRules.isEmpty {
                        let cwd = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
                        graphRules = GraphRuleLoader.loadFromProjectSource(projectRoot: cwd, enabledStatuses: ruleStatuses)
                    }
                    // v1.12.0 RC4 fix (Sec-R4-N3): always swap the
                    // evaluator, even when the new ruleset is empty.
                    // Pre-fix an operator who deleted all graph rules
                    // and SIGHUPed would still see the old rules
                    // fire silently — inconsistent with
                    // ruleEngine.reloadRules which fully replaces.
                    state.setGraphEvaluator(GraphRuleEvaluator(rules: graphRules))
                    print("[SIGHUP] Graph rules: \(graphRules.count)")
                    try Task.checkCancellation()
                    // v1.21.6 (PERF-02): re-point the demand-gated ES families at
                    // the ruleset just loaded. Without this the boot-time gate
                    // would create exactly the failure it exists to avoid — an
                    // ENABLED introspection rule that can never fire because the
                    // kernel subscription was decided before the rule was enabled.
                    // Cheap and idempotent (es_subscribe is additive).
                    if let esCollector = state.collector {
                        let esSelectors = await state.ruleEngine.enabledEventActionSelectors()
                        let esDemand = ESCollector.optionalFamiliesDemanded(
                            selectors: esSelectors.values,
                            unanalyzable: esSelectors.hasUnanalyzableSelector)
                        let introspectionOn = freshConfig.subscribeIntrospectionEvents && esDemand.introspection
                        let subscriptionsApplied = esCollector.applyOptionalSubscriptions(
                            introspection: introspectionOn,
                            memoryProtection: esDemand.memoryProtection)
                        if subscriptionsApplied {
                            if var entry = freshConfig.effectiveRuntimeEntries()["subscribe_introspection_events"] {
                                entry.adjustment = "Effective subscription policy; enabled-rule demand governs actual capture"
                                try await state.runtimeConfigurationReporter.apply(["subscribe_introspection_events": entry])
                            }
                            print("[SIGHUP] ES demand-gated families: introspection=\(introspectionOn), memory_protection=\(esDemand.memoryProtection)")
                        } else {
                            throw RuntimeConfigContractError("Rules were reloaded but the native subscription update was not fully applied")
                        }
                    }
                    await state.suppressionManager.load()
                    let stats = await state.suppressionManager.stats()
                    print("[SIGHUP] Suppressions: \(stats.pathCount) paths across \(stats.ruleCount) rules")

                    // Retroactive detection: scan last 6 hours of events against new rules
                    // v1.22.0: the scan is advisory. It used to abort the whole
                    // reload — right after the rule swap, silently skipping the
                    // storage, notification, response-action and feed reloads
                    // below — whenever its exact query came back incomplete,
                    // which on a busy engine is every time: the array byte
                    // budget fills long before 10,000 events. A resource-bounded
                    // result is scanned as far as it goes and the bound is
                    // logged; a hard evidence gap (poison, corrupt legacy,
                    // inherited loss) or any other scan error is logged and the
                    // remaining reloads still run. Cancellation still aborts.
                    do {
                        let retroSince = Date().addingTimeInterval(-6 * 3600)
                        let retroSnapshot = try await state.eventStore
                            .exactEventsSnapshot(
                                since: retroSince,
                                limit: 10_000
                            )
                        if let gap = retroSnapshot.retroactiveScanGap {
                            throw gap
                        }
                        if retroSnapshot.resourceLimitedRecords > 0 {
                            print("[SIGHUP] Retroactive scan bounded by the exact-query resource budget: \(retroSnapshot.events.count) newest events retained, up to \(retroSnapshot.resourceLimitedRecords) record(s) in the window not scanned")
                            logger.notice(
                                "[SIGHUP] Retroactive scan bounded by the exact-query resource budget: \(retroSnapshot.events.count, privacy: .public) newest events retained, up to \(retroSnapshot.resourceLimitedRecords, privacy: .public) record(s) in the window not scanned"
                            )
                        }
                        let recentEvents = retroSnapshot.events
                        var retroMatches = 0
                        for event in recentEvents {
                            try Task.checkCancellation()
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
                        withExtendedLifetime(retroSnapshot) {}
                        if retroMatches > 0 {
                            print("[SIGHUP] Retroactive scan: \(retroMatches) new detections from \(recentEvents.count) events")
                        } else {
                            print("[SIGHUP] Retroactive scan: no new detections in \(recentEvents.count) events")
                        }
                        // A system extension's stdout is discarded; the unified
                        // log is the operator-visible record of the reload.
                        logger.notice(
                            "[SIGHUP] Retroactive scan: \(retroMatches, privacy: .public) new detections from \(recentEvents.count, privacy: .public) events"
                        )
                    } catch let cancellation as CancellationError {
                        throw cancellation
                    } catch {
                        // The installed-qualification gate reads this line's
                        // TEXT, not its level: it fails a reload window whose
                        // [SIGHUP] lines say error/failed/rejected. A bounded
                        // or gapped scan is tolerable and its description
                        // carries no such word, while a storage step or
                        // decode failure says "failed" and should fail the
                        // run — the reload completed, but an engine that
                        // cannot read its own journal is not qualified.
                        // ExactQueryByteBudgetTests pins that split.
                        let reason = String(error.localizedDescription.prefix(200))
                        retroactiveScanNote = "; retroactive scan skipped: " + reason
                        print("[SIGHUP] Retroactive scan skipped: \(reason)")
                        logger.error(
                            "[SIGHUP] Retroactive scan skipped: \(reason, privacy: .public)"
                        )
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
                    try Task.checkCancellation()
                    await state.notifier.setMinimumSeverity(notifConfig.minSeverity)
                    await state.notifier.setEnabled(notifConfig.enabled)
                    print("[SIGHUP] Alert-notification config reloaded: enabled=\(notifConfig.enabled), minSeverity=\(notifConfig.minSeverity.rawValue)")

                    // (freshConfig loaded above, alongside the rule-profile derivation.)
                    let old = state.storage
                    // Same floors as boot, from the same function — this used to
                    // be a hand-maintained copy of DaemonSetup's list and had
                    // fallen eight knobs behind it, so a reload could re-admit a
                    // `traces_retention_days: 0` that boot would have clamped.
                    let newStorage = freshConfig.storage.clampedToSafeFloors()
                    let previousTransition = state
                        .legacyEvidenceTransitionBudget.snapshot()
                    let transitionTicket = state
                        .legacyEvidenceTransitionBudget
                        .installStorageConfig(newStorage)
                    let legacyMeasurement: LegacyAlertEvidenceTransitionMeasurement?
                    do {
                        legacyMeasurement = try await state.eventStore
                            .legacyAlertEvidenceTransitionMeasurement(
                                maxBytes: SQLitePersistentStorePolicy.capBytes(
                                    maxSizeMiB: newStorage.evidenceMaxSizeMB
                                )
                            )
                    } catch {
                        legacyMeasurement = nil
                        print("[SIGHUP] Legacy evidence measurement failed; retaining full transition reserve: \(error.localizedDescription)")
                    }
                    var newTransition = state.legacyEvidenceTransitionBudget
                        .update(
                            measurement: legacyMeasurement,
                            ticket: transitionTicket
                        )
                    let oldEventsFamilyCap = old
                        .effectiveEventsFamilyMaxSizeMB(
                            appliedLegacyEvidenceTransitionReserveMiB:
                                previousTransition.appliedReserveMiB
                        )
                    let proposedReserve = newTransition
                        .pendingReserveFitsHardBoundary == true
                        ? newTransition.pendingReserveMiB
                            ?? newTransition.appliedReserveMiB
                        : newTransition.appliedReserveMiB
                    var newEventsFamilyCap = newStorage
                        .effectiveEventsFamilyMaxSizeMB(
                            appliedLegacyEvidenceTransitionReserveMiB:
                                proposedReserve
                        )
                    let oldAlertsFamilyCap = old.effectiveAlertsFamilyMaxSizeMB
                    let newAlertsFamilyCap = newStorage.effectiveAlertsFamilyMaxSizeMB
                    let tracegraphCapChanged = old.tracegraphMaxSizeMB != newStorage.tracegraphMaxSizeMB
                    let tracegraphCapLowered = newStorage.tracegraphMaxSizeMB < old.tracegraphMaxSizeMB
                    let eventsCapChanged = oldEventsFamilyCap != newEventsFamilyCap
                    let eventsCapLowered = newEventsFamilyCap < oldEventsFamilyCap
                    let eventsRetentionBudgetChanged = eventsCapChanged
                        || old.evidenceMaxSizeMB != newStorage.evidenceMaxSizeMB
                        || old.eventsHotTierMinutes != newStorage.eventsHotTierMinutes
                        || old.processEventsFloorMinutes != newStorage.processEventsFloorMinutes
                    let alertsCapChanged = oldAlertsFamilyCap != newAlertsFamilyCap
                    let evidenceBudgetChanged = old.evidenceMaxSizeMB
                        != newStorage.evidenceMaxSizeMB
                    let campaignsCapChanged = old.campaignsMaxSizeMB != newStorage.campaignsMaxSizeMB
                    state.storage = newStorage
                    if eventsRetentionBudgetChanged {
                        state.eventRetentionBudgetHealth.recordConfigurationChange()
                    }

                    func persistentPolicy(
                        maxSizeMiB: Int,
                        transactionReserveBytes: Int64 = 8 * SQLitePersistentStorePolicy.bytesPerMiB
                    ) -> SQLitePersistentStorePolicy {
                        SQLitePersistentStorePolicy(
                            maxFootprintBytes: SQLitePersistentStorePolicy.capBytes(
                                maxSizeMiB: maxSizeMiB
                            ),
                            freeSpaceFloorBytes: SQLitePersistentStorePolicy.freeSpaceFloorBytes,
                            transactionReserveBytes: transactionReserveBytes,
                            storageVolumePath: state.supportDir
                        )
                    }

                    // Hard admission lives inside each actor, so changing only
                    // DaemonState would leave the boot-time ceiling in force.
                    // Adopt lowered policies even when already over budget: the
                    // returned latch blocks growth while the maintenance paths
                    // shrink the family and retry max_page_count.
                    if eventsCapChanged {
                        do {
                            let snapshot = try await state.eventStore.updateStorageAdmission(
                                persistentPolicy(
                                    maxSizeMiB: newEventsFamilyCap,
                                    transactionReserveBytes: SQLitePersistentStorePolicy
                                        .eventTransactionReserveBytes
                                )
                            )
                            if newTransition.pendingReserveFitsHardBoundary == true,
                               let pendingReserve = newTransition
                                    .pendingReserveMiB {
                                newTransition = state
                                    .legacyEvidenceTransitionBudget
                                    .commitPendingReserve(
                                        pendingReserve,
                                        ticket: transitionTicket
                                    )
                                newEventsFamilyCap = newStorage
                                    .effectiveEventsFamilyMaxSizeMB(
                                        appliedLegacyEvidenceTransitionReserveMiB:
                                            newTransition.appliedReserveMiB
                                    )
                            }
                            let latch = snapshot?.latchedFailure ?? "none"
                            let pending = snapshot?.pageLimitPending ?? false
                            print("[SIGHUP] events.db hard admission: latch=\(latch), page_limit_pending=\(pending)")
                            // v1.22.0: ALSO emit through os.log (see the matching
                            // note on the rule-reload line above — print is
                            // discarded for a sysext).
                            logger.notice(
                                "[SIGHUP] events.db hard admission: latch=\(latch, privacy: .public), page_limit_pending=\(pending, privacy: .public)"
                            )
                        } catch {
                            newEventsFamilyCap = newStorage
                                .effectiveEventsFamilyMaxSizeMB(
                                    appliedLegacyEvidenceTransitionReserveMiB:
                                        newTransition.appliedReserveMiB
                                )
                            print("[SIGHUP] events.db hard admission reload refused; previous bound retained: \(error.localizedDescription)")
                            logger.error(
                                "[SIGHUP] events.db hard admission reload refused; previous bound retained: \(error.localizedDescription, privacy: .public)"
                            )
                        }
                    } else if newTransition.pendingReserveFitsHardBoundary == true,
                              let pendingReserve = newTransition
                                .pendingReserveMiB {
                        // The numeric ceiling is already identical (possible
                        // only through saturation/offsetting config changes),
                        // so no actor policy mutation is needed before commit.
                        newTransition = state.legacyEvidenceTransitionBudget
                            .commitPendingReserve(
                                pendingReserve,
                                ticket: transitionTicket
                            )
                    }
                    if alertsCapChanged {
                        do {
                            let snapshot = try await state.alertStore.updateStorageAdmission(
                                persistentPolicy(maxSizeMiB: newAlertsFamilyCap)
                            )
                            let latch = snapshot?.latchedFailure ?? "none"
                            let pending = snapshot?.pageLimitPending ?? false
                            print("[SIGHUP] alerts.db hard admission: latch=\(latch), page_limit_pending=\(pending)")
                            logger.notice(
                                "[SIGHUP] alerts.db hard admission: latch=\(latch, privacy: .public), page_limit_pending=\(pending, privacy: .public)"
                            )
                        } catch {
                            print("[SIGHUP] alerts.db hard admission reload refused; previous bound retained: \(error.localizedDescription)")
                            logger.error(
                                "[SIGHUP] alerts.db hard admission reload refused; previous bound retained: \(error.localizedDescription, privacy: .public)"
                            )
                        }
                    }
                    if evidenceBudgetChanged {
                        await state.alertSink.updateEvidenceBudget(
                            maxBytes: SQLitePersistentStorePolicy.capBytes(
                                maxSizeMiB: newStorage.evidenceMaxSizeMB
                            )
                        )
                    }
                    if campaignsCapChanged, let campaignStore = state.campaignStore {
                        do {
                            let snapshot = try await campaignStore.updateStorageAdmission(
                                persistentPolicy(maxSizeMiB: newStorage.campaignsMaxSizeMB)
                            )
                            let latch = snapshot?.latchedFailure ?? "none"
                            let pending = snapshot?.pageLimitPending ?? false
                            print("[SIGHUP] campaigns.db hard admission: latch=\(latch), page_limit_pending=\(pending)")
                            logger.notice(
                                "[SIGHUP] campaigns.db hard admission: latch=\(latch, privacy: .public), page_limit_pending=\(pending, privacy: .public)"
                            )
                        } catch {
                            print("[SIGHUP] campaigns.db hard admission reload refused; previous bound retained: \(error.localizedDescription)")
                            logger.error(
                                "[SIGHUP] campaigns.db hard admission reload refused; previous bound retained: \(error.localizedDescription, privacy: .public)"
                            )
                        }
                    }
                    if let causalStore = state.causalStore {
                        // Actor-owned admission changes in the same turn as the
                        // config snapshot. A lower cap is measured and latched
                        // here, before another graph mutation can be admitted.
                        let admission = await causalStore.updateStorageAdmission(
                            maxFootprintBytes: TraceGraphStoragePolicy.capBytes(
                                maxSizeMiB: newStorage.tracegraphMaxSizeMB),
                            freeSpaceFloorBytes: TraceGraphStoragePolicy.freeSpaceFloorBytes
                        )
                        if tracegraphCapLowered || admission.blocked {
                            do {
                                let result = try await causalStore.recoverStorageBudget(
                                    retentionCutoff: Date().addingTimeInterval(
                                        -Double(newStorage.tracegraphRetentionDays) * 86_400),
                                    orphanCutoff: Date().addingTimeInterval(-3_600)
                                )
                                print("[SIGHUP] TraceGraph bounded recovery: traces=\(result.tracesDeleted), trace_children=\(result.traceChildRowsDeleted), edges=\(result.edgesDeleted), entities=\(result.entitiesDeleted), reclaimed_pages=\(result.vacuumPagesReclaimed), footprint=\(result.footprintBeforeBytes ?? -1)->\(result.footprintBytes ?? -1), pinned=\(result.pinnedReader)")
                                logger.notice(
                                    "[SIGHUP] TraceGraph bounded recovery: traces=\(result.tracesDeleted, privacy: .public), trace_children=\(result.traceChildRowsDeleted, privacy: .public), edges=\(result.edgesDeleted, privacy: .public), entities=\(result.entitiesDeleted, privacy: .public), reclaimed_pages=\(result.vacuumPagesReclaimed, privacy: .public), footprint=\(result.footprintBeforeBytes ?? -1, privacy: .public)->\(result.footprintBytes ?? -1, privacy: .public), pinned=\(result.pinnedReader, privacy: .public)"
                                )
                            } catch {
                                print("[SIGHUP] TraceGraph bounded recovery did not complete: \(error.localizedDescription)")
                                logger.error(
                                    "[SIGHUP] TraceGraph bounded recovery did not complete: \(error.localizedDescription, privacy: .public)"
                                )
                            }
                        }
                    }

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
                    let refreshedRuntimeEntries = freshConfig.effectiveRuntimeEntries()
                        .filter { RuntimeConfigurationContract.byKey[$0.key]?.disableOnly == true }
                    try await state.runtimeConfigurationReporter.apply(refreshedRuntimeEntries)

                    let anyChange = old.eventsHotTierMinutes  != newStorage.eventsHotTierMinutes
                                 || old.eventsMaxSizeMB       != newStorage.eventsMaxSizeMB
                                 || old.aggregateDays         != newStorage.aggregateDays
                                 || old.alertsRetentionDays   != newStorage.alertsRetentionDays
                                 || old.alertsMaxSizeMB       != newStorage.alertsMaxSizeMB
                                 || evidenceBudgetChanged
                                 || old.campaignsRetentionDays != newStorage.campaignsRetentionDays
                                 || old.campaignsMaxSizeMB    != newStorage.campaignsMaxSizeMB
                                 || old.tracesRetentionDays   != newStorage.tracesRetentionDays
                                 || old.tracesMaxSizeMB       != newStorage.tracesMaxSizeMB
                                 || old.tracegraphRetentionDays != newStorage.tracegraphRetentionDays
                                 || tracegraphCapChanged
                    if anyChange {
                        let liveTotal = newStorage
                            .configuredEventsAndAlertsTotalMaxSizeMB(
                                appliedLegacyEvidenceTransitionReserveMiB:
                                    newTransition.appliedReserveMiB
                            )
                        print("[SIGHUP] Storage config reloaded: events=\(newStorage.eventsHotTierMinutes)m/\(newEventsFamilyCap)MB live (steady \(newStorage.effectiveEventsFamilyMaxSizeMB)MB + applied legacy reserve \(newTransition.appliedReserveMiB)MB, pending \(newTransition.pendingReserveMiB ?? -1)MB), alerts=\(newStorage.alertsRetentionDays)d/\(newStorage.alertsMaxSizeMB)MB + evidence=\(newStorage.evidenceMaxSizeMB)MB (family \(newAlertsFamilyCap)MB), events+alerts live total=\(liveTotal)MB (steady \(newStorage.configuredEventsAndAlertsTotalMaxSizeMB)MB), campaigns=\(newStorage.campaignsRetentionDays)d/\(newStorage.campaignsMaxSizeMB)MB, traces=\(newStorage.tracesRetentionDays)d/\(newStorage.tracesMaxSizeMB)MB, tracegraph=\(newStorage.tracegraphRetentionDays)d/\(newStorage.tracegraphMaxSizeMB)MB, aggregates=\(newStorage.aggregateDays)d")
                        if eventsCapLowered {
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

                    try Task.checkCancellation()

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
                    reloadSucceeded = true
                } catch {
                    reloadFailureReason = String(error.localizedDescription.prefix(300))
                    print("[SIGHUP] ERROR: \(error)")
                    logger.error(
                        "[SIGHUP] ERROR: reload incomplete: \(reloadFailureReason, privacy: .public)"
                    )
                }
                do {
                    try await state.runtimeConfigurationReporter.finishReload(
                        reloadRequestIDs, succeeded: reloadSucceeded,
                        reason: reloadSucceeded ? "Rule reload completed" + retroactiveScanNote : "Reload incomplete; some components may have changed: " + reloadFailureReason
                    )
                } catch {
                    logger.error("Rule reload completion status could not be persisted: \(error.localizedDescription)")
                }
                await state.daemonLifecycle.endRuleReload()
                if await state.runtimeConfigurationReporter.hasQueuedReloads(),
                   !(await state.daemonLifecycle.isShuttingDown()) {
                    kill(getpid(), SIGHUP)
                }
            }
            if !accepted {
                print("[SIGHUP] Reload not admitted: another reload is active, runtime work capacity is unavailable, or shutdown has begun")
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
                if await DaemonShutdownCoordinator.finalize(
                    state: state,
                    supervisor: supervisor,
                    timerLifecycle: timerLifecycle,
                    livenessLifecycle: livenessLifecycle,
                    totalDeadline: 3.75,
                    context: "SIGTERM/SIGINT shutdown",
                ) != nil {
                    exit(DaemonExitRequest.exitCode())
                }
            }
            // Hard fallback: if the Task above gets stuck (supervisor
            // actor deadlocked, scheduler starved), make sure we still
            // exit within ~4s of the signal. exit() from any thread is
            // fine once we're past the graceful window.
            DispatchQueue.global().asyncAfter(deadline: .now() + 4.0) {
                logger.warning("MacCrab daemon shutdown deadline exceeded — forcing exit")
                exit(DaemonExitRequest.exitCode())
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
            let accepted = timerLifecycle.submit(
                label: "signal.threat-intel-refresh"
            ) {
                await state.threatIntel.refreshNow()
                print("[SIGUSR1] Threat intel refresh complete")
            }
            if !accepted {
                print("[SIGUSR1] Refresh not admitted: already active, capacity unavailable, or shutdown in progress")
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
            let accepted = timerLifecycle.submit(
                label: "signal.events-size-cap"
            ) {
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
            if !accepted {
                print("[SIGUSR2] Sweep not admitted: already active, capacity unavailable, or shutdown in progress")
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
