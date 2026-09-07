// AlertSink.swift
// MacCrabCore
//
// Single chokepoint through which every alert reaches AlertStore. Closes the
// v1.6.9 NoiseFilter-layering bug class architecturally: direct
// AlertStore.insert calls scattered across EventLoop, MonitorTasks,
// DaemonSetup, and SignalHandlers bypassed both NoiseFilter and the
// AlertDeduplicator. Routing every emission through AlertSink means dedup
// is mandatory by construction.
//
// The rule-engine batch path calls `insertEngineBatch(alerts:event:)` after it
// has applied NoiseFilter + operator suppression. AlertSink transactionally
// reserves per-rule and same-evidence dedup, commits those reservations only
// after SQLite succeeds, and returns the exact stored survivors. Direct
// emissions (AI-Guard, supply chain, threat intel, monitor tasks, self-defense)
// use the same reserve/write/commit contract through `submit`.
//
// NoiseFilter is intentionally NOT applied to direct emissions — its gates
// were tuned for RuleMatch context and applying them blanket to AI-Guard
// or threat-intel alerts would suppress legitimate signal. Dedup is the
// universal guard.

import Foundation
import os.log

public actor AlertSink {

    private struct EvidenceCaptureRequest: Sendable {
        let alertId: String
        let timestamp: Date
        let enqueuedAt: ContinuousClock.Instant
        /// The exact bounded representation prepared before AlertStore commit.
        /// Never carry the raw Event onto the post-commit worker: doing so lets
        /// the snapshot and evidence paths apply different privacy/bounds.
        let triggeringCandidate: AlertEvidenceCandidate?
        /// Identity-bound current-trigger durability plus prior filter-passing
        /// admission completeness, frozen before the parent alert committed.
        /// This must survive independently of a later exact-window query.
        let journalContext: EventJournalContextStatus
    }

    private let alertStore: AlertStore
    private let eventStore: EventStore?
    private let evidenceCaptureOverride: (@Sendable (
        _ alertId: String,
        _ timestamp: Date
    ) async throws -> AlertEvidenceCaptureResult)?
    /// Identity-bound durability + prior-prefix barrier for EventLoop receipts.
    /// A terminal writer outcome is insufficient: implementations return
    /// `.verified` only when this exact UUID is durable and every earlier
    /// filter-passing admission is durable. Earlier intentional filter outcomes
    /// are conserved exclusions; drops, failures, and unknown outcomes are gaps.
    private let journalAdmissionVerifier: (@Sendable (
        EventJournalAdmission
    ) async -> EventJournalContextStatus)?
    /// Event-bearing producers outside EventLoop do not own a batched-writer
    /// receipt. Production injects an idempotent exact EventStore admission
    /// here so those alerts cannot commit ahead of their canonical trigger.
    private let journalEventEnsurer: (@Sendable (
        Event
    ) async -> EventJournalContextStatus)?
    /// The same process-wide envelope used by journal/deferred/heavy storage.
    /// Trigger sanitization acquires workspace before encoding and releases it
    /// before AlertStore commit, so a large direct alert cannot allocate an
    /// unaccounted second Event+JSON graph.
    private let liveMemoryBudget: EventPipelineLiveMemoryBudget
    private var evidenceBudgetBytes: Int64
    /// A fixed-size ring keeps the alert commit path O(1) and makes memory
    /// ownership explicit. Jobs carry only alert identity/time; event payloads
    /// are selected by the single worker after the alert transaction returns.
    private let evidenceQueueCapacity: Int
    private var evidenceQueue: [EvidenceCaptureRequest?]
    private var evidenceQueueHead = 0
    private var evidenceQueueTail = 0
    private var evidenceQueueCount = 0
    private var evidenceWorker: Task<Void, Never>?
    private let evidenceMonotonicNow: @Sendable () -> ContinuousClock.Instant
    private var evidenceInFlightEnqueuedAt: ContinuousClock.Instant?
    private var evidenceOperationStartedAt: ContinuousClock.Instant?
    private var evidenceAccepting = true
    private var evidenceCaptureOffered = 0
    private var evidenceCaptureCompleted = 0
    private var evidenceCaptureShed = 0
    private var evidenceCaptureInFlight = 0
    private var evidencePrefixBarrierTimeouts = 0
    private var evidenceExactContextIncomplete = 0
    private var evidenceExactContextQueryFailures = 0
    private var triggerSnapshotCompleteTotal: UInt64 = 0
    private var triggerSnapshotCompactedTotal: UInt64 = 0
    private var triggerSnapshotPoisonTotal: UInt64 = 0
    private var journalContextGapTotal: UInt64 = 0
    private var missingJournalAdmissionTotal: UInt64 = 0
    private var mismatchedJournalAdmissionTotal: UInt64 = 0
    private var evidenceShedAtShutdownDeadline = 0
    private var alertAccepting = true
    private var alertAdmissionsInFlight = 0
    private var alertsRejectedAfterSeal = 0
    private let deduplicator: AlertDeduplicator
    private let logger = Logger(subsystem: "com.maccrab.detection", category: "AlertSink")

    /// Support dir holding `builtin_rules_settings.json`. nil disables built-in
    /// rule gating (tests). v1.18.
    private let builtinSettingsDir: String?
    private var cachedBuiltinSettings = BuiltinRuleSettings()
    private var builtinSettingsMtime: Date?

    /// Counter of suppressed alerts since the sink was created. Useful for
    /// the metrics file and diagnostic surfaces.
    private(set) public var suppressedCount: Int = 0
    private(set) public var insertedCount: Int = 0
    private(set) public var evidenceRowsCaptured: Int = 0
    private(set) public var evidenceRowsPruned: Int = 0
    private(set) public var evidenceCaptureFailures: Int = 0

    /// Shared "alerts emitted" counter incremented once per successfully
    /// inserted (post-dedup) alert across EVERY emission path — the sink is
    /// the single chokepoint all ~60 alert paths flow through, so counting
    /// here is the only place that counts every alert exactly once. The
    /// daemon injects the same `LockedCounter` the heartbeat reads
    /// (`_sharedAlertCount`), so `alerts_emitted` / Prometheus `alerts_total`
    /// reflect the true total rather than only the single-event-rule path
    /// (the pre-fix ~16x undercount). A synchronous LockedCounter (not an
    /// actor) so the heartbeat's read stays a lock-guarded, actor-hop-free
    /// snapshot. Defaults to a fresh counter so existing/test constructors
    /// that don't wire the shared instance keep working.
    private let alertCounter: LockedCounter

    public init(
        alertStore: AlertStore,
        deduplicator: AlertDeduplicator,
        eventStore: EventStore? = nil,
        builtinSettingsDir: String? = nil,
        alertCounter: LockedCounter = LockedCounter(),
        evidenceBudgetBytes: Int64 = 100
            * SQLitePersistentStorePolicy.bytesPerMiB,
        evidenceQueueCapacity: Int = 512,
        journalAdmissionVerifier: (@Sendable (
            EventJournalAdmission
        ) async -> EventJournalContextStatus)? = nil,
        journalEventEnsurer: (@Sendable (
            Event
        ) async -> EventJournalContextStatus)? = nil,
        liveMemoryBudget: EventPipelineLiveMemoryBudget = .processShared,
        evidenceMonotonicNow: @escaping @Sendable () -> ContinuousClock.Instant = { ContinuousClock.now },
        evidenceCaptureOverride: (@Sendable (
            _ alertId: String,
            _ timestamp: Date
        ) async throws -> AlertEvidenceCaptureResult)? = nil
    ) {
        self.alertStore = alertStore
        self.eventStore = eventStore
        self.evidenceCaptureOverride = evidenceCaptureOverride
        self.evidenceMonotonicNow = evidenceMonotonicNow
        self.journalAdmissionVerifier = journalAdmissionVerifier
        self.journalEventEnsurer = journalEventEnsurer
        self.liveMemoryBudget = liveMemoryBudget
        self.evidenceBudgetBytes = max(0, evidenceBudgetBytes)
        self.evidenceQueueCapacity = max(1, evidenceQueueCapacity)
        self.evidenceQueue = Array(
            repeating: nil,
            count: max(1, evidenceQueueCapacity)
        )
        self.deduplicator = deduplicator
        self.builtinSettingsDir = builtinSettingsDir
        self.alertCounter = alertCounter
    }

    private func beginAlertAdmission(offers: Int) -> Bool {
        guard alertAccepting else {
            alertsRejectedAfterSeal += max(0, offers)
            return false
        }
        alertAdmissionsInFlight += 1
        return true
    }

    private func finishAlertAdmission() {
        alertAdmissionsInFlight = max(0, alertAdmissionsInFlight - 1)
    }

    /// Built-in `maccrab.*` rule gating (v1.18). Returns the (possibly
    /// severity-overridden) alert, or nil when the operator has muted it via
    /// `builtin_rules_settings.json`. Non-built-in alerts pass through unchanged.
    /// The settings file is mtime-cached so the common path is one cheap stat.
    private func applyBuiltinSettings(_ alert: Alert) -> Alert? {
        guard alert.ruleId.hasPrefix("maccrab."), let dir = builtinSettingsDir else { return alert }
        let path = BuiltinRuleSettings.path(inDir: dir)
        let mtime = (try? FileManager.default.attributesOfItem(atPath: path)[.modificationDate]) as? Date
        if mtime != builtinSettingsMtime {
            cachedBuiltinSettings = mtime == nil ? BuiltinRuleSettings() : BuiltinRuleSettings.load(fromDir: dir)
            builtinSettingsMtime = mtime
        }
        guard let setting = cachedBuiltinSettings.setting(forRuleId: alert.ruleId) else { return alert }
        if !setting.enabled { return nil }
        if let override = setting.severityOverride, override != alert.severity {
            var copy = alert
            copy.severity = override
            return copy
        }
        return alert
    }

    /// True when the alert's ACTOR is one of MacCrab's own binaries (app
    /// bundle, dev `.build`, sysext, CLI, MCP server) or the Tier-B
    /// verified-execution trampoline's scratch path. Path-based mirror of
    /// `NoiseFilter.isMacCrabProcess`, usable where only the alert (not the
    /// Event) is in hand. Real self-tamper is covered by the SelfDefense /
    /// code-signing path, so behavioral / cross-process / sequence alerts where
    /// MacCrab is the actor are self-noise.
    static func isMacCrabSelfNoise(_ processPath: String?) -> Bool {
        guard let path = processPath else { return false }
        // Installed locations: the app bundle and the system extension. Anchored
        // PREFIXES — never a bare suffix that an attacker's /tmp/maccrabd could
        // satisfy (the v1.19.3 down-weight also covers direct emissions that
        // bypass NoiseFilter, so the path test is the only gate here).
        if path.hasPrefix("/Applications/MacCrab.app/") { return true }
        if path.hasPrefix("/Library/SystemExtensions/") && path.contains("com.maccrab.agent") { return true }
        // Dev builds: the CLI / daemon / MCP binaries, but ONLY when they sit
        // inside a SwiftPM build dir or a built .app — not an arbitrary path
        // that merely ends in /maccrabd.
        let isOurBinaryName = path.hasSuffix("/maccrabd")
            || path.hasSuffix("/maccrabctl") || path.hasSuffix("/maccrab-mcp")
        if isOurBinaryName && (path.contains("/.build/") || path.contains("/DerivedData/") || path.contains("/maccrab.app/")) {
            return true
        }
        // Tier-B sandbox trampoline staging the verified plugin binary — anchored
        // to the per-user temp dir (/var/folders/.../T/, mode 0700), NOT
        // world-writable /tmp where an attacker could drop a same-named payload.
        if path.contains("/var/folders/") && path.contains("maccrab-tier-b-verified-") { return true }
        return false
    }

    /// FP recalibration (v1.19.3): DOWN-WEIGHT (never drop) two noise classes so
    /// they surface for review instead of screaming high/critical. The floor is
    /// `.low` (NOT `.informational`) so down-weighted alerts stay visible in the
    /// default dashboard / notification views — quieted, not hidden.
    ///   1. Self-noise — alerts whose actor is one of MacCrab's own binaries
    ///      (self-tamper is covered by SelfDefense, not behavioral alerts).
    ///   2. Trusted development-tooling lineage — routine bundler/runtime
    ///      behavior (esbuild/workerd/node fetch+exec, etc.).
    /// PRESERVED at full severity (must-fire) on dev paths: credential-access,
    /// keychain, honeyfile, and the catastrophic-if-real classes a malicious
    /// package is a primary delivery vector for — impact (ransomware / disk
    /// wipe), defense-evasion (SIP / Gatekeeper disable), persistence (launchd),
    /// and exfiltration. The ONLY credential exception is a self-credential tool
    /// reading its OWN credential (the GitHub CLI `gh` reading the GitHub token
    /// is its job, not theft; a real token thief is a different process).
    /// Campaign meta-alerts are skipped entirely — their severity is correlation-
    /// derived, not from one process, and dev-tooling FPs are already filtered at
    /// the contributing-alert level. Single sink chokepoint so every engine is
    /// covered uniformly; runs AFTER enrichment so the parent-lineage check sees
    /// the parent executable lifted from the event.
    private func recalibrateDevToolingSeverity(_ alert: Alert) -> Alert {
        func downweighted(_ note: String) -> Alert {
            var copy = alert
            copy.severity = .low
            copy.description = alert.description.map { "\($0) — \(note)" } ?? note
            return copy
        }

        // (1) MacCrab self-noise — any severity above the floor, regardless of
        // alert type (own-process behavioral/chain alerts are noise).
        if alert.severity > .low, Self.isMacCrabSelfNoise(alert.processPath) {
            return downweighted("Severity reduced — MacCrab's own process; self-tamper is covered by integrity/code-signing checks, not behavioral alerts.")
        }

        // (2) Campaign meta-alerts: severity is correlation-derived; do not
        // down-weight on a single contributing process's path.
        if alert.ruleId.hasPrefix("maccrab.campaign.") { return alert }

        // (3) Trusted browser reading its OWN credential store (passwords /
        // cookies / sync) — routine, and the dominant credential FP on a
        // workstation. Down-weight, but keep SYSTEM keychain access LOUD
        // (login./System.keychain is indistinguishable from theft) and ONLY for
        // a trusted browser/Electron actor — so a non-browser (e.g. the `claude`
        // CLI under ~/.local) reading credentials then beaconing still escalates.
        if alert.severity > .low, let p = alert.processPath,
           NoiseFilter.isTrustedBrowserHelper(path: p) {
            let blob = "\(alert.ruleTitle) \(alert.description ?? "")".lowercased()
            let isCredential = blob.contains("credential")
                || (alert.mitreTactics ?? "").lowercased().contains("credential")
            let isSystemKeychain = blob.contains("login.keychain") || blob.contains("system.keychain")
                || blob.contains("keychain database") || blob.contains("keychain db")
            if isCredential && !isSystemKeychain {
                return downweighted("Severity reduced — trusted browser accessing its own credential store (routine password/cookie sync); system-keychain access is still escalated.")
            }
        }

        // (4) Development-tooling lineage — high/critical only.
        guard alert.severity >= .high else { return alert }
        guard CampaignDetector.isDevelopmentToolingPath(alert.processPath)
            || CampaignDetector.isDevelopmentToolingPath(alert.parentExecutable) else { return alert }
        let tac = (alert.mitreTactics ?? "").lowercased()
        let title = alert.ruleTitle.lowercased()
        let rid = alert.ruleId.lowercased()
        // Self-credential tool: a tool reading its OWN credential domain. Kept
        // deliberately narrow (gh ↔ GitHub token) so we never weaken detection
        // of a *different* process stealing that credential.
        let basename = (alert.processPath.map { ($0 as NSString).lastPathComponent } ?? "").lowercased()
        let isSelfCredentialTool = basename == "gh" && title.contains("github token")
        let isCredentialClass = tac.contains("credential") || title.contains("credential")
            || title.contains("keychain") || rid.contains("credential")
        let isHoneyfile = title.contains("honey") || rid.contains("honey")
        // Catastrophic-if-real classes: a malicious package is a primary delivery
        // vector for exactly these, so they must keep escalating on dev paths.
        let isCatastrophic = tac.contains("impact") || tac.contains("defense_evasion")
            || tac.contains("persistence") || tac.contains("exfiltration")
        if (isCredentialClass || isHoneyfile || isCatastrophic) && !isSelfCredentialTool {
            return alert  // preserve must-fire / high-signal classes at full severity
        }
        return downweighted("Severity reduced — trusted development-tooling lineage (\(alert.processName ?? "dev tool")); routine build/runtime activity, surfaced for review not escalation.")
    }

    /// Prove the direct trigger and the already-admitted journal prefix durable
    /// before an alert row can commit. This is a precommit durability barrier,
    /// not a frozen evidence-selection epoch: post-commit evidence deliberately
    /// queries a capture-time timestamp-window superset. The direct trigger is
    /// separately supplied from the precomputed snapshot and UUID-deduplicated.
    ///
    /// A false barrier is retained as an honest context gap rather than hiding
    /// the alert. The shared trigger snapshot still survives with the alert,
    /// while telemetry makes the incomplete journal prefix operator-visible.
    private func settleJournalDurabilityBeforeCommit(
        event: Event,
        admission: EventJournalAdmission?,
        preparedTrigger: PreparedAlertTrigger
    ) async -> EventJournalContextStatus {
        if let forced = EventJournalAdmissionContext.forcedNonverifiedStatus {
            if forced == .timedOut || forced == .prefixIncomplete {
                evidencePrefixBarrierTimeouts += 1
            }
            return forced
        }
        var status: EventJournalContextStatus
        if let admission {
            if admission.eventID == event.id, admission.generation > 0,
               let baseDigest = admission.canonicalSHA256,
               baseDigest.count == 32,
               admission.canonicalByteCount > 0 {
                if let journalAdmissionVerifier {
                    status = await journalAdmissionVerifier(admission)
                    if status == .timedOut || status == .prefixIncomplete {
                        evidencePrefixBarrierTimeouts += 1
                    }
                } else {
                    status = .unavailable
                }
                guard status.isVerified else { return status }

                // A UUID-durable base is not enough when review or deferred
                // enrichment changed the alert-time Event. Require the exact
                // sanitized trigger digest to match either that base or a
                // terminal append outcome settled before this fanout began.
                guard let triggerDigest = preparedTrigger.canonicalSHA256,
                      triggerDigest.count == 32,
                      preparedTrigger.canonicalByteCount > 0 else {
                    return .poisoned
                }
                if triggerDigest == baseDigest {
                    return .verified
                }
                guard let terminal = EventJournalAdmissionContext
                    .terminalRevision,
                      terminal.eventID == event.id,
                      terminal.baseGeneration == admission.generation,
                      terminal.baseCanonicalSHA256 == baseDigest,
                      terminal.terminalCanonicalSHA256 == triggerDigest,
                      terminal.terminalCanonicalByteCount
                        == preparedTrigger.canonicalByteCount,
                      terminal.storageMutationGeneration > 0 else {
                    return .failed
                }
                if terminal.status == .timedOut
                    || terminal.status == .prefixIncomplete {
                    evidencePrefixBarrierTimeouts += 1
                }
                return terminal.status
            } else {
                if mismatchedJournalAdmissionTotal < UInt64.max {
                    mismatchedJournalAdmissionTotal += 1
                }
                // A bad receipt never authorizes the barrier. Still run the
                // universal exact ensure path when present so the trigger is
                // not lost merely because a caller supplied the wrong token.
                _ = await journalEventEnsurer?(event)
                status = .mismatchedReceipt
            }
        } else {
            if let journalEventEnsurer {
                status = await journalEventEnsurer(event)
            } else {
                if missingJournalAdmissionTotal < UInt64.max {
                    missingJournalAdmissionTotal += 1
                }
                status = .unavailable
            }
            if status == .timedOut || status == .prefixIncomplete {
                evidencePrefixBarrierTimeouts += 1
            }
        }
        return status
    }

    private func recordCommittedJournalContext(
        _ status: EventJournalContextStatus,
        alertCount: Int
    ) {
        guard !status.isVerified, alertCount > 0 else { return }
        let amount = UInt64(alertCount)
        let sum = journalContextGapTotal.addingReportingOverflow(amount)
        journalContextGapTotal = sum.overflow
            ? UInt64.max : sum.partialValue
    }

    private func recordTriggerSnapshot(
        _ disposition: PreparedAlertTrigger.Disposition
    ) {
        switch disposition {
        case .complete:
            if triggerSnapshotCompleteTotal < UInt64.max {
                triggerSnapshotCompleteTotal += 1
            }
        case .compacted:
            if triggerSnapshotCompactedTotal < UInt64.max {
                triggerSnapshotCompactedTotal += 1
            }
        case .poison:
            if triggerSnapshotPoisonTotal < UInt64.max {
                triggerSnapshotPoisonTotal += 1
            }
        }
    }

    private func prepareTrigger(
        event: Event,
        admission _: EventJournalAdmission?
    ) async -> PreparedAlertTrigger {
        // Never borrow the admission handle's payload here. The writer may
        // compact that shared handle as soon as SQLite verifies the base, while
        // this exact alert-time Event intentionally remains independent and is
        // sanitized/bounded before the alert transaction. Preflight does not
        // allocate a payload-sized copy; the shared J lease is acquired before
        // sanitizer/JSON work and dies with this scope before SQLite commit.
        let preflight: EventJournalIngressPreflight
        do {
            preflight = try EventJournalAdmissionValidator.preflight(event)
        } catch {
            return EventSnapshot.poisonTrigger(for: event)
        }
        guard let workspace = await liveMemoryBudget.acquire(
            bytes: preflight.preparationWorkspaceByteEstimate,
            owner: .journalPrepared
        ) else {
            return EventSnapshot.poisonTrigger(for: event)
        }
        do {
            let prepared = try EventJournalAdmissionValidator.prepare(
                event,
                preflight: preflight
            )
            guard prepared.event.id == preflight.eventID else {
                return EventSnapshot.poisonTrigger(for: event)
            }
            // Keep `workspace` live through compaction of canonical bytes. The
            // result is at most 64 KiB and becomes alert-owned after return.
            _ = workspace.bytes
            return EventSnapshot.prepare(prepared)
        } catch {
            return EventSnapshot.poisonTrigger(for: event)
        }
    }

    // Post-commit only: queue a small identity record and return to the alert
    // producer. Event selection, validation, SQLite accounting, and pruning all
    // run on one bounded worker lane so an alert storm cannot serialize the
    // EventLoop behind O(total-evidence) work.
    private func enqueueEvidenceCapture(
        alertId: String,
        timestamp: Date,
        triggeringCandidate: AlertEvidenceCandidate? = nil,
        journalContext: EventJournalContextStatus
    ) {
        guard evidenceCaptureOverride != nil || eventStore != nil else { return }
        evidenceCaptureOffered += 1
        guard evidenceAccepting, evidenceBudgetBytes > 0,
              evidenceQueueCount < evidenceQueueCapacity else {
            evidenceCaptureShed += 1
            // First and power-of-two losses provide an actionable signal without
            // turning an alert storm into a second log storm.
            if evidenceCaptureShed == 1
                || (evidenceCaptureShed & (evidenceCaptureShed - 1)) == 0 {
                logger.warning("Evidence capture queue shed \(self.evidenceCaptureShed, privacy: .public) job(s); capacity=\(self.evidenceQueueCapacity, privacy: .public), accepting=\(self.evidenceAccepting, privacy: .public)")
            }
            return
        }
        evidenceQueue[evidenceQueueTail] = EvidenceCaptureRequest(
            alertId: alertId,
            timestamp: timestamp,
            enqueuedAt: evidenceMonotonicNow(),
            triggeringCandidate: triggeringCandidate,
            journalContext: journalContext
        )
        evidenceQueueTail = (evidenceQueueTail + 1) % evidenceQueueCapacity
        evidenceQueueCount += 1
        startEvidenceWorkerIfNeeded()
    }

    private func dequeueEvidenceCapture() -> EvidenceCaptureRequest? {
        guard evidenceQueueCount > 0 else { return nil }
        let request = evidenceQueue[evidenceQueueHead]
        evidenceQueue[evidenceQueueHead] = nil
        evidenceQueueHead = (evidenceQueueHead + 1) % evidenceQueueCapacity
        evidenceQueueCount -= 1
        return request
    }

    private func startEvidenceWorkerIfNeeded() {
        guard evidenceWorker == nil, evidenceQueueCount > 0 else { return }
        evidenceWorker = Task { [weak self] in
            await self?.drainEvidenceQueue()
        }
    }

    private func drainEvidenceQueue() async {
        while let request = dequeueEvidenceCapture() {
            evidenceCaptureInFlight = 1
            evidenceInFlightEnqueuedAt = request.enqueuedAt
            evidenceOperationStartedAt = evidenceMonotonicNow()
            await captureEvidence(request)
            evidenceCaptureInFlight = 0
            evidenceInFlightEnqueuedAt = nil
            evidenceOperationStartedAt = nil
        }
        evidenceWorker = nil
        // Actor isolation makes the empty-check + nil transition atomic with
        // enqueue, but retain this guard as a drift-proof invariant if drain
        // gains a suspension between those operations in the future.
        startEvidenceWorkerIfNeeded()
    }

    /// Evidence selection shares the process-wide bounded decode budget with
    /// the live ingestion pipeline. A synchronous offer may therefore lose a
    /// short race without implying corruption. Keep the durable context row
    /// pending and retry only explicitly transient EventStore failures.
    /// Continuous ingestion may keep a non-blocking reader behind FIFO memory
    /// waiters for a long period, which is pressure rather than evidence loss —
    /// so the cutoff below is deliberately generous. It is NOT absent, though:
    /// before rc.32 this retried forever, and an unrelieved pressure condition
    /// pinned an evidence capture for the life of the process. Codec, authentication, and
    /// schema failures remain terminal on their first try; shutdown cancellation
    /// leaves the durable pending row as honest, restart-stable unfinished work.
    private func exactEvidenceSnapshotWithTransientRetry(
        eventStore: EventStore,
        alertTimestamp: Date,
        maxRows: Int
    ) async throws -> ExactAlertEvidenceSnapshot {
        var delay = Duration.milliseconds(10)
        // Bounded since rc.32. This was `while true`, so a pressure condition
        // that never cleared held an evidence capture forever. Both retryable
        // classes are waited out, but only inside a finite window: in-process
        // credit exhaustion (`memoryLeaseUnavailable`) in particular cannot be
        // cleared by the waiter itself.
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: Self.exactEvidenceRetryWindow)
        while true {
            try Task.checkCancellation()
            do {
                return try await eventStore.exactAlertEvidenceSnapshot(
                    alertTimestamp: alertTimestamp,
                    maxRows: maxRows
                )
            } catch let error as EventStoreError {
                switch error {
                case .busy, .memoryLeaseUnavailable:
                    guard clock.now < deadline else { throw error }
                default:
                    throw error
                }
                try await Task.sleep(for: delay)
                delay = min(delay * 2, .milliseconds(100))
            }
        }
    }

    /// Finite window for waiting out storage/credit pressure on an exact
    /// evidence read. Past it the capture fails honestly rather than pinning a
    /// capture slot indefinitely. Generous by intent: it exists to guarantee the
    /// wait terminates, not to cut short a genuinely transient pressure interval
    /// (the ownership suite exercises ~5s intervals deliberately).
    private static let exactEvidenceRetryWindow: Duration =
        .seconds(AlertEvidenceCaptureResponsiveness.exactSnapshotRetrySeconds)

    private func captureEvidence(_ request: EvidenceCaptureRequest) async {
        do {
            try Task.checkCancellation()
            let result: AlertEvidenceCaptureResult
            if let evidenceCaptureOverride {
                result = try await evidenceCaptureOverride(
                    request.alertId,
                    request.timestamp
                )
                if !request.journalContext.isVerified {
                    // Test/fault-injection captures do not expose an exact
                    // journal generation, but a known precommit admission gap
                    // must still become restart-stable durable truth.
                    try await alertStore.recordEvidenceContext(
                        AlertEvidenceContextRecord(
                            alertId: request.alertId,
                            status: .incomplete,
                            sourceMutationGeneration: 0,
                            poisonRecordCount: 0,
                            corruptRecordCount: 0,
                            journalAdmissionGapCount: 1
                        )
                    )
                    evidenceExactContextIncomplete += 1
                }
            } else {
                guard let eventStore else { return }
                try Task.checkCancellation()
                var candidates: [AlertEvidenceCandidate] = []
                if let trigger = request.triggeringCandidate {
                    candidates.append(trigger)
                }
                let remaining = max(
                    0,
                    AlertEvidencePolicy.maximumEventsPerAlert
                        - candidates.count
                )
                let exactSnapshot: ExactAlertEvidenceSnapshot?
                var selectionError: (any Error)?
                do {
                    exactSnapshot = try await
                        exactEvidenceSnapshotWithTransientRetry(
                        eventStore: eventStore,
                        alertTimestamp: request.timestamp,
                        maxRows: remaining
                    )
                    selectionError = nil
                } catch {
                    exactSnapshot = nil
                    selectionError = error
                }
                if let exactSnapshot {
                    candidates.append(contentsOf: exactSnapshot.candidates)
                }
                try Task.checkCancellation()
                var seen: Set<String> = []
                candidates = candidates.filter {
                    seen.insert($0.eventId.lowercased()).inserted
                }
                let contextRecord: AlertEvidenceContextRecord
                if let exactSnapshot {
                    let journalAdmissionGapCount = request.journalContext
                        .isVerified ? 0 : 1
                    let complete = exactSnapshot.isComplete
                        && journalAdmissionGapCount == 0
                    contextRecord = AlertEvidenceContextRecord(
                        alertId: request.alertId,
                        status: complete ? .complete : .incomplete,
                        sourceMutationGeneration:
                            exactSnapshot.mutationGeneration,
                        poisonRecordCount:
                            exactSnapshot.poisonRecords.count,
                        corruptRecordCount:
                            exactSnapshot.corruptLegacyRecords,
                        inheritedLossCount:
                            exactSnapshot.inheritedLegacyLossRecords,
                        resourceLimitedCount:
                            exactSnapshot.resourceLimitedRecords,
                        journalAdmissionGapCount:
                            journalAdmissionGapCount
                    )
                    if !complete {
                        evidenceExactContextIncomplete += 1
                    }
                } else {
                    contextRecord = AlertEvidenceContextRecord(
                        alertId: request.alertId,
                        status: .captureFailed,
                        sourceMutationGeneration: 0,
                        poisonRecordCount: 0,
                        corruptRecordCount: 0,
                        journalAdmissionGapCount:
                            request.journalContext.isVerified ? 0 : 1
                    )
                    evidenceExactContextIncomplete += 1
                    evidenceExactContextQueryFailures += 1
                }

                // Every alert commit already owns a durable `.pending` row.
                // Write evidence first and publish the terminal context state
                // only after that succeeds. A crash or context-write failure
                // therefore remains visibly pending; it can never leave rows
                // whose completeness is falsely reported as terminal.
                do {
                    result = try await alertStore.captureEvidence(
                        alertId: request.alertId,
                        candidates: candidates,
                        maxBytes: evidenceBudgetBytes
                    )
                } catch {
                    throw error
                }
                try await alertStore.recordEvidenceContext(contextRecord)
                if let selectionError {
                    logger.warning("Exact evidence selection was incomplete for alert \(request.alertId, privacy: .public): \(selectionError.localizedDescription, privacy: .public)")
                }
            }
            evidenceRowsCaptured += result.insertedRows
            evidenceRowsPruned += result.prunedRows
            evidenceCaptureCompleted += 1
        } catch is CancellationError {
            // Shutdown has a fixed deadline. A transiently blocked selection
            // cancelled at that boundary must retain the alert's atomic
            // `.pending` context as restart-stable unfinished work; it is not
            // evidence of a terminal capture failure. The live lane must still
            // settle its ownership: this is reported shed, while the durable
            // context deliberately remains pending for later recovery.
            evidenceCaptureShed += 1
            if !evidenceAccepting && Task.isCancelled {
                evidenceShedAtShutdownDeadline += 1
            }
            return
        } catch {
            // The parent insert's atomic `.pending` row is already fail-visible.
            // Advance it to a terminal failure when possible; if this write also
            // fails, leaving `.pending` is deliberately still unhealthy truth.
            try? await alertStore.recordEvidenceContext(
                AlertEvidenceContextRecord(
                    alertId: request.alertId,
                    status: .captureFailed,
                    sourceMutationGeneration: 0,
                    poisonRecordCount: 0,
                    corruptRecordCount: 0,
                    journalAdmissionGapCount:
                        request.journalContext.isVerified ? 0 : 1
                )
            )
            evidenceCaptureFailures += 1
            logger.warning("Evidence capture failed for alert \(request.alertId, privacy: .public): \(error.localizedDescription, privacy: .public)")
        }
    }

    // MARK: - Single alert with event context

    /// Submit a single alert produced outside the rule-engine batch path.
    /// Applies dedup keyed on `(alert.ruleId, event.process.executable)`,
    /// then inserts into the store. Returns `true` if the alert was inserted,
    /// `false` if it was suppressed as a duplicate. Throws on storage error
    /// so the caller can route to StorageErrorTracker (which lives in the
    /// agent-kit layer, not MacCrabCore).
    ///
    /// v1.12.6 Wave 2B: before insertion, the alert is enriched with
    /// attribution fields lifted from the triggering Event (user, CWD,
    /// AI tool, parent exec, exec sha256). Doing this in the sink — the
    /// single chokepoint — means every call site automatically picks up
    /// the new schema v5 columns without changes, and no second
    /// insertion path is introduced (preserves Pass 2 of
    /// pre-release-audit.sh: only one place writes to alerts.db).
    @discardableResult
    public func submit(
        alert: Alert,
        event: Event,
        dedupProcessPath: String? = nil,
        journalAdmission: EventJournalAdmission? = nil
    ) async throws -> Bool {
        guard beginAlertAdmission(offers: 1) else { return false }
        defer { finishAlertAdmission() }
        // v1.18: built-in maccrab.* rule mute / severity override.
        guard let settled = applyBuiltinSettings(alert) else { suppressedCount += 1; return false }
        // Prepare exactly once and before the first possible AlertStore write.
        // This value — not the raw Event — feeds both durable trigger columns.
        let effectiveAdmission = journalAdmission
            ?? EventJournalAdmissionContext.current
        let preparedTrigger = await prepareTrigger(
            event: event,
            admission: effectiveAdmission
        )
        recordTriggerSnapshot(preparedTrigger.disposition)
        // Most detections dedup on the triggering executable. Correlators may
        // supply their actual shared evidence identity (file/destination), but
        // the reservation still belongs here so it commits with the alert row
        // instead of poisoning a caller-side window on SQLite failure.
        let dedupKey = dedupProcessPath ?? event.process.executable
        // Enrich before reserving so same-evidence severity matches the row that
        // will actually be stored. A reservation blocks concurrent duplicates
        // but becomes committed dedup state only after SQLite succeeds.
        let reservedAlert = recalibrateDevToolingSeverity(
            Self.enrichWithAttribution(
                alert: settled,
                event: event,
                precomputedSnapshot: preparedTrigger.snapshotJSON
            )
        )
        let reservation: AlertDeduplicator.EmissionReservation
        switch await deduplicator.reserveEmission(
            ruleId: reservedAlert.ruleId,
            processPath: dedupKey,
            eventId: reservedAlert.ruleId.hasPrefix("maccrab.campaign.")
                ? nil : event.id.uuidString,
            tactics: reservedAlert.mitreTactics,
            severity: reservedAlert.severity
        ) {
        case .suppressed:
            suppressedCount += 1
            return false
        case .reserved(let reserved):
            reservation = reserved
        }

        let journalContext = await settleJournalDurabilityBeforeCommit(
            event: event,
            admission: effectiveAdmission,
            preparedTrigger: preparedTrigger
        )
        let enriched = Self.enrichWithAttribution(
            alert: reservedAlert,
            event: event,
            precomputedSnapshot: preparedTrigger.snapshotJSON(
                journalContext: journalContext
            )
        )

        // Shutdown may seal the sink while either the deduplicator or journal
        // barrier actor hop is suspended. Do not begin a write afterward.
        guard alertAccepting else {
            alertsRejectedAfterSeal += 1
            await deduplicator.rollbackEmission(reservation)
            return false
        }

        do {
            try await alertStore.insert(alert: enriched)
        } catch {
            await deduplicator.rollbackEmission(reservation)
            throw error
        }
        await deduplicator.commitEmission(reservation)
        recordCommittedJournalContext(journalContext, alertCount: 1)
        insertedCount += 1
        // Count this emitted alert exactly once, here at the chokepoint (post
        // built-in-mute + post-dedup) — see `alertCounter`.
        alertCounter.increment()
        enqueueEvidenceCapture(
            alertId: enriched.id,
            timestamp: enriched.timestamp,
            triggeringCandidate: preparedTrigger.evidenceCandidate,
            journalContext: journalContext
        )
        return true
    }

    // MARK: - Single alert without event context

    /// Submit a single alert that has no associated event (self-defense,
    /// ES-health, or other infrastructure alerts). Uses `alert.processPath`
    /// (when present) or `alert.ruleId` as the dedup key.
    ///
    /// v1.12.6 Wave 2B: even without an Event we set `hostName` so the
    /// alert row carries the originating machine — useful for fleet
    /// dashboards consolidating multiple hosts' alerts.
    @discardableResult
    public func submit(alert: Alert) async throws -> Bool {
        guard beginAlertAdmission(offers: 1) else { return false }
        defer { finishAlertAdmission() }
        // v1.18: built-in maccrab.* rule mute / severity override.
        guard let settled = applyBuiltinSettings(alert) else { suppressedCount += 1; return false }
        let dedupKey = settled.processPath ?? settled.ruleId
        // v1.19.3 FP recalibration (no event context — parent comes from the
        // alert as-supplied by the caller, if any).
        let enriched = recalibrateDevToolingSeverity(Self.enrichWithHostOnly(alert: settled))
        let reservation: AlertDeduplicator.EmissionReservation
        switch await deduplicator.reserveEmission(
            ruleId: enriched.ruleId,
            processPath: dedupKey,
            severity: enriched.severity
        ) {
        case .suppressed:
            suppressedCount += 1
            return false
        case .reserved(let reserved):
            reservation = reserved
        }
        guard alertAccepting else {
            alertsRejectedAfterSeal += 1
            await deduplicator.rollbackEmission(reservation)
            return false
        }
        do {
            try await alertStore.insert(alert: enriched)
        } catch {
            await deduplicator.rollbackEmission(reservation)
            throw error
        }
        await deduplicator.commitEmission(reservation)
        insertedCount += 1
        // Count this emitted alert exactly once, here at the chokepoint (post
        // built-in-mute + post-dedup) — see `alertCounter`.
        alertCounter.increment()
        enqueueEvidenceCapture(
            alertId: enriched.id,
            timestamp: enriched.timestamp,
            journalContext: .verified
        )
        return true
    }

    // MARK: - Engine batch (already noise/operator-suppression filtered)

    /// Insert a batch of alerts produced by the rule-engine path that has
    /// already applied NoiseFilter + operator suppression. The sink does not
    /// re-apply NoiseFilter; this exists so the engine path uses the same
    /// chokepoint as direct emissions and the architectural invariant holds.
    /// Per-rule dedup and same-evidence collapse are both reserved here and only
    /// committed after AlertStore succeeds. It runs highest-severity-first so
    /// the strongest same-evidence match is the one that survives.
    ///
    /// v1.12.6 Wave 2B: optional `event` parameter so the engine path
    /// (which generates N alerts from one Event) can supply the
    /// triggering Event once and have every alert enriched. Callers that
    /// already pre-populated attribution on the alert (or have no Event
    /// context, like test harnesses) pass nil and the alerts go through
    /// unchanged.
    @discardableResult
    public func insertEngineBatch(
        alerts: [Alert],
        event: Event? = nil,
        journalAdmission: EventJournalAdmission? = nil
    ) async throws -> [Alert] {
        guard !alerts.isEmpty else { return [] }
        guard beginAlertAdmission(offers: alerts.count) else { return [] }
        defer { finishAlertAdmission() }
        // v1.19.3 FP recalibration runs AFTER enrichment (so the dev-tooling
        // lineage check sees each alert's parent executable) and here too so the
        // engine batch path shares the same chokepoint as direct emissions.
        var toInsert: [Alert]
        let preparedTrigger: PreparedAlertTrigger?
        var reservations: [AlertDeduplicator.EmissionReservation] = []
        if let event {
            // All alerts in a batch share one triggering event — encode the
            // snapshot ONCE rather than per alert.
            let effectiveAdmission = journalAdmission
                ?? EventJournalAdmissionContext.current
            let trigger = await prepareTrigger(
                event: event,
                admission: effectiveAdmission
            )
            preparedTrigger = trigger
            recordTriggerSnapshot(trigger.disposition)
            let enriched = alerts.map {
                recalibrateDevToolingSeverity(Self.enrichWithAttribution(
                    alert: $0,
                    event: event,
                    precomputedSnapshot: trigger.snapshotJSON
                ))
            }
            // Reserve both dedup dimensions before writing, but do not commit
            // their windows yet. A failed batch rolls every reservation back.
            var kept: [Alert] = []
            for alert in enriched.sorted(by: { $0.severity > $1.severity }) {
                switch await deduplicator.reserveEmission(
                    ruleId: alert.ruleId,
                    processPath: event.process.executable,
                    eventId: alert.ruleId.hasPrefix("maccrab.campaign.")
                        ? nil : event.id.uuidString,
                    tactics: alert.mitreTactics,
                    severity: alert.severity
                ) {
                case .suppressed:
                    suppressedCount += 1
                    continue
                case .reserved(let reservation):
                    reservations.append(reservation)
                    kept.append(alert)
                }
            }
            toInsert = kept
        } else {
            preparedTrigger = nil
            toInsert = alerts.map { recalibrateDevToolingSeverity(Self.enrichWithHostOnly(alert: $0)) }
        }
        // The whole batch can collapse into an already-emitted direct alert on
        // the same evidence; don't hand an empty array to the store.
        guard !toInsert.isEmpty else { return [] }
        let journalContext: EventJournalContextStatus
        if let event {
            if let preparedTrigger {
                journalContext = await settleJournalDurabilityBeforeCommit(
                    event: event,
                    admission: journalAdmission
                        ?? EventJournalAdmissionContext.current,
                    preparedTrigger: preparedTrigger
                )
            } else {
                // Construction above is exhaustive, but preserve fail-closed
                // semantics if a future branch can produce an event without
                // its precommit trigger representation.
                journalContext = .poisoned
            }
            if let preparedTrigger {
                let snapshot = preparedTrigger.snapshotJSON(
                    journalContext: journalContext
                )
                toInsert = toInsert.map {
                    Self.enrichWithAttribution(
                        alert: $0,
                        event: event,
                        precomputedSnapshot: snapshot
                    )
                }
            }
        } else {
            journalContext = .verified
        }
        guard alertAccepting else {
            alertsRejectedAfterSeal += toInsert.count
            for reservation in reservations {
                await deduplicator.rollbackEmission(reservation)
            }
            return []
        }
        let persistedAlerts: [Alert]
        do {
            persistedAlerts = try await alertStore.insert(alerts: toInsert)
        } catch let partial as AlertBatchInsertFailure {
            // AlertStore commits reserve-bounded prefixes. Settle reservations in
            // the identical insertion order: only rows in the durable prefix may
            // enter dedup state; every uncommitted suffix reservation is released.
            // This also lets EventLoop recover the exact committed alerts from the
            // typed error and run their post-commit fan-out.
            for (index, reservation) in reservations.enumerated() {
                if index < partial.committedAlerts.count {
                    await deduplicator.commitEmission(reservation)
                } else {
                    await deduplicator.rollbackEmission(reservation)
                }
            }
            insertedCount += partial.committedAlerts.count
            recordCommittedJournalContext(
                journalContext,
                alertCount: partial.committedAlerts.count
            )
            alertCounter.add(partial.committedAlerts.count)
            for alert in partial.committedAlerts {
                enqueueEvidenceCapture(
                    alertId: alert.id,
                    timestamp: alert.timestamp,
                    triggeringCandidate: preparedTrigger?.evidenceCandidate,
                    journalContext: journalContext
                )
            }
            throw partial
        } catch {
            for reservation in reservations {
                await deduplicator.rollbackEmission(reservation)
            }
            throw error
        }
        for reservation in reservations {
            await deduplicator.commitEmission(reservation)
        }
        insertedCount += persistedAlerts.count
        recordCommittedJournalContext(
            journalContext,
            alertCount: persistedAlerts.count
        )
        // Count every alert in the batch exactly once (the rule-match path's
        // per-match increment was REMOVED from EventLoop so it isn't
        // double-counted) — see `alertCounter`. Callers pre-apply
        // NoiseFilter + suppression, and this method commits dedup, so
        // `toInsert` is the true emitted set.
        alertCounter.add(persistedAlerts.count)
        // Evidence capture is per-alert because each alert's window center
        // is its own timestamp. The PRIMARY KEY (alert_id, event_id) on
        // alert_evidence dedupes overlapping windows automatically.
        for alert in persistedAlerts {
            enqueueEvidenceCapture(
                alertId: alert.id,
                timestamp: alert.timestamp,
                triggeringCandidate: preparedTrigger?.evidenceCandidate,
                journalContext: journalContext
            )
        }
        // This is the authoritative post-collapse, post-commit set. Callers
        // must use it for follow-up work (not the pre-sink candidate batch),
        // otherwise they can race an absent row or analyze a suppressed alert.
        return persistedAlerts
    }

    // MARK: - Stats

    public func stats() -> (inserted: Int, suppressed: Int) {
        (insertedCount, suppressedCount)
    }

    /// Monotonic trigger-preparation truth. Release qualification requires the
    /// poison total to remain zero; compaction is a bounded alert-row outcome
    /// and must never be confused with complete canonical journal storage.
    public func triggerSnapshotStats() -> AlertTriggerSnapshotTelemetry {
        AlertTriggerSnapshotTelemetry(
            completeTotal: triggerSnapshotCompleteTotal,
            compactedTotal: triggerSnapshotCompactedTotal,
            poisonTotal: triggerSnapshotPoisonTotal,
            journalContextGapTotal: journalContextGapTotal,
            missingJournalAdmissionTotal: missingJournalAdmissionTotal,
            mismatchedJournalAdmissionTotal:
                mismatchedJournalAdmissionTotal
        )
    }

    public func evidenceStats() -> AlertEvidenceCaptureTelemetry {
        let instant = evidenceMonotonicNow()
        func age(_ started: ContinuousClock.Instant?) -> TimeInterval {
            guard let started else { return 0 }
            let elapsed = started.duration(to: instant).components
            return Double(elapsed.seconds) + Double(elapsed.attoseconds) / 1e18
        }
        // FIFO head is the oldest queued item; no per-snapshot queue traversal.
        let queuedAt = evidenceQueueCount > 0 ? evidenceQueue[evidenceQueueHead]?.enqueuedAt : nil
        let oldest = [queuedAt, evidenceInFlightEnqueuedAt].compactMap { $0 }.min()
        return AlertEvidenceCaptureTelemetry(
            offered: evidenceCaptureOffered,
            completed: evidenceCaptureCompleted,
            shed: evidenceCaptureShed,
            shedAtShutdownDeadline: evidenceShedAtShutdownDeadline,
            failures: evidenceCaptureFailures,
            pending: evidenceQueueCount,
            inFlight: evidenceCaptureInFlight,
            capturedRows: evidenceRowsCaptured,
            prunedRows: evidenceRowsPruned,
            budgetBytes: evidenceBudgetBytes,
            queueCapacity: evidenceQueueCapacity,
            accepting: evidenceAccepting,
            prefixBarrierTimeouts: evidencePrefixBarrierTimeouts,
            exactContextIncomplete: evidenceExactContextIncomplete,
            exactContextQueryFailures: evidenceExactContextQueryFailures,
            alertsRejectedAfterSeal: alertsRejectedAfterSeal,
            alertAdmissionsInFlight: alertAdmissionsInFlight,
            oldestOutstandingAgeSeconds: age(oldest),
            activeOperationAgeSeconds: age(evidenceOperationStartedAt)
        )
    }

    /// Join all work offered before this call without sealing the lane. Tests,
    /// diagnostics, and an explicit flush request use this; graceful process
    /// teardown should call `shutdownEvidenceCapture()` instead.
    public func flushEvidenceCapture() async {
        startEvidenceWorkerIfNeeded()
        while let worker = evidenceWorker {
            await worker.value
        }
    }

    /// Atomically seal alert admission and evidence admission, then wait only to
    /// the supplied deadline for work accepted before the seal. Queued evidence
    /// remaining at the deadline is moved to the terminal shed ledger; one
    /// cancellation-uncooperative in-flight job remains honestly `pending`.
    /// Call only after the producer lifecycles have been joined or cancelled.
    @discardableResult
    public func shutdownEvidenceCapture(
        timeout: Duration = .seconds(5)
    ) async -> AlertSinkShutdownResult {
        alertAccepting = false
        evidenceAccepting = false
        startEvidenceWorkerIfNeeded()

        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: timeout)
        while alertAdmissionsInFlight > 0 || evidenceWorker != nil {
            guard !Task.isCancelled, clock.now < deadline else { break }
            try? await Task.sleep(for: .milliseconds(10))
        }

        let expired = alertAdmissionsInFlight > 0 || evidenceWorker != nil
        var shedAtDeadline = 0
        if expired, evidenceQueueCount > 0 {
            shedAtDeadline = evidenceQueueCount
            while dequeueEvidenceCapture() != nil {}
            evidenceCaptureShed += shedAtDeadline
            evidenceShedAtShutdownDeadline += shedAtDeadline
        }
        if expired {
            evidenceWorker?.cancel()
        }

        let durablePendingContexts = (try? await alertStore
            .pendingEvidenceContextCount()) ?? Int.max
        return AlertSinkShutdownResult(
            completed: evidenceCaptureCompleted,
            failed: evidenceCaptureFailures,
            shedAtDeadline: evidenceShedAtShutdownDeadline,
            pending: evidenceQueueCount + evidenceCaptureInFlight,
            durablePendingContexts: durablePendingContexts,
            alertAdmissionsInFlight: alertAdmissionsInFlight,
            alertsRejectedAfterSeal: alertsRejectedAfterSeal,
            deadlineExpired: expired
        )
    }

    /// Apply a SIGHUP-reloaded evidence ownership budget before the next
    /// capture. AlertStore's combined family admission is updated separately.
    public func updateEvidenceBudget(maxBytes: Int64) {
        evidenceBudgetBytes = max(0, maxBytes)
    }

    // MARK: - Attribution enrichment (schema v5)

    /// Return a copy of `alert` with the schema-v5 attribution fields
    /// populated from the triggering Event. Existing values on the
    /// alert are preserved — i.e. a caller that already filled in
    /// `aiTool` (say, from a richer enrichment source) keeps that value;
    /// nil-fields fall through to the Event-derived defaults.
    ///
    /// Empty strings on the Event side are converted to nil here so the
    /// "" → NULL contract is enforced at the chokepoint rather than
    /// scattered through every Alert constructor.
    /// - Parameter precomputedSnapshot: when several alerts share ONE event
    ///   (the rule-engine batch path), the caller encodes the event snapshot
    ///   once and passes it here, so we don't re-encode the identical JSON
    ///   per alert. nil → encode from `event` (single-alert path).
    nonisolated static func enrichWithAttribution(
        alert: Alert, event: Event, precomputedSnapshot: String? = nil
    ) -> Alert {
        let aiTool = event.enrichments["ai_tool"] ?? event.enrichments["agent_tool"]
        let aiSession = event.enrichments["ai_tool_session_id"]
        let parentExec = event.process.ancestors.first?.executable
        let sha256 = event.process.hashes?.sha256
        // Deterministic, LLM-free "What To Do": map the alert's ATT&CK
        // tactics to MacCrab's D3FEND prevention modules. Preserve any
        // caller-supplied values (a richer LLM/IOC source already filled
        // them); only fill nil fields.
        let derivedDefense = D3FENDMapping.forTactics(alert.mitreTactics ?? "")
        let d3fend = alert.d3fendTechniques
            ?? (derivedDefense.isEmpty ? nil : derivedDefense.map { $0.id })
        let remediation = alert.remediationHint
            ?? (derivedDefense.isEmpty ? nil
                : "Defensive options: " + derivedDefense.map { "\($0.name) (\($0.id))" }.joined(separator: "; "))
        return Alert(
            id: alert.id,
            timestamp: alert.timestamp,
            ruleId: alert.ruleId,
            ruleTitle: alert.ruleTitle,
            severity: alert.severity,
            eventId: alert.eventId,
            processPath: alert.processPath,
            processName: alert.processName,
            description: alert.description,
            mitreTactics: alert.mitreTactics,
            mitreTechniques: alert.mitreTechniques,
            suppressed: alert.suppressed,
            campaignId: alert.campaignId,
            hostContext: alert.hostContext,
            analyst: alert.analyst,
            d3fendTechniques: d3fend,
            remediationHint: remediation,
            llmInvestigation: alert.llmInvestigation,
            userId: alert.userId ?? event.process.userId,
            userName: alert.userName ?? Self.nilIfEmpty(event.process.userName),
            workingDirectory: alert.workingDirectory ?? Self.nilIfEmpty(event.process.workingDirectory),
            aiTool: alert.aiTool ?? Self.nilIfEmpty(aiTool),
            parentExecutable: alert.parentExecutable ?? Self.nilIfEmpty(parentExec),
            processSha256: alert.processSha256 ?? Self.nilIfEmpty(sha256),
            hostName: alert.hostName ?? Self.defaultHostName(),
            // The sink never trusts a caller-supplied JSON blob here: it may
            // contain the raw secret-bearing Event. Production submit paths
            // pass the one precomputed, privacy-sanitized representation shared
            // with alert evidence; direct helper calls prepare the same value.
            triggeringEventsJson: precomputedSnapshot
                ?? EventSnapshot.prepare(event).snapshotJSON,
            // Wave-3 P2: tie the alert to the agent session that tripped it.
            aiToolSessionId: alert.aiToolSessionId ?? Self.nilIfEmpty(aiSession)
        )
    }

    /// Variant for alerts that have no triggering Event (self-defense,
    /// ES health, scheduled-report stubs). Only sets `hostName` — the
    /// other attribution fields stay nil since there's no source.
    nonisolated static func enrichWithHostOnly(alert: Alert) -> Alert {
        guard alert.hostName == nil else { return alert }
        return Alert(
            id: alert.id,
            timestamp: alert.timestamp,
            ruleId: alert.ruleId,
            ruleTitle: alert.ruleTitle,
            severity: alert.severity,
            eventId: alert.eventId,
            processPath: alert.processPath,
            processName: alert.processName,
            description: alert.description,
            mitreTactics: alert.mitreTactics,
            mitreTechniques: alert.mitreTechniques,
            suppressed: alert.suppressed,
            campaignId: alert.campaignId,
            hostContext: alert.hostContext,
            analyst: alert.analyst,
            d3fendTechniques: alert.d3fendTechniques,
            remediationHint: alert.remediationHint,
            llmInvestigation: alert.llmInvestigation,
            userId: alert.userId,
            userName: alert.userName,
            workingDirectory: alert.workingDirectory,
            aiTool: alert.aiTool,
            parentExecutable: alert.parentExecutable,
            processSha256: alert.processSha256,
            hostName: Self.defaultHostName()
        )
    }

    /// Resolve the host name for local alert storage. Uses
    /// `Foundation.ProcessInfo.processInfo.hostName` — same convention
    /// as FleetClient.hostId and BundleRedactor.systemDefault. Falls
    /// back to the v1.12.5 webhook/syslog default `"maccrab-host"` if
    /// the lookup returns an empty string (rare; defensive).
    nonisolated static func defaultHostName() -> String {
        let raw = Foundation.ProcessInfo.processInfo.hostName
        return raw.isEmpty ? "maccrab-host" : raw
    }

    nonisolated private static func nilIfEmpty(_ s: String?) -> String? {
        guard let s, !s.isEmpty else { return nil }
        return s
    }
}
