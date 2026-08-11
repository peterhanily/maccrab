import Foundation
import MacCrabCore
import os.log

/// Daemon configuration loaded from `daemon_config.json` in the support directory.
/// All values have sensible defaults — the config file is optional.
struct DaemonConfig: Codable {
    /// `daemon_config.json` and the dashboard overlay are control records, not
    /// bulk data. Keeping a shared explicit ceiling prevents the boot and
    /// SIGHUP paths from drifting back to unbounded Foundation reads.
    static let maximumConfigurationBytes = 1 * 1024 * 1024

    // MARK: - Behavioral Scoring
    var behaviorAlertThreshold: Double = 10.0
    var behaviorCriticalThreshold: Double = 20.0

    // MARK: - Incident Grouper
    var incidentCorrelationWindow: Double = 300
    var incidentStaleWindow: Double = 600

    // MARK: - Statistical Anomaly
    var statisticalZThreshold: Double = 3.0
    var statisticalMinSamples: Int = 50

    // MARK: - Monitor Poll Intervals (seconds)
    var esHealthPollInterval: TimeInterval = 60
    var usbPollInterval: TimeInterval = 10
    var clipboardPollInterval: TimeInterval = 3
    var browserExtensionPollInterval: TimeInterval = 120
    var ultrasonicPollInterval: TimeInterval = 60
    var ultrasonicEnabled: Bool = false  // Opt-in: requires microphone access
    /// Deception tier (honeyfiles + honey-prompts). OFF by default.
    ///
    /// v1.21.6 (audit DET-02): the tier used to be gated SOLELY on the
    /// `MACCRAB_DECEPTION=1` process environment variable. A System Extension is
    /// launched by `sysextd`, not by a shell, so there is no supported way for an
    /// operator to put that variable in its environment — meaning the deception
    /// tier was permanently inert on every DMG / Homebrew install, and with it
    /// `Rules/persistence/honeyfile_accessed.yml`, the one `suppressible: false`
    /// rule in the corpus whose false-positive rate is near-zero by construction.
    /// Mirrors `ultrasonicEnabled`: config key OR env var, so the dev env-var
    /// workflow keeps working. JSON key: `deception_enabled`.
    var deceptionEnabled: Bool = false
    var rootkitPollInterval: TimeInterval = 120
    var eventTapPollInterval: TimeInterval = 30
    var systemPolicyPollInterval: TimeInterval = 300
    /// v1.21.4: how often BTMSnapshotMonitor reconciles Background Task
    /// Management state (read-only `sfltool dumpbtm`) for ghost login items.
    var btmPollInterval: TimeInterval = 300
    /// v1.17.4: subscribe to ES NOTIFY_OPEN so credential/secret-file READ
    /// rules can fire (emission is bounded to a tight credential-dir
    /// allowlist in ESCollector). Kill-switch: set false (or
    /// `subscribe_file_open_events: false` in daemon_config.json) if the
    /// OPEN firehose ever degrades a host — the rest of detection is
    /// unaffected. Live-validated only (ES events aren't unit-testable).
    var subscribeFileOpenEvents: Bool = true

    /// v1.18: subscribe to the ES introspection family (get_task_read / trace /
    /// remote_thread_create / cs_invalidated) for memory-scrape + injection +
    /// code-sig-tamper detection. Emission is bounded to non-platform-binary
    /// actors in ESCollector. Kill-switch: set `subscribe_introspection_events:
    /// false` in daemon_config.json to disable the family independently.
    var subscribeIntrospectionEvents: Bool = true

    /// v1.21.6 (RES-05): per-client `ESMessageWorker` in-flight message cap —
    /// the stage that was silently discarding 11.8-22% of the kernel stream on a
    /// normal developer host with a hardcoded, unreachable constant. Raising it
    /// trades RSS (kernel memory is held per retained message) for coverage on a
    /// host that genuinely offers more than the parse worker can absorb; it is
    /// NOT the first thing to reach for — reduce what is ingested first (see the
    /// PERF-02 demand gate). Clamped to [256, 65536] in `ESCollector.init`.
    /// JSON key: `es_worker_max_inflight`.
    var esWorkerMaxInFlight: Int = ESCollector.maxInFlightMessages

    // MARK: - UEBA (User Entity Behaviour Analytics) — v1.21.4
    /// OFF by default. When enabled, the daemon feeds process-exec events
    /// (carrying SSH-session + executable context) into `UEBAEngine`, which
    /// baselines each user SILENTLY for the first 100 observations and then
    /// flags off-hours activity, first-seen SSH source IPs, and novel tool
    /// executions as alerts. Opt-in because per-user baselining is a
    /// behavioural signal that can be noisy on shared / multi-user hosts, and
    /// `novelTool` in particular is chatty on a developer box until the
    /// baseline warms. Local rule / sequence / campaign detection is
    /// unaffected either way. JSON key: `ueba_enabled`.
    var uebaEnabled: Bool = false

    // MARK: - Rule profile
    /// Which Sigma `status` tiers ship ENABLED at load (F-04). `"stable"`
    /// (default, since v1.21.4) enables only the curated stable corpus; the
    /// experimental and test tiers still load (their ids/titles surface) but stay
    /// disabled, keeping the daily false-positive budget honest. Set
    /// `"rule_profile": "all"` in daemon_config.json to enable every non-deprecated
    /// rule (the pre-1.21.4 behavior). Operator per-rule overlays / explicit
    /// enables (user_rules) are unaffected by this setting.
    var ruleProfile: String = "stable"

    /// v1.19 (S1-T6): suppress the self-inflicted honeyfile noise that
    /// `make test` / `make test-*` generate — the Swift test runner reading
    /// MacCrab's OWN deployed decoy files and tripping the credential/discovery
    /// rules that key on those paths. OFF in prod (dev-harness only). The
    /// must-fire `honeyfile_accessed` rule is UNAFFECTED. JSON key:
    /// `suppress_selftest_noise`. Also settable via
    /// `MACCRAB_SUPPRESS_SELFTEST_NOISE=1`.
    var suppressSelftestNoise: Bool = false

    // MARK: - Network Enrichment (opt-in; v1.19.1)
    //
    // The three features that make OUTBOUND network requests are OFF by
    // default — MacCrab's promise is on-device-by-default, so nothing about
    // your machine leaves it until you opt in. Local detection (rules,
    // sequences, campaigns, bundled IOCs) is UNAFFECTED; these only add network
    // enrichment. Each is independently toggleable (daemon_config.json key,
    // the dashboard's user_overrides.json, or `maccrabctl config set`) and is
    // honored LIVE on SIGHUP — disabling stops the egress without a restart.
    //
    //   threatIntelEnabled      — abuse.ch / URLhaus IOC feeds. Download-only
    //                             GET; nothing about your machine is uploaded.
    //   vulnScanEnabled         — osv.dev CVE lookups. POSTs your installed
    //                             app/package inventory (anonymous, but it is
    //                             your software list).
    //   packageFreshnessEnabled — npm / PyPI / Homebrew / crates freshness
    //                             checks on package installs. The GET reveals
    //                             the package name you are installing.
    //   certTransparencyEnabled — crt.sh Certificate-Transparency lookups on
    //                             observed destination domains. The GET reveals
    //                             the domain you are connecting to. (The local
    //                             typosquat check is UNAFFECTED — it makes no
    //                             network request.)
    var threatIntelEnabled: Bool = false
    var vulnScanEnabled: Bool = false
    var packageFreshnessEnabled: Bool = false
    var certTransparencyEnabled: Bool = false

    // MARK: - Prompt Injection
    var promptInjectionConfidence: Int = 40

    // MARK: - Intent Posterior (v1.12.0)
    // Top non-benign goal probability that must be reached for the
    // `maccrab.intent.bayesian-posterior` alert to fire. Strict by
    // design — single-event Sigma rules already cover lower-confidence
    // signals.
    var intentPosteriorThreshold: Double = 0.85
    // Distinct evidence types that must have accumulated before
    // emitting the posterior alert. Prevents a single observation
    // from flipping the alert despite the prior strongly favoring
    // benign.
    var intentPosteriorMinDistinctEvidence: Int = 3

    // MARK: - Storage (v1.8.0)
    //
    // Per-tier retention budgets. Pre-v1.8 used a single retentionDays +
    // maxDatabaseSizeMB pair to govern events, alerts, and campaigns
    // together — meaning a heavy event firehose would evict alert and
    // campaign history as collateral damage. v1.8 splits these into three
    // independent tiers with their own retention and size caps.
    //
    // Migration: v1.7-shape config files (top-level retentionDays /
    // maxDatabaseSizeMB) are folded into `storage` at decode time —
    // retentionDays maps onto BOTH alertsRetentionDays AND
    // campaignsRetentionDays (the union of their old behavior);
    // maxDatabaseSizeMB maps onto eventsMaxSizeMB (events were the file's
    // dominant tenant). See `migrateLegacyStorageKeys`.
    var storage: StorageConfig = StorageConfig()

    /// Three independent retention budgets — events (firehose, short),
    /// alerts (signal, long), campaigns (signal, long).
    struct StorageConfig: Codable, Equatable, Sendable {
        // Operator-controlled integers cross into Dispatch timer arithmetic,
        // Date offsets, buffer allocation, and byte conversions. Floors alone
        // do not make those operations safe: Int.max minutes, for example,
        // traps in `minutes * 60` before the timer can even be armed. Keep the
        // ceilings deliberately generous while guaranteeing every downstream
        // conversion remains finite and operationally bounded.
        static let maximumHotTierMinutes = 525_600       // one year
        static let maximumSweepIntervalMinutes = 10_080 // one week
        static let maximumRetentionDays = 3_650         // ten years
        static let maximumSizeMiB = 1_048_576            // one TiB
        /// The events writer reserves 32 MiB for one bounded transaction. The
        /// maintenance watermark needs a second reserve below hard admission,
        /// and must still leave at least one reserve of retained store. Caps
        /// below 3x the reserve cannot satisfy that invariant and previously
        /// collapsed the maintenance target to zero.
        static let minimumEventsSizeMiB = Int(
            (SQLitePersistentStorePolicy.eventTransactionReserveBytes * 3)
                / SQLitePersistentStorePolicy.bytesPerMiB
        )
        static let maximumStreamCap = 1_000_000
        static let maximumAutoGeneratedRules = 1_000_000

        /// Hot-tier retention for raw events, in MINUTES. Past this window,
        /// events are rolled into daily aggregates and the rows deleted
        /// from the events table.
        ///
        /// Default 30 minutes: 3× the longest sequence-rule window
        /// (`ransomware_kill_chain.yml` at 10 minutes) so the SequenceEngine
        /// has a safe rebuild headroom on rule-reload / daemon-restart.
        /// Floor enforcement (DaemonSetup) clamps to 15 min — anything
        /// shorter risks dropping events mid-sequence.
        ///
        /// Renamed from `eventsHotTierHours` in v1.8.0 because 1h was
        /// already too long for most workloads; the granularity needed to
        /// be sub-hour configurable. Legacy `eventsHotTierHours` keys are
        /// folded onto this field by `migrateLegacyStorageKeys` (× 60).
        var eventsHotTierMinutes: Int = 30

        /// Per-category retention FLOOR for the low-volume process/exec
        /// channel, in MINUTES. Process-category rows newer than this cutoff
        /// are spared by the size-cap eviction paths (adaptive rollup + the
        /// oldest-first row-count fallback) even when a cheap file-write flood
        /// has collapsed the general retention window.
        ///
        /// Rationale: file + exec share one events.db, and a benign file storm
        /// can balloon the file ~30× and evict the low-volume — but high-value
        /// — process/exec rows (and their attribution) as collateral. This
        /// floor inverts that: non-process rows are evicted first, and recent
        /// process rows survive up to `processEventsFloorMinutes`. Because the
        /// default (60) exceeds `eventsHotTierMinutes` (30), process rows also
        /// get a longer guaranteed hot-tier window than the general firehose.
        ///
        /// SOFT floor: if the protected process rows within this window ALONE
        /// exceed `eventsMaxSizeMB`, the size-cap sweep falls back to
        /// oldest-first even on process rows (the pruneOldest safety valve), so
        /// events.db can never grow unbounded. Set 0 to disable the floor
        /// entirely (fully category-blind, pre-v1.21.4 behavior).
        ///
        /// JSON key mapping: both `process_events_floor_minutes` (snake_case)
        /// and `processEventsFloorMinutes` (camelCase) decode to this field via
        /// the storage block's snake-rewrite. See `migrateLegacyStorageKeys`.
        var processEventsFloorMinutes: Int = 60

        /// Legacy combined event+evidence envelope, in MB. Since schema v8
        /// moved new alert evidence to alerts.db, the steady-state events.db
        /// family cap is `eventsMaxSizeMB - evidenceMaxSizeMB`; the alerts.db
        /// family cap is `alertsMaxSizeMB + evidenceMaxSizeMB`. Their exact sum
        /// remains `eventsMaxSizeMB + alertsMaxSizeMB`, so the ownership move
        /// neither raises the steady-state disk budget nor labels 440 MiB as an
        /// event-only allowance.
        ///
        /// Upgrades are different: the preserved legacy
        /// `events.db.alert_evidence` table can still own as much as the full
        /// evidence allocation. Daemon startup measures that table and adds a
        /// bounded transition reserve to the steady-state events family. The
        /// reserve is never larger than `evidenceMaxSizeMB`, is zero on a fresh
        /// install, and shrinks as legacy rows age out. A failed measurement
        /// retains the full reserve (fail-safe for evidence availability). Use
        /// the transition-aware accessor below at every live admission and
        /// maintenance site; the property alone is the steady-state value.
        ///
        /// The adaptive rollup
        /// tightens the cutoff (1h → 30m → 15m) if needed to stay under
        /// this. Last-resort row-count prune kicks in if even the tightest
        /// cutoff can't fit.
        ///
        /// v1.19.0: raised 200 → 350. The events.db FILE holds more than the
        /// events table — it also carries `alert_evidence` (its own ~100 MB
        /// sub-cap) and the events FTS5 search index (~60 MB on a busy host).
        /// Those two alone are ~160 MB before a single event row, so a 200 MB
        /// file cap could never be honoured on an active machine (the file
        /// settled ~300 MB; rc.2 live-test finding D4). 350 is honest about the
        /// file's real components. The events working set is still bounded by
        /// `eventsHotTierMinutes`; this only relaxes the whole-FILE ceiling.
        ///
        /// v1.21.4: raised 350 → 420. This cap is enforced against the full
        /// on-disk FOOTPRINT (`measureDatabaseFootprintMB` = db + -wal + -shm),
        /// but the 350 justification above only accounted for the main-file
        /// floor (~300 MB) and omitted the ≤64 MB WAL sidecar the footprint
        /// measurement itself includes (+ ~4 MB shm). So even a healthy file at
        /// its ~300 MB floor could measure ~300 + 64 + 4 ≈ 368 MB, and the
        /// enforcer target `0.8 × 350 = 280 MB` sat BELOW the ~300 MB floor —
        /// meaning the hourly sweep never converged and prune+VACUUMed on every
        /// tick (perpetual file rewrites that fed both RSS churn and CPU). 420
        /// makes the target `0.8 × 420 = 336 MB` sit above the ~300 MB floor so
        /// the sweep converges instead of churning. Working set still bounded by
        /// `eventsHotTierMinutes`.
        ///
        /// v1.21.6 (PERF-03) — that convergence claim DID NOT HOLD under
        /// ordinary developer activity, and the cap is not a fix for the write
        /// volume underneath it. Field-sampled every 9 s on the author's host:
        /// 325.9 → 423.6 → 519.7 → 567.6 MB, then 291.6 MB (276 MB reclaimed in
        /// under 9 s), and the same cycle again 4 minutes later — a peak footprint
        /// of 587 MB with WAL, i.e. 140% of this cap, plus a multi-hundred-MB file
        /// rewrite every few minutes. Sustained ~1.59 MB/s of DB writes
        /// (~137 GB/day) at ~7,214 on-disk bytes per event.
        ///
        /// A broad cap increase by itself would only move that thrash point. The
        /// release therefore first removes avoidable write volume with the
        /// PERF-02 demand gate and relevance-aware physical-row suppression.
        /// EventStore's duplicated raw_json + typed-column + FTS cost remains a
        /// separate write-amplification concern, and the rc.12 cap correction is
        /// not evidence that the runtime <=1 MiB/s write-rate contract is met.
        /// v1.21.6-rc.12: raised 420 → 440 after an installed-host measurement put
        /// the irreducible 15-minute family footprint at 302.7 decimal MB. The
        /// live upgrade cap was 353 MiB, whose 80% target was only 296.1 MB;
        /// the file-lane reserve also stopped growth below that floor. The
        /// 20 MiB correction leaves measured headroom above both boundaries
        /// without weakening the 15-minute forensic floor. Explicit operator
        /// values remain authoritative; this changes only the shipped default.
        var eventsMaxSizeMB: Int = 440

        /// Cadence (in minutes) for the events.db size-cap enforcer.
        ///
        /// v1.12.6: pre-fix the size-cap timer was hardcoded to 6 hours.
        /// On a busy machine (`~47 MB/min` event firehose observed on
        /// field hosts) the DB could overrun a 300 MB cap by ~17 GB
        /// between sweeps. Exposing the cadence here lets operators
        /// match the cadence to their workload: workhorse hosts may
        /// want 5 min; idle hosts can stay at 60 min to save CPU.
        ///
        /// Default: 60 min (1 h). A 0/negative override is clamped to
        /// the default at scheduling time with a warning logged.
        ///
        /// JSON key mapping: both `events_size_cap_interval_minutes`
        /// (snake_case) and `eventsSizeCapIntervalMinutes` (camelCase)
        /// decode to this field via the storage block's snake-rewrite.
        /// See `migrateLegacyStorageKeys` for the rewrite table.
        ///
        /// An out-of-band early-fire watchdog (60 s cadence) catches
        /// sudden growth bursts between scheduled sweeps when the DB
        /// exceeds 1.5× the configured cap. The watchdog is not
        /// configurable — it is a defense-in-depth guarantee that the
        /// disk budget is never radically violated regardless of the
        /// scheduled cadence the operator picked.
        var eventsSizeCapIntervalMinutes: Int = 60

        /// Days of `event_aggregates` rows to keep. Aggregates are tiny
        /// (one row per day per category per signer per path); 90d is
        /// cheap and useful for "what did this machine do last Tuesday?".
        var aggregateDays: Int = 90

        /// Alert retention, in days. Alerts are small (~1-10 KB each) and
        /// intrinsically valuable; defaulting to a year captures the
        /// forensic horizon most operators want. Independent of events —
        /// a year of alert history won't blow the disk because the alert
        /// rate is orders of magnitude lower than the event rate.
        var alertsRetentionDays: Int = 365

        /// Hard cap on the alerts.db file size, in MB.
        var alertsMaxSizeMB: Int = 100

        /// Hard ownership cap for slim `alerts.db.alert_evidence`. The alerts
        /// and evidence knobs remain independently enforceable inside the same
        /// family; combined hard admission uses their exact sum. Existing
        /// `events.db.alert_evidence` rows are preserved read-only-for-new-
        /// capture and retained/cleaned as legacy data without migration.
        ///
        /// v1.17.5: the legacy table
        /// was governed only by age (alertsRetentionDays) + a per-alert row
        /// cap, NOT by total size, so on a busy host it ballooned past the
        /// events cap (field-observed 194 MB). Oldest rows are evicted once
        /// the table's raw_json payload exceeds this. (RC H2)
        var evidenceMaxSizeMB: Int = 100

        /// Authoritative per-family caps after evidence ownership moved. Keep
        /// these calculations centralized: boot, SIGHUP, timers, and heartbeat
        /// must never rediscover the subtraction/addition independently.
        var effectiveEventsFamilyMaxSizeMB: Int {
            max(
                Self.minimumEventsSizeMiB,
                eventsMaxSizeMB - evidenceMaxSizeMB
            )
        }

        /// Live events-family ceiling while preserved legacy evidence remains.
        /// The caller supplies the measured, rounded-up legacy ownership; the
        /// configured evidence tier is an absolute ceiling on transition cost.
        func effectiveEventsFamilyMaxSizeMB(
            legacyEvidenceTransitionReserveMiB requestedReserve: Int
        ) -> Int {
            let reserve = min(
                evidenceMaxSizeMB,
                max(0, requestedReserve)
            )
            let (sum, overflow) = effectiveEventsFamilyMaxSizeMB
                .addingReportingOverflow(reserve)
            return overflow ? Int.max : sum
        }

        /// Runtime ceiling for a reserve already admitted by the two-phase
        /// transition controller. Unlike the candidate helper above, this does
        /// not clamp to the *new* evidence knob: a config reload may lower that
        /// knob while the old physical DB/WAL/freelist still requires a larger
        /// temporary allowance. The controller keeps that allowance explicit
        /// as `appliedReserveMiB` until a fresh generation-matched footprint
        /// proof says the lower candidate is safe.
        func effectiveEventsFamilyMaxSizeMB(
            appliedLegacyEvidenceTransitionReserveMiB appliedReserve: Int
        ) -> Int {
            let (sum, overflow) = effectiveEventsFamilyMaxSizeMB
                .addingReportingOverflow(max(0, appliedReserve))
            return overflow ? Int.max : sum
        }

        var effectiveAlertsFamilyMaxSizeMB: Int {
            let (sum, overflow) = alertsMaxSizeMB.addingReportingOverflow(
                evidenceMaxSizeMB
            )
            return overflow ? Int.max : sum
        }

        var configuredEventsAndAlertsTotalMaxSizeMB: Int {
            let (sum, overflow) = eventsMaxSizeMB.addingReportingOverflow(
                alertsMaxSizeMB
            )
            return overflow ? Int.max : sum
        }

        /// Honest live envelope including the bounded upgrade reserve. This is
        /// intentionally separate from the operator's steady-state total.
        func configuredEventsAndAlertsTotalMaxSizeMB(
            legacyEvidenceTransitionReserveMiB requestedReserve: Int
        ) -> Int {
            let reserve = min(
                evidenceMaxSizeMB,
                max(0, requestedReserve)
            )
            let (sum, overflow) = configuredEventsAndAlertsTotalMaxSizeMB
                .addingReportingOverflow(reserve)
            return overflow ? Int.max : sum
        }

        /// Honest live combined ceiling for the reserve already applied by the
        /// transition controller. This intentionally does not clamp to a newly
        /// lowered evidence knob; doing so would hide the bounded, still-
        /// physical upgrade allowance from heartbeat and SIGHUP diagnostics.
        func configuredEventsAndAlertsTotalMaxSizeMB(
            appliedLegacyEvidenceTransitionReserveMiB appliedReserve: Int
        ) -> Int {
            let (sum, overflow) = configuredEventsAndAlertsTotalMaxSizeMB
                .addingReportingOverflow(max(0, appliedReserve))
            return overflow ? Int.max : sum
        }

        /// Campaign retention, in days. Campaigns are the highest-density
        /// signal in the store — even a year is tiny.
        var campaignsRetentionDays: Int = 365

        /// Hard cap on the campaigns.db file size, in MB.
        var campaignsMaxSizeMB: Int = 50

        // MARK: TraceGraph + OTLP traces (v1.18.0)
        //
        // Pre-v1.18 these two stores had retention + size caps HARDCODED
        // in DaemonTimers (tracegraph 90d / 250 MB, traces 90d / 100 MB)
        // and were absent from daemon_config.json — operators could
        // neither see nor tune them. tracegraph.db in particular
        // accumulated the causal-graph substrate (entities/edges) with no
        // reclaim path and was field-observed at 17 GB. These knobs
        // surface both, and the substrate now has its own retention sweep
        // (SQLiteCausalGraphStore.pruneOrphanedGraph / pruneOldestGraph).

        /// TraceGraph (tracegraph.db) retention, in days. Governs both
        /// expired-trace pruning AND the orphaned entity/edge substrate
        /// sweep that bounds the file's dominant tables.
        var tracegraphRetentionDays: Int = 90

        /// Hard cap on tracegraph.db, in MB. Over cap, the daemon evicts
        /// the oldest unreferenced graph substrate (by last_seen) until
        /// back under budget.
        var tracegraphMaxSizeMB: Int = 250

        /// OTLP span trace (traces.db) retention, in days.
        var tracesRetentionDays: Int = 90

        /// Hard cap on traces.db, in MB.
        var tracesMaxSizeMB: Int = 100

        /// v1.21.4 (F2/A3): depth of the split merged-stream detection buffers,
        /// in events. The priority stream carries exec/network/tcc/auth; the
        /// file stream carries the high-volume file-write family. Bursts above a
        /// stream's cap evict its oldest queued event (visible as
        /// `merged_priority_dropped_total` / `merged_file_dropped_total`). Raise
        /// the file cap to absorb bigger file floods (trades RAM for headroom;
        /// it does NOT raise throughput). Keep each <= a few hundred k.
        var mergedPriorityStreamCap: Int = 100_000
        var mergedFileStreamCap: Int = 100_000

        // MARK: Generated artifacts (v1.18.0)
        //
        // Directory-based daemon outputs that previously had no retention.
        // (Forensic case retention lives app-side under the
        // `forensics.retentionDays` setting — the daemon does not own the
        // user's Cases/ directory.)

        /// Retention, in days, for generated report files under
        /// `<support>/reports/`. 0 disables the sweep (keep forever).
        var reportsRetentionDays: Int = 90

        /// Max auto-generated rule files to keep under
        /// `<support>/compiled_rules/auto_generated/` (oldest pruned
        /// first). 0 disables the cap.
        var autoGeneratedRulesMax: Int = 200

        /// Clamp every knob to a floor that keeps the tier functional.
        /// `daemon_config.json` is operator-editable, so a hand-typed `0` or a
        /// negative reaches the daemon verbatim: `traces_retention_days: 0`
        /// prunes every span the moment it lands,
        /// `events_size_cap_interval_minutes: 0` re-arms the sweep timer on a
        /// zero deadline (a spin), and a negative size cap makes its enforcer
        /// delete without ever converging.
        ///
        /// This lives here, on the type, because it must run at BOTH config
        /// entry points — boot (`DaemonSetup`) and SIGHUP reload
        /// (`SignalHandlers`). Those two carried separate hand-maintained
        /// copies of the clamp list, and eight tiers added after the list was
        /// written were folded into neither, so a reload could re-admit values
        /// boot had rejected. One function, two call sites.
        func clampedToSafeFloors() -> Self {
            var s = self
            // 15 min: the longest sequence rule (ransomware_kill_chain.yml)
            // needs a 10-minute window; anything shorter drops events
            // mid-sequence.
            s.eventsHotTierMinutes = min(
                Self.maximumHotTierMinutes,
                max(15, s.eventsHotTierMinutes)
            )
            // 0 is the documented "disable the category floor" value.
            s.processEventsFloorMinutes = min(
                Self.maximumHotTierMinutes,
                max(0, s.processEventsFloorMinutes)
            )
            s.eventsSizeCapIntervalMinutes = min(
                Self.maximumSweepIntervalMinutes,
                max(1, s.eventsSizeCapIntervalMinutes)
            )
            // The envelope must have room for both the event-family operational
            // minimum and the minimum independently-budgeted evidence tier.
            s.eventsMaxSizeMB = min(
                Self.maximumSizeMiB,
                max(Self.minimumEventsSizeMiB + 50, s.eventsMaxSizeMB)
            )
            s.aggregateDays = min(Self.maximumRetentionDays, max(1, s.aggregateDays))
            s.alertsRetentionDays = min(Self.maximumRetentionDays, max(1, s.alertsRetentionDays))
            s.alertsMaxSizeMB = min(Self.maximumSizeMiB, max(50, s.alertsMaxSizeMB))
            // Evidence is an allocation *inside* eventsMaxSizeMB's historical
            // envelope. Clamp an impossible request down instead of silently
            // increasing the global disk budget. The subtraction is safe after
            // the envelope floor above.
            s.evidenceMaxSizeMB = min(
                s.eventsMaxSizeMB - Self.minimumEventsSizeMiB,
                min(Self.maximumSizeMiB, max(50, s.evidenceMaxSizeMB))
            )
            s.campaignsRetentionDays = min(Self.maximumRetentionDays, max(1, s.campaignsRetentionDays))
            s.campaignsMaxSizeMB = min(Self.maximumSizeMiB, max(50, s.campaignsMaxSizeMB))
            s.tracegraphRetentionDays = min(Self.maximumRetentionDays, max(1, s.tracegraphRetentionDays))
            s.tracegraphMaxSizeMB = min(Self.maximumSizeMiB, max(50, s.tracegraphMaxSizeMB))
            s.tracesRetentionDays = min(Self.maximumRetentionDays, max(1, s.tracesRetentionDays))
            s.tracesMaxSizeMB = min(Self.maximumSizeMiB, max(50, s.tracesMaxSizeMB))
            s.reportsRetentionDays = min(Self.maximumRetentionDays, max(1, s.reportsRetentionDays))
            s.mergedPriorityStreamCap = min(Self.maximumStreamCap, max(1000, s.mergedPriorityStreamCap))
            s.mergedFileStreamCap = min(Self.maximumStreamCap, max(1000, s.mergedFileStreamCap))
            // NOT max(1, …): 0 is the documented "no cap" value for this one.
            // Only a negative is nonsense.
            s.autoGeneratedRulesMax = min(
                Self.maximumAutoGeneratedRules,
                max(0, s.autoGeneratedRulesMax)
            )
            return s
        }
    }

    // MARK: - LLM Backend
    var llm: LLMConfig = LLMConfig()

    // MARK: - Outputs
    //
    // Additional alert sinks beyond the existing webhook / syslog /
    // notification paths. Each entry becomes a `FileOutput` or
    // `StreamOutput` instance in DaemonSetup.
    //
    // Example daemon_config.json.outputs:
    //   "outputs": [
    //     {"type": "file", "path": "/var/log/maccrab/alerts.jsonl", "format": "ocsf", "maxMb": 100},
    //     {"type": "splunk_hec", "url": "https://hec.example.com", "tokenEnv": "SPLUNK_HEC_TOKEN"},
    //     {"type": "elastic_bulk", "url": "https://es.example.com/_bulk", "tokenEnv": "ES_AUTH_HEADER", "indexName": "sec-alerts"}
    //   ]
    var outputs: [OutputSpec] = []

    struct OutputSpec: Codable {
        /// "file" | "splunk_hec" | "elastic_bulk" | "datadog_logs" |
        /// "wazuh_api" | "s3" | "sftp"
        var type: String
        // file-specific
        var path: String?
        var format: String?        // "ocsf" | "native"
        var maxMb: Int?
        var maxAgeHours: Double?
        var maxArchives: Int?
        // stream-specific
        var url: String?
        var token: String?         // literal value (avoid — prefer tokenEnv)
        var tokenEnv: String?      // env var name to read the token from
        var indexName: String?
        var retryCount: Int?
        var timeoutSeconds: Double?
        // s3-specific
        var bucket: String?
        var region: String?
        var keyPrefix: String?
        var accessKeyEnv: String?      // env var name for AWS access key
        var secretKeyEnv: String?      // env var name for AWS secret key
        var sessionTokenEnv: String?   // env var name for AWS STS session token
        var endpoint: String?          // S3-compatible endpoint (MinIO, R2)
        var maxBatchBytes: Int?
        // sftp-specific
        var host: String?
        var port: Int?
        var user: String?
        var keyPath: String?           // path to SSH private key on disk
        var remotePath: String?
        var flushIntervalSeconds: Double?
    }

    // MARK: - Loading

    /// Load config from a JSON file, falling back to defaults for missing keys.
    ///
    /// v1.6.14: after parsing the primary `daemon_config.json` from the
    /// daemon's support directory, overlay a small user-writable
    /// overrides file so the MacCrab.app Settings sliders for
    /// `maxDatabaseSizeMB` and `retentionDays` actually reach the
    /// sysext. The dashboard runs as a non-root GUI process and can't
    /// write `/Library/Application Support/MacCrab/daemon_config.json`;
    /// it writes instead to `~/Library/Application Support/MacCrab/
    /// user_overrides.json`, which the daemon overlays on top of the
    /// system config here. Overrides are clamped by the same floors
    /// (50 MB / 1 d) the daemon already applies, so a hostile local
    /// config can't evict telemetry.
    static func load(from directory: String, applyOverrides: Bool = true) -> DaemonConfig {
        let path = directory + "/daemon_config.json"
        var config: DaemonConfig
        if let data = BoundedRegularFileReader.read(
            at: path,
            maximumBytes: maximumConfigurationBytes
        ) {
            config = decode(data) ?? DaemonConfig()
        } else {
            config = DaemonConfig()
        }

        // v1.7.6: applyUserOverrides resolves each validated local user's
        // Application Support directory independently of `directory`. That is
        // real production behavior, but it can leak the developer's overrides
        // into tests that pass a temp `directory`; tests opt out with
        // applyOverrides:false.
        if applyOverrides {
            applyUserOverrides(into: &config)
        }
        return config
    }

    /// F-04: map the operator's `rule_profile` to the Sigma-status set the
    /// engines enable — nil means "all" (every non-deprecated rule).
    ///
    /// corr-detection #273: validate the value against the known set. A typo
    /// ("stabel", "full", …) previously fell through to "stable" SILENTLY — an
    /// operator who set rule_profile: all with a typo ran with ~352 rules
    /// disabled and no signal. Warn loudly and keep the safe default (stable)
    /// on an unrecognized value.
    ///
    /// v1.21.5: extracted from DaemonSetup so the boot path and the SIGHUP
    /// reload path (SignalHandlers) share one mapping — the profile now gates
    /// sequence + graph rules too, not just single-event rules.
    static func enabledRuleStatuses(forProfile rawProfile: String) -> Set<String>? {
        switch rawProfile.lowercased() {
        case "all":
            return nil
        case "stable":
            return ["stable"]
        default:
            logger.warning("Unknown rule_profile '\(rawProfile)' — expected 'stable' or 'all'. Falling back to 'stable'.")
            print("Warning: unknown rule_profile '\(rawProfile)' — expected 'stable' or 'all'. Using 'stable'.")
            return ["stable"]
        }
    }

    /// Decode `daemon_config.json` data, handling two long-standing
    /// hazards in one place:
    ///
    /// 1. **Trailing-uppercase abbreviations.** `JSONDecoder` with
    ///    `.convertFromSnakeCase` turns `max_database_size_mb` into
    ///    `maxDatabaseSizeMb` (lowercase `b`), but the Swift property
    ///    is `maxDatabaseSizeMB`. The decode fails with `keyNotFound`.
    ///
    /// 2. **Auto-synthesized Decodable ignores property defaults.**
    ///    A partial `daemon_config.json` (only a few keys set) fails
    ///    decode because every non-Optional property must appear in
    ///    the JSON. Default-value declarations on stored properties
    ///    only apply to the memberwise init, not the synthesized
    ///    `init(from:)`.
    ///
    /// Combined, these two meant any `try?`-guarded load silently
    /// dropped the whole file on partial or snake_case configs —
    /// operators who copied the CLAUDE.md example got full defaults
    /// on every field, not just the one they expected.
    ///
    /// v1.6.14 fix: mutate the JSON dict in place, rewriting known
    /// snake_case keys to their exact camelCase property names, then
    /// overlay the user's keys onto a freshly-encoded "defaults dict"
    /// produced from `DaemonConfig()`. That gives us complete coverage
    /// of every field, so decode succeeds even when the operator only
    /// sets the handful of keys they actually want to override.
    static func decode(_ data: Data) -> DaemonConfig? {
        guard var userObj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }

        let snakeToCamel: [String: String] = [
            "behavior_alert_threshold": "behaviorAlertThreshold",
            "behavior_critical_threshold": "behaviorCriticalThreshold",
            "incident_correlation_window": "incidentCorrelationWindow",
            "incident_stale_window": "incidentStaleWindow",
            "statistical_z_threshold": "statisticalZThreshold",
            "statistical_min_samples": "statisticalMinSamples",
            "es_health_poll_interval": "esHealthPollInterval",
            "usb_poll_interval": "usbPollInterval",
            "clipboard_poll_interval": "clipboardPollInterval",
            "browser_extension_poll_interval": "browserExtensionPollInterval",
            "ultrasonic_poll_interval": "ultrasonicPollInterval",
            "ultrasonic_enabled": "ultrasonicEnabled",
            // v1.21.6 (audit DET-02): without this entry the key would decode as
            // the default and the config gate would be a silent no-op — exactly
            // the `rule_profile` bug recorded below.
            "deception_enabled": "deceptionEnabled",
            "rootkit_poll_interval": "rootkitPollInterval",
            "event_tap_poll_interval": "eventTapPollInterval",
            "system_policy_poll_interval": "systemPolicyPollInterval",
            "btm_poll_interval": "btmPollInterval",
            // v1.21.4 (audit): these 4 keys were added to the struct but never
            // to this map, so the JSONDecoder (no `.convertFromSnakeCase`) never
            // matched the snake_case key and silently used the default. Most
            // importantly `rule_profile: "all"` — the documented F-04 override to
            // re-enable the experimental rule corpus — was a complete no-op.
            "rule_profile": "ruleProfile",
            "subscribe_file_open_events": "subscribeFileOpenEvents",
            "subscribe_introspection_events": "subscribeIntrospectionEvents",
            // v1.21.6 (RES-05): without this entry the snake key decodes as the
            // default and the knob is a silent no-op — the exact `rule_profile`
            // and `deception_enabled` bug recorded above.
            "es_worker_max_inflight": "esWorkerMaxInFlight",
            "ueba_enabled": "uebaEnabled",
            "suppress_selftest_noise": "suppressSelftestNoise",
            // v1.19.1 opt-in network-enrichment flags
            "threat_intel_enabled": "threatIntelEnabled",
            "vuln_scan_enabled": "vulnScanEnabled",
            "package_freshness_enabled": "packageFreshnessEnabled",
            "cert_transparency_enabled": "certTransparencyEnabled",
            "prompt_injection_confidence": "promptInjectionConfidence",
            // v1.12.0 intent posterior thresholds
            "intent_posterior_threshold": "intentPosteriorThreshold",
            "intent_posterior_min_distinct_evidence": "intentPosteriorMinDistinctEvidence",
            // v1.8.0 legacy keys: rewritten in place by migrateLegacyStorageKeys
            // below. Keeping the snake_case → camelCase rewrite here so the
            // legacy migrator sees a consistent input dict.
            "max_database_size_mb": "maxDatabaseSizeMB",
            "retention_days": "retentionDays",
            // v1.8.0 storage block — snake_case nested keys also rewrite, so
            // operators can write storage.events_hot_tier_hours and have it
            // decode correctly. The nested block itself is rewritten inside
            // migrateLegacyStorageKeys.
        ]
        for (snake, camel) in snakeToCamel where userObj[snake] != nil && userObj[camel] == nil {
            userObj[camel] = userObj.removeValue(forKey: snake)
        }

        // v1.8.0: fold legacy top-level retention/size keys into the new
        // storage{} block, then snake-case-rewrite the storage block's own
        // keys.
        migrateLegacyStorageKeys(in: &userObj)

        // Build a "complete defaults" dict by encoding a blank
        // DaemonConfig, then overlay the user's keys on top. This
        // gives us a JSON payload that contains every key the
        // synthesized decoder expects, regardless of how sparse the
        // user's file is.
        //
        // v1.8.0: shallow-overlay was wrong for nested structs like
        // `storage` and `llm`. A user setting only `storage.alertsRetentionDays`
        // would replace the entire defaults storage dict with a partial
        // one — making the synthesized StorageConfig decoder fail
        // (missing eventsHotTierHours, etc.). Deep-merge dict-typed values
        // one level so the user's keys overlay onto defaults, not replace.
        let encoder = JSONEncoder()
        guard let defaultsData = try? encoder.encode(DaemonConfig()),
              var merged = try? JSONSerialization.jsonObject(with: defaultsData) as? [String: Any] else {
            return nil
        }
        for (k, v) in userObj {
            if let userDict = v as? [String: Any],
               let defaultDict = merged[k] as? [String: Any] {
                var combined = defaultDict
                for (subK, subV) in userDict {
                    combined[subK] = subV
                }
                merged[k] = combined
            } else {
                merged[k] = v
            }
        }

        guard let mergedData = try? JSONSerialization.data(withJSONObject: merged) else {
            return nil
        }
        return try? JSONDecoder().decode(DaemonConfig.self, from: mergedData)
    }

    /// Recognize the exact seven-key storage block emitted by the Settings UI
    /// before the rc.12 events-envelope rebaseline. This is intentionally an
    /// exact fingerprint: a partial file, any tuned companion value, any extra
    /// storage knob, or the current Settings generation marker is an operator
    /// override and remains authoritative.
    ///
    /// The old generated events value inherits the already-decoded system
    /// configuration instead of blindly becoming 440. With the shipped config
    /// that inherited value is 440; if an administrator explicitly configured
    /// a different envelope in daemon_config.json, the stale generated UI
    /// default no longer shadows it.
    @discardableResult
    static func rebaselineGeneratedSettingsStorage(
        _ storage: inout [String: Any],
        inheritedEventsMaxSizeMB: Int
    ) -> Bool {
        let generationKey = "settingsDefaultsGeneration"
        guard storage[generationKey] == nil else { return false }

        let generatedValues: [String: Int] = [
            "eventsHotTierMinutes": 30,
            "eventsMaxSizeMB": 420,
            "alertsRetentionDays": 365,
            "alertsMaxSizeMB": 100,
            "evidenceMaxSizeMB": 100,
            "campaignsRetentionDays": 365,
            "campaignsMaxSizeMB": 50,
        ]
        guard Set(storage.keys) == Set(generatedValues.keys) else {
            return false
        }
        for (key, value) in generatedValues {
            guard storage[key] as? Int == value else { return false }
        }

        storage["eventsMaxSizeMB"] = inheritedEventsMaxSizeMB
        return true
    }

    /// Object-level gate retained separately so legacy top-level cap spellings
    /// are examined before `migrateLegacyStorageKeys` consumes the camel-case
    /// one. Their presence is explicit operator provenance and must prevent the
    /// generated-default classifier even when the nested tuple is otherwise an
    /// exact match.
    @discardableResult
    static func rebaselineGeneratedSettingsOverrides(
        _ object: inout [String: Any],
        inheritedEventsMaxSizeMB: Int
    ) -> Bool {
        guard object["maxDatabaseSizeMB"] == nil,
              object["max_database_size_mb"] == nil,
              var storage = object["storage"] as? [String: Any] else {
            return false
        }
        guard rebaselineGeneratedSettingsStorage(
            &storage,
            inheritedEventsMaxSizeMB: inheritedEventsMaxSizeMB
        ) else {
            return false
        }
        object["storage"] = storage
        return true
    }

    /// Read `user_overrides.json` from the console user's home (if
    /// any) and merge the storage tuning keys into `config`. Any other
    /// keys in the file are ignored — we do not let a user-writable
    /// file override security-sensitive settings like
    /// `statisticalZThreshold` or `outputs`.
    ///
    /// File ownership is validated: the overrides file must be owned
    /// by the same uid as the enclosing `/Users/<u>` home. This blocks
    /// a rogue process that wrote the file as a different user.
    ///
    /// v1.8.0: read both new (storage.{eventsMaxSizeMB, alertsRetentionDays,
    /// ...}) and legacy (top-level maxDatabaseSizeMB, retentionDays) shapes.
    /// Legacy keys are folded onto the new shape via the same mapping
    /// `migrateLegacyStorageKeys` uses — alertsRetentionDays gets the legacy
    /// retentionDays, campaignsRetentionDays gets it too, eventsMaxSizeMB
    /// gets the legacy maxDatabaseSizeMB.
    private static func applyUserOverrides(into config: inout DaemonConfig) {
        struct Candidate {
            let path: String
            let data: Data
            let mtime: Date
        }
        var candidates: [Candidate] = []

        for home in RealUserHomeResolver.all() {
            let overridesPath = home.appending(
                "Library/Application Support/MacCrab/user_overrides.json"
            )
            guard case .success(let snapshot) = BoundedRegularFileReader.readOutcome(
                      at: overridesPath,
                      maximumBytes: maximumConfigurationBytes
                  ) else { continue }
            guard home.userID == snapshot.ownerUID else { continue }
            // v1.21.4 (audit A2-02): these overrides can shrink retention /
            // storage caps (anti-forensics — evict evidence early). Mirror the
            // ResponseAction.findUserHomeActionsPath gate — only honor a
            // user-home overrides file owned by an ADMIN user, so a non-admin on
            // a shared / managed Mac can't weaken the operator's config.
            guard DaemonTimers.isAdminUID(home.userID) else { continue }
            candidates.append(Candidate(
                path: overridesPath,
                data: snapshot.data,
                mtime: snapshot.modificationDate
            ))
        }

        // Use the most recently modified overrides file. In the typical
        // single-user install there's only one; on a multi-user box we
        // favor the freshest edit.
        guard let pick = candidates.max(by: { $0.mtime < $1.mtime }) else { return }
        guard var obj = try? JSONSerialization.jsonObject(
            with: pick.data
        ) as? [String: Any] else { return }

        // Settings used to write all of its default values as if they were
        // operator overrides. Upgrade that one known generated fingerprint at
        // daemon read time so boot does not depend on the preferences view
        // being opened first. This is a read-time classification only; the app
        // persists the generation marker on its next merge-safe sync. Run this
        // before legacy folding so an explicit top-level cap remains visible as
        // provenance and is never mistaken for a generated default.
        rebaselineGeneratedSettingsOverrides(
            &obj,
            inheritedEventsMaxSizeMB: config.storage.eventsMaxSizeMB
        )

        // Mirror decode()'s migration pass so legacy keys in the user
        // overrides file get folded the same way.
        migrateLegacyStorageKeys(in: &obj)

        // DL-07: snapshot the pre-merge config so the summary at the end of this
        // function can name exactly what the overrides file shadows, and with
        // which numbers. Precedence is deliberately NOT changed — the file still
        // wins; it just stops winning silently.
        let before = config

        // Merge the storage{} block into the running config. Each key is
        // optional — only the ones the user actually set get applied.
        if let storage = obj["storage"] as? [String: Any] {
            if let v = storage["eventsHotTierMinutes"] as? Int { config.storage.eventsHotTierMinutes = v }
            // Legacy: eventsHotTierHours rolls onto minutes if no new-shape key.
            if let v = storage["eventsHotTierHours"] as? Int, storage["eventsHotTierMinutes"] == nil {
                config.storage.eventsHotTierMinutes = Self.storageMinutes(
                    fromLegacyHours: v
                )
            }
            if let v = storage["processEventsFloorMinutes"] as? Int { config.storage.processEventsFloorMinutes = v }
            if let v = storage["eventsMaxSizeMB"]    as? Int { config.storage.eventsMaxSizeMB = v }
            // v1.12.6 per-host tunable sweep cadence
            if let v = storage["eventsSizeCapIntervalMinutes"] as? Int { config.storage.eventsSizeCapIntervalMinutes = v }
            if let v = storage["aggregateDays"]      as? Int { config.storage.aggregateDays = v }
            if let v = storage["alertsRetentionDays"]    as? Int { config.storage.alertsRetentionDays = v }
            if let v = storage["alertsMaxSizeMB"]    as? Int { config.storage.alertsMaxSizeMB = v }
            if let v = storage["evidenceMaxSizeMB"]  as? Int { config.storage.evidenceMaxSizeMB = v }
            if let v = storage["campaignsRetentionDays"] as? Int { config.storage.campaignsRetentionDays = v }
            if let v = storage["campaignsMaxSizeMB"] as? Int { config.storage.campaignsMaxSizeMB = v }
            // v1.18.0: tracegraph + traces caps (were hardcoded in DaemonTimers).
            if let v = storage["tracegraphRetentionDays"] as? Int { config.storage.tracegraphRetentionDays = v }
            if let v = storage["tracegraphMaxSizeMB"] as? Int { config.storage.tracegraphMaxSizeMB = v }
            if let v = storage["tracesRetentionDays"] as? Int { config.storage.tracesRetentionDays = v }
            if let v = storage["tracesMaxSizeMB"] as? Int { config.storage.tracesMaxSizeMB = v }
            // v1.21.4 (F2/A3): split merged-stream buffer depths.
            if let v = storage["mergedPriorityStreamCap"] as? Int { config.storage.mergedPriorityStreamCap = v }
            if let v = storage["mergedFileStreamCap"] as? Int { config.storage.mergedFileStreamCap = v }
            if let v = storage["reportsRetentionDays"] as? Int { config.storage.reportsRetentionDays = v }
            if let v = storage["autoGeneratedRulesMax"] as? Int { config.storage.autoGeneratedRulesMax = v }
        }

        // v1.19.1: the dashboard's privacy toggles for the three network
        // enrichment feeds. Unlike the security-sensitive thresholds (which a
        // user-writable file must NOT override), these are user-OWNED: the user
        // is the privacy principal opting into their OWN enrichment, and the
        // file is uid-validated above. Accept camelCase (dashboard) and
        // snake_case (hand-edited) keys.
        if let v = (obj["threatIntelEnabled"] ?? obj["threat_intel_enabled"]) as? Bool { config.threatIntelEnabled = v }
        if let v = (obj["vulnScanEnabled"] ?? obj["vuln_scan_enabled"]) as? Bool { config.vulnScanEnabled = v }
        if let v = (obj["packageFreshnessEnabled"] ?? obj["package_freshness_enabled"]) as? Bool { config.packageFreshnessEnabled = v }
        if let v = (obj["certTransparencyEnabled"] ?? obj["cert_transparency_enabled"]) as? Bool { config.certTransparencyEnabled = v }

        // DL-07: this merge used to be completely silent. A user_overrides.json
        // that Settings wrote months ago keeps pinning its values across every
        // upgrade, so shipped cap corrections could be inert with no diagnostic.
        // rc.12 explicitly recognizes only the complete prior UI-generated 420
        // tuple above and inherits the current 440 default; partial, tuned,
        // current-generation, and legacy-cap overrides remain authoritative.
        // Name every value this file shadows, with both numbers, so all other
        // config shadowing is visible in the log instead of only in behaviour.
        let storageKnobs: [(String, KeyPath<StorageConfig, Int>)] = [
            ("eventsHotTierMinutes", \.eventsHotTierMinutes),
            ("processEventsFloorMinutes", \.processEventsFloorMinutes),
            ("eventsMaxSizeMB", \.eventsMaxSizeMB),
            ("eventsSizeCapIntervalMinutes", \.eventsSizeCapIntervalMinutes),
            ("aggregateDays", \.aggregateDays),
            ("alertsRetentionDays", \.alertsRetentionDays),
            ("alertsMaxSizeMB", \.alertsMaxSizeMB),
            ("evidenceMaxSizeMB", \.evidenceMaxSizeMB),
            ("campaignsRetentionDays", \.campaignsRetentionDays),
            ("campaignsMaxSizeMB", \.campaignsMaxSizeMB),
            ("tracegraphRetentionDays", \.tracegraphRetentionDays),
            ("tracegraphMaxSizeMB", \.tracegraphMaxSizeMB),
            ("tracesRetentionDays", \.tracesRetentionDays),
            ("tracesMaxSizeMB", \.tracesMaxSizeMB),
            ("mergedPriorityStreamCap", \.mergedPriorityStreamCap),
            ("mergedFileStreamCap", \.mergedFileStreamCap),
            ("reportsRetentionDays", \.reportsRetentionDays),
            ("autoGeneratedRulesMax", \.autoGeneratedRulesMax),
        ]
        var shadowed: [String] = []
        for (name, kp) in storageKnobs
        where before.storage[keyPath: kp] != config.storage[keyPath: kp] {
            shadowed.append("storage.\(name) \(before.storage[keyPath: kp]) → \(config.storage[keyPath: kp])")
        }
        let enrichmentFlags: [(String, KeyPath<DaemonConfig, Bool>)] = [
            ("threatIntelEnabled", \.threatIntelEnabled),
            ("vulnScanEnabled", \.vulnScanEnabled),
            ("packageFreshnessEnabled", \.packageFreshnessEnabled),
            ("certTransparencyEnabled", \.certTransparencyEnabled),
        ]
        for (name, kp) in enrichmentFlags where before[keyPath: kp] != config[keyPath: kp] {
            shadowed.append("\(name) \(before[keyPath: kp]) → \(config[keyPath: kp])")
        }
        guard !shadowed.isEmpty else { return }
        let shadowSummary = shadowed.joined(separator: ", ")
        let summary = "user_overrides.json (\(pick.path)) shadows compiled defaults: \(shadowSummary)"
        logger.notice("\(summary, privacy: .public)")
        print("[config] \(summary)")
    }

    /// Fold v1.7-shape storage keys onto the v1.8 `storage{}` block.
    ///
    /// Pre-v1.8 daemon_config.json had `retentionDays` + `maxDatabaseSizeMB`
    /// at the top level. v1.8 moves them into a nested `storage` block with
    /// six per-tier knobs. This function rewrites the legacy keys onto the
    /// new shape so a user upgrading their config without changes still
    /// gets sensible behavior:
    ///
    ///   - `retentionDays` → `storage.alertsRetentionDays` AND
    ///     `storage.campaignsRetentionDays` (the legacy knob governed both)
    ///   - `maxDatabaseSizeMB` → `storage.eventsMaxSizeMB` (events were the
    ///     file's dominant tenant; the legacy cap effectively bounded events)
    ///
    /// New (v1.8) keys, if present, take precedence over folded legacy keys.
    /// If only the new shape is in the file this is a no-op.
    static func migrateLegacyStorageKeys(in obj: inout [String: Any]) {
        var storage = (obj["storage"] as? [String: Any]) ?? [:]

        if let legacyDays = obj.removeValue(forKey: "retentionDays") {
            if storage["alertsRetentionDays"] == nil    { storage["alertsRetentionDays"] = legacyDays }
            if storage["campaignsRetentionDays"] == nil { storage["campaignsRetentionDays"] = legacyDays }
        }
        if let legacyCap = obj.removeValue(forKey: "maxDatabaseSizeMB") {
            if storage["eventsMaxSizeMB"] == nil { storage["eventsMaxSizeMB"] = legacyCap }
        }

        // Snake-case rewrite for the storage block's own keys.
        let storageSnakeToCamel: [String: String] = [
            "events_hot_tier_hours":            "eventsHotTierHours",   // legacy alias (handled below)
            "events_hot_tier_minutes":          "eventsHotTierMinutes",
            "process_events_floor_minutes":     "processEventsFloorMinutes",
            "events_max_size_mb":               "eventsMaxSizeMB",
            // v1.12.6: per-host tunable sweep cadence. `*Minutes` is
            // safe under JSONDecoder's `.convertFromSnakeCase` (no
            // trailing-uppercase abbreviation), but we still rewrite
            // here for parity with sibling keys and so partial-decode
            // JSON dicts use the exact property name the synthesized
            // decoder expects after the overlay-onto-defaults step.
            "events_size_cap_interval_minutes": "eventsSizeCapIntervalMinutes",
            "aggregate_days":                   "aggregateDays",
            "alerts_retention_days":            "alertsRetentionDays",
            "alerts_max_size_mb":               "alertsMaxSizeMB",
            "evidence_max_size_mb":             "evidenceMaxSizeMB",
            "campaigns_retention_days":         "campaignsRetentionDays",
            "campaigns_max_size_mb":            "campaignsMaxSizeMB",
            "tracegraph_retention_days":        "tracegraphRetentionDays",
            "tracegraph_max_size_mb":           "tracegraphMaxSizeMB",
            "traces_retention_days":            "tracesRetentionDays",
            "traces_max_size_mb":               "tracesMaxSizeMB",
            "merged_priority_stream_cap":       "mergedPriorityStreamCap",
            "merged_file_stream_cap":           "mergedFileStreamCap",
            "reports_retention_days":           "reportsRetentionDays",
            "auto_generated_rules_max":         "autoGeneratedRulesMax",
        ]
        for (snake, camel) in storageSnakeToCamel where storage[snake] != nil && storage[camel] == nil {
            storage[camel] = storage.removeValue(forKey: snake)
        }

        // v1.8.0-rc4 → rc5: eventsHotTierHours folded onto
        // eventsHotTierMinutes (× 60). New key wins if both present.
        if let legacyHours = storage.removeValue(forKey: "eventsHotTierHours") as? Int {
            if storage["eventsHotTierMinutes"] == nil {
                storage["eventsHotTierMinutes"] = storageMinutes(
                    fromLegacyHours: legacyHours
                )
            }
        }

        if !storage.isEmpty {
            obj["storage"] = storage
        }
    }

    /// Saturating legacy conversion; the shared storage clamp applies the
    /// operational ceiling after decode/overlay. Keeping this conversion
    /// non-trapping is necessary because both daemon_config.json and the
    /// dashboard-owned override file may still carry the old hours key.
    private static func storageMinutes(fromLegacyHours hours: Int) -> Int {
        let (minutes, overflow) = hours.multipliedReportingOverflow(by: 60)
        if overflow { return hours >= 0 ? Int.max : Int.min }
        return minutes
    }
}
