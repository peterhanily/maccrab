import Foundation
import MacCrabCore

/// Daemon configuration loaded from `daemon_config.json` in the support directory.
/// All values have sensible defaults — the config file is optional.
struct DaemonConfig: Codable {
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
    var rootkitPollInterval: TimeInterval = 120
    var eventTapPollInterval: TimeInterval = 30
    var systemPolicyPollInterval: TimeInterval = 300

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
    struct StorageConfig: Codable {
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

        /// Hard cap on the events.db file size, in MB. The adaptive rollup
        /// tightens the cutoff (1h → 30m → 15m) if needed to stay under
        /// this. Last-resort row-count prune kicks in if even the tightest
        /// cutoff can't fit.
        var eventsMaxSizeMB: Int = 200

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

        /// Campaign retention, in days. Campaigns are the highest-density
        /// signal in the store — even a year is tiny.
        var campaignsRetentionDays: Int = 365

        /// Hard cap on the campaigns.db file size, in MB.
        var campaignsMaxSizeMB: Int = 50
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
        if let data = try? Data(contentsOf: URL(fileURLWithPath: path)) {
            config = decode(data) ?? DaemonConfig()
        } else {
            config = DaemonConfig()
        }

        // v1.7.6: applyUserOverrides scans /Users/*/Library/Application Support/MacCrab/
        // unconditionally — independent of `directory`. That path is real production
        // behavior on a single-user box, but it leaked the dev's actual overrides into
        // tests that pass a temp `directory`. Tests opt out by passing applyOverrides:false.
        if applyOverrides {
            applyUserOverrides(into: &config)
        }
        return config
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
            "rootkit_poll_interval": "rootkitPollInterval",
            "event_tap_poll_interval": "eventTapPollInterval",
            "system_policy_poll_interval": "systemPolicyPollInterval",
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
        let fm = FileManager.default
        guard let users = try? fm.contentsOfDirectory(atPath: "/Users") else { return }

        struct Candidate {
            let path: String
            let mtime: Date
        }
        var candidates: [Candidate] = []

        for user in users where user != "Shared" && !user.hasPrefix(".") {
            let home = "/Users/\(user)"
            let overridesPath = home + "/Library/Application Support/MacCrab/user_overrides.json"
            guard fm.fileExists(atPath: overridesPath) else { continue }
            guard let homeAttrs = try? fm.attributesOfItem(atPath: home),
                  let overrideAttrs = try? fm.attributesOfItem(atPath: overridesPath) else { continue }
            let homeUID = (homeAttrs[.ownerAccountID] as? NSNumber)?.uint32Value ?? UInt32.max
            let fileUID = (overrideAttrs[.ownerAccountID] as? NSNumber)?.uint32Value ?? UInt32.max
            guard homeUID == fileUID, homeUID != UInt32.max else { continue }
            let mtime = (overrideAttrs[.modificationDate] as? Date) ?? .distantPast
            candidates.append(Candidate(path: overridesPath, mtime: mtime))
        }

        // Use the most recently modified overrides file. In the typical
        // single-user install there's only one; on a multi-user box we
        // favor the freshest edit.
        guard let pick = candidates.max(by: { $0.mtime < $1.mtime }) else { return }
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: pick.path)),
              var obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }

        // Mirror decode()'s migration pass so legacy keys in the user
        // overrides file get folded the same way.
        migrateLegacyStorageKeys(in: &obj)

        // Merge the storage{} block into the running config. Each key is
        // optional — only the ones the user actually set get applied.
        if let storage = obj["storage"] as? [String: Any] {
            if let v = storage["eventsHotTierMinutes"] as? Int { config.storage.eventsHotTierMinutes = v }
            // Legacy: eventsHotTierHours rolls onto minutes if no new-shape key.
            if let v = storage["eventsHotTierHours"] as? Int, storage["eventsHotTierMinutes"] == nil {
                config.storage.eventsHotTierMinutes = v * 60
            }
            if let v = storage["eventsMaxSizeMB"]    as? Int { config.storage.eventsMaxSizeMB = v }
            if let v = storage["aggregateDays"]      as? Int { config.storage.aggregateDays = v }
            if let v = storage["alertsRetentionDays"]    as? Int { config.storage.alertsRetentionDays = v }
            if let v = storage["alertsMaxSizeMB"]    as? Int { config.storage.alertsMaxSizeMB = v }
            if let v = storage["campaignsRetentionDays"] as? Int { config.storage.campaignsRetentionDays = v }
            if let v = storage["campaignsMaxSizeMB"] as? Int { config.storage.campaignsMaxSizeMB = v }
        }
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
            "events_hot_tier_hours":   "eventsHotTierHours",   // legacy alias (handled below)
            "events_hot_tier_minutes": "eventsHotTierMinutes",
            "events_max_size_mb":      "eventsMaxSizeMB",
            "aggregate_days":          "aggregateDays",
            "alerts_retention_days":   "alertsRetentionDays",
            "alerts_max_size_mb":      "alertsMaxSizeMB",
            "campaigns_retention_days":"campaignsRetentionDays",
            "campaigns_max_size_mb":   "campaignsMaxSizeMB",
        ]
        for (snake, camel) in storageSnakeToCamel where storage[snake] != nil && storage[camel] == nil {
            storage[camel] = storage.removeValue(forKey: snake)
        }

        // v1.8.0-rc4 → rc5: eventsHotTierHours folded onto
        // eventsHotTierMinutes (× 60). New key wins if both present.
        if let legacyHours = storage.removeValue(forKey: "eventsHotTierHours") as? Int {
            if storage["eventsHotTierMinutes"] == nil {
                storage["eventsHotTierMinutes"] = legacyHours * 60
            }
        }

        if !storage.isEmpty {
            obj["storage"] = storage
        }
    }
}
