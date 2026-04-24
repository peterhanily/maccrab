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

    // MARK: - Storage
    var maxDatabaseSizeMB: Int = 500
    var retentionDays: Int = 30

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
    static func load(from directory: String) -> DaemonConfig {
        let path = directory + "/daemon_config.json"
        var config: DaemonConfig
        if let data = try? Data(contentsOf: URL(fileURLWithPath: path)) {
            config = decode(data) ?? DaemonConfig()
        } else {
            config = DaemonConfig()
        }

        applyUserOverrides(into: &config)
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
            "max_database_size_mb": "maxDatabaseSizeMB",
            "retention_days": "retentionDays",
        ]
        for (snake, camel) in snakeToCamel where userObj[snake] != nil && userObj[camel] == nil {
            userObj[camel] = userObj.removeValue(forKey: snake)
        }

        // Build a "complete defaults" dict by encoding a blank
        // DaemonConfig, then overlay the user's keys on top. This
        // gives us a JSON payload that contains every key the
        // synthesized decoder expects, regardless of how sparse the
        // user's file is.
        let encoder = JSONEncoder()
        guard let defaultsData = try? encoder.encode(DaemonConfig()),
              var merged = try? JSONSerialization.jsonObject(with: defaultsData) as? [String: Any] else {
            return nil
        }
        for (k, v) in userObj {
            merged[k] = v
        }

        guard let mergedData = try? JSONSerialization.data(withJSONObject: merged) else {
            return nil
        }
        return try? JSONDecoder().decode(DaemonConfig.self, from: mergedData)
    }

    /// Read `user_overrides.json` from the console user's home (if
    /// any) and merge the `maxDatabaseSizeMB` / `retentionDays` keys
    /// into `config`. Any other keys in the file are ignored — we do
    /// not let a user-writable file override security-sensitive
    /// settings like `statisticalZThreshold` or `outputs`.
    ///
    /// File ownership is validated: the overrides file must be owned
    /// by the same uid as the enclosing `/Users/<u>` home. This blocks
    /// a rogue process that wrote the file as a different user.
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
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }

        if let cap = obj["maxDatabaseSizeMB"] as? Int {
            config.maxDatabaseSizeMB = cap
        }
        if let days = obj["retentionDays"] as? Int {
            config.retentionDays = days
        }
    }
}
