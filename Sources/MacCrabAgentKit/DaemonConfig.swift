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
    static func load(from directory: String) -> DaemonConfig {
        let path = directory + "/daemon_config.json"
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
            return DaemonConfig()
        }
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return (try? decoder.decode(DaemonConfig.self, from: data)) ?? DaemonConfig()
    }
}
