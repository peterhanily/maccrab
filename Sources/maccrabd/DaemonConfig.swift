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
