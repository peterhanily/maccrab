import Foundation
import MacCrabCore

// MARK: - ANSI Terminal Colors

/// Whether stdout is a terminal (enables color output).
/// Falls back to plain text when output is piped or redirected.
let isTerminal = isatty(STDOUT_FILENO) != 0

enum ANSIColor: String {
    case red = "\u{001B}[31m"
    case orange = "\u{001B}[33m"      // yellow in most terminals
    case yellow = "\u{001B}[93m"      // bright yellow
    case blue = "\u{001B}[34m"
    case gray = "\u{001B}[90m"
    case bold = "\u{001B}[1m"
    case reset = "\u{001B}[0m"

    static func wrap(_ text: String, _ color: ANSIColor) -> String {
        guard isTerminal else { return text }
        return "\(color.rawValue)\(text)\(ANSIColor.reset.rawValue)"
    }
}

extension Severity {
    /// Colored severity label for CLI output.
    var coloredLabel: String {
        switch self {
        case .critical:      return ANSIColor.wrap("[CRITICAL]", .red)
        case .high:          return ANSIColor.wrap("[HIGH]    ", .orange)
        case .medium:        return ANSIColor.wrap("[MEDIUM]  ", .yellow)
        case .low:           return ANSIColor.wrap("[LOW]     ", .blue)
        case .informational: return ANSIColor.wrap("[INFO]    ", .gray)
        }
    }
}

/// Resolve the MacCrab data directory.
/// Prefers the system dir (root daemon) when its DB is newer, since the
/// user dir may contain stale data from a previous non-root run.
func maccrabDataDir() -> String {
    let fm = FileManager.default
    let userDir = fm.urls(
        for: .applicationSupportDirectory,
        in: .userDomainMask
    ).first.map { $0.appendingPathComponent("MacCrab").path }
        ?? NSHomeDirectory() + "/Library/Application Support/MacCrab"
    let systemDir = "/Library/Application Support/MacCrab"

    let userDB = userDir + "/events.db"
    let systemDB = systemDir + "/events.db"
    let userExists = fm.fileExists(atPath: userDB)
    let systemReadable = fm.isReadableFile(atPath: systemDB)

    if userExists && systemReadable {
        let userMod = (try? fm.attributesOfItem(atPath: userDB))?[.modificationDate] as? Date
        let sysMod = (try? fm.attributesOfItem(atPath: systemDB))?[.modificationDate] as? Date
        if let s = sysMod, let u = userMod, s >= u {
            return systemDir
        }
        return userDir
    }
    if systemReadable { return systemDir }
    if userExists { return userDir }
    return systemDir
}

extension MacCrabCtl {
    static func printUsage() {
        // LOCALIZE: All CLI usage/help strings below are candidates for future localization.
        // In a CLI context without a resource bundle, NSLocalizedString is not practical.
        // Mark strings with LOCALIZE comments for extraction tooling.
        print("""
        maccrabctl - MacCrab Detection Engine CLI

        Usage: maccrabctl <command> [options]

        Monitoring:
          status              Show daemon status and statistics
          events tail [N] [--hours H] [--category C]  Show recent events
          events search <q>   Full-text search over events
          events stats        Show event statistics
          alerts [N] [--hours H] [--severity S]  Show alerts (N=count, H=hours, S=critical|high|medium|low)
          campaigns [N]       Show last N campaigns (default: 10)
          campaigns watch     Live stream campaigns as they are detected
          watch               Live stream alerts as they happen

        Rules:
          rules list          List all loaded detection rules
          rules count         Count rules by category
          rule create [cat]   Generate a rule YAML template
          compile <in> <out>  Compile Sigma YAML rules to JSON

        Response:
          suppress <rule> <path>  Allowlist a process for a rule (v1 API)
          unsuppress <rule> [path]  Remove a suppression (all paths if no path given)
          suppression list        Show all configured suppressions
          allow <sub>             Allowlist v2 — TTL, scope, audit
                                  (add / list / remove / stats)
          export [format] [N]     Export alerts (json|csv, default: json)

        Deception (opt-in):
          deception <sub>         Honeyfile canaries
                                  (deploy / status / remove)

        Forensics:
          hunt <query>            Natural language threat hunting
          report [--hours N] [--output file]  Generate HTML incident report
          cdhash <PID>            Extract CDHash for a process
          cdhash --all            Extract CDHashes for all processes
          tree-score [N]          Top-N suspicious processes (behavioral + Markov scoring)
          mcp list [--suspicious] List MCP server configs across all AI tools
          extensions [--suspicious]  Scan browser extensions for dangerous permissions
          vulns [--hours H] [--severity S]  Vulnerability alerts from the CVE scanner
          privacy [--hours H]  Privacy anomaly alerts (bulk egress, trackers, domain spikes)
          security            Full security posture breakdown with recommendations

        Other:
          version             Show version information
          help                Show this help message

        Examples:
          maccrabctl status
          maccrabctl watch
          maccrabctl alerts --hours 24
          maccrabctl alerts --severity critical
          maccrabctl campaigns
          maccrabctl campaigns watch
          maccrabctl events search "curl Downloads"
          maccrabctl export csv 500
          maccrabctl rule create network_connection
          maccrabctl suppress my-rule-id /usr/bin/safe-process
          maccrabctl unsuppress my-rule-id /usr/bin/safe-process
          maccrabctl suppression list
          maccrabctl hunt "show critical alerts from last hour"
          maccrabctl report --hours 48 --output incident.html
          maccrabctl cdhash 1234
          maccrabctl tree-score 20
          maccrabctl mcp list
          maccrabctl extensions --suspicious
          maccrabctl vulns
          maccrabctl vulns --hours 24 --severity critical
          maccrabctl privacy
          maccrabctl privacy --hours 24
          maccrabctl security
          maccrabctl allow add --rule rule.noisy --path /usr/local/bin/vendor --ttl 7d --reason "vendor rollout"
          maccrabctl allow list --expired
          maccrabctl deception deploy
          maccrabctl deception status
        """)
    }

    static func printVersion() {
        // LOCALIZE: "MacCrab Detection Engine v1.3.4"
        print("MacCrab Detection Engine v1.5.1")
        // LOCALIZE: "License: Apache 2.0 (code), DRL 1.1 (rules)"
        print("License: Apache 2.0 (code), DRL 1.1 (rules)")
        print("https://github.com/maccrab-detection/maccrab")
    }

    static func formatBytes(_ bytes: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)
    }

    static func formatDate(_ date: Date) -> String {
        "\(Self._datePart.string(from: date).uppercased()) \(Self._timePart.string(from: date))"
    }

    private static let _datePart: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "ddMMMyyyy"
        return f
    }()
    private static let _timePart: DateFormatter = {
        let f = DateFormatter()
        f.timeStyle = .medium
        f.dateStyle = .none
        return f
    }()

    /// Create a transient LLM service for CLI use.
    ///
    /// Resolution order (highest priority first):
    ///   1. Env vars — legacy / CI path, kept for backward compat
    ///   2. Keychain (SecretsStore) — authoritative in v1.3.5+, written
    ///      by the dashboard's Settings > AI Backend tab
    ///   3. llm_config.json — dashboard also writes here so the sysext can
    ///      read without the shared-keychain-access-group entitlement
    ///
    /// Env vars intentionally win over Keychain so CI / one-off invocations
    /// can override without disturbing the user's stored credentials.
    static func createCLILLMService() -> LLMService? {
        var config = LLMConfig()
        var hasConfig = false

        // Read dashboard-written llm_config.json (non-secret config + legacy key copy)
        let supportDir = maccrabDataDir()
        let configPath = supportDir + "/llm_config.json"
        if let data = try? Data(contentsOf: URL(fileURLWithPath: configPath)),
           let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            if let enabled = json["enabled"] as? Bool { config.enabled = enabled }
            if let provider = json["provider"] as? String {
                config.provider = LLMProvider(rawValue: provider) ?? config.provider
            }
            if let v = json["ollama_url"] as? String { config.ollamaURL = v }
            if let v = json["ollama_model"] as? String { config.ollamaModel = v }
            if let v = json["ollama_api_key"] as? String { config.ollamaAPIKey = v }
            if let v = json["claude_api_key"] as? String { config.claudeAPIKey = v }
            if let v = json["claude_model"] as? String { config.claudeModel = v }
            if let v = json["openai_url"] as? String { config.openaiURL = v }
            if let v = json["openai_api_key"] as? String { config.openaiAPIKey = v }
            if let v = json["openai_model"] as? String { config.openaiModel = v }
            if let v = json["mistral_api_key"] as? String { config.mistralAPIKey = v }
            if let v = json["mistral_model"] as? String { config.mistralModel = v }
            if let v = json["gemini_api_key"] as? String { config.geminiAPIKey = v }
            if let v = json["gemini_model"] as? String { config.geminiModel = v }
            hasConfig = config.enabled
        }

        // Keychain overrides JSON. CLI runs as user, so the dashboard's
        // login-keychain items are directly accessible. This is the secure
        // path when llm_config.json might have stale / missing keys.
        let secrets = SecretsStore()
        func keychainValue(_ key: SecretKey) -> String? {
            (try? secrets.get(key)).flatMap { $0 }
        }
        if let v = keychainValue(.ollamaAPIKey)  { config.ollamaAPIKey  = v }
        if let v = keychainValue(.claudeAPIKey)  { config.claudeAPIKey  = v }
        if let v = keychainValue(.openaiAPIKey)  { config.openaiAPIKey  = v }
        if let v = keychainValue(.mistralAPIKey) { config.mistralAPIKey = v }
        if let v = keychainValue(.geminiAPIKey)  { config.geminiAPIKey  = v }

        // Env vars override everything (backward compat + CI ergonomics)
        let env = ProcessInfo.processInfo.environment
        if let p = env["MACCRAB_LLM_PROVIDER"] {
            config.provider = LLMProvider(rawValue: p) ?? config.provider
            hasConfig = true
        }
        if let v = env["MACCRAB_LLM_OLLAMA_URL"] { config.ollamaURL = v }
        if let v = env["MACCRAB_LLM_OLLAMA_MODEL"] { config.ollamaModel = v }
        if let v = env["MACCRAB_LLM_CLAUDE_KEY"] { config.claudeAPIKey = v }
        if let v = env["MACCRAB_LLM_OPENAI_URL"] { config.openaiURL = v }
        if let v = env["MACCRAB_LLM_OPENAI_KEY"] { config.openaiAPIKey = v }

        guard hasConfig else { return nil }

        let backend: any LLMBackend
        switch config.provider {
        case .ollama:
            backend = OllamaBackend(baseURL: config.ollamaURL, model: config.ollamaModel, apiKey: config.ollamaAPIKey)
        case .claude:
            guard let key = config.claudeAPIKey, !key.isEmpty else { return nil }
            backend = ClaudeBackend(apiKey: key, model: config.claudeModel)
        case .openai:
            guard let key = config.openaiAPIKey, !key.isEmpty else { return nil }
            backend = OpenAIBackend(baseURL: config.openaiURL, apiKey: key, model: config.openaiModel)
        case .mistral:
            guard let key = config.mistralAPIKey, !key.isEmpty else { return nil }
            backend = MistralBackend(apiKey: key, model: config.mistralModel)
        case .gemini:
            guard let key = config.geminiAPIKey, !key.isEmpty else { return nil }
            backend = GeminiBackend(apiKey: key, model: config.geminiModel)
        }

        return LLMService(backend: backend, config: config)
    }
}
