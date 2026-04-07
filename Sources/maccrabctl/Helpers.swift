import Foundation
import MacCrabCore

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
          events tail [N]     Show last N events (default: 20)
          events search <q>   Full-text search over events
          events stats        Show event statistics
          alerts [N]          Show last N alerts (default: 20)
          watch               Live stream alerts as they happen

        Rules:
          rules list          List all loaded detection rules
          rules count         Count rules by category
          rule create [cat]   Generate a rule YAML template
          compile <in> <out>  Compile Sigma YAML rules to JSON

        Response:
          suppress <rule> <path>  Allowlist a process for a rule
          export [format] [N]     Export alerts (json|csv, default: json)

        Forensics:
          hunt <query>            Natural language threat hunting
          report [--hours N] [--output file]  Generate HTML incident report
          cdhash <PID>            Extract CDHash for a process
          cdhash --all            Extract CDHashes for all processes

        Other:
          version             Show version information
          help                Show this help message

        Examples:
          maccrabctl status
          maccrabctl watch
          maccrabctl events search "curl Downloads"
          maccrabctl export csv 500
          maccrabctl rule create network_connection
          maccrabctl suppress my-rule-id /usr/bin/safe-process
          maccrabctl hunt "show critical alerts from last hour"
          maccrabctl report --hours 48 --output incident.html
          maccrabctl cdhash 1234
        """)
    }

    static func printVersion() {
        // LOCALIZE: "MacCrab Detection Engine v1.0.0"
        print("MacCrab Detection Engine v1.0.0")
        // LOCALIZE: "License: Apache 2.0 (code), DRL 1.1 (rules)"
        print("License: Apache 2.0 (code), DRL 1.1 (rules)")
        print("https://github.com/maccrab-detection/maccrab")
    }

    static func formatBytes(_ bytes: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)
    }

    static func formatDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale.current
        formatter.dateStyle = .short
        formatter.timeStyle = .medium
        return formatter.string(from: date)
    }

    /// Create a transient LLM service for CLI use.
    /// Reads from llm_config.json (dashboard settings), then env var overrides.
    static func createCLILLMService() -> LLMService? {
        var config = LLMConfig()
        var hasConfig = false

        // Read dashboard-written llm_config.json
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

        // Env vars override (backward compat)
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
