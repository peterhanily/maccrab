// LLMTypes.swift
// MacCrabCore
//
// Shared types for the LLM subsystem.

import Foundation

/// Which LLM provider to use.
public enum LLMProvider: String, Codable, Sendable {
    case ollama
    case claude
    case openai
    case mistral
    case gemini
}

/// Configuration for the LLM subsystem.
public struct LLMConfig: Codable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    /// Which provider to use. Default: ollama (local, private).
    public var provider: LLMProvider = .ollama

    // MARK: - Ollama
    public var ollamaURL: String = "http://localhost:11434"
    public var ollamaModel: String = "llama3.1:8b"
    public var ollamaAPIKey: String?

    // MARK: - Claude (Anthropic)
    public var claudeAPIKey: String?
    public var claudeModel: String = "claude-sonnet-4-6"

    // MARK: - OpenAI Compatible
    public var openaiURL: String = "https://api.openai.com/v1"
    public var openaiAPIKey: String?
    public var openaiModel: String = "gpt-4o-mini"

    // MARK: - Mistral
    public var mistralAPIKey: String?
    public var mistralModel: String = "mistral-small-latest"

    // MARK: - Gemini (Google)
    public var geminiAPIKey: String?
    public var geminiModel: String = "gemini-2.0-flash"

    /// Whether to sanitize data before sending to cloud APIs.
    /// Automatically true for cloud providers; false for local Ollama.
    public var sanitizeForCloud: Bool = true

    /// Strict no-leak mode (opt-in). The sanitizer is best-effort regex and
    /// CANNOT guarantee no novel sensitive shape slips through. When this is on,
    /// a cloud LLM call is REFUSED if the sanitized prompt still contains
    /// high-entropy / unparseable content that looks like it could be a secret —
    /// trading some analysis coverage for a hard no-leak boundary. Default false
    /// (best-effort). Only meaningful with a cloud provider + sanitizeForCloud.
    public var strictSanitize: Bool = false

    /// v1.21.5 (audit S-02): whether the configured Ollama endpoint may be
    /// treated as trusted-local (i.e. may bypass the sanitizer). A loopback URL
    /// alone is NOT evidence that data stays on the host — any local process can
    /// run a listener on 127.0.0.1 — so this flag records WHERE the endpoint came
    /// from. True for the compiled default and for operator channels uid 501
    /// cannot write (root-owned daemon_config.json, the daemon's launch env);
    /// false when the endpoint arrived over the privileged-inbox control plane,
    /// which post-compromise code running as the console user can drive.
    /// Deliberately NOT in `CodingKeys`: it must never round-trip through
    /// llm_config.json, or an attacker who can write that file could simply
    /// re-assert trust — the same reason the API keys are excluded.
    public var trustLocalEndpoint: Bool = true

    /// Enable/disable the LLM subsystem entirely.
    ///
    /// Default is OFF. It used to be `true`, which combined with the default
    /// `ollamaURL` of localhost:11434 meant any machine that merely happened to
    /// be running Ollama on the standard port got LLM commentary — 16% of the
    /// alert corpus — without the operator ever opening Settings. "Ollama is
    /// running" is a coincidence, not consent: the engine runs as root, and
    /// feeding its process telemetry to a model the user started for unrelated
    /// work is a surprise, however local that model is.
    ///
    /// Migration is handled at the load site, not here: DaemonSetup treats the
    /// EXISTENCE of a dashboard-written llm_config.json as opt-in, so anyone who
    /// already configured a backend keeps working. Only fresh installs are quiet.
    public var enabled: Bool = false

    public init() {}

    // Exclude API keys from Codable serialization to prevent credential leaks
    private enum CodingKeys: String, CodingKey {
        case provider, ollamaURL, ollamaModel, claudeModel
        case openaiURL, openaiModel, mistralModel, geminiModel
        case sanitizeForCloud, strictSanitize, enabled
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        provider = try c.decodeIfPresent(LLMProvider.self, forKey: .provider) ?? .ollama
        ollamaURL = try c.decodeIfPresent(String.self, forKey: .ollamaURL) ?? "http://localhost:11434"
        ollamaModel = try c.decodeIfPresent(String.self, forKey: .ollamaModel) ?? "llama3.1:8b"
        claudeModel = try c.decodeIfPresent(String.self, forKey: .claudeModel) ?? "claude-sonnet-4-6"
        openaiURL = try c.decodeIfPresent(String.self, forKey: .openaiURL) ?? "https://api.openai.com/v1"
        openaiModel = try c.decodeIfPresent(String.self, forKey: .openaiModel) ?? "gpt-4o-mini"
        mistralModel = try c.decodeIfPresent(String.self, forKey: .mistralModel) ?? "mistral-small-latest"
        geminiModel = try c.decodeIfPresent(String.self, forKey: .geminiModel) ?? "gemini-2.0-flash"
        sanitizeForCloud = try c.decodeIfPresent(Bool.self, forKey: .sanitizeForCloud) ?? true
        strictSanitize = try c.decodeIfPresent(Bool.self, forKey: .strictSanitize) ?? false
        enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? true
    }

    // MARK: - Safe string descriptions
    //
    // `LLMConfig` holds API keys as public `var` fields. Any accidental
    // `print(config)`, `String(describing: config)`, or logger call
    // that takes the struct would dump those keys via Mirror-based
    // reflection. Override both `description` and `debugDescription`
    // so the stringified form never carries the keys — only a
    // redacted marker + the first/last character of each configured
    // key for troubleshooting.

    public var description: String {
        "LLMConfig(provider=\(provider.rawValue), " +
        "ollamaModel=\(ollamaModel), claudeModel=\(claudeModel), " +
        "openaiModel=\(openaiModel), mistralModel=\(mistralModel), " +
        "geminiModel=\(geminiModel), sanitizeForCloud=\(sanitizeForCloud), " +
        "enabled=\(enabled), " +
        "ollamaAPIKey=\(Self.maskKey(ollamaAPIKey)), " +
        "claudeAPIKey=\(Self.maskKey(claudeAPIKey)), " +
        "openaiAPIKey=\(Self.maskKey(openaiAPIKey)), " +
        "mistralAPIKey=\(Self.maskKey(mistralAPIKey)), " +
        "geminiAPIKey=\(Self.maskKey(geminiAPIKey)))"
    }

    public var debugDescription: String { description }

    /// Redact an API key for log/debug output. Returns `"<unset>"`
    /// for nil, `"<empty>"` for empty, else `"<len=N,first=X,last=Y>"`
    /// — enough for a human to confirm "the key I expected is
    /// configured" without the key itself leaving the log.
    static func maskKey(_ key: String?) -> String {
        guard let key, !key.isEmpty else {
            return key == nil ? "<unset>" : "<empty>"
        }
        let first = String(key.prefix(1))
        let last = String(key.suffix(1))
        return "<len=\(key.count),first=\(first),last=\(last)>"
    }
}

/// Result wrapper for an LLM-enhanced operation.
public struct LLMEnhancement: Sendable {
    public let provider: String
    public let prompt: String
    public let response: String
    public let latency: TimeInterval
    public let cached: Bool

    public init(provider: String, prompt: String, response: String, latency: TimeInterval, cached: Bool) {
        self.provider = provider
        self.prompt = prompt
        self.response = response
        self.latency = latency
        self.cached = cached
    }
}
