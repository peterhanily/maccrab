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

    /// Enable/disable the LLM subsystem entirely.
    public var enabled: Bool = true

    public init() {}

    // Exclude API keys from Codable serialization to prevent credential leaks
    private enum CodingKeys: String, CodingKey {
        case provider, ollamaURL, ollamaModel, claudeModel
        case openaiURL, openaiModel, mistralModel, geminiModel
        case sanitizeForCloud, enabled
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
