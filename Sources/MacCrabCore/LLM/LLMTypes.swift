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
}

/// Configuration for the LLM subsystem.
public struct LLMConfig: Codable, Sendable {
    /// Which provider to use. Default: ollama (local, private).
    public var provider: LLMProvider = .ollama

    /// Ollama base URL.
    public var ollamaURL: String = "http://localhost:11434"

    /// Ollama model name.
    public var ollamaModel: String = "llama3.1:8b"

    /// Claude API key (only needed if provider == .claude).
    public var claudeAPIKey: String?

    /// Claude model.
    public var claudeModel: String = "claude-sonnet-4-20250514"

    /// OpenAI-compatible API base URL.
    public var openaiURL: String = "https://api.openai.com/v1"

    /// OpenAI API key.
    public var openaiAPIKey: String?

    /// OpenAI model name.
    public var openaiModel: String = "gpt-4o-mini"

    /// Whether to sanitize data before sending to cloud APIs.
    /// Automatically true for cloud providers; always false for ollama.
    public var sanitizeForCloud: Bool = true

    /// Enable/disable the LLM subsystem entirely.
    public var enabled: Bool = true

    public init() {}

    // Exclude API keys from serialization to prevent credential leaks in logs/debug output
    private enum CodingKeys: String, CodingKey {
        case provider, ollamaURL, ollamaModel, claudeModel
        case openaiURL, openaiModel, sanitizeForCloud, enabled
        // claudeAPIKey and openaiAPIKey intentionally excluded
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        provider = try c.decodeIfPresent(LLMProvider.self, forKey: .provider) ?? .ollama
        ollamaURL = try c.decodeIfPresent(String.self, forKey: .ollamaURL) ?? "http://localhost:11434"
        ollamaModel = try c.decodeIfPresent(String.self, forKey: .ollamaModel) ?? "llama3.1:8b"
        claudeModel = try c.decodeIfPresent(String.self, forKey: .claudeModel) ?? "claude-sonnet-4-20250514"
        openaiURL = try c.decodeIfPresent(String.self, forKey: .openaiURL) ?? "https://api.openai.com/v1"
        openaiModel = try c.decodeIfPresent(String.self, forKey: .openaiModel) ?? "gpt-4o-mini"
        sanitizeForCloud = try c.decodeIfPresent(Bool.self, forKey: .sanitizeForCloud) ?? true
        enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? true
        // Keys loaded only from env vars, never from JSON
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
