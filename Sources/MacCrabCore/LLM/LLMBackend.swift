// LLMBackend.swift
// MacCrabCore
//
// Protocol defining a pluggable LLM reasoning backend.
// Conforming types handle HTTP transport, authentication, and response parsing.

import Foundation

/// A pluggable LLM reasoning backend.
public protocol LLMBackend: Actor {
    /// Human-readable name of this backend (e.g., "Ollama", "Claude", "OpenAI").
    var providerName: String { get }

    /// Whether the backend is reachable and configured.
    func isAvailable() async -> Bool

    /// Send a prompt to the LLM and return the text response.
    func complete(
        systemPrompt: String,
        userPrompt: String,
        maxTokens: Int,
        temperature: Double
    ) async -> String?
}
