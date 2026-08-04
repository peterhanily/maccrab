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

// MARK: - Bounded built-in transport result

/// Internal result channel used by MacCrab's built-in HTTP backends. The public
/// LLMBackend API remains source-compatible for third-party/test backends, while
/// LLMService can distinguish a transfer that was cancelled at the byte cap
/// from an ordinary network/backend failure.
enum LLMBackendCompletionResult: Sendable, Equatable {
    case response(String)
    case responseOversize
    case failure

    var value: String? {
        guard case .response(let value) = self else { return nil }
        return value
    }
}

/// Refinement adopted by all built-in providers. Keeping this separate from
/// public `LLMBackend` avoids breaking injected backends while still giving the
/// service an exhaustive transport outcome for circuit/telemetry accounting.
protocol BoundedLLMBackend: LLMBackend {
    func completeResult(
        systemPrompt: String,
        userPrompt: String,
        maxTokens: Int,
        temperature: Double
    ) async -> LLMBackendCompletionResult

    func completeWithExtendedThinkingResult(
        systemPrompt: String,
        userPrompt: String,
        thinkingBudgetTokens: Int,
        maxOutputTokens: Int
    ) async -> LLMBackendCompletionResult
}

extension BoundedLLMBackend {
    /// Mirrors LLMBackend's default extended-thinking fallback, but retains an
    /// oversize transport disposition instead of collapsing it into nil.
    func completeWithExtendedThinkingResult(
        systemPrompt: String,
        userPrompt: String,
        thinkingBudgetTokens: Int = 8000,
        maxOutputTokens: Int = 4096
    ) async -> LLMBackendCompletionResult {
        await completeResult(
            systemPrompt: systemPrompt,
            userPrompt: userPrompt,
            maxTokens: maxOutputTokens,
            temperature: 0.3
        )
    }
}

// MARK: - Optional extended thinking

extension LLMBackend {
    /// Send a prompt requesting extended thinking (deep multi-step reasoning).
    /// The default implementation falls back to a regular `complete()` call so
    /// all existing backends work unchanged. Claude backends override this with
    /// the API's `thinking` parameter, which causes the model to emit an
    /// internal reasoning block before the final answer.
    ///
    /// - Parameters:
    ///   - systemPrompt: Context and task description.
    ///   - userPrompt: The specific question or data to analyse.
    ///   - thinkingBudgetTokens: Max tokens the model can spend thinking
    ///     (does not count toward the output token budget).
    ///   - maxOutputTokens: Max tokens for the visible answer.
    public func completeWithExtendedThinking(
        systemPrompt: String,
        userPrompt: String,
        thinkingBudgetTokens: Int = 8000,
        maxOutputTokens: Int = 4096
    ) async -> String? {
        await complete(
            systemPrompt: systemPrompt,
            userPrompt: userPrompt,
            maxTokens: maxOutputTokens,
            temperature: 0.3
        )
    }
}
