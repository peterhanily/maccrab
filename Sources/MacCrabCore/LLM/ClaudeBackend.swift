// ClaudeBackend.swift
// MacCrabCore
//
// Anthropic Claude API backend. Cloud-based, opt-in.
//
// Prompt caching: the system prompt is sent with cache_control so repeated
// calls with identical system prompts (all LLM analysis types do this) hit
// Anthropic's prompt cache. Cache TTL is 5 minutes server-side; the LLMCache
// layer above us deduplicates identical (system, user) pairs at the application
// level for the full daemon session.

import Foundation
import os.log

public actor ClaudeBackend: LLMBackend {
    public let providerName = "Claude"
    private let apiKey: String
    private let model: String
    private let logger = Logger(subsystem: "com.maccrab.llm", category: "claude")
    private let session: URLSession = SecureURLSession.make(for: .anthropic)

    public init(apiKey: String, model: String = "claude-sonnet-4-6") {
        self.apiKey = apiKey
        self.model = model
    }

    public func isAvailable() async -> Bool {
        !apiKey.isEmpty
    }

    public func complete(systemPrompt: String, userPrompt: String,
                         maxTokens: Int, temperature: Double) async -> String? {
        guard let url = URL(string: "https://api.anthropic.com/v1/messages") else { return nil }

        // System prompt as a structured block with cache_control so the API
        // caches it server-side across calls that share the same system prompt.
        // Minimum cacheable size is 1024 tokens; MacCrab system prompts are all
        // well above that threshold.
        struct CacheControl: Encodable { let type: String = "ephemeral" }
        struct SystemBlock: Encodable {
            let type: String = "text"
            let text: String
            let cache_control: CacheControl
        }
        struct Message: Encodable {
            let role: String
            let content: String
        }
        struct Request: Encodable {
            let model: String
            let max_tokens: Int
            let system: [SystemBlock]
            let messages: [Message]
        }

        let body = Request(
            model: model,
            max_tokens: maxTokens,
            system: [SystemBlock(text: systemPrompt, cache_control: CacheControl())],
            messages: [Message(role: "user", content: userPrompt)]
        )

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(apiKey, forHTTPHeaderField: "x-api-key")
        request.setValue("2023-06-01", forHTTPHeaderField: "anthropic-version")
        request.setValue("prompt-caching-2024-07-31", forHTTPHeaderField: "anthropic-beta")
        request.httpBody = try? JSONEncoder().encode(body)
        request.timeoutInterval = 60

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            logger.error("Claude network error: \(error.localizedDescription)")
            return nil
        }
        guard let http = response as? HTTPURLResponse else { return nil }
        guard http.statusCode == 200 else {
            let body = String(data: data.prefix(200), encoding: .utf8) ?? ""
            logger.error("Claude API error \(http.statusCode): \(body)")
            return nil
        }

        struct Content: Decodable { let type: String; let text: String }
        struct Response: Decodable { let content: [Content] }

        guard let resp = try? JSONDecoder().decode(Response.self, from: data),
              let block = resp.content.first(where: { $0.type == "text" }) else { return nil }
        return block.text
    }

    /// Extended thinking: instructs Claude to reason deeply before answering.
    /// Only available on Opus 4 models; falls back to regular complete() for
    /// all other models. Temperature is forced to 1 as required by the API.
    ///
    /// The thinking block in the response is discarded — callers receive only
    /// the final answer. The `thinkingBudgetTokens` budget is additional to
    /// `maxOutputTokens` so the total API consumption is the sum of both.
    public func completeWithExtendedThinking(
        systemPrompt: String,
        userPrompt: String,
        thinkingBudgetTokens: Int = 8000,
        maxOutputTokens: Int = 4096
    ) async -> String? {
        // Extended thinking is only supported on Opus 4+ models.
        guard model.contains("opus") else {
            return await complete(
                systemPrompt: systemPrompt, userPrompt: userPrompt,
                maxTokens: maxOutputTokens, temperature: 0.3
            )
        }
        guard let url = URL(string: "https://api.anthropic.com/v1/messages") else { return nil }

        struct CacheControl: Encodable { let type: String = "ephemeral" }
        struct SystemBlock: Encodable {
            let type: String = "text"; let text: String; let cache_control: CacheControl
        }
        struct Message: Encodable { let role: String; let content: String }
        struct Thinking: Encodable { let type: String = "enabled"; let budget_tokens: Int }
        struct Request: Encodable {
            let model: String
            let max_tokens: Int
            let thinking: Thinking
            let system: [SystemBlock]
            let messages: [Message]
            // Extended thinking requires temperature 1.
            let temperature: Int = 1
        }

        let body = Request(
            model: model,
            max_tokens: maxOutputTokens,
            thinking: Thinking(budget_tokens: thinkingBudgetTokens),
            system: [SystemBlock(text: systemPrompt, cache_control: CacheControl())],
            messages: [Message(role: "user", content: userPrompt)]
        )

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(apiKey, forHTTPHeaderField: "x-api-key")
        request.setValue("2023-06-01", forHTTPHeaderField: "anthropic-version")
        // Both caching and interleaved thinking must be declared together.
        request.setValue(
            "prompt-caching-2024-07-31,interleaved-thinking-2025-05-14",
            forHTTPHeaderField: "anthropic-beta"
        )
        request.httpBody = try? JSONEncoder().encode(body)
        request.timeoutInterval = 120  // Thinking models run longer

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            logger.error("Claude extended-thinking network error: \(error.localizedDescription)")
            return nil
        }
        guard let http = response as? HTTPURLResponse else { return nil }
        guard http.statusCode == 200 else {
            let body = String(data: data.prefix(200), encoding: .utf8) ?? ""
            logger.error("Claude extended-thinking API error \(http.statusCode): \(body)")
            return nil
        }

        // The response contains thinking blocks followed by text blocks.
        // Discard thinking blocks and return only the final text answer.
        struct Content: Decodable { let type: String; let text: String? }
        struct Response: Decodable { let content: [Content] }
        guard let resp = try? JSONDecoder().decode(Response.self, from: data),
              let text = resp.content.first(where: { $0.type == "text" })?.text else { return nil }
        return text
    }
}
