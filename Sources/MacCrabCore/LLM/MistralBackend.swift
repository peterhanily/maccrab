// MistralBackend.swift
// MacCrabCore
//
// Mistral AI API backend. Uses the Chat Completions API.

import Foundation
import os.log

public actor MistralBackend: LLMBackend, BoundedLLMBackend {
    public let providerName = "Mistral"
    private let apiKey: String
    private let model: String
    private let logger = Logger(subsystem: "com.maccrab.llm", category: "mistral")
    private let session: URLSession = SecureURLSession.make(for: .mistral)

    public init(apiKey: String, model: String = "mistral-small-latest") {
        self.apiKey = apiKey
        self.model = model
    }

    public func isAvailable() async -> Bool {
        !apiKey.isEmpty
    }

    public func complete(systemPrompt: String, userPrompt: String,
                         maxTokens: Int, temperature: Double) async -> String? {
        await completeResult(
            systemPrompt: systemPrompt,
            userPrompt: userPrompt,
            maxTokens: maxTokens,
            temperature: temperature
        ).value
    }

    func completeResult(
        systemPrompt: String,
        userPrompt: String,
        maxTokens: Int,
        temperature: Double
    ) async -> LLMBackendCompletionResult {
        guard let url = URL(string: "https://api.mistral.ai/v1/chat/completions") else {
            return .failure
        }

        struct Request: Encodable {
            let model: String
            let max_tokens: Int
            let temperature: Double
            let messages: [[String: String]]
        }

        let body = Request(
            model: model, max_tokens: maxTokens, temperature: temperature,
            messages: [
                ["role": "system", "content": systemPrompt],
                ["role": "user", "content": userPrompt]
            ]
        )

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
        // Zero-data-retention / no-train posture: the Mistral API has no
        // documented request header to opt out of retention/training;
        // it is governed by the account/plan terms, not a per-request flag.
        // Documented in PRIVACY.md. (Audit P1 finding 2.)
        request.httpBody = try? JSONEncoder().encode(body)
        request.timeoutInterval = 60

        let bounded: LLMBoundedHTTPResponse
        do {
            bounded = try await LLMBoundedHTTPReader.read(
                request: request,
                using: session
            )
        } catch LLMBoundedHTTPError.responseTooLarge {
            logger.error("Mistral response exceeded the bounded HTTP body limit")
            return .responseOversize
        } catch {
            logger.error("Mistral network error: \(error.localizedDescription)")
            return .failure
        }
        let data = bounded.data
        let http = bounded.response
        guard http.statusCode == 200 else {
            let body = String(data: data.prefix(200), encoding: .utf8) ?? ""
            logger.error("Mistral API error \(http.statusCode): \(body)")
            return .failure
        }

        // Mistral uses OpenAI-compatible response format
        struct Response: Decodable {
            struct Choice: Decodable {
                struct Message: Decodable { let content: String }
                let message: Message
            }
            let choices: [Choice]
        }

        guard let resp = try? JSONDecoder().decode(Response.self, from: data),
              let text = resp.choices.first?.message.content else {
            return .failure
        }
        return .response(text)
    }
}
