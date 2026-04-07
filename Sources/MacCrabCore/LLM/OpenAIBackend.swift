// OpenAIBackend.swift
// MacCrabCore
//
// OpenAI-compatible API backend. Works with OpenAI, Azure, or any
// service implementing the Chat Completions API.

import Foundation
import os.log

public actor OpenAIBackend: LLMBackend {
    public let providerName = "OpenAI"
    private let baseURL: URL
    private let apiKey: String
    private let model: String
    private let logger = Logger(subsystem: "com.maccrab.llm", category: "openai")

    public init(baseURL: String = "https://api.openai.com/v1",
                apiKey: String, model: String = "gpt-4o-mini") {
        self.baseURL = URL(string: baseURL) ?? URL(string: "https://api.openai.com/v1")!
        self.apiKey = apiKey
        self.model = model
    }

    public func isAvailable() async -> Bool {
        !apiKey.isEmpty
    }

    public func complete(systemPrompt: String, userPrompt: String,
                         maxTokens: Int, temperature: Double) async -> String? {
        let url = baseURL.appendingPathComponent("chat/completions")

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
        request.httpBody = try? JSONEncoder().encode(body)
        request.timeoutInterval = 60

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await URLSession.shared.data(for: request)
        } catch {
            logger.error("OpenAI network error: \(error.localizedDescription)")
            return nil
        }
        guard let http = response as? HTTPURLResponse else { return nil }
        guard http.statusCode == 200 else {
            let body = String(data: data.prefix(200), encoding: .utf8) ?? ""
            logger.error("OpenAI API error \(http.statusCode): \(body)")
            return nil
        }

        struct Response: Decodable {
            struct Choice: Decodable {
                struct Message: Decodable { let content: String }
                let message: Message
            }
            let choices: [Choice]
        }

        guard let resp = try? JSONDecoder().decode(Response.self, from: data),
              let text = resp.choices.first?.message.content else { return nil }
        return text
    }
}
