// ClaudeBackend.swift
// MacCrabCore
//
// Anthropic Claude API backend. Cloud-based, opt-in.

import Foundation
import os.log

public actor ClaudeBackend: LLMBackend {
    public let providerName = "Claude"
    private let apiKey: String
    private let model: String
    private let logger = Logger(subsystem: "com.maccrab.llm", category: "claude")
    private let session: URLSession = SecureURLSession.make(for: .anthropic)

    public init(apiKey: String, model: String = "claude-sonnet-4-20250514") {
        self.apiKey = apiKey
        self.model = model
    }

    public func isAvailable() async -> Bool {
        !apiKey.isEmpty
    }

    public func complete(systemPrompt: String, userPrompt: String,
                         maxTokens: Int, temperature: Double) async -> String? {
        guard let url = URL(string: "https://api.anthropic.com/v1/messages") else { return nil }

        struct Request: Encodable {
            let model: String
            let max_tokens: Int
            let system: String
            let messages: [[String: String]]
        }

        let body = Request(
            model: model, max_tokens: maxTokens, system: systemPrompt,
            messages: [["role": "user", "content": userPrompt]]
        )

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(apiKey, forHTTPHeaderField: "x-api-key")
        request.setValue("2025-04-14", forHTTPHeaderField: "anthropic-version")
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

        struct Response: Decodable {
            struct Content: Decodable { let type: String; let text: String }
            let content: [Content]
        }

        guard let resp = try? JSONDecoder().decode(Response.self, from: data),
              let text = resp.content.first(where: { $0.type == "text" })?.text else { return nil }
        return text
    }
}
