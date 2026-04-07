// OllamaBackend.swift
// MacCrabCore
//
// Ollama local LLM backend. Fully private — no data leaves the machine.

import Foundation
import os.log

public actor OllamaBackend: LLMBackend {
    public let providerName = "Ollama"
    private let baseURL: URL
    private let model: String
    private let logger = Logger(subsystem: "com.maccrab.llm", category: "ollama")

    public init(baseURL: String = "http://localhost:11434", model: String = "llama3.1:8b") {
        self.baseURL = URL(string: baseURL) ?? URL(string: "http://localhost:11434")!
        self.model = model
    }

    public func isAvailable() async -> Bool {
        let url = baseURL.appendingPathComponent("api/tags")
        guard let (_, response) = try? await URLSession.shared.data(from: url),
              let http = response as? HTTPURLResponse,
              http.statusCode == 200 else { return false }
        return true
    }

    public func complete(systemPrompt: String, userPrompt: String,
                         maxTokens: Int, temperature: Double) async -> String? {
        let url = baseURL.appendingPathComponent("api/generate")
        let payload: [String: Any] = [
            "model": model,
            "system": systemPrompt,
            "prompt": userPrompt,
            "stream": false,
            "options": [
                "num_predict": maxTokens,
                "temperature": temperature
            ]
        ]

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try? JSONSerialization.data(withJSONObject: payload)
        request.timeoutInterval = 120

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await URLSession.shared.data(for: request)
        } catch {
            logger.error("Ollama network error: \(error.localizedDescription)")
            return nil
        }
        guard let http = response as? HTTPURLResponse else { return nil }
        guard http.statusCode == 200 else {
            let body = String(data: data.prefix(200), encoding: .utf8) ?? ""
            logger.error("Ollama error \(http.statusCode): \(body)")
            return nil
        }

        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let text = json["response"] as? String else { return nil }
        return text.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
