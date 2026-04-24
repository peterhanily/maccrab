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
    private let apiKey: String?
    private let logger = Logger(subsystem: "com.maccrab.llm", category: "ollama")
    private let session: URLSession = SecureURLSession.make(for: .ollama)

    public init(baseURL: String = "http://localhost:11434", model: String = "llama3.1:8b", apiKey: String? = nil) {
        self.baseURL = URL(string: baseURL) ?? URL(string: "http://localhost:11434")!
        self.model = model
        self.apiKey = apiKey?.isEmpty == true ? nil : apiKey
    }

    /// Return true when `url` is plaintext HTTP to a non-loopback
    /// host. `http://localhost`, `http://127.0.0.1`, and `http://[::1]`
    /// are safe; `http://10.0.0.5` is not. Used as a guard before
    /// attaching an API key.
    static func isPlaintextRemote(_ url: URL) -> Bool {
        guard url.scheme?.lowercased() == "http" else { return false }
        guard let host = url.host?.lowercased() else { return true }
        if host == "localhost" { return false }
        if host == "127.0.0.1" || host.hasPrefix("127.") { return false }
        if host == "::1" || host == "[::1]" { return false }
        return true
    }

    public func isAvailable() async -> Bool {
        let url = baseURL.appendingPathComponent("api/tags")
        guard let (_, response) = try? await session.data(from: url),
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
        if let apiKey {
            // v1.6.7: if a key is configured, refuse to send it over
            // plaintext HTTP to anything other than loopback. The
            // default Ollama URL is `http://localhost:11434`, which is
            // fine — but remote-Ollama setups that forget to switch to
            // https would leak the Bearer token in clear.
            if Self.isPlaintextRemote(self.baseURL) {
                let urlForLog = self.baseURL.absoluteString
                logger.error("Refusing to send Ollama Bearer token over plaintext HTTP to non-loopback host (\(urlForLog)). Use https:// or drop the API key.")
                return nil
            }
            request.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
        }
        request.httpBody = try? JSONSerialization.data(withJSONObject: payload)
        request.timeoutInterval = 120

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
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
