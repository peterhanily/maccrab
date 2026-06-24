// GeminiBackend.swift
// MacCrabCore
//
// Google Gemini API backend. Uses the generateContent endpoint.

import Foundation
import os.log

public actor GeminiBackend: LLMBackend {
    public let providerName = "Gemini"
    private let apiKey: String
    private let model: String
    private let logger = Logger(subsystem: "com.maccrab.llm", category: "gemini")
    private let session: URLSession = SecureURLSession.make(for: .gemini)

    /// Validate that the model string is a plain `[a-z0-9._-]+` token.
    /// Pre-fix the model was interpolated into the URL path with no
    /// validation — an attacker-controlled config value of `../../admin`
    /// would alter the request path and could be used to exfiltrate the
    /// API key to an attacker domain via redirect or to poison HTTP
    /// caches in front of the Google endpoint.
    private static let modelAllowedChars: Set<Character> = {
        var s = Set<Character>("abcdefghijklmnopqrstuvwxyz0123456789-._")
        return s
    }()

    // `internal` (not private) so the model-name allowlist is unit-tested — an
    // attacker-controlled `../../admin`-shaped model would alter the request
    // path (key exfil via redirect / cache poisoning), so this must stay tight.
    static func isValidModelName(_ s: String) -> Bool {
        guard !s.isEmpty, s.count <= 64 else { return false }
        return s.allSatisfy { Self.modelAllowedChars.contains($0) }
    }

    public init(apiKey: String, model: String = "gemini-2.0-flash") {
        self.apiKey = apiKey
        if Self.isValidModelName(model.lowercased()) {
            self.model = model
        } else {
            os_log("GeminiBackend: rejecting model name %{public}@ — falling back to gemini-2.0-flash",
                   log: OSLog(subsystem: "com.maccrab.llm", category: "gemini"),
                   type: .error,
                   model)
            self.model = "gemini-2.0-flash"
        }
    }

    public func isAvailable() async -> Bool {
        !apiKey.isEmpty
    }

    public func complete(systemPrompt: String, userPrompt: String,
                         maxTokens: Int, temperature: Double) async -> String? {
        // Gemini API: POST https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent
        // The API key is sent via the x-goog-api-key header rather than a query parameter
        // to prevent exposure in HTTP access logs and proxy logs.
        let urlStr = "https://generativelanguage.googleapis.com/v1beta/models/\(model):generateContent"
        guard let url = URL(string: urlStr) else { return nil }

        // Gemini uses a different request format than OpenAI
        let payload: [String: Any] = [
            "systemInstruction": ["parts": [["text": systemPrompt]]],
            "contents": [["parts": [["text": userPrompt]]]],
            "generationConfig": [
                "maxOutputTokens": maxTokens,
                "temperature": temperature
            ]
        ]

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(apiKey, forHTTPHeaderField: "x-goog-api-key")
        // Zero-data-retention / no-train posture: the Gemini API has no
        // documented request header to opt out of retention/training. Paid-
        // tier API data is not used for training by default; retention is a
        // project/account setting, not a per-request flag. Documented in
        // PRIVACY.md. (Audit P1 finding 2.)
        request.httpBody = try? JSONSerialization.data(withJSONObject: payload)
        request.timeoutInterval = 60

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            logger.error("Gemini network error: \(error.localizedDescription)")
            return nil
        }
        guard let http = response as? HTTPURLResponse else { return nil }
        guard http.statusCode == 200 else {
            let body = String(data: data.prefix(200), encoding: .utf8) ?? ""
            logger.error("Gemini API error \(http.statusCode): \(body)")
            return nil
        }

        // Response: {"candidates": [{"content": {"parts": [{"text": "..."}]}}]}
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let candidates = json["candidates"] as? [[String: Any]],
              let content = candidates.first?["content"] as? [String: Any],
              let parts = content["parts"] as? [[String: Any]],
              let text = parts.first?["text"] as? String else { return nil }
        return text
    }
}
