// OpenAIBackend.swift
// MacCrabCore
//
// OpenAI-compatible API backend. Works with OpenAI, Azure, or any
// service implementing the Chat Completions API.

import Foundation
import os.log

public actor OpenAIBackend: LLMBackend {
    public let providerName = "OpenAI"
    // `nonisolated` + `internal` (not private) so the baseURL allowlist +
    // cleartext-scheme guard is unit-tested synchronously. Immutable Sendable,
    // safe to expose without actor isolation.
    nonisolated let baseURL: URL
    private let apiKey: String
    private let model: String
    private let logger = Logger(subsystem: "com.maccrab.llm", category: "openai")
    private let session: URLSession = SecureURLSession.make(for: .openai)

    /// Hosts an operator can legitimately point an OpenAI-compatible
    /// backend at. Pre-fix any user-set `baseURL` was accepted —
    /// including attacker-controlled hosts that would happily collect
    /// the API key on the first request. We allow the canonical OpenAI
    /// API, Azure OpenAI endpoints, and the `localhost` family used by
    /// LocalAI / vLLM-shaped self-hosted gateways.
    /// Exact host names (no subdomains accepted) plus dot-anchored
    /// suffix entries. v1.12.0 RC27 audit: the previous suffix list
    /// used `lower.hasSuffix(suffix)` which let `evilapi.openai.com`
    /// pass the `api.openai.com` check (suffix matches because
    /// "evilapi.openai.com" ends with "api.openai.com" character-wise).
    /// Now we require either the EXACT host or a dot-anchored suffix —
    /// "x.openai.azure.com" matches ".openai.azure.com" but plain
    /// "openai.azure.com.attacker.com" does NOT.
    private static let allowedExactHosts: Set<String> = [
        "api.openai.com",
        "localhost",
        "127.0.0.1",
        "::1",
    ]
    private static let allowedDotSuffixes: [String] = [
        ".openai.azure.com",
    ]

    // `internal` (not private) so the allow/reject matrix is unit-tested — this
    // is the RC27 key-exfil guard: a non-allowlisted baseURL host must never
    // carry the API key off to an attacker domain.
    static func isHostAllowed(_ host: String) -> Bool {
        let lower = host.lowercased()
        if allowedExactHosts.contains(lower) { return true }
        return allowedDotSuffixes.contains { suffix in
            lower.hasSuffix(suffix) && lower.count > suffix.count
        }
    }

    public init(baseURL: String = "https://api.openai.com/v1",
                apiKey: String, model: String = "gpt-4o-mini") {
        let fallback = URL(string: "https://api.openai.com/v1")!
        let parsed = URL(string: baseURL)
        if let parsed,
           let host = parsed.host,
           Self.isHostAllowed(host),
           // RC27 leak guard (mirrors OllamaBackend.isPlaintextRemote): an
           // `http://` base URL to a non-loopback host — e.g. `http://api.openai.com`
           // or a spoofed `http://127.0.0.1.evil.com` — would send the Bearer API
           // key in cleartext. Reject it; loopback over http stays allowed.
           !OllamaBackend.isPlaintextRemote(parsed) {
            self.baseURL = parsed
        } else {
            // Log the rejected URL at .public privacy — operators need to
            // see WHICH baseURL we rejected so they can fix the config.
            // Logger isn't accessible from init (instance not built yet),
            // so use os_log directly.
            os_log("OpenAIBackend: rejecting non-allowlisted baseURL %{public}@ — falling back to api.openai.com",
                   log: OSLog(subsystem: "com.maccrab.llm", category: "openai"),
                   type: .error,
                   baseURL)
            self.baseURL = fallback
        }
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
            (data, response) = try await session.data(for: request)
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
