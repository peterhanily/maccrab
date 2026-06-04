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
    /// v1.12.0 RC25 audit fix: nil-host URLs (`http:///path`, malformed
    /// scheme://) are now treated as remote — the old nil-then-true
    /// path also caught the case but inconsistently. Be explicit.
    static func isPlaintextRemote(_ url: URL) -> Bool {
        guard url.scheme?.lowercased() == "http" else { return false }
        guard let host = url.host, !host.isEmpty else {
            // A nil/empty host means the URL parsed weirdly (e.g.,
            // `http:////path`). Treat as remote so we never leak an
            // API key over plaintext to an unknown destination.
            return true
        }
        // Strict loopback check (IPv4-literal parse, not a `127.` prefix):
        // a host like `127.0.0.1.evil.com` is remote and must not receive
        // a plaintext Bearer token.
        return !LoopbackEndpoint.isLoopback(host: host)
    }

    public func isAvailable() async -> Bool {
        let url = baseURL.appendingPathComponent("api/tags")
        guard let (_, response) = try? await session.data(from: url),
              let http = response as? HTTPURLResponse,
              http.statusCode == 200 else { return false }
        return true
    }

    // MARK: - Model presence probe (v1.17.4)

    /// True iff `configured` names a model present in `availableTags`.
    /// Pure + unit-testable. Matches the exact tag, and tolerates Ollama's
    /// `:latest` aliasing (so `llama3.1` matches `llama3.1:latest` and vice
    /// versa) — but does NOT treat a bare name as matching an arbitrary
    /// version tag (`llama3.1` does not match only-`llama3.1:8b`), mirroring
    /// Ollama's own resolution.
    static func modelTagMatches(configured: String, availableTags: [String]) -> Bool {
        func norm(_ s: String) -> String {
            let l = s.lowercased()
            return l.hasSuffix(":latest") ? String(l.dropLast(":latest".count)) : l
        }
        let want = configured.lowercased()
        let wantNorm = norm(configured)
        return availableTags.contains { $0.lowercased() == want || norm($0) == wantNorm }
    }

    /// Installed model tags from `GET /api/tags` (e.g. `["qwen2.5:7b"]`),
    /// or nil on any network/parse failure.
    public func listModels() async -> [String]? {
        let url = baseURL.appendingPathComponent("api/tags")
        guard let (data, response) = try? await session.data(from: url),
              let http = response as? HTTPURLResponse, http.statusCode == 200,
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let models = obj["models"] as? [[String: Any]] else { return nil }
        return models.compactMap { $0["name"] as? String }
    }

    /// Whether this backend's configured model is actually pulled.
    /// `true`/`false` = determined; `nil` = couldn't reach `/api/tags`, so
    /// the caller should stay optimistic (a transiently-down Ollama at boot
    /// must not permanently disable LLM until restart).
    public func modelIsInstalled() async -> Bool? {
        guard let tags = await listModels() else { return nil }
        return Self.modelTagMatches(configured: model, availableTags: tags)
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
