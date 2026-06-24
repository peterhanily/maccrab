// LLMService.swift
// MacCrabCore
//
// Central LLM orchestrator. Routes requests through sanitization,
// caching, and rate limiting before dispatching to the configured backend.

import Foundation
import os.log

/// v1.18: engine LLM health snapshot, surfaced in heartbeat_rich.json so an
/// "enabled but unreachable / misconfigured" backend is visible instead of
/// failing silently. Sendable so it can cross the actor boundary.
public struct LLMHealth: Sendable {
    public let provider: String
    public let model: String
    public let lastSuccessAtUnix: Double?
    public let consecutiveFailures: Int
    public let circuitOpen: Bool
}

public actor LLMService {
    private let logger = Logger(subsystem: "com.maccrab.llm", category: "service")

    private let backend: any LLMBackend
    private let cache: LLMCache
    private let shouldSanitize: Bool

    /// Rate limiting: minimum interval between calls (seconds). Injectable
    /// (default 5.0, production unchanged) so tests can drive multi-call paths
    /// — circuit breaker, cache — without 5s stalls per call.
    private let minInterval: TimeInterval
    private var lastCallTime: Date = .distantPast

    /// Circuit breaker: disable after consecutive failures.
    private var consecutiveFailures: Int = 0
    private var circuitOpenUntil: Date = .distantPast
    private let maxConsecutiveFailures: Int = 3
    private let circuitResetInterval: TimeInterval = 300  // 5 minutes

    /// Max response size to accept (bytes).
    private let maxResponseSize: Int = 50_000  // ~50KB

    private var totalCalls: Int = 0
    private var cacheHits: Int = 0

    /// v1.18: health observability — timestamp of the last successful
    /// backend response + the configured provider/model labels, so
    /// "enabled but never succeeded" is distinguishable from "working".
    private var lastSuccessAt: Date?
    private let providerLabel: String
    private let modelLabel: String

    public init(backend: any LLMBackend, config: LLMConfig,
                cache: LLMCache = LLMCache(),
                minInterval: TimeInterval = 5.0) {
        self.backend = backend
        self.cache = cache
        self.minInterval = minInterval
        // Only sanitize for cloud providers; Ollama is local. The host is
        // parsed (strict loopback check) rather than substring-matched: a
        // remote Ollama at `http://127.0.0.1.evil.com` must NOT be treated
        // as local, or every prompt would skip the sanitizer and leak
        // usernames/paths/IPs to the attacker host. Sanitization stays on
        // for all genuinely-remote endpoints.
        self.shouldSanitize = Self.shouldSanitize(for: config)
        self.providerLabel = config.provider.rawValue
        switch config.provider {
        case .ollama:  self.modelLabel = config.ollamaModel
        case .claude:  self.modelLabel = config.claudeModel
        case .openai:  self.modelLabel = config.openaiModel
        case .mistral: self.modelLabel = config.mistralModel
        case .gemini:  self.modelLabel = config.geminiModel
        }
    }

    /// Whether prompts must be run through `LLMSanitizer` before dispatch.
    /// Local Ollama on a loopback URL bypasses it (no data leaves the host);
    /// every genuinely-remote endpoint sanitizes when `sanitizeForCloud` is
    /// on. `nonisolated static` so the local-vs-cloud decision is unit-tested
    /// without building a backend or crossing the actor boundary.
    nonisolated static func shouldSanitize(for config: LLMConfig) -> Bool {
        // A remote Ollama at `http://127.0.0.1.evil.com` must NOT be treated
        // as local, or every prompt would skip the sanitizer and leak
        // usernames/paths/IPs to the attacker host — hence the strict
        // loopback parse rather than a substring match.
        let isLocalProvider = config.provider == .ollama
            && LoopbackEndpoint.isLoopback(urlString: config.ollamaURL)
        return !isLocalProvider && config.sanitizeForCloud
    }

    /// Reset the failure counter AND stamp the last-success time. Called on
    /// every successful backend response (regular + extended-thinking paths).
    private func markSuccess() {
        consecutiveFailures = 0
        lastSuccessAt = Date()
    }

    /// v1.18: current LLM health for the heartbeat. Pure read of internal
    /// state; safe to call from the heartbeat timer.
    public func healthSnapshot() -> LLMHealth {
        LLMHealth(
            provider: providerLabel,
            model: modelLabel,
            lastSuccessAtUnix: lastSuccessAt?.timeIntervalSince1970,
            consecutiveFailures: consecutiveFailures,
            circuitOpen: Date() < circuitOpenUntil
        )
    }

    /// Build an `LLMService` from an `LLMConfig`, picking the right
    /// backend per `config.provider`. Returns nil when the config is
    /// disabled, when the chosen provider needs an API key that is
    /// empty, or when the backend reports itself unavailable.
    ///
    /// Used by both the daemon (DaemonSetup) and the app (AppState) so
    /// the construction path stays identical on both sides of the
    /// privilege boundary. The dashboard side is the v1.6.10 home for
    /// the LLM-orchestration trio (TriageService, LLMConsensusService,
    /// AgenticInvestigator) — making outbound HTTPS at root privilege
    /// is unnecessary trust surface, so those callers use the user-side
    /// service instead.
    public static func makeFromConfig(_ config: LLMConfig) async -> LLMService? {
        guard config.enabled else { return nil }
        let backend: any LLMBackend
        switch config.provider {
        case .ollama:
            backend = OllamaBackend(
                baseURL: config.ollamaURL,
                model: config.ollamaModel,
                apiKey: config.ollamaAPIKey
            )
        case .claude:
            guard let key = config.claudeAPIKey, !key.isEmpty else { return nil }
            backend = ClaudeBackend(apiKey: key, model: config.claudeModel)
        case .openai:
            guard let key = config.openaiAPIKey, !key.isEmpty else { return nil }
            backend = OpenAIBackend(baseURL: config.openaiURL, apiKey: key, model: config.openaiModel)
        case .mistral:
            guard let key = config.mistralAPIKey, !key.isEmpty else { return nil }
            backend = MistralBackend(apiKey: key, model: config.mistralModel)
        case .gemini:
            guard let key = config.geminiAPIKey, !key.isEmpty else { return nil }
            backend = GeminiBackend(apiKey: key, model: config.geminiModel)
        }
        let service = LLMService(backend: backend, config: config)
        // v1.12.0 RC27 (resiliency): bound the availability probe with
        // a 3-second deadline. URLSession's default timeout is 60 s; on
        // an unreachable Ollama or a captive-portal network the
        // pre-fix await blocked the entire caller (dashboard launch,
        // daemon boot path) for that full minute.
        let available: Bool = await withTaskGroup(of: Bool?.self) { group in
            group.addTask { await service.isAvailable() }
            group.addTask {
                try? await Task.sleep(nanoseconds: 3_000_000_000)
                return nil  // timeout sentinel
            }
            let first = await group.next() ?? .some(false)
            group.cancelAll()
            return first ?? false  // nil means timeout — treat as unavailable
        }
        return available ? service : nil
    }

    /// Check if the LLM backend is available.
    public func isAvailable() async -> Bool {
        await backend.isAvailable()
    }

    /// Best-effort human-readable backend name. Useful for logging and
    /// for the consensus service, which needs a vote identifier even
    /// when a query times out (no `LLMEnhancement` to read `.provider`
    /// from).
    public func describeProvider() async -> String {
        await backend.providerName
    }

    /// Send a prompt to the LLM with sanitization, caching, and rate limiting.
    public func query(
        systemPrompt: String,
        userPrompt: String,
        maxTokens: Int = 2048,
        temperature: Double = 0.2,
        useCache: Bool = true
    ) async -> LLMEnhancement? {
        // Circuit breaker: skip if too many recent failures
        if consecutiveFailures >= maxConsecutiveFailures {
            if Date() < circuitOpenUntil {
                logger.info("LLM circuit breaker open, skipping query")
                return nil
            }
            // Reset after cooldown
            consecutiveFailures = 0
        }

        let finalSystem = shouldSanitize ? LLMSanitizer.sanitize(systemPrompt) : systemPrompt
        let finalUser = shouldSanitize ? LLMSanitizer.sanitize(userPrompt) : userPrompt

        // Check cache
        if useCache {
            let key = LLMCache.cacheKey(system: finalSystem, user: finalUser,
                                        temperature: temperature, maxTokens: maxTokens)
            if let cached = await cache.get(key: key) {
                cacheHits += 1
                return LLMEnhancement(
                    provider: await backend.providerName,
                    prompt: finalUser, response: cached,
                    latency: 0, cached: true
                )
            }
        }

        // Rate limiting
        let elapsed = Date().timeIntervalSince(lastCallTime)
        if elapsed < minInterval {
            try? await Task.sleep(nanoseconds: UInt64((minInterval - elapsed) * 1_000_000_000))
        }

        let start = Date()
        lastCallTime = Date()
        totalCalls += 1

        let providerName = await backend.providerName

        guard let response = await backend.complete(
            systemPrompt: finalSystem, userPrompt: finalUser,
            maxTokens: maxTokens, temperature: temperature
        ) else {
            consecutiveFailures += 1
            if consecutiveFailures >= maxConsecutiveFailures {
                circuitOpenUntil = Date().addingTimeInterval(circuitResetInterval)
                logger.warning("LLM circuit breaker opened after \(self.consecutiveFailures) failures (provider: \(providerName))")
            } else {
                logger.warning("LLM query failed (provider: \(providerName), failures: \(self.consecutiveFailures))")
            }
            return nil
        }

        markSuccess()  // reset failures + stamp last-success time

        // Response size guard
        guard response.count <= maxResponseSize else {
            logger.warning("LLM response too large (\(response.count) bytes), discarding")
            return nil
        }

        let latency = Date().timeIntervalSince(start)

        if useCache {
            let key = LLMCache.cacheKey(system: finalSystem, user: finalUser,
                                        temperature: temperature, maxTokens: maxTokens)
            await cache.set(key: key, response: response)
        }

        logger.info("LLM query completed in \(String(format: "%.2f", latency))s (\(providerName))")

        return LLMEnhancement(
            provider: await backend.providerName,
            prompt: finalUser, response: response,
            latency: latency, cached: false
        )
    }

    /// Send a prompt using extended thinking when the backend supports it.
    /// Applies the same circuit breaker, rate limiting, and sanitization as
    /// `query()`, but calls `backend.completeWithExtendedThinking()` instead
    /// of `backend.complete()`. On backends that don't support extended
    /// thinking, this falls back to a regular `complete()` call — callers
    /// always receive a response or nil.
    ///
    /// Use for tasks that benefit from deep multi-step reasoning:
    /// - Full kill-chain campaign attribution
    /// - Novel malware family classification
    /// - Complex threat hunting queries
    ///
    /// Extended thinking calls take significantly longer (30–90s); the
    /// timeout on the HTTP request is 120s. Do not use for latency-sensitive
    /// paths.
    public func queryWithExtendedThinking(
        systemPrompt: String,
        userPrompt: String,
        thinkingBudgetTokens: Int = 8000,
        maxOutputTokens: Int = 4096
    ) async -> LLMEnhancement? {
        if consecutiveFailures >= maxConsecutiveFailures {
            if Date() < circuitOpenUntil { return nil }
            consecutiveFailures = 0
        }
        let finalSystem = shouldSanitize ? LLMSanitizer.sanitize(systemPrompt) : systemPrompt
        let finalUser = shouldSanitize ? LLMSanitizer.sanitize(userPrompt) : userPrompt

        let elapsed = Date().timeIntervalSince(lastCallTime)
        if elapsed < minInterval {
            try? await Task.sleep(nanoseconds: UInt64((minInterval - elapsed) * 1_000_000_000))
        }

        let start = Date()
        lastCallTime = Date()
        totalCalls += 1

        let providerName = await backend.providerName

        guard let response = await backend.completeWithExtendedThinking(
            systemPrompt: finalSystem,
            userPrompt: finalUser,
            thinkingBudgetTokens: thinkingBudgetTokens,
            maxOutputTokens: maxOutputTokens
        ) else {
            consecutiveFailures += 1
            if consecutiveFailures >= maxConsecutiveFailures {
                circuitOpenUntil = Date().addingTimeInterval(circuitResetInterval)
                logger.warning("LLM circuit breaker opened (extended thinking) after \(self.consecutiveFailures) failures")
            }
            return nil
        }

        markSuccess()  // reset failures + stamp last-success time
        guard response.count <= maxResponseSize else {
            logger.warning("LLM extended-thinking response too large, discarding")
            return nil
        }
        let latency = Date().timeIntervalSince(start)
        logger.info("LLM extended-thinking query completed in \(String(format: "%.2f", latency))s (\(providerName))")

        return LLMEnhancement(
            provider: providerName,
            prompt: finalUser, response: response,
            latency: latency, cached: false
        )
    }

    /// Statistics for monitoring.
    public func stats() async -> (totalCalls: Int, cacheHits: Int, cacheEntries: Int, provider: String) {
        let cs = await cache.stats()
        let name = await backend.providerName
        return (totalCalls, cacheHits, cs.entries, name)
    }
}
