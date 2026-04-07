// LLMService.swift
// MacCrabCore
//
// Central LLM orchestrator. Routes requests through sanitization,
// caching, and rate limiting before dispatching to the configured backend.

import Foundation
import os.log

public actor LLMService {
    private let logger = Logger(subsystem: "com.maccrab.llm", category: "service")

    private let backend: any LLMBackend
    private let cache: LLMCache
    private let shouldSanitize: Bool

    /// Rate limiting: minimum interval between calls (seconds).
    private let minInterval: TimeInterval = 5.0
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

    public init(backend: any LLMBackend, config: LLMConfig,
                cache: LLMCache = LLMCache()) {
        self.backend = backend
        self.cache = cache
        // Only sanitize for cloud providers; Ollama is local
        let isLocalProvider = config.provider == .ollama
            && config.ollamaURL.contains("localhost") || config.ollamaURL.contains("127.0.0.1")
        self.shouldSanitize = !isLocalProvider && config.sanitizeForCloud
    }

    /// Check if the LLM backend is available.
    public func isAvailable() async -> Bool {
        await backend.isAvailable()
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
            let key = LLMCache.cacheKey(system: finalSystem, user: finalUser)
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

        consecutiveFailures = 0  // Reset on success

        // Response size guard
        guard response.count <= maxResponseSize else {
            logger.warning("LLM response too large (\(response.count) bytes), discarding")
            return nil
        }

        let latency = Date().timeIntervalSince(start)

        if useCache {
            let key = LLMCache.cacheKey(system: finalSystem, user: finalUser)
            await cache.set(key: key, response: response)
        }

        logger.info("LLM query completed in \(String(format: "%.2f", latency))s (\(providerName))")

        return LLMEnhancement(
            provider: await backend.providerName,
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
