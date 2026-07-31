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
    /// AI-06/AI-08: the single "is this backend genuinely usable right now"
    /// answer — see `LLMService.isUsable()`. The heartbeat's `healthy` field
    /// and the `maccrab.llm.*` emission gate BOTH read this one value, so the
    /// gauge and the behaviour can never disagree.
    public let usable: Bool
}

public actor LLMService {
    private let logger = Logger(subsystem: "com.maccrab.llm", category: "service")

    private let backend: any LLMBackend
    private let cache: LLMCache
    private let shouldSanitize: Bool
    /// Strict no-leak mode — refuse a cloud call if the sanitized prompt still
    /// has residual high-entropy content (LLMConfig.strictSanitize).
    private let strictSanitize: Bool

    /// Rate limiting: minimum interval between calls (seconds). Injectable
    /// (default 5.0, production unchanged) so tests can drive multi-call paths
    /// — circuit breaker, cache — without 5s stalls per call.
    private let minInterval: TimeInterval
    private var lastCallTime: Date = .distantPast

    /// AI-14 admission control. There was NO bound on how many callers could be
    /// in the slow path at once: a burst of N behaviour-threshold crossings
    /// queued N suspended tasks, each pinning its captured enrichedEvent and
    /// indicator array, draining at one per `minInterval` — so the last alert
    /// arrived minutes stale and memory grew with the burst, all to produce
    /// advisory prose. Cache hits are served BEFORE this gate (they cost
    /// nothing), so only genuine backend calls are counted. Over the cap we drop
    /// the NEWEST request and say so in the log rather than growing the queue:
    /// LLM output is advisory, the alert itself is stored regardless, and a
    /// silent unbounded backlog is the worse failure.
    private var pendingBackendCalls: Int = 0
    private let maxPendingBackendCalls: Int = 4
    private var droppedForAdmission: Int = 0

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
        self.strictSanitize = config.strictSanitize
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
            // v1.21.5 (audit S-02): loopback is necessary but NOT sufficient for
            // the sanitizer bypass. Any local process can run a listener on
            // 127.0.0.1, and the ENGINE's LLM endpoint is settable over the
            // privileged inbox by any console-admin uid — so a uid-501 attacker
            // could point the root engine at its own port and, because the URL
            // parses as loopback, receive every prompt unsanitized.
            // `trustLocalEndpoint` carries the provenance: false when the
            // endpoint arrived over that control plane, in which case prompts are
            // sanitized even though the host is genuinely loopback.
            && config.trustLocalEndpoint
            && LoopbackEndpoint.isLoopback(urlString: config.ollamaURL)
        return !isLocalProvider && config.sanitizeForCloud
    }

    /// Reset the failure counter AND stamp the last-success time. Called on
    /// every successful backend response (regular + extended-thinking paths).
    private func markSuccess() {
        consecutiveFailures = 0
        lastSuccessAt = Date()
    }

    /// AI-06/AI-08: the single honest "is this LLM genuinely usable right now"
    /// predicate. Three conditions, all required:
    ///
    ///  - the backend has actually answered at least once (`lastSuccessAt`).
    ///    "Configured" is not evidence: every cloud backend's `isAvailable()`
    ///    is only `!apiKey.isEmpty`, and the ENGINE skips the probe entirely
    ///    (DaemonSetup: "availability checked lazily"), so a non-empty key
    ///    pointed at a dead port looks configured and answers nothing;
    ///  - no failure streak. `consecutiveFailures` returns to 0 only on a
    ///    success, so any non-zero value means the last thing we know is a
    ///    failure;
    ///  - the circuit is not open.
    ///
    /// The failure-streak term is what fixes the AI-08 lie. `circuitOpenUntil`
    /// expires on the CLOCK alone — no success required — while
    /// `consecutiveFailures` stays at 3, so a backend that succeeded once at
    /// boot and then died reported `healthy: true, circuit_open: false,
    /// consecutive_failures: 3` for the rest of the daemon's life.
    ///
    /// Deliberately NOT time-boxed: an idle-but-working local Ollama that has
    /// not been asked anything for hours is healthy, not stale, and must keep
    /// both its "healthy" gauge and its commentary.
    public func isUsable() -> Bool {
        lastSuccessAt != nil && consecutiveFailures == 0 && Date() >= circuitOpenUntil
    }

    /// v1.18: current LLM health for the heartbeat. Pure read of internal
    /// state; safe to call from the heartbeat timer.
    public func healthSnapshot() -> LLMHealth {
        LLMHealth(
            provider: providerLabel,
            model: modelLabel,
            lastSuccessAtUnix: lastSuccessAt?.timeIntervalSince1970,
            consecutiveFailures: consecutiveFailures,
            circuitOpen: Date() < circuitOpenUntil,
            usable: isUsable()
        )
    }

    /// Build an `LLMService` from an `LLMConfig`, picking the right
    /// backend per `config.provider`. Returns nil when the config is
    /// disabled, when the chosen provider needs an API key that is
    /// empty, or when the backend reports itself unavailable.
    ///
    /// Used by both the daemon (DaemonSetup) and the app (SettingsView's
    /// "Test connection") so the construction path stays identical on both
    /// sides of the privilege boundary. The v1.6.10 LLM-orchestration trio
    /// that used to live on the app side (TriageService, LLMConsensusService,
    /// AgenticInvestigator) was deleted in v1.21.6 — all three had zero call
    /// sites. Keeping outbound HTTPS off the ES-entitlement root process is
    /// still the rule for anything added back here.
    public static func makeFromConfig(_ config: LLMConfig) async -> LLMService? {
        guard config.enabled else { return nil }
        // AI-08: every failure path below used to `return nil` silently, so a
        // user-side config of `provider: openai` with an EMPTY key produced a
        // dead LLM stack with no signal anywhere — and the only health gauge in
        // the product is the DAEMON's LLMService, which happily reported its own
        // Ollama as healthy. The owner had no way to learn their Settings choice
        // had produced nothing. Log the concrete reason on each path.
        let setupLog = Logger(subsystem: "com.maccrab.llm", category: "service")
        let backend: any LLMBackend
        switch config.provider {
        case .ollama:
            backend = OllamaBackend(
                baseURL: config.ollamaURL,
                model: config.ollamaModel,
                apiKey: config.ollamaAPIKey
            )
        case .claude:
            guard let key = config.claudeAPIKey, !key.isEmpty else {
                setupLog.error("LLM disabled: provider=claude but no API key configured")
                return nil
            }
            backend = ClaudeBackend(apiKey: key, model: config.claudeModel)
        case .openai:
            guard let key = config.openaiAPIKey, !key.isEmpty else {
                setupLog.error("LLM disabled: provider=openai but no API key configured (url=\(config.openaiURL, privacy: .public))")
                return nil
            }
            backend = OpenAIBackend(baseURL: config.openaiURL, apiKey: key, model: config.openaiModel)
        case .mistral:
            guard let key = config.mistralAPIKey, !key.isEmpty else {
                setupLog.error("LLM disabled: provider=mistral but no API key configured")
                return nil
            }
            backend = MistralBackend(apiKey: key, model: config.mistralModel)
        case .gemini:
            guard let key = config.geminiAPIKey, !key.isEmpty else {
                setupLog.error("LLM disabled: provider=gemini but no API key configured")
                return nil
            }
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
        if !available {
            // AI-08: the second silent death. The user-side config on the
            // reporting host pointed at `http://127.0.0.1:52429/v1` — an
            // EPHEMERAL port from a long-gone proxy — so this probe failed and
            // the whole user-side LLM stack (MCP intent classification,
            // `maccrabctl hunt`, dashboard triage, agentic investigation)
            // silently went dark while the heartbeat still reported the
            // daemon's Ollama healthy. Name the endpoint that failed.
            setupLog.error("LLM disabled: provider=\(config.provider.rawValue, privacy: .public) configured but backend did not answer the availability probe within 3s")
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

        // Strict no-leak mode: if we're sending to a cloud endpoint and the
        // sanitized prompt STILL has residual high-entropy content the best-effort
        // regex may have missed, refuse the call rather than risk leaking a novel
        // secret shape. Trades analysis coverage for a hard no-leak boundary.
        if shouldSanitize && strictSanitize &&
            (LLMSanitizer.hasResidualSensitiveContent(finalSystem) ||
             LLMSanitizer.hasResidualSensitiveContent(finalUser)) {
            logger.warning("LLM strict mode: refusing cloud call — sanitized prompt still has residual high-entropy content")
            return nil
        }

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

        // AI-14: bounded admission, placed AFTER the cache lookup so a cached
        // answer is never dropped, and BEFORE the rate-limit sleep so the cap
        // bounds exactly the set of callers that would otherwise pile up at one
        // per minInterval.
        guard pendingBackendCalls < maxPendingBackendCalls else {
            droppedForAdmission += 1
            logger.warning("LLM admission control: \(self.maxPendingBackendCalls) backend calls already in flight — dropping this request (dropped so far: \(self.droppedForAdmission)). The alert itself is unaffected; only the advisory analysis is skipped.")
            return nil
        }
        pendingBackendCalls += 1
        defer { pendingBackendCalls -= 1 }

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

    /// AI-06: the entry point an emitter must use for LLM prose that becomes a
    /// `maccrab.llm.*` alert. Identical to `query()` except that it returns nil
    /// unless `isUsable()` holds AFTER the call — commentary is published only
    /// when AI analysis is genuinely set up and working.
    ///
    /// Why AFTER and not before: `isUsable()` requires evidence of a real
    /// exchange, and on a freshly-booted daemon that evidence can only come
    /// from the first call. Gating BEFORE would mean the first call never
    /// happens, `lastSuccessAt` is never set, and commentary would be dead
    /// forever on a perfectly good local Ollama.
    ///
    /// What this actually excludes: a cache hit (6 h TTL) served after the
    /// backend has died. `query()` returns the stored prose without touching
    /// the backend and without updating the failure/success state, so a dead
    /// LLM could otherwise keep publishing fresh-looking alerts.
    public func commentary(
        systemPrompt: String,
        userPrompt: String,
        maxTokens: Int = 2048,
        temperature: Double = 0.2,
        useCache: Bool = true
    ) async -> LLMEnhancement? {
        guard let result = await query(
            systemPrompt: systemPrompt, userPrompt: userPrompt,
            maxTokens: maxTokens, temperature: temperature, useCache: useCache
        ) else { return nil }
        guard isUsable() else {
            logger.info("Suppressing LLM commentary: backend not currently usable (failures: \(self.consecutiveFailures))")
            return nil
        }
        return result
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

        // Strict no-leak mode: same hard boundary the regular query() path
        // enforces. If the sanitized prompt STILL has residual high-entropy
        // content the best-effort regex may have missed, refuse rather than risk
        // leaking a novel secret shape to a cloud endpoint. This path was
        // previously missing the gate — a strict-mode leak could slip through the
        // extended-thinking route.
        if shouldSanitize && strictSanitize &&
            (LLMSanitizer.hasResidualSensitiveContent(finalSystem) ||
             LLMSanitizer.hasResidualSensitiveContent(finalUser)) {
            logger.warning("LLM strict mode: refusing cloud call (extended thinking) — sanitized prompt still has residual high-entropy content")
            return nil
        }

        // AI-14: extended thinking shares the same bound. These calls run 30–90s
        // each, so an unbounded pile-up here is strictly worse than on query().
        guard pendingBackendCalls < maxPendingBackendCalls else {
            droppedForAdmission += 1
            logger.warning("LLM admission control: \(self.maxPendingBackendCalls) backend calls already in flight — dropping this extended-thinking request (dropped so far: \(self.droppedForAdmission)).")
            return nil
        }
        pendingBackendCalls += 1
        defer { pendingBackendCalls -= 1 }

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
