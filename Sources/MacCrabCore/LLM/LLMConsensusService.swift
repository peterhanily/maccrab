// LLMConsensusService.swift
// MacCrabCore
//
// Fan out a classification prompt to multiple LLM backends in parallel,
// then aggregate the per-backend labels into a consensus. Used to reduce
// single-model hallucination risk on high-severity alerts: if Claude
// flags something as malicious but Ollama and GPT-4o disagree, the
// dashboard surfaces the disagreement rather than acting on one vote.
//
// The service takes pre-built `LLMService` instances rather than
// building them internally — this keeps wiring explicit (each backend
// is configured with its own config object, its own sanitizer flag,
// its own cache) and leaves the caller in control of how many backends
// to consult. A lone-backend ConsensusService still works: it just
// degenerates to single-vote, which is fine.
//
// Prompts are designed to produce one-word answers from the allowed
// label set. We parse responses with a case-insensitive prefix match
// and fall back to `.inconclusive` when the LLM refuses, wanders, or
// times out — the goal is "don't lose a vote", not "extract the right
// answer from any response".

import Foundation
import os.log

// MARK: - ConsensusVote

/// A single backend's vote in a consensus query.
public struct ConsensusVote: Sendable, Hashable {
    public let backend: String
    public let label: String
    public let rawResponse: String
    public let latencySeconds: Double
    public let usedCache: Bool

    public init(backend: String, label: String, rawResponse: String,
                latencySeconds: Double, usedCache: Bool) {
        self.backend = backend
        self.label = label
        self.rawResponse = rawResponse
        self.latencySeconds = latencySeconds
        self.usedCache = usedCache
    }
}

// MARK: - ConsensusResult

/// Outcome of a consensus query across N backends.
public struct ConsensusResult: Sendable, Hashable {
    /// Every vote collected (backends that timed out / errored are
    /// still represented, with label == `.inconclusive`).
    public let votes: [ConsensusVote]

    /// The winning label if at least `threshold` votes agreed; nil
    /// when no label reaches the threshold.
    public let consensus: String?

    /// Number of votes that landed on the winning label, or 0 if
    /// there is no winner.
    public let winningVoteCount: Int

    /// Fraction of backends (0.0 – 1.0) that agreed with the
    /// consensus. 0.0 when `consensus` is nil.
    public let agreement: Double

    /// Distribution of labels across votes.
    public let tally: [String: Int]

    public init(votes: [ConsensusVote], consensus: String?, winningVoteCount: Int,
                agreement: Double, tally: [String: Int]) {
        self.votes = votes
        self.consensus = consensus
        self.winningVoteCount = winningVoteCount
        self.agreement = agreement
        self.tally = tally
    }
}

// MARK: - LLMConsensusService

public actor LLMConsensusService {
    private let logger = Logger(subsystem: "com.maccrab.llm", category: "consensus")

    private let services: [LLMService]
    private let threshold: Int
    private let perQueryTimeout: Duration

    /// Inconclusive label used when a backend times out or answers
    /// with text that doesn't match any of the requested labels.
    public static let inconclusiveLabel = "inconclusive"

    /// Designated initializer.
    ///
    /// - Parameters:
    ///   - services: one `LLMService` per configured backend. Order
    ///     is preserved in `ConsensusResult.votes`.
    ///   - threshold: minimum number of agreeing votes for a
    ///     consensus to be declared. Clamped to `[1, services.count]`.
    ///   - perQueryTimeout: per-backend deadline. The slowest
    ///     backend can't block the full result; on timeout that
    ///     backend's vote becomes `inconclusive`.
    public init(services: [LLMService],
                threshold: Int = 2,
                perQueryTimeout: Duration = .seconds(15)) {
        self.services = services
        self.threshold = max(1, min(threshold, max(1, services.count)))
        self.perQueryTimeout = perQueryTimeout
    }

    public var backendCount: Int { services.count }

    // MARK: Classification

    /// Ask every configured backend to label the prompt with one of
    /// `labels`, then tally the votes.
    ///
    /// Response parsing is a simple case-insensitive prefix match —
    /// if the LLM answers "malicious: this looks like ransomware",
    /// we treat it as `malicious`. This is robust against common
    /// LLM verbosity but does require the labels to be prefix-free
    /// relative to each other (`"real"` vs `"really_real"` would
    /// collide — just avoid that).
    public func classify(
        systemPrompt: String,
        userPrompt: String,
        labels: [String],
        temperature: Double = 0.1,
        maxTokens: Int = 120
    ) async -> ConsensusResult {
        guard !services.isEmpty else {
            return Self.empty
        }
        guard !labels.isEmpty else {
            return Self.empty
        }

        let enforcedSystem = Self.enforceLabelsInSystemPrompt(
            systemPrompt: systemPrompt,
            labels: labels
        )

        let timeout = perQueryTimeout
        let services = self.services
        let votes = await withTaskGroup(of: ConsensusVote.self) { group in
            for service in services {
                group.addTask {
                    await Self.collectVote(
                        service: service,
                        systemPrompt: enforcedSystem,
                        userPrompt: userPrompt,
                        labels: labels,
                        maxTokens: maxTokens,
                        temperature: temperature,
                        timeout: timeout
                    )
                }
            }
            var collected: [ConsensusVote] = []
            collected.reserveCapacity(services.count)
            for await vote in group {
                collected.append(vote)
            }
            return collected
        }

        return Self.aggregate(votes: votes, threshold: threshold)
    }

    // MARK: Internals

    private static let empty = ConsensusResult(
        votes: [], consensus: nil, winningVoteCount: 0,
        agreement: 0.0, tally: [:]
    )

    /// Prepend a terse "answer with ONE of these labels" directive to
    /// the caller's system prompt so we don't rely on prompt authors
    /// always remembering to constrain the output shape.
    static func enforceLabelsInSystemPrompt(systemPrompt: String, labels: [String]) -> String {
        let shown = labels.joined(separator: ", ")
        let directive = """
        Answer with exactly ONE of these labels and nothing else: \(shown).
        No punctuation, no explanation, no preamble — just the label word.
        """
        return systemPrompt.isEmpty ? directive : "\(directive)\n\n\(systemPrompt)"
    }

    /// Run a single backend with a timeout, parse its response into a
    /// vote. Errors and timeouts map to `inconclusive`.
    static func collectVote(
        service: LLMService,
        systemPrompt: String,
        userPrompt: String,
        labels: [String],
        maxTokens: Int,
        temperature: Double,
        timeout: Duration
    ) async -> ConsensusVote {
        let providerName = await service.providerNameBestEffort()
        let start = Date()

        // Race the query against a timeout task.
        let enhancement: LLMEnhancement? = await withTaskGroup(of: LLMEnhancement?.self) { group in
            group.addTask {
                await service.query(
                    systemPrompt: systemPrompt,
                    userPrompt: userPrompt,
                    maxTokens: maxTokens,
                    temperature: temperature,
                    useCache: false  // fresh vote every time
                )
            }
            group.addTask {
                try? await Task.sleep(for: timeout)
                return nil
            }
            let first = await group.next() ?? nil
            group.cancelAll()
            return first ?? nil
        }

        guard let enhancement = enhancement else {
            return ConsensusVote(
                backend: providerName,
                label: inconclusiveLabel,
                rawResponse: "",
                latencySeconds: Date().timeIntervalSince(start),
                usedCache: false
            )
        }

        let label = parseLabel(enhancement.response, labels: labels)
        return ConsensusVote(
            backend: enhancement.provider.isEmpty ? providerName : enhancement.provider,
            label: label,
            rawResponse: enhancement.response,
            latencySeconds: enhancement.latency > 0 ? enhancement.latency : Date().timeIntervalSince(start),
            usedCache: enhancement.cached
        )
    }

    /// Case-insensitive prefix match against the allowed labels.
    /// Strips leading whitespace/quotes/markdown so a response like
    /// `"**real**"` or `"'malicious'"` still classifies.
    static func parseLabel(_ raw: String, labels: [String]) -> String {
        let stripped = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "*`'\"\n\r\t .,:"))
            .lowercased()
        if stripped.isEmpty { return inconclusiveLabel }
        for label in labels {
            let l = label.lowercased()
            if stripped == l || stripped.hasPrefix(l + " ") || stripped.hasPrefix(l + ":") {
                return label
            }
        }
        // Softer match: any label that appears as a whole-word prefix
        // of the trimmed response. Helps when the LLM prepends a
        // disclaimer that the directive was supposed to prevent.
        for label in labels {
            let l = label.lowercased()
            if stripped.hasPrefix(l) {
                return label
            }
        }
        return inconclusiveLabel
    }

    /// Aggregate a collection of votes into a ConsensusResult. Ties
    /// are broken alphabetically so the output is deterministic.
    static func aggregate(votes: [ConsensusVote], threshold: Int) -> ConsensusResult {
        guard !votes.isEmpty else { return empty }
        var tally: [String: Int] = [:]
        for vote in votes {
            tally[vote.label, default: 0] += 1
        }
        let sorted = tally.sorted { lhs, rhs in
            if lhs.value != rhs.value { return lhs.value > rhs.value }
            return lhs.key < rhs.key
        }
        let winner = sorted.first
        let winnerCount = winner?.value ?? 0
        let consensus = (winnerCount >= threshold && winner?.key != inconclusiveLabel) ? winner?.key : nil
        let agreement = consensus.map { _ in Double(winnerCount) / Double(votes.count) } ?? 0.0
        return ConsensusResult(
            votes: votes,
            consensus: consensus,
            winningVoteCount: consensus == nil ? 0 : winnerCount,
            agreement: agreement,
            tally: tally
        )
    }
}

// MARK: - LLMService convenience (internal)

internal extension LLMService {
    /// Best-effort provider name for logging / vote attribution.
    /// LLMService exposes this only indirectly through `LLMEnhancement`,
    /// and we need a name even when the query times out — so peek at
    /// the backend directly here.
    func providerNameBestEffort() async -> String {
        // The `backend` actor-isolated property isn't directly
        // reachable; route through a tiny query-less helper.
        await self.describeProvider()
    }
}
