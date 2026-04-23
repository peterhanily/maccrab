// LLMConsensusServiceTests.swift
//
// Coverage for the v1.6.6 Multi-Model Consensus feature. The actual
// fan-out across real LLM backends is exercised by the LLM integration
// tests (they run only when Ollama is reachable); this suite focuses
// on the parsing, tally, and threshold-application logic which is the
// source of subtle bugs.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("LLMConsensusService: label parsing")
struct ConsensusLabelParsingTests {

    @Test("Exact label match")
    func exactMatch() {
        #expect(LLMConsensusService.parseLabel("real", labels: ["real", "fp"]) == "real")
    }

    @Test("Case-insensitive match")
    func caseInsensitive() {
        #expect(LLMConsensusService.parseLabel("REAL", labels: ["real", "fp"]) == "real")
        #expect(LLMConsensusService.parseLabel("Real", labels: ["real", "fp"]) == "real")
    }

    @Test("Trailing period/newline stripped")
    func trailingPunctuation() {
        #expect(LLMConsensusService.parseLabel("real.", labels: ["real", "fp"]) == "real")
        #expect(LLMConsensusService.parseLabel("real\n", labels: ["real", "fp"]) == "real")
        #expect(LLMConsensusService.parseLabel("**real**", labels: ["real", "fp"]) == "real")
        #expect(LLMConsensusService.parseLabel("'real'", labels: ["real", "fp"]) == "real")
    }

    @Test("Label followed by colon-explanation still parses")
    func labelWithColon() {
        let result = LLMConsensusService.parseLabel(
            "malicious: this looks like ransomware",
            labels: ["malicious", "benign", "inconclusive"]
        )
        #expect(result == "malicious")
    }

    @Test("Label followed by space-explanation still parses")
    func labelWithSpace() {
        let result = LLMConsensusService.parseLabel(
            "benign because the parent is Apple-signed",
            labels: ["malicious", "benign"]
        )
        #expect(result == "benign")
    }

    @Test("Off-script answer falls back to inconclusive")
    func offScriptFallback() {
        let result = LLMConsensusService.parseLabel(
            "I cannot determine this without more context",
            labels: ["real", "fp"]
        )
        #expect(result == LLMConsensusService.inconclusiveLabel)
    }

    @Test("Empty response falls back to inconclusive")
    func emptyFallback() {
        #expect(LLMConsensusService.parseLabel("", labels: ["real", "fp"]) == LLMConsensusService.inconclusiveLabel)
        #expect(LLMConsensusService.parseLabel("   ", labels: ["real", "fp"]) == LLMConsensusService.inconclusiveLabel)
    }
}

@Suite("LLMConsensusService: aggregation")
struct ConsensusAggregationTests {

    private func vote(_ backend: String, _ label: String) -> ConsensusVote {
        ConsensusVote(
            backend: backend, label: label, rawResponse: label,
            latencySeconds: 0.1, usedCache: false
        )
    }

    @Test("Three votes, two agree on 'real', threshold=2 → consensus is 'real'")
    func majorityWins() {
        let votes = [vote("claude", "real"), vote("ollama", "real"), vote("openai", "fp")]
        let result = LLMConsensusService.aggregate(votes: votes, threshold: 2)
        #expect(result.consensus == "real")
        #expect(result.winningVoteCount == 2)
        #expect(result.agreement == 2.0 / 3.0)
        #expect(result.tally["real"] == 2)
        #expect(result.tally["fp"] == 1)
    }

    @Test("Three votes, all disagree, threshold=2 → no consensus")
    func noConsensusBelowThreshold() {
        let votes = [vote("a", "alpha"), vote("b", "beta"), vote("c", "gamma")]
        let result = LLMConsensusService.aggregate(votes: votes, threshold: 2)
        #expect(result.consensus == nil)
        #expect(result.winningVoteCount == 0)
        #expect(result.agreement == 0.0)
    }

    @Test("Consensus around inconclusive is NOT reported as consensus")
    func inconclusiveIsNotConsensus() {
        // Two backends timed out (→ inconclusive), one gave a real
        // answer. The aggregator must NOT declare "inconclusive" as
        // the winning consensus — that would be worse than nil.
        let votes = [
            vote("a", LLMConsensusService.inconclusiveLabel),
            vote("b", LLMConsensusService.inconclusiveLabel),
            vote("c", "real"),
        ]
        let result = LLMConsensusService.aggregate(votes: votes, threshold: 2)
        #expect(result.consensus == nil)
        #expect(result.tally[LLMConsensusService.inconclusiveLabel] == 2)
    }

    @Test("Ties broken alphabetically for deterministic output")
    func alphabeticTiebreak() {
        let votes = [vote("a", "zebra"), vote("b", "alpha")]
        let result = LLMConsensusService.aggregate(votes: votes, threshold: 1)
        #expect(result.consensus == "alpha", "With threshold=1 and a 1-1 tie, alphabetically-first label wins")
    }

    @Test("Single backend with threshold=1 behaves as pass-through")
    func singleBackendPassthrough() {
        let votes = [vote("only", "real")]
        let result = LLMConsensusService.aggregate(votes: votes, threshold: 1)
        #expect(result.consensus == "real")
        #expect(result.agreement == 1.0)
    }

    @Test("Empty votes return the 'no consensus' empty struct")
    func emptyVotes() {
        let result = LLMConsensusService.aggregate(votes: [], threshold: 1)
        #expect(result.consensus == nil)
        #expect(result.votes.isEmpty)
    }
}

@Suite("LLMConsensusService: system-prompt label enforcement")
struct ConsensusSystemPromptTests {

    @Test("Directive prepends the original system prompt")
    func prependsDirective() {
        let out = LLMConsensusService.enforceLabelsInSystemPrompt(
            systemPrompt: "You are a strict analyst.",
            labels: ["real", "fp", "inconclusive"]
        )
        #expect(out.contains("real, fp, inconclusive"))
        #expect(out.contains("You are a strict analyst."))
        // The label directive must come before the caller's prompt so
        // the model sees it even if the caller prompt is long.
        let directiveIdx = out.range(of: "Answer with exactly ONE")!.lowerBound
        let callerIdx = out.range(of: "strict analyst")!.lowerBound
        #expect(directiveIdx < callerIdx)
    }

    @Test("Empty system prompt still produces a directive-only prompt")
    func emptySystemPrompt() {
        let out = LLMConsensusService.enforceLabelsInSystemPrompt(
            systemPrompt: "", labels: ["yes", "no"]
        )
        #expect(out.contains("yes, no"))
    }
}

@Suite("LLMConsensusService: threshold clamping")
struct ConsensusThresholdClampingTests {

    @Test("Threshold larger than backend count is clamped")
    func clampUp() async {
        // Even with threshold=10, three backends can only agree 3-deep.
        // Using the aggregator directly (no real LLMs involved).
        let votes = [
            ConsensusVote(backend: "a", label: "yes", rawResponse: "yes", latencySeconds: 0.01, usedCache: false),
            ConsensusVote(backend: "b", label: "yes", rawResponse: "yes", latencySeconds: 0.01, usedCache: false),
            ConsensusVote(backend: "c", label: "yes", rawResponse: "yes", latencySeconds: 0.01, usedCache: false),
        ]
        let result = LLMConsensusService.aggregate(votes: votes, threshold: 3)
        #expect(result.consensus == "yes")
        #expect(result.winningVoteCount == 3)
    }

    @Test("Threshold=0 clamped to 1 via init")
    func clampDown() async {
        let svc = LLMConsensusService(services: [], threshold: 0)
        #expect(await svc.backendCount == 0)
        // With no backends, we expect the `empty` result from classify.
        let result = await svc.classify(
            systemPrompt: "", userPrompt: "doesn't matter",
            labels: ["a", "b"]
        )
        #expect(result.votes.isEmpty)
        #expect(result.consensus == nil)
    }
}
