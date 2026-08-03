import Foundation
import Testing
@testable import MacCrabCore

@Suite("Detection pipeline filtering order")
struct DetectionPipelineOrderingTests {
    private func appleEvent(
        executable: String = "/usr/bin/true",
        commandLine: String = "true"
    ) -> Event {
        let signature = CodeSignatureInfo(
            signerType: .apple,
            teamId: nil,
            signingId: nil,
            authorities: [],
            flags: 0,
            isNotarized: true,
            issuerChain: nil,
            certHashes: nil,
            isAdhocSigned: nil,
            entitlements: nil
        )
        let process = MacCrabCore.ProcessInfo(
            pid: 7_777,
            ppid: 1,
            rpid: 1,
            name: (executable as NSString).lastPathComponent,
            executable: executable,
            commandLine: commandLine,
            args: [executable],
            workingDirectory: "/private/tmp",
            userId: 501,
            userName: "test",
            groupId: 20,
            startTime: Date(),
            codeSignature: signature,
            ancestors: [],
            architecture: "arm64",
            isPlatformBinary: true
        )
        return Event(
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: process
        )
    }

    @Test("NoiseFilter-rejected primary cannot taint BehaviorScoring or consume its threshold latch")
    func rejectedPrimaryDoesNotScore() async throws {
        let scorer = BehaviorScoring(
            alertThreshold: 4,
            criticalThreshold: 8,
            decayHalfLife: 300
        )
        let event = appleEvent()
        var rejected = [
            RuleMatch(
                ruleId: "test.discovery-noise",
                ruleName: "Discovery noise",
                severity: .high,
                description: "",
                mitreTechniques: ["attack.t1083"],
                suppressible: true
            )
        ]

        NoiseFilter.apply(&rejected, event: event, isWarmingUp: false)
        #expect(rejected.isEmpty)
        for match in rejected {
            _ = await scorer.addRuleMatch(
                severity: match.severity,
                ruleTitle: match.ruleName,
                forProcess: event.process.pid,
                path: event.process.executable
            )
        }
        #expect(
            await scorer.score(
                forPid: event.process.pid,
                path: event.process.executable
            ) == 0
        )

        // A later must-fire primary still crosses immediately. If the rejected
        // match had reached the scorer first, it would have consumed the actor's
        // one-shot `alerted` latch and this result would be nil.
        var survivor = [
            RuleMatch(
                ruleId: "test.must-fire",
                ruleName: "Must fire",
                severity: .high,
                description: "",
                mitreTechniques: ["attack.t1083"],
                suppressible: false
            )
        ]
        NoiseFilter.apply(&survivor, event: event, isWarmingUp: false)
        let match = try #require(survivor.first)
        let crossed = await scorer.addRuleMatch(
            severity: match.severity,
            ruleTitle: match.ruleName,
            forProcess: event.process.pid,
            path: event.process.executable
        )
        #expect(crossed != nil)
    }

    @Test("EventLoop filters primaries before derivatives and scoring, then filters composites")
    func eventLoopOrderingDriftGuard() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/MacCrabAgentKit/EventLoop.swift"
            ),
            encoding: .utf8
        )

        let primaryFilter = try #require(source.range(of: "&primaryMatches,"))
        let survivingSequences = try #require(source.range(
            of: "let survivingSequenceMatches = sequenceMatches.filter"
        ))
        let deterministicDerivative = try #require(source.range(
            of: "let result = await reasoner.analyze(chain: [step])"
        ))
        let scoring = try #require(source.range(
            of: "state.behaviorScoring.addRuleMatch("
        ))
        let compositeFilter = try #require(source.range(of: "&compositeMatches,"))
        let emissionMerge = try #require(source.range(
            of: "matches.append(contentsOf: compositeMatches)"
        ))
        let batchCommit = try #require(source.range(
            of: "persistedAlerts = try await state.alertSink.insertEngineBatch("
        ))

        #expect(primaryFilter.lowerBound < survivingSequences.lowerBound)
        #expect(primaryFilter.lowerBound < scoring.lowerBound)
        #expect(scoring.lowerBound < compositeFilter.lowerBound)
        #expect(compositeFilter.lowerBound < emissionMerge.lowerBound)
        #expect(emissionMerge.lowerBound < batchCommit.lowerBound)
        #expect(survivingSequences.lowerBound < batchCommit.lowerBound)
        #expect(batchCommit.lowerBound < deterministicDerivative.lowerBound)

        #expect(!source.contains("maccrab.llm.sequence-analysis"))
        #expect(!source.contains("maccrab.llm.baseline-analysis"))
        #expect(!source.contains("maccrab.llm.behavior-analysis"))
        #expect(!source.contains("LLMPrompts.sequenceAnalysis"))
        #expect(!source.contains("LLMPrompts.baselineAnomaly"))
        #expect(!source.contains("LLMPrompts.behaviorAnalysis"))
    }
}
