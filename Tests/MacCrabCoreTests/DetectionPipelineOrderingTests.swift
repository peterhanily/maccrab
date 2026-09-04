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

    @Test("EventLoop filters primaries before durable scoring and commit")
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

        let preparationStart = try #require(source.range(
            of: "static func prepareReviewedMatches("
        ))
        let preparationEnd = try #require(source.range(
            of: "/// The one reviewed rule-match path",
            range: preparationStart.upperBound..<source.endIndex
        ))
        let preparation = source[
            preparationStart.lowerBound..<preparationEnd.lowerBound
        ]
        let primaryFilter = try #require(preparation.range(
            of: "NoiseFilter.apply("
        ))
        let normalization = try #require(preparation.range(
            of: "primaryMatches = ReviewedRuleMatches.normalized(primaryMatches)"
        ))
        let survivingPrimarySet = try #require(preparation.range(
            of: "let survivingPrimaryMatches = Set(primaryMatches)"
        ))
        let survivingSequences = try #require(preparation.range(
            of: "sequenceMatches: normalizedSequenceMatches.filter"
        ))
        #expect(primaryFilter.lowerBound < normalization.lowerBound)
        #expect(normalization.lowerBound < survivingPrimarySet.lowerBound)
        #expect(survivingPrimarySet.lowerBound < survivingSequences.lowerBound)
        #expect(!preparation.contains("BehaviorScoreAlertEmitter.recordRuleMatch("))
        #expect(!preparation.contains("insertEngineBatch("))

        let dispatchStart = try #require(source.range(
            of: "static func dispatchReviewedMatches("
        ))
        let dispatchEnd = try #require(source.range(
            of: "// NoiseFilter logic lives",
            range: dispatchStart.upperBound..<source.endIndex
        ))
        let dispatch = source[dispatchStart.lowerBound..<dispatchEnd.lowerBound]
        let reviewedPrimary = try #require(dispatch.range(
            of: "let primaryMatches = reviewed.primaryMatches"
        ))
        let reviewedSequences = try #require(dispatch.range(
            of: "let survivingSequenceMatches = reviewed.sequenceMatches"
        ))
        let scoring = try #require(dispatch.range(
            of: "BehaviorScoreAlertEmitter.recordRuleMatch("
        ))
        let batchCommit = try #require(dispatch.range(
            of: "persistedAlerts = try await state.alertSink.insertEngineBatch("
        ))
        #expect(reviewedPrimary.lowerBound < scoring.lowerBound)
        #expect(reviewedSequences.lowerBound < scoring.lowerBound)
        #expect(scoring.lowerBound < batchCommit.lowerBound)
        #expect(!dispatch.contains("NoiseFilter.apply("))

        // The reviewed value is made canonical before the one function that
        // owns scoring and alert commit. This keeps a crash between review and
        // fanout from making an unjournaled match durable only in alerts.db.
        let detectionStart = try #require(source.range(
            of: "// === Detection: 3 layers ==="
        ))
        let detectionEnd = try #require(source.range(
            of: "// Replay cannot overtake the initial evaluation.",
            range: detectionStart.upperBound..<source.endIndex
        ))
        let detection = source[detectionStart.lowerBound..<detectionEnd.lowerBound]
        let prepareCall = try #require(detection.range(
            of: "let reviewedDispatch = prepareReviewedMatches("
        ))
        let terminalSettlement = try #require(detection.range(
            of: "let terminalAdmission = await settleTerminalJournalRevision("
        ))
        let dispatchCall = try #require(detection.range(
            of: "await dispatchReviewedMatches("
        ))
        #expect(prepareCall.lowerBound < terminalSettlement.lowerBound)
        #expect(terminalSettlement.lowerBound < dispatchCall.lowerBound)

        // v1.22.0: every revision settles canonically here — there is no
        // batched bypass. Diverting unmatched revisions to the writer's
        // terminal buffer was measured inert (97% of changed revisions are
        // rule-matched) and the wider gate it would need silently drops sparse
        // projection promotion. Pin the absence so it is not reintroduced
        // without re-measuring.
        #expect(!detection.contains("await enqueueTerminalJournalRevision("))

        // Counterfactual/forecast engines remain explicit analyst tools. The
        // old source guard required their automatic one-step derivative after
        // commit, but that emitter was retired because one synthetic step
        // cannot establish an observed chain or calibrated forecast.
        #expect(!source.contains("reasoner.analyze(chain: [step])"))
        #expect(!source.contains("label: \"sequence-forecast\""))

        #expect(!source.contains("maccrab.llm.sequence-analysis"))
        #expect(!source.contains("maccrab.llm.baseline-analysis"))
        #expect(!source.contains("maccrab.llm.behavior-analysis"))
        #expect(!source.contains("LLMPrompts.sequenceAnalysis"))
        #expect(!source.contains("LLMPrompts.baselineAnomaly"))
        #expect(!source.contains("LLMPrompts.behaviorAnalysis"))
    }
}
