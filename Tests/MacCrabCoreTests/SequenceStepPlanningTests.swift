import Foundation
import Testing
@testable import MacCrabCore

/// Inert metadata and in-memory checkpoint bytes only. The two-filter reference
/// is deliberately the pre-change planning shape: these behavioral controls
/// must also pass with the RC8 loop. They are not an allocation/latency claim.
@Suite("Sequence single-pass step planning")
struct SequenceStepPlanningTests {
    private struct ReferenceStep {
        let step: SequenceStep
        let consumesContent: Bool
        let predicateMatches: Bool
    }

    private func predicate(_ field: String, _ value: String) -> MacCrabCore.Predicate {
        MacCrabCore.Predicate(field: field, modifier: .equals, values: [value], negate: false)
    }

    private func event(_ action: FileAction = .create, id: UInt8 = 1,
                       at timestamp: Date = Date(), content: String? = "notes",
                       unresolved: Bool = false) -> Event {
        let process = MacCrabCore.ProcessInfo(pid: 41, ppid: 1, rpid: 41,
            name: "fixture", executable: "/usr/bin/true", commandLine: "ordinary notes",
            args: [], workingDirectory: "/private/tmp", userId: 501, userName: "fixture",
            groupId: 20, startTime: timestamp)
        var enrichment: [String: String] = [:]
        if let content { enrichment["FileContent"] = content }
        if unresolved {
            enrichment[DeferredEventEnrichment.coverageKey] =
                DeferredEventEnrichment.coverageMarker([.fileContent: .pending])
        }
        return Event(id: UUID(uuid: (0, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, id)),
            timestamp: timestamp, eventCategory: .file, eventType: .info,
            eventAction: action.rawValue, process: process,
            file: FileInfo(path: "/private/tmp/ordinary-planning.txt", action: action),
            enrichments: enrichment)
    }

    private func rule(_ steps: [SequenceStep], id: String = "ordinary-planning",
                      ordered: Bool = false, enabled: Bool = true) -> SequenceRule {
        SequenceRule(id: id, title: "Ordinary note progression", description: "inert planning fixture",
            level: .low, tags: [], window: 60, correlationType: .none, ordered: ordered,
            steps: steps, trigger: .allSteps, enabled: enabled)
    }

    private func referenceSteps() -> [ReferenceStep] {
        let plain = predicate("FileAction", "create")
        let content = predicate("FileContent", "notes")
        return [
            .init(step: SequenceStep(id: "a-plain", logsourceCategory: "file_event", predicates: [plain]),
                  consumesContent: false, predicateMatches: true),
            .init(step: SequenceStep(id: "b-other-category", logsourceCategory: "process_creation", predicates: [content]),
                  consumesContent: true, predicateMatches: true),
            .init(step: SequenceStep(id: "c-content", logsourceCategory: "file_event", predicates: [content]),
                  consumesContent: true, predicateMatches: true),
            .init(step: SequenceStep(id: "d-miss", logsourceCategory: "file_event", predicates: [predicate("FileAction", "close")]),
                  consumesContent: false, predicateMatches: false),
            // An unreferenced heavy predicate must not make this tree dependent.
            .init(step: SequenceStep(id: "e-tree-plain", logsourceCategory: "file_event",
                                    predicates: [plain, content], conditionTree: .predicate(0)),
                  consumesContent: false, predicateMatches: true),
            .init(step: SequenceStep(id: "f-content", logsourceCategory: "file_event", predicates: [content]),
                  consumesContent: true, predicateMatches: true),
        ]
    }

    private func legacyReference(_ steps: [ReferenceStep], completed: Set<HeavyEnrichmentComponent>?,
                                 unresolved: Bool) -> (eligible: Int, matching: [String]) {
        if let completed, completed.isEmpty { return (0, []) }
        let eligible = steps.filter { item in
            guard item.step.logsourceCategory == "file_event" else { return false }
            guard let completed else { return true }
            return item.consumesContent && completed.contains(.fileContent)
        }
        let matching = eligible.filter { $0.predicateMatches && !(unresolved && $0.consumesContent) }
        return (eligible.count, matching.map { $0.step.id })
    }

    @Test("Pre-change two-filter control preserves step order, dependencies and once-per-rule counts",
          arguments: [false, true])
    func referencePlanning(unresolved: Bool) async throws {
        let steps = referenceSteps()
        let modes: [Set<HeavyEnrichmentComponent>?] = [nil, [], [.fileContent], [.environment], [.fileContent, .environment]]
        for completed in modes {
            let expected = legacyReference(steps, completed: completed, unresolved: unresolved)
            let engine = SequenceEngine(lineage: ProcessLineage())
            try await engine.addRule(rule(steps.map(\.step)))
            let input = event(unresolved: unresolved)
            let result: [RuleMatch]
            if let completed { result = await engine.reevaluate(input, forCompleted: completed) }
            else { result = await engine.evaluate(input) }
            #expect(result.isEmpty)
            let saved = try await engine.checkpointCapture()
            let partials = saved.partialBuckets.flatMap(\.partials)
            #expect(partials.map { $0.matchedSteps.map(\.stepID) } == expected.matching.map { [$0] })
            #expect(partials.flatMap(\.matchedSteps).map(\.eventID) == Array(repeating: input.id, count: expected.matching.count))
            #expect(Set(partials.map(\.id)).count == expected.matching.count)
            #expect(saved.evictionOrder == partials.map(\.id))
            #expect(saved.pendingBuckets.isEmpty)
            let stats = await engine.statsSnapshot()
            #expect((stats.first?.evaluationCount ?? 0) == (expected.eligible == 0 ? 0 : 1))
            #expect((stats.first?.fireCount ?? 0) == 0)
        }
    }

    @Test("Disabled and other-category rules never count; eligible misses still count")
    func countBoundaryControls() async throws {
        let engine = SequenceEngine(lineage: ProcessLineage())
        let miss = SequenceStep(id: "miss", logsourceCategory: "file_event", predicates: [predicate("FileContent", "different")])
        try await engine.addRule(rule([miss], id: "eligible-miss"))
        try await engine.addRule(rule([miss], id: "disabled", enabled: false))
        try await engine.addRule(rule([SequenceStep(id: "other", logsourceCategory: "process_creation", predicates: [])], id: "other-category"))
        for _ in 0..<3 { #expect(await engine.evaluate(event()).isEmpty) }
        #expect(await engine.reevaluate(event(unresolved: true), forCompleted: [.fileContent]).isEmpty)
        #expect(await engine.reevaluate(event(), forCompleted: [.environment]).isEmpty)
        let stats = await engine.statsSnapshot()
        #expect(stats.map(\.ruleId) == ["eligible-miss"])
        #expect(stats.first?.evaluationCount == 4 && stats.first?.fireCount == 0)
        #expect(await engine.activePartialMatchCount == 0)
    }

    @Test("Ordered pending replay and checkpoint recovery retain exact event identities and window limits")
    func orderedReplayAndRecovery() async throws {
        let definition = rule([
            SequenceStep(id: "a", logsourceCategory: "file_event", predicates: [predicate("FileAction", "create")]),
            SequenceStep(id: "b", logsourceCategory: "file_event", predicates: [predicate("FileContent", "notes")], afterStep: "a"),
            SequenceStep(id: "c", logsourceCategory: "file_event", predicates: [predicate("FileAction", "close")], afterStep: "b"),
        ], ordered: true)
        let engine = SequenceEngine(lineage: ProcessLineage())
        try await engine.addRule(definition)
        let time = Date().addingTimeInterval(-10)
        let later = event(.write, id: 2, at: time.addingTimeInterval(1))
        #expect(await engine.reevaluate(later, forCompleted: [.fileContent]).isEmpty)
        let seed = event(.create, id: 1, at: time, content: nil)
        #expect(await engine.evaluate(seed).isEmpty)
        let saved = try await engine.checkpointCapture()
        #expect(saved.partialBuckets.flatMap(\.partials).flatMap(\.matchedSteps).map(\.eventID) == [seed.id, later.id])
        #expect(saved.pendingBuckets.flatMap(\.steps).count == 1)
        let prepared = try SequenceCheckpointCodec.prepare(saved)
        let decoded = try SequenceCheckpointCodec.decode(prepared.encodedFile)
        let restored = SequenceEngine(lineage: ProcessLineage())
        try await restored.addRule(definition)
        #expect(try await restored.restoreCheckpoint(decoded, now: saved.capturedAt).partialCount == 1)
        #expect(await restored.reevaluate(later, forCompleted: [.fileContent]).isEmpty)
        let afterReplay = try await restored.checkpointCapture()
        #expect(afterReplay.partialBuckets == saved.partialBuckets)
        #expect(afterReplay.pendingBuckets == saved.pendingBuckets)
        #expect(afterReplay.evictionOrder == saved.evictionOrder)
        #expect(afterReplay.pendingEvictionOrder == saved.pendingEvictionOrder)
        let finish = event(.close, id: 3, at: time.addingTimeInterval(2), content: nil)
        let originalMatches = await engine.evaluate(finish)
        let restoredMatches = await restored.evaluate(finish)
        #expect(originalMatches.count == 1 && restoredMatches == originalMatches)
        let outsideWindow = SequenceEngine(lineage: ProcessLineage())
        try await outsideWindow.addRule(definition)
        // Expiry is based on retained state age, not a fabricated future event
        // timestamp. Exercise that unchanged contract without sleeping.
        let expired = try await outsideWindow.restoreCheckpoint(decoded,
            now: saved.capturedAt.addingTimeInterval(61))
        #expect(expired.partialCount == 0 && expired.expiredPartialCount == 1)
        #expect(await outsideWindow.evaluate(event(.close, id: 4, at: time.addingTimeInterval(2), content: nil)).isEmpty)
        #expect(await restored.pendingStepConservation().conservationMaintained)
        #expect(await restored.configurationDiagnostics().maxPartialMatches == 13_000)
        #expect(await restored.checkpointWeightDiagnostics().maximumWeight == 7_864_320)
        let partialLoss = await restored.partialsEvictedTotal
        let pendingLoss = await restored.pendingStepsEvictedTotal
        #expect(partialLoss == 0 && pendingLoss == 0)
    }
}
