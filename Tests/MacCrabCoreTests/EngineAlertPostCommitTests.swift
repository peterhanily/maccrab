import Foundation
import Testing
@testable import MacCrabAgentKit
@testable import MacCrabCore

@Suite("Engine alert post-commit boundary")
struct EngineAlertPostCommitTests {
    private func match(
        id: String,
        name: String,
        severity: Severity = .high
    ) -> RuleMatch {
        RuleMatch(
            ruleId: id,
            ruleName: name,
            severity: severity,
            description: name,
            tags: ["attack.execution", "attack.t1059"]
        )
    }

    private func alert(
        id: String,
        ruleId: String,
        severity: Severity = .high
    ) -> Alert {
        Alert(
            id: id,
            timestamp: Date(timeIntervalSince1970: 1_700_000_000),
            ruleId: ruleId,
            ruleTitle: id,
            severity: severity,
            eventId: "event-1"
        )
    }

    @Test("A collapsed or failed batch authorizes no fan-out, derivatives, or LLM triage")
    func emptyPersistedSetAuthorizesNothing() {
        let candidate = alert(id: "candidate", ruleId: "same-rule")
        let plan = EngineAlertPostCommit.plan(
            persistedAlerts: [],
            contextsByAlertID: [
                candidate.id: EngineAlertCandidateContext(
                    match: match(id: candidate.ruleId, name: "candidate"),
                    isSequence: true
                )
            ]
        )

        #expect(plan.survivors.isEmpty)
        #expect(plan.sequenceSurvivors.isEmpty)
        #expect(plan.triageAlert == nil)
        var authorizedSideEffects = 0
        for _ in plan.survivors { authorizedSideEffects += 1 }
        #expect(authorizedSideEffects == 0)
    }

    @Test("Only exact persisted alert ids recover context and authorize downstream work")
    func exactPersistedIDsOnly() throws {
        // Both candidates deliberately share a rule id. Rule-id recovery would
        // attach the wrong context and incorrectly launch a sequence derivative.
        let collapsedSequence = alert(id: "collapsed", ruleId: "shared-rule")
        var storedSurvivor = alert(
            id: "stored",
            ruleId: "shared-rule",
            severity: .critical
        )
        storedSurvivor.description = "post-sink stored form"

        let plan = EngineAlertPostCommit.plan(
            persistedAlerts: [storedSurvivor],
            contextsByAlertID: [
                collapsedSequence.id: EngineAlertCandidateContext(
                    match: match(id: "shared-rule", name: "collapsed sequence"),
                    isSequence: true
                ),
                storedSurvivor.id: EngineAlertCandidateContext(
                    match: match(id: "shared-rule", name: "stored primary"),
                    isSequence: false
                ),
            ]
        )

        let committed = try #require(plan.survivors.first)
        #expect(plan.survivors.count == 1)
        #expect(committed.alert.id == "stored")
        #expect(committed.alert.description == "post-sink stored form")
        #expect(committed.match.ruleName == "stored primary")
        #expect(plan.sequenceSurvivors.isEmpty)
        #expect(plan.triageAlert?.id == "stored")
    }

    @Test("A store result without candidate context fails closed")
    func unknownPersistedIDFailsClosed() {
        let unknown = alert(id: "unknown", ruleId: "unknown-rule", severity: .critical)
        let plan = EngineAlertPostCommit.plan(
            persistedAlerts: [unknown],
            contextsByAlertID: [:]
        )

        #expect(plan.survivors.isEmpty)
        #expect(plan.sequenceSurvivors.isEmpty)
        #expect(plan.triageAlert == nil)
    }

    @Test("EventLoop invokes primary and campaign fan-out only after authoritative persistence")
    func eventLoopBoundaryDriftGuard() throws {
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

        let batchStart = try #require(source.range(
            of: "var batchAlerts: [Alert] = []"
        ))
        let batchCommit = try #require(source.range(
            of: "persistedAlerts = try await state.alertSink.insertEngineBatch(",
            range: batchStart.lowerBound..<source.endIndex
        ))
        let plan = try #require(source.range(
            of: "let postCommitPlan = EngineAlertPostCommit.plan(",
            range: batchCommit.lowerBound..<source.endIndex
        ))
        let partialRecovery = try #require(source.range(
            of: "persistedAlerts = partial.committedAlerts",
            range: batchCommit.lowerBound..<plan.lowerBound
        ))
        let fanOut = try #require(source.range(
            of: "await fanOut(committed.alert)",
            range: plan.lowerBound..<source.endIndex
        ))
        let triage = try #require(source.range(
            of: "let triageAlert = postCommitPlan.triageAlert",
            range: fanOut.lowerBound..<source.endIndex
        ))

        #expect(batchCommit.lowerBound < plan.lowerBound)
        #expect(batchCommit.lowerBound < partialRecovery.lowerBound)
        #expect(partialRecovery.lowerBound < plan.lowerBound)
        #expect(plan.lowerBound < fanOut.lowerBound)
        #expect(fanOut.lowerBound < triage.lowerBound)
        #expect(!source.contains(
            "for committed in postCommitPlan.sequenceSurvivors"
        ), "retired automatic forecast/counterfactual work must stay absent")

        let preCommit = source[batchStart.lowerBound..<batchCommit.lowerBound]
        #expect(!preCommit.contains("shouldSuppressAndRecord"))
        #expect(!source.contains("state.deduplicator.shouldSuppressAndRecord"))

        let fanOutStart = try #require(source.range(
            of: "batchFanOut[alert.id] = { persistedAlert in",
            range: batchStart.lowerBound..<batchCommit.lowerBound
        ))
        let fanOutBranch = source[fanOutStart.lowerBound..<batchCommit.lowerBound]
        #expect(fanOutBranch.contains("severity: effectiveSeverity"))
        #expect(
            !fanOutBranch.contains("severity: match.severity"),
            "post-commit incident/campaign consumers must use stored severity"
        )

        let campaignStart = try #require(source.range(
            of: "for campaign in campaigns {",
            range: batchStart.lowerBound..<batchCommit.lowerBound
        ))
        let campaignEnd = try #require(source.range(
            of: "// v1.17.4: removed the always-on inline alerts.jsonl writer.",
            range: campaignStart.lowerBound..<batchCommit.lowerBound
        ))
        let campaignBranch = source[campaignStart.lowerBound..<campaignEnd.lowerBound]
        let campaignGate = try #require(campaignBranch.range(
            of: "guard campaignPersisted else { continue }"
        ))
        for downstream in [
            "if let store = state.campaignStore",
            "await state.notifier.notify(alert: campaignAlert)",
            "ruleGenerator.generateFromCampaignEnhanced",
            "state.advisoryWorkLifecycle.submit(",
        ] {
            let action = try #require(campaignBranch.range(of: downstream))
            #expect(campaignGate.lowerBound < action.lowerBound)
        }
    }
}
