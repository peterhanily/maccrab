import Foundation
import Testing
@testable import MacCrabCore

@Suite("LLM batch triage admission")
struct LLMBatchTriageTests {
    private func alert(
        id: String,
        severity: Severity,
        timestamp: TimeInterval,
        ruleId: String? = nil
    ) -> Alert {
        Alert(
            id: id,
            timestamp: Date(timeIntervalSince1970: timestamp),
            ruleId: ruleId ?? "rule.\(id)",
            ruleTitle: id,
            severity: severity,
            eventId: "event",
            processPath: "/private/tmp/tool",
            processName: "tool"
        )
    }

    @Test("ten persisted serious alerts select exactly one critical representative")
    func selectsExactlyOneFromMany() throws {
        let alerts = (0..<10).map { index in
            alert(
                id: String(format: "a-%02d", index),
                severity: index == 7 ? .critical : .high,
                timestamp: TimeInterval(100 + index)
            )
        }

        let selected = try #require(
            LLMBatchTriage.representative(from: alerts)
        )
        #expect(selected.id == "a-07")
    }

    @Test("selection is deterministic and excludes non-serious or recursive meta alerts")
    func deterministicSelectionAndGates() throws {
        let eligibleEarly = alert(id: "a", severity: .critical, timestamp: 10)
        let eligibleLate = alert(id: "z", severity: .critical, timestamp: 20)
        let inputs = [
            alert(id: "medium", severity: .medium, timestamp: 1),
            alert(
                id: "campaign",
                severity: .critical,
                timestamp: 1,
                ruleId: "maccrab.campaign.chain"
            ),
            alert(
                id: "meta",
                severity: .critical,
                timestamp: 1,
                ruleId: "maccrab.llm.generated"
            ),
            eligibleLate,
            eligibleEarly,
        ]

        #expect(LLMBatchTriage.representative(from: inputs)?.id == "a")
        #expect(
            LLMBatchTriage.representative(from: Array(inputs.reversed()))?.id
                == "a"
        )
        #expect(LLMBatchTriage.representative(from: Array(inputs.prefix(3))) == nil)
    }

    @Test("production path investigates only after the sink returns persisted survivors")
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
        let insert = try #require(source.range(
            of: "persistedAlerts = try await state.alertSink.insertEngineBatch("
        ))
        let plan = try #require(source.range(
            of: "let postCommitPlan = EngineAlertPostCommit.plan("
        ))
        let select = try #require(source.range(
            of: "let triageAlert = postCommitPlan.triageAlert"
        ))
        let investigate = try #require(source.range(
            of: "if let investigation = await llm.investigate("
        ))

        #expect(insert.lowerBound < plan.lowerBound)
        #expect(plan.lowerBound < select.lowerBound)
        #expect(select.lowerBound < investigate.lowerBound)
        let planner = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/MacCrabAgentKit/EngineAlertPostCommit.swift"
            ),
            encoding: .utf8
        )
        #expect(planner.contains("LLMBatchTriage.representative("))
        #expect(planner.contains("from: survivors.map(\\.alert)"))
        #expect(source.components(separatedBy: "await llm.investigate(").count - 1 == 1)
        #expect(!source.contains("maccrab.llm.alert-analysis"))
        #expect(!source.contains("maccrab.llm.sequence-analysis"))
        #expect(!source.contains("maccrab.llm.baseline-analysis"))
        #expect(!source.contains("maccrab.llm.behavior-analysis"))
    }
}
