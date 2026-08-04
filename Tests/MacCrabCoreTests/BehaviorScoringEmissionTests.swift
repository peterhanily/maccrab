import Foundation
import Testing
@testable import MacCrabCore

@Suite("Behavior scoring durable threshold delivery")
struct BehaviorScoringEmissionTests {
    @Test("non-rule crossing stays retryable until durable acknowledgement")
    func crossingIsNotLatchedByReturn() async throws {
        let scorer = BehaviorScoring(
            alertThreshold: 4,
            criticalThreshold: 8,
            decayHalfLife: 300
        )
        let indicator = BehaviorScoring.Indicator(
            name: "ai_tool_boundary_violation",
            weight: 5,
            detail: "fixture"
        )
        let first = try #require(await scorer.addIndicator(
            indicator,
            forProcess: 42,
            path: "/tmp/fixture"
        ))

        // The same indicator is cooldown-suppressed, but an undelivered
        // crossing must still be returned with the identical token.
        let retry = try #require(await scorer.addIndicator(
            indicator,
            forProcess: 42,
            path: "/tmp/fixture"
        ))
        #expect(retry.deliveryToken == first.deliveryToken)
        await scorer.recordThresholdDeliveryFailure(
            deliveryToken: first.deliveryToken
        )
        #expect(await scorer.resolveThreshold(
            deliveryToken: first.deliveryToken,
            as: .committed
        ))
        #expect(!(await scorer.resolveThreshold(
            deliveryToken: first.deliveryToken,
            as: .committed
        )))

        // A different signal while the score remains above threshold does not
        // mint a second alert after the one committed acknowledgement.
        let afterCommit = await scorer.addIndicator(
            .init(name: "writes_launch_agent", weight: 5),
            forProcess: 42,
            path: "/tmp/fixture"
        )
        #expect(afterCommit == nil)
        let telemetry = await scorer.thresholdTelemetry()
        #expect(telemetry.crossings == 1)
        #expect(telemetry.committed == 1)
        #expect(telemetry.pending == 0)
        #expect(telemetry.deliveryFailures == 1)
        #expect(telemetry.conservesCrossings)
    }

    @Test("intentional filtering settles rather than retrying forever")
    func filteredCrossingSettles() async throws {
        let scorer = BehaviorScoring(
            alertThreshold: 1,
            criticalThreshold: 5
        )
        let crossing = try #require(await scorer.addIndicator(
            .init(name: "unsigned_binary", weight: 3),
            forProcess: 7,
            path: "/System/fixture"
        ))
        #expect(await scorer.resolveThreshold(
            deliveryToken: crossing.deliveryToken,
            as: .filteredOrSuppressed
        ))
        let telemetry = await scorer.thresholdTelemetry()
        #expect(telemetry.filteredOrSuppressed == 1)
        #expect(telemetry.pending == 0)
        #expect(telemetry.conservesCrossings)
    }

    @Test("production callers cannot silently discard scoring results")
    func sourceWiringUsesOneEmitter() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        for relative in [
            "Sources/MacCrabAgentKit/EventLoop.swift",
            "Sources/MacCrabAgentKit/MonitorTasks.swift",
        ] {
            let source = try String(
                contentsOf: root.appendingPathComponent(relative),
                encoding: .utf8
            )
            #expect(!source.contains("behaviorScoring.addIndicator("))
            #expect(!source.contains("behaviorScoring.addRuleMatch("))
            #expect(source.contains("BehaviorScoreAlertEmitter.record"))
        }

        let emitter = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/MacCrabAgentKit/BehaviorScoreAlertEmitter.swift"
            ),
            encoding: .utf8
        )
        let submit = try #require(emitter.range(of: "alertSink.submit"))
        let resolve = try #require(emitter.range(
            of: "behaviorScoring.resolveThreshold",
            range: submit.upperBound..<emitter.endIndex
        ))
        #expect(submit.lowerBound < resolve.lowerBound)
        #expect(emitter.contains("recordThresholdDeliveryFailure"))
    }
}
