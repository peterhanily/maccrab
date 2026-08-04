import Foundation
import Testing
@testable import MacCrabCore

@Suite("CampaignDetector bounded incremental indexes")
struct CampaignDetectorIncrementalIndexTests {
    private var sourceURL: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent() // MacCrabCoreTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // repository
            .appendingPathComponent("Sources/MacCrabCore/Detection/CampaignDetector.swift")
    }

    private func fingerprint(_ campaigns: [CampaignDetector.Campaign]) -> [String] {
        campaigns.map { campaign in
            let alerts = campaign.alerts.map { alert in
                [
                    alert.ruleId,
                    alert.ruleTitle,
                    alert.severity.rawValue,
                    alert.processPath ?? "-",
                    alert.pid.map(String.init) ?? "-",
                    alert.userId ?? "-",
                    String(alert.timestamp.timeIntervalSinceReferenceDate),
                    alert.tactics.sorted().joined(separator: ","),
                ].joined(separator: "|")
            }.joined(separator: ";")
            return [
                campaign.type.rawValue,
                campaign.severity.rawValue,
                campaign.title,
                campaign.description,
                campaign.tactics.sorted().joined(separator: ","),
                String(campaign.timeSpanSeconds),
                alerts,
            ].joined(separator: "#")
        }
    }

    @Test("Incremental evaluator is equivalent to the scan reference under cap and expiry churn")
    func differentialEquivalenceUnderChurn() async {
        let incremental = CampaignDetector(
            campaignWindow: 20,
            stormThreshold: 3,
            stormCriticalThreshold: 5,
            stormWindow: 8,
            minTacticsForKillChain: 3,
            maxRecentAlerts: 12,
            campaignDedupWindow: 7
        )
        let reference = CampaignDetector(
            campaignWindow: 20,
            stormThreshold: 3,
            stormCriticalThreshold: 5,
            stormWindow: 8,
            minTacticsForKillChain: 3,
            maxRecentAlerts: 12,
            campaignDedupWindow: 7
        )
        let base = Date()
        let tacticSets: [Set<String>] = [
            ["attack.discovery"],
            ["attack.credential_access"],
            ["attack.persistence"],
            ["attack.command_and_control"],
            ["attack.lateral_movement"],
            ["attack.execution", "attack.initial_access"],
        ]
        let aiRules = [
            "maccrab.ai-guard.credential-access",
            "maccrab.ai-guard.boundary-violation",
            "maccrab.ai-guard.network-sandbox",
            "maccrab.ai-guard.prompt-injection",
        ]

        for index in 0..<180 {
            let evaluatedAt = base.addingTimeInterval(Double(index))
            // Periodically inject an already-stale timestamp. Because cap
            // eviction happens before time expiry, this also exercises the
            // intentionally non-obvious "evict one valid, then expire stale"
            // historical behavior.
            let timestamp = evaluatedAt.addingTimeInterval(index.isMultiple(of: 11) ? -30 : -Double(index % 4))
            let aiRule: String? = index.isMultiple(of: 5) ? aiRules[index % aiRules.count] : nil
            let ruleID = aiRule ?? (index.isMultiple(of: 3) ? "storm.shared" : "rule.\(index % 9)")
            let title = ruleID == "maccrab.ai-guard.prompt-injection"
                ? "Compound prompt injection" : ruleID
            let alert = CampaignDetector.AlertSummary(
                ruleId: ruleID,
                ruleTitle: title,
                severity: index.isMultiple(of: 17) ? .critical : (index.isMultiple(of: 2) ? .high : .medium),
                processPath: "/tmp/tool-\(index % 4)",
                pid: 7000 + index % 6,
                userId: index.isMultiple(of: 4) ? "0" : "501",
                timestamp: timestamp,
                tactics: tacticSets[index % tacticSets.count],
                aiTool: aiRule == nil ? nil : "claude_code"
            )

            let fast = await incremental.processAlert(alert, evaluatedAt: evaluatedAt)
            let slow = await reference.processAlertUsingReferenceEvaluator(alert, evaluatedAt: evaluatedAt)
            #expect(fingerprint(fast) == fingerprint(slow), "evaluator drift at input \(index)")
            #expect(await incremental.indexInvariantFailures().isEmpty)
        }

        let telemetry = await incremental.telemetrySnapshot()
        #expect(telemetry.activeAlerts <= 12)
        #expect(telemetry.capEvictedAlerts > 0)
        #expect(telemetry.timeExpiredAlerts > 0)
        #expect(telemetry.conservationHolds)
    }

    @Test("Production candidate evaluation cannot regress to full-window filters")
    func sourceDriftGuard() throws {
        let source = try String(contentsOf: sourceURL, encoding: .utf8)
        let start = try #require(source.range(of: "// MARK: - Incremental Evaluation"))
        let end = try #require(source.range(
            of: "// MARK: - Slow Reference Evaluation",
            range: start.upperBound..<source.endIndex
        ))
        let productionEvaluation = source[start.upperBound..<end.lowerBound]
        #expect(!productionEvaluation.contains("recentAlerts"))
        #expect(!productionEvaluation.contains(".filter {"))
        #expect(source.contains("private var recentAlerts: [AlertSummary]"),
                "the independent scan reference seam must remain available")
    }

    @Test("A 5k window plus 1k alerts has bounded decision work and conserved cap eviction")
    func fiveThousandPlusOneThousandBound() async {
        let detector = CampaignDetector(
            campaignWindow: 86_400,
            stormThreshold: 10,
            stormCriticalThreshold: 50,
            stormWindow: 300,
            maxRecentAlerts: 5_000
        )
        let base = Date()
        let clock = ContinuousClock()
        let start = clock.now

        for index in 0..<6_000 {
            _ = await detector.processAlert(
                .init(
                    ruleId: "informational.chatter",
                    ruleTitle: "Informational chatter",
                    severity: .informational,
                    timestamp: base.addingTimeInterval(Double(index) / 10_000)
                ),
                evaluatedAt: base.addingTimeInterval(Double(index) / 10_000)
            )
        }
        let elapsed = start.duration(to: clock.now)
        let telemetry = await detector.telemetrySnapshot()

        #expect(telemetry.acceptedAlerts == 6_000)
        #expect(telemetry.activeAlerts == 5_000)
        #expect(telemetry.peakActiveAlerts <= 5_000)
        #expect(telemetry.capEvictedAlerts == 1_000)
        #expect(telemetry.timeExpiredAlerts == 0)
        #expect(telemetry.expirationEntries == 5_000)
        #expect(telemetry.candidateAlertVisits == 0,
                "dedup/ineligible traffic must not repeatedly materialize the 5k window")
        #expect(telemetry.indexMutationOperations <= 40_000,
                "maintenance work must scale with admitted/removed memberships, not active-window scans")
        #expect(telemetry.decisionOperations == 30_000)
        #expect(telemetry.totalAccountedOperations <= 70_000)
        #expect(telemetry.conservationHolds)
        #expect(await detector.indexInvariantFailures().isEmpty)
        #expect(elapsed < .seconds(10), "6k bounded updates took \(elapsed)")
    }

    @Test("Out-of-order stale admission preserves cap-before-expiry conservation")
    func outOfOrderCapThenExpiry() async {
        let detector = CampaignDetector(
            campaignWindow: 10,
            stormThreshold: 100,
            stormCriticalThreshold: 200,
            maxRecentAlerts: 5
        )
        let base = Date()
        for index in 0..<5 {
            _ = await detector.processAlert(
                .init(
                    ruleId: "fresh.\(index)",
                    ruleTitle: "Fresh",
                    severity: .informational,
                    timestamp: base
                ),
                evaluatedAt: base
            )
        }

        _ = await detector.processAlert(
            .init(
                ruleId: "already.stale",
                ruleTitle: "Already stale",
                severity: .informational,
                timestamp: base.addingTimeInterval(-100)
            ),
            evaluatedAt: base
        )
        var telemetry = await detector.telemetrySnapshot()
        #expect(telemetry.activeAlerts == 4)
        #expect(telemetry.capEvictedAlerts == 1)
        #expect(telemetry.timeExpiredAlerts == 1)
        #expect(telemetry.conservationHolds)

        _ = await detector.processAlert(
            .init(
                ruleId: "new.epoch",
                ruleTitle: "New epoch",
                severity: .informational,
                timestamp: base.addingTimeInterval(20)
            ),
            evaluatedAt: base.addingTimeInterval(20)
        )
        telemetry = await detector.telemetrySnapshot()
        #expect(telemetry.activeAlerts == 1)
        #expect(telemetry.timeExpiredAlerts == 5)
        #expect(telemetry.conservationHolds)
        #expect(await detector.indexInvariantFailures().isEmpty)
    }
}
