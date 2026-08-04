import Foundation
import Testing
@testable import MacCrabCore

@Suite("Statistical anomaly: delivery-invariant baselines")
struct StatisticalAnomalyQualityTests {
    private var eventLoopURL: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Sources/MacCrabAgentKit/EventLoop.swift")
    }

    @Test("frequency abstains unless timing coverage is explicitly complete")
    func incompleteTimingCoverageAbstains() async {
        let detector = StatisticalAnomalyDetector(zThreshold: 2, minSamples: 2)
        let base = Date(timeIntervalSince1970: 1_700_000_000)
        var features: [String] = []
        for offset in [0.0, 60.0, 120.0, 120.001] {
            let results = await detector.processEvent(
                processPath: "/usr/bin/tool",
                argCount: 2,
                commandLine: "tool -v",
                category: "process",
                timestamp: base.addingTimeInterval(offset)
            )
            features.append(contentsOf: results.map(\.feature))
        }

        #expect(!features.contains("event_frequency"))
        let telemetry = await detector.telemetry()
        #expect(telemetry.observations == 4)
        #expect(telemetry.timingCoverageSkipped == 4)
        #expect(telemetry.timingObservations == 0)
    }

    @Test("event categories and binary identities cannot contaminate each other")
    func stableIdentityAndCategoryIsolation() async {
        let detector = StatisticalAnomalyDetector(zThreshold: 3, minSamples: 2)
        let now = Date(timeIntervalSince1970: 1_700_000_000)

        for index in 0..<4 {
            _ = await detector.processEvent(
                processPath: "/opt/tool",
                argCount: 100,
                commandLine: "ignored file-event shape",
                category: "file",
                timestamp: now.addingTimeInterval(Double(index)),
                binaryIdentity: "cdhash-a"
            )
        }
        _ = await detector.processEvent(
            processPath: "/opt/tool",
            argCount: 2,
            commandLine: "tool -v",
            category: "process",
            timestamp: now,
            binaryIdentity: "cdhash-a"
        )
        _ = await detector.processEvent(
            processPath: "/opt/tool",
            argCount: 7,
            commandLine: "tool one two three four five six",
            category: "process",
            timestamp: now,
            binaryIdentity: "cdhash-b"
        )

        let file = await detector.stats(
            for: "/opt/tool", category: "file", binaryIdentity: "cdhash-a"
        )
        let processA = await detector.stats(
            for: "/opt/tool", category: "process", binaryIdentity: "cdhash-a"
        )
        let processB = await detector.stats(
            for: "/opt/tool", category: "process", binaryIdentity: "cdhash-b"
        )
        #expect(file?.argCountMean == 0, "file events must not train launch arguments")
        #expect(processA?.argCountMean == 2)
        #expect(processB?.argCountMean == 7)
        #expect(await detector.telemetry().trackedIdentities == 3)
    }

    @Test("anomalies compare with the frozen prior and are clipped before learning")
    func evaluateBeforeRobustUpdate() async {
        let detector = StatisticalAnomalyDetector(zThreshold: 3, minSamples: 5)
        let base = Date(timeIntervalSince1970: 1_700_000_000)
        for index in 0..<5 {
            _ = await detector.processEvent(
                processPath: "/usr/bin/cron",
                argCount: 2,
                commandLine: "cron -s",
                category: "process",
                timestamp: base.addingTimeInterval(Double(index) * 60)
            )
        }

        let anomalies = await detector.processEvent(
            processPath: "/usr/bin/cron",
            argCount: 50,
            commandLine: "cron " + String(repeating: "-x ", count: 49),
            category: "process",
            timestamp: base.addingTimeInterval(360)
        )
        let argument = anomalies.first(where: { $0.feature == "argument_count" })
        #expect(argument != nil)
        #expect(argument?.mean == 2)
        #expect(argument?.stddev == 0)

        let learned = await detector.stats(for: "/usr/bin/cron")
        #expect((learned?.argCountMean ?? 50) < 4, "one outlier must not poison the baseline")
        let telemetry = await detector.telemetry()
        #expect(telemetry.clippedBaselineUpdates >= 1)
        #expect(telemetry.emittedAnomalies >= 1)
    }

    @Test("out-of-order timing cannot rewind the frequency clock")
    func outOfOrderDoesNotRewind() async {
        let detector = StatisticalAnomalyDetector(zThreshold: 10, minSamples: 2)
        let base = Date(timeIntervalSince1970: 1_700_000_000)
        for offset in [0.0, 60.0, 30.0, 120.0] {
            _ = await detector.processEvent(
                processPath: "/usr/bin/tool",
                argCount: 1,
                commandLine: "tool",
                category: "process",
                timestamp: base.addingTimeInterval(offset),
                timingCoverageComplete: true
            )
        }

        let telemetry = await detector.telemetry()
        #expect(telemetry.outOfOrderTimestamps == 1)
        #expect(telemetry.timingObservations == 2)
    }

    @Test("runtime learns launch shape only from exec with stable identity")
    func runtimeWiringCannotRegressToPerEventTraining() throws {
        let source = try String(contentsOf: eventLoopURL, encoding: .utf8)
        #expect(source.contains("let isProcessExec = enrichedEvent.eventCategory == .process"))
        #expect(source.contains("eventAction.caseInsensitiveCompare(\"exec\")"))
        #expect(source.contains("binaryIdentity: Self.statisticalBinaryIdentity("))
        #expect(source.contains("timingCoverageComplete: false"))
        #expect(source.contains("statistical_process_shape_anomaly"))
        #expect(!source.contains("Kept per-event (NOT gated to exec)"))
    }
}
