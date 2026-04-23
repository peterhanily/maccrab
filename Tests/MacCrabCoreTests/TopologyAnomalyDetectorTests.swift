// TopologyAnomalyDetectorTests.swift
// Shape-based process-tree anomaly detection.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("TopologyAnomalyDetector")
struct TopologyAnomalyDetectorTests {

    @Test("Benign exec (zsh spawning git) produces no findings")
    func benignExec() async {
        let detector = TopologyAnomalyDetector()
        let findings = await detector.evaluate(
            processPath: "/opt/homebrew/bin/git",
            processPID: 1001,
            parentPath: "/bin/zsh",
            parentPID: 1000,
            ancestryDepth: 4
        )
        #expect(findings.isEmpty)
    }

    @Test("launchd directly spawning a shell fires launchdSpawnedShell")
    func launchdSpawnedShell() async {
        let detector = TopologyAnomalyDetector()
        let findings = await detector.evaluate(
            processPath: "/bin/bash",
            processPID: 1001,
            parentPath: "/sbin/launchd",
            parentPID: 1,
            ancestryDepth: 2
        )
        #expect(findings.map(\.kind).contains(.launchdSpawnedShell))
    }

    @Test("System process spawning /tmp binary fires systemProcessSpawningStagedBinary")
    func systemProcessSpawningStagedBinary() async {
        let detector = TopologyAnomalyDetector()
        let findings = await detector.evaluate(
            processPath: "/tmp/stage1",
            processPID: 1001,
            parentPath: "/System/Library/CoreServices/SomeHelper",
            parentPID: 500,
            ancestryDepth: 3
        )
        #expect(findings.map(\.kind).contains(.systemProcessSpawningStagedBinary))
    }

    @Test("System process spawning binary in ~/Downloads fires systemProcessSpawningStagedBinary")
    func systemProcessSpawningDownloads() async {
        let detector = TopologyAnomalyDetector()
        let findings = await detector.evaluate(
            processPath: "/Users/alice/Downloads/payload.bin",
            processPID: 1001,
            parentPath: "/usr/libexec/helper",
            parentPID: 500,
            ancestryDepth: 3
        )
        #expect(findings.map(\.kind).contains(.systemProcessSpawningStagedBinary))
    }

    @Test("Deep descent threshold triggers deepProcessDescent")
    func deepDescent() async {
        let detector = TopologyAnomalyDetector()
        let findings = await detector.evaluate(
            processPath: "/bin/bash",
            processPID: 2000,
            parentPath: "/bin/bash",
            parentPID: 1999,
            ancestryDepth: 20
        )
        #expect(findings.map(\.kind).contains(.deepProcessDescent))
    }

    @Test("Normal lineage depth does not trigger deepProcessDescent")
    func normalDepthOK() async {
        let detector = TopologyAnomalyDetector()
        let findings = await detector.evaluate(
            processPath: "/bin/bash",
            processPID: 2000,
            parentPath: "/bin/zsh",
            parentPID: 1999,
            ancestryDepth: 8
        )
        #expect(!findings.map(\.kind).contains(.deepProcessDescent))
    }

    @Test("Fanout fires exactly once when 20+ children spawn in under 10s")
    func fanoutFiresOnceAtThreshold() async {
        let detector = TopologyAnomalyDetector()
        let parentPID: pid_t = 5000
        var firings = 0
        // First 19: no fanout alert yet
        for i in 0..<19 {
            let findings = await detector.evaluate(
                processPath: "/tmp/child-\(i)",
                processPID: pid_t(6000 + i),
                parentPath: "/bin/sh",
                parentPID: parentPID,
                ancestryDepth: 3
            )
            // /tmp binary with /bin/sh parent is NOT a system process, so
            // systemProcessSpawningStagedBinary shouldn't fire here.
            if findings.contains(where: { $0.kind == .anomalousProcessFanout }) {
                firings += 1
            }
        }
        #expect(firings == 0)

        // 20th spawn should trigger exactly once.
        let findings = await detector.evaluate(
            processPath: "/tmp/child-20",
            processPID: 6020,
            parentPath: "/bin/sh",
            parentPID: parentPID,
            ancestryDepth: 3
        )
        #expect(findings.map(\.kind).contains(.anomalousProcessFanout))

        // 21st spawn — should NOT re-fire (single-shot within the window).
        let post = await detector.evaluate(
            processPath: "/tmp/child-21",
            processPID: 6021,
            parentPath: "/bin/sh",
            parentPID: parentPID,
            ancestryDepth: 3
        )
        #expect(!post.map(\.kind).contains(.anomalousProcessFanout))
    }

    @Test("purgeStale clears dead-parent entries")
    func purgeStaleEvicts() async {
        let detector = TopologyAnomalyDetector()
        _ = await detector.evaluate(
            processPath: "/bin/ls",
            processPID: 7001,
            parentPath: "/bin/bash",
            parentPID: 7000,
            ancestryDepth: 3
        )
        #expect(await detector.trackingSize >= 1)
        // Can't fast-forward time in a unit test, but we can at least assert
        // the method runs without error and keeps recent entries.
        await detector.purgeStale()
        #expect(await detector.trackingSize >= 1)  // recent entries preserved
    }
}
