// CollectorProducerLifecycleTests.swift
//
// Adversarial contracts for one-shot collector ownership. These tests avoid
// privileged/live sensors: the lifecycle races are exercised through the same
// lock-backed primitives used by the production collectors.

import Foundation
import Testing
@testable import MacCrabCore

@Suite("Collector producer lifecycle")
struct CollectorProducerLifecycleTests {
    @Test("bounded join reports an uncooperative owned task honestly")
    func boundedJoinReportsTimeoutThenCleanDrain() async {
        let gate = CollectorLifecycleTestGate()
        let task = Task { await gate.wait() }
        while !(await gate.hasEntered()) { await Task.yield() }

        #expect(!(await CollectorBoundedTaskJoin.waitForAll(
            [task],
            deadline: 0.01
        )))

        await gate.release()
        #expect(await CollectorBoundedTaskJoin.waitForAll(
            [task],
            deadline: 1.0
        ))
    }

    @Test("callback lifecycle seals admission before joining accepted prefix")
    func callbackAdmissionCannotResurrectAfterSeal() async {
        let lifecycle = CollectorCallbackTaskLifecycle(maximumInFlight: 1)
        let gate = CollectorLifecycleTestGate()
        #expect(lifecycle.open())
        #expect(lifecycle.submit { await gate.wait() })
        while !(await gate.hasEntered()) { await Task.yield() }

        let acceptedPrefix = lifecycle.sealAndCancel()
        #expect(!lifecycle.submit {})
        #expect(!(await CollectorBoundedTaskJoin.waitForAll(
            acceptedPrefix,
            deadline: 0.01
        )))

        await gate.release()
        #expect(await CollectorBoundedTaskJoin.waitForAll(
            acceptedPrefix,
            deadline: 1.0
        ))
        #expect(await lifecycle.shutdown(deadline: 1.0))
    }

    @Test("FSEvents stop-before-install rejects late stream adoption")
    func fsEventsStopBeforeInstall() throws {
        let control = FSEventsWorkerControl()
        control.requestStop()
        let runLoop = try #require(CFRunLoopGetCurrent())
        #expect(!control.install(runLoop: runLoop))
        #expect(control.shouldStop)
    }

    @Test("every daemon-owned producer exposes an explicit join boundary")
    func sourceInventoryHasJoinBoundaries() throws {
        let root = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        let relativePaths = [
            "Sources/MacCrabCore/Collectors/ESCollector.swift",
            "Sources/MacCrabCore/Collectors/EsloggerCollector.swift",
            "Sources/MacCrabCore/Collectors/KdebugCollector.swift",
            "Sources/MacCrabCore/Collectors/UnifiedLogCollector.swift",
            "Sources/MacCrabCore/Collectors/FSEventsCollector.swift",
            "Sources/MacCrabCore/Collectors/NetworkCollector.swift",
            "Sources/MacCrabCore/Collectors/TCCMonitor.swift",
            "Sources/MacCrabCore/Collectors/DNSCollector.swift",
            "Sources/MacCrabCore/Collectors/MCPMonitor.swift",
            "Sources/MacCrabCore/Collectors/USBMonitor.swift",
            "Sources/MacCrabCore/Collectors/ClipboardMonitor.swift",
            "Sources/MacCrabCore/Collectors/BrowserExtensionMonitor.swift",
            "Sources/MacCrabCore/Collectors/EventTapMonitor.swift",
            "Sources/MacCrabCore/Collectors/SystemPolicyMonitor.swift",
            "Sources/MacCrabCore/Collectors/EDRMonitor.swift",
            "Sources/MacCrabCore/Collectors/SDRDeviceMonitor.swift",
            "Sources/MacCrabCore/Collectors/BTMSnapshotMonitor.swift",
            "Sources/MacCrabCore/Collectors/UltrasonicMonitor.swift",
            "Sources/MacCrabCore/Detection/ESClientMonitor.swift",
            "Sources/MacCrabCore/Detection/RootkitDetector.swift",
        ]
        for relativePath in relativePaths {
            let source = try String(
                contentsOf: root.appendingPathComponent(relativePath),
                encoding: .utf8
            )
            #expect(
                source.contains("stopAndJoin(deadline:"),
                "missing join API: \(relativePath)"
            )
        }
    }

    @Test("watchdog collectors gate restart by lifecycle generation")
    func watchdogRestartIsGenerationBound() throws {
        let root = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        for name in ["EsloggerCollector", "KdebugCollector"] {
            let source = try String(
                contentsOf: root.appendingPathComponent(
                    "Sources/MacCrabCore/Collectors/\(name).swift"
                ),
                encoding: .utf8
            )
            #expect(source.contains("generation == lifecycleGeneration"))
            #expect(source.contains("lifecyclePhase == .running"))
            #expect(!source.contains("Task { await weakSelf?.handle"))
        }
    }

    @Test("restartable-looking actor starts are one-shot phase gated")
    func actorStartsCannotResurrectFinishedStreams() throws {
        let root = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        let relativePaths = [
            "Sources/MacCrabCore/Collectors/EsloggerCollector.swift",
            "Sources/MacCrabCore/Collectors/KdebugCollector.swift",
            "Sources/MacCrabCore/Collectors/FSEventsCollector.swift",
            "Sources/MacCrabCore/Collectors/NetworkCollector.swift",
            "Sources/MacCrabCore/Collectors/TCCMonitor.swift",
            "Sources/MacCrabCore/Collectors/DNSCollector.swift",
            "Sources/MacCrabCore/Collectors/MCPMonitor.swift",
            "Sources/MacCrabCore/Collectors/USBMonitor.swift",
            "Sources/MacCrabCore/Collectors/ClipboardMonitor.swift",
            "Sources/MacCrabCore/Collectors/BrowserExtensionMonitor.swift",
            "Sources/MacCrabCore/Collectors/EventTapMonitor.swift",
            "Sources/MacCrabCore/Collectors/SystemPolicyMonitor.swift",
            "Sources/MacCrabCore/Collectors/EDRMonitor.swift",
            "Sources/MacCrabCore/Collectors/SDRDeviceMonitor.swift",
            "Sources/MacCrabCore/Collectors/BTMSnapshotMonitor.swift",
            "Sources/MacCrabCore/Collectors/UltrasonicMonitor.swift",
            "Sources/MacCrabCore/Detection/ESClientMonitor.swift",
            "Sources/MacCrabCore/Detection/RootkitDetector.swift",
        ]
        for relativePath in relativePaths {
            let source = try String(
                contentsOf: root.appendingPathComponent(relativePath),
                encoding: .utf8
            )
            #expect(
                source.contains("lifecyclePhase == .initialized"),
                "start is not one-shot phase gated: \(relativePath)"
            )
        }
    }
}

private actor CollectorLifecycleTestGate {
    private var entered = false
    private var released = false
    private var waiter: CheckedContinuation<Void, Never>?

    func wait() async {
        entered = true
        guard !released else { return }
        await withCheckedContinuation { continuation in
            waiter = continuation
        }
    }

    func hasEntered() -> Bool { entered }

    func release() {
        released = true
        let pending = waiter
        waiter = nil
        pending?.resume()
    }
}
