import Foundation
import Testing
import MacCrabCore
@testable import MacCrabAgentKit

private actor BlockingTimerHandler {
    private var started = false
    private var released = false
    private var startWaiters: [CheckedContinuation<Void, Never>] = []
    private var releaseWaiters: [CheckedContinuation<Void, Never>] = []

    func run() async {
        started = true
        let waitingForStart = startWaiters
        startWaiters.removeAll()
        for waiter in waitingForStart { waiter.resume() }
        guard !released else { return }
        await withCheckedContinuation { continuation in
            releaseWaiters.append(continuation)
        }
    }

    func waitUntilStarted() async {
        guard !started else { return }
        await withCheckedContinuation { continuation in
            startWaiters.append(continuation)
        }
    }

    func release() {
        released = true
        let waiters = releaseWaiters
        releaseWaiters.removeAll()
        for waiter in waiters { waiter.resume() }
    }
}

@Suite("Daemon dispatch-timer lifecycle")
struct DaemonTimerLifecycleTests {
    private func waitForHandlerExit(
        _ lifecycle: DaemonTimerLifecycle,
        timeoutSeconds: TimeInterval = 30
    ) async {
        let interval = UInt64(max(0, timeoutSeconds) * 1_000_000_000)
        let addition = DispatchTime.now().uptimeNanoseconds
            .addingReportingOverflow(interval)
        let deadline = addition.overflow ? UInt64.max : addition.partialValue
        while lifecycle.snapshot().inFlightHandlers != 0,
              DispatchTime.now().uptimeNanoseconds < deadline {
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
    }

    @Test("accepted handlers conserve and shutdown joins a released handler")
    func cleanJoin() async {
        let lifecycle = DaemonTimerLifecycle()
        let blocker = BlockingTimerHandler()
        #expect(lifecycle.submit(label: "test") {
            await blocker.run()
        })
        await blocker.waitUntilStarted()
        // Release synchronously. A separately scheduled release task can be
        // starved behind the thousands of peers in a full package run, turning
        // this into a scheduler benchmark instead of a join/conservation test.
        await blocker.release()

        #expect(await lifecycle.shutdown(deadline: 30.0))
        let snapshot = lifecycle.snapshot()
        #expect(!snapshot.accepting)
        #expect(snapshot.acceptedHandlers == 1)
        #expect(snapshot.completedHandlers == 1)
        #expect(snapshot.inFlightHandlers == 0)
        #expect(snapshot.conservesAcceptedHandlers)
        #expect(snapshot.conservesOfferedHandlers)
    }

    @Test("blocked handler makes shutdown explicitly unclean and closes admission")
    func blockedJoin() async {
        let lifecycle = DaemonTimerLifecycle()
        let blocker = BlockingTimerHandler()
        #expect(lifecycle.submit(label: "blocked") {
            // Deliberately cancellation-uncooperative, modeling an actor call
            // already inside SQLite when the timer source is cancelled.
            await blocker.run()
        })
        await blocker.waitUntilStarted()

        #expect(!(await lifecycle.shutdown(deadline: 0.01)))
        #expect(!lifecycle.submit(label: "late") {})
        var snapshot = lifecycle.snapshot()
        #expect(!snapshot.accepting)
        #expect(snapshot.acceptedHandlers == 1)
        #expect(snapshot.inFlightHandlers == 1)
        #expect(snapshot.rejectedHandlers == 1)
        #expect(snapshot.conservesAcceptedHandlers)
        #expect(snapshot.conservesOfferedHandlers)

        await blocker.release()
        await waitForHandlerExit(lifecycle)
        snapshot = lifecycle.snapshot()
        #expect(snapshot.completedHandlers == 1)
        #expect(snapshot.inFlightHandlers == 0)
        #expect(snapshot.conservesAcceptedHandlers)
        #expect(snapshot.conservesOfferedHandlers)
    }

    @Test("bounded admission rejects overload without losing conservation")
    func boundedAdmission() async {
        let lifecycle = DaemonTimerLifecycle(maximumInFlightHandlers: 2)
        let first = BlockingTimerHandler()
        let second = BlockingTimerHandler()
        #expect(lifecycle.submit(label: "first") { await first.run() })
        #expect(lifecycle.submit(label: "second") { await second.run() })
        await first.waitUntilStarted()
        await second.waitUntilStarted()

        #expect(!lifecycle.submit(label: "overflow") {})
        var snapshot = lifecycle.snapshot()
        #expect(snapshot.acceptedHandlers == 2)
        #expect(snapshot.rejectedHandlers == 1)
        #expect(snapshot.inFlightHandlers == 2)
        #expect(snapshot.maximumInFlightHandlers == 2)
        #expect(snapshot.conservesAcceptedHandlers)
        #expect(snapshot.conservesOfferedHandlers)

        await first.release()
        await second.release()
        #expect(await lifecycle.shutdown(deadline: 30.0))
        snapshot = lifecycle.snapshot()
        #expect(snapshot.completedHandlers == 2)
        #expect(snapshot.inFlightHandlers == 0)
        #expect(snapshot.conservesAcceptedHandlers)
        #expect(snapshot.conservesOfferedHandlers)
    }

    @Test("repeating timer labels coalesce while one handler is active")
    func coalescesRepeatingLabel() async {
        let lifecycle = DaemonTimerLifecycle(coalesceByLabel: true)
        let blocker = BlockingTimerHandler()
        #expect(lifecycle.submit(label: "rich-heartbeat") {
            await blocker.run()
        })
        await blocker.waitUntilStarted()
        #expect(!lifecycle.submit(label: "rich-heartbeat") {})
        var snapshot = lifecycle.snapshot()
        #expect(snapshot.offeredHandlers == 2)
        #expect(snapshot.acceptedHandlers == 1)
        #expect(snapshot.coalescedHandlers == 1)
        #expect(snapshot.coalescedByLabel["rich-heartbeat"] == 1)
        #expect(snapshot.rejectedHandlers == 0)
        #expect(snapshot.conservesOfferedHandlers)
        await blocker.release()
        #expect(await lifecycle.shutdown(deadline: 30.0))
        snapshot = lifecycle.snapshot()
        #expect(snapshot.completedHandlers == 1)
        #expect(snapshot.conservesAcceptedHandlers)
    }

    @Test("concurrent shutdown callers share one recorded result")
    func concurrentShutdownSharesResult() async {
        let lifecycle = DaemonTimerLifecycle()
        let blocker = BlockingTimerHandler()
        #expect(lifecycle.submit(label: "blocked") { await blocker.run() })
        await blocker.waitUntilStarted()
        async let first = lifecycle.shutdown(deadline: 0.01)
        async let second = lifecycle.shutdown(deadline: 1.0)
        let results = await (first, second)
        #expect(results.0 == results.1)
        #expect(!results.0)
        await blocker.release()
    }

    @Test("every terminal surface delegates to one ordered finalizer")
    func sourceWiring() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent()
        let bootstrap = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/MacCrabAgentKit/DaemonBootstrap.swift"
            ),
            encoding: .utf8
        )
        let signals = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/MacCrabAgentKit/SignalHandlers.swift"
            ),
            encoding: .utf8
        )
        let lifecycle = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/MacCrabAgentKit/DaemonLifecycle.swift"
            ),
            encoding: .utf8
        )
        #expect(bootstrap.contains("DaemonShutdownCoordinator.finalize("))
        #expect(signals.contains("DaemonShutdownCoordinator.finalize("))
        #expect(!bootstrap.contains("eventWriter.shutdown()"))
        #expect(!signals.contains("eventWriter.shutdown()"))
        for plane in [
            "eventIngestionLifecycle", "livenessLifecycle",
            "startupWorkLifecycle", "detectionWorkLifecycle",
            "advisoryWorkLifecycle", "outputWorkLifecycle",
        ] {
            #expect(lifecycle.contains(plane))
        }
        let writer = try #require(lifecycle.range(of: "eventWriter.shutdown()"))
        let evidence = try #require(lifecycle.range(
            of: "alertSink.shutdownEvidenceCapture("
        ))
        let graph = try #require(lifecycle.range(of: "bridge.flushPending()"))
        let checkpoint = try #require(lifecycle.range(of: ".forceFlush("))
        #expect(writer.lowerBound < evidence.lowerBound)
        #expect(evidence.lowerBound < graph.lowerBound)
        #expect(graph.lowerBound < checkpoint.lowerBound)
        #expect(lifecycle.contains("evidenceShutdown?.clean"))
        #expect(lifecycle.contains("evidenceShutdown.pending"))
        #expect(lifecycle.contains(
            "evidenceShutdown.alertAdmissionsInFlight"
        ))
        #expect(lifecycle.contains("stopRuntimeProducers("))
        #expect(lifecycle.contains("stopAndJoin("))
        for producer in [
            "collector", "unifiedLog", "eslogger", "kdebug", "tcc",
            "network", "fsEvents", "esHealth", "eventTap",
            "systemPolicy", "mcp", "ultrasonic", "usb", "clipboard",
            "browser", "dns", "rootkit", "sdr", "btm", "edr",
        ] {
            #expect(
                lifecycle.contains("\(producer).stopAndJoin("),
                "central finalizer omitted producer \(producer)"
            )
        }
        #expect(lifecycle.contains("threatIntel.stop(deadline:"))
        #expect(lifecycle.contains("selfDefense.stop(deadline:"))
        #expect(lifecycle.contains("certificateTransparency.shutdown()"))
        #expect(lifecycle.contains("baseline.stopAutoSaveAndJoin("))
        #expect(lifecycle.contains("fleet.stop(deadline:"))
        #expect(lifecycle.contains("receiver.stop("))
        #expect(lifecycle.contains(".cleanlyStopped"))
        #expect(lifecycle.contains("await ueba.save()"))
        #expect(lifecycle.contains("uebaPersistence: uebaPersistence"))
    }

    @Test("clean shutdown requires a successful non-dirty checkpoint")
    func checkpointResultParticipatesInBoundaryTruth() {
        func result(
            checkpoint: SequenceCheckpointWriteResult?,
            dirty: Bool,
            heavyEnrichmentClean: Bool = true
        ) -> DaemonShutdownResult {
            DaemonShutdownResult(
                producerPlane: true,
                ingestionPlane: true,
                timerPlane: true,
                livenessPlane: true,
                monitorPlane: true,
                startupPlane: true,
                heavyEnrichmentPlane: heavyEnrichmentClean,
                detectionWorkPlane: true,
                advisoryWorkPlane: true,
                outputWorkPlane: true,
                uebaPersistence: true,
                writer: true,
                evidence: true,
                evidenceShutdown: nil,
                graph: true,
                checkpoint: checkpoint,
                checkpointDirty: dirty
            )
        }

        #expect(result(checkpoint: .written(bytes: 42), dirty: false)
            .cleanMutationBoundary)
        #expect(result(checkpoint: .unchanged, dirty: false)
            .cleanMutationBoundary)
        #expect(!result(checkpoint: .failed("disk full"), dirty: false)
            .cleanMutationBoundary)
        #expect(!result(checkpoint: .alreadyInProgress, dirty: false)
            .cleanMutationBoundary)
        #expect(!result(checkpoint: .written(bytes: 42), dirty: true)
            .cleanMutationBoundary)
        #expect(!result(
            checkpoint: .written(bytes: 42),
            dirty: false,
            heavyEnrichmentClean: false
        ).cleanMutationBoundary)
    }

    @Test("EventLoop derivative mutations cannot escape the owned lifecycle")
    func eventLoopDerivedWorkWiring() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/MacCrabAgentKit/EventLoop.swift"
            ),
            encoding: .utf8
        )
        let timers = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/MacCrabAgentKit/DaemonTimers.swift"
            ),
            encoding: .utf8
        )
        #expect(!source.contains("Task.detached"))
        for label in [
            "notarization-check", "graph-rule-evaluation",
            "intent-refinement", "intent-model-advisory", "prompt-intent", "rule-candidate",
            "campaign-llm",
            "webhook", "syslog", "additional-output",
            "llm-triage", "package-freshness",
            "cert-transparency",
        ] {
            #expect(source.contains("label: \"\(label)\""))
        }
        #expect(timers.contains(
            "timerLifecycle.submit(label: \"deferred-enrichment-drain\")"
        ))
    }
}
