// HeavyEnrichmentPlaneTests.swift
// Adversarial ownership and evidence-correctness tests for the enrichment
// plane.  These use injected operations only: no Security.framework timing,
// privileged collector, or live filesystem stall is required.

import Foundation
import Testing
@testable import MacCrabCore

private actor HeavyEnrichmentTestGate {
    private var entered = false
    private var released = false
    private var enterWaiters: [CheckedContinuation<Void, Never>] = []
    private var releaseWaiters: [CheckedContinuation<Void, Never>] = []

    func runIgnoringCancellation() async {
        entered = true
        let waiting = enterWaiters
        enterWaiters.removeAll()
        for waiter in waiting { waiter.resume() }
        guard !released else { return }
        await withCheckedContinuation { continuation in
            releaseWaiters.append(continuation)
        }
    }

    func waitUntilEntered() async {
        guard !entered else { return }
        await withCheckedContinuation { continuation in
            enterWaiters.append(continuation)
        }
    }

    func release() {
        released = true
        let waiting = releaseWaiters
        releaseWaiters.removeAll()
        for waiter in waiting { waiter.resume() }
    }
}

private actor HeavyEnrichmentTestCounter {
    private var value = 0
    func increment() { value += 1 }
    func read() -> Int { value }
}

@Suite("Heavy enrichment plane")
struct HeavyEnrichmentPlaneTests {
    private static let start = Date(timeIntervalSince1970: 1_750_000_000)

    private static func isolatedMemoryBudget() -> EventPipelineLiveMemoryBudget {
        EventPipelineLiveMemoryBudget(
            maximumBytes: EventPipelineLiveMemoryBudget.productionMaximumBytes,
            forwardProgressReserveBytes: EventPipelineLiveMemoryBudget
                .productionForwardProgressReserveBytes,
            eventStoreWorkspaceReserveBytes: EventPipelineLiveMemoryBudget
                .productionEventStoreWorkspaceReserveBytes,
            compactReceiptReserveBytes: EventPipelineLiveMemoryBudget
                .productionCompactReceiptReserveBytes
        )
    }

    private static func event(
        id: UUID = UUID(),
        pid: Int32 = 4242,
        uid: UInt32 = 501,
        filePath: String? = nil,
        fileSize: UInt64? = nil
    ) -> Event {
        let process = MacCrabCore.ProcessInfo(
            pid: pid,
            ppid: 1,
            rpid: pid,
            name: "fixture",
            executable: "/usr/bin/true",
            commandLine: "true",
            args: [],
            workingDirectory: "/",
            userId: uid,
            userName: "fixture",
            groupId: 20,
            startTime: start,
            codeSignature: CodeSignatureInfo(signerType: .apple),
            isPlatformBinary: true
        )
        return Event(
            id: id,
            timestamp: start,
            eventCategory: filePath == nil ? .process : .file,
            eventType: filePath == nil ? .start : .change,
            eventAction: filePath == nil ? "exec" : "close_modified",
            process: process,
            file: filePath.map {
                FileInfo(path: $0, size: fileSize, action: .write)
            }
        )
    }

    private static func waitForSnapshot(
        _ plane: HeavyEnrichmentPlane,
        timeoutSeconds: TimeInterval = 30,
        predicate: (HeavyEnrichmentPlaneSnapshot) -> Bool
    ) async -> HeavyEnrichmentPlaneSnapshot {
        // Heavy workers and their timeout owners deliberately run at utility
        // priority. A full parallel package run can starve that executor for
        // longer than one wall-clock second without violating the plane's
        // conservation contract. Keep this as an eventual-state assertion
        // with a coarse hang detector, and use a monotonic clock so a wall-clock
        // adjustment cannot end the wait early.
        let interval = UInt64(max(0, timeoutSeconds) * 1_000_000_000)
        let addition = DispatchTime.now().uptimeNanoseconds
            .addingReportingOverflow(interval)
        let deadline = addition.overflow ? UInt64.max : addition.partialValue
        var latest = await plane.snapshot()
        while !predicate(latest),
              DispatchTime.now().uptimeNanoseconds < deadline {
            try? await Task.sleep(nanoseconds: 5_000_000)
            latest = await plane.snapshot()
        }
        if !predicate(latest) {
            // Returning the last snapshot anyway keeps the caller's remaining
            // assertions readable, but the expired wait is the real failure:
            // report it here so the caller's downstream expectations are not
            // mistaken for the root cause.
            Issue.record(
                """
                waitForSnapshot expired after \(timeoutSeconds)s without the \
                predicate holding; the snapshot below is the last observed \
                state, not a satisfied one: \(latest)
                """
            )
        }
        return latest
    }

    @Test("timed-out worker remains charged; queue cap and request conservation hold")
    func stalledWorkerStaysCharged() async {
        let plane = HeavyEnrichmentPlane(configuration: .init(
            maximumConcurrentWorkers: 1,
            maximumQueuedWorkItems: 1,
            maximumOutstandingResults: 8,
            cacheCapacity: 0,
            operationTimeoutSeconds: 0.02
        ), liveMemoryBudget: Self.isolatedMemoryBudget())
        let gate = HeavyEnrichmentTestGate()
        let firstBinding = HeavyEnrichmentBinding(event: Self.event(uid: 501))

        let firstOffer = await plane.offer(component: .userName, binding: firstBinding) {
            await gate.runIgnoringCancellation()
            return .userName("first")
        }
        guard case .pending = firstOffer else {
            Issue.record("first offer should be accepted before waiting on its worker")
            await gate.release()
            _ = await plane.shutdown()
            return
        }
        await gate.waitUntilEntered()
        let timedOut = await Self.waitForSnapshot(plane) {
            $0.timedOutRequestsTotal == 1
        }
        #expect(timedOut.requestsConserved)
        #expect(timedOut.physicalWorkers == 1)
        #expect(timedOut.lingeringTimedOutOrCancelledWorkers == 1)

        let second = await plane.offer(
            component: .userName,
            binding: HeavyEnrichmentBinding(event: Self.event(uid: 502)),
            // This operation tests queue promotion after the deliberately
            // stalled worker exits, not a one-second SLA. A full package run
            // can saturate Swift's utility executor for tens of seconds.
            timeoutSeconds: 60
        ) { .userName("second") }
        guard case .pending = second else {
            Issue.record("second operation should be queued")
            return
        }
        let third = await plane.offer(
            component: .userName,
            binding: HeavyEnrichmentBinding(event: Self.event(uid: 503)),
            timeoutSeconds: 1
        ) { .userName("third") }
        #expect(third == .rejected)

        let capped = await plane.snapshot()
        #expect(capped.physicalWorkers == 1)
        #expect(capped.queuedRequests == 1)
        #expect(capped.rejectedRequestsTotal == 1)
        #expect(capped.requestsConserved)
        #expect(capped.physicalCapacityConserved)

        await gate.release()
        let drained = await Self.waitForSnapshot(plane) {
            $0.completedRequestsTotal == 1 && $0.physicalWorkers == 0
        }
        #expect(drained.requestsConserved)
        #expect(drained.offeredRequestsTotal == 3)
        #expect(drained.completedRequestsTotal == 1)
        #expect(drained.timedOutRequestsTotal == 1)
        #expect(drained.rejectedRequestsTotal == 1)

        let results = await plane.drainDeferredResults(limit: 8)
        #expect(results.count == 2)
        #expect(results.map(\.outcome).contains(.timedOut))
        #expect(results.map(\.outcome).contains(.completed))
        _ = await plane.shutdown()
    }

    @Test("same stable subject coalesces and completed evidence is a same-subject cache hit")
    func coalescingAndCacheHit() async {
        let plane = HeavyEnrichmentPlane(configuration: .init(
            maximumConcurrentWorkers: 1,
            maximumQueuedWorkItems: 2,
            maximumOutstandingResults: 8,
            cacheCapacity: 4,
            // The plane's deadline clock starts at admission, not at worker
            // entry, so any budget that executor starvation can outrun turns
            // this into a timeout-policy test: work 1 goes terminal, its key
            // leaves activeByKey, and the second offer opens a second work
            // that re-runs the operation instead of coalescing. This test
            // asserts coalescing/cache semantics only, so it must never be
            // able to reach a deadline.
            operationTimeoutSeconds: 86_400
        ), liveMemoryBudget: Self.isolatedMemoryBudget())
        let gate = HeavyEnrichmentTestGate()
        let counter = HeavyEnrichmentTestCounter()
        let first = HeavyEnrichmentBinding(event: Self.event(uid: 501))
        let second = HeavyEnrichmentBinding(event: Self.event(uid: 501))

        let firstOffer = await plane.offer(component: .userName, binding: first) {
            await counter.increment()
            await gate.runIgnoringCancellation()
            return .userName("alice")
        }
        guard case .pending = firstOffer else {
            Issue.record("first offer should be accepted before waiting on its worker")
            await gate.release()
            _ = await plane.shutdown()
            return
        }
        await gate.waitUntilEntered()
        let coalesced = await plane.offer(component: .userName, binding: second) {
            await counter.increment()
            return .userName("wrong-worker")
        }
        guard case .pending(_, let wasCoalesced) = coalesced else {
            Issue.record("second offer should be pending")
            await gate.release()
            _ = await plane.shutdown()
            return
        }
        #expect(wasCoalesced)

        await gate.release()
        let completed = await Self.waitForSnapshot(plane) {
            $0.completedRequestsTotal == 2
        }
        #expect(completed.coalescedRequestsTotal == 1)
        #expect(await counter.read() == 1)
        #expect(completed.requestsConserved)

        let cacheHit = await plane.offer(
            component: .userName,
            binding: HeavyEnrichmentBinding(event: Self.event(uid: 501))
        ) {
            await counter.increment()
            return .userName("wrong-cache-miss")
        }
        #expect(cacheHit == .cacheHit(.userName("alice")))
        #expect(await counter.read() == 1)
        let cached = await plane.snapshot()
        #expect(cached.cacheHitsTotal == 1)
        #expect(cached.offeredRequestsTotal == 3)
        #expect(cached.completedRequestsTotal == 3)
        #expect(cached.requestsConserved)
        _ = await plane.shutdown()
    }

    @Test("shutdown seals admission and reports an uncooperative owned worker")
    func shutdownIsBoundedAndTruthful() async {
        let declaredMaximum = EventJournalAdmissionValidator
            .maximumAcceptedSourceRetainedBytes
        let plane = HeavyEnrichmentPlane(configuration: .init(
            maximumConcurrentWorkers: 1,
            maximumQueuedWorkItems: 1,
            maximumOutstandingResults: 8,
            cacheCapacity: 0,
            // Shutdown must be what terminates this work. The deadline clock
            // starts at admission, so any budget executor starvation can
            // outrun retires a request as .timedOut instead of .cancelled and
            // breaks the cancellation accounting this test exists to check.
            operationTimeoutSeconds: 86_400
        ), liveMemoryBudget: Self.isolatedMemoryBudget())
        let gate = HeavyEnrichmentTestGate()
        _ = await plane.offer(
            component: .userName,
            binding: HeavyEnrichmentBinding(event: Self.event(uid: 501)),
            maximumResultBytes: declaredMaximum
        ) {
            await gate.runIgnoringCancellation()
            return .userName(String(
                repeating: "x",
                count: declaredMaximum - 8_192
            ))
        }
        await gate.waitUntilEntered()
        _ = await plane.offer(
            component: .userName,
            binding: HeavyEnrichmentBinding(event: Self.event(uid: 502))
        ) { .userName("queued") }

        let stopped = await plane.shutdown(deadlineSeconds: 0.01)
        #expect(!stopped.accepting)
        #expect(stopped.cancelledRequestsTotal == 2)
        #expect(stopped.physicalWorkers == 1)
        #expect(stopped.lingeringTimedOutOrCancelledWorkers == 1)
        #expect(stopped.activeReservedResultBytes > 0,
                "uncooperative worker keeps its value reservation")
        #expect(stopped.activeReservedResultBytes >= declaredMaximum,
                "the full declared maximum remains charged after cancel")
        #expect(stopped.deferredResultBytes > 0,
                "cancel marker transfers within the original reservation")
        #expect(stopped.resultByteCapacityConserved)
        #expect(stopped.requestsConserved)

        let afterSeal = await plane.offer(
            component: .userName,
            binding: HeavyEnrichmentBinding(event: Self.event(uid: 503))
        ) { .userName("must-not-run") }
        #expect(afterSeal == .rejected)
        let sealed = await plane.snapshot()
        #expect(sealed.offeredRequestsTotal == 3)
        #expect(sealed.rejectedRequestsTotal == 1)
        #expect(sealed.requestsConserved)

        await gate.release()
        _ = await Self.waitForSnapshot(plane) { $0.physicalWorkers == 0 }
        _ = await plane.drainDeferredResults(limit: 8)
        let exited = await plane.snapshot()
        #expect(exited.cleanlyDrained)
        #expect(exited.lateWorkerExitsTotal == 1)
        #expect(exited.requestsConserved)
    }

    @Test("512-result count cannot bypass the shared result and cache byte cap")
    func resultByteCapacityBackpressures() async {
        let binding = HeavyEnrichmentBinding(event: Self.event(uid: 700))
        let declaredValueBytes = 1_048_576
        let perResult = binding.retainedByteEstimate
            + declaredValueBytes + 1_024
        let plane = HeavyEnrichmentPlane(configuration: .init(
            maximumConcurrentWorkers: 1,
            maximumQueuedWorkItems: 512,
            maximumOutstandingResults: 512,
            maximumRetainedResultBytes: perResult * 2,
            cacheCapacity: 512,
            // Byte-capacity accounting only; a reachable deadline would retire
            // gated work mid-run and change the reservation totals asserted
            // below. Same admission-clock reasoning as the coalescing test.
            operationTimeoutSeconds: 86_400
        ), liveMemoryBudget: Self.isolatedMemoryBudget())
        let gate = HeavyEnrichmentTestGate()
        var accepted = 0
        for index in 0..<512 {
            let offer = await plane.offer(
                component: .environment,
                binding: HeavyEnrichmentBinding(event: Self.event(
                    pid: Int32(8_000 + index),
                    uid: UInt32(700 + index)
                )),
                cacheResult: false,
                maximumResultBytes: declaredValueBytes
            ) {
                await gate.runIgnoringCancellation()
                return .environment(["PATH": String(
                    repeating: "x",
                    count: declaredValueBytes - 2_048
                )])
            }
            if case .pending = offer { accepted += 1 }
        }
        let saturated = await plane.snapshot()
        #expect(accepted <= 2)
        #expect(saturated.rejectedRequestsTotal == UInt64(512 - accepted))
        #expect(saturated.activeReservedResultBytes
            <= saturated.maximumRetainedResultBytes)
        #expect(saturated.resultByteCapacityConserved)
        #expect(saturated.requestsConserved)

        await gate.release()
        let completed = await Self.waitForSnapshot(plane) {
            Int($0.completedRequestsTotal) == accepted
        }
        #expect(completed.deferredResultBytes
            <= completed.maximumRetainedResultBytes)
        #expect(completed.retainedResultBytesHighWatermark
            <= completed.maximumRetainedResultBytes)
        #expect(completed.resultByteCapacityConserved)
        #expect(completed.requestsConserved)
        _ = await plane.drainDeferredResults(
            limit: 512,
            maximumBytes: completed.maximumRetainedResultBytes
        )
        _ = await plane.shutdown()
    }

    @Test("deferred patches reject event or stable-file identity mismatch")
    func deferredPatchIdentityBinding() throws {
        let id = UUID()
        let event = Self.event(id: id, filePath: "/tmp/README.md", fileSize: 3)
        var enrichments = event.enrichments
        DeferredEventEnrichment.storeCoverage([.fileContent: .pending], in: &enrichments)
        let pending = Event(
            id: event.id,
            timestamp: event.timestamp,
            eventCategory: event.eventCategory,
            eventType: event.eventType,
            eventAction: event.eventAction,
            process: event.process,
            file: event.file,
            enrichments: enrichments
        )
        let identity = HeavyEnrichmentFileIdentity(
            deviceID: 1,
            inodeNumber: 2,
            sizeBytes: 3,
            modificationSeconds: 4,
            modificationNanoseconds: 5,
            statusChangeSeconds: 6,
            statusChangeNanoseconds: 7
        )
        let patch = DeferredEventEnrichment(
            ticket: HeavyEnrichmentTicket(),
            binding: HeavyEnrichmentBinding(event: event),
            component: .fileContent,
            outcome: .completed,
            value: .fileContent(HeavyFileContentEvidence(
                content: "ioc",
                fileIdentity: identity
            ))
        )
        let applied = try #require(patch.applying(to: pending))
        #expect(applied.enrichments["FileContent"] == "ioc")
        #expect(applied.enrichments[DeferredEventEnrichment.coverageKey] == nil)
        #expect(patch.applying(to: Self.event(filePath: "/tmp/README.md", fileSize: 3)) == nil)

        let wrongSizeIdentity = HeavyEnrichmentFileIdentity(
            deviceID: 1,
            inodeNumber: 2,
            sizeBytes: 4,
            modificationSeconds: 4,
            modificationNanoseconds: 5,
            statusChangeSeconds: 6,
            statusChangeNanoseconds: 7
        )
        let wrongSize = DeferredEventEnrichment(
            ticket: HeavyEnrichmentTicket(),
            binding: HeavyEnrichmentBinding(event: event),
            component: .fileContent,
            outcome: .completed,
            value: .fileContent(HeavyFileContentEvidence(
                content: "stale",
                fileIdentity: wrongSizeIdentity
            ))
        )
        #expect(wrongSize.applying(to: pending) == nil)
    }

    @Test("source owns worker and deadline handles and exposes a bounded drain seam")
    func sourceOwnershipGuard() throws {
        let root = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        let plane = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/MacCrabCore/Enrichment/HeavyEnrichmentPlane.swift"
            ),
            encoding: .utf8
        )
        let enricher = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/MacCrabCore/Enrichment/EventEnricher.swift"
            ),
            encoding: .utf8
        )
        #expect(plane.contains("private var workerTasks: [UInt64: Task<Void, Never>]"))
        #expect(plane.contains("private var deadlineTasks: [UInt64: Task<Void, Never>]"))
        #expect(plane.contains("lingeringTimedOutOrCancelledWorkers"))
        #expect(plane.contains("public func shutdown(deadlineSeconds:"))
        #expect(enricher.contains("public func drainDeferredEnrichments("))
        #expect(enricher.contains("maximumBytes: Int = Int.max"))
        #expect(enricher.contains("HeavyEnrichmentCoverage"))
        #expect(!enricher.contains("await scanner.scan(path:"))
        #expect(!enricher.contains("await codeSigningCache.evaluate(path:"))
        #expect(!enricher.contains("return EnvCapture.capture(pid:"))
    }
}
