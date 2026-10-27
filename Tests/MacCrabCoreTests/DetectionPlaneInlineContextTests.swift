import Foundation
import Testing
@testable import MacCrabAgentKit
@testable import MacCrabCore

/// Derived work that runs inline on a saturated plane must know it, so slow
/// shared resources (spctl) are never awaited on an event lane.
@Suite("Detection-plane inline context")
struct DetectionPlaneInlineContextTests {
    private final class Flag: @unchecked Sendable {
        private let lock = NSLock()
        private var values: [Bool] = []
        func record(_ value: Bool) { lock.lock(); values.append(value); lock.unlock() }
        var recorded: [Bool] { lock.lock(); defer { lock.unlock() }; return values }
    }

    @Test("only an inline overload run sees the lane context")
    func inlineRunIsMarked() async throws {
        let lifecycle = DaemonTimerLifecycle(maximumInFlightHandlers: 1)
        let flag = Flag()
        let gate = AsyncStream<Void>.makeStream()
        let started = AsyncStream<Void>.makeStream()
        // Occupy the plane's only slot. The slot is taken at submission, but
        // the handler records only once it runs; shutdown cancels work that
        // has not started, so wait for it before anything else happens.
        #expect(await lifecycle.submitOrRunInlineOnOverload(label: "occupant") {
            flag.record(DaemonWorkInlineContext.isRunningOnLane)
            started.continuation.yield()
            started.continuation.finish()
            for await _ in gate.stream { break }
        } == .accepted)
        for await _ in started.stream { break }
        #expect(await lifecycle.submitOrRunInlineOnOverload(label: "derived") {
            flag.record(DaemonWorkInlineContext.isRunningOnLane)
        } == .ranInlineOnOverload)
        gate.continuation.yield()
        gate.continuation.finish()
        _ = await lifecycle.shutdown(deadline: 5)
        #expect(flag.recorded.sorted { !$0 && $1 } == [false, true])
        #expect(!DaemonWorkInlineContext.isRunningOnLane)
    }

    @Test("a follow-up submitted from a lane-inline run completes off the lane")
    func followUpRunsOffLane() async throws {
        let lifecycle = DaemonTimerLifecycle(maximumInFlightHandlers: 1)
        let followUps = DaemonTimerLifecycle(maximumInFlightHandlers: 1)
        let flag = Flag()
        let gate = AsyncStream<Void>.makeStream()
        #expect(await lifecycle.submitOrRunInlineOnOverload(label: "occupant") {
            for await _ in gate.stream { break }
        } == .accepted)
        #expect(await lifecycle.submitOrRunInlineOnOverload(label: "notarization-check") {
            followUps.submit(label: "notarization-follow-up") {
                await DaemonWorkInlineContext.$isRunningOnLane.withValue(false) {
                    flag.record(DaemonWorkInlineContext.isRunningOnLane)
                }
            }
        } == .ranInlineOnOverload)
        // Shutdown cancels work that has not started, as on every plane, so
        // wait for the follow-up to finish first.
        let deadline = Date().addingTimeInterval(5)
        while followUps.snapshot().completedHandlers < 1, Date() < deadline {
            try await Task.sleep(nanoseconds: 1_000_000)
        }
        #expect(await followUps.shutdown(deadline: 5), "the follow-up plane joins its work")
        gate.continuation.yield()
        gate.continuation.finish()
        _ = await lifecycle.shutdown(deadline: 5)
        #expect(flag.recorded == [false])
        #expect(followUps.snapshot().completedHandlers == 1)
    }

    @Test("a lane-inline notarization lookup never assesses and counts its miss")
    func overloadLookupIsCacheOnly() async {
        let checker = NotarizationChecker()
        let unknown = NSTemporaryDirectory() + "maccrab-unassessed-\(UUID().uuidString)"
        #expect(await checker.cachedResultForOverload(binaryPath: unknown) == nil)
        let diagnostics = await checker.diagnostics()
        #expect(diagnostics.overloadCacheMisses == 1)
        #expect(diagnostics.assessmentsCompleted == 0)
        #expect(await checker.cachedResultForOverload(binaryPath: "/usr/bin/true")?.status == .notarized)
    }
}
