import Foundation
import Testing
@testable import MacCrabCore

/// Blocking work must not occupy Swift cooperative-pool threads.
/// No collector, process or device is opened; bodies block on semaphores.
@Suite("Blocking work stays off the cooperative pool", .serialized)
struct BlockingWorkOffloadTests {
    @Test("dedicated-thread work returns its result on the named thread")
    func dedicatedThreadResult() async {
        let name = await BlockingWorkOffload.runOnDedicatedThread(
            name: "com.maccrab.test.blocking-reader"
        ) { _ in Thread.current.name ?? "" }
        #expect(name == "com.maccrab.test.blocking-reader")
    }

    @Test("cancelling the owning task reaches the blocking loop")
    func cancellationForwarded() async {
        let started = DispatchSemaphore(value: 0)
        let task = Task.detached {
            await BlockingWorkOffload.runOnDedicatedThread(name: "com.maccrab.test.cancel") { flag in
                started.signal()
                let deadline = Date().addingTimeInterval(5)
                while !flag.isCancelled, Date() < deadline { usleep(1_000) }
                return flag.isCancelled
            }
        }
        started.wait()
        task.cancel()
        #expect(await task.value)
    }

    @Test("an already-cancelled task starts its loop cancelled")
    func cancelledBeforeStart() async {
        let task = Task.detached {
            withUnsafeCurrentTask { $0?.cancel() }
            return await BlockingWorkOffload.runOnDedicatedThread(name: "com.maccrab.test.precancel") {
                $0.isCancelled
            }
        }
        #expect(await task.value)
    }

    @Test("single blocking calls run on the requested serial queue")
    func performOnQueue() async {
        let queue = DispatchQueue(label: "com.maccrab.test.perform")
        let value = await BlockingWorkOffload.perform(on: queue) { () -> Int in
            dispatchPrecondition(condition: .onQueue(queue))
            return 42
        }
        #expect(value == 42)
    }

    @Test("more blocked readers than CPUs leave the cooperative pool usable")
    func poolRemainsAvailable() async throws {
        let readers = Foundation.ProcessInfo.processInfo.activeProcessorCount + 2
        let release = DispatchSemaphore(value: 0)
        let entered = DispatchSemaphore(value: 0)
        let owners = (0..<readers).map { index in
            Task.detached {
                await BlockingWorkOffload.runOnDedicatedThread(name: "com.maccrab.test.reader-\(index)") { _ in
                    entered.signal()
                    release.wait()
                    return index
                }
            }
        }
        // Bounded waits: if readers occupied pool threads, later ones could
        // never start and this control must fail rather than hang the run.
        var enteredCount = 0
        for _ in 0..<readers where entered.wait(timeout: .now() + 5) == .success { enteredCount += 1 }
        // Every reader is now parked in a blocking wait. Ordinary async work
        // must still be scheduled promptly; parked pool threads would stall it.
        let probeDone = DispatchSemaphore(value: 0)
        let probe = Task.detached { () -> Int in
            let sum = await withTaskGroup(of: Int.self) { group in
                for value in 0..<64 { group.addTask { value } }
                return await group.reduce(0, +)
            }
            probeDone.signal()
            return sum
        }
        let probeCompleted = probeDone.wait(timeout: .now() + 2) == .success
        for _ in 0..<readers { release.signal() }
        var joined = 0
        for owner in owners { joined += await owner.value >= 0 ? 1 : 0 }
        #expect(enteredCount == readers)
        #expect(probeCompleted)
        #expect(await probe.value == 2_016)
        #expect(joined == readers)
    }
}
