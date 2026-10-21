import Foundation
import Testing
@testable import MacCrabCore

/// Privileged commands each hold a dispatch thread while they run; the
/// permits bound how many do at once.
@Suite("Async permits")
struct AsyncPermitsTests {
    @Test("acquirers past the limit wait until a permit is released, in order")
    func permitsBoundConcurrency() async throws {
        let permits = AsyncPermits(2)
        await permits.acquire()
        await permits.acquire()
        let third = Task { await permits.acquire(); return true }
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(5))
        while await permits.waiting < 1, clock.now < deadline {
            try await Task.sleep(for: .milliseconds(2))
        }
        #expect(await permits.waiting == 1, "the third acquirer waits")
        await permits.release()
        #expect(await third.value)
        #expect(await permits.waiting == 0)
        await permits.release()
        await permits.release()
        // Both permits are free again.
        await permits.acquire()
        await permits.acquire()
        #expect(await permits.waiting == 0)
    }

    @Test("waiters take a released permit in arrival order")
    func waitersInOrder() async throws {
        actor Log { var names: [String] = []; func add(_ name: String) { names.append(name) } }
        let permits = AsyncPermits(1)
        let log = Log()
        await permits.acquire()
        let clock = ContinuousClock()
        func waitFor(_ count: Int) async throws {
            let deadline = clock.now.advanced(by: .seconds(5))
            while await permits.waiting < count, clock.now < deadline {
                try await Task.sleep(for: .milliseconds(2))
            }
        }
        let first = Task { await permits.acquire(); await log.add("first"); await permits.release() }
        try await waitFor(1)
        let second = Task { await permits.acquire(); await log.add("second"); await permits.release() }
        try await waitFor(2)
        await permits.release()
        await first.value
        await second.value
        #expect(await log.names == ["first", "second"])
    }

    @Test("runAsync holds a permit for each running command")
    func runAsyncIsBounded() async throws {
        // Five one-second commands on two permits take at least three rounds;
        // unbounded they all finish in about one. Load only lengthens it.
        // Completion is polled against a deadline rather than awaited, so a
        // permit that is never released fails the test instead of hanging it.
        actor Finished { var count = 0; func add() { count += 1 } }
        let finished = Finished()
        let permits = AsyncPermits(2)
        let started = ContinuousClock.now
        let commands = (0..<5).map { _ in
            Task { () -> BoundedPrivilegedProcessRunner.Result? in
                let result = await BoundedPrivilegedProcessRunner.runAsync(
                    executable: "/bin/sleep", arguments: ["1"], timeout: 10,
                    maximumOutputBytes: 1_024, permits: permits)
                await finished.add()
                return result
            }
        }
        let deadline = started.advanced(by: .seconds(30))
        while await finished.count < 5, ContinuousClock.now < deadline {
            try await Task.sleep(for: .milliseconds(50))
        }
        let elapsed = ContinuousClock.now - started
        let count = await finished.count
        guard count == 5 else {
            Issue.record("\(count) of 5 commands finished: a permit was never released")
            return
        }
        for command in commands {
            #expect(await command.value?.succeeded == true)
        }
        #expect(elapsed >= .milliseconds(2_500), "at most two commands ran at once")
        #expect(await permits.waiting == 0)
    }
}
