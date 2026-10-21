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
        let permits = AsyncPermits(2)
        let commands = (0..<5).map { _ in
            Task {
                await BoundedPrivilegedProcessRunner.runAsync(
                    executable: "/bin/sleep", arguments: ["0.5"], timeout: 10,
                    maximumOutputBytes: 1_024, permits: permits)
            }
        }
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(5))
        while await permits.waiting < 3, clock.now < deadline {
            try await Task.sleep(for: .milliseconds(5))
        }
        #expect(await permits.waiting == 3, "two run, three wait")
        for command in commands {
            let result = await command.value
            #expect(result?.succeeded == true)
        }
        #expect(await permits.waiting == 0)
    }
}
