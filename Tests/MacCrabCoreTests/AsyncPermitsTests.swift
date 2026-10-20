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
}
