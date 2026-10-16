import Foundation
import Testing
@testable import MacCrabApp

#if DEBUG
@MainActor
@Suite("Bounded window-owned Events backend flight")
struct EventReadFlightTests {
    private final class Gate {
        var continuation: CheckedContinuation<Int, Error>?
        var cancelled = false
        var starts = 0
        func read() async throws -> Int {
            starts += 1
            let watchdog = Task { @MainActor [weak self] in
                do { try await Task.sleep(for: .seconds(30)); try Task.checkCancellation() }
                catch { return }
                Issue.record("Fixture backend did not unwind within the independent cleanup bound")
                self?.finish(.failure(CancellationError()))
            }
            defer { watchdog.cancel() }
            return try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { continuation = $0 }
            } onCancel: {
                Task { @MainActor [weak self] in self?.cancelled = true }
            }
        }
        func finish(_ result: Result<Int, Error> = .success(7)) {
            let pending = continuation
            continuation = nil
            pending?.resume(with: result)
        }
    }
    private final class DeadlineGates {
        let gates = [Gate(), Gate()]
        var calls = 0
        func wait() async throws {
            guard calls < gates.count else {
                Issue.record("Unexpected extra scheduled deadline")
                throw CancellationError()
            }
            let gate = gates[calls]
            calls += 1
            _ = try await gate.read()
        }
        func releaseAll() { for gate in gates { gate.finish() } }
    }
    private func until(_ predicate: () -> Bool) async -> Bool {
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while !predicate() && ContinuousClock.now < deadline { await Task.yield() }
        return predicate()
    }
    private func request(_ lane: EventReadFlight<Int, Int>, key: Int, gate: Gate,
                         cancel: Bool = false, current: @escaping () -> Bool = { true }) -> Task<Int, Error> {
        Task { try await lane.read(key: key, cancelExisting: { _ in cancel },
                                   isCurrent: current, operation: { try await gate.read() }) }
    }

    @Test("View waiter cancellation leaves the backend live and an identical return joins it")
    func leavingDoesNotCancelOwner() async throws {
        let lane = EventReadFlight<Int, Int>(), gate = Gate()
        let first = request(lane, key: 1, gate: gate)
        defer { first.cancel(); lane.cancel(); gate.finish() }
        let began = await until { gate.continuation != nil }
        try #require(began)
        first.cancel()
        _ = await first.result
        #expect(!gate.cancelled && lane.occupiedForTesting)
        let returned = request(lane, key: 1, gate: gate)
        defer { returned.cancel() }
        let joined = await until { lane.waiterCountForTesting == 1 }
        try #require(joined)
        gate.finish()
        #expect(try await returned.value == 7)
        #expect(gate.starts == 1 && !lane.occupiedForTesting)
    }

    @Test("Changed coverage waits for the old result but executes its own exact request")
    func coverageNeverRelabelled() async throws {
        let lane = EventReadFlight<Int, Int>(), firstGate = Gate(), secondGate = Gate()
        let first = request(lane, key: 1, gate: firstGate)
        defer { first.cancel(); lane.cancel(); firstGate.finish(); secondGate.finish() }
        let began = await until { firstGate.continuation != nil }
        try #require(began)
        let second = request(lane, key: 2, gate: secondGate)
        defer { second.cancel() }
        let waiting = await until { lane.waiterCountForTesting == 2 }
        try #require(waiting)
        #expect(secondGate.starts == 0 && !firstGate.cancelled)
        firstGate.finish(.success(11))
        #expect(try await first.value == 11)
        let replacement = await until { secondGate.continuation != nil }
        try #require(replacement)
        secondGate.finish(.success(22))
        #expect(try await second.value == 22)
    }

    @Test("Incompatible replacement cancels but cannot overlap a noncooperative owner")
    func replacementWaitsForActualReturn() async throws {
        let lane = EventReadFlight<Int, Int>(), firstGate = Gate(), secondGate = Gate()
        let first = request(lane, key: 1, gate: firstGate)
        defer { first.cancel(); lane.cancel(); firstGate.finish(); secondGate.finish() }
        let began = await until { firstGate.continuation != nil }
        try #require(began)
        let second = request(lane, key: 2, gate: secondGate, cancel: true)
        defer { second.cancel() }
        let cancelled = await until { firstGate.cancelled }
        try #require(cancelled)
        _ = await first.result
        #expect(lane.occupiedForTesting && secondGate.starts == 0)
        firstGate.finish()
        let replacement = await until { secondGate.continuation != nil }
        try #require(replacement)
        secondGate.finish()
        #expect(try await second.value == 7)
    }

    @Test("Deadline is shared by joins; timeout remains occupied and rejects late success")
    func deadlineDoesNotFreeOccupiedSlot() async throws {
        let lane = EventReadFlight<Int, Int>(), gate = Gate()
        let first = request(lane, key: 1, gate: gate)
        defer { first.cancel(); lane.cancel(); gate.finish() }
        let began = await until { gate.continuation != nil }
        try #require(began)
        let second = request(lane, key: 1, gate: gate)
        defer { second.cancel() }
        let joined = await until { lane.waiterCountForTesting == 2 }
        try #require(joined)
        lane.expireForTesting() // Same production expiry branch; no wall-clock delay.
        for task in [first, second] {
            do { _ = try await task.value; Issue.record("timeout returned a value") }
            catch EventReadFlight<Int, Int>.Failure.deadlineExceeded {}
            catch { Issue.record("unexpected timeout type") }
        }
        #expect(lane.occupiedForTesting && gate.starts == 1)
        let replacement = request(lane, key: 2, gate: gate)
        do { _ = try await replacement.value; Issue.record("occupied timeout admitted replacement") }
        catch EventReadFlight<Int, Int>.Failure.deadlineExceeded {}
        catch { Issue.record("unexpected replacement type") }
        gate.finish(.success(99))
        let drained = await until { !lane.occupiedForTesting }
        #expect(drained && gate.starts == 1)
    }

    @Test("The scheduled deadline is created once and really cancels the owned backend")
    func scheduledDeadlineWiring() async throws {
        let delays = DeadlineGates(), backend = Gate()
        let lane = EventReadFlight<Int, Int>(waitForDeadline: { try await delays.wait() })
        let first = request(lane, key: 1, gate: backend)
        defer { first.cancel(); lane.cancel(); backend.finish(); delays.releaseAll() }
        let began = await until { backend.continuation != nil && delays.gates[0].continuation != nil }
        try #require(began)
        let joined = request(lane, key: 1, gate: backend)
        defer { joined.cancel() }
        let waiting = await until { lane.waiterCountForTesting == 2 }
        try #require(waiting)
        #expect(delays.calls == 1)
        delays.gates[0].finish() // Inject only the wait; exercise production timer Task + expiry.
        for task in [first, joined] {
            do { _ = try await task.value; Issue.record("scheduled deadline returned success") }
            catch EventReadFlight<Int, Int>.Failure.deadlineExceeded {}
            catch { Issue.record("unexpected scheduled deadline type") }
        }
        let cancelled = await until { backend.cancelled }
        #expect(cancelled && lane.occupiedForTesting && delays.calls == 1)
        backend.finish()
        let drained = await until { !lane.occupiedForTesting }
        #expect(drained)
    }

    @Test("Completion cancels its deadline; a late cancelled timer cannot expire a replacement")
    func completedDeadlineCannotTouchReplacement() async throws {
        let delays = DeadlineGates(), firstGate = Gate(), secondGate = Gate()
        let lane = EventReadFlight<Int, Int>(waitForDeadline: { try await delays.wait() })
        let first = request(lane, key: 1, gate: firstGate)
        defer { first.cancel(); lane.cancel(); firstGate.finish(); secondGate.finish(); delays.releaseAll() }
        let began = await until { firstGate.continuation != nil && delays.gates[0].continuation != nil }
        try #require(began)
        firstGate.finish()
        #expect(try await first.value == 7)
        let cancelled = await until { delays.gates[0].cancelled }
        try #require(cancelled)
        let second = request(lane, key: 2, gate: secondGate)
        defer { second.cancel() }
        let replacement = await until { secondGate.continuation != nil && delays.gates[1].continuation != nil }
        try #require(replacement)
        delays.gates[0].finish() // Noncooperative timer returns after its cancellation.
        let oldTimerReturned = await until { lane.completedDeadlineTasksForTesting == 1 }
        try #require(oldTimerReturned)
        #expect(lane.occupiedForTesting && !secondGate.cancelled && secondGate.continuation != nil)
        secondGate.finish(.success(22))
        #expect(try await second.value == 22)
        #expect(!secondGate.cancelled && delays.calls == 2)
    }

    @Test("Obsolete drain waiters never launch a replacement after source/query invalidation")
    func obsoleteWaitingRequestDoesNotStart() async throws {
        let lane = EventReadFlight<Int, Int>(), firstGate = Gate(), secondGate = Gate()
        var current = true
        let first = request(lane, key: 1, gate: firstGate)
        defer { first.cancel(); lane.cancel(); firstGate.finish(); secondGate.finish() }
        let began = await until { firstGate.continuation != nil }
        try #require(began)
        let second = request(lane, key: 2, gate: secondGate, current: { current })
        defer { second.cancel() }
        let waiting = await until { lane.waiterCountForTesting == 2 }
        try #require(waiting)
        current = false
        firstGate.finish()
        _ = await first.result
        do { _ = try await second.value; Issue.record("obsolete request succeeded") }
        catch is CancellationError {}
        #expect(secondGate.starts == 0)
    }

    @Test("Sixteen waiter bound is explicit failure; the original owner is preserved")
    func waiterBound() async throws {
        let lane = EventReadFlight<Int, Int>(), gate = Gate()
        let tasks = (0..<16).map { _ in request(lane, key: 1, gate: gate) }
        defer { for task in tasks { task.cancel() }; lane.cancel(); gate.finish() }
        let full = await until { lane.waiterCountForTesting == 16 && gate.continuation != nil }
        try #require(full)
        // Different-key drain requests must fail too, not spin/retry forever.
        let overflow = request(lane, key: 2, gate: gate)
        do { _ = try await overflow.value; Issue.record("overflow waiter succeeded") }
        catch EventReadFlight<Int, Int>.Failure.tooManyWaiters {}
        catch { Issue.record("unexpected overflow type") }
        #expect(gate.starts == 1 && lane.waiterCountForTesting == 16)
        gate.finish()
        for task in tasks { #expect(try await task.value == 7) }
    }

    @Test("Backend errors drain once; a subsequent request is genuinely executed")
    func failureThenRecovery() async throws {
        let lane = EventReadFlight<Int, Int>(), firstGate = Gate(), secondGate = Gate()
        let first = request(lane, key: 1, gate: firstGate)
        defer { first.cancel(); lane.cancel(); firstGate.finish(); secondGate.finish() }
        let began = await until { firstGate.continuation != nil }
        try #require(began)
        firstGate.finish(.failure(NSError(domain: "InertEventRead", code: 1)))
        do { _ = try await first.value; Issue.record("backend error hidden") }
        catch { #expect((error as NSError).domain == "InertEventRead") }
        let second = request(lane, key: 1, gate: secondGate)
        defer { second.cancel() }
        let replacement = await until { secondGate.continuation != nil }
        try #require(replacement)
        secondGate.finish()
        #expect(try await second.value == 7)
        #expect(firstGate.starts == 1 && secondGate.starts == 1)
    }
}
#endif
