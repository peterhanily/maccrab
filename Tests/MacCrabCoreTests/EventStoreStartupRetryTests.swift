import CSQLCipher
import Foundation
import Testing
@testable import MacCrabCore
@testable import MacCrabAgentKit

@Suite("EventStore startup monotonic retry grace")
struct EventStoreStartupRetryTests {
    private final class Clock: @unchecked Sendable {
        private let lock = NSLock()
        private var instant = ContinuousClock.now
        private var recordedSleeps: [Duration] = []

        func now() -> ContinuousClock.Instant {
            lock.lock(); defer { lock.unlock() }
            return instant
        }
        func advance(_ duration: Duration) {
            lock.lock(); defer { lock.unlock() }
            instant = instant.advanced(by: duration)
        }
        func sleep(_ duration: Duration) async throws {
            try Task.checkCancellation()
            recordSleep(duration)
        }
        private func recordSleep(_ duration: Duration) {
            lock.lock(); defer { lock.unlock() }
            recordedSleeps.append(duration)
            instant = instant.advanced(by: duration)
        }
        var sleeps: [Duration] {
            lock.lock(); defer { lock.unlock() }
            return recordedSleeps
        }
    }

    @Test("Slow initial preparation does not consume the later contention grace")
    func slowPreparationThenSuccess() async throws {
        let clock = Clock()
        var attempts = 0
        var observations: [EventStoreStartupRetryObservation] = []
        let value: Int = try await retryTransientEventStoreStartupOperation(
            retryDelayNanoseconds: 500_000_000,
            monotonicNow: clock.now, sleep: clock.sleep,
            onObservation: { observations.append($0) }, operation: {
                attempts += 1
                if attempts == 1 {
                    clock.advance(.seconds(54))
                    throw EventStoreError.busy("ordinary checkpoint contention")
                }
                return 42
            })
        #expect(value == 42)
        #expect(attempts == 2)
        #expect(clock.sleeps == [.milliseconds(500)])
        let result = try #require(observations.last)
        #expect(result.outcome == "completed")
        #expect(result.initialAttemptDuration == .seconds(54))
        #expect(result.retryElapsed == .milliseconds(500))
        #expect(result.totalElapsed == .milliseconds(54_500))
    }

    @Test("Retry sleep is capped to remaining grace and no attempt starts at its deadline")
    func graceDeadline() async throws {
        let clock = Clock()
        var attempts = 0
        var observations: [EventStoreStartupRetryObservation] = []
        do {
            let _: Int = try await retryTransientEventStoreStartupOperation(
                maximumAttempts: 1000, retryDelayNanoseconds: 5_200_000_000,
                monotonicNow: clock.now, sleep: clock.sleep,
                onObservation: { observations.append($0) }, operation: {
                    attempts += 1
                    throw EventStoreError.busy("ordinary checkpoint contention")
                })
            Issue.record("persistent contention was accepted")
        } catch let error as EventStoreError {
            guard case .busy = error else { throw error }
        }
        #expect(attempts == 1)
        #expect(clock.sleeps == [.seconds(5)])
        let last = try #require(observations.last)
        #expect(last.outcome == "grace_exhausted")
        #expect(last.retryElapsed == .seconds(5))
    }

    @Test("A finite attempt limit still bounds retries when no elapsed time advances")
    func attemptLimit() async throws {
        let clock = Clock()
        var attempts = 0
        var observations: [EventStoreStartupRetryObservation] = []
        do {
            let _: Int = try await retryTransientEventStoreStartupOperation(
                maximumAttempts: 3, retryDelayNanoseconds: 0,
                monotonicNow: clock.now, sleep: clock.sleep,
                onObservation: { observations.append($0) }, operation: {
                    attempts += 1
                    throw EventStoreError.busy("ordinary checkpoint contention")
                })
            Issue.record("attempt limit was ignored")
        } catch let error as EventStoreError {
            guard case .busy = error else { throw error }
        }
        #expect(attempts == 3)
        #expect(clock.sleeps.isEmpty)
        #expect(observations.last?.outcome == "attempts_exhausted")
    }

    @Test("A completed in-flight operation is retained and its deadline overrun remains measured")
    func inFlightCompletionCost() async throws {
        let clock = Clock()
        var attempts = 0
        var observations: [EventStoreStartupRetryObservation] = []
        let value: Int = try await retryTransientEventStoreStartupOperation(
            retryDelayNanoseconds: 0, monotonicNow: clock.now, sleep: clock.sleep,
            onObservation: { observations.append($0) }, operation: {
                attempts += 1
                if attempts == 1 { throw EventStoreError.busy("ordinary checkpoint contention") }
                clock.advance(.seconds(6))
                return 9
            })
        #expect(value == 9)
        #expect(attempts == 2)
        #expect(observations.last?.retryElapsed == .seconds(6))
        #expect(observations.last?.latestAttemptDuration == .seconds(6))
    }

    @Test("Memory credit keeps its bounded retry path and distinct diagnostic cause")
    func memoryCreditRetry() async throws {
        let clock = Clock()
        var attempts = 0
        var observations: [EventStoreStartupRetryObservation] = []
        let _: Int = try await retryTransientEventStoreStartupOperation(
            retryDelayNanoseconds: 0, monotonicNow: clock.now, sleep: clock.sleep,
            onObservation: { observations.append($0) }, operation: {
                attempts += 1
                if attempts == 1 { throw EventStoreError.memoryLeaseUnavailable("ordinary credit shortage") }
                return 1
            })
        #expect(attempts == 2)
        #expect(observations.first?.retryCause == "memory_credit")
    }

    @Test("Admission and non-contention errors escape unchanged without retry")
    func nonretryableErrors() async throws {
        let admission = SQLitePersistentStoreAdmissionError.lowFreeSpace(
            freeBytes: 1, floorBytes: 10, reserveBytes: 20, requiredFreeBytes: 30)
        let io = EventStoreError.sqliteFailure(context: "ordinary checkpoint", message: "IO unavailable",
            resultCode: SQLITE_IOERR, extendedResultCode: SQLITE_IOERR, systemErrno: EIO)
        let integrity = EventStoreError.decodingFailed("ordinary integrity failure")
        for expected in [admission as any Error, io, integrity] {
            let clock = Clock()
            var attempts = 0
            do {
                let _: Int = try await retryTransientEventStoreStartupOperation(
                    monotonicNow: clock.now, sleep: clock.sleep,
                    onObservation: { _ in }, operation: {
                        attempts += 1
                        throw expected
                    })
                Issue.record("nonretryable error was accepted")
            } catch {
                #expect(String(reflecting: type(of: error)) == String(reflecting: type(of: expected)))
                #expect(error.localizedDescription == expected.localizedDescription)
                #expect(SQLiteFailureClassifier.details(from: error) == SQLiteFailureClassifier.details(from: expected))
            }
            #expect(attempts == 1)
            #expect(clock.sleeps.isEmpty)
        }
    }

    @Test("Cancellation during retry grace starts no subsequent operation")
    func cancellationDuringGrace() async throws {
        let task = Task { () async throws -> Int in
            let clock = Clock()
            var attempts = 0
            defer { #expect(attempts == 1) }
            return try await retryTransientEventStoreStartupOperation(
                monotonicNow: clock.now, sleep: clock.sleep,
                onRetry: { _ in withUnsafeCurrentTask { $0?.cancel() } },
                onObservation: { _ in }, operation: {
                    attempts += 1
                    throw EventStoreError.busy("ordinary checkpoint contention")
                })
        }
        do {
            _ = try await task.value
            Issue.record("cancelled startup retry unexpectedly completed")
        } catch is CancellationError { }
    }
}
