import Foundation
import Testing
@testable import MacCrabCore

@Suite("Async journal admission scopes")
struct EventJournalAdmissionContextTests {
    private struct Values: Sendable, Equatable {
        var admission: EventJournalAdmission?
        var terminal: EventJournalTerminalAdmission?
        var forced: EventJournalContextStatus?

        static let empty = Values()

        static func current() -> Values {
            Values(
                admission: EventJournalAdmissionContext.current,
                terminal: EventJournalAdmissionContext.terminalRevision,
                forced: EventJournalAdmissionContext.forcedNonverifiedStatus
            )
        }
    }

    private actor Probe {
        func read() -> Values { Values.current() }
    }

    private actor Gate {
        private var entered = false
        private var released = false
        private var enterWaiters: [CheckedContinuation<Void, Never>] = []
        private var releaseWaiters: [CheckedContinuation<Void, Never>] = []

        func wait() async {
            entered = true
            let waiters = enterWaiters
            enterWaiters.removeAll()
            for waiter in waiters { waiter.resume() }
            guard !released else { return }
            await withCheckedContinuation { releaseWaiters.append($0) }
        }

        func waitUntilEntered() async {
            guard !entered else { return }
            await withCheckedContinuation { enterWaiters.append($0) }
        }

        func release() {
            released = true
            let waiters = releaseWaiters
            releaseWaiters.removeAll()
            for waiter in waiters { waiter.resume() }
        }
    }

    private func fixture() -> Values {
        let admission = EventJournalAdmission(
            eventID: UUID(), generation: 7,
            canonicalSHA256: Data(repeating: 0x31, count: 32),
            canonicalByteCount: 123
        )
        return Values(
            admission: admission,
            terminal: EventJournalTerminalAdmission(
                eventID: admission.eventID,
                baseGeneration: admission.generation,
                baseCanonicalSHA256: admission.canonicalSHA256,
                terminalCanonicalSHA256: Data(repeating: 0x32, count: 32),
                terminalCanonicalByteCount: 145,
                status: .verified,
                storageMutationGeneration: 8
            ),
            forced: .poisoned
        )
    }

    private func withValues<Result>(
        _ values: Values,
        isolation: isolated (any Actor)? = #isolation,
        operation: () async throws -> Result
    ) async rethrows -> Result {
        try await EventJournalAdmissionContext.withAdmission(
            values.admission, isolation: isolation
        ) {
            try await EventJournalAdmissionContext.withTerminalRevision(
                values.terminal, isolation: isolation
            ) {
                try await EventJournalAdmissionContext
                    .withForcedNonverifiedStatus(
                        values.forced, isolation: isolation,
                        operation: operation
                    )
            }
        }
    }

    @Test("nested nil bindings restore all values after asynchronous suspension")
    func nestedNilRestoration() async {
        let expected = fixture()
        let probe = Probe()
        #expect(Values.current() == .empty)
        await withValues(expected) {
            #expect(await probe.read() == expected)
            await withValues(.empty) {
                await Task.yield()
                #expect(await probe.read() == .empty)
            }
            #expect(await probe.read() == expected)
        }
        #expect(Values.current() == .empty)
    }

    @Test("ordinary children inherit bindings beyond scope exit; detached tasks do not")
    func inheritedChildOutlivesScope() async {
        let expected = fixture()
        let gate = Gate()
        let probe = Probe()
        let child = await withValues(expected) {
            #expect(await Task.detached { Values.current() }.value == .empty)
            return Task {
                await gate.wait()
                return await probe.read()
            }
        }
        await gate.waitUntilEntered()
        #expect(Values.current() == .empty)
        await gate.release()
        #expect(await child.value == expected)
    }

    @Test("throwing out of an inner binding restores the outer journal context")
    func throwingRestoration() async {
        enum ExpectedError: Error { case stop }
        let expected = fixture()
        let probe = Probe()
        await withValues(expected) {
            do {
                try await withValues(.empty) {
                    await Task.yield()
                    #expect(await probe.read() == .empty)
                    throw ExpectedError.stop
                }
                Issue.record("the scoped operation did not propagate its error")
            } catch ExpectedError.stop {
                #expect(await probe.read() == expected)
            } catch {
                Issue.record("unexpected scoped error: \(error)")
            }
        }
        #expect(Values.current() == .empty)
    }

    @Test("cancellation reaches the same task and restores enclosing bindings")
    func cancellationRestoration() async {
        let expected = fixture()
        let gate = Gate()
        let probe = Probe()
        let operation = Task {
            await withValues(expected) {
                do {
                    try await withValues(.empty) {
                        await gate.wait()
                        #expect(await probe.read() == .empty)
                        try Task.checkCancellation()
                    }
                    Issue.record("scope lost the caller's cancellation")
                } catch is CancellationError {
                    #expect(Task.isCancelled)
                    #expect(await probe.read() == expected)
                } catch {
                    Issue.record("unexpected cancellation error: \(error)")
                }
            }
            return Values.current()
        }
        await gate.waitUntilEntered()
        operation.cancel()
        await gate.release()
        #expect(await operation.value == .empty)
        #expect(Values.current() == .empty)
    }

    @Test("async value scopes preserve shared source and patch lease ownership")
    func inheritedLeaseOwnership() async throws {
        let budget = EventPipelineLiveMemoryBudget(maximumBytes: 1_024)
        let gate = Gate()
        let expected = fixture()
        var child: Task<Values, Never>? = try await makeLeaseHoldingChild(
            budget: budget, gate: gate, values: expected
        )
        await gate.waitUntilEntered()
        #expect(budget.snapshot().currentBytes == 1_000)
        #expect(budget.snapshot().activeLeases == 2)
        #expect(budget.snapshot().leasesConserved)
        #expect(EventJournalAdmissionContext.sourceMemoryLease == nil)
        #expect(EventJournalAdmissionContext.deferredPatchMemoryLeases.isEmpty)
        await gate.release()
        #expect(await child?.value == expected)
        child = nil
        // Task completion may hand off cleanup after delivering its result.
        // Yield a bounded number of times; never use timing to arrange ownership.
        for _ in 0..<2_000 {
            if budget.snapshot().activeLeases == 0 { break }
            await Task.yield()
        }
        #expect(budget.snapshot().currentBytes == 0)
        #expect(budget.snapshot().activeLeases == 0)
        #expect(budget.snapshot().leasesConserved)
    }

    private func makeLeaseHoldingChild(
        budget: EventPipelineLiveMemoryBudget,
        gate: Gate,
        values: Values
    ) async throws -> Task<Values, Never> {
        let source = try #require(
            budget.tryAcquire(bytes: 700, owner: .eventSource)
        )
        let patch = try #require(
            budget.tryAcquire(bytes: 300, owner: .deferredPatch)
        )
        return await EventJournalAdmissionContext.$sourceMemoryLease.withValue(
            source
        ) {
            await EventJournalAdmissionContext.$deferredPatchMemoryLeases
                .withValue([patch]) {
                    await withValues(values) {
                        Task {
                            await gate.wait()
                            #expect(EventJournalAdmissionContext
                                .sourceMemoryLease?.bytes == 700)
                            #expect(EventJournalAdmissionContext
                                .deferredPatchMemoryLeases.map(\.bytes) == [300])
                            return Values.current()
                        }
                    }
                }
        }
    }

    @MainActor
    @Test("async scopes preserve the caller's actor isolation")
    func callerIsolation() async {
        let expected = fixture()
        await withValues(expected) {
            MainActor.preconditionIsolated()
            await Task.yield()
            MainActor.preconditionIsolated()
            #expect(Values.current() == expected)
        }
        #expect(Values.current() == .empty)
    }
}
