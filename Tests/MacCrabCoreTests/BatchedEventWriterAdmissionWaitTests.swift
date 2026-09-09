import Foundation
import Testing
@testable import MacCrabAgentKit
@testable import MacCrabCore

@Suite("Bounded journal admission notifications", .serialized)
struct BatchedEventWriterAdmissionWaitTests {
    private actor Store: EventBatchInserting {
        private var blockedCalls: Set<Int>
        private var gates: [Int: CheckedContinuation<Void, Never>] = [:]
        private let busyCalls: Set<Int>
        private let filteredIDs: Set<UUID>
        private(set) var calls = 0
        private(set) var persistedIDs: [UUID] = []

        init(
            blockedCalls: Set<Int> = [1],
            busyCalls: Set<Int> = [],
            filteredIDs: Set<UUID> = []
        ) {
            self.blockedCalls = blockedCalls
            self.busyCalls = busyCalls
            self.filteredIDs = filteredIDs
        }

        func insert(
            events: [Event],
            lane _: EventPipelineLane
        ) async throws -> EventBatchInsertResult {
            calls += 1
            let call = calls
            if blockedCalls.contains(call) {
                await withCheckedContinuation { gates[call] = $0 }
            }
            if busyCalls.contains(call) {
                throw EventStoreError.busy("owned admission-wait fixture")
            }
            let durable = events.filter { !filteredIDs.contains($0.id) }
            persistedIDs.append(contentsOf: durable.map(\.id))
            return EventBatchInsertResult(
                inputCount: events.count,
                persistedCount: durable.count,
                filteredCount: events.count - durable.count,
                committedTransactionCount: 1,
                inputDispositions: events.map {
                    filteredIDs.contains($0.id)
                        ? .filtered(eventID: $0.id) : .durable(eventID: $0.id)
                }
            )
        }

        func release(_ call: Int) {
            blockedCalls.remove(call)
            gates.removeValue(forKey: call)?.resume()
        }

        func releaseAll() {
            blockedCalls.removeAll()
            let pending = gates.values
            gates.removeAll()
            for gate in pending { gate.resume() }
        }
    }

    private func event(_ index: Int) -> Event {
        let timestamp = Date(timeIntervalSince1970: 1_780_000_000 + Double(index))
        return Event(
            timestamp: timestamp,
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: ProcessInfo(
                pid: Int32(5_000 + index), ppid: 1, rpid: 1,
                name: "fixture", executable: "/usr/bin/true",
                commandLine: "/usr/bin/true", args: [],
                workingDirectory: "/", userId: 501, userName: "fixture",
                groupId: 20, startTime: timestamp, ancestors: [],
                isPlatformBinary: false
            )
        )
    }

    private func writer(
        _ store: Store,
        historyCapacity: Int = 100,
        waiterCapacity: Int = 256
    ) -> BatchedEventWriter {
        BatchedEventWriter(
            store: store,
            flushThreshold: 10_000,
            hardCap: 100,
            admissionResolutionCapacity: historyCapacity,
            admissionWaiterCapacity: waiterCapacity,
            liveMemoryBudget: .isolatedProductionEquivalentForTesting()
        )
    }

    private func enqueue(
        _ event: Event,
        into writer: BatchedEventWriter,
        lane: EventPipelineLane = .priority
    ) async throws -> EventJournalAdmission {
        try #require(await writer.enqueuePrepared(
            EventJournalAdmissionValidator.prepare(event),
            lane: lane
        ))
    }

    private func eventually(
        _ predicate: () async -> Bool
    ) async throws {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(2))
        while !(await predicate()) {
            try #require(clock.now < deadline, "fixture synchronization timed out")
            try await Task.sleep(for: .milliseconds(1))
        }
    }

    @Test("one cancelled receipt waiter cannot cancel a shared durable drain")
    func cancellationIsPerWaiter() async throws {
        let store = Store()
        defer { Task { await store.releaseAll() } }
        let writer = writer(store)
        let receipt = try await enqueue(event(1), into: writer)
        let first = Task { await writer.awaitJournalAdmission(receipt) }
        let second = Task { await writer.awaitJournalAdmission(receipt) }
        try await eventually { await writer.admissionWaiterCountForTesting() == 2 }
        first.cancel()
        #expect(await first.value == .timedOut)
        #expect(await writer.admissionWaiterCountForTesting() == 1)
        await store.releaseAll()
        #expect(await second.value == .verified)
        #expect(await store.persistedIDs == [receipt.eventID])
        #expect(await writer.admissionWaiterCountForTesting() == 0)
        #expect(writer.droppedCount == 0)
        await writer.shutdown()
    }

    @Test("a cancelled caller cannot register later or start an abandoned drain")
    func cancellationBeforeRegistration() async throws {
        let store = Store(blockedCalls: [])
        let writer = writer(store)
        let receipt = try await enqueue(event(2), into: writer)
        let waiter = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return await writer.awaitJournalAdmission(receipt)
        }
        #expect(await waiter.value == .timedOut)
        #expect(await writer.admissionWaiterCountForTesting() == 0)
        #expect(await store.calls == 0)
        await writer.shutdown()
        #expect(await store.persistedIDs == [receipt.eventID])
    }

    @Test("a deadline removes the waiter while a late commit stays available")
    func deadlineDoesNotCancelStorage() async throws {
        let store = Store()
        defer { Task { await store.releaseAll() } }
        let writer = writer(store)
        let receipt = try await enqueue(event(3), into: writer)
        #expect(await writer.awaitJournalAdmission(
            receipt, timeout: .milliseconds(30)
        ) == .timedOut)
        #expect(await writer.admissionWaiterCountForTesting() == 0)
        let later = Task { await writer.awaitJournalAdmission(receipt) }
        try await eventually { await writer.admissionWaiterCountForTesting() == 1 }
        await store.releaseAll()
        #expect(await later.value == .verified)
        #expect(await store.calls == 1)
        #expect(writer.droppedCount == 0)
        await writer.shutdown()
    }

    @Test("transient retries notify the original receipt without a flush timer")
    func retryWithoutTimer() async throws {
        let store = Store(busyCalls: [1, 2])
        defer { Task { await store.releaseAll() } }
        let writer = writer(store)
        let receipt = try await enqueue(event(4), into: writer)
        let waiter = Task { await writer.awaitJournalAdmission(receipt) }
        try await eventually { await writer.admissionWaiterCountForTesting() == 1 }
        await store.releaseAll()
        #expect(await waiter.value == .verified)
        #expect(await store.calls == 3)
        #expect(await store.persistedIDs == [receipt.eventID])
        #expect(writer.retriedCount == 2)
        #expect(writer.droppedCount == 0)
        #expect(await writer.admissionWaiterCountForTesting() == 0)
        await writer.shutdown()
    }

    @Test("exact notification survives same-batch receipt history trimming")
    func trimmedHistoryKeepsResolvedValue() async throws {
        let store = Store()
        defer { Task { await store.releaseAll() } }
        let writer = writer(store, historyCapacity: 1)
        let first = try await enqueue(event(5), into: writer)
        let second = try await enqueue(event(6), into: writer)
        _ = try await enqueue(event(7), into: writer)
        // Public scalar receipts have no repair handle to hide a lost wakeup
        // by re-verifying storage after the bounded history has been trimmed.
        let scalar = EventJournalAdmission(
            eventID: first.eventID, generation: first.generation,
            canonicalSHA256: first.canonicalSHA256,
            canonicalByteCount: first.canonicalByteCount
        )
        let firstWait = Task { await writer.awaitJournalAdmission(scalar) }
        let secondWait = Task { await writer.awaitJournalAdmission(second) }
        try await eventually { await writer.admissionWaiterCountForTesting() == 2 }
        await store.releaseAll()
        #expect(await firstWait.value == .verified)
        #expect(await secondWait.value == .verified)
        #expect(await writer.awaitJournalAdmission(scalar) == .mismatchedReceipt)
        #expect(await store.calls == 1)
        await writer.shutdown()
    }

    @Test("a later priority receipt cannot advance an unfinished file prefix")
    func prefixRemainsContiguousAcrossLanes() async throws {
        let store = Store(blockedCalls: [1, 2])
        defer { Task { await store.releaseAll() } }
        let writer = writer(store)
        let file = try await enqueue(event(8), into: writer, lane: .file)
        let priority = try await enqueue(event(9), into: writer)
        let exact = Task { await writer.awaitJournalAdmission(priority) }
        let prefix = Task {
            await writer.awaitEvidencePrefix(through: priority.generation)
        }
        try await eventually { await writer.admissionWaiterCountForTesting() == 2 }
        await store.release(1)
        #expect(await exact.value == .verified)
        try await eventually { await store.calls == 2 }
        #expect(await writer.admissionWaiterCountForTesting() == 1)
        #expect((await writer.telemetrySnapshot()).terminalGeneration == 0)
        await store.releaseAll()
        #expect(await prefix.value)
        #expect(await store.persistedIDs == [priority.eventID, file.eventID])
        #expect(await writer.admissionWaiterCountForTesting() == 0)
        await writer.shutdown()
    }

    @Test("registration saturation retains bounded polling and exact outcomes")
    func capacityFallbackDoesNotShed() async throws {
        let store = Store()
        defer { Task { await store.releaseAll() } }
        let writer = writer(store, waiterCapacity: 1)
        let receipt = try await enqueue(event(10), into: writer)
        let first = Task { await writer.awaitJournalAdmission(receipt) }
        try await eventually { await writer.admissionWaiterCountForTesting() == 1 }
        #expect(await writer.awaitJournalAdmission(
            receipt, timeout: .milliseconds(30)
        ) == .timedOut)
        #expect(await writer.admissionWaiterCountForTesting() == 1)
        await store.releaseAll()
        #expect(await first.value == .verified)
        #expect(await writer.awaitJournalAdmission(receipt) == .verified)
        #expect(await store.calls == 1)
        #expect(writer.droppedCount == 0)
        #expect(await writer.admissionWaiterCountForTesting() == 0)
        await writer.shutdown()
    }

    @Test("notifications preserve filtered status and reject a forged receipt")
    func exactStatusAndIdentity() async throws {
        let value = event(11)
        let store = Store(filteredIDs: [value.id])
        defer { Task { await store.releaseAll() } }
        let writer = writer(store)
        let receipt = try await enqueue(value, into: writer)
        let forged = EventJournalAdmission(
            eventID: UUID(), generation: receipt.generation,
            canonicalSHA256: receipt.canonicalSHA256,
            canonicalByteCount: receipt.canonicalByteCount
        )
        #expect(await writer.awaitJournalAdmission(forged) == .mismatchedReceipt)
        let waiter = Task { await writer.awaitJournalAdmission(receipt) }
        try await eventually { await writer.admissionWaiterCountForTesting() == 1 }
        await store.releaseAll()
        #expect(await waiter.value == .filtered)
        #expect(await writer.awaitEvidencePrefix(through: receipt.generation))
        #expect(await store.persistedIDs.isEmpty)
        #expect(writer.droppedCount == 0)
        await writer.shutdown()
    }
}
