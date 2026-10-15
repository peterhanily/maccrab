import Foundation
import Testing
@testable import MacCrabCore

/// Inert, task-owned SQLite data through the real journal admission/read paths.
/// "Cold" means a fresh EventStore index, not a flushed filesystem cache. These
/// timings describe Core reads only, not SwiftUI first content or a release SLA.
@Suite("Events cold/warm authenticated read cost", .serialized)
struct EventsColdWarmReadTests {
    private static let eventCount = 10_000
    private static let pageSize = 500
    private static let epoch = Date(timeIntervalSince1970: 1_700_000_000)

    private final class VerificationStates: @unchecked Sendable {
        private let lock = NSLock()
        private var values: [Bool] = []

        func record(_ inTransaction: Bool) {
            lock.lock()
            defer { lock.unlock() }
            values.append(inTransaction)
        }

        var snapshot: [Bool] {
            lock.lock()
            defer { lock.unlock() }
            return values
        }
    }

    private func event(_ index: Int) -> Event {
        let value = UInt32(index)
        let id = UUID(uuid: (0, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0,
            UInt8(truncatingIfNeeded: value >> 24), UInt8(truncatingIfNeeded: value >> 16),
            UInt8(truncatingIfNeeded: value >> 8), UInt8(truncatingIfNeeded: value)))
        // Equal-time pairs exercise the UUID tie-breaker as well as chronology.
        let timestamp = Self.epoch.addingTimeInterval(Double(index / 2))
        let process = MacCrabCore.ProcessInfo(
            pid: 42, ppid: 1, rpid: 42, name: "ordinary-fixture",
            executable: "/usr/bin/true", commandLine: "/usr/bin/true", args: [],
            workingDirectory: "/private/tmp", userId: 501, userName: "fixture",
            groupId: 20, startTime: Self.epoch, ancestors: [], isPlatformBinary: false
        )
        return Event(id: id, timestamp: timestamp, eventCategory: .process,
            eventType: .start, eventAction: "exec", process: process)
    }

    private func expectPage(_ snapshot: ExactEventQuerySnapshot) {
        let expected = (Self.eventCount - Self.pageSize..<Self.eventCount)
            .reversed().map { event($0) }
        #expect(snapshot.isComplete)
        #expect(snapshot.events.map(\.id) == expected.map(\.id))
        #expect(snapshot.events.map(\.timestamp) == expected.map(\.timestamp))
        #expect(snapshot.events.allSatisfy { $0.eventCategory == .process })
    }

    /// Interrupt the currently executing read at its ordinary, pre-verification
    /// batch boundary. This does not alter journal bytes or bypass validation.
    private func interruptedRead(_ reader: EventStore, retire: Bool) async throws {
        let states = VerificationStates()
        await reader.setJournalIndexRebuildHookForTesting { inTransaction in
            states.record(inTransaction)
            if retire {
                reader.retireReadOnlyReads()
            } else {
                withUnsafeCurrentTask { $0?.cancel() }
            }
        }
        // Cancel this child only; the test must remain able to check recovery.
        let operation = Task {
            _ = try await reader.exactEventsSnapshot(
                since: Self.epoch, category: .process, limit: Self.pageSize)
        }
        let result = await operation.result
        // In particular, release the hook's reader capture after retirement.
        await reader.setJournalIndexRebuildHookForTesting(nil)
        #expect(!states.snapshot.isEmpty)
        #expect(states.snapshot.allSatisfy { !$0 })
        switch result {
        case .success:
            Issue.record("An interrupted cold reader returned a successful page")
        case .failure(let error):
            guard error is CancellationError else { throw error }
        }
    }

    @Test("10k retained events preserve exact newest pages, cancellation and reader retirement")
    func coldWarmAndInterruptedReaders() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-events-cold-warm-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let writerBudget = EventPipelineLiveMemoryBudget.isolatedProductionEquivalentForTesting()
        let writer = try EventStore(directory: directory.path, liveMemoryBudget: writerBudget)
        let setupStarted = DispatchTime.now().uptimeNanoseconds
        // Bounded production batches, not 10k singleton commits or raw SQL.
        for start in stride(from: 0, to: Self.eventCount, by: 200) {
            let batch = (start..<min(start + 200, Self.eventCount)).map { event($0) }
            let inserted = try await writer.insert(events: batch, lane: .priority)
            try #require(inserted.persistedCount == batch.count)
            try #require(inserted.filteredCount == 0)
        }
        try #require(try await writer.count() == Self.eventCount)
        try #require(await writer.walCheckpointTruncate())
        let setupNanoseconds = DispatchTime.now().uptimeNanoseconds - setupStarted
        #expect(writerBudget.snapshot().currentBytes == 0)
        #expect(writerBudget.snapshot().leasesConserved)

        let budget = EventPipelineLiveMemoryBudget.isolatedProductionEquivalentForTesting()
        let openStarted = DispatchTime.now().uptimeNanoseconds
        let reader = try EventStore(directory: directory.path, forceReadOnly: true,
            liveMemoryBudget: budget)
        let openNanoseconds = DispatchTime.now().uptimeNanoseconds - openStarted
        defer { reader.retireReadOnlyReads() }
        let states = VerificationStates()
        await reader.setJournalIndexRebuildHookForTesting { states.record($0) }
        let before = await reader.journalIndexRefreshDiagnostics()
        let decodesBefore = await reader.journalBaseBlockDecodesForTesting
        let coldStarted = DispatchTime.now().uptimeNanoseconds
        var cold: ExactEventQuerySnapshot? = try await reader.exactEventsSnapshot(
            since: Self.epoch, category: .process, limit: Self.pageSize)
        let coldNanoseconds = DispatchTime.now().uptimeNanoseconds - coldStarted
        expectPage(try #require(cold))
        let generation = try #require(cold).mutationGeneration
        let coldDiagnostics = await reader.journalIndexRefreshDiagnostics()
        let decodesAfterCold = await reader.journalBaseBlockDecodesForTesting
        #expect(coldDiagnostics.fullRebuilds == before.fullRebuilds + 1)
        #expect(coldDiagnostics.stagesComplete)
        #expect(!states.snapshot.isEmpty)
        #expect(states.snapshot.allSatisfy { !$0 })
        #expect(budget.snapshot().currentBytes > 0)
        cold = nil
        #expect(budget.snapshot().currentBytes == 0)
        #expect(budget.snapshot().leasesConserved)

        let warmStarted = DispatchTime.now().uptimeNanoseconds
        var warm: ExactEventQuerySnapshot? = try await reader.exactEventsSnapshot(
            since: Self.epoch, category: .process, limit: Self.pageSize)
        let warmNanoseconds = DispatchTime.now().uptimeNanoseconds - warmStarted
        expectPage(try #require(warm))
        #expect(warm?.mutationGeneration == generation)
        let warmDiagnostics = await reader.journalIndexRefreshDiagnostics()
        let decodesAfterWarm = await reader.journalBaseBlockDecodesForTesting
        #expect(warmDiagnostics.fullRebuilds == coldDiagnostics.fullRebuilds)
        #expect(warmDiagnostics.appendRefreshes == coldDiagnostics.appendRefreshes)
        #expect(decodesAfterWarm - decodesAfterCold < decodesAfterCold - decodesBefore)
        warm = nil
        #expect(budget.snapshot().currentBytes == 0)
        #expect(budget.snapshot().leasesConserved)
        await reader.setJournalIndexRebuildHookForTesting(nil)
        reader.retireReadOnlyReads()

        print("events_cold_warm_diagnostic events=\(Self.eventCount) page=\(Self.pageSize) "
            + "setup_ns=\(setupNanoseconds) open_ns=\(openNanoseconds) "
            + "cold_page_ns=\(coldNanoseconds) warm_page_ns=\(warmNanoseconds) "
            + "cold_index_ns=\(coldDiagnostics.lastNanoseconds) "
            + "warm_index_ns=\(warmDiagnostics.lastNanoseconds) "
            + "cold_base_decodes=\(decodesAfterCold - decodesBefore) "
            + "warm_base_decodes=\(decodesAfterWarm - decodesAfterCold)")
        for stage in coldDiagnostics.stagesNanoseconds.keys.sorted() {
            print("events_cold_index_stage name=\(stage) ns=\(coldDiagnostics.stagesNanoseconds[stage]!)")
        }

        let cancelled = try EventStore(directory: directory.path, forceReadOnly: true,
            liveMemoryBudget: budget)
        defer { cancelled.retireReadOnlyReads() }
        try await interruptedRead(cancelled, retire: false)
        #expect(budget.snapshot().currentBytes == 0)
        #expect(await writer.walCheckpointTruncate())
        // Task cancellation is not a permanent store retirement. An ordinary
        // caller can rebuild the discarded partial index and read exactly.
        expectPage(try await cancelled.exactEventsSnapshot(
            since: Self.epoch, category: .process, limit: Self.pageSize))
        #expect(budget.snapshot().currentBytes == 0)
        cancelled.retireReadOnlyReads()

        let retired = try EventStore(directory: directory.path, forceReadOnly: true,
            liveMemoryBudget: budget)
        try await interruptedRead(retired, retire: true)
        #expect(budget.snapshot().currentBytes == 0)
        #expect(budget.snapshot().leasesConserved)
        #expect(await writer.walCheckpointTruncate())
        do {
            _ = try await retired.exactEventsSnapshot(since: Self.epoch, limit: Self.pageSize)
            Issue.record("A permanently retired reader accepted another query")
        } catch is CancellationError { }
        // Retirement/cancellation must not mutate, expire or lose the corpus.
        #expect(try await writer.count() == Self.eventCount)
    }
}
