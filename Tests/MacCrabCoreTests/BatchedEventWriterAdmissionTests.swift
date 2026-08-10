import Testing
import Foundation
import MacCrabCore
@testable import MacCrabAgentKit

/// Regression guard for the audit's systemic finding: there was NO free-space
/// check on any write path. `statvfs` appeared only in VACUUM preflights, so the
/// root daemon would write until the volume was 100% full — disk-full was
/// handled reactively, in the drain's permanent-error arm, i.e. after the damage.
@Suite("BatchedEventWriter: disk admission control")
struct BatchedEventWriterAdmissionTests {

    private func makeEvent(_ i: Int) -> Event {
        let proc = ProcessInfo(
            pid: Int32(4000 + i), ppid: 1, rpid: 1,
            name: "adm\(i)", executable: "/bin/adm\(i)",
            commandLine: "/bin/adm\(i)", args: [], workingDirectory: "/",
            userId: 501, userName: "t", groupId: 20,
            startTime: Date(timeIntervalSince1970: 1_700_000_000 + Double(i)), ancestors: [],
            isPlatformBinary: false)
        return Event(
            timestamp: Date(timeIntervalSince1970: 1_700_000_000 + Double(i)),
            eventCategory: .file, eventType: .creation, eventAction: "file",
            process: proc, file: FileInfo(path: "/tmp/adm/\(i).tmp", action: .write))
    }

    private actor CountingInserter: EventBatchInserting {
        private(set) var inserted = 0
        func insert(
            events: [Event],
            lane _: EventPipelineLane
        ) throws -> EventBatchInsertResult {
            inserted += events.count
            return EventBatchInsertResult(
                inputCount: events.count,
                persistedCount: events.count,
                filteredCount: 0,
                committedTransactionCount: events.isEmpty ? 0 : 1
            )
        }
        var total: Int { inserted }
    }

    @Test("below the free-space floor, persistence is paused and the batch is shed")
    func blocksBelowFloor() async {
        let sink = CountingInserter()
        // A floor larger than any real volume guarantees the breach.
        let w = BatchedEventWriter(
            store: sink, flushThreshold: 4, hardCap: 100,
            volumePath: FileManager.default.temporaryDirectory.path,
            freeSpaceFloorMB: Int.max / 2)

        for i in 0..<8 { await w.enqueue(makeEvent(i)) }
        await w.shutdown()

        #expect(await sink.total == 0, "no event may be persisted while below the floor")
        #expect(w.droppedCount >= 8, "shed events must be counted as drops, not lost silently")
    }

    @Test("with no volume configured the admission check is inert — nothing is blocked")
    func noVolumeMeansNoBlocking() async {
        let sink = CountingInserter()
        let w = BatchedEventWriter(store: sink, flushThreshold: 4, hardCap: 100)

        for i in 0..<8 { await w.enqueue(makeEvent(i)) }
        await w.shutdown()

        #expect(await sink.total == 8)
        #expect(w.droppedCount == 0)
    }

    @Test("a FAILED free-space probe allows the write — telemetry must not stop on a stat glitch")
    func failedProbeFailsOpen() async {
        let sink = CountingInserter()
        // freeDiskMB returns 0 for an unstattable path. 0 must mean "probe
        // failed, allow" — not "no space, block" — otherwise a transient stat
        // error silences the entire engine.
        let w = BatchedEventWriter(
            store: sink, flushThreshold: 4, hardCap: 100,
            volumePath: "/nonexistent-volume-\(UUID().uuidString)",
            freeSpaceFloorMB: 1024)

        for i in 0..<8 { await w.enqueue(makeEvent(i)) }
        await w.shutdown()

        #expect(await sink.total == 8, "a failed probe must fail OPEN, not block ingestion")
    }

    @Test("a generous floor on a healthy volume does not block")
    func healthyVolumePasses() async {
        let sink = CountingInserter()
        let w = BatchedEventWriter(
            store: sink, flushThreshold: 4, hardCap: 100,
            volumePath: FileManager.default.temporaryDirectory.path,
            freeSpaceFloorMB: 1)

        for i in 0..<8 { await w.enqueue(makeEvent(i)) }
        await w.shutdown()

        #expect(await sink.total == 8)
    }
}
