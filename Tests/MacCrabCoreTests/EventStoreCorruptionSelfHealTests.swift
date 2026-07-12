// EventStoreCorruptionSelfHealTests.swift
//
// C-04: mid-run SQLITE_CORRUPT self-heal. Init-time recovery already handles a
// store that is corrupt at open; this covers a store that corrupts while the
// daemon is live. The self-heal closes the connection, quarantines the corrupt
// files aside (shared CorruptDBBackup naming), and reopens a fresh DB — bounded
// (max attempts) and rate-limited (min interval) so a failing device can't
// thrash.

import Testing
import Foundation
import CSQLCipher
@testable import MacCrabCore

@Suite("C-04: EventStore mid-run corruption self-heal")
struct EventStoreCorruptionSelfHealTests {

    private func makeTempStore() async throws -> (EventStore, URL) {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-selfheal-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        let store = try EventStore(directory: tmp.path)
        return (store, tmp)
    }

    private func insertSample(_ store: EventStore, count: Int) async throws {
        let base = Date()
        for i in 0..<count {
            let proc = ProcessInfo(
                pid: Int32(1000 + i), ppid: 1, rpid: 1,
                name: "sample\(i)", executable: "/bin/sample\(i)",
                commandLine: "/bin/sample\(i)", args: [],
                workingDirectory: "/",
                userId: 501, userName: "t", groupId: 20,
                startTime: base,
                ancestors: [],
                isPlatformBinary: false
            )
            let ev = Event(
                timestamp: base.addingTimeInterval(Double(i)),
                eventCategory: .process, eventType: .start,
                eventAction: "exec", process: proc
            )
            try await store.insert(event: ev)
        }
    }

    @Test("corruption result codes are classified, transient codes are not")
    func classifiesCorruptionCodes() {
        #expect(EventStore.isCorruptionResultCode(SQLITE_CORRUPT))
        #expect(EventStore.isCorruptionResultCode(SQLITE_NOTADB))
        // Extended corrupt codes share the low byte with the primary code
        // (e.g. SQLITE_CORRUPT_VTAB == SQLITE_CORRUPT | (1 << 8)).
        #expect(EventStore.isCorruptionResultCode(SQLITE_CORRUPT | Int32(1 << 8)))
        // Transient / non-corruption codes must NOT trigger a reopen.
        #expect(!EventStore.isCorruptionResultCode(SQLITE_FULL))
        #expect(!EventStore.isCorruptionResultCode(SQLITE_BUSY))
        #expect(!EventStore.isCorruptionResultCode(SQLITE_DONE))
    }

    @Test("a simulated mid-run corruption triggers exactly one bounded reopen")
    func oneBoundedReopen() async throws {
        let (store, tmp) = try await makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        try await insertSample(store, count: 5)
        #expect(try await store.count() == 5)

        let healed = await store.attemptCorruptionSelfHeal(reason: "simulated SQLITE_CORRUPT")
        #expect(healed == true)

        // The corrupt DB was quarantined aside using the shared naming scheme,
        // so the init-time prune bounds these backups too.
        let entries = (try? FileManager.default.contentsOfDirectory(atPath: tmp.path)) ?? []
        #expect(entries.contains { $0.hasPrefix("events.db") && $0.contains(".corrupt-") })

        // Reopened onto a fresh DB and it's usable again — ingestion recovered
        // instead of failing forever.
        #expect(try await store.count() == 0)
        try await insertSample(store, count: 1)
        #expect(try await store.count() == 1)
    }

    @Test("self-heal is rate-limited within the cooldown and capped over the lifetime")
    func rateLimitedAndCapped() async throws {
        let (store, tmp) = try await makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }
        try await insertSample(store, count: 1)

        let t0 = Date()
        // Attempt #1 at t0 heals.
        #expect(await store.attemptCorruptionSelfHeal(reason: "c1", now: t0) == true)
        // A second attempt 10 s later is inside the 5-minute cooldown → refused.
        #expect(await store.attemptCorruptionSelfHeal(reason: "c2", now: t0.addingTimeInterval(10)) == false)
        // Past the cooldown, attempts #2 and #3 go through...
        #expect(await store.attemptCorruptionSelfHeal(reason: "c3", now: t0.addingTimeInterval(400)) == true)
        #expect(await store.attemptCorruptionSelfHeal(reason: "c4", now: t0.addingTimeInterval(800)) == true)
        // ...but the 4th distinct attempt is refused by the lifetime cap (3).
        #expect(await store.attemptCorruptionSelfHeal(reason: "c5", now: t0.addingTimeInterval(1200)) == false)
    }
}
