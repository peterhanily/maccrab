// WALReadMarkTests.swift
//
// v1.21.6-rc.41. Every dashboard read used to run full journal verification
// (SHA256 + double JSON-decode of every retained block) while holding a WAL
// read-mark — first inside an explicit BEGIN DEFERRED, and, one layer deeper,
// inside the implicit transaction that lasts for a scan statement's whole
// stepping lifetime. Two dashboard connections on 5s/60s cadences left the
// writer no reader-free window: the WAL grew to 2-5x its 64 MiB limit
// (147.5 MiB and 353 MiB measured live), pushed the db+WAL family through the
// 320 MiB cap, silently dropped ~14k events in 80 minutes, and once prevented
// the engine from booting. Twice proven live: the moment the dashboard process
// died, the next checkpoint truncated.
//
// The fix: verification is hoisted outside the read transaction
// (withVerifiedExactReadSnapshot) and the journal scan is chunked so no single
// statement — and therefore no implicit transaction — spans the heavy work.
// The hook below reports, per verified batch, whether the connection is inside
// a SQLite transaction. The contract this file pins: it never is.

import Testing
import Foundation
import CSQLCipher
@testable import MacCrabCore

@Suite("rc.41 WAL read-mark boundedness", .serialized)
struct WALReadMarkTests {

    private func makeEvent(_ i: Int) -> Event {
        let proc = MacCrabCore.ProcessInfo(
            pid: Int32(7000 + i), ppid: 1, rpid: 1,
            name: "walmark\(i)", executable: "/usr/bin/walmark\(i)",
            commandLine: "/usr/bin/walmark\(i)", args: [],
            workingDirectory: "/",
            userId: 501, userName: "t", groupId: 20,
            startTime: Date(timeIntervalSince1970: 1_700_000_000 + Double(i)),
            ancestors: [],
            isPlatformBinary: false
        )
        return Event(
            timestamp: Date(timeIntervalSince1970: 1_700_000_000 + Double(i)),
            eventCategory: .process, eventType: .start,
            eventAction: "exec", process: proc
        )
    }

    private final class StateBox: @unchecked Sendable {
        private let lock = NSLock()
        private var states: [Bool] = []
        func record(_ inTransaction: Bool) {
            lock.lock(); states.append(inTransaction); lock.unlock()
        }
        var snapshot: [Bool] {
            lock.lock(); defer { lock.unlock() }; return states
        }
    }

    @Test("Journal verification never runs inside a SQLite transaction")
    func verificationRunsOutsideTransactions() async throws {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-walmark-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: dir, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: dir) }

        // Build a store with real journal blocks, then release it so the next
        // open is COLD — the case that used to verify the whole journal inside
        // one transaction for minutes on an installed host.
        do {
            let writer = try EventStore(directory: dir.path)
            for i in 0..<40 {
                try await writer.insert(event: makeEvent(i))
            }
        }

        let reader = try EventStore(directory: dir.path, forceReadOnly: true)
        let box = StateBox()
        await reader.setJournalIndexRebuildHookForTesting { inTransaction in
            box.record(inTransaction)
        }

        // A dashboard-shaped read on the cold store forces the full rebuild.
        _ = try await reader.searchSnapshot(text: "walmark", limit: 10)

        let states = box.snapshot
        #expect(
            !states.isEmpty,
            "the cold read must have rebuilt the journal index (hook never fired)"
        )
        #expect(
            states.allSatisfy { $0 == false },
            "journal verification ran INSIDE a transaction — the WAL read-mark pin is back: \(states)"
        )
    }

    @Test("Retiring a cold reader cancels verification and preserves writer progress")
    func retireDuringVerification() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-read-retirement-\(UUID())")
        defer { try? FileManager.default.removeItem(at: dir) }
        let writer = try EventStore(directory: dir.path)
        for i in 0..<40 { try await writer.insert(event: makeEvent(i)) }
        let reader = try EventStore(directory: dir.path, forceReadOnly: true)
        let box = StateBox()
        await reader.setJournalIndexRebuildHookForTesting { inTransaction in
            box.record(inTransaction)
            reader.retireReadOnlyReads()
        }
        do {
            _ = try await reader.searchSnapshot(text: "walmark", limit: 40)
            Issue.record("The retired reader completed its cold exact read")
        } catch is CancellationError { }
        #expect(!box.snapshot.isEmpty)
        #expect(box.snapshot.allSatisfy { !$0 })
        #expect(await writer.walCheckpointTruncate())
        // Retirement is permanent for this handle, even after partial rebuild.
        do {
            _ = try await reader.exactEventsSnapshot(since: .distantPast, limit: 40)
            Issue.record("Retired reader accepted another query")
        } catch is CancellationError { }
        let fresh = try EventStore(directory: dir.path, forceReadOnly: true)
        let snapshot = try await fresh.exactEventsSnapshot(since: .distantPast, limit: 40)
        #expect(snapshot.isComplete)
        #expect(snapshot.events.count == 40)
        // The public retirement entry point cannot cancel the writer actor.
        writer.retireReadOnlyReads()
        try await writer.insert(event: makeEvent(40))
        #expect(try await writer.exactEventsSnapshot(since: .distantPast, limit: 50).events.count == 41)
    }
}
