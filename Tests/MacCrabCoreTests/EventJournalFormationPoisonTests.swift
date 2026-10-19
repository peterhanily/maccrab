import Foundation
import Testing
@testable import MacCrabCore

/// Real-store journal formation with interleaved exact and poisoned members,
/// in-call duplicates, a reserve boundary that forces several transactions,
/// and an immutable-identity conflict. Each input ordinal must keep its exact
/// disposition while the running poison count replaces the prefix recount.
@Suite("Event journal formation with mixed poison", .serialized)
struct EventJournalFormationPoisonTests {
    private func makeStore(reserve: Int64) async throws -> (EventStore, URL) {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("journal-formation-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        let store = try EventStore(
            path: directory.appendingPathComponent("events.db").path,
            storagePolicy: SQLitePersistentStorePolicy(
                maxFootprintBytes: 512 * 1_048_576, freeSpaceFloorBytes: 0,
                transactionReserveBytes: reserve,
                storageVolumePath: directory.path
            ),
            liveMemoryBudget: EventPipelineLiveMemoryBudget.isolatedProductionEquivalentForTesting()
        )
        try #require(try await store.recoverJournalBeforeProducers().complete)
        return (store, directory)
    }

    private func event(_ index: Int, args: [String] = ["ordinary"], padding: Int = 0) -> Event {
        let timestamp = Date().addingTimeInterval(-30 + Double(index) / 1_000)
        var enrichments: [String: String] = [:]
        if padding > 0 { enrichments["fixture_padding"] = String(repeating: "p", count: padding) }
        return Event(
            id: UUID(uuidString: String(format: "00000000-0000-4000-8000-%012x", index + 1))!,
            timestamp: timestamp, eventCategory: .file, eventType: .change, eventAction: "write",
            process: MacCrabCore.ProcessInfo(
                pid: Int32(2_000 + index), ppid: 1, rpid: 1, name: "formation-fixture",
                executable: "/usr/local/bin/formation-fixture",
                commandLine: "formation-fixture " + args.joined(separator: " ").prefix(16), args: args,
                workingDirectory: "/private/tmp", userId: 501, userName: "fixture", groupId: 20,
                startTime: timestamp, ancestors: [], isPlatformBinary: false
            ),
            file: FileInfo(path: "/private/tmp/formation-\(index).txt", action: .write),
            enrichments: enrichments
        )
    }

    /// One argument above the 8-MiB structural string ceiling: a compact,
    /// durably poisoned journal marker replaces the source.
    private func poisoned(_ index: Int) throws -> EventJournalIngressPreparation {
        let prepared = try EventJournalAdmissionValidator.prepare(
            event(index, args: [String(repeating: "S", count: 8 * 1_048_576 + 1)])
        )
        try #require(prepared.overflow != nil)
        return prepared
    }

    private func expected(_ prepared: EventJournalIngressPreparation) -> EventJournalInsertDisposition {
        prepared.overflow.map { .poisoned($0) } ?? .durable(eventID: prepared.event.id)
    }

    @Test("interleaved poison and in-call duplicates keep every ordinal's disposition")
    func interleavedDispositions() async throws {
        let (store, directory) = try await makeStore(
            reserve: SQLitePersistentStorePolicy.eventTransactionReserveBytes
        )
        defer { try? FileManager.default.removeItem(at: directory) }
        let o = try (0..<6).map { try EventJournalAdmissionValidator.prepare(event($0)) }
        let p = try (100..<103).map { try poisoned($0) }
        let batch = [o[0], p[0], o[1], o[1], p[0], o[2], p[1], o[3], p[2], o[4], p[1], o[5], o[0]]
        let result = try await store.insert(preparedEvents: batch, lane: .file)
        #expect(result.inputDispositions == batch.map(expected))
        #expect(result.persistedCount == batch.filter { $0.overflow == nil }.count)
        #expect(result.committedTransactionCount == 1)
        #expect(try await store.payloadPoisonTotalSnapshot() == 3)
        let snapshot = try await store.exactEventsSnapshot(since: .distantPast, limit: 100)
        #expect(Set(snapshot.events.map(\.id)) == Set(o.map(\.event.id)))
        #expect(Set(snapshot.poisonRecords.map(\.eventID)) == Set(p.map(\.event.id)))
    }

    @Test("a reserve boundary splits mixed formation into several exact transactions")
    func reserveBoundarySplits() async throws {
        let (store, directory) = try await makeStore(reserve: 24 * 1_048_576)
        defer { try? FileManager.default.removeItem(at: directory) }
        var batch: [EventJournalIngressPreparation] = []
        for index in 0..<24 {
            batch.append(try EventJournalAdmissionValidator.prepare(event(index, padding: 512 * 1_024)))
            if index % 6 == 5 { batch.append(try poisoned(200 + index)) }
        }
        batch.append(batch[3])
        let result = try await store.insert(preparedEvents: batch, lane: .file)
        #expect(result.inputDispositions == batch.map(expected))
        #expect(result.committedTransactionCount > 1)
        #expect(result.committedTransactionCount < batch.count)
        #expect(try await store.payloadPoisonTotalSnapshot() == 4)
        let snapshot = try await store.exactEventsSnapshot(since: .distantPast, limit: 100)
        #expect(snapshot.events.count == 24)
    }

    @Test("one UUID with two contents in a call is an immutable conflict")
    func immutableConflictInCall() async throws {
        let (store, directory) = try await makeStore(
            reserve: SQLitePersistentStorePolicy.eventTransactionReserveBytes
        )
        defer { try? FileManager.default.removeItem(at: directory) }
        let first = try EventJournalAdmissionValidator.prepare(event(7))
        let conflicting = try EventJournalAdmissionValidator.prepare(event(7, padding: 32))
        try #require(first.event.id == conflicting.event.id)
        do {
            _ = try await store.insert(preparedEvents: [first, try poisoned(300), conflicting], lane: .file)
            Issue.record("conflicting contents for one UUID must not both commit")
        } catch let failure as EventBatchInsertFailure {
            guard case EventStoreError.immutableEventConflict(let id) = failure.underlyingError else {
                Issue.record("unexpected underlying error \(failure.underlyingError)")
                return
            }
            #expect(id == first.event.id)
            #expect(failure.progress.persistedCount == 0)
        }
    }
}

/// White-box parity for the running poison count: replay formation with the
/// original per-candidate prefix recount against the store's real charge, at
/// a reserve chosen so ignoring poison would split the batch differently.
@Suite("Event journal formation poison-count parity", .serialized)
struct EventJournalFormationPoisonCountParityTests {
    private func makeStore(reserve: Int64) async throws -> (EventStore, URL) {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("journal-poison-count-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        let store = try EventStore(
            path: directory.appendingPathComponent("events.db").path,
            storagePolicy: SQLitePersistentStorePolicy(
                maxFootprintBytes: 512 * 1_048_576, freeSpaceFloorBytes: 0,
                transactionReserveBytes: reserve,
                storageVolumePath: directory.path
            ),
            liveMemoryBudget: EventPipelineLiveMemoryBudget.isolatedProductionEquivalentForTesting()
        )
        try #require(try await store.recoverJournalBeforeProducers().complete)
        return (store, directory)
    }

    private func event(_ index: Int, args: [String], padding: Int) -> Event {
        let timestamp = Date().addingTimeInterval(-30 + Double(index) / 1_000)
        return Event(
            id: UUID(uuidString: String(format: "00000000-0000-4000-9000-%012x", index + 1))!,
            timestamp: timestamp, eventCategory: .file, eventType: .change, eventAction: "write",
            process: MacCrabCore.ProcessInfo(
                pid: Int32(3_000 + index), ppid: 1, rpid: 1, name: "formation-count",
                executable: "/usr/local/bin/formation-count", commandLine: "formation-count", args: args,
                workingDirectory: "/private/tmp", userId: 501, userName: "fixture", groupId: 20,
                startTime: timestamp, ancestors: [], isPlatformBinary: false
            ),
            file: FileInfo(path: "/private/tmp/count-\(index).txt", action: .write),
            enrichments: padding > 0 ? ["fixture_padding": String(repeating: "c", count: padding)] : [:]
        )
    }

    private enum PoisonCounting { case prefixRecount, candidateOnly, ignored }

    /// Original chunking with the quadratic recount kept verbatim; returns
    /// the number of transactions (no duplicates or split requests here).
    /// The other two modes model plausible regressions of the running count.
    private func replay(
        _ batch: [EventJournalIngressPreparation],
        reserve: Int64,
        counting: PoisonCounting,
        store: EventStore
    ) async -> Int {
        var committedRows = 0, transactions = 0
        while committedRows < batch.count {
            var sourceCount = 0, framedBytes = 12
            var preparedUnique: [EventJournalIngressPreparation] = []
            while committedRows + sourceCount < batch.count,
                  sourceCount < EventJournalCodec.maximumEventsPerBlock {
                let prepared = batch[committedRows + sourceCount]
                let nextBytes = framedBytes + 4 + prepared.canonicalJSON.count
                let own = prepared.overflow == nil ? 0 : 1
                let poison: Int
                switch counting {
                case .prefixRecount:
                    poison = preparedUnique.reduce(into: 0) { count, item in
                        if item.overflow != nil { count += 1 }
                    } + own
                case .candidateOnly: poison = own
                case .ignored: poison = 0
                }
                let estimate = await store.journalBlockTransactionEstimate(
                    payloadBytes: nextBytes,
                    eventCount: preparedUnique.count + 1,
                    poisonCount: poison
                )
                if !preparedUnique.isEmpty, estimate > reserve { break }
                framedBytes = nextBytes
                sourceCount += 1
                preparedUnique.append(prepared)
            }
            transactions += 1
            committedRows += sourceCount
        }
        return transactions
    }

    @Test("the running count reproduces the original recount at a poison-sensitive reserve")
    func runningCountMatchesRecount() async throws {
        let (probe, probeDirectory) = try await makeStore(
            reserve: SQLitePersistentStorePolicy.eventTransactionReserveBytes
        )
        defer { try? FileManager.default.removeItem(at: probeDirectory) }
        var batch: [EventJournalIngressPreparation] = []
        for index in 0..<48 {
            batch.append(try EventJournalAdmissionValidator.prepare(
                event(index, args: ["ordinary"], padding: 512 * 1_024)
            ))
            if index % 3 == 2 {
                // Above the element ceiling: a compact poisoned marker.
                let prepared = try EventJournalAdmissionValidator.prepare(event(
                    1_000 + index,
                    args: Array(repeating: "", count: EventJournalAdmissionValidator.maximumPreflightElements + 1),
                    padding: 0
                ))
                try #require(prepared.overflow != nil)
                batch.append(prepared)
            }
        }
        let single = await probe.journalBlockTransactionEstimate(
            payloadBytes: 16 + batch.map(\.canonicalJSON.count).max()!,
            eventCount: 1, poisonCount: 1
        )
        var chosen: (reserve: Int64, transactions: Int)?
        // Once poison exists the store also protects one full terminal
        // settlement, so search well above that headroom.
        var reserve = max(single, 24 * 1_048_576)
        while chosen == nil, reserve < 64 * 1_048_576 {
            let counted = await replay(batch, reserve: reserve, counting: .prefixRecount, store: probe)
            let candidateOnly = await replay(batch, reserve: reserve, counting: .candidateOnly, store: probe)
            let ignored = await replay(batch, reserve: reserve, counting: .ignored, store: probe)
            // Sensitive to the prefix's poison, not merely the candidate's own.
            if counted != candidateOnly, counted != ignored { chosen = (reserve, counted) }
            reserve += 4 * 1_024
        }
        let sensitive = try #require(chosen, "no reserve distinguishes the prefix poison count")
        let (store, directory) = try await makeStore(reserve: sensitive.reserve)
        defer { try? FileManager.default.removeItem(at: directory) }
        let result = try await store.insert(preparedEvents: batch, lane: .file)
        #expect(result.committedTransactionCount == sensitive.transactions)
        #expect(result.inputDispositions == batch.map {
            $0.overflow.map { .poisoned($0) } ?? .durable(eventID: $0.event.id)
        })
    }
}
