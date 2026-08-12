// EventStorePayloadCapTests.swift
//
// rc.13 stores the privacy-sanitized canonical Event losslessly in the exact
// journal through the journal admission ceiling. The historical 64-KiB limit
// now applies only to the sparse compatibility/search projection.

import Testing
import Foundation
import CSQLCipher
@testable import MacCrabCore

@Suite("EventStore: exact journal and bounded sparse payload")
struct EventStorePayloadCapTests {

    private enum TestError: Error {
        case sqlite(String)
        case missingProjection
    }

    private func makeTempStore() throws -> (EventStore, URL) {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(
                "maccrab-payloadcap-\(UUID().uuidString)",
                isDirectory: true
            )
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        return (try EventStore(directory: directory.path), directory)
    }

    private func makeEvent(
        args: [String],
        commandLine: String? = nil,
        enrichments: [String: String] = [:]
    ) -> Event {
        let timestamp = Date(timeIntervalSince1970: 1_700_000_000)
        return Event(
            timestamp: timestamp,
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: ProcessInfo(
                pid: 1234,
                ppid: 1,
                rpid: 1,
                name: "payloadcap-test",
                executable: "/usr/local/bin/payloadcap-test",
                commandLine: commandLine ?? args.joined(separator: " "),
                args: args,
                workingDirectory: "/",
                userId: 501,
                userName: "tester",
                groupId: 20,
                startTime: timestamp,
                ancestors: [],
                isPlatformBinary: false
            ),
            enrichments: enrichments
        )
    }

    private func fetchOnlyExact(
        _ store: EventStore
    ) async throws -> ExactEventQuerySnapshot {
        let snapshot = try await store.exactEventsSnapshot(
            since: .distantPast,
            limit: 10
        )
        #expect(snapshot.events.count == 1)
        #expect(snapshot.isComplete)
        return snapshot
    }

    private func fetchOnlyProjection(
        in directory: URL
    ) throws -> (event: Event, rawBytes: Int) {
        let path = directory.appendingPathComponent("events.db").path
        var db: OpaquePointer?
        guard sqlite3_open_v2(
            path,
            &db,
            SQLITE_OPEN_READONLY,
            nil
        ) == SQLITE_OK, let db else {
            throw TestError.sqlite("open projection")
        }
        defer { sqlite3_close(db) }

        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(
            db,
            "SELECT raw_json FROM events ORDER BY rowid",
            -1,
            &statement,
            nil
        ) == SQLITE_OK, let statement else {
            throw TestError.sqlite("prepare projection")
        }
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else {
            throw TestError.missingProjection
        }
        let count = Int(sqlite3_column_bytes(statement, 0))
        guard count > 0, let bytes = sqlite3_column_blob(statement, 0) else {
            throw TestError.missingProjection
        }
        let data = Data(bytes: bytes, count: count)
        let event = try JSONDecoder().decode(Event.self, from: data)
        guard sqlite3_step(statement) == SQLITE_DONE else {
            throw TestError.sqlite("projection cardinality")
        }
        return (event, count)
    }

    private func projectionRowCount(in directory: URL) throws -> Int {
        let path = directory.appendingPathComponent("events.db").path
        var db: OpaquePointer?
        guard sqlite3_open_v2(
            path,
            &db,
            SQLITE_OPEN_READONLY,
            nil
        ) == SQLITE_OK, let db else {
            throw TestError.sqlite("open projection count")
        }
        defer { sqlite3_close(db) }
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(
            db,
            "SELECT COUNT(*) FROM events",
            -1,
            &statement,
            nil
        ) == SQLITE_OK, let statement else {
            throw TestError.sqlite("prepare projection count")
        }
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else {
            throw TestError.sqlite("read projection count")
        }
        return Int(sqlite3_column_int64(statement, 0))
    }

    @Test("64 KiB is projection-only; exact journal uses the canonical ceiling")
    func contractCeilings() {
        #expect(EventStore.maxRawJsonBytes == 65_536)
        #expect(
            EventJournalAdmissionValidator.maximumCanonicalRecordBytes
                == 12 * 1_024 * 1_024
        )
        #expect(
            EventJournalAdmissionValidator.maximumAcceptedSourceRetainedBytes
                == 24 * 1_024 * 1_024
        )
    }

    @Test("small canonical event is exact and projection-equivalent")
    func smallEventRoundTripsUnchanged() async throws {
        let (store, directory) = try makeTempStore()
        defer { try? FileManager.default.removeItem(at: directory) }
        let args = ["payloadcap-test", "--safe", "value"]
        let event = makeEvent(args: args)

        try await store.insert(event: event)

        let exact = try await fetchOnlyExact(store)
        #expect(exact.events[0].process.args == args)
        #expect(exact.events[0].enrichments["payload.truncated"] == nil)
        let projection = try fetchOnlyProjection(in: directory)
        #expect(projection.event.process.args == args)
        #expect(projection.event.enrichments["payload.truncated"] == nil)
        #expect(projection.rawBytes <= EventStore.maxRawJsonBytes)
        #expect(try await store.payloadPoisonTotalSnapshot() == 0)
    }

    @Test("200 KiB fields stay exact while sparse projection is bounded and marked")
    func largeFieldsAreExactAndProjectionIsBounded() async throws {
        let (store, directory) = try makeTempStore()
        defer { try? FileManager.default.removeItem(at: directory) }
        let largeArg = String(repeating: "A", count: 200_000)
        let largeEvidence = String(repeating: "E", count: 200_000)
        let event = makeEvent(
            args: ["/usr/bin/python3", "-c", largeArg],
            commandLine: "python3 -c payload",
            enrichments: ["agent_evidence_json": largeEvidence]
        )

        try await store.insert(event: event)

        let exact = try await fetchOnlyExact(store)
        #expect(exact.events[0].process.args[2] == largeArg)
        #expect(
            exact.events[0].enrichments["agent_evidence_json"]
                == largeEvidence
        )
        #expect(exact.events[0].enrichments["payload.truncated"] == nil)

        let projection = try fetchOnlyProjection(in: directory)
        #expect(projection.rawBytes <= EventStore.maxRawJsonBytes)
        #expect(
            projection.event.process.args[2]
                == "<truncated:200000 bytes>"
        )
        #expect(
            projection.event.enrichments["agent_evidence_json"]
                == "<truncated:200000 bytes>"
        )
        #expect(projection.event.enrichments["payload.truncated"] == "true")
        #expect(try await store.payloadPoisonTotalSnapshot() == 0)
    }

    @Test("canonical ceiling overflow is durably poisoned and idempotent")
    func canonicalOverflowIsDurablePoison() async throws {
        let (store, directory) = try makeTempStore()
        defer { try? FileManager.default.removeItem(at: directory) }

        // Each field remains below the 8-MiB structural string ceiling and the
        // raw graph remains below 24 MiB. Only the canonical JSON crosses the
        // true 12-MiB journal record ceiling.
        let chunkBytes =
            EventJournalAdmissionValidator.maximumCanonicalRecordBytes / 2
                + 32 * 1_024
        let event = makeEvent(
            args: [
                String(repeating: "P", count: chunkBytes),
                String(repeating: "Q", count: chunkBytes),
            ],
            commandLine: "payloadcap canonical overflow"
        )
        let preflight = try EventJournalAdmissionValidator.preflight(event)
        #expect(!preflight.structurallyOverflowed)
        let prepared = try EventJournalAdmissionValidator.prepare(
            event,
            preflight: preflight
        )
        #expect(prepared.overflow?.digestKind == .canonicalJSON)
        #expect(
            prepared.overflow?.originalBytes ?? 0
                > EventJournalAdmissionValidator.maximumCanonicalRecordBytes
        )

        let first = try await store.insert(
            preparedEvents: [prepared],
            lane: .priority
        )
        #expect(first.persistedCount == 0)
        #expect(
            first.inputDispositions
                == [.poisoned(prepared.overflow!)]
        )
        #expect(try await store.payloadPoisonTotalSnapshot() == 1)
        #expect(try projectionRowCount(in: directory) == 0)

        let snapshot = try await store.exactEventsSnapshot(
            since: .distantPast,
            limit: 10
        )
        #expect(snapshot.events.isEmpty)
        #expect(snapshot.poisonRecords.count == 1)
        #expect(snapshot.poisonRecords[0].eventID == event.id)
        #expect(snapshot.poisonRecords[0].digestKind == .canonicalJSON)
        #expect(!snapshot.isComplete)

        let retry = try await store.insert(
            preparedEvents: [prepared],
            lane: .priority
        )
        #expect(retry.persistedCount == 0)
        #expect(
            retry.inputDispositions
                == [.poisoned(prepared.overflow!)]
        )
        #expect(try await store.payloadPoisonTotalSnapshot() == 1)
    }
}
