import Foundation
import Darwin
import CryptoKit
import Testing
@testable import MacCrabCore

@Suite("Bounded streaming event journal codec")
struct EventJournalCodecTests {
    private struct Fixture: Codable, Equatable, Sendable {
        let id: Int
        let text: String
        let tags: [String]
    }

    private func encoded(_ values: [Fixture]) throws -> [Data] {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try values.map(encoder.encode)
    }

    private func payloadData(
        _ payload: PreparedEventJournalPayload
    ) -> Data {
        var result = Data()
        result.reserveCapacity(payload.storedBytes)
        payload.forEachFragment { result.append($0) }
        return result
    }

    private func reader(_ data: Data) -> EventJournalCodec.PayloadChunkReader {
        { offset, destination in
            guard offset >= 0,
                  offset <= data.count - destination.count else { return 0 }
            guard destination.count > 0 else { return 0 }
            _ = data.withUnsafeBytes { source in
                memcpy(
                    destination.baseAddress!,
                    source.baseAddress!.advanced(by: offset),
                    destination.count
                )
            }
            return destination.count
        }
    }

    private func roundTrip(
        _ block: PreparedEventJournalBlock,
        payload: Data,
        budget: EventPipelineLiveMemoryBudget
    ) throws -> [Fixture] {
        var decoded: [Fixture] = []
        let count = try EventJournalCodec.decodeRecordsStreaming(
            codec: block.codec,
            rawBytes: block.rawBytes,
            expectedDigest: block.digest,
            payloadBytes: payload.count,
            expectedRecordCount: block.eventCount,
            workspaceLease: block.workspaceLease,
            reader: reader(payload),
            recordLeaseProvider: { _, _ in
                budget.tryAcquire(
                    bytes: EventJournalAdmissionValidator
                        .maximumPreparationWorkspaceBytes,
                    owner: .journalPrepared
                )
            },
            as: Fixture.self
        ) { owned in
            decoded.append(owned.value)
        }
        #expect(count == decoded.count)
        return decoded
    }

    @Test("compresses and decodes without a raw block allocation")
    func compressedRoundTrip() throws {
        let values = (0..<16).map {
            Fixture(
                id: $0,
                text: String(repeating: "repeatable-evidence-\($0)-", count: 2_000),
                tags: ["journal", "streaming", "journal"]
            )
        }
        let records = try encoded(values)
        let budget = EventPipelineLiveMemoryBudget(
            maximumBytes: 96 * 1_024 * 1_024,
            forwardProgressReserveBytes: 48 * 1_024 * 1_024,
            eventStoreWorkspaceReserveBytes:
                EventJournalCodec.maximumWorkspaceBytes
        )
        let workspace = try #require(budget.tryAcquire(
            bytes: EventJournalCodec.maximumWorkspaceBytes,
            owner: .eventStoreWorkspace
        ))
        let block = try EventJournalCodec.prepare(
            jsonRecords: records,
            workspaceLease: workspace
        )
        #expect(block.codec == EventJournalCodec.lzfseCodec)
        #expect(block.payload.storedBytes < block.rawBytes)
        #expect(block.digest.count == 32)

        let payload = payloadData(block.payload)
        #expect(try roundTrip(block, payload: payload, budget: budget) == values)
        let snapshot = budget.snapshot()
        #expect(snapshot.withinCapacity)
        #expect(snapshot.leasesConserved)
        #expect(snapshot.bytesByOwner[
            EventPipelineMemoryOwner.eventStoreWorkspace.rawValue
        ] == EventJournalCodec.maximumWorkspaceBytes)
    }

    @Test("raw fallback reuses canonical fragments when S output is unavailable")
    func rawFragmentFallback() throws {
        let values = [
            Fixture(id: 1, text: "raw-fragment", tags: ["a", "b"]),
            Fixture(id: 2, text: "second", tags: [])
        ]
        let records = try encoded(values)
        let budget = EventPipelineLiveMemoryBudget(
            maximumBytes: 96 * 1_024 * 1_024,
            forwardProgressReserveBytes: 48 * 1_024 * 1_024,
            eventStoreWorkspaceReserveBytes:
                EventJournalCodec.maximumWorkspaceBytes
        )
        let workspace = try #require(budget.tryAcquire(
            bytes: EventJournalCodec.maximumWorkspaceBytes,
            owner: .eventStoreWorkspace
        ))
        let block = try EventJournalCodec.prepare(
            jsonRecords: records,
            workspaceLease: workspace,
            workspaceRetainedInputBytes:
                EventJournalCodec.maximumWorkspaceBytes
        )
        #expect(block.codec == EventJournalCodec.rawCodec)
        guard case .rawFragments(let fragments, let rawBytes) = block.payload else {
            Issue.record("expected raw-fragment payload")
            return
        }
        #expect(fragments.count == 1 + records.count * 2)
        #expect(rawBytes == block.rawBytes)
        let payload = payloadData(block.payload)
        #expect(payload.count == rawBytes)
        #expect(Data(SHA256.hash(data: payload)) == block.digest)
        #expect(try roundTrip(block, payload: payload, budget: budget) == values)
    }

    @Test("decode rejects unowned record allocation before JSON decoding")
    func recordOwnershipIsMandatory() throws {
        let values = [Fixture(id: 7, text: "owned", tags: [])]
        let budget = EventPipelineLiveMemoryBudget(
            maximumBytes: 96 * 1_024 * 1_024,
            forwardProgressReserveBytes: 48 * 1_024 * 1_024,
            eventStoreWorkspaceReserveBytes:
                EventJournalCodec.maximumWorkspaceBytes
        )
        let workspace = try #require(budget.tryAcquire(
            bytes: EventJournalCodec.maximumWorkspaceBytes,
            owner: .eventStoreWorkspace
        ))
        let block = try EventJournalCodec.prepare(
            jsonRecords: try encoded(values),
            workspaceLease: workspace
        )
        let payload = payloadData(block.payload)
        #expect(throws: EventJournalCodecError.recordWorkspaceUnavailable(0)) {
            _ = try EventJournalCodec.decodeRecordsStreaming(
                codec: block.codec,
                rawBytes: block.rawBytes,
                expectedDigest: block.digest,
                payloadBytes: payload.count,
                expectedRecordCount: block.eventCount,
                workspaceLease: workspace,
                reader: reader(payload),
                recordLeaseProvider: { _, _ in nil },
                as: Fixture.self,
                consume: { _ in }
            )
        }
    }

    @Test("short reads and compressed trailing bytes fail closed")
    func exactPayloadFraming() throws {
        let values = [Fixture(
            id: 9,
            text: String(repeating: "compress-me", count: 20_000),
            tags: []
        )]
        let budget = EventPipelineLiveMemoryBudget(
            maximumBytes: 96 * 1_024 * 1_024,
            forwardProgressReserveBytes: 48 * 1_024 * 1_024,
            eventStoreWorkspaceReserveBytes:
                EventJournalCodec.maximumWorkspaceBytes
        )
        let workspace = try #require(budget.tryAcquire(
            bytes: EventJournalCodec.maximumWorkspaceBytes,
            owner: .eventStoreWorkspace
        ))
        let block = try EventJournalCodec.prepare(
            jsonRecords: try encoded(values),
            workspaceLease: workspace
        )
        #expect(block.codec == EventJournalCodec.lzfseCodec)
        var payload = payloadData(block.payload)
        payload.append(0)

        #expect(throws: EventJournalCodecError.self) {
            _ = try EventJournalCodec.decodeRecordsStreaming(
                codec: block.codec,
                rawBytes: block.rawBytes,
                expectedDigest: block.digest,
                payloadBytes: payload.count,
                expectedRecordCount: block.eventCount,
                workspaceLease: workspace,
                reader: reader(payload),
                recordLeaseProvider: { _, _ in
                    budget.tryAcquire(
                        bytes: EventJournalAdmissionValidator
                            .maximumPreparationWorkspaceBytes,
                        owner: .journalPrepared
                    )
                },
                as: Fixture.self,
                consume: { _ in }
            )
        }

        let exact = Data(payload.dropLast())
        let shortReader: EventJournalCodec.PayloadChunkReader = {
            offset, destination in
            guard destination.count > 1 else { return 0 }
            let shortened = UnsafeMutableRawBufferPointer(
                start: destination.baseAddress,
                count: destination.count - 1
            )
            return try reader(exact)(offset, shortened)
        }
        #expect(throws: EventJournalCodecError.self) {
            _ = try EventJournalCodec.decodeRecordsStreaming(
                codec: block.codec,
                rawBytes: block.rawBytes,
                expectedDigest: block.digest,
                payloadBytes: exact.count,
                expectedRecordCount: block.eventCount,
                workspaceLease: workspace,
                reader: shortReader,
                recordLeaseProvider: { _, _ in nil },
                as: Fixture.self,
                consume: { _ in }
            )
        }
    }

    @Test("codec refuses workspace credit from the wrong owner")
    func workspaceIdentityIsMandatory() throws {
        let budget = EventPipelineLiveMemoryBudget(
            maximumBytes: 64 * 1_024 * 1_024,
            forwardProgressReserveBytes: 48 * 1_024 * 1_024,
            eventStoreWorkspaceReserveBytes:
                EventJournalCodec.maximumWorkspaceBytes
        )
        let wrong = try #require(budget.tryAcquire(
            bytes: EventJournalCodec.maximumWorkspaceBytes,
            owner: .journalPrepared
        ))
        #expect(throws: EventJournalCodecError.invalidWorkspace) {
            _ = try EventJournalCodec.prepare(
                jsonRecords: try encoded([
                    Fixture(id: 1, text: "x", tags: [])
                ]),
                workspaceLease: wrong
            )
        }
    }
}
