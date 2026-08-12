// EventJournalCodec.swift
// MacCrabCore
//
// Bounded, checksummed block framing for the exact event journal. Encoding and
// decoding are deliberately streaming: canonical record Data is already owned
// by the journal-preparation budget, so the codec must never materialize a
// second block-sized raw buffer alongside a block-sized compressed buffer.

import Foundation
import Compression
import CryptoKit

enum EventJournalCodecError: Error, LocalizedError, Equatable {
    case emptyBlock
    case tooManyEvents(Int)
    case recordTooLarge(Int)
    case blockTooLarge(Int)
    case invalidCodec(Int)
    case invalidDigest
    case invalidWorkspace
    case recordWorkspaceUnavailable(Int)
    case decompressionFailed
    case invalidFraming(String)
    case invalidEvent(String)

    var errorDescription: String? {
        switch self {
        case .emptyBlock:
            return "event journal block is empty"
        case .tooManyEvents(let count):
            return "event journal block contains too many events: \(count)"
        case .recordTooLarge(let bytes):
            return "event journal record exceeds its byte ceiling: \(bytes)"
        case .blockTooLarge(let bytes):
            return "event journal block exceeds its byte ceiling: \(bytes)"
        case .invalidCodec(let codec):
            return "event journal block has unsupported codec \(codec)"
        case .invalidDigest:
            return "event journal block checksum mismatch"
        case .invalidWorkspace:
            return "event journal codec workspace is missing or mis-accounted"
        case .recordWorkspaceUnavailable(let ordinal):
            return "event journal record \(ordinal) has no bounded decode ownership"
        case .decompressionFailed:
            return "event journal block decompression failed"
        case .invalidFraming(let detail):
            return "event journal block framing is invalid: \(detail)"
        case .invalidEvent(let detail):
            return "event journal block contains an invalid event: \(detail)"
        }
    }
}

/// The stored payload is either one bounded compressed allocation or a set of
/// COW-borrowed canonical fragments. EventStore writes raw fragments into an
/// exact-size SQLite zeroblob; no raw block Data is ever constructed.
enum PreparedEventJournalPayload: Sendable, Equatable {
    case compressed(Data)
    case rawFragments([Data], rawBytes: Int)

    var storedBytes: Int {
        switch self {
        case .compressed(let data):
            return data.count
        case .rawFragments(_, let rawBytes):
            return rawBytes
        }
    }

    func forEachFragment(
        _ body: (Data) throws -> Void
    ) rethrows {
        switch self {
        case .compressed(let data):
            try body(data)
        case .rawFragments(let fragments, _):
            for fragment in fragments {
                try body(fragment)
            }
        }
    }
}

struct PreparedEventJournalBlock: Sendable, Equatable {
    let codec: Int
    let rawBytes: Int
    let digest: Data
    let payload: PreparedEventJournalPayload
    let eventCount: Int
    /// Retains the exact shared-budget credit for every allocation owned by
    /// `payload` until SQLite has copied or blob-written it.
    let workspaceLease: EventPipelineMemoryLease

    static func == (
        lhs: PreparedEventJournalBlock,
        rhs: PreparedEventJournalBlock
    ) -> Bool {
        lhs.codec == rhs.codec
            && lhs.rawBytes == rhs.rawBytes
            && lhs.digest == rhs.digest
            && lhs.payload == rhs.payload
            && lhs.eventCount == rhs.eventCount
    }
}

/// A decoded value may not escape without the pessimistic J/result lease that
/// covered its canonical bytes and reconstructed object graph. Callers either
/// consume it synchronously or shrink/transfer and retain the lease with their
/// typed snapshot ownership.
struct OwnedDecodedJournalRecord<Record: Sendable>: Sendable {
    let value: Record
    let canonicalByteCount: Int
    let canonicalSHA256: Data
    let ownershipLease: EventPipelineMemoryLease
}

/// The journal intentionally has no JSON array wrapper. A small fixed header
/// and UInt32 length before each independently-decodable record makes bounds
/// and trailing-byte validation unambiguous.
enum EventJournalCodec {
    typealias PayloadChunkReader = (
        _ offset: Int,
        _ destination: UnsafeMutableRawBufferPointer
    ) throws -> Int

    static let rawCodec = 0
    static let lzfseCodec = 1
    static let maximumEventsPerBlock = 128
    static let maximumRecordBytes = EventJournalAdmissionValidator
        .maximumCanonicalRecordBytes
    static let maximumUncompressedBytes = 24 * 1_024 * 1_024
    static let maximumCompressedBytes = maximumUncompressedBytes

    /// J is 36 MiB + 4 KiB. S is 12 MiB - 4 KiB, so J+S is exactly
    /// 48 MiB and two independent 24-MiB source lanes still fit beneath the
    /// process-shared 96-MiB envelope.
    static let maximumWorkspaceBytes = 12 * 1_024 * 1_024 - 4_096

    private static let magic = Data("MCEJNL01".utf8)
    private static let headerBytes = 12
    private static let ioChunkBytes = 64 * 1_024
    /// Apple's public scratch query reports ~668 KiB for LZFSE today. Round to
    /// a full MiB so stream state, two 64-KiB chunks, fragment carriers, and
    /// allocator slack remain inside S across supported macOS versions.
    private static let codecScratchReserveBytes: Int = {
        let algorithmScratch = max(
            Int(compression_encode_scratch_buffer_size(COMPRESSION_LZFSE)),
            Int(compression_decode_scratch_buffer_size(COMPRESSION_LZFSE))
        )
        let buffersAndSlack = 3 * ioChunkBytes
        let combined = algorithmScratch.addingReportingOverflow(
            buffersAndSlack
        )
        guard !combined.overflow else { return maximumWorkspaceBytes }
        let page = 4_096
        let padded = combined.partialValue.addingReportingOverflow(page - 1)
        guard !padded.overflow else { return maximumWorkspaceBytes }
        let rounded = padded.partialValue / page * page
        return max(1 * 1_024 * 1_024, rounded)
    }()
    private static let maximumLZFSEBlocks = 4_096

    static func prepare(
        jsonRecords: [Data],
        workspaceLease: EventPipelineMemoryLease,
        workspaceRetainedInputBytes: Int = 0
    ) throws -> PreparedEventJournalBlock {
        try validateWorkspace(workspaceLease)
        guard workspaceRetainedInputBytes >= 0,
              workspaceRetainedInputBytes <= maximumWorkspaceBytes else {
            throw EventJournalCodecError.invalidWorkspace
        }

        let framed = try framedFragments(jsonRecords)
        let availableOutput = maximumWorkspaceBytes
            - workspaceRetainedInputBytes
            - codecScratchReserveBytes
        let outputLimit = min(
            max(0, availableOutput),
            max(0, framed.rawBytes - 1)
        )
        let compressed = outputLimit > 0
            ? compressLZFSE(
                fragments: framed.fragments,
                maximumOutputBytes: outputLimit
            )
            : nil

        let codec: Int
        let payload: PreparedEventJournalPayload
        if let compressed, compressed.count < framed.rawBytes {
            codec = lzfseCodec
            payload = .compressed(compressed)
        } else {
            codec = rawCodec
            payload = .rawFragments(
                framed.fragments,
                rawBytes: framed.rawBytes
            )
        }
        return PreparedEventJournalBlock(
            codec: codec,
            rawBytes: framed.rawBytes,
            digest: framed.digest,
            payload: payload,
            eventCount: jsonRecords.count,
            workspaceLease: workspaceLease
        )
    }

    /// Decode one authenticated record at a time from a random-access payload
    /// reader (EventStore uses sqlite3_blob_read). No complete payload or raw
    /// block is retained. The provider must return a full pessimistic J/result
    /// lease before the codec allocates a record or invokes JSONDecoder.
    @discardableResult
    static func decodeRecordsStreaming<Record: Decodable & Sendable>(
        codec: Int,
        rawBytes: Int,
        expectedDigest: Data,
        payloadBytes: Int,
        expectedRecordCount: Int,
        workspaceLease: EventPipelineMemoryLease,
        reader: PayloadChunkReader,
        shouldDecodeRecord: @escaping (_ ordinal: Int) -> Bool = { _ in true },
        recordLeaseProvider: @escaping (_ ordinal: Int, _ bytes: Int) throws
            -> EventPipelineMemoryLease?,
        as recordType: Record.Type,
        decoder: JSONDecoder = JSONDecoder(),
        consume: @escaping (OwnedDecodedJournalRecord<Record>) throws -> Void
    ) throws -> Int {
        try validateWorkspace(workspaceLease)
        guard expectedRecordCount > 0,
              expectedRecordCount <= maximumEventsPerBlock else {
            throw EventJournalCodecError.tooManyEvents(expectedRecordCount)
        }
        guard rawBytes >= headerBytes,
              rawBytes <= maximumUncompressedBytes,
              payloadBytes > 0,
              payloadBytes <= maximumCompressedBytes else {
            throw EventJournalCodecError.blockTooLarge(
                max(rawBytes, payloadBytes)
            )
        }
        guard expectedDigest.count == SHA256.byteCount else {
            throw EventJournalCodecError.invalidDigest
        }

        var parser = StreamingFrameParser<Record>(
            expectedRawBytes: rawBytes,
            expectedDigest: expectedDigest,
            expectedRecordCount: expectedRecordCount,
            decoder: decoder,
            shouldDecodeRecord: shouldDecodeRecord,
            recordLeaseProvider: recordLeaseProvider,
            consume: consume
        )

        switch codec {
        case rawCodec:
            guard payloadBytes == rawBytes else {
                throw EventJournalCodecError.invalidFraming(
                    "raw payload length does not match metadata"
                )
            }
            try streamRaw(
                payloadBytes: payloadBytes,
                reader: reader,
                consume: { try parser.consume($0) }
            )
        case lzfseCodec:
            try validateLZFSEStreamFraming(
                payloadBytes: payloadBytes,
                exactOutputBytes: rawBytes,
                reader: reader
            )
            try streamLZFSEDecode(
                payloadBytes: payloadBytes,
                reader: reader,
                consume: { try parser.consume($0) }
            )
        default:
            throw EventJournalCodecError.invalidCodec(codec)
        }
        return try parser.finish()
    }

    private static func validateWorkspace(
        _ lease: EventPipelineMemoryLease
    ) throws {
        guard lease.owner == .eventStoreWorkspace,
              lease.bytes >= maximumWorkspaceBytes else {
            throw EventJournalCodecError.invalidWorkspace
        }
    }

    private static func framedFragments(
        _ jsonRecords: [Data]
    ) throws -> (fragments: [Data], rawBytes: Int, digest: Data) {
        guard !jsonRecords.isEmpty else {
            throw EventJournalCodecError.emptyBlock
        }
        guard jsonRecords.count <= maximumEventsPerBlock else {
            throw EventJournalCodecError.tooManyEvents(jsonRecords.count)
        }

        var requiredBytes = headerBytes
        for record in jsonRecords {
            guard !record.isEmpty, record.count <= maximumRecordBytes else {
                throw EventJournalCodecError.recordTooLarge(record.count)
            }
            let addition = requiredBytes.addingReportingOverflow(
                4 + record.count
            )
            guard !addition.overflow,
                  addition.partialValue <= maximumUncompressedBytes else {
                throw EventJournalCodecError.blockTooLarge(
                    addition.overflow ? Int.max : addition.partialValue
                )
            }
            requiredBytes = addition.partialValue
        }

        var header = magic
        appendUInt32(UInt32(jsonRecords.count), to: &header)
        var fragments: [Data] = []
        fragments.reserveCapacity(1 + jsonRecords.count * 2)
        fragments.append(header)
        var hasher = SHA256()
        hasher.update(data: header)
        for record in jsonRecords {
            var length = Data()
            length.reserveCapacity(4)
            appendUInt32(UInt32(record.count), to: &length)
            fragments.append(length)
            fragments.append(record)
            hasher.update(data: length)
            hasher.update(data: record)
        }
        return (fragments, requiredBytes, Data(hasher.finalize()))
    }

    private static func compressLZFSE(
        fragments: [Data],
        maximumOutputBytes: Int
    ) -> Data? {
        guard !fragments.isEmpty, maximumOutputBytes > 0 else { return nil }
        var output = Data(count: maximumOutputBytes)
        var producedBytes: Int?
        output.withUnsafeMutableBytes { destination in
            guard let destinationBase = destination
                .bindMemory(to: UInt8.self).baseAddress else { return }
            var stream = compression_stream(
                dst_ptr: destinationBase,
                dst_size: maximumOutputBytes,
                src_ptr: UnsafePointer(destinationBase),
                src_size: 0,
                state: nil
            )
            let initStatus = compression_stream_init(
                &stream,
                COMPRESSION_STREAM_ENCODE,
                COMPRESSION_LZFSE
            )
            guard initStatus != COMPRESSION_STATUS_ERROR else { return }
            defer { compression_stream_destroy(&stream) }
            stream.dst_ptr = destinationBase
            stream.dst_size = maximumOutputBytes

            var status = COMPRESSION_STATUS_OK
            var failed = false
            for (index, fragment) in fragments.enumerated() {
                let isFinal = index == fragments.index(before: fragments.endIndex)
                fragment.withUnsafeBytes { source in
                    guard let sourceBase = source
                        .bindMemory(to: UInt8.self).baseAddress else {
                        failed = !fragment.isEmpty
                        return
                    }
                    stream.src_ptr = sourceBase
                    stream.src_size = fragment.count
                    while !failed,
                          stream.src_size > 0
                            || (isFinal && status == COMPRESSION_STATUS_OK) {
                        let sourceBefore = stream.src_size
                        let destinationBefore = stream.dst_size
                        status = compression_stream_process(
                            &stream,
                            isFinal
                                ? Int32(COMPRESSION_STREAM_FINALIZE.rawValue)
                                : 0
                        )
                        if status == COMPRESSION_STATUS_ERROR
                            || (!isFinal
                                && status == COMPRESSION_STATUS_END)
                            || (stream.dst_size == 0
                                && status != COMPRESSION_STATUS_END)
                            || (stream.src_size == sourceBefore
                                && stream.dst_size == destinationBefore
                                && status == COMPRESSION_STATUS_OK) {
                            failed = true
                        }
                    }
                }
                if failed { return }
            }
            guard !failed, status == COMPRESSION_STATUS_END,
                  stream.src_size == 0 else { return }
            let produced = maximumOutputBytes - stream.dst_size
            if produced > 0 { producedBytes = produced }
        }
        guard let producedBytes else { return nil }
        output.count = producedBytes
        return output
    }

    private static func streamRaw(
        payloadBytes: Int,
        reader: PayloadChunkReader,
        consume: (UnsafeRawBufferPointer) throws -> Void
    ) throws {
        var offset = 0
        var buffer = [UInt8](repeating: 0, count: ioChunkBytes)
        while offset < payloadBytes {
            let count = min(ioChunkBytes, payloadBytes - offset)
            try buffer.withUnsafeMutableBytes { destination in
                let slice = UnsafeMutableRawBufferPointer(
                    start: destination.baseAddress,
                    count: count
                )
                guard try reader(offset, slice) == count else {
                    throw EventJournalCodecError.invalidFraming(
                        "payload reader returned a short chunk"
                    )
                }
            }
            try buffer.withUnsafeBytes { source in
                try consume(UnsafeRawBufferPointer(
                    start: source.baseAddress,
                    count: count
                ))
            }
            offset += count
        }
    }

    private static func streamLZFSEDecode(
        payloadBytes: Int,
        reader: PayloadChunkReader,
        consume: (UnsafeRawBufferPointer) throws -> Void
    ) throws {
        var input = [UInt8](repeating: 0, count: ioChunkBytes)
        var output = [UInt8](repeating: 0, count: ioChunkBytes)
        let dummy = UnsafeMutablePointer<UInt8>.allocate(capacity: 1)
        defer { dummy.deallocate() }
        var stream = compression_stream(
            dst_ptr: dummy,
            dst_size: 0,
            src_ptr: UnsafePointer(dummy),
            src_size: 0,
            state: nil
        )
        guard compression_stream_init(
            &stream,
            COMPRESSION_STREAM_DECODE,
            COMPRESSION_LZFSE
        ) != COMPRESSION_STATUS_ERROR else {
            throw EventJournalCodecError.decompressionFailed
        }
        defer { compression_stream_destroy(&stream) }

        var inputOffset = 0
        var status = COMPRESSION_STATUS_OK
        while inputOffset < payloadBytes, status == COMPRESSION_STATUS_OK {
            let count = min(ioChunkBytes, payloadBytes - inputOffset)
            try input.withUnsafeMutableBytes { destination in
                let slice = UnsafeMutableRawBufferPointer(
                    start: destination.baseAddress,
                    count: count
                )
                guard try reader(inputOffset, slice) == count else {
                    throw EventJournalCodecError.decompressionFailed
                }
            }
            try input.withUnsafeBytes { source in
                guard let sourceBase = source
                    .bindMemory(to: UInt8.self).baseAddress else {
                    throw EventJournalCodecError.decompressionFailed
                }
                stream.src_ptr = sourceBase
                stream.src_size = count
                while stream.src_size > 0, status == COMPRESSION_STATUS_OK {
                    let sourceBefore = stream.src_size
                    var produced = 0
                    try output.withUnsafeMutableBytes { destination in
                        guard let destinationBase = destination
                            .bindMemory(to: UInt8.self).baseAddress else {
                            throw EventJournalCodecError.decompressionFailed
                        }
                        stream.dst_ptr = destinationBase
                        stream.dst_size = ioChunkBytes
                        status = compression_stream_process(&stream, 0)
                        produced = ioChunkBytes - stream.dst_size
                        if produced > 0 {
                            try consume(UnsafeRawBufferPointer(
                                start: destinationBase,
                                count: produced
                            ))
                        }
                    }
                    guard status != COMPRESSION_STATUS_ERROR,
                          produced > 0 || stream.src_size < sourceBefore else {
                        throw EventJournalCodecError.decompressionFailed
                    }
                }
            }
            guard stream.src_size == 0 else {
                throw EventJournalCodecError.decompressionFailed
            }
            inputOffset += count
        }
        while status == COMPRESSION_STATUS_OK {
            stream.src_ptr = UnsafePointer(dummy)
            stream.src_size = 0
            var produced = 0
            try output.withUnsafeMutableBytes { destination in
                guard let destinationBase = destination
                    .bindMemory(to: UInt8.self).baseAddress else {
                    throw EventJournalCodecError.decompressionFailed
                }
                stream.dst_ptr = destinationBase
                stream.dst_size = ioChunkBytes
                status = compression_stream_process(&stream, 0)
                produced = ioChunkBytes - stream.dst_size
                if produced > 0 {
                    try consume(UnsafeRawBufferPointer(
                        start: destinationBase,
                        count: produced
                    ))
                }
            }
            guard status != COMPRESSION_STATUS_ERROR,
                  produced > 0 || status == COMPRESSION_STATUS_END else {
                throw EventJournalCodecError.decompressionFailed
            }
        }
        guard status == COMPRESSION_STATUS_END,
              inputOffset == payloadBytes,
              stream.src_size == 0 else {
            throw EventJournalCodecError.decompressionFailed
        }
    }

    /// Validate LZFSE's public outer block container with bounded random reads.
    /// Apple's decoder may accept concatenated streams, so END + consumed input
    /// is not by itself exact-framing proof.
    private static func validateLZFSEStreamFraming(
        payloadBytes: Int,
        exactOutputBytes: Int,
        reader: PayloadChunkReader
    ) throws {
        let endMagic: UInt32 = 0x2478_7662
        let rawMagic: UInt32 = 0x2d78_7662
        let v1Magic: UInt32 = 0x3178_7662
        let v2Magic: UInt32 = 0x3278_7662
        let lzvnMagic: UInt32 = 0x6e78_7662
        let v1HeaderBytes = 772
        let v2MinimumHeaderBytes = 32
        let v2MaximumHeaderBytes = 752

        func read(_ offset: Int, _ count: Int) throws -> [UInt8] {
            guard offset >= 0, count >= 0,
                  offset <= payloadBytes - count else {
                throw EventJournalCodecError.decompressionFailed
            }
            var bytes = [UInt8](repeating: 0, count: count)
            try bytes.withUnsafeMutableBytes { destination in
                guard try reader(offset, destination) == count else {
                    throw EventJournalCodecError.decompressionFailed
                }
            }
            return bytes
        }
        func uint32(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
            UInt32(bytes[offset])
                | (UInt32(bytes[offset + 1]) << 8)
                | (UInt32(bytes[offset + 2]) << 16)
                | (UInt32(bytes[offset + 3]) << 24)
        }
        func uint64(_ bytes: [UInt8], _ offset: Int) -> UInt64 {
            UInt64(uint32(bytes, offset))
                | (UInt64(uint32(bytes, offset + 4)) << 32)
        }
        func add(_ lhs: Int, _ rhs: Int) throws -> Int {
            guard lhs >= 0, rhs >= 0, lhs <= Int.max - rhs else {
                throw EventJournalCodecError.decompressionFailed
            }
            return lhs + rhs
        }

        var offset = 0
        var decodedBytes = 0
        var blockCount = 0
        while true {
            let prefix = try read(offset, 4)
            let magic = uint32(prefix, 0)
            if magic == endMagic {
                guard offset + 4 == payloadBytes,
                      decodedBytes == exactOutputBytes else {
                    throw EventJournalCodecError.decompressionFailed
                }
                return
            }
            blockCount += 1
            guard blockCount <= maximumLZFSEBlocks else {
                throw EventJournalCodecError.decompressionFailed
            }

            let headerBytes: Int
            let encodedBytes: Int
            let rawBytes: Int
            switch magic {
            case rawMagic:
                let header = try read(offset, 8)
                rawBytes = Int(uint32(header, 4))
                headerBytes = 8
                encodedBytes = rawBytes
            case lzvnMagic:
                let header = try read(offset, 12)
                rawBytes = Int(uint32(header, 4))
                headerBytes = 12
                encodedBytes = Int(uint32(header, 8))
            case v1Magic:
                let header = try read(offset, v1HeaderBytes)
                rawBytes = Int(uint32(header, 4))
                let declared = Int(uint32(header, 8))
                encodedBytes = try add(
                    Int(uint32(header, 20)),
                    Int(uint32(header, 24))
                )
                guard encodedBytes == declared else {
                    throw EventJournalCodecError.decompressionFailed
                }
                headerBytes = v1HeaderBytes
            case v2Magic:
                let header = try read(offset, v2MinimumHeaderBytes)
                rawBytes = Int(uint32(header, 4))
                let packed0 = uint64(header, 8)
                let packed1 = uint64(header, 16)
                let packed2 = uint64(header, 24)
                headerBytes = Int(UInt32(truncatingIfNeeded: packed2))
                guard headerBytes >= v2MinimumHeaderBytes,
                      headerBytes <= v2MaximumHeaderBytes else {
                    throw EventJournalCodecError.decompressionFailed
                }
                encodedBytes = try add(
                    Int((packed0 >> 20) & 0x000f_ffff),
                    Int((packed1 >> 40) & 0x000f_ffff)
                )
            default:
                throw EventJournalCodecError.decompressionFailed
            }
            decodedBytes = try add(decodedBytes, rawBytes)
            guard decodedBytes <= exactOutputBytes else {
                throw EventJournalCodecError.decompressionFailed
            }
            offset = try add(offset, try add(headerBytes, encodedBytes))
            guard offset <= payloadBytes else {
                throw EventJournalCodecError.decompressionFailed
            }
        }
    }

    private static func appendUInt32(_ value: UInt32, to data: inout Data) {
        data.append(UInt8(value & 0xff))
        data.append(UInt8((value >> 8) & 0xff))
        data.append(UInt8((value >> 16) & 0xff))
        data.append(UInt8((value >> 24) & 0xff))
    }
}

private struct StreamingFrameParser<Record: Decodable & Sendable> {
    private let expectedRawBytes: Int
    private let expectedDigest: Data
    private let expectedRecordCount: Int
    private let decoder: JSONDecoder
    private let shouldDecodeRecord: (Int) -> Bool
    private let recordLeaseProvider: (Int, Int) throws
        -> EventPipelineMemoryLease?
    private let recordConsumer: (OwnedDecodedJournalRecord<Record>) throws
        -> Void
    private var hasher = SHA256()
    private var totalBytes = 0
    private var header = Data()
    private var lengthBytes = Data()
    private var record: Data?
    private var recordLength = 0
    private var decodeCurrentRecord = false
    private var recordOffset = 0
    private var recordLease: EventPipelineMemoryLease?
    private var decodedCount = 0

    init(
        expectedRawBytes: Int,
        expectedDigest: Data,
        expectedRecordCount: Int,
        decoder: JSONDecoder,
        shouldDecodeRecord: @escaping (Int) -> Bool,
        recordLeaseProvider: @escaping (Int, Int) throws
            -> EventPipelineMemoryLease?,
        consume: @escaping (OwnedDecodedJournalRecord<Record>) throws -> Void
    ) {
        self.expectedRawBytes = expectedRawBytes
        self.expectedDigest = expectedDigest
        self.expectedRecordCount = expectedRecordCount
        self.decoder = decoder
        self.shouldDecodeRecord = shouldDecodeRecord
        self.recordLeaseProvider = recordLeaseProvider
        self.recordConsumer = consume
        header.reserveCapacity(12)
        lengthBytes.reserveCapacity(4)
    }

    mutating func consume(_ source: UnsafeRawBufferPointer) throws {
        guard totalBytes <= expectedRawBytes - source.count else {
            throw EventJournalCodecError.invalidFraming(
                "decoded bytes exceed metadata"
            )
        }
        if source.count > 0 {
            hasher.update(data: Data(source))
        }
        totalBytes += source.count
        let bytes = source.bindMemory(to: UInt8.self)
        var cursor = 0
        while cursor < bytes.count {
            if header.count < 12 {
                let count = min(12 - header.count, bytes.count - cursor)
                header.append(contentsOf: bytes[cursor..<(cursor + count)])
                cursor += count
                if header.count == 12 {
                    guard Array(header.prefix(8)) == Array("MCEJNL01".utf8),
                          readUInt32(header, at: 8)
                            == UInt32(expectedRecordCount) else {
                        throw EventJournalCodecError.invalidFraming(
                            "bad magic or record count"
                        )
                    }
                }
                continue
            }

            if recordLength == 0 {
                let count = min(4 - lengthBytes.count, bytes.count - cursor)
                lengthBytes.append(contentsOf: bytes[cursor..<(cursor + count)])
                cursor += count
                guard lengthBytes.count == 4 else { continue }
                guard decodedCount < expectedRecordCount else {
                    throw EventJournalCodecError.invalidFraming(
                        "trailing record"
                    )
                }
                let length = Int(readUInt32(lengthBytes, at: 0))
                guard length > 0,
                      length <= EventJournalCodec.maximumRecordBytes else {
                    throw EventJournalCodecError.invalidFraming(
                        "record \(decodedCount) length is out of bounds"
                    )
                }
                recordLength = length
                decodeCurrentRecord = shouldDecodeRecord(decodedCount)
                if decodeCurrentRecord {
                    guard let lease = try recordLeaseProvider(
                        decodedCount,
                        length
                    ), lease.owner == .journalPrepared,
                       lease.bytes >= EventJournalAdmissionValidator
                        .maximumPreparationWorkspaceBytes else {
                        throw EventJournalCodecError.recordWorkspaceUnavailable(
                            decodedCount
                        )
                    }
                    recordLease = lease
                    record = Data(count: length)
                }
                recordOffset = 0
                lengthBytes.removeAll(keepingCapacity: true)
            }

            let count = min(
                recordLength - recordOffset,
                bytes.count - cursor
            )
            if decodeCurrentRecord {
                guard var current = record else {
                    throw EventJournalCodecError.invalidFraming(
                        "record decode state is unavailable"
                    )
                }
                current.withUnsafeMutableBytes { destination in
                    guard let target = destination.baseAddress,
                          let input = source.baseAddress else { return }
                    target.advanced(by: recordOffset).copyMemory(
                        from: input.advanced(by: cursor),
                        byteCount: count
                    )
                }
                record = current
            }
            recordOffset += count
            cursor += count
            guard recordOffset == recordLength else { continue }

            if !decodeCurrentRecord {
                recordLength = 0
                recordOffset = 0
                decodedCount += 1
                continue
            }

            guard var current = record else {
                throw EventJournalCodecError.invalidFraming(
                    "completed record bytes are unavailable"
                )
            }

            let canonicalByteCount = current.count
            let canonicalSHA256 = Data(SHA256.hash(data: current))
            let value: Record
            do {
                value = try decoder.decode(Record.self, from: current)
            } catch {
                throw EventJournalCodecError.invalidEvent(
                    "record \(decodedCount): \(error.localizedDescription)"
                )
            }
            guard let lease = recordLease else {
                throw EventJournalCodecError.recordWorkspaceUnavailable(
                    decodedCount
                )
            }
            // Drop the canonical record buffer before handing the decoded
            // value to EventStore. The consumer may now shrink the pessimistic
            // J lease to the decoded graph's retained charge without briefly
            // under-accounting this record Data.
            record = nil
            current = Data()
            recordLease = nil
            recordLength = 0
            decodeCurrentRecord = false
            recordOffset = 0
            decodedCount += 1
            try recordConsumer(OwnedDecodedJournalRecord(
                value: value,
                canonicalByteCount: canonicalByteCount,
                canonicalSHA256: canonicalSHA256,
                ownershipLease: lease
            ))
        }
    }

    mutating func finish() throws -> Int {
        guard totalBytes == expectedRawBytes,
              header.count == 12,
              lengthBytes.isEmpty,
              record == nil,
              recordLength == 0,
              decodedCount == expectedRecordCount else {
            throw EventJournalCodecError.invalidFraming(
                "truncated or trailing framed records"
            )
        }
        guard Data(hasher.finalize()) == expectedDigest else {
            throw EventJournalCodecError.invalidDigest
        }
        return decodedCount
    }

    private func readUInt32(_ data: Data, at offset: Int) -> UInt32 {
        data.withUnsafeBytes { raw in
            let bytes = raw.bindMemory(to: UInt8.self)
            return UInt32(bytes[offset])
                | (UInt32(bytes[offset + 1]) << 8)
                | (UInt32(bytes[offset + 2]) << 16)
                | (UInt32(bytes[offset + 3]) << 24)
        }
    }
}
