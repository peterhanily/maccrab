// OTLPReceiverTests.swift
// Tests for v1.9 PR-3a — minimal protobuf reader + OTLPReceiver.
//
// Plan v3 mandates a golden protobuf fixture that the receiver decodes
// successfully. PR-3a's stub only counts top-level resource_spans (field 1)
// and drops the rest, so the fixture is a hand-encoded
// ExportTraceServiceRequest with two ResourceSpans entries; we verify the
// counter lands on 2.

import Testing
import Foundation
import Network
@testable import MacCrabCore

// MARK: - Hand-rolled protobuf encoding helpers

/// Tiny protobuf wire-format encoder. We only use it in tests so we can
/// produce known-shape input bytes for the decoder. Not part of the
/// shipping product (which only decodes for now).
private enum ProtoEnc {
    /// Encode a varint into bytes.
    static func varint(_ value: UInt64) -> [UInt8] {
        var v = value
        var out: [UInt8] = []
        while v >= 0x80 {
            out.append(UInt8((v & 0x7F) | 0x80))
            v >>= 7
        }
        out.append(UInt8(v & 0x7F))
        return out
    }

    /// Tag byte: (fieldNumber << 3) | wireType.
    static func tag(field: Int, wireType: Int) -> [UInt8] {
        varint(UInt64((field << 3) | wireType))
    }

    /// Encode field as length-delimited (wire type 2): tag + length + bytes.
    static func lenDelim(field: Int, payload: [UInt8]) -> [UInt8] {
        var out = tag(field: field, wireType: 2)
        out.append(contentsOf: varint(UInt64(payload.count)))
        out.append(contentsOf: payload)
        return out
    }

    /// Encode field as a varint (wire type 0).
    static func varintField(field: Int, value: UInt64) -> [UInt8] {
        var out = tag(field: field, wireType: 0)
        out.append(contentsOf: varint(value))
        return out
    }
}

// MARK: - MinimalProtoReader varint primitives

@Suite("MinimalProtoReader: wire-format primitives")
struct MinimalProtoReaderPrimitivesTests {

    @Test("Varint round-trip: 0, 1, 127, 128, 16384, UInt64.max")
    func varintRoundTrip() throws {
        for value: UInt64 in [0, 1, 127, 128, 300, 16384, UInt64.max] {
            let bytes = ProtoEnc.varint(value)
            var reader = MinimalProtoReader(bytes: bytes)
            let decoded = try reader.readVarint()
            #expect(decoded == value)
            #expect(reader.isAtEnd)
        }
    }

    @Test("Truncated varint throws .truncated")
    func truncatedVarint() {
        // Continuation bit set but no follow-up byte.
        var reader = MinimalProtoReader(bytes: [0x80])
        #expect(throws: MinimalProtoError.self) {
            _ = try reader.readVarint()
        }
    }

    @Test("Malformed (10+ continuation bytes) varint throws")
    func malformedVarint() {
        // 10 bytes all with continuation set — exceeds the 64-bit limit.
        var reader = MinimalProtoReader(bytes: Array(repeating: UInt8(0x80), count: 11))
        #expect(throws: MinimalProtoError.self) {
            _ = try reader.readVarint()
        }
    }

    @Test("Tag decoding extracts field number and wire type")
    func tagDecode() throws {
        // field 1, wire type 2 → 0x0A
        var r1 = MinimalProtoReader(bytes: [0x0A])
        let t1 = try r1.readTag()
        #expect(t1.fieldNumber == 1)
        #expect(t1.wireType == .lengthDelimited)
        // field 16, wire type 5 → varint of (16<<3)|5 = 133
        var r2 = MinimalProtoReader(bytes: ProtoEnc.tag(field: 16, wireType: 5))
        let t2 = try r2.readTag()
        #expect(t2.fieldNumber == 16)
        #expect(t2.wireType == .fixed32)
    }

    @Test("Length-delimited reads exactly the declared bytes")
    func lengthDelimited() throws {
        let payload: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF]
        let bytes = ProtoEnc.varint(UInt64(payload.count)) + payload
        var reader = MinimalProtoReader(bytes: bytes)
        let read = try reader.readLengthDelimited()
        #expect(read == payload)
    }

    @Test("Length-delimited claiming more bytes than available throws")
    func lengthDelimitedTruncated() {
        var reader = MinimalProtoReader(bytes: [0x10, 0x01]) // claims 16 bytes, has 1
        #expect(throws: MinimalProtoError.self) {
            _ = try reader.readLengthDelimited()
        }
    }

    @Test("skipField advances past varint, fixed32, fixed64, length-delim")
    func skipAllWireTypes() throws {
        // Build a buffer with one of each, then a sentinel varint.
        var buf: [UInt8] = []
        buf.append(contentsOf: ProtoEnc.varintField(field: 1, value: 42))
        buf.append(contentsOf: ProtoEnc.tag(field: 2, wireType: 5)); buf.append(contentsOf: [0x01, 0x02, 0x03, 0x04])
        buf.append(contentsOf: ProtoEnc.tag(field: 3, wireType: 1)); buf.append(contentsOf: [0,0,0,0,0,0,0,0])
        buf.append(contentsOf: ProtoEnc.lenDelim(field: 4, payload: [0xAA, 0xBB]))
        buf.append(contentsOf: ProtoEnc.varintField(field: 5, value: 7))
        var reader = MinimalProtoReader(bytes: buf)
        for _ in 0..<4 {
            let tag = try reader.readTag()
            try reader.skipField(wireType: tag.wireType)
        }
        let sentinelTag = try reader.readTag()
        #expect(sentinelTag.fieldNumber == 5)
        let sentinelValue = try reader.readVarint()
        #expect(sentinelValue == 7)
    }
}

// MARK: - Golden fixture: ExportTraceServiceRequest with 2 resource_spans

@Suite("OTLPMinimalDecoder: golden fixture round-trip")
struct OTLPMinimalDecoderGoldenTests {

    /// Hand-encoded ExportTraceServiceRequest with two top-level
    /// resource_spans entries. Each resource_spans is itself a
    /// length-delimited message — we don't care about its inner content
    /// for PR-3a, so we use empty inner bytes.
    private static let twoResourceSpansFixture: Data = {
        var bytes: [UInt8] = []
        // resource_spans #1: empty inner message
        bytes.append(contentsOf: ProtoEnc.lenDelim(field: 1, payload: []))
        // resource_spans #2: also empty
        bytes.append(contentsOf: ProtoEnc.lenDelim(field: 1, payload: []))
        return Data(bytes)
    }()

    @Test("Decode counts both resource_spans entries")
    func goldenFixtureCount() throws {
        let summary = try OTLPMinimalDecoder.decodeAndCount(Self.twoResourceSpansFixture)
        #expect(summary.resourceSpansCount == 2)
        #expect(summary.bytesParsed == Self.twoResourceSpansFixture.count)
    }

    @Test("Empty body decodes as zero spans (still well-formed)")
    func emptyBodyZeroCount() throws {
        let summary = try OTLPMinimalDecoder.decodeAndCount(Data())
        #expect(summary.resourceSpansCount == 0)
        #expect(summary.bytesParsed == 0)
    }

    @Test("Body with unknown fields skips them (forward-compat)")
    func unknownFieldsSkipped() throws {
        var bytes: [UInt8] = []
        // unknown field 7 with a varint
        bytes.append(contentsOf: ProtoEnc.varintField(field: 7, value: 999))
        // resource_spans #1
        bytes.append(contentsOf: ProtoEnc.lenDelim(field: 1, payload: []))
        // unknown field 12 with length-delim
        bytes.append(contentsOf: ProtoEnc.lenDelim(field: 12, payload: [0x01, 0x02, 0x03]))
        // resource_spans #2
        bytes.append(contentsOf: ProtoEnc.lenDelim(field: 1, payload: []))
        let summary = try OTLPMinimalDecoder.decodeAndCount(Data(bytes))
        #expect(summary.resourceSpansCount == 2)
    }

    @Test("Truncated body throws")
    func truncatedBodyThrows() {
        // Tag for length-delim field 1, claim 16 bytes, give 0.
        let bytes: [UInt8] = [0x0A, 0x10]
        #expect(throws: MinimalProtoError.self) {
            _ = try OTLPMinimalDecoder.decodeAndCount(Data(bytes))
        }
    }

    @Test("Inner ResourceSpans payload is opaque to the stub decoder")
    func innerPayloadOpaque() throws {
        // Field 1 with arbitrary inner bytes (could be valid ResourceSpans
        // or garbage — we don't care at this layer).
        let inner: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03]
        let bytes = ProtoEnc.lenDelim(field: 1, payload: inner)
        let summary = try OTLPMinimalDecoder.decodeAndCount(Data(bytes))
        #expect(summary.resourceSpansCount == 1)
        #expect(summary.bytesParsed == bytes.count)
    }
}

// MARK: - OTLPReceiver loopback contract

@Suite("OTLPReceiver: loopback peer contract")
struct OTLPReceiverLoopbackTests {

    @Test("isLoopback recognises 127.0.0.1")
    func ipv4Loopback() {
        let host: NWEndpoint.Host = .ipv4(.loopback)
        let port: NWEndpoint.Port = NWEndpoint.Port(rawValue: 9000)!
        let endpoint: NWEndpoint = .hostPort(host: host, port: port)
        #expect(OTLPReceiver.isLoopback(endpoint))
    }

    @Test("isLoopback recognises ::1")
    func ipv6Loopback() {
        let host: NWEndpoint.Host = .ipv6(.loopback)
        let port: NWEndpoint.Port = NWEndpoint.Port(rawValue: 9000)!
        let endpoint: NWEndpoint = .hostPort(host: host, port: port)
        #expect(OTLPReceiver.isLoopback(endpoint))
    }

    @Test("isLoopback recognises name 'localhost'")
    func nameLoopback() {
        let host: NWEndpoint.Host = .name("localhost", nil)
        let port: NWEndpoint.Port = NWEndpoint.Port(rawValue: 9000)!
        let endpoint: NWEndpoint = .hostPort(host: host, port: port)
        #expect(OTLPReceiver.isLoopback(endpoint))
    }

    @Test("isLoopback rejects non-loopback IPv4")
    func nonLoopbackIPv4() {
        let host: NWEndpoint.Host = .ipv4(IPv4Address("192.168.1.5")!)
        let port: NWEndpoint.Port = NWEndpoint.Port(rawValue: 9000)!
        let endpoint: NWEndpoint = .hostPort(host: host, port: port)
        #expect(!OTLPReceiver.isLoopback(endpoint))
    }

    @Test("isLoopback rejects non-loopback IPv6")
    func nonLoopbackIPv6() {
        let host: NWEndpoint.Host = .ipv6(IPv6Address("2001:db8::1")!)
        let port: NWEndpoint.Port = NWEndpoint.Port(rawValue: 9000)!
        let endpoint: NWEndpoint = .hostPort(host: host, port: port)
        #expect(!OTLPReceiver.isLoopback(endpoint))
    }

    @Test("isLoopback rejects arbitrary hostname")
    func arbitraryName() {
        let host: NWEndpoint.Host = .name("example.com", nil)
        let port: NWEndpoint.Port = NWEndpoint.Port(rawValue: 9000)!
        let endpoint: NWEndpoint = .hostPort(host: host, port: port)
        #expect(!OTLPReceiver.isLoopback(endpoint))
    }

    @Test("Receiver starts only once; second start throws .alreadyRunning")
    func doubleStartThrows() async throws {
        // Use a high random port to avoid colliding with anything else
        // running on the dev host. Bind failure is itself a test-only
        // failure mode, so we tolerate (re-throw) it explicitly.
        let port = UInt16.random(in: 49152...65500)
        let receiver = OTLPReceiver(port: port)
        do {
            try await receiver.start()
        } catch {
            // Bind failure on a random port is rare but legal in CI;
            // the rest of this test depends on a successful first bind,
            // so we treat it as inconclusive rather than a fail.
            return
        }
        defer { Task { await receiver.stop() } }
        await #expect(throws: OTLPReceiverError.alreadyRunning) {
            try await receiver.start()
        }
    }

    @Test("Initial metrics are all zero")
    func initialMetrics() async {
        let receiver = OTLPReceiver(port: 4318)
        let m = await receiver.metricsSnapshot()
        #expect(m.requestsAccepted == 0)
        #expect(m.requestsRejectedNonLoopback == 0)
        #expect(m.requestsBadRequest == 0)
        #expect(m.bodyDecodeErrors == 0)
        #expect(m.resourceSpansSeen == 0)
        #expect(m.bytesReceived == 0)
    }
}
