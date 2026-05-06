// MinimalProtoReader.swift
// MacCrabCore
//
// v1.9 PR-3a — minimal protobuf wire-format reader.
//
// We do not yet ship SwiftProtobuf-generated OTLP types. PR-3a's stub
// receiver only needs to verify that incoming bodies parse as valid
// protobuf messages (so we can return 200 OK or 400 honestly), and to
// count top-level repeated fields (so the golden-fixture test can pin
// the round-trip shape).
//
// PR-3b will replace this with `vendor/opentelemetry-proto`-generated
// code once protoc + swift-protobuf are wired into the build. The code
// below is intentionally NOT a full protobuf decoder — it only handles
// the wire-format primitives required by `ExportTraceServiceRequest`'s
// outermost shape:
//
//   message ExportTraceServiceRequest {
//     repeated ResourceSpans resource_spans = 1;
//   }
//
// Wire format reference:
//   https://protobuf.dev/programming-guides/encoding/
//
// Wire types we recognise:
//   0  VARINT          int32, int64, uint32, uint64, bool, enum
//   1  FIXED64         fixed64, sfixed64, double
//   2  LENGTH_DELIM    string, bytes, embedded messages, packed repeated
//   5  FIXED32         fixed32, sfixed32, float
//   3, 4 are deprecated start/end-group; we treat them as decode errors.

import Foundation

public enum MinimalProtoError: Error, Equatable {
    case truncated
    case malformedVarint
    case unsupportedWireType(Int)
    case overflow
}

public struct MinimalProtoReader {

    public enum WireType: Int {
        case varint = 0
        case fixed64 = 1
        case lengthDelimited = 2
        case startGroup = 3   // deprecated
        case endGroup = 4     // deprecated
        case fixed32 = 5
    }

    public struct Tag {
        public let fieldNumber: Int
        public let wireType: WireType
    }

    /// v1.9 audit (Phase-1.2): operate on `Data` directly. Pre-fix,
    /// `init(_:)` did `Array(data)` (full copy on every reader created),
    /// and every length-delimited slice did another `Array` copy. With
    /// nested decoders allocating fresh readers per ResourceSpans →
    /// ScopeSpans → Span → KeyValue → AnyValue, an 8 MB body produced
    /// ~5× memory traffic. Storing `Data` lets us hand sub-slices around
    /// (Data is COW; sub-data is a free retain) without copies.
    ///
    /// `start` is the absolute offset within `data.startIndex` that this
    /// reader's window begins at; `end` is the exclusive upper bound.
    /// `index` is the absolute offset of the next byte to read.
    private let data: Data
    private let start: Data.Index
    private let end: Data.Index
    private var index: Data.Index

    public init(_ data: Data) {
        self.data = data
        self.start = data.startIndex
        self.end = data.endIndex
        self.index = data.startIndex
    }

    public init(bytes: [UInt8]) {
        let d = Data(bytes)
        self.data = d
        self.start = d.startIndex
        self.end = d.endIndex
        self.index = d.startIndex
    }

    /// Internal init used for sub-readers over a slice of an already-
    /// owned Data. No copy.
    private init(parent: Data, start: Data.Index, end: Data.Index) {
        self.data = parent
        self.start = start
        self.end = end
        self.index = start
    }

    public var isAtEnd: Bool { index >= end }

    /// Read a varint per the protobuf encoding rules. Each byte's MSB is the
    /// continuation flag; the low 7 bits accumulate little-endian.
    public mutating func readVarint() throws -> UInt64 {
        var result: UInt64 = 0
        var shift: UInt64 = 0
        // protobuf varints are at most 10 bytes (64 bits + continuation).
        for _ in 0..<10 {
            guard index < end else { throw MinimalProtoError.truncated }
            let b = data[index]
            index = data.index(after: index)
            result |= UInt64(b & 0x7F) << shift
            if (b & 0x80) == 0 {
                return result
            }
            shift += 7
            if shift >= 64 {
                throw MinimalProtoError.malformedVarint
            }
        }
        throw MinimalProtoError.malformedVarint
    }

    /// Read a tag (field number + wire type) prefix.
    public mutating func readTag() throws -> Tag {
        let raw = try readVarint()
        let wireRaw = Int(raw & 0x7)
        let fieldNumber = Int(raw >> 3)
        guard let wire = WireType(rawValue: wireRaw) else {
            throw MinimalProtoError.unsupportedWireType(wireRaw)
        }
        return Tag(fieldNumber: fieldNumber, wireType: wire)
    }

    /// Read a length-delimited field's payload as `[UInt8]`.
    /// Kept for callers that need raw bytes (e.g. hex-rendering a small
    /// trace_id). For larger nested-message payloads, prefer
    /// `readLengthDelimitedSubReader()` which avoids the copy.
    public mutating func readLengthDelimited() throws -> [UInt8] {
        let (subStart, subEnd) = try readLengthDelimitedRange()
        // Materialise into [UInt8] for hex / string callers.
        return Array(data[subStart..<subEnd])
    }

    /// v1.9 audit (Phase-1.2): zero-copy length-delimited read. Returns
    /// a sub-reader over the same Data buffer. Used by the nested
    /// decoders (ResourceSpans → ScopeSpans → Span → KeyValue) to avoid
    /// per-message Array allocations.
    public mutating func readLengthDelimitedSubReader() throws -> MinimalProtoReader {
        let (subStart, subEnd) = try readLengthDelimitedRange()
        return MinimalProtoReader(parent: data, start: subStart, end: subEnd)
    }

    /// Internal helper: resolve the absolute Data range a length-delimited
    /// payload occupies, advance the index past it.
    private mutating func readLengthDelimitedRange() throws -> (Data.Index, Data.Index) {
        let len = try readVarint()
        guard let intLen = Int(exactly: len), intLen >= 0 else {
            throw MinimalProtoError.truncated
        }
        let subStart = index
        // Bounds check using Data.index(_:offsetBy:limitedBy:) so we
        // never overshoot the parent's window.
        guard let subEnd = data.index(subStart, offsetBy: intLen, limitedBy: end) else {
            throw MinimalProtoError.truncated
        }
        index = subEnd
        return (subStart, subEnd)
    }

    /// Skip a field of the given wire type. Used for any field number we
    /// don't care to parse — we still need to advance past it correctly so
    /// later fields decode.
    public mutating func skipField(wireType: WireType) throws {
        switch wireType {
        case .varint:
            _ = try readVarint()
        case .fixed64:
            guard data.distance(from: index, to: end) >= 8 else { throw MinimalProtoError.truncated }
            index = data.index(index, offsetBy: 8)
        case .lengthDelimited:
            // Skip the payload without materialising. readLengthDelimitedRange
            // is internal but we'd rather not duplicate; advance via varint
            // then offset.
            let len = try readVarint()
            guard let intLen = Int(exactly: len), intLen >= 0,
                  let newIndex = data.index(index, offsetBy: intLen, limitedBy: end) else {
                throw MinimalProtoError.truncated
            }
            index = newIndex
        case .fixed32:
            guard data.distance(from: index, to: end) >= 4 else { throw MinimalProtoError.truncated }
            index = data.index(index, offsetBy: 4)
        case .startGroup, .endGroup:
            throw MinimalProtoError.unsupportedWireType(wireType.rawValue)
        }
    }
}

// MARK: - Fixed-width readers

extension MinimalProtoReader {
    /// Read a 64-bit little-endian fixed (wire type 1).
    public mutating func readFixed64() throws -> UInt64 {
        guard data.distance(from: index, to: end) >= 8 else { throw MinimalProtoError.truncated }
        var v: UInt64 = 0
        var cursor = index
        for i in 0..<8 {
            v |= UInt64(data[cursor]) << (8 * i)
            cursor = data.index(after: cursor)
        }
        index = cursor
        return v
    }

    /// Read a 32-bit little-endian fixed (wire type 5).
    public mutating func readFixed32() throws -> UInt32 {
        guard data.distance(from: index, to: end) >= 4 else { throw MinimalProtoError.truncated }
        var v: UInt32 = 0
        var cursor = index
        for i in 0..<4 {
            v |= UInt32(data[cursor]) << (8 * i)
            cursor = data.index(after: cursor)
        }
        index = cursor
        return v
    }
}

// MARK: - ExportTraceServiceRequest summary (PR-3a hold-over)

/// Result of decode-and-drop: the number of top-level `resource_spans` (field
/// 1) entries observed. Used by PR-3a's stub path to confirm the body parses
/// as a valid OTLP traces request and to log a count without persistence.
public struct OTLPTracesSummary: Sendable, Equatable {
    public let resourceSpansCount: Int
    /// Total bytes of the parsed body. For the receiver to emit a
    /// telemetry counter without persisting any payload.
    public let bytesParsed: Int
}

public enum OTLPMinimalDecoder {

    /// Decode the outermost shape of an `ExportTraceServiceRequest` and
    /// return a count of top-level entries.
    ///
    /// Throws if the body is not a well-formed protobuf message. Unknown
    /// fields are skipped per the protobuf compatibility rules — we are
    /// strict on syntax but permissive on schema, which is the right
    /// stance for an external receiver.
    public static func decodeAndCount(_ body: Data) throws -> OTLPTracesSummary {
        var reader = MinimalProtoReader(body)
        var resourceSpansCount = 0
        while !reader.isAtEnd {
            let tag = try reader.readTag()
            switch (tag.fieldNumber, tag.wireType) {
            case (1, .lengthDelimited):
                _ = try reader.readLengthDelimited()
                resourceSpansCount += 1
            default:
                try reader.skipField(wireType: tag.wireType)
            }
        }
        return OTLPTracesSummary(
            resourceSpansCount: resourceSpansCount,
            bytesParsed: body.count
        )
    }
}

// MARK: - PR-3b: nested span decoding

/// Best-effort raw shape of a single OTLP Span. PR-3b extracts only the
/// fields TraceStore actually needs — full proto fidelity is out of scope.
public struct OTLPRawSpan: Sendable, Equatable {
    public var traceIdHex: String       // 32 lowercase hex (or empty if missing)
    public var spanIdHex: String        // 16 lowercase hex
    public var parentSpanIdHex: String  // 16 lowercase hex (empty if root)
    public var name: String
    public var startTimeUnixNano: UInt64
    public var endTimeUnixNano: UInt64
    /// Decoded as [(key, value-as-string)]. Each AnyValue is rendered to a
    /// concise string (string→raw, int→decimal, bool→"true"/"false",
    /// double→%.17g, bytes/array/kvlist→summary placeholder). Sanitiser is
    /// applied later by the caller.
    public var attributes: [(String, String)]

    public init() {
        self.traceIdHex = ""
        self.spanIdHex = ""
        self.parentSpanIdHex = ""
        self.name = ""
        self.startTimeUnixNano = 0
        self.endTimeUnixNano = 0
        self.attributes = []
    }

    public static func == (lhs: OTLPRawSpan, rhs: OTLPRawSpan) -> Bool {
        lhs.traceIdHex == rhs.traceIdHex
            && lhs.spanIdHex == rhs.spanIdHex
            && lhs.parentSpanIdHex == rhs.parentSpanIdHex
            && lhs.name == rhs.name
            && lhs.startTimeUnixNano == rhs.startTimeUnixNano
            && lhs.endTimeUnixNano == rhs.endTimeUnixNano
            && lhs.attributes.elementsEqual(rhs.attributes, by: { $0.0 == $1.0 && $0.1 == $1.1 })
    }
}

/// One ResourceSpans group, with the resource-level service.name plucked out
/// (since rules and the dashboard need it adjacent to every span).
public struct OTLPRawResourceGroup: Sendable, Equatable {
    public var serviceName: String?
    /// Raw resource attributes (post-extraction, pre-sanitiser). Currently
    /// only used to find `service.name`; surfaced for completeness so the
    /// caller can derive other resource-level fields without re-decoding.
    public var resourceAttributes: [(String, String)]
    public var scopeName: String
    public var scopeVersion: String
    public var spans: [OTLPRawSpan]

    public init() {
        self.serviceName = nil
        self.resourceAttributes = []
        self.scopeName = ""
        self.scopeVersion = ""
        self.spans = []
    }

    public static func == (lhs: OTLPRawResourceGroup, rhs: OTLPRawResourceGroup) -> Bool {
        lhs.serviceName == rhs.serviceName
            && lhs.scopeName == rhs.scopeName
            && lhs.scopeVersion == rhs.scopeVersion
            && lhs.spans == rhs.spans
            && lhs.resourceAttributes.elementsEqual(rhs.resourceAttributes, by: { $0.0 == $1.0 && $0.1 == $1.1 })
    }
}

public enum OTLPNestedDecoder {

    /// v1.9 audit (Phase-1.2): nested decoders all operate on
    /// sub-readers that share the request's original Data buffer.
    /// Pre-fix each nested message body went through a fresh
    /// `Array(bytes)` + `Data(bytes)` round-trip — at typical request
    /// shapes that was 5× extra allocation per request. The
    /// `readLengthDelimitedSubReader()` API hands out a sub-window
    /// without copying; the parent Data is held by reference so the
    /// COW backing buffer stays alive.

    /// Walk an `ExportTraceServiceRequest` body and return all extracted
    /// resource groups. Throws on syntactically-invalid protobuf;
    /// schema-unknown fields are skipped per the proto compat rules.
    public static func decodeRequest(_ body: Data) throws -> [OTLPRawResourceGroup] {
        var reader = MinimalProtoReader(body)
        var groups: [OTLPRawResourceGroup] = []
        while !reader.isAtEnd {
            let tag = try reader.readTag()
            switch (tag.fieldNumber, tag.wireType) {
            case (1, .lengthDelimited):
                var sub = try reader.readLengthDelimitedSubReader()
                groups.append(try decodeResourceSpans(reader: &sub))
            default:
                try reader.skipField(wireType: tag.wireType)
            }
        }
        return groups
    }

    /// Decode a single `ResourceSpans` message body. Spec:
    ///   message ResourceSpans {
    ///     Resource resource = 1;          // common.Resource
    ///     repeated ScopeSpans scope_spans = 2;
    ///     string schema_url = 3;
    ///   }
    private static func decodeResourceSpans(reader: inout MinimalProtoReader) throws -> OTLPRawResourceGroup {
        var group = OTLPRawResourceGroup()
        while !reader.isAtEnd {
            let tag = try reader.readTag()
            switch (tag.fieldNumber, tag.wireType) {
            case (1, .lengthDelimited):
                // Resource → repeated KeyValue attributes (field 1).
                var sub = try reader.readLengthDelimitedSubReader()
                group.resourceAttributes = try decodeKeyValueList(reader: &sub)
                if let s = group.resourceAttributes.first(where: { $0.0 == "service.name" }) {
                    group.serviceName = s.1
                }
            case (2, .lengthDelimited):
                var sub = try reader.readLengthDelimitedSubReader()
                let scope = try decodeScopeSpans(reader: &sub)
                if !scope.scopeName.isEmpty { group.scopeName = scope.scopeName }
                if !scope.scopeVersion.isEmpty { group.scopeVersion = scope.scopeVersion }
                group.spans.append(contentsOf: scope.spans)
            default:
                try reader.skipField(wireType: tag.wireType)
            }
        }
        return group
    }

    /// Decode a `ScopeSpans` message body. Returns scope name + version +
    /// the raw spans found inside.
    private static func decodeScopeSpans(reader: inout MinimalProtoReader) throws -> OTLPRawResourceGroup {
        var out = OTLPRawResourceGroup()
        while !reader.isAtEnd {
            let tag = try reader.readTag()
            switch (tag.fieldNumber, tag.wireType) {
            case (1, .lengthDelimited):
                // InstrumentationScope: name (1), version (2), attrs (3), dropped (4)
                var sub = try reader.readLengthDelimitedSubReader()
                let (name, version) = try decodeScope(reader: &sub)
                out.scopeName = name
                out.scopeVersion = version
            case (2, .lengthDelimited):
                var sub = try reader.readLengthDelimitedSubReader()
                out.spans.append(try decodeSpan(reader: &sub))
            default:
                try reader.skipField(wireType: tag.wireType)
            }
        }
        return out
    }

    private static func decodeScope(reader: inout MinimalProtoReader) throws -> (String, String) {
        var name = ""
        var version = ""
        while !reader.isAtEnd {
            let tag = try reader.readTag()
            switch (tag.fieldNumber, tag.wireType) {
            case (1, .lengthDelimited):
                let b = try reader.readLengthDelimited()
                name = String(decoding: b, as: UTF8.self)
            case (2, .lengthDelimited):
                let b = try reader.readLengthDelimited()
                version = String(decoding: b, as: UTF8.self)
            default:
                try reader.skipField(wireType: tag.wireType)
            }
        }
        return (name, version)
    }

    /// Decode a single Span body. Per the upstream `trace.proto` (vendored
    /// at vendor/opentelemetry-proto):
    ///   1: bytes trace_id      → 16 bytes
    ///   2: bytes span_id       → 8 bytes
    ///   4: bytes parent_span_id → 8 bytes (optional)
    ///   5: string name
    ///   7: fixed64 start_time_unix_nano
    ///   8: fixed64 end_time_unix_nano
    ///   9: repeated KeyValue attributes
    /// Other fields skipped.
    private static func decodeSpan(reader: inout MinimalProtoReader) throws -> OTLPRawSpan {
        var span = OTLPRawSpan()
        while !reader.isAtEnd {
            let tag = try reader.readTag()
            switch (tag.fieldNumber, tag.wireType) {
            case (1, .lengthDelimited):
                let b = try reader.readLengthDelimited()
                span.traceIdHex = bytesToHex(b)
            case (2, .lengthDelimited):
                let b = try reader.readLengthDelimited()
                span.spanIdHex = bytesToHex(b)
            case (4, .lengthDelimited):
                let b = try reader.readLengthDelimited()
                span.parentSpanIdHex = bytesToHex(b)
            case (5, .lengthDelimited):
                let b = try reader.readLengthDelimited()
                span.name = String(decoding: b, as: UTF8.self)
            case (7, .fixed64):
                span.startTimeUnixNano = try reader.readFixed64()
            case (8, .fixed64):
                span.endTimeUnixNano = try reader.readFixed64()
            case (9, .lengthDelimited):
                var sub = try reader.readLengthDelimitedSubReader()
                if let pair = try decodeKeyValue(reader: &sub) {
                    span.attributes.append(pair)
                }
            default:
                try reader.skipField(wireType: tag.wireType)
            }
        }
        return span
    }

    /// Decode a single `KeyValue` message: key (1, string) + value (2, AnyValue).
    /// Returns nil if the key was missing — guards the caller from blank
    /// keys that would never be useful anyway.
    private static func decodeKeyValue(reader: inout MinimalProtoReader) throws -> (String, String)? {
        var key = ""
        var rendered: String? = nil
        while !reader.isAtEnd {
            let tag = try reader.readTag()
            switch (tag.fieldNumber, tag.wireType) {
            case (1, .lengthDelimited):
                let b = try reader.readLengthDelimited()
                key = String(decoding: b, as: UTF8.self)
            case (2, .lengthDelimited):
                var sub = try reader.readLengthDelimitedSubReader()
                rendered = try decodeAnyValue(reader: &sub)
            default:
                try reader.skipField(wireType: tag.wireType)
            }
        }
        if key.isEmpty { return nil }
        return (key, rendered ?? "")
    }

    /// Render an AnyValue to a string. AnyValue is a oneof:
    ///   1: string string_value
    ///   2: bool bool_value
    ///   3: int64 int_value
    ///   4: double double_value
    ///   5: ArrayValue array_value
    ///   6: KeyValueList kvlist_value
    ///   7: bytes bytes_value
    private static func decodeAnyValue(reader: inout MinimalProtoReader) throws -> String {
        // Take the first set field — AnyValue is a oneof so there should be
        // at most one anyway. Skip everything else defensively.
        while !reader.isAtEnd {
            let tag = try reader.readTag()
            switch (tag.fieldNumber, tag.wireType) {
            case (1, .lengthDelimited):
                let b = try reader.readLengthDelimited()
                return String(decoding: b, as: UTF8.self)
            case (2, .varint):
                return try reader.readVarint() == 0 ? "false" : "true"
            case (3, .varint):
                let raw = try reader.readVarint()
                let signed = Int64(bitPattern: raw)
                return String(signed)
            case (4, .fixed64):
                let bits = try reader.readFixed64()
                let d = Double(bitPattern: bits)
                return String(d)
            case (5, .lengthDelimited):
                _ = try reader.readLengthDelimited()
                return "[ARRAY]"
            case (6, .lengthDelimited):
                _ = try reader.readLengthDelimited()
                return "[KVLIST]"
            case (7, .lengthDelimited):
                let b = try reader.readLengthDelimited()
                return "[BYTES \(b.count)]"
            default:
                try reader.skipField(wireType: tag.wireType)
            }
        }
        return ""
    }

    /// Decode a flat list of KeyValue messages — used for both the Resource
    /// attributes block and the InstrumentationScope attributes block. The
    /// proto wire shape is `repeated KeyValue` packed as repeated
    /// length-delimited entries of field 1.
    private static func decodeKeyValueList(reader: inout MinimalProtoReader) throws -> [(String, String)] {
        var out: [(String, String)] = []
        while !reader.isAtEnd {
            let tag = try reader.readTag()
            switch (tag.fieldNumber, tag.wireType) {
            case (1, .lengthDelimited):
                var sub = try reader.readLengthDelimitedSubReader()
                if let pair = try decodeKeyValue(reader: &sub) {
                    out.append(pair)
                }
            default:
                try reader.skipField(wireType: tag.wireType)
            }
        }
        return out
    }

    /// Lowercase-hex render of a raw byte payload.
    private static func bytesToHex(_ bytes: [UInt8]) -> String {
        let table: [Character] = Array("0123456789abcdef")
        var s = ""
        s.reserveCapacity(bytes.count * 2)
        for b in bytes {
            s.append(table[Int(b >> 4)])
            s.append(table[Int(b & 0x0F)])
        }
        return s
    }
}
