// Enricher result types. Enrichments live alongside events / alerts
// without owning a primary data source. The codesign-resolve
// enricher (v1.13a-2) is the reference shape.
//
// Plan reference: §5.2.

import Foundation

/// What an Enricher returns from `enrich(...)`. Provides metadata
/// about provenance + a payload bag the consumer can merge.
public struct Enrichment: Sendable, Codable {
    /// Reverse-DNS plugin id (matches manifest.id).
    public let pluginID: String

    /// SemVer (matches manifest.version at the time of enrichment).
    public let pluginVersion: String

    /// Internal schema version of the emitted fields. Increment
    /// when the field-name set changes incompatibly.
    public let schemaVersion: Int

    /// When the enricher produced the result.
    public let producedAt: Date

    /// The actual fields. Consumers merge by `fields["key"] = value`.
    /// Key namespace convention: `<short-plugin-name>.<field>`,
    /// e.g. `codesign.team_id`, `codesign.signing_status`.
    public let fields: [String: EnrichmentValue]

    /// Confidence in the emitted fields as a whole. Per-field
    /// confidence is not modeled in v1.13a — fields share the
    /// enrichment's confidence.
    public let confidence: Confidence

    /// Privacy class of the fields. The codesign-resolve enricher
    /// emits `.metadata`. Future enrichers that surface message
    /// content (none planned in v1.13a-v1.15) would emit higher
    /// classes.
    public let privacyClass: PrivacyClass

    public init(
        pluginID: String,
        pluginVersion: String,
        schemaVersion: Int,
        producedAt: Date = Date(),
        fields: [String: EnrichmentValue],
        confidence: Confidence,
        privacyClass: PrivacyClass
    ) {
        self.pluginID = pluginID
        self.pluginVersion = pluginVersion
        self.schemaVersion = schemaVersion
        self.producedAt = producedAt
        self.fields = fields
        self.confidence = confidence
        self.privacyClass = privacyClass
    }
}

/// Type-erased value placed in `Enrichment.fields`. JSON-round-trip
/// preserves the underlying type. Kept minimal — Enrichers emitting
/// nested structures encode them as JSON-encoded strings.
public enum EnrichmentValue: Codable, Sendable, Equatable {
    case bool(Bool)
    case integer(Int)
    case double(Double)
    case string(String)
    case stringArray([String])
    case `nil`

    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() {
            self = .nil
        } else if let b = try? c.decode(Bool.self) {
            self = .bool(b)
        } else if let i = try? c.decode(Int.self) {
            self = .integer(i)
        } else if let d = try? c.decode(Double.self) {
            self = .double(d)
        } else if let s = try? c.decode(String.self) {
            self = .string(s)
        } else if let a = try? c.decode([String].self) {
            self = .stringArray(a)
        } else {
            throw DecodingError.dataCorruptedError(
                in: c,
                debugDescription: "EnrichmentValue requires bool/int/double/string/[String]/null"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .bool(let b): try c.encode(b)
        case .integer(let i): try c.encode(i)
        case .double(let d): try c.encode(d)
        case .string(let s): try c.encode(s)
        case .stringArray(let a): try c.encode(a)
        case .nil: try c.encodeNil()
        }
    }
}

/// What can be enriched. Cases reference MacCrabCore types but the
/// shape is intentionally narrow — `subject(.event)` covers the
/// detection-pipeline case, `subject(.alert)` covers post-emission
/// decoration, `subject(.path)` covers ad-hoc operator queries
/// from the dashboard.
public enum EnrichmentSubject: Sendable {
    /// An event in flight through the detection pipeline. The
    /// runtime constructs an erased payload via this case — the
    /// codesign-resolve enricher reads the .executable path off
    /// the wrapped event.
    case event(EnrichmentEventPayload)

    /// An alert that's been committed. Used at the `.postEmission`
    /// stage.
    case alert(EnrichmentAlertPayload)

    /// A path-on-disk target. Used at `.onDemand` for ad-hoc
    /// lookups initiated by the operator or an AI agent.
    case path(URL)
}

/// Minimal event payload an enricher sees. Decoupled from
/// `MacCrabCore.Event` so the plugin protocol doesn't drag the
/// full event type graph into MacCrabForensics. The runtime
/// constructs this from the full Event before invoking enrichers.
public struct EnrichmentEventPayload: Sendable, Codable {
    public let id: String
    public let processExecutablePath: String?
    public let processPID: Int32?
    public let timestamp: Date
    public let categoryRaw: String?

    public init(
        id: String,
        processExecutablePath: String?,
        processPID: Int32?,
        timestamp: Date,
        categoryRaw: String?
    ) {
        self.id = id
        self.processExecutablePath = processExecutablePath
        self.processPID = processPID
        self.timestamp = timestamp
        self.categoryRaw = categoryRaw
    }
}

/// Minimal alert payload. Same rationale as
/// `EnrichmentEventPayload`.
public struct EnrichmentAlertPayload: Sendable, Codable {
    public let id: String
    public let ruleID: String
    public let timestamp: Date
    public let processExecutablePath: String?

    public init(
        id: String,
        ruleID: String,
        timestamp: Date,
        processExecutablePath: String?
    ) {
        self.id = id
        self.ruleID = ruleID
        self.timestamp = timestamp
        self.processExecutablePath = processExecutablePath
    }
}
