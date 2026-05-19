// Artifact value types — the in-memory shape every plugin hands to
// the ArtifactStore for commit.
//
// Plan reference: §3.4 schema.

import Foundation

/// A single artifact a plugin emits. Constructed by plugins, then
/// passed to `ArtifactStore.commit(_:)`. The store assigns the
/// integer `id` post-INSERT.
public struct ArtifactRecord: Sendable {

    /// Owning case (foreign key into `cases.id`).
    public let caseID: String

    /// Plugin that produced this artifact.
    public let pluginID: String
    public let pluginVersion: String

    /// Internal artifact schema version (from manifest).
    public let schemaVersion: Int

    /// Namespaced content type, e.g. `tcc.grant`, `launchd.entry`,
    /// `posture.unsigned_persistence`. Must be one of the contentType
    /// strings declared in the producing plugin's manifest outputs.
    public let contentType: String

    /// Optional pointer back to the on-disk source. For TCC-lite,
    /// this is the snapshotted TCC.db path. For launchd-lite, the
    /// plist path.
    public let sourcePath: String?

    /// File inode (when `sourcePath` is set) — drives change
    /// detection on subsequent runs.
    public let sourceInode: UInt64?

    /// File mtime (unix epoch ns) at the time of capture.
    public let sourceMtime: Int64?

    /// SHA-256 of the artifact's canonical content (as represented
    /// in `data` below). Doubles as the dedup key when the same
    /// row is observed across multiple runs.
    public let sha256: String

    /// Relative path under `<case>/vault/blobs/` when the artifact
    /// is large enough to spill (the BlobVault picks a threshold
    /// per plan §3.4). `nil` for purely structured artifacts.
    public let blobRelpath: String?

    /// When the underlying fact occurred (a TCC grant's
    /// `last_modified`, a launchd plist's mtime, an event's
    /// kernel-clock timestamp). Plan §3.4 carries `observed_at`
    /// distinct from `captured_at` so timelines reflect "when was
    /// this state", not "when did we look."
    public let observedAt: Date

    /// When the plugin actually captured the artifact.
    public let capturedAt: Date

    /// Short human-readable label. Powers dashboard list rendering.
    public let summary: String?

    /// Reported size of the artifact (bytes of `data` blob + JSON,
    /// per plugin's accounting). Used by per-case retention
    /// enforcement.
    public let sizeBytes: Int64

    /// Confidence of the artifact as a whole. Plan §3.4.
    public let confidence: Confidence

    /// Privacy class. Pass 2026-D enforces at INSERT that the
    /// declared class matches the manifest output declaration AND
    /// that plaintext cases reject non-metadata artifacts.
    public let privacyClass: PrivacyClass

    /// Optional UID/UUID of the user account that owns the
    /// artifact's source (relevant for per-user TCC.db, per-user
    /// launchd plists). Drives dashboard "filter by user."
    public let actor: String?

    /// JSON payload — the artifact's actual contents. Stored in
    /// the JSON1 `artifact_data.json` column; queryable via SQLite
    /// JSON path expressions.
    public let data: [String: JSONValue]

    public init(
        caseID: String,
        pluginID: String,
        pluginVersion: String,
        schemaVersion: Int,
        contentType: String,
        sourcePath: String? = nil,
        sourceInode: UInt64? = nil,
        sourceMtime: Int64? = nil,
        sha256: String,
        blobRelpath: String? = nil,
        observedAt: Date,
        capturedAt: Date = Date(),
        summary: String? = nil,
        sizeBytes: Int64 = 0,
        confidence: Confidence = .observed,
        privacyClass: PrivacyClass,
        actor: String? = nil,
        data: [String: JSONValue] = [:]
    ) {
        self.caseID = caseID
        self.pluginID = pluginID
        self.pluginVersion = pluginVersion
        self.schemaVersion = schemaVersion
        self.contentType = contentType
        self.sourcePath = sourcePath
        self.sourceInode = sourceInode
        self.sourceMtime = sourceMtime
        self.sha256 = sha256
        self.blobRelpath = blobRelpath
        self.observedAt = observedAt
        self.capturedAt = capturedAt
        self.summary = summary
        self.sizeBytes = sizeBytes
        self.confidence = confidence
        self.privacyClass = privacyClass
        self.actor = actor
        self.data = data
    }
}

/// Post-commit shape — same as the input but with the assigned
/// integer id. Returned by query APIs.
public struct CommittedArtifact: Sendable {
    public let id: Int64
    public let record: ArtifactRecord

    public init(id: Int64, record: ArtifactRecord) {
        self.id = id
        self.record = record
    }
}

/// Type-erased JSON value for the `artifact_data` payload. Mirror
/// of `InputValue` / `EnrichmentValue` but admits nested objects
/// + arrays — the artifact payload can be arbitrarily structured.
public indirect enum JSONValue: Codable, Sendable, Equatable {
    case string(String)
    case integer(Int64)
    case double(Double)
    case bool(Bool)
    case array([JSONValue])
    case object([String: JSONValue])
    case null

    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() {
            self = .null
        } else if let b = try? c.decode(Bool.self) {
            self = .bool(b)
        } else if let i = try? c.decode(Int64.self) {
            self = .integer(i)
        } else if let d = try? c.decode(Double.self) {
            self = .double(d)
        } else if let s = try? c.decode(String.self) {
            self = .string(s)
        } else if let a = try? c.decode([JSONValue].self) {
            self = .array(a)
        } else if let o = try? c.decode([String: JSONValue].self) {
            self = .object(o)
        } else {
            throw DecodingError.dataCorruptedError(
                in: c,
                debugDescription: "JSONValue: unexpected token"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .string(let s): try c.encode(s)
        case .integer(let i): try c.encode(i)
        case .double(let d): try c.encode(d)
        case .bool(let b): try c.encode(b)
        case .array(let a): try c.encode(a)
        case .object(let o): try c.encode(o)
        case .null: try c.encodeNil()
        }
    }
}

/// Search parameters for `ArtifactStore.query(...)`.
public struct ArtifactQuery: Sendable {
    public let caseID: String
    public let contentType: String?
    public let observedAfter: Date?
    public let observedBefore: Date?
    public let privacyClassAtMost: PrivacyClass?
    public let limit: Int
    public let offset: Int

    public init(
        caseID: String,
        contentType: String? = nil,
        observedAfter: Date? = nil,
        observedBefore: Date? = nil,
        privacyClassAtMost: PrivacyClass? = nil,
        limit: Int = 100,
        offset: Int = 0
    ) {
        self.caseID = caseID
        self.contentType = contentType
        self.observedAfter = observedAfter
        self.observedBefore = observedBefore
        self.privacyClassAtMost = privacyClassAtMost
        self.limit = limit
        self.offset = offset
    }
}
