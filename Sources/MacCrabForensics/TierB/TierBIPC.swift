// TierBIPC — the FROZEN host↔plugin wire contract for out-of-process first-party
// Tier-B collectors (Shape 2, Phase 2). SINGLE SOURCE OF TRUTH for both sides:
// the host (FirstPartyTierBRunner) and the plugin author build to exactly this.
//
// Flow:
//   1. Host spawns the verified plugin binary (env scrubbed to PATH+HOME).
//   2. Host writes ONE TierBCollectRequest as a single JSON line to stdin, closes stdin.
//   3. Plugin emits zero or more TierBOutputLine JSON objects, one per line (JSONL),
//      on stdout: any number of `.artifact` lines, then exactly one `.result` line.
//   4. Plugin exits. Host streams + caps stdout the whole time (never buffers
//      unbounded), commits artifacts to the case store, then cleans up.
//
// SECURITY CONTRACT (Shape-2 attack-pass mitigations — the host enforces these;
// a plugin cannot opt out):
//   - The host stamps the AUTHORITATIVE identity (caseID, pluginID, pluginVersion,
//     schemaVersion) from the VERIFIED manifest. The DTO deliberately does NOT
//     carry them — a plugin cannot spoof which case/plugin an artifact belongs to.
//   - The host recomputes sizeBytes and OWNS blobRelpath; the plugin only names a
//     scratch-relative blob file, which the host validates (no traversal) + ingests.
//   - sourcePath is untrusted free-text the host records but NEVER opens.
//   - privacyClass/confidence cross the wire as strings; the host validates them
//     (e.g. a non-metadata artifact is rejected in a plaintext case) — the wire
//     never carries a raw host enum a plugin could push an invalid value into.

import Foundation

public enum TierBIPC {
    /// Bumped only on a breaking wire change. The plugin echoes the request's
    /// protocolVersion; a mismatch is a host-side hard error.
    public static let protocolVersion = 1

    // Caps the host enforces while reading stdout (attack-pass: unbounded-stream
    // OOM/deadlock, JSON-nesting DoS, runaway artifact counts).
    public static let maxStdoutBytes = 64 * 1024 * 1024   // 64 MB total stdout
    public static let maxLineBytes = 4 * 1024 * 1024       // 4 MB per JSONL line
    public static let maxArtifacts = 100_000               // per invocation
    public static let maxJSONDepth = 64                    // nesting guard
    public static let defaultTimeoutSeconds: TimeInterval = 120
}

/// Host → plugin, written as one JSON line to stdin.
public struct TierBCollectRequest: Codable, Sendable {
    public let protocolVersion: Int
    public let pluginID: String
    public let pluginVersion: String
    /// A host-owned scratch directory the plugin MAY write blob files into (the
    /// host ingests + re-keys them). The plugin must NOT write anywhere else.
    public let scratchDir: String
    /// Optional collection time window (unix seconds); nil = unbounded.
    public let windowStartUnix: Int64?
    public let windowEndUnix: Int64?

    public init(
        protocolVersion: Int = TierBIPC.protocolVersion,
        pluginID: String,
        pluginVersion: String,
        scratchDir: String,
        windowStartUnix: Int64? = nil,
        windowEndUnix: Int64? = nil
    ) {
        self.protocolVersion = protocolVersion
        self.pluginID = pluginID
        self.pluginVersion = pluginVersion
        self.scratchDir = scratchDir
        self.windowStartUnix = windowStartUnix
        self.windowEndUnix = windowEndUnix
    }
}

/// One artifact as emitted by the plugin — CONTENT ONLY. Host-authoritative
/// fields (caseID/pluginID/pluginVersion/schemaVersion/sizeBytes/blobRelpath)
/// are intentionally absent; the host stamps them when mapping to ArtifactRecord.
public struct TierBArtifactDTO: Codable, Sendable {
    public let contentType: String
    public let summary: String?
    public let data: [String: JSONValue]
    /// "metadata" | "content" | "personalComms" | "credentialAdjacent" | "secret"
    /// — host maps to PrivacyClass and validates against the case encryption state.
    public let privacyClass: String
    /// "low" | "medium" | "high" — host maps to Confidence, defaults if absent/invalid.
    public let confidence: String?
    /// Untrusted free-text; the host records it but NEVER opens it.
    public let sourcePath: String?
    public let observedAtUnix: Int64?
    public let capturedAtUnix: Int64?
    /// Optional scratch-relative file name the plugin wrote into scratchDir; the
    /// host validates (no traversal / leading slash / dotdot / null) then ingests.
    public let blobScratchName: String?

    public init(
        contentType: String,
        summary: String? = nil,
        data: [String: JSONValue] = [:],
        privacyClass: String = "metadata",
        confidence: String? = nil,
        sourcePath: String? = nil,
        observedAtUnix: Int64? = nil,
        capturedAtUnix: Int64? = nil,
        blobScratchName: String? = nil
    ) {
        self.contentType = contentType
        self.summary = summary
        self.data = data
        self.privacyClass = privacyClass
        self.confidence = confidence
        self.sourcePath = sourcePath
        self.observedAtUnix = observedAtUnix
        self.capturedAtUnix = capturedAtUnix
        self.blobScratchName = blobScratchName
    }

    // Lenient decode: only contentType is required on the wire. A plugin may omit
    // data ([:]) / privacyClass ("metadata") / any optional field. Encode stays
    // synthesized, so round-trips are preserved.
    private enum CodingKeys: String, CodingKey {
        case contentType, summary, data, privacyClass, confidence
        case sourcePath, observedAtUnix, capturedAtUnix, blobScratchName
    }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        contentType = try c.decode(String.self, forKey: .contentType)
        summary = try c.decodeIfPresent(String.self, forKey: .summary)
        data = try c.decodeIfPresent([String: JSONValue].self, forKey: .data) ?? [:]
        privacyClass = try c.decodeIfPresent(String.self, forKey: .privacyClass) ?? "metadata"
        confidence = try c.decodeIfPresent(String.self, forKey: .confidence)
        sourcePath = try c.decodeIfPresent(String.self, forKey: .sourcePath)
        observedAtUnix = try c.decodeIfPresent(Int64.self, forKey: .observedAtUnix)
        capturedAtUnix = try c.decodeIfPresent(Int64.self, forKey: .capturedAtUnix)
        blobScratchName = try c.decodeIfPresent(String.self, forKey: .blobScratchName)
    }
}

/// The single terminal line a plugin emits to close the stream.
public struct TierBCollectResult: Codable, Sendable {
    /// "ok" | "partial" | "error" | "cancelled" — host maps to CollectionResult.ExitStatus.
    public let status: String
    public let notes: [String]

    public init(status: String, notes: [String] = []) {
        self.status = status
        self.notes = notes
    }

    // Lenient decode: status required, notes defaults to [] when omitted.
    private enum CodingKeys: String, CodingKey { case status, notes }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        status = try c.decode(String.self, forKey: .status)
        notes = try c.decodeIfPresent([String].self, forKey: .notes) ?? []
    }
}

/// One stdout line is exactly one of these, tagged by `kind`, so the host can
/// distinguish artifact lines from the terminal result without positional rules.
public enum TierBOutputLine: Codable, Sendable {
    case artifact(TierBArtifactDTO)
    case result(TierBCollectResult)

    private enum CodingKeys: String, CodingKey { case kind, artifact, result }
    private enum Kind: String, Codable { case artifact, result }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        switch try c.decode(Kind.self, forKey: .kind) {
        case .artifact: self = .artifact(try c.decode(TierBArtifactDTO.self, forKey: .artifact))
        case .result:   self = .result(try c.decode(TierBCollectResult.self, forKey: .result))
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .artifact(let a):
            try c.encode(Kind.artifact, forKey: .kind); try c.encode(a, forKey: .artifact)
        case .result(let r):
            try c.encode(Kind.result, forKey: .kind); try c.encode(r, forKey: .result)
        }
    }
}
