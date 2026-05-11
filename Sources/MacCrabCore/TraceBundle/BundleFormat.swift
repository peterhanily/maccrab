// BundleFormat.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-10a) — Codable types for the .maccrabtrace
// bundle format per §18 of the v1.10.0 spec. These types are the
// canonical Swift representation of the published bundle artifacts;
// third-party readers in other languages should mirror the same
// shape against the JSON Schemas published in
// `docs/maccrabtrace.v1.spec.md`.
//
// The bundle is a directory tree (typically packaged as tar.gz)
// containing JSON / JSONL / Markdown / HTML files. PR-10a covers
// directory-level validation; tar.gz handling lives with the CLI
// (PR-9) and exporter (PR-10b).
//
// Validation strategy: decode each artifact into a typed Swift
// struct via Codable. Decode failures map to validator exit code 1
// (schema invalid). Cross-artifact integrity claims (prov_compliant,
// otel_aligned, signature, hash chain) map to dedicated exit codes
// 2-10 in BundleValidator.

import Foundation

// MARK: - BundleManifest

/// `manifest.json` per §18.2.
public struct BundleManifest: Codable, Equatable, Sendable {

    public let format: String
    public let maccrabVersion: String
    public let rulesetVersion: String
    public let normalizationVersion: String
    public let createdAt: Date
    public let hostRedacted: Bool
    public let traceId: String
    public let title: String
    public let severity: String
    public let confidence: Double
    public let provCompliant: Bool
    public let otelAligned: Bool
    public let otelConventionVersion: String
    public let processIdentityVersion: String
    public let traceSigningKeyMode: String
    public let replayScope: String
    public let attributionOverridePolicy: String

    /// The published format identifier. Major version bumps require
    /// readers to refuse with exit code 5.
    public static let currentFormat = "maccrab.tracebundle.v1"

    /// Detect the major version (e.g. `v1`) from a format string.
    /// Returns nil for malformed or non-`maccrab.tracebundle.v*` values.
    public var formatMajorVersion: Int? {
        Self.formatMajorVersion(of: format)
    }

    public static func formatMajorVersion(of format: String) -> Int? {
        let prefix = "maccrab.tracebundle.v"
        guard format.hasPrefix(prefix) else { return nil }
        let suffix = String(format.dropFirst(prefix.count))
        let majorPart = suffix.split(separator: ".").first.map(String.init) ?? suffix
        return Int(majorPart)
    }

    public init(
        format: String = BundleManifest.currentFormat,
        maccrabVersion: String,
        rulesetVersion: String,
        normalizationVersion: String,
        createdAt: Date,
        hostRedacted: Bool,
        traceId: String,
        title: String,
        severity: String,
        confidence: Double,
        provCompliant: Bool,
        otelAligned: Bool,
        otelConventionVersion: String,
        processIdentityVersion: String,
        traceSigningKeyMode: String,
        replayScope: String,
        attributionOverridePolicy: String
    ) {
        self.format = format
        self.maccrabVersion = maccrabVersion
        self.rulesetVersion = rulesetVersion
        self.normalizationVersion = normalizationVersion
        self.createdAt = createdAt
        self.hostRedacted = hostRedacted
        self.traceId = traceId
        self.title = title
        self.severity = severity
        self.confidence = confidence
        self.provCompliant = provCompliant
        self.otelAligned = otelAligned
        self.otelConventionVersion = otelConventionVersion
        self.processIdentityVersion = processIdentityVersion
        self.traceSigningKeyMode = traceSigningKeyMode
        self.replayScope = replayScope
        self.attributionOverridePolicy = attributionOverridePolicy
    }
}

// MARK: - GraphArtifact

/// `graph.json` — the trace's entity + edge graph plus the trace
/// header. PR-10a represents this as a wrapper around the existing
/// `Trace`, `TraceEntity`, `TraceEdge`, and `TraceMembership` types.
public struct GraphArtifact: Codable, Equatable, Sendable {
    public let trace: Trace
    public let entities: [TraceEntity]
    public let edges: [TraceEdge]
    public let memberships: [TraceMembership]
    public let rootCauseEntityId: String?
    public let anchorEntityId: String

    public init(
        trace: Trace,
        entities: [TraceEntity],
        edges: [TraceEdge],
        memberships: [TraceMembership],
        rootCauseEntityId: String?,
        anchorEntityId: String
    ) {
        self.trace = trace
        self.entities = entities
        self.edges = edges
        self.memberships = memberships
        self.rootCauseEntityId = rootCauseEntityId
        self.anchorEntityId = anchorEntityId
    }
}

// MARK: - ReplayManifestArtifact

/// `replay/replay_manifest.json` — captures everything ReplayEngine
/// needs to reproduce the trace deterministically per §17.
public struct ReplayManifestArtifact: Codable, Equatable, Sendable {
    public let daemonVersion: String
    public let rulesetVersion: String
    public let normalizationVersion: String
    public let replayScope: String
    public let unsupportedEngines: [String]
    public let unsupportedRuleIds: [String]
    public let canonicalEventOrdering: String
    public let baselineMode: String
    public let policySnapshotJson: String

    public init(
        daemonVersion: String,
        rulesetVersion: String,
        normalizationVersion: String,
        replayScope: String,
        unsupportedEngines: [String] = [],
        unsupportedRuleIds: [String] = [],
        canonicalEventOrdering: String = "(timestamp_ns, event_id)",
        baselineMode: String = "reset",
        policySnapshotJson: String
    ) {
        self.daemonVersion = daemonVersion
        self.rulesetVersion = rulesetVersion
        self.normalizationVersion = normalizationVersion
        self.replayScope = replayScope
        self.unsupportedEngines = unsupportedEngines
        self.unsupportedRuleIds = unsupportedRuleIds
        self.canonicalEventOrdering = canonicalEventOrdering
        self.baselineMode = baselineMode
        self.policySnapshotJson = policySnapshotJson
    }
}

// MARK: - Integrity artifacts

/// `integrity/hash_chain.json` — canonical artifact list + per-artifact
/// SHA-256 in sorted-path order. The Merkle root over this list
/// (computed by the validator and verifier) is what gets signed in
/// `chain_head_signature.json` per §19.2.
public struct HashChainArtifact: Codable, Equatable, Sendable {

    public struct ArtifactHash: Codable, Equatable, Sendable {
        public let path: String       // canonical path within the bundle root
        public let sha256: String     // lowercase hex

        public init(path: String, sha256: String) {
            self.path = path
            self.sha256 = sha256
        }
    }

    public let bundleFormatVersion: String
    public let artifacts: [ArtifactHash]
    public let merkleRoot: String

    public init(
        bundleFormatVersion: String = BundleManifest.currentFormat,
        artifacts: [ArtifactHash],
        merkleRoot: String
    ) {
        self.bundleFormatVersion = bundleFormatVersion
        self.artifacts = artifacts
        self.merkleRoot = merkleRoot
    }
}

/// `integrity/chain_head_signature.json` — the daemon's signature over
/// the Merkle root from `hash_chain.json`. The public key for
/// verification is bundled at install in
/// `/Library/Application Support/MacCrab/keys/trace-signing.pub`.
public struct ChainHeadSignatureArtifact: Codable, Equatable, Sendable {

    public let merkleRoot: String
    public let signatureBase64: String
    public let signingKeyMode: String          // "secure_enclave" | "filesystem_degraded"
    public let signingKeyFingerprint: String   // sha256 of the public key DER, hex
    public let signedAt: Date

    public init(
        merkleRoot: String,
        signatureBase64: String,
        signingKeyMode: String,
        signingKeyFingerprint: String,
        signedAt: Date
    ) {
        self.merkleRoot = merkleRoot
        self.signatureBase64 = signatureBase64
        self.signingKeyMode = signingKeyMode
        self.signingKeyFingerprint = signingKeyFingerprint
        self.signedAt = signedAt
    }
}

// MARK: - Attribution artifacts (§18.5)

public struct MachineAttributionArtifact: Codable, Equatable, Sendable {
    public let entries: [MachineAttribution]

    public struct MachineAttribution: Codable, Equatable, Sendable {
        public let eventId: String
        public let traceId: String?
        public let spanId: String?
        public let agentTool: String?
        public let confidence: Double
        public let attributionMethod: String?

        public init(
            eventId: String,
            traceId: String?,
            spanId: String?,
            agentTool: String?,
            confidence: Double,
            attributionMethod: String?
        ) {
            self.eventId = eventId
            self.traceId = traceId
            self.spanId = spanId
            self.agentTool = agentTool
            self.confidence = confidence
            self.attributionMethod = attributionMethod
        }
    }

    public init(entries: [MachineAttribution]) {
        self.entries = entries
    }
}

public struct HumanOverridesArtifact: Codable, Equatable, Sendable {

    public struct Verdict: Codable, Equatable, Sendable {
        public let eventId: String
        public let verdict: String  // "confirmed" | "wrong_tool" | "no_agent" | "unknown"
        public let userNote: String?
        public let createdAt: Date
        public let updatedAt: Date

        public init(
            eventId: String,
            verdict: String,
            userNote: String?,
            createdAt: Date,
            updatedAt: Date
        ) {
            self.eventId = eventId
            self.verdict = verdict
            self.userNote = userNote
            self.createdAt = createdAt
            self.updatedAt = updatedAt
        }
    }

    public let verdicts: [Verdict]

    public init(verdicts: [Verdict]) {
        self.verdicts = verdicts
    }
}

// MARK: - Encoding helpers

/// Canonical JSON encoder used throughout the bundle pipeline. Sorted
/// keys + ISO-8601 dates + no whitespace insertion. Ensures bundle
/// artifacts hash identically across daemon runs.
public func canonicalJSONEncoder() -> JSONEncoder {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    encoder.keyEncodingStrategy = .convertToSnakeCase
    encoder.dateEncodingStrategy = .iso8601
    return encoder
}

/// Decoder companion for `canonicalJSONEncoder()`.
public func canonicalJSONDecoder() -> JSONDecoder {
    let decoder = JSONDecoder()
    decoder.keyDecodingStrategy = .convertFromSnakeCase
    decoder.dateDecodingStrategy = .iso8601
    return decoder
}
