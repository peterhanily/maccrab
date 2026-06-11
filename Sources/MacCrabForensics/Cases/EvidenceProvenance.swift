// EvidenceProvenance — S2-08 evidence-integrity provenance + chain-of-custody.
//
// Two value types underpin the signed forensic case manifest (S2-09):
//
//   1. ArtifactProvenance — the SHA-256 (plus minimal identifying
//      metadata) of EVERY artifact a case collected. The artifact's
//      sha256 is already the digest of its canonical content (see
//      ArtifactRecord.sha256); we re-publish it here under signature so
//      an auditor can confirm the manifest enumerates exactly the
//      artifacts the case holds, with no additions or omissions.
//
//   2. CustodyEntry / CustodyLog — an append-only, hash-chained
//      chain-of-custody log. One entry is appended AT COLLECTION TIME
//      per plugin invocation, capturing the trust context in effect:
//      engine_version, rule_pack_hash, plugin id/version/hash,
//      collector, timestamp. Each entry commits to the previous
//      entry's hash (entryHash = SHA-256(prevHash || canonical(payload))),
//      so the chain is tamper-evident: mutating, reordering, inserting,
//      or deleting any entry breaks every downstream entryHash and the
//      log head.
//
// COURT-DEFENSIBLE CANONICAL FORM (decision recorded by S2-09):
// Every timestamp in the signed surface is rendered as a fixed-precision
// UTC ISO-8601 string (millisecond precision, 'Z' suffix, no local TZ),
// and every JSON object is serialized with sorted keys and no
// insignificant whitespace. For encrypted-at-rest cases this means the
// signed digest is computed over a DETERMINISTIC PRE-ENCRYPTION canonical
// form: the same logical case produces byte-identical signed bytes on any
// machine, in any timezone, regardless of SQLCipher page layout or row
// ordering. That stable cross-machine reproducibility is the property an
// evidentiary verification needs — the verifier never has to decrypt to
// the same ciphertext, only to reconstruct the same canonical manifest.

import Foundation
import CryptoKit

// MARK: - Canonical timestamp

/// Renders a `Date` as a fixed-precision UTC ISO-8601 string
/// (`yyyy-MM-dd'T'HH:mm:ss.SSS'Z'`). Pinned millisecond precision +
/// UTC + 'Z' so the signed bytes never vary with the signing host's
/// locale or timezone — the cross-machine determinism guarantee.
public enum CanonicalTimestamp {
    private static let formatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        f.timeZone = TimeZone(identifier: "UTC")
        return f
    }()

    public static func string(from date: Date) -> String {
        formatter.string(from: date)
    }
}

// MARK: - Artifact provenance

/// Provenance for a single collected artifact: its content digest plus
/// the minimal metadata needed to attribute it. The list of these (under
/// signature) is the manifest's claim about WHAT the case holds.
public struct ArtifactProvenance: Sendable, Equatable, Codable {
    /// SHA-256 hex of the artifact's canonical content (ArtifactRecord.sha256).
    public let sha256: String
    /// Namespaced content type, e.g. `tcc.grant`.
    public let contentType: String
    /// Plugin that produced the artifact.
    public let pluginID: String
    /// Reported size in bytes.
    public let sizeBytes: Int64

    public init(sha256: String, contentType: String, pluginID: String, sizeBytes: Int64) {
        self.sha256 = sha256
        self.contentType = contentType
        self.pluginID = pluginID
        self.sizeBytes = sizeBytes
    }

    enum CodingKeys: String, CodingKey {
        case sha256
        case contentType = "content_type"
        case pluginID = "plugin_id"
        case sizeBytes = "size_bytes"
    }
}

// MARK: - Chain of custody

/// The signed payload of one chain-of-custody entry — the trust context
/// captured AT COLLECTION TIME. `prevHash` links to the previous entry's
/// `entryHash` (or the genesis sentinel for the first entry), making the
/// log append-only and tamper-evident.
public struct CustodyEntryPayload: Sendable, Equatable, Codable {
    /// Running MacCrab engine version (`MacCrabVersion.current`).
    public let engineVersion: String
    /// Hash of the compiled rule pack in effect (caller-supplied;
    /// empty when not applicable to this collector).
    public let rulePackHash: String
    /// Plugin that collected.
    public let pluginID: String
    public let pluginVersion: String
    /// sha256 of the installed plugin bundle (binds the artifact to the
    /// exact, verified plugin build). Empty for built-in collectors.
    public let pluginHash: String
    /// Free-form collector label (e.g. `tcc-lite`, `launchd-lite`).
    public let collector: String
    /// UTC ISO-8601 collection timestamp (canonical form).
    public let timestamp: String
    /// `entryHash` of the previous entry, or the genesis sentinel.
    public let prevHash: String

    public init(
        engineVersion: String,
        rulePackHash: String,
        pluginID: String,
        pluginVersion: String,
        pluginHash: String,
        collector: String,
        timestamp: String,
        prevHash: String
    ) {
        self.engineVersion = engineVersion
        self.rulePackHash = rulePackHash
        self.pluginID = pluginID
        self.pluginVersion = pluginVersion
        self.pluginHash = pluginHash
        self.collector = collector
        self.timestamp = timestamp
        self.prevHash = prevHash
    }

    enum CodingKeys: String, CodingKey {
        case engineVersion = "engine_version"
        case rulePackHash = "rule_pack_hash"
        case pluginID = "plugin_id"
        case pluginVersion = "plugin_version"
        case pluginHash = "plugin_hash"
        case collector
        case timestamp
        case prevHash = "prev_hash"
    }

    /// Canonical bytes the entryHash commits to: sorted keys, no
    /// insignificant whitespace. Includes `prevHash`, so the hash chains.
    public func canonicalBytes() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(self)
    }
}

/// A custody entry = its payload + the derived `entryHash`. `entryHash`
/// is recomputable from the payload alone, so a verifier never trusts
/// the stored value — it recomputes and compares.
public struct CustodyEntry: Sendable, Equatable, Codable {
    public let payload: CustodyEntryPayload
    /// SHA-256 hex of the payload's canonical bytes.
    public let entryHash: String

    public init(payload: CustodyEntryPayload, entryHash: String) {
        self.payload = payload
        self.entryHash = entryHash
    }

    enum CodingKeys: String, CodingKey {
        case payload
        case entryHash = "entry_hash"
    }

    /// The hash a payload reduces to: SHA-256 over its canonical bytes
    /// (which already include `prevHash`).
    public static func hash(of payload: CustodyEntryPayload) throws -> String {
        let bytes = try payload.canonicalBytes()
        return SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }
}

/// Append-only chain-of-custody log. The first entry's `prevHash` is the
/// genesis sentinel; every subsequent entry's `prevHash` is the prior
/// entry's `entryHash`. `head` is the last `entryHash` (or genesis when
/// empty) and is what the signed manifest commits to — signing the head
/// transitively commits to the whole chain.
public struct CustodyLog: Sendable, Equatable, Codable {
    /// Genesis sentinel for the first entry's prevHash. A fixed,
    /// well-known constant so an empty/first-entry chain is unambiguous.
    public static let genesis = String(repeating: "0", count: 64)

    public private(set) var entries: [CustodyEntry]

    public init(entries: [CustodyEntry] = []) {
        self.entries = entries
    }

    /// The hash a new entry must chain onto.
    public var head: String {
        entries.last?.entryHash ?? Self.genesis
    }

    /// Append a collection event. The new entry's `prevHash` is wired to
    /// the current head and its `entryHash` is derived — append-only by
    /// construction (no API mutates or removes an existing entry).
    public mutating func append(
        engineVersion: String,
        rulePackHash: String,
        pluginID: String,
        pluginVersion: String,
        pluginHash: String,
        collector: String,
        timestamp: Date
    ) throws {
        let payload = CustodyEntryPayload(
            engineVersion: engineVersion,
            rulePackHash: rulePackHash,
            pluginID: pluginID,
            pluginVersion: pluginVersion,
            pluginHash: pluginHash,
            collector: collector,
            timestamp: CanonicalTimestamp.string(from: timestamp),
            prevHash: head
        )
        let entryHash = try CustodyEntry.hash(of: payload)
        entries.append(CustodyEntry(payload: payload, entryHash: entryHash))
    }

    /// Recompute the chain from scratch and confirm every link.
    /// Returns the verified head on success; throws `.brokenAt` at the
    /// first entry whose stored `entryHash` or `prevHash` doesn't match
    /// the recomputed chain. Reordering, mutating, inserting, or deleting
    /// any entry trips this.
    @discardableResult
    public func verifyChain() throws -> String {
        var expectedPrev = Self.genesis
        for (index, entry) in entries.enumerated() {
            guard entry.payload.prevHash == expectedPrev else {
                throw CustodyLogError.brokenAt(index: index, reason: "prev_hash mismatch")
            }
            let recomputed = try CustodyEntry.hash(of: entry.payload)
            guard recomputed == entry.entryHash else {
                throw CustodyLogError.brokenAt(index: index, reason: "entry_hash mismatch")
            }
            expectedPrev = entry.entryHash
        }
        return head
    }
}

public enum CustodyLogError: Error, Equatable, CustomStringConvertible {
    case brokenAt(index: Int, reason: String)

    public var description: String {
        switch self {
        case .brokenAt(let index, let reason):
            return "Custody chain broken at entry \(index): \(reason)"
        }
    }
}
