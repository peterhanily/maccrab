// CaseEvidenceSigner — S2-09 signed, offline-verifiable forensic case
// manifest. Builds an EvidenceManifest over a case's collected artifacts
// (provenance: SHA-256 of every artifact + an artifacts Merkle root) and
// its chain-of-custody head, signs the canonical manifest bytes with the
// per-install P256 TrustSubstrate (the SAME primitive that signs trace
// bundles via BundleValidator.chain_head_signature — but the payload here
// is a forensic CASE, not a trace), and writes a self-contained signed
// envelope to `<case>/evidence_manifest.json`.
//
// The envelope embeds the signing public key (SPKI DER) so verification
// is fully offline — `verify(at:)` needs nothing but the file and the
// case's manifest.json (for the cross-binding id). This mirrors
// PluginInstallReceiptStore and the verify_bundle contract.
//
// CANONICAL / COURT-DEFENSIBLE FORM: see EvidenceProvenance.swift. The
// signed bytes are a deterministic pre-encryption canonical form (UTC
// timestamps, sorted keys, pinned precision) so an encrypted-at-rest case
// reproduces byte-identical signed bytes on any machine — the verifier
// reconstructs the canonical manifest, never the same ciphertext.

import Foundation
import CryptoKit
import MacCrabCore

/// The signed body of an evidence manifest. Commits to the case identity,
/// the full artifact provenance set, the artifacts Merkle root, and the
/// chain-of-custody head — signing this transitively seals the case's
/// evidentiary state.
public struct EvidenceManifestBody: Sendable, Equatable, Codable {
    /// Case id (cross-bound against manifest.json at verify time).
    public let caseID: String
    /// Case name (provenance convenience; not security-load-bearing).
    public let caseName: String
    /// Engine version that produced the signed manifest.
    public let engineVersion: String
    /// UTC ISO-8601 time the manifest was sealed.
    public let sealedAt: String
    /// One provenance entry per collected artifact, sorted by sha256
    /// then content_type then plugin_id for canonical stability.
    public let artifacts: [ArtifactProvenance]
    /// Merkle root over the sorted artifact sha256 leaves (reuses the
    /// trace-bundle BundleMerkle reduction). A single value that fixes
    /// the entire artifact set under signature.
    public let artifactsMerkleRoot: String
    /// Number of artifacts (redundant with `artifacts.count` but
    /// explicit so a truncated `artifacts[]` is self-evident).
    public let artifactCount: Int
    /// Head of the chain-of-custody log at seal time.
    public let custodyHead: String
    /// Number of custody entries (so a trimmed log is self-evident).
    public let custodyEntryCount: Int

    public init(
        caseID: String,
        caseName: String,
        engineVersion: String,
        sealedAt: String,
        artifacts: [ArtifactProvenance],
        artifactsMerkleRoot: String,
        artifactCount: Int,
        custodyHead: String,
        custodyEntryCount: Int
    ) {
        self.caseID = caseID
        self.caseName = caseName
        self.engineVersion = engineVersion
        self.sealedAt = sealedAt
        self.artifacts = artifacts
        self.artifactsMerkleRoot = artifactsMerkleRoot
        self.artifactCount = artifactCount
        self.custodyHead = custodyHead
        self.custodyEntryCount = custodyEntryCount
    }

    enum CodingKeys: String, CodingKey {
        case caseID = "case_id"
        case caseName = "case_name"
        case engineVersion = "engine_version"
        case sealedAt = "sealed_at"
        case artifacts
        case artifactsMerkleRoot = "artifacts_merkle_root"
        case artifactCount = "artifact_count"
        case custodyHead = "custody_head"
        case custodyEntryCount = "custody_entry_count"
    }

    /// Canonical bytes the signature commits to: sorted keys, no
    /// insignificant whitespace. Deterministic across encoder runs and
    /// machines — the verifier reproduces exactly these bytes from the
    /// parsed body.
    public func canonicalBytes() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(self)
    }

    /// Build the artifacts Merkle root + sorted provenance list from a
    /// raw provenance set. Sorting is canonical (sha256, then
    /// content_type, then plugin_id) so the same artifact set always
    /// yields the same root regardless of DB row order.
    public static func sortedArtifacts(_ raw: [ArtifactProvenance]) -> [ArtifactProvenance] {
        raw.sorted {
            if $0.sha256 != $1.sha256 { return $0.sha256 < $1.sha256 }
            if $0.contentType != $1.contentType { return $0.contentType < $1.contentType }
            return $0.pluginID < $1.pluginID
        }
    }
}

public enum CaseEvidenceError: Error, CustomStringConvertible {
    case writeFailed(String)
    case readFailed(String)
    case malformed(String)
    case signatureInvalid
    case custodyChainInvalid(String)
    case caseIDMismatch(expected: String, found: String)

    public var description: String {
        switch self {
        case .writeFailed(let m): return "Evidence manifest write failed: \(m)"
        case .readFailed(let m):  return "Evidence manifest read failed: \(m)"
        case .malformed(let m):   return "Evidence manifest malformed: \(m)"
        case .signatureInvalid:   return "Evidence manifest signature does not verify (tampered or wrong key)."
        case .custodyChainInvalid(let m): return "Custody chain invalid: \(m)"
        case .caseIDMismatch(let e, let f): return "Evidence manifest case_id '\(f)' does not match case '\(e)'."
        }
    }
}

/// Seals + verifies forensic case evidence manifests. Signing reuses the
/// P256 TrustSubstrate; the envelope embeds the signing public key so
/// `verify(at:)` is fully self-contained.
public struct CaseEvidenceSigner: Sendable {
    private let substrate: TrustSubstrate

    public init(substrate: TrustSubstrate) {
        self.substrate = substrate
    }

    /// Enumerate every artifact in a case store as provenance. Pages
    /// through `query` with no privacy-class filter so ALL artifacts are
    /// captured — provenance must be complete or the Merkle root is a lie.
    public static func collectProvenance(
        from store: ArtifactStore,
        caseID: String
    ) async throws -> [ArtifactProvenance] {
        var out: [ArtifactProvenance] = []
        let page = 500
        var offset = 0
        while true {
            let batch = try await store.query(ArtifactQuery(
                caseID: caseID, limit: page, offset: offset
            ))
            if batch.isEmpty { break }
            for committed in batch {
                let r = committed.record
                out.append(ArtifactProvenance(
                    sha256: r.sha256,
                    contentType: r.contentType,
                    pluginID: r.pluginID,
                    sizeBytes: r.sizeBytes
                ))
            }
            if batch.count < page { break }
            offset += page
        }
        return out
    }

    /// Build the signed body from collected provenance + a custody head.
    /// The artifacts list is canonically sorted and the Merkle root is
    /// computed over the sorted sha256 leaves.
    public static func buildBody(
        caseID: String,
        caseName: String,
        engineVersion: String = MacCrabVersion.current,
        sealedAt: Date = Date(),
        provenance: [ArtifactProvenance],
        custodyHead: String,
        custodyEntryCount: Int
    ) -> EvidenceManifestBody {
        let sorted = EvidenceManifestBody.sortedArtifacts(provenance)
        let root = BundleMerkle.reduce(sorted.map { $0.sha256 })
        return EvidenceManifestBody(
            caseID: caseID,
            caseName: caseName,
            engineVersion: engineVersion,
            sealedAt: CanonicalTimestamp.string(from: sealedAt),
            artifacts: sorted,
            artifactsMerkleRoot: root,
            artifactCount: sorted.count,
            custodyHead: custodyHead,
            custodyEntryCount: custodyEntryCount
        )
    }

    /// Seal a case: collect provenance, verify the supplied custody log,
    /// sign the canonical body, and write the envelope to
    /// `<case>/evidence_manifest.json`. Returns the written URL.
    @discardableResult
    public func seal(
        caseID: String,
        caseName: String,
        store: ArtifactStore,
        custodyLog: CustodyLog,
        layout: CaseDirectoryLayout,
        sealedAt: Date = Date()
    ) async throws -> URL {
        // Refuse to seal over a broken custody chain — a tamper-evident
        // log that's already broken must not be blessed with a signature.
        let head: String
        do { head = try custodyLog.verifyChain() }
        catch { throw CaseEvidenceError.custodyChainInvalid("\(error)") }

        let provenance = try await Self.collectProvenance(from: store, caseID: caseID)
        let body = Self.buildBody(
            caseID: caseID,
            caseName: caseName,
            sealedAt: sealedAt,
            provenance: provenance,
            custodyHead: head,
            custodyEntryCount: custodyLog.entries.count
        )
        return try await writeEnvelope(body: body, custodyLog: custodyLog, to: layout.evidenceManifestFile)
    }

    /// Sign `body` + embed the full custody log, then write the envelope.
    /// Split out so tests can seal a hand-built body without a live store.
    public func writeEnvelope(
        body: EvidenceManifestBody,
        custodyLog: CustodyLog,
        to url: URL
    ) async throws -> URL {
        let canonical = try body.canonicalBytes()
        let signature = try await substrate.sign(canonical)
        let publicKey = try await substrate.publicKey()

        // The custody log travels alongside the signed body so the
        // verifier can re-verify the chain AND confirm its head matches
        // the signed custody_head. The body (not the log) is signed; the
        // log is bound by signing its head.
        let custodyData = try JSONEncoder().encode(custodyLog)
        let custodyObj = try JSONSerialization.jsonObject(with: custodyData)

        let top: [String: Any] = [
            "schema_version": 1,
            "body": try JSONSerialization.jsonObject(with: canonical),
            "custody_log": custodyObj,
            "signature": signature.base64EncodedString(),
            "public_key_der": publicKey.derBytes.base64EncodedString(),
        ]

        let data: Data
        do {
            data = try JSONSerialization.data(
                withJSONObject: top, options: [.prettyPrinted, .sortedKeys]
            )
        } catch {
            throw CaseEvidenceError.writeFailed("serialize: \(error)")
        }
        do {
            try data.write(to: url, options: .atomic)
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o600], ofItemAtPath: url.path
            )
        } catch {
            throw CaseEvidenceError.writeFailed("write \(url.path): \(error)")
        }
        return url
    }

    // MARK: - Offline verification

    /// Result of verifying an evidence manifest.
    public struct VerifiedEvidence: Sendable, Equatable {
        public let body: EvidenceManifestBody
        public let custodyLog: CustodyLog
    }

    /// Verify a manifest at `url` offline using only its embedded key.
    /// When `expectedCaseID` is supplied, cross-binds the signed case_id
    /// (defeats lifting a valid envelope onto a different case directory).
    public static func verify(at url: URL, expectedCaseID: String? = nil) throws -> VerifiedEvidence {
        let data: Data
        do { data = try Data(contentsOf: url) }
        catch { throw CaseEvidenceError.readFailed("\(url.path): \(error)") }
        return try verify(data: data, expectedCaseID: expectedCaseID)
    }

    /// Verify envelope bytes directly. Checks, in order: signature over
    /// the canonical body, custody-chain integrity, and that the chain's
    /// head equals the signed custody_head (so the bundled log can't be
    /// swapped for a different-but-internally-valid one).
    public static func verify(data: Data, expectedCaseID: String? = nil) throws -> VerifiedEvidence {
        guard let top = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw CaseEvidenceError.malformed("not a JSON object")
        }
        guard let bodyObj = top["body"] else {
            throw CaseEvidenceError.malformed("missing 'body'")
        }
        guard let sigB64 = top["signature"] as? String,
              let signature = Data(base64Encoded: sigB64) else {
            throw CaseEvidenceError.malformed("missing/invalid 'signature'")
        }
        guard let keyB64 = top["public_key_der"] as? String,
              let pubDER = Data(base64Encoded: keyB64) else {
            throw CaseEvidenceError.malformed("missing/invalid 'public_key_der'")
        }
        guard let custodyObj = top["custody_log"] else {
            throw CaseEvidenceError.malformed("missing 'custody_log'")
        }

        // Decode the body, then re-canonicalize from the typed model so
        // verification is independent of the file's pretty-printing.
        let bodyData: Data
        do { bodyData = try JSONSerialization.data(withJSONObject: bodyObj) }
        catch { throw CaseEvidenceError.malformed("body not serializable: \(error)") }
        let body: EvidenceManifestBody
        do { body = try JSONDecoder().decode(EvidenceManifestBody.self, from: bodyData) }
        catch { throw CaseEvidenceError.malformed("body decode: \(error)") }

        if let expected = expectedCaseID, expected != body.caseID {
            throw CaseEvidenceError.caseIDMismatch(expected: expected, found: body.caseID)
        }

        let canonical = try body.canonicalBytes()

        // Signature over the canonical body, against the embedded key.
        let p256Key: P256.Signing.PublicKey
        do { p256Key = try P256.Signing.PublicKey(derRepresentation: pubDER) }
        catch { throw CaseEvidenceError.malformed("public key DER: \(error)") }
        let p256Sig: P256.Signing.ECDSASignature
        do { p256Sig = try P256.Signing.ECDSASignature(derRepresentation: signature) }
        catch { throw CaseEvidenceError.signatureInvalid }
        guard p256Key.isValidSignature(p256Sig, for: canonical) else {
            throw CaseEvidenceError.signatureInvalid
        }

        // Decode + re-verify the custody chain, then bind it to the
        // signed head.
        let custodyData: Data
        do { custodyData = try JSONSerialization.data(withJSONObject: custodyObj) }
        catch { throw CaseEvidenceError.malformed("custody_log not serializable: \(error)") }
        let custodyLog: CustodyLog
        do { custodyLog = try JSONDecoder().decode(CustodyLog.self, from: custodyData) }
        catch { throw CaseEvidenceError.malformed("custody_log decode: \(error)") }

        let head: String
        do { head = try custodyLog.verifyChain() }
        catch { throw CaseEvidenceError.custodyChainInvalid("\(error)") }
        guard head == body.custodyHead else {
            throw CaseEvidenceError.custodyChainInvalid(
                "custody head \(head) does not match signed custody_head \(body.custodyHead)"
            )
        }
        guard custodyLog.entries.count == body.custodyEntryCount else {
            throw CaseEvidenceError.custodyChainInvalid(
                "custody entry count \(custodyLog.entries.count) does not match signed count \(body.custodyEntryCount)"
            )
        }

        return VerifiedEvidence(body: body, custodyLog: custodyLog)
    }
}
