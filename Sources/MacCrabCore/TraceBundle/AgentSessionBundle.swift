// AgentSessionBundle — Wave-3 Phase 3.
//
// A signed, Merkle-rooted, tamper-evident export of one agent session's
// three rails (events / alerts / mutations) — the "replayable black box"
// for an AI-coding session. Reuses the shipped crypto primitives
// (BundleMerkle for the content hash tree, TrustSubstrate for ECDSA-P256
// signing) rather than the trace-graph BundleExporter, because a session
// is a flat timeline, not a causal trace graph.
//
// Layout:
//   <dir>/manifest.json        session metadata
//   <dir>/events.jsonl         the proc/file/net timeline (one JSON/line)
//   <dir>/alerts.json          alerts tied to the session
//   <dir>/mutations.json       mutations the agent made
//   <dir>/integrity/signature.json   merkle_root + ECDSA signature
//
// The content files are hashed into the Merkle root; the signature lives
// under integrity/ which BundleMerkle.compute excludes by convention, so
// the root is stable across sign + verify.

import Foundation
import CryptoKit

public enum AgentSessionBundle {

    public enum BundleError: Swift.Error, CustomStringConvertible, LocalizedError {
        case directoryExists(URL)
        case partialBundle(URL, String)
        case committedBundle(URL, String)
        case exportFailed(String)
        case malformedSignature
        public var description: String {
            switch self {
            case .directoryExists(let u): return "bundle directory already exists: \(u.path)"
            case .partialBundle(let u, let detail): return "partial session bundle retained at \(u.path): \(detail)"
            case .committedBundle(let u, let detail): return "complete session bundle committed at \(u.path), but durability/postflight failed: \(detail)"
            case .exportFailed(let detail): return "session bundle export failed: \(detail)"
            case .malformedSignature: return "integrity/signature.json missing or malformed"
            }
        }

        public var errorDescription: String? { description }
    }

    public struct ExportResult: Sendable {
        public let bundleDir: URL
        public let merkleRoot: String
        public let signed: Bool
        public let keyMode: String
        /// Set when signing was attempted but failed — surfaced instead of
        /// silently swallowed, so an unsigned (forgeable) bundle is never
        /// mistaken for a signed one.
        public let signError: String?
    }

    public struct VerifyResult: Sendable {
        public let merkleOk: Bool      // content matches the signed root
        public let signed: Bool        // a signature was present
        public let signatureOk: Bool   // signature verifies (false when unsigned)
        /// SHA-256 of the public-key DER that actually verified the signature.
        /// For an invalid/unsigned bundle this falls back to the fingerprint
        /// claimed by signature.json so callers can still diagnose the input.
        public let signerFingerprint: String
        /// True only when that fingerprint is THIS install's own key. A valid
        /// signature from an unknown key is not the same fact as a signature
        /// from a key you trust, and callers must report them separately.
        public let signerIsLocalInstall: Bool
        /// True only when the verified signing key is authenticated by the
        /// caller's trust policy: this install's key by default, or an explicit
        /// out-of-band pinned fingerprint when VerifyOptions supplies one.
        public let signerTrusted: Bool

        /// Cryptographic integrity is necessary but not sufficient here. The
        /// embedded public key lives beside the signature, so any attacker can
        /// rewrite the content and re-sign it with a new self-generated key.
        /// Only a trusted signer turns a self-consistent bundle into
        /// authenticated evidence.
        public var authenticated: Bool {
            merkleOk && signed && signatureOk && signerTrusted
        }
    }

    /// Trust policy for session verification. This mirrors
    /// BundleVerifier.Options.pinnedKeyFingerprint: the pin is an EXTERNAL
    /// trust anchor, never a value learned from the bundle being verified.
    public struct VerifyOptions: Sendable {
        public var pinnedKeyFingerprint: String?

        public init(pinnedKeyFingerprint: String? = nil) {
            self.pinnedKeyFingerprint = pinnedKeyFingerprint
        }
    }

    /// Write a signed session bundle. Content is supplied pre-serialized so
    /// this stays store-agnostic and unit-testable.
    @discardableResult
    public static func export(
        sessionId: String,
        eventsJsonl: [String],
        alertsJson: String,
        mutationsJson: String,
        metadataJson: String,
        toolCallsJson: String = "[]",
        to bundleDir: URL,
        trustSubstrate: TrustSubstrate?
    ) async throws -> ExportResult {
        let workspace: BundleExportWorkspace
        do {
            workspace = try BundleExportWorkspace.create(at: bundleDir)
        } catch let error as BundleExportWorkspace.WorkspaceError {
            if case .destinationExists = error {
                throw BundleError.directoryExists(bundleDir)
            }
            throw BundleError.exportFailed(error.localizedDescription)
        }

        do {
        try workspace.createDirectory("integrity")
        let eventsBlob = eventsJsonl.isEmpty ? "" : eventsJsonl.joined(separator: "\n") + "\n"
        try workspace.writeNew(Data(eventsBlob.utf8), to: "events.jsonl")
        try workspace.writeNew(Data(alertsJson.utf8), to: "alerts.json")
        try workspace.writeNew(Data(mutationsJson.utf8), to: "mutations.json")
        try workspace.writeNew(Data(toolCallsJson.utf8), to: "tool_calls.json")
        try workspace.writeNew(Data(metadataJson.utf8), to: "manifest.json")

        // Merkle root over the content files (integrity/ is excluded).
        let merkleRoot = BundleMerkle.compute(
            exportArtifacts: try workspace.snapshotArtifacts(
                excludingRootIntegrity: true
            )
        ).merkleRoot

        var signed = false
        var keyMode = "unsigned"
        var signatureHex = ""
        var fingerprint = ""
        var signError: String? = nil
        if let ts = trustSubstrate {
            do {
                let sigBytes = try await ts.sign(Data(merkleRoot.utf8))
                signatureHex = sigBytes.map { String(format: "%02x", $0) }.joined()
                signed = true
                keyMode = ((try? await ts.activeMode())?.rawValue) ?? "unknown"
                fingerprint = (try? await ts.publicKeyFingerprint()) ?? ""
                // Ship the SIGNER's public key with the bundle. Without it a
                // recipient has nothing to verify against: `verify` below used
                // to consult only the VERIFYING install's own key, so a
                // perfectly intact bundle opened on any other Mac came back
                // "TAMPERED / invalid" — a false tamper accusation on evidence,
                // in a tool that advertises `verify_with:` as a share step.
                // integrity/ is excluded from the Merkle root by BundleMerkle
                // convention, so this file does not perturb the signed root.
                if let pub = try? await ts.publicKey() {
                    try? workspace.writeNew(
                        pub.derBytes,
                        to: "integrity/session-signing.pub"
                    )
                }
            } catch {
                // Do NOT swallow: an unsigned bundle is forgeable, so the
                // failure must reach the caller (e.g. Secure-Enclave path
                // -34018 in an unentitled process — callers should force
                // .filesystemDegraded).
                signError = "\(error)"
            }
        }

        let sig: [String: Any] = [
            "session_id": sessionId,
            "merkle_root": merkleRoot,
            "signed": signed,
            "signature_hex": signatureHex,
            "key_mode": keyMode,
            "public_key_fingerprint": fingerprint,
        ]
        let sigData = try JSONSerialization.data(withJSONObject: sig, options: [.sortedKeys, .prettyPrinted])
        try workspace.writeNew(sigData, to: "integrity/signature.json")

        let publishedURL = try workspace.publish()
        return ExportResult(bundleDir: publishedURL, merkleRoot: merkleRoot, signed: signed, keyMode: keyMode, signError: signError)
        } catch let error as BundleError {
            throw error
        } catch {
            if let workspaceError = error as? BundleExportWorkspace.WorkspaceError,
               case .committedBundle(let url, let detail) = workspaceError {
                throw BundleError.committedBundle(url, detail)
            }
            if let committed = workspace.committedOrPublishedURLIfStillOwned {
                throw BundleError.committedBundle(
                    committed,
                    error.localizedDescription
                )
            }
            if let partial = workspace.diagnosticPartialURLIfStillOwned {
                throw BundleError.partialBundle(partial, error.localizedDescription)
            }
            throw BundleError.exportFailed(error.localizedDescription)
        }
    }

    /// Verify a session bundle: recompute the Merkle root over the content
    /// (detects any tamper) and verify the signature over the signed root.
    public static func verify(
        at bundleDir: URL,
        trustSubstrate: TrustSubstrate?,
        options: VerifyOptions = VerifyOptions()
    ) async throws -> VerifyResult {
        let resolution = try SafeTraceBundleResolver.resolve(inputAt: bundleDir)
        defer { resolution.cleanup() }
        return try await verify(
            resolvedBundle: resolution,
            trustSubstrate: trustSubstrate,
            options: options
        )
    }

    /// Verify a session bundle from the caller's single owned snapshot.
    public static func verify(
        resolvedBundle resolution: SafeTraceBundleResolver.Resolution,
        trustSubstrate: TrustSubstrate?,
        options: VerifyOptions = VerifyOptions()
    ) async throws -> VerifyResult {
        guard let sigData = resolution.dataIfPresent(
                  at: "integrity/signature.json"
              ),
              let obj = try? JSONSerialization.jsonObject(with: sigData) as? [String: Any],
              let storedRoot = obj["merkle_root"] as? String else {
            throw BundleError.malformedSignature
        }
        let recomputed = BundleMerkle.compute(resolvedBundle: resolution).merkleRoot
        let merkleOk = (recomputed == storedRoot)

        let signed = (obj["signed"] as? Bool) ?? false
        let recordedFingerprint = (obj["public_key_fingerprint"] as? String) ?? ""
        var signerFingerprint = recordedFingerprint
        var signatureOk = false
        var signerIsLocalInstall = false
        var signerTrusted = false
        if signed, let hex = obj["signature_hex"] as? String, let sigBytes = hexData(hex) {
            let signedBytes = Data(storedRoot.utf8)
            // Verify against the key the BUNDLE ships, not the verifying host's
            // own key. Pre-fix this called ts.verify(), which resolves THIS
            // install's public key, so a foreign signature could never validate
            // and every intact bundle from another Mac was reported as tampered.
            // The embedded key is cross-checked against the fingerprint recorded
            // in signature.json so the two cannot disagree silently.
            if resolution.containsArtifact("integrity/session-signing.pub") {
                // Never fall back to a local key when a bundle DOES carry an
                // embedded key but that key is malformed or disagrees with its
                // claimed fingerprint. That would blur two different signer
                // identities and could accidentally bless corrupted metadata.
                if let der = resolution.dataIfPresent(
                    at: "integrity/session-signing.pub"
                ) {
                    let computedFingerprint = SHA256.hash(data: der)
                        .map { String(format: "%02x", $0) }.joined()
                    if computedFingerprint == recordedFingerprint,
                       let embedded = try? P256.Signing.PublicKey(derRepresentation: der),
                       let parsed = try? P256.Signing.ECDSASignature(derRepresentation: sigBytes) {
                        signatureOk = embedded.isValidSignature(parsed, for: signedBytes)
                        if signatureOk { signerFingerprint = computedFingerprint }
                    }
                }
            } else if let ts = trustSubstrate {
                // Bundles exported before the key was embedded carry no .pub —
                // fall back to the local substrate, which is the correct key for
                // the host that produced them.
                signatureOk = (try? await ts.verify(signedBytes, signature: sigBytes)) ?? false
                if signatureOk, let localFingerprint = try? await ts.publicKeyFingerprint() {
                    // For legacy bundles the claim in signature.json is not a
                    // trustworthy identity. Use the key that actually verified.
                    signerFingerprint = localFingerprint
                }
            }

            if signatureOk {
                // "Signature valid" and "signed by a key this host trusts" are
                // different facts. The bundle-provided key proves only
                // self-consistency; authentication needs a key identity that
                // came from outside the bundle.
                if let ts = trustSubstrate,
                   let localFingerprint = try? await ts.publicKeyFingerprint() {
                    signerIsLocalInstall = (localFingerprint == signerFingerprint)
                }
                if options.pinnedKeyFingerprint != nil {
                    // An explicit pin is a constraint: when supplied it, not
                    // the local-install key, defines the expected signer. A
                    // malformed pin fails closed rather than silently falling
                    // back to the local key.
                    signerTrusted = normalizedFingerprint(options.pinnedKeyFingerprint)
                        .map { $0 == signerFingerprint } ?? false
                } else {
                    signerTrusted = signerIsLocalInstall
                }
            }
        }
        return VerifyResult(
            merkleOk: merkleOk,
            signed: signed,
            signatureOk: signatureOk,
            signerFingerprint: signerFingerprint,
            signerIsLocalInstall: signerIsLocalInstall,
            signerTrusted: signerTrusted
        )
    }

    private static func normalizedFingerprint(_ raw: String?) -> String? {
        guard let raw else { return nil }
        let candidate = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard candidate.count == 64,
              candidate.allSatisfy({ $0.isHexDigit }) else { return nil }
        return candidate
    }

    private static func hexData(_ hex: String) -> Data? {
        guard hex.count % 2 == 0 else { return nil }
        var out = Data(capacity: hex.count / 2)
        var idx = hex.startIndex
        while idx < hex.endIndex {
            let next = hex.index(idx, offsetBy: 2)
            guard let byte = UInt8(hex[idx..<next], radix: 16) else { return nil }
            out.append(byte)
            idx = next
        }
        return out
    }
}
