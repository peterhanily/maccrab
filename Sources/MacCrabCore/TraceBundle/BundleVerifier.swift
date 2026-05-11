// BundleVerifier.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-10c) — tamper-evidence verification per §19 of
// the v1.10.0 spec. Distinct from `BundleValidator` — see §18.9:
//
//   validate → structural conformance to the bundle schemas
//   verify   → tamper-evidence (hash chain + signature + optional log anchor)
//
// Verification pipeline (closes the §18.9 exit codes left by
// BundleValidator):
//
//   1. Run BundleValidator first. Any failure short-circuits the verify
//      with the validator's outcome.
//   2. Recompute the canonical artifact Merkle root from on-disk
//      contents via BundleMerkle.compute. Mismatch → exit 2.
//   3. Verify chain_head_signature.signature_base64 against the
//      Merkle root using the bundled public key
//      (integrity/trace-signing.pub). Failure → exit 3.
//   4. (optional) Query the unified-log anchor for the matching
//      chain head record. Missing → exit 4 (only when --check-unified-log
//      was requested explicitly).
//
// Verification is pure-functional: no actor, no daemon dependency.
// Third-party readers in any language can mirror this logic against
// the bundled public key and the published Merkle reduction.

import Foundation
import CryptoKit

public enum BundleVerifier {

    public struct Options: Sendable {
        public var checkUnifiedLog: Bool = false
        /// How wide a window around the bundle's `chain_head_signature.signed_at`
        /// to query for the unified-log anchor. Default ±5 minutes — generous
        /// enough to absorb clock drift between the daemon and the verifier.
        public var unifiedLogWindowSeconds: TimeInterval = 300

        public init() {}
    }

    public static func verify(
        at directory: URL,
        unifiedLogAnchor: UnifiedLogAnchor? = nil,
        options: Options = Options()
    ) async -> BundleValidator.Outcome {
        // Step 1: structural validation
        let validatorOutcome = BundleValidator.validate(at: directory)
        guard validatorOutcome.exitCode == 0 else {
            return validatorOutcome
        }

        // Step 2: recompute Merkle root, compare to stored
        let computation: BundleMerkle.Computation
        do {
            computation = try BundleMerkle.compute(forBundleAt: directory)
        } catch {
            return BundleValidator.Outcome(
                exitCode: 9,
                kind: .internalError("Merkle recomputation failed: \(error)")
            )
        }
        let chainURL = directory.appendingPathComponent("integrity/hash_chain.json")
        let storedChain: HashChainArtifact
        do {
            let data = try Data(contentsOf: chainURL)
            storedChain = try canonicalJSONDecoder().decode(HashChainArtifact.self, from: data)
        } catch {
            return BundleValidator.Outcome(
                exitCode: 1,
                kind: .schemaInvalid("integrity/hash_chain.json failed to decode at verify time: \(error)")
            )
        }
        if storedChain.merkleRoot != computation.merkleRoot {
            return BundleValidator.Outcome(
                exitCode: 2,
                kind: .schemaInvalid(
                    "Merkle root mismatch: bundled \(storedChain.merkleRoot) != recomputed \(computation.merkleRoot)"
                ),
                messages: [
                    "Bundled artifact list claims root \(storedChain.merkleRoot)",
                    "Recomputed root from on-disk contents: \(computation.merkleRoot)",
                    "This indicates the bundle has been modified since signing.",
                ]
            )
        }
        // Cross-check: stored artifact list must agree with the recomputed
        // list (per-artifact + ordering). If it doesn't, an attacker
        // tampered with hash_chain.json itself rather than the artifacts.
        if storedChain.artifacts.map({ $0.path }) != computation.artifacts.map({ $0.path }) {
            return BundleValidator.Outcome(
                exitCode: 2,
                kind: .schemaInvalid("hash_chain.json artifact list does not match the on-disk artifacts")
            )
        }
        for (stored, computed) in zip(storedChain.artifacts, computation.artifacts) {
            if stored.sha256 != computed.sha256 {
                return BundleValidator.Outcome(
                    exitCode: 2,
                    kind: .schemaInvalid(
                        "hash mismatch on \(stored.path): bundled \(stored.sha256) != computed \(computed.sha256)"
                    )
                )
            }
        }

        // Step 3: signature
        let sigURL = directory.appendingPathComponent("integrity/chain_head_signature.json")
        let signature: ChainHeadSignatureArtifact
        do {
            let data = try Data(contentsOf: sigURL)
            signature = try canonicalJSONDecoder().decode(ChainHeadSignatureArtifact.self, from: data)
        } catch {
            return BundleValidator.Outcome(
                exitCode: 1,
                kind: .schemaInvalid("integrity/chain_head_signature.json failed to decode at verify time: \(error)")
            )
        }

        // Honest "UNSIGNED" sentinel from a placeholder bundle (e.g. PR-10b
        // tests) → fail with exit 3. The bundle isn't claiming verification
        // and we won't fake one.
        if signature.signatureBase64 == "UNSIGNED" {
            return BundleValidator.Outcome(
                exitCode: 3,
                kind: .schemaInvalid("bundle signature is the UNSIGNED placeholder — bundle was exported without a TrustSubstrate"),
                messages: ["chain_head_signature.signature_base64 == 'UNSIGNED'"]
            )
        }

        // Verify the signature against the Merkle root using the
        // bundled public key. Self-contained — no daemon needed.
        let pubKeyURL = directory.appendingPathComponent("integrity/trace-signing.pub")
        guard FileManager.default.fileExists(atPath: pubKeyURL.path) else {
            return BundleValidator.Outcome(
                exitCode: 3,
                kind: .schemaInvalid("integrity/trace-signing.pub missing — cannot verify signature")
            )
        }
        let pubKeyDER: Data
        do {
            pubKeyDER = try Data(contentsOf: pubKeyURL)
        } catch {
            return BundleValidator.Outcome(
                exitCode: 9,
                kind: .internalError("could not read integrity/trace-signing.pub: \(error)")
            )
        }
        // Cross-check: bundled public key fingerprint matches what the
        // signature artifact claims. If not, somebody swapped the key.
        let computedFingerprint = SHA256.hash(data: pubKeyDER).map { String(format: "%02x", $0) }.joined()
        if computedFingerprint != signature.signingKeyFingerprint {
            return BundleValidator.Outcome(
                exitCode: 3,
                kind: .schemaInvalid(
                    "bundled public key fingerprint (\(computedFingerprint)) does not match chain_head_signature.signing_key_fingerprint (\(signature.signingKeyFingerprint))"
                )
            )
        }
        // ECDSA P-256 SHA-256 verification via CryptoKit.
        let p256Key: P256.Signing.PublicKey
        do {
            p256Key = try P256.Signing.PublicKey(derRepresentation: pubKeyDER)
        } catch {
            return BundleValidator.Outcome(
                exitCode: 3,
                kind: .schemaInvalid("bundled public key DER could not be parsed: \(error)")
            )
        }
        guard let signatureBytes = Data(base64Encoded: signature.signatureBase64) else {
            return BundleValidator.Outcome(
                exitCode: 3,
                kind: .schemaInvalid("signature_base64 is not valid base64")
            )
        }
        let p256Signature: P256.Signing.ECDSASignature
        do {
            p256Signature = try P256.Signing.ECDSASignature(derRepresentation: signatureBytes)
        } catch {
            return BundleValidator.Outcome(
                exitCode: 3,
                kind: .schemaInvalid("signature is not valid DER ECDSA: \(error)")
            )
        }
        // Sign-payload is the Merkle root bytes (UTF-8 of the hex string).
        // Both the exporter and the verifier sign the same canonical
        // bytes; this keeps the contract simple and human-inspectable.
        let payload = Data(signature.merkleRoot.utf8)
        guard p256Key.isValidSignature(p256Signature, for: payload) else {
            return BundleValidator.Outcome(
                exitCode: 3,
                kind: .schemaInvalid("signature does not verify against bundled public key")
            )
        }

        // Step 4: optional unified-log anchor
        if options.checkUnifiedLog {
            guard let anchor = unifiedLogAnchor else {
                return BundleValidator.Outcome(
                    exitCode: 4,
                    kind: .schemaInvalid("--check-unified-log requested but no UnifiedLogAnchor available")
                )
            }
            let window = TimeWindow(
                start: signature.signedAt.addingTimeInterval(-options.unifiedLogWindowSeconds),
                end: signature.signedAt.addingTimeInterval(options.unifiedLogWindowSeconds)
            )
            let record: UnifiedLogChainHeadRecord?
            do {
                record = try await anchor.findChainHead(
                    merkleRoot: signature.merkleRoot,
                    within: window
                )
            } catch {
                return BundleValidator.Outcome(
                    exitCode: 9,
                    kind: .internalError("unified log query failed: \(error)")
                )
            }
            guard let record else {
                return BundleValidator.Outcome(
                    exitCode: 4,
                    kind: .schemaInvalid(
                        "no matching chain head record found in unified log for Merkle root \(signature.merkleRoot)"
                    ),
                    messages: ["Per §19.4: when unified-log records are unavailable, this is a degraded-verification warning — re-run without --check-unified-log to proceed."]
                )
            }
            // Sanity: anchor's signature matches the bundle's signature.
            if record.signatureBase64 != signature.signatureBase64 {
                return BundleValidator.Outcome(
                    exitCode: 4,
                    kind: .schemaInvalid(
                        "unified log chain head signature differs from bundled signature"
                    )
                )
            }
        }

        return BundleValidator.Outcome(exitCode: 0, kind: .valid)
    }
}
