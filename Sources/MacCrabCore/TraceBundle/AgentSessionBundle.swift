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

    public enum BundleError: Swift.Error, CustomStringConvertible {
        case directoryExists(URL)
        case malformedSignature
        public var description: String {
            switch self {
            case .directoryExists(let u): return "bundle directory already exists: \(u.path)"
            case .malformedSignature: return "integrity/signature.json missing or malformed"
            }
        }
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
        let fm = FileManager.default
        if fm.fileExists(atPath: bundleDir.path) { throw BundleError.directoryExists(bundleDir) }
        try fm.createDirectory(at: bundleDir.appendingPathComponent("integrity"),
                               withIntermediateDirectories: true)

        let eventsBlob = eventsJsonl.isEmpty ? "" : eventsJsonl.joined(separator: "\n") + "\n"
        try Data(eventsBlob.utf8).write(to: bundleDir.appendingPathComponent("events.jsonl"))
        try Data(alertsJson.utf8).write(to: bundleDir.appendingPathComponent("alerts.json"))
        try Data(mutationsJson.utf8).write(to: bundleDir.appendingPathComponent("mutations.json"))
        try Data(toolCallsJson.utf8).write(to: bundleDir.appendingPathComponent("tool_calls.json"))
        try Data(metadataJson.utf8).write(to: bundleDir.appendingPathComponent("manifest.json"))

        // Merkle root over the content files (integrity/ is excluded).
        let merkleRoot = try BundleMerkle.compute(forBundleAt: bundleDir).merkleRoot

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
        try sigData.write(to: bundleDir.appendingPathComponent("integrity/signature.json"))

        return ExportResult(bundleDir: bundleDir, merkleRoot: merkleRoot, signed: signed, keyMode: keyMode, signError: signError)
    }

    /// Verify a session bundle: recompute the Merkle root over the content
    /// (detects any tamper) and verify the signature over the signed root.
    public static func verify(at bundleDir: URL, trustSubstrate: TrustSubstrate?) async throws -> VerifyResult {
        let sigURL = bundleDir.appendingPathComponent("integrity/signature.json")
        guard let sigData = try? Data(contentsOf: sigURL),
              let obj = try? JSONSerialization.jsonObject(with: sigData) as? [String: Any],
              let storedRoot = obj["merkle_root"] as? String else {
            throw BundleError.malformedSignature
        }
        let recomputed = try BundleMerkle.compute(forBundleAt: bundleDir).merkleRoot
        let merkleOk = (recomputed == storedRoot)

        let signed = (obj["signed"] as? Bool) ?? false
        var signatureOk = false
        if signed, let ts = trustSubstrate,
           let hex = obj["signature_hex"] as? String, let sigBytes = hexData(hex) {
            signatureOk = (try? await ts.verify(Data(storedRoot.utf8), signature: sigBytes)) ?? false
        }
        return VerifyResult(merkleOk: merkleOk, signed: signed, signatureOk: signatureOk)
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
