// EvidenceBundleExporter.swift
//
// Writes a `.maccrabevidence` bundle: a single, self-describing JSON document
// carrying case metadata + every committed artifact (id, content_type, summary,
// observed_at, privacy_class, sha256, data). Offline-verifiable — it carries a
// sha256 over the canonical artifacts payload so a recipient can detect
// tampering. Shared by `maccrabctl scan export` and `maccrabctl evidence export`
// so the two CLI entry points can't drift.

import Foundation
import CryptoKit
import MacCrabCore

public enum EvidenceBundleExporter {

    /// Render the bundle bytes for a case's artifacts. Pure (no I/O) so it's
    /// unit-testable; `export` wraps it with a file write.
    public static func render(
        caseID: String,
        artifacts: [CommittedArtifact],
        exportedAt: Date,
        appVersion: String,
        includeSensitive: Bool = false
    ) throws -> Data {
        let iso = ISO8601DateFormatter()
        let artifactObjs: [[String: Any]] = artifacts.map { a in
            // Privacy-class filter: only `metadata` is safe to serialize in
            // the clear. Every other class (content / personalComms /
            // credentialAdjacent / secret) carries body/payload data — and
            // summaries often embed it too (e.g. a FaceTime peer address) —
            // so redact both `data` and `summary` unless the operator
            // explicitly opts in with includeSensitive. Mirrors the codebase
            // invariant that only metadata is exposable without a grant.
            let redact = a.record.privacyClass != .metadata && !includeSensitive
            var o: [String: Any] = [
                "id": a.id,
                "content_type": a.record.contentType,
                "observed_at": iso.string(from: a.record.observedAt),
                "privacy_class": a.record.privacyClass.rawValue,
                "sha256": a.record.sha256,
            ]
            if let src = a.record.sourcePath { o["source_path"] = src }
            if redact {
                // Keep the envelope (type / hash / privacy_class) so the
                // export still attests the artifact EXISTS, without leaking
                // its content.
                o["redacted"] = true
            } else {
                if let s = a.record.summary { o["summary"] = s }
                if !a.record.data.isEmpty {
                    o["data"] = a.record.data.mapValues { $0.foundationValue }
                }
            }
            return o
        }
        // Canonical (sorted-keys) payload bytes → integrity hash.
        let payloadData = try JSONSerialization.data(withJSONObject: artifactObjs, options: [.sortedKeys])
        let payloadSHA = SHA256.hash(data: payloadData).map { String(format: "%02x", $0) }.joined()
        let bundle: [String: Any] = [
            "format": "maccrabevidence",
            "schema_version": 1,
            "case_id": caseID,
            "exported_at": iso.string(from: exportedAt),
            "app_version": appVersion,
            "artifact_count": artifacts.count,
            "artifacts_sha256": payloadSHA,
            "artifacts": artifactObjs,
        ]
        return try JSONSerialization.data(withJSONObject: bundle, options: [.prettyPrinted, .sortedKeys])
    }

    /// Render + write the bundle to `output` atomically. Returns the URL written.
    @discardableResult
    public static func export(
        caseID: String,
        artifacts: [CommittedArtifact],
        to output: URL,
        exportedAt: Date = Date(),
        appVersion: String = MacCrabVersion.current,
        includeSensitive: Bool = false
    ) throws -> URL {
        let data = try render(
            caseID: caseID,
            artifacts: artifacts,
            exportedAt: exportedAt,
            appVersion: appVersion,
            includeSensitive: includeSensitive
        )
        try data.write(to: output, options: .atomic)
        return output
    }

    /// Default output path for a case export: ~/Downloads/maccrab-evidence-<short>.maccrabevidence
    public static func defaultOutputURL(caseID: String) -> URL {
        let short = String(caseID.prefix(8))
        let downloads = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Downloads")
        return downloads.appendingPathComponent("maccrab-evidence-\(short).maccrabevidence")
    }
}
