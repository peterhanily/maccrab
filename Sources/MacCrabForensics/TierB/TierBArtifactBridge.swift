// TierBArtifactBridge — maps plugin-emitted TierBArtifactDTOs to host-stamped
// ArtifactRecords and commits them to the case store (Shape 2, Phase 2c).
//
// The HOST owns every authoritative field (Shape-2 attack-pass: a plugin must not
// be able to spoof which case/plugin an artifact belongs to, inflate its size, or
// path-traverse):
//   - caseID is the host's; pluginID/pluginVersion/schemaVersion come from the
//     VERIFIED manifest, NEVER the DTO (the DTO carries no identity).
//   - sha256 + sizeBytes are RECOMPUTED from the canonical content.
//   - sourcePath is recorded as untrusted free-text and NEVER opened host-side.
//   - blobs are NOT ingested in this MVP: blobRelpath is always nil and a
//     plugin-named scratch file is never opened (the riskiest IPC surface is
//     simply absent until a hardened BlobVault ingest lands; the hero is
//     all-metadata and needs no blobs).
//   - a non-metadata artifact in a plaintext case is rejected here with a clear
//     reason + count (belt-and-suspenders for the store's Pass-2026-D guard).

import Foundation
import CryptoKit

public enum TierBArtifactBridge {

    public enum MapResult: Sendable {
        case record(ArtifactRecord)
        case rejected(reason: String)
    }

    /// Pure map of one DTO → a host-stamped ArtifactRecord (or a rejection).
    public static func map(
        dto: TierBArtifactDTO,
        caseID: String,
        manifest: TierBManifest,
        caseAllowsSensitive: Bool,
        now: Date = Date()
    ) -> MapResult {
        let privacy = PrivacyClass(rawValue: dto.privacyClass) ?? .metadata
        if privacy != .metadata && !caseAllowsSensitive {
            return .rejected(reason: "non-metadata artifact (\(privacy.rawValue)) refused in a plaintext case")
        }
        let confidence = dto.confidence.flatMap { Confidence(rawValue: $0) } ?? .observed

        // Recompute content sha256 + sizeBytes from the canonical encoding — never
        // trust a wire value (the DTO carries none by design).
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let canonical = (try? encoder.encode(dto.data)) ?? Data()
        let sha = SHA256.hash(data: canonical).map { String(format: "%02x", $0) }.joined()
        let size = Int64(canonical.count) + Int64((dto.summary ?? "").utf8.count)
        let observed = dto.observedAtUnix.map { Date(timeIntervalSince1970: TimeInterval($0)) } ?? now
        let captured = dto.capturedAtUnix.map { Date(timeIntervalSince1970: TimeInterval($0)) } ?? now

        let record = ArtifactRecord(
            caseID: caseID,                          // HOST
            pluginID: manifest.id,                   // HOST (verified manifest, not DTO)
            pluginVersion: manifest.version,         // HOST
            schemaVersion: manifest.schemaVersion,   // HOST
            contentType: dto.contentType,
            sourcePath: dto.sourcePath,              // untrusted free-text; never opened
            sourceInode: nil,
            sourceMtime: nil,
            sha256: sha,                             // HOST recomputed
            blobRelpath: nil,                        // blobs not ingested in MVP
            observedAt: observed,
            capturedAt: captured,
            summary: dto.summary,
            sizeBytes: size,                         // HOST recomputed
            confidence: confidence,
            privacyClass: privacy,
            actor: manifest.id,
            data: dto.data
        )
        return .record(record)
    }

    /// Map + commit a runner outcome to the case store. Returns a CollectionResult
    /// (committed/rejected counts + a status derived from the plugin's terminal
    /// result, downgraded/errored on timeout / missing result / rejections).
    public static func commit(
        outcome: TierBRunOutcome,
        caseID: String,
        manifest: TierBManifest,
        caseAllowsSensitive: Bool,
        output: CollectorOutput,
        now: Date = Date()
    ) async -> CollectionResult {
        var committed = 0
        var rejected = 0
        var notes: [String] = []
        for dto in outcome.artifacts {
            switch map(dto: dto, caseID: caseID, manifest: manifest,
                       caseAllowsSensitive: caseAllowsSensitive, now: now) {
            case .record(let rec):
                do { _ = try await output.commit(rec); committed += 1 }
                catch { rejected += 1; notes.append("commit failed: \(error)") }
            case .rejected(let reason):
                rejected += 1
                notes.append(reason)
            }
        }
        var status: CollectionResult.ExitStatus
        if outcome.timedOut {
            status = .error; notes.append("plugin timed out")
        } else if let r = outcome.result {
            status = CollectionResult.ExitStatus(rawValue: r.status) ?? .error
            notes.append(contentsOf: r.notes)
        } else {
            status = .error; notes.append("plugin emitted no terminal result")
        }
        if outcome.stdoutTruncated { notes.append("plugin output truncated at a host cap") }
        if outcome.decodeErrors > 0 { notes.append("\(outcome.decodeErrors) malformed output line(s) dropped") }
        if status == .ok && rejected > 0 { status = .partial }
        return CollectionResult(
            artifactsCommitted: committed, artifactsRejected: rejected, notes: notes, status: status)
    }
}
