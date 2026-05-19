// Errors emitted by ArtifactStore. The store is the single writer
// for `artifacts`, `artifact_data`, and `plugin_invocations`
// (audit Pass 2026-B); every commit failure routes through one of
// these errors so callers can react uniformly.
//
// Plan reference: §3.4, §3.8 audit Pass 2026-B + 2026-D.

import Foundation

public enum ArtifactStoreError: Error, CustomStringConvertible {

    /// `sqlite3_open` failed at the C-API level.
    case openFailed(message: String, code: Int32)

    /// SQLCipher's `PRAGMA key` failed — typically wrong DEK or
    /// corrupted header. Surfaces to the operator as "case unlock
    /// failed; check your password / keychain."
    case keyApplicationFailed(message: String)

    /// Schema migration failed midway. The store falls back to
    /// returning this error rather than leaving the DB at an
    /// inconsistent intermediate version.
    case migrationFailed(fromVersion: Int, toVersion: Int, message: String)

    /// `sqlite3_prepare_v2` / `sqlite3_step` returned non-OK.
    case stepFailed(operation: String, message: String, code: Int32)

    /// **Pass 2026-D invariant** — a non-metadata-class artifact
    /// was offered to a plaintext case. The store rejects at
    /// INSERT time rather than letting the row settle on disk.
    /// Plan §3.4 + §3.8 enforce this; the audit script also scans
    /// every plugin manifest at build time to surface the same
    /// invariant ahead of runtime.
    case plaintextCaseRejectsNonMetadata(
        contentType: String,
        privacyClass: PrivacyClass
    )

    /// The case id named on an artifact / invocation row doesn't
    /// match any row in `cases`. Always a programming error in the
    /// caller — the runtime guarantees CaseContext only carries
    /// valid case ids.
    case unknownCase(caseID: String)

    /// JSON serialization of a JSON1 payload failed. Implies the
    /// caller is committing a non-Codable structure.
    case jsonSerializationFailed(message: String)

    /// FTS5 / index creation failed. Non-fatal for commit — the
    /// store retains the rows; the caller may log and continue.
    case auxiliaryStructureFailed(message: String)

    public var description: String {
        switch self {
        case .openFailed(let msg, let code):
            return "ArtifactStore open failed (sqlite3 code \(code)): \(msg)"
        case .keyApplicationFailed(let msg):
            return "ArtifactStore key application failed: \(msg)"
        case .migrationFailed(let from, let to, let msg):
            return "ArtifactStore migration \(from) -> \(to) failed: \(msg)"
        case .stepFailed(let op, let msg, let code):
            return "ArtifactStore \(op) failed (sqlite3 code \(code)): \(msg)"
        case .plaintextCaseRejectsNonMetadata(let ct, let pc):
            return "ArtifactStore Pass 2026-D: plaintext case rejected \(pc.rawValue)-class artifact (contentType=\(ct))"
        case .unknownCase(let id):
            return "ArtifactStore unknown case id \(id)"
        case .jsonSerializationFailed(let msg):
            return "ArtifactStore JSON serialization failed: \(msg)"
        case .auxiliaryStructureFailed(let msg):
            return "ArtifactStore auxiliary structure failed: \(msg)"
        }
    }
}
