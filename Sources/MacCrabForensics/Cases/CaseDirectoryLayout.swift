// CaseDirectoryLayout — on-disk shape of a single case under
// `~/Library/Application Support/MacCrab/Cases/<case-id>/`.
//
// Plan reference: §3.4 per-case directory layout.

import Foundation

/// Resolves the canonical paths for a single case. CaseManager
/// uses this to construct + access on-disk artifacts; ArtifactStore
/// receives the resolved case.sqlite path directly.
public struct CaseDirectoryLayout: Sendable {

    /// Root for ALL cases. Default points to MacCrab's standard
    /// Application Support directory; tests override.
    public let casesRoot: URL

    /// Case id this layout targets.
    public let caseID: String

    public init(casesRoot: URL, caseID: String) {
        self.casesRoot = casesRoot
        self.caseID = caseID
    }

    public var caseDirectory: URL {
        casesRoot.appendingPathComponent(caseID, isDirectory: true)
    }

    /// SQLite database file (SQLCipher-encrypted unless the case
    /// was created as plaintext).
    public var sqliteFile: URL {
        caseDirectory.appendingPathComponent("case.sqlite", isDirectory: false)
    }

    /// Unencrypted manifest with the minimum metadata needed to
    /// list cases without unlocking — id, name, created_at,
    /// encryption_state. Plan §3.4: "operators need to see 'test
    /// case' / 'Tuesday review' without unlocking."
    public var manifestFile: URL {
        caseDirectory.appendingPathComponent("manifest.json", isDirectory: false)
    }

    /// Per-blob AES-GCM vault root. Layout:
    ///     vault/blobs/<first-2-hex-of-sha256>/<sha256>
    public var vaultRoot: URL {
        caseDirectory.appendingPathComponent("vault", isDirectory: true)
            .appendingPathComponent("blobs", isDirectory: true)
    }

    /// Snapshot directory — copied-then-frozen source DBs that
    /// Collectors parse from (TCC.db, BAM, etc., per plan §3.5).
    public var snapshotsRoot: URL {
        caseDirectory.appendingPathComponent("snapshots", isDirectory: true)
    }

    /// Append-only plain-text log of plugin invocations. The
    /// SQLite plugin_invocations table is the structured source
    /// of truth; this file is the human-readable mirror.
    public var invocationsLog: URL {
        caseDirectory.appendingPathComponent("invocations.log", isDirectory: false)
    }

    /// Per-case MCP audit log. Plan §10.4: every MCP tool
    /// invocation that touched non-metadata artifacts is logged
    /// here, in addition to the structured DB record.
    public var mcpAuditLog: URL {
        caseDirectory.appendingPathComponent("mcp_audit.log", isDirectory: false)
    }

    /// Resolve the file path for a blob keyed by sha256. Uses a
    /// 2-character prefix dir to keep directory fan-out
    /// manageable.
    public func blobPath(for sha256: String) -> URL {
        let prefix = String(sha256.prefix(2))
        return vaultRoot
            .appendingPathComponent(prefix, isDirectory: true)
            .appendingPathComponent(sha256, isDirectory: false)
    }

    /// `vault/blobs/<prefix>/<sha256>` relative to caseDirectory.
    /// Stored in `artifacts.blob_relpath` so the JSON payload
    /// stays portable across case moves.
    public func blobRelpath(for sha256: String) -> String {
        let prefix = String(sha256.prefix(2))
        return "vault/blobs/\(prefix)/\(sha256)"
    }

    /// Standard MacCrab Application Support cases root. Equivalent
    /// to `~/Library/Application Support/MacCrab/Cases/`.
    public static var defaultCasesRoot: URL {
        let fm = FileManager.default
        let appSupport = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support")
        return appSupport
            .appendingPathComponent("MacCrab", isDirectory: true)
            .appendingPathComponent("Cases", isDirectory: true)
    }

    /// Create the case directory + subdirectories with restrictive
    /// permissions. Idempotent: existing directories are accepted.
    /// Plan §10.4: case storage is sensitive; chmod 0700 keeps
    /// other users on shared Macs out.
    public func createDirectoryStructure() throws {
        let fm = FileManager.default
        try fm.createDirectory(
            at: caseDirectory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try fm.createDirectory(
            at: vaultRoot,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try fm.createDirectory(
            at: snapshotsRoot,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
    }
}

/// Unencrypted manifest written to manifest.json. Lets case
/// listing operate without unlocking individual cases. Contains
/// only non-sensitive metadata; ai_content_allowed and
/// scheduled_trusted stay in the encrypted store proper because
/// flipping them requires unlock anyway.
public struct CaseManifest: Codable, Sendable {
    public let id: String
    public let name: String
    public let createdAtMillis: Int64
    public let encryptionState: CaseEncryptionState
    public let schemaVersion: Int

    public init(
        id: String,
        name: String,
        createdAt: Date,
        encryptionState: CaseEncryptionState,
        schemaVersion: Int = 1
    ) {
        self.id = id
        self.name = name
        self.createdAtMillis = Int64(createdAt.timeIntervalSince1970 * 1000)
        self.encryptionState = encryptionState
        self.schemaVersion = schemaVersion
    }

    public var createdAt: Date {
        Date(timeIntervalSince1970: Double(createdAtMillis) / 1000)
    }
}
