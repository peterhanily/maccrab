// LiveDBSnapshot — atomically copies an actively-written SQLite
// database into the per-case snapshots/ directory so the parsing
// plugin operates on a frozen image.
//
// Plan reference: §3.5 — "for plugins reading live application
// databases (TCC.db, chat.db, Mail Index, BAM): copy source DB +
// WAL + SHM atomically into <case>/snapshots/<sha256>.db. record
// snapshot_hash in plugin_invocations. open snapshot read-only;
// parse from snapshot only."
//
// Implementation note: we use SQLite's backup API
// (sqlite3_backup_init/step/finish), not a raw filesystem copy.
// The backup API drains the WAL into the destination as part of
// the copy, so the resulting file is internally consistent even
// while tccd / the BAM daemon are writing the source. A raw
// `cp source.db dest.db` would miss WAL-resident pages and could
// land a torn read.

import Foundation
import CSQLCipher
import CryptoKit

public enum LiveDBSnapshotError: Error, CustomStringConvertible {
    case sourceMissing(path: String)
    case openSourceFailed(message: String, code: Int32)
    case openDestFailed(message: String, code: Int32)
    case backupInitFailed(message: String)
    case backupStepFailed(message: String, code: Int32)
    case renameFailed(message: String)

    public var description: String {
        switch self {
        case .sourceMissing(let p): return "LiveDBSnapshot: source database missing at \(p)"
        case .openSourceFailed(let m, let c): return "LiveDBSnapshot: open source failed (\(c)): \(m)"
        case .openDestFailed(let m, let c): return "LiveDBSnapshot: open destination failed (\(c)): \(m)"
        case .backupInitFailed(let m): return "LiveDBSnapshot: sqlite3_backup_init failed: \(m)"
        case .backupStepFailed(let m, let c): return "LiveDBSnapshot: sqlite3_backup_step failed (\(c)): \(m)"
        case .renameFailed(let m): return "LiveDBSnapshot: rename failed: \(m)"
        }
    }
}

/// Result of a successful snapshot.
public struct LiveDBSnapshotResult: Sendable {
    /// Final on-disk path of the snapshot inside the case's
    /// `snapshots/` directory. Filename is `<sha256>.db`.
    public let path: URL

    /// SHA-256 of the snapshot file. Doubles as the
    /// `plugin_invocations.snapshot_hash` value and the filename.
    public let sha256: String

    /// Size in bytes of the snapshot file. Useful for retention /
    /// disk-budget enforcement.
    public let sizeBytes: Int64
}

public enum LiveDBSnapshot {

    /// Snapshot a live SQLite database into the case's snapshots/
    /// directory. Source is opened read-only. Destination is built
    /// at a temp path first, then renamed to `<sha256>.db` so a
    /// crash mid-copy can't leave a half-baked file.
    public static func snapshot(
        sourcePath: String,
        layout: CaseDirectoryLayout
    ) throws -> LiveDBSnapshotResult {

        guard FileManager.default.fileExists(atPath: sourcePath) else {
            throw LiveDBSnapshotError.sourceMissing(path: sourcePath)
        }

        // Ensure the snapshots/ dir exists. It's normally created by
        // CaseDirectoryLayout.createDirectoryStructure() at case
        // creation, but accept that a case may have been created
        // before this code path landed (forward-compat shim).
        try FileManager.default.createDirectory(
            at: layout.snapshotsRoot,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )

        // Temp destination — written first, then renamed.
        let tempName = "snapshot-inprogress-\(UUID().uuidString).db"
        let tempURL = layout.snapshotsRoot.appendingPathComponent(tempName)
        defer {
            // If we exit via error, clean up the half-finished temp
            // file. If we exit via success, the file's been renamed
            // already and this is a no-op.
            try? FileManager.default.removeItem(at: tempURL)
        }

        // v1.16.0-rc.18: serialize the sqlite3_open + backup
        // window via the shared CSQLCipherInitGate. Resolves the
        // parallel-test race that previously forced 3
        // LiveDBSnapshot tests to @Test(.disabled).
        try CSQLCipherInitGate.withLock {
            var srcDB: OpaquePointer?
            let srcOpen = sqlite3_open_v2(
                sourcePath,
                &srcDB,
                SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX,
                nil
            )
            guard srcOpen == SQLITE_OK, let src = srcDB else {
                let msg = srcDB.map { String(cString: sqlite3_errmsg($0)) } ?? "sqlite3_open returned \(srcOpen)"
                if let s = srcDB { sqlite3_close(s) }
                throw LiveDBSnapshotError.openSourceFailed(message: msg, code: srcOpen)
            }
            defer { sqlite3_close(src) }

            var destDB: OpaquePointer?
            let destOpen = sqlite3_open_v2(
                tempURL.path,
                &destDB,
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                nil
            )
            guard destOpen == SQLITE_OK, let dest = destDB else {
                let msg = destDB.map { String(cString: sqlite3_errmsg($0)) } ?? "sqlite3_open returned \(destOpen)"
                if let d = destDB { sqlite3_close(d) }
                throw LiveDBSnapshotError.openDestFailed(message: msg, code: destOpen)
            }
            defer { sqlite3_close(dest) }

            guard let backup = sqlite3_backup_init(dest, "main", src, "main") else {
                let msg = String(cString: sqlite3_errmsg(dest))
                throw LiveDBSnapshotError.backupInitFailed(message: msg)
            }
            let stepRC = sqlite3_backup_step(backup, -1)
            sqlite3_backup_finish(backup)
            guard stepRC == SQLITE_DONE else {
                let msg = String(cString: sqlite3_errmsg(dest))
                throw LiveDBSnapshotError.backupStepFailed(message: msg, code: stepRC)
            }
        }

        // Hash the resulting file.
        let data = try Data(contentsOf: tempURL)
        let digest = SHA256.hash(data: data)
        let sha = digest.map { String(format: "%02x", $0) }.joined()
        let finalURL = layout.snapshotsRoot.appendingPathComponent("\(sha).db")

        // If a snapshot with this content already exists, dedup:
        // remove temp + return existing.
        if FileManager.default.fileExists(atPath: finalURL.path) {
            try? FileManager.default.removeItem(at: tempURL)
        } else {
            do {
                try FileManager.default.moveItem(at: tempURL, to: finalURL)
                try? FileManager.default.setAttributes(
                    [.posixPermissions: 0o600],
                    ofItemAtPath: finalURL.path
                )
            } catch {
                throw LiveDBSnapshotError.renameFailed(message: error.localizedDescription)
            }
        }

        let attrs = try? FileManager.default.attributesOfItem(atPath: finalURL.path)
        let size = (attrs?[.size] as? NSNumber)?.int64Value ?? 0

        return LiveDBSnapshotResult(path: finalURL, sha256: sha, sizeBytes: size)
    }
}

// MARK: - SQLite open flags (CSQLCipher re-exports them, but Swift
// imports them as Int32; the bitwise OR in sqlite3_open_v2 above
// needs them spelled out)

// Already imported via CSQLCipher; nothing to add here.
