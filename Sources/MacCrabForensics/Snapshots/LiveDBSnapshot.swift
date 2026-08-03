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
import MacCrabCore

public enum LiveDBSnapshotError: Error, CustomStringConvertible {
    case sourceMissing(path: String)
    case openSourceFailed(message: String, code: Int32)
    case openDestFailed(message: String, code: Int32)
    case backupInitFailed(message: String)
    case backupStepFailed(message: String, code: Int32)
    case renameFailed(message: String)
    case unsafePath(path: String)
    case sourceTooLarge(actualBytes: Int64, maxBytes: Int64)
    case storageProbeFailed(path: String)
    case lowFreeSpace(freeBytes: Int64, requiredBytes: Int64)

    public var description: String {
        switch self {
        case .sourceMissing(let p): return "LiveDBSnapshot: source database missing at \(p)"
        case .openSourceFailed(let m, let c): return "LiveDBSnapshot: open source failed (\(c)): \(m)"
        case .openDestFailed(let m, let c): return "LiveDBSnapshot: open destination failed (\(c)): \(m)"
        case .backupInitFailed(let m): return "LiveDBSnapshot: sqlite3_backup_init failed: \(m)"
        case .backupStepFailed(let m, let c): return "LiveDBSnapshot: sqlite3_backup_step failed (\(c)): \(m)"
        case .renameFailed(let m): return "LiveDBSnapshot: rename failed: \(m)"
        case .unsafePath(let p):
            return "LiveDBSnapshot: refusing symlink, non-regular, or multiply-linked path at \(p)"
        case .sourceTooLarge(let actual, let max):
            return "LiveDBSnapshot: source requires \(actual) bytes, above the \(max)-byte snapshot cap"
        case .storageProbeFailed(let p):
            return "LiveDBSnapshot: could not measure storage at \(p); refusing an unbounded copy"
        case .lowFreeSpace(let free, let required):
            return "LiveDBSnapshot: \(free) bytes free, below the \(required)-byte snapshot requirement"
        }
    }
}

/// Hard production bounds for plaintext forensic snapshots. These copies can
/// contain Messages, Mail, Safari, or TCC data, so they must neither exhaust the
/// boot volume nor remain indefinitely next to an encrypted case.
public enum LiveDBSnapshotStoragePolicy {
    public static let maxSQLiteBytes: Int64 = 1_024 * 1_048_576
    public static let freeSpaceFloorBytes: Int64 = 1_024 * 1_048_576
    public static let transactionReserveBytes: Int64 = 16 * 1_048_576
}

private enum SnapshotLeaseRegistry {
    private static let lock = NSLock()
    private nonisolated(unsafe) static var counts: [String: Int] = [:]

    static func acquire(_ path: URL) {
        lock.lock()
        counts[path.path, default: 0] += 1
        lock.unlock()
    }

    /// Returns true only when the final owner should unlink the snapshot.
    static func release(_ path: URL) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard let count = counts[path.path] else { return false }
        if count > 1 {
            counts[path.path] = count - 1
            return false
        }
        counts.removeValue(forKey: path.path)
        return true
    }
}

/// Result of a successful snapshot.
///
/// This is a **reference type on purpose**: for the case-bundle
/// (`layout`) snapshot it OWNS the on-disk snapshot file and removes it
/// when the last reference is released (RAII). A layout snapshot is a
/// transient parse artifact — a PLAINTEXT copy of a TCC-protected store
/// (chat.db, TCC.db, Mail index, Safari history). Persisting it for the
/// case lifetime would defeat `case.sqlite`'s at-rest SQLCipher
/// encryption against offline-media theft (stolen disk / Time Machine),
/// because the snapshot itself is not encrypted. Collectors hold this
/// result for exactly the duration of their parse, so releasing it (end
/// of `collect()`) is the natural "parse finished" signal — and because
/// the collector's already-open SQLite fd survives an unlink, parsing is
/// unaffected even if the file is removed while a parse is in flight.
///
/// The brokered-TCC path (`destDir` / `snapshotFile`) leaves the file in
/// place (`autoDeletePath == nil`): the file broker must serve the
/// snapshot fd to the sandboxed child AFTER this call returns.
///
/// `@unchecked Sendable`: all stored properties are immutable; the only
/// side effect is the best-effort file removal in `deinit`.
public final class LiveDBSnapshotResult: @unchecked Sendable {
    /// Final on-disk path of the snapshot inside the case's
    /// `snapshots/` directory. Filename is `<sha256>.db`.
    public let path: URL

    /// SHA-256 of the snapshot file. Doubles as the
    /// `plugin_invocations.snapshot_hash` value and the filename.
    public let sha256: String

    /// Size in bytes of the snapshot file. Useful for retention /
    /// disk-budget enforcement.
    public let sizeBytes: Int64

    /// When non-nil, the snapshot at this path (plus any SQLite journal
    /// siblings) is removed on `deinit`. Set only for the layout
    /// (case-bundle) snapshot; nil for brokered-TCC snapshots that must
    /// outlive this result so the broker can serve their fd.
    private let autoDeletePath: URL?

    init(
        path: URL,
        sha256: String,
        sizeBytes: Int64,
        autoDeletePath: URL? = nil,
        leaseAlreadyAcquired: Bool = false
    ) {
        self.path = path
        self.sha256 = sha256
        self.sizeBytes = sizeBytes
        self.autoDeletePath = autoDeletePath
        if let autoDeletePath, !leaseAlreadyAcquired {
            SnapshotLeaseRegistry.acquire(autoDeletePath)
        }
    }

    deinit {
        guard let base = autoDeletePath,
              SnapshotLeaseRegistry.release(base) else { return }
        let fm = FileManager.default
        try? fm.removeItem(at: base)
        // The backup API copies into a fresh file, but be defensive about
        // any rollback-journal / WAL siblings SQLite may have left behind.
        for suffix in ["-wal", "-shm", "-journal"] {
            try? fm.removeItem(at: URL(fileURLWithPath: base.path + suffix))
        }
    }
}

public enum LiveDBSnapshot {

    /// Snapshot a live SQLite database into the case's snapshots/
    /// directory. Source is opened read-only. Destination is built
    /// at a temp path first, then renamed to `<sha256>.db` so a
    /// crash mid-copy can't leave a half-baked file.
    public static func snapshot(
        sourcePath: String,
        layout: CaseDirectoryLayout,
        maxBytes: Int64 = LiveDBSnapshotStoragePolicy.maxSQLiteBytes,
        freeSpaceFloorBytes: Int64 = LiveDBSnapshotStoragePolicy.freeSpaceFloorBytes,
        transactionReserveBytes: Int64 = LiveDBSnapshotStoragePolicy.transactionReserveBytes
    ) throws -> LiveDBSnapshotResult {
        // autoDelete: the returned result OWNS the plaintext copy and
        // removes it when the collector releases it (end of parse). A
        // TCC-protected store must not sit unencrypted next to the
        // SQLCipher case.sqlite for the case lifetime.
        try snapshot(
            sourcePath: sourcePath,
            destDir: layout.snapshotsRoot,
            autoDelete: true,
            maxBytes: maxBytes,
            freeSpaceFloorBytes: freeSpaceFloorBytes,
            transactionReserveBytes: transactionReserveBytes
        )
    }

    /// Snapshot a live SQLite database into an ARBITRARY destination directory
    /// (not just a case layout). Used by the brokered-TCC path: the host
    /// snapshots a manifest-declared TCC-protected store (chat.db, TCC.db, Safari
    /// History.db…) into a host-owned, plugin-UNWRITABLE dir, then the file broker
    /// serves the snapshot fd to the sandboxed plugin — so the untrusted child
    /// never opens the live protected store and never inherits host FDA/TCC.
    /// (Plan §3.1 / Invariant 2.) Same backup-API copy + sha256 filename.
    ///
    /// `autoDelete` (default false, for the brokered-TCC path which needs
    /// the file to outlive the result): when true, the returned result
    /// owns the snapshot and removes it on release. The `layout` overload
    /// passes true so the case-bundle copy never persists past the parse.
    public static func snapshot(
        sourcePath: String,
        destDir: URL,
        autoDelete: Bool = false,
        maxBytes: Int64 = LiveDBSnapshotStoragePolicy.maxSQLiteBytes,
        freeSpaceFloorBytes: Int64 = LiveDBSnapshotStoragePolicy.freeSpaceFloorBytes,
        transactionReserveBytes: Int64 = LiveDBSnapshotStoragePolicy.transactionReserveBytes
    ) throws -> LiveDBSnapshotResult {

        guard maxBytes > 0 else {
            throw LiveDBSnapshotError.sourceTooLarge(actualBytes: 0, maxBytes: maxBytes)
        }
        var sourceInfo = stat()
        guard lstat(sourcePath, &sourceInfo) == 0 else {
            throw LiveDBSnapshotError.sourceMissing(path: sourcePath)
        }
        guard (UInt32(sourceInfo.st_mode) & UInt32(S_IFMT)) == UInt32(S_IFREG),
              sourceInfo.st_nlink == 1 else {
            throw LiveDBSnapshotError.unsafePath(path: sourcePath)
        }

        // Ensure the destination dir exists, is a real owner-owned directory,
        // and remains 0700 even when it predated this invocation.
        let destDirectoryFD = try openSecureDestinationDirectory(destDir)
        defer { close(destDirectoryFD) }

        // Temp destination — written first, then renamed.
        let tempName = "snapshot-inprogress-\(UUID().uuidString).db"
        let tempURL = destDir.appendingPathComponent(tempName)
        defer {
            // If we exit via error, clean up the half-finished temp
            // file. If we exit via success, the file's been renamed
            // already and this is a no-op.
            try? FileManager.default.removeItem(at: tempURL)
            for suffix in ["-wal", "-shm", "-journal"] {
                try? FileManager.default.removeItem(
                    at: URL(fileURLWithPath: tempURL.path + suffix)
                )
            }
        }

        // v1.16.0-rc.18: serialize the sqlite3_open + backup
        // window via the shared CSQLCipherInitGate. Resolves the
        // parallel-test race that previously forced 3
        // LiveDBSnapshot tests to @Test(.disabled).
        try CSQLCipherInitGate.withLock {
            var srcDB: OpaquePointer?
            let srcOpen = SQLiteOpenPathPolicy.open(
                sourcePath,
                database: &srcDB,
                flags: SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX
            )
            guard srcOpen == SQLITE_OK, let src = srcDB else {
                let msg = srcDB.map { String(cString: sqlite3_errmsg($0)) } ?? "sqlite3_open returned \(srcOpen)"
                if let s = srcDB { sqlite3_close(s) }
                throw LiveDBSnapshotError.openSourceFailed(message: msg, code: srcOpen)
            }
            defer { sqlite3_close(src) }

            let sourcePageSize = try pragmaInt64(src, name: "page_size")
            let sourcePageCount = try pragmaInt64(src, name: "page_count")
            guard sourcePageSize > 0, sourcePageCount >= 0 else {
                throw LiveDBSnapshotError.storageProbeFailed(path: sourcePath)
            }
            let (logicalBytes, logicalOverflow) = sourcePageSize.multipliedReportingOverflow(
                by: sourcePageCount
            )
            guard !logicalOverflow else {
                throw LiveDBSnapshotError.sourceTooLarge(
                    actualBytes: Int64.max,
                    maxBytes: maxBytes
                )
            }
            guard logicalBytes <= maxBytes else {
                throw LiveDBSnapshotError.sourceTooLarge(
                    actualBytes: logicalBytes,
                    maxBytes: maxBytes
                )
            }
            try requireFreeSpace(
                at: destDir.path,
                floorBytes: max(0, freeSpaceFloorBytes),
                copyBytes: logicalBytes,
                reserveBytes: max(0, transactionReserveBytes)
            )

            var destDB: OpaquePointer?
            let destOpen = SQLiteOpenPathPolicy.open(
                tempURL.path,
                database: &destDB,
                flags: SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE
                    | SQLITE_OPEN_FULLMUTEX
            )
            guard destOpen == SQLITE_OK, let dest = destDB else {
                let msg = destDB.map { String(cString: sqlite3_errmsg($0)) } ?? "sqlite3_open returned \(destOpen)"
                if let d = destDB { sqlite3_close(d) }
                throw LiveDBSnapshotError.openDestFailed(message: msg, code: destOpen)
            }
            defer { sqlite3_close(dest) }

            // Match the source page size while the destination is still empty,
            // then install a hard SQLite page ceiling. The preflight above is a
            // point-in-time estimate; max_page_count remains authoritative if
            // the live source grows during backup.
            try execute(dest, sql: "PRAGMA page_size = \(sourcePageSize)")
            let maximumPages = max(Int64(1), maxBytes / sourcePageSize)
            try execute(dest, sql: "PRAGMA max_page_count = \(maximumPages)")
            let installedMaximum = try pragmaInt64(dest, name: "max_page_count")
            guard installedMaximum <= maximumPages else {
                throw LiveDBSnapshotError.storageProbeFailed(path: tempURL.path)
            }
            try execute(dest, sql: "PRAGMA journal_mode = OFF")

            guard let backup = sqlite3_backup_init(dest, "main", src, "main") else {
                let msg = String(cString: sqlite3_errmsg(dest))
                throw LiveDBSnapshotError.backupInitFailed(message: msg)
            }
            var backupFinished = false
            defer {
                if !backupFinished { sqlite3_backup_finish(backup) }
            }
            var busyRetries = 0
            while true {
                let stepRC = sqlite3_backup_step(backup, 256)
                if stepRC == SQLITE_DONE { break }
                if stepRC == SQLITE_OK {
                    busyRetries = 0
                } else if (stepRC == SQLITE_BUSY || stepRC == SQLITE_LOCKED),
                          busyRetries < 50 {
                    busyRetries += 1
                    usleep(10_000)
                    continue
                } else {
                    let msg = String(cString: sqlite3_errmsg(dest))
                    throw LiveDBSnapshotError.backupStepFailed(message: msg, code: stepRC)
                }

                let footprint = try sqliteFamilyFootprint(at: tempURL.path)
                guard footprint <= maxBytes else {
                    throw LiveDBSnapshotError.sourceTooLarge(
                        actualBytes: footprint,
                        maxBytes: maxBytes
                    )
                }
                // Stop before crossing the hard free-space floor even if other
                // writers consume the volume after our initial reservation.
                try requireFreeSpace(
                    at: destDir.path,
                    floorBytes: max(0, freeSpaceFloorBytes),
                    copyBytes: 0,
                    reserveBytes: max(0, transactionReserveBytes)
                )
            }
            let finishRC = sqlite3_backup_finish(backup)
            backupFinished = true
            guard finishRC == SQLITE_OK else {
                let msg = String(cString: sqlite3_errmsg(dest))
                throw LiveDBSnapshotError.backupStepFailed(
                    message: "backup finish failed: \(msg)",
                    code: finishRC
                )
            }
        }

        let finalFootprint = try sqliteFamilyFootprint(at: tempURL.path)
        guard finalFootprint <= maxBytes else {
            throw LiveDBSnapshotError.sourceTooLarge(
                actualBytes: finalFootprint,
                maxBytes: maxBytes
            )
        }

        // Hash incrementally; loading a cap-sized (1 GiB) snapshot into one Data
        // allocation merely moves the denial of service from disk to memory.
        let (digest, mainFileBytes) = try hashRegularFile(at: tempURL)
        let sha = digest.map { String(format: "%02x", $0) }.joined()
        let finalURL = destDir.appendingPathComponent("\(sha).db")

        // Acquire before publishing/replacing the shared content-addressed path.
        // Otherwise the previous owner's deinit can unlink the new generation in
        // the narrow window between rename and the new result's initializer.
        let ownsAutoDeleteLease = autoDelete
        if ownsAutoDeleteLease { SnapshotLeaseRegistry.acquire(finalURL) }
        var renamedFinal = false
        var transferredLease = false
        defer {
            if ownsAutoDeleteLease, !transferredLease {
                let shouldRemove = SnapshotLeaseRegistry.release(finalURL)
                if renamedFinal, shouldRemove {
                    try? FileManager.default.removeItem(at: finalURL)
                }
            }
        }

        // POSIX rename atomically replaces an existing file or symlink without
        // following it. Rebuilding the content-addressed snapshot is safer than
        // trusting a same-uid attacker-planted `<sha>.db` as a dedup hit.
        guard rename(tempURL.path, finalURL.path) == 0 else {
            throw LiveDBSnapshotError.renameFailed(message: String(cString: strerror(errno)))
        }
        renamedFinal = true
        let finalFD = open(finalURL.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard finalFD >= 0 else {
            throw LiveDBSnapshotError.unsafePath(path: finalURL.path)
        }
        defer { close(finalFD) }
        var finalInfo = stat()
        guard fstat(finalFD, &finalInfo) == 0,
              (UInt32(finalInfo.st_mode) & UInt32(S_IFMT)) == UInt32(S_IFREG),
              finalInfo.st_nlink == 1,
              fchmod(finalFD, 0o600) == 0 else {
            throw LiveDBSnapshotError.unsafePath(path: finalURL.path)
        }
        try requireFreeSpace(
            at: destDir.path,
            floorBytes: max(0, freeSpaceFloorBytes),
            copyBytes: 0,
            reserveBytes: max(0, transactionReserveBytes)
        )

        let result = LiveDBSnapshotResult(
            path: finalURL,
            sha256: sha,
            sizeBytes: mainFileBytes,
            autoDeletePath: autoDelete ? finalURL : nil,
            leaseAlreadyAcquired: ownsAutoDeleteLease
        )
        transferredLease = true
        return result
    }

    private static func pragmaInt64(_ db: OpaquePointer, name: String) throws -> Int64 {
        var statement: OpaquePointer?
        let prepare = sqlite3_prepare_v2(db, "PRAGMA \(name)", -1, &statement, nil)
        defer { sqlite3_finalize(statement) }
        guard prepare == SQLITE_OK, let statement else {
            throw LiveDBSnapshotError.storageProbeFailed(path: name)
        }
        guard sqlite3_step(statement) == SQLITE_ROW else {
            throw LiveDBSnapshotError.storageProbeFailed(path: name)
        }
        return sqlite3_column_int64(statement, 0)
    }

    private static func execute(_ db: OpaquePointer, sql: String) throws {
        let rc = sqlite3_exec(db, sql, nil, nil, nil)
        guard rc == SQLITE_OK else {
            throw LiveDBSnapshotError.backupStepFailed(
                message: String(cString: sqlite3_errmsg(db)),
                code: rc
            )
        }
    }

    private static func sqliteFamilyFootprint(at path: String) throws -> Int64 {
        var total: Int64 = 0
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let member = path + suffix
            var info = stat()
            if lstat(member, &info) == 0 {
                guard (UInt32(info.st_mode) & UInt32(S_IFMT)) == UInt32(S_IFREG),
                      info.st_nlink == 1,
                      info.st_size >= 0 else {
                    throw LiveDBSnapshotError.unsafePath(path: member)
                }
                let (next, overflow) = total.addingReportingOverflow(Int64(info.st_size))
                guard !overflow else {
                    throw LiveDBSnapshotError.sourceTooLarge(
                        actualBytes: Int64.max,
                        maxBytes: LiveDBSnapshotStoragePolicy.maxSQLiteBytes
                    )
                }
                total = next
            } else if errno != ENOENT {
                throw LiveDBSnapshotError.storageProbeFailed(path: member)
            }
        }
        return total
    }

    private static func requireFreeSpace(
        at path: String,
        floorBytes: Int64,
        copyBytes: Int64,
        reserveBytes: Int64
    ) throws {
        var info = statfs()
        guard statfs(path, &info) == 0 else {
            throw LiveDBSnapshotError.storageProbeFailed(path: path)
        }
        let blocks = UInt64(info.f_bavail)
        let blockSize = UInt64(info.f_bsize)
        let freeUnsigned = blocks.multipliedReportingOverflow(by: blockSize)
        guard !freeUnsigned.overflow else {
            throw LiveDBSnapshotError.storageProbeFailed(path: path)
        }
        let free = Int64(clamping: freeUnsigned.partialValue)
        let (floorAndCopy, overflow1) = floorBytes.addingReportingOverflow(copyBytes)
        let (required, overflow2) = floorAndCopy.addingReportingOverflow(reserveBytes)
        guard !overflow1, !overflow2, free >= required else {
            throw LiveDBSnapshotError.lowFreeSpace(
                freeBytes: free,
                requiredBytes: (overflow1 || overflow2) ? Int64.max : required
            )
        }
    }

    private static func hashRegularFile(at url: URL) throws -> (SHA256.Digest, Int64) {
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw LiveDBSnapshotError.unsafePath(path: url.path) }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0,
              (UInt32(info.st_mode) & UInt32(S_IFMT)) == UInt32(S_IFREG),
              info.st_nlink == 1,
              info.st_size >= 0 else {
            throw LiveDBSnapshotError.unsafePath(path: url.path)
        }
        var hasher = SHA256()
        var buffer = [UInt8](repeating: 0, count: 1 << 20)
        while true {
            let count = buffer.withUnsafeMutableBytes {
                read(fd, $0.baseAddress, $0.count)
            }
            if count < 0, errno == EINTR { continue }
            guard count >= 0 else {
                throw LiveDBSnapshotError.storageProbeFailed(path: url.path)
            }
            if count == 0 { break }
            hasher.update(data: Data(buffer[0..<count]))
        }
        return (hasher.finalize(), Int64(info.st_size))
    }

    private static func openSecureDestinationDirectory(_ url: URL) throws -> Int32 {
        try FileManager.default.createDirectory(
            at: url,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let fd = open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw LiveDBSnapshotError.unsafePath(path: url.path) }
        var info = stat()
        guard fstat(fd, &info) == 0,
              (UInt32(info.st_mode) & UInt32(S_IFMT)) == UInt32(S_IFDIR),
              info.st_uid == geteuid(),
              fchmod(fd, 0o700) == 0 else {
            close(fd)
            throw LiveDBSnapshotError.unsafePath(path: url.path)
        }
        return fd
    }

    /// Snapshot a single NON-SQLite regular file (e.g. a plist or .emlx a plugin
    /// declared) into `destDir` as `<sha>.bin`, 0o600. The source is opened
    /// O_NOFOLLOW (a symlinked source is refused) and must be a regular file; the
    /// copy is size-capped. For the brokered-TCC path alongside the DB snapshot.
    public static func snapshotFile(
        sourcePath: String,
        destDir: URL,
        maxBytes: Int64 = 256 * 1_048_576,
        freeSpaceFloorBytes: Int64 = LiveDBSnapshotStoragePolicy.freeSpaceFloorBytes,
        transactionReserveBytes: Int64 = LiveDBSnapshotStoragePolicy.transactionReserveBytes
    ) throws -> LiveDBSnapshotResult {
        let fd = open(sourcePath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw LiveDBSnapshotError.sourceMissing(path: sourcePath) }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0,
              (UInt32(st.st_mode) & UInt32(S_IFMT)) == UInt32(S_IFREG),
              st.st_nlink == 1 else {
            throw LiveDBSnapshotError.sourceMissing(path: sourcePath)
        }
        guard maxBytes > 0, st.st_size >= 0, Int64(st.st_size) <= maxBytes else {
            throw LiveDBSnapshotError.sourceTooLarge(
                actualBytes: max(0, Int64(st.st_size)),
                maxBytes: maxBytes
            )
        }

        let destinationDirectoryFD = try openSecureDestinationDirectory(destDir)
        defer { close(destinationDirectoryFD) }
        try requireFreeSpace(
            at: destDir.path,
            floorBytes: max(0, freeSpaceFloorBytes),
            copyBytes: Int64(st.st_size),
            reserveBytes: max(0, transactionReserveBytes)
        )

        let tempURL = destDir.appendingPathComponent(
            "filesnap-inprogress-\(UUID().uuidString).bin"
        )
        let destinationFD = open(
            tempURL.path,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            0o600
        )
        guard destinationFD >= 0 else {
            throw LiveDBSnapshotError.renameFailed(
                message: "could not create bounded temp snapshot: \(String(cString: strerror(errno)))"
            )
        }
        defer {
            close(destinationFD)
            unlink(tempURL.path)
        }

        var hasher = SHA256()
        var total: Int64 = 0
        var buffer = [UInt8](repeating: 0, count: 1 << 20)
        while true {
            let count = buffer.withUnsafeMutableBytes {
                read(fd, $0.baseAddress, $0.count)
            }
            if count < 0, errno == EINTR { continue }
            guard count >= 0 else {
                throw LiveDBSnapshotError.openSourceFailed(
                    message: "read error",
                    code: errno
                )
            }
            if count == 0 { break }
            let (nextTotal, overflow) = total.addingReportingOverflow(Int64(count))
            guard !overflow, nextTotal <= maxBytes else {
                throw LiveDBSnapshotError.sourceTooLarge(
                    actualBytes: overflow ? Int64.max : nextTotal,
                    maxBytes: maxBytes
                )
            }
            var offset = 0
            while offset < count {
                let written = buffer.withUnsafeBytes { raw -> Int in
                    guard let base = raw.baseAddress else { return -1 }
                    return write(
                        destinationFD,
                        base.advanced(by: offset),
                        count - offset
                    )
                }
                if written < 0, errno == EINTR { continue }
                guard written > 0 else {
                    throw LiveDBSnapshotError.renameFailed(message: "snapshot write failed")
                }
                offset += written
            }
            hasher.update(data: Data(buffer[0..<count]))
            total = nextTotal
            try requireFreeSpace(
                at: destDir.path,
                floorBytes: max(0, freeSpaceFloorBytes),
                copyBytes: 0,
                reserveBytes: max(0, transactionReserveBytes)
            )
        }
        guard fsync(destinationFD) == 0, fchmod(destinationFD, 0o600) == 0 else {
            throw LiveDBSnapshotError.renameFailed(message: "snapshot fsync failed")
        }

        let sha = hasher.finalize().map { String(format: "%02x", $0) }.joined()
        let finalURL = destDir.appendingPathComponent("\(sha).bin")
        guard rename(tempURL.path, finalURL.path) == 0 else {
            throw LiveDBSnapshotError.renameFailed(message: String(cString: strerror(errno)))
        }
        return LiveDBSnapshotResult(path: finalURL, sha256: sha, sizeBytes: total)
    }
}

// MARK: - SQLite open flags (CSQLCipher re-exports them, but Swift
// imports them as Int32; the bitwise OR in sqlite3_open_v2 above
// needs them spelled out)

// Already imported via CSQLCipher; nothing to add here.
