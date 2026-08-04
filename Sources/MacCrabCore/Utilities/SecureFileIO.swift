// SecureFileIO.swift
// MacCrabCore
//
// Symlink-safe + race-safe file I/O primitives. v1.12.0 hardening pass
// after the pre-release audit flagged TOCTOU races in HoneyfileManager
// and arbitrary-path traversal in PackageContentAnalyzer /
// PromptIntentBridge.
//
// All public reads and writes resolve every path component relative to an
// already-open directory descriptor. Final-component O_NOFOLLOW alone is not
// enough: a privileged caller can otherwise be redirected through a raced
// intermediate symlink. Writes stage complete bytes in a same-directory
// private temporary and publish with renameatx_np(RENAME_EXCL), so observers
// never see a partially-written destination and an existing name is never
// clobbered by atomicCreate.

import Foundation
import Darwin

public enum SecureFileIO {

    struct TemporaryCleanupReport: Sendable, Equatable {
        let inspectedEntries: Int
        let matchingFiles: Int
        let removedFiles: Int
        let removedBytes: Int
        let remainingFiles: Int
        let remainingBytes: Int
        let scanTruncated: Bool
    }

    public enum Error: Swift.Error, LocalizedError, Equatable {
        case pathOutsideScope(path: String, scope: String)
        case symlinkRefused(path: String)
        case fileAlreadyExists(path: String)
        case openFailed(path: String, errno: Int32)
        case writeFailed(path: String, errno: Int32)
        case readFailed(path: String, errno: Int32)
        case invalidScope(scope: String)

        public var errorDescription: String? {
            switch self {
            case .pathOutsideScope(let p, let s): return "Refused: \(p) is outside the allowed scope \(s)"
            case .symlinkRefused(let p): return "Refused: \(p) is a symbolic link"
            case .fileAlreadyExists(let p): return "Refused: \(p) already exists (no clobber)"
            case .openFailed(let p, let e): return "open(\(p)) failed: errno \(e)"
            case .writeFailed(let p, let e): return "write(\(p)) failed: errno \(e)"
            case .readFailed(let p, let e): return "read(\(p)) failed: errno \(e)"
            case .invalidScope(let s): return "Scope path is invalid: \(s)"
            }
        }
    }

    // MARK: - Path scoping

    /// Returns true if `path`, after symlink resolution and
    /// normalization, is contained inside `scope` (also normalized).
    /// Defeats `../`-relative paths and symlink-escape attempts.
    ///
    /// v1.12.0 post-audit (H-Sec2): `NSString.standardizingPath` only
    /// resolves lexical `../` / `./` / `~` — it does NOT resolve
    /// symbolic links. POSIX `O_NOFOLLOW` only refuses a symlink at
    /// the *final* path component, not intermediate ones. So a user-
    /// controllable intermediate dir replaced with a symlink would
    /// bypass scope check + O_NOFOLLOW combined. We now call
    /// `realpath(3)` on both path and scope so the scope test
    /// operates on physical paths. If realpath fails (e.g., path
    /// doesn't exist yet), fall back to the lexical comparison
    /// (write paths legitimately don't exist before atomicCreate).
    public static func isPathInScope(_ path: String, scope: String) -> Bool {
        let normalizedScope = realpathOrStandardize(scope)
        let normalizedPath = realpathOrStandardize(path)
        guard !normalizedScope.isEmpty, normalizedScope.hasPrefix("/") else { return false }
        // Append "/" to scope to avoid matching "/Users/me/.ssh"
        // against scope "/Users/me/.s".
        let scopeWithSlash = normalizedScope.hasSuffix("/") ? normalizedScope : normalizedScope + "/"
        if normalizedPath == normalizedScope { return true }
        return normalizedPath.hasPrefix(scopeWithSlash)
    }

    /// Best-effort canonical form for the preliminary scope decision. Resolves
    /// symlinks when the full path exists and falls back to lexical
    /// standardization when it does not. This check is never the carrier
    /// boundary: the subsequent reader/writer independently walks every
    /// component with descriptor-relative O_NOFOLLOW, so a fallback or race
    /// cannot turn an intermediate symlink into a scope escape.
    private static func realpathOrStandardize(_ p: String) -> String {
        let resolved = p.withCString { cpath -> String? in
            guard let buf = realpath(cpath, nil) else { return nil }
            defer { free(buf) }
            return String(cString: buf)
        }
        if let resolved { return resolved }
        return (p as NSString).standardizingPath
    }

    // MARK: - Writes

    private struct FileIdentity: Equatable {
        let device: dev_t
        let inode: ino_t

        init(_ metadata: stat) {
            device = metadata.st_dev
            inode = metadata.st_ino
        }

        func matches(_ metadata: stat) -> Bool {
            device == metadata.st_dev && inode == metadata.st_ino
        }
    }

    /// Write `data` to `path` atomically, refusing to clobber and refusing
    /// symlinks at every component. Complete bytes are fsync'd in a private
    /// same-directory temporary before exclusive publication.
    /// Use mode 0o400 for credential-shaped bait, 0o600 for
    /// MacCrab-private state, 0o644 for user-visible bait files.
    public static func atomicCreate(at path: String, data: Data, mode: mode_t) throws {
        try atomicWrite(
            at: path,
            data: data,
            mode: mode,
            replaceExisting: false,
            afterDirectoryOpened: nil
        )
    }

    /// Atomic replacement for MacCrab-owned state. An existing destination
    /// must be a single-link regular file owned by the effective uid; a
    /// symlink, hard link, foreign-owned file, or non-regular carrier fails
    /// closed. Absent destinations retain exclusive-create semantics.
    public static func atomicReplace(at path: String, data: Data, mode: mode_t) throws {
        try atomicWrite(
            at: path,
            data: data,
            mode: mode,
            replaceExisting: true,
            temporaryNamePrefix: ".maccrab-write-",
            afterDirectoryOpened: nil
        )
    }

    /// Caller-scoped staging namespace for durable state that also performs
    /// exact orphan accounting/cleanup. The prefix must be a short hidden leaf
    /// prefix ending in `-`; it is never interpreted as a path.
    static func atomicReplace(
        at path: String,
        data: Data,
        mode: mode_t,
        temporaryNamePrefix: String
    ) throws {
        try atomicWrite(
            at: path,
            data: data,
            mode: mode,
            replaceExisting: true,
            temporaryNamePrefix: temporaryNamePrefix,
            afterDirectoryOpened: nil
        )
    }

    /// Descriptor-safe, caller-namespace-exact cleanup for crash-orphaned
    /// atomic-write temporaries. It never touches the shared default namespace.
    /// Only stale, private, single-link regular files owned by the effective UID
    /// and carrying the exact `<prefix><UUID>.tmp` shape are eligible.
    static func cleanupStaleAtomicWriteTemporaries(
        near path: String,
        temporaryNamePrefix: String,
        olderThan minimumAge: TimeInterval,
        now: Date = Date(),
        maximumEntries: Int = 4_096,
        maximumFilesToRemove: Int = 32,
        maximumBytesToRemove: Int = 64 * 1_024 * 1_024,
        maximumCandidateBytes: Int = 8 * 1_024 * 1_024
    ) throws -> TemporaryCleanupReport {
        guard isSafeTemporaryNamePrefix(temporaryNamePrefix),
              minimumAge.isFinite, minimumAge >= 0,
              maximumEntries > 0, maximumEntries <= 65_536,
              maximumFilesToRemove >= 0, maximumFilesToRemove <= maximumEntries,
              maximumBytesToRemove >= 0,
              maximumCandidateBytes >= 0 else {
            throw Error.writeFailed(path: path, errno: EINVAL)
        }

        return try withParentDirectory(of: path) {
            parentDescriptor, _, _ in
            let duplicate = Darwin.openat(
                parentDescriptor,
                ".",
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
            )
            guard duplicate >= 0 else {
                throw Error.openFailed(path: path, errno: errno)
            }
            guard let stream = Darwin.fdopendir(duplicate) else {
                let savedErrno = errno
                Darwin.close(duplicate)
                throw Error.openFailed(path: path, errno: savedErrno)
            }
            defer { Darwin.closedir(stream) }

            var inspected = 0
            var matching = 0
            var removedFiles = 0
            var removedBytes = 0
            var remainingFiles = 0
            var remainingBytes = 0
            var truncated = false
            Darwin.errno = 0

            while let entry = Darwin.readdir(stream) {
                let name = withUnsafePointer(to: &entry.pointee.d_name) { pointer in
                    pointer.withMemoryRebound(
                        to: CChar.self,
                        capacity: Int(MAXNAMLEN) + 1
                    ) { String(cString: $0) }
                }
                guard name != ".", name != "..", !name.isEmpty else { continue }
                if inspected == maximumEntries {
                    truncated = true
                    break
                }
                inspected += 1
                guard temporaryNameMatches(name, prefix: temporaryNamePrefix) else {
                    continue
                }

                var metadata = stat()
                let statStatus = name.withCString {
                    Darwin.fstatat(
                        Darwin.dirfd(stream),
                        $0,
                        &metadata,
                        AT_SYMLINK_NOFOLLOW
                    )
                }
                guard statStatus == 0,
                      (metadata.st_mode & S_IFMT) == S_IFREG,
                      metadata.st_nlink == 1,
                      metadata.st_uid == geteuid(),
                      metadata.st_mode & 0o077 == 0,
                      metadata.st_size >= 0,
                      metadata.st_size <= off_t(maximumCandidateBytes) else {
                    continue
                }

                matching += 1
                let size = Int(metadata.st_size)
                let modifiedAt = TimeInterval(metadata.st_mtimespec.tv_sec)
                    + TimeInterval(metadata.st_mtimespec.tv_nsec) / 1_000_000_000
                let age = now.timeIntervalSince1970 - modifiedAt
                let removalWithinBounds = removedFiles < maximumFilesToRemove
                    && size <= maximumBytesToRemove
                    && removedBytes <= maximumBytesToRemove - size
                var removed = false

                if age >= minimumAge, removalWithinBounds {
                    var revalidated = stat()
                    let unchanged = name.withCString {
                        Darwin.fstatat(
                            Darwin.dirfd(stream),
                            $0,
                            &revalidated,
                            AT_SYMLINK_NOFOLLOW
                        )
                    } == 0
                        && FileIdentity(metadata).matches(revalidated)
                        && revalidated.st_size == metadata.st_size
                        && revalidated.st_nlink == 1
                        && revalidated.st_uid == geteuid()
                        && (revalidated.st_mode & S_IFMT) == S_IFREG
                        && revalidated.st_mode & 0o077 == 0
                        && revalidated.st_mtimespec.tv_sec == metadata.st_mtimespec.tv_sec
                        && revalidated.st_mtimespec.tv_nsec == metadata.st_mtimespec.tv_nsec
                    if unchanged {
                        removed = name.withCString {
                            Darwin.unlinkat(Darwin.dirfd(stream), $0, 0)
                        } == 0
                    }
                }

                if removed {
                    removedFiles += 1
                    removedBytes += size
                } else {
                    remainingFiles += 1
                    remainingBytes = remainingBytes > Int.max - size
                        ? Int.max : remainingBytes + size
                }
                Darwin.errno = 0
            }
            guard Darwin.errno == 0 else {
                throw Error.readFailed(path: path, errno: errno)
            }
            return TemporaryCleanupReport(
                inspectedEntries: inspected,
                matchingFiles: matching,
                removedFiles: removedFiles,
                removedBytes: removedBytes,
                remainingFiles: remainingFiles,
                remainingBytes: remainingBytes,
                scanTruncated: truncated
            )
        }
    }

    /// Internal race seam used only by adversarial tests. Production callers
    /// use the public overload above.
    static func atomicCreate(
        at path: String,
        data: Data,
        mode: mode_t,
        afterDirectoryOpened: @escaping (String, Int32) -> Void
    ) throws {
        try atomicWrite(
            at: path,
            data: data,
            mode: mode,
            replaceExisting: false,
            temporaryNamePrefix: ".maccrab-write-",
            afterDirectoryOpened: afterDirectoryOpened
        )
    }

    private static func atomicWrite(
        at path: String,
        data: Data,
        mode: mode_t,
        replaceExisting: Bool,
        temporaryNamePrefix: String = ".maccrab-write-",
        afterDirectoryOpened: ((String, Int32) -> Void)?
    ) throws {
        guard mode & ~mode_t(0o7777) == 0 else {
            throw Error.writeFailed(path: path, errno: EINVAL)
        }
        guard isSafeTemporaryNamePrefix(temporaryNamePrefix) else {
            throw Error.writeFailed(path: path, errno: EINVAL)
        }

        try withParentDirectory(
            of: path,
            afterDirectoryOpened: afterDirectoryOpened
        ) { parentDescriptor, leaf, normalizedPath in
            var parentMetadata = stat()
            guard Darwin.fstat(parentDescriptor, &parentMetadata) == 0 else {
                throw Error.openFailed(path: path, errno: errno)
            }
            let expectedParent = FileIdentity(parentMetadata)

            let temporaryLeaf = "\(temporaryNamePrefix)\(UUID().uuidString).tmp"
            let temporaryDescriptor = temporaryLeaf.withCString {
                Darwin.openat(
                    parentDescriptor,
                    $0,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                    mode_t(0o600)
                )
            }
            guard temporaryDescriptor >= 0 else {
                throw openError(path: path, code: errno)
            }

            var descriptorOpen = true
            var temporaryExists = true
            defer {
                if descriptorOpen { Darwin.close(temporaryDescriptor) }
                if temporaryExists {
                    temporaryLeaf.withCString {
                        _ = Darwin.unlinkat(parentDescriptor, $0, 0)
                    }
                }
            }

            guard Darwin.fchmod(temporaryDescriptor, mode) == 0 else {
                throw Error.writeFailed(path: path, errno: errno)
            }
            try writeAll(data, descriptor: temporaryDescriptor, path: path)
            guard Darwin.fsync(temporaryDescriptor) == 0 else {
                throw Error.writeFailed(path: path, errno: errno)
            }

            var temporaryMetadata = stat()
            guard Darwin.fstat(temporaryDescriptor, &temporaryMetadata) == 0,
                  (temporaryMetadata.st_mode & S_IFMT) == S_IFREG,
                  temporaryMetadata.st_nlink == 1,
                  temporaryMetadata.st_size == off_t(data.count) else {
                throw Error.writeFailed(path: path, errno: EIO)
            }
            let temporaryIdentity = FileIdentity(temporaryMetadata)
            // Surface delayed close errors before publication, while the
            // private temporary can still be removed without changing the
            // destination contract.
            guard Darwin.close(temporaryDescriptor) == 0 else {
                descriptorOpen = false
                throw Error.writeFailed(path: path, errno: errno)
            }
            descriptorOpen = false

            let existingIdentity = try destinationIdentity(
                parentDescriptor: parentDescriptor,
                leaf: leaf,
                path: path,
                allowExisting: replaceExisting
            )
            guard parentStillMatches(
                normalizedPath: normalizedPath,
                expected: expectedParent
            ) else {
                throw Error.openFailed(path: path, errno: ESTALE)
            }

            let publicationStatus: Int32
            if let existingIdentity {
                // Revalidate immediately before replacement. renameat replaces
                // the directory entry itself and never follows a leaf symlink.
                guard destinationStillMatches(
                    parentDescriptor: parentDescriptor,
                    leaf: leaf,
                    expected: existingIdentity
                ) else {
                    throw Error.openFailed(path: path, errno: ESTALE)
                }
                publicationStatus = temporaryLeaf.withCString { temporaryName in
                    leaf.withCString { destinationName in
                        Darwin.renameat(
                            parentDescriptor,
                            temporaryName,
                            parentDescriptor,
                            destinationName
                        )
                    }
                }
            } else {
                publicationStatus = temporaryLeaf.withCString { temporaryName in
                    leaf.withCString { destinationName in
                        Darwin.renameatx_np(
                            parentDescriptor,
                            temporaryName,
                            parentDescriptor,
                            destinationName,
                            UInt32(RENAME_EXCL)
                        )
                    }
                }
            }
            guard publicationStatus == 0 else {
                if errno == EEXIST {
                    throw Error.fileAlreadyExists(path: path)
                }
                throw openError(path: path, code: errno)
            }
            temporaryExists = false

            guard namedFileStillMatches(
                parentDescriptor: parentDescriptor,
                leaf: leaf,
                expected: temporaryIdentity
            ), parentStillMatches(
                normalizedPath: normalizedPath,
                expected: expectedParent
            ) else {
                // Exclusive creation can be rolled back without risking an
                // unrelated inode. Replacement has already committed and is
                // intentionally left intact rather than attempting a lossy
                // rollback of the old contents.
                if !replaceExisting {
                    unlinkNamedFileIfOwned(
                        parentDescriptor: parentDescriptor,
                        leaf: leaf,
                        expected: temporaryIdentity
                    )
                }
                throw Error.writeFailed(path: path, errno: ESTALE)
            }

            // Directory fsync is best-effort because publication has already
            // committed; reporting a failure as "not created" would invite a
            // destructive retry against the now-existing name.
            _ = Darwin.fsync(parentDescriptor)
        }
    }

    private static func isSafeTemporaryNamePrefix(_ prefix: String) -> Bool {
        prefix.hasPrefix(".maccrab-")
            && prefix.hasSuffix("-")
            && !prefix.contains("/")
            && !prefix.contains("\0")
            && prefix.utf8.count <= 96
    }

    private static func temporaryNameMatches(_ name: String, prefix: String) -> Bool {
        guard name.hasPrefix(prefix), name.hasSuffix(".tmp") else { return false }
        let uuidStart = name.index(name.startIndex, offsetBy: prefix.count)
        let uuidEnd = name.index(name.endIndex, offsetBy: -4)
        guard uuidStart < uuidEnd else { return false }
        return UUID(uuidString: String(name[uuidStart..<uuidEnd])) != nil
    }

    private static func writeAll(
        _ data: Data,
        descriptor: Int32,
        path: String
    ) throws {
        try data.withUnsafeBytes { buffer in
            guard let baseAddress = buffer.baseAddress else { return }
            var offset = 0
            while offset < buffer.count {
                let count = Darwin.write(
                    descriptor,
                    baseAddress.advanced(by: offset),
                    buffer.count - offset
                )
                if count < 0 {
                    if errno == EINTR { continue }
                    throw Error.writeFailed(path: path, errno: errno)
                }
                guard count > 0 else {
                    throw Error.writeFailed(path: path, errno: EIO)
                }
                offset += count
            }
        }
    }

    private static func destinationIdentity(
        parentDescriptor: Int32,
        leaf: String,
        path: String,
        allowExisting: Bool
    ) throws -> FileIdentity? {
        var metadata = stat()
        let status = leaf.withCString {
            Darwin.fstatat(
                parentDescriptor,
                $0,
                &metadata,
                AT_SYMLINK_NOFOLLOW
            )
        }
        if status != 0 {
            if errno == ENOENT { return nil }
            throw openError(path: path, code: errno)
        }
        guard allowExisting else {
            throw Error.fileAlreadyExists(path: path)
        }
        guard (metadata.st_mode & S_IFMT) == S_IFREG,
              metadata.st_nlink == 1,
              metadata.st_uid == geteuid() else {
            throw Error.symlinkRefused(path: path)
        }
        return FileIdentity(metadata)
    }

    private static func destinationStillMatches(
        parentDescriptor: Int32,
        leaf: String,
        expected: FileIdentity
    ) -> Bool {
        var metadata = stat()
        return leaf.withCString {
            Darwin.fstatat(
                parentDescriptor,
                $0,
                &metadata,
                AT_SYMLINK_NOFOLLOW
            )
        } == 0
            && (metadata.st_mode & S_IFMT) == S_IFREG
            && metadata.st_nlink == 1
            && metadata.st_uid == geteuid()
            && expected.matches(metadata)
    }

    private static func namedFileStillMatches(
        parentDescriptor: Int32,
        leaf: String,
        expected: FileIdentity
    ) -> Bool {
        var metadata = stat()
        return leaf.withCString {
            Darwin.fstatat(
                parentDescriptor,
                $0,
                &metadata,
                AT_SYMLINK_NOFOLLOW
            )
        } == 0
            && (metadata.st_mode & S_IFMT) == S_IFREG
            && metadata.st_nlink == 1
            && expected.matches(metadata)
    }

    private static func unlinkNamedFileIfOwned(
        parentDescriptor: Int32,
        leaf: String,
        expected: FileIdentity
    ) {
        guard namedFileStillMatches(
            parentDescriptor: parentDescriptor,
            leaf: leaf,
            expected: expected
        ) else { return }
        leaf.withCString { _ = Darwin.unlinkat(parentDescriptor, $0, 0) }
    }

    private static func parentStillMatches(
        normalizedPath: String,
        expected: FileIdentity
    ) -> Bool {
        (try? withParentDirectory(of: normalizedPath) {
            parentDescriptor, _, _ in
            var metadata = stat()
            return Darwin.fstat(parentDescriptor, &metadata) == 0
                && expected.matches(metadata)
        }) == true
    }

    private static func withParentDirectory<T>(
        of path: String,
        afterDirectoryOpened: ((String, Int32) -> Void)? = nil,
        _ body: (Int32, String, String) throws -> T
    ) throws -> T {
        guard let normalizedPath = BoundedRegularFileReader.normalizedAbsolutePath(path) else {
            throw Error.openFailed(path: path, errno: EINVAL)
        }
        let components = normalizedPath
            .dropFirst()
            .split(separator: "/", omittingEmptySubsequences: false)
            .map(String.init)
        guard let leaf = components.last, !leaf.isEmpty else {
            throw Error.openFailed(path: path, errno: EINVAL)
        }

        var directoryDescriptor = Darwin.open(
            "/",
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        guard directoryDescriptor >= 0 else {
            throw openError(path: path, code: errno)
        }
        defer { Darwin.close(directoryDescriptor) }

        var openedPath = ""
        for component in components.dropLast() {
            let nextDescriptor = component.withCString {
                Darwin.openat(
                    directoryDescriptor,
                    $0,
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
                )
            }
            guard nextDescriptor >= 0 else {
                throw openError(path: path, code: errno)
            }
            Darwin.close(directoryDescriptor)
            directoryDescriptor = nextDescriptor
            openedPath += "/\(component)"
            afterDirectoryOpened?(openedPath, directoryDescriptor)
        }
        return try body(directoryDescriptor, leaf, normalizedPath)
    }

    private static func openError(path: String, code: Int32) -> Error {
        switch code {
        case ELOOP, ENOTDIR:
            return .symlinkRefused(path: path)
        case EEXIST:
            return .fileAlreadyExists(path: path)
        default:
            return .openFailed(path: path, errno: code)
        }
    }

    // MARK: - Reads

    /// Read up to `maxBytes` from `path`, refusing to follow symlinks.
    /// Optionally enforce `scope` — the path must be inside scope after
    /// normalization, or `pathOutsideScope` is thrown.
    public static func readBytes(at path: String, maxBytes: Int, scope: String? = nil) throws -> Data {
        guard maxBytes >= 0 else {
            throw Error.readFailed(path: path, errno: EINVAL)
        }
        if let scope, !isPathInScope(path, scope: scope) {
            throw Error.pathOutsideScope(path: path, scope: scope)
        }
        switch BoundedRegularFileReader.readPrefixOutcome(
            at: path,
            maximumBytes: maxBytes
        ) {
        case .success(let snapshot):
            return snapshot.data
        case .rejected(.notFound):
            throw Error.openFailed(path: path, errno: ENOENT)
        case .rejected(.inaccessible):
            throw Error.openFailed(path: path, errno: EACCES)
        case .rejected(.unsafeCarrier):
            throw Error.symlinkRefused(path: path)
        case .rejected(.invalidRequest):
            throw Error.readFailed(path: path, errno: EINVAL)
        case .rejected(.oversized):
            // Prefix mode never rejects solely because the full file is larger.
            throw Error.readFailed(path: path, errno: EFBIG)
        case .rejected(.changedDuringRead), .rejected(.ioFailure):
            throw Error.readFailed(path: path, errno: EIO)
        }
    }

    /// Returns true if `path` is a regular file (no symlinks followed)
    /// and the file is inside `scope` if provided. Safe replacement for
    /// FileManager.fileExists — which follows symlinks.
    public static func isSafeRegularFile(at path: String, scope: String? = nil) -> Bool {
        if let scope, !isPathInScope(path, scope: scope) { return false }
        guard case .success = BoundedRegularFileReader.readPrefixOutcome(
            at: path,
            maximumBytes: 0
        ) else { return false }
        return true
    }
}
