// SecureFileIO.swift
// MacCrabCore
//
// Symlink-safe + race-safe file I/O primitives. v1.12.0 hardening pass
// after the pre-release audit flagged TOCTOU races in HoneyfileManager
// and arbitrary-path traversal in PackageContentAnalyzer /
// PromptIntentBridge.
//
// All public helpers:
//   - Use POSIX open(2) directly with O_NOFOLLOW (refuse-on-symlink)
//     and O_CLOEXEC (no leaked fd's into child processes).
//   - For writes, also add O_EXCL — refuses to clobber an existing
//     file. Defeats the "win the race + plant a symlink" TOCTOU
//     vector against the existence check that FileManager.fileExists
//     leaves wide open.
//   - For reads, also enforce a caller-supplied scope prefix —
//     a path that's outside the scope after symlink-free
//     `realpath` resolution is rejected.

import Foundation
import Darwin

public enum SecureFileIO {

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

    /// Best-effort canonical form. Resolves symlinks when the path
    /// already exists on disk (read operations / extant dirs) but
    /// falls back to lexical standardization when the path doesn't
    /// exist yet (atomicCreate target file). The lexical fallback is
    /// still safer than the pre-fix code because writes use O_NOFOLLOW
    /// at the final component AND fail with EEXIST if a symlink-target
    /// file already exists.
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

    /// Write `data` to `path` atomically, refusing to clobber, refusing
    /// to follow symlinks, with the chosen POSIX mode. Throws
    /// `SecureFileIO.Error` on failure.
    /// Use mode 0o400 for credential-shaped bait, 0o600 for
    /// MacCrab-private state, 0o644 for user-visible bait files.
    public static func atomicCreate(at path: String, data: Data, mode: mode_t) throws {
        // Open with O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC.
        // O_EXCL means "fail if file exists" — TOCTOU-safe; the kernel
        // does the existence check + creation atomically.
        // O_NOFOLLOW means "fail if the path is a symlink" — defeats
        // the "plant a symlink at the target" attack.
        let fd = path.withCString { cpath -> Int32 in
            return open(cpath, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode)
        }
        guard fd >= 0 else {
            switch errno {
            case EEXIST: throw Error.fileAlreadyExists(path: path)
            case ELOOP:  throw Error.symlinkRefused(path: path)
            default:     throw Error.openFailed(path: path, errno: errno)
            }
        }
        defer { close(fd) }

        try data.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) throws in
            guard let baseAddress = buffer.baseAddress else { return }
            var remaining = buffer.count
            var ptr = baseAddress
            while remaining > 0 {
                let written = write(fd, ptr, remaining)
                if written < 0 {
                    if errno == EINTR { continue }
                    throw Error.writeFailed(path: path, errno: errno)
                }
                if written == 0 { break }
                remaining -= written
                ptr = ptr.advanced(by: written)
            }
        }

        // Force POSIX mode after write — open's mode arg can be masked
        // by umask; fchmod() ensures we get exactly what we asked for.
        _ = fchmod(fd, mode)
    }

    // MARK: - Reads

    /// Read up to `maxBytes` from `path`, refusing to follow symlinks.
    /// Optionally enforce `scope` — the path must be inside scope after
    /// normalization, or `pathOutsideScope` is thrown.
    public static func readBytes(at path: String, maxBytes: Int, scope: String? = nil) throws -> Data {
        if let scope, !isPathInScope(path, scope: scope) {
            throw Error.pathOutsideScope(path: path, scope: scope)
        }
        let fd = path.withCString { cpath -> Int32 in
            return open(cpath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        }
        guard fd >= 0 else {
            switch errno {
            case ELOOP: throw Error.symlinkRefused(path: path)
            default:    throw Error.openFailed(path: path, errno: errno)
            }
        }
        defer { close(fd) }

        var buffer = Data(count: maxBytes)
        let actuallyRead = buffer.withUnsafeMutableBytes { (raw: UnsafeMutableRawBufferPointer) -> Int in
            guard let base = raw.baseAddress else { return -1 }
            var total = 0
            while total < maxBytes {
                let n = read(fd, base.advanced(by: total), maxBytes - total)
                if n < 0 {
                    if errno == EINTR { continue }
                    return -1
                }
                if n == 0 { break } // EOF
                total += n
            }
            return total
        }
        if actuallyRead < 0 {
            throw Error.readFailed(path: path, errno: errno)
        }
        return buffer.prefix(actuallyRead)
    }

    /// Returns true if `path` is a regular file (no symlinks followed)
    /// and the file is inside `scope` if provided. Safe replacement for
    /// FileManager.fileExists — which follows symlinks.
    public static func isSafeRegularFile(at path: String, scope: String? = nil) -> Bool {
        if let scope, !isPathInScope(path, scope: scope) { return false }
        var st = stat()
        let result = path.withCString { lstat($0, &st) }
        guard result == 0 else { return false }
        return (st.st_mode & S_IFMT) == S_IFREG
    }
}
