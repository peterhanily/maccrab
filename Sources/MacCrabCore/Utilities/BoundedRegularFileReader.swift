// BoundedRegularFileReader.swift
// MacCrabCore
//
// Safe reader for local files whose surrounding bundle/tree may be controlled
// by another user. Foundation's Data(contentsOf:) follows links, opens FIFOs
// blocking, accepts devices, and allocates until EOF. Root inventory lanes must
// instead open no-follow/nonblocking, prove a regular file on the descriptor,
// enforce size before allocation, and reject concurrent mutation.

import Foundation
import Darwin

public enum BoundedRegularFileReader {
    /// Metadata captured from the same descriptor that supplied `data`.
    /// Callers making age or ownership decisions must not re-stat the path,
    /// because the pathname can name a different inode after this read.
    public struct Snapshot: Sendable, Equatable {
        public let data: Data
        public let modificationDate: Date
        /// Metadata-change time cannot be restored by an unprivileged writer;
        /// it closes same-size/same-mtime replacement cache collisions.
        public let statusChangeDate: Date
        public let statusChangeSeconds: Int64
        public let statusChangeNanoseconds: Int64
        public let ownerUID: UInt32
        public let deviceID: UInt64
        public let inodeNumber: UInt64
        /// Full descriptor size, even when `data` is a bounded prefix.
        public let sizeBytes: Int64

        fileprivate init(data: Data, metadata: stat) {
            self.data = data
            self.modificationDate = Date(
                timeIntervalSince1970: Double(metadata.st_mtimespec.tv_sec)
                    + Double(metadata.st_mtimespec.tv_nsec) / 1_000_000_000
            )
            self.statusChangeDate = Date(
                timeIntervalSince1970: Double(metadata.st_ctimespec.tv_sec)
                    + Double(metadata.st_ctimespec.tv_nsec) / 1_000_000_000
            )
            self.statusChangeSeconds = Int64(metadata.st_ctimespec.tv_sec)
            self.statusChangeNanoseconds = Int64(metadata.st_ctimespec.tv_nsec)
            self.ownerUID = metadata.st_uid
            self.deviceID = UInt64(metadata.st_dev)
            self.inodeNumber = UInt64(metadata.st_ino)
            self.sizeBytes = metadata.st_size
        }
    }

    /// A typed rejection keeps security-sensitive callers from treating an
    /// attacker-controlled carrier as merely absent or malformed input.
    public enum Rejection: Sendable, Equatable {
        case invalidRequest
        case notFound
        case inaccessible
        case unsafeCarrier
        case oversized(actualBytes: Int64, maximumBytes: Int)
        case changedDuringRead
        case ioFailure
    }

    public enum Outcome: Sendable, Equatable {
        case success(Snapshot)
        case rejected(Rejection)
    }

    public static func read(
        at path: String,
        maximumBytes: Int
    ) -> Data? {
        guard case .success(let snapshot) = readOutcome(
            at: path,
            maximumBytes: maximumBytes
        ) else { return nil }
        return snapshot.data
    }

    /// Typed form for callers that must distinguish expected absence from an
    /// oversized, non-regular, linked, or concurrently-mutated carrier.
    public static func readOutcome(
        at path: String,
        maximumBytes: Int
    ) -> Outcome {
        readOutcome(
            at: path,
            maximumBytes: maximumBytes,
            allowPrefix: false,
            afterDirectoryOpened: nil,
            afterMetadataValidated: nil
        )
    }

    /// Read at most `maximumBytes` from the start of a stable regular file.
    /// Unlike `readOutcome`, a larger file is accepted and `Snapshot.sizeBytes`
    /// reports its full descriptor size. This preserves header/content-probe
    /// semantics without reintroducing path-based preflight races.
    public static func readPrefixOutcome(
        at path: String,
        maximumBytes: Int
    ) -> Outcome {
        readOutcome(
            at: path,
            maximumBytes: maximumBytes,
            allowPrefix: true,
            afterDirectoryOpened: nil,
            afterMetadataValidated: nil
        )
    }

    static func read(
        at path: String,
        maximumBytes: Int,
        afterMetadataValidated: @escaping (Int32) -> Void
    ) -> Data? {
        guard case .success(let snapshot) = readOutcome(
            at: path,
            maximumBytes: maximumBytes,
            allowPrefix: false,
            afterDirectoryOpened: nil,
            afterMetadataValidated: afterMetadataValidated
        ) else { return nil }
        return snapshot.data
    }

    static func read(
        at path: String,
        maximumBytes: Int,
        afterDirectoryOpened: ((String, Int32) -> Void)?,
        afterMetadataValidated: ((Int32) -> Void)? = nil
    ) -> Data? {
        guard case .success(let snapshot) = readOutcome(
            at: path,
            maximumBytes: maximumBytes,
            allowPrefix: false,
            afterDirectoryOpened: afterDirectoryOpened,
            afterMetadataValidated: afterMetadataValidated
        ) else { return nil }
        return snapshot.data
    }

    private static func readOutcome(
        at path: String,
        maximumBytes: Int,
        allowPrefix: Bool,
        afterDirectoryOpened: ((String, Int32) -> Void)?,
        afterMetadataValidated: ((Int32) -> Void)? = nil
    ) -> Outcome {
        guard maximumBytes >= 0,
              let normalizedPath = normalizedAbsolutePath(path) else {
            return .rejected(.invalidRequest)
        }

        let components = normalizedPath
            .dropFirst()
            .split(separator: "/", omittingEmptySubsequences: false)
            .map(String.init)
        guard let leaf = components.last, !leaf.isEmpty else {
            return .rejected(.invalidRequest)
        }

        // Open the root once and resolve every subsequent component relative
        // to an already-open directory descriptor. A path-based lstat/open
        // pair still follows intermediate symlinks and lets an attacker swap a
        // validated parent before the leaf open. O_DIRECTORY|O_NOFOLLOW on
        // each openat closes both windows; renaming a parent merely leaves us
        // walking the directory inode we already pinned.
        var directoryDescriptor = Darwin.open(
            "/",
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        guard directoryDescriptor >= 0 else {
            return .rejected(rejectionForOpenError(errno))
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
                return .rejected(rejectionForOpenError(errno))
            }
            Darwin.close(directoryDescriptor)
            directoryDescriptor = nextDescriptor
            openedPath += "/\(component)"

            // Internal test seam: a fixture can rename/replace the textual
            // parent here and prove that the next open remains relative to the
            // pinned descriptor. Production callers never supply it.
            afterDirectoryOpened?(openedPath, directoryDescriptor)
        }

        let descriptor = leaf.withCString {
            Darwin.openat(
                directoryDescriptor,
                $0,
                O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW
            )
        }
        guard descriptor >= 0 else {
            return .rejected(rejectionForOpenError(errno))
        }
        defer { Darwin.close(descriptor) }

        var before = stat()
        guard Darwin.fstat(descriptor, &before) == 0 else {
            return .rejected(.ioFailure)
        }
        guard (before.st_mode & S_IFMT) == S_IFREG,
              before.st_nlink == 1,
              before.st_size >= 0 else {
            return .rejected(.unsafeCarrier)
        }
        guard allowPrefix || before.st_size <= Int64(maximumBytes) else {
            return .rejected(.oversized(
                actualBytes: before.st_size,
                maximumBytes: maximumBytes
            ))
        }

        // Test seam for deterministic concurrent-truncation verification. It is
        // internal to MacCrabCore and never used by production callers.
        afterMetadataValidated?(descriptor)

        let expectedSize = allowPrefix
            ? min(Int(before.st_size), maximumBytes)
            : Int(before.st_size)
        var output = Data(count: expectedSize)
        let actualSize = output.withUnsafeMutableBytes { bytes -> Int in
            guard expectedSize > 0 else { return 0 }
            guard let base = bytes.baseAddress else { return -1 }
            var offset = 0
            while offset < expectedSize {
                let count = Darwin.read(
                    descriptor,
                    base.advanced(by: offset),
                    expectedSize - offset
                )
                if count < 0 {
                    if errno == EINTR { continue }
                    return -1
                }
                if count == 0 { break }
                offset += count
            }
            return offset
        }
        guard actualSize >= 0 else { return .rejected(.ioFailure) }
        guard actualSize == expectedSize else {
            return .rejected(.changedDuringRead)
        }

        if !allowPrefix || before.st_size <= Int64(maximumBytes) {
            // Exact reads must observe EOF. Prefix reads do the same when the
            // full file fit; when it did not, the retained prefix is complete
            // by definition and descriptor metadata below still catches a
            // concurrent size/mtime/ctime mutation.
            var excess: UInt8 = 0
            let extraCount = Darwin.read(descriptor, &excess, 1)
            guard extraCount >= 0 else { return .rejected(.ioFailure) }
            guard extraCount == 0 else { return .rejected(.changedDuringRead) }
        }

        var after = stat()
        guard Darwin.fstat(descriptor, &after) == 0,
              (after.st_mode & S_IFMT) == S_IFREG,
              before.st_dev == after.st_dev,
              before.st_ino == after.st_ino,
              before.st_nlink == after.st_nlink,
              before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
              before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec else {
            return .rejected(.changedDuringRead)
        }
        return .success(Snapshot(data: output, metadata: after))
    }

    private static func rejectionForOpenError(_ code: Int32) -> Rejection {
        switch code {
        case ENOENT:
            return .notFound
        case EACCES, EPERM:
            return .inaccessible
        case ELOOP, ENOTDIR:
            return .unsafeCarrier
        default:
            return .ioFailure
        }
    }

    /// macOS exposes `/var` and `/tmp` as symlinks into `/private`. Those are
    /// the only aliases this root-reachable reader intentionally accepts.
    /// Rewriting only a complete leading component avoids treating lookalikes
    /// such as `/variable` or `/tmp-owned` as trusted aliases. All other empty,
    /// dot, parent, relative, repeated-slash, and NUL-bearing paths fail closed
    /// instead of being silently canonicalized by Foundation.
    /// Shared by descriptor-relative readers and writers so `/tmp` and `/var`
    /// aliases, dot components, repeated separators, and NUL handling cannot
    /// drift between the two privileged filesystem boundaries.
    static func normalizedAbsolutePath(_ path: String) -> String? {
        guard path.first == "/", !path.utf8.contains(0) else { return nil }

        let normalized: String
        if path == "/var" || path.hasPrefix("/var/") {
            normalized = "/private" + path
        } else if path == "/tmp" || path.hasPrefix("/tmp/") {
            normalized = "/private" + path
        } else {
            normalized = path
        }

        let components = normalized
            .dropFirst()
            .split(separator: "/", omittingEmptySubsequences: false)
        guard !components.isEmpty,
              components.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
            return nil
        }
        return normalized
    }
}
