// PluginBundleSnapshot — immutable handoff for Tier-B plugin installation.
//
// A mode-0700 temporary directory is private from other users, not from another
// process running as the same account. Catalog verification and installation
// must therefore share captured bytes rather than reopen a staging pathname.

import Darwin
import Foundation

public struct PluginBundleSnapshot: Sendable, Equatable {
    public enum SnapshotError: Error, CustomStringConvertible, Equatable {
        case sourceNotDirectory(String)
        case unsafeEntry(String)
        case unexpectedEntry(String)
        case missingEntry(String)
        case oversizedEntry(path: String, maximum: Int)
        case changedDuringRead(String)
        case io(String)

        public var description: String {
            switch self {
            case .sourceNotDirectory(let path):
                return "plugin bundle source is not a no-follow directory: \(path)"
            case .unsafeEntry(let path):
                return "plugin bundle contains a link or non-regular entry: \(path)"
            case .unexpectedEntry(let path):
                return "plugin bundle contains an unexpected entry: \(path)"
            case .missingEntry(let path):
                return "plugin bundle is missing required entry: \(path)"
            case .oversizedEntry(let path, let maximum):
                return "plugin bundle entry \(path) exceeds \(maximum) bytes"
            case .changedDuringRead(let path):
                return "plugin bundle changed while it was being snapshotted: \(path)"
            case .io(let detail):
                return "plugin bundle snapshot I/O failed: \(detail)"
            }
        }
    }

    /// The signed bundle format is deliberately exact. In particular, no
    /// unsigned adjacent dylib/resource is copied into the executable bundle.
    public static let requiredFileNames: Set<String> = [
        "manifest.json", "binary", "signature", "signing.key.pub",
    ]
    public static let maximumSingleFileBytes = 64 * 1_024 * 1_024
    public static let maximumTotalBytes = 128 * 1_024 * 1_024

    private let capturedFiles: [String: Data]

    public init(files: [String: Data]) throws {
        let names = Set(files.keys)
        for missing in Self.requiredFileNames.subtracting(names).sorted() {
            throw SnapshotError.missingEntry(missing)
        }
        for unexpected in names.subtracting(Self.requiredFileNames).sorted() {
            throw SnapshotError.unexpectedEntry(unexpected)
        }

        var total = 0
        for (path, data) in files {
            guard data.count <= Self.maximumSingleFileBytes else {
                throw SnapshotError.oversizedEntry(
                    path: path,
                    maximum: Self.maximumSingleFileBytes
                )
            }
            let addition = total.addingReportingOverflow(data.count)
            guard !addition.overflow, addition.partialValue <= Self.maximumTotalBytes else {
                throw SnapshotError.oversizedEntry(
                    path: path,
                    maximum: Self.maximumTotalBytes
                )
            }
            total = addition.partialValue
        }
        self.capturedFiles = files
    }

    public func data(at relativePath: String) -> Data? {
        capturedFiles[relativePath]
    }

    public var manifestData: Data { capturedFiles["manifest.json"]! }
    public var binaryData: Data { capturedFiles["binary"]! }
    public var signatureData: Data { capturedFiles["signature"]! }
    public var publicKeyData: Data { capturedFiles["signing.key.pub"]! }

    /// Capture the documented four-file bundle through one pinned directory
    /// descriptor. This removes the installer's verify-then-copy pathname race:
    /// every later trust decision and every written destination byte comes from
    /// this value. Per-file metadata is checked before/after each exact read and
    /// the directory identity/timestamps/census are checked before/after the
    /// whole capture.
    public static func capture(sourceDirectory: URL) throws -> PluginBundleSnapshot {
        let path = sourceDirectory.path
        let directoryFD = path.withCString {
            Darwin.open($0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        }
        guard directoryFD >= 0 else {
            throw SnapshotError.sourceNotDirectory(path)
        }
        defer { Darwin.close(directoryFD) }

        var rootBefore = stat()
        guard Darwin.fstat(directoryFD, &rootBefore) == 0,
              (rootBefore.st_mode & S_IFMT) == S_IFDIR else {
            throw SnapshotError.sourceNotDirectory(path)
        }

        let beforeNames = try directoryEntryNames(directoryFD: directoryFD)
        try validateEntryCensus(beforeNames, directoryFD: directoryFD, rootPath: path)

        var files: [String: Data] = [:]
        files.reserveCapacity(Self.requiredFileNames.count)
        for name in Self.requiredFileNames.sorted() {
            files[name] = try readStableRegularFile(
                directoryFD: directoryFD,
                name: name,
                rootPath: path,
                maximumBytes: Self.maximumSingleFileBytes
            )
        }

        let afterNames = try directoryEntryNames(directoryFD: directoryFD)
        var rootAfter = stat()
        guard Darwin.fstat(directoryFD, &rootAfter) == 0,
              sameDirectoryIdentityAndGeneration(rootBefore, rootAfter),
              beforeNames == afterNames else {
            throw SnapshotError.changedDuringRead(path)
        }
        return try PluginBundleSnapshot(files: files)
    }

    private static func validateEntryCensus(
        _ names: Set<String>,
        directoryFD: Int32,
        rootPath: String
    ) throws {
        for name in names.sorted() {
            var metadata = stat()
            let status = name.withCString {
                Darwin.fstatat(directoryFD, $0, &metadata, AT_SYMLINK_NOFOLLOW)
            }
            guard status == 0 else {
                throw SnapshotError.io("fstatat \(rootPath)/\(name): errno \(errno)")
            }
            let type = metadata.st_mode & S_IFMT
            if type == S_IFLNK || type != S_IFREG || metadata.st_nlink != 1 {
                throw SnapshotError.unsafeEntry("\(rootPath)/\(name)")
            }
            guard Self.requiredFileNames.contains(name) else {
                throw SnapshotError.unexpectedEntry("\(rootPath)/\(name)")
            }
        }
        for missing in Self.requiredFileNames.subtracting(names).sorted() {
            throw SnapshotError.missingEntry("\(rootPath)/\(missing)")
        }
    }

    /// Read at most five names: four admitted entries plus one sentinel. This
    /// keeps an attacker from turning an exact-layout rejection into unbounded
    /// name buffering.
    private static func directoryEntryNames(directoryFD: Int32) throws -> Set<String> {
        // `dup(directoryFD)` would share the same open-file-description offset:
        // the first readdir census would leave the second at EOF and make every
        // unchanged bundle look mutated. Reopen `.` relative to the already-
        // pinned descriptor to get an independent stream for each census while
        // retaining the exact same directory inode.
        let censusFD = ".".withCString {
            Darwin.openat(
                directoryFD,
                $0,
                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
            )
        }
        guard censusFD >= 0, let stream = Darwin.fdopendir(censusFD) else {
            if censusFD >= 0 { Darwin.close(censusFD) }
            throw SnapshotError.io("fdopendir failed: errno \(errno)")
        }
        defer { Darwin.closedir(stream) }

        var names = Set<String>()
        while let entry = Darwin.readdir(stream) {
            let name = withUnsafePointer(to: &entry.pointee.d_name) { pointer in
                pointer.withMemoryRebound(to: CChar.self, capacity: Int(MAXNAMLEN) + 1) {
                    String(validatingUTF8: $0)
                }
            }
            guard let name else {
                throw SnapshotError.unsafeEntry("<non-UTF8 name>")
            }
            if name == "." || name == ".." { continue }
            names.insert(name)
            if names.count > Self.requiredFileNames.count {
                // One over-cap name is enough to prove the exact layout failed.
                break
            }
        }
        return names
    }

    private static func readStableRegularFile(
        directoryFD: Int32,
        name: String,
        rootPath: String,
        maximumBytes: Int
    ) throws -> Data {
        let descriptor = name.withCString {
            Darwin.openat(
                directoryFD,
                $0,
                O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW
            )
        }
        guard descriptor >= 0 else {
            throw SnapshotError.io("openat \(rootPath)/\(name): errno \(errno)")
        }
        defer { Darwin.close(descriptor) }

        var before = stat()
        guard Darwin.fstat(descriptor, &before) == 0,
              (before.st_mode & S_IFMT) == S_IFREG,
              before.st_nlink == 1,
              before.st_size >= 0 else {
            throw SnapshotError.unsafeEntry("\(rootPath)/\(name)")
        }
        guard before.st_size <= off_t(maximumBytes) else {
            throw SnapshotError.oversizedEntry(path: name, maximum: maximumBytes)
        }

        let expected = Int(before.st_size)
        var output = Data(count: expected)
        let actual = output.withUnsafeMutableBytes { bytes -> Int in
            guard expected > 0 else { return 0 }
            guard let base = bytes.baseAddress else { return -1 }
            var offset = 0
            while offset < expected {
                let count = Darwin.read(
                    descriptor,
                    base.advanced(by: offset),
                    expected - offset
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
        guard actual == expected else {
            throw SnapshotError.changedDuringRead("\(rootPath)/\(name)")
        }
        var excess: UInt8 = 0
        guard Darwin.read(descriptor, &excess, 1) == 0 else {
            throw SnapshotError.changedDuringRead("\(rootPath)/\(name)")
        }

        var after = stat()
        guard Darwin.fstat(descriptor, &after) == 0,
              sameFileIdentityAndGeneration(before, after) else {
            throw SnapshotError.changedDuringRead("\(rootPath)/\(name)")
        }
        return output
    }

    private static func sameFileIdentityAndGeneration(_ lhs: stat, _ rhs: stat) -> Bool {
        (rhs.st_mode & S_IFMT) == S_IFREG
            && lhs.st_dev == rhs.st_dev
            && lhs.st_ino == rhs.st_ino
            && lhs.st_nlink == rhs.st_nlink
            && lhs.st_size == rhs.st_size
            && lhs.st_mtimespec.tv_sec == rhs.st_mtimespec.tv_sec
            && lhs.st_mtimespec.tv_nsec == rhs.st_mtimespec.tv_nsec
            && lhs.st_ctimespec.tv_sec == rhs.st_ctimespec.tv_sec
            && lhs.st_ctimespec.tv_nsec == rhs.st_ctimespec.tv_nsec
    }

    private static func sameDirectoryIdentityAndGeneration(_ lhs: stat, _ rhs: stat) -> Bool {
        (rhs.st_mode & S_IFMT) == S_IFDIR
            && lhs.st_dev == rhs.st_dev
            && lhs.st_ino == rhs.st_ino
            && lhs.st_mtimespec.tv_sec == rhs.st_mtimespec.tv_sec
            && lhs.st_mtimespec.tv_nsec == rhs.st_mtimespec.tv_nsec
            && lhs.st_ctimespec.tv_sec == rhs.st_ctimespec.tv_sec
            && lhs.st_ctimespec.tv_nsec == rhs.st_ctimespec.tv_nsec
    }
}
