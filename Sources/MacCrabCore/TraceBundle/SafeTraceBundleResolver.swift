// SafeTraceBundleResolver.swift
// MacCrabCore
//
// A directory that passed lstat-based validation is not an immutable input: a
// writer can replace a file with a link/FIFO, grow it past the byte ceiling, or
// mix two bundle versions before the caller's later Data(contentsOf:) reads.
// Resolve both archives and already-unpacked directories to one private,
// bounded snapshot and make every downstream reader consume that snapshot.

import Darwin
import Foundation

public enum SafeTraceBundleResolver {
    /// One cleanup owner for either an archive extraction or a directory
    /// snapshot. The initializer is deliberately not public: a caller cannot
    /// forge the type token around an untrusted directory and bypass resolution.
    public final class Resolution: @unchecked Sendable {
        public let bundleDirectory: URL
        public let temporaryRoot: URL

        /// The filesystem copy is retained only for consumers that must hand a
        /// path to a platform tool. Semantic readers must use these captured
        /// bytes: a mode-0700 directory is still writable by another process
        /// running as the same uid.
        private let capturedFiles: [String: Data]
        private let capturedDirectories: Set<String>

        private let lock = NSLock()
        private var hasCleaned = false
        private let cleanupHandler: @Sendable () -> Void

        fileprivate init(
            bundleDirectory: URL,
            temporaryRoot: URL,
            capturedFiles: [String: Data],
            capturedDirectories: Set<String>,
            cleanupHandler: @escaping @Sendable () -> Void
        ) {
            self.bundleDirectory = bundleDirectory
            self.temporaryRoot = temporaryRoot
            self.capturedFiles = capturedFiles
            self.capturedDirectories = capturedDirectories
            self.cleanupHandler = cleanupHandler
        }

        /// Exact logical artifact names captured during the descriptor walk.
        public var artifactPaths: [String] { capturedFiles.keys.sorted() }

        /// Exact logical directory names captured during the descriptor walk;
        /// the bundle root is represented by the empty string.
        public var directoryPaths: [String] { capturedDirectories.sorted() }

        public var artifactByteCount: UInt64 {
            var total: UInt64 = 0
            for data in capturedFiles.values {
                let addition = total.addingReportingOverflow(UInt64(data.count))
                if addition.overflow { return UInt64.max }
                total = addition.partialValue
            }
            return total
        }

        public func containsArtifact(_ relativePath: String) -> Bool {
            capturedFiles[relativePath] != nil
        }

        /// Return the exact bytes captured while resolving the hostile input.
        /// `Data` is copy-on-write, so callers cannot mutate the retained value.
        public func data(at relativePath: String) throws -> Data {
            guard let data = capturedFiles[relativePath] else {
                throw SafeTraceArchiveExtractor.ExtractionError
                    .unsafeFilesystemEntry(
                        path: relativePath,
                        reason: "artifact was not present in the resolved snapshot"
                    )
            }
            return data
        }

        public func dataIfPresent(at relativePath: String) -> Data? {
            capturedFiles[relativePath]
        }

        func snapshotArtifacts(
            excludingRootIntegrity: Bool
        ) -> [(path: String, data: Data)] {
            capturedFiles.keys.sorted().compactMap { path in
                if excludingRootIntegrity,
                   BundleArtifactPathPolicy.isRootIntegrityArtifact(relativePath: path) {
                    return nil
                }
                return (path, capturedFiles[path]!)
            }
        }

        func hasSameCapturedContents(as other: Resolution) -> Bool {
            capturedDirectories == other.capturedDirectories
                && capturedFiles == other.capturedFiles
        }

        /// Idempotent so explicit cleanup before Darwin.exit and a defensive
        /// defer/deinit can safely converge on the same owner.
        public func cleanup() {
            lock.lock()
            let shouldClean = !hasCleaned
            hasCleaned = true
            lock.unlock()
            if shouldClean { cleanupHandler() }
        }

        deinit { cleanup() }
    }

    struct TestHooks {
        var afterFileMetadataValidated: ((String) -> Void)?
        var beforeDirectoryPostflight: ((String) -> Void)?
        var afterDirectoryEntryRead: ((String) -> Void)?

        init(
            afterFileMetadataValidated: ((String) -> Void)? = nil,
            beforeDirectoryPostflight: ((String) -> Void)? = nil,
            afterDirectoryEntryRead: ((String) -> Void)? = nil
        ) {
            self.afterFileMetadataValidated = afterFileMetadataValidated
            self.beforeDirectoryPostflight = beforeDirectoryPostflight
            self.afterDirectoryEntryRead = afterDirectoryEntryRead
        }
    }

    /// Resolve an archive or a real directory to a private bounded tree. The
    /// source leaf and every parent directory are opened one component at a
    /// time with O_NOFOLLOW. macOS's two standard lexical aliases are expanded
    /// explicitly; every other symlink component is rejected.
    public static func resolve(
        inputAt inputURL: URL,
        limits: SafeTraceArchiveExtractor.Limits = .default
    ) throws -> Resolution {
        try resolve(inputAt: inputURL, limits: limits, testHooks: TestHooks())
    }

    static func resolve(
        inputAt inputURL: URL,
        limits: SafeTraceArchiveExtractor.Limits,
        testHooks: TestHooks
    ) throws -> Resolution {
        try SafeTraceArchiveExtractor.validateLimits(limits)
        let opened = try openInputPath(inputURL)
        defer { opened.close() }

        var metadata = stat()
        guard Darwin.fstat(opened.leafDescriptor, &metadata) == 0 else {
            throw filesystemError("fstat failed for input \(opened.displayPath)")
        }
        switch metadata.st_mode & S_IFMT {
        case S_IFDIR:
            return try snapshotDirectory(
                sourceDescriptor: opened.leafDescriptor,
                sourcePath: opened.displayPath,
                limits: limits,
                testHooks: testHooks
            )
        case S_IFREG:
            return try resolveArchive(
                sourceDescriptor: opened.leafDescriptor,
                sourcePath: opened.displayPath,
                metadata: metadata,
                limits: limits
            )
        default:
            throw SafeTraceArchiveExtractor.ExtractionError.inputNotRegular(
                opened.displayPath
            )
        }
    }

    // MARK: - Secure path walk

    private final class OpenedInputPath {
        let leafDescriptor: Int32
        let displayPath: String
        private var descriptors: [Int32]
        private var closed = false

        init(leafDescriptor: Int32, displayPath: String, descriptors: [Int32]) {
            self.leafDescriptor = leafDescriptor
            self.displayPath = displayPath
            self.descriptors = descriptors
        }

        func close() {
            guard !closed else { return }
            closed = true
            for descriptor in descriptors.reversed() {
                Darwin.close(descriptor)
            }
            descriptors.removeAll(keepingCapacity: false)
        }

        deinit { close() }
    }

    private static func openInputPath(_ url: URL) throws -> OpenedInputPath {
        let rawPath = url.path
        guard rawPath.first == "/", !rawPath.utf8.contains(0) else {
            throw SafeTraceArchiveExtractor.ExtractionError.unsafeFilesystemEntry(
                path: rawPath,
                reason: "bundle input must be an absolute NUL-free path"
            )
        }
        var components = rawPath.split(separator: "/", omittingEmptySubsequences: true)
            .map(String.init)
        guard !components.isEmpty,
              components.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
            throw SafeTraceArchiveExtractor.ExtractionError.unsafeFilesystemEntry(
                path: rawPath,
                reason: "bundle input has an empty, dot, or parent component"
            )
        }

        // `/var` and `/tmp` are platform-owned symlinks to `/private/...` on
        // macOS. Expand only these documented aliases; never canonicalize an
        // attacker-controlled component by following it.
        if components[0] == "var" {
            components.insert("private", at: 0)
        } else if components[0] == "tmp" {
            components.insert("private", at: 0)
        }

        let rootDescriptor = Darwin.open(
            "/",
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
        )
        guard rootDescriptor >= 0 else {
            throw filesystemError("could not open filesystem root")
        }
        var descriptors = [rootDescriptor]
        var parent = rootDescriptor

        for (index, component) in components.enumerated() {
            let isLeaf = index == components.count - 1
            var flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
            if !isLeaf { flags |= O_DIRECTORY }
            let descriptor = component.withCString {
                Darwin.openat(parent, $0, flags)
            }
            guard descriptor >= 0 else {
                let savedErrno = errno
                for openDescriptor in descriptors.reversed() {
                    Darwin.close(openDescriptor)
                }
                throw SafeTraceArchiveExtractor.ExtractionError.unsafeFilesystemEntry(
                    path: rawPath,
                    reason: "no-follow component open failed at \(component): errno \(savedErrno)"
                )
            }
            descriptors.append(descriptor)
            parent = descriptor

            if !isLeaf {
                var metadata = stat()
                guard Darwin.fstat(descriptor, &metadata) == 0,
                      (metadata.st_mode & S_IFMT) == S_IFDIR else {
                    let savedErrno = errno
                    for openDescriptor in descriptors.reversed() {
                        Darwin.close(openDescriptor)
                    }
                    throw SafeTraceArchiveExtractor.ExtractionError.unsafeFilesystemEntry(
                        path: rawPath,
                        reason: "parent component \(component) is not a real directory: errno \(savedErrno)"
                    )
                }
            }
        }
        return OpenedInputPath(
            leafDescriptor: parent,
            displayPath: "/" + components.joined(separator: "/"),
            descriptors: descriptors
        )
    }

    // MARK: - Directory snapshot

    private struct DirectoryFrame {
        let sourceDescriptor: Int32
        let destinationDescriptor: Int32
        let relativePath: String
    }

    private struct FilesystemIdentity: Sendable {
        let device: dev_t
        let inode: ino_t
    }

    private final class DescriptorOwner {
        private var descriptors = Set<Int32>()

        func retain(_ descriptor: Int32) { descriptors.insert(descriptor) }

        func close(_ descriptor: Int32) {
            guard descriptors.remove(descriptor) != nil else { return }
            Darwin.close(descriptor)
        }

        deinit {
            for descriptor in descriptors { Darwin.close(descriptor) }
        }
    }

    private static func snapshotDirectory(
        sourceDescriptor: Int32,
        sourcePath: String,
        limits: SafeTraceArchiveExtractor.Limits,
        testHooks: TestHooks
    ) throws -> Resolution {
        let temporaryRoot = try makePrivateTemporaryRoot(prefix: "maccrab-safe-resolve")
        var preserveTemporaryRoot = false
        defer {
            if !preserveTemporaryRoot {
                try? FileManager.default.removeItem(at: temporaryRoot)
            }
        }
        try requireSnapshotCapacity(
            at: temporaryRoot,
            compressedBytes: 0,
            compressedCopies: 0,
            limits: limits
        )

        let temporaryDescriptor = Darwin.open(
            temporaryRoot.path,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
        )
        guard temporaryDescriptor >= 0 else {
            throw filesystemError("could not open private snapshot root")
        }
        defer { Darwin.close(temporaryDescriptor) }
        guard TraceBundlePrivateFilePolicy.enforceDirectory(temporaryDescriptor) else {
            throw filesystemError(
                "private snapshot root has unsafe permissions or an extended ACL"
            )
        }
        guard Darwin.mkdirat(temporaryDescriptor, "bundle", mode_t(0o700)) == 0 else {
            throw filesystemError("could not create private bundle snapshot")
        }
        let destinationRoot = Darwin.openat(
            temporaryDescriptor,
            "bundle",
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
        )
        guard destinationRoot >= 0 else {
            throw filesystemError("could not open private bundle snapshot")
        }
        guard TraceBundlePrivateFilePolicy.enforceDirectory(destinationRoot) else {
            Darwin.close(destinationRoot)
            throw filesystemError(
                "private bundle snapshot has unsafe permissions or an extended ACL"
            )
        }

        let sourceRoot = Darwin.dup(sourceDescriptor)
        guard sourceRoot >= 0 else {
            Darwin.close(destinationRoot)
            throw filesystemError("could not retain source bundle descriptor")
        }

        let owner = DescriptorOwner()
        owner.retain(sourceRoot)
        owner.retain(destinationRoot)
        var stack = [DirectoryFrame(
            sourceDescriptor: sourceRoot,
            destinationDescriptor: destinationRoot,
            relativePath: ""
        )]
        var entryCount = 0
        var totalBytes: UInt64 = 0
        var capturedFiles: [String: Data] = [:]
        var capturedDirectories: Set<String> = [""]

        while let frame = stack.popLast() {
            var before = stat()
            guard Darwin.fstat(frame.sourceDescriptor, &before) == 0,
                  (before.st_mode & S_IFMT) == S_IFDIR else {
                throw unsafeEntry(
                    sourcePath: sourcePath,
                    relativePath: frame.relativePath,
                    reason: "source directory changed type"
                )
            }

            let remainingEntryBudget = limits.maxEntries - entryCount
            let names = try directoryEntryNames(
                descriptor: frame.sourceDescriptor,
                sourcePath: sourcePath,
                relativePath: frame.relativePath,
                remainingEntryBudget: remainingEntryBudget,
                maximumEntries: limits.maxEntries,
                afterEntryRead: testHooks.afterDirectoryEntryRead
            )
            var childFrames: [DirectoryFrame] = []
            childFrames.reserveCapacity(names.count)

            for name in names {
                try validateSnapshotComponent(name, under: frame.relativePath)
                entryCount += 1
                guard entryCount <= limits.maxEntries else {
                    throw SafeTraceArchiveExtractor.ExtractionError.entryCountLimit(
                        actual: entryCount,
                        maximum: limits.maxEntries
                    )
                }
                let relative = joinedPath(frame.relativePath, name)
                let childSource = name.withCString {
                    Darwin.openat(
                        frame.sourceDescriptor,
                        $0,
                        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
                    )
                }
                guard childSource >= 0 else {
                    throw unsafeEntry(
                        sourcePath: sourcePath,
                        relativePath: relative,
                        reason: "no-follow entry open failed: errno \(errno)"
                    )
                }
                owner.retain(childSource)

                var childMetadata = stat()
                guard Darwin.fstat(childSource, &childMetadata) == 0 else {
                    throw unsafeEntry(
                        sourcePath: sourcePath,
                        relativePath: relative,
                        reason: "fstat failed: errno \(errno)"
                    )
                }
                switch childMetadata.st_mode & S_IFMT {
                case S_IFDIR:
                    let madeDirectory = name.withCString {
                        Darwin.mkdirat(frame.destinationDescriptor, $0, mode_t(0o700))
                    }
                    guard madeDirectory == 0 else {
                        throw filesystemError("could not create snapshot directory \(relative)")
                    }
                    let childDestination = name.withCString {
                        Darwin.openat(
                            frame.destinationDescriptor,
                            $0,
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
                        )
                    }
                    guard childDestination >= 0 else {
                        throw filesystemError("could not open snapshot directory \(relative)")
                    }
                    guard TraceBundlePrivateFilePolicy.enforceDirectory(
                        childDestination
                    ) else {
                        Darwin.close(childDestination)
                        throw filesystemError(
                            "snapshot directory \(relative) has unsafe permissions or an extended ACL"
                        )
                    }
                    owner.retain(childDestination)
                    capturedDirectories.insert(relative)
                    childFrames.append(DirectoryFrame(
                        sourceDescriptor: childSource,
                        destinationDescriptor: childDestination,
                        relativePath: relative
                    ))

                case S_IFREG:
                    guard childMetadata.st_nlink == 1 else {
                        throw unsafeEntry(
                            sourcePath: sourcePath,
                            relativePath: relative,
                            reason: "hard-linked files are not allowed"
                        )
                    }
                    guard childMetadata.st_size >= 0,
                          UInt64(childMetadata.st_size) <= UInt64(Int.max) else {
                        throw SafeTraceArchiveExtractor.ExtractionError.singleFileSizeLimit(
                            path: relative,
                            actual: childMetadata.st_size < 0
                                ? UInt64.max
                                : UInt64(childMetadata.st_size),
                            maximum: min(limits.maxSingleFileBytes, UInt64(Int.max))
                        )
                    }
                    let size = UInt64(childMetadata.st_size)
                    guard size <= limits.maxSingleFileBytes else {
                        throw SafeTraceArchiveExtractor.ExtractionError.singleFileSizeLimit(
                            path: relative,
                            actual: size,
                            maximum: limits.maxSingleFileBytes
                        )
                    }
                    let addition = totalBytes.addingReportingOverflow(size)
                    guard !addition.overflow,
                          addition.partialValue <= limits.maxTotalFileBytes else {
                        throw SafeTraceArchiveExtractor.ExtractionError.totalFileSizeLimit(
                            actual: addition.overflow ? UInt64.max : addition.partialValue,
                            maximum: limits.maxTotalFileBytes
                        )
                    }
                    totalBytes = addition.partialValue
                    testHooks.afterFileMetadataValidated?(relative)
                    capturedFiles[relative] = try copyRegularFile(
                        sourceDescriptor: childSource,
                        before: childMetadata,
                        destinationParent: frame.destinationDescriptor,
                        destinationName: name,
                        sourcePath: sourcePath,
                        relativePath: relative
                    )
                    owner.close(childSource)

                default:
                    throw unsafeEntry(
                        sourcePath: sourcePath,
                        relativePath: relative,
                        reason: "only real directories and regular files are allowed"
                    )
                }
            }

            testHooks.beforeDirectoryPostflight?(frame.relativePath)
            var after = stat()
            guard Darwin.fstat(frame.sourceDescriptor, &after) == 0,
                  sameDirectory(before, after) else {
                throw unsafeEntry(
                    sourcePath: sourcePath,
                    relativePath: frame.relativePath,
                    reason: "directory entry set changed while snapshotting"
                )
            }
            guard TraceBundlePrivateFilePolicy.validateDirectory(
                frame.destinationDescriptor
            ) else {
                throw filesystemError(
                    "snapshot directory \(frame.relativePath) lost its private permissions"
                )
            }
            owner.close(frame.sourceDescriptor)
            owner.close(frame.destinationDescriptor)

            // Reverse-push preserves lexical traversal while retaining every
            // child dirfd opened from the verified parent.
            for child in childFrames.reversed() { stack.append(child) }
        }

        let bundleDirectory = temporaryRoot.appendingPathComponent(
            "bundle",
            isDirectory: true
        )
        let cleanupIdentity = try filesystemIdentity(ofDirectory: temporaryRoot)
        preserveTemporaryRoot = true
        return Resolution(
            bundleDirectory: bundleDirectory,
            temporaryRoot: temporaryRoot,
            capturedFiles: capturedFiles,
            capturedDirectories: capturedDirectories,
            cleanupHandler: {
                removeTemporaryRootIfUnchanged(
                    temporaryRoot,
                    expectedIdentity: cleanupIdentity
                )
            }
        )
    }

    private static func directoryEntryNames(
        descriptor: Int32,
        sourcePath: String,
        relativePath: String,
        remainingEntryBudget: Int,
        maximumEntries: Int,
        afterEntryRead: ((String) -> Void)?
    ) throws -> [String] {
        guard remainingEntryBudget >= 0 else {
            throw SafeTraceArchiveExtractor.ExtractionError.entryCountLimit(
                actual: maximumEntries,
                maximum: maximumEntries
            )
        }
        let duplicate = Darwin.dup(descriptor)
        guard duplicate >= 0 else {
            throw filesystemError("could not duplicate source directory descriptor")
        }
        guard let stream = Darwin.fdopendir(duplicate) else {
            let savedErrno = errno
            Darwin.close(duplicate)
            throw unsafeEntry(
                sourcePath: sourcePath,
                relativePath: relativePath,
                reason: "fdopendir failed: errno \(savedErrno)"
            )
        }
        defer { Darwin.closedir(stream) }

        var names: [String] = []
        errno = 0
        while let entry = Darwin.readdir(stream) {
            let bytes = withUnsafeBytes(of: entry.pointee.d_name) { raw in
                Array(raw.prefix { $0 != 0 })
            }
            guard let name = String(bytes: bytes, encoding: .utf8) else {
                throw unsafeEntry(
                    sourcePath: sourcePath,
                    relativePath: relativePath,
                    reason: "directory entry name is not UTF-8"
                )
            }
            if name == "." || name == ".." { continue }
            afterEntryRead?(name)
            // Enforce the global tree budget while reading the directory, not
            // after collecting and sorting all of its names. A hostile direct
            // bundle can otherwise make the bounded resolver allocate for an
            // arbitrarily padded directory before the outer traversal notices
            // `maxEntries` was exceeded.
            guard names.count < remainingEntryBudget else {
                let actual = maximumEntries == Int.max
                    ? Int.max
                    : maximumEntries + 1
                throw SafeTraceArchiveExtractor.ExtractionError.entryCountLimit(
                    actual: actual,
                    maximum: maximumEntries
                )
            }
            names.append(name)
        }
        guard errno == 0 else {
            throw unsafeEntry(
                sourcePath: sourcePath,
                relativePath: relativePath,
                reason: "readdir failed: errno \(errno)"
            )
        }
        names.sort()
        return names
    }

    private static func validateSnapshotComponent(
        _ component: String,
        under parent: String
    ) throws {
        let relative = joinedPath(parent, component)
        guard !component.isEmpty,
              component != ".",
              component != "..",
              !component.hasPrefix("."),
              component.utf8.count <= 255,
              relative.utf8.count <= 4_096 else {
            throw SafeTraceArchiveExtractor.ExtractionError.unsafePath(relative)
        }
        for scalar in component.unicodeScalars {
            let value = scalar.value
            let safe = (value >= 48 && value <= 57)
                || (value >= 65 && value <= 90)
                || (value >= 97 && value <= 122)
                || value == 45 || value == 46 || value == 95
            guard safe else {
                throw SafeTraceArchiveExtractor.ExtractionError.unsafePath(relative)
            }
        }
    }

    private static func copyRegularFile(
        sourceDescriptor: Int32,
        before: stat,
        destinationParent: Int32,
        destinationName: String,
        sourcePath: String,
        relativePath: String
    ) throws -> Data {
        let destination = destinationName.withCString {
            Darwin.openat(
                destinationParent,
                $0,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                mode_t(0o600)
            )
        }
        guard destination >= 0 else {
            throw filesystemError("could not create snapshot file \(relativePath)")
        }
        defer { Darwin.close(destination) }
        guard TraceBundlePrivateFilePolicy.enforceRegularFile(destination) else {
            throw filesystemError(
                "snapshot file \(relativePath) has unsafe permissions or an extended ACL"
            )
        }

        let expectedSize = Int(before.st_size)
        var remaining = expectedSize
        var buffer = [UInt8](repeating: 0, count: 64 * 1_024)
        var captured = Data()
        captured.reserveCapacity(expectedSize)
        while remaining > 0 {
            let wanted = min(buffer.count, remaining)
            let count = buffer.withUnsafeMutableBytes { bytes in
                Darwin.read(sourceDescriptor, bytes.baseAddress, wanted)
            }
            if count < 0 {
                if errno == EINTR { continue }
                throw unsafeEntry(
                    sourcePath: sourcePath,
                    relativePath: relativePath,
                    reason: "source read failed: errno \(errno)"
                )
            }
            guard count > 0 else {
                throw unsafeEntry(
                    sourcePath: sourcePath,
                    relativePath: relativePath,
                    reason: "source file was truncated while snapshotting"
                )
            }
            captured.append(contentsOf: buffer[0..<count])
            var writeOffset = 0
            while writeOffset < count {
                let wrote = buffer.withUnsafeBytes { bytes in
                    Darwin.write(
                        destination,
                        bytes.baseAddress?.advanced(by: writeOffset),
                        count - writeOffset
                    )
                }
                if wrote < 0 {
                    if errno == EINTR { continue }
                    throw filesystemError("snapshot write failed for \(relativePath)")
                }
                guard wrote > 0 else {
                    throw filesystemError("snapshot write made no progress for \(relativePath)")
                }
                writeOffset += wrote
            }
            remaining -= count
        }

        var excess: UInt8 = 0
        let extraCount = Darwin.read(sourceDescriptor, &excess, 1)
        guard extraCount == 0 else {
            throw unsafeEntry(
                sourcePath: sourcePath,
                relativePath: relativePath,
                reason: "source file grew while snapshotting"
            )
        }
        var after = stat()
        guard Darwin.fstat(sourceDescriptor, &after) == 0,
              sameRegularFile(before, after) else {
            throw unsafeEntry(
                sourcePath: sourcePath,
                relativePath: relativePath,
                reason: "source file changed while snapshotting"
            )
        }
        guard TraceBundlePrivateFilePolicy.validateRegularFile(destination) else {
            throw filesystemError(
                "snapshot file \(relativePath) lost its private permissions"
            )
        }
        return captured
    }

    // MARK: - Archive resolution

    private static func resolveArchive(
        sourceDescriptor: Int32,
        sourcePath: String,
        metadata: stat,
        limits: SafeTraceArchiveExtractor.Limits
    ) throws -> Resolution {
        let compressedBytes = UInt64(max(metadata.st_size, 0))
        let hardMaximum = min(
            limits.maxCompressedBytes,
            UInt64(BoundedPrivilegedProcessRunner.maximumStandardInputBytes)
        )
        guard compressedBytes <= hardMaximum else {
            throw SafeTraceArchiveExtractor.ExtractionError.compressedSizeLimit(
                actual: compressedBytes,
                maximum: hardMaximum
            )
        }
        guard metadata.st_size <= Int64(Int.max) else {
            throw SafeTraceArchiveExtractor.ExtractionError.compressedSizeLimit(
                actual: compressedBytes,
                maximum: UInt64(Int.max)
            )
        }
        let archiveData = try readRegularDescriptor(
            sourceDescriptor,
            before: metadata,
            maximumBytes: Int(min(hardMaximum, UInt64(Int.max))),
            sourcePath: sourcePath
        )
        return try resolve(archiveData: archiveData, limits: limits)
    }

    /// Resolve archive bytes already held by a trusted caller. Used by archive
    /// publication to prove the exact bounded stdout bytes encode the same
    /// logical snapshot before those bytes become externally visible.
    static func resolve(
        archiveData: Data,
        limits: SafeTraceArchiveExtractor.Limits = .default
    ) throws -> Resolution {
        try SafeTraceArchiveExtractor.validateLimits(limits)
        let hardMaximum = min(
            limits.maxCompressedBytes,
            UInt64(BoundedPrivilegedProcessRunner.maximumStandardInputBytes)
        )
        guard UInt64(archiveData.count) <= hardMaximum else {
            throw SafeTraceArchiveExtractor.ExtractionError.compressedSizeLimit(
                actual: UInt64(archiveData.count),
                maximum: hardMaximum
            )
        }
        let extraction = try SafeTraceArchiveExtractor.extract(
            archiveData: archiveData,
            limits: limits
        )
        var transferCleanup = false
        defer {
            if !transferCleanup { extraction.cleanup() }
        }

        // `Extraction.capturedFiles` came from one bounded `bsdtar -xO` pass
        // whose stdin was the exact immutable archiveData value. The extracted
        // 0700 tree is retained only as a compatibility path; semantic readers
        // must never recapture it because another process with our uid can
        // rewrite that pathname after the extractor's postflight.
        let temporaryRoot = extraction.temporaryRoot
        let cleanupIdentity = try filesystemIdentity(ofDirectory: temporaryRoot)
        transferCleanup = true
        return Resolution(
            bundleDirectory: extraction.bundleDirectory,
            temporaryRoot: temporaryRoot,
            capturedFiles: extraction.capturedFiles,
            capturedDirectories: extraction.capturedDirectories,
            cleanupHandler: {
                removeTemporaryRootIfUnchanged(
                    temporaryRoot,
                    expectedIdentity: cleanupIdentity
                )
            }
        )
    }

    private static func readRegularDescriptor(
        _ descriptor: Int32,
        before: stat,
        maximumBytes: Int,
        sourcePath: String
    ) throws -> Data {
        guard (before.st_mode & S_IFMT) == S_IFREG,
              before.st_size >= 0,
              before.st_size <= Int64(maximumBytes),
              Darwin.lseek(descriptor, 0, SEEK_SET) == 0 else {
            throw SafeTraceArchiveExtractor.ExtractionError.inputNotRegular(sourcePath)
        }
        let expectedSize = Int(before.st_size)
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
        guard actualSize == expectedSize else {
            throw SafeTraceArchiveExtractor.ExtractionError.inputNotRegular(sourcePath)
        }
        var excess: UInt8 = 0
        guard Darwin.read(descriptor, &excess, 1) == 0 else {
            throw SafeTraceArchiveExtractor.ExtractionError.inputNotRegular(sourcePath)
        }
        var after = stat()
        guard Darwin.fstat(descriptor, &after) == 0,
              sameRegularFile(before, after) else {
            throw SafeTraceArchiveExtractor.ExtractionError.inputNotRegular(sourcePath)
        }
        return output
    }

    // MARK: - Shared accounting and identity checks

    private static func requireSnapshotCapacity(
        at directory: URL,
        compressedBytes: UInt64,
        compressedCopies: UInt64,
        limits: SafeTraceArchiveExtractor.Limits
    ) throws {
        var filesystem = statfs()
        guard statfs(directory.path, &filesystem) == 0,
              filesystem.f_bavail >= 0,
              filesystem.f_bsize > 0 else {
            throw filesystemError("statfs failed for \(directory.path)")
        }
        let availableResult = UInt64(filesystem.f_bavail)
            .multipliedReportingOverflow(by: UInt64(filesystem.f_bsize))
        guard !availableResult.overflow else {
            throw SafeTraceArchiveExtractor.ExtractionError.filesystem(
                "free-space accounting overflow"
            )
        }
        let overheadResult = UInt64(limits.maxEntries)
            .multipliedReportingOverflow(by: 16 * 1_024)
        let compressedResult = compressedBytes
            .multipliedReportingOverflow(by: compressedCopies)
        var required = limits.freeSpaceReserveBytes
        var overflow = overheadResult.overflow || compressedResult.overflow
        for increment in [
            limits.maxTotalFileBytes,
            overheadResult.partialValue,
            compressedResult.partialValue,
        ] {
            let addition = required.addingReportingOverflow(increment)
            required = addition.partialValue
            overflow = overflow || addition.overflow
        }
        if overflow { required = UInt64.max }
        guard availableResult.partialValue >= required else {
            throw SafeTraceArchiveExtractor.ExtractionError.insufficientFreeSpace(
                available: availableResult.partialValue,
                required: required
            )
        }
    }

    private static func makePrivateTemporaryRoot(prefix: String) throws -> URL {
        var template = Array("/private/tmp/\(prefix).XXXXXX".utf8CString)
        let path: String? = template.withUnsafeMutableBufferPointer { buffer in
            guard let base = buffer.baseAddress,
                  let created = Darwin.mkdtemp(base) else {
                return nil
            }
            return String(cString: created)
        }
        guard let path else {
            throw filesystemError("mkdtemp failed under /private/tmp")
        }
        return URL(fileURLWithPath: path, isDirectory: true)
    }

    private static func filesystemIdentity(
        ofDirectory directory: URL
    ) throws -> FilesystemIdentity {
        var metadata = stat()
        guard Darwin.lstat(directory.path, &metadata) == 0,
              (metadata.st_mode & S_IFMT) == S_IFDIR else {
            throw filesystemError("could not identify private temporary root")
        }
        return FilesystemIdentity(device: metadata.st_dev, inode: metadata.st_ino)
    }

    private static func temporaryRootHasIdentity(
        _ directory: URL,
        expectedIdentity: FilesystemIdentity
    ) -> Bool {
        var metadata = stat()
        return Darwin.lstat(directory.path, &metadata) == 0
            && (metadata.st_mode & S_IFMT) == S_IFDIR
            && metadata.st_dev == expectedIdentity.device
            && metadata.st_ino == expectedIdentity.inode
    }

    private static func removeTemporaryRootIfUnchanged(
        _ directory: URL,
        expectedIdentity: FilesystemIdentity
    ) {
        guard temporaryRootHasIdentity(
            directory,
            expectedIdentity: expectedIdentity
        ) else { return }
        try? FileManager.default.removeItem(at: directory)
    }

    private static func sameDirectory(_ lhs: stat, _ rhs: stat) -> Bool {
        (rhs.st_mode & S_IFMT) == S_IFDIR
            && lhs.st_dev == rhs.st_dev
            && lhs.st_ino == rhs.st_ino
            && lhs.st_size == rhs.st_size
            && lhs.st_mtimespec.tv_sec == rhs.st_mtimespec.tv_sec
            && lhs.st_mtimespec.tv_nsec == rhs.st_mtimespec.tv_nsec
            && lhs.st_ctimespec.tv_sec == rhs.st_ctimespec.tv_sec
            && lhs.st_ctimespec.tv_nsec == rhs.st_ctimespec.tv_nsec
    }

    private static func sameRegularFile(_ lhs: stat, _ rhs: stat) -> Bool {
        (rhs.st_mode & S_IFMT) == S_IFREG
            && rhs.st_nlink == 1
            && lhs.st_dev == rhs.st_dev
            && lhs.st_ino == rhs.st_ino
            && lhs.st_size == rhs.st_size
            && lhs.st_mtimespec.tv_sec == rhs.st_mtimespec.tv_sec
            && lhs.st_mtimespec.tv_nsec == rhs.st_mtimespec.tv_nsec
            && lhs.st_ctimespec.tv_sec == rhs.st_ctimespec.tv_sec
            && lhs.st_ctimespec.tv_nsec == rhs.st_ctimespec.tv_nsec
    }

    private static func joinedPath(_ parent: String, _ name: String) -> String {
        parent.isEmpty ? name : parent + "/" + name
    }

    private static func unsafeEntry(
        sourcePath: String,
        relativePath: String,
        reason: String
    ) -> SafeTraceArchiveExtractor.ExtractionError {
        let path = relativePath.isEmpty ? sourcePath : relativePath
        return .unsafeFilesystemEntry(path: path, reason: reason)
    }

    private static func filesystemError(
        _ message: String
    ) -> SafeTraceArchiveExtractor.ExtractionError {
        .filesystem("\(message): errno \(errno)")
    }
}
