// SafeTraceArchivePackager.swift
//
// Package a completed trace bundle without reopening a mutable public tree or
// letting bsdtar choose/overwrite the destination path. The source is first
// resolved to one private bounded snapshot. A fixed Apple bsdtar writes the
// archive to bounded stdout; those exact bytes are hashed and installed with
// an exclusive same-directory rename. The digest sidecar follows the same
// publication rule and is never allowed to clobber an existing leaf.

import CryptoKit
import Darwin
import Foundation

public enum SafeTraceArchivePackager {
    public struct Options: Sendable, Equatable {
        public var limits: SafeTraceArchiveExtractor.Limits
        /// Deadline for the external `/usr/bin/bsdtar` process. Snapshot and
        /// publication I/O remain synchronously bounded by byte/entry counts,
        /// but cannot be safely interrupted mid-syscall.
        public var archiveToolTimeoutSeconds: TimeInterval

        public init(
            limits: SafeTraceArchiveExtractor.Limits = .default,
            archiveToolTimeoutSeconds: TimeInterval = 60
        ) {
            self.limits = limits
            self.archiveToolTimeoutSeconds = archiveToolTimeoutSeconds
        }

        @available(*, deprecated, renamed: "archiveToolTimeoutSeconds")
        public var timeoutSeconds: TimeInterval {
            get { archiveToolTimeoutSeconds }
            set { archiveToolTimeoutSeconds = newValue }
        }

        @available(*, deprecated, message: "Use archiveToolTimeoutSeconds")
        public init(
            limits: SafeTraceArchiveExtractor.Limits,
            timeoutSeconds: TimeInterval
        ) {
            self.init(
                limits: limits,
                archiveToolTimeoutSeconds: timeoutSeconds
            )
        }
    }

    public struct Result: Sendable, Equatable {
        public let archiveURL: URL
        public let archiveBytes: Int
        public let sha256Hex: String
        public let sidecarURL: URL?
        public let sidecarWarning: String?
    }

    public enum PackagingError: Error, LocalizedError, Equatable {
        case invalidOptions
        case outputExists(URL)
        case unsafeDestination(String)
        case insufficientFreeSpace(available: UInt64, required: UInt64)
        case archiveToolUnavailable
        case archiveTimedOut
        case archiveOutputLimit(maximum: UInt64)
        case archiveFailed(status: Int32?)
        case emptyArchive
        case archiveContentMismatch(String)
        case filesystem(String)
        case archiveCommitted(URL, sha256Hex: String, detail: String)

        public var errorDescription: String? {
            switch self {
            case .invalidOptions:
                return "invalid trace archive packaging limits or archive-tool timeout"
            case .outputExists(let url):
                return "refusing to overwrite existing archive output at \(url.path)"
            case .unsafeDestination(let path):
                return "unsafe trace archive destination: \(path)"
            case .insufficientFreeSpace(let available, let required):
                return "trace archive publication requires \(required) free bytes but only \(available) are available"
            case .archiveToolUnavailable:
                return "trusted /usr/bin/bsdtar could not be started"
            case .archiveTimedOut:
                return "trace archive packaging exceeded its hard deadline"
            case .archiveOutputLimit(let maximum):
                return "trace archive exceeded the \(maximum)-byte compressed limit"
            case .archiveFailed(let status):
                let renderedStatus = status.map(String.init) ?? "unknown"
                return "bsdtar failed with status \(renderedStatus)"
            case .emptyArchive:
                return "bsdtar returned success without producing archive bytes"
            case .archiveContentMismatch(let detail):
                return "bsdtar output does not reproduce the resolved bundle snapshot: \(detail)"
            case .filesystem(let detail):
                return "trace archive publication failed: \(detail)"
            case .archiveCommitted(let url, _, let detail):
                return "complete archive committed at \(url.path), but durability/postflight failed: \(detail)"
            }
        }
    }

    struct TestHooks {
        var archiveProducer: ((URL, Int, TimeInterval) -> BoundedPrivilegedProcessRunner.Result?)?
        var beforeArchiveTool: ((URL) -> Void)?
        var beforeArchiveRename: ((URL, URL) -> Void)?
        var afterArchiveRename: ((URL) -> Void)?
        var beforeSidecarRename: ((URL, URL) -> Void)?
        var afterSidecarRename: ((URL) -> Void)?

        init(
            archiveProducer: ((URL, Int, TimeInterval) -> BoundedPrivilegedProcessRunner.Result?)? = nil,
            beforeArchiveTool: ((URL) -> Void)? = nil,
            beforeArchiveRename: ((URL, URL) -> Void)? = nil,
            afterArchiveRename: ((URL) -> Void)? = nil,
            beforeSidecarRename: ((URL, URL) -> Void)? = nil,
            afterSidecarRename: ((URL) -> Void)? = nil
        ) {
            self.archiveProducer = archiveProducer
            self.beforeArchiveTool = beforeArchiveTool
            self.beforeArchiveRename = beforeArchiveRename
            self.afterArchiveRename = afterArchiveRename
            self.beforeSidecarRename = beforeSidecarRename
            self.afterSidecarRename = afterSidecarRename
        }
    }

    public static func package(
        bundleAt bundleURL: URL,
        archiveAt archiveURL: URL,
        options: Options = Options()
    ) throws -> Result {
        try package(
            bundleAt: bundleURL,
            archiveAt: archiveURL,
            options: options,
            testHooks: TestHooks()
        )
    }

    static func package(
        bundleAt bundleURL: URL,
        archiveAt archiveURL: URL,
        options: Options,
        testHooks: TestHooks
    ) throws -> Result {
        guard options.archiveToolTimeoutSeconds.isFinite,
              options.archiveToolTimeoutSeconds > 0,
              options.archiveToolTimeoutSeconds <= 3_600,
              options.limits.maxCompressedBytes > 0,
              options.limits.maxCompressedBytes
                <= UInt64(BoundedPrivilegedProcessRunner.maximumCapturedOutputBytes),
              let maximumOutputBytes = Int(exactly: options.limits.maxCompressedBytes) else {
            throw PackagingError.invalidOptions
        }
        guard isSafeSidecarFileName(archiveURL.lastPathComponent) else {
            throw PackagingError.unsafeDestination(
                "archive filename contains a control character or backslash"
            )
        }

        // Pin both names before spending time snapshotting/compressing. This is
        // advisory only; publication still uses RENAME_EXCL after revalidation.
        let archiveDestination: AtomicFileDestination
        do {
            archiveDestination = try AtomicFileDestination(targetURL: archiveURL)
        } catch {
            throw mapDestinationError(error)
        }

        let sidecarURL = ArchiveDigest.sidecarURL(forArchiveAt: archiveURL)
        let sidecarDestination: AtomicFileDestination?
        var sidecarWarning: String?
        do {
            sidecarDestination = try AtomicFileDestination(targetURL: sidecarURL)
        } catch {
            // The sidecar is transport convenience, not the signed evidence.
            // Refuse to overwrite it, but do not discard an otherwise valid
            // archive merely because a stale/raced sidecar name is occupied.
            sidecarDestination = nil
            sidecarWarning = mapDestinationError(error).localizedDescription
        }

        let resolution: SafeTraceBundleResolver.Resolution
        do {
            resolution = try SafeTraceBundleResolver.resolve(
                inputAt: bundleURL,
                limits: options.limits
            )
        } catch {
            throw PackagingError.filesystem(
                "bundle snapshot failed: \(error.localizedDescription)"
            )
        }
        defer { resolution.cleanup() }
        testHooks.beforeArchiveTool?(resolution.bundleDirectory)

        let processResult: BoundedPrivilegedProcessRunner.Result?
        if let producer = testHooks.archiveProducer {
            processResult = producer(
                resolution.bundleDirectory,
                maximumOutputBytes,
                options.archiveToolTimeoutSeconds
            )
        } else {
            var environment = BoundedPrivilegedProcessRunner.minimalEnvironment
            environment["COPYFILE_DISABLE"] = "1"
            processResult = BoundedPrivilegedProcessRunner.run(
                executable: "/usr/bin/bsdtar",
                arguments: [
                    "-czf", "-", "--",
                    resolution.bundleDirectory.lastPathComponent,
                ],
                environment: environment,
                workingDirectory: resolution.bundleDirectory
                    .deletingLastPathComponent().path,
                timeout: options.archiveToolTimeoutSeconds,
                maximumOutputBytes: maximumOutputBytes,
                mergeStandardErrorIntoOutput: false
            )
        }

        guard let processResult else {
            throw PackagingError.archiveToolUnavailable
        }
        if processResult.timedOut { throw PackagingError.archiveTimedOut }
        if processResult.outputLimitExceeded {
            throw PackagingError.archiveOutputLimit(
                maximum: options.limits.maxCompressedBytes
            )
        }
        guard processResult.terminationStatus == 0 else {
            throw PackagingError.archiveFailed(
                status: processResult.terminationStatus
            )
        }
        let archiveData = processResult.output
        guard !archiveData.isEmpty else { throw PackagingError.emptyArchive }
        guard UInt64(archiveData.count) <= options.limits.maxCompressedBytes else {
            throw PackagingError.archiveOutputLimit(
                maximum: options.limits.maxCompressedBytes
            )
        }

        // A same-uid process can rewrite the mode-0700 path while bsdtar is
        // reading it. Before publication, parse the exact bounded stdout bytes
        // back through stdin and require an exact file/directory/byte match with
        // the resolver's immutable logical snapshot. Custom archive producers
        // are test doubles for atomic-publication tests; the shipping bsdtar
        // path always performs this round trip.
        if testHooks.archiveProducer == nil {
            let roundTrip: SafeTraceBundleResolver.Resolution
            do {
                roundTrip = try SafeTraceBundleResolver.resolve(
                    archiveData: archiveData,
                    limits: options.limits
                )
            } catch {
                throw PackagingError.archiveContentMismatch(
                    "produced archive could not be safely resolved: \(error.localizedDescription)"
                )
            }
            defer { roundTrip.cleanup() }
            guard resolution.hasSameCapturedContents(as: roundTrip) else {
                throw PackagingError.archiveContentMismatch(
                    "captured artifact bytes or directory set changed during packaging"
                )
            }
        }

        let digest = SHA256.hash(data: archiveData)
        let digestHex = digest.map { String(format: "%02x", $0) }.joined()

        let archiveOutcome: AtomicFileDestination.Outcome
        do {
            archiveOutcome = try archiveDestination.publish(
                archiveData,
                freeSpaceReserveBytes: options.limits.freeSpaceReserveBytes,
                beforeRename: testHooks.beforeArchiveRename,
                afterRename: testHooks.afterArchiveRename
            )
        } catch {
            throw mapDestinationError(error)
        }
        if case .committedWithWarning(let detail) = archiveOutcome {
            throw PackagingError.archiveCommitted(
                archiveURL,
                sha256Hex: digestHex,
                detail: detail
            )
        }

        var publishedSidecarURL: URL?
        if let sidecarDestination {
            let line = ArchiveDigest.sidecarLine(
                hex: digestHex,
                fileName: archiveURL.lastPathComponent
            )
            do {
                let outcome = try sidecarDestination.publish(
                    Data(line.utf8),
                    freeSpaceReserveBytes: options.limits.freeSpaceReserveBytes,
                    beforeRename: testHooks.beforeSidecarRename,
                    afterRename: testHooks.afterSidecarRename
                )
                publishedSidecarURL = sidecarURL
                if case .committedWithWarning(let detail) = outcome {
                    sidecarWarning = detail
                }
            } catch {
                sidecarWarning = mapDestinationError(error).localizedDescription
            }
        }

        // The optional sidecar has its own retained parent descriptor and may
        // take long enough for the archive's textual parent to be displaced.
        // Revalidate the primary evidence last so a sidecar-only warning can
        // never turn a detached or replaced archive pathname into success.
        do {
            try archiveDestination.revalidatePublished(archiveData)
        } catch {
            throw PackagingError.archiveCommitted(
                archiveURL,
                sha256Hex: digestHex,
                detail: "final archive postflight failed: \(error.localizedDescription)"
            )
        }

        return Result(
            archiveURL: archiveURL,
            archiveBytes: archiveData.count,
            sha256Hex: digestHex,
            sidecarURL: publishedSidecarURL,
            sidecarWarning: sidecarWarning
        )
    }

    private static func mapDestinationError(_ error: Error) -> PackagingError {
        guard let error = error as? AtomicFileDestination.DestinationError else {
            return .filesystem(error.localizedDescription)
        }
        switch error {
        case .exists(let url):
            return .outputExists(url)
        case .unsafePath(let path):
            return .unsafeDestination(path)
        case .insufficientFreeSpace(let available, let required):
            return .insufficientFreeSpace(available: available, required: required)
        case .filesystem(let detail):
            return .filesystem(detail)
        }
    }

    private static func isSafeSidecarFileName(_ fileName: String) -> Bool {
        !fileName.isEmpty && fileName.unicodeScalars.allSatisfy { scalar in
            let value = scalar.value
            return value >= 0x20 && value != 0x7f && value != 0x5c
        }
    }
}

// MARK: - Exclusive atomic file publication

private final class AtomicFileDestination {
    enum Outcome {
        case published
        case committedWithWarning(String)
    }

    enum DestinationError: Error, LocalizedError {
        case exists(URL)
        case unsafePath(String)
        case insufficientFreeSpace(available: UInt64, required: UInt64)
        case filesystem(String)

        var errorDescription: String? {
            switch self {
            case .exists(let url): return "destination already exists: \(url.path)"
            case .unsafePath(let path): return "unsafe destination path: \(path)"
            case .insufficientFreeSpace(let available, let required):
                return "only \(available) free bytes are available; \(required) are required"
            case .filesystem(let detail): return detail
            }
        }
    }

    private struct Identity {
        let device: dev_t
        let inode: ino_t
        let owner: uid_t

        init(_ metadata: stat) {
            device = metadata.st_dev
            inode = metadata.st_ino
            owner = metadata.st_uid
        }

        func matches(_ metadata: stat) -> Bool {
            device == metadata.st_dev
                && inode == metadata.st_ino
                && owner == metadata.st_uid
        }
    }

    let targetURL: URL
    private let normalizedParentPath: String
    private let finalLeaf: String
    private let parentDescriptor: Int32
    private let parentIdentity: Identity
    private var publishedIdentity: Identity?

    init(targetURL: URL) throws {
        let normalized = try Self.normalizeAbsolutePath(targetURL.path)
        let components = normalized.dropFirst().split(
            separator: "/",
            omittingEmptySubsequences: false
        ).map(String.init)
        guard let finalLeaf = components.last,
              !finalLeaf.isEmpty,
              finalLeaf.utf8.count <= 255 else {
            throw DestinationError.unsafePath(targetURL.path)
        }
        let parentComponents = components.dropLast()
        let parentPath = parentComponents.isEmpty
            ? "/"
            : "/" + parentComponents.joined(separator: "/")
        let parent = try Self.openDirectoryNoFollow(at: parentPath)
        var keepParent = false
        defer { if !keepParent { Darwin.close(parent) } }

        var metadata = stat()
        guard Darwin.fstat(parent, &metadata) == 0,
              (metadata.st_mode & S_IFMT) == S_IFDIR else {
            throw DestinationError.filesystem(
                "could not validate destination parent \(parentPath): errno \(errno)"
            )
        }
        try Self.requireAbsent(
            parentDescriptor: parent,
            leaf: finalLeaf,
            targetURL: targetURL
        )

        self.targetURL = targetURL
        self.normalizedParentPath = parentPath
        self.finalLeaf = finalLeaf
        self.parentDescriptor = parent
        self.parentIdentity = Identity(metadata)
        self.publishedIdentity = nil
        keepParent = true
    }

    deinit { Darwin.close(parentDescriptor) }

    func publish(
        _ data: Data,
        freeSpaceReserveBytes: UInt64,
        beforeRename: ((URL, URL) -> Void)?,
        afterRename: ((URL) -> Void)?
    ) throws -> Outcome {
        let available = try availableBytes()
        let required = freeSpaceReserveBytes.addingReportingOverflow(
            UInt64(data.count)
        )
        guard !required.overflow, available >= required.partialValue else {
            throw DestinationError.insufficientFreeSpace(
                available: available,
                required: required.overflow ? UInt64.max : required.partialValue
            )
        }

        let (temporaryLeaf, descriptor) = try createTemporaryFile()
        let temporaryURL = URL(
            fileURLWithPath: normalizedParentPath,
            isDirectory: true
        ).appendingPathComponent(temporaryLeaf)
        var descriptorOpen = true
        var committed = false
        var initialMetadata = stat()
        guard Darwin.fstat(descriptor, &initialMetadata) == 0 else {
            let savedErrno = errno
            Darwin.close(descriptor)
            descriptorOpen = false
            temporaryLeaf.withCString {
                _ = Darwin.unlinkat(parentDescriptor, $0, 0)
            }
            throw DestinationError.filesystem(
                "could not stat private output temporary: errno \(savedErrno)"
            )
        }
        let initialIdentity = Identity(initialMetadata)
        var expectedIdentity: Identity? = initialIdentity
        defer {
            if descriptorOpen { Darwin.close(descriptor) }
            if !committed, let expectedIdentity {
                Self.unlinkIfOwned(
                    parentDescriptor: parentDescriptor,
                    leaf: temporaryLeaf,
                    expected: expectedIdentity
                )
            }
        }

        // Check privacy before the first byte is written. A file created below
        // a parent with an inheritable ACL can otherwise expose archive bytes
        // even though its POSIX mode is 0600.
        var privateMetadata = stat()
        guard TraceBundlePrivateFilePolicy.enforceRegularFile(descriptor),
              Darwin.fstat(descriptor, &privateMetadata) == 0,
              initialIdentity.matches(privateMetadata),
              TraceBundlePrivateFilePolicy.validateRegularFile(descriptor) else {
            throw DestinationError.filesystem(
                "private output temporary inherited unsafe permissions or ACLs"
            )
        }
        try Self.writeAll(data, descriptor: descriptor)
        guard Darwin.fsync(descriptor) == 0 else {
            throw DestinationError.filesystem(
                "could not sync private output temporary: errno \(errno)"
            )
        }

        var metadata = stat()
        guard Darwin.fstat(descriptor, &metadata) == 0,
              UInt64(metadata.st_size) == UInt64(data.count),
              TraceBundlePrivateFilePolicy.validateRegularFile(descriptor) else {
            throw DestinationError.filesystem(
                "private output temporary failed descriptor validation"
            )
        }
        let identity = Identity(metadata)
        expectedIdentity = identity

        beforeRename?(temporaryURL, targetURL)
        guard textualParentStillMatches() else {
            throw DestinationError.filesystem(
                "destination parent path was replaced before publication"
            )
        }
        try Self.requireAbsent(
            parentDescriptor: parentDescriptor,
            leaf: finalLeaf,
            targetURL: targetURL
        )
        try Self.verifyNamedFile(
            parentDescriptor: parentDescriptor,
            leaf: temporaryLeaf,
            expected: identity,
            expectedData: data
        )

        let renameStatus = temporaryLeaf.withCString { temporaryName in
            finalLeaf.withCString { destinationName in
                Darwin.renameatx_np(
                    parentDescriptor,
                    temporaryName,
                    parentDescriptor,
                    destinationName,
                    UInt32(RENAME_EXCL)
                )
            }
        }
        guard renameStatus == 0 else {
            if errno == EEXIST { throw DestinationError.exists(targetURL) }
            throw DestinationError.filesystem(
                "exclusive output publication failed: errno \(errno)"
            )
        }
        committed = true
        publishedIdentity = identity
        afterRename?(targetURL)

        do {
            try Self.verifyNamedFile(
                parentDescriptor: parentDescriptor,
                leaf: finalLeaf,
                expected: identity,
                expectedData: data
            )
            guard Darwin.fsync(parentDescriptor) == 0 else {
                return .committedWithWarning(
                    "destination parent fsync failed with errno \(errno)"
                )
            }
            guard textualParentStillMatches() else {
                return .committedWithWarning(
                    "destination parent path changed after publication"
                )
            }
        } catch {
            return .committedWithWarning(
                "published output postflight failed: \(error.localizedDescription)"
            )
        }
        descriptorOpen = false
        guard Darwin.close(descriptor) == 0 else {
            return .committedWithWarning(
                "published output descriptor close failed with errno \(errno)"
            )
        }
        return .published
    }

    func revalidatePublished(_ data: Data) throws {
        guard let publishedIdentity else {
            throw DestinationError.filesystem(
                "output has not been committed by this destination"
            )
        }
        guard textualParentStillMatches() else {
            throw DestinationError.filesystem(
                "destination parent path changed after publication"
            )
        }
        try Self.verifyNamedFile(
            parentDescriptor: parentDescriptor,
            leaf: finalLeaf,
            expected: publishedIdentity,
            expectedData: data
        )
    }

    private func createTemporaryFile() throws -> (String, Int32) {
        for _ in 0..<16 {
            let leaf = ".partial-maccrab-archive-\(UUID().uuidString)"
            let descriptor = leaf.withCString {
                Darwin.openat(
                    parentDescriptor,
                    $0,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                    mode_t(0o600)
                )
            }
            if descriptor >= 0 {
                return (leaf, descriptor)
            }
            guard errno == EEXIST else {
                throw DestinationError.filesystem(
                    "could not create private output temporary: errno \(errno)"
                )
            }
        }
        throw DestinationError.filesystem(
            "could not allocate a unique private output temporary"
        )
    }

    private func availableBytes() throws -> UInt64 {
        var info = statfs()
        guard Darwin.fstatfs(parentDescriptor, &info) == 0 else {
            throw DestinationError.filesystem(
                "could not probe destination free space: errno \(errno)"
            )
        }
        let result = UInt64(info.f_bavail).multipliedReportingOverflow(
            by: UInt64(info.f_bsize)
        )
        guard !result.overflow else {
            throw DestinationError.filesystem(
                "destination free-space calculation overflowed"
            )
        }
        return result.partialValue
    }

    private func textualParentStillMatches() -> Bool {
        guard let descriptor = try? Self.openDirectoryNoFollow(
            at: normalizedParentPath
        ) else { return false }
        defer { Darwin.close(descriptor) }
        var metadata = stat()
        return Darwin.fstat(descriptor, &metadata) == 0
            && parentIdentity.matches(metadata)
    }

    private static func requireAbsent(
        parentDescriptor: Int32,
        leaf: String,
        targetURL: URL
    ) throws {
        var metadata = stat()
        let status = leaf.withCString {
            Darwin.fstatat(
                parentDescriptor,
                $0,
                &metadata,
                AT_SYMLINK_NOFOLLOW
            )
        }
        if status == 0 { throw DestinationError.exists(targetURL) }
        guard errno == ENOENT else {
            throw DestinationError.filesystem(
                "could not inspect output destination: errno \(errno)"
            )
        }
    }

    private static func verifyNamedFile(
        parentDescriptor: Int32,
        leaf: String,
        expected: Identity,
        expectedData: Data
    ) throws {
        let descriptor = leaf.withCString {
            Darwin.openat(
                parentDescriptor,
                $0,
                O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW
            )
        }
        guard descriptor >= 0 else {
            throw DestinationError.filesystem(
                "could not open output name for verification: errno \(errno)"
            )
        }
        defer { Darwin.close(descriptor) }

        var metadata = stat()
        guard Darwin.fstat(descriptor, &metadata) == 0,
              expected.matches(metadata),
              UInt64(metadata.st_size) == UInt64(expectedData.count),
              TraceBundlePrivateFilePolicy.validateRegularFile(descriptor),
              try hashDescriptor(descriptor, size: expectedData.count)
                == Data(SHA256.hash(data: expectedData)) else {
            throw DestinationError.filesystem(
                "output name/identity/content changed during publication"
            )
        }
    }

    private static func hashDescriptor(
        _ descriptor: Int32,
        size: Int
    ) throws -> Data {
        var hasher = SHA256()
        var offset = 0
        var buffer = [UInt8](repeating: 0, count: 64 * 1_024)
        while offset < size {
            let wanted = min(buffer.count, size - offset)
            let count = buffer.withUnsafeMutableBytes { bytes in
                Darwin.pread(
                    descriptor,
                    bytes.baseAddress,
                    wanted,
                    off_t(offset)
                )
            }
            if count < 0 {
                if errno == EINTR { continue }
                throw DestinationError.filesystem(
                    "could not read output for verification: errno \(errno)"
                )
            }
            guard count > 0 else {
                throw DestinationError.filesystem(
                    "output became short during verification"
                )
            }
            hasher.update(data: Data(buffer.prefix(Int(count))))
            offset += Int(count)
        }
        var excess: UInt8 = 0
        let extra = Darwin.pread(descriptor, &excess, 1, off_t(size))
        guard extra == 0 else {
            throw DestinationError.filesystem(
                "output grew during verification"
            )
        }
        return Data(hasher.finalize())
    }

    private static func unlinkIfOwned(
        parentDescriptor: Int32,
        leaf: String,
        expected: Identity
    ) {
        var metadata = stat()
        let status = leaf.withCString {
            Darwin.fstatat(
                parentDescriptor,
                $0,
                &metadata,
                AT_SYMLINK_NOFOLLOW
            )
        }
        guard status == 0, expected.matches(metadata) else { return }
        leaf.withCString { _ = Darwin.unlinkat(parentDescriptor, $0, 0) }
    }

    private static func writeAll(_ data: Data, descriptor: Int32) throws {
        var offset = 0
        try data.withUnsafeBytes { bytes in
            while offset < bytes.count {
                let count = Darwin.write(
                    descriptor,
                    bytes.baseAddress?.advanced(by: offset),
                    bytes.count - offset
                )
                if count < 0 {
                    if errno == EINTR { continue }
                    throw DestinationError.filesystem(
                        "could not write private output temporary: errno \(errno)"
                    )
                }
                guard count > 0 else {
                    throw DestinationError.filesystem(
                        "private output temporary made no write progress"
                    )
                }
                offset += count
            }
        }
    }

    private static func normalizeAbsolutePath(_ path: String) throws -> String {
        guard path.first == "/",
              !path.hasSuffix("/"),
              !path.utf8.contains(0) else {
            throw DestinationError.unsafePath(path)
        }
        let normalized: String
        if path == "/var" || path.hasPrefix("/var/") {
            normalized = "/private" + path
        } else if path == "/tmp" || path.hasPrefix("/tmp/") {
            normalized = "/private" + path
        } else {
            normalized = path
        }
        let components = normalized.dropFirst().split(
            separator: "/",
            omittingEmptySubsequences: false
        )
        guard !components.isEmpty,
              components.allSatisfy({
                  !$0.isEmpty && $0 != "." && $0 != ".." && $0.utf8.count <= 255
              }) else {
            throw DestinationError.unsafePath(path)
        }
        return normalized
    }

    private static func openDirectoryNoFollow(at path: String) throws -> Int32 {
        let components = path == "/"
            ? []
            : path.dropFirst().split(
                separator: "/",
                omittingEmptySubsequences: false
            ).map(String.init)
        var descriptor = Darwin.open(
            "/",
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
        )
        guard descriptor >= 0 else {
            throw DestinationError.filesystem(
                "could not open filesystem root: errno \(errno)"
            )
        }
        do {
            for component in components {
                let next = component.withCString {
                    Darwin.openat(
                        descriptor,
                        $0,
                        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
                    )
                }
                guard next >= 0 else {
                    throw DestinationError.filesystem(
                        "could not open destination parent without following links: errno \(errno)"
                    )
                }
                Darwin.close(descriptor)
                descriptor = next
            }
            return descriptor
        } catch {
            Darwin.close(descriptor)
            throw error
        }
    }
}
