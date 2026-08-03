// SafeTraceArchiveExtractor.swift
// MacCrabCore
//
// Treat trace bundles as hostile input. Both maccrabctl and maccrab-mcp accept
// bundles supplied by another machine, so invoking `tar -xzf` directly is not
// an archive boundary: bsdtar faithfully creates symbolic links and will
// expand whatever sizes the archive declares. A later `Data(contentsOf:)` can
// then follow a link such as manifest.json -> /dev/zero, while a compressed
// archive can consume the remaining boot volume before validation begins.

import Darwin
import Foundation

/// Shared, fail-closed extraction and filesystem policy for `.maccrabtrace`
/// archives. Callers own the returned temporary directory and must call
/// `cleanup()` when finished.
public enum SafeTraceArchiveExtractor {
    /// Fixed environment for every archive listing/extraction subprocess.
    /// Archive handling is an attacker-controlled boundary, so inheriting
    /// TAR_OPTIONS, DYLD_*, HOME, PATH, or locale settings would let ambient
    /// process state change `/usr/bin/tar` semantics. HOME points at an inert
    /// system directory and PATH contains only immutable platform tools.
    static let tarEnvironment: [String: String] = [
        "COPYFILE_DISABLE": "1",
        "HOME": "/var/empty",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": "/private/tmp",
    ]


    public struct Limits: Sendable, Equatable {
        public var maxCompressedBytes: UInt64
        public var maxEntries: Int
        public var maxSingleFileBytes: UInt64
        public var maxTotalFileBytes: UInt64
        public var maxListingBytes: Int
        public var listingTimeoutSeconds: TimeInterval
        public var extractionTimeoutSeconds: TimeInterval
        /// Free bytes that must remain after the bounded snapshot + declared
        /// extraction. Trace tools must not turn a hostile archive into the
        /// same boot-volume exhaustion incident the engine storage clamps
        /// prevent.
        public var freeSpaceReserveBytes: UInt64

        public init(
            maxCompressedBytes: UInt64 = 64 * 1_024 * 1_024,
            maxEntries: Int = 4_096,
            maxSingleFileBytes: UInt64 = 64 * 1_024 * 1_024,
            maxTotalFileBytes: UInt64 = 128 * 1_024 * 1_024,
            maxListingBytes: Int = 4 * 1_024 * 1_024,
            listingTimeoutSeconds: TimeInterval = 10,
            extractionTimeoutSeconds: TimeInterval = 20,
            freeSpaceReserveBytes: UInt64 = 1 * 1_024 * 1_024 * 1_024
        ) {
            self.maxCompressedBytes = maxCompressedBytes
            self.maxEntries = maxEntries
            self.maxSingleFileBytes = maxSingleFileBytes
            self.maxTotalFileBytes = maxTotalFileBytes
            self.maxListingBytes = maxListingBytes
            self.listingTimeoutSeconds = listingTimeoutSeconds
            self.extractionTimeoutSeconds = extractionTimeoutSeconds
            self.freeSpaceReserveBytes = freeSpaceReserveBytes
        }

        public static let `default` = Limits()
    }

    public struct Extraction: Sendable {
        public let bundleDirectory: URL
        public let temporaryRoot: URL

        /// Logical bundle bytes derived directly from the immutable archive
        /// input. These are intentionally internal: semantic readers receive
        /// them only through `SafeTraceBundleResolver.Resolution`, while the
        /// public filesystem tree remains a compatibility surface for callers
        /// that explicitly asked to extract an archive.
        let capturedFiles: [String: Data]
        let capturedDirectories: Set<String>

        public func cleanup() {
            try? FileManager.default.removeItem(at: temporaryRoot)
        }
    }

    public enum ExtractionError: Error, LocalizedError, Equatable {
        case inputNotRegular(String)
        case compressedSizeLimit(actual: UInt64, maximum: UInt64)
        case listingTimedOut
        case extractionTimedOut
        case listingOutputLimit(maximum: Int)
        case tarFailed(operation: String, status: Int32)
        case malformedListing(String)
        case unsafePath(String)
        case unsupportedEntry(path: String, type: Character)
        case entryCountLimit(actual: Int, maximum: Int)
        case singleFileSizeLimit(path: String, actual: UInt64, maximum: UInt64)
        case totalFileSizeLimit(actual: UInt64, maximum: UInt64)
        case insufficientFreeSpace(available: UInt64, required: UInt64)
        case unsafeFilesystemEntry(path: String, reason: String)
        case filesystem(String)

        public var errorDescription: String? {
            switch self {
            case .inputNotRegular(let path):
                return "archive is not a regular, non-symlink file: \(path)"
            case .compressedSizeLimit(let actual, let maximum):
                return "compressed archive is \(actual) bytes; limit is \(maximum) bytes"
            case .listingTimedOut:
                return "archive listing exceeded its time limit"
            case .extractionTimedOut:
                return "archive extraction exceeded its time limit"
            case .listingOutputLimit(let maximum):
                return "archive listing exceeded \(maximum) bytes"
            case .tarFailed(let operation, let status):
                return "tar \(operation) failed with status \(status)"
            case .malformedListing(let detail):
                return "archive listing is malformed: \(detail)"
            case .unsafePath(let path):
                return "archive contains an unsafe path: \(path)"
            case .unsupportedEntry(let path, let type):
                return "archive entry \(path) has unsupported type '\(type)'"
            case .entryCountLimit(let actual, let maximum):
                return "archive contains \(actual) entries; limit is \(maximum)"
            case .singleFileSizeLimit(let path, let actual, let maximum):
                return "archive entry \(path) is \(actual) bytes; per-file limit is \(maximum)"
            case .totalFileSizeLimit(let actual, let maximum):
                return "archive expands to \(actual) bytes; limit is \(maximum)"
            case .insufficientFreeSpace(let available, let required):
                return "archive extraction requires \(required) free bytes; only \(available) are available"
            case .unsafeFilesystemEntry(let path, let reason):
                return "unsafe bundle entry \(path): \(reason)"
            case .filesystem(let detail):
                return "bundle filesystem error: \(detail)"
            }
        }
    }

    private struct ArchiveEntry: Sendable {
        enum Kind: Sendable { case file, directory }
        let path: String
        let kind: Kind
        let size: UInt64
    }

    private struct LogicalArchiveSnapshot: Sendable {
        let files: [String: Data]
        let directories: Set<String>
        let topLevelNames: Set<String>
        let selectedRootComponent: String?
    }

    struct TestHooks {
        /// Runs after the extracted tree has passed its first exact postflight,
        /// but before root selection and the final exact postflight. A fixture
        /// can deterministically model a same-uid writer in that gap.
        var afterInitialFilesystemValidation: ((URL) -> Void)?
        var afterTopLevelEntryRead: ((String) -> Void)?

        init(
            afterInitialFilesystemValidation: ((URL) -> Void)? = nil,
            afterTopLevelEntryRead: ((String) -> Void)? = nil
        ) {
            self.afterInitialFilesystemValidation = afterInitialFilesystemValidation
            self.afterTopLevelEntryRead = afterTopLevelEntryRead
        }
    }

    private enum TarOperation: Equatable { case names, verbose, payload, extract }

    /// Extract a gzip-compressed tar archive into a private temporary root.
    /// The archive is listed and bounded before any payload bytes are written,
    /// and the resulting tree is independently checked with `lstat` afterward.
    public static func extract(
        archiveAt archiveURL: URL,
        limits: Limits = .default
    ) throws -> Extraction {
        try validateLimits(limits)
        let archivePath = archiveURL.path
        var archiveStat = stat()
        guard archivePath.withCString({ Darwin.lstat($0, &archiveStat) }) == 0,
              (archiveStat.st_mode & S_IFMT) == S_IFREG else {
            throw ExtractionError.inputNotRegular(archivePath)
        }
        let compressedBytes = UInt64(max(archiveStat.st_size, 0))
        let hardMaximum = min(
            limits.maxCompressedBytes,
            UInt64(BoundedPrivilegedProcessRunner.maximumStandardInputBytes)
        )
        guard compressedBytes <= hardMaximum else {
            throw ExtractionError.compressedSizeLimit(
                actual: compressedBytes,
                maximum: hardMaximum
            )
        }

        // Snapshot the exact regular-file bytes once. The source path may be
        // in an attacker-writable directory; invoking tar by that path three
        // times leaves a swap window between lstat, both listings, and
        // extraction. The shared reader opens O_NOFOLLOW|O_NONBLOCK, validates
        // the descriptor, bounds allocation, and rejects concurrent mutation.
        let readerLimit = Int(min(hardMaximum, UInt64(Int.max)))
        guard let archiveData = BoundedRegularFileReader.read(
            at: archivePath,
            maximumBytes: readerLimit
        ) else {
            throw ExtractionError.inputNotRegular(archivePath)
        }

        return try extract(archiveData: archiveData, limits: limits)
    }

    /// Extract an already-captured archive without rematerializing it at a
    /// same-uid-mutable pathname. Each bsdtar pass receives the identical
    /// bounded Data value on stdin.
    static func extract(
        archiveData: Data,
        limits: Limits = .default
    ) throws -> Extraction {
        try extract(
            archiveData: archiveData,
            limits: limits,
            testHooks: TestHooks()
        )
    }

    static func extract(
        archiveData: Data,
        limits: Limits,
        testHooks: TestHooks
    ) throws -> Extraction {
        try validateLimits(limits)
        let hardMaximum = min(
            limits.maxCompressedBytes,
            UInt64(BoundedPrivilegedProcessRunner.maximumStandardInputBytes)
        )
        guard UInt64(archiveData.count) <= hardMaximum else {
            throw ExtractionError.compressedSizeLimit(
                actual: UInt64(archiveData.count),
                maximum: hardMaximum
            )
        }

        let temporaryRoot = try makePrivateTemporaryRoot()
        var preserveTemporaryRoot = false
        defer {
            if !preserveTemporaryRoot {
                try? FileManager.default.removeItem(at: temporaryRoot)
            }
        }
        let temporaryRootDescriptor = Darwin.open(
            temporaryRoot.path,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
        )
        guard temporaryRootDescriptor >= 0 else {
            throw ExtractionError.filesystem(
                "could not open private extraction root: errno \(errno)"
            )
        }
        defer { Darwin.close(temporaryRootDescriptor) }
        guard TraceBundlePrivateFilePolicy.enforceDirectory(
            temporaryRootDescriptor
        ) else {
            throw ExtractionError.filesystem(
                "private extraction root has unsafe permissions or an extended ACL"
            )
        }
        try requireExtractionCapacity(
            at: temporaryRoot,
            compressedBytes: UInt64(archiveData.count),
            limits: limits
        )
        let extractionRoot = temporaryRoot.appendingPathComponent("extracted", isDirectory: true)
        guard Darwin.mkdirat(
            temporaryRootDescriptor,
            extractionRoot.lastPathComponent,
            mode_t(0o700)
        ) == 0 else {
            throw ExtractionError.filesystem(
                "could not create private extraction directory: errno \(errno)"
            )
        }
        let extractionRootDescriptor = extractionRoot.lastPathComponent.withCString {
            Darwin.openat(
                temporaryRootDescriptor,
                $0,
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
            )
        }
        guard extractionRootDescriptor >= 0 else {
            throw ExtractionError.filesystem(
                "could not open private extraction directory: errno \(errno)"
            )
        }
        defer { Darwin.close(extractionRootDescriptor) }
        guard TraceBundlePrivateFilePolicy.enforceDirectory(
            extractionRootDescriptor
        ) else {
            throw ExtractionError.filesystem(
                "private extraction directory has unsafe permissions or an extended ACL"
            )
        }

        // Use two machine-local listings. `-t` gives paths without having to
        // parse the variable-width date/name tail of `-tv`; `-tv` supplies the
        // entry type and declared size. LC_ALL=C makes the fixed fields stable,
        // while --numeric-owner is security-critical: archive-controlled
        // uname/gname fields may contain whitespace and otherwise shift the
        // declared-size column that we enforce before extraction.
        let namesData = try runTar(
            operation: .names,
            arguments: ["-tzf", "-"],
            maximumOutputBytes: limits.maxListingBytes,
            timeoutSeconds: limits.listingTimeoutSeconds,
            standardInputData: archiveData
        )
        let verboseData = try runTar(
            operation: .verbose,
            arguments: ["--numeric-owner", "-tvzf", "-"],
            maximumOutputBytes: limits.maxListingBytes,
            timeoutSeconds: limits.listingTimeoutSeconds,
            standardInputData: archiveData
        )
        let entries = try validateListings(namesData, verboseData, limits: limits)
        let capturedArchiveFiles = try captureRegularFilePayloads(
            entries: entries,
            archiveData: archiveData,
            timeoutSeconds: limits.extractionTimeoutSeconds
        )
        let logicalSnapshot = try makeLogicalSnapshot(
            entries: entries,
            capturedArchiveFiles: capturedArchiveFiles
        )

        _ = try runTar(
            operation: .extract,
            arguments: [
                "-xzf", "-",
                "-C", extractionRoot.path,
                "--no-same-owner",
                "--no-same-permissions",
                "--no-acls",
                "--no-fflags",
                "--no-mac-metadata",
                "--no-xattrs",
            ],
            maximumOutputBytes: 64 * 1_024,
            timeoutSeconds: limits.extractionTimeoutSeconds,
            standardInputData: archiveData
        )

        try validateBundleDirectory(
            at: extractionRoot,
            limits: limits,
            expectedEntries: entries,
            expectedFiles: capturedArchiveFiles
        )
        guard TraceBundlePrivateFilePolicy.validateDirectory(
            temporaryRootDescriptor
        ), TraceBundlePrivateFilePolicy.validateDirectory(
            extractionRootDescriptor
        ) else {
            throw ExtractionError.filesystem(
                "private extraction workspace lost its private permissions"
            )
        }

        testHooks.afterInitialFilesystemValidation?(extractionRoot)

        // Root selection used to call FileManager.contentsOfDirectory, which
        // buffers every same-uid-injectable name before applying any limit.
        // Enumerate through the retained dirfd and stop after one over-limit
        // sentinel, then require the actual top-level set to remain exactly the
        // set derived from the validated archive listing.
        let topLevelNames = try directoryEntryNames(
            descriptor: extractionRootDescriptor,
            path: extractionRoot.path,
            maximumEntries: limits.maxEntries,
            afterEntryRead: testHooks.afterTopLevelEntryRead
        )
        guard Set(topLevelNames) == logicalSnapshot.topLevelNames else {
            throw ExtractionError.unsafeFilesystemEntry(
                path: extractionRoot.path,
                reason: "top-level entry set changed after archive extraction"
            )
        }

        let bundleDirectory: URL
        if let selectedRoot = logicalSnapshot.selectedRootComponent {
            let selectedURL = extractionRoot.appendingPathComponent(
                selectedRoot,
                isDirectory: true
            )
            let info = try lstatInfo(selectedURL)
            guard (info.st_mode & S_IFMT) == S_IFDIR else {
                throw ExtractionError.unsafeFilesystemEntry(
                    path: selectedRoot,
                    reason: "archive-selected bundle root is no longer a real directory"
                )
            }
            bundleDirectory = selectedURL
        } else {
            bundleDirectory = extractionRoot
        }

        // A mode-0700 directory is still writable by another process running
        // as our uid. Re-run the exact byte/tree postflight after the test seam
        // and root selection. Even if a mutation lands after this check, the
        // semantic Resolution below consumes `capturedFiles`, never this path.
        try validateBundleDirectory(
            at: extractionRoot,
            limits: limits,
            expectedEntries: entries,
            expectedFiles: capturedArchiveFiles
        )

        preserveTemporaryRoot = true
        return Extraction(
            bundleDirectory: bundleDirectory,
            temporaryRoot: temporaryRoot,
            capturedFiles: logicalSnapshot.files,
            capturedDirectories: logicalSnapshot.directories
        )
    }

    /// Use a fixed system temporary base instead of inheriting TMPDIR from the
    /// invoking environment. `mkdtemp` creates the leaf atomically with 0700
    /// permissions, avoiding the create-after-existence-check race of a UUID
    /// path assembled through FileManager.
    private static func makePrivateTemporaryRoot() throws -> URL {
        var template = Array("/private/tmp/maccrab-safe-extract.XXXXXX".utf8CString)
        let path: String? = template.withUnsafeMutableBufferPointer { buffer in
            guard let base = buffer.baseAddress,
                  let created = Darwin.mkdtemp(base) else {
                return nil
            }
            return String(cString: created)
        }
        guard let path else {
            throw ExtractionError.filesystem(
                "mkdtemp failed under /private/tmp: errno \(errno)"
            )
        }
        return URL(fileURLWithPath: path, isDirectory: true)
    }

    /// Reserve space for the immutable compressed snapshot, the maximum
    /// declared payload, conservative per-entry filesystem metadata, and a
    /// one-GiB operational floor. The archive remains bounded even if another
    /// writer races this measurement; this admission prevents our own maximum
    /// extraction from knowingly consuming the remaining boot volume.
    private static func requireExtractionCapacity(
        at directory: URL,
        compressedBytes: UInt64,
        limits: Limits
    ) throws {
        guard limits.maxEntries >= 0,
              limits.maxListingBytes >= 0,
              limits.listingTimeoutSeconds > 0,
              limits.extractionTimeoutSeconds > 0 else {
            throw ExtractionError.filesystem("invalid negative/zero archive limits")
        }

        var filesystem = statfs()
        guard statfs(directory.path, &filesystem) == 0,
              filesystem.f_bavail >= 0,
              filesystem.f_bsize > 0 else {
            throw ExtractionError.filesystem(
                "statfs failed for \(directory.path): errno \(errno)"
            )
        }
        let (available, availableOverflow) = UInt64(filesystem.f_bavail)
            .multipliedReportingOverflow(by: UInt64(filesystem.f_bsize))
        guard !availableOverflow else {
            throw ExtractionError.filesystem("free-space accounting overflow")
        }

        let (entryOverhead, entryOverflow) = UInt64(limits.maxEntries)
            .multipliedReportingOverflow(by: 16 * 1_024)
        var required = limits.freeSpaceReserveBytes
        var overflow = entryOverflow
        for increment in [compressedBytes, limits.maxTotalFileBytes, entryOverhead] {
            let addition = required.addingReportingOverflow(increment)
            required = addition.partialValue
            overflow = overflow || addition.overflow
        }
        if overflow { required = UInt64.max }
        guard available >= required else {
            throw ExtractionError.insufficientFreeSpace(
                available: available,
                required: required
            )
        }
    }

    /// Validate an already-unpacked bundle before any caller loads whole files
    /// into memory. This protects directory inputs as well as archives.
    public static func validateBundleDirectory(
        at directory: URL,
        limits: Limits = .default
    ) throws {
        try validateLimits(limits)
        var metadata = stat()
        guard Darwin.lstat(directory.path, &metadata) == 0,
              (metadata.st_mode & S_IFMT) == S_IFDIR else {
            throw ExtractionError.unsafeFilesystemEntry(
                path: directory.path,
                reason: "bundle-directory validation requires a real directory"
            )
        }
        let resolution = try SafeTraceBundleResolver.resolve(
            inputAt: directory,
            limits: limits
        )
        defer { resolution.cleanup() }
        try validateBundleDirectory(
            resolvedBundle: resolution,
            limits: limits
        )
    }

    /// Validate a resolver-owned private snapshot without taking a redundant
    /// second copy. The unforgeable Resolution token makes the trusted input
    /// boundary explicit to production callers.
    public static func validateBundleDirectory(
        resolvedBundle resolution: SafeTraceBundleResolver.Resolution,
        limits: Limits = .default
    ) throws {
        try validateLimits(limits)
        let directoryCount = max(0, resolution.directoryPaths.count - 1)
        let entryCount = resolution.artifactPaths.count + directoryCount
        guard entryCount <= limits.maxEntries else {
            throw ExtractionError.entryCountLimit(
                actual: entryCount,
                maximum: limits.maxEntries
            )
        }
        var total: UInt64 = 0
        for path in resolution.artifactPaths {
            let data = try resolution.data(at: path)
            let size = UInt64(data.count)
            guard size <= limits.maxSingleFileBytes else {
                throw ExtractionError.singleFileSizeLimit(
                    path: path,
                    actual: size,
                    maximum: limits.maxSingleFileBytes
                )
            }
            let addition = total.addingReportingOverflow(size)
            guard !addition.overflow,
                  addition.partialValue <= limits.maxTotalFileBytes else {
                throw ExtractionError.totalFileSizeLimit(
                    actual: addition.overflow ? UInt64.max : addition.partialValue,
                    maximum: limits.maxTotalFileBytes
                )
            }
            total = addition.partialValue
        }
    }

    static func validateLimits(_ limits: Limits) throws {
        guard limits.maxEntries >= 0,
              limits.maxListingBytes >= 0,
              limits.maxListingBytes
                <= BoundedPrivilegedProcessRunner.maximumCapturedOutputBytes,
              limits.maxTotalFileBytes
                <= UInt64(BoundedPrivilegedProcessRunner.maximumCapturedOutputBytes),
              limits.listingTimeoutSeconds.isFinite,
              limits.listingTimeoutSeconds > 0,
              limits.listingTimeoutSeconds <= 3_600,
              limits.extractionTimeoutSeconds.isFinite,
              limits.extractionTimeoutSeconds > 0,
              limits.extractionTimeoutSeconds <= 3_600 else {
            throw ExtractionError.filesystem(
                "archive limits require bounded counts/output and finite 0-3600 second timeouts"
            )
        }
    }

    // MARK: - Listing validation

    private static func validateListings(
        _ namesData: Data,
        _ verboseData: Data,
        limits: Limits
    ) throws -> [ArchiveEntry] {
        guard let namesText = String(data: namesData, encoding: .utf8),
              let verboseText = String(data: verboseData, encoding: .utf8) else {
            throw ExtractionError.malformedListing("tar output is not UTF-8")
        }
        guard !namesText.utf8.contains(0), !verboseText.utf8.contains(0) else {
            throw ExtractionError.malformedListing("tar output contains NUL")
        }

        let nameLines = namesText.split(separator: "\n", omittingEmptySubsequences: false)
        let verboseLines = verboseText.split(separator: "\n", omittingEmptySubsequences: false)
        let names = dropOneTrailingEmptyLine(nameLines)
        let verbose = dropOneTrailingEmptyLine(verboseLines)
        guard !names.isEmpty else {
            throw ExtractionError.malformedListing("archive has no entries")
        }
        guard names.count == verbose.count else {
            throw ExtractionError.malformedListing(
                "name/type listing counts differ (\(names.count) vs \(verbose.count))"
            )
        }
        guard names.count <= limits.maxEntries else {
            throw ExtractionError.entryCountLimit(actual: names.count, maximum: limits.maxEntries)
        }

        var entries: [ArchiveEntry] = []
        entries.reserveCapacity(names.count)
        var seen = Set<String>()
        var totalBytes: UInt64 = 0

        for (nameSlice, verboseSlice) in zip(names, verbose) {
            let rawName = String(nameSlice)
            let fields = verboseSlice.split(whereSeparator: { $0 == " " || $0 == "\t" })
            guard let type = fields.first?.first, fields.count >= 5,
                  let size = UInt64(fields[4]) else {
                throw ExtractionError.malformedListing("cannot parse entry metadata for \(rawName)")
            }
            guard type == "-" || type == "d" else {
                throw ExtractionError.unsupportedEntry(path: rawName, type: type)
            }

            guard let normalized = try normalizeArchivePath(rawName) else {
                // A conventional leading `./` root entry carries no payload.
                guard type == "d" else {
                    throw ExtractionError.unsafePath(rawName)
                }
                continue
            }
            guard seen.insert(normalized).inserted else {
                throw ExtractionError.unsafePath("duplicate normalized path: \(normalized)")
            }

            if type == "-" {
                guard size <= limits.maxSingleFileBytes else {
                    throw ExtractionError.singleFileSizeLimit(
                        path: normalized,
                        actual: size,
                        maximum: limits.maxSingleFileBytes
                    )
                }
                let (nextTotal, overflow) = totalBytes.addingReportingOverflow(size)
                guard !overflow, nextTotal <= limits.maxTotalFileBytes else {
                    throw ExtractionError.totalFileSizeLimit(
                        actual: overflow ? UInt64.max : nextTotal,
                        maximum: limits.maxTotalFileBytes
                    )
                }
                totalBytes = nextTotal
            } else if size != 0 {
                throw ExtractionError.malformedListing(
                    "directory \(normalized) declares non-zero size \(size)"
                )
            }

            entries.append(ArchiveEntry(
                path: normalized,
                kind: type == "-" ? .file : .directory,
                size: size
            ))
        }
        return entries
    }

    /// Ask bsdtar for one concatenated stdout stream of regular-file contents.
    /// The validated listing fixes both order and each slice length, so the
    /// stream can be split without reopening the extracted filesystem tree.
    private static func captureRegularFilePayloads(
        entries: [ArchiveEntry],
        archiveData: Data,
        timeoutSeconds: TimeInterval
    ) throws -> [String: Data] {
        var declaredBytes: UInt64 = 0
        for entry in entries {
            guard case .file = entry.kind else { continue }
            let addition = declaredBytes.addingReportingOverflow(entry.size)
            guard !addition.overflow else {
                throw ExtractionError.totalFileSizeLimit(
                    actual: UInt64.max,
                    maximum: UInt64.max
                )
            }
            declaredBytes = addition.partialValue
        }
        guard let maximumOutputBytes = Int(exactly: declaredBytes) else {
            throw ExtractionError.totalFileSizeLimit(
                actual: declaredBytes,
                maximum: UInt64(Int.max)
            )
        }

        let payload = try runTar(
            operation: .payload,
            arguments: ["-xOzf", "-"],
            maximumOutputBytes: maximumOutputBytes,
            timeoutSeconds: timeoutSeconds,
            standardInputData: archiveData
        )
        guard payload.count == maximumOutputBytes else {
            throw ExtractionError.malformedListing(
                "payload stream is \(payload.count) bytes; listing declares \(maximumOutputBytes)"
            )
        }

        var captured: [String: Data] = [:]
        var offset = 0
        for entry in entries {
            guard case .file = entry.kind else { continue }
            guard let count = Int(exactly: entry.size),
                  count <= payload.count - offset else {
                throw ExtractionError.malformedListing(
                    "payload stream ended inside \(entry.path)"
                )
            }
            captured[entry.path] = payload.subdata(in: offset..<(offset + count))
            offset += count
        }
        guard offset == payload.count else {
            throw ExtractionError.malformedListing("payload stream has trailing bytes")
        }
        return captured
    }

    /// Mirror the historical extraction-root convention without consulting a
    /// mutable pathname: when the archive has exactly one top-level directory,
    /// that directory is the logical bundle root; otherwise extractionRoot is.
    private static func makeLogicalSnapshot(
        entries: [ArchiveEntry],
        capturedArchiveFiles: [String: Data]
    ) throws -> LogicalArchiveSnapshot {
        let topLevelNames = Set(entries.compactMap { entry in
            entry.path.split(separator: "/", maxSplits: 1).first.map(String.init)
        })
        var selectedRoot: String?
        if topLevelNames.count == 1, let only = topLevelNames.first {
            let topLevelIsFile = entries.contains { entry in
                guard entry.path == only else { return false }
                if case .file = entry.kind { return true }
                return false
            }
            if !topLevelIsFile { selectedRoot = only }
        }

        let archiveDirectories = directoryPaths(for: entries)
        var logicalFiles: [String: Data] = [:]
        var logicalDirectories: Set<String> = [""]

        for (path, data) in capturedArchiveFiles {
            let logicalPath = try stripSelectedRoot(selectedRoot, from: path)
            guard !logicalPath.isEmpty else {
                throw ExtractionError.malformedListing(
                    "selected archive root is also a regular file"
                )
            }
            logicalFiles[logicalPath] = data
        }
        for path in archiveDirectories where !path.isEmpty {
            let logicalPath = try stripSelectedRoot(selectedRoot, from: path)
            if !logicalPath.isEmpty { logicalDirectories.insert(logicalPath) }
        }
        return LogicalArchiveSnapshot(
            files: logicalFiles,
            directories: logicalDirectories,
            topLevelNames: topLevelNames,
            selectedRootComponent: selectedRoot
        )
    }

    private static func stripSelectedRoot(
        _ selectedRoot: String?,
        from path: String
    ) throws -> String {
        guard let selectedRoot else { return path }
        if path == selectedRoot { return "" }
        let prefix = selectedRoot + "/"
        guard path.hasPrefix(prefix) else {
            throw ExtractionError.malformedListing(
                "archive entry \(path) falls outside selected root \(selectedRoot)"
            )
        }
        return String(path.dropFirst(prefix.count))
    }

    private static func directoryPaths(for entries: [ArchiveEntry]) -> Set<String> {
        var directories: Set<String> = [""]
        for entry in entries {
            let components = entry.path.split(separator: "/").map(String.init)
            if components.count > 1 {
                for end in 1..<components.count {
                    directories.insert(components.prefix(end).joined(separator: "/"))
                }
            }
            if case .directory = entry.kind { directories.insert(entry.path) }
        }
        return directories
    }

    private static func dropOneTrailingEmptyLine(
        _ lines: [Substring]
    ) -> ArraySlice<Substring> {
        guard lines.last?.isEmpty == true else { return lines[...] }
        return lines.dropLast()
    }

    /// Return nil only for the conventional `.` / `./` archive root entry.
    /// The bundle exporter emits ASCII filenames, so a conservative alphabet
    /// avoids ambiguous bsdtar escaping (notably literal `\\n` versus newline).
    private static func normalizeArchivePath(_ rawPath: String) throws -> String? {
        guard !rawPath.isEmpty, !rawPath.contains("\r"), !rawPath.contains("\\") else {
            throw ExtractionError.unsafePath(rawPath)
        }
        var path = rawPath
        while path.hasPrefix("./") { path.removeFirst(2) }
        while path.hasSuffix("/") { path.removeLast() }
        if path == "." || path.isEmpty { return nil }
        guard !path.hasPrefix("/"), path.utf8.count <= 4_096 else {
            throw ExtractionError.unsafePath(rawPath)
        }

        let components = path.split(separator: "/", omittingEmptySubsequences: false)
        guard !components.isEmpty else { throw ExtractionError.unsafePath(rawPath) }
        for component in components {
            guard !component.isEmpty,
                  component != ".",
                  component != "..",
                  !component.hasPrefix("."),
                  component.utf8.count <= 255 else {
                throw ExtractionError.unsafePath(rawPath)
            }
            for scalar in component.unicodeScalars {
                let value = scalar.value
                let safe = (value >= 48 && value <= 57)   // 0-9
                    || (value >= 65 && value <= 90)       // A-Z
                    || (value >= 97 && value <= 122)      // a-z
                    || value == 45 || value == 46 || value == 95 // - . _
                guard safe else { throw ExtractionError.unsafePath(rawPath) }
            }
        }
        return components.map(String.init).joined(separator: "/")
    }

    // MARK: - Extracted filesystem validation

    private static func directoryEntryNames(
        descriptor: Int32,
        path: String,
        maximumEntries: Int,
        afterEntryRead: ((String) -> Void)?
    ) throws -> [String] {
        let independent = Darwin.openat(
            descriptor,
            ".",
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
        )
        guard independent >= 0 else {
            throw ExtractionError.filesystem(
                "could not open extraction root for enumeration: errno \(errno)"
            )
        }
        guard let stream = Darwin.fdopendir(independent) else {
            let savedErrno = errno
            Darwin.close(independent)
            throw ExtractionError.filesystem(
                "could not enumerate extraction root: errno \(savedErrno)"
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
                throw ExtractionError.unsafeFilesystemEntry(
                    path: path,
                    reason: "top-level entry name is not UTF-8"
                )
            }
            if name == "." || name == ".." { continue }
            afterEntryRead?(name)
            guard names.count < maximumEntries else {
                let actual = maximumEntries == Int.max
                    ? Int.max
                    : maximumEntries + 1
                throw ExtractionError.entryCountLimit(
                    actual: actual,
                    maximum: maximumEntries
                )
            }
            names.append(name)
        }
        guard errno == 0 else {
            throw ExtractionError.filesystem(
                "could not enumerate extraction root: errno \(errno)"
            )
        }
        return names.sorted()
    }

    private static func validateBundleDirectory(
        at directory: URL,
        limits: Limits,
        expectedEntries: [ArchiveEntry]?,
        expectedFiles: [String: Data]? = nil
    ) throws {
        let rootInfo = try lstatInfo(directory)
        guard (rootInfo.st_mode & S_IFMT) == S_IFDIR else {
            throw ExtractionError.unsafeFilesystemEntry(
                path: directory.path,
                reason: "bundle root is not a real directory"
            )
        }

        var enumerationFailure: Swift.Error?
        guard let enumerator = FileManager.default.enumerator(
            at: directory,
            includingPropertiesForKeys: nil,
            options: [],
            errorHandler: { _, error in
                enumerationFailure = error
                return false
            }
        ) else {
            throw ExtractionError.filesystem("cannot enumerate \(directory.path)")
        }

        let rootPath = directory.standardizedFileURL.path
        let rootPrefix = rootPath.hasSuffix("/") ? rootPath : rootPath + "/"
        var observed: [String: (ArchiveEntry.Kind, UInt64)] = [:]
        var totalBytes: UInt64 = 0
        var count = 0

        for case let itemURL as URL in enumerator {
            count += 1
            guard count <= limits.maxEntries else {
                throw ExtractionError.entryCountLimit(actual: count, maximum: limits.maxEntries)
            }
            let standardized = itemURL.standardizedFileURL.path
            guard standardized.hasPrefix(rootPrefix) else {
                throw ExtractionError.unsafeFilesystemEntry(
                    path: itemURL.path,
                    reason: "entry resolves outside the bundle root"
                )
            }
            let relative = String(standardized.dropFirst(rootPrefix.count))
            guard let normalized = try normalizeArchivePath(relative) else {
                throw ExtractionError.unsafeFilesystemEntry(
                    path: itemURL.path,
                    reason: "invalid empty path"
                )
            }

            let info = try lstatInfo(itemURL)
            let fileType = info.st_mode & S_IFMT
            if fileType == S_IFDIR {
                observed[normalized] = (.directory, 0)
                continue
            }
            guard fileType == S_IFREG else {
                enumerator.skipDescendants()
                throw ExtractionError.unsafeFilesystemEntry(
                    path: normalized,
                    reason: "only real directories and regular files are allowed"
                )
            }
            guard info.st_nlink == 1 else {
                throw ExtractionError.unsafeFilesystemEntry(
                    path: normalized,
                    reason: "hard-linked files are not allowed"
                )
            }
            let size = UInt64(max(info.st_size, 0))
            guard size <= limits.maxSingleFileBytes else {
                throw ExtractionError.singleFileSizeLimit(
                    path: normalized,
                    actual: size,
                    maximum: limits.maxSingleFileBytes
                )
            }
            let (nextTotal, overflow) = totalBytes.addingReportingOverflow(size)
            guard !overflow, nextTotal <= limits.maxTotalFileBytes else {
                throw ExtractionError.totalFileSizeLimit(
                    actual: overflow ? UInt64.max : nextTotal,
                    maximum: limits.maxTotalFileBytes
                )
            }
            totalBytes = nextTotal
            observed[normalized] = (.file, size)

            if let expectedFiles {
                guard let expectedData = expectedFiles[normalized],
                      expectedData.count == Int(size),
                      let actualData = BoundedRegularFileReader.read(
                          at: itemURL.path,
                          maximumBytes: expectedData.count
                      ),
                      actualData == expectedData else {
                    throw ExtractionError.unsafeFilesystemEntry(
                        path: normalized,
                        reason: "extracted bytes differ from immutable archive payload"
                    )
                }
            }
        }

        if let enumerationFailure {
            throw ExtractionError.filesystem(
                "directory enumeration failed under \(directory.path): \(enumerationFailure)"
            )
        }

        guard let expectedEntries else { return }
        let expected = Dictionary(uniqueKeysWithValues: expectedEntries.map { ($0.path, ($0.kind, $0.size)) })
        for entry in expectedEntries {
            guard let actual = observed[entry.path] else {
                throw ExtractionError.unsafeFilesystemEntry(
                    path: entry.path,
                    reason: "listed entry was not extracted"
                )
            }
            switch (entry.kind, actual.0) {
            case (.file, .file):
                guard entry.size == actual.1 else {
                    throw ExtractionError.unsafeFilesystemEntry(
                        path: entry.path,
                        reason: "extracted size \(actual.1) differs from listed size \(entry.size)"
                    )
                }
            case (.directory, .directory):
                break
            default:
                throw ExtractionError.unsafeFilesystemEntry(
                    path: entry.path,
                    reason: "extracted type differs from listed type"
                )
            }
        }
        // Tar may create parent directories that were implicit in the archive,
        // but every extracted regular file must have appeared in the listing.
        for (path, value) in observed where value.0 == .file && expected[path] == nil {
            throw ExtractionError.unsafeFilesystemEntry(
                path: path,
                reason: "unlisted regular file appeared during extraction"
            )
        }
        let expectedDirectories = directoryPaths(for: expectedEntries)
            .subtracting([""])
        let observedDirectories = Set(observed.compactMap { path, value in
            if case .directory = value.0 { return path }
            return nil
        })
        guard observedDirectories == expectedDirectories else {
            throw ExtractionError.unsafeFilesystemEntry(
                path: directory.path,
                reason: "extracted directory set differs from archive listing"
            )
        }
    }

    private static func lstatInfo(_ url: URL) throws -> stat {
        var info = stat()
        guard url.path.withCString({ Darwin.lstat($0, &info) }) == 0 else {
            throw ExtractionError.filesystem(
                "lstat failed for \(url.path): errno \(errno)"
            )
        }
        return info
    }

    // MARK: - Bounded subprocess

    private static func runTar(
        operation: TarOperation,
        arguments: [String],
        maximumOutputBytes: Int,
        timeoutSeconds: TimeInterval,
        standardInputData: Data
    ) throws -> Data {
        // `/usr/bin/tar` is a symlink on macOS; invoke its immutable regular
        // target so the shared privileged executable policy can validate the
        // complete component chain without following links. The runner uses a
        // nonblocking pipe, a retained-byte cap, and a SIGKILL deadline; a
        // descendant retaining stdout cannot hold this caller open forever.
        guard let result = BoundedPrivilegedProcessRunner.run(
            executable: "/usr/bin/bsdtar",
            arguments: arguments,
            environment: tarEnvironment,
            workingDirectory: "/",
            timeout: max(timeoutSeconds, 0.1),
            maximumOutputBytes: maximumOutputBytes,
            mergeStandardErrorIntoOutput: false,
            standardInputData: standardInputData
        ) else {
            throw ExtractionError.filesystem("could not launch trusted /usr/bin/bsdtar")
        }
        if result.timedOut {
            throw operation == .extract
                ? ExtractionError.extractionTimedOut
                : ExtractionError.listingTimedOut
        }
        if result.outputLimitExceeded {
            if operation == .payload {
                let maximum = UInt64(maximumOutputBytes)
                throw ExtractionError.totalFileSizeLimit(
                    actual: maximum + 1,
                    maximum: maximum
                )
            }
            throw ExtractionError.listingOutputLimit(maximum: maximumOutputBytes)
        }
        guard result.terminationStatus == 0 else {
            let label: String
            switch operation {
            case .names: label = "name listing"
            case .verbose: label = "metadata listing"
            case .payload: label = "payload capture"
            case .extract: label = "extraction"
            }
            throw ExtractionError.tarFailed(
                operation: label,
                status: result.terminationStatus ?? -1
            )
        }
        return result.output
    }
}
