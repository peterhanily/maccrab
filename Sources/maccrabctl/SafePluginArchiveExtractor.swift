// SafePluginArchiveExtractor.swift
//
// The rave catalog signature and artifact SHA authorize plugin bytes; they do
// not make the transport or archive parser a safe resource boundary. Keep the
// HTTP and ZIP ceilings next to the one shipped catalog-install implementation,
// and extract regular files ourselves so an archive tool never gets to create
// paths, links, or an attacker-declared amount of data on disk.

import Darwin
import Foundation
import MacCrabCore
import MacCrabForensics

struct PluginFetchLimits: Sendable, Equatable {
    var maximumMetadataBytes: Int
    var maximumSignatureBytes: Int
    var maximumArtifactBytes: Int

    init(
        maximumMetadataBytes: Int = 4 * 1_024 * 1_024,
        maximumSignatureBytes: Int = 64,
        maximumArtifactBytes: Int = 64 * 1_024 * 1_024
    ) {
        self.maximumMetadataBytes = maximumMetadataBytes
        self.maximumSignatureBytes = maximumSignatureBytes
        self.maximumArtifactBytes = maximumArtifactBytes
    }

    static let production = PluginFetchLimits()
}

/// Small value type used by the streamed URLSession path. It deliberately does
/// not retain the first byte over the ceiling.
struct PluginFetchBodyAccumulator: Sendable {
    let maximumBytes: Int
    private(set) var data = Data()

    init(maximumBytes: Int) {
        self.maximumBytes = max(0, maximumBytes)
    }

    mutating func append(_ byte: UInt8) -> Bool {
        guard data.count < maximumBytes else { return false }
        data.append(byte)
        return true
    }
}

enum SafePluginArchiveExtractor {
    struct Limits: Sendable, Equatable {
        var maximumCompressedBytes: UInt64
        var maximumEntries: Int
        var maximumSingleFileBytes: UInt64
        var maximumExpandedBytes: UInt64
        var maximumListingBytes: Int
        var listingTimeoutSeconds: TimeInterval
        var extractionTimeoutSeconds: TimeInterval
        /// Operational floor that must remain after the maximum expanded
        /// payload and conservative per-entry/filesystem headroom are admitted.
        var freeSpaceReserveBytes: UInt64

        init(
            maximumCompressedBytes: UInt64 = 64 * 1_024 * 1_024,
            maximumEntries: Int = 128,
            maximumSingleFileBytes: UInt64 = 64 * 1_024 * 1_024,
            maximumExpandedBytes: UInt64 = 128 * 1_024 * 1_024,
            maximumListingBytes: Int = 1 * 1_024 * 1_024,
            listingTimeoutSeconds: TimeInterval = 10,
            extractionTimeoutSeconds: TimeInterval = 30,
            freeSpaceReserveBytes: UInt64 = 1 * 1_024 * 1_024 * 1_024
        ) {
            self.maximumCompressedBytes = maximumCompressedBytes
            self.maximumEntries = maximumEntries
            self.maximumSingleFileBytes = maximumSingleFileBytes
            self.maximumExpandedBytes = maximumExpandedBytes
            self.maximumListingBytes = maximumListingBytes
            self.listingTimeoutSeconds = listingTimeoutSeconds
            self.extractionTimeoutSeconds = extractionTimeoutSeconds
            self.freeSpaceReserveBytes = freeSpaceReserveBytes
        }

        static let production = Limits()
    }

    struct Extraction: Sendable {
        let bundleDirectory: URL
        let temporaryRoot: URL
        /// Authoritative installation input. The directory is retained only
        /// for diagnostics/tests; same-uid processes can mutate it, so callers
        /// must make trust decisions and install from this captured value.
        let snapshot: PluginBundleSnapshot

        func cleanup() {
            try? FileManager.default.removeItem(at: temporaryRoot)
        }
    }

    enum ExtractionError: Error, LocalizedError, CustomStringConvertible, Equatable {
        case inputNotRegular(String)
        case notZipArchive
        case compressedSizeLimit(actual: UInt64, maximum: UInt64)
        case listingTimedOut
        case extractionTimedOut
        case listingOutputLimit(maximum: Int)
        case archiveToolFailed(operation: String, status: Int32)
        case malformedListing(String)
        case unsafePath(String)
        case pathOutsidePlugin(path: String, pluginID: String)
        case unsupportedEntry(path: String, type: Character)
        case entryCountLimit(actual: Int, maximum: Int)
        case singleFileSizeLimit(path: String, actual: UInt64, maximum: UInt64)
        case expandedSizeLimit(actual: UInt64, maximum: UInt64)
        case insufficientFreeSpace(available: UInt64, required: UInt64)
        case extractedSizeMismatch(path: String, expected: UInt64, actual: UInt64)
        case filesystem(String)

        var errorDescription: String? {
            switch self {
            case .inputNotRegular(let path):
                return "plugin archive is not a regular, single-link file: \(path)"
            case .notZipArchive:
                return "plugin artifact is not a ZIP archive"
            case .compressedSizeLimit(let actual, let maximum):
                return "compressed plugin archive is \(actual) bytes; limit is \(maximum) bytes"
            case .listingTimedOut:
                return "plugin archive listing exceeded its time limit"
            case .extractionTimedOut:
                return "plugin archive extraction exceeded its time limit"
            case .listingOutputLimit(let maximum):
                return "plugin archive listing exceeded \(maximum) bytes"
            case .archiveToolFailed(let operation, let status):
                return "plugin archive \(operation) failed with status \(status)"
            case .malformedListing(let detail):
                return "plugin archive listing is malformed: \(detail)"
            case .unsafePath(let path):
                return "plugin archive contains an unsafe path: \(path)"
            case .pathOutsidePlugin(let path, let pluginID):
                return "plugin archive entry \(path) is outside its \(pluginID)/ bundle root"
            case .unsupportedEntry(let path, let type):
                return "plugin archive entry \(path) has unsupported type '\(type)'"
            case .entryCountLimit(let actual, let maximum):
                return "plugin archive contains \(actual) entries; limit is \(maximum)"
            case .singleFileSizeLimit(let path, let actual, let maximum):
                return "plugin archive entry \(path) is \(actual) bytes; per-file limit is \(maximum)"
            case .expandedSizeLimit(let actual, let maximum):
                return "plugin archive expands to \(actual) bytes; limit is \(maximum)"
            case .insufficientFreeSpace(let available, let required):
                return "plugin archive extraction requires \(required) free bytes; only \(available) are available"
            case .extractedSizeMismatch(let path, let expected, let actual):
                return "plugin archive entry \(path) emitted \(actual) bytes; listing declared \(expected)"
            case .filesystem(let detail):
                return "plugin archive filesystem error: \(detail)"
            }
        }

        var description: String { errorDescription ?? "plugin archive rejected" }
    }

    private struct ArchiveEntry: Sendable {
        enum Kind: Sendable, Equatable { case file, directory }
        let archivePath: String
        let relativePath: String
        let kind: Kind
        let size: UInt64
    }

    private enum ToolOperation {
        case names
        case verbose

        var label: String {
            switch self {
            case .names: return "name listing"
            case .verbose: return "metadata listing"
            }
        }
    }

    static func extract(
        archiveAt archiveURL: URL,
        pluginID: String,
        limits: Limits = .production
    ) throws -> Extraction {
        // Validate configuration before touching the carrier. Tests and callers
        // rely on invalid limits failing even when the supplied path is absent.
        try PluginInstaller.validatePluginID(pluginID)
        guard limits.maximumEntries >= 0,
              limits.maximumEntries <= Int.max - 32,
              limits.maximumListingBytes >= 0,
              limits.listingTimeoutSeconds.isFinite,
              limits.listingTimeoutSeconds > 0,
              limits.listingTimeoutSeconds <= 3_600,
              limits.extractionTimeoutSeconds.isFinite,
              limits.extractionTimeoutSeconds > 0,
              limits.extractionTimeoutSeconds <= 3_600 else {
            throw ExtractionError.filesystem("invalid archive limits")
        }
        let archivePath = archiveURL.path
        var archiveInfo = stat()
        guard archivePath.withCString({ Darwin.lstat($0, &archiveInfo) }) == 0,
              (archiveInfo.st_mode & S_IFMT) == S_IFREG,
              archiveInfo.st_nlink == 1 else {
            throw ExtractionError.inputNotRegular(archivePath)
        }
        let compressedBytes = UInt64(max(archiveInfo.st_size, 0))
        guard compressedBytes <= limits.maximumCompressedBytes else {
            throw ExtractionError.compressedSizeLimit(
                actual: compressedBytes,
                maximum: limits.maximumCompressedBytes
            )
        }

        // Freeze the exact input bytes once before any archive-tool pass. The
        // downloaded path can live in a caller-controlled directory; lstat
        // followed by three path-based tool invocations otherwise lets it be
        // swapped between magic checking, the two listings, and extraction.
        // The shared reader performs a descriptor-relative O_NOFOLLOW walk,
        // bounds allocation, rejects hard links, and detects mutation.
        let readerLimit = Int(min(limits.maximumCompressedBytes, UInt64(Int.max)))
        guard let archiveData = BoundedRegularFileReader.read(
            at: archivePath,
            maximumBytes: readerLimit
        ) else {
            throw ExtractionError.inputNotRegular(archivePath)
        }
        return try extract(
            archiveData: archiveData,
            pluginID: pluginID,
            limits: limits
        )
    }

    /// Parse an already-captured archive without re-materializing it at a
    /// pathname. Every bsdtar pass receives these exact bytes over stdin, so a
    /// process under the same uid cannot swap the authenticated artifact after
    /// its catalog SHA-256 check.
    static func extract(
        archiveData: Data,
        pluginID: String,
        limits: Limits = .production
    ) throws -> Extraction {
        try PluginInstaller.validatePluginID(pluginID)
        guard limits.maximumEntries >= 0,
              limits.maximumEntries <= Int.max - 32,
              limits.maximumListingBytes >= 0,
              limits.listingTimeoutSeconds.isFinite,
              limits.listingTimeoutSeconds > 0,
              limits.listingTimeoutSeconds <= 3_600,
              limits.extractionTimeoutSeconds.isFinite,
              limits.extractionTimeoutSeconds > 0,
              limits.extractionTimeoutSeconds <= 3_600 else {
            throw ExtractionError.filesystem("invalid archive limits")
        }
        let compressedBytes = UInt64(archiveData.count)
        guard compressedBytes <= limits.maximumCompressedBytes,
              archiveData.count <= BoundedPrivilegedProcessRunner.maximumStandardInputBytes else {
            throw ExtractionError.compressedSizeLimit(
                actual: compressedBytes,
                maximum: min(
                    limits.maximumCompressedBytes,
                    UInt64(BoundedPrivilegedProcessRunner.maximumStandardInputBytes)
                )
            )
        }
        try assertZipMagic(archiveData)

        let temporaryRoot = try makePrivateTemporaryRoot()
        var keepTemporaryRoot = false
        defer {
            if !keepTemporaryRoot {
                try? FileManager.default.removeItem(at: temporaryRoot)
            }
        }
        try requireExtractionCapacity(
            at: temporaryRoot,
            compressedBytes: UInt64(archiveData.count),
            limits: limits
        )
        let extractionRoot = temporaryRoot.appendingPathComponent(
            "extracted", isDirectory: true
        )
        try FileManager.default.createDirectory(
            at: extractionRoot,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )

        // bsdtar auto-detects ZIP. Its name-only listing avoids parsing the
        // variable-width filename tail of `-tvf`; the verbose listing supplies
        // only the entry type and declared size. Both outputs are independently
        // bounded and must have exactly the same number of lines.
        let names = try runArchiveToolCapture(
            operation: .names,
            arguments: ["-tf", "-"],
            archiveData: archiveData,
            maximumOutputBytes: limits.maximumListingBytes,
            timeoutSeconds: limits.listingTimeoutSeconds
        )
        let verbose = try runArchiveToolCapture(
            operation: .verbose,
            arguments: ["--numeric-owner", "-tvf", "-"],
            archiveData: archiveData,
            maximumOutputBytes: limits.maximumListingBytes,
            timeoutSeconds: limits.listingTimeoutSeconds
        )
        let entries = try validateListings(
            names,
            verbose,
            pluginID: pluginID,
            limits: limits
        )

        let bundleDirectory = extractionRoot.appendingPathComponent(pluginID, isDirectory: true)
        try createPrivateDirectory(bundleDirectory)
        let extractionBudget = UInt64(
            max(limits.extractionTimeoutSeconds, 0.1) * 1_000_000_000
        )
        let (deadline, deadlineOverflow) = DispatchTime.now().uptimeNanoseconds
            .addingReportingOverflow(extractionBudget)
        var capturedFiles: [String: Data] = [:]
        capturedFiles.reserveCapacity(PluginBundleSnapshot.requiredFileNames.count)

        // Do not grant the archive tool a filesystem extraction primitive. For
        // each preflighted regular file, ask it for stdout and write no more than
        // the declared size into a path we created under the private root. This
        // bounds actual disk consumption even if a malformed ZIP lies about its
        // expanded size, and makes path traversal/link creation impossible.
        for entry in entries {
            let destination = extractionRoot.appendingPathComponent(entry.relativePath)
            switch entry.kind {
            case .directory:
                try createPrivateDirectory(destination)
            case .file:
                try createPrivateDirectory(destination.deletingLastPathComponent())
                let now = DispatchTime.now().uptimeNanoseconds
                guard !deadlineOverflow, deadline > now else {
                    throw ExtractionError.extractionTimedOut
                }
                let remaining = TimeInterval(deadline - now) / 1_000_000_000
                let bytes = try extractRegularFile(
                    archiveData: archiveData,
                    entry: entry,
                    destination: destination,
                    timeoutSeconds: remaining
                )
                let bundlePrefix = pluginID + "/"
                guard entry.relativePath.hasPrefix(bundlePrefix) else {
                    throw ExtractionError.pathOutsidePlugin(
                        path: entry.relativePath,
                        pluginID: pluginID
                    )
                }
                capturedFiles[String(entry.relativePath.dropFirst(bundlePrefix.count))] = bytes
            }
        }

        try validateExtractedTree(
            root: extractionRoot,
            entries: entries,
            limits: limits
        )
        let snapshot: PluginBundleSnapshot
        do {
            snapshot = try PluginBundleSnapshot(files: capturedFiles)
        } catch {
            throw ExtractionError.filesystem(String(describing: error))
        }
        keepTemporaryRoot = true
        return Extraction(
            bundleDirectory: bundleDirectory,
            temporaryRoot: temporaryRoot,
            snapshot: snapshot
        )
    }

    // MARK: - Preflight

    /// Use a fixed system temporary base instead of inheriting TMPDIR. mkdtemp
    /// atomically creates the 0700 workspace, eliminating the UUID
    /// exists-check/create race before hostile bytes are staged.
    private static func makePrivateTemporaryRoot() throws -> URL {
        var template = Array("/private/tmp/maccrab-plugin-extract.XXXXXX".utf8CString)
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

    /// Admit the configured maximum expanded output, conservative per-entry
    /// metadata (plus compressed-size headroom), and at least the production
    /// one-GiB operational floor before any bytes are copied.
    private static func requireExtractionCapacity(
        at directory: URL,
        compressedBytes: UInt64,
        limits: Limits
    ) throws {
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

        let (entryOverhead, entryOverflow) = UInt64(limits.maximumEntries)
            .multipliedReportingOverflow(by: 16 * 1_024)
        var required = limits.freeSpaceReserveBytes
        var overflow = entryOverflow
        for increment in [compressedBytes, limits.maximumExpandedBytes, entryOverhead] {
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

    private static func assertZipMagic(_ archiveData: Data) throws {
        let magic = archiveData.prefix(4)
        let accepted: Set<[UInt8]> = [
            [0x50, 0x4b, 0x03, 0x04], // ordinary ZIP
            [0x50, 0x4b, 0x05, 0x06], // empty ZIP
            [0x50, 0x4b, 0x07, 0x08], // spanned ZIP marker
        ]
        guard magic.count == 4, accepted.contains(Array(magic)) else {
            throw ExtractionError.notZipArchive
        }
    }

    private static func validateListings(
        _ namesData: Data,
        _ verboseData: Data,
        pluginID: String,
        limits: Limits
    ) throws -> [ArchiveEntry] {
        guard let namesText = String(data: namesData, encoding: .utf8),
              let verboseText = String(data: verboseData, encoding: .utf8) else {
            throw ExtractionError.malformedListing("archive-tool output is not UTF-8")
        }
        guard !namesText.utf8.contains(0), !verboseText.utf8.contains(0) else {
            throw ExtractionError.malformedListing("archive-tool output contains NUL")
        }

        let names = dropTrailingEmptyLine(namesText.split(
            separator: "\n", omittingEmptySubsequences: false))
        let verbose = dropTrailingEmptyLine(verboseText.split(
            separator: "\n", omittingEmptySubsequences: false))
        guard !names.isEmpty else {
            throw ExtractionError.malformedListing("archive has no entries")
        }
        guard names.count == verbose.count else {
            throw ExtractionError.malformedListing(
                "name/type listing counts differ (\(names.count) vs \(verbose.count))"
            )
        }
        guard names.count <= limits.maximumEntries else {
            throw ExtractionError.entryCountLimit(
                actual: names.count,
                maximum: limits.maximumEntries
            )
        }

        var entries: [ArchiveEntry] = []
        entries.reserveCapacity(names.count)
        var seenExact = Set<String>()
        var seenCaseFolded = Set<String>()
        var totalBytes: UInt64 = 0

        for (nameSlice, verboseSlice) in zip(names, verbose) {
            let rawName = String(nameSlice)
            let fields = verboseSlice.split(whereSeparator: { $0 == " " || $0 == "\t" })
            guard let type = fields.first?.first,
                  fields.count >= 5,
                  let size = UInt64(fields[4]) else {
                throw ExtractionError.malformedListing(
                    "cannot parse entry metadata for \(rawName)"
                )
            }
            guard type == "-" || type == "d" else {
                throw ExtractionError.unsupportedEntry(path: rawName, type: type)
            }

            guard let normalized = try normalizeArchivePath(rawName) else {
                guard type == "d" else { throw ExtractionError.unsafePath(rawName) }
                continue
            }
            let components = normalized.split(separator: "/", omittingEmptySubsequences: false)
            guard components.first == Substring(pluginID) else {
                throw ExtractionError.pathOutsidePlugin(path: rawName, pluginID: pluginID)
            }
            if type == "d" {
                guard components.count == 1 else {
                    throw ExtractionError.unsafePath(
                        "plugin bundles may not contain nested directories: \(normalized)"
                    )
                }
            } else {
                guard components.count == 2,
                      PluginBundleSnapshot.requiredFileNames.contains(String(components[1])) else {
                    throw ExtractionError.unsafePath(
                        "plugin bundles contain exactly manifest.json, binary, signature, and signing.key.pub: \(normalized)"
                    )
                }
            }
            guard seenExact.insert(normalized).inserted,
                  seenCaseFolded.insert(normalized.lowercased()).inserted else {
                throw ExtractionError.unsafePath(
                    "duplicate or case-colliding path: \(normalized)"
                )
            }

            if type == "-" {
                guard components.count > 1 else {
                    throw ExtractionError.unsafePath(rawName)
                }
                guard size <= limits.maximumSingleFileBytes else {
                    throw ExtractionError.singleFileSizeLimit(
                        path: normalized,
                        actual: size,
                        maximum: limits.maximumSingleFileBytes
                    )
                }
                let (nextTotal, overflow) = totalBytes.addingReportingOverflow(size)
                guard !overflow, nextTotal <= limits.maximumExpandedBytes else {
                    throw ExtractionError.expandedSizeLimit(
                        actual: overflow ? UInt64.max : nextTotal,
                        maximum: limits.maximumExpandedBytes
                    )
                }
                totalBytes = nextTotal
            } else if size != 0 {
                throw ExtractionError.malformedListing(
                    "directory \(normalized) declares non-zero size \(size)"
                )
            }

            entries.append(ArchiveEntry(
                archivePath: normalized,
                relativePath: normalized,
                kind: type == "-" ? .file : .directory,
                size: size
            ))
        }

        guard entries.contains(where: {
            $0.kind == .file && $0.relativePath == "\(pluginID)/manifest.json"
        }) else {
            throw ExtractionError.malformedListing("bundle has no \(pluginID)/manifest.json")
        }
        return entries
    }

    private static func dropTrailingEmptyLine(
        _ lines: [Substring]
    ) -> ArraySlice<Substring> {
        guard lines.last?.isEmpty == true else { return lines[...] }
        return lines.dropLast()
    }

    /// Plugin bundles have a deliberately conservative filename vocabulary.
    /// Restricting it avoids ambiguous bsdtar escaping (literal backslash-n vs
    /// newline), Unicode normalization collisions, hidden payloads, and option-
    /// shaped components. It still covers the documented four bundle files and
    /// future ASCII-named resource directories.
    static func normalizeArchivePath(_ rawPath: String) throws -> String? {
        guard !rawPath.isEmpty,
              !rawPath.contains("\r"),
              !rawPath.contains("\\") else {
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
        guard !components.isEmpty, components.count <= 32 else {
            throw ExtractionError.unsafePath(rawPath)
        }
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
                let safe = (value >= 48 && value <= 57)
                    || (value >= 65 && value <= 90)
                    || (value >= 97 && value <= 122)
                    || value == 45 || value == 46 || value == 95
                guard safe else { throw ExtractionError.unsafePath(rawPath) }
            }
        }
        return components.map(String.init).joined(separator: "/")
    }

    // MARK: - Controlled extraction

    private static func createPrivateDirectory(_ directory: URL) throws {
        let fm = FileManager.default
        var isDirectory: ObjCBool = false
        if fm.fileExists(atPath: directory.path, isDirectory: &isDirectory) {
            guard isDirectory.boolValue else {
                throw ExtractionError.filesystem(
                    "expected directory but found another type at \(directory.path)"
                )
            }
            return
        }
        do {
            try fm.createDirectory(
                at: directory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            try fm.setAttributes(
                [.posixPermissions: 0o700],
                ofItemAtPath: directory.path
            )
        } catch {
            throw ExtractionError.filesystem(
                "cannot create private directory \(directory.path): \(error)"
            )
        }
    }

    private static func extractRegularFile(
        archiveData: Data,
        entry: ArchiveEntry,
        destination: URL,
        timeoutSeconds: TimeInterval
    ) throws -> Data {
        let maximumOutputBytes = Int(min(entry.size, UInt64(Int.max)))
        guard let result = BoundedPrivilegedProcessRunner.run(
            executable: "/usr/bin/bsdtar",
            arguments: ["-xOf", "-", "--", entry.archivePath],
            environment: archiveToolEnvironment,
            workingDirectory: "/",
            timeout: max(timeoutSeconds, 0.1),
            maximumOutputBytes: maximumOutputBytes,
            mergeStandardErrorIntoOutput: false,
            standardInputData: archiveData
        ) else {
            throw ExtractionError.filesystem("could not launch trusted /usr/bin/bsdtar")
        }
        if result.timedOut {
            throw ExtractionError.extractionTimedOut
        }
        if result.outputLimitExceeded {
            throw ExtractionError.extractedSizeMismatch(
                path: entry.relativePath,
                expected: entry.size,
                actual: entry.size == UInt64.max ? UInt64.max : entry.size + 1
            )
        }
        guard result.terminationStatus == 0 else {
            throw ExtractionError.archiveToolFailed(
                operation: "extraction of \(entry.relativePath)",
                status: result.terminationStatus ?? -1
            )
        }
        guard UInt64(result.output.count) == entry.size else {
            throw ExtractionError.extractedSizeMismatch(
                path: entry.relativePath,
                expected: entry.size,
                actual: UInt64(result.output.count)
            )
        }

        let fd = destination.path.withCString {
            Darwin.open(
                $0,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                mode_t(S_IRUSR | S_IWUSR)
            )
        }
        guard fd >= 0 else {
            throw ExtractionError.filesystem(
                "cannot create \(destination.path): errno \(errno)"
            )
        }
        defer { Darwin.close(fd) }
        let wroteAll = result.output.withUnsafeBytes { bytes -> Bool in
            guard let base = bytes.baseAddress else { return result.output.isEmpty }
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(fd, base.advanced(by: offset), bytes.count - offset)
                if count < 0 {
                    if errno == EINTR { continue }
                    return false
                }
                guard count > 0 else { return false }
                offset += count
            }
            return true
        }
        guard wroteAll else {
            throw ExtractionError.filesystem(
                "write failed for \(entry.relativePath): errno \(errno)"
            )
        }
        return result.output
    }

    private static func validateExtractedTree(
        root: URL,
        entries: [ArchiveEntry],
        limits: Limits
    ) throws {
        var enumerationError: Swift.Error?
        guard let enumerator = FileManager.default.enumerator(
            at: root,
            includingPropertiesForKeys: nil,
            options: [],
            errorHandler: { _, error in
                enumerationError = error
                return false
            }
        ) else {
            throw ExtractionError.filesystem("cannot enumerate \(root.path)")
        }

        let expectedFiles = Dictionary(uniqueKeysWithValues: entries.compactMap { entry in
            entry.kind == .file ? (entry.relativePath, entry.size) : nil
        })
        let rootPath = root.standardizedFileURL.path
        let prefix = rootPath.hasSuffix("/") ? rootPath : rootPath + "/"
        var seenFiles = Set<String>()
        var count = 0
        var total: UInt64 = 0
        // `maximumEntries` was admitted with 32 slots of headroom before any
        // archive work. Keep the calculation explicit here so a future guard
        // cannot silently reintroduce an Int.max addition trap.
        let (treeEntryAllowance, allowanceOverflow) = limits.maximumEntries
            .addingReportingOverflow(32)
        guard !allowanceOverflow else {
            throw ExtractionError.filesystem("entry allowance overflow")
        }

        for case let item as URL in enumerator {
            count += 1
            guard count <= treeEntryAllowance else {
                throw ExtractionError.entryCountLimit(
                    actual: count,
                    maximum: treeEntryAllowance
                )
            }
            let path = item.standardizedFileURL.path
            guard path.hasPrefix(prefix) else {
                throw ExtractionError.unsafePath(item.path)
            }
            let relative = String(path.dropFirst(prefix.count))
            var info = stat()
            guard item.path.withCString({ Darwin.lstat($0, &info) }) == 0 else {
                throw ExtractionError.filesystem(
                    "lstat failed for \(relative): errno \(errno)"
                )
            }
            let type = info.st_mode & S_IFMT
            if type == S_IFDIR { continue }
            guard type == S_IFREG, info.st_nlink == 1 else {
                throw ExtractionError.unsupportedEntry(path: relative, type: "?")
            }
            let size = UInt64(max(info.st_size, 0))
            guard let expected = expectedFiles[relative] else {
                throw ExtractionError.unsafePath("unlisted extracted file: \(relative)")
            }
            guard expected == size else {
                throw ExtractionError.extractedSizeMismatch(
                    path: relative,
                    expected: expected,
                    actual: size
                )
            }
            seenFiles.insert(relative)
            let (next, overflow) = total.addingReportingOverflow(size)
            guard !overflow, next <= limits.maximumExpandedBytes else {
                throw ExtractionError.expandedSizeLimit(
                    actual: overflow ? UInt64.max : next,
                    maximum: limits.maximumExpandedBytes
                )
            }
            total = next
        }
        if let enumerationError {
            throw ExtractionError.filesystem("enumeration failed: \(enumerationError)")
        }
        guard seenFiles == Set(expectedFiles.keys) else {
            let missing = Set(expectedFiles.keys).subtracting(seenFiles).sorted()
            throw ExtractionError.filesystem(
                "listed files were not extracted: \(missing.joined(separator: ", "))"
            )
        }
    }

    // MARK: - Bounded archive-tool subprocesses

    private static func runArchiveToolCapture(
        operation: ToolOperation,
        arguments: [String],
        archiveData: Data,
        maximumOutputBytes: Int,
        timeoutSeconds: TimeInterval
    ) throws -> Data {
        // The shared runner drains a nonblocking pipe only while the direct
        // child is live, applies a hard SIGKILL deadline, and then closes its
        // read descriptor. A malicious archive that spawns/retains a stdout
        // descendant therefore cannot keep the CLI blocked waiting for EOF.
        guard let result = BoundedPrivilegedProcessRunner.run(
            executable: "/usr/bin/bsdtar",
            arguments: arguments,
            environment: archiveToolEnvironment,
            workingDirectory: "/",
            timeout: max(timeoutSeconds, 0.1),
            maximumOutputBytes: maximumOutputBytes,
            mergeStandardErrorIntoOutput: false,
            standardInputData: archiveData
        ) else {
            throw ExtractionError.filesystem("could not launch trusted /usr/bin/bsdtar")
        }
        if result.timedOut {
            throw ExtractionError.listingTimedOut
        }
        if result.outputLimitExceeded {
            throw ExtractionError.listingOutputLimit(maximum: maximumOutputBytes)
        }
        guard result.terminationStatus == 0 else {
            throw ExtractionError.archiveToolFailed(
                operation: operation.label,
                status: result.terminationStatus ?? -1
            )
        }
        return result.output
    }

    static let archiveToolEnvironment: [String: String] = {
        // This boundary consumes an attacker-supplied archive.  Do not pass
        // through DYLD_*, locale, tar/unzip option, or other caller-controlled
        // variables to the archive parser.  bsdtar needs none of the user's
        // shell environment; HOME/TMPDIR are pinned in case a future system
        // implementation consults them while parsing.
        [
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            "LANG": "C",
            "COPYFILE_DISABLE": "1",
            "HOME": "/var/empty",
            "TMPDIR": "/private/tmp",
        ]
    }()
}
