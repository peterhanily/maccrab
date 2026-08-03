// BundleExportWorkspace.swift
//
// A bundle export is a security boundary: the destination commonly lives in
// an attacker-writable user directory, and Foundation path writes follow a
// root symlink raced in after a fileExists check. Build under a random private
// staging directory pinned by descriptors, then publish the complete signed
// tree with one exclusive rename. A requested `.maccrabtrace` name is never a
// half-built bundle.

import Darwin
import CryptoKit
import Foundation

final class BundleExportWorkspace: @unchecked Sendable {
    struct Artifact: Sendable, Equatable {
        let path: String
        let data: Data
    }

    enum WorkspaceError: Error, LocalizedError {
        case destinationExists(URL)
        case committedBundle(URL, String)
        case unsafePath(String)
        case io(operation: String, path: String, code: Int32)
        case treeChanged(String)
        case sizeLimit(path: String, actual: UInt64, maximum: UInt64)

        var errorDescription: String? {
            switch self {
            case .destinationExists(let url):
                return "bundle destination already exists: \(url.path)"
            case .committedBundle(let url, let detail):
                return "complete bundle was atomically committed at \(url.path), but durability/postflight failed: \(detail)"
            case .unsafePath(let path):
                return "unsafe bundle export path: \(path)"
            case .io(let operation, let path, let code):
                return "bundle export \(operation) failed for \(path): errno \(code)"
            case .treeChanged(let detail):
                return "bundle export workspace changed during export: \(detail)"
            case .sizeLimit(let path, let actual, let maximum):
                return "bundle artifact \(path) is \(actual) bytes; limit is \(maximum) bytes"
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

    private struct FileRecord {
        let identity: Identity
        let size: off_t
        let modifiedSeconds: Int
        let modifiedNanoseconds: Int
        let changedSeconds: Int
        let changedNanoseconds: Int
        let sha256: Data

        init(metadata: stat, data: Data) {
            identity = Identity(metadata)
            size = metadata.st_size
            modifiedSeconds = metadata.st_mtimespec.tv_sec
            modifiedNanoseconds = metadata.st_mtimespec.tv_nsec
            changedSeconds = metadata.st_ctimespec.tv_sec
            changedNanoseconds = metadata.st_ctimespec.tv_nsec
            sha256 = Data(SHA256.hash(data: data))
        }

        func matchesMetadata(_ metadata: stat) -> Bool {
            identity.matches(metadata)
                && size == metadata.st_size
                && modifiedSeconds == metadata.st_mtimespec.tv_sec
                && modifiedNanoseconds == metadata.st_mtimespec.tv_nsec
                && changedSeconds == metadata.st_ctimespec.tv_sec
                && changedNanoseconds == metadata.st_ctimespec.tv_nsec
        }
    }

    struct TestHooks {
        var beforeReplacementPostflight: ((URL, String, String) -> Void)?
        var beforeFinalPublicationSnapshot: ((URL) -> Void)?
        var afterFinalRename: ((URL) -> Void)?

        init(
            beforeReplacementPostflight: ((URL, String, String) -> Void)? = nil,
            beforeFinalPublicationSnapshot: ((URL) -> Void)? = nil,
            afterFinalRename: ((URL) -> Void)? = nil
        ) {
            self.beforeReplacementPostflight = beforeReplacementPostflight
            self.beforeFinalPublicationSnapshot = beforeFinalPublicationSnapshot
            self.afterFinalRename = afterFinalRename
        }
    }

    private enum PublicationState {
        case staging
        case committed
        case published
    }

    let requestedURL: URL

    private let normalizedParentPath: String
    private let finalLeaf: String
    private let stagingLeaf: String
    private let parentDescriptor: Int32
    private let rootDescriptor: Int32
    private let parentIdentity: Identity
    private let rootIdentity: Identity
    private let testHooks: TestHooks
    private var ownedDirectories: [String: Identity]
    private var ownedFiles: [String: FileRecord] = [:]
    private var publicationState: PublicationState = .staging

    private init(
        requestedURL: URL,
        normalizedParentPath: String,
        finalLeaf: String,
        stagingLeaf: String,
        parentDescriptor: Int32,
        rootDescriptor: Int32,
        parentIdentity: Identity,
        rootIdentity: Identity,
        testHooks: TestHooks
    ) {
        self.requestedURL = requestedURL
        self.normalizedParentPath = normalizedParentPath
        self.finalLeaf = finalLeaf
        self.stagingLeaf = stagingLeaf
        self.parentDescriptor = parentDescriptor
        self.rootDescriptor = rootDescriptor
        self.parentIdentity = parentIdentity
        self.rootIdentity = rootIdentity
        self.testHooks = testHooks
        self.ownedDirectories = ["": rootIdentity]
    }

    deinit {
        Darwin.close(rootDescriptor)
        Darwin.close(parentDescriptor)
    }

    static func create(at requestedURL: URL) throws -> BundleExportWorkspace {
        try create(at: requestedURL, testHooks: TestHooks())
    }

    static func create(
        at requestedURL: URL,
        testHooks: TestHooks
    ) throws -> BundleExportWorkspace {
        let normalized = try normalizeAbsolutePath(requestedURL.path)
        let components = normalized.dropFirst().split(
            separator: "/",
            omittingEmptySubsequences: false
        ).map(String.init)
        guard let finalLeaf = components.last,
              !finalLeaf.isEmpty,
              finalLeaf != ".",
              finalLeaf != "..",
              finalLeaf.utf8.count <= 255 else {
            throw WorkspaceError.unsafePath(requestedURL.path)
        }
        let parentComponents = components.dropLast()
        let parentPath = parentComponents.isEmpty
            ? "/"
            : "/" + parentComponents.joined(separator: "/")
        let parentDescriptor = try openDirectoryNoFollow(at: parentPath)
        var keepParentOpen = false
        defer {
            if !keepParentOpen { Darwin.close(parentDescriptor) }
        }

        var parentMetadata = stat()
        guard Darwin.fstat(parentDescriptor, &parentMetadata) == 0,
              (parentMetadata.st_mode & S_IFMT) == S_IFDIR else {
            throw WorkspaceError.io(
                operation: "stat destination parent",
                path: parentPath,
                code: errno
            )
        }

        var destinationMetadata = stat()
        let destinationStatus = finalLeaf.withCString {
            Darwin.fstatat(parentDescriptor, $0, &destinationMetadata, AT_SYMLINK_NOFOLLOW)
        }
        if destinationStatus == 0 {
            throw WorkspaceError.destinationExists(requestedURL)
        }
        guard errno == ENOENT else {
            throw WorkspaceError.io(
                operation: "inspect destination",
                path: requestedURL.path,
                code: errno
            )
        }

        var stagingLeaf: String?
        for _ in 0..<16 {
            let candidate = ".partial-maccrab-export-\(UUID().uuidString)"
            let status = candidate.withCString {
                Darwin.mkdirat(parentDescriptor, $0, mode_t(0o700))
            }
            if status == 0 {
                stagingLeaf = candidate
                break
            }
            guard errno == EEXIST else {
                throw WorkspaceError.io(
                    operation: "create staging directory",
                    path: parentPath + "/" + candidate,
                    code: errno
                )
            }
        }
        guard let stagingLeaf else {
            throw WorkspaceError.io(
                operation: "create unique staging directory",
                path: parentPath,
                code: EEXIST
            )
        }
        var keepStagingDirectory = false
        defer {
            if !keepStagingDirectory {
                stagingLeaf.withCString {
                    _ = Darwin.unlinkat(parentDescriptor, $0, AT_REMOVEDIR)
                }
            }
        }

        let rootDescriptor = stagingLeaf.withCString {
            Darwin.openat(
                parentDescriptor,
                $0,
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
            )
        }
        guard rootDescriptor >= 0 else {
            let savedErrno = errno
            throw WorkspaceError.io(
                operation: "open staging directory",
                path: parentPath + "/" + stagingLeaf,
                code: savedErrno
            )
        }
        var keepRootOpen = false
        defer {
            if !keepRootOpen { Darwin.close(rootDescriptor) }
        }
        guard Darwin.fchmod(rootDescriptor, mode_t(0o700)) == 0 else {
            throw WorkspaceError.io(
                operation: "set private staging permissions",
                path: parentPath + "/" + stagingLeaf,
                code: errno
            )
        }
        guard Darwin.fsync(rootDescriptor) == 0 else {
            throw WorkspaceError.io(
                operation: "sync private staging permissions",
                path: parentPath + "/" + stagingLeaf,
                code: errno
            )
        }

        var rootMetadata = stat()
        guard Darwin.fstat(rootDescriptor, &rootMetadata) == 0,
              (rootMetadata.st_mode & S_IFMT) == S_IFDIR,
              rootMetadata.st_uid == geteuid(),
              Self.hasExactMode(rootMetadata, mode: 0o700),
              Self.hasNoExtendedACL(rootDescriptor) else {
            let savedErrno = errno
            throw WorkspaceError.io(
                operation: "validate staging directory",
                path: parentPath + "/" + stagingLeaf,
                code: savedErrno == 0 ? EPERM : savedErrno
            )
        }
        guard Darwin.fsync(parentDescriptor) == 0 else {
            throw WorkspaceError.io(
                operation: "sync staging parent",
                path: parentPath,
                code: errno
            )
        }

        keepParentOpen = true
        keepRootOpen = true
        keepStagingDirectory = true
        return BundleExportWorkspace(
            requestedURL: requestedURL,
            normalizedParentPath: parentPath,
            finalLeaf: finalLeaf,
            stagingLeaf: stagingLeaf,
            parentDescriptor: parentDescriptor,
            rootDescriptor: rootDescriptor,
            parentIdentity: Identity(parentMetadata),
            rootIdentity: Identity(rootMetadata),
            testHooks: testHooks
        )
    }

    var diagnosticPartialURLIfStillOwned: URL? {
        guard case .staging = publicationState,
              textualParentStillMatches(),
              stagingEntryStillMatches() else {
            return nil
        }
        return stagingDisplayURL
    }

    var committedOrPublishedURLIfStillOwned: URL? {
        switch publicationState {
        case .staging:
            return nil
        case .committed, .published:
            guard textualParentStillMatches(), finalEntryStillMatches() else {
                return nil
            }
            return requestedURL
        }
    }

    private var stagingDisplayURL: URL {
        URL(fileURLWithPath: normalizedParentPath, isDirectory: true)
            .appendingPathComponent(stagingLeaf, isDirectory: true)
    }

    func createDirectory(_ relativePath: String) throws {
        let components = try Self.relativeComponents(relativePath)
        var descriptor = try Self.duplicateDescriptor(rootDescriptor, path: relativePath)
        defer { Darwin.close(descriptor) }
        _ = try validateOwnedDirectoryDescriptor(
            descriptor,
            path: "bundle root",
            expected: rootIdentity
        )
        var traversed = ""

        for component in components {
            let nextPath = traversed.isEmpty ? component : traversed + "/" + component
            let createdNow: Bool
            if ownedDirectories[nextPath] == nil {
                let status = component.withCString {
                    Darwin.mkdirat(descriptor, $0, mode_t(0o700))
                }
                guard status == 0 else {
                    throw WorkspaceError.io(
                        operation: "create bundle directory",
                        path: nextPath,
                        code: errno
                    )
                }
                createdNow = true
            } else {
                createdNow = false
            }

            let nextDescriptor = component.withCString {
                Darwin.openat(
                    descriptor,
                    $0,
                    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
                )
            }
            guard nextDescriptor >= 0 else {
                throw WorkspaceError.io(
                    operation: "open bundle directory",
                    path: nextPath,
                    code: errno
                )
            }
            if createdNow,
               Darwin.fchmod(nextDescriptor, mode_t(0o700)) != 0 {
                let savedErrno = errno
                Darwin.close(nextDescriptor)
                throw WorkspaceError.io(
                    operation: "set private bundle directory permissions",
                    path: nextPath,
                    code: savedErrno
                )
            }
            if createdNow,
               Darwin.fsync(nextDescriptor) != 0 {
                let savedErrno = errno
                Darwin.close(nextDescriptor)
                throw WorkspaceError.io(
                    operation: "sync private bundle directory permissions",
                    path: nextPath,
                    code: savedErrno
                )
            }
            var metadata = stat()
            guard Darwin.fstat(nextDescriptor, &metadata) == 0,
                  (metadata.st_mode & S_IFMT) == S_IFDIR,
                  metadata.st_uid == geteuid(),
                  Self.hasExactMode(metadata, mode: 0o700),
                  Self.hasNoExtendedACL(nextDescriptor) else {
                let savedErrno = errno
                Darwin.close(nextDescriptor)
                throw WorkspaceError.treeChanged(
                    "directory \(nextPath) is not an owned real directory (errno \(savedErrno))"
                )
            }
            if let expected = ownedDirectories[nextPath] {
                guard expected.matches(metadata) else {
                    Darwin.close(nextDescriptor)
                    throw WorkspaceError.treeChanged("directory \(nextPath) was replaced")
                }
            } else {
                ownedDirectories[nextPath] = Identity(metadata)
            }
            if createdNow,
               Darwin.fsync(descriptor) != 0 {
                let savedErrno = errno
                Darwin.close(nextDescriptor)
                throw WorkspaceError.io(
                    operation: "sync bundle directory parent",
                    path: nextPath,
                    code: savedErrno
                )
            }
            Darwin.close(descriptor)
            descriptor = nextDescriptor
            traversed = nextPath
        }
    }

    func writeNew(_ data: Data, to relativePath: String) throws {
        let (parent, leaf) = try openArtifactParent(relativePath)
        defer { Darwin.close(parent) }
        let descriptor = leaf.withCString {
            Darwin.openat(
                parent,
                $0,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                mode_t(0o600)
            )
        }
        guard descriptor >= 0 else {
            throw WorkspaceError.io(
                operation: "create artifact",
                path: relativePath,
                code: errno
            )
        }

        var descriptorOpen = true
        var artifactExists = true
        defer {
            if descriptorOpen { Darwin.close(descriptor) }
            if artifactExists {
                leaf.withCString { _ = Darwin.unlinkat(parent, $0, 0) }
            }
        }
        guard Darwin.fchmod(descriptor, mode_t(0o600)) == 0 else {
            throw WorkspaceError.io(
                operation: "set private artifact permissions",
                path: relativePath,
                code: errno
            )
        }
        try Self.validateEmptyPrivateArtifact(
            parent: parent,
            leaf: leaf,
            descriptor: descriptor,
            path: relativePath
        )
        try Self.writeAll(data, descriptor: descriptor, path: relativePath)
        guard Darwin.fsync(descriptor) == 0 else {
            throw WorkspaceError.io(operation: "sync artifact", path: relativePath, code: errno)
        }
        var metadata = stat()
        guard Darwin.fstat(descriptor, &metadata) == 0,
              (metadata.st_mode & S_IFMT) == S_IFREG,
              metadata.st_nlink == 1,
              metadata.st_uid == geteuid(),
              Self.hasExactMode(metadata, mode: 0o600),
              Self.hasNoExtendedACL(descriptor),
              metadata.st_size == off_t(data.count) else {
            throw WorkspaceError.treeChanged("new artifact \(relativePath) failed descriptor validation")
        }
        let record = FileRecord(metadata: metadata, data: data)
        guard Darwin.close(descriptor) == 0 else {
            descriptorOpen = false
            throw WorkspaceError.io(operation: "close artifact", path: relativePath, code: errno)
        }
        descriptorOpen = false
        try verifyFileEntry(parent: parent, leaf: leaf, path: relativePath, expected: record)
        guard Darwin.fsync(parent) == 0 else {
            throw WorkspaceError.io(operation: "sync artifact parent", path: relativePath, code: errno)
        }
        ownedFiles[relativePath] = record
        artifactExists = false
    }

    func replaceOwned(_ data: Data, at relativePath: String) throws {
        guard let expected = ownedFiles[relativePath] else {
            throw WorkspaceError.treeChanged("attempted to replace unowned artifact \(relativePath)")
        }
        let (parent, leaf) = try openArtifactParent(relativePath)
        defer { Darwin.close(parent) }
        try verifyFileEntry(parent: parent, leaf: leaf, path: relativePath, expected: expected)

        let temporaryLeaf = ".partial-artifact-\(UUID().uuidString)"
        let descriptor = temporaryLeaf.withCString {
            Darwin.openat(
                parent,
                $0,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                mode_t(0o600)
            )
        }
        guard descriptor >= 0 else {
            throw WorkspaceError.io(operation: "create replacement artifact", path: relativePath, code: errno)
        }
        var descriptorOpen = true
        var temporaryExists = true
        defer {
            if descriptorOpen { Darwin.close(descriptor) }
            if temporaryExists {
                temporaryLeaf.withCString { _ = Darwin.unlinkat(parent, $0, 0) }
            }
        }

        guard Darwin.fchmod(descriptor, mode_t(0o600)) == 0 else {
            throw WorkspaceError.io(
                operation: "set private replacement permissions",
                path: relativePath,
                code: errno
            )
        }
        try Self.validateEmptyPrivateArtifact(
            parent: parent,
            leaf: temporaryLeaf,
            descriptor: descriptor,
            path: relativePath + " (replacement)"
        )
        try Self.writeAll(data, descriptor: descriptor, path: relativePath)
        guard Darwin.fsync(descriptor) == 0 else {
            throw WorkspaceError.io(operation: "sync replacement artifact", path: relativePath, code: errno)
        }
        var replacementMetadata = stat()
        guard Darwin.fstat(descriptor, &replacementMetadata) == 0,
              (replacementMetadata.st_mode & S_IFMT) == S_IFREG,
              replacementMetadata.st_nlink == 1,
              replacementMetadata.st_uid == geteuid(),
              Self.hasExactMode(replacementMetadata, mode: 0o600),
              Self.hasNoExtendedACL(descriptor),
              replacementMetadata.st_size == off_t(data.count) else {
            throw WorkspaceError.treeChanged("replacement artifact \(relativePath) failed descriptor validation")
        }
        guard Darwin.close(descriptor) == 0 else {
            descriptorOpen = false
            throw WorkspaceError.io(operation: "close replacement artifact", path: relativePath, code: errno)
        }
        descriptorOpen = false

        // Re-check both the destination and the temporary NAME immediately
        // before publication. Validating only the temp descriptor leaves a
        // same-uid name-swap window between close and renameat.
        testHooks.beforeReplacementPostflight?(
            stagingDisplayURL,
            relativePath,
            temporaryLeaf
        )
        try verifyFileEntry(parent: parent, leaf: leaf, path: relativePath, expected: expected)
        let replacementRecord = FileRecord(metadata: replacementMetadata, data: data)
        try verifyFileEntry(
            parent: parent,
            leaf: temporaryLeaf,
            path: relativePath + " (replacement)",
            expected: replacementRecord
        )
        let renameStatus = temporaryLeaf.withCString { temporaryName in
            leaf.withCString { destinationName in
                Darwin.renameat(parent, temporaryName, parent, destinationName)
            }
        }
        guard renameStatus == 0 else {
            throw WorkspaceError.io(operation: "publish replacement artifact", path: relativePath, code: errno)
        }
        temporaryExists = false
        var installedMetadata = stat()
        let installedStatus = leaf.withCString {
            Darwin.fstatat(parent, $0, &installedMetadata, AT_SYMLINK_NOFOLLOW)
        }
        guard installedStatus == 0,
              (installedMetadata.st_mode & S_IFMT) == S_IFREG,
              installedMetadata.st_nlink == 1,
              replacementRecord.identity.matches(installedMetadata),
              installedMetadata.st_size == replacementRecord.size,
              installedMetadata.st_mtimespec.tv_sec == replacementRecord.modifiedSeconds,
              installedMetadata.st_mtimespec.tv_nsec == replacementRecord.modifiedNanoseconds,
              Self.hasExactMode(installedMetadata, mode: 0o600) else {
            throw WorkspaceError.treeChanged("replacement artifact \(relativePath) changed during rename")
        }
        let installedDescriptor = leaf.withCString {
            Darwin.openat(
                parent,
                $0,
                O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW
            )
        }
        guard installedDescriptor >= 0 else {
            throw WorkspaceError.io(
                operation: "open installed replacement artifact",
                path: relativePath,
                code: errno
            )
        }
        defer { Darwin.close(installedDescriptor) }
        var installedDescriptorMetadata = stat()
        guard Darwin.fstat(installedDescriptor, &installedDescriptorMetadata) == 0,
              (installedDescriptorMetadata.st_mode & S_IFMT) == S_IFREG,
              installedDescriptorMetadata.st_nlink == 1,
              replacementRecord.identity.matches(installedDescriptorMetadata),
              installedDescriptorMetadata.st_size == replacementRecord.size,
              installedDescriptorMetadata.st_mtimespec.tv_sec == replacementRecord.modifiedSeconds,
              installedDescriptorMetadata.st_mtimespec.tv_nsec == replacementRecord.modifiedNanoseconds,
              Self.hasExactMode(installedDescriptorMetadata, mode: 0o600),
              Self.hasNoExtendedACL(installedDescriptor),
              Identity(installedMetadata).matches(installedDescriptorMetadata) else {
            throw WorkspaceError.treeChanged(
                "replacement artifact \(relativePath) failed installed descriptor validation"
            )
        }
        ownedFiles[relativePath] = FileRecord(
            metadata: installedDescriptorMetadata,
            data: data
        )
        guard Darwin.fsync(parent) == 0 else {
            throw WorkspaceError.io(operation: "sync replacement parent", path: relativePath, code: errno)
        }
    }

    func snapshotArtifacts(excludingRootIntegrity: Bool) throws -> [Artifact] {
        try validateTree()
        let limits = SafeTraceArchiveExtractor.Limits.default
        var total: UInt64 = 0
        var artifacts: [Artifact] = []
        for path in ownedFiles.keys.sorted() {
            if excludingRootIntegrity,
               BundleArtifactPathPolicy.isRootIntegrityArtifact(relativePath: path) {
                continue
            }
            let data = try readOwned(path, maximumBytes: limits.maxSingleFileBytes)
            let addition = total.addingReportingOverflow(UInt64(data.count))
            guard !addition.overflow,
                  addition.partialValue <= limits.maxTotalFileBytes else {
                throw WorkspaceError.sizeLimit(
                    path: path,
                    actual: addition.overflow ? UInt64.max : addition.partialValue,
                    maximum: limits.maxTotalFileBytes
                )
            }
            total = addition.partialValue
            artifacts.append(Artifact(path: path, data: data))
        }
        return artifacts
    }

    func publish() throws -> URL {
        switch publicationState {
        case .published:
            return requestedURL
        case .committed:
            throw WorkspaceError.committedBundle(
                requestedURL,
                "a previous publication attempt committed the final name"
            )
        case .staging:
            break
        }
        testHooks.beforeFinalPublicationSnapshot?(stagingDisplayURL)
        // Re-read and content-hash EVERY owned file, including integrity
        // metadata, immediately before the one-way publication. Tree metadata
        // alone cannot detect same-inode writes by another process.
        _ = try snapshotArtifacts(excludingRootIntegrity: false)
        guard textualParentStillMatches() else {
            throw WorkspaceError.treeChanged("destination parent path was replaced")
        }
        guard stagingEntryStillMatches() else {
            throw WorkspaceError.treeChanged("staging directory name was replaced")
        }

        let status = stagingLeaf.withCString { stagingName in
            finalLeaf.withCString { destinationName in
                Darwin.renameatx_np(
                    parentDescriptor,
                    stagingName,
                    parentDescriptor,
                    destinationName,
                    UInt32(RENAME_EXCL)
                )
            }
        }
        guard status == 0 else {
            if errno == EEXIST {
                throw WorkspaceError.destinationExists(requestedURL)
            }
            throw WorkspaceError.io(
                operation: "publish complete bundle",
                path: requestedURL.path,
                code: errno
            )
        }
        publicationState = .committed
        testHooks.afterFinalRename?(requestedURL)

        do {
            _ = try snapshotArtifacts(excludingRootIntegrity: false)
        } catch {
            throw WorkspaceError.committedBundle(
                requestedURL,
                "post-rename content/tree verification failed: \(error.localizedDescription)"
            )
        }

        guard Darwin.fsync(parentDescriptor) == 0 else {
            throw WorkspaceError.committedBundle(
                requestedURL,
                "parent fsync failed with errno \(errno)"
            )
        }
        guard textualParentStillMatches(), finalEntryStillMatches() else {
            throw WorkspaceError.committedBundle(
                requestedURL,
                "final path/identity postflight failed"
            )
        }
        publicationState = .published
        return requestedURL
    }

    // MARK: - Tree validation and reads

    private func validateTree() throws {
        _ = try validateOwnedDirectoryDescriptor(
            rootDescriptor,
            path: "bundle root",
            expected: rootIdentity
        )
        var observedDirectories: Set<String> = [""]
        var observedFiles: Set<String> = []
        var entryCount = 0
        try enumerate(
            descriptor: rootDescriptor,
            prefix: "",
            observedDirectories: &observedDirectories,
            observedFiles: &observedFiles,
            entryCount: &entryCount
        )
        guard observedDirectories == Set(ownedDirectories.keys) else {
            throw WorkspaceError.treeChanged(
                "bundle directory set differs from the exporter-owned skeleton "
                    + "(observed=\(observedDirectories.sorted()), expected=\(ownedDirectories.keys.sorted()))"
            )
        }
        guard observedFiles == Set(ownedFiles.keys) else {
            throw WorkspaceError.treeChanged(
                "bundle artifact set contains a missing or unowned entry "
                    + "(observed=\(observedFiles.sorted()), expected=\(ownedFiles.keys.sorted()))"
            )
        }
    }

    private func enumerate(
        descriptor: Int32,
        prefix: String,
        observedDirectories: inout Set<String>,
        observedFiles: inout Set<String>,
        entryCount: inout Int
    ) throws {
        let maximumEntries = SafeTraceArchiveExtractor.Limits.default.maxEntries
        let remainingEntryBudget = max(0, maximumEntries - entryCount)
        let names = try Self.directoryEntryNames(
            descriptor: descriptor,
            path: prefix,
            remainingEntryBudget: remainingEntryBudget,
            maximumEntries: maximumEntries
        )
        for name in names {
            let path = prefix.isEmpty ? name : prefix + "/" + name
            entryCount += 1
            guard entryCount <= maximumEntries else {
                throw WorkspaceError.treeChanged("bundle export exceeded \(maximumEntries) entries")
            }
            var metadata = stat()
            let status = name.withCString {
                Darwin.fstatat(descriptor, $0, &metadata, AT_SYMLINK_NOFOLLOW)
            }
            guard status == 0 else {
                throw WorkspaceError.io(operation: "stat workspace entry", path: path, code: errno)
            }
            switch metadata.st_mode & S_IFMT {
            case S_IFDIR:
                guard let expected = ownedDirectories[path],
                      expected.matches(metadata),
                      Self.hasExactMode(metadata, mode: 0o700) else {
                    throw WorkspaceError.treeChanged("unowned or replaced directory \(path)")
                }
                let child = name.withCString {
                    Darwin.openat(
                        descriptor,
                        $0,
                        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
                    )
                }
                guard child >= 0 else {
                    throw WorkspaceError.io(operation: "open workspace directory", path: path, code: errno)
                }
                observedDirectories.insert(path)
                do {
                    _ = try validateOwnedDirectoryDescriptor(
                        child,
                        path: path,
                        expected: expected
                    )
                    try enumerate(
                        descriptor: child,
                        prefix: path,
                        observedDirectories: &observedDirectories,
                        observedFiles: &observedFiles,
                        entryCount: &entryCount
                    )
                    Darwin.close(child)
                } catch {
                    Darwin.close(child)
                    throw error
                }

            case S_IFREG:
                guard metadata.st_nlink == 1,
                      let expected = ownedFiles[path],
                      expected.matchesMetadata(metadata),
                      Self.hasExactMode(metadata, mode: 0o600) else {
                    throw WorkspaceError.treeChanged("unowned, hard-linked, or replaced artifact \(path)")
                }
                try verifyFileEntry(
                    parent: descriptor,
                    leaf: name,
                    path: path,
                    expected: expected
                )
                observedFiles.insert(path)

            default:
                throw WorkspaceError.treeChanged("unsupported filesystem entry at \(path)")
            }
        }
    }

    private func readOwned(_ relativePath: String, maximumBytes: UInt64) throws -> Data {
        guard let expected = ownedFiles[relativePath] else {
            throw WorkspaceError.treeChanged("attempted to read unowned artifact \(relativePath)")
        }
        let (parent, leaf) = try openArtifactParent(relativePath)
        defer { Darwin.close(parent) }
        let descriptor = leaf.withCString {
            Darwin.openat(
                parent,
                $0,
                O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW
            )
        }
        guard descriptor >= 0 else {
            throw WorkspaceError.io(operation: "open artifact", path: relativePath, code: errno)
        }
        defer { Darwin.close(descriptor) }

        var before = stat()
        guard Darwin.fstat(descriptor, &before) == 0,
              (before.st_mode & S_IFMT) == S_IFREG,
              before.st_nlink == 1,
              expected.matchesMetadata(before),
              Self.hasExactMode(before, mode: 0o600),
              Self.hasNoExtendedACL(descriptor),
              before.st_size >= 0 else {
            throw WorkspaceError.treeChanged("artifact \(relativePath) was replaced before read")
        }
        let size = UInt64(before.st_size)
        guard size <= maximumBytes, size <= UInt64(Int.max) else {
            throw WorkspaceError.sizeLimit(path: relativePath, actual: size, maximum: maximumBytes)
        }

        var output = Data(count: Int(size))
        let readCount = output.withUnsafeMutableBytes { bytes -> Int in
            guard size > 0, let base = bytes.baseAddress else { return 0 }
            var offset = 0
            while offset < Int(size) {
                let count = Darwin.read(descriptor, base.advanced(by: offset), Int(size) - offset)
                if count < 0 {
                    if errno == EINTR { continue }
                    return -1
                }
                if count == 0 { break }
                offset += count
            }
            return offset
        }
        guard readCount == Int(size) else {
            throw WorkspaceError.treeChanged("artifact \(relativePath) changed size during read")
        }
        var excess: UInt8 = 0
        guard Darwin.read(descriptor, &excess, 1) == 0 else {
            throw WorkspaceError.treeChanged("artifact \(relativePath) grew during read")
        }
        var after = stat()
        guard Darwin.fstat(descriptor, &after) == 0,
              (after.st_mode & S_IFMT) == S_IFREG,
              after.st_nlink == 1,
              expected.matchesMetadata(after),
              Self.hasExactMode(after, mode: 0o600),
              Self.hasNoExtendedACL(descriptor),
              before.st_nlink == after.st_nlink,
              before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
              before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec else {
            throw WorkspaceError.treeChanged("artifact \(relativePath) changed during read")
        }
        guard Data(SHA256.hash(data: output)) == expected.sha256 else {
            throw WorkspaceError.treeChanged("artifact \(relativePath) content hash changed")
        }
        return output
    }

    // MARK: - Descriptor helpers

    private func openArtifactParent(_ relativePath: String) throws -> (Int32, String) {
        let components = try Self.relativeComponents(relativePath)
        guard let leaf = components.last else {
            throw WorkspaceError.unsafePath(relativePath)
        }
        let parentPath = components.dropLast().joined(separator: "/")
        return (try openOwnedDirectory(parentPath), leaf)
    }

    private func openOwnedDirectory(_ relativePath: String) throws -> Int32 {
        if relativePath.isEmpty {
            let descriptor = try Self.duplicateDescriptor(rootDescriptor, path: relativePath)
            do {
                _ = try validateOwnedDirectoryDescriptor(
                    descriptor,
                    path: "bundle root",
                    expected: rootIdentity
                )
                return descriptor
            } catch {
                Darwin.close(descriptor)
                throw error
            }
        }
        let components = try Self.relativeComponents(relativePath)
        var descriptor = try Self.duplicateDescriptor(rootDescriptor, path: relativePath)
        var traversed = ""
        do {
            _ = try validateOwnedDirectoryDescriptor(
                descriptor,
                path: "bundle root",
                expected: rootIdentity
            )
            for component in components {
                let path = traversed.isEmpty ? component : traversed + "/" + component
                guard let expected = ownedDirectories[path] else {
                    throw WorkspaceError.treeChanged("directory \(path) was not created by this exporter")
                }
                let next = component.withCString {
                    Darwin.openat(
                        descriptor,
                        $0,
                        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
                    )
                }
                guard next >= 0 else {
                    throw WorkspaceError.io(operation: "open artifact parent", path: path, code: errno)
                }
                do {
                    _ = try validateOwnedDirectoryDescriptor(
                        next,
                        path: path,
                        expected: expected
                    )
                } catch {
                    Darwin.close(next)
                    throw error
                }
                Darwin.close(descriptor)
                descriptor = next
                traversed = path
            }
            return descriptor
        } catch {
            Darwin.close(descriptor)
            throw error
        }
    }

    private func verifyFileEntry(
        parent: Int32,
        leaf: String,
        path: String,
        expected: FileRecord
    ) throws {
        var namedMetadata = stat()
        let namedStatus = leaf.withCString {
            Darwin.fstatat(parent, $0, &namedMetadata, AT_SYMLINK_NOFOLLOW)
        }
        guard namedStatus == 0,
              (namedMetadata.st_mode & S_IFMT) == S_IFREG,
              namedMetadata.st_nlink == 1,
              expected.matchesMetadata(namedMetadata),
              Self.hasExactMode(namedMetadata, mode: 0o600) else {
            throw WorkspaceError.treeChanged("artifact \(path) was replaced")
        }
        let descriptor = leaf.withCString {
            Darwin.openat(
                parent,
                $0,
                O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW
            )
        }
        guard descriptor >= 0 else {
            throw WorkspaceError.io(operation: "open artifact for validation", path: path, code: errno)
        }
        defer { Darwin.close(descriptor) }
        var descriptorMetadata = stat()
        guard Darwin.fstat(descriptor, &descriptorMetadata) == 0,
              (descriptorMetadata.st_mode & S_IFMT) == S_IFREG,
              descriptorMetadata.st_nlink == 1,
              expected.matchesMetadata(descriptorMetadata),
              Self.hasExactMode(descriptorMetadata, mode: 0o600),
              Self.hasNoExtendedACL(descriptor),
              Identity(namedMetadata).matches(descriptorMetadata) else {
            throw WorkspaceError.treeChanged("artifact \(path) failed descriptor validation")
        }
    }

    private func validateOwnedDirectoryDescriptor(
        _ descriptor: Int32,
        path: String,
        expected: Identity
    ) throws -> stat {
        var metadata = stat()
        guard Darwin.fstat(descriptor, &metadata) == 0,
              (metadata.st_mode & S_IFMT) == S_IFDIR,
              expected.matches(metadata),
              Self.hasExactMode(metadata, mode: 0o700),
              Self.hasNoExtendedACL(descriptor) else {
            throw WorkspaceError.treeChanged(
                "directory \(path) changed identity, permissions, or extended ACL"
            )
        }
        return metadata
    }

    private func textualParentStillMatches() -> Bool {
        guard let descriptor = try? Self.openDirectoryNoFollow(at: normalizedParentPath) else {
            return false
        }
        defer { Darwin.close(descriptor) }
        var metadata = stat()
        return Darwin.fstat(descriptor, &metadata) == 0 && parentIdentity.matches(metadata)
    }

    private func stagingEntryStillMatches() -> Bool {
        entryStillMatches(leaf: stagingLeaf)
    }

    private func finalEntryStillMatches() -> Bool {
        entryStillMatches(leaf: finalLeaf)
    }

    private func entryStillMatches(leaf: String) -> Bool {
        var descriptorMetadata = stat()
        guard Darwin.fstat(rootDescriptor, &descriptorMetadata) == 0,
              (descriptorMetadata.st_mode & S_IFMT) == S_IFDIR,
              rootIdentity.matches(descriptorMetadata),
              Self.hasExactMode(descriptorMetadata, mode: 0o700),
              Self.hasNoExtendedACL(rootDescriptor) else {
            return false
        }
        var metadata = stat()
        let status = leaf.withCString {
            Darwin.fstatat(parentDescriptor, $0, &metadata, AT_SYMLINK_NOFOLLOW)
        }
        return status == 0
            && (metadata.st_mode & S_IFMT) == S_IFDIR
            && rootIdentity.matches(metadata)
            && Self.hasExactMode(metadata, mode: 0o700)
    }

    private static func directoryEntryNames(
        descriptor: Int32,
        path: String,
        remainingEntryBudget: Int,
        maximumEntries: Int
    ) throws -> [String] {
        // dup/fcntl shares the directory file-description offset. Because this
        // workspace validates more than once (pre-sign and pre/post-publish), a
        // second fdopendir over a dup would start at EOF and falsely observe an
        // empty tree. openat(".") pins the same inode with an independent
        // directory offset.
        let duplicate = Darwin.openat(
            descriptor,
            ".",
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
        )
        guard duplicate >= 0 else {
            throw WorkspaceError.io(operation: "duplicate workspace directory", path: path, code: errno)
        }
        guard let stream = Darwin.fdopendir(duplicate) else {
            let savedErrno = errno
            Darwin.close(duplicate)
            throw WorkspaceError.io(operation: "enumerate workspace directory", path: path, code: savedErrno)
        }
        defer { Darwin.closedir(stream) }

        var names: [String] = []
        errno = 0
        while let entry = Darwin.readdir(stream) {
            let bytes = withUnsafeBytes(of: entry.pointee.d_name) { raw in
                Array(raw.prefix { $0 != 0 })
            }
            guard let name = String(bytes: bytes, encoding: .utf8) else {
                throw WorkspaceError.treeChanged("non-UTF-8 entry under \(path)")
            }
            if name == "." || name == ".." { continue }
            guard names.count < remainingEntryBudget else {
                let actual = maximumEntries == Int.max
                    ? Int.max
                    : maximumEntries + 1
                throw WorkspaceError.treeChanged(
                    "bundle export contains \(actual) or more entries; limit is \(maximumEntries)"
                )
            }
            names.append(name)
        }
        guard errno == 0 else {
            throw WorkspaceError.io(operation: "enumerate workspace directory", path: path, code: errno)
        }
        return names.sorted()
    }

    private static func duplicateDescriptor(_ descriptor: Int32, path: String) throws -> Int32 {
        let duplicate = Darwin.fcntl(descriptor, F_DUPFD_CLOEXEC, 0)
        guard duplicate >= 0 else {
            throw WorkspaceError.io(operation: "duplicate directory descriptor", path: path, code: errno)
        }
        return duplicate
    }

    private static func writeAll(_ data: Data, descriptor: Int32, path: String) throws {
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
                    throw WorkspaceError.io(operation: "write artifact", path: path, code: errno)
                }
                guard count > 0 else {
                    throw WorkspaceError.io(operation: "write artifact", path: path, code: EIO)
                }
                offset += count
            }
        }
    }

    private static func validateEmptyPrivateArtifact(
        parent: Int32,
        leaf: String,
        descriptor: Int32,
        path: String
    ) throws {
        var descriptorMetadata = stat()
        guard Darwin.fstat(descriptor, &descriptorMetadata) == 0,
              (descriptorMetadata.st_mode & S_IFMT) == S_IFREG,
              descriptorMetadata.st_nlink == 1,
              descriptorMetadata.st_uid == geteuid(),
              descriptorMetadata.st_size == 0,
              hasExactMode(descriptorMetadata, mode: 0o600),
              hasNoExtendedACL(descriptor) else {
            throw WorkspaceError.treeChanged(
                "empty artifact \(path) failed private descriptor validation"
            )
        }
        var namedMetadata = stat()
        let namedStatus = leaf.withCString {
            Darwin.fstatat(parent, $0, &namedMetadata, AT_SYMLINK_NOFOLLOW)
        }
        guard namedStatus == 0,
              (namedMetadata.st_mode & S_IFMT) == S_IFREG,
              namedMetadata.st_nlink == 1,
              descriptorMetadata.st_dev == namedMetadata.st_dev,
              descriptorMetadata.st_ino == namedMetadata.st_ino,
              descriptorMetadata.st_uid == namedMetadata.st_uid,
              namedMetadata.st_size == 0,
              hasExactMode(namedMetadata, mode: 0o600) else {
            throw WorkspaceError.treeChanged(
                "empty artifact \(path) failed private name validation"
            )
        }
    }

    private static func hasExactMode(_ metadata: stat, mode: mode_t) -> Bool {
        (metadata.st_mode & mode_t(0o7777)) == mode
    }

    private static func hasNoExtendedACL(_ descriptor: Int32) -> Bool {
        errno = 0
        guard let acl = Darwin.acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
            return errno == ENOENT || errno == ENOTSUP || errno == EOPNOTSUPP
        }
        Darwin.acl_free(UnsafeMutableRawPointer(acl))
        return false
    }

    private static func relativeComponents(_ path: String) throws -> [String] {
        guard !path.isEmpty,
              !path.hasPrefix("/"),
              !path.hasSuffix("/"),
              !path.utf8.contains(0) else {
            throw WorkspaceError.unsafePath(path)
        }
        let components = path.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard !components.isEmpty,
              components.allSatisfy({ component in
                  !component.isEmpty
                      && component != "."
                      && component != ".."
                      && component.utf8.count <= 255
              }) else {
            throw WorkspaceError.unsafePath(path)
        }
        return components
    }

    private static func normalizeAbsolutePath(_ path: String) throws -> String {
        guard path.first == "/", !path.hasSuffix("/"), !path.utf8.contains(0) else {
            throw WorkspaceError.unsafePath(path)
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
              components.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
            throw WorkspaceError.unsafePath(path)
        }
        return normalized
    }

    private static func openDirectoryNoFollow(at path: String) throws -> Int32 {
        guard path.first == "/" else { throw WorkspaceError.unsafePath(path) }
        let components = path == "/"
            ? []
            : path.dropFirst().split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        var descriptor = Darwin.open(
            "/",
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
        )
        guard descriptor >= 0 else {
            throw WorkspaceError.io(operation: "open filesystem root", path: path, code: errno)
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
                    throw WorkspaceError.io(operation: "open destination parent", path: path, code: errno)
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
