// BundledRuleSynchronizer.swift
// MacCrabAgentKit
//
// Installs the detection corpus sealed inside the running System Extension into
// the root-owned support directory before any rule reader starts. The source is
// never supplied by the app, an environment variable, or the world-writable
// inbox: sysextd stages and launches the signed bundle under
// /Library/SystemExtensions, and the designated-signature check below includes
// its CodeResources seal.

import CryptoKit
import Darwin
import Foundation
import MacCrabCore
import Security
import os.log

enum BundledRuleSyncOutcome: Equatable, Sendable {
    case skipped(String)
    case unchanged(version: String)
    case installed(version: String)
    case failed(
        reason: String,
        bundledTampered: Bool,
        installedTampered: Bool,
        installedCorpusVerified: Bool
    )
}

enum BundledRuleSynchronizer {
    typealias DirectoryReplacer = (
        _ staged: URL,
        _ destination: URL,
        _ destinationExists: Bool
    ) throws -> Void

    private static let logger = Logger(
        subsystem: "com.maccrab.agent",
        category: "bundled-rule-sync"
    )
    private static let manifestName = "manifest.json"
    private static let versionName = ".bundle_version"
    private static let recoveryStagePrefix = ".compiled_rules.stage."
    private static let allowedRuntimeDirectories: Set<String> = [
        "auto_generated",
        "pushed",
    ]
    // Runtime-generated rules are preserved across signed-corpus swaps, but a
    // bounded tree is essential: copying an unbounded root-owned tree doubles
    // its live footprint during every repair/update and can exhaust APFS.
    static let maximumRuntimeEntries = 4_096
    static let maximumRuntimeFileBytes: off_t = 4 * 1_024 * 1_024
    static let maximumRuntimeAggregateBytes: off_t = 64 * 1_024 * 1_024
    private static let maximumRuntimeDepth = 32
    // A signed manifest is authenticated, but a bad release build can still be
    // pathologically large. Keep source/install verification and DMG packaging
    // pinned to the same bounded resource contract.
    static let maximumSignedCorpusEntries = 4_096
    static let maximumSignedCorpusFileBytes: off_t = 16 * 1_024 * 1_024
    static let maximumSignedCorpusAggregateBytes: off_t = 64 * 1_024 * 1_024
    static let maximumSignedCorpusDepth = 32
    /// Production Developer ID Application requirement. `anchor apple generic`
    /// plus the Team ID alone is not sufficient: the same team can issue Apple
    /// Development or Mac App Store certificates. Pin both the Developer ID
    /// intermediate and Developer ID Application leaf marker OIDs.
    static let systemExtensionDesignatedRequirement =
        "identifier \"com.maccrab.agent\" and anchor apple generic"
        + " and certificate 1[field.1.2.840.113635.100.6.2.6] exists"
        + " and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
        + " and certificate leaf[subject.OU] = \"79S425CW99\""
    /// Flags that can make a verified path mutable only by append, impossible
    /// to replace, entitlement-gated, or a dataless placeholder. Compression,
    /// archive and hidden flags are harmless metadata and remain allowed.
    private static let unsafeBSDFlags = UInt32(
        UF_IMMUTABLE | UF_APPEND | UF_DATAVAULT
            | SF_IMMUTABLE | SF_APPEND | SF_NOUNLINK | SF_DATALESS
    )

    private struct RuleManifest: Decodable {
        let schemaVersion: Int
        let bundleVersion: String
        let hashes: [String: String]

        enum CodingKeys: String, CodingKey {
            case schemaVersion = "schema_version"
            case bundleVersion = "bundle_version"
            case hashes
        }
    }

    private struct VerifiedCorpus {
        let version: String
        let manifestData: Data
    }

    private struct Inventory {
        var files: Set<String> = []
        var directories: Set<String> = []
        var entryCount = 0
        var regularFileBytes: off_t = 0
    }

    private struct InventoryLimits {
        let maximumEntries: Int
        let maximumFileBytes: off_t
        let maximumAggregateBytes: off_t
        let maximumDepth: Int
    }

    private enum InstalledCorpusStatus {
        case absent
        case verified(VerifiedCorpus)
        case invalid

        var isVerified: Bool {
            if case .verified = self { return true }
            return false
        }

        var isTampered: Bool {
            if case .invalid = self { return true }
            return false
        }
    }

    private enum SyncError: LocalizedError {
        case invalid(String)
        case io(String)

        var errorDescription: String? {
            switch self {
            case .invalid(let reason), .io(let reason): return reason
            }
        }
    }

    /// Production entry point. It deliberately accepts only the currently
    /// executing, Developer-ID-signed System Extension staged by sysextd.
    static func synchronizeAtBoot(supportDirectory: String) -> BundledRuleSyncOutcome {
        let bundleURL = Bundle.main.bundleURL.resolvingSymlinksInPath()
        let trustedRoot = "/Library/SystemExtensions/"
        let isStagedSystemExtension = bundleURL.path.hasPrefix(trustedRoot)
            && bundleURL.pathExtension == "systemextension"
        let hasProductionIdentifier = Bundle.main.bundleIdentifier == "com.maccrab.agent"

        // A standalone developer daemon deliberately has neither production
        // marker and keeps its source-tree behavior. If either marker says this
        // is the shipping System Extension, however, identity/privilege drift is
        // a trust failure—not a reason to silently bypass synchronization.
        guard hasProductionIdentifier || isStagedSystemExtension else {
            return .skipped("not_system_extension_bundle")
        }
        guard geteuid() == 0 else {
            return recordFailure(
                supportDirectory: supportDirectory,
                reason: "running System Extension is not root",
                bundledTampered: true
            )
        }
        guard hasProductionIdentifier else {
            return recordFailure(
                supportDirectory: supportDirectory,
                reason: "running System Extension bundle identifier is invalid",
                bundledTampered: true
            )
        }
        guard isStagedSystemExtension else {
            logger.fault("Refusing bundled-rule sync from non-sysextd path: \(bundleURL.path, privacy: .public)")
            return recordFailure(
                supportDirectory: supportDirectory,
                reason: "running System Extension is not staged under /Library/SystemExtensions",
                bundledTampered: true
            )
        }
        guard systemExtensionSignatureIsTrusted(bundleURL: bundleURL) else {
            logger.fault("Refusing bundled-rule sync: designated signature/resource seal failed")
            return recordFailure(
                supportDirectory: supportDirectory,
                reason: "System Extension signature or resource seal is invalid",
                bundledTampered: true
            )
        }

        let bundledRules = bundleURL
            .appendingPathComponent("Contents/Resources/compiled_rules", isDirectory: true)
        let installedRules = URL(fileURLWithPath: supportDirectory, isDirectory: true)
            .appendingPathComponent("compiled_rules", isDirectory: true)
        let adminGID = getgrnam("admin").map { $0.pointee.gr_gid }
        let outcome = synchronize(
            bundledDirectory: bundledRules,
            installedDirectory: installedRules,
            requiredOwnerUID: 0,
            destinationGroupID: adminGID
        )

        switch outcome {
        case .installed(let version):
            logger.notice("Installed signed System Extension rules \(version, privacy: .public) before rule-engine startup")
            clearTamperState(supportDirectory: supportDirectory)
        case .unchanged(let version):
            logger.debug("Installed rules already match signed System Extension corpus \(version, privacy: .public)")
            clearTamperState(supportDirectory: supportDirectory)
        case .failed(
            let reason,
            let bundledTampered,
            let installedTampered,
            _
        ):
            logger.fault("Bundled-rule sync failed closed: \(reason, privacy: .public). Last-known-good corpus retained.")
            writeTamperState(
                supportDirectory: supportDirectory,
                bundledTampered: bundledTampered,
                installedTampered: installedTampered,
                reason: reason
            )
        case .skipped:
            break
        }
        return outcome
    }

    /// Hermetic/testable transaction. The caller supplies the trusted source
    /// and expected owner; production reaches it only after the sysext path and
    /// designated-signature gates above.
    static func synchronize(
        bundledDirectory: URL,
        installedDirectory: URL,
        requiredOwnerUID: uid_t,
        destinationGroupID: gid_t? = nil,
        afterStaging: ((URL) throws -> Void)? = nil,
        replacingDirectoryWith replacement: DirectoryReplacer? = nil
    ) -> BundledRuleSyncOutcome {
        // Assess the installed tree independently and before trusting the new
        // bundled source. A missing/broken first-install source must not turn
        // an empty compiled_rules carrier into an alleged last-known-good.
        let initialInstalledStatus = installedCorpusStatus(
            at: installedDirectory,
            requiredOwnerUID: requiredOwnerUID
        )
        // An installed manifest is not a trust anchor: a coordinated edit can
        // change both the rules and their unsigned manifest while remaining
        // internally self-consistent.  It is a usable fallback only after the
        // currently running, code-sealed source has verified AND the installed
        // manifest/version match that authenticated source byte-for-byte.
        var installedMatchesVerifiedBundle = false
        var installedWasTampered = initialInstalledStatus.isTampered

        let bundled: VerifiedCorpus
        do {
            bundled = try verifyCorpus(
                at: bundledDirectory,
                requiredOwnerUID: requiredOwnerUID,
                allowRuntimeDirectories: false,
                requireCanonicalModes: false
            )
        } catch {
            return .failed(
                reason: "bundled corpus: \(error.localizedDescription)",
                bundledTampered: true,
                installedTampered: installedWasTampered,
                installedCorpusVerified: false
            )
        }

        if case .verified(let installed) = initialInstalledStatus {
            installedMatchesVerifiedBundle = installed.manifestData == bundled.manifestData
                && installed.version == bundled.version
        }

        let fm = FileManager.default
        let parent = installedDirectory.deletingLastPathComponent()
        do {
            try validateDirectory(
                at: parent,
                requiredOwnerUID: requiredOwnerUID
            )
        } catch {
            return .failed(
                reason: "installed parent: \(error.localizedDescription)",
                bundledTampered: false,
                installedTampered: true,
                installedCorpusVerified: false
            )
        }

        let destinationExists = pathExistsWithoutFollowing(installedDirectory.path)
        var preservedRuntimeDirectories: [(name: String, source: URL)] = []
        if destinationExists {
            do {
                // The carrier name itself must remain a real, securely-owned
                // directory. We will heal invalid contents, but never swap over
                // a symlink/foreign-owned destination.
                try validateDirectory(
                    at: installedDirectory,
                    requiredOwnerUID: requiredOwnerUID
                )
                preservedRuntimeDirectories = try validatedRuntimeDirectories(
                    in: installedDirectory,
                    requiredOwnerUID: requiredOwnerUID
                )
            } catch {
                return .failed(
                    reason: "installed corpus carrier/runtime data: \(error.localizedDescription)",
                    bundledTampered: false,
                    installedTampered: true,
                    installedCorpusVerified: false
                )
            }

            if case .verified = initialInstalledStatus {
                if installedMatchesVerifiedBundle {
                    // A crash after a failed post-publish rollback can leave
                    // the previous corpus at a stage name. Only reap those
                    // recovery copies after re-verifying that the canonical
                    // installed name is the authenticated signed corpus. This
                    // must precede the unchanged fast path or the copies would
                    // otherwise survive every subsequent boot.
                    removeRecoveryStagesIfCanonicalCorpusMatches(
                        installedDirectory: installedDirectory,
                        bundled: bundled,
                        requiredOwnerUID: requiredOwnerUID
                    )
                    return .unchanged(version: bundled.version)
                }
            } else {
                // A securely-carried but malformed/hash-mismatched corpus is
                // exactly what the signed source is meant to self-heal.
                installedWasTampered = true
            }
        }

        let stagedDirectory = parent.appendingPathComponent(
            ".compiled_rules.stage.\(UUID().uuidString)",
            isDirectory: true
        )
        var preserveStagedForRecovery = false
        defer {
            if !preserveStagedForRecovery,
               pathExistsWithoutFollowing(stagedDirectory.path) {
                try? fm.removeItem(at: stagedDirectory)
            }
        }

        do {
            try fm.copyItem(at: bundledDirectory, to: stagedDirectory)
            for runtimeDirectory in preservedRuntimeDirectories {
                try fm.copyItem(
                    at: runtimeDirectory.source,
                    to: stagedDirectory.appendingPathComponent(
                        runtimeDirectory.name,
                        isDirectory: true
                    )
                )
            }
            try normalizeTree(
                at: stagedDirectory,
                ownerUID: requiredOwnerUID,
                groupID: destinationGroupID
            )
            try afterStaging?(stagedDirectory)

            let staged = try verifyCorpus(
                at: stagedDirectory,
                requiredOwnerUID: requiredOwnerUID,
                allowRuntimeDirectories: true,
                requireCanonicalModes: true
            )
            guard staged.manifestData == bundled.manifestData,
                  staged.version == bundled.version else {
                throw SyncError.invalid("staged manifest drifted from the signed source")
            }
        } catch {
            return .failed(
                reason: "staging: \(error.localizedDescription)",
                bundledTampered: false,
                installedTampered: installedWasTampered,
                installedCorpusVerified: installedMatchesVerifiedBundle
            )
        }

        let replacer = replacement ?? replaceDirectoryAtomically
        do {
            try replacer(stagedDirectory, installedDirectory, destinationExists)
        } catch {
            return .failed(
                reason: "atomic publication: \(error.localizedDescription)",
                bundledTampered: false,
                installedTampered: installedWasTampered,
                installedCorpusVerified: installedMatchesVerifiedBundle
            )
        }

        // A same-filesystem rename cannot alter bytes, but verify the published
        // name before deleting the swapped-out last-known-good directory. If an
        // unexpected filesystem fault appears, swap back first.
        do {
            let published = try verifyCorpus(
                at: installedDirectory,
                requiredOwnerUID: requiredOwnerUID,
                allowRuntimeDirectories: true,
                requireCanonicalModes: true
            )
            guard published.manifestData == bundled.manifestData,
                  published.version == bundled.version else {
                throw SyncError.invalid("published manifest differs from signed source")
            }
        } catch let publicationError {
            do {
                if destinationExists {
                    try replaceDirectoryAtomically(
                        staged: stagedDirectory,
                        destination: installedDirectory,
                        destinationExists: true
                    )
                } else {
                    try fm.removeItem(at: installedDirectory)
                }
            } catch let rollbackError {
                // With RENAME_SWAP, stagedDirectory still names the previous
                // corpus. Never delete it if canonical-name restoration fails.
                preserveStagedForRecovery = destinationExists
                return .failed(
                    reason: "post-publish verification failed (\(publicationError.localizedDescription)); rollback failed (\(rollbackError.localizedDescription)); prior corpus retained at \(stagedDirectory.path)",
                    bundledTampered: false,
                    installedTampered: true,
                    installedCorpusVerified: false
                )
            }
            return .failed(
                reason: "post-publish verification failed and was rolled back: \(publicationError.localizedDescription)",
                bundledTampered: false,
                installedTampered: !installedMatchesVerifiedBundle,
                installedCorpusVerified: installedMatchesVerifiedBundle
            )
        }

        // Existing destination: RENAME_SWAP leaves the old corpus at the staged
        // name. A prior crash can have left other recovery stages as well. The
        // cleanup routine re-verifies the canonical published corpus before it
        // removes any strict, direct-child stage name.
        removeRecoveryStagesIfCanonicalCorpusMatches(
            installedDirectory: installedDirectory,
            bundled: bundled,
            requiredOwnerUID: requiredOwnerUID
        )
        return .installed(version: bundled.version)
    }

    /// Best-effort cleanup for crash-retained rollback copies. A stage is never
    /// considered until the canonical installed corpus has been freshly
    /// verified and matched byte-for-byte to the authenticated bundle. Names
    /// must be direct children in the exact UUID form emitted by synchronize();
    /// lookalikes, symlinks, regular files and insecure/foreign-owned directories
    /// are deliberately left untouched.
    private static func removeRecoveryStagesIfCanonicalCorpusMatches(
        installedDirectory: URL,
        bundled: VerifiedCorpus,
        requiredOwnerUID: uid_t
    ) {
        let parent = installedDirectory.deletingLastPathComponent()
        do {
            try validateDirectory(at: parent, requiredOwnerUID: requiredOwnerUID)
            let installed = try verifyCorpus(
                at: installedDirectory,
                requiredOwnerUID: requiredOwnerUID,
                allowRuntimeDirectories: true,
                requireCanonicalModes: true
            )
            guard installed.manifestData == bundled.manifestData,
                  installed.version == bundled.version else {
                return
            }

            for name in try FileManager.default.contentsOfDirectory(atPath: parent.path) {
                guard isStrictRecoveryStageName(name) else { continue }
                let candidate = parent.appendingPathComponent(name, isDirectory: true)
                do {
                    // validateDirectory uses lstat plus O_NOFOLLOW and binds the
                    // opened descriptor back to the same inode. FileManager's
                    // recursive removal unlinks symlink entries rather than
                    // traversing them; the carrier itself must be a real,
                    // securely-owned directory before removal is attempted.
                    try validateDirectory(
                        at: candidate,
                        requiredOwnerUID: requiredOwnerUID
                    )
                    try FileManager.default.removeItem(at: candidate)
                    logger.notice("Removed obsolete bundled-rule recovery stage \(name, privacy: .public)")
                } catch {
                    logger.warning("Leaving unsafe or unavailable bundled-rule recovery stage \(name, privacy: .public): \(error.localizedDescription, privacy: .public)")
                }
            }
        } catch {
            // Cleanup is not part of the trust decision and must not make a
            // verified last-known-good corpus unavailable. A later boot retries.
            logger.warning("Bundled-rule recovery-stage cleanup deferred: \(error.localizedDescription, privacy: .public)")
        }
    }

    private static func isStrictRecoveryStageName(_ name: String) -> Bool {
        guard name.hasPrefix(recoveryStagePrefix) else { return false }
        let suffix = String(name.dropFirst(recoveryStagePrefix.count))
        guard suffix.utf8.count == 36,
              let uuid = UUID(uuidString: suffix) else {
            return false
        }
        // UUID().uuidString is uppercase and hyphenated. Exact round-tripping
        // rejects lowercase aliases, braces, suffixes and other lookalikes.
        return uuid.uuidString == suffix
    }

    private static func installedCorpusStatus(
        at installedDirectory: URL,
        requiredOwnerUID: uid_t
    ) -> InstalledCorpusStatus {
        guard pathExistsWithoutFollowing(installedDirectory.path) else {
            return .absent
        }
        do {
            try validateDirectory(
                at: installedDirectory.deletingLastPathComponent(),
                requiredOwnerUID: requiredOwnerUID
            )
            return .verified(try verifyCorpus(
                at: installedDirectory,
                requiredOwnerUID: requiredOwnerUID,
                allowRuntimeDirectories: true,
                requireCanonicalModes: true
            ))
        } catch {
            return .invalid
        }
    }

    private static var runtimeInventoryLimits: InventoryLimits {
        InventoryLimits(
            maximumEntries: maximumRuntimeEntries,
            maximumFileBytes: maximumRuntimeFileBytes,
            maximumAggregateBytes: maximumRuntimeAggregateBytes,
            maximumDepth: maximumRuntimeDepth
        )
    }

    private static var signedCorpusInventoryLimits: InventoryLimits {
        InventoryLimits(
            maximumEntries: maximumSignedCorpusEntries,
            maximumFileBytes: maximumSignedCorpusFileBytes,
            maximumAggregateBytes: maximumSignedCorpusAggregateBytes,
            maximumDepth: maximumSignedCorpusDepth
        )
    }

    private static func verifyCorpus(
        at root: URL,
        requiredOwnerUID: uid_t,
        allowRuntimeDirectories: Bool,
        requireCanonicalModes: Bool
    ) throws -> VerifiedCorpus {
        let allowed = allowRuntimeDirectories ? allowedRuntimeDirectories : []
        let inventory = try inspectTree(
            at: root,
            requiredOwnerUID: requiredOwnerUID,
            allowedRuntimeDirectories: allowed,
            requireCanonicalModes: requireCanonicalModes,
            limits: signedCorpusInventoryLimits
        )
        let manifestURL = root.appendingPathComponent(manifestName)
        let versionURL = root.appendingPathComponent(versionName)
        let manifestData = try readRegularFile(
            at: manifestURL,
            requiredOwnerUID: requiredOwnerUID,
            maximumBytes: 2 * 1_024 * 1_024
        )
        let versionData = try readRegularFile(
            at: versionURL,
            requiredOwnerUID: requiredOwnerUID,
            maximumBytes: 4 * 1_024
        )

        let manifest: RuleManifest
        do {
            manifest = try JSONDecoder().decode(RuleManifest.self, from: manifestData)
        } catch {
            throw SyncError.invalid("manifest cannot be decoded: \(error.localizedDescription)")
        }
        guard manifest.schemaVersion == 1 else {
            throw SyncError.invalid("unsupported manifest schema \(manifest.schemaVersion)")
        }
        let markerVersion = String(data: versionData, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !markerVersion.isEmpty,
              markerVersion == manifest.bundleVersion else {
            throw SyncError.invalid("bundle version marker and manifest disagree")
        }
        guard !manifest.hashes.isEmpty else {
            throw SyncError.invalid("manifest contains no rule hashes")
        }

        var expectedFiles: Set<String> = [manifestName, versionName]
        var expectedDirectories: Set<String> = []
        for (relativePath, expectedHash) in manifest.hashes {
            try validateManifestPath(relativePath)
            guard expectedHash.range(
                of: "^[0-9a-f]{64}$",
                options: .regularExpression
            ) != nil else {
                throw SyncError.invalid("invalid SHA-256 for \(relativePath)")
            }
            guard expectedFiles.insert(relativePath).inserted else {
                throw SyncError.invalid("duplicate manifest path \(relativePath)")
            }
            let components = relativePath.split(separator: "/").dropLast()
            var prefix = ""
            for component in components {
                prefix = prefix.isEmpty ? String(component) : "\(prefix)/\(component)"
                expectedDirectories.insert(prefix)
            }

            let ruleData = try readRegularFile(
                at: root.appendingPathComponent(relativePath),
                requiredOwnerUID: requiredOwnerUID,
                maximumBytes: Int(maximumSignedCorpusFileBytes)
            )
            let actualHash = SHA256.hash(data: ruleData)
                .map { String(format: "%02x", $0) }
                .joined()
            guard actualHash == expectedHash else {
                throw SyncError.invalid("hash mismatch for \(relativePath)")
            }
        }

        guard inventory.files == expectedFiles else {
            let missing = expectedFiles.subtracting(inventory.files).sorted()
            let extra = inventory.files.subtracting(expectedFiles).sorted()
            throw SyncError.invalid(
                "manifest file set mismatch (missing=\(missing.prefix(3)); extra=\(extra.prefix(3)))"
            )
        }
        guard inventory.directories == expectedDirectories else {
            let missing = expectedDirectories.subtracting(inventory.directories).sorted()
            let extra = inventory.directories.subtracting(expectedDirectories).sorted()
            throw SyncError.invalid(
                "manifest directory set mismatch (missing=\(missing.prefix(3)); extra=\(extra.prefix(3)))"
            )
        }
        return VerifiedCorpus(version: markerVersion, manifestData: manifestData)
    }

    private static func validateManifestPath(_ path: String) throws {
        guard !path.isEmpty,
              path.utf8.count <= 1_024,
              !path.hasPrefix("/"),
              !path.contains("\\"),
              path.hasSuffix(".json") else {
            throw SyncError.invalid("unsafe manifest path \(path)")
        }
        let components = path.split(separator: "/", omittingEmptySubsequences: false)
        guard !components.isEmpty,
              components.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
            throw SyncError.invalid("unsafe manifest path \(path)")
        }
        guard !allowedRuntimeDirectories.contains(String(components[0])) else {
            throw SyncError.invalid("manifest may not claim runtime directory \(components[0])")
        }
    }

    private static func inspectTree(
        at root: URL,
        requiredOwnerUID: uid_t,
        allowedRuntimeDirectories: Set<String>,
        requireCanonicalModes: Bool,
        limits: InventoryLimits?
    ) throws -> Inventory {
        try validateDirectory(
            at: root,
            requiredOwnerUID: requiredOwnerUID,
            requireCanonicalMode: requireCanonicalModes
        )
        var inventory = Inventory()
        var runtimeEntryCount = 0
        var runtimeFileBytes: off_t = 0

        func walk(_ directory: URL, relativeDirectory: String, depth: Int) throws {
            let names = try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted()
            for name in names {
                inventory.entryCount += 1
                if let limits {
                    guard inventory.entryCount <= limits.maximumEntries else {
                        throw SyncError.invalid(
                            "rule tree exceeds \(limits.maximumEntries) entries"
                        )
                    }
                    guard depth + 1 <= limits.maximumDepth else {
                        throw SyncError.invalid(
                            "rule tree exceeds depth \(limits.maximumDepth)"
                        )
                    }
                }
                guard name != ".", name != "..", !name.contains("/") else {
                    throw SyncError.invalid("unsafe directory entry \(name)")
                }
                let relative = relativeDirectory.isEmpty
                    ? name
                    : "\(relativeDirectory)/\(name)"
                let child = directory.appendingPathComponent(name)
                let metadata = try metadataWithoutFollowing(child.path)
                try validateOwnershipAndMode(
                    metadata,
                    path: child.path,
                    requiredOwnerUID: requiredOwnerUID,
                    canonicalMode: requireCanonicalModes
                        ? ((metadata.st_mode & S_IFMT) == S_IFDIR ? 0o755 : 0o644)
                        : nil
                )

                if (metadata.st_mode & S_IFMT) == S_IFDIR {
                    if relativeDirectory.isEmpty,
                       allowedRuntimeDirectories.contains(name) {
                        let runtimeInventory = try inspectTree(
                            at: child,
                            requiredOwnerUID: requiredOwnerUID,
                            allowedRuntimeDirectories: [],
                            requireCanonicalModes: requireCanonicalModes,
                            limits: runtimeInventoryLimits
                        )
                        runtimeEntryCount += runtimeInventory.entryCount
                        runtimeFileBytes += runtimeInventory.regularFileBytes
                        try enforceRuntimeInventoryLimits(
                            entryCount: runtimeEntryCount,
                            aggregateBytes: runtimeFileBytes
                        )
                        continue
                    }
                    inventory.directories.insert(relative)
                    try walk(child, relativeDirectory: relative, depth: depth + 1)
                } else if (metadata.st_mode & S_IFMT) == S_IFREG {
                    guard metadata.st_nlink == 1 else {
                        throw SyncError.invalid("hard-linked file refused: \(child.path)")
                    }
                    guard metadata.st_size >= 0 else {
                        throw SyncError.invalid("negative file size refused: \(child.path)")
                    }
                    if let limits {
                        guard metadata.st_size <= limits.maximumFileBytes else {
                            throw SyncError.invalid(
                                "rule file exceeds \(limits.maximumFileBytes) bytes: \(child.path)"
                            )
                        }
                        let (total, overflow) = inventory.regularFileBytes
                            .addingReportingOverflow(metadata.st_size)
                        guard !overflow, total <= limits.maximumAggregateBytes else {
                            throw SyncError.invalid(
                                "rule tree exceeds \(limits.maximumAggregateBytes) bytes"
                            )
                        }
                        inventory.regularFileBytes = total
                    } else {
                        inventory.regularFileBytes += metadata.st_size
                    }
                    inventory.files.insert(relative)
                } else {
                    throw SyncError.invalid("non-regular rule-tree entry refused: \(child.path)")
                }
            }
        }

        try walk(root, relativeDirectory: "", depth: 0)
        return inventory
    }

    private static func enforceRuntimeInventoryLimits(
        entryCount: Int,
        aggregateBytes: off_t
    ) throws {
        guard entryCount <= maximumRuntimeEntries else {
            throw SyncError.invalid(
                "preserved runtime rules exceed \(maximumRuntimeEntries) entries"
            )
        }
        guard aggregateBytes <= maximumRuntimeAggregateBytes else {
            throw SyncError.invalid(
                "preserved runtime rules exceed \(maximumRuntimeAggregateBytes) bytes"
            )
        }
    }

    private static func validatedRuntimeDirectories(
        in installedDirectory: URL,
        requiredOwnerUID: uid_t
    ) throws -> [(name: String, source: URL)] {
        var result: [(String, URL)] = []
        var totalEntries = 0
        var totalBytes: off_t = 0
        for name in allowedRuntimeDirectories.sorted() {
            let candidate = installedDirectory.appendingPathComponent(name, isDirectory: true)
            guard pathExistsWithoutFollowing(candidate.path) else { continue }
            let inventory = try inspectTree(
                at: candidate,
                requiredOwnerUID: requiredOwnerUID,
                allowedRuntimeDirectories: [],
                requireCanonicalModes: false,
                limits: runtimeInventoryLimits
            )
            totalEntries += inventory.entryCount
            totalBytes += inventory.regularFileBytes
            try enforceRuntimeInventoryLimits(
                entryCount: totalEntries,
                aggregateBytes: totalBytes
            )
            result.append((name, candidate))
        }
        return result
    }

    private static func validateDirectory(
        at url: URL,
        requiredOwnerUID: uid_t,
        requireCanonicalMode: Bool = false
    ) throws {
        let metadata = try metadataWithoutFollowing(url.path)
        guard (metadata.st_mode & S_IFMT) == S_IFDIR else {
            throw SyncError.invalid("not a real directory: \(url.path)")
        }
        try validateOwnershipAndMode(
            metadata,
            path: url.path,
            requiredOwnerUID: requiredOwnerUID,
            canonicalMode: requireCanonicalMode ? 0o755 : nil
        )
    }

    private static func validateOwnershipAndMode(
        _ metadata: stat,
        path: String,
        requiredOwnerUID: uid_t,
        canonicalMode: mode_t? = nil
    ) throws {
        guard metadata.st_uid == requiredOwnerUID else {
            throw SyncError.invalid(
                "foreign-owned path refused: \(path) (uid \(metadata.st_uid), expected \(requiredOwnerUID))"
            )
        }
        guard metadata.st_mode & mode_t(0o022) == 0 else {
            throw SyncError.invalid("group/world-writable path refused: \(path)")
        }
        guard metadata.st_flags & unsafeBSDFlags == 0 else {
            throw SyncError.invalid(
                "unsafe BSD flags refused at \(path): 0x\(String(metadata.st_flags, radix: 16))"
            )
        }
        if let canonicalMode,
           metadata.st_mode & mode_t(0o777) != canonicalMode {
            throw SyncError.invalid(
                "non-canonical mode at \(path): \(String(metadata.st_mode & mode_t(0o777), radix: 8)); expected \(String(canonicalMode, radix: 8))"
            )
        }
        let type = metadata.st_mode & S_IFMT
        if type == S_IFDIR || type == S_IFREG {
            try validateDescriptorSecurity(
                path: path,
                expected: metadata,
                isDirectory: type == S_IFDIR
            )
        }
    }

    /// Validate ACLs through an O_NOFOLLOW descriptor and bind that descriptor
    /// back to the lstat identity. POSIX mode bits alone do not constrain an
    /// extended ACL; e.g. root:admin 0644 can still grant a named user write.
    private static func validateDescriptorSecurity(
        path: String,
        expected: stat,
        isDirectory: Bool
    ) throws {
        let flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW | (isDirectory ? O_DIRECTORY : 0)
        let descriptor = path.withCString { Darwin.open($0, flags) }
        guard descriptor >= 0 else {
            throw SyncError.io("secure open failed for \(path): \(posixMessage(errno))")
        }
        defer { Darwin.close(descriptor) }

        var actual = stat()
        guard Darwin.fstat(descriptor, &actual) == 0,
              actual.st_dev == expected.st_dev,
              actual.st_ino == expected.st_ino,
              (actual.st_mode & S_IFMT) == (expected.st_mode & S_IFMT) else {
            throw SyncError.invalid("path changed while security metadata was checked: \(path)")
        }
        guard actual.st_flags & unsafeBSDFlags == 0 else {
            throw SyncError.invalid(
                "unsafe BSD flags refused at \(path): 0x\(String(actual.st_flags, radix: 16))"
            )
        }
        guard hasNoExtendedACL(descriptor) else {
            throw SyncError.invalid("extended ACL refused at \(path)")
        }
    }

    private static func hasNoExtendedACL(_ descriptor: Int32) -> Bool {
        errno = 0
        guard let acl = Darwin.acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
            return errno == ENOENT || errno == ENOTSUP || errno == EOPNOTSUPP
        }
        Darwin.acl_free(UnsafeMutableRawPointer(acl))
        return false
    }

    private static func metadataWithoutFollowing(_ path: String) throws -> stat {
        var metadata = stat()
        guard path.withCString({ Darwin.lstat($0, &metadata) }) == 0 else {
            throw SyncError.io("lstat failed for \(path): \(posixMessage(errno))")
        }
        guard (metadata.st_mode & S_IFMT) != S_IFLNK else {
            throw SyncError.invalid("symbolic link refused: \(path)")
        }
        return metadata
    }

    private static func readRegularFile(
        at url: URL,
        requiredOwnerUID: uid_t,
        maximumBytes: Int
    ) throws -> Data {
        let descriptor = url.path.withCString {
            Darwin.open($0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard descriptor >= 0 else {
            throw SyncError.io("open failed for \(url.path): \(posixMessage(errno))")
        }
        defer { Darwin.close(descriptor) }

        var before = stat()
        guard Darwin.fstat(descriptor, &before) == 0,
              (before.st_mode & S_IFMT) == S_IFREG,
              before.st_nlink == 1,
              before.st_uid == requiredOwnerUID,
              before.st_mode & mode_t(0o022) == 0,
              before.st_flags & unsafeBSDFlags == 0,
              before.st_size >= 0,
              before.st_size <= off_t(maximumBytes),
              hasNoExtendedACL(descriptor) else {
            throw SyncError.invalid("unsafe or oversized regular file: \(url.path)")
        }

        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
        let data: Data
        do {
            data = try handle.readToEnd() ?? Data()
        } catch {
            throw SyncError.io("read failed for \(url.path): \(error.localizedDescription)")
        }
        var after = stat()
        guard Darwin.fstat(descriptor, &after) == 0,
              before.st_dev == after.st_dev,
              before.st_ino == after.st_ino,
              before.st_size == after.st_size,
              data.count == Int(after.st_size) else {
            throw SyncError.invalid("file changed while being verified: \(url.path)")
        }
        return data
    }

    private static func normalizeTree(
        at root: URL,
        ownerUID: uid_t,
        groupID: gid_t?
    ) throws {
        func normalize(_ url: URL) throws {
            let metadata = try metadataWithoutFollowing(url.path)
            let type = metadata.st_mode & S_IFMT
            guard type == S_IFDIR || type == S_IFREG else {
                throw SyncError.invalid("cannot normalize non-file entry: \(url.path)")
            }
            let descriptorFlags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW
                | (type == S_IFDIR ? O_DIRECTORY : 0)
            let descriptor = url.path.withCString { Darwin.open($0, descriptorFlags) }
            guard descriptor >= 0 else {
                throw SyncError.io(
                    "secure normalization open failed for \(url.path): \(posixMessage(errno))"
                )
            }
            defer { Darwin.close(descriptor) }

            var opened = stat()
            guard Darwin.fstat(descriptor, &opened) == 0,
                  opened.st_dev == metadata.st_dev,
                  opened.st_ino == metadata.st_ino,
                  (opened.st_mode & S_IFMT) == type else {
                throw SyncError.invalid("path changed during normalization: \(url.path)")
            }

            let safeFlags = opened.st_flags & ~unsafeBSDFlags
            if safeFlags != opened.st_flags,
               Darwin.fchflags(descriptor, safeFlags) != 0 {
                throw SyncError.io(
                    "fchflags failed for \(url.path): \(posixMessage(errno))"
                )
            }
            try removeExtendedACL(from: descriptor, path: url.path)

            if opened.st_uid != ownerUID || (groupID != nil && opened.st_gid != groupID) {
                guard geteuid() == 0 else {
                    throw SyncError.invalid("ownership normalization requires root: \(url.path)")
                }
                let desiredGroup = groupID ?? opened.st_gid
                guard Darwin.fchown(descriptor, ownerUID, desiredGroup) == 0 else {
                    throw SyncError.io("chown failed for \(url.path): \(posixMessage(errno))")
                }
            }
            let mode: mode_t = type == S_IFDIR ? 0o755 : 0o644
            guard Darwin.fchmod(descriptor, mode) == 0 else {
                throw SyncError.io("chmod failed for \(url.path): \(posixMessage(errno))")
            }
            if type == S_IFDIR {
                for name in try FileManager.default.contentsOfDirectory(atPath: url.path) {
                    try normalize(url.appendingPathComponent(name))
                }
            }
        }
        try normalize(root)
    }

    private static func removeExtendedACL(from descriptor: Int32, path: String) throws {
        errno = 0
        guard let existing = Darwin.acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
            if errno == ENOENT || errno == ENOTSUP || errno == EOPNOTSUPP {
                return
            }
            throw SyncError.io("ACL read failed for \(path): \(posixMessage(errno))")
        }
        Darwin.acl_free(UnsafeMutableRawPointer(existing))

        guard let empty = Darwin.acl_init(0) else {
            throw SyncError.io("empty ACL allocation failed for \(path)")
        }
        defer { Darwin.acl_free(UnsafeMutableRawPointer(empty)) }
        guard Darwin.acl_set_fd_np(descriptor, empty, ACL_TYPE_EXTENDED) == 0 else {
            throw SyncError.io("ACL removal failed for \(path): \(posixMessage(errno))")
        }
    }

    static func replaceDirectoryAtomically(
        staged: URL,
        destination: URL,
        destinationExists: Bool
    ) throws {
        let status: Int32 = staged.path.withCString { stagedPath in
            destination.path.withCString { destinationPath in
                if destinationExists {
                    return Darwin.renamex_np(
                        stagedPath,
                        destinationPath,
                        UInt32(RENAME_SWAP)
                    )
                }
                return Darwin.rename(stagedPath, destinationPath)
            }
        }
        guard status == 0 else {
            throw SyncError.io(
                "atomic directory replacement failed: \(posixMessage(errno))"
            )
        }
    }

    private static func pathExistsWithoutFollowing(_ path: String) -> Bool {
        var metadata = stat()
        return path.withCString { Darwin.lstat($0, &metadata) } == 0
    }

    private static func systemExtensionSignatureIsTrusted(bundleURL: URL) -> Bool {
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(bundleURL as CFURL, [], &staticCode) == errSecSuccess,
              let staticCode else { return false }
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(
            systemExtensionDesignatedRequirement as CFString,
            [],
            &requirement
        ) == errSecSuccess,
              let requirement else { return false }
        // Default validation includes the bundle resource seal. That is
        // load-bearing: compiled_rules is trusted because it is CodeResources-
        // sealed inside this root-staged System Extension.
        return SecStaticCodeCheckValidity(staticCode, [], requirement) == errSecSuccess
    }

    private static func recordFailure(
        supportDirectory: String,
        reason: String,
        bundledTampered: Bool
    ) -> BundledRuleSyncOutcome {
        let installedStatus = installedCorpusStatus(
            at: URL(fileURLWithPath: supportDirectory, isDirectory: true)
                .appendingPathComponent("compiled_rules", isDirectory: true),
            requiredOwnerUID: 0
        )
        writeTamperState(
            supportDirectory: supportDirectory,
            bundledTampered: bundledTampered,
            installedTampered: installedStatus.isTampered,
            reason: reason
        )
        return .failed(
            reason: reason,
            bundledTampered: bundledTampered,
            installedTampered: installedStatus.isTampered,
            // A source path/signature failure leaves no authenticated manifest
            // against which an installed tree can be called last-known-good.
            installedCorpusVerified: false
        )
    }

    /// Pure boot policy seam: a sync failure may use last-known-good only when
    /// that installed corpus independently passed ownership, mode, exact-set,
    /// hash and bounded-runtime verification. Missing/empty/invalid is never a
    /// continuation state.
    static func shouldAbortBoot(after outcome: BundledRuleSyncOutcome) -> Bool {
        guard case .failed(
            _,
            let bundledTampered,
            _,
            let installedCorpusVerified
        ) = outcome else {
            return false
        }
        return bundledTampered || !installedCorpusVerified
    }

    private static func writeTamperState(
        supportDirectory: String,
        bundledTampered: Bool,
        installedTampered: Bool,
        reason: String
    ) {
        let payload: [String: Any] = [
            "bundled_tampered": bundledTampered,
            "installed_tampered": installedTampered,
            "mismatched_file_count": (bundledTampered || installedTampered) ? 1 : 0,
            "detected_at_unix": Date().timeIntervalSince1970,
            "sync_error": reason,
        ]
        guard let data = try? JSONSerialization.data(
            withJSONObject: payload,
            options: [.prettyPrinted, .sortedKeys]
        ) else { return }
        let path = supportDirectory + "/rule_tamper.json"
        do {
            try SecureFileIO.atomicReplace(at: path, data: data, mode: 0o644)
        } catch {
            logger.error("Could not persist rule tamper state: \(error.localizedDescription, privacy: .public)")
        }
    }

    private static func clearTamperState(supportDirectory: String) {
        let path = supportDirectory + "/rule_tamper.json"
        if pathExistsWithoutFollowing(path) {
            do {
                try FileManager.default.removeItem(atPath: path)
            } catch {
                logger.error("Could not clear rule tamper state: \(error.localizedDescription, privacy: .public)")
            }
        }
    }

    private static func posixMessage(_ code: Int32) -> String {
        String(cString: strerror(code))
    }
}
