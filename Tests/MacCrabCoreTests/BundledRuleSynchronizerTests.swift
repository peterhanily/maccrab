import CryptoKit
import Darwin
import Foundation
import Security
import Testing
@testable import MacCrabAgentKit

@Suite("Signed System Extension rule synchronization", .serialized)
struct BundledRuleSynchronizerTests {
    private enum InjectedFailure: Error { case publication }

    private let uid = geteuid()

    private func fixture() throws -> (root: URL, bundled: URL, installed: URL) {
        let root = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("maccrab-bundled-rules-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        try chmod(root, 0o700)
        return (
            root,
            root.appendingPathComponent("bundled", isDirectory: true),
            root.appendingPathComponent("compiled_rules", isDirectory: true)
        )
    }

    private func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private func makeCorpus(
        at root: URL,
        version: String,
        rules: [String: Data] = ["rules/example.json": Data("{\"rule\":1}\n".utf8)]
    ) throws {
        if FileManager.default.fileExists(atPath: root.path) {
            try FileManager.default.removeItem(at: root)
        }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        var hashes: [String: String] = [:]
        for (relative, data) in rules {
            let file = root.appendingPathComponent(relative)
            try FileManager.default.createDirectory(
                at: file.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            try data.write(to: file)
            hashes[relative] = sha256(data)
        }
        let manifest: [String: Any] = [
            "schema_version": 1,
            "bundle_version": version,
            "hashes": hashes,
        ]
        let manifestData = try JSONSerialization.data(
            withJSONObject: manifest,
            options: [.prettyPrinted, .sortedKeys]
        )
        try manifestData.write(to: root.appendingPathComponent("manifest.json"))
        try Data("\(version)\n".utf8).write(to: root.appendingPathComponent(".bundle_version"))
        try canonicalize(root)
    }

    private func canonicalize(_ root: URL) throws {
        let fm = FileManager.default
        guard let enumerator = fm.enumerator(at: root, includingPropertiesForKeys: nil) else {
            throw CocoaError(.fileReadUnknown)
        }
        try chmod(root, 0o755)
        for case let child as URL in enumerator {
            var metadata = stat()
            guard child.path.withCString({ lstat($0, &metadata) }) == 0 else {
                throw POSIXError(.EIO)
            }
            if (metadata.st_mode & S_IFMT) == S_IFDIR {
                try chmod(child, 0o755)
            } else if (metadata.st_mode & S_IFMT) == S_IFREG {
                try chmod(child, 0o644)
            }
        }
    }

    private func chmod(_ url: URL, _ mode: mode_t) throws {
        guard url.path.withCString({ Darwin.chmod($0, mode) }) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
    }

    private func contents(_ url: URL) throws -> String {
        try String(contentsOf: url, encoding: .utf8)
    }

    private func mode(_ url: URL) throws -> mode_t {
        var metadata = stat()
        guard url.path.withCString({ lstat($0, &metadata) }) == 0 else {
            throw POSIXError(.EIO)
        }
        return metadata.st_mode & mode_t(0o777)
    }

    private func existsWithoutFollowing(_ url: URL) -> Bool {
        var metadata = stat()
        return url.path.withCString { lstat($0, &metadata) } == 0
    }

    private func createSparseFile(at url: URL, size: off_t) throws {
        let descriptor = url.path.withCString {
            Darwin.open($0, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o644)
        }
        guard descriptor >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        defer { Darwin.close(descriptor) }
        guard Darwin.ftruncate(descriptor, size) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
    }

    private func addWritableACL(to url: URL) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/chmod")
        process.arguments = ["+a", "everyone allow write", url.path]
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw POSIXError(.EPERM)
        }
    }

    private func expectBundledFailure(_ outcome: BundledRuleSyncOutcome) {
        guard case .failed(_, let bundledTampered, _, _) = outcome else {
            Issue.record("expected bundled-corpus failure, got \(outcome)")
            return
        }
        #expect(bundledTampered)
    }

    @Test("System Extension trust is pinned to Developer ID Application")
    func developerIDApplicationRequirementIsCompleteAndParsable() {
        let requirement = BundledRuleSynchronizer.systemExtensionDesignatedRequirement
        #expect(requirement.contains("identifier \"com.maccrab.agent\""))
        #expect(requirement.contains("certificate 1[field.1.2.840.113635.100.6.2.6] exists"))
        #expect(requirement.contains("certificate leaf[field.1.2.840.113635.100.6.1.13] exists"))
        #expect(requirement.contains("certificate leaf[subject.OU] = \"79S425CW99\""))

        var parsed: SecRequirement?
        #expect(SecRequirementCreateWithString(
            requirement as CFString,
            [],
            &parsed
        ) == errSecSuccess)
        #expect(parsed != nil)
    }

    @Test("First install publishes an exact canonical corpus")
    func firstInstall() throws {
        let f = try fixture()
        defer { try? FileManager.default.removeItem(at: f.root) }
        try makeCorpus(at: f.bundled, version: "2.0")

        let manifestData = try Data(
            contentsOf: f.bundled.appendingPathComponent("manifest.json")
        )
        let observation = BundledRuleSynchronizer.synchronizeObserved(
            bundledDirectory: f.bundled,
            installedDirectory: f.installed,
            requiredOwnerUID: uid
        )
        let outcome = observation.outcome

        #expect(outcome == .installed(version: "2.0"))
        #expect(observation.installedCorpus?.version == "2.0")
        #expect(observation.installedCorpus?.manifestSHA256 ==
            sha256(manifestData))
        #expect(observation.installedCorpus?.manifestHashEntryCount == 1)
        #expect(try contents(f.installed.appendingPathComponent(".bundle_version")) == "2.0\n")
        #expect(try mode(f.installed) == 0o755)
        #expect(try mode(f.installed.appendingPathComponent("rules/example.json")) == 0o644)
    }

    @Test("An exact canonical corpus is unchanged, including its inode")
    func unchanged() throws {
        let f = try fixture()
        defer { try? FileManager.default.removeItem(at: f.root) }
        try makeCorpus(at: f.bundled, version: "2.0")
        _ = BundledRuleSynchronizer.synchronize(
            bundledDirectory: f.bundled,
            installedDirectory: f.installed,
            requiredOwnerUID: uid
        )
        var before = stat()
        #expect(f.installed.path.withCString { lstat($0, &before) } == 0)

        let outcome = BundledRuleSynchronizer.synchronize(
            bundledDirectory: f.bundled,
            installedDirectory: f.installed,
            requiredOwnerUID: uid
        )
        var after = stat()
        #expect(f.installed.path.withCString { lstat($0, &after) } == 0)

        #expect(outcome == .unchanged(version: "2.0"))
        #expect(before.st_ino == after.st_ino)
    }

    @Test("Unchanged boot reaps a crash-retained rollback stage")
    func unchangedReapsCrashRecoveryStage() throws {
        let f = try fixture()
        defer { try? FileManager.default.removeItem(at: f.root) }
        try makeCorpus(at: f.bundled, version: "2.0")
        try makeCorpus(at: f.installed, version: "2.0")
        let stale = f.root.appendingPathComponent(
            ".compiled_rules.stage.11111111-2222-3333-4444-555555555555",
            isDirectory: true
        )
        try makeCorpus(at: stale, version: "1.0")

        let outcome = BundledRuleSynchronizer.synchronize(
            bundledDirectory: f.bundled,
            installedDirectory: f.installed,
            requiredOwnerUID: uid
        )

        #expect(outcome == .unchanged(version: "2.0"))
        #expect(!existsWithoutFollowing(stale))
    }

    @Test("Successful replacement reaps older crash recovery stages")
    func successfulReplacementReapsCrashRecoveryStages() throws {
        let f = try fixture()
        defer { try? FileManager.default.removeItem(at: f.root) }
        try makeCorpus(at: f.bundled, version: "2.0")
        try makeCorpus(at: f.installed, version: "1.0")
        let stale = f.root.appendingPathComponent(
            ".compiled_rules.stage.AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
            isDirectory: true
        )
        try makeCorpus(at: stale, version: "0.9")

        let outcome = BundledRuleSynchronizer.synchronize(
            bundledDirectory: f.bundled,
            installedDirectory: f.installed,
            requiredOwnerUID: uid
        )

        #expect(outcome == .installed(version: "2.0"))
        #expect(!existsWithoutFollowing(stale))
        let recoveryStages = try FileManager.default.contentsOfDirectory(atPath: f.root.path)
            .filter { $0.hasPrefix(".compiled_rules.stage.") }
        #expect(recoveryStages.isEmpty)
    }

    @Test("A recovery stage survives until canonical install matches signed bundle")
    func recoveryStageSurvivesFailedRepair() throws {
        let f = try fixture()
        defer { try? FileManager.default.removeItem(at: f.root) }
        try makeCorpus(at: f.bundled, version: "2.0")
        try makeCorpus(at: f.installed, version: "1.0")
        let stale = f.root.appendingPathComponent(
            ".compiled_rules.stage.01234567-89AB-CDEF-0123-456789ABCDEF",
            isDirectory: true
        )
        try makeCorpus(at: stale, version: "0.9")

        let outcome = BundledRuleSynchronizer.synchronize(
            bundledDirectory: f.bundled,
            installedDirectory: f.installed,
            requiredOwnerUID: uid,
            replacingDirectoryWith: { _, _, _ in throw InjectedFailure.publication }
        )

        guard case .failed(let reason, false, false, false) = outcome else {
            Issue.record("expected publication failure while canonical corpus mismatches")
            return
        }
        #expect(reason.contains("atomic publication"))
        #expect(existsWithoutFollowing(stale))
        #expect(try contents(f.installed.appendingPathComponent(".bundle_version")) == "1.0\n")
    }

    @Test("Recovery cleanup rejects lookalikes, non-directories, insecure carriers and symlinks")
    func recoveryCleanupAdversarialNamesAndCarriers() throws {
        let f = try fixture()
        defer { try? FileManager.default.removeItem(at: f.root) }
        try makeCorpus(at: f.bundled, version: "2.0")
        try makeCorpus(at: f.installed, version: "2.0")

        let malformed = f.root.appendingPathComponent(
            ".compiled_rules.stage.not-a-uuid",
            isDirectory: true
        )
        try FileManager.default.createDirectory(at: malformed, withIntermediateDirectories: false)
        try chmod(malformed, 0o755)

        let lowercase = f.root.appendingPathComponent(
            ".compiled_rules.stage.aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            isDirectory: true
        )
        try FileManager.default.createDirectory(at: lowercase, withIntermediateDirectories: false)
        try chmod(lowercase, 0o755)

        let regularFile = f.root.appendingPathComponent(
            ".compiled_rules.stage.10000000-2000-3000-4000-500000000000"
        )
        try Data("do not remove\n".utf8).write(to: regularFile)
        try chmod(regularFile, 0o644)

        let insecureDirectory = f.root.appendingPathComponent(
            ".compiled_rules.stage.60000000-7000-8000-9000-A00000000000",
            isDirectory: true
        )
        try FileManager.default.createDirectory(
            at: insecureDirectory,
            withIntermediateDirectories: false
        )
        try chmod(insecureDirectory, 0o777)

        let outside = f.root.appendingPathComponent("outside", isDirectory: true)
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: false)
        try chmod(outside, 0o755)
        let sentinel = outside.appendingPathComponent("sentinel")
        try Data("outside survives\n".utf8).write(to: sentinel)
        let symlink = f.root.appendingPathComponent(
            ".compiled_rules.stage.B0000000-C000-D000-E000-F00000000000"
        )
        #expect(symlink.path.withCString { destination in
            outside.path.withCString { source in Darwin.symlink(source, destination) }
        } == 0)

        // A real eligible stage may itself contain a symlink after a crash or
        // privileged mutation. Cleanup may remove that stage, but must unlink
        // the child rather than recurse into its target.
        let stageWithInnerSymlink = f.root.appendingPathComponent(
            ".compiled_rules.stage.D0000000-E000-F000-A000-B00000000000",
            isDirectory: true
        )
        try FileManager.default.createDirectory(
            at: stageWithInnerSymlink,
            withIntermediateDirectories: false
        )
        try chmod(stageWithInnerSymlink, 0o755)
        let innerSymlink = stageWithInnerSymlink.appendingPathComponent("outside-link")
        #expect(innerSymlink.path.withCString { destination in
            outside.path.withCString { source in Darwin.symlink(source, destination) }
        } == 0)

        let holder = f.root.appendingPathComponent("holder", isDirectory: true)
        try FileManager.default.createDirectory(at: holder, withIntermediateDirectories: false)
        try chmod(holder, 0o755)
        let nested = holder.appendingPathComponent(
            ".compiled_rules.stage.C0000000-D000-E000-F000-A00000000000",
            isDirectory: true
        )
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: false)
        try chmod(nested, 0o755)

        let outcome = BundledRuleSynchronizer.synchronize(
            bundledDirectory: f.bundled,
            installedDirectory: f.installed,
            requiredOwnerUID: uid
        )

        #expect(outcome == .unchanged(version: "2.0"))
        for retained in [malformed, lowercase, regularFile, insecureDirectory, symlink, nested] {
            #expect(existsWithoutFollowing(retained), "unexpected cleanup of \(retained.lastPathComponent)")
        }
        #expect(!existsWithoutFollowing(stageWithInnerSymlink))
        #expect(try contents(sentinel) == "outside survives\n")
    }

    @Test("Matching bytes with owner-only modes are healed for GUI/CLI readers")
    func unreadableModesAreHealed() throws {
        let f = try fixture()
        defer { try? FileManager.default.removeItem(at: f.root) }
        try makeCorpus(at: f.bundled, version: "2.0")
        try makeCorpus(at: f.installed, version: "2.0")
        try chmod(f.installed, 0o700)
        try chmod(f.installed.appendingPathComponent("rules"), 0o700)
        try chmod(f.installed.appendingPathComponent("rules/example.json"), 0o600)
        try chmod(f.installed.appendingPathComponent("manifest.json"), 0o600)
        try chmod(f.installed.appendingPathComponent(".bundle_version"), 0o600)

        let outcome = BundledRuleSynchronizer.synchronize(
            bundledDirectory: f.bundled,
            installedDirectory: f.installed,
            requiredOwnerUID: uid
        )

        #expect(outcome == .installed(version: "2.0"))
        #expect(try mode(f.installed) == 0o755)
        #expect(try mode(f.installed.appendingPathComponent("rules/example.json")) == 0o644)
    }

    @Test("Manifest identity, not version text alone, decides replacement")
    func sameVersionDifferentManifestUpdates() throws {
        let f = try fixture()
        defer { try? FileManager.default.removeItem(at: f.root) }
        try makeCorpus(
            at: f.bundled,
            version: "2.0",
            rules: ["rules/example.json": Data("new\n".utf8)]
        )
        try makeCorpus(
            at: f.installed,
            version: "2.0",
            rules: ["rules/example.json": Data("old\n".utf8)]
        )

        let outcome = BundledRuleSynchronizer.synchronize(
            bundledDirectory: f.bundled,
            installedDirectory: f.installed,
            requiredOwnerUID: uid
        )

        #expect(outcome == .installed(version: "2.0"))
        #expect(try contents(f.installed.appendingPathComponent("rules/example.json")) == "new\n")
    }

    @Test("Installed hash tampering self-heals from the signed source")
    func installedTamperHeals() throws {
        let f = try fixture()
        defer { try? FileManager.default.removeItem(at: f.root) }
        try makeCorpus(at: f.bundled, version: "2.0")
        try makeCorpus(at: f.installed, version: "1.0")
        try Data("tampered\n".utf8).write(
            to: f.installed.appendingPathComponent("rules/example.json")
        )
        try chmod(f.installed.appendingPathComponent("rules/example.json"), 0o644)

        let outcome = BundledRuleSynchronizer.synchronize(
            bundledDirectory: f.bundled,
            installedDirectory: f.installed,
            requiredOwnerUID: uid
        )

        #expect(outcome == .installed(version: "2.0"))
        #expect(try contents(f.installed.appendingPathComponent("rules/example.json")) == "{\"rule\":1}\n")
    }

    @Test("Runtime rule subdirectories survive only after recursive validation")
    func runtimeDirectoriesArePreserved() throws {
        let f = try fixture()
        defer { try? FileManager.default.removeItem(at: f.root) }
        try makeCorpus(at: f.bundled, version: "2.0")
        try makeCorpus(at: f.installed, version: "1.0")
        let pushed = f.installed.appendingPathComponent("pushed", isDirectory: true)
        try FileManager.default.createDirectory(at: pushed, withIntermediateDirectories: false)
        try Data("runtime\n".utf8).write(to: pushed.appendingPathComponent("operator.json"))
        try canonicalize(pushed)

        let outcome = BundledRuleSynchronizer.synchronize(
            bundledDirectory: f.bundled,
            installedDirectory: f.installed,
            requiredOwnerUID: uid
        )

        #expect(outcome == .installed(version: "2.0"))
        #expect(try contents(f.installed.appendingPathComponent("pushed/operator.json")) == "runtime\n")
    }

    @Test("Symlinked runtime data fails closed and leaves last-known-good intact")
    func invalidRuntimeDirectoryFailsClosed() throws {
        let f = try fixture()
        defer { try? FileManager.default.removeItem(at: f.root) }
        try makeCorpus(at: f.bundled, version: "2.0")
        try makeCorpus(at: f.installed, version: "1.0")
        let pushed = f.installed.appendingPathComponent("pushed", isDirectory: true)
        try FileManager.default.createDirectory(at: pushed, withIntermediateDirectories: false)
        let link = pushed.appendingPathComponent("operator.json")
        #expect(link.path.withCString { Darwin.symlink("../manifest.json", $0) } == 0)

        let outcome = BundledRuleSynchronizer.synchronize(
            bundledDirectory: f.bundled,
            installedDirectory: f.installed,
            requiredOwnerUID: uid
        )

        guard case .failed(_, _, let installedTampered, _) = outcome else {
            Issue.record("expected invalid runtime tree to fail")
            return
        }
        #expect(installedTampered)
        #expect(try contents(f.installed.appendingPathComponent(".bundle_version")) == "1.0\n")
    }

    @Test("Unsafe paths, links, special files and extras are rejected as bundled tamper")
    func adversarialBundledTreesFailClosed() throws {
        typealias Mutation = (URL) throws -> Void
        let mutations: [Mutation] = [
            { root in
                let data = Data("escape\n".utf8)
                let manifest: [String: Any] = [
                    "schema_version": 1,
                    "bundle_version": "2.0",
                    "hashes": ["../escape.json": self.sha256(data)],
                ]
                try JSONSerialization.data(withJSONObject: manifest, options: [.sortedKeys])
                    .write(to: root.appendingPathComponent("manifest.json"))
                try self.chmod(root.appendingPathComponent("manifest.json"), 0o644)
            },
            { root in
                let rule = root.appendingPathComponent("rules/example.json")
                try FileManager.default.removeItem(at: rule)
                #expect(rule.path.withCString { Darwin.symlink("../.bundle_version", $0) } == 0)
            },
            { root in
                let rule = root.appendingPathComponent("rules/example.json")
                try FileManager.default.removeItem(at: rule)
                let marker = root.appendingPathComponent(".bundle_version")
                #expect(marker.path.withCString { source in
                    rule.path.withCString { destination in Darwin.link(source, destination) }
                } == 0)
            },
            { root in
                let rule = root.appendingPathComponent("rules/example.json")
                try FileManager.default.removeItem(at: rule)
                #expect(rule.path.withCString { Darwin.mkfifo($0, 0o644) } == 0)
            },
            { root in
                let extra = root.appendingPathComponent("unmanifested.json")
                try Data("extra\n".utf8).write(to: extra)
                try self.chmod(extra, 0o644)
            },
        ]

        for mutate in mutations {
            let f = try fixture()
            defer { try? FileManager.default.removeItem(at: f.root) }
            try makeCorpus(at: f.bundled, version: "2.0")
            try makeCorpus(at: f.installed, version: "1.0")
            try mutate(f.bundled)

            let outcome = BundledRuleSynchronizer.synchronize(
                bundledDirectory: f.bundled,
                installedDirectory: f.installed,
                requiredOwnerUID: uid
            )
            expectBundledFailure(outcome)
            #expect(try contents(f.installed.appendingPathComponent(".bundle_version")) == "1.0\n")
        }
    }

    @Test("Staging mutation and publication errors never replace last-known-good")
    func transactionFailuresRetainOldCorpus() throws {
        let f = try fixture()
        defer { try? FileManager.default.removeItem(at: f.root) }
        try makeCorpus(at: f.bundled, version: "2.0")
        try makeCorpus(at: f.installed, version: "1.0")

        let stagingFailure = BundledRuleSynchronizer.synchronize(
            bundledDirectory: f.bundled,
            installedDirectory: f.installed,
            requiredOwnerUID: uid,
            afterStaging: { staged in
                try Data("changed after verification copy\n".utf8).write(
                    to: staged.appendingPathComponent("rules/example.json")
                )
            }
        )
        guard case .failed(let reason, _, _, _) = stagingFailure else {
            Issue.record("expected staging mutation failure")
            return
        }
        #expect(reason.contains("staging"))
        #expect(try contents(f.installed.appendingPathComponent(".bundle_version")) == "1.0\n")

        let publicationFailure = BundledRuleSynchronizer.synchronize(
            bundledDirectory: f.bundled,
            installedDirectory: f.installed,
            requiredOwnerUID: uid,
            replacingDirectoryWith: { _, _, _ in throw InjectedFailure.publication }
        )
        guard case .failed(let publishReason, _, _, _) = publicationFailure else {
            Issue.record("expected publication failure")
            return
        }
        #expect(publishReason.contains("atomic publication"))
        #expect(BundledRuleSynchronizer.shouldAbortBoot(after: publicationFailure))
        #expect(try contents(f.installed.appendingPathComponent(".bundle_version")) == "1.0\n")
    }

    @Test("Post-publication corruption swaps the prior corpus back")
    func postPublicationVerificationRollsBack() throws {
        let f = try fixture()
        defer { try? FileManager.default.removeItem(at: f.root) }
        try makeCorpus(at: f.bundled, version: "2.0")
        try makeCorpus(at: f.installed, version: "1.0")

        let outcome = BundledRuleSynchronizer.synchronize(
            bundledDirectory: f.bundled,
            installedDirectory: f.installed,
            requiredOwnerUID: uid,
            replacingDirectoryWith: { staged, destination, exists in
                try BundledRuleSynchronizer.replaceDirectoryAtomically(
                    staged: staged,
                    destination: destination,
                    destinationExists: exists
                )
                try Data("post-publish corruption\n".utf8).write(
                    to: destination.appendingPathComponent("rules/example.json")
                )
                try self.chmod(destination.appendingPathComponent("rules/example.json"), 0o644)
            }
        )

        guard case .failed(let reason, _, _, _) = outcome else {
            Issue.record("expected post-publication verification failure")
            return
        }
        #expect(reason.contains("rolled back"))
        #expect(try contents(f.installed.appendingPathComponent(".bundle_version")) == "1.0\n")
        #expect(try contents(f.installed.appendingPathComponent("rules/example.json")) == "{\"rule\":1}\n")
    }

    @Test("Source trust failure always aborts even with an internally consistent installed corpus")
    func sourceTrustFailureAlwaysAborts() throws {
        let valid = try fixture()
        defer { try? FileManager.default.removeItem(at: valid.root) }
        try makeCorpus(at: valid.bundled, version: "2.0")
        try makeCorpus(at: valid.installed, version: "2.0")
        try FileManager.default.removeItem(
            at: valid.bundled.appendingPathComponent("manifest.json")
        )

        let sourceFailure = BundledRuleSynchronizer.synchronize(
            bundledDirectory: valid.bundled,
            installedDirectory: valid.installed,
            requiredOwnerUID: uid
        )
        guard case .failed(_, true, false, let installedVerified) = sourceFailure else {
            Issue.record("expected bundled failure with an internally valid installed corpus")
            return
        }
        #expect(!installedVerified)
        #expect(BundledRuleSynchronizer.shouldAbortBoot(after: sourceFailure))

        let empty = try fixture()
        defer { try? FileManager.default.removeItem(at: empty.root) }
        try makeCorpus(at: empty.bundled, version: "2.0")
        try FileManager.default.removeItem(
            at: empty.bundled.appendingPathComponent("manifest.json")
        )
        try FileManager.default.createDirectory(
            at: empty.installed,
            withIntermediateDirectories: false
        )
        try chmod(empty.installed, 0o755)

        let firstInstallFailure = BundledRuleSynchronizer.synchronize(
            bundledDirectory: empty.bundled,
            installedDirectory: empty.installed,
            requiredOwnerUID: uid
        )
        guard case .failed(_, true, true, let installedVerified) = firstInstallFailure else {
            Issue.record("expected source + empty installed corpus failure")
            return
        }
        #expect(!installedVerified)
        #expect(BundledRuleSynchronizer.shouldAbortBoot(after: firstInstallFailure))
    }

    @Test("Fallback policy accepts only an installed corpus matched to an authenticated source")
    func fallbackPolicyRequiresAuthenticatedManifestMatch() {
        let matched = BundledRuleSyncOutcome.failed(
            reason: "publication unavailable",
            bundledTampered: false,
            installedTampered: false,
            installedCorpusVerified: true
        )
        #expect(!BundledRuleSynchronizer.shouldAbortBoot(after: matched))

        let sourceUntrusted = BundledRuleSyncOutcome.failed(
            reason: "source seal invalid",
            bundledTampered: true,
            installedTampered: false,
            installedCorpusVerified: true
        )
        #expect(BundledRuleSynchronizer.shouldAbortBoot(after: sourceUntrusted))

        let unmatched = BundledRuleSyncOutcome.failed(
            reason: "publication unavailable",
            bundledTampered: false,
            installedTampered: false,
            installedCorpusVerified: false
        )
        #expect(BundledRuleSynchronizer.shouldAbortBoot(after: unmatched))
    }

    @Test("Extended ACLs are never accepted as secure POSIX-only rule paths")
    func extendedACLIsRejected() throws {
        let f = try fixture()
        defer { try? FileManager.default.removeItem(at: f.root) }
        try makeCorpus(at: f.bundled, version: "2.0")
        try makeCorpus(at: f.installed, version: "1.0")
        try addWritableACL(to: f.bundled.appendingPathComponent("rules/example.json"))

        let outcome = BundledRuleSynchronizer.synchronize(
            bundledDirectory: f.bundled,
            installedDirectory: f.installed,
            requiredOwnerUID: uid
        )
        expectBundledFailure(outcome)
        #expect(BundledRuleSynchronizer.shouldAbortBoot(after: outcome))
        #expect(try contents(f.installed.appendingPathComponent(".bundle_version")) == "1.0\n")
    }

    @Test("Append/immutable BSD flags are rejected before copy or publication")
    func unsafeBSDFlagsAreRejected() throws {
        let f = try fixture()
        let flagged = f.bundled.appendingPathComponent("rules/example.json")
        defer {
            _ = flagged.path.withCString { Darwin.chflags($0, 0) }
            try? FileManager.default.removeItem(at: f.root)
        }
        try makeCorpus(at: f.bundled, version: "2.0")
        try makeCorpus(at: f.installed, version: "1.0")
        #expect(flagged.path.withCString {
            Darwin.chflags($0, UInt32(UF_APPEND))
        } == 0)

        let outcome = BundledRuleSynchronizer.synchronize(
            bundledDirectory: f.bundled,
            installedDirectory: f.installed,
            requiredOwnerUID: uid
        )
        expectBundledFailure(outcome)
        #expect(BundledRuleSynchronizer.shouldAbortBoot(after: outcome))
        #expect(try contents(f.installed.appendingPathComponent(".bundle_version")) == "1.0\n")
    }

    @Test("Runtime preservation is bounded by count, per-file and aggregate bytes")
    func runtimePreservationBoundsPreventCopyAmplification() throws {
        enum Variant { case count, perFile, aggregate }
        for variant in [Variant.count, .perFile, .aggregate] {
            let f = try fixture()
            defer { try? FileManager.default.removeItem(at: f.root) }
            try makeCorpus(at: f.bundled, version: "2.0")
            try makeCorpus(at: f.installed, version: "1.0")
            let pushed = f.installed.appendingPathComponent("pushed", isDirectory: true)
            try FileManager.default.createDirectory(
                at: pushed,
                withIntermediateDirectories: false
            )

            switch variant {
            case .count:
                for index in 0...BundledRuleSynchronizer.maximumRuntimeEntries {
                    try Data().write(
                        to: pushed.appendingPathComponent("rule-\(index).json")
                    )
                }
            case .perFile:
                try createSparseFile(
                    at: pushed.appendingPathComponent("oversized.json"),
                    size: BundledRuleSynchronizer.maximumRuntimeFileBytes + 1
                )
            case .aggregate:
                let fileCount = Int(
                    BundledRuleSynchronizer.maximumRuntimeAggregateBytes
                        / BundledRuleSynchronizer.maximumRuntimeFileBytes
                ) + 1
                for index in 0..<fileCount {
                    try createSparseFile(
                        at: pushed.appendingPathComponent("chunk-\(index).json"),
                        size: BundledRuleSynchronizer.maximumRuntimeFileBytes
                    )
                }
            }
            try canonicalize(pushed)

            let outcome = BundledRuleSynchronizer.synchronize(
                bundledDirectory: f.bundled,
                installedDirectory: f.installed,
                requiredOwnerUID: uid
            )
            guard case .failed(_, _, true, false) = outcome else {
                Issue.record("expected bounded runtime-tree rejection for \(variant)")
                continue
            }
            #expect(BundledRuleSynchronizer.shouldAbortBoot(after: outcome))
            #expect(try contents(f.installed.appendingPathComponent(".bundle_version")) == "1.0\n")
            let stages = try FileManager.default.contentsOfDirectory(atPath: f.root.path)
                .filter { $0.hasPrefix(".compiled_rules.stage.") }
            #expect(stages.isEmpty)
        }
    }

    @Test("Signed corpora are bounded before manifest hashing or publication")
    func signedCorpusAggregateBoundPreventsBuildAmplification() throws {
        let f = try fixture()
        defer { try? FileManager.default.removeItem(at: f.root) }
        try makeCorpus(at: f.bundled, version: "2.0")
        try makeCorpus(at: f.installed, version: "1.0")
        let rules = f.bundled.appendingPathComponent("rules", isDirectory: true)
        for index in 0..<17 {
            try createSparseFile(
                at: rules.appendingPathComponent("oversized-total-\(index).json"),
                size: 4 * 1_024 * 1_024
            )
        }

        let outcome = BundledRuleSynchronizer.synchronize(
            bundledDirectory: f.bundled,
            installedDirectory: f.installed,
            requiredOwnerUID: uid
        )
        guard case .failed(let reason, true, false, false) = outcome else {
            Issue.record("expected oversized signed corpus to fail as bundled tamper")
            return
        }
        #expect(reason.contains("\(BundledRuleSynchronizer.maximumSignedCorpusAggregateBytes) bytes"))
        #expect(BundledRuleSynchronizer.shouldAbortBoot(after: outcome))
        #expect(try contents(f.installed.appendingPathComponent(".bundle_version")) == "1.0\n")
    }
}
