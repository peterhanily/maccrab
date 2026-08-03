import CryptoKit
import Darwin
import Foundation
import Testing
@testable import MacCrabCore

@Suite("Bounded atomic trace archive packaging")
struct SafeTraceArchivePackagerTests {
    private func scratch(_ tag: String) throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(tag)-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        return root
    }

    private func sourceBundle(under root: URL) throws -> URL {
        let bundle = root.appendingPathComponent("source.maccrabtrace", isDirectory: true)
        try FileManager.default.createDirectory(
            at: bundle,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        try Data("manifest".utf8).write(
            to: bundle.appendingPathComponent("manifest.json")
        )
        return bundle
    }

    private func options(maximum: UInt64 = 1_024 * 1_024) -> SafeTraceArchivePackager.Options {
        var limits = SafeTraceArchiveExtractor.Limits.default
        limits.maxCompressedBytes = maximum
        limits.freeSpaceReserveBytes = 0
        return .init(limits: limits, archiveToolTimeoutSeconds: 2)
    }

    private static func successfulProcess(
        _ bytes: Data
    ) -> BoundedPrivilegedProcessRunner.Result {
        .init(
            terminationStatus: 0,
            output: bytes,
            timedOut: false,
            outputLimitExceeded: false
        )
    }

    private func producer(
        _ bytes: Data
    ) -> (URL, Int, TimeInterval) -> BoundedPrivilegedProcessRunner.Result? {
        { _, _, _ in Self.successfulProcess(bytes) }
    }

    @Test("captured bytes are exclusively published and hashed without reopening tar output")
    func exactBytesAndSidecar() throws {
        let root = try scratch("safe-packager-exact")
        defer { try? FileManager.default.removeItem(at: root) }
        let bundle = try sourceBundle(under: root)
        let archive = root.appendingPathComponent("result.maccrabtrace.tar.gz")
        let bytes = Data("synthetic bounded archive bytes".utf8)

        let result = try SafeTraceArchivePackager.package(
            bundleAt: bundle,
            archiveAt: archive,
            options: options(),
            testHooks: .init(archiveProducer: producer(bytes))
        )

        let expectedDigest = SHA256.hash(data: bytes)
            .map { String(format: "%02x", $0) }.joined()
        #expect(try Data(contentsOf: archive) == bytes)
        #expect(result.archiveBytes == bytes.count)
        #expect(result.sha256Hex == expectedDigest)
        #expect(result.sidecarURL == URL(fileURLWithPath: archive.path + ".sha256"))
        #expect(result.sidecarWarning == nil)
        let sidecar = try #require(result.sidecarURL)
        #expect(try String(
            contentsOf: sidecar,
            encoding: .utf8
        ) == "\(expectedDigest)  \(archive.lastPathComponent)\n")

        var metadata = stat()
        #expect(lstat(archive.path, &metadata) == 0)
        #expect((metadata.st_mode & S_IFMT) == S_IFREG)
        #expect((metadata.st_mode & 0o777) == 0o600)
        #expect(metadata.st_nlink == 1)
        let debris = try FileManager.default.contentsOfDirectory(atPath: root.path)
            .filter { $0.hasPrefix(".partial-maccrab-archive-") }
        #expect(debris.isEmpty)
    }

    @Test("shipping bsdtar output round-trips through the hardened resolver")
    func realBsdtarRoundTrip() throws {
        let root = try scratch("safe-packager-real-tar")
        defer { try? FileManager.default.removeItem(at: root) }
        let bundle = try sourceBundle(under: root)
        let archive = root.appendingPathComponent("result.maccrabtrace.tar.gz")

        let result = try SafeTraceArchivePackager.package(
            bundleAt: bundle,
            archiveAt: archive,
            options: options()
        )
        #expect(result.archiveBytes > 0)
        #expect(try Data(contentsOf: archive).count == result.archiveBytes)

        let resolution = try SafeTraceBundleResolver.resolve(
            inputAt: archive,
            limits: options().limits
        )
        defer { resolution.cleanup() }
        #expect(try String(
            contentsOf: resolution.bundleDirectory
                .appendingPathComponent("manifest.json"),
            encoding: .utf8
        ) == "manifest")
    }

    @Test("same-uid mutation of the bsdtar staging path is rejected before publication")
    func sameUIDSnapshotMutationCannotBePublished() throws {
        let root = try scratch("safe-packager-same-uid")
        defer { try? FileManager.default.removeItem(at: root) }
        let bundle = try sourceBundle(under: root)
        let archive = root.appendingPathComponent("result.maccrabtrace.tar.gz")

        do {
            _ = try SafeTraceArchivePackager.package(
                bundleAt: bundle,
                archiveAt: archive,
                options: options(),
                testHooks: .init(beforeArchiveTool: { snapshot in
                    try! Data("same-uid-attacker".utf8).write(
                        to: snapshot.appendingPathComponent("manifest.json")
                    )
                })
            )
            Issue.record("same-uid-mutated archive was published")
        } catch let error as SafeTraceArchivePackager.PackagingError {
            guard case .archiveContentMismatch = error else {
                Issue.record("unexpected packaging rejection: \(error)")
                return
            }
        }
        #expect(!FileManager.default.fileExists(atPath: archive.path))
        #expect(!FileManager.default.fileExists(atPath: archive.path + ".sha256"))
    }

    @Test("preplanted archive symlink is refused without touching its target")
    func preplantedArchiveSymlink() throws {
        let root = try scratch("safe-packager-prelink")
        defer { try? FileManager.default.removeItem(at: root) }
        let bundle = try sourceBundle(under: root)
        let outside = root.appendingPathComponent("outside")
        try Data("unchanged".utf8).write(to: outside)
        let archive = root.appendingPathComponent("result.maccrabtrace.tar.gz")
        try FileManager.default.createSymbolicLink(
            atPath: archive.path,
            withDestinationPath: outside.path
        )

        #expect(throws: SafeTraceArchivePackager.PackagingError.self) {
            _ = try SafeTraceArchivePackager.package(
                bundleAt: bundle,
                archiveAt: archive,
                options: options(),
                testHooks: .init(
                    archiveProducer: producer(Data("attacker".utf8))
                )
            )
        }
        #expect(try String(contentsOf: outside, encoding: .utf8) == "unchanged")
    }

    @Test("a destination symlink raced after preflight loses to RENAME_EXCL")
    func racedArchiveSymlink() throws {
        let root = try scratch("safe-packager-racelink")
        defer { try? FileManager.default.removeItem(at: root) }
        let bundle = try sourceBundle(under: root)
        let outside = root.appendingPathComponent("outside")
        try Data("unchanged".utf8).write(to: outside)
        let archive = root.appendingPathComponent("result.maccrabtrace.tar.gz")

        #expect(throws: SafeTraceArchivePackager.PackagingError.self) {
            _ = try SafeTraceArchivePackager.package(
                bundleAt: bundle,
                archiveAt: archive,
                options: options(),
                testHooks: .init(
                    archiveProducer: producer(Data("archive".utf8)),
                    beforeArchiveRename: { _, target in
                        try! FileManager.default.createSymbolicLink(
                            atPath: target.path,
                            withDestinationPath: outside.path
                        )
                    }
                )
            )
        }
        #expect(try String(contentsOf: outside, encoding: .utf8) == "unchanged")
        #expect(
            try FileManager.default.destinationOfSymbolicLink(
                atPath: archive.path
            ) == outside.path
        )
    }

    @Test("widened temporary permissions are rejected before publication")
    func widenedTemporaryPermissions() throws {
        let root = try scratch("safe-packager-mode-race")
        defer { try? FileManager.default.removeItem(at: root) }
        let bundle = try sourceBundle(under: root)
        let archive = root.appendingPathComponent("result.maccrabtrace.tar.gz")

        #expect(throws: SafeTraceArchivePackager.PackagingError.self) {
            _ = try SafeTraceArchivePackager.package(
                bundleAt: bundle,
                archiveAt: archive,
                options: options(),
                testHooks: .init(
                    archiveProducer: producer(Data("archive".utf8)),
                    beforeArchiveRename: { temporary, _ in
                        try! FileManager.default.setAttributes(
                            [.posixPermissions: NSNumber(value: 0o644)],
                            ofItemAtPath: temporary.path
                        )
                    }
                )
            )
        }
        #expect(!FileManager.default.fileExists(atPath: archive.path))
    }

    @Test("a replaced destination parent cannot redirect archive publication")
    func replacedArchiveParent() throws {
        let root = try scratch("safe-packager-parent-race")
        defer { try? FileManager.default.removeItem(at: root) }
        let bundle = try sourceBundle(under: root)
        let output = root.appendingPathComponent("output", isDirectory: true)
        let outside = root.appendingPathComponent("outside", isDirectory: true)
        try FileManager.default.createDirectory(
            at: output,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        try FileManager.default.createDirectory(
            at: outside,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let detached = root.appendingPathComponent("detached", isDirectory: true)
        let archive = output.appendingPathComponent("result.maccrabtrace.tar.gz")

        #expect(throws: SafeTraceArchivePackager.PackagingError.self) {
            _ = try SafeTraceArchivePackager.package(
                bundleAt: bundle,
                archiveAt: archive,
                options: options(),
                testHooks: .init(
                    archiveProducer: producer(Data("archive".utf8)),
                    beforeArchiveRename: { _, _ in
                        try! FileManager.default.moveItem(at: output, to: detached)
                        try! FileManager.default.createSymbolicLink(
                            atPath: output.path,
                            withDestinationPath: outside.path
                        )
                    }
                )
            )
        }
        #expect(!FileManager.default.fileExists(
            atPath: outside.appendingPathComponent(archive.lastPathComponent).path
        ))
        let debris = try FileManager.default.contentsOfDirectory(atPath: detached.path)
            .filter { $0.hasPrefix(".partial-maccrab-archive-") }
        #expect(debris.isEmpty)
    }

    @Test("an inherited output ACL cannot expose archive bytes")
    func inheritedOutputACL() throws {
        let root = try scratch("safe-packager-inherited-acl")
        defer { try? FileManager.default.removeItem(at: root) }
        let bundle = try sourceBundle(under: root)
        let chmod = Process()
        chmod.executableURL = URL(fileURLWithPath: "/bin/chmod")
        chmod.arguments = [
            "+a",
            "everyone allow read,search,file_inherit,directory_inherit",
            root.path,
        ]
        try chmod.run()
        chmod.waitUntilExit()
        // Filesystems without macOS extended ACL support cannot inherit one,
        // so there is no ACL boundary to exercise there.
        guard chmod.terminationStatus == 0 else { return }

        let archive = root.appendingPathComponent("result.maccrabtrace.tar.gz")
        #expect(throws: SafeTraceArchivePackager.PackagingError.self) {
            _ = try SafeTraceArchivePackager.package(
                bundleAt: bundle,
                archiveAt: archive,
                options: options(),
                testHooks: .init(
                    archiveProducer: producer(Data("private archive".utf8))
                )
            )
        }
        #expect(!FileManager.default.fileExists(atPath: archive.path))
        let debris = try FileManager.default.contentsOfDirectory(atPath: root.path)
            .filter { $0.hasPrefix(".partial-maccrab-archive-") }
        #expect(debris.isEmpty)
    }

    @Test("a raced or stale sidecar is never overwritten and does not invalidate the archive")
    func occupiedSidecarIsWarning() throws {
        let root = try scratch("safe-packager-sidecar")
        defer { try? FileManager.default.removeItem(at: root) }
        let bundle = try sourceBundle(under: root)
        let archive = root.appendingPathComponent("result.maccrabtrace.tar.gz")
        let sidecar = URL(fileURLWithPath: archive.path + ".sha256")
        try Data("owner-data".utf8).write(to: sidecar)
        let bytes = Data("archive".utf8)

        let result = try SafeTraceArchivePackager.package(
            bundleAt: bundle,
            archiveAt: archive,
            options: options(),
            testHooks: .init(archiveProducer: producer(bytes))
        )
        #expect(try Data(contentsOf: archive) == bytes)
        #expect(result.sidecarURL == nil)
        #expect(result.sidecarWarning != nil)
        #expect(try String(contentsOf: sidecar, encoding: .utf8) == "owner-data")
    }

    @Test("archive parent replacement during sidecar publication is committed failure")
    func archiveParentReplacementIsNotSuccess() throws {
        let root = try scratch("safe-packager-parent-replacement")
        defer { try? FileManager.default.removeItem(at: root) }
        let bundle = try sourceBundle(under: root)
        let output = root.appendingPathComponent("output", isDirectory: true)
        try FileManager.default.createDirectory(
            at: output,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let detached = root.appendingPathComponent("detached", isDirectory: true)
        let archive = output.appendingPathComponent("result.maccrabtrace.tar.gz")

        var observedCommitted = false
        do {
            _ = try SafeTraceArchivePackager.package(
                bundleAt: bundle,
                archiveAt: archive,
                options: options(),
                testHooks: .init(
                    archiveProducer: producer(Data("archive".utf8)),
                    beforeSidecarRename: { _, _ in
                        try! FileManager.default.moveItem(at: output, to: detached)
                        try! FileManager.default.createDirectory(
                            at: output,
                            withIntermediateDirectories: false,
                            attributes: [.posixPermissions: 0o700]
                        )
                    }
                )
            )
        } catch let error as SafeTraceArchivePackager.PackagingError {
            if case .archiveCommitted(let url, _, _) = error {
                observedCommitted = (url == archive)
            }
        }
        #expect(observedCommitted)
        #expect(!FileManager.default.fileExists(atPath: archive.path))
        #expect(FileManager.default.fileExists(
            atPath: detached.appendingPathComponent(archive.lastPathComponent).path
        ))
    }

    @Test("post-rename mutation is reported as committed rather than a missing archive")
    func committedPostflightFailure() throws {
        let root = try scratch("safe-packager-committed")
        defer { try? FileManager.default.removeItem(at: root) }
        let bundle = try sourceBundle(under: root)
        let archive = root.appendingPathComponent("result.maccrabtrace.tar.gz")
        let original = Data("original archive".utf8)
        let expectedDigest = SHA256.hash(data: original)
            .map { String(format: "%02x", $0) }.joined()

        var observedCommitted = false
        do {
            _ = try SafeTraceArchivePackager.package(
                bundleAt: bundle,
                archiveAt: archive,
                options: options(),
                testHooks: .init(
                    archiveProducer: producer(original),
                    afterArchiveRename: { published in
                        try! Data("changed".utf8).write(to: published)
                    }
                )
            )
        } catch let error as SafeTraceArchivePackager.PackagingError {
            if case .archiveCommitted(let url, let digest, _) = error {
                observedCommitted = url == archive && digest == expectedDigest
            }
        }
        #expect(observedCommitted)
        #expect(FileManager.default.fileExists(atPath: archive.path))
    }

    @Test("timeout and compressed-output limit never publish a final leaf")
    func processBounds() throws {
        let root = try scratch("safe-packager-bounds")
        defer { try? FileManager.default.removeItem(at: root) }
        let bundle = try sourceBundle(under: root)

        let timeoutArchive = root.appendingPathComponent("timeout.tar.gz")
        #expect(throws: SafeTraceArchivePackager.PackagingError.self) {
            _ = try SafeTraceArchivePackager.package(
                bundleAt: bundle,
                archiveAt: timeoutArchive,
                options: options(),
                testHooks: .init(archiveProducer: { _, _, _ in
                    .init(
                        terminationStatus: nil,
                        output: Data(),
                        timedOut: true,
                        outputLimitExceeded: false
                    )
                })
            )
        }
        #expect(!FileManager.default.fileExists(atPath: timeoutArchive.path))

        let limitArchive = root.appendingPathComponent("limit.tar.gz")
        #expect(throws: SafeTraceArchivePackager.PackagingError.self) {
            _ = try SafeTraceArchivePackager.package(
                bundleAt: bundle,
                archiveAt: limitArchive,
                options: options(maximum: 4),
                testHooks: .init(archiveProducer: { _, _, _ in
                    .init(
                        terminationStatus: nil,
                        output: Data("part".utf8),
                        timedOut: false,
                        outputLimitExceeded: true
                    )
                })
            )
        }
        #expect(!FileManager.default.fileExists(atPath: limitArchive.path))

        let failedArchive = root.appendingPathComponent("failed.tar.gz")
        var sawStatus = false
        do {
            _ = try SafeTraceArchivePackager.package(
                bundleAt: bundle,
                archiveAt: failedArchive,
                options: options(),
                testHooks: .init(archiveProducer: { _, _, _ in
                    .init(
                        terminationStatus: 7,
                        output: Data(),
                        timedOut: false,
                        outputLimitExceeded: false
                    )
                })
            )
        } catch let error as SafeTraceArchivePackager.PackagingError {
            if case .archiveFailed(status: 7) = error { sawStatus = true }
        }
        #expect(sawStatus)
        #expect(!FileManager.default.fileExists(atPath: failedArchive.path))

        var invalid = options()
        invalid.archiveToolTimeoutSeconds = 0
        #expect(throws: SafeTraceArchivePackager.PackagingError.self) {
            _ = try SafeTraceArchivePackager.package(
                bundleAt: bundle,
                archiveAt: root.appendingPathComponent("invalid.tar.gz"),
                options: invalid,
                testHooks: .init(archiveProducer: producer(Data("unused".utf8)))
            )
        }

        let unsafeName = root.appendingPathComponent("bad\nname.tar.gz")
        var rejectedUnsafeName = false
        do {
            _ = try SafeTraceArchivePackager.package(
                bundleAt: bundle,
                archiveAt: unsafeName,
                options: options(),
                testHooks: .init(archiveProducer: producer(Data("unused".utf8)))
            )
        } catch let error as SafeTraceArchivePackager.PackagingError {
            if case .unsafeDestination = error { rejectedUnsafeName = true }
        }
        #expect(rejectedUnsafeName)
        #expect(!FileManager.default.fileExists(atPath: unsafeName.path))
    }

    @Test("production CLI is pinned to the bounded stdout packager")
    func sourceGuard() throws {
        let repositoryRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let packager = try String(
            contentsOf: repositoryRoot.appendingPathComponent(
                "Sources/MacCrabCore/TraceBundle/SafeTraceArchivePackager.swift"
            ),
            encoding: .utf8
        )
        let command = try String(
            contentsOf: repositoryRoot.appendingPathComponent(
                "Sources/maccrabctl/TraceCommands.swift"
            ),
            encoding: .utf8
        )

        #expect(packager.contains("executable: \"/usr/bin/bsdtar\""))
        #expect(packager.contains("maximumOutputBytes: maximumOutputBytes"))
        #expect(packager.contains("mergeStandardErrorIntoOutput: false"))
        #expect(packager.contains("Darwin.renameatx_np("))
        #expect(packager.contains("UInt32(RENAME_EXCL)"))
        #expect(command.contains("SafeTraceArchivePackager.package("))
        #expect(!command.contains("proc.arguments = [\"-czf\""))
        #expect(!command.contains("ArchiveDigest.writeSidecar("))

        for relativePath in [
            "Sources/MacCrabCore/TraceBundle/SafeTraceArchiveExtractor.swift",
            "Sources/MacCrabCore/TraceBundle/SafeTraceBundleResolver.swift",
            "Sources/MacCrabCore/TraceBundle/SafeTraceArchivePackager.swift",
        ] {
            let source = try String(
                contentsOf: repositoryRoot.appendingPathComponent(relativePath),
                encoding: .utf8
            )
            #expect(source.contains("TraceBundlePrivateFilePolicy"))
            #expect(!source.contains("_ = Darwin.fchmod"))
        }
    }
}
