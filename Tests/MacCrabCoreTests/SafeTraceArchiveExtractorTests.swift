import Darwin
import Foundation
import Testing
@testable import MacCrabCore

@Suite("Trace bundle hostile-archive boundary")
struct SafeTraceArchiveExtractorTests {

    private static let repoRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()

    private func makeScratch() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-archive-boundary-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        return root
    }

    private func createArchive(
        sourceRoot: URL,
        entry: String,
        archive: URL,
        substitutions: [String] = [],
        creationOptions: [String] = []
    ) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/tar")
        process.currentDirectoryURL = sourceRoot
        var arguments = ["-czf", archive.path]
        for substitution in substitutions {
            arguments += ["-s", substitution]
        }
        arguments += creationOptions
        arguments.append(entry)
        process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw NSError(
                domain: "SafeTraceArchiveExtractorTests",
                code: Int(process.terminationStatus),
                userInfo: [NSLocalizedDescriptionKey: "fixture tar creation failed"]
            )
        }
    }

    @Test("A regular bounded archive extracts under a private temporary root")
    func extractsRegularArchive() throws {
        let scratch = try makeScratch()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let source = scratch.appendingPathComponent("source")
        let bundle = source.appendingPathComponent("sample.maccrabtrace")
        try FileManager.default.createDirectory(at: bundle, withIntermediateDirectories: true)
        try Data("{}".utf8).write(to: bundle.appendingPathComponent("manifest.json"))
        let archive = scratch.appendingPathComponent("sample.tar.gz")
        try createArchive(sourceRoot: source, entry: bundle.lastPathComponent, archive: archive)

        let extraction = try SafeTraceArchiveExtractor.extract(archiveAt: archive)
        defer { extraction.cleanup() }

        #expect(extraction.bundleDirectory.lastPathComponent == "sample.maccrabtrace")
        #expect(FileManager.default.fileExists(
            atPath: extraction.bundleDirectory.appendingPathComponent("manifest.json").path
        ))
        var rootInfo = stat()
        #expect(lstat(extraction.temporaryRoot.path, &rootInfo) == 0)
        #expect((rootInfo.st_mode & 0o777) == 0o700)
    }

    @Test("Immutable payload capture preserves archive order, multiple files, and zero-byte files")
    func capturesExactOrderedPayloadBytes() throws {
        let scratch = try makeScratch()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let source = scratch.appendingPathComponent("source")
        let bundle = source.appendingPathComponent("bundle")
        let nested = bundle.appendingPathComponent("nested")
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
        try Data("alpha".utf8).write(to: bundle.appendingPathComponent("a.txt"))
        try Data().write(to: bundle.appendingPathComponent("empty.bin"))
        try Data("omega-long".utf8).write(to: nested.appendingPathComponent("z.txt"))
        let archive = scratch.appendingPathComponent("ordered.tar.gz")
        try createArchive(sourceRoot: source, entry: "bundle", archive: archive)

        var limits = SafeTraceArchiveExtractor.Limits.default
        limits.freeSpaceReserveBytes = 0
        let extraction = try SafeTraceArchiveExtractor.extract(
            archiveData: try Data(contentsOf: archive),
            limits: limits
        )
        defer { extraction.cleanup() }

        #expect(extraction.capturedFiles["a.txt"] == Data("alpha".utf8))
        #expect(extraction.capturedFiles["empty.bin"] == Data())
        #expect(extraction.capturedFiles["nested/z.txt"] == Data("omega-long".utf8))
        #expect(extraction.capturedDirectories == Set(["", "nested"]))
    }

    @Test("Same-size post-extraction mutation cannot replace immutable archive payload bytes")
    func rejectsSameUIDPostExtractionMutation() throws {
        let scratch = try makeScratch()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let source = scratch.appendingPathComponent("source")
        try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
        try Data("good".utf8).write(to: source.appendingPathComponent("payload"))
        let archive = scratch.appendingPathComponent("mutation.tar.gz")
        try createArchive(sourceRoot: source, entry: "payload", archive: archive)

        var limits = SafeTraceArchiveExtractor.Limits.default
        limits.freeSpaceReserveBytes = 0
        #expect(throws: SafeTraceArchiveExtractor.ExtractionError.self) {
            _ = try SafeTraceArchiveExtractor.extract(
                archiveData: try Data(contentsOf: archive),
                limits: limits,
                testHooks: .init(afterInitialFilesystemValidation: { extractionRoot in
                    try! Data("evil".utf8).write(
                        to: extractionRoot.appendingPathComponent("payload")
                    )
                })
            )
        }
    }

    @Test("Top-level extraction padding stops at the first entry beyond the cap")
    func topLevelPaddingStopsAtFirstSentinel() throws {
        let scratch = try makeScratch()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let source = scratch.appendingPathComponent("source")
        try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
        try Data("x".utf8).write(to: source.appendingPathComponent("payload"))
        let archive = scratch.appendingPathComponent("padding.tar.gz")
        try createArchive(sourceRoot: source, entry: "payload", archive: archive)

        var limits = SafeTraceArchiveExtractor.Limits.default
        limits.maxEntries = 1
        limits.freeSpaceReserveBytes = 0
        var rawEntriesRead = 0
        do {
            _ = try SafeTraceArchiveExtractor.extract(
                archiveData: try Data(contentsOf: archive),
                limits: limits,
                testHooks: .init(
                    afterInitialFilesystemValidation: { extractionRoot in
                        for index in 0..<128 {
                            try! Data("x".utf8).write(
                                to: extractionRoot.appendingPathComponent(
                                    String(format: "padding-%03d", index)
                                )
                            )
                        }
                    },
                    afterTopLevelEntryRead: { _ in rawEntriesRead += 1 }
                )
            )
            Issue.record("same-uid-padded extraction root was accepted")
        } catch let error as SafeTraceArchiveExtractor.ExtractionError {
            guard case .entryCountLimit(let actual, let maximum) = error else {
                Issue.record("unexpected padding rejection: \(error)")
                return
            }
            #expect(actual == 2)
            #expect(maximum == 1)
        }
        #expect(rawEntriesRead == 2)
    }

    @Test("Tar subprocesses use a fixed minimal environment")
    func tarEnvironmentIsNotInherited() throws {
        #expect(SafeTraceArchiveExtractor.tarEnvironment == [
            "COPYFILE_DISABLE": "1",
            "HOME": "/var/empty",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
            "TMPDIR": "/private/tmp",
        ])

        let source = try String(
            contentsOf: Self.repoRoot.appendingPathComponent(
                "Sources/MacCrabCore/TraceBundle/SafeTraceArchiveExtractor.swift"
            ),
            encoding: .utf8
        )
        #expect(source.contains("environment: tarEnvironment"))
        #expect(source.contains("executable: \"/usr/bin/bsdtar\""))
        #expect(source.contains("BoundedPrivilegedProcessRunner.run("))
        #expect(!source.contains("ProcessInfo.processInfo.environment"),
                "attacker-controlled tar must not inherit TAR_OPTIONS/DYLD/HOME/PATH")
    }

    @Test("Archive bytes are captured once and fed to every tar pass without a pathname")
    func archivePathCannotBeSwappedBetweenTarPasses() throws {
        let source = try String(
            contentsOf: Self.repoRoot.appendingPathComponent(
                "Sources/MacCrabCore/TraceBundle/SafeTraceArchiveExtractor.swift"
            ),
            encoding: .utf8
        )
        #expect(source.contains("BoundedRegularFileReader.read("),
                "source archive must be opened no-follow and mutation-checked")
        #expect(!source.contains("snapshotURL.path"))
        #expect(source.contains("arguments: [\"-tzf\", \"-\"]"))
        #expect(source.contains("arguments: [\"--numeric-owner\", \"-tvzf\", \"-\"]"))
        #expect(source.contains("standardInputData: archiveData"),
                "both listings and extraction must consume captured bytes over stdin")
        #expect(source.contains("Darwin.mkdtemp"))
        #expect(source.contains("/private/tmp/maccrab-safe-extract.XXXXXX"))
        #expect(source.contains("requireExtractionCapacity("),
                "bounded expansion must preserve an operational free-space floor")
        for disabledMetadata in [
            "--no-same-owner",
            "--no-same-permissions",
            "--no-acls",
            "--no-fflags",
            "--no-mac-metadata",
            "--no-xattrs",
        ] {
            #expect(source.contains("\"\(disabledMetadata)\""),
                    "hostile archives must not restore privileged metadata: \(disabledMetadata)")
        }
    }

    @Test("Symlink archive entries are rejected before extraction")
    func rejectsSymlinkEntry() throws {
        let scratch = try makeScratch()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let source = scratch.appendingPathComponent("source")
        let bundle = source.appendingPathComponent("sample.maccrabtrace")
        try FileManager.default.createDirectory(at: bundle, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(
            atPath: bundle.appendingPathComponent("manifest.json").path,
            withDestinationPath: "/dev/zero"
        )
        let archive = scratch.appendingPathComponent("symlink.tar.gz")
        try createArchive(sourceRoot: source, entry: bundle.lastPathComponent, archive: archive)

        do {
            _ = try SafeTraceArchiveExtractor.extract(archiveAt: archive)
            Issue.record("symlink-bearing archive was accepted")
        } catch let error as SafeTraceArchiveExtractor.ExtractionError {
            guard case .unsupportedEntry(let path, let type) = error else {
                Issue.record("unexpected rejection: \(error)")
                return
            }
            #expect(path.hasSuffix("manifest.json"))
            #expect(type == "l")
        }
    }

    @Test("Parent traversal names are rejected before tar writes payloads")
    func rejectsParentTraversal() throws {
        let scratch = try makeScratch()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let source = scratch.appendingPathComponent("source")
        let bundle = source.appendingPathComponent("bundle")
        try FileManager.default.createDirectory(at: bundle, withIntermediateDirectories: true)
        try Data("x".utf8).write(to: bundle.appendingPathComponent("file"))
        let archive = scratch.appendingPathComponent("traversal.tar.gz")
        try createArchive(
            sourceRoot: source,
            entry: "bundle/file",
            archive: archive,
            substitutions: [",bundle/file,../escape,"]
        )

        do {
            _ = try SafeTraceArchiveExtractor.extract(archiveAt: archive)
            Issue.record("parent-traversal archive was accepted")
        } catch let error as SafeTraceArchiveExtractor.ExtractionError {
            guard case .unsafePath(let path) = error else {
                Issue.record("unexpected rejection: \(error)")
                return
            }
            #expect(path == "../escape")
        }
    }

    @Test("Declared file and expanded-total limits are enforced before extraction")
    func rejectsOversizedPayload() throws {
        let scratch = try makeScratch()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let source = scratch.appendingPathComponent("source")
        try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
        try Data("four".utf8).write(to: source.appendingPathComponent("payload"))
        let archive = scratch.appendingPathComponent("oversized.tar.gz")
        try createArchive(sourceRoot: source, entry: "payload", archive: archive)
        let limits = SafeTraceArchiveExtractor.Limits(
            maxCompressedBytes: 1_024,
            maxEntries: 4,
            maxSingleFileBytes: 3,
            maxTotalFileBytes: 3,
            maxListingBytes: 1_024,
            listingTimeoutSeconds: 2,
            extractionTimeoutSeconds: 2
        )

        do {
            _ = try SafeTraceArchiveExtractor.extract(archiveAt: archive, limits: limits)
            Issue.record("oversized archive was accepted")
        } catch let error as SafeTraceArchiveExtractor.ExtractionError {
            guard case .singleFileSizeLimit(let path, let actual, let maximum) = error else {
                Issue.record("unexpected rejection: \(error)")
                return
            }
            #expect(path == "payload")
            #expect(actual == 4)
            #expect(maximum == 3)
        }
    }

    @Test("Whitespace in archive owner names cannot spoof the declared size")
    func ownerNameCannotShiftVerboseSizeField() throws {
        let scratch = try makeScratch()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let source = scratch.appendingPathComponent("source")
        try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
        try Data("0123456789".utf8).write(to: source.appendingPathComponent("payload"))
        let archive = scratch.appendingPathComponent("owner-fields.tar.gz")
        try createArchive(
            sourceRoot: source,
            entry: "payload",
            archive: archive,
            creationOptions: ["--uname", "evil", "--gname", "1 2"]
        )
        var limits = SafeTraceArchiveExtractor.Limits.default
        limits.maxSingleFileBytes = 9
        limits.maxTotalFileBytes = 9

        do {
            _ = try SafeTraceArchiveExtractor.extract(archiveAt: archive, limits: limits)
            Issue.record("archive-controlled owner fields bypassed the pre-extraction size cap")
        } catch let error as SafeTraceArchiveExtractor.ExtractionError {
            guard case .singleFileSizeLimit(let path, let actual, let maximum) = error else {
                Issue.record("unexpected rejection: \(error)")
                return
            }
            #expect(path == "payload")
            #expect(actual == 10)
            #expect(maximum == 9)
        }
    }

    @Test("Extraction refuses to consume the configured free-space reserve")
    func preservesFreeSpaceReserve() throws {
        let scratch = try makeScratch()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let source = scratch.appendingPathComponent("source")
        try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
        try Data("x".utf8).write(to: source.appendingPathComponent("payload"))
        let archive = scratch.appendingPathComponent("reserve.tar.gz")
        try createArchive(sourceRoot: source, entry: "payload", archive: archive)

        var limits = SafeTraceArchiveExtractor.Limits.default
        limits.freeSpaceReserveBytes = UInt64.max
        do {
            _ = try SafeTraceArchiveExtractor.extract(archiveAt: archive, limits: limits)
            Issue.record("archive extraction consumed an impossible disk reserve")
        } catch let error as SafeTraceArchiveExtractor.ExtractionError {
            guard case .insufficientFreeSpace(_, let required) = error else {
                Issue.record("unexpected rejection: \(error)")
                return
            }
            #expect(required == UInt64.max)
        }
    }

    @Test("non-finite and runner-incompatible timeouts are rejected explicitly")
    func rejectsInvalidTimeoutLimits() throws {
        let scratch = try makeScratch()
        defer { try? FileManager.default.removeItem(at: scratch) }

        var infinite = SafeTraceArchiveExtractor.Limits.default
        infinite.listingTimeoutSeconds = .infinity
        #expect(throws: SafeTraceArchiveExtractor.ExtractionError.self) {
            _ = try SafeTraceArchiveExtractor.extract(
                archiveAt: scratch.appendingPathComponent("unused.tar.gz"),
                limits: infinite
            )
        }

        var tooLong = SafeTraceArchiveExtractor.Limits.default
        tooLong.extractionTimeoutSeconds = 3_601
        #expect(throws: SafeTraceArchiveExtractor.ExtractionError.self) {
            try SafeTraceArchiveExtractor.validateBundleDirectory(
                at: scratch,
                limits: tooLong
            )
        }
    }

    @Test("Already-unpacked bundle directories reject links and special files")
    func rejectsUnsafeDirectoryTree() throws {
        let scratch = try makeScratch()
        defer { try? FileManager.default.removeItem(at: scratch) }
        try FileManager.default.createSymbolicLink(
            atPath: scratch.appendingPathComponent("events.jsonl").path,
            withDestinationPath: "/dev/zero"
        )

        do {
            try SafeTraceArchiveExtractor.validateBundleDirectory(at: scratch)
            Issue.record("symlink-bearing directory was accepted")
        } catch let error as SafeTraceArchiveExtractor.ExtractionError {
            guard case .unsafeFilesystemEntry(let path, _) = error else {
                Issue.record("unexpected rejection: \(error)")
                return
            }
            #expect(path == "events.jsonl")
        }
    }

    @Test("CLI, MCP, trace validator, and session verifier share one hostile-filesystem policy")
    func allBundleReadersUseSharedPolicy() throws {
        func source(_ relative: String) throws -> String {
            try String(
                contentsOf: Self.repoRoot.appendingPathComponent(relative),
                encoding: .utf8
            )
        }

        let cli = try source("Sources/maccrabctl/TraceCommands.swift")
        let mcp = try source("Sources/maccrab-mcp/main.swift")
        let validator = try source("Sources/MacCrabCore/TraceBundle/BundleValidator.swift")
        let sessions = try source("Sources/MacCrabCore/TraceBundle/AgentSessionBundle.swift")

        let cliResolutionCalls = cli.components(
            separatedBy: "resolveBundleOrExit(url, operation:"
        ).count - 1
        #expect(cliResolutionCalls == 7,
                "every new trace-archive CLI reader must use the shared bounded resolver")
        #expect(cli.contains("SafeTraceBundleResolver.resolve(inputAt: url)"))
        #expect(!cli.contains("proc.arguments = [\"-xzf\", url.path]"),
                "direct unbounded tar extraction returned to the CLI")

        #expect(mcp.contains("SafeTraceBundleResolver.resolve(inputAt: url)"))
        #expect(mcp.contains("BundleVerifier.verify(\n        resolvedBundle: resolution"))
        #expect(!mcp.contains("p.arguments = [\"-xzf\", url.path]"),
                "direct unbounded tar extraction returned to MCP")
        #expect(validator.contains("SafeTraceBundleResolver.resolve(inputAt: directory)"))
        #expect(sessions.contains("SafeTraceBundleResolver.resolve(inputAt: bundleDir)"))
    }
}
