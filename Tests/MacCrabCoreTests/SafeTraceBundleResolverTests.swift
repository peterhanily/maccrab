import Darwin
import Foundation
import Testing
@testable import MacCrabCore

@Suite("Trace bundle immutable directory resolution")
struct SafeTraceBundleResolverTests {
    private func scratch(_ label: String = "root") throws -> URL {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            "maccrab-resolver-\(label)-\(UUID().uuidString)",
            isDirectory: true
        )
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false
        )
        return root
    }

    private func limits(
        maxEntries: Int = 32,
        maxSingleFileBytes: UInt64 = 1 * 1_024 * 1_024,
        maxTotalFileBytes: UInt64 = 2 * 1_024 * 1_024,
        freeSpaceReserveBytes: UInt64 = 0
    ) -> SafeTraceArchiveExtractor.Limits {
        SafeTraceArchiveExtractor.Limits(
            maxCompressedBytes: 1 * 1_024 * 1_024,
            maxEntries: maxEntries,
            maxSingleFileBytes: maxSingleFileBytes,
            maxTotalFileBytes: maxTotalFileBytes,
            maxListingBytes: 256 * 1_024,
            listingTimeoutSeconds: 5,
            extractionTimeoutSeconds: 5,
            freeSpaceReserveBytes: freeSpaceReserveBytes
        )
    }

    private func write(_ text: String, to url: URL) throws {
        try Data(text.utf8).write(to: url)
    }

    private func createArchive(
        sourceRoot: URL,
        entry: String,
        archive: URL
    ) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/tar")
        process.currentDirectoryURL = sourceRoot
        process.arguments = ["-czf", archive.path, entry]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw NSError(
                domain: "SafeTraceBundleResolverTests",
                code: Int(process.terminationStatus),
                userInfo: [NSLocalizedDescriptionKey: "fixture tar creation failed"]
            )
        }
    }

    @Test("Direct directory bytes are copied once and cleanup has one idempotent owner")
    func sourceChangesCannotChangeResolvedSnapshot() throws {
        let root = try scratch("stable")
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("source", isDirectory: true)
        let nested = source.appendingPathComponent("evidence", isDirectory: true)
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
        let sourceFile = nested.appendingPathComponent("events.jsonl")
        try write("version-one", to: sourceFile)

        // FileManager's temp URL is `/var/...` on macOS. A successful resolve
        // also proves the one explicitly allowed `/var` -> `/private/var` alias.
        let resolution = try SafeTraceBundleResolver.resolve(
            inputAt: source,
            limits: limits()
        )
        let snapshotFile = resolution.bundleDirectory
            .appendingPathComponent("evidence/events.jsonl")
        #expect(try String(contentsOf: snapshotFile, encoding: .utf8) == "version-one")
        #expect(
            try String(
                data: resolution.data(at: "evidence/events.jsonl"),
                encoding: .utf8
            ) == "version-one"
        )
        #expect(resolution.artifactPaths == ["evidence/events.jsonl"])
        #expect(resolution.directoryPaths == ["", "evidence"])

        try write("version-two", to: sourceFile)
        #expect(try String(contentsOf: snapshotFile, encoding: .utf8) == "version-one")

        // A private mode-0700 snapshot is still writable by another process
        // running as this uid. Semantic reads must remain pinned to the bytes
        // captured by the Resolution token, not reopen this path.
        try write("same-uid-attacker", to: snapshotFile)
        #expect(try String(contentsOf: snapshotFile, encoding: .utf8) == "same-uid-attacker")
        #expect(
            try String(
                data: resolution.data(at: "evidence/events.jsonl"),
                encoding: .utf8
            ) == "version-one"
        )

        let temporaryRoot = resolution.temporaryRoot
        resolution.cleanup()
        resolution.cleanup()
        #expect(!FileManager.default.fileExists(atPath: temporaryRoot.path))
    }

    @Test("Archive resolution semantics remain bound to archive bytes after same-uid path mutation")
    func archiveResolutionIgnoresCompatibilityTreeMutation() throws {
        let root = try scratch("archive-captured-bytes")
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("source", isDirectory: true)
        let bundle = source.appendingPathComponent("bundle", isDirectory: true)
        try FileManager.default.createDirectory(at: bundle, withIntermediateDirectories: true)
        try write("original", to: bundle.appendingPathComponent("manifest.json"))
        let archive = root.appendingPathComponent("bundle.tar.gz")
        try createArchive(sourceRoot: source, entry: "bundle", archive: archive)

        let resolution = try SafeTraceBundleResolver.resolve(
            inputAt: archive,
            limits: limits()
        )
        defer { resolution.cleanup() }
        try write(
            "attacker",
            to: resolution.bundleDirectory.appendingPathComponent("manifest.json")
        )

        #expect(
            try String(data: resolution.data(at: "manifest.json"), encoding: .utf8)
                == "original"
        )
    }

    @Test("Every source path component is opened no-follow")
    func rejectsLeafAndParentSymlinks() throws {
        let root = try scratch("path-links")
        defer { try? FileManager.default.removeItem(at: root) }
        let realParent = root.appendingPathComponent("real", isDirectory: true)
        let realBundle = realParent.appendingPathComponent("bundle", isDirectory: true)
        try FileManager.default.createDirectory(at: realBundle, withIntermediateDirectories: true)
        try write("{}", to: realBundle.appendingPathComponent("manifest.json"))

        let leafLink = root.appendingPathComponent("leaf-link")
        try FileManager.default.createSymbolicLink(at: leafLink, withDestinationURL: realBundle)
        #expect(throws: SafeTraceArchiveExtractor.ExtractionError.self) {
            _ = try SafeTraceBundleResolver.resolve(inputAt: leafLink, limits: limits())
        }

        let parentLink = root.appendingPathComponent("parent-link")
        try FileManager.default.createSymbolicLink(at: parentLink, withDestinationURL: realParent)
        #expect(throws: SafeTraceArchiveExtractor.ExtractionError.self) {
            _ = try SafeTraceBundleResolver.resolve(
                inputAt: parentLink.appendingPathComponent("bundle"),
                limits: limits()
            )
        }
    }

    @Test("A hard-linked archive input is rejected by descriptor postflight")
    func rejectsHardLinkedArchiveInput() throws {
        let root = try scratch("archive-hardlink")
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("source", isDirectory: true)
        let bundle = source.appendingPathComponent("bundle", isDirectory: true)
        try FileManager.default.createDirectory(at: bundle, withIntermediateDirectories: true)
        try write("{}", to: bundle.appendingPathComponent("manifest.json"))
        let archive = root.appendingPathComponent("bundle.tar.gz")
        try createArchive(sourceRoot: source, entry: "bundle", archive: archive)
        let secondLink = root.appendingPathComponent("bundle-second-link.tar.gz")
        try #require(Darwin.link(archive.path, secondLink.path) == 0)

        do {
            let unexpected = try SafeTraceBundleResolver.resolve(
                inputAt: archive,
                limits: limits()
            )
            unexpected.cleanup()
            Issue.record("hard-linked archive input was accepted")
        } catch let error as SafeTraceArchiveExtractor.ExtractionError {
            guard case .inputNotRegular = error else {
                Issue.record("hard-linked archive reached extraction: \(error)")
                return
            }
        }
    }

    @Test("Links, hard links, and FIFOs inside direct bundles are rejected")
    func rejectsUnsafeEntryKinds() throws {
        enum FixtureKind: CaseIterable { case symlink, hardLink, fifo }

        for kind in FixtureKind.allCases {
            let root = try scratch("entry-\(kind)")
            defer { try? FileManager.default.removeItem(at: root) }
            let source = root.appendingPathComponent("bundle", isDirectory: true)
            try FileManager.default.createDirectory(at: source, withIntermediateDirectories: false)
            let ordinary = source.appendingPathComponent("ordinary.json")
            try write("{}", to: ordinary)

            switch kind {
            case .symlink:
                try FileManager.default.createSymbolicLink(
                    atPath: source.appendingPathComponent("linked.json").path,
                    withDestinationPath: "/dev/zero"
                )
            case .hardLink:
                let linked = source.appendingPathComponent("hard.json")
                #expect(Darwin.link(ordinary.path, linked.path) == 0)
            case .fifo:
                let fifo = source.appendingPathComponent("pipe.json")
                #expect(Darwin.mkfifo(fifo.path, mode_t(0o600)) == 0)
            }

            #expect(throws: SafeTraceArchiveExtractor.ExtractionError.self) {
                _ = try SafeTraceBundleResolver.resolve(inputAt: source, limits: limits())
            }
        }
    }

    @Test("Concurrent file and directory mutations fail closed")
    func detectsMutationDuringSnapshot() throws {
        let fileRoot = try scratch("file-mutation")
        defer { try? FileManager.default.removeItem(at: fileRoot) }
        let fileBundle = fileRoot.appendingPathComponent("bundle", isDirectory: true)
        try FileManager.default.createDirectory(at: fileBundle, withIntermediateDirectories: false)
        let mutableFile = fileBundle.appendingPathComponent("events.jsonl")
        try write(String(repeating: "x", count: 4_096), to: mutableFile)
        let fileHooks = SafeTraceBundleResolver.TestHooks(
            afterFileMetadataValidated: { relative in
                guard relative == "events.jsonl" else { return }
                let descriptor = Darwin.open(mutableFile.path, O_WRONLY | O_CLOEXEC)
                if descriptor >= 0 {
                    _ = Darwin.ftruncate(descriptor, 1)
                    Darwin.close(descriptor)
                }
            }
        )
        #expect(throws: SafeTraceArchiveExtractor.ExtractionError.self) {
            _ = try SafeTraceBundleResolver.resolve(
                inputAt: fileBundle,
                limits: limits(),
                testHooks: fileHooks
            )
        }

        let directoryRoot = try scratch("directory-mutation")
        defer { try? FileManager.default.removeItem(at: directoryRoot) }
        let directoryBundle = directoryRoot.appendingPathComponent("bundle", isDirectory: true)
        try FileManager.default.createDirectory(
            at: directoryBundle,
            withIntermediateDirectories: false
        )
        try write("{}", to: directoryBundle.appendingPathComponent("manifest.json"))
        let directoryHooks = SafeTraceBundleResolver.TestHooks(
            beforeDirectoryPostflight: { relative in
                guard relative.isEmpty else { return }
                try? Data("late".utf8).write(
                    to: directoryBundle.appendingPathComponent("late.json")
                )
            }
        )
        #expect(throws: SafeTraceArchiveExtractor.ExtractionError.self) {
            _ = try SafeTraceBundleResolver.resolve(
                inputAt: directoryBundle,
                limits: limits(),
                testHooks: directoryHooks
            )
        }
    }

    @Test("Entry, file, total, and free-space ceilings apply before consumers read")
    func enforcesAllDirectoryBounds() throws {
        let root = try scratch("limits")
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("bundle", isDirectory: true)
        try FileManager.default.createDirectory(at: source, withIntermediateDirectories: false)
        try write("four", to: source.appendingPathComponent("one.json"))
        try write("four", to: source.appendingPathComponent("two.json"))

        #expect(throws: SafeTraceArchiveExtractor.ExtractionError.self) {
            _ = try SafeTraceBundleResolver.resolve(
                inputAt: source,
                limits: limits(maxEntries: 1)
            )
        }
        #expect(throws: SafeTraceArchiveExtractor.ExtractionError.self) {
            _ = try SafeTraceBundleResolver.resolve(
                inputAt: source,
                limits: limits(maxSingleFileBytes: 3)
            )
        }
        #expect(throws: SafeTraceArchiveExtractor.ExtractionError.self) {
            _ = try SafeTraceBundleResolver.resolve(
                inputAt: source,
                limits: limits(maxTotalFileBytes: 7)
            )
        }
        #expect(throws: SafeTraceArchiveExtractor.ExtractionError.self) {
            _ = try SafeTraceBundleResolver.resolve(
                inputAt: source,
                limits: limits(freeSpaceReserveBytes: UInt64.max)
            )
        }

        var infiniteTimeout = limits()
        infiniteTimeout.listingTimeoutSeconds = .infinity
        #expect(throws: SafeTraceArchiveExtractor.ExtractionError.self) {
            _ = try SafeTraceBundleResolver.resolve(
                inputAt: source,
                limits: infiniteTimeout
            )
        }
        var nanTimeout = limits()
        nanTimeout.extractionTimeoutSeconds = .nan
        #expect(throws: SafeTraceArchiveExtractor.ExtractionError.self) {
            _ = try SafeTraceBundleResolver.resolve(
                inputAt: source,
                limits: nanTimeout
            )
        }
    }

    @Test("Direct-directory padding stops at the first entry beyond the global cap")
    func paddedDirectoryDoesNotBufferPastEntryCap() throws {
        let root = try scratch("entry-padding")
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("bundle", isDirectory: true)
        try FileManager.default.createDirectory(
            at: source,
            withIntermediateDirectories: false
        )
        for index in 0..<128 {
            try write(
                "x",
                to: source.appendingPathComponent(
                    String(format: "padding-%03d.json", index)
                )
            )
        }

        var rawEntriesRead = 0
        let hooks = SafeTraceBundleResolver.TestHooks(
            afterDirectoryEntryRead: { _ in rawEntriesRead += 1 }
        )
        do {
            _ = try SafeTraceBundleResolver.resolve(
                inputAt: source,
                limits: limits(maxEntries: 1),
                testHooks: hooks
            )
            Issue.record("over-cap padded direct bundle was accepted")
        } catch let error as SafeTraceArchiveExtractor.ExtractionError {
            guard case .entryCountLimit(let actual, let maximum) = error else {
                Issue.record("unexpected padded-directory rejection: \(error)")
                return
            }
            #expect(actual == 2)
            #expect(maximum == 1)
        }
        #expect(rawEntriesRead == 2,
                "resolver read past the one sentinel entry needed to prove truncation")
    }

    @Test("Core readers expose one resolved-token path for nested reuse")
    func coreReaderResolvedOverloadsRemainWired() throws {
        let repoRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        func source(_ name: String) throws -> String {
            try String(
                contentsOf: repoRoot.appendingPathComponent(
                    "Sources/MacCrabCore/TraceBundle/\(name)"
                ),
                encoding: .utf8
            )
        }
        let validator = try source("BundleValidator.swift")
        let verifier = try source("BundleVerifier.swift")
        let replay = try source("ReplayEngine.swift")
        let sessions = try source("AgentSessionBundle.swift")

        #expect(validator.contains("validate(resolvedBundle: resolution)"))
        #expect(verifier.contains("BundleValidator.validate(resolvedBundle: resolution)"))
        #expect(replay.contains("BundleValidator.validate(resolvedBundle: resolution)"))
        #expect(replay.contains("BundleVerifier.verify(\n                resolvedBundle: resolution"))
        #expect(sessions.contains("resolvedBundle resolution: SafeTraceBundleResolver.Resolution"))
        for semanticReader in [validator, verifier, replay, sessions] {
            #expect(!semanticReader.contains("resolution.bundleDirectory"))
        }
        #expect(verifier.contains("BundleMerkle.compute(resolvedBundle: resolution)"))
        #expect(sessions.contains("BundleMerkle.compute(resolvedBundle: resolution)"))
    }

    @Test("CLI and MCP bundle readers keep every mixed read on one resolution")
    func frontEndReadersReuseResolvedToken() throws {
        let repoRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        func source(_ relativePath: String) throws -> String {
            try String(
                contentsOf: repoRoot.appendingPathComponent(relativePath),
                encoding: .utf8
            )
        }
        func occurrenceCount(_ needle: String, in haystack: String) -> Int {
            haystack.components(separatedBy: needle).count - 1
        }

        let cli = try source("Sources/maccrabctl/TraceCommands.swift")
        #expect(occurrenceCount("resolveBundleOrExit(url, operation:", in: cli) == 7)
        #expect(occurrenceCount("resolvedBundle: resolution", in: cli) == 8)
        #expect(!cli.contains("let target = resolution.bundleDirectory"))
        #expect(cli.contains("resolution.data(at: \"manifest.json\")"))
        #expect(cli.contains("resolution.dataIfPresent(at: \"manifest.json\")"))
        #expect(cli.contains("SafeTraceBundleResolver.resolve(inputAt: url)"))
        #expect(!cli.contains("extractIfArchive("))
        #expect(!cli.contains("cleanupExtracted("))
        #expect(!cli.contains("BundleValidator.validate(at:"))
        #expect(!cli.contains("BundleVerifier.verify(at:"))
        #expect(!cli.contains(".replay(bundleAt:"))

        let mcp = try source("Sources/maccrab-mcp/main.swift")
        let handlerStart = try #require(mcp.range(of: "func handleVerifyBundle("))
        let handlerEnd = try #require(
            mcp.range(
                of: "func handleTraceFromEvent(",
                range: handlerStart.upperBound..<mcp.endIndex
            )
        )
        let verifyHandler = String(mcp[handlerStart.lowerBound..<handlerEnd.lowerBound])
        #expect(
            occurrenceCount(
                "SafeTraceBundleResolver.resolve(inputAt: url)",
                in: verifyHandler
            ) == 1
        )
        #expect(!verifyHandler.contains("resolution.bundleDirectory"))
        #expect(verifyHandler.contains("resolution.dataIfPresent(at: \"manifest.json\")"))
        #expect(verifyHandler.contains("at: \"integrity/chain_head_signature.json\""))
        #expect(verifyHandler.contains("resolvedBundle: resolution"))
        #expect(!verifyHandler.contains("BundleVerifier.verify(at:"))
    }
}
