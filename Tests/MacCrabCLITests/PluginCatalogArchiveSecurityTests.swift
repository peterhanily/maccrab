import Darwin
import Foundation
import Testing
@testable import maccrabctl

@Suite("maccrabctl: plugin catalog transport and ZIP boundary")
struct PluginCatalogArchiveSecurityTests {
    private static let repoRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()

    private let pluginID = "com.example.security-fixture"

    private func scratchDirectory() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-plugin-archive-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        return root
    }

    private func makeCanonicalBundle(at root: URL) throws -> URL {
        let bundle = root.appendingPathComponent(pluginID, isDirectory: true)
        try FileManager.default.createDirectory(at: bundle, withIntermediateDirectories: true)
        try Data(#"{"id":"com.example.security-fixture"}"#.utf8)
            .write(to: bundle.appendingPathComponent("manifest.json"))
        try Data("fixture-binary".utf8).write(to: bundle.appendingPathComponent("binary"))
        try Data(repeating: 0x53, count: 64).write(to: bundle.appendingPathComponent("signature"))
        try Data(repeating: 0x4b, count: 32).write(to: bundle.appendingPathComponent("signing.key.pub"))
        return bundle
    }

    private func createZip(
        sourceRoot: URL,
        entries: [String],
        archive: URL,
        preserveSymlinks: Bool = true
    ) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/zip")
        process.currentDirectoryURL = sourceRoot
        var arguments = ["-q", "-r"]
        if preserveSymlinks { arguments.append("-y") }
        arguments.append(archive.path)
        arguments.append(contentsOf: entries)
        process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        var environment = Foundation.ProcessInfo.processInfo.environment
        environment["PATH"] = "/usr/bin:/bin"
        environment["LC_ALL"] = "C"
        environment.removeValue(forKey: "ZIPOPT")
        process.environment = environment
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw NSError(
                domain: "PluginCatalogArchiveSecurityTests",
                code: Int(process.terminationStatus),
                userInfo: [NSLocalizedDescriptionKey: "fixture ZIP creation failed"]
            )
        }
    }

    @Test("documented four-file ZIP yields immutable bytes and a caller-cleaned diagnostic tree")
    func validArchiveExtracts() throws {
        let scratch = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        _ = try makeCanonicalBundle(at: scratch)
        let archive = scratch.appendingPathComponent("plugin.zip")
        try createZip(sourceRoot: scratch, entries: [pluginID], archive: archive)

        let extraction = try SafePluginArchiveExtractor.extract(
            archiveAt: archive,
            pluginID: pluginID
        )
        let temporaryRoot = extraction.temporaryRoot
        defer { extraction.cleanup() }

        #expect(extraction.bundleDirectory.lastPathComponent == pluginID)
        for component in ["manifest.json", "binary", "signature", "signing.key.pub"] {
            let url = extraction.bundleDirectory.appendingPathComponent(component)
            var info = stat()
            #expect(lstat(url.path, &info) == 0)
            #expect((info.st_mode & S_IFMT) == S_IFREG)
            #expect(info.st_nlink == 1)
        }
        var rootInfo = stat()
        #expect(lstat(temporaryRoot.path, &rootInfo) == 0)
        #expect((rootInfo.st_mode & 0o777) == 0o700)
        #expect(temporaryRoot.path.hasPrefix("/private/tmp/maccrab-plugin-extract."))
        #expect(extraction.snapshot.binaryData == Data("fixture-binary".utf8))
        #expect(extraction.snapshot.signatureData == Data(repeating: 0x53, count: 64))
        #expect(extraction.snapshot.publicKeyData == Data(repeating: 0x4b, count: 32))
        #expect(!FileManager.default.fileExists(
            atPath: temporaryRoot.appendingPathComponent("archive.zip").path
        ), "authenticated ZIP bytes must never be exposed at a same-uid-mutable path")
    }

    @Test("same-uid mutation of the diagnostic tree cannot change the captured install bytes")
    func extractedTreeMutationDoesNotChangeSnapshot() throws {
        let scratch = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        _ = try makeCanonicalBundle(at: scratch)
        let archive = scratch.appendingPathComponent("plugin.zip")
        try createZip(sourceRoot: scratch, entries: [pluginID], archive: archive)
        let archiveData = try Data(contentsOf: archive)

        let extraction = try SafePluginArchiveExtractor.extract(
            archiveData: archiveData,
            pluginID: pluginID
        )
        defer { extraction.cleanup() }
        let authorized = extraction.snapshot

        try Data("attacker-binary".utf8).write(
            to: extraction.bundleDirectory.appendingPathComponent("binary"),
            options: .atomic
        )
        try Data(repeating: 0x99, count: 32).write(
            to: extraction.bundleDirectory.appendingPathComponent("signing.key.pub"),
            options: .atomic
        )

        #expect(authorized.binaryData == Data("fixture-binary".utf8))
        #expect(authorized.publicKeyData == Data(repeating: 0x4b, count: 32))
    }

    @Test("ZIP symlinks are refused before any archive-directed extraction")
    func symlinkEntryRejected() throws {
        let scratch = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let bundle = try makeCanonicalBundle(at: scratch)
        try FileManager.default.createSymbolicLink(
            atPath: bundle.appendingPathComponent("credential-link").path,
            withDestinationPath: "/dev/zero"
        )
        let archive = scratch.appendingPathComponent("symlink.zip")
        try createZip(sourceRoot: scratch, entries: [pluginID], archive: archive)

        do {
            _ = try SafePluginArchiveExtractor.extract(
                archiveAt: archive,
                pluginID: pluginID
            )
            Issue.record("symlink-bearing plugin ZIP was accepted")
        } catch let error as SafePluginArchiveExtractor.ExtractionError {
            switch error {
            case .unsupportedEntry(let path, let type):
                #expect(path.hasSuffix("credential-link"))
                #expect(type == "l")
            case .unsafePath(let path):
                // libarchive can surface a ZIP symlink as a regular entry when
                // consuming a non-seekable stdin stream. The exact four-file
                // layout is the independent fail-closed gate in that case.
                #expect(path.contains("credential-link"))
                #expect(path.contains("exactly manifest.json"))
            default:
                Issue.record("unexpected rejection: \(error)")
            }
        }
    }

    @Test("unsigned adjacent plugin files are refused by the exact four-file layout")
    func unsignedAdjacentFileRejected() throws {
        let scratch = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let bundle = try makeCanonicalBundle(at: scratch)
        try Data("unsigned-adjacent-code".utf8).write(
            to: bundle.appendingPathComponent("payload.dylib")
        )
        let archive = scratch.appendingPathComponent("extra.zip")
        try createZip(sourceRoot: scratch, entries: [pluginID], archive: archive)

        do {
            _ = try SafePluginArchiveExtractor.extract(
                archiveAt: archive,
                pluginID: pluginID
            )
            Issue.record("plugin ZIP with unsigned adjacent payload was accepted")
        } catch let error as SafePluginArchiveExtractor.ExtractionError {
            guard case .unsafePath(let path) = error else {
                Issue.record("unexpected rejection: \(error)")
                return
            }
            #expect(path.contains("payload.dylib"))
        }
    }

    @Test("a sibling top-level payload is rejected before files are written")
    func siblingRootRejected() throws {
        let scratch = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        _ = try makeCanonicalBundle(at: scratch)
        let sibling = scratch.appendingPathComponent("outside", isDirectory: true)
        try FileManager.default.createDirectory(at: sibling, withIntermediateDirectories: true)
        try Data("escape".utf8).write(to: sibling.appendingPathComponent("payload"))
        let archive = scratch.appendingPathComponent("sibling.zip")
        try createZip(
            sourceRoot: scratch,
            entries: [pluginID, "outside"],
            archive: archive
        )

        do {
            _ = try SafePluginArchiveExtractor.extract(
                archiveAt: archive,
                pluginID: pluginID
            )
            Issue.record("multi-root plugin ZIP was accepted")
        } catch let error as SafePluginArchiveExtractor.ExtractionError {
            guard case .pathOutsidePlugin(let path, let expectedID) = error else {
                Issue.record("unexpected rejection: \(error)")
                return
            }
            #expect(path.hasPrefix("outside"))
            #expect(expectedID == pluginID)
        }
    }

    @Test("traversal, absolute, hidden, escaped, and ambiguous names fail closed")
    func unsafePathShapesRejected() throws {
        let unsafe = [
            "../escape",
            "\(pluginID)/../escape",
            "/\(pluginID)/manifest.json",
            "\(pluginID)/.hidden",
            "\(pluginID)/line\\nbreak",
            "\(pluginID)//manifest.json",
            "\(pluginID)/space name",
        ]
        for path in unsafe {
            do {
                _ = try SafePluginArchiveExtractor.normalizeArchivePath(path)
                Issue.record("unsafe plugin archive path was accepted: \(path)")
            } catch let error as SafePluginArchiveExtractor.ExtractionError {
                guard case .unsafePath = error else {
                    Issue.record("\(path): expected unsafePath, got \(error)")
                    continue
                }
            }
        }
    }

    @Test("declared single-file and total limits reject a ZIP before extraction")
    func expandedLimitsRejected() throws {
        let scratch = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        _ = try makeCanonicalBundle(at: scratch)
        let archive = scratch.appendingPathComponent("oversized.zip")
        try createZip(sourceRoot: scratch, entries: [pluginID], archive: archive)
        let limits = SafePluginArchiveExtractor.Limits(
            maximumCompressedBytes: 1_024 * 1_024,
            maximumEntries: 32,
            maximumSingleFileBytes: 4,
            maximumExpandedBytes: 16,
            maximumListingBytes: 16 * 1_024,
            listingTimeoutSeconds: 2,
            extractionTimeoutSeconds: 2
        )

        do {
            _ = try SafePluginArchiveExtractor.extract(
                archiveAt: archive,
                pluginID: pluginID,
                limits: limits
            )
            Issue.record("oversized plugin ZIP was accepted")
        } catch let error as SafePluginArchiveExtractor.ExtractionError {
            guard case .singleFileSizeLimit(let path, let actual, let maximum) = error else {
                Issue.record("unexpected rejection: \(error)")
                return
            }
            #expect(path.hasPrefix("\(pluginID)/"))
            #expect(actual > maximum)
            #expect(maximum == 4)
        }
    }

    @Test("extraction admission preserves the configured free-space reserve")
    func freeSpaceReserveRejected() throws {
        let scratch = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        _ = try makeCanonicalBundle(at: scratch)
        let archive = scratch.appendingPathComponent("reserve.zip")
        try createZip(sourceRoot: scratch, entries: [pluginID], archive: archive)

        var limits = SafePluginArchiveExtractor.Limits.production
        #expect(limits.freeSpaceReserveBytes == 1_073_741_824)
        limits.freeSpaceReserveBytes = UInt64.max
        do {
            _ = try SafePluginArchiveExtractor.extract(
                archiveAt: archive,
                pluginID: pluginID,
                limits: limits
            )
            Issue.record("plugin extraction consumed an impossible disk reserve")
        } catch let error as SafePluginArchiveExtractor.ExtractionError {
            guard case .insufficientFreeSpace(_, let required) = error else {
                Issue.record("unexpected rejection: \(error)")
                return
            }
            #expect(required == UInt64.max)
        }
    }

    @Test("non-finite timeouts and overflowing entry allowances fail before archive work")
    func invalidNumericLimitsRejected() throws {
        let scratch = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let archive = scratch.appendingPathComponent("not-read.zip")

        for timeout in [TimeInterval.nan, TimeInterval.infinity] {
            var listing = SafePluginArchiveExtractor.Limits.production
            listing.listingTimeoutSeconds = timeout
            do {
                _ = try SafePluginArchiveExtractor.extract(
                    archiveAt: archive,
                    pluginID: pluginID,
                    limits: listing
                )
                Issue.record("non-finite listing timeout was accepted")
            } catch let error as SafePluginArchiveExtractor.ExtractionError {
                guard case .filesystem("invalid archive limits") = error else {
                    Issue.record("unexpected listing-limit rejection: \(error)")
                    continue
                }
            }

            var extraction = SafePluginArchiveExtractor.Limits.production
            extraction.extractionTimeoutSeconds = timeout
            do {
                _ = try SafePluginArchiveExtractor.extract(
                    archiveAt: archive,
                    pluginID: pluginID,
                    limits: extraction
                )
                Issue.record("non-finite extraction timeout was accepted")
            } catch let error as SafePluginArchiveExtractor.ExtractionError {
                guard case .filesystem("invalid archive limits") = error else {
                    Issue.record("unexpected extraction-limit rejection: \(error)")
                    continue
                }
            }
        }

        var overflowing = SafePluginArchiveExtractor.Limits.production
        overflowing.maximumEntries = Int.max
        do {
            _ = try SafePluginArchiveExtractor.extract(
                archiveAt: archive,
                pluginID: pluginID,
                limits: overflowing
            )
            Issue.record("overflowing tree-entry allowance was accepted")
        } catch let error as SafePluginArchiveExtractor.ExtractionError {
            guard case .filesystem("invalid archive limits") = error else {
                Issue.record("unexpected entry-limit rejection: \(error)")
                return
            }
        }
    }

    @Test("stream accumulator accepts exactly the ceiling and retains no excess byte")
    func networkBodyCeiling() {
        #expect(PluginFetchLimits.production.maximumMetadataBytes == 4_194_304)
        #expect(PluginFetchLimits.production.maximumSignatureBytes == 64)
        #expect(PluginFetchLimits.production.maximumArtifactBytes == 67_108_864)

        var body = PluginFetchBodyAccumulator(maximumBytes: 2)
        let acceptedFirst = body.append(0x41)
        let acceptedSecond = body.append(0x42)
        let acceptedExcess = body.append(0x43)
        #expect(acceptedFirst)
        #expect(acceptedSecond)
        #expect(!acceptedExcess)
        #expect(body.data == Data([0x41, 0x42]))
    }

    @Test("debug plaintext transport is loopback-only and credentials are always refused")
    func fetchURLPolicy() throws {
        let allowed = [
            "https://rave.maccrab.com/catalog.json",
            "http://localhost:8080/catalog.json",
            "http://127.0.0.42:8080/catalog.json",
            "http://[::1]:8080/catalog.json",
        ]
        for raw in allowed {
            let url = try #require(URL(string: raw))
            #expect(PluginCatalogFetcher.isAllowedFetchURL(url), "expected allowed: \(raw)")
        }

        let refused = [
            "http://example.com/catalog.json",
            "http://10.0.0.8/catalog.json",
            "http://127.0.0.1.evil.invalid/catalog.json",
            "http://user:password@localhost:8080/catalog.json",
            "https://user@example.com/catalog.json",
            "file:///tmp/catalog.json",
        ]
        for raw in refused {
            let url = try #require(URL(string: raw))
            #expect(!PluginCatalogFetcher.isAllowedFetchURL(url), "expected refused: \(raw)")
        }
    }

    @Test("all network plugin installs converge on the one bounded archive boundary")
    func archiveBoundaryDriftGuard() throws {
        func source(_ relative: String) throws -> String {
            try String(
                contentsOf: Self.repoRoot.appendingPathComponent(relative),
                encoding: .utf8
            )
        }

        let catalog = try source("Sources/maccrabctl/PluginCatalogFetch.swift")
        let extractor = try source("Sources/maccrabctl/SafePluginArchiveExtractor.swift")
        let commands = try source("Sources/maccrabctl/PluginCommands.swift")
        let app = try source("Sources/MacCrabApp/V2/Forensics/RaveInstallConsentSheet.swift")
        let mcp = try source("Sources/maccrab-mcp/main.swift")

        #expect(catalog.contains("maximumBytes: fetchLimits.maximumArtifactBytes"))
        #expect(catalog.contains("SafePluginArchiveExtractor.extract("))
        #expect(catalog.contains("archiveData: zipData"))
        #expect(catalog.contains("snapshot: bundleSnapshot"))
        #expect(!catalog.contains("sourceDir: bundleDir"),
                "catalog checks must not hand a mutable extracted path to the installer")
        #expect(!catalog.contains("Data(contentsOf: bundleDir"),
                "catalog trust checks must consume the immutable extraction snapshot")
        #expect(!catalog.contains("bundle.zip"),
                "authenticated artifact bytes must not be re-exposed through a temp path")
        #expect(!catalog.contains("/usr/bin/unzip"))
        #expect(!catalog.contains("data(for: req)"),
                "catalog responses must stay streamed and bounded before accumulation")

        #expect(extractor.contains("BoundedRegularFileReader.read("),
                "the optional path API must capture through the shared no-follow reader")
        #expect(extractor.components(separatedBy: "standardInputData: archiveData").count - 1 == 2,
                "listing and extraction helpers must feed captured bytes over stdin")
        #expect(!extractor.contains("archive.zip"),
                "the archive parser must have no same-uid-mutable input pathname")
        #expect(extractor.contains("Darwin.mkdtemp"))
        #expect(extractor.contains("/private/tmp/maccrab-plugin-extract.XXXXXX"))
        #expect(extractor.contains("requireExtractionCapacity("))
        #expect(extractor.contains("freeSpaceReserveBytes"))
        #expect(extractor.contains("[\"-xOf\", \"-\", \"--\", entry.archivePath]"))
        #expect(extractor.contains("PluginBundleSnapshot(files: capturedFiles)"))
        #expect(extractor.contains("executable: \"/usr/bin/bsdtar\""))
        #expect(extractor.contains("BoundedPrivilegedProcessRunner.run("),
                "listing/extraction output must use the nonblocking hard-deadline runner")
        #expect(!extractor.contains("/usr/bin/tar"),
                "the macOS /usr/bin/tar symlink must not return to this boundary")
        #expect(!extractor.contains("Process()"))
        #expect(!extractor.contains("[\"-xf\""),
                "the archive tool must never regain filesystem extraction authority")
        #expect(!extractor.contains("/usr/bin/unzip"))
        #expect(!extractor.contains("ProcessInfo.processInfo.environment"),
                "attacker-facing archive tools must not inherit caller environment")
        for assignment in [
            "\"PATH\": \"/usr/bin:/bin\"",
            "\"LC_ALL\": \"C\"",
            "\"LANG\": \"C\"",
            "\"COPYFILE_DISABLE\": \"1\"",
            "\"HOME\": \"/var/empty\"",
            "\"TMPDIR\": \"/private/tmp\"",
        ] {
            #expect(extractor.contains(assignment), "missing fixed tar environment key: \(assignment)")
        }

        let directInstallCalls = commands.components(
            separatedBy: "installPluginByID("
        ).count - 1
        #expect(directInstallCalls == 2,
                "fresh install and update must both use PluginCatalogFetcher")
        #expect(app.contains("var argv = [\"plugin\", \"install\", id]"),
                "the app must delegate to the bounded bundled CLI path")
        #expect(mcp.contains("runMaccrabctl([\"plugin\", \"install\", id, \"--yes\"])"),
                "MCP must delegate to the bounded bundled CLI path")

        let maccrabctlRoot = Self.repoRoot.appendingPathComponent("Sources/maccrabctl")
        let files = try FileManager.default.contentsOfDirectory(
            at: maccrabctlRoot,
            includingPropertiesForKeys: nil
        ).filter { $0.pathExtension == "swift" }
        let zipOwners = try files.compactMap { file -> String? in
            let text = try String(contentsOf: file, encoding: .utf8)
            return text.contains(".maccrabplugin.zip") ? file.lastPathComponent : nil
        }
        #expect(zipOwners == ["PluginCatalogFetch.swift"],
                "a new plugin archive entry point must reuse this boundary and update the guard")
        for file in files {
            let text = try String(contentsOf: file, encoding: .utf8)
            #expect(!(text.contains("/usr/bin/unzip") && text.contains("\"-d\"")),
                    "raw ZIP filesystem extraction returned in \(file.lastPathComponent)")
        }
    }
}
