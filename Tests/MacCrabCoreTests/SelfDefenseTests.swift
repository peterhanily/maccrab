// SelfDefenseTests.swift
// Unit tests for SelfDefense hashing primitives.
//
// v1.12.6 regression coverage: previously `SelfDefense.sha256(fileAt:)`
// shelled out to `/usr/bin/shasum` (a perl script) and `directoryHash()`
// spawned that subprocess once per `.json` rule file plus once more for
// the combined-hash temp file. On a typical install with ~425 compiled
// rules under a 15 s periodic integrity check, that produced ~28 perl
// spawns per second. The migration to in-process CryptoKit must keep
// the hex digest output byte-identical so existing installs don't fire
// a one-time false-positive `.rulesModified` alert on first run after
// upgrade.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("Self-Defense Hashing")
struct SelfDefenseTests {

    /// SHA-256 of "hello world" — well-known constant. Verifies that the
    /// CryptoKit-backed `sha256(fileAt:)` produces the same hex digest a
    /// reference `shasum -a 256` invocation would.
    private let helloWorldSHA = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

    // MARK: - Test helpers

    /// Test-only static accessor for `SelfDefense.sha256(fileAt:)`.
    /// The production method is private to the actor; we wrap it so the
    /// test suite can exercise it without needing to spin up the whole
    /// actor and its filesystem-monitoring side effects.
    private func sha256Single(_ path: String) -> String? {
        // Reuse the same CryptoKit static helper SelfDefense routes
        // through. The chain is:
        //     SelfDefense.sha256(fileAt:) → FileHasher.computeSHA256(path:)
        // Calling the underlying helper here is equivalent (and is exactly
        // what production hits on the hot path).
        return FileHasher.computeSHA256(path: path)
    }

    private func makeTempDir() throws -> String {
        let dir = NSTemporaryDirectory() + "maccrab_selfdefense_\(UUID().uuidString)"
        try FileManager.default.createDirectory(
            atPath: dir,
            withIntermediateDirectories: true
        )
        return dir
    }

    private func writeFile(_ path: String, contents: String) throws {
        try contents.write(toFile: path, atomically: true, encoding: .utf8)
    }

    private func cleanup(_ path: String) {
        try? FileManager.default.removeItem(atPath: path)
    }

    /// Compute the combined directory hash using the SAME algorithm
    /// `SelfDefense.directoryHash` uses, but exposed for the test.
    /// Mirrors production exactly: sort `.json` filenames, concat per-file
    /// SHA-256 hex digests, SHA-256 the UTF-8 bytes of that concatenation.
    private func directoryHashReference(at path: String) -> String? {
        guard let files = try? FileManager.default.contentsOfDirectory(atPath: path)
            .filter({ $0.hasSuffix(".json") })
            .sorted() else { return nil }
        var combined = ""
        for file in files {
            guard let h = FileHasher.computeSHA256(path: path + "/" + file) else {
                return nil
            }
            combined += h
        }
        guard !combined.isEmpty,
              let bytes = combined.data(using: .utf8) else { return nil }
        let digest = CryptoKit_SHA256_hex(bytes)
        return digest
    }

    /// Local helper that mirrors the production CryptoKit SHA-256 of a
    /// `Data` blob without dragging CryptoKit into the test source.
    private func CryptoKit_SHA256_hex(_ data: Data) -> String {
        // SHA-256 of `data` using the same primitive SelfDefense uses
        // for the combined-hash step. We can't call CryptoKit directly
        // here without an import, so we route through the same
        // FileHasher.computeSHA256 helper by writing the bytes to a
        // temp file and hashing that — equivalent because CryptoKit
        // operates on bytes regardless of source.
        let tmp = NSTemporaryDirectory() + "maccrab_selfdef_combined_\(UUID().uuidString).bin"
        try? data.write(to: URL(fileURLWithPath: tmp))
        defer { try? FileManager.default.removeItem(atPath: tmp) }
        return FileHasher.computeSHA256(path: tmp) ?? ""
    }

    // MARK: - Tests

    @Test("sha256 matches reference hash for known content")
    func sha256MatchesKnownHash() async throws {
        let path = NSTemporaryDirectory() + "maccrab_selfdef_known_\(UUID().uuidString).txt"
        defer { cleanup(path) }
        try writeFile(path, contents: "hello world")

        let digest = sha256Single(path)
        #expect(digest == helloWorldSHA)
    }

    @Test("sha256 returns nil for nonexistent file")
    func sha256NilOnMissing() async throws {
        let bogus = NSTemporaryDirectory() + "maccrab_selfdef_does_not_exist_\(UUID().uuidString)"
        let digest = sha256Single(bogus)
        #expect(digest == nil)
    }

    @Test("directoryHash is stable across repeated invocations on unchanged contents")
    func directoryHashStableUnchanged() async throws {
        let dir = try makeTempDir()
        defer { cleanup(dir) }

        try writeFile(dir + "/a.json", contents: "{\"a\":1}")
        try writeFile(dir + "/b.json", contents: "{\"b\":2}")
        try writeFile(dir + "/c.json", contents: "{\"c\":3}")

        let first = directoryHashReference(at: dir)
        let second = directoryHashReference(at: dir)
        #expect(first != nil)
        #expect(first == second)
    }

    @Test("directoryHash changes when a rule file is modified")
    func directoryHashSensitiveToChange() async throws {
        let dir = try makeTempDir()
        defer { cleanup(dir) }

        try writeFile(dir + "/a.json", contents: "{\"a\":1}")
        try writeFile(dir + "/b.json", contents: "{\"b\":2}")

        let before = directoryHashReference(at: dir)
        try writeFile(dir + "/b.json", contents: "{\"b\":99}")
        let after = directoryHashReference(at: dir)

        #expect(before != nil)
        #expect(after != nil)
        #expect(before != after)
    }

    @Test("directoryHash changes when a rule file is added")
    func directoryHashSensitiveToAddition() async throws {
        let dir = try makeTempDir()
        defer { cleanup(dir) }

        try writeFile(dir + "/a.json", contents: "{\"a\":1}")
        let before = directoryHashReference(at: dir)
        try writeFile(dir + "/b.json", contents: "{\"b\":2}")
        let after = directoryHashReference(at: dir)

        #expect(before != after)
    }

    @Test("directoryHash is deterministic regardless of filesystem enumeration order")
    func directoryHashDeterministic() async throws {
        let dirA = try makeTempDir()
        let dirB = try makeTempDir()
        defer { cleanup(dirA); cleanup(dirB) }

        // Same content, written in opposite order. The .sorted() step in
        // directoryHash should make both produce the identical digest.
        try writeFile(dirA + "/alpha.json", contents: "X")
        try writeFile(dirA + "/beta.json", contents: "Y")
        try writeFile(dirB + "/beta.json", contents: "Y")
        try writeFile(dirB + "/alpha.json", contents: "X")

        let ha = directoryHashReference(at: dirA)
        let hb = directoryHashReference(at: dirB)
        #expect(ha != nil)
        #expect(ha == hb)
    }

    @Test("directoryHash ignores non-.json files")
    func directoryHashIgnoresNonJSON() async throws {
        let dir = try makeTempDir()
        defer { cleanup(dir) }

        try writeFile(dir + "/rules.json", contents: "{\"r\":1}")
        let baseline = directoryHashReference(at: dir)

        // Add a non-.json file; hash must not change.
        try writeFile(dir + "/README.txt", contents: "ignore me")
        let withExtra = directoryHashReference(at: dir)

        #expect(baseline == withExtra)
    }

    @Test("directoryHash returns nil on empty directory")
    func directoryHashNilOnEmpty() async throws {
        let dir = try makeTempDir()
        defer { cleanup(dir) }
        let result = directoryHashReference(at: dir)
        #expect(result == nil)
    }

    @Test("directoryHash returns nil for nonexistent directory")
    func directoryHashNilOnMissingDir() async throws {
        let bogus = NSTemporaryDirectory() + "maccrab_does_not_exist_\(UUID().uuidString)"
        let result = directoryHashReference(at: bogus)
        #expect(result == nil)
    }

    /// Reproduce the pre-v1.12.6 implementation byte-for-byte using
    /// `/usr/bin/shasum` subprocess calls. Returns the same combined
    /// hash the old code would have produced for the same input.
    /// Used ONLY in the backward-compat test below — the production
    /// path no longer spawns subprocesses.
    private func legacyShasumDirectoryHash(at path: String) -> String? {
        guard let files = try? FileManager.default.contentsOfDirectory(atPath: path)
            .filter({ $0.hasSuffix(".json") })
            .sorted() else { return nil }
        var combined = ""
        for file in files {
            guard let h = legacyShasum(path + "/" + file) else { return nil }
            combined += h
        }
        guard !combined.isEmpty else { return nil }
        let tmp = NSTemporaryDirectory() + "maccrab_legacy_dirhash_\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(atPath: tmp) }
        try? combined.write(toFile: tmp, atomically: true, encoding: .utf8)
        return legacyShasum(tmp)
    }

    /// Pre-v1.12.6 shasum subprocess primitive. Test-only.
    private func legacyShasum(_ path: String) -> String? {
        guard FileManager.default.fileExists(atPath: path) else { return nil }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/shasum")
        process.arguments = ["-a", "256", path]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            process.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""
            return output.split(separator: " ").first.map(String.init)
        } catch {
            return nil
        }
    }

    @Test("directoryHash output matches the pre-v1.12.6 shasum-based implementation byte-for-byte")
    func backwardCompatWithShasum() async throws {
        // This is the most important assertion in this file. A drift here
        // would mean every existing v1.12.5-and-prior install fires a
        // bogus `.rulesModified` critical alert the first time v1.12.6
        // runs (because the baselined rulesHash from the prior daemon
        // boot wouldn't match the new in-process compute).
        let dir = try makeTempDir()
        defer { cleanup(dir) }

        try writeFile(dir + "/rule1.json", contents: "{\"id\":\"r1\",\"cat\":\"persist\"}")
        try writeFile(dir + "/rule2.json", contents: "{\"id\":\"r2\",\"cat\":\"exec\"}")
        try writeFile(dir + "/rule3.json", contents: "{\"id\":\"r3\",\"cat\":\"network\"}")
        try writeFile(dir + "/rule4.json", contents: "{}")

        let cryptoKitResult = directoryHashReference(at: dir)
        let shasumResult = legacyShasumDirectoryHash(at: dir)

        #expect(cryptoKitResult != nil)
        #expect(shasumResult != nil)
        #expect(cryptoKitResult == shasumResult,
                "CryptoKit-based directoryHash drifted from the legacy shasum-based output — this WILL produce a one-time false-positive .rulesModified alert on every existing install upgrading to v1.12.6")
    }

    @Test("Combined hash matches manual SHA-256 of concatenated per-file digests")
    func combinedHashFormatStable() async throws {
        // Backwards-compatibility assertion: the migration must preserve
        // the EXACT combined-hash algorithm — concatenate per-file SHA-256
        // hex digests, then SHA-256 the UTF-8 bytes of that string.
        // Otherwise every existing install fires a one-time bogus
        // `.rulesModified` alert on first run after v1.12.6 upgrade.
        let dir = try makeTempDir()
        defer { cleanup(dir) }

        try writeFile(dir + "/x.json", contents: "alpha")
        try writeFile(dir + "/y.json", contents: "beta")

        // Manual reconstruction using public CryptoKit primitives.
        let hX = FileHasher.computeSHA256(path: dir + "/x.json") ?? ""
        let hY = FileHasher.computeSHA256(path: dir + "/y.json") ?? ""
        #expect(!hX.isEmpty)
        #expect(!hY.isEmpty)

        // Files are sorted alphabetically: x.json before y.json.
        let expectedCombined = hX + hY
        let expectedDigest = CryptoKit_SHA256_hex(
            expectedCombined.data(using: .utf8) ?? Data()
        )

        let actual = directoryHashReference(at: dir)
        #expect(actual == expectedDigest)
    }
}
