// CodeSigningCacheExtendedTests.swift
// Verifies the Phase 1 extensions to CodeSignatureInfo (issuerChain,
// certHashes, isAdhocSigned) are populated by CodeSigningCache.evaluate.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("CodeSigningCache extended fields")
struct CodeSigningCacheExtendedTests {

    /// A platform binary whose signature remains available through both the
    /// Security framework and the kernel signature-info API on supported macOS
    /// releases. `/bin/ls` is not a stable certificate-chain fixture on newer
    /// sealed-system releases.
    private let appleBinary = "/usr/bin/true"

    @Test("Apple-signed binary populates authorities and issuerChain")
    func appleSignedChain() async throws {
        // Skip if the platform fixture is unexpectedly absent (CI hardened images).
        guard FileManager.default.fileExists(atPath: appleBinary) else {
            return
        }

        let cache = CodeSigningCache()
        let info = await cache.evaluate(path: appleBinary)

        #expect(info.signerType == .apple, "Expected Apple signer for \(appleBinary)")
        #expect(!info.authorities.isEmpty,
                "Expected at least one cert CN in authorities")

        let issuerChain = try #require(info.issuerChain)
        #expect(issuerChain.count == info.authorities.count - 1,
                "issuerChain should be authorities minus the leaf")
    }

    @Test("certHashes has one entry per authority and each is 64 hex chars")
    func certHashesShape() async throws {
        guard FileManager.default.fileExists(atPath: appleBinary) else {
            return
        }

        let cache = CodeSigningCache()
        let info = await cache.evaluate(path: appleBinary)

        let hashes = try #require(info.certHashes)
        #expect(hashes.count == info.authorities.count,
                "certHashes should be 1:1 with authorities")
        for h in hashes {
            #expect(h.count == 64, "SHA-256 hex is 64 chars; got \(h.count)")
            #expect(h.allSatisfy { $0.isHexDigit },
                    "Hash must be hex: \(h)")
        }
    }

    @Test("Apple-signed binary has isAdhocSigned == false")
    func appleNotAdhoc() async {
        guard FileManager.default.fileExists(atPath: appleBinary) else { return }

        let cache = CodeSigningCache()
        let info = await cache.evaluate(path: appleBinary)
        #expect(info.isAdhocSigned == false)
    }

    @Test("Nonexistent path returns unsigned with nil extended fields")
    func nonexistentPath() async {
        let cache = CodeSigningCache()
        let info = await cache.evaluate(
            path: "/definitely/does/not/exist/\(UUID().uuidString)"
        )
        #expect(info.signerType == .unsigned)
        #expect(info.issuerChain == nil)
        #expect(info.certHashes == nil)
    }

    @Test("Cache returns identical instance on repeat lookups")
    func cachedResultStable() async throws {
        guard FileManager.default.fileExists(atPath: appleBinary) else { return }

        let cache = CodeSigningCache()
        let first = await cache.evaluate(path: appleBinary)
        let second = await cache.evaluate(path: appleBinary)
        #expect(first.authorities == second.authorities)
        #expect(first.certHashes == second.certHashes)
        #expect(first.issuerChain == second.issuerChain)

        let stats = await cache.stats()
        #expect(stats.hits >= 1, "Second lookup should be a cache hit")
    }

    @Test("In-place file replacement invalidates the cached verdict")
    func inPlaceReplacementInvalidatesCache() async throws {
        let fm = FileManager.default
        let path = fm.temporaryDirectory
            .appendingPathComponent("maccrab_cs_\(UUID().uuidString)")
            .path
        // Initial 4 KB file (evaluates to .unsigned — it's not a Mach-O).
        fm.createFile(atPath: path, contents: Data(repeating: 0x41, count: 4096))
        defer { try? fm.removeItem(atPath: path) }

        let cache = CodeSigningCache()

        // First evaluation: cache miss, verdict stored with the file's identity.
        _ = await cache.evaluate(path: path)
        #expect(await cache.stats().misses == 1)

        // Re-evaluating the unchanged file is a cache hit (identity matches).
        _ = await cache.evaluate(path: path)
        #expect(await cache.stats().hits == 1)

        // Replace the binary in place with different bytes. The size (and mtime)
        // change, so the on-disk identity no longer matches the cached entry —
        // the stale (trusted-style) verdict MUST be invalidated and the file
        // re-evaluated (v1.21.4 audit MEDIUM).
        try Data(repeating: 0x42, count: 8192).write(to: URL(fileURLWithPath: path))
        _ = await cache.evaluate(path: path)
        #expect(
            await cache.stats().misses == 2,
            "in-place replacement must force a fresh evaluation, not serve the stale verdict"
        )
    }

    /// A copy of an Apple platform tool keeps its embedded Apple signature,
    /// so it stands in for the genuine binary a spoofer would prime.
    private func appleSignedCopy() throws -> String {
        let fm = FileManager.default
        let dir = fm.temporaryDirectory.appendingPathComponent("maccrab_cs_\(UUID().uuidString)")
        try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        let path = dir.appendingPathComponent("com.apple.helper").path
        try fm.copyItem(atPath: "/usr/bin/true", toPath: path)
        return path
    }

    @Test("A vanished path is a miss and never inherits the verdict primed under it")
    func vanishedPathIsMiss() async throws {
        let fm = FileManager.default
        let path = try appleSignedCopy()
        defer { try? fm.removeItem(atPath: (path as NSString).deletingLastPathComponent) }
        let cache = CodeSigningCache()
        #expect(await cache.evaluate(path: path).signerType == .apple)
        #expect(cache.lookup(path: path)?.signerType == .apple)

        // A self-unlinking spoofer that ran from this path must not be served
        // the genuine binary's verdict once the path is gone.
        try fm.removeItem(atPath: path)
        #expect(cache.lookup(path: path) == nil)
        // Evaluating the missing path stores nothing for a later lookup.
        _ = await cache.evaluate(path: path)
        #expect(cache.lookup(path: path) == nil)
    }

    @Test("A verdict computed while the path was replaced is not bound to the new file")
    func replacementDuringEvaluationIsNotCached() async throws {
        let fm = FileManager.default
        let path = try appleSignedCopy()
        defer { try? fm.removeItem(atPath: (path as NSString).deletingLastPathComponent) }
        let cache = CodeSigningCache(afterEvaluationForTesting: { evaluated in
            // Rename a different file into place mid-evaluation.
            let staged = evaluated + ".staged"
            FileManager.default.createFile(atPath: staged, contents: Data("#!/bin/sh\n".utf8))
            _ = rename(staged, evaluated)
        })
        #expect(await cache.evaluate(path: path).signerType == .apple)
        #expect(cache.lookup(path: path) == nil)
        #expect(await CodeSigningCache().evaluate(path: path).signerType != .apple)
    }

    @Test("A same-size rewrite with a restored mtime is still a miss")
    func restoredMtimeRewriteIsMiss() async throws {
        let fm = FileManager.default
        let path = fm.temporaryDirectory.appendingPathComponent("maccrab_cs_\(UUID().uuidString)").path
        defer { try? fm.removeItem(atPath: path) }
        fm.createFile(atPath: path, contents: Data(repeating: 0x41, count: 4096))
        let cache = CodeSigningCache()
        _ = await cache.evaluate(path: path)
        #expect(cache.lookup(path: path) != nil)
        let original = try fm.attributesOfItem(atPath: path)[.modificationDate] as? Date
        let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: path))
        try handle.write(contentsOf: Data(repeating: 0x42, count: 4096))
        try handle.close()
        try fm.setAttributes([.modificationDate: try #require(original)], ofItemAtPath: path)
        #expect(cache.lookup(path: path) == nil)
    }
}
