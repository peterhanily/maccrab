// CodeSigningCacheExtendedTests.swift
// Verifies the Phase 1 extensions to CodeSignatureInfo (issuerChain,
// certHashes, isAdhocSigned) are populated by CodeSigningCache.evaluate.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("CodeSigningCache extended fields")
struct CodeSigningCacheExtendedTests {

    /// A system binary that's Apple-signed on every macOS version MacCrab
    /// targets. Used as a positive fixture for the extended fields.
    private let appleBinary = "/bin/ls"

    @Test("Apple-signed binary populates authorities and issuerChain")
    func appleSignedChain() async throws {
        // Skip if /bin/ls is unexpectedly absent (CI hardened images).
        guard FileManager.default.fileExists(atPath: appleBinary) else {
            return
        }

        let cache = CodeSigningCache()
        let info = await cache.evaluate(path: appleBinary)

        #expect(info.signerType == .apple, "Expected Apple signer for /bin/ls")
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
}
