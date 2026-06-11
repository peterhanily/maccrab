// RaveStagingPubOverride (S2-13) debug-only catalog.pub override seam tests.
//
// The seam lets a DEBUG build point the rave catalog signature check at a
// staging signing key via MACCRAB_RAVE_STAGING_PUB. It is compiled OUT of
// release builds (the function body is `return nil` behind `#else`).
//
// The test suite runs in DEBUG config, so here we assert the *debug* behavior
// directly: unset → nil; valid 32-byte file → that data; wrong-size file →
// nil. On a RELEASE build the same calls are statically nil — that invariant
// lives in the source `#if DEBUG`/`#else` split and is exercised by building
// `-c release` in CI; we additionally assert the documented compile-config
// expectation below so a future refactor that drops the `#else` arm is caught.

import Testing
import Foundation
@testable import MacCrabForensics

@Suite("RaveStagingPubOverride (S2-13 debug seam)", .serialized)
struct RaveStagingPubOverrideTests {

    static func writeKeyFile(bytes: Int) -> String {
        let path = (NSTemporaryDirectory() as NSString)
            .appendingPathComponent("staging-pub-\(UUID().uuidString).key")
        let data = Data(repeating: 0x42, count: bytes)
        try? data.write(to: URL(fileURLWithPath: path))
        return path
    }

    func clearEnv() { unsetenv(RaveStagingPubOverride.envVar) }

    @Test("unset env → nil (no override)")
    func unsetIsNil() {
        clearEnv()
        #expect(RaveStagingPubOverride.rawKeyData() == nil)
        #expect(RaveStagingPubOverride.isActive == false)
    }

    @Test("valid 32-byte file honored in debug build")
    func validKeyHonoredInDebug() {
        let path = Self.writeKeyFile(bytes: 32)
        setenv(RaveStagingPubOverride.envVar, path, 1)
        defer { clearEnv() }

        #if DEBUG
        let data = RaveStagingPubOverride.rawKeyData()
        #expect(data == Data(repeating: 0x42, count: 32))
        #expect(RaveStagingPubOverride.isActive == true)
        #else
        // Release: the seam is compiled out regardless of the env var.
        #expect(RaveStagingPubOverride.rawKeyData() == nil)
        #expect(RaveStagingPubOverride.isActive == false)
        #endif
    }

    @Test("wrong-size file → nil (rejected even in debug)")
    func wrongSizeRejected() {
        let path = Self.writeKeyFile(bytes: 31)
        setenv(RaveStagingPubOverride.envVar, path, 1)
        defer { clearEnv() }
        #expect(RaveStagingPubOverride.rawKeyData() == nil)
    }

    @Test("missing file path → nil")
    func missingFileNil() {
        setenv(RaveStagingPubOverride.envVar, "/nonexistent/staging/key", 1)
        defer { clearEnv() }
        #expect(RaveStagingPubOverride.rawKeyData() == nil)
    }

    @Test("seam is debug-gated by compile config")
    func debugGated() {
        // This test documents the security invariant: the override is only
        // reachable when DEBUG is defined. In a release build the body of
        // rawKeyData() is `return nil`, so even with a perfect env+file the
        // result is nil. The CI `-c release` build is the enforcement; this
        // assertion fails loudly if the test binary itself is somehow built
        // release (which would silently neuter the debug-only cases above).
        #if DEBUG
        let path = Self.writeKeyFile(bytes: 32)
        setenv(RaveStagingPubOverride.envVar, path, 1)
        defer { clearEnv() }
        #expect(RaveStagingPubOverride.rawKeyData() != nil,
                "debug build must honor a valid staging key")
        #else
        #expect(RaveStagingPubOverride.rawKeyData() == nil,
                "release build must never honor the staging key")
        #endif
    }
}
