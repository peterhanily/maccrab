// MacCrabVersionTests.swift
// MacCrabCoreTests
//
// v1.9.0 audit: regression test for the version-literal drift class.
// Pre-fix the codebase carried four hardcoded version strings that
// each drifted independently across releases. The single source of
// truth now lives in MacCrabVersion; this test pins its shape so a
// future "let's just hardcode it" reverts get caught at CI time.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("MacCrabVersion: single-source-of-truth shape")
struct MacCrabVersionTests {

    @Test("fallback is non-empty and looks like SemVer")
    func fallbackIsSemVer() {
        let v = MacCrabVersion.fallback
        #expect(!v.isEmpty)
        // Three numeric components separated by dots — strict SemVer
        // shape we ship every release. If this assertion ever needs
        // to soften, prerelease-check.sh's parity comparison with
        // release.json should be updated in the same change.
        let parts = v.split(separator: ".")
        #expect(parts.count == 3)
        for part in parts {
            #expect(Int(String(part)) != nil)
        }
    }

    @Test("current returns a non-empty string in every bundle context")
    func currentReturnsNonEmpty() {
        let v = MacCrabVersion.current
        #expect(!v.isEmpty)
        // In the test bundle context, Bundle.main has no
        // CFBundleShortVersionString, so `current` should fall back
        // to `fallback`. Documenting that pin here.
        #expect(v == MacCrabVersion.fallback)
    }
}
