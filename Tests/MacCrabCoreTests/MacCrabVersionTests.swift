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
        // SemVer core MAJOR.MINOR.PATCH, with an OPTIONAL pre-release suffix
        // ("1.18.0" or an RC build like "1.18.0-rc1"). Release builds ship the
        // strict 3-numeric shape; RC branches carry -rcN. prerelease-check.sh
        // still enforces the strict release shape + release.json parity at
        // publish time, so softening here does not weaken the release gate.
        let core = v.split(separator: "-", maxSplits: 1).first.map(String.init) ?? v
        let parts = core.split(separator: ".")
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
