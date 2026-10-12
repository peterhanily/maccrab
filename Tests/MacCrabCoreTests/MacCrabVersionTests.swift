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

    // No binaries are executed and no process-wide environment or cwd is changed.
    private func withVersionFixture(_ body: (URL, URL, URL) throws -> Void) throws {
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent(
            "MacCrabVersionTests-\(UUID().uuidString)", isDirectory: true)
        try fm.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? fm.removeItem(at: root) }
        let contents = root.appendingPathComponent("MacCrab.app/Contents", isDirectory: true)
        let bin = contents.appendingPathComponent("Resources/bin", isDirectory: true)
        try fm.createDirectory(at: bin, withIntermediateDirectories: true)
        let tool = bin.appendingPathComponent("maccrabctl")
        try Data("inert fixture, not executable".utf8).write(to: tool)
        let plist = contents.appendingPathComponent("Info.plist")
        let data = try PropertyListSerialization.data(
            fromPropertyList: ["CFBundleShortVersionString": "9.8.7-rc.2"],
            format: .xml, options: 0)
        try data.write(to: plist)
        try body(root, tool, plist)
    }

    @Test("direct bundled tool reads the enclosing prerelease version")
    func directBundledToolVersion() throws {
        try withVersionFixture { _, tool, _ in
            #expect(MacCrabVersion.enclosingAppVersion(executableURL: tool) == "9.8.7-rc.2")
        }
    }

    @Test("selected external executable URL resolves absolute, relative and chained symlinks")
    func selectedExecutableSymlinkVersions() throws {
        try withVersionFixture { root, tool, _ in
            let fm = FileManager.default
            let aliases = root.appendingPathComponent("usr/local/bin", isDirectory: true)
            try fm.createDirectory(at: aliases, withIntermediateDirectories: true)
            // If the selected URL is not resolved, its parent walk reaches this
            // unrelated plist instead of the actual executable's app version.
            let decoy = try PropertyListSerialization.data(
                fromPropertyList: ["CFBundleShortVersionString": "0.0.0"],
                format: .xml, options: 0)
            try decoy.write(to: root.appendingPathComponent("usr/Info.plist"))
            let absolute = aliases.appendingPathComponent("maccrabctl")
            try fm.createSymbolicLink(atPath: absolute.path, withDestinationPath: tool.path)
            let relative = aliases.appendingPathComponent("relative-tool")
            try fm.createSymbolicLink(atPath: relative.path,
                withDestinationPath: "../../../MacCrab.app/Contents/Resources/bin/maccrabctl")
            let chained = aliases.appendingPathComponent("chained-tool")
            try fm.createSymbolicLink(atPath: chained.path, withDestinationPath: "relative-tool")
            for selectedURL in [absolute, relative, chained] {
                #expect(MacCrabVersion.enclosingAppVersion(executableURL: selectedURL) == "9.8.7-rc.2")
            }
        }
    }

    @Test("symlinked app directory resolves to the executable's real enclosing plist")
    func symlinkedAppDirectoryVersion() throws {
        try withVersionFixture { root, _, _ in
            let alias = root.appendingPathComponent("linked-app", isDirectory: true)
            try FileManager.default.createSymbolicLink(atPath: alias.path,
                withDestinationPath: "MacCrab.app")
            let selectedURL = alias.appendingPathComponent("Contents/Resources/bin/maccrabctl")
            #expect(MacCrabVersion.enclosingAppVersion(executableURL: selectedURL) == "9.8.7-rc.2")
        }
    }

    @Test("missing, malformed and non-string enclosing versions preserve the fallback path")
    func unavailableEnclosingVersion() throws {
        try withVersionFixture { _, tool, plist in
            try FileManager.default.removeItem(at: plist)
            #expect(MacCrabVersion.enclosingAppVersion(executableURL: tool) == nil)
            try Data("not a property list".utf8).write(to: plist)
            #expect(MacCrabVersion.enclosingAppVersion(executableURL: tool) == nil)
            let nonString = try PropertyListSerialization.data(
                fromPropertyList: ["CFBundleShortVersionString": 42],
                format: .xml, options: 0)
            try nonString.write(to: plist)
            #expect(MacCrabVersion.enclosingAppVersion(executableURL: tool) == nil)
        }
    }
}
