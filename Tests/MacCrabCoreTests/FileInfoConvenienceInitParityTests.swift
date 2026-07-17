// FileInfoConvenienceInitParityTests.swift
// v1.21.4 — Tier-B perf item #21: the FileInfo(path:action:) convenience init
// switched from `URL(fileURLWithPath: path)` (which stats the filesystem to
// resolve directory-ness) to `URL(fileURLWithPath: path, isDirectory: false)`
// to drop the per-file-event stat.
//
// DETECTION SAFETY: file.name / file.directory / file.extension feed rules
// (TargetFilename, file.extension). These tests assert the derived values are
// BYTE-IDENTICAL to the previous `URL(fileURLWithPath: path)` output across the
// full edge-case corpus — dotfiles, trailing slash, multi-dot, no-extension,
// root, spaces, unicode, and (decisively) REAL on-disk directories, where the
// old stat-based form would have resolved a trailing-slash directory URL.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("FileInfo convenience init: URL parity (perf item #21)")
struct FileInfoConvenienceInitParityTests {

    /// The pre-change oracle: derive name/directory/extension exactly as the old
    /// convenience init did, via `URL(fileURLWithPath: path)` (stats the disk).
    private func oracle(_ path: String) -> (name: String, directory: String, ext: String?) {
        let url = URL(fileURLWithPath: path)
        return (
            url.lastPathComponent,
            url.deletingLastPathComponent().path,
            url.pathExtension.isEmpty ? nil : url.pathExtension
        )
    }

    private func assertParity(_ path: String, sourceLocation: SourceLocation = #_sourceLocation) {
        let want = oracle(path)
        let got = FileInfo(path: path, action: .write)
        #expect(got.name == want.name, "name mismatch for \(path)", sourceLocation: sourceLocation)
        #expect(got.directory == want.directory, "directory mismatch for \(path)", sourceLocation: sourceLocation)
        #expect(got.extension_ == want.ext, "extension mismatch for \(path)", sourceLocation: sourceLocation)
        // path is passed through verbatim, unchanged by the derivation.
        #expect(got.path == path, "path mismatch for \(path)", sourceLocation: sourceLocation)
    }

    @Test("string-only edge cases derive identically (no filesystem)")
    func stringCorpusParity() {
        let corpus = [
            "/Users/alice/.npmrc",            // dotfile (leading dot)
            "/Users/alice/file.txt",          // normal single-extension
            "/Users/alice/a.b.c",             // multi-dot -> ext = last component
            "/Users/alice/noext",             // no extension
            "/Users/alice/dir/",              // trailing slash
            "/",                              // root
            "/Users/alice/my file.txt",       // spaces
            "/Users/alice/café/naïve.tëxt",   // unicode
            "/Users/alice/.hidden.tar.gz",    // dotfile + multi-dot
            "relative/path.log",              // relative path
            "noslashatall",                   // bare filename
            ".bashrc",                        // bare dotfile
            "/Users/alice/trailingdot.",      // trailing dot
            "/Users/alice/..",                // dotdot component
            "/Users/alice/.",                 // dot component
            "//double//slash//x.y",           // collapsed double slashes
            "/Users/alice/emoji😀/file.md",    // emoji in path
            "",                               // empty string
        ]
        for path in corpus {
            assertParity(path)
        }
    }

    @Test("real on-disk directories still derive identically (the stat-flip case)")
    func realDirectoryParity() throws {
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent("fileinfo-parity-\(UUID().uuidString)")
        try fm.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: root) }

        // A real directory whose name LOOKS like it has an extension (bundle-style):
        // the old `URL(fileURLWithPath:)` stats this, finds a directory, and appends
        // a trailing slash — the exact scenario where a naive change could diverge.
        let bundleDir = root.appendingPathComponent("realdir.app").path
        try fm.createDirectory(atPath: bundleDir, withIntermediateDirectories: true)

        // A real directory with no extension.
        let plainDir = root.appendingPathComponent("plaindir").path
        try fm.createDirectory(atPath: plainDir, withIntermediateDirectories: true)

        // A real file, for symmetry.
        let realFile = root.appendingPathComponent("realfile.txt").path
        #expect(fm.createFile(atPath: realFile, contents: Data("x".utf8)))

        for path in [bundleDir, plainDir, realFile] {
            assertParity(path)
        }
    }
}
