// FileAnalyzerIOTests.swift
// SEC-DELTA-1/2: the FileAnalyzer collectors must reject symlinks + over-cap
// files (no unbounded in-process read) and hash via streaming (no whole-file
// load). Pin the shared helper.

import Testing
import Foundation
import CryptoKit
@testable import MacCrabForensics

@Suite("FileAnalyzerIO (SEC-DELTA-1/2)")
struct FileAnalyzerIOTests {

    private func freshDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("fa-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    @Test("regularFileSize: size for a normal file; nil for symlink / dir / oversized / missing")
    func gate() throws {
        let dir = try freshDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("f.bin")
        try Data(repeating: 0xAB, count: 4096).write(to: file)

        #expect(FileAnalyzerIO.regularFileSize(file) == 4096)
        #expect(FileAnalyzerIO.regularFileSize(file, cap: 1024) == nil)          // SEC-DELTA-1: over cap → skip

        let link = dir.appendingPathComponent("link.bin")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: file)
        #expect(FileAnalyzerIO.regularFileSize(link) == nil)                      // SEC-DELTA-2: symlink → reject

        #expect(FileAnalyzerIO.regularFileSize(dir) == nil)                       // a directory → reject
        #expect(FileAnalyzerIO.regularFileSize(dir.appendingPathComponent("nope")) == nil)  // missing → nil
    }

    @Test("streamingSHA256 matches CryptoKit over the same bytes (multi-chunk)")
    func sha() throws {
        let dir = try freshDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("f.bin")
        // > 1 MB so the 1 MB-chunk streaming loop iterates more than once.
        let bytes = Data((0..<(3 * (1 << 20) + 17)).map { UInt8($0 & 0xFF) })
        try bytes.write(to: file)
        let expected = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
        #expect(FileAnalyzerIO.streamingSHA256(file) == expected)
        #expect(FileAnalyzerIO.streamingSHA256(dir.appendingPathComponent("nope")) == nil)
    }
}
