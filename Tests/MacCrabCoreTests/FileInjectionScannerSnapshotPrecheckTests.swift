import Foundation
import Testing
@testable import MacCrabCore

/// The cached-snapshot pre-check may only skip a read the descriptor-pinned
/// reader would have answered with the same nil verdict. Files live in a
/// private temporary directory; nothing outside it is touched.
@Suite("File injection scanner snapshot pre-check")
struct FileInjectionScannerSnapshotPrecheckTests {
    private static let carrier = "a\u{200B}b\u{200C}c\u{200D}d"

    private func makeFile(_ content: String) throws -> (dir: URL, path: String) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("fis-precheck-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let path = dir.appendingPathComponent("notes.md").path
        try content.write(toFile: path, atomically: true, encoding: .utf8)
        return (dir, path)
    }

    private func inode(_ path: String) throws -> UInt64 {
        var info = stat()
        try #require(lstat(path, &info) == 0)
        return UInt64(info.st_ino)
    }

    @Test("an in-place rewrite of the same inode is read and rescanned")
    func inPlaceRewriteRescans() async throws {
        // Same byte length as the carrier, so only content and ctime change:
        // size and inode alone cannot reveal the rewrite.
        let clean = String(repeating: "x", count: Self.carrier.utf8.count)
        let (dir, path) = try makeFile(clean)
        defer { try? FileManager.default.removeItem(at: dir) }
        let scanner = FileInjectionScanner()
        #expect(await scanner.scanFile(path: path, eventAction: "open") == nil)
        let before = try inode(path)

        let handle = try #require(FileHandle(forWritingAtPath: path))
        try handle.truncate(atOffset: 0)
        try handle.write(contentsOf: Data(Self.carrier.utf8))
        try handle.close()
        #expect(try inode(path) == before)  // same inode; only content and ctime changed

        let rescanned = await scanner.scanFile(path: path, eventAction: "close_modified")
        #expect(rescanned?.isInjected == true)
        // The rescanned snapshot is now cached, as before.
        #expect(await scanner.scanFile(path: path, eventAction: "open") == nil)
    }

    @Test("a multiply-linked file falls through to the reader's own rejection")
    func hardLinkFallsThrough() async throws {
        let (dir, path) = try makeFile(Self.carrier)
        defer { try? FileManager.default.removeItem(at: dir) }
        let scanner = FileInjectionScanner()
        #expect(await scanner.scanFile(path: path, eventAction: "open")?.isInjected == true)

        let link = dir.appendingPathComponent("alias.md").path
        try FileManager.default.linkItem(atPath: path, toPath: link)
        // nlink > 1: the reader refuses the carrier, with or without the pre-check.
        #expect(await scanner.scanFile(path: path, eventAction: "open") == nil)

        try FileManager.default.removeItem(atPath: link)
        let handle = try #require(FileHandle(forWritingAtPath: path))
        try handle.seekToEnd()
        try handle.write(contentsOf: Data("\u{200B}".utf8))
        try handle.close()
        // Single link again and changed: a full read and a finding.
        #expect(await scanner.scanFile(path: path, eventAction: "open")?.isInjected == true)
    }

    @Test("an unchanged single-link snapshot is coalesced without a new finding")
    func unchangedSnapshotCoalesces() async throws {
        let (dir, path) = try makeFile(Self.carrier)
        defer { try? FileManager.default.removeItem(at: dir) }
        let scanner = FileInjectionScanner()
        #expect(await scanner.scanFile(path: path, eventAction: "open")?.isInjected == true)
        for _ in 0..<3 {
            #expect(await scanner.scanFile(path: path, eventAction: "open") == nil)
        }
    }
}
