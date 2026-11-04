// UserRuleFileWriteTests.swift
// MacCrabCoreTests
//
// The root install-rule handler writes user_rules/<id>.yml and <id>.json. The
// engine loads a user_rules file only when the daemon's euid owns it, so each
// write must leave a new file owned by the writer's euid, mode 0644, and must
// never write through a symlink. A file owned by another uid takes the same
// unlink-then-write path as the symlink and hard-link cases below; creating
// one needs root, so these tests use the cases a normal user can create.
//
// Before the writes, the handler readies the user_rules folder. It refuses a
// folder that lstat finds is not a directory, a symlink included, because the
// chmod that sets the folder to 0755 would follow a symlink.

import Testing
import Foundation
@testable import MacCrabAgentKit

@Suite("User rule file writes")
struct UserRuleFileWriteTests {

    /// SecureFileIO refuses a symlink in any path component other than the
    /// /tmp and /var aliases it rewrites, so the tests use the resolved path
    /// of a fresh temporary folder.
    private func tempDir() throws -> String {
        let dir = NSTemporaryDirectory() + "maccrab-userrule-write-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        guard let resolved = realpath(dir, nil) else {
            try? FileManager.default.removeItem(atPath: dir)
            throw CocoaError(.fileNoSuchFile)
        }
        defer { free(resolved) }
        return String(cString: resolved)
    }

    private func metadata(_ path: String) throws -> stat {
        var st = stat()
        try #require(lstat(path, &st) == 0, "lstat failed for \(path)")
        return st
    }

    private func contents(_ path: String) throws -> Data {
        try Data(contentsOf: URL(fileURLWithPath: path))
    }

    @Test("replacing an existing 0660 file leaves a new inode, mode 0644, owned by this euid")
    func replacesExistingFileWithNewInode() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let path = dir + "/rule.json"
        try Data("{\"level\":\"low\"}".utf8).write(to: URL(fileURLWithPath: path))
        try #require(chmod(path, 0o660) == 0)
        let before = try metadata(path)

        try DaemonTimers.writeUserRuleFile(Data("{\"level\":\"high\"}".utf8), toPath: path)

        let after = try metadata(path)
        #expect(after.st_ino != before.st_ino, "the file was rewritten in place, so it keeps its owner")
        #expect(after.st_mode & S_IFMT == S_IFREG)
        #expect(after.st_mode & 0o7777 == 0o644)
        #expect(after.st_uid == geteuid())
        #expect(try contents(path) == Data("{\"level\":\"high\"}".utf8))
    }

    @Test("a missing file is created with mode 0644")
    func createsMissingFile() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let path = dir + "/rule.yml"

        try DaemonTimers.writeUserRuleFile(Data("title: Fixture\n".utf8), toPath: path)

        let st = try metadata(path)
        #expect(st.st_mode & S_IFMT == S_IFREG)
        #expect(st.st_mode & 0o7777 == 0o644)
        #expect(st.st_uid == geteuid())
        #expect(try contents(path) == Data("title: Fixture\n".utf8))
    }

    @Test("a symlink at the destination is replaced, and the file it points to is unchanged")
    func doesNotFollowSymlink() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let target = dir + "/target.json"
        try Data("target".utf8).write(to: URL(fileURLWithPath: target))
        let path = dir + "/rule.json"
        try FileManager.default.createSymbolicLink(atPath: path, withDestinationPath: target)

        try DaemonTimers.writeUserRuleFile(Data("rule".utf8), toPath: path)

        #expect(try contents(target) == Data("target".utf8))
        let st = try metadata(path)
        #expect(st.st_mode & S_IFMT == S_IFREG)
        #expect(st.st_mode & 0o7777 == 0o644)
        #expect(try contents(path) == Data("rule".utf8))
    }

    @Test("a hard-linked file is replaced, and its other name keeps the old bytes")
    func replacesHardLinkedFile() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let path = dir + "/rule.json"
        let other = dir + "/other.json"
        try Data("old".utf8).write(to: URL(fileURLWithPath: path))
        try #require(link(path, other) == 0)

        try DaemonTimers.writeUserRuleFile(Data("new".utf8), toPath: path)

        #expect(try contents(other) == Data("old".utf8))
        let st = try metadata(path)
        #expect(st.st_nlink == 1)
        #expect(st.st_mode & 0o7777 == 0o644)
        #expect(try contents(path) == Data("new".utf8))
    }

    @Test("a symlinked user_rules folder is refused, and the folder it points to keeps its mode")
    func refusesSymlinkedFolder() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let target = dir + "/elsewhere"
        try FileManager.default.createDirectory(atPath: target, withIntermediateDirectories: false)
        try #require(chmod(target, 0o700) == 0)
        let folder = dir + "/user_rules"
        try FileManager.default.createSymbolicLink(atPath: folder, withDestinationPath: target)

        #expect(try DaemonTimers.prepareUserRulesFolder(atPath: folder) == false)

        #expect(try metadata(target).st_mode & 0o7777 == 0o700)
        #expect(try metadata(folder).st_mode & S_IFMT == S_IFLNK)
    }

    @Test("a regular file named user_rules is refused and left as it was")
    func refusesNonDirectory() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let folder = dir + "/user_rules"
        try Data("not a folder".utf8).write(to: URL(fileURLWithPath: folder))
        try #require(chmod(folder, 0o600) == 0)

        #expect(try DaemonTimers.prepareUserRulesFolder(atPath: folder) == false)

        let st = try metadata(folder)
        #expect(st.st_mode & S_IFMT == S_IFREG)
        #expect(st.st_mode & 0o7777 == 0o600)
        #expect(try contents(folder) == Data("not a folder".utf8))
    }

    @Test("a missing user_rules folder is created with mode 0755")
    func createsMissingFolder() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let folder = dir + "/user_rules"

        #expect(try DaemonTimers.prepareUserRulesFolder(atPath: folder))

        let st = try metadata(folder)
        #expect(st.st_mode & S_IFMT == S_IFDIR)
        #expect(st.st_mode & 0o7777 == 0o755)
    }

    @Test("an existing 0775 user_rules folder is set to 0755")
    func setsExistingFolderMode() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let folder = dir + "/user_rules"
        try FileManager.default.createDirectory(atPath: folder, withIntermediateDirectories: false)
        try #require(chmod(folder, 0o775) == 0)

        #expect(try DaemonTimers.prepareUserRulesFolder(atPath: folder))

        #expect(try metadata(folder).st_mode & 0o7777 == 0o755)
    }
}
