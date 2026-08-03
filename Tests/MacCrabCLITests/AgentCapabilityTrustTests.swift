import Foundation
import Darwin
import Testing
@testable import maccrab_mcp

@Suite("MCP capability trust anchor")
struct AgentCapabilityTrustTests {
    private func temporaryDirectory() throws -> String {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-cap-trust-\(UUID().uuidString)").path
        try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: false)
        return path
    }

    @Test("Only a bounded single-link non-writable trusted-owner file grants tiers")
    func strictFileTrust() throws {
        let dir = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let path = dir + "/mcp_capabilities.json"
        try Data(#"{"config":true,"authoring":false,"response":true}"#.utf8)
            .write(to: URL(fileURLWithPath: path))
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: path)

        let trusted = readTrustedAgentCapabilities(
            at: path, expectedOwnerUID: getuid())
        #expect(trusted == [.config, .response])

        // Root ownership would not save a mode-0666 production file: another
        // uid can modify its bytes in place while st_uid remains root.
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o666], ofItemAtPath: path)
        #expect(readTrustedAgentCapabilities(
            at: path, expectedOwnerUID: getuid()).isEmpty)

        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: path)
        let hardlink = dir + "/second-link.json"
        try FileManager.default.linkItem(atPath: path, toPath: hardlink)
        #expect(readTrustedAgentCapabilities(
            at: path, expectedOwnerUID: getuid()).isEmpty)
    }

    @Test("Symlink, FIFO, and oversized carriers fail closed without blocking")
    func hostileCarriers() throws {
        let dir = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let target = dir + "/target.json"
        try Data(#"{"config":true,"authoring":true,"response":true}"#.utf8)
            .write(to: URL(fileURLWithPath: target))
        let link = dir + "/link.json"
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: target)
        #expect(readTrustedAgentCapabilities(
            at: link, expectedOwnerUID: getuid()).isEmpty)

        let fifo = dir + "/fifo.json"
        try #require(mkfifo(fifo, 0o600) == 0)
        let started = Date()
        #expect(readTrustedAgentCapabilities(
            at: fifo, expectedOwnerUID: getuid()).isEmpty)
        #expect(Date().timeIntervalSince(started) < 1)

        let oversized = dir + "/oversized.json"
        #expect(FileManager.default.createFile(atPath: oversized, contents: Data()))
        try #require(truncate(oversized, 64 * 1024 + 1) == 0)
        #expect(readTrustedAgentCapabilities(
            at: oversized, expectedOwnerUID: getuid()).isEmpty)
    }
}
