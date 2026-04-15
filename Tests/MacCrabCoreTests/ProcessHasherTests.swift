// ProcessHasherTests.swift
// Unit tests for the combined SHA-256 + CDHash ProcessHasher actor.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("Process Hasher")
struct ProcessHasherTests {

    private func makeTempFile(bytes: Data) throws -> String {
        let path = NSTemporaryDirectory() + "maccrab_process_hasher_\(UUID().uuidString).bin"
        try bytes.write(to: URL(fileURLWithPath: path))
        return path
    }

    private func cleanup(_ path: String) {
        try? FileManager.default.removeItem(atPath: path)
    }

    @Test("Returns nil SHA-256 for missing path")
    func missingPath() async {
        let hasher = ProcessHasher()
        let result = await hasher.hash(pid: 999_999, executablePath: "/does/not/exist/\(UUID().uuidString)")
        #expect(result.sha256 == nil)
    }

    @Test("Produces SHA-256 for an existing file")
    func existingFile() async throws {
        let path = try makeTempFile(bytes: "hello".data(using: .utf8)!)
        defer { cleanup(path) }

        let hasher = ProcessHasher()
        let result = await hasher.hash(pid: 999_999, executablePath: path)
        #expect(result.sha256 == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
    }

    @Test("hashFile shortcut returns SHA-256 without needing a PID")
    func hashFileShortcut() async throws {
        let path = try makeTempFile(bytes: Data())
        defer { cleanup(path) }

        let hasher = ProcessHasher()
        let digest = await hasher.hashFile(path: path)
        #expect(digest == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }

    @Test("hasAny is true when at least one hash is produced")
    func hasAnyFlag() async throws {
        let path = try makeTempFile(bytes: "data".data(using: .utf8)!)
        defer { cleanup(path) }

        let hasher = ProcessHasher()
        let result = await hasher.hash(pid: 999_999, executablePath: path)
        #expect(result.hasAny)
    }

    @Test("Shares the injected FileHasher for cache reuse")
    func sharedFileHasher() async throws {
        let path = try makeTempFile(bytes: "shared".data(using: .utf8)!)
        defer { cleanup(path) }

        let shared = FileHasher()
        let hasher = ProcessHasher(fileHasher: shared)

        _ = await hasher.hashFile(path: path)
        _ = await hasher.hashFile(path: path)

        let stats = await shared.stats()
        #expect(stats.misses == 1)
        #expect(stats.hits == 1)
    }
}
