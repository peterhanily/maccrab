// FileHasherTests.swift
// Unit tests for the SHA-256 FileHasher actor.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("File Hasher")
struct FileHasherTests {

    /// SHA-256 of the empty string.
    private let emptySHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    /// Create a temp file with the given bytes, return its path.
    private func makeTempFile(bytes: Data) throws -> String {
        let path = NSTemporaryDirectory() + "maccrab_hasher_\(UUID().uuidString).bin"
        try bytes.write(to: URL(fileURLWithPath: path))
        return path
    }

    private func cleanup(_ path: String) {
        try? FileManager.default.removeItem(atPath: path)
    }

    @Test("Hashes empty file to known SHA-256")
    func emptyFile() async throws {
        let path = try makeTempFile(bytes: Data())
        defer { cleanup(path) }

        let hasher = FileHasher()
        let digest = await hasher.hash(path: path)
        #expect(digest == emptySHA)
    }

    @Test("Hashes known payload to known digest")
    func knownPayload() async throws {
        // echo -n "hello" | shasum -a 256
        // => 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        let path = try makeTempFile(bytes: "hello".data(using: .utf8)!)
        defer { cleanup(path) }

        let hasher = FileHasher()
        let digest = await hasher.hash(path: path)
        #expect(digest == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
    }

    @Test("Cache hit on second call; miss on first")
    func cachesHits() async throws {
        let path = try makeTempFile(bytes: "abc".data(using: .utf8)!)
        defer { cleanup(path) }

        let hasher = FileHasher()
        _ = await hasher.hash(path: path)
        _ = await hasher.hash(path: path)

        let stats = await hasher.stats()
        #expect(stats.misses == 1)
        #expect(stats.hits == 1)
        #expect(stats.total == 2)
    }

    @Test("Mtime change invalidates the cache entry")
    func mtimeInvalidates() async throws {
        let path = try makeTempFile(bytes: "v1".data(using: .utf8)!)
        defer { cleanup(path) }

        let hasher = FileHasher()
        let d1 = await hasher.hash(path: path)

        // Rewrite with new content — mtime AND size change.
        try "v2-longer".data(using: .utf8)!.write(to: URL(fileURLWithPath: path))
        // Ensure mtime is distinct from the previous stat (filesystem timestamp resolution).
        try? FileManager.default.setAttributes(
            [.modificationDate: Date(timeIntervalSinceNow: 1)],
            ofItemAtPath: path
        )

        let d2 = await hasher.hash(path: path)
        #expect(d1 != d2)

        let stats = await hasher.stats()
        #expect(stats.misses == 2)
        #expect(stats.hits == 0)
    }

    @Test("Skips files larger than the configured cap")
    func sizeCapSkips() async throws {
        // 2 KB file, cap set to 1 KB.
        let payload = Data(count: 2048)
        let path = try makeTempFile(bytes: payload)
        defer { cleanup(path) }

        let hasher = FileHasher(capacity: 16, maxFileBytes: 1024)
        let digest = await hasher.hash(path: path)
        #expect(digest == nil)

        let stats = await hasher.stats()
        #expect(stats.skippedSize == 1)
        #expect(stats.misses == 0)
    }

    @Test("Returns nil for nonexistent path")
    func missingPath() async {
        let hasher = FileHasher()
        let digest = await hasher.hash(path: "/definitely/does/not/exist/\(UUID().uuidString)")
        #expect(digest == nil)

        let stats = await hasher.stats()
        #expect(stats.skippedMissing == 1)
    }

    @Test("Returns nil for a directory")
    func directory() async throws {
        let dir = NSTemporaryDirectory() + "maccrab_hasher_dir_\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }

        let hasher = FileHasher()
        let digest = await hasher.hash(path: dir)
        #expect(digest == nil)
    }

    @Test("LRU evicts oldest entry when over capacity")
    func lruEvicts() async throws {
        let hasher = FileHasher(capacity: 2, maxFileBytes: 1024)

        let p1 = try makeTempFile(bytes: "a".data(using: .utf8)!)
        let p2 = try makeTempFile(bytes: "b".data(using: .utf8)!)
        let p3 = try makeTempFile(bytes: "c".data(using: .utf8)!)
        defer { [p1, p2, p3].forEach(cleanup) }

        _ = await hasher.hash(path: p1)        // populates p1
        _ = await hasher.hash(path: p2)        // populates p2  (cache: [p2, p1])
        _ = await hasher.hash(path: p1)        // hit on p1,    (cache: [p1, p2])
        _ = await hasher.hash(path: p3)        // miss, evicts p2 (cache: [p3, p1])

        let count = await hasher.cacheCount()
        #expect(count == 2)

        // Rehashing p2 should be a miss (evicted), p1 should be a hit.
        _ = await hasher.hash(path: p1)
        _ = await hasher.hash(path: p2)

        let stats = await hasher.stats()
        #expect(stats.hits >= 2)
        #expect(stats.misses >= 4)
    }

    @Test("invalidate removes entries for that path")
    func invalidate() async throws {
        let path = try makeTempFile(bytes: "x".data(using: .utf8)!)
        defer { cleanup(path) }

        let hasher = FileHasher()
        _ = await hasher.hash(path: path)
        #expect(await hasher.cacheCount() == 1)

        await hasher.invalidate(path: path)
        #expect(await hasher.cacheCount() == 0)

        _ = await hasher.hash(path: path)
        let stats = await hasher.stats()
        #expect(stats.misses == 2)
    }

    @Test("reset clears cache and stats")
    func resetClears() async throws {
        let path = try makeTempFile(bytes: "y".data(using: .utf8)!)
        defer { cleanup(path) }

        let hasher = FileHasher()
        _ = await hasher.hash(path: path)
        await hasher.reset()

        let stats = await hasher.stats()
        #expect(stats.total == 0)
        #expect(await hasher.cacheCount() == 0)
    }
}
