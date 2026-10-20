import Foundation
import Testing
@testable import MacCrabCore

@Suite("File identity digest cache")
struct FileIdentityDigestCacheTests {
    @Test("a digest is reused for an unchanged file and recomputed after any write")
    func reuseUntilChanged() throws {
        let path = NSTemporaryDirectory() + "maccrab_digest_\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(atPath: path) }
        try Data(repeating: 0x41, count: 4096).write(to: URL(fileURLWithPath: path))
        let cache = FileIdentityDigestCache()
        var computations = 0
        let compute: (String) -> String? = { computations += 1; return FileHasher.computeSHA256(path: $0) }

        let first = try #require(cache.sha256(of: path, compute: compute))
        #expect(cache.sha256(of: path, compute: compute) == first)
        #expect(computations == 1)

        // Same size, restored mtime: the change time still moves.
        let mtime = try FileManager.default.attributesOfItem(atPath: path)[.modificationDate] as? Date
        let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: path))
        try handle.write(contentsOf: Data(repeating: 0x42, count: 4096))
        try handle.close()
        try FileManager.default.setAttributes([.modificationDate: try #require(mtime)], ofItemAtPath: path)
        let second = try #require(cache.sha256(of: path, compute: compute))
        #expect(second != first)
        #expect(computations == 2)
        #expect(cache.sha256(of: NSTemporaryDirectory() + "absent-\(UUID().uuidString)", compute: compute) == nil)
    }
}
