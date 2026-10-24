import CryptoKit
import Foundation
import Testing
@testable import MacCrabCore

/// Every miss for a file waits on the one hash in flight, so that hash must
/// always end, and must hash only the file its key names: a path swapped to a
/// FIFO or a device since the lstat must not block or read without end.
@Suite("File hasher reads only the file its key names")
struct FileHasherIdentityTests {
    private func directory() throws -> String {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-hash-identity-\(UUID().uuidString)").path
        try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true)
        return path
    }

    /// Runs `body` on its own thread and reports whether it finished in time.
    private func finishes<T>(within seconds: TimeInterval, _ body: @escaping @Sendable () -> T) -> (done: Bool, value: T?) {
        let lock = NSLock()
        var value: T?
        let finished = DispatchSemaphore(value: 0)
        Thread.detachNewThread {
            let result = body()
            lock.lock(); value = result; lock.unlock()
            finished.signal()
        }
        let done = finished.wait(timeout: .now() + seconds) == .success
        lock.lock(); defer { lock.unlock() }
        return (done, value)
    }

    @Test("ordinary files hash to the SHA-256 of their bytes")
    func digestsMatchContent() async throws {
        let base = try directory()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let hasher = FileHasher()
        for size in [0, 1, 64 * 1024, 64 * 1024 + 1, 1_000_003] {
            let bytes = (0..<size).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ 7) }
            let path = base + "/file-\(size)"
            #expect(FileManager.default.createFile(atPath: path, contents: Data(bytes)))
            let expected = SHA256.hash(data: Data(bytes)).map { String(format: "%02x", $0) }.joined()
            #expect(await hasher.hash(path: path) == expected, "\(size) bytes")
            #expect(FileHasher.computeSHA256(path: path) == expected, "the public path-based hash is unchanged")
        }
    }

    @Test("a path swapped to a FIFO since its key was taken returns at once")
    func swappedToFIFO() throws {
        let base = try directory()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let path = base + "/bin"
        #expect(FileManager.default.createFile(atPath: path, contents: Data("payload".utf8)))
        let key = try #require(FileHasher.cacheKey(path: path))
        let fifo = base + "/pipe"
        #expect(mkfifo(fifo, 0o600) == 0)
        #expect(rename(fifo, path) == 0)
        let outcome = finishes(within: 5) { FileHasher.computeSHA256(path: path, matching: key) }
        if !outcome.done {
            // Release the reader blocked in open() so the process can exit.
            let writer = open(path, O_WRONLY)
            if writer >= 0 { close(writer) }
        }
        #expect(outcome.done, "the hash must not wait for a FIFO writer")
        #expect(outcome.value ?? nil == nil)
    }

    @Test("a path swapped into a device directory is refused, not read without end")
    func swappedParentToDevice() throws {
        let base = try directory()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let parent = base + "/dir"
        try FileManager.default.createDirectory(atPath: parent, withIntermediateDirectories: false)
        let path = parent + "/zero"
        #expect(FileManager.default.createFile(atPath: path, contents: Data(repeating: 1, count: 4_096)))
        let key = try #require(FileHasher.cacheKey(path: path))
        #expect(rename(parent, base + "/moved") == 0)
        try FileManager.default.createSymbolicLink(atPath: parent, withDestinationPath: "/dev")
        let outcome = finishes(within: 5) { FileHasher.computeSHA256(path: path, matching: key) }
        #expect(outcome.done, "/dev/zero must not be read without end")
        #expect(outcome.value ?? nil == nil)
    }

    @Test("a symlink, or a file changed since its key was taken, is not hashed")
    func symlinkAndChangedFile() throws {
        let base = try directory()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let target = base + "/target"
        #expect(FileManager.default.createFile(atPath: target, contents: Data("one".utf8)))
        let key = try #require(FileHasher.cacheKey(path: target))
        // A link to the very same file still names another path's lookup.
        let link = base + "/link"
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: target)
        #expect(FileHasher.computeSHA256(path: link, matching: key) == nil)

        #expect(FileHasher.computeSHA256(path: target, matching: key) != nil)
        let handle = try #require(FileHandle(forWritingAtPath: target))
        try handle.seekToEnd()
        try handle.write(contentsOf: Data("two".utf8))
        try handle.close()
        #expect(FileHasher.computeSHA256(path: target, matching: key) == nil)
    }

    @Test("a swapped path is refused before any byte is read, and a rewrite during the read is caught after it")
    func checkedBeforeAndAfterTheRead() throws {
        let base = try directory()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let path = base + "/bin"
        #expect(FileManager.default.createFile(atPath: path, contents: Data("same-size-1".utf8)))
        let key = try #require(FileHasher.cacheKey(path: path))

        // Another file of the same size renamed over the path: refused at the
        // open, so nothing of it is read.
        let other = base + "/other"
        #expect(FileManager.default.createFile(atPath: other, contents: Data("same-size-2".utf8)))
        #expect(rename(other, path) == 0)
        var reachedRead = false
        #expect(FileHasher.computeSHA256(path: path, matching: key) { _ in reachedRead = true } == nil)
        #expect(!reachedRead)

        // The named file, grown while it is read: the read stops at the key's
        // size, and the identity no longer matches afterwards.
        let fresh = try #require(FileHasher.cacheKey(path: path))
        let grown = FileHasher.computeSHA256(path: path, matching: fresh) { _ in
            let handle = FileHandle(forWritingAtPath: path)
            try? handle?.seekToEnd()
            try? handle?.write(contentsOf: Data("more".utf8))
            try? handle?.close()
        }
        #expect(grown == nil)
    }

    @Test("misses sharing a hash that fails are all released with nil", .timeLimit(.minutes(1)))
    func sharedFailureReleasesWaiters() async throws {
        let base = try directory()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let path = base + "/bin"
        #expect(FileManager.default.createFile(atPath: path, contents: Data("payload".utf8)))
        let gate = DispatchSemaphore(value: 0)
        let calls = Counter()
        // The shared hash runs the real identity-bound compute after the path
        // is swapped for a FIFO. A miss that arrives after it ends sees the
        // FIFO at its own lstat, so it never computes either.
        let hasher = FileHasher(capacity: 16, maxFileBytes: 1_024) { path, key in
            calls.increment()
            _ = gate.wait(timeout: .now() + 10)
            let fifo = (path as NSString).deletingLastPathComponent + "/pipe"
            guard mkfifo(fifo, 0o600) == 0, rename(fifo, path) == 0 else {
                return .digest("not swapped", stillInPlace: false)
            }
            return FileHasher.hashAndRecheck(path: path, matching: key)
        }
        async let first = hasher.hash(path: path)
        async let second = hasher.hash(path: path)
        try await Task.sleep(nanoseconds: 200_000_000)
        gate.signal()
        let results = await [first, second]
        #expect(results == [nil, nil])
        #expect(calls.value == 1, "one compute for both misses")
        #expect(await hasher.cacheCount() == 0)
    }

    @Test("a parent swapped for a symlink to the same directory is refused")
    func symlinkedParentIsRefused() throws {
        let base = try directory()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let parent = base + "/dir"
        try FileManager.default.createDirectory(atPath: parent, withIntermediateDirectories: false)
        let path = parent + "/bin"
        #expect(FileManager.default.createFile(atPath: path, contents: Data("payload".utf8)))
        let key = try #require(FileHasher.cacheKey(path: path))
        #expect(FileHasher.computeSHA256(path: path, matching: key) != nil)
        // The same inode stays reachable, but only through a symlink, which
        // could as well have pointed at a tty or an automount trigger.
        #expect(rename(parent, base + "/moved") == 0)
        try FileManager.default.createSymbolicLink(atPath: parent, withDestinationPath: base + "/moved")
        #expect(FileHasher.computeSHA256(path: path, matching: key) == nil)
        #expect(FileHasher.computeSHA256(path: base + "/moved/bin", matching: key) != nil)
    }

    @Test("a parent swapped for a symlink fails the key step, before any cache or hash")
    func symlinkedParentFailsTheKey() async throws {
        let base = try directory()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let parent = base + "/dir"
        try FileManager.default.createDirectory(atPath: parent, withIntermediateDirectories: false)
        let path = parent + "/bin"
        #expect(FileManager.default.createFile(atPath: path, contents: Data("payload".utf8)))
        #expect(FileHasher.cacheKey(path: path) != nil)
        // The same file through a symlinked parent, which could as well have
        // led to an automount trigger or a stalled network volume.
        #expect(rename(parent, base + "/moved") == 0)
        try FileManager.default.createSymbolicLink(atPath: parent, withDestinationPath: base + "/moved")
        #expect(FileHasher.probe(path: path) == .unavailable)
        let hasher = FileHasher()
        #expect(await hasher.hash(path: path) == nil)
        #expect(await hasher.stats().skippedMissing == 1)
        #expect(await hasher.hash(path: base + "/moved/bin") != nil)
    }

    @Test("the hasher's path probes run off its actor, and network-ness comes from the descriptor")
    func probesRunOffTheActor() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let source = try String(
            contentsOf: root.appendingPathComponent("Sources/MacCrabCore/Enrichment/FileHasher.swift"),
            encoding: .utf8)
        #expect(source.contains("switch await HeavyEnrichmentBlockingWork.run({ Self.probe(path: path) }) {"))
        #expect(source.contains("if fstatfs(descriptor, &volume) == 0, volume.f_flags & UInt32(MNT_LOCAL) == 0 {"))
        #expect(!source.contains("lstat("), "a path probe that follows a parent symlink")
        #expect(!source.contains("resourceValues("), "a path-based volume lookup on the actor")
        // The key, which every call takes and a cache hit needs nothing more
        // than, comes from one fstatat that refuses symlinks; nothing opens.
        let probe = try #require(source.range(of: "nonisolated static func probe(path: String) -> Probe {"))
        let probeEnd = try #require(source.range(of: "nonisolated static func cacheKey(path: String)"))
        let body = source[probe.upperBound..<probeEnd.lowerBound]
        #expect(body.contains("fstatat(AT_FDCWD, resolved, &st, AT_SYMLINK_NOFOLLOW_ANY)"))
        #expect(!body.contains("open(") && !body.contains("fstatfs("))
        // The path recheck runs inside the compute's hop, and a digest is
        // cached before its in-flight entry ends: no window for a second read.
        #expect(source.contains("return .digest(digest, stillInPlace: cacheKey(path: path) == key)"))
        #expect(!source.contains("HeavyEnrichmentBlockingWork.run({ Self.cacheKey(path: path) == key })"))
        let ending = try #require(source.range(of: "defer { inFlight.removeValue(forKey: key) }"))
        let insert = try #require(source.range(of: "if stillInPlace { insert(key, digest: digest) }"))
        #expect(ending.upperBound < insert.lowerBound, "the digest must be cached in the same actor turn the in-flight entry ends")
    }

    @Test("a miss that overlaps the hash in flight reads the file once, and later calls hit the cache")
    func overlappingMissesReadOnce() async throws {
        let base = try directory()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let path = base + "/bin"
        #expect(FileManager.default.createFile(atPath: path, contents: Data("payload".utf8)))
        let gate = DispatchSemaphore(value: 0)
        let calls = Counter()
        let hasher = FileHasher(capacity: 16, maxFileBytes: 1_024) { path, key in
            calls.increment()
            _ = gate.wait(timeout: .now() + 10)
            return FileHasher.hashAndRecheck(path: path, matching: key)
        }
        async let first = hasher.hash(path: path)
        async let second = hasher.hash(path: path)
        try await Task.sleep(nanoseconds: 200_000_000)
        gate.signal()
        let results = await [first, second]
        #expect(results[0] != nil && results[0] == results[1])
        #expect(await hasher.hash(path: path) == results[0])
        #expect(calls.value == 1, "one read for every request of the same bytes")
        let stats = await hasher.stats()
        #expect(stats.misses == 1 && stats.hits == 2)
    }

    /// The hasher a compute seam calls back into, set once it exists.
    private final class HasherBox: @unchecked Sendable {
        private let lock = NSLock()
        private var hasher: FileHasher?
        private var late: Task<String?, Never>?
        func set(_ hasher: FileHasher) { lock.lock(); self.hasher = hasher; lock.unlock() }
        /// Starts one more request for `path` from inside the compute, once.
        func startLateRequest(for path: String) {
            lock.lock(); defer { lock.unlock() }
            guard late == nil, let hasher else { return }
            late = Task { await hasher.hash(path: path) }
        }
        var lateRequest: Task<String?, Never>? { lock.lock(); defer { lock.unlock() }; return late }
    }

    @Test("a request that lands while the hash ends joins it or hits the cache, never reading again")
    func requestAtTheEndOfAHashReadsNothing() async throws {
        let base = try directory()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let path = base + "/bin"
        #expect(FileManager.default.createFile(atPath: path, contents: Data("payload".utf8)))
        // The late request starts inside the compute, so it reaches the actor
        // while the owner is finishing: with the in-flight entry gone and the
        // digest not yet cached, it would read the file a second time.
        for round in 0..<50 {
            let calls = Counter()
            let box = HasherBox()
            let hasher = FileHasher(capacity: 16, maxFileBytes: 1_024) { path, key in
                calls.increment()
                let computed = FileHasher.hashAndRecheck(path: path, matching: key)
                box.startLateRequest(for: path)
                return computed
            }
            box.set(hasher)
            let digest = await hasher.hash(path: path)
            let late = try #require(box.lateRequest)
            #expect(await late.value == digest)
            #expect(calls.value == 1, "round \(round): a request at the end of the hash read the file again")
            if calls.value != 1 { break }
        }
    }

    @Test("misses sharing a hash on a network volume are all skipped, counted as such, and never cached")
    func networkVolumeIsSkippedForEveryWaiter() async throws {
        let base = try directory()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let path = base + "/bin"
        #expect(FileManager.default.createFile(atPath: path, contents: Data("payload".utf8)))
        let gate = DispatchSemaphore(value: 0)
        let calls = Counter()
        let hasher = FileHasher(capacity: 16, maxFileBytes: 1_024) { _, _ in
            calls.increment()
            _ = gate.wait(timeout: .now() + 10)
            return .network
        }
        async let first = hasher.hash(path: path)
        async let second = hasher.hash(path: path)
        try await Task.sleep(nanoseconds: 200_000_000)
        gate.signal()
        let results = await [first, second]
        #expect(results[0] == nil && results[1] == nil)
        #expect(calls.value == 1, "a waiter computed a second time")
        let stats = await hasher.stats()
        #expect(stats.skippedNetwork == 2 && stats.errors == 0, "\(stats)")
        #expect(await hasher.cacheCount() == 0)
        gate.signal()
        #expect(await hasher.hash(path: path) == nil)
        #expect(calls.value == 2, "a network result was remembered")
    }

    @Test("the hash answers a network volume from its own descriptor; a local file is hashed")
    func networkVolumeComesFromTheDescriptor() throws {
        let base = try directory()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let path = base + "/bin"
        #expect(FileManager.default.createFile(atPath: path, contents: Data("payload".utf8)))
        let key = try #require(FileHasher.cacheKey(path: path))
        guard case .digest(_, let stillInPlace) = FileHasher.hashAndRecheck(path: path, matching: key) else {
            Issue.record("a local file was not hashed")
            return
        }
        #expect(stillInPlace)
        #expect(FileHasher.hashFile(path: path, matching: key) != .network)

        // On a network volume nothing is read: the check comes before the
        // test seam and the read loop, and answers .network.
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let source = try String(
            contentsOf: root.appendingPathComponent("Sources/MacCrabCore/Enrichment/FileHasher.swift"),
            encoding: .utf8)
        let body = try #require(source.range(of: "nonisolated static func hashFile("))
        let tail = source[body.upperBound...]
        let check = try #require(tail.range(of: """
                    if fstatfs(descriptor, &volume) == 0, volume.f_flags & UInt32(MNT_LOCAL) == 0 {
                        return .network
                    }
            """))
        let seam = try #require(tail.range(of: "afterIdentityCheckForTesting?(descriptor)"))
        let read = try #require(tail.range(of: "var hasher = SHA256()"))
        #expect(check.upperBound < seam.lowerBound && check.upperBound < read.lowerBound)
    }

    @Test("the read stops at the key's size while the file grows")
    func readStopsAtTheKeySize() throws {
        let base = try directory()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let path = base + "/bin"
        #expect(FileManager.default.createFile(atPath: path, contents: Data(repeating: 7, count: 100 * 1_024)))
        let key = try #require(FileHasher.cacheKey(path: path))
        var duplicate: Int32 = -1
        _ = FileHasher.computeSHA256(path: path, matching: key) { descriptor in
            // A dup shares the hash's file offset; grow the file as it is read.
            duplicate = dup(descriptor)
            let handle = FileHandle(forWritingAtPath: path)
            try? handle?.seekToEnd()
            try? handle?.write(contentsOf: Data(repeating: 9, count: 1_024 * 1_024))
            try? handle?.close()
        }
        #expect(duplicate >= 0)
        let offset = lseek(duplicate, 0, SEEK_CUR)
        close(duplicate)
        #expect(offset == off_t(key.size), "a read to the moving end of file need not terminate")
    }

    @Test("the enrichment hasher uses the identity-bound hash")
    func productionWiring() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let source = try String(
            contentsOf: root.appendingPathComponent("Sources/MacCrabCore/Enrichment/FileHasher.swift"),
            encoding: .utf8)
        #expect(source.contains("computeDigest: { FileHasher.hashAndRecheck(path: $0, matching: $1) }"))
        #expect(source.contains("let computed = hashFile(path: path, matching: key)"))
        #expect(source.contains("await HeavyEnrichmentBlockingWork.run({ compute(path, key) })"))
    }

    private final class Counter: @unchecked Sendable {
        private let lock = NSLock()
        private var count = 0
        func increment() { lock.lock(); count += 1; lock.unlock() }
        var value: Int { lock.lock(); defer { lock.unlock() }; return count }
    }
}
