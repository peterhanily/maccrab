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
        #expect(source.contains("let volumeKnown = fstatfs(descriptor, &volume) == 0"))
        #expect(source.contains("if volumeKnown, volume.f_flags & UInt32(MNT_LOCAL) == 0 {"))
        // Bindability is asked of the same descriptor, and an unknown volume is not bindable.
        #expect(source.contains("let imageBindable = volumeKnown\n            && Self.volumeBindsImage(fileSystemTypeName: Self.fileSystemTypeName(of: volume), owner: volume.f_owner)"))
        // A cached or shared digest is bindable only while its file's volume still binds,
        // asked in production of the file's own descriptor.
        #expect(source.contains("imageBindable: await stillBindable(cached.imageBindable, path: path, key: key))"))
        #expect(source.contains("imageBindable: await stillBindable(imageBindable, path: path, key: key))"))
        #expect(source.contains("FileHasher.currentVolumeBindsImage(path: $0, matching: $1)"))
        #expect(!source.contains("lstat("), "a path probe that follows a parent symlink")
        #expect(!source.contains("resourceValues("), "a path-based volume lookup on the actor")
        // The key, which every call takes, comes from one fstatat that
        // refuses symlinks, and the probe opens nothing; only a bindable hit
        // or join opens the file again, to ask its volume.
        let probe = try #require(source.range(of: "nonisolated static func probe(path: String) -> Probe {"))
        let probeEnd = try #require(source.range(of: "nonisolated static func cacheKey(path: String)"))
        let body = source[probe.upperBound..<probeEnd.lowerBound]
        #expect(body.contains("fstatat(AT_FDCWD, resolved, &st, AT_SYMLINK_NOFOLLOW_ANY)"))
        #expect(!body.contains("open(") && !body.contains("fstatfs("))
        // The path recheck runs inside the compute's hop, and a digest is
        // cached before its in-flight entry ends: no window for a second read.
        #expect(source.contains("return .digest(digest, stillInPlace: cacheKey(path: path) == key, imageBindable: imageBindable)"))
        #expect(!source.contains("HeavyEnrichmentBlockingWork.run({ Self.cacheKey(path: path) == key })"))
        let ending = try #require(source.range(of: "defer { inFlight.removeValue(forKey: key) }"))
        let insert = try #require(source.range(of: "if stillInPlace { insert(key, digest: digest, imageBindable: imageBindable) }"))
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
        guard case .digest(_, let stillInPlace, _) = FileHasher.hashAndRecheck(path: path, matching: key) else {
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
                    let volumeKnown = fstatfs(descriptor, &volume) == 0
                    if volumeKnown, volume.f_flags & UInt32(MNT_LOCAL) == 0 {
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

    /// A hasher that does the real identity-bound read but reports the volume
    /// as APFS or not, optionally holding the read until `gate` is signalled.
    /// With `cacheResults` false a later miss can only join the read in
    /// flight or read again, never hit the cache.
    /// `currentVolume` stands in for the question asked before a cached or
    /// shared digest is handed out as bindable (nil asks the file's real
    /// volume); `joins` counts calls that joined the read in flight.
    private func volumeSeam(apfs: Bool, cacheResults: Bool = true,
                            gate: DispatchSemaphore? = nil, calls: Counter? = nil,
                            currentVolume: Bool? = nil, volumeAsks: Counter? = nil,
                            joins: Counter? = nil) -> FileHasher {
        var observer: (@Sendable () -> Void)? = nil
        if let joins { observer = { joins.increment() } }
        return FileHasher(capacity: 16, maxFileBytes: 1 << 20,
                          currentVolumeBinds: { path, key in
                              volumeAsks?.increment()
                              return currentVolume ?? FileHasher.currentVolumeBindsImage(path: path, matching: key)
                          },
                          joinObserverForTesting: observer) { path, key in
            calls?.increment()
            if let gate { _ = gate.wait(timeout: .now() + 10) }
            guard case .digest(let digest, let inPlace, _) = FileHasher.hashAndRecheck(path: path, matching: key) else {
                return .unavailable
            }
            return .digest(digest, stillInPlace: cacheResults && inPlace, imageBindable: apfs)
        }
    }

    @Test("the volume the bytes came from decides bindability, on a miss, a cache hit and a join",
          .timeLimit(.minutes(1)), arguments: [false, true])
    func volumeDecidesBindability(apfs: Bool) async throws {
        let base = try directory()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let path = base + "/tool"
        try Data(repeating: 0x41, count: 4096).write(to: URL(fileURLWithPath: path))
        let digest = try #require(FileHasher.computeSHA256(path: path))

        let hasher = volumeSeam(apfs: apfs)
        let miss = try #require(await hasher.hashWithIdentity(path: path))
        #expect(miss.sha256 == digest)
        #expect(miss.imageBindable == apfs)
        let hit = try #require(await hasher.hashWithIdentity(path: path))
        #expect(await hasher.stats().hits == 1)
        #expect(hit.sha256 == digest)
        #expect(hit.imageBindable == apfs, "the cache keeps the volume's verdict")

        let gate = DispatchSemaphore(value: 0)
        let calls = Counter()
        let held = volumeSeam(apfs: apfs, cacheResults: false, gate: gate, calls: calls)
        async let first = held.hashWithIdentity(path: path)
        async let second = held.hashWithIdentity(path: path)
        try await Task.sleep(nanoseconds: 200_000_000)
        gate.signal()
        let joined = await [first, second]
        #expect(calls.value == 1, "the second miss joined the read in flight")
        for result in joined {
            #expect(result?.sha256 == digest)
            #expect(result?.imageBindable == apfs, "a join keeps the volume's verdict")
        }
    }

    @Test("a real read reports whether its own descriptor's volume binds, and a cache hit asks again")
    func realReadReportsItsVolume() async throws {
        let base = try directory()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let path = base + "/tool"
        try Data(repeating: 0x41, count: 512).write(to: URL(fileURLWithPath: path))
        var volume = statfs()
        #expect(statfs(base, &volume) == 0)
        let binds = FileHasher.volumeBindsImage(
            fileSystemTypeName: FileHasher.fileSystemTypeName(of: volume), owner: volume.f_owner)
        #expect(binds, "the temporary directory is on APFS the system mounted here, so the bindable path is exercised")
        let key = try #require(FileHasher.cacheKey(path: path))
        guard case .digest(_, _, let bindable) = FileHasher.hashFile(path: path, matching: key) else {
            Issue.record("a local file was not hashed")
            return
        }
        #expect(bindable == binds)
        #expect(FileHasher.currentVolumeBindsImage(path: path, matching: key) == binds)
        let hasher = FileHasher()
        #expect(await hasher.hashWithIdentity(path: path)?.imageBindable == binds)
        #expect(await hasher.hashWithIdentity(path: path)?.imageBindable == binds, "a hit asks the file's real volume")
        #expect(await hasher.stats().hits == 1)
    }

    @Test("only APFS the system mounted may bind a digest to an image")
    func bindingVolumeTable() {
        let cases: [(type: String?, owner: uid_t?, binds: Bool)] = [
            ("apfs", 0, true),
            ("apfs", 501, false),
            ("hfs", 0, false), ("msdos", 0, false), ("exfat", 0, false), ("nullfs", 0, false),
            (nil, 0, false), ("apfs", nil, false), (nil, nil, false),
        ]
        for row in cases {
            #expect(FileHasher.volumeBindsImage(fileSystemTypeName: row.type, owner: row.owner) == row.binds,
                    "\(row.type ?? "unknown volume") owned by \(row.owner.map { String($0) } ?? "unknown")")
        }
    }

    @Test("the current-volume question is asked of the key's own file")
    func currentVolumeQuestionNeedsTheKeyedFile() throws {
        let base = try directory()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let path = base + "/tool"
        try Data(repeating: 0x41, count: 512).write(to: URL(fileURLWithPath: path))
        let key = try #require(FileHasher.cacheKey(path: path))
        #expect(FileHasher.currentVolumeBindsImage(path: path, matching: key),
                "the temporary directory is on APFS the system mounted here")
        let other = base + "/other"
        try Data(repeating: 0x42, count: 512).write(to: URL(fileURLWithPath: other))
        #expect(rename(other, path) == 0)
        #expect(!FileHasher.currentVolumeBindsImage(path: path, matching: key), "another file now holds the path")
        #expect(!FileHasher.currentVolumeBindsImage(path: base + "/missing", matching: key))
    }

    /// Waits until `condition` holds, recording an issue after `seconds`.
    private func waitFor(_ seconds: Int = 10, _ condition: @escaping () -> Bool) async throws {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(seconds))
        while !condition() {
            guard clock.now < deadline else {
                Issue.record("timed out waiting for the condition")
                return
            }
            try await Task.sleep(for: .milliseconds(2))
        }
    }

    @Test("a cached or shared bindable digest is handed out unbound once its file's volume no longer binds",
          .timeLimit(.minutes(1)))
    func hitAndJoinAskTheVolumeAgain() async throws {
        let base = try directory()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let path = base + "/tool"
        try Data(repeating: 0x41, count: 4096).write(to: URL(fileURLWithPath: path))
        let digest = try #require(FileHasher.computeSHA256(path: path))

        // The read was on APFS the system mounted; since then the volume was
        // detached and one a user mounted attached on its device number,
        // which the current-volume question reports.
        let asks = Counter()
        let hasher = volumeSeam(apfs: true, currentVolume: false, volumeAsks: asks)
        let miss = try #require(await hasher.hashWithIdentity(path: path))
        #expect(miss.imageBindable, "a miss decides from its own descriptor")
        #expect(asks.value == 0)
        let hit = try #require(await hasher.hashWithIdentity(path: path))
        #expect(await hasher.stats().hits == 1)
        #expect(hit.sha256 == digest, "the digest is still reported")
        #expect(hit.identity == miss.identity)
        #expect(!hit.imageBindable, "a cached digest is unbound once its file's volume no longer binds")
        #expect(asks.value == 1)
        // While the volume still binds, the hit keeps the binding.
        let steady = volumeSeam(apfs: true, currentVolume: true)
        _ = await steady.hashWithIdentity(path: path)
        #expect(await steady.hashWithIdentity(path: path)?.imageBindable == true)

        // A join: the second call waits on the read the first started, and
        // the read is released only once the join is waiting.
        let gate = DispatchSemaphore(value: 0)
        let calls = Counter()
        let joins = Counter()
        let joinAsks = Counter()
        let held = volumeSeam(apfs: true, cacheResults: false, gate: gate, calls: calls,
                              currentVolume: false, volumeAsks: joinAsks, joins: joins)
        async let first = held.hashWithIdentity(path: path)
        async let second = held.hashWithIdentity(path: path)
        try await waitFor { joins.value == 1 }
        gate.signal()
        let results = await [first, second].compactMap { $0 }
        #expect(results.count == 2)
        #expect(calls.value == 1, "the second call joined the read in flight")
        #expect(results.allSatisfy { $0.sha256 == digest })
        #expect(results.filter(\.imageBindable).count == 1, "only the read's own result is bound")
        #expect(joinAsks.value == 1, "the join asked about the file's current volume")
    }

    @Test("a volume's type name is read within its fixed field")
    func fileSystemTypeNames() {
        func volume(named name: String) -> statfs {
            var volume = statfs()
            withUnsafeMutableBytes(of: &volume.f_fstypename) { raw in
                for (index, byte) in name.utf8.prefix(raw.count).enumerated() { raw[index] = byte }
            }
            return volume
        }
        for name in ["apfs", "hfs", "msdos", "exfat"] {
            #expect(FileHasher.fileSystemTypeName(of: volume(named: name)) == name)
        }
        // A full field without a terminator is read to its end, not past it.
        let width = MemoryLayout.size(ofValue: statfs().f_fstypename)
        let full = String(repeating: "x", count: width)
        #expect(FileHasher.fileSystemTypeName(of: volume(named: full)) == full)
        #expect(FileHasher.fileSystemTypeName(of: statfs()).isEmpty)
        #expect(FileHasher.fileSystemTypeName(of: volume(named: "apfsx")) != "apfs")
    }

    @Test("a stat device number converts one way, without trapping on the sign bit")
    func deviceNumberConversion() throws {
        #expect(HeavyEnrichmentFileIdentity.deviceID(fromStatDevice: 16_777_231) == 16_777_231)
        #expect(HeavyEnrichmentFileIdentity.deviceID(fromStatDevice: 0) == 0)
        #expect(HeavyEnrichmentFileIdentity.deviceID(fromStatDevice: -1) == UInt64.max)
        #expect(HeavyEnrichmentFileIdentity.deviceID(fromStatDevice: dev_t.min)
            == UInt64(bitPattern: Int64(dev_t.min)))
        // The hasher's key and the image identity agree for a real file.
        let base = try directory()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let path = base + "/tool"
        try Data(repeating: 0x41, count: 512).write(to: URL(fileURLWithPath: path))
        let key = try #require(FileHasher.cacheKey(path: path))
        #expect(key.fileIdentity == HeavyEnrichmentFileIdentity.capture(path: path))
    }

    @Test("no source converts a stat device number with a conversion that traps")
    func noTrappingDeviceConversion() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let sources = root.appendingPathComponent("Sources")
        let pattern = try NSRegularExpression(pattern: #"UInt64\(\s*[A-Za-z_.]*st_dev\s*\)"#)
        var offenders: [String] = []
        let files = try #require(FileManager.default.enumerator(at: sources, includingPropertiesForKeys: nil))
        for case let url as URL in files where url.pathExtension == "swift" {
            let text = try String(contentsOf: url, encoding: .utf8)
            if pattern.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)) != nil {
                offenders.append(url.lastPathComponent)
            }
        }
        #expect(offenders.isEmpty, "UInt64(_:) traps on a negative dev_t: \(offenders)")
    }

    @Test("a digest is returned with the identity of the file it hashed")
    func digestCarriesIdentity() async throws {
        let base = try directory()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let path = base + "/tool"
        try Data(repeating: 0x41, count: 70_000).write(to: URL(fileURLWithPath: path))
        let hasher = FileHasher()
        let hashed = try #require(await hasher.hashWithIdentity(path: path))
        #expect(hashed.sha256 == FileHasher.computeSHA256(path: path))
        #expect(hashed.identity == HeavyEnrichmentFileIdentity.capture(path: path))
        #expect(await hasher.hash(path: path) == hashed.sha256)
        // Served from the cache now, with the same identity.
        #expect(await hasher.hashWithIdentity(path: path) == hashed)
        #expect(await hasher.stats().hits == 2)
        // Replacing the file gives a new identity with the new digest.
        let replacement = base + "/replacement"
        try Data(repeating: 0x42, count: 70_000).write(to: URL(fileURLWithPath: replacement))
        #expect(rename(replacement, path) == 0)
        let replaced = try #require(await hasher.hashWithIdentity(path: path))
        #expect(replaced.sha256 != hashed.sha256)
        #expect(replaced.identity != hashed.identity)
        #expect(replaced.identity == HeavyEnrichmentFileIdentity.capture(path: path))
    }
}
