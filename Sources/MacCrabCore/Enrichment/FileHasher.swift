// FileHasher.swift
// MacCrabCore
//
// SHA-256 file hashing with an LRU cache keyed on path + mtime + size.
// Skips network-mounted filesystems and files larger than a configurable cap.

import Foundation
import CryptoKit
import os.log

/// Actor-isolated file hasher used by enrichment.
///
/// Cache semantics: a file's SHA-256 is cached under `(path, mtime, size)`.
/// If any of those change, the entry is effectively invalidated and the file
/// is rehashed on next request. This avoids serving stale hashes for files
/// rewritten in place.
///
/// Files are skipped (return `nil`) under any of:
/// - Path does not exist or is not a regular file
/// - Size exceeds `maxFileBytes` (default 256 MB)
/// - Path resides on a network filesystem (NFS, SMB, AFP, WebDAV, FUSE)
/// - I/O error opening or reading the file
public actor FileHasher {

    // MARK: - Stats

    /// Hit/miss/skip counters for observability.
    public struct Stats: Sendable, Equatable {
        public var hits: Int = 0
        public var misses: Int = 0
        public var skippedSize: Int = 0
        public var skippedNetwork: Int = 0
        public var skippedMissing: Int = 0
        public var errors: Int = 0

        public var total: Int {
            hits + misses + skippedSize + skippedNetwork + skippedMissing + errors
        }
    }

    // MARK: - Private state

    /// Device, inode and change time join size and mtime: a same-size
    /// rewrite with a restored mtime must not keep serving the old digest,
    /// which would hide the new bytes from hash IOCs.
    struct CacheKey: Hashable {
        let path: String
        let device: UInt64
        let inode: UInt64
        let size: Int64
        let mtimeSeconds: Int
        let mtimeNanoseconds: Int
        let ctimeSeconds: Int
        let ctimeNanoseconds: Int
    }

    private let logger = Logger(subsystem: "com.maccrab.enrichment", category: "file-hasher")
    private let capacity: Int
    private let maxFileBytes: Int64

    private var cache: [CacheKey: String] = [:]
    /// Front of the list is most recently used.
    private var lru: [CacheKey] = []
    /// The hash in flight for each (path, identity). The actor suspends
    /// while hashing, so N processes exec'ing one new binary would otherwise
    /// read it N times; later misses for the same bytes wait for this one.
    private var inFlight: [CacheKey: Task<String?, Never>] = [:]
    private var statsStore = Stats()
    /// The digest computation; a seam so tests can hold or fail the hash
    /// that concurrent misses share.
    private let computeDigest: @Sendable (String, CacheKey) -> String?

    // MARK: - Init

    /// Creates a file hasher.
    ///
    /// - Parameters:
    ///   - capacity: Max cache entries before LRU eviction (default 4096).
    ///   - maxFileBytes: Files larger than this are skipped (default 256 MB).
    public init(capacity: Int = 4096, maxFileBytes: Int64 = 256 * 1024 * 1024) {
        self.init(capacity: capacity, maxFileBytes: maxFileBytes,
                  computeDigest: { FileHasher.computeSHA256(path: $0, matching: $1) })
    }

    init(
        capacity: Int,
        maxFileBytes: Int64,
        computeDigest: @escaping @Sendable (String, CacheKey) -> String?
    ) {
        precondition(capacity > 0, "capacity must be > 0")
        precondition(maxFileBytes > 0, "maxFileBytes must be > 0")
        self.capacity = capacity
        self.maxFileBytes = maxFileBytes
        self.computeDigest = computeDigest
    }

    // MARK: - Public API

    /// Returns the SHA-256 hex digest of `path`, or `nil` if the file is
    /// unavailable, too large, on a network mount, or errors during I/O.
    public func hash(path: String) async -> String? {
        // Type, size and identity in one call. lstat: regular files only, as
        // before, so a symlink is never followed.
        guard let key = Self.cacheKey(path: path) else {
            statsStore.skippedMissing += 1
            return nil
        }

        // Size cap.
        if key.size > maxFileBytes {
            statsStore.skippedSize += 1
            return nil
        }

        // Network-filesystem skip.
        if isOnNetworkFS(path: path) {
            statsStore.skippedNetwork += 1
            return nil
        }

        if let cached = cache[key] {
            statsStore.hits += 1
            touch(key)
            return cached
        }

        if let pending = inFlight[key] {
            let digest = await pending.value
            if digest == nil { statsStore.errors += 1 } else { statsStore.hits += 1 }
            return digest
        }

        // Cache miss: compute off the actor and the cooperative pool. Up to
        // 256 MiB is read; concurrent misses for other files proceed. Every
        // later miss for this key waits on this one, so it must always end:
        // the hash reads only the file the key names, never what a swapped
        // path now resolves to (a FIFO that never opens, a device that never
        // ends).
        let compute = computeDigest
        let task = Task<String?, Never> {
            await HeavyEnrichmentBlockingWork.run({ compute(path, key) })
        }
        inFlight[key] = task
        let computed = await task.value
        inFlight.removeValue(forKey: key)
        guard let digest = computed else {
            statsStore.errors += 1
            return nil
        }

        statsStore.misses += 1
        // Cache only a digest of bytes that stayed in place while hashing.
        if Self.cacheKey(path: path) == key {
            insert(key, digest: digest)
        }
        return digest
    }

    static func cacheKey(path: String) -> CacheKey? {
        var st = stat()
        guard lstat(path, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else {
            return nil
        }
        return CacheKey(
            path: path,
            device: UInt64(st.st_dev),
            inode: UInt64(st.st_ino),
            size: Int64(st.st_size),
            mtimeSeconds: st.st_mtimespec.tv_sec,
            mtimeNanoseconds: st.st_mtimespec.tv_nsec,
            ctimeSeconds: st.st_ctimespec.tv_sec,
            ctimeNanoseconds: st.st_ctimespec.tv_nsec
        )
    }

    /// Current observability counters (copy).
    public func stats() -> Stats { statsStore }

    /// Remove any cached entries for `path` (all mtime/size variants).
    public func invalidate(path: String) {
        cache = cache.filter { $0.key.path != path }
        lru.removeAll { $0.path == path }
    }

    /// Clear the entire cache and reset stats.
    public func reset() {
        cache.removeAll()
        lru.removeAll()
        statsStore = Stats()
    }

    /// Current cache population (for tests + diagnostics).
    public func cacheCount() -> Int { cache.count }

    // MARK: - Private LRU

    private func touch(_ key: CacheKey) {
        if let idx = lru.firstIndex(of: key) {
            lru.remove(at: idx)
        }
        lru.insert(key, at: 0)
    }

    private func insert(_ key: CacheKey, digest: String) {
        // Idempotent: a duplicate key in `lru` would later evict the live
        // entry and leave the other copy dangling.
        if cache.updateValue(digest, forKey: key) != nil {
            touch(key)
            return
        }
        lru.insert(key, at: 0)
        while lru.count > capacity {
            let evicted = lru.removeLast()
            cache.removeValue(forKey: evicted)
        }
    }

    // MARK: - Private filesystem probes

    /// Returns true if `path` resides on a non-local volume (network mount).
    /// Conservative: treats lookup failure as "not network" so we don't skip
    /// legitimate local files when URL resource lookup is flaky.
    private func isOnNetworkFS(path: String) -> Bool {
        let url = URL(fileURLWithPath: path)
        guard let values = try? url.resourceValues(forKeys: [.volumeIsLocalKey]),
              let isLocal = values.volumeIsLocal else {
            return false
        }
        return !isLocal
    }

    // MARK: - Hashing

    /// SHA-256 of exactly the file `key` names. The descriptor is opened
    /// without blocking or following a final symlink, and must be a regular
    /// file with the key's device, inode, size, mtime and ctime, before and
    /// after the read; the read stops at the key's size. Anything else, a
    /// path swapped since the lstat that made the key, a file rewritten while
    /// it was read, is unavailable (nil) rather than hashed.
    nonisolated static func computeSHA256(
        path: String,
        matching key: CacheKey,
        afterIdentityCheckForTesting: ((Int32) -> Void)? = nil
    ) -> String? {
        let descriptor = open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { return nil }
        defer { close(descriptor) }
        var opened = stat()
        guard fstat(descriptor, &opened) == 0, identity(of: opened, matches: key) else { return nil }
        // Test seam: a fixture can change the file between the check and the
        // read. Production callers never supply it.
        afterIdentityCheckForTesting?(descriptor)

        var hasher = SHA256()
        let chunkSize = 64 * 1024
        var buffer = [UInt8](repeating: 0, count: chunkSize)
        var remaining = Int(key.size)
        while remaining > 0 {
            let count = buffer.withUnsafeMutableBytes { bytes in
                read(descriptor, bytes.baseAddress, min(chunkSize, remaining))
            }
            if count < 0 {
                if errno == EINTR { continue }
                return nil
            }
            if count == 0 { return nil }   // shorter than the key says
            buffer.withUnsafeBytes { bytes in
                hasher.update(bufferPointer: UnsafeRawBufferPointer(rebasing: bytes[..<count]))
            }
            remaining -= count
        }
        var after = stat()
        guard fstat(descriptor, &after) == 0, identity(of: after, matches: key) else { return nil }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    private nonisolated static func identity(of info: stat, matches key: CacheKey) -> Bool {
        (info.st_mode & S_IFMT) == S_IFREG
            && UInt64(info.st_dev) == key.device
            && UInt64(info.st_ino) == key.inode
            && Int64(info.st_size) == key.size
            && info.st_mtimespec.tv_sec == key.mtimeSeconds
            && info.st_mtimespec.tv_nsec == key.mtimeNanoseconds
            && info.st_ctimespec.tv_sec == key.ctimeSeconds
            && info.st_ctimespec.tv_nsec == key.ctimeNanoseconds
    }

    /// Compute SHA-256 of file contents via streaming 64 KB chunks.
    ///
    /// Nonisolated + public: pure I/O + CryptoKit, no actor state touched.
    /// Exposed so callers that don't need actor-level LRU caching (e.g.
    /// `SelfDefense`'s integrity checks, which compute hashes at startup
    /// and on a 15 s periodic tick) can hash in-process without spawning
    /// per-file `/usr/bin/shasum` subprocesses. The cached `hash(path:)`
    /// instance method remains the preferred entry point for enrichment.
    nonisolated public static func computeSHA256(path: String) -> String? {
        let url = URL(fileURLWithPath: path)
        let handle: FileHandle
        do {
            handle = try FileHandle(forReadingFrom: url)
        } catch {
            return nil
        }
        defer { try? handle.close() }

        var hasher = SHA256()
        let chunkSize = 64 * 1024
        do {
            // v1.7.9: per-iteration autoreleasepool — `handle.read(upToCount:)`
            // returns autoreleased NSConcreteData per chunk. Hashing a 1 GB
            // binary at 64 KB/chunk = 16K autoreleased Data objects. Called
            // from per-file-event paths, accumulates fast — heap evidence
            // on a v1.7.8 install showed 135K × 16 KB NSConcreteData = 2.22 GB
            // private heap as the dominant leak after the v1.7.7 collector
            // wraps. Drains per chunk so memory peak stays at one buffer's
            // worth regardless of file size.
            while true {
                var done = false
                try autoreleasepool {
                    if let data = try handle.read(upToCount: chunkSize), !data.isEmpty {
                        hasher.update(data: data)
                    } else {
                        done = true
                    }
                }
                if done { break }
            }
        } catch {
            return nil
        }

        let digest = hasher.finalize()
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
