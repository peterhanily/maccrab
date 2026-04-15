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

    private struct CacheKey: Hashable {
        let path: String
        let mtime: Double
        let size: Int64
    }

    private let logger = Logger(subsystem: "com.maccrab.enrichment", category: "file-hasher")
    private let capacity: Int
    private let maxFileBytes: Int64

    private var cache: [CacheKey: String] = [:]
    /// Front of the list is most recently used.
    private var lru: [CacheKey] = []
    private var statsStore = Stats()

    // MARK: - Init

    /// Creates a file hasher.
    ///
    /// - Parameters:
    ///   - capacity: Max cache entries before LRU eviction (default 4096).
    ///   - maxFileBytes: Files larger than this are skipped (default 256 MB).
    public init(capacity: Int = 4096, maxFileBytes: Int64 = 256 * 1024 * 1024) {
        precondition(capacity > 0, "capacity must be > 0")
        precondition(maxFileBytes > 0, "maxFileBytes must be > 0")
        self.capacity = capacity
        self.maxFileBytes = maxFileBytes
    }

    // MARK: - Public API

    /// Returns the SHA-256 hex digest of `path`, or `nil` if the file is
    /// unavailable, too large, on a network mount, or errors during I/O.
    public func hash(path: String) -> String? {
        let fm = FileManager.default

        // Type, size, mtime in one call.
        guard let attrs = try? fm.attributesOfItem(atPath: path) else {
            statsStore.skippedMissing += 1
            return nil
        }

        // Regular files only.
        guard let fileType = attrs[.type] as? FileAttributeType,
              fileType == .typeRegular else {
            statsStore.skippedMissing += 1
            return nil
        }

        // Size cap.
        let size = (attrs[.size] as? NSNumber)?.int64Value ?? 0
        if size > maxFileBytes {
            statsStore.skippedSize += 1
            return nil
        }

        // Modification date for cache key.
        guard let mtimeDate = attrs[.modificationDate] as? Date else {
            statsStore.skippedMissing += 1
            return nil
        }

        // Network-filesystem skip.
        if isOnNetworkFS(path: path) {
            statsStore.skippedNetwork += 1
            return nil
        }

        let key = CacheKey(path: path, mtime: mtimeDate.timeIntervalSince1970, size: size)
        if let cached = cache[key] {
            statsStore.hits += 1
            touch(key)
            return cached
        }

        // Cache miss: compute.
        guard let digest = Self.computeSHA256(path: path) else {
            statsStore.errors += 1
            return nil
        }

        statsStore.misses += 1
        insert(key, digest: digest)
        return digest
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
        cache[key] = digest
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

    // MARK: - Private hashing

    /// Compute SHA-256 of file contents via streaming 64 KB chunks.
    ///
    /// Nonisolated: pure I/O + CryptoKit, no actor state touched.
    nonisolated private static func computeSHA256(path: String) -> String? {
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
            while let data = try handle.read(upToCount: chunkSize), !data.isEmpty {
                hasher.update(data: data)
            }
        } catch {
            return nil
        }

        let digest = hasher.finalize()
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
