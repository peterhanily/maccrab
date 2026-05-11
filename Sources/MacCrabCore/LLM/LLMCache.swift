// LLMCache.swift
// MacCrabCore
//
// In-memory LRU cache for LLM responses. Eviction uses a partial-min
// sweep over the monotonic accessSeq counter — O(n) worst case for the
// rare "delete N oldest from M total" path, with M small (default 100).
// Avoids the previous O(n log n) full-dict sort on every overflow.

import Foundation
import CryptoKit

/// Prevents redundant API calls for repeated identical prompts.
public actor LLMCache {
    private var entries: [String: CacheEntry] = [:]
    private let maxEntries: Int
    private let ttl: TimeInterval

    /// Monotonic access counter. Four rapid inserts can share the
    /// same `Date()` to the millisecond, which made the LRU ordering
    /// undefined and produced a flaky "Cache evicts when over
    /// capacity" test (~1/15). The counter ensures strict insertion/
    /// access order regardless of clock resolution.
    private var accessSeq: UInt64 = 0

    /// Each entry tracks its value, creation time (for TTL), and the
    /// last access sequence number (for LRU ordering).
    private struct CacheEntry {
        let response: String
        let createdAt: Date
        var lastAccessedSeq: UInt64
    }

    public init(maxEntries: Int = 100, ttlSeconds: TimeInterval = 3600) {
        self.maxEntries = maxEntries
        self.ttl = ttlSeconds
    }

    /// Look up a cached response. Returns nil on miss or expiry.
    public func get(key: String) -> String? {
        guard var entry = entries[key] else { return nil }
        if Date().timeIntervalSince(entry.createdAt) > ttl {
            entries.removeValue(forKey: key)
            return nil
        }
        accessSeq += 1
        entry.lastAccessedSeq = accessSeq
        entries[key] = entry
        return entry.response
    }

    /// Store a response in the cache.
    public func set(key: String, response: String) {
        accessSeq += 1
        entries[key] = CacheEntry(
            response: response,
            createdAt: Date(),
            lastAccessedSeq: accessSeq
        )

        // Evict least-recently-accessed entries if over capacity.
        // For the common case (overflow by 1 after a single set), we
        // do a single O(n) min scan — cheaper than O(n log n) sort.
        // For the rare bulk-overflow case (n > maxEntries by k > 1),
        // we repeat the min scan k times: O(n × k) but k is typically
        // 1 and bounded by 1 unless someone inserts in a loop without
        // letting the cache drain.
        let overflow = entries.count - maxEntries
        if overflow > 0 {
            evictOldest(count: overflow)
        }
    }

    /// Remove the `count` entries with the smallest `lastAccessedSeq`.
    /// O(n × count); for the typical count=1 path this is a single
    /// O(n) scan.
    private func evictOldest(count: Int) {
        for _ in 0..<count {
            guard let oldestKey = entries.min(
                by: { $0.value.lastAccessedSeq < $1.value.lastAccessedSeq }
            )?.key else { return }
            entries.removeValue(forKey: oldestKey)
        }
    }

    /// Generate a stable, cross-restart cache key from prompt
    /// components. Pre-fix used Swift's `Hasher` with a random
    /// per-process seed — every daemon restart invalidated the cache,
    /// so a host that restarted hourly paid full LLM cost on every
    /// alert. Now SHA-256 over all inputs that could affect the
    /// response: system + user + temperature + maxTokens. Same
    /// prompt at different temperature settings no longer collides.
    public static func cacheKey(system: String, user: String,
                                temperature: Double = 0.2,
                                maxTokens: Int = 2048) -> String {
        let payload = "\(system)\n\u{1f}\n\(user)\n\u{1f}\n\(temperature)\n\u{1f}\n\(maxTokens)"
        let digest = SHA256.hash(data: Data(payload.utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    public func stats() -> (entries: Int, maxEntries: Int) {
        (entries.count, maxEntries)
    }
}
