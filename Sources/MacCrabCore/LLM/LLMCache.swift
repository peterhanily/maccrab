// LLMCache.swift
// MacCrabCore
//
// In-memory LRU cache for LLM responses.
// Uses a dictionary + doubly-linked list for O(1) get/set/evict.

import Foundation

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
        if entries.count > maxEntries {
            let sorted = entries.sorted { $0.value.lastAccessedSeq < $1.value.lastAccessedSeq }
            for (k, _) in sorted.prefix(entries.count - maxEntries) {
                entries.removeValue(forKey: k)
            }
        }
    }

    /// Generate a cache key from prompt components.
    public static func cacheKey(system: String, user: String) -> String {
        var hasher = Hasher()
        hasher.combine(system)
        hasher.combine(user)
        return String(hasher.finalize(), radix: 16)
    }

    public func stats() -> (entries: Int, maxEntries: Int) {
        (entries.count, maxEntries)
    }
}
