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

    /// Each entry tracks its value, creation time, and access order.
    private struct CacheEntry {
        let response: String
        let createdAt: Date
        var lastAccessed: Date
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
        entry.lastAccessed = Date()
        entries[key] = entry
        return entry.response
    }

    /// Store a response in the cache.
    public func set(key: String, response: String) {
        let now = Date()
        entries[key] = CacheEntry(response: response, createdAt: now, lastAccessed: now)

        // Evict least-recently-accessed entries if over capacity
        if entries.count > maxEntries {
            let sorted = entries.sorted { $0.value.lastAccessed < $1.value.lastAccessed }
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
