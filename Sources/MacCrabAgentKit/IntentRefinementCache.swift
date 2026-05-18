// IntentRefinementCache.swift
// MacCrabAgentKit
//
// v1.12.6 — bounds the cost of the LLM-aware IntentClassifier when it's
// wired into EventLoop's hot path. The cache answers two questions per
// process-tree key:
//
//   1. "Should we dispatch an LLM classification for this tree right
//      now?" — answered by `shouldClassify(treeKey:)`. Returns false
//      when either (a) a result is already cached within the TTL, or
//      (b) a dispatch was recorded but hasn't returned yet (in-flight).
//
//   2. "Do we have a refined verdict from the LLM for this tree that we
//      should overlay onto a freshly-built event?" — answered by
//      `refinement(for:)`. Returns the most recent successful LLM
//      result if one is still inside the TTL.
//
// LRU-bounded at 256 entries with a 10-minute TTL. At one tree per
// minute, 256 entries gives >4 hours of headroom for the 10-min TTL.
// The numbers match the design memo from the v1.12.6 audit:
// the LLM is a tie-breaker for ambiguous AI-attributed installs, not a
// per-event classifier.

import Foundation

/// Per-tree LLM-classification budget + result cache.
///
/// Thread-safety: actor-isolated. EventLoop reads + writes from its own
/// async loop; detached LLM Tasks write back via `recordResult`.
actor IntentRefinementCache {

    /// TTL on both the "recently dispatched" flag AND the cached result.
    /// 10 minutes matches the rationale in the task brief — the same
    /// process tree shouldn't trigger two LLM calls in quick succession,
    /// and a refined verdict is good for at least one short attacker
    /// session.
    private let ttl: TimeInterval

    /// Max entries before LRU eviction. 256 covers heavy multi-tenant
    /// dev hosts while staying tiny in memory (<32 KB).
    private let maxEntries: Int

    /// Monotonic counter for LRU ordering. Avoids the LLMCache
    /// "same-millisecond Date collision" bug class — we never compare
    /// timestamps for ordering.
    private var accessSeq: UInt64 = 0

    /// What we know about a tree.
    private struct Entry {
        /// Wall-clock time the dispatch was recorded. Used for TTL.
        let recordedAt: Date
        /// LRU ordering.
        var lastAccessSeq: UInt64
        /// nil while the LLM task is in-flight; populated once the
        /// detached Task calls `recordResult`.
        var result: Refinement?
    }

    /// The refined verdict written back from the LLM task.
    struct Refinement: Sendable {
        let label: String
        let confidence: Double
        let provider: String
        /// Three-line summary of why the LLM reached this label.
        let reasons: [String]
    }

    private var entries: [String: Entry] = [:]

    init(ttlSeconds: TimeInterval = 600, maxEntries: Int = 256) {
        self.ttl = ttlSeconds
        self.maxEntries = maxEntries
    }

    /// Returns true iff there is no in-flight or recently-completed
    /// classification for this tree. Caller is expected to then call
    /// `recordDispatch(treeKey:)` if they decide to launch the task.
    func shouldClassify(treeKey: String) -> Bool {
        purgeIfExpired(treeKey: treeKey)
        return entries[treeKey] == nil
    }

    /// Mark a treeKey as having a dispatch in-flight. Subsequent
    /// `shouldClassify` calls return false until the TTL elapses,
    /// regardless of whether the dispatch ultimately succeeds.
    /// (We don't want a failing LLM to be retried every event.)
    func recordDispatch(treeKey: String) {
        accessSeq += 1
        entries[treeKey] = Entry(
            recordedAt: Date(),
            lastAccessSeq: accessSeq,
            result: nil
        )
        evictIfNeeded()
    }

    /// Called by the detached LLM Task on success. Stores the result
    /// for future `refinement(for:)` calls within the TTL.
    func recordResult(treeKey: String, refinement: Refinement) {
        accessSeq += 1
        // Preserve recordedAt from the dispatch entry so TTL counts
        // from dispatch time, not result time. (A long LLM round-trip
        // shouldn't extend the budget window.)
        let recordedAt = entries[treeKey]?.recordedAt ?? Date()
        entries[treeKey] = Entry(
            recordedAt: recordedAt,
            lastAccessSeq: accessSeq,
            result: refinement
        )
        evictIfNeeded()
    }

    /// Return the cached refinement for this tree, or nil if absent
    /// or expired. Also bumps LRU order — a tree we're still seeing
    /// events for stays hot.
    func refinement(for treeKey: String) -> Refinement? {
        purgeIfExpired(treeKey: treeKey)
        guard var entry = entries[treeKey], let result = entry.result else {
            return nil
        }
        accessSeq += 1
        entry.lastAccessSeq = accessSeq
        entries[treeKey] = entry
        return result
    }

    /// Test-only: number of currently-cached entries.
    func entryCount() -> Int { entries.count }

    // MARK: - Private

    private func purgeIfExpired(treeKey: String) {
        guard let entry = entries[treeKey] else { return }
        if Date().timeIntervalSince(entry.recordedAt) > ttl {
            entries.removeValue(forKey: treeKey)
        }
    }

    private func evictIfNeeded() {
        let overflow = entries.count - maxEntries
        guard overflow > 0 else { return }
        // O(n × overflow). Overflow is almost always 1; a bulk-overflow
        // worst case (e.g., a stress test) does n × k work, which is
        // still fine for n=256.
        for _ in 0..<overflow {
            guard let oldestKey = entries.min(
                by: { $0.value.lastAccessSeq < $1.value.lastAccessSeq }
            )?.key else { return }
            entries.removeValue(forKey: oldestKey)
        }
    }
}
