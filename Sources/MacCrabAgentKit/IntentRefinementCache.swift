// IntentRefinementCache.swift
// MacCrabAgentKit
//
// Bounds the cost of EventLoop's asynchronous LLM intent refinement without
// allowing one package verdict to leak into another install. A cache scope is:
//
//   durable AI-tool session (or process-tree fallback) + SHA-256(BehaviorBrief)
//
// Dispatch admission is a single actor operation. `begin(scope:)` both checks
// the cooldown and records a new generation, closing the race that existed
// between the old `shouldClassify` and `recordDispatch` calls. A detached task
// may commit only with that exact, still-live generation. Late results can
// therefore never recreate an expired or LRU-evicted entry.

import CryptoKit
import Foundation
import MacCrabCore

/// Scope-safe LLM-classification budget and result cache.
///
/// Thread-safety: actor-isolated. EventLoop reads and writes from its async
/// loop; detached LLM tasks write back with the generation token returned by
/// `begin(scope:)`.
actor IntentRefinementCache {

    struct Telemetry: Sendable, Equatable {
        let beginOffered: UInt64
        let admitted: UInt64
        let coalesced: UInt64
        let cancelledBeforeDispatch: UInt64
        let expired: UInt64
        let evicted: UInt64
        let resultOffered: UInt64
        let resultAccepted: UInt64
        let resultRejected: UInt64
        let currentEntries: Int
        let currentInFlight: Int
        let currentCompleted: Int

        var beginConservationMaintained: Bool {
            beginOffered == admitted + coalesced
        }

        var entryConservationMaintained: Bool {
            admitted == cancelledBeforeDispatch + expired + evicted
                + UInt64(currentEntries)
        }

        var resultConservationMaintained: Bool {
            resultOffered == resultAccepted + resultRejected
        }
    }

    /// Session/tree identity plus a canonical digest of the exact classifier
    /// input. The explicit prefixes keep a session identifier from colliding
    /// with a fallback tree string that happens to contain the same bytes.
    struct Scope: Hashable, Sendable {
        let subjectIdentity: String
        let behaviorSHA256: String
    }

    /// Opaque proof that a caller owns the current dispatch generation for a
    /// scope. Callers can retain and return it, but cannot manufacture one.
    struct GenerationToken: Hashable, Sendable {
        fileprivate let generation: UInt64
    }

    /// The refined verdict written back from the LLM task.
    struct Refinement: Sendable {
        let label: String
        let confidence: Double
        let provider: String
        /// Three-line summary of why the LLM reached this label.
        let reasons: [String]
    }

    private struct CanonicalBriefEnvelope: Encodable {
        /// Bump if canonical scope semantics change independently of the
        /// BehaviorBrief Codable schema.
        let schemaVersion = 1
        let brief: IntentClassifier.BehaviorBrief
    }

    private struct Entry {
        /// Monotonic time at admission. TTL never extends when a result lands.
        let admittedAt: TimeInterval
        let token: GenerationToken
        var lastAccessSeq: UInt64
        /// nil while the LLM task is in flight or yielded no useful verdict.
        var result: Refinement?
    }

    /// TTL on both in-flight admission and a completed result.
    private let ttl: TimeInterval
    /// Maximum number of distinct session+brief scopes retained.
    private let maxEntries: Int
    /// Injectable monotonic source keeps expiry tests deterministic and avoids
    /// wall-clock adjustment extending or prematurely ending a cooldown.
    private let monotonicNow: @Sendable () -> TimeInterval

    /// Monotonic counters avoid timestamp ties for LRU and prevent ABA when an
    /// expired/evicted scope is admitted again while its old task is still live.
    private var accessSeq: UInt64 = 0
    private var nextGeneration: UInt64 = 0
    private var entries: [Scope: Entry] = [:]
    private var beginOffered: UInt64 = 0
    private var admitted: UInt64 = 0
    private var coalesced: UInt64 = 0
    private var cancelledBeforeDispatch: UInt64 = 0
    private var expired: UInt64 = 0
    private var evicted: UInt64 = 0
    private var resultOffered: UInt64 = 0
    private var resultAccepted: UInt64 = 0
    private var resultRejected: UInt64 = 0

    init(
        ttlSeconds: TimeInterval = 600,
        maxEntries: Int = 256,
        monotonicNow: @escaping @Sendable () -> TimeInterval = {
            ProcessInfo.processInfo.systemUptime
        }
    ) {
        self.ttl = ttlSeconds.isFinite ? max(0, ttlSeconds) : 600
        self.maxEntries = max(1, maxEntries)
        self.monotonicNow = monotonicNow
    }

    /// Build the only valid cache key for a BehaviorBrief. The existing
    /// anti-PID-reuse `ai_tool_session_id` is authoritative when present;
    /// callers supply the stable process-tree identity only as a fallback for
    /// legacy/unattributed events.
    ///
    /// Returns nil only if canonical JSON encoding fails. EventLoop treats that
    /// as cache/LLM ineligibility and keeps the synchronous heuristic verdict,
    /// which fails closed against cross-package verdict reuse.
    nonisolated static func scope(
        sessionID: String?,
        fallbackTreeKey: String,
        brief: IntentClassifier.BehaviorBrief
    ) -> Scope? {
        let trimmedSession = sessionID?.trimmingCharacters(in: .whitespacesAndNewlines)
        let subjectIdentity: String
        if let trimmedSession, !trimmedSession.isEmpty {
            subjectIdentity = "session:\(trimmedSession)"
        } else {
            subjectIdentity = "tree:\(fallbackTreeKey)"
        }

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        guard let canonical = try? encoder.encode(
            CanonicalBriefEnvelope(brief: brief)
        ) else {
            return nil
        }
        let digest = SHA256.hash(data: canonical)
            .map { String(format: "%02x", $0) }
            .joined()
        return Scope(
            subjectIdentity: subjectIdentity,
            behaviorSHA256: digest
        )
    }

    /// Atomically admit one classification for `scope` and return its unique
    /// generation. nil means the same session+brief already has an in-flight or
    /// completed entry inside the TTL.
    func begin(scope: Scope) -> GenerationToken? {
        beginOffered &+= 1
        let now = monotonicNow()
        purgeIfExpired(scope: scope, now: now)
        guard entries[scope] == nil else {
            coalesced &+= 1
            return nil
        }

        let token = makeGenerationToken()
        entries[scope] = Entry(
            admittedAt: now,
            token: token,
            lastAccessSeq: nextAccessSequence(),
            result: nil
        )
        admitted &+= 1
        evictIfNeeded()
        return token
    }

    /// Release the exact reservation when the owning advisory lifecycle rejects
    /// the task before it starts. A stale token cannot cancel a replacement.
    /// Without this rollback, an overload shed consumed the full ten-minute
    /// cooldown despite making no model call.
    @discardableResult
    func cancelBeforeDispatch(
        scope: Scope,
        token: GenerationToken
    ) -> Bool {
        guard entries[scope]?.token == token else { return false }
        entries.removeValue(forKey: scope)
        cancelledBeforeDispatch &+= 1
        return true
    }

    /// Commit a successful refinement only when `token` still owns the current,
    /// unexpired entry for `scope`. Returning false is expected for a late task
    /// whose entry expired, was evicted, or was replaced by a newer generation.
    /// Crucially, this method never inserts an absent entry.
    @discardableResult
    func recordResult(
        scope: Scope,
        token: GenerationToken,
        refinement: Refinement
    ) -> Bool {
        resultOffered &+= 1
        let now = monotonicNow()
        purgeIfExpired(scope: scope, now: now)
        guard var entry = entries[scope], entry.token == token else {
            resultRejected &+= 1
            return false
        }
        entry.lastAccessSeq = nextAccessSequence()
        entry.result = refinement
        entries[scope] = entry
        resultAccepted &+= 1
        return true
    }

    /// Return a cached refinement only for the exact session+brief scope. Also
    /// bumps LRU order so an actively reused result stays hot.
    func refinement(for scope: Scope) -> Refinement? {
        let now = monotonicNow()
        purgeIfExpired(scope: scope, now: now)
        guard var entry = entries[scope], let result = entry.result else {
            return nil
        }
        entry.lastAccessSeq = nextAccessSequence()
        entries[scope] = entry
        return result
    }

    /// Test/diagnostic-only count after purging all expired entries.
    func entryCount() -> Int {
        purgeExpiredEntries(now: monotonicNow())
        return entries.count
    }

    func telemetry() -> Telemetry {
        purgeExpiredEntries(now: monotonicNow())
        let inFlight = entries.values.reduce(into: 0) { count, entry in
            if entry.result == nil { count += 1 }
        }
        return Telemetry(
            beginOffered: beginOffered,
            admitted: admitted,
            coalesced: coalesced,
            cancelledBeforeDispatch: cancelledBeforeDispatch,
            expired: expired,
            evicted: evicted,
            resultOffered: resultOffered,
            resultAccepted: resultAccepted,
            resultRejected: resultRejected,
            currentEntries: entries.count,
            currentInFlight: inFlight,
            currentCompleted: entries.count - inFlight
        )
    }

    // MARK: - Private

    private func makeGenerationToken() -> GenerationToken {
        nextGeneration &+= 1
        // Reserve zero so a wrapped counter cannot look like an uninitialized
        // value in a debugger. Reaching this branch requires 2^64 admissions.
        if nextGeneration == 0 { nextGeneration = 1 }
        return GenerationToken(generation: nextGeneration)
    }

    private func nextAccessSequence() -> UInt64 {
        accessSeq &+= 1
        if accessSeq == 0 {
            // A 2^64-access wrap is not operationally reachable, but retain LRU
            // correctness if a long-lived process ever gets there.
            let ordered = entries.keys.sorted {
                entries[$0]!.lastAccessSeq < entries[$1]!.lastAccessSeq
            }
            for (index, key) in ordered.enumerated() {
                entries[key]!.lastAccessSeq = UInt64(index + 1)
            }
            accessSeq = UInt64(ordered.count + 1)
        }
        return accessSeq
    }

    private func purgeIfExpired(scope: Scope, now: TimeInterval) {
        guard let entry = entries[scope], isExpired(entry, now: now) else {
            return
        }
        entries.removeValue(forKey: scope)
        expired &+= 1
    }

    private func purgeExpiredEntries(now: TimeInterval) {
        let expiredKeys = entries.compactMap { key, entry in
            isExpired(entry, now: now) ? key : nil
        }
        for key in expiredKeys { entries.removeValue(forKey: key) }
        expired &+= UInt64(expiredKeys.count)
    }

    private func isExpired(_ entry: Entry, now: TimeInterval) -> Bool {
        let age = now - entry.admittedAt
        return !age.isFinite || age >= ttl
    }

    private func evictIfNeeded() {
        while entries.count > maxEntries {
            guard let oldest = entries.min(
                by: { $0.value.lastAccessSeq < $1.value.lastAccessSeq }
            )?.key else { return }
            entries.removeValue(forKey: oldest)
            evicted &+= 1
        }
    }
}
