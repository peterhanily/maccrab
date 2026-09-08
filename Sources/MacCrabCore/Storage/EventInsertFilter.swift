// EventInsertFilter.swift
// MacCrabCore
//
// v1.8.0 Layer 1: pre-insert filter.
//
// Designed after empirical measurement on a real user's events.db revealed
// 17% of volume was the daemon monitoring its own filesystem activity
// (own log, own DB, own support dir) and another 43% was Swift toolchain
// scratch (swiftpm-testing-helper, swift-frontend, dsymutil) on dev
// machines. Both classes have zero detection value — they're machine
// noise, not threat signal.
//
// Filtering at insert is the right architectural layer. The collectors
// already filter for "interesting" categories (process / file / network
// / TCC); EventInsertFilter is the second-pass exclusion that drops
// known-noise events before they hit SQLite. Cheaper than filter-at-rule
// time and prevents the disk-cap pressure entirely.
//
// Safe-by-default: an empty filter is the identity — nothing gets dropped.
// The default filter built by `defaultFilter(supportDir:)` drops only
// measured, path-specific maintenance churn: the daemon's own self-monitoring
// loop, selected developer-tool state databases, and Apple-owned search-index
// internals. Detection still evaluates every Event in memory, and a later
// security-relevant journal ensure explicitly bypasses this routine-noise
// filter. Operators add additional patterns via daemon_config.json.

import Foundation

/// Pre-insert filter applied by `EventStore.insert(event:)`. Each pattern
/// is a substring match against the event's identifying fields. Patterns
/// are case-sensitive; macOS paths and bundle IDs are case-stable in
/// practice, so this is fine.
public struct EventInsertFilter: Sendable {

    /// File paths whose substring presence in `event.file?.path` causes
    /// the event to be dropped. Examples:
    ///   `/private/tmp/maccrabd.log`           — daemon's own log file
    ///   `/Library/Application Support/MacCrab/` — daemon's own DB+support dir
    ///   `/private/var/folders/`                 — macOS per-user scratch
    public let pathSubstrings: [String]

    /// Process names whose presence in `event.process.name` (or in the
    /// ancestor chain) causes the event to be dropped. Useful for
    /// dropping noisy dev-tool processes wholesale. Examples:
    ///   `swiftpm-testing-helper`
    ///   `dsymutil`
    public let processNames: Set<String>

    /// Counters exposed for observability. Tests + `OutputStats` consumers
    /// can read these to see how aggressive the filter is being.
    public final class Counters: @unchecked Sendable {
        public private(set) var dropped: Int = 0
        public private(set) var passed: Int = 0
        /// Subset of `dropped` that were suppressed as in-window duplicates
        /// of an already-journaled exemplar (v1.21.6 Layer 1b).
        public private(set) var suppressedDuplicates: Int = 0
        private let lock = NSLock()
        public init() {}
        func recordDropped() {
            lock.lock(); dropped += 1; lock.unlock()
        }
        func recordSuppressedDuplicate() {
            lock.lock(); dropped += 1; suppressedDuplicates += 1; lock.unlock()
        }
        func recordPassed() {
            lock.lock(); passed += 1; lock.unlock()
        }
        public func snapshot() -> (dropped: Int, passed: Int) {
            lock.lock(); defer { lock.unlock() }
            return (dropped, passed)
        }
        public func duplicateSnapshot() -> Int {
            lock.lock(); defer { lock.unlock() }
            return suppressedDuplicates
        }
    }

    /// v1.21.6 Layer 1b: bounded rolling-window duplicate suppression.
    ///
    /// Measured on a wedged installed host: the exact journal — 78% of the
    /// whole events family at 267 MiB — was dominated by near-identical
    /// platform-daemon chatter (bluetoothd 5,171 rows, secd 3,582,
    /// mDNSResponder 1,631), a 16.4x duplication ratio over distinct
    /// (process, action, path) tuples, each copy hash-chained at ~1.4 KiB.
    /// Journaling every copy exactly is what made the family cap unreachable
    /// at default settings on a busy Mac.
    ///
    /// The window keeps the FIRST occurrence of an eligible tuple as the
    /// exact-journaled exemplar and suppresses repeats for `windowSeconds`.
    /// This is safe where blanket dropping is not:
    ///
    ///   - Detection is UPSTREAM of persistence: every instance is still
    ///     evaluated in memory against every rule. Suppression costs raw
    ///     forensic replay of the Nth copy, never threat coverage.
    ///   - Only platform-signed binaries' process/file chatter is eligible.
    ///     TCC, network, and everything from non-platform binaries — which is
    ///     what adversary tooling is — journals exactly, every time.
    ///   - The alert path bypasses this filter entirely (the security-relevant
    ///     journal ensure), so alert-correlated events are always kept.
    ///   - Suppression lands as the `.filtered` disposition, a conserved,
    ///     qualification-legal outcome — never `.dropped`/shed.
    ///   - Eviction and expiry FAIL OPEN: losing a window entry merely admits
    ///     one extra exemplar. No path here can lose a novel event.
    final class DuplicateWindow: @unchecked Sendable {
        private let lock = NSLock()
        private let windowSeconds: TimeInterval
        private let capacity: Int
        /// Key is a 64-bit Hasher digest of the identity tuple, not a string:
        /// this sits on the per-event hot path and must not allocate. With a
        /// per-process-seeded 64-bit hash and <= `capacity` live keys, an
        /// accidental collision (which would suppress one unrelated event) is
        /// ~1e-12 — and the exemplar of the colliding key is journaled anyway.
        private var lastExemplar: [Int: TimeInterval] = [:]

        init(windowSeconds: TimeInterval, capacity: Int) {
            self.windowSeconds = max(1, windowSeconds)
            self.capacity = max(16, capacity)
        }

        /// True when this key repeats within the window (suppress it); false
        /// when it is novel or the window lapsed (journal it as the exemplar).
        func isDuplicate(key: Int, now: TimeInterval) -> Bool {
            lock.lock(); defer { lock.unlock() }
            if let last = lastExemplar[key], now - last < windowSeconds {
                return true
            }
            if lastExemplar.count >= capacity {
                // Purge expired entries first; if the working set genuinely
                // exceeds capacity, drop arbitrary entries. Both fail open.
                lastExemplar = lastExemplar.filter { now - $0.value < windowSeconds }
                while lastExemplar.count >= capacity,
                      let victim = lastExemplar.keys.first {
                    lastExemplar.removeValue(forKey: victim)
                }
            }
            lastExemplar[key] = now
            return false
        }
    }

    /// nil disables duplicate suppression (the v1.8.0 identity behaviour).
    let duplicateWindow: DuplicateWindow?

    public let counters: Counters

    public init(
        pathSubstrings: [String] = [],
        processNames: Set<String> = [],
        duplicateWindowSeconds: TimeInterval? = nil,
        duplicateWindowCapacity: Int = 4_096
    ) {
        self.pathSubstrings = pathSubstrings
        self.processNames = processNames
        self.duplicateWindow = duplicateWindowSeconds.map {
            DuplicateWindow(windowSeconds: $0, capacity: duplicateWindowCapacity)
        }
        self.counters = Counters()
    }

    /// True iff the event should be dropped. The hot path: called on
    /// every collector tick before `EventStore.insert`, so this MUST be
    /// allocation-free and O(filter-size). Substring scan + set lookup
    /// are both that.
    public func shouldDrop(event: Event) -> Bool {
        if processNames.contains(event.process.name) {
            counters.recordDropped()
            return true
        }
        if let filePath = event.file?.path {
            for substring in pathSubstrings {
                if filePath.contains(substring) {
                    counters.recordDropped()
                    return true
                }
            }
        }
        if let window = duplicateWindow,
           Self.isDuplicateEligible(event),
           window.isDuplicate(
                key: Self.duplicateKey(event),
                now: event.timestamp.timeIntervalSince1970
           ) {
            counters.recordSuppressedDuplicate()
            return true
        }
        counters.recordPassed()
        return false
    }

    /// Only routine platform-binary process/file chatter may be suppressed as
    /// a duplicate. Everything else journals exactly, every occurrence:
    /// TCC decisions and network flows are high-signal per-instance, and
    /// non-platform binaries are precisely the population adversary tooling
    /// lives in. Unknown categories default to NOT eligible.
    static func isDuplicateEligible(_ event: Event) -> Bool {
        guard event.process.isPlatformBinary else { return false }
        // A coverage probe proves this particular nonce reached persistence.
        // Ordinary true executions share its duplicate tuple because that tuple
        // intentionally omits argv. Do not let them consume the probe, or let
        // a probe seed the routine duplicate window. Explicit process/path
        // exclusions still run first in shouldDrop(event:).
        guard !NoiseFilter.isCoverageCanaryProbe(event: event) else { return false }
        switch event.eventCategory {
        case .process, .file: return true
        default: return false
        }
    }

    /// Identity tuple for the window: what-kind-of-thing happened, by whom,
    /// to what. Deliberately EXCLUDES the command line and raw payload — two
    /// bluetoothd log ticks with different payload bytes are still the same
    /// forensic fact, and including payload would defeat the window entirely.
    static func duplicateKey(_ event: Event) -> Int {
        var hasher = Hasher()
        hasher.combine(event.eventCategory)
        hasher.combine(event.eventAction)
        hasher.combine(event.process.name)
        hasher.combine(event.process.executable)
        hasher.combine(event.file?.path)
        hasher.combine(event.network?.destinationIp)
        return hasher.finalize()
    }

    // MARK: - Defaults

    /// The always-correct default: drop the daemon's own self-monitoring
    /// loop. Empirically the largest single contributor to event volume
    /// on a busy machine (17% of 1.66M events on field-measured hardware
    /// were just the daemon watching its own log + DB + support dir).
    /// `supportDir` is whichever path the daemon resolved (`~/Library/...`
    /// for non-root dev runs, `/Library/...` for root sysext).
    public static func defaultFilter(supportDir: String) -> EventInsertFilter {
        // Strip trailing slash so substring match catches both
        // "/Library/Application Support/MacCrab/events.db" and the dir
        // itself.
        let normalizedDir = supportDir.hasSuffix("/")
            ? String(supportDir.dropLast())
            : supportDir
        return EventInsertFilter(
            pathSubstrings: [
                // --- Daemon self-monitoring (own writes) ---
                normalizedDir,                       // resolved support dir (root or user-uid)
                "Library/Application Support/MacCrab/", // catches both /Library/ and ~/Library/ (dev-mode parallel daemon)
                "/private/tmp/maccrabd.log",         // daemon's own log file
                // --- pty / null device noise ---
                "/dev/null",                         // shells / scripts redirecting
                "/dev/ttys",                         // pty noise on Terminal-heavy machines
                "/dev/ptmx",                         // pty multiplexer
                "/dev/console",                      // virtual console
                // --- SQLite temp-file pattern (universal across SQLite-using apps) ---
                "/T/etilqs_",                        // /private/var/folders/.../T/etilqs_<hash> — SQLite's mkstemp prefix
                // --- Apple internal log/data daemons ---
                "/private/var/log/com.apple.xpc.launchd/", // launchd's own log churn
                "/private/var/db/systemstats/",      // systemstats coalitions/memory dumps
                // --- Path-specific developer-tool database churn ---
                // Field qualification on a Codex-active host measured dozens
                // of ES WRITE callbacks per logical state mutation. Preserve
                // session JSONL and every other ~/.codex path; suppress only
                // the three replaceable local SQLite families.
                "/.codex/state_",
                "/.codex/thread_history_",
                "/.codex/logs_",
                // --- Apple-owned derived search/embedding indexes ---
                // These are replaceable SpotlightKnowledge internals, not the
                // user documents being indexed. The exact subtree prevents a
                // broad Library/Metadata or CoreSpotlight blind spot.
                "/Library/Metadata/CoreSpotlight/SpotlightKnowledge/",
            ],
            processNames: [
                "maccrabctl",                        // own CLI
                "maccrabd",                          // own dev/legacy daemon
            ],
            // v1.21.6: suppress in-window duplicates of platform-daemon
            // chatter (see DuplicateWindow). Five minutes keeps one exact
            // exemplar per distinct (category, action, process, target) tuple
            // per window; the aggregates tier retains counts and detection
            // evaluates every instance regardless. Measured 16.4x duplication
            // on field hardware — this is the difference between the default
            // family cap holding a busy Mac and it being unreachable.
            duplicateWindowSeconds: 300
        )
    }
}
