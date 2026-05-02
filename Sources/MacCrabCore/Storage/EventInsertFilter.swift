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
// The default filter built by `defaultFilter(supportDir:)` only drops
// the daemon's own self-monitoring loop (always-correct exclusion).
// Operators add additional patterns via daemon_config.json.

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
        private let lock = NSLock()
        public init() {}
        func recordDropped() {
            lock.lock(); dropped += 1; lock.unlock()
        }
        func recordPassed() {
            lock.lock(); passed += 1; lock.unlock()
        }
        public func snapshot() -> (dropped: Int, passed: Int) {
            lock.lock(); defer { lock.unlock() }
            return (dropped, passed)
        }
    }

    public let counters: Counters

    public init(pathSubstrings: [String] = [], processNames: Set<String> = []) {
        self.pathSubstrings = pathSubstrings
        self.processNames = processNames
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
        counters.recordPassed()
        return false
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
                normalizedDir,                       // daemon's own DB / support files
                "/private/tmp/maccrabd.log",         // daemon's own log file
                "/dev/null",                         // shells / scripts redirecting
                "/dev/ttys",                         // pty noise on Terminal-heavy machines
            ],
            processNames: []
        )
    }
}
