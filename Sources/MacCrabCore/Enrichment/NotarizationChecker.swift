// NotarizationChecker.swift
// MacCrabCore
//
// Checks notarization status of binaries using spctl --assess.
// Caches results keyed by binary path with an LRU eviction strategy.
// Rate-limited to avoid excessive spctl invocations under load.

import Foundation
import Darwin
import os.log

/// Evaluates and caches notarization status for executed binaries.
///
/// On process execution events, checks whether a binary has been notarized
/// by Apple using `spctl --assess`. Flags:
/// - Binaries that are NOT notarized, NOT Apple-signed, and NOT from /System/
/// - Binaries from ~/Downloads that lack notarization
///
/// Results are cached (LRU, max 2000 entries) against the identity of the
/// assessed file. A pathname is not an identity: installers and attackers can
/// replace a binary in place, so a path-only cache can incorrectly transfer a
/// trusted verdict to different bytes.
public actor NotarizationChecker {

    private let logger = Logger(subsystem: "com.maccrab", category: "notarization-checker")

    // MARK: - Types

    public enum NotarizationStatus: String, Sendable {
        case notarized = "notarized"
        case notNotarized = "not_notarized"
        case revoked = "revoked"
        case unknown = "unknown"
    }

    public struct NotarizationResult: Sendable {
        public let path: String
        public let status: NotarizationStatus
        public let source: String?
        public let isFromDownloads: Bool
    }

    /// Fixed-cardinality operational counters. These make cache invalidation,
    /// duplicate-work coalescing, and overload shedding measurable without
    /// retaining executable paths.
    public struct Diagnostics: Sendable, Equatable {
        public let cacheHits: UInt64
        public let cacheMisses: UInt64
        public let cacheIdentityInvalidations: UInt64
        public let coalescedChecks: UInt64
        public let saturatedChecks: UInt64
        public let assessmentsCompleted: UInt64
        public let identityChangesDuringAssessment: UInt64
        public let diagnosticLogsEmitted: UInt64
        public let diagnosticLogsSuppressed: UInt64
        public let cacheSize: Int
        public let assessmentsInFlightOrQueued: Int
    }

    // MARK: - Cache

    private struct FileIdentity: Hashable, Sendable {
        let device: UInt64
        let inode: UInt64
        let size: UInt64
        let modifiedSeconds: Int64
        let modifiedNanoseconds: Int64
        let changedSeconds: Int64
        let changedNanoseconds: Int64
    }

    private struct AssessmentKey: Hashable, Sendable {
        let path: String
        let identity: FileIdentity
    }

    private struct AssessmentOutcome: Sendable {
        let result: NotarizationResult
        let identityUnchanged: Bool
    }

    /// LRU cache entry wrapping a result, the exact file assessed, and access
    /// order. Revalidating identity is a fork-free `stat(2)` call.
    private struct CacheEntry {
        let result: NotarizationResult
        let identity: FileIdentity
        let accessOrder: UInt64
    }

    /// Path-keyed result cache.
    private var cache: [String: CacheEntry] = [:]
    private var accessCounter: UInt64 = 0
    private let maxCacheSize = 2000

    private var cacheHits: UInt64 = 0
    private var cacheMisses: UInt64 = 0
    private var cacheIdentityInvalidations: UInt64 = 0
    private var coalescedChecks: UInt64 = 0
    private var saturatedChecks: UInt64 = 0
    private var assessmentsCompleted: UInt64 = 0
    private var identityChangesDuringAssessment: UInt64 = 0

    /// One task per distinct (path, identity). This both coalesces duplicate
    /// execs of the same image and places a hard bound on the work waiting for
    /// the five `spctl` slots. Without the outer bound, a unique-path exec flood
    /// could still create an unbounded continuation queue.
    private var assessments: [AssessmentKey: Task<AssessmentOutcome, Never>] = [:]
    private let maximumAssessmentDemand: Int

    private let assessmentRunner: @Sendable (String) async -> String
    private let monotonicNow: @Sendable () -> TimeInterval
    private static let diagnosticLogInterval: TimeInterval = 30
    private var lastDiagnosticLogTick: TimeInterval?
    private var diagnosticLogsEmitted: UInt64 = 0
    private var diagnosticLogsSuppressed: UInt64 = 0
    private var suppressedSinceLastDiagnosticLog: UInt64 = 0

    // MARK: - Concurrency Limiter

    /// Tracks the number of in-flight spctl invocations.
    /// spctl is expensive; more than 5 concurrent calls can degrade system performance.
    private var inFlightCount = 0
    private let maxConcurrent = 5
    private var waiters: [CheckedContinuation<Void, Never>] = []

    /// Minimum binary size to bother checking (files < 1KB are unlikely to be real executables).
    private let minimumBinarySize: UInt64 = 1024

    // MARK: - System Path Prefixes

    /// Paths under which binaries are assumed to be Apple-provided and skip spctl checks.
    private static let systemPrefixes: [String] = [
        "/System/",
        "/usr/bin/",
        "/usr/sbin/",
        "/usr/libexec/",
        "/bin/",
        "/sbin/",
    ]

    // MARK: - Initialization

    public init() {
        maximumAssessmentDemand = 128
        monotonicNow = { Foundation.ProcessInfo.processInfo.systemUptime }
        assessmentRunner = { path in
            await Task.detached(priority: .utility) {
                Self.runSpctl(binaryPath: path)
            }.value
        }
    }

    /// Deterministic seam for concurrency, replacement, and overload tests.
    /// Internal so production callers cannot substitute the trust assessor.
    init(
        maximumAssessmentDemand: Int = 128,
        monotonicNow: @escaping @Sendable () -> TimeInterval = {
            Foundation.ProcessInfo.processInfo.systemUptime
        },
        assessmentRunner: @escaping @Sendable (String) async -> String
    ) {
        self.maximumAssessmentDemand = max(1, maximumAssessmentDemand)
        self.monotonicNow = monotonicNow
        self.assessmentRunner = assessmentRunner
    }

    // MARK: - Public API

    /// Check notarization status of a binary. Uses cache for repeated lookups.
    ///
    /// Skips checking for:
    /// - Binaries under /System/, /usr/bin/, etc. (assumed Apple-provided)
    /// - Binaries smaller than 1KB
    /// - Paths that don't exist on disk
    ///
    /// - Parameter binaryPath: Absolute path to the binary to check.
    /// - Returns: The notarization assessment result.
    public func check(binaryPath: String) async -> NotarizationResult {
        let canonicalPath = Self.canonicalPath(binaryPath)

        // Skip system binaries
        if Self.isSystemPath(canonicalPath) {
            return NotarizationResult(
                path: canonicalPath,
                status: .notarized,
                source: "Apple",
                isFromDownloads: false
            )
        }

        // A valid identity is required both for the cache key and for the
        // post-assessment replacement check. Missing/tiny paths remain honest
        // unknown and are deliberately not cached.
        guard let identity = Self.fileIdentity(at: canonicalPath),
              identity.size >= minimumBinarySize else {
            increment(&cacheMisses)
            return NotarizationResult(
                path: canonicalPath,
                status: .unknown,
                source: nil,
                isFromDownloads: isFromDownloads(canonicalPath)
            )
        }

        // Fast path: only an entry for these exact bytes is a cache hit.
        if let entry = cache[canonicalPath] {
            if entry.identity == identity {
                increment(&cacheHits)
                touchCacheEntry(path: canonicalPath, entry: entry)
                return entry.result
            }
            cache.removeValue(forKey: canonicalPath)
            increment(&cacheIdentityInvalidations)
        }
        increment(&cacheMisses)

        let key = AssessmentKey(path: canonicalPath, identity: identity)
        let task: Task<AssessmentOutcome, Never>
        if let existing = assessments[key] {
            increment(&coalescedChecks)
            task = existing
        } else {
            guard assessments.count < maximumAssessmentDemand else {
                increment(&saturatedChecks)
                return NotarizationResult(
                    path: canonicalPath,
                    status: .unknown,
                    source: nil,
                    isFromDownloads: isFromDownloads(canonicalPath)
                )
            }
            task = Task { [self] in
                let assessed = await performAssessment(binaryPath: canonicalPath)
                let unchanged = Self.fileIdentity(at: canonicalPath) == identity
                return AssessmentOutcome(
                    result: unchanged ? assessed : NotarizationResult(
                        path: canonicalPath,
                        status: .unknown,
                        source: nil,
                        isFromDownloads: isFromDownloads(canonicalPath)
                    ),
                    identityUnchanged: unchanged
                )
            }
            assessments[key] = task
        }

        let outcome = await task.value

        // Exactly one waiter owns completion accounting and cache publication.
        // Every coalesced waiter still receives the identity-checked outcome.
        if assessments.removeValue(forKey: key) != nil {
            increment(&assessmentsCompleted)
            if outcome.identityUnchanged {
                cacheResult(
                    path: canonicalPath,
                    identity: identity,
                    result: outcome.result
                )
                logSuspiciousResultIfNeeded(outcome.result)
            } else {
                increment(&identityChangesDuringAssessment)
            }
        }

        return outcome.result
    }

    /// Synchronous, fork-free cache lookup for the hot enrichment path.
    ///
    /// Returns a result WITHOUT ever invoking `spctl`:
    /// - System-prefix binaries resolve inline (cheap, no I/O).
    /// - Otherwise returns the identity-bound LRU result if present, else nil.
    ///
    /// Does not mutate hit/miss counters. It may evict a stale entry after the
    /// fork-free identity check; callers that get nil must treat notarization as
    /// not-yet-known and let an async `check` enrich it for next time.
    public func cachedResult(binaryPath: String) -> NotarizationResult? {
        let canonicalPath = Self.canonicalPath(binaryPath)
        if Self.isSystemPath(canonicalPath) {
            return NotarizationResult(
                path: canonicalPath,
                status: .notarized,
                source: "Apple",
                isFromDownloads: false
            )
        }
        if let entry = cache[canonicalPath] {
            guard Self.fileIdentity(at: canonicalPath) == entry.identity else {
                cache.removeValue(forKey: canonicalPath)
                increment(&cacheIdentityInvalidations)
                return nil
            }
            touchCacheEntry(path: canonicalPath, entry: entry)
            return entry.result
        }
        return nil
    }

    /// Return cache statistics.
    public func stats() -> (hits: Int, misses: Int, hitRate: Double, cacheSize: Int) {
        let total = cacheHits + cacheMisses
        let rate = total > 0 ? Double(cacheHits) / Double(total) : 0
        return (
            Int(clamping: cacheHits),
            Int(clamping: cacheMisses),
            rate,
            cache.count
        )
    }

    public func diagnostics() -> Diagnostics {
        Diagnostics(
            cacheHits: cacheHits,
            cacheMisses: cacheMisses,
            cacheIdentityInvalidations: cacheIdentityInvalidations,
            coalescedChecks: coalescedChecks,
            saturatedChecks: saturatedChecks,
            assessmentsCompleted: assessmentsCompleted,
            identityChangesDuringAssessment: identityChangesDuringAssessment,
            diagnosticLogsEmitted: diagnosticLogsEmitted,
            diagnosticLogsSuppressed: diagnosticLogsSuppressed,
            cacheSize: cache.count,
            assessmentsInFlightOrQueued: assessments.count
        )
    }

    /// Clear all cached results.
    public func clearCache() {
        cache.removeAll()
        accessCounter = 0
    }

    // MARK: - Assessment

    /// Acquire a slot for an spctl invocation, waiting if at capacity.
    private func acquireSlot() async {
        if inFlightCount < maxConcurrent {
            inFlightCount += 1
            return
        }
        // At capacity — suspend until a releasing task HANDS us its slot.
        // releaseSlot transfers the slot without decrementing, so the in-flight
        // count already accounts for us on resume; we must NOT re-increment.
        //
        // v1.21.4 audit LOW: the previous code decremented in releaseSlot and
        // re-incremented here after the await. Between the decrement and this
        // increment a fresh acquireSlot could take the freed slot via the fast
        // path, and then the woken waiter's increment pushed inFlightCount past
        // maxConcurrent. Atomic hand-off keeps the count pinned at the cap while
        // a waiter is queued, so an over-admission can't happen.
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            waiters.append(cont)
        }
    }

    /// Release a slot. Hand it directly to the next waiter when one is queued —
    /// the count is unchanged (one holder replaced by another), so it can neither
    /// exceed maxConcurrent nor transiently dip and let an extra fast-path
    /// acquirer in. Only decrement when nobody is waiting.
    private func releaseSlot() {
        if !waiters.isEmpty {
            let next = waiters.removeFirst()
            next.resume()
        } else {
            inFlightCount -= 1
        }
    }

    // MARK: - Test Seam (concurrency limiter)

    // Exposed for NotarizationCheckerTests to exercise the slot accounting
    // without forking spctl. Not referenced by any production path.
    func acquireSlotForTesting() async { await acquireSlot() }
    func releaseSlotForTesting() { releaseSlot() }
    var inFlightForTesting: Int { inFlightCount }

    /// Run `spctl --assess` and parse the output.
    private func performAssessment(binaryPath: String) async -> NotarizationResult {
        let downloadsFlag = isFromDownloads(binaryPath)

        // Rate-limit concurrent spctl calls
        await acquireSlot()

        // The production runner detaches the blocking, bounded subprocess. The
        // injectable async seam lets tests hold/release work without forking.
        let output = await assessmentRunner(binaryPath)

        // Release the concurrency slot now that spctl has finished
        releaseSlot()

        // Parse spctl output:
        // Accepted: "<path>: accepted\nsource=Notarized Developer ID\n..."
        // Rejected: "<path>: rejected\n..."
        // Revoked:  "<path>: rejected\norigin=... (revoked)\n..."

        let lowerOutput = output.lowercased()

        if lowerOutput.contains("accepted") {
            let source = Self.parseSource(output)
            return NotarizationResult(
                path: binaryPath,
                status: .notarized,
                source: source,
                isFromDownloads: downloadsFlag
            )
        }

        if lowerOutput.contains("revoked") || lowerOutput.contains("revocation") {
            let source = Self.parseSource(output)
            return NotarizationResult(
                path: binaryPath,
                status: .revoked,
                source: source,
                isFromDownloads: downloadsFlag
            )
        }

        if lowerOutput.contains("rejected") {
            let source = Self.parseSource(output)
            return NotarizationResult(
                path: binaryPath,
                status: .notNotarized,
                source: source,
                isFromDownloads: downloadsFlag
            )
        }

        // Could not determine status
        return NotarizationResult(
            path: binaryPath,
            status: .unknown,
            source: nil,
            isFromDownloads: downloadsFlag
        )
    }

    /// Execute spctl and capture combined stdout+stderr.
    private nonisolated static func runSpctl(binaryPath: String) -> String {
        guard let result = BoundedPrivilegedProcessRunner.run(
            executable: "/usr/sbin/spctl",
            arguments: ["--assess", "--type", "execute", "-v", binaryPath],
            timeout: 15,
            maximumOutputBytes: 256 * 1_024
        ), !result.timedOut, !result.outputLimitExceeded else { return "" }
        // Rejected assessments exit non-zero; their stderr is still the input
        // to the accepted/rejected/revoked parser.
        return String(data: result.output, encoding: .utf8) ?? ""
    }

    /// Extract the "source=..." or "origin=..." value from spctl output.
    private nonisolated static func parseSource(_ output: String) -> String? {
        // Look for "source=<value>" line
        for line in output.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.lowercased().hasPrefix("source=") {
                return String(trimmed.dropFirst("source=".count))
            }
            if trimmed.lowercased().hasPrefix("origin=") {
                return String(trimmed.dropFirst("origin=".count))
            }
        }

        // Try to extract from inline format: "accepted source=Notarized Developer ID"
        if let sourceRange = output.range(of: "source=") {
            let afterSource = output[sourceRange.upperBound...]
            let endIndex = afterSource.firstIndex(of: "\n") ?? afterSource.endIndex
            let value = String(afterSource[..<endIndex]).trimmingCharacters(in: .whitespaces)
            if !value.isEmpty { return value }
        }

        return nil
    }

    // MARK: - Cache Management

    private func cacheResult(
        path: String,
        identity: FileIdentity,
        result: NotarizationResult
    ) {
        // Evict oldest entries if cache is full
        if cache.count >= maxCacheSize {
            evictOldest(count: maxCacheSize / 4)
        }

        advanceAccessCounter()
        cache[path] = CacheEntry(
            result: result,
            identity: identity,
            accessOrder: accessCounter
        )
    }

    private func touchCacheEntry(path: String, entry: CacheEntry) {
        advanceAccessCounter()
        cache[path] = CacheEntry(
            result: entry.result,
            identity: entry.identity,
            accessOrder: accessCounter
        )
    }

    private func advanceAccessCounter() {
        if accessCounter == UInt64.max {
            // Extremely defensive renumbering. Fixed at 2K entries, so this is
            // bounded and preserves LRU order without wrapping old entries ahead.
            let ordered = cache.sorted { $0.value.accessOrder < $1.value.accessOrder }
            cache.removeAll(keepingCapacity: true)
            accessCounter = 0
            for (path, entry) in ordered {
                accessCounter += 1
                cache[path] = CacheEntry(
                    result: entry.result,
                    identity: entry.identity,
                    accessOrder: accessCounter
                )
            }
        }
        accessCounter += 1
    }

    /// Evict the N oldest entries from the cache.
    private func evictOldest(count: Int) {
        let sorted = cache.sorted { $0.value.accessOrder < $1.value.accessOrder }
        for (key, _) in sorted.prefix(count) {
            cache.removeValue(forKey: key)
        }
    }

    // MARK: - Helpers

    private nonisolated static func canonicalPath(_ path: String) -> String {
        (path as NSString).standardizingPath
    }

    private nonisolated static func isSystemPath(_ path: String) -> Bool {
        systemPrefixes.contains { path.hasPrefix($0) }
    }

    /// Identity of the bytes reached by this path. `stat`, rather than `lstat`,
    /// intentionally follows a symlink because `spctl` assesses the executable
    /// target. Device+inode catches atomic replacement; size+mtime+ctime catches
    /// in-place mutation. Nanosecond timestamps avoid one-second cache windows.
    private nonisolated static func fileIdentity(at path: String) -> FileIdentity? {
        var metadata = stat()
        let rc = path.withCString { Darwin.fstatat(AT_FDCWD, $0, &metadata, 0) }
        guard rc == 0, metadata.st_size >= 0 else { return nil }
        return FileIdentity(
            device: UInt64(bitPattern: Int64(metadata.st_dev)),
            inode: UInt64(metadata.st_ino),
            size: UInt64(metadata.st_size),
            modifiedSeconds: Int64(metadata.st_mtimespec.tv_sec),
            modifiedNanoseconds: Int64(metadata.st_mtimespec.tv_nsec),
            changedSeconds: Int64(metadata.st_ctimespec.tv_sec),
            changedNanoseconds: Int64(metadata.st_ctimespec.tv_nsec)
        )
    }

    private func logSuspiciousResultIfNeeded(_ result: NotarizationResult) {
        guard result.status == .notNotarized || result.status == .revoked else {
            return
        }
        let now = monotonicNow()
        if lastDiagnosticLogTick == nil
            || now - (lastDiagnosticLogTick ?? now) >= Self.diagnosticLogInterval {
            let suppressed = suppressedSinceLastDiagnosticLog
            suppressedSinceLastDiagnosticLog = 0
            lastDiagnosticLogTick = now
            increment(&diagnosticLogsEmitted)
            if result.status == .revoked {
                logger.error("Binary certificate revoked: \(result.path); \(suppressed) similar diagnostic(s) suppressed")
            } else {
                logger.warning("Binary not notarized: \(result.path); \(suppressed) similar diagnostic(s) suppressed")
            }
        } else {
            increment(&suppressedSinceLastDiagnosticLog)
            increment(&diagnosticLogsSuppressed)
        }
    }

    private func increment(_ value: inout UInt64) {
        if value < UInt64.max { value += 1 }
    }

    private nonisolated func isFromDownloads(_ path: String) -> Bool {
        guard let home = RealUserHomeResolver.home(containingPath: path) else {
            return false
        }
        return path.hasPrefix(home.appending("Downloads") + "/")
            || path.hasPrefix(home.appending("Desktop") + "/")
    }

    /// Enrich an event's enrichments dict with notarization info.
    public func enrich(_ enrichments: inout [String: String], forBinary binaryPath: String) async {
        let result = await check(binaryPath: binaryPath)
        enrichments["notarization.status"] = result.status.rawValue
        if let source = result.source {
            enrichments["notarization.source"] = source
        }
        enrichments["notarization.from_downloads"] = result.isFromDownloads ? "true" : "false"
    }
}
