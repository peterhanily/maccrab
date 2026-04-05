// NotarizationChecker.swift
// MacCrabCore
//
// Checks notarization status of binaries using spctl --assess.
// Caches results keyed by binary path with an LRU eviction strategy.
// Rate-limited to avoid excessive spctl invocations under load.

import Foundation
import os.log

/// Evaluates and caches notarization status for executed binaries.
///
/// On process execution events, checks whether a binary has been notarized
/// by Apple using `spctl --assess`. Flags:
/// - Binaries that are NOT notarized, NOT Apple-signed, and NOT from /System/
/// - Binaries from ~/Downloads that lack notarization
///
/// Results are cached (LRU, max 2000 entries) since notarization status
/// does not change for a given binary on disk.
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

    // MARK: - Cache

    /// LRU cache entry wrapping a result and insertion order.
    private struct CacheEntry {
        let result: NotarizationResult
        let insertionOrder: UInt64
    }

    /// Path-keyed result cache.
    private var cache: [String: CacheEntry] = [:]
    private var insertionCounter: UInt64 = 0
    private let maxCacheSize = 2000

    private var cacheHits: Int = 0
    private var cacheMisses: Int = 0

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

    public init() {}

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
        // Fast path: cache hit
        if let entry = cache[binaryPath] {
            cacheHits += 1
            return entry.result
        }

        cacheMisses += 1

        // Skip system binaries
        for prefix in Self.systemPrefixes {
            if binaryPath.hasPrefix(prefix) {
                let result = NotarizationResult(
                    path: binaryPath,
                    status: .notarized,
                    source: "Apple",
                    isFromDownloads: false
                )
                cacheResult(path: binaryPath, result: result)
                return result
            }
        }

        // Skip non-existent or tiny binaries
        let fm = FileManager.default
        guard fm.fileExists(atPath: binaryPath),
              let attrs = try? fm.attributesOfItem(atPath: binaryPath),
              let fileSize = attrs[.size] as? UInt64,
              fileSize >= minimumBinarySize else {
            let result = NotarizationResult(
                path: binaryPath,
                status: .unknown,
                source: nil,
                isFromDownloads: isFromDownloads(binaryPath)
            )
            return result
        }

        // Perform the actual spctl assessment (rate-limited)
        let result = await performAssessment(binaryPath: binaryPath)
        cacheResult(path: binaryPath, result: result)

        if result.status == .notNotarized {
            logger.warning("Binary not notarized: \(binaryPath)")
        } else if result.status == .revoked {
            logger.error("Binary certificate revoked: \(binaryPath)")
        }

        return result
    }

    /// Return cache statistics.
    public func stats() -> (hits: Int, misses: Int, hitRate: Double, cacheSize: Int) {
        let total = cacheHits + cacheMisses
        let rate = total > 0 ? Double(cacheHits) / Double(total) : 0
        return (cacheHits, cacheMisses, rate, cache.count)
    }

    /// Clear all cached results.
    public func clearCache() {
        cache.removeAll()
        insertionCounter = 0
    }

    // MARK: - Assessment

    /// Acquire a slot for an spctl invocation, waiting if at capacity.
    private func acquireSlot() async {
        if inFlightCount < maxConcurrent {
            inFlightCount += 1
            return
        }
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            waiters.append(cont)
        }
        inFlightCount += 1
    }

    /// Release a slot, waking the next waiter if any.
    private func releaseSlot() {
        inFlightCount -= 1
        if !waiters.isEmpty {
            let next = waiters.removeFirst()
            next.resume()
        }
    }

    /// Run `spctl --assess` and parse the output.
    private func performAssessment(binaryPath: String) async -> NotarizationResult {
        let downloadsFlag = isFromDownloads(binaryPath)

        // Rate-limit concurrent spctl calls
        await acquireSlot()

        let output = runSpctl(binaryPath: binaryPath)

        // Release the concurrency slot now that spctl has finished
        releaseSlot()

        // Parse spctl output:
        // Accepted: "<path>: accepted\nsource=Notarized Developer ID\n..."
        // Rejected: "<path>: rejected\n..."
        // Revoked:  "<path>: rejected\norigin=... (revoked)\n..."

        let lowerOutput = output.lowercased()

        if lowerOutput.contains("accepted") {
            let source = parseSource(output)
            return NotarizationResult(
                path: binaryPath,
                status: .notarized,
                source: source,
                isFromDownloads: downloadsFlag
            )
        }

        if lowerOutput.contains("revoked") || lowerOutput.contains("revocation") {
            let source = parseSource(output)
            return NotarizationResult(
                path: binaryPath,
                status: .revoked,
                source: source,
                isFromDownloads: downloadsFlag
            )
        }

        if lowerOutput.contains("rejected") {
            let source = parseSource(output)
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
    private nonisolated func runSpctl(binaryPath: String) -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/spctl")
        process.arguments = ["--assess", "--type", "execute", "-v", binaryPath]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        do {
            try process.run()
            // Timeout after 15 seconds to avoid hanging on unresponsive binaries
            let deadline = DispatchTime.now() + 15
            DispatchQueue.global().asyncAfter(deadline: deadline) {
                if process.isRunning { process.terminate() }
            }
            process.waitUntilExit()
            return String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        } catch {
            return ""
        }
    }

    /// Extract the "source=..." or "origin=..." value from spctl output.
    private nonisolated func parseSource(_ output: String) -> String? {
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

    private func cacheResult(path: String, result: NotarizationResult) {
        // Evict oldest entries if cache is full
        if cache.count >= maxCacheSize {
            evictOldest(count: maxCacheSize / 4)
        }

        insertionCounter += 1
        cache[path] = CacheEntry(result: result, insertionOrder: insertionCounter)
    }

    /// Evict the N oldest entries from the cache.
    private func evictOldest(count: Int) {
        let sorted = cache.sorted { $0.value.insertionOrder < $1.value.insertionOrder }
        for (key, _) in sorted.prefix(count) {
            cache.removeValue(forKey: key)
        }
    }

    // MARK: - Helpers

    private nonisolated func isFromDownloads(_ path: String) -> Bool {
        let home = NSHomeDirectory()
        return path.hasPrefix(home + "/Downloads/") || path.hasPrefix(home + "/Desktop/")
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
