// CDHashExtractor.swift
// MacCrabCore
//
// Extracts CDHash for any running process using undocumented proc_pidinfo
// flavor 17. This is faster than csops and works for processes not caught
// at exec time. Falls back to csops(CS_OPS_CDHASH) if flavor 17 fails.

import Foundation
import Darwin
import os.log

// csops C function declaration
@_silgen_name("csops")
private func csops(_ pid: Int32, _ ops: UInt32, _ useraddr: UnsafeMutableRawPointer?, _ usersize: Int) -> Int32

/// CDHash operation constant for csops.
private let CS_OPS_CDHASH: UInt32 = 6

/// CDHash size in bytes.
private let kCDHashSize = 20

/// The all-zeros hash returned when no CDHash is available.
private let kZeroCDHash = String(repeating: "00", count: 20)

/// Extracts CDHash for any running process using undocumented proc_pidinfo flavor 17.
/// Faster than csops, works for processes not caught at exec time.
public actor CDHashExtractor {
    private let logger = Logger(subsystem: "com.maccrab.enrichment", category: "cdhash-extractor")

    /// Cache of extracted CDHashes.
    private var cache: [Int32: String] = [:]
    private let maxCacheSize = 5000

    /// Undocumented proc_pidinfo flavor for code signing info (56 bytes).
    private static let PROC_PIDCODESIGNINFO: Int32 = 17
    private static let codeSignInfoSize: Int32 = 56

    public init() {}

    /// Extract CDHash for a process. Returns hex string or nil.
    public func extractCDHash(pid: Int32) -> String? {
        // Check cache first
        if let cached = cache[pid] { return cached }

        // Try undocumented flavor 17 first (56 bytes)
        if let hash = extractViaFlavor17(pid: pid) {
            cacheResult(pid: pid, hash: hash)
            return hash
        }

        // Fallback to csops
        if let hash = extractViaCsops(pid: pid) {
            cacheResult(pid: pid, hash: hash)
            return hash
        }

        return nil
    }

    /// Batch extract CDHashes for multiple PIDs.
    public func extractBatch(pids: [Int32]) -> [Int32: String] {
        var results: [Int32: String] = [:]
        for pid in pids {
            if let hash = extractCDHash(pid: pid) {
                results[pid] = hash
            }
        }
        return results
    }

    /// Invalidate a cached entry (e.g. when a process exits and PID may be reused).
    public func invalidate(pid: Int32) {
        cache.removeValue(forKey: pid)
    }

    // MARK: - Private

    private nonisolated func extractViaFlavor17(pid: Int32) -> String? {
        var buf = [UInt8](repeating: 0, count: Int(Self.codeSignInfoSize))
        let size = proc_pidinfo(pid, Self.PROC_PIDCODESIGNINFO, 0, &buf, Self.codeSignInfoSize)

        guard size >= Int32(kCDHashSize) else { return nil }

        // CDHash is the first 20 bytes
        let hash = buf.prefix(kCDHashSize).map { String(format: "%02x", $0) }.joined()

        // Verify it is not all zeros
        guard hash != kZeroCDHash else { return nil }
        return hash
    }

    private nonisolated func extractViaCsops(pid: Int32) -> String? {
        var cdhash = [UInt8](repeating: 0, count: kCDHashSize)
        let rc = csops(pid, CS_OPS_CDHASH, &cdhash, kCDHashSize)
        guard rc == 0 else { return nil }

        let hash = cdhash.map { String(format: "%02x", $0) }.joined()
        guard hash != kZeroCDHash else { return nil }
        return hash
    }

    private func cacheResult(pid: Int32, hash: String) {
        cache[pid] = hash
        if cache.count > maxCacheSize {
            // Evict oldest entries (approximate — remove a batch to amortize)
            let toRemove = cache.count - maxCacheSize + 100
            for key in cache.keys.prefix(toRemove) {
                cache.removeValue(forKey: key)
            }
        }
    }
}
