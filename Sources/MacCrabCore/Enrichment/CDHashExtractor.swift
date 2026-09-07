// CDHashExtractor.swift
// MacCrabCore
//
// Reads the kernel's CodeDirectory hash for a running process with
// csops(CS_OPS_CDHASH). Each request queries the current process image.

import Foundation
import Darwin

// csops C function declaration
@_silgen_name("csops")
private func csops(_ pid: Int32, _ ops: UInt32, _ useraddr: UnsafeMutableRawPointer?, _ usersize: Int) -> Int32

/// CS_OPS_CDHASH from Apple's xnu bsd/sys/codesign.h (operation 6 is PIDOFFSET).
private let CS_OPS_CDHASH: UInt32 = 5

/// The kernel exposes a 20-byte CodeDirectory hash. This is not necessarily
/// SHA-1: a SHA-256 CodeDirectory hash is truncated to this length.
private let kCDHashSize = 20

/// The all-zeros hash returned when no CDHash is available.
private let kZeroCDHash = String(repeating: "00", count: 20)

/// Reads the current running image's CodeDirectory hash from the kernel.
/// A PID alone cannot safely identify a cached image across PID reuse or exec.
public actor CDHashExtractor {
    public init() {}

    /// Query a positive process ID. Returns lowercase hexadecimal, or nil if
    /// the process has no available code hash or the native query fails.
    public func extractCDHash(pid: Int32) -> String? {
        guard pid > 0 else { return nil }
        return extractViaCsops(pid: pid)
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

    /// Retained for caller compatibility. No invalidation is needed because
    /// every extraction queries the kernel instead of a PID-keyed cache.
    public func invalidate(pid: Int32) {}

    // MARK: - Private

    private nonisolated func extractViaCsops(pid: Int32) -> String? {
        var cdhash = [UInt8](repeating: 0, count: kCDHashSize)
        let rc = cdhash.withUnsafeMutableBytes { bytes in
            csops(pid, CS_OPS_CDHASH, bytes.baseAddress, bytes.count)
        }
        guard rc == 0 else { return nil }

        let hash = cdhash.map { String(format: "%02x", $0) }.joined()
        guard hash != kZeroCDHash else { return nil }
        return hash
    }
}
