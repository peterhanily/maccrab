// DigestKeyedStringMemo.swift
// MacCrabCore
//
// Bounded memo for a pure String -> String transform on the event hot path.

import CryptoKit
import Foundation

/// Remembers the results of a deterministic String transform, keyed by the
/// SHA-256 of its input.
///
/// Every file event from one process repeats the same command line and
/// arguments, and the privacy redactors run a fixed suite of regular
/// expressions over each. Because those redactors are pure, replaying a
/// remembered output is exact. Keys are digests, so raw inputs (which may
/// carry a credential before redaction) are never retained; only outputs
/// are, and those are the redacted values the journal persists anyway.
/// Inputs or outputs above `maximumInputBytes` bypass the memo (a redactor
/// can expand `-p''` into `-p'[REDACTED]'`), and at most `capacity` entries
/// are kept with first-in, first-out replacement, so retained values never
/// exceed `capacity * maximumInputBytes` bytes.
final class DigestKeyedStringMemo: @unchecked Sendable {
    struct Key: Hashable {
        let w0: UInt64, w1: UInt64, w2: UInt64, w3: UInt64
    }

    private let capacity: Int
    private let maximumInputBytes: Int
    private let lock = NSLock()
    private var entries: [Key: String] = [:]
    private var insertionOrder: [Key] = []
    private var nextReplacement = 0

    init(capacity: Int, maximumInputBytes: Int) {
        precondition(capacity > 0 && maximumInputBytes >= 0)
        self.capacity = capacity
        self.maximumInputBytes = maximumInputBytes
        entries.reserveCapacity(capacity)
        insertionOrder.reserveCapacity(capacity)
    }

    /// `transform(input)`, replayed from the memo when this input was seen.
    func value(for input: String, transform: (String) -> String) -> String {
        guard input.utf8.count <= maximumInputBytes else { return transform(input) }
        let key = Self.key(for: input)
        lock.lock()
        if let remembered = entries[key] {
            lock.unlock()
            return remembered
        }
        lock.unlock()
        // Computed outside the lock: concurrent misses for one input may both
        // compute, and both results are identical by construction.
        let output = transform(input)
        guard output.utf8.count <= maximumInputBytes else { return output }
        lock.lock()
        if entries[key] == nil {
            if insertionOrder.count == capacity {
                entries.removeValue(forKey: insertionOrder[nextReplacement])
                insertionOrder[nextReplacement] = key
                nextReplacement = (nextReplacement + 1) % capacity
            } else {
                insertionOrder.append(key)
            }
            entries[key] = output
        }
        lock.unlock()
        return output
    }

    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return entries.count
    }

    static func key(for input: String) -> Key {
        var hasher = SHA256()
        hasher.update(data: Data(input.utf8))
        return hasher.finalize().withUnsafeBytes { bytes in
            Key(
                w0: bytes.loadUnaligned(fromByteOffset: 0, as: UInt64.self),
                w1: bytes.loadUnaligned(fromByteOffset: 8, as: UInt64.self),
                w2: bytes.loadUnaligned(fromByteOffset: 16, as: UInt64.self),
                w3: bytes.loadUnaligned(fromByteOffset: 24, as: UInt64.self)
            )
        }
    }
}
