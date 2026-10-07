// ESRepeatCoalescer.swift
// MacCrabCore
//
// v1.22.7 ES ingress throughput. Repeated NOTIFY_WRITE / NOTIFY_OPEN callbacks
// by the same (pid, pidversion) on the same path within a short window are a
// single observation to every downstream consumer: the first callback already
// fired every single-event rule, formed the cross-process write→execute chain,
// scored the behaviour indicator, materialised the agent-timeline entry and
// created the TraceGraph edge. Measured on the maintainer's host (attempt4
// capture): 204,547 WRITE events yielded against 21,515 modified CLOSEs — ~9.5
// write callbacks per completed file, of which only the first carries
// detection input. Ambient 34 h sample: NOTIFY_WRITE was 97% of the ES
// copy-backpressure drops and 76% of file-lane offers, and the file lane
// evicted 66% of everything offered to it.
//
// The first callback for a key ALWAYS passes through unchanged. Only repeats
// inside the window are coalesced, they are counted per type in the heartbeat
// (`es_coalesced_on_worker_by_type`), and the matching modified CLOSE carries
// the write count as `coalesced_write_count` so forensics can see it.
//
// Owned by one serial `ESMessageWorker` queue, so it needs no lock; the
// per-type counters live in the locked `ESSeqTracker` for the heartbeat.
// Bounded: at most `capacity` keys (default 4096 — ~1 MiB with ~200-byte
// paths); when full, expired keys are swept and, if none expired, the oldest
// half is evicted so the worst case is one O(n log n) sort per n/2 inserts.

import Foundation

final class ESRepeatCoalescer {
    struct Key: Hashable {
        let pid: Int32
        let pidversion: UInt32
        let path: String
    }

    enum Kind {
        case write
        case open
    }

    private struct Entry {
        var lastWriteNanos: UInt64?
        var lastOpenNanos: UInt64?
        var coalescedWrites: UInt64 = 0
        var coalescedOpens: UInt64 = 0

        var newestNanos: UInt64 {
            Swift.max(lastWriteNanos ?? 0, lastOpenNanos ?? 0)
        }
    }

    /// Repeats inside this many nanoseconds of the previous callback for the
    /// same key and kind are coalesced. 2 s: long enough to cover a build tool
    /// streaming one file, short enough that a genuinely new interaction with
    /// the same path (a later edit, a later read) is observed again.
    static let defaultWindowNanos: UInt64 = 2_000_000_000
    static let defaultCapacity = 4096

    private let windowNanos: UInt64
    private let capacity: Int
    private var entries: [Key: Entry] = [:]

    init(windowNanos: UInt64 = ESRepeatCoalescer.defaultWindowNanos,
         capacity: Int = ESRepeatCoalescer.defaultCapacity) {
        self.windowNanos = windowNanos
        self.capacity = Swift.max(1, capacity)
    }

    var count: Int { entries.count }

    /// Returns `true` when this callback is a repeat inside the window and must
    /// be coalesced (not yielded). The FIRST callback for a key and kind always
    /// returns `false` and starts the window.
    func shouldCoalesce(_ key: Key, kind: Kind, nowNanos: UInt64) -> Bool {
        if var entry = entries[key] {
            switch kind {
            case .write:
                if let last = entry.lastWriteNanos, nowNanos &- last <= windowNanos {
                    entry.coalescedWrites &+= 1
                    entry.lastWriteNanos = nowNanos
                    entries[key] = entry
                    return true
                }
                entry.lastWriteNanos = nowNanos
            case .open:
                if let last = entry.lastOpenNanos, nowNanos &- last <= windowNanos {
                    entry.coalescedOpens &+= 1
                    entry.lastOpenNanos = nowNanos
                    entries[key] = entry
                    return true
                }
                entry.lastOpenNanos = nowNanos
            }
            entries[key] = entry
            return false
        }
        makeRoom(nowNanos: nowNanos)
        var entry = Entry()
        switch kind {
        case .write: entry.lastWriteNanos = nowNanos
        case .open: entry.lastOpenNanos = nowNanos
        }
        entries[key] = entry
        return false
    }

    /// Terminal callback for a key (modified CLOSE, RENAME source, UNLINK): ends
    /// the window and returns how many writes were coalesced into the first one
    /// so the terminal event can carry the count. Zero when nothing was coalesced
    /// or the key was never seen.
    @discardableResult
    func terminate(_ key: Key) -> UInt64 {
        entries.removeValue(forKey: key)?.coalescedWrites ?? 0
    }

    private func makeRoom(nowNanos: UInt64) {
        guard entries.count >= capacity else { return }
        entries = entries.filter { nowNanos &- $0.value.newestNanos <= windowNanos }
        guard entries.count >= capacity else { return }
        // Every key is live inside the window (a build touching more distinct
        // files than the capacity in one window). Evict the older half so the
        // sort cost is amortised over the next capacity/2 inserts.
        let ordered = entries.sorted { $0.value.newestNanos < $1.value.newestNanos }
        for (key, _) in ordered.prefix(entries.count / 2 + 1) {
            entries.removeValue(forKey: key)
        }
    }
}
