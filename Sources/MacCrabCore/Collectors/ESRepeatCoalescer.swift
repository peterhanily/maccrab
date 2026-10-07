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
// The first callback for a key ALWAYS passes through unchanged. The window is
// anchored at that yielded callback (it does not slide with each repeat), so a
// process that keeps writing or re-reading the same file is observed once per
// window, never once for its lifetime. Repeats inside the window are counted
// per type in the heartbeat (`es_coalesced_on_worker_by_type`), and the
// matching modified CLOSE carries the write count as `coalesced_write_count`
// so forensics can see it.
//
// A terminal event on a path (modified CLOSE, RENAME source or destination,
// UNLINK) ends the OPEN window of EVERY process on that path, not just the
// writer's: the file changed under its readers, and a re-read after a
// third-party modification must reach FileInjectionScanner again. The
// writer's own WRITE window (and its count) is the only one the terminal
// consumes.
//
// Owned by one serial `ESMessageWorker` queue, so it needs no lock; the
// per-type counters live in the locked `ESSeqTracker` for the heartbeat.
// Bounded: at most `capacity` (path, process) entries (default 4096 — ~1 MiB
// with ~200-byte paths); when full, expired entries are swept and, if none
// expired, the oldest half is evicted so the worst case is one O(n log n)
// sort per n/2 inserts.

import Foundation

final class ESRepeatCoalescer {
    struct ProcessKey: Hashable {
        let pid: Int32
        let pidversion: UInt32
    }

    enum Kind {
        case write
        case open
    }

    private struct Entry {
        /// Start of the current WRITE window (the yielded callback), if open.
        var writeWindowStart: UInt64?
        /// Start of the current OPEN window (the yielded callback), if open.
        var openWindowStart: UInt64?
        /// Writes folded into yielded ones since the last terminal event.
        var coalescedWrites: UInt64 = 0

        var newestNanos: UInt64 {
            Swift.max(writeWindowStart ?? 0, openWindowStart ?? 0)
        }

        var isEmpty: Bool { writeWindowStart == nil && openWindowStart == nil }
    }

    /// Repeats within this many nanoseconds of the YIELDED callback for the
    /// same key and kind are coalesced. 2 s: long enough to cover a build tool
    /// streaming one file, short enough that a genuinely new interaction with
    /// the same path (a later edit, a later read) is observed again.
    static let defaultWindowNanos: UInt64 = 2_000_000_000
    static let defaultCapacity = 4096

    private let windowNanos: UInt64
    private let capacity: Int
    /// path → process → window state. Keyed by path first so a terminal event
    /// can end every reader's OPEN window on that path in one lookup.
    private var entries: [String: [ProcessKey: Entry]] = [:]
    private(set) var count = 0

    init(windowNanos: UInt64 = ESRepeatCoalescer.defaultWindowNanos,
         capacity: Int = ESRepeatCoalescer.defaultCapacity) {
        self.windowNanos = windowNanos
        self.capacity = Swift.max(1, capacity)
    }

    /// Returns `true` when this callback is a repeat inside the window and must
    /// be coalesced (not yielded). The FIRST callback for a key and kind, and
    /// the first one after the window, always return `false` and (re)start the
    /// window at `nowNanos`.
    func shouldCoalesce(
        path: String, pid: Int32, pidversion: UInt32, kind: Kind, nowNanos: UInt64
    ) -> Bool {
        let process = ProcessKey(pid: pid, pidversion: pidversion)
        if var entry = entries[path]?[process] {
            switch kind {
            case .write:
                if let start = entry.writeWindowStart, nowNanos &- start <= windowNanos {
                    entry.coalescedWrites &+= 1
                    entries[path]?[process] = entry
                    return true
                }
                entry.writeWindowStart = nowNanos
            case .open:
                if let start = entry.openWindowStart, nowNanos &- start <= windowNanos {
                    return true
                }
                entry.openWindowStart = nowNanos
            }
            entries[path]?[process] = entry
            return false
        }
        makeRoom(nowNanos: nowNanos)
        var entry = Entry()
        switch kind {
        case .write: entry.writeWindowStart = nowNanos
        case .open: entry.openWindowStart = nowNanos
        }
        entries[path, default: [:]][process] = entry
        count += 1
        return false
    }

    /// Terminal callback on a path (modified CLOSE, RENAME source/destination,
    /// UNLINK) by `pid`/`pidversion`. Ends that process's windows and returns
    /// how many writes were coalesced into its yielded ones so the terminal
    /// event can carry the count (zero when nothing was coalesced or the key
    /// was never seen). Also ends every OTHER process's OPEN window on the
    /// path: the file changed, so their next read is a new observation. Their
    /// WRITE windows and counts are left for their own terminal event.
    @discardableResult
    func terminate(path: String, pid: Int32, pidversion: UInt32) -> UInt64 {
        guard var processes = entries.removeValue(forKey: path) else { return 0 }
        let process = ProcessKey(pid: pid, pidversion: pidversion)
        var folded: UInt64 = 0
        if let own = processes.removeValue(forKey: process) {
            folded = own.coalescedWrites
            count -= 1
        }
        var survivors: [ProcessKey: Entry] = [:]
        for (other, var entry) in processes {
            entry.openWindowStart = nil
            if entry.isEmpty { count -= 1 } else { survivors[other] = entry }
        }
        if !survivors.isEmpty { entries[path] = survivors }
        return folded
    }

    private func makeRoom(nowNanos: UInt64) {
        guard count >= capacity else { return }
        // Sweep entries whose every window has expired.
        var swept: [String: [ProcessKey: Entry]] = [:]
        var sweptCount = 0
        for (path, processes) in entries {
            let live = processes.filter { nowNanos &- $0.value.newestNanos <= windowNanos }
            if !live.isEmpty {
                swept[path] = live
                sweptCount += live.count
            }
        }
        entries = swept
        count = sweptCount
        guard count >= capacity else { return }
        // Every entry is live inside the window (a build touching more distinct
        // files than the capacity in one window). Evict the older half so the
        // sort cost is amortised over the next capacity/2 inserts.
        var ordered: [(path: String, process: ProcessKey, newest: UInt64)] = []
        ordered.reserveCapacity(count)
        for (path, processes) in entries {
            for (process, entry) in processes {
                ordered.append((path, process, entry.newestNanos))
            }
        }
        ordered.sort { $0.newest < $1.newest }
        for victim in ordered.prefix(count / 2 + 1) {
            entries[victim.path]?.removeValue(forKey: victim.process)
            if entries[victim.path]?.isEmpty == true { entries.removeValue(forKey: victim.path) }
            count -= 1
        }
    }
}
