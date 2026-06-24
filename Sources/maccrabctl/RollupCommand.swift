// RollupCommand.swift
// maccrabctl
//
// v1.8.0: force the tier-rollup-and-prune sweep on demand, outside the
// daemon's 6h timer. Useful for:
//   - First-launch verification on an oversized v1.7-era events.db.
//     A 1.8 GB DB shrinks to ~150-200 MB on first sweep; this command
//     surfaces the size delta + duration immediately so operators don't
//     wait up to 6 h for the timer.
//   - Ops drills (lower the cap, force a sweep, watch the result).
//   - Tests + soak harnesses.
//
// Reads the same data dir the daemon writes, so running this against
// a live daemon's DB is safe — the EventStore actor serializes writes
// across processes via SQLite WAL.

import Foundation
import MacCrabCore

func runRollup(olderThanHours: Double, dbPathOverride: String? = nil) async {
    let dbPath: String
    if let override = dbPathOverride {
        dbPath = override
    } else {
        dbPath = maccrabDataDir() + "/events.db"
    }

    guard FileManager.default.fileExists(atPath: dbPath) else {
        print("No events.db at \(dbPath) — daemon hasn't run yet, or wrong data dir.")
        return
    }

    let beforeSize = footprintMB(dbPath: dbPath)
    print("Tier rollup: \(beforeSize) MB before, cutoff \(Int(olderThanHours))h ago")
    print("  DB: \(dbPath)")

    let started = Date()
    do {
        let store = try EventStore(path: dbPath)
        let cutoff = Date().addingTimeInterval(-olderThanHours * 3600)
        let pruned = try await store.rollUpAndPrune(olderThan: cutoff)
        try await store.vacuum()                  // reclaim freed pages
        await store.walCheckpoint()               // drain WAL into main file
        let afterSize = footprintMB(dbPath: dbPath)
        let elapsed = Date().timeIntervalSince(started)
        print("Tier rollup: complete")
        print("  Pruned: \(pruned) events older than \(Int(olderThanHours))h")
        // afterSize can exceed beforeSize (WAL drain / vacuum repack on a busy
        // DB), so report the signed delta honestly: "freed" only when it shrank.
        let delta = beforeSize - afterSize
        let deltaStr = delta >= 0 ? "-\(delta) MB freed" : "+\(-delta) MB grew"
        print("  Size:   \(beforeSize) MB → \(afterSize) MB (\(deltaStr))")
        print("  Took:   \(String(format: "%.2f", elapsed))s")
    } catch {
        print("Tier rollup FAILED: \(error.localizedDescription)")
    }
}

/// db + wal + shm in MB. Same shape as `measureDatabaseFootprintMB` in
/// DaemonTimers — duplicated here because maccrabctl can't import the
/// agent-kit module directly (different SPM target).
private func footprintMB(dbPath: String) -> Int {
    let fm = FileManager.default
    func size(_ p: String) -> UInt64 {
        guard let attrs = try? fm.attributesOfItem(atPath: p),
              let b = attrs[.size] as? UInt64 else { return 0 }
        return b
    }
    let total = size(dbPath) + size(dbPath + "-wal") + size(dbPath + "-shm")
    return Int(total / 1_000_000)
}
