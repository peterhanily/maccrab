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
    // v1.21.5 (audit sec-storage-crypto): the live events.db is now root-owned
    // 0o640 (group-read, NOT group-write), so a non-root CLI can no longer open
    // it read-write — and the root daemon already runs the tier-rollup + prune
    // sweep on its own timer. For the LIVE DB we therefore trigger the daemon
    // via the privileged `flush-request` inbox verb (the same channel the
    // dashboard's "Run cleanup now" uses) instead of writing the store directly.
    //
    // The `--db <path>` override still runs directly: it targets a user-supplied
    // COPY (tests / soak harnesses), never the root-owned live DB. If someone
    // points it at the live DB anyway, the tightened perms make the read-write
    // open fall back to read-only and the sweep fails cleanly — no write.
    guard let override = dbPathOverride else {
        await triggerDaemonRollup(olderThanHours: olderThanHours)
        return
    }
    let dbPath = override

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

/// Trigger the ROOT daemon's size-cap prune + VACUUM sweep (which runs
/// `rollUpAndPrune` internally) by dropping a `flush-request` file into the
/// privileged inbox. This is the non-root, cross-uid-safe path for the live
/// events.db, which the CLI can no longer (and should not) write directly.
/// The daemon authorizes the request by file-owner uid (root or the admin
/// console user) and removes it after processing.
private func triggerDaemonRollup(olderThanHours: Double) async {
    let dataDir = maccrabDataDir()
    let dbPath = dataDir + "/events.db"
    let fm = FileManager.default
    guard fm.fileExists(atPath: dbPath) else {
        print("No events.db at \(dbPath) — daemon hasn't run yet, or wrong data dir.")
        return
    }

    let inboxDir = dataDir + "/inbox"
    try? fm.createDirectory(atPath: inboxDir, withIntermediateDirectories: true)
    let payload: [String: Any] = [
        "schema_version": 1,
        "requested_at_unix": Date().timeIntervalSince1970,
        "requester": "maccrabctl rollup",
        "requester_pid": getpid(),
    ]
    let path = inboxDir + "/flush-request-\(Int(Date().timeIntervalSince1970))-\(getpid()).json"
    guard let data = try? JSONSerialization.data(withJSONObject: payload),
          (try? data.write(to: URL(fileURLWithPath: path))) != nil else {
        print("Tier rollup: could not queue a flush request in \(inboxDir).")
        print("  The daemon runs the tier-rollup + prune sweep automatically on its timer.")
        return
    }

    print("Tier rollup: requested — the root daemon runs its size-cap prune + VACUUM")
    print("  sweep (which rolls events up first) within ~5s. It also does this")
    print("  automatically on its own timer.")
    print("  Request: \(path)")
    if olderThanHours != 24 {
        print("  Note: --hours \(Int(olderThanHours)) is honored only with --db <copy>; the live")
        print("        sweep uses the daemon's configured retention cutoffs.")
    }
    print("  Watch: log show --predicate 'subsystem == \"com.maccrab.agent\"' --last 2m")
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
