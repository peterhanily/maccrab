// StoragePragmas.swift
// MacCrabCore
//
// Single source of truth for SQLite per-connection memory pragmas.
//
// Both EventStore and AlertStore open separate connections to the same
// `events.db` file. SQLite's `mmap_size` and `cache_size` are
// per-connection — every open handle reserves its own page cache in the
// process heap, and its own mmap region in the virtual address space.
//
// v1.6.22 cut these by 4× (mmap) and 4–8× (cache) after Activity
// Monitor on a test host showed the daemon at 2.76 GB resident with
// 2 connections × 256 MB mmap + 64 MB cache reserved per connection.

import Foundation
import SQLite3

enum StoragePragmas {
    /// EventStore page cache. Negative values are KB.
    /// 16 MB covers a typical timestamp-range scan (1K–10K rows × ~2KB JSON =
    /// 2–20 MB of page traffic) without thrashing. Larger queries (full FTS
    /// rebuild, hunt across millions of rows) will spill to mmap, which is
    /// fine — those are interactive, not hot-path.
    static let eventCacheSizeKB: Int32 = -16_000

    /// AlertStore page cache. Smaller table (alerts << events), 4 MB suffices.
    static let alertCacheSizeKB: Int32 = -4_000

    /// EventStore mmap window. 64 MB lets index lookups page in without
    /// reserving the full file address space. Below this, certain BLOB column
    /// fetches fall back to read() syscalls — acceptable for the cold path.
    static let eventMmapSizeBytes: Int64 = 67_108_864 // 64 MB

    /// AlertStore mmap window. 16 MB — alert JSON blobs are the only large
    /// values; the rest of the alerts schema fits comfortably in cache.
    static let alertMmapSizeBytes: Int64 = 16_777_216 // 16 MB

    /// WAL autocheckpoint threshold (pages). 1000 pages × 4 KB = 4 MB WAL
    /// before checkpoint. v1.6.21 had this at 10000 (40 MB), which let the
    /// WAL grow large during write storms before draining. 1000 keeps the
    /// `.db-wal` file small and reduces transient memory.
    static let walAutocheckpointPages: Int32 = 1000

    // CRITICAL ORDERING NOTE (Wave 9B.1, v1.12.6 RC2):
    //
    // `PRAGMA auto_vacuum = INCREMENTAL` MUST be set BEFORE
    // `PRAGMA journal_mode = WAL`. SQLite refuses to flip
    // auto_vacuum once the DB header has been dirtied by WAL
    // setup, and the failure is SILENT — no error, just
    // `PRAGMA auto_vacuum` keeps returning 0 (NONE). Pre-fix
    // (Wave 9B audit finding): every fresh DB shipped in
    // mode 0, so `incremental_vacuum` was a no-op and the
    // size-cap enforcer's reclaim path never functioned.
    // Field-confirmed via runtime PRAGMA inspection on v1.12.6
    // RC1 user machine: tracegraph.db at 11 GB in mode 0.
    //
    // Order also matters for `synchronous` / `cache_size` /
    // `mmap_size` etc. — those are per-connection and can be
    // set in any order. Only auto_vacuum has the empty-DB
    // header-clean constraint.

    /// Apply EventStore-specific pragmas to an open handle.
    static func applyEventStorePragmas(to handle: OpaquePointer) {
        // auto_vacuum MUST come first — see Wave 9B.1 ordering note above.
        sqlite3_exec(handle, "PRAGMA auto_vacuum = INCREMENTAL", nil, nil, nil)
        sqlite3_exec(handle, "PRAGMA journal_mode = WAL", nil, nil, nil)
        sqlite3_exec(handle, "PRAGMA synchronous = NORMAL", nil, nil, nil)
        sqlite3_exec(handle, "PRAGMA wal_autocheckpoint = \(walAutocheckpointPages)", nil, nil, nil)
        sqlite3_exec(handle, "PRAGMA cache_size = \(eventCacheSizeKB)", nil, nil, nil)
        sqlite3_exec(handle, "PRAGMA mmap_size = \(eventMmapSizeBytes)", nil, nil, nil)
    }

    /// Apply AlertStore-specific pragmas to an open handle.
    static func applyAlertStorePragmas(to handle: OpaquePointer) {
        // auto_vacuum MUST come first — see Wave 9B.1 ordering note above.
        sqlite3_exec(handle, "PRAGMA auto_vacuum = INCREMENTAL", nil, nil, nil)
        sqlite3_exec(handle, "PRAGMA journal_mode = WAL", nil, nil, nil)
        sqlite3_exec(handle, "PRAGMA synchronous = NORMAL", nil, nil, nil)
        sqlite3_exec(handle, "PRAGMA wal_autocheckpoint = \(walAutocheckpointPages)", nil, nil, nil)
        sqlite3_exec(handle, "PRAGMA cache_size = \(alertCacheSizeKB)", nil, nil, nil)
        sqlite3_exec(handle, "PRAGMA mmap_size = \(alertMmapSizeBytes)", nil, nil, nil)
    }

    /// Apply CampaignStore-specific pragmas. Same shape as alerts.
    static func applyCampaignStorePragmas(to handle: OpaquePointer) {
        // auto_vacuum MUST come first — see Wave 9B.1 ordering note above.
        sqlite3_exec(handle, "PRAGMA auto_vacuum = INCREMENTAL", nil, nil, nil)
        sqlite3_exec(handle, "PRAGMA journal_mode = WAL", nil, nil, nil)
        sqlite3_exec(handle, "PRAGMA synchronous = NORMAL", nil, nil, nil)
        sqlite3_exec(handle, "PRAGMA wal_autocheckpoint = \(walAutocheckpointPages)", nil, nil, nil)
        sqlite3_exec(handle, "PRAGMA cache_size = \(alertCacheSizeKB)", nil, nil, nil)
    }

    // MARK: - Incremental vacuum (Wave 9B, v1.12.6)
    //
    // Full VACUUM rewrites the whole file into a parallel temp file and
    // therefore needs ~= DB size of scratch space on disk. On a host
    // with a 7+ GB events.db and < 4 GB free, the size-cap enforcer
    // skipped VACUUM forever — pages were freed internally by
    // `pruneOldest()` but the `.db` file never shrank, so the
    // file grew unbounded between sweeps.
    //
    // `PRAGMA incremental_vacuum(N)` reclaims up to N pages from the
    // *end* of the file by truncating in place. It requires **zero**
    // scratch space — only that the DB was created with
    // `auto_vacuum = INCREMENTAL` (mode 2). Mode is per-file and
    // persistent; we read it at runtime and only attempt the reclaim
    // when the file actually supports it.
    //
    // Hard cap per call: 200K pages (~800 MB at the 4 KB default page
    // size) so a single sweep can't stall the actor for too long.
    // The caller schedules the next sweep on its own timer; we never
    // loop inside this call.

    /// Maximum pages reclaimed per incremental_vacuum call, regardless
    /// of what the caller requested. Keeps wall-clock bounded (~5-30 s
    /// for 200K pages even on slow SSDs) so the actor can serve other
    /// requests in a reasonable window.
    static let incrementalVacuumHardCap: Int = 200_000

    /// Outcome of a single `incrementalVacuum` call.
    struct IncrementalVacuumResult: Sendable {
        /// Pages the DB had on the freelist before the call.
        let freelistBefore: Int
        /// Pages remaining on the freelist after the call.
        let freelistAfter: Int
        /// Pages physically removed from the end of the file
        /// (`freelistBefore - freelistAfter`, never negative).
        var pagesReclaimed: Int { max(0, freelistBefore - freelistAfter) }
        /// True iff `auto_vacuum = INCREMENTAL` is active on the file.
        /// When false, the call short-circuited and reclaimed nothing.
        let autoVacuumActive: Bool
    }

    /// Read `PRAGMA auto_vacuum` from the handle. Returns the raw mode:
    ///   - 0 = NONE   (full VACUUM only path)
    ///   - 1 = FULL   (auto-vacuums on every commit, no incremental)
    ///   - 2 = INCREMENTAL (the mode we set on fresh DBs)
    /// On any error, returns 0 — the caller will treat that as "no
    /// incremental path available".
    static func readAutoVacuumMode(_ handle: OpaquePointer) -> Int32 {
        return readPragmaInt(handle, sql: "PRAGMA auto_vacuum")
    }

    /// Read `PRAGMA freelist_count` from the handle. Returns 0 on
    /// error or empty result.
    static func readFreelistCount(_ handle: OpaquePointer) -> Int {
        let raw = readPragmaInt(handle, sql: "PRAGMA freelist_count")
        return Int(raw)
    }

    /// Helper to read a single-row, single-column integer PRAGMA.
    private static func readPragmaInt(_ handle: OpaquePointer, sql: String) -> Int32 {
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_prepare_v2(handle, sql, -1, &stmt, nil) == SQLITE_OK,
              let stmt else {
            return 0
        }
        guard sqlite3_step(stmt) == SQLITE_ROW else { return 0 }
        return sqlite3_column_int(stmt, 0)
    }

    /// Run `PRAGMA incremental_vacuum(N)` with a passive checkpoint
    /// before and a truncate checkpoint after so the WAL doesn't keep
    /// "deleted" pages alive after the in-place truncate.
    ///
    /// `maxPages` is clamped to `incrementalVacuumHardCap` and to the
    /// current `freelist_count` — passing a larger value to
    /// `incremental_vacuum` is harmless (SQLite caps at freelist size)
    /// but the explicit clamp lets us log a precise "reclaimed N" line.
    ///
    /// Returns an `IncrementalVacuumResult` with the freelist deltas.
    /// Errors propagate via `result.autoVacuumActive == false` (when
    /// the file is not in INCREMENTAL mode) or a thrown
    /// `IncrementalVacuumError` (when the SQLite call itself fails).
    enum IncrementalVacuumError: Error {
        case sqliteFailed(String)
    }

    static func runIncrementalVacuum(
        on handle: OpaquePointer,
        maxPages: Int
    ) throws -> IncrementalVacuumResult {
        let mode = readAutoVacuumMode(handle)
        guard mode == 2 else {
            // Not in INCREMENTAL mode — the pragma would be a no-op
            // anyway, but we explicitly skip so callers can log the
            // gap. (Pre-v1.10 EventStore DBs and all current
            // TraceStore / CausalGraphStore DBs are mode 0.)
            return IncrementalVacuumResult(
                freelistBefore: 0,
                freelistAfter: 0,
                autoVacuumActive: false
            )
        }

        // Best-effort passive checkpoint: drains as much of the WAL
        // as we can without blocking concurrent writers. If a writer
        // is mid-transaction this is a no-op; that's fine — the
        // truncate checkpoint below will retry under the same lock
        // semantics that the next size-cap sweep already uses.
        var passiveLog: Int32 = 0
        var passiveCkpt: Int32 = 0
        _ = sqlite3_wal_checkpoint_v2(
            handle, nil,
            Int32(SQLITE_CHECKPOINT_PASSIVE),
            &passiveLog, &passiveCkpt
        )

        let freelistBefore = readFreelistCount(handle)
        guard freelistBefore > 0 else {
            // No pages to reclaim — short-circuit so we don't even
            // bother with the truncate checkpoint, which would just
            // be noise in the structured log.
            return IncrementalVacuumResult(
                freelistBefore: 0,
                freelistAfter: 0,
                autoVacuumActive: true
            )
        }

        let requested = max(0, min(maxPages, incrementalVacuumHardCap, freelistBefore))
        if requested > 0 {
            // `PRAGMA incremental_vacuum(N)` is the documented form;
            // SQLite reclaims min(N, freelist_count) pages from the
            // end of the file by truncating in place. No scratch
            // disk needed.
            let sql = "PRAGMA incremental_vacuum(\(requested))"
            var errmsg: UnsafeMutablePointer<CChar>?
            let rc = sqlite3_exec(handle, sql, nil, nil, &errmsg)
            if rc != SQLITE_OK {
                let msg = errmsg.flatMap { String(cString: $0) } ?? "unknown error"
                sqlite3_free(errmsg)
                throw IncrementalVacuumError.sqliteFailed(msg)
            }
        }

        // Truncate the WAL so the pages we just freed don't survive
        // as zombie copies in the .wal sidecar. Best-effort — if
        // readers are active the truncate may degrade to RESTART
        // semantics, which is still fine.
        var truncLog: Int32 = 0
        var truncCkpt: Int32 = 0
        _ = sqlite3_wal_checkpoint_v2(
            handle, nil,
            Int32(SQLITE_CHECKPOINT_TRUNCATE),
            &truncLog, &truncCkpt
        )

        let freelistAfter = readFreelistCount(handle)
        return IncrementalVacuumResult(
            freelistBefore: freelistBefore,
            freelistAfter: freelistAfter,
            autoVacuumActive: true
        )
    }
}
