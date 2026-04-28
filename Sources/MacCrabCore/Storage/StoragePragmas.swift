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

    /// Apply EventStore-specific pragmas to an open handle.
    static func applyEventStorePragmas(to handle: OpaquePointer) {
        sqlite3_exec(handle, "PRAGMA journal_mode = WAL", nil, nil, nil)
        sqlite3_exec(handle, "PRAGMA synchronous = NORMAL", nil, nil, nil)
        sqlite3_exec(handle, "PRAGMA wal_autocheckpoint = \(walAutocheckpointPages)", nil, nil, nil)
        sqlite3_exec(handle, "PRAGMA cache_size = \(eventCacheSizeKB)", nil, nil, nil)
        sqlite3_exec(handle, "PRAGMA mmap_size = \(eventMmapSizeBytes)", nil, nil, nil)
    }

    /// Apply AlertStore-specific pragmas to an open handle.
    static func applyAlertStorePragmas(to handle: OpaquePointer) {
        sqlite3_exec(handle, "PRAGMA journal_mode = WAL", nil, nil, nil)
        sqlite3_exec(handle, "PRAGMA synchronous = NORMAL", nil, nil, nil)
        sqlite3_exec(handle, "PRAGMA wal_autocheckpoint = \(walAutocheckpointPages)", nil, nil, nil)
        sqlite3_exec(handle, "PRAGMA cache_size = \(alertCacheSizeKB)", nil, nil, nil)
        sqlite3_exec(handle, "PRAGMA mmap_size = \(alertMmapSizeBytes)", nil, nil, nil)
    }
}
