// Initial schema for the per-case `case.sqlite` ArtifactStore.
//
// Versioned via PRAGMA user_version (matches the pattern used by
// MacCrabCore's EventStore + AlertStore + CampaignStore). v1.13a-1
// ships user_version = 1. Future sub-slices may bump.
//
// Plan reference: §3.4 schema.

import Foundation
import CSQLCipher

enum SchemaV1 {

    static let userVersion: Int32 = 1

    /// Full DDL for a brand-new database. Idempotent: every
    /// `CREATE TABLE` uses `IF NOT EXISTS` so applying twice is a
    /// no-op. Index statements likewise.
    static let createDDL: String = """
    -- cases: one row per maccrabctl case new.
    CREATE TABLE IF NOT EXISTS cases (
        id TEXT PRIMARY KEY NOT NULL,
        name TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        time_window_start INTEGER,
        time_window_end INTEGER,
        notes TEXT,
        encryption_state TEXT NOT NULL,
        ai_content_allowed INTEGER NOT NULL DEFAULT 0,
        scheduled_trusted INTEGER NOT NULL DEFAULT 0
    );

    -- artifacts: one row per emitted artifact. The JSON payload
    -- lives separately in `artifact_data` so the hot path of
    -- listing/filtering doesn't pay JSON decoding cost.
    CREATE TABLE IF NOT EXISTS artifacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT NOT NULL,
        plugin_id TEXT NOT NULL,
        plugin_version TEXT NOT NULL,
        schema_version INTEGER NOT NULL,
        content_type TEXT NOT NULL,
        source_path TEXT,
        source_inode INTEGER,
        source_mtime INTEGER,
        sha256 TEXT NOT NULL,
        blob_relpath TEXT,
        observed_at INTEGER NOT NULL,
        captured_at INTEGER NOT NULL,
        summary TEXT,
        size_bytes INTEGER NOT NULL DEFAULT 0,
        confidence TEXT NOT NULL,
        privacy_class TEXT NOT NULL,
        actor TEXT,
        FOREIGN KEY (case_id) REFERENCES cases(id)
    );

    -- Composite indices matching the three dominant query shapes:
    --   case + time order (timeline view)
    --   case + content type + time (filtered list)
    --   case + privacy class (Pass 2026-D + dashboard filtering)
    CREATE INDEX IF NOT EXISTS idx_artifacts_observed
        ON artifacts(case_id, observed_at);
    CREATE INDEX IF NOT EXISTS idx_artifacts_type
        ON artifacts(case_id, content_type, observed_at);
    CREATE INDEX IF NOT EXISTS idx_artifacts_privacy
        ON artifacts(case_id, privacy_class);

    -- artifact_data: JSON1 payload. 1:1 with artifacts.
    CREATE TABLE IF NOT EXISTS artifact_data (
        artifact_id INTEGER PRIMARY KEY NOT NULL,
        json TEXT NOT NULL,
        FOREIGN KEY (artifact_id) REFERENCES artifacts(id) ON DELETE CASCADE
    );

    -- plugin_invocations: one row per plugin run. Powers the
    -- invocation log + the `case show` activity table.
    CREATE TABLE IF NOT EXISTS plugin_invocations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT NOT NULL,
        plugin_id TEXT NOT NULL,
        plugin_version TEXT NOT NULL,
        inputs_json TEXT NOT NULL,
        started_at INTEGER NOT NULL,
        completed_at INTEGER,
        exit_status TEXT NOT NULL,
        artifacts_committed INTEGER NOT NULL DEFAULT 0,
        artifacts_rejected INTEGER NOT NULL DEFAULT 0,
        error_message TEXT,
        snapshot_hash TEXT,
        FOREIGN KEY (case_id) REFERENCES cases(id)
    );

    CREATE INDEX IF NOT EXISTS idx_plugin_invocations_case_time
        ON plugin_invocations(case_id, started_at);
    """

    /// PRAGMAs applied at open time, AFTER the SQLCipher key has
    /// been set. Order matters per the StoragePragmas.swift
    /// Wave 9B.1 note carried over from MacCrabCore: `auto_vacuum`
    /// must precede `journal_mode = WAL`.
    static let openPragmas: [String] = [
        "PRAGMA foreign_keys = ON",
        "PRAGMA busy_timeout = 5000",
        "PRAGMA auto_vacuum = INCREMENTAL",
        "PRAGMA journal_mode = WAL",
        "PRAGMA synchronous = NORMAL",
        "PRAGMA wal_autocheckpoint = 1000",
        "PRAGMA cache_size = -8192",   // ~8 MB cache, negative = KB
        "PRAGMA mmap_size = 16777216", // 16 MB mmap window
    ]
}
