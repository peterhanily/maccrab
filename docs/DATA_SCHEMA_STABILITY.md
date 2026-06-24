# Data Schema Stability Statement

This document states the stability guarantees (and non-guarantees) for MacCrab's
on-disk SQLite stores, and points integrators — including an acquirer's SOC — at
the **stable export interfaces** they should build against.

> Source of truth: `Sources/MacCrabCore/Storage/` — in particular
> `SchemaMigrator.swift`, and the per-store `schemaMigrations` arrays in
> `EventStore.swift`, `AlertStore.swift`, `CampaignStore.swift`,
> `TraceStore.swift`, and `SQLiteCausalGraphStore.swift`.

---

## The on-disk schema is NOT a stable public contract

MacCrab persists its working state in several SQLite files under the support
directory:

| File | Owner store(s) | Contents |
|---|---|---|
| `events.db` | `EventStore` (+ `alert_evidence`, FTS5 index) | Raw/enriched event records |
| `alerts.db` | `AlertStore` | Alert history (split out of `events.db` in v1.8.0) |
| `campaigns.db` | `CampaignStore` | Detected attack campaigns |
| `tracegraph.db` | `SQLiteCausalGraphStore` | The global causal entity/edge substrate |
| `traces.db` | `TraceStore` | Materialized causal traces (OTLP/HTTP, v1.9+) |

**These files are an internal implementation detail, not a supported API.**
Their table layouts, column sets, indexes, file-split boundaries, encryption
state, and retention/compaction behaviour change between MacCrab versions, and
have done so repeatedly (e.g. alert history was split out of `events.db` into
`alerts.db` in v1.8.0; attribution overrides were relocated to their own file;
columns are added across versions). The stores are also opened by the root engine
mode `0600`, may be encrypted (SQLCipher), and run in WAL mode with active
size-cap/rollup sweeps — so a file read out from under the engine is neither
schema-stable nor read-safe.

Consumers MUST NOT read these `.db` files directly. Direct reads will break on
upgrade and may observe partial/compacting state.

---

## How the schema evolves: forward-only, additive migrations

Schema evolution is handled by `SchemaMigrator`, keyed on SQLite's
`PRAGMA user_version`:

- **Forward-only.** Each store declares an ordered `schemaMigrations` array.
  On open, the migrator applies every step in ascending version order and bumps
  `user_version` only on forward progress. There is no down-migration path.
- **Additive.** Migrations are `ALTER TABLE … ADD COLUMN` and
  `CREATE TABLE/INDEX … IF NOT EXISTS` — they add columns/tables, they do not
  drop or rewrite existing ones. The migrator treats "duplicate column" /
  "already exists" errors as idempotent re-runs, so applying the full set to an
  existing DB is safe. (No migration uses `DROP`/destructive `UPDATE`.)
- **Co-resident-store aware.** Because `user_version` is a *single* per-file
  counter but multiple stores can share a file, each store always re-applies its
  own migrations idempotently rather than trusting the shared counter — a fix
  for a v1.7.5 field crash where a co-resident store's pending migration was
  silently skipped.
- **Integrity-checked.** After migrating, the migrator runs `PRAGMA quick_check`
  (deferrable for cold-start latency) to catch structural corruption.

### Newer-than-binary (downgrade / version-skew) warning

As of v1.19.1, if a store's `user_version` **exceeds** the running binary's
latest known migration version — i.e. an **older** MacCrab opened a DB written by
a **newer** one (a Sparkle/MDM downgrade, a rolled-back update onto an existing
evidence store, or a mixed-version fleet) — the migrator surfaces the skew
**loudly** via both an optional callback and `os.Logger.warning`
(`com.maccrab.agent` / `schema-migrator`), then proceeds additively. Because
migrations are additive and reads/writes are column-explicit, the old binary
keeps working, but it may not understand columns/semantics a newer build added.
A caller that wants to hard-refuse can check `current > latest` and throw
`SchemaMigrationError.unknownVersion`. This is the only "downgrade" handling: it
is a *warning*, not a guarantee that an old binary reads a new schema correctly.

The practical takeaway for integrators: because the binary itself negotiates the
schema (and only forward), there is no version of the on-disk format you can pin
to. Any tool that reads the files directly is coupled to a specific binary build.

---

## Use the documented EXPORT interfaces instead

MacCrab provides stable, supported read/export paths. **Build against these, not
the database files.** An acquirer's SOC should integrate exclusively through:

- **CLI — `maccrabctl`.** `maccrabctl report`, alert/event/campaign query and
  export subcommands, and threat-hunting (`hunt`). Stable, human- and
  machine-consumable output, ANSI auto-disabled when piped.
  (`Sources/maccrabctl/`.)

- **MCP read tools (`maccrab-mcp`).** A programmatic, versioned read surface for
  AI agents and integrations: `get_alerts`, `get_alert_detail`, `get_events`,
  `get_campaigns`, `get_traces` / `get_trace_detail`, `hunt`, `get_status`,
  `get_security_score`, `get_audit_log`, etc. (~80 tools).
  (`Sources/maccrab-mcp/`.)

- **OCSF / SIEM output sinks.** For streaming/forwarding into a SIEM, MacCrab
  maps to **OCSF** (`OCSFMapper`) and ships output adapters for syslog, webhooks,
  files, S3, SFTP, OTLP, and scheduled reports. These are the stable formats for
  off-box consumption. (`Sources/MacCrabCore/Output/` — `OCSFMapper.swift`,
  `SyslogOutput.swift`, `WebhookOutput.swift`, `S3Output.swift`,
  `SFTPOutput.swift`, `OTLPOutput.swift`, `ReportGenerator.swift`,
  `ScheduledReports.swift`.)

These interfaces present a stable view that is decoupled from the on-disk schema:
when the storage layer migrates underneath, the export contracts are what stay
constant. Point any SOC tooling, evidence pipeline, or SIEM integration at the
export interfaces — never at direct `.db` reads.
