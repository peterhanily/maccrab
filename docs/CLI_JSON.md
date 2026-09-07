# CLI JSON and runtime configuration

`maccrabctl status --json`, `rules list --json`, `rules count --json`, and configuration reads produce machine-readable JSON. Output documents have `schema_version: 1`; object keys use snake case and dates use ISO 8601 UTC. Consumers should ignore unfamiliar fields. Missing optional fields mean unavailable information, never zero or healthy.

`MACCRAB_DATA_DIR` explicitly selects one engine directory for these reads and request submissions. Without it, the existing installed/user-store resolver selects the directory. Status JSON names `source_directory`. A fresh heartbeat is a liveness observation; it is not by itself a protection verdict.

Status JSON includes `agent_trace_trust: "unauthenticated_self_reported"`. This fixed provenance label describes OTLP Agent Trace data; it does not claim that the receiver is enabled, its storage is available, or its spans are authenticated. Current admission is separately reported in `current_health.traces_storage_admission` when a fresh matching engine heartbeat provides it. Missing or stale health is unavailable information; the trust label remains valid without current health. Older schema-1 status documents may omit this label.

| Command | Main fields and meaning |
| --- | --- |
| `status --json` | `liveness`, `heartbeat_written_at`, `engine_identity`, `boot_phase`, `current_health`, `retained_event_count`, `retained_alert_count`. Counts use bounded physical storage metadata rather than authenticating the entire event journal. A missing store gives an absent count; a present store that cannot be read fails the command. |
| `rules list --json` | `rules`, `rule_profile`, `telemetry_freshness`, `telemetry_written_at`, `telemetry_age_seconds`, `engine_identity`. The inventory describes readable compiled single-event files. Current coverage uses the running engine's loaded/enabled IDs and counters. |
| `rules count --json` | `total`, `by_severity`, `by_category`. An empty readable directory is a successful zero; an absent/unreadable corpus or incomplete rule metadata is an error. |
| `config get [key] --json` | `view: configured`, `file_present`, `values`. Known omitted tunables show defaults. These are configured values, not proof of application. An unreadable/incomplete file or unknown requested key is an error. |
| `config effective [key] --json` | `view: effective_runtime_tunables`, `current`, `generation`, `engine_identity`, `written_at`, `values`. Each entry identifies its effective policy value, original configured value, source and any adjustment. Missing `value` means that this release has no runtime consumer. |
| `config schema --json` | The shared catalog of keys, types, defaults, numeric bounds, capability requirements, disable-only restrictions and application timing. This command emits an array of definitions. |
| `config status <UUID> --json` | The daemon's durable request receipt; a still-present inbox file without acknowledgement reports `pending`. An absent/expired outcome reports `unknown`. |

Coverage states are `unknown`, `disabled`, `unobserved`, `quiet`, and `matched`. A missing evaluation entry does not establish a dead producer. Telemetry becomes historical or unavailable when its timestamp exceeds 120 seconds, its engine identity differs from the current heartbeat, or its identity cannot be established. Disabled state can describe file configuration while the observation itself is historical; always read the document's freshness.

The effective view covers the 19-key runtime-tunable catalog, not every daemon option or secret. Poll values are base intervals; power policy can lengthen scheduling. ES switches are effective subscription policy, while native sensor availability and enabled-rule demand govern actual capture. `prompt_injection_confidence` has no runtime consumer in this release and is not settable. Numeric bounds apply during configuration loading and request processing; adjustments preserve the original configured value in the runtime report.

`config set <key> <value> --json` and `rules reload --json` return `state: pending` and `request_id`. A successful submission means that a request was written to the inbox. It does not establish daemon acceptance or runtime application. The response's `normalized_value` is the shared contract's prediction, not a daemon acknowledgement.

Receipts distinguish `accepted` (validated/persisted, application pending), `applied` (confirmed by runtime state/completion), `rejected`, and `superseded`. Restart-only settings remain accepted until a boot reports the accepted effective value. An interrupted reload reports that completion could not be confirmed. A failed reload may have updated some components; its reason says so. Applied generations are scoped to `engine_identity`, not comparable across process epochs.

Receipts persist in the engine's `request_status` directory for up to 30 days and the newest 4,096 requests. They contain request metadata and catalog values, not secrets or event bodies. An unknown/expired outcome must not be treated as rejection or success. Built-in rule settings, authored-rule changes and other legacy action types do not yet use this receipt protocol.

| Exit code | Meaning |
| --- | --- |
| `0` | The read/submission completed. Inspect liveness or receipt state for its meaning. |
| `1` | Invalid arguments, unknown key, unsupported mutation, or a read/write/decoding error. Diagnostics go to stderr. |
| `2` | Rule-update channel refusal or verification/fetch failure. The channel remains disabled in this release. |
| `4` | A requested receipt is unknown or expired; JSON status remains available on stdout. |

Human-formatted command text is for operators and is not a stable parsing interface.

Suppression removal preserves v2 entry metadata. `maccrabctl unsuppress RULE [PATH]` supports both legacy rule/path dictionaries and v2 rule scopes; read, match and persistence failures exit nonzero. `allow remove ID` also requires persisted removal before reporting success. These direct CLI writes may require administrator permissions, and an engine reload may still be pending. The dashboard uses an exact-ID removal request in the selected engine inbox and observes `suppressions_snapshot.json`, an admin-readable saved-state copy. The private authoritative `suppressions.json` retains mode 0600; the snapshot uses mode 0640 and the admin group on root installs. Suppression-removal receipts use the same durable request state vocabulary.

## Explicit storage diagnostic

`maccrabctl storage check --directory PATH [--timeout-seconds 1…300] --json`
returns schema 1 with `diagnostic: sqlite_quick_check`,
`writes_database: false`, `timeout_seconds_per_database`, and `results`.
Each result contains `database`, `status`, `elapsed_seconds`, optional
`sqlite_code`, and `issue_count`. The default budget is 30 seconds per store;
it bounds SQLite work but cannot interrupt a stuck filesystem syscall.
Statuses are `passed`, `failed`, `incomplete`, `unavailable`,
`unsupported_file`, or `invalid_budget`. Exit zero requires all five selected
stores to pass; missing optional stores remain unverified and produce exit one.
The command never creates, migrates, quarantines, checkpoints or repairs a store.
This checks SQLite structure, not journal authenticity, FTS content equivalence,
whole-file encrypted forensic cases, or protection readiness.

`repair --fix-storage` and `repair --force-fix-storage` are retired: their old
schema and partial-file replacement cannot safely repair v8 stores. `repair
--dry-run` diagnoses an install without requesting a reload. Preserve complete
database families before any supported recovery operation.
