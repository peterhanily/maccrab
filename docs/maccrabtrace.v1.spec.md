# `.maccrabtrace` Bundle Format — v1

**Status:** v1.10.0 (2026-05-07)
**Format identifier:** `maccrab.tracebundle.v1`
**Reference implementation:** [MacCrab](https://maccrab.com) `BundleFormat.swift` + `BundleValidator.swift`

A `.maccrabtrace` bundle is a portable, replayable, tamper-evident
record of one macOS security trace. It is designed to be readable,
diffable, and verifiable by third-party tools without depending on
the MacCrab daemon.

This document is the canonical specification for v1 bundles.
Companion implementation lives in
`Sources/MacCrabCore/TraceBundle/`. JSON Schemas are forthcoming;
in the interim the Swift types in `BundleFormat.swift` define the
authoritative shape.

---

## 1. Packaging

A bundle is a directory tree, typically packaged as `tar.gz`. Internal
artifacts are ordinary JSON, JSONL, Markdown, and HTML files so they
can be inspected with `jq`, `grep`, and a browser after extraction.

The outer archive layer (tar.gz, zip, etc.) is **not** part of the
signed integrity chain — see §6. Recompressing a bundle does not
invalidate it as long as the canonical artifact contents and paths
are unchanged.

---

## 2. Directory layout

```
trace_001.maccrabtrace/
  manifest.json                          (required)
  graph.json                             (required)
  events.jsonl                           (required)
  attribution/
    machine_attribution.json             (recommended)
    human_overrides.json                 (when overrides exist)
  rules/
    matched_rules.json
    rule_versions.json
  evidence/
    files.json
    processes.json
    network.json
    persistence.json
    code_signing.json
    agents.json
  baseline/
    baseline_snapshot.json
    baseline_mode.txt
  replay/
    replay_manifest.json                 (required)
  llm/
    summary.md                           (when generated)
    summary_metadata.json                (when generated)
  prov/
    prov.jsonld                          (required when prov_compliant=true)
  otel/
    spans.json                           (required when otel_aligned=true)
  integrity/
    hash_chain.json                      (required)
    chain_head_signature.json            (required)
    bundle_sha256.txt                    (informational only)
  schema/
    manifest.schema.json                 (forthcoming)
    graph.schema.json
    replay.schema.json
    evidence.schema.json
  report/
    timeline.html
    summary.md
```

Required artifacts must be present for the bundle to validate. Optional
artifacts may be omitted when no corresponding data exists.

---

## 3. `manifest.json`

```json
{
  "format": "maccrab.tracebundle.v1",
  "maccrab_version": "1.10.0",
  "ruleset_version": "1.10.0",
  "normalization_version": "1",
  "created_at": "2026-05-07T22:00:00Z",
  "host_redacted": true,
  "trace_id": "trace_001",
  "title": "AI-assisted credential access and persistence chain",
  "severity": "high",
  "confidence": 0.92,
  "prov_compliant": true,
  "otel_aligned": true,
  "otel_convention_version": "gen_ai_mcp_current_at_build",
  "process_identity_version": "maccrab.process_identity.v1",
  "trace_signing_key_mode": "secure_enclave",
  "replay_scope": "declared_deterministic_subset",
  "attribution_override_policy": "include_as_human_annotation_do_not_apply_by_default"
}
```

### 3.1 Field reference

| Field | Type | Notes |
| --- | --- | --- |
| `format` | string | Always `maccrab.tracebundle.v1` for v1 bundles. Major-version bumps require readers to refuse with exit 5. |
| `maccrab_version` | string | Semver of the daemon that produced the bundle. |
| `ruleset_version` | string | Semver of the rules at materialization time. |
| `normalization_version` | string | Event-normalization schema version. Replay refuses incompatible versions (exit 6). |
| `created_at` | ISO 8601 datetime | Bundle creation time. |
| `host_redacted` | bool | When true, `/Users/<name>/` paths must be redacted. Validator enforces (exit 7). |
| `trace_id` | string | Must equal `graph.json.trace.id`. |
| `title` | string | Investigator-facing summary. |
| `severity` | string | `"informational" | "low" | "medium" | "high" | "critical"`. |
| `confidence` | number | 0.0–1.0. |
| `prov_compliant` | bool | When true, validator runs PROV-O claim check (exit 10). |
| `otel_aligned` | bool | When true, validator runs OTel claim check (exit 10). |
| `otel_convention_version` | string | OTel semantic conventions version this bundle was emitted against. |
| `process_identity_version` | string | Schema version of the process-identity computation. v1.10 = `maccrab.process_identity.v1`. |
| `trace_signing_key_mode` | string | `"secure_enclave"` or `"filesystem_degraded"`. Must match `chain_head_signature.json.signing_key_mode`. |
| `replay_scope` | string | `"declared_deterministic_subset"` or `"include_bundled_state"`. |
| `attribution_override_policy` | string | `"include_as_human_annotation_do_not_apply_by_default"` or `"include_and_apply_on_replay_when_flagged"`. |

---

## 4. `graph.json`

The trace's entity + edge graph plus a copy of the trace header. Cross-checked against `manifest.trace_id`.

The Swift representation is `GraphArtifact` in `BundleFormat.swift`. JSON shape is:

```json
{
  "trace": { /* full Trace row including policy snapshot */ },
  "entities": [ /* TraceEntity[] */ ],
  "edges": [ /* TraceEdge[] */ ],
  "memberships": [ /* TraceMembership[] */ ],
  "root_cause_entity_id": "process:abc",
  "anchor_entity_id": "process:xyz"
}
```

Validator invariants:

- `trace.id == manifest.trace_id`
- `anchor_entity_id` appears in `entities[]`
- every edge's `source_entity_id` and `target_entity_id` appear in `entities[]`

---

## 5. `events.jsonl`

Line-delimited JSON. One event per line. Each line must be a valid JSON
object; the validator parses each line independently.

The exact event shape is the daemon's normalized `Event`. Replay
enforces deterministic ordering by `(timestamp_ns, event_id)` per
§17.1.3 of the v1.10.0 spec.

---

## 6. Integrity (`integrity/`)

### 6.1 `hash_chain.json`

Canonical artifact list with per-artifact SHA-256 in sorted-path order
plus the Merkle root computed over those hashes.

```json
{
  "bundle_format_version": "maccrab.tracebundle.v1",
  "artifacts": [
    { "path": "manifest.json", "sha256": "..." },
    { "path": "graph.json",    "sha256": "..." }
  ],
  "merkle_root": "..."
}
```

### 6.2 `chain_head_signature.json`

The daemon's signature over the Merkle root.

```json
{
  "merkle_root": "...",
  "signature_base64": "...",
  "signing_key_mode": "secure_enclave",
  "signing_key_fingerprint": "...",
  "signed_at": "2026-05-07T22:00:00Z"
}
```

Verifiers must:

1. Recompute the Merkle root from the on-disk artifacts.
2. Confirm `chain_head_signature.merkle_root == hash_chain.merkle_root`.
3. Confirm `chain_head_signature.signing_key_mode == manifest.trace_signing_key_mode`.
4. Verify `signature_base64` against the public key at
   `/Library/Application Support/MacCrab/keys/trace-signing.pub`.

The verifier (`BundleVerifier`) is **out of
scope for the v1.10.0 validator** — `validate` covers structure and
manifest-claim checks; `verify` covers tamper-evidence.

### 6.3 `bundle_sha256.txt`

Plain hex of the outer `.tar.gz` SHA-256, included for convenience
only. **Not** part of the signed Merkle root. Recompressing the bundle
changes this value but does not invalidate the signature.

### 6.4 Tamper-evidence: what is guaranteed (and what is not)

A `.maccrabtrace` bundle is **tamper-EVIDENT, not tamper-PROOF.** Two
independent integrity layers back it, and one on-device witness:

1. **Per-export signature (bundle).** `§6.1` + `§6.2` above: a canonical
   Merkle root over the bundle's artifacts, signed by the daemon's key.
   A verifier that holds the trusted public key **out of band** — an
   operator `--expect-key` fingerprint, a fleet/install pin, or the
   trust-on-first-use `TraceKeyPinStore` — can confirm the bundle was
   signed by that key and that no artifact changed since signing. Without
   an out-of-band key it is self-contained/TOFU only (an attacker who
   rewrites the artifacts can re-sign with their own key; the pin closes
   this).

2. **On-DB continuity chain (`tracegraph.db`).** Each materialized trace
   appends one linked entry to an append-only ledger (`trace_hash_chain`)
   whose `previous_hash` chains to the prior head. `verifyHashChain()`
   walks the ledger and flags an in-place field mutation, a reorder
   (both caught by recomputing each row's digest), and an interior
   deletion or insertion (caught by the `previous_hash` linkage).
   Retention prunes the **oldest** entries (a prefix); verify tolerates
   that shifted start and does not treat it as tampering. `trace export`
   runs this check before writing a bundle and warns on a break.

3. **Unified-log external witness.** On export the daemon emits the
   signed chain head to the `com.maccrab.tracegraph.chain` subsystem of
   the macOS unified log — an OS-managed, append-oriented record that
   raises the cost of silent retroactive tampering. `verify
   --check-unified-log` reads it back (`OSLogStore`), degrading to a
   §-`10`/`19.4` warning (never a hard failure) where log access is
   entitlement-restricted.

**Guarantee scope (honest):**

- **Forgery-resistant against a NON-root attacker.** A process that edits
  `tracegraph.db` or a bundle without the daemon's signing key breaks the
  hash chain or fails the signature; a party holding the out-of-band key
  detects it.
- **Local ROOT is out of scope.** Root can rewrite the whole ledger and
  re-sign, so the on-DB chain cannot bind root. See
  [`docs/THREAT_MODEL.md`](THREAT_MODEL.md) — local root is out of scope
  for tamper protection by design. The bundle signature still constrains
  root to a key an out-of-band verifier trusts.
- **Tail-truncation** (deleting the newest ledger entries) leaves the
  retained prefix internally consistent and is *not* caught by the on-DB
  chain alone; the unified-log witness bounds it.
- **Read-back caveat.** The cross-process / cross-run unified-log
  read-back (root sysext emits, uid-501 verifier reads on a later run) is
  wired but **pending on-device verification** — treat the log witness as
  a hardening layer, not a proven control, until validated on a real host.

---

## 7. Standards-aligned artifacts

### 7.1 `prov/prov.jsonld`

PROV-O JSON-LD per §22.1 of the v1.10.0 spec. Required when
`manifest.prov_compliant == true`.

The validator's claim check (exit 10) ensures:

- File is valid JSON.
- Root is a JSON object.
- Either `@context` references a `prov` namespace, or the graph
  contains entries with `@type` matching `prov:` / `Activity` /
  `Entity` / `Agent`.

Full PROV-O conformance against an external validator is a future
extension.

### 7.2 `otel/spans.json`

OTLP/JSON-shaped span artifact per §22.2. Required when
`manifest.otel_aligned == true`.

The validator's claim check (exit 10) ensures:

- File is valid JSON.
- Root is a JSON object with non-empty `resourceSpans[]`.
- Some resource carries an `otel.semconv.version` attribute.

The OTel GenAI / MCP convention surface is young (experimental at
v1.10.0 ship time). The `otel_convention_version` manifest field
records which convention version this bundle expects.

---

## 8. Attribution (`attribution/`)

`machine_attribution.json` is the daemon's machine-observed attribution
state for events in this bundle. `human_overrides.json` contains
analyst verdicts (`confirmed`, `wrong_tool`, `no_agent`, `unknown`) per
§18.5.

Default semantics:

- Both are part of the signed Merkle root.
- Replay re-runs the machine logic; overrides are not applied unless
  `--honor-attribution-overrides` is passed.
- The deterministic explainer does **not** blend overrides into prose.
- The dashboard may surface overrides as analyst annotations.

---

## 9. Replay (`replay/replay_manifest.json`)

Captures the inputs the ReplayEngine needs to reproduce the trace
deterministically.

```json
{
  "daemon_version": "1.10.0",
  "ruleset_version": "1.10.0",
  "normalization_version": "1",
  "replay_scope": "declared_deterministic_subset",
  "unsupported_engines": [],
  "unsupported_rule_ids": [],
  "canonical_event_ordering": "(timestamp_ns, event_id)",
  "baseline_mode": "reset",
  "policy_snapshot_json": "{...}"
}
```

Replay of bundles whose matched rules require engines outside the
declared deterministic subset (`BehaviorScoring`, `BaselineEngine`,
etc.) returns `unsupported_stateful_replay` with exit code 11.

---

## 10. Validator exit codes

Stable API per §18.9.

| Exit | Meaning |
| --: | --- |
| 0  | Valid / verified successfully. |
| 1  | Schema invalid. |
| 2  | Hash-chain invalid (verifier). |
| 3  | Signature invalid (verifier). |
| 4  | Unified-log anchor mismatch or missing when explicitly required (verifier). |
| 5  | Incompatible bundle major version. |
| 6  | Replay or normalization version incompatible. |
| 7  | Redaction policy violation. |
| 8  | Bundle archive malformed or unreadable. |
| 9  | Internal validation error. |
| 10 | Manifest claim does not match artifact content (e.g., `prov_compliant: true` but `prov/prov.jsonld` fails PROV-O validation). |
| 11 | Replay scope exceeded (replay engine). |

Codes 1, 5, 7, 9, 10 are produced by `BundleValidator`. The
remaining codes belong to `BundleVerifier` and `ReplayEngine`.

`validate` and `verify` are different contracts:

- `validate` checks **structural conformance** to the published bundle
  schemas. Does not require the daemon's signing key.
- `verify` checks **tamper evidence**: hash chain, daemon signature,
  and (when requested) unified-log anchor. Requires the public key
  bundled at install.

---

## 11. Versioning

- `maccrabtrace.v1` is the published surface.
- Backwards-compatible additions land as minor versions (`v1.1`, `v1.2`).
- Breaking changes require `v2`. Readers must refuse unknown major
  versions with exit code 5.

---

## 12. Privacy defaults (positive list)

Always **redacted** by default:

- username, hostname, full home paths (replaced with `~/...`)
- local IPs where appropriate
- command-line arguments matching secret patterns (delegates to
  `CommandSanitizer`)
- environment variables
- prompt content
- token-like and high-entropy key-shaped strings

Always **included** by default:

- system-path executable paths
- user paths in redacted form
- code-signing metadata (team ID, signing identifier, notarization status)
- process exec timestamps
- file kinds
- SHA-256 hashes where available
- network destination ports and protocol (host redacted per policy)
- ATT&CK mapping
- rule IDs and rule versions
- edge relations + confidence tiers
- agent name when known with direct or strong-inferred confidence

This explicit positive list lets investigators know what they're
getting before opening a bundle.

---

## 13. Companion documents

- `tracegraph-replay-determinism.md` — replay invariants (forthcoming)
- `tracegraph-redaction-policy.md` — full redaction rules (forthcoming)
- `tracegraph-policy.md` — TracePolicy loading + signing (forthcoming)
- `tracegraph-trust-substrate.md` — `TrustSubstrate` design (forthcoming)
- `prov-dm-mapping.md` — PROV-O/PROV-DM mapping table (forthcoming)
- `otel-semantic-conventions-mapping.md` — OTel mapping (forthcoming)
- [`tracegraph-rule-schema.md`](tracegraph-rule-schema.md) — graph rule schema
