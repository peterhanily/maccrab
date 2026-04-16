# MacCrab v2.0.0 — Ship Notes

**Local-first macOS threat detection engine, now with OCSF-native
exports, agentic LLM triage, deception tier, and UEBA.**

v1 users: this is a drop-in upgrade. Schema migrates automatically;
existing config keeps working; every new capability is opt-in.

## Highlights

**OCSF 1.3 on the wire.** Every alert can now ship as a vendor-neutral
OCSF Security Finding to any SIEM that speaks OCSF — Amazon Security
Lake, Splunk, Elastic, Wazuh, SentinelOne, Datadog. Three new sinks
(file NDJSON, Splunk HEC, Elastic Bulk API, Datadog Logs) behind a
shared `Output` protocol.

**Agentic LLM triage.** Every HIGH/CRITICAL alert auto-invokes the
configured LLM backend, which produces a structured investigation —
verdict, confidence, evidence chain, MITRE reasoning, and suggested
actions with D3FEND references + blast-radius badges. The dashboard
shows the investigation inside the alert detail, with **Preview /
Confirm / Dismiss** controls on every action. Nothing auto-executes.

**Deception tier.** `maccrabctl deception deploy` plants 8 canary
files at standard credential paths (AWS, SSH, kube, netrc, docker,
gcp, browser passwords, keychain backup). Any read by a non-MacCrab
process fires a CRITICAL alert via the standard rule pipeline. Maps
to MITRE D3FEND D3-DF.

**Allowlist v2.** Suppressions now carry TTL, scope (rule+path,
rule+hash, rule-only, path-only, host), source, and a required reason.
An append-only audit log preserves every add/remove/expire. CLI:
`maccrabctl allow add --rule ... --path ... --ttl 7d --reason "..."`.

**UI complexity modes.** Home users can switch the dashboard to
**Basic** (5 views) or **Standard** (10 views) instead of the full
Advanced surface (15 views). Settings > Appearance.

**UEBA.** Per-user baseline (login hours, SSH source IPs, tool usage)
with anomaly detection after a cold-start window. Addresses the 80%
of attacks that are malware-free / credential abuse.

**Integration bundles** in `integrations/`: Wazuh decoder + rules XML,
Elastic index template + Kibana saved-objects, osquery pack with 12
macOS posture queries.

## Stats

- 524 tests (up from 326 at v1.0) — zero regressions across the v2
  development cycle.
- 379 Sigma-compatible YAML rules, each with positive + negative test
  fixtures for the hash-aware additions.
- 10 D3FEND-annotated prevention modules.

## Upgrade

```sh
brew upgrade maccrab    # when the Homebrew formula is updated
```

Schema migrates automatically on first v2 daemon start.
`daemon_config.json` keys are additive — existing files keep working.

## What's next (v2.1)

- `S3Output` / `SFTPOutput` sinks.
- Actually executing confirmed investigation suggested-actions.
- LLM eval harness with 50 labeled scenarios per backend.
- UEBA baseline persistence across daemon restarts.
- Native macOS 15.4+ TCC ESF event (pending ES entitlement).

## Credits

All releases so far shipped by @peterhanily with Claude (Opus 4.6,
1M context) as co-author across the v2 development cycle.

---

*Made with love and tokens in Ireland.*
