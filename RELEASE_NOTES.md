# MacCrab 1.2.0 — Ship Notes

**Local-first macOS threat detection engine, now with OCSF-native
exports, agentic LLM triage, deception tier, and UEBA.**

1.1.x users: this is a drop-in upgrade. Schema migrates automatically;
existing config keeps working; every new capability is opt-in.

## Highlights

**OCSF 1.3 on the wire.** Every alert can now ship as a vendor-neutral
OCSF Security Finding to any SIEM that speaks OCSF — Amazon Security
Lake, Splunk, Elastic, Wazuh, SentinelOne, Datadog. Five new sinks
(file NDJSON, Splunk HEC, Elastic Bulk API, Datadog Logs, Wazuh
Manager API, Amazon S3, SFTP) behind a shared `Output` protocol.

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
of attacks that are malware-free / credential abuse. Profiles persist
across daemon restarts.

**Integration bundles** in `integrations/`: Wazuh decoder + rules XML,
Elastic index template + Kibana saved-objects, osquery pack with 12
macOS posture queries.

**AWS S3 + SFTP exports.** Hand-rolled SigV4 signer (no AWS SDK
dependency) pushes batched NDJSON to date-partitioned S3 keys,
Athena/Security-Lake query-friendly. SFTP output shells out to the
system `sftp` binary with StrictHostKeyChecking for data-diode
deployments.

## Stats

- 535 tests (up from 326 at 1.1.1) — zero regressions across the
  1.2.0 development cycle.
- 379 Sigma-compatible YAML rules, each with positive + negative test
  fixtures for the hash-aware additions.
- 10 D3FEND-annotated prevention modules.

## Upgrade

```sh
brew upgrade maccrab    # when the Homebrew formula is updated
```

Schema migrates automatically on first 1.2.0 daemon start.
`daemon_config.json` keys are additive — existing files keep working.

## What's next (1.3.0)

- Executing confirmed investigation suggested-actions (daemon ↔
  dashboard IPC — currently UI-only).
- Osquery **producer** extension so analysts can JOIN MacCrab's
  `maccrab_alerts` / `maccrab_events` / `maccrab_campaigns` tables
  inside `osqueryi`.
- Native macOS 15.4+ `ES_EVENT_TYPE_NOTIFY_TCC_MODIFY` for the TCC
  monitor (pending an ES-entitlement-signed provisioning profile).

## Credits

All releases so far shipped by @peterhanily with Claude (Opus 4.6,
1M context) as co-author across the 1.2.0 development cycle.

---

*Made with love and tokens in Ireland.*
