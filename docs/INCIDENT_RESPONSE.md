# Incident Response (Operator Guide)

How to triage what MacCrab surfaces, read a degraded state, deal with a
revoked plugin, pull evidence, and roll back a bad rule or release. This is
operator-facing and command-first. Everything here is **local** — MacCrab has
no managed response and no cloud console.

> Two interfaces do the same reads: the `maccrabctl` CLI and the `maccrab-mcp`
> MCP server (for an AI agent). Both are **read-first**; the few state-changing
> verbs (suppress, allow, revoke, response-action config) are called out where
> they appear. MCP mutation tools are gated behind an operator-enabled
> capability tier — see [`AUTHORIZATION_MODEL.md`](AUTHORIZATION_MODEL.md).

---

## 1. Triage a campaign or alert

### From the CLI

```bash
maccrabctl security                       # posture score (0–100) with factors
maccrabctl campaigns [N]                  # recent detected campaigns
maccrabctl campaigns watch                # live campaign feed
maccrabctl alerts [N] [--hours H] [--severity critical|high|medium|low]
maccrabctl why <alert-id>                 # why this alert fired (rule + evidence)
maccrabctl hunt "unsigned process with a network connection"
maccrabctl events tail [N] [--category process|file|network|tcc|...]
maccrabctl events search "<substring>"
maccrabctl trace ...                      # causal traces (TraceGraph)
```

Start wide (`security`, `campaigns`), then drill into a specific finding with
`why` / `events search` / `trace`. A campaign bundles the contributing alerts,
so triage the campaign first and let it point you at the underlying alerts.

### From MCP (agent)

| Tool | Use |
|---|---|
| `get_security_score` | Posture 0–100 with contributing factors. |
| `get_campaigns` | List detected attack campaigns. |
| `get_alerts` | Query alerts with severity/time/suppression filters. |
| `get_alert_detail` | Full alert: description, LLM investigation, MITRE D3FEND mitigations, parent ancestry, remediation hints. |
| `cluster_alerts` | Group recent alerts by rule + process fingerprint (collapses a storm into a few clusters). |
| `hunt` | Full-text threat hunting across events. |
| `get_events` | Query events by category/search/time. |
| `get_traces` / `get_trace_detail` / `trace_from_event` | Causal traces and pivots. |
| `get_ai_alerts` | AI Guard alerts (credential / boundary / injection / MCP). |

Typical loop: `get_campaigns` → `get_alerts` → `get_alert_detail` on the ones
that matter → `cluster_alerts` if it's noisy → `hunt` / `get_traces` to
confirm scope.

### Dispositioning a finding

When a finding is a confirmed false positive (not a real threat):

```bash
# v2 store — TTL + audit-logged (preferred):
maccrabctl allow <rule-id> <process-path>    # see: maccrabctl allow --help
maccrabctl allow list
```

MCP equivalents: `suppress_alert` (single alert) and `suppress_campaign`
(campaign + its contributing alerts). Both are **audit-logged** — read the
trail with `get_audit_log`. Suppress only what you've actually cleared;
suppression is how a real detection gets silenced, so treat it as a decision,
not a mute button.

---

## 2. Read a degraded state

MacCrab's design is degrade-loud, not fail-silent (see
[`STABILITY.md`](STABILITY.md)). Two kinds of "degraded" matter operationally.

**Detection-degraded** (a data source is down, or ES is unavailable and
detection fell back to Unified Log / FSEvents / network tap / BPF DNS):

```bash
maccrabctl status                # daemon status, rule count, DB size, ev/s
```

MCP: `get_status`. A source stuck at 0 ev/s, or a status that reports fallback
mode, means reduced coverage — the daemon surfaces this in its heartbeat
rather than hiding it. If ES itself is down, MacCrab may relaunch to
re-establish the client (rate-limited to ≥3 relaunches / 10 min before it
stays degraded and waits for a manual restart — see `STABILITY.md §2`).

**Trust-degraded** (an installed plugin no longer verifies against the current
trust + revocation lists):

```bash
maccrabctl plugin status         # trusted/revoked counts, verified/failed buckets
maccrabctl plugin verify         # re-verify all installed against trust + revocation
maccrabctl plugin trust-list     # trusted + revoked publisher keys
```

MCP: `forensics_verify_installed_plugins`, `forensics_list_installed_plugins`.
A non-zero `failed` / `revoked` bucket is the signal to act on — see §3.

---

## 3. Escalate a revoked or untrusted plugin

If a plugin's publisher key is revoked (by the signed catalog revocation list
or by you), or a plugin fails verification:

1. **Confirm** the state:
   ```bash
   maccrabctl plugin verify <plugin-id>
   maccrabctl plugin trust-list
   ```
2. **Refresh the signed revocation list and reconcile quarantine.** Re-running
   an install against the catalog fetches the current (Ed25519-verified,
   anti-rollback) revocation list and reconciles it against everything already
   installed — a now-revoked on-disk plugin is **quarantined**, not left
   loading:
   ```bash
   maccrabctl plugin install <plugin-id>   # doubles as a revocation sync
   ```
   A bad signature, malformed list, or older serial fails closed and aborts —
   the prior revocation state is kept.
3. **Revoke locally** if you don't trust a publisher key regardless of the
   catalog (revocation preempts trust and is never blocked by a pin):
   ```bash
   maccrabctl plugin revoke <key-hex>
   ```
4. **Remove** the plugin outright:
   ```bash
   maccrabctl plugin uninstall <plugin-id>
   ```

Trust and revocation gate **whether a plugin runs**; the sandbox + fd-broker
gate **what it can reach** (deny-default, declared reads only). See
[`SUPPLY_CHAIN_SECURITY.md`](SUPPLY_CHAIN_SECURITY.md) and
[`PLUGIN_AUTHORING.md`](PLUGIN_AUTHORING.md).

---

## 4. Pull evidence

To hand a scan's artifacts to another analyst or preserve them, export a signed
`.maccrabevidence` bundle:

```bash
maccrabctl scan list                                   # find the scan id
maccrabctl evidence list --scan <scan-id>              # what's in it
maccrabctl evidence export --scan <scan-id> \
    --output ~/case-<scan-id>.maccrabevidence
# (equivalently: maccrabctl scan export <scan-id> [--output <path>.maccrabevidence])
```

The bundle is written by `EvidenceBundleExporter` over every artifact in the
case. For agent-session evidence, `export_session_bundle` (MCP) writes a
Merkle-rooted, daemon-signed `.maccrabsession` bundle, verifiable with
`verify_session_bundle`. Causal-trace bundles verify with `verify_bundle`.
Forensic scan collectors/analyzers are also driveable over MCP
(`forensics_run_collector` / `forensics_run_analyzer` / `forensics_run_all` /
`forensics_search_artifacts` / `forensics_timeline` / `forensics_explain_case`).

---

## 5. Roll back a bad rule or release

Two independent channels; roll back the right one:

- **Bad detection rule (pushed via the signed rule channel).** Rules are
  detection-only and additive, so a bad pushed rule can add noise but can't
  disable a built-in or arm a response. Drop the pushed corpus and reload, or
  publish a corrected manifest with a higher serial. Full procedure:
  [`RULE_CHANNEL.md`](RULE_CHANNEL.md) → "Rolling back".

  ```bash
  # Quick local drop of ALL pushed rules (release build; sysext-owned dir):
  sudo rm -rf "/Library/Application Support/MacCrab/compiled_rules/pushed"
  sudo pkill -HUP com.maccrab.agent        # dev daemon: pkill -HUP maccrabd
  maccrabctl rules status                  # confirm accepted serial + pushed count
  ```

  A user-authored rule that's misfiring can instead be disabled without
  deleting it: `maccrabctl rule disable <id>` (survives reload/restart).

- **Bad app release (a whole build).** Sparkle cannot auto-downgrade an
  already-installed client — rollback is "stop the bleeding" (halt
  distribution across the three surfaces) plus "forward-fix" (ship the next
  version). Full procedure: [`ROLLBACK_RUNBOOK.md`](ROLLBACK_RUNBOOK.md).

- **Supply-chain compromise** (signing key / appcast token leaked): follow the
  incident playbook in [`SUPPLY_CHAIN_SECURITY.md`](SUPPLY_CHAIN_SECURITY.md)
  §4, not this doc.

---

## Related docs

- [`STABILITY.md`](STABILITY.md) — degrade-not-break mechanisms and resource ceilings.
- [`RULE_CHANNEL.md`](RULE_CHANNEL.md) — signed rule updates and rollback.
- [`ROLLBACK_RUNBOOK.md`](ROLLBACK_RUNBOOK.md) — pulling a bad app release.
- [`SUPPLY_CHAIN_SECURITY.md`](SUPPLY_CHAIN_SECURITY.md) — supply-chain incident playbook.
- [`AUTHORIZATION_MODEL.md`](AUTHORIZATION_MODEL.md) — what the agent/MCP tier can and can't do.
- [`RESPONSE_SAFETY.md`](RESPONSE_SAFETY.md) — which response actions are gated by which validators.
