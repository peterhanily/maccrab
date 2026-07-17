# Stability & Operating Policy

This document describes how MacCrab behaves under stress: what it does when a
collector dies, how much disk it is allowed to use, how it slows itself down
on battery, and what "stable" means for an alpha build. It describes
**mechanisms and policy**, not uptime guarantees — there are no SLA numbers
here, and none should be inferred.

> Source of truth for the facts below:
> `Sources/MacCrabAgentKit/DaemonState.swift` (collector supervision + relaunch),
> `Sources/MacCrabAgentKit/DaemonConfig.swift` (`StorageConfig` caps),
> `Sources/MacCrabCore/Utilities/PowerGate.swift` (battery/thermal gating),
> `Sources/MacCrabCore/Collectors/ESCollector.swift` (ES NOTIFY subscription),
> and the Storage Footprint section of [`README.md`](../README.md).

---

## 1. What "stable" means for an alpha

This is a pre-1.0 build (`1.21.4-rc.x`). "Stable" here does **not** mean
"proven at scale over long uptime." It means:

- The engine's **failure mode is degrade-or-halt, never silent blindness.**
  When a data source dies or the host is under pressure, MacCrab either
  recovers, keeps running with reduced coverage that is **visible in the
  heartbeat**, or exits for a clean relaunch — it does not sit at zero events
  while reporting healthy.
- Data-handling paths are **fail-closed**: a bad rule manifest, a malformed
  revocation list, or a failed atomic swap leaves the previous good state in
  place rather than corrupting or half-applying (see
  [`RULE_CHANNEL.md`](RULE_CHANNEL.md), [`SUPPLY_CHAIN_SECURITY.md`](SUPPLY_CHAIN_SECURITY.md)).
- Resource use is **bounded by configured caps**, not by load.

What it does **not** promise: no crash-free guarantee, no throughput number,
no "N nines." Some recovery paths (notably ES-client relaunch) are marked
`NEEDS ON-DEVICE VERIFICATION` in the source and depend on the OS relaunching
a supervised System Extension.

---

## 2. Restart / relaunch policy

Each event source runs in a **restart loop**. If the underlying `AsyncStream`
ends, the source re-attaches after a short back-off (≈2s) so a transient
failure recovers without a full daemon restart.

If a source stays down across repeated re-attaches, MacCrab escalates rather
than sitting silently at 0 ev/s:

- A source confirmed **DOWN** logs a `fault` and is surfaced as **host
  detection degraded on that source** — the degradation is reflected in the
  heartbeat, not hidden.
- For the Endpoint Security client specifically, the daemon can **exit for a
  clean relaunch** (exit code 75) so `sysextd` starts a fresh process that
  re-establishes `es_new_client`. This is gated by three guards:
  - **Supervised-only** — relaunch happens only for a supervised,
    non-interactive process. In an interactive session (no supervisor) it
    logs the fault and **stays degraded** rather than exiting from under you.
  - **Startup guard window** — a source that goes down very soon after start
    does not trigger a relaunch (avoids boot-time thrash).
  - **Cross-restart rate limit** — a marker file records recent relaunches;
    if MacCrab has already relaunched **≥3 times in the last 10 minutes**, it
    **gives up auto-recovery and stays degraded** (the CRITICAL fault is
    already logged) rather than entering a restart loop. Recovery then
    requires a manual restart.

The policy is deliberately biased so the worst outcome is "degraded and
loud," never "thrashing" or "silently blind."

---

## 3. Resource ceilings

MacCrab stores everything locally in SQLite. Every store has a configured cap;
all caps are tunable under the `storage` block in `daemon_config.json` (see
[`daemon_config.example.json`](daemon_config.example.json)). Defaults:

| Store | Default cap | Notes |
|-------|------------:|-------|
| `events.db` | ~350 MB (`events_max_size_mb`) | Whole-**file** cap. The event working set is bounded by `events_hot_tier_minutes` (default 30), but the file also carries `alert_evidence` (its own ~100 MB `evidence_max_size_mb` sub-cap) and the FTS5 search index (~60 MB on a busy host), so the file floor is ~300–350 MB regardless. |
| `alerts.db` | 100 MB (`alerts_max_size_mb`) | Retained `alerts_retention_days` (default 365). |
| `campaigns.db` | 50 MB (`campaigns_max_size_mb`) | Retained `campaigns_retention_days` (default 365). |
| `tracegraph.db` | 250 MB (`tracegraph_max_size_mb`) | Causal-graph entity/edge substrate; retained `tracegraph_retention_days` (default 90). Over cap, oldest graph is evicted; an orphan sweep also runs. |
| traces | 100 MB (`traces_max_size_mb`) | Retained `traces_retention_days` (default 90). |
| `event_aggregates` | — | Daily rollups kept `aggregate_days` (default 90); tiny. |

On an actively-used machine this is roughly **~750 MB of disk allocation**
(much smaller on a lightly-used one). This is **disk, not RAM** — resident
memory is far smaller.

Enforcement is a periodic size-cap sweep (`events_size_cap_interval_minutes`,
default 60): over-cap stores are trimmed oldest-first. Retention days and size
caps are independent ceilings — whichever binds first wins.

> Before v1.18, `tracegraph.db` had no retention sweep and was field-observed
> at 17 GB. v1.18 added retention + a size cap + an orphan sweep; v1.19 made
> the caps configurable. A pre-v1.18 install reclaims the space on first
> launch.

---

## 4. Battery & thermal gating (PowerGate)

Poll-based collectors do **not** run at a fixed rate. `PowerGate` scales each
collector's base poll interval by the current power/thermal state, with zero
user configuration, so MacCrab slows itself down instead of draining the
battery or fighting the OS thermal governor:

- **Low Power Mode enabled** → 3.0× slower (the user explicitly asked to save
  battery).
- **Thermal state critical/serious** → 2.5× (throttle before the OS throttles
  us).
- **Thermal state fair** → 1.5× (light touch, still responsive).
- **Nominal / on AC** → 1.0× (no change; round-trip exact).

Truly optional collectors (Clipboard, USB) carry a higher aggressiveness knob
so they back off harder on battery; the multiplier is clamped to ≥1.0 so a
collector can never be sped up past what it asked for. Real-time sources
(Endpoint Security, DNS BPF) are event-driven and are not poll-gated.

---

## 5. Degrade-not-break stance

MacCrab is built to lose capability gracefully rather than fail hard:

- **ES is NOTIFY-only.** The System Extension subscribes to Endpoint Security
  **NOTIFY** events (`ES_EVENT_TYPE_NOTIFY_*`) — it observes and records, it
  does **not** sit in the AUTH path gating kernel operations. A slow or wedged
  MacCrab therefore cannot block or delay process exec, file opens, or signals
  on the host. Detection can lag or degrade; the system keeps running.
- **Fallback collectors.** Without the ES entitlement (or on the dev
  standalone daemon), detection collapses to fallback sources — Unified Log,
  FSEvents, the network tap, BPF DNS — rather than going dark. This is a
  reduced-coverage mode, surfaced as degraded, not a failure. (See
  [`TRUST.md`](TRUST.md) for the entitlement's role.)
- **Drop-oldest under storm, and counted.** The merged event stream has a
  bounded cap (`mergedStreamCap`). Under an event storm the stream drops
  oldest rather than growing memory unbounded — and every drop is **counted**
  (`events_dropped` / `events_dropped_total`) and exposed in the heartbeat, so
  a detection gap under load is **visible**, not silent. The insert path
  likewise records a dropped/passed counter surfaced to the dashboard.
- **Fail-closed data channels.** The signed rule-update channel and the
  plugin catalog both leave the prior good state untouched on any verification
  or write failure (anti-rollback serial, per-item validation, atomic swap).
  The worst case is "no update / stale update," never a corrupt or partial
  corpus.

---

## Related docs

- [`RULE_CHANNEL.md`](RULE_CHANNEL.md) — fail-closed signed rule updates.
- [`SUPPLY_CHAIN_SECURITY.md`](SUPPLY_CHAIN_SECURITY.md) — release/update supply chain and incident playbook.
- [`ROLLBACK_RUNBOOK.md`](ROLLBACK_RUNBOOK.md) — pulling a bad app release.
- [`INCIDENT_RESPONSE.md`](INCIDENT_RESPONSE.md) — operator triage and response.
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — what MacCrab does and doesn't defend against.
