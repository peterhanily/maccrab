# Module Status

MacCrab's feature surface is large for an alpha tool. This page makes
the maturity of each subsystem explicit. The catalog below is generated
from `Sources/MacCrabCore/ModuleStatus.swift` — when you change a
subsystem's maturity in code, update this doc with `make modules-doc`
(or hand-sync — there are only a few dozen entries).

Three classifications:

- **Stable** — production-ready by current alpha standards. Stable APIs,
  substantial test coverage, in active use, no known correctness issues.
- **Experimental** — functional but iterating. May produce false
  positives, have rough UX, or change shape between releases. Output is
  advisory.
- **Opt-in** — built-in but disabled by default. Requires explicit
  opt-in (config flag or env var). Documented edges, not for casual use.

If you're integrating MacCrab into a serious workflow, treat
**experimental** subsystems as suggestion-only and lean on the **stable**
core for load-bearing decisions.

## Detection core

| Module | Status | Summary |
|---|---|---|
| Rule engine | **stable** | Sigma-compatible YAML → JSON predicates. 380+ rules indexed by category. |
| Endpoint Security collector | **stable** | Native ES client for exec/fork/exit/file/network/signal events. |
| Alert + campaign storage | **stable** | Per-tier SQLite stores with retention + size-cap discipline. |
| Alert deduplicator | **stable** | Single-sink chokepoint for alert insertion. Per-rule dismissal feedback. |
| Sequence engine | experimental | 38 multi-step sequence rules with bounded windows. |
| Campaign detector | experimental | Kill chain, alert storm, AI compromise, lateral movement clustering. |
| Behavioral scoring | experimental | 70+ weighted indicators with feedback-adjusted weights. |
| Baseline anomaly | experimental | Welford z-score + 2nd-order Markov process tree anomaly. |
| Topology anomaly | experimental | Process-graph structural-novelty detection. |
| Cross-process correlator | experimental | Multi-process activity-pattern correlation across lineage graph. |

## Collectors

| Module | Status | Summary |
|---|---|---|
| Unified log collector | **stable** | 18 macOS subsystems incl. Bluetooth, Wi-Fi, AirDrop. |
| Network collector | **stable** | TCP/UDP connection tracking via lsof poll. |
| DNS collector | **stable** | BPF-based DNS query capture. |
| TCC monitor | **stable** | Privacy-permission grant/revoke detection. |
| FSEvents collector | **stable** | Filesystem event fallback when ES is unavailable. |
| EDR / RMM scanner | **stable** | Discovery of 30+ EDR/MDM/insider-threat/remote-access tools. |
| Browser extension monitor | **stable** | Chrome/Firefox/Brave/Edge/Arc extension inventory. |
| Rootkit detector | **stable** | Dual-API process cross-reference. |
| System policy monitor | **stable** | SIP / XProtect / MDM / auth-plugin posture. |
| Event tap / keylogger detector | experimental | Detects processes with accessibility permission consuming key events. |
| USB monitor | experimental | USB device connect/disconnect. |
| Clipboard monitor | experimental | Clipboard content + injection-pattern detection. |
| MCP server monitor | experimental | MCP server config inventory across AI tools. |
| Ultrasonic / DolphinAttack | opt-in | Audio-injection detection. Requires microphone permission. |
| TEMPEST / Van Eck | opt-in | SDR device + display anomaly detection. Research-grade. |

## AI Guard (cluster — all experimental)

The AI Guard subsystem is one of MacCrab's most distinctive and most
new. Treat its output as advisory and combine with rule-engine
detections for load-bearing decisions.

| Module | Status | Summary |
|---|---|---|
| AI tool registry | experimental | Catalog of known AI coding tools. |
| AI process tracker | experimental | Per-AI-tool session lineage from process ancestry. |
| Agent lineage service | experimental | Weaves ES events into per-AI-session timelines. |
| Credential fence | experimental | Watches AI agents for credential file access. |
| Project boundary | experimental | Detects AI agent writes outside the active project. |
| Prompt injection scanner | experimental | Pattern + LLM-based prompt-injection detection. |
| MCP attributor | experimental | Attributes events back to specific MCP servers. |
| LLM orchestration | experimental | 5 backend providers. Advisory only — never auto-executes. |

## Outputs

| Module | Status | Summary |
|---|---|---|
| OS notifications | **stable** | User-notification delivery for alerts. |
| Webhook output | **stable** | POST alerts to a webhook URL with TLS + SSRF policy. |
| Syslog output | **stable** | Local syslog forwarding. |
| Splunk HEC output | **stable** | HTTP Event Collector with token + TLS. |
| Elastic Bulk output | **stable** | Elasticsearch `_bulk` endpoint. |
| Datadog Logs output | **stable** | Datadog HTTP intake. |
| S3 / S3-compatible output | **stable** | S3 / MinIO / R2 / Wasabi archive. |
| Wazuh API output | experimental | Wazuh manager API forwarding. |
| SFTP output | experimental | SFTP alert log shipping. |
| OpenTelemetry (OTLP) output | experimental | OTLP HTTP/JSON. New in v1.8.0. |
| Fleet telemetry | opt-in | Optional per-host telemetry to a self-hosted fleet collector. |

## Prevention / response

All response actions default-off and require explicit per-rule wiring.
See [`RESPONSE_SAFETY.md`](RESPONSE_SAFETY.md) for the safety
validators on each path.

| Module | Status | Summary |
|---|---|---|
| Response action engine | experimental | Per-rule kill / quarantine / network-block / runScript / TCC-revoke. |
| DNS sinkhole | experimental | Block DNS resolution for known-bad domains via `/etc/hosts` overlay. |
| Network blocker | experimental | Per-process or per-domain network blocking. |
| Persistence guard | experimental | Blocks LaunchAgent / LaunchDaemon writes by suspicious processes. |
| Honeyfile deception | opt-in | Plants canary credential files. Requires `MACCRAB_DECEPTION=1`. |

## Why module status matters

The motivating insight from external review (May 2026): "There are many
subsystems for an alpha security agent. The product would benefit from
very crisp 'core reliable path' vs 'experimental module' labeling."
This page is the canonical answer.

Operators making deployment decisions: stick to **stable** modules for
load-bearing detection, treat **experimental** as supplementary signal,
and treat **opt-in** modules as explicit research-mode features.
