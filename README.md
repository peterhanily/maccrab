# MacCrab

**Real-time threat detection for macOS -- no cloud, no SIEM, no telemetry.**

[![Status](https://img.shields.io/badge/status-alpha-f59e0b)]()
[![Build](https://img.shields.io/badge/build-passing-brightgreen)]()
[![Tests](https://img.shields.io/badge/tests-748%20passing-brightgreen)]()
[![Version](https://img.shields.io/badge/version-1.6.8-blue)](https://github.com/peterhanily/maccrab/releases)
[![Website](https://img.shields.io/badge/site-maccrab.com-e04820)](https://maccrab.com)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![macOS](https://img.shields.io/badge/macOS-13%2B%20(Ventura)-lightgrey)]()
[![Swift](https://img.shields.io/badge/Swift-5.9%2B-F05138)]()

> [!WARNING]
> **Alpha software under active development.** MacCrab ships in public
> alpha and is iterating rapidly on detection quality, UX, and the
> release pipeline. Expect false positives, occasional rule changes,
> and frequent updates. Run it on a Mac you're comfortable debugging
> on. Issue reports and field data are very welcome — they're driving
> most of the current release cadence. See
> [CHANGELOG.md](CHANGELOG.md) for what's shipped recently.

MacCrab is an on-device security engine that monitors your Mac in real time using Apple's Endpoint Security framework, a library of Sigma-compatible detection rules, behavioral scoring, and temporal sequence analysis. Everything runs locally as a native Endpoint Security System Extension with a SwiftUI menubar dashboard -- no cloud console, no vendor lock-in, no data leaving your machine. Think of it as what Sysmon + Sigma + a lightweight SIEM provides on Windows, but native to macOS.

**Who it's for:** Security researchers, developers who want endpoint visibility, macOS administrators, privacy-conscious users, and anyone who wants to know what's actually happening on their machine **and is OK running alpha software.**

**Releases:** Signed, notarized, auto-updating builds ship via Sparkle through [maccrab.com/appcast.xml](https://maccrab.com/appcast.xml). See [CHANGELOG.md](CHANGELOG.md) for the release history.

---

## Quick Start

### Option A: Homebrew (recommended)

```bash
# 1. Install
brew tap peterhanily/maccrab https://github.com/peterhanily/maccrab
brew install --cask maccrab

# 2. Open the dashboard
open /Applications/MacCrab.app

# 3. Click "Enable Protection" on the Overview screen, then approve the
#    extension in System Settings → General → Login Items & Extensions →
#    Endpoint Security Extensions.
```

> **Note:** Full Endpoint Security coverage requires granting Full Disk Access to MacCrab.app in **System Settings > Privacy & Security > Full Disk Access**.

### Option B: Build from source (developers)

```bash
# 1. Clone and build
git clone https://github.com/peterhanily/maccrab.git && cd maccrab
make dev    # builds, codesigns, compiles rules, starts daemon

# 2. Check status
.build/debug/maccrabctl status

# 3. Open the dashboard
make app
```

> **Note:** `make dev` runs `maccrabd` directly from `.build/` without the SystemExtension wrapper -- event coverage falls back through `eslogger` → `kdebug` → FSEvents. Native ES requires the approved provisioning profile that ships in release builds. The fallback chain is a first-class code path and is fully supported for development.

---

## What You Get

Once running, MacCrab gives you:

- **Real-time alerts** -- macOS notifications and a live alert dashboard when suspicious activity is detected (shell spawned by browser, unsigned binary persistence, credential access, etc.)
- **A SwiftUI menubar dashboard** with 15 views -- security overview, alert triage with bulk actions, live event stream, campaign timelines, rule browser, AI Guard status, and more
- **CLI threat hunting** -- `maccrabctl hunt "show processes connecting to unusual ports"` for natural-language queries against your event data
- **Behavioral scoring** -- even if no single rule fires at critical severity, accumulated suspicious indicators across a process tree will still trigger an alert
- **Campaign detection** -- multi-step attack chains (download, execute, persist, call home) are correlated across process lineage and time windows
- **AI coding tool guardrails** -- monitors Claude Code, Codex, Cursor, and 5 other AI tools for credential access, project boundary escapes, and prompt injection
- **Zero telemetry by default** -- all data stays in a local SQLite database; optional LLM backends sanitize data before any external call

---

## How MacCrab Compares

| Capability | MacCrab | Santa | osquery | Commercial EDR |
|------------|:-------:|:-----:|:-------:|:--------------:|
| Real-time kernel events (90+ ES types) | Yes | Exec only | Scheduled | Yes |
| Sigma-compatible rules | **Yes** | No | No | Varies |
| Temporal sequence detection | **Yes** | No | No | Some |
| Behavioral scoring | **Yes** | No | No | Yes |
| AI coding tool guardrails | **Yes** | No | No | No |
| Threat intel feeds (abuse.ch) | **Yes** | No | No | Yes |
| Baseline anomaly detection | **Yes** | No | No | Yes |
| TCC permission monitoring | **Yes** | No | Partial | Some |
| Process lineage DAG | **Yes** | No | Partial | Yes |
| Native macOS dashboard | **Yes** | Yes | No | Agent only |
| Self-defense (8 layers) | **Yes** | No | No | Yes |
| Runs entirely local | **Yes** | **Yes** | **Yes** | No |
| Open source | **Yes** | **Yes** | **Yes** | No |
| Infrastructure required | **None** | Sync server | Fleet server | Cloud console |

---

## Privacy

MacCrab has **zero telemetry** and no phone-home behavior. All data is collected and stored locally in SQLite. Nothing leaves your machine unless you explicitly enable an optional feature (LLM backends, threat intel feeds, or fleet telemetry) -- and when you do, usernames, private IPs, hostnames, and credentials are automatically redacted before transmission.

Read the full [Privacy Policy](PRIVACY.md).

---

## Security

MacCrab's detection engine runs as a System Extension (a sandboxed userspace process managed by `sysextd`, as required for Endpoint Security). The CLI and dashboard run as your user with read-only database access. The engine protects its own integrity with 8 layers of tamper detection including binary integrity checks, anti-debug, and process injection detection.

To report a vulnerability, **do not open a public issue** -- email maccrab@peterhanily.com instead.

Read the full [Security Policy](SECURITY.md).

---

## Documentation

| Document | What's in it |
|---|---|
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Sysext approval failures, FDA silent drops, `make compile-rules` errors, "Protection active but no alerts", webhook validation rejections, Homebrew upgrade cleanup |
| [UPGRADE.md](UPGRADE.md) | v1.2 LaunchDaemon → v1.3 SystemExtension migration, within-family upgrade notes, rollback guidance |
| [FAQ.md](FAQ.md) | Top 14 questions: custom rules, data that leaves the machine, air-gapped use, SIEM export, license, macOS versions, Apple Silicon |
| [Rules/README.md](Rules/README.md) | Sigma YAML rule authoring, field mappings, sequence rule syntax |
| [docs/daemon_config.example.json](docs/daemon_config.example.json) | Annotated reference config with every tunable knob and every output-sink type |
| [docs/suppressions.example.json](docs/suppressions.example.json) | Per-rule process allowlist format |
| [PRIVACY.md](PRIVACY.md) | Data inventory — what's collected, what leaves, what's redacted |
| [SECURITY.md](SECURITY.md) | Threat model, privilege boundaries, vulnerability disclosure |
| [CHANGELOG.md](CHANGELOG.md) | Dated version history |

---

## Architecture

```
                         MacCrab Detection Pipeline

 +--------------------+     +---------------------+     +----------------------+
 |   Event Sources    |     |    Enrichment       |     |     Detection        |
 |                    |     |                     |     |                      |
 | ES Framework  ----------> Process Lineage DAG  |     | Single-Event Rules   |
 | Unified Log   ----------> Code Signing Cache   |     |     (Sigma YAML)     |
 | TCC Monitor   ----------> Quarantine Origin    +---->| Sequence Rules       |
 | Network Coll. ----------> Threat Intel Feeds   |     | Baseline Anomaly     |
 | DNS Collector ----------> Cert Transparency    |     | Statistical Anomaly  |
 | Event Tap     ----------> YARA Scanner         |     | Behavioral Scoring   |
 | System Policy ----------> Entropy Analysis     |     | AI Guard             |
 | FSEvents      ----------> CDHash Extraction    |     | Rootkit Detector     |
 | Crash Reports --------->                       |     | Power Anomaly        |
 +--------------------+     +---------------------+     +----------+-----------+
                                                                   |
                                                                   v
                                                        +----------+-----------+
                                                        |  Incident Grouper    |
                                                        |  Dedup & Suppression |
                                                        |  Self-Defense (8 ly) |
                                                        +----------+-----------+
                                                                   |
                            +------------+------------+------------+-----+--------+
                            |            |            |            |     |        |
                            v            v            v            v     v        v
                        +-------+  +---------+  +---------+  +-------+  +------+ +------+
                        | CLI   |  |  JSONL   |  |  macOS  |  |Webhook|  |Syslog| | Fleet|
                        |stdout |  |  File    |  |  Notif  |  | POST  |  |5424  | | Tele |
                        +-------+  +---------+  +---------+  +-------+  +------+ +------+
```

---

## CLI Reference

```bash
maccrabctl status                       # Daemon status
maccrabctl alerts                       # Recent alerts
maccrabctl events tail 20               # Live event stream
maccrabctl watch                        # Streaming alert tail
maccrabctl rules list                   # Loaded rules
maccrabctl hunt "show critical alerts"  # NL threat hunting
maccrabctl report --hours 48            # Incident report
maccrabctl suppress <rule-id> <path>    # Suppress false positive
maccrabctl cdhash 1234                  # CDHash lookup
maccrabctl tree-score 20                # Behavioral scoring
maccrabctl mcp list                     # MCP server inventory
maccrabctl extensions --suspicious      # Browser extension scan
```

---

## MCP Server

MacCrab ships a built-in [Model Context Protocol](https://modelcontextprotocol.io/) server (`maccrab-mcp`) that lets AI coding tools query your security data directly from the editor.

**Setup** — copy `.mcp.json` from the repo root to your project, or add the entry manually:

```json
{
  "mcpServers": {
    "maccrab": { "command": "/path/to/.build/debug/maccrab-mcp" }
  }
}
```

Build the MCP binary with `swift build --target maccrab-mcp`.

**Available tools (11):**

| Tool | Purpose |
|------|---------|
| `get_alerts` | Query alerts with severity, time, and suppression filters |
| `get_events` | Search events by category, keyword, or time window |
| `get_campaigns` | List detected attack campaigns with contributing alerts |
| `get_status` | Daemon status, rule count, uptime, database size |
| `hunt` | Natural-language threat hunting across all stored events |
| `get_security_score` | Security posture score (0–100) with per-factor breakdown |
| `suppress_alert` | Suppress a false-positive alert by ID |
| `get_alert_detail` | Full detail for one alert: LLM investigation, d3fend techniques, remediation hint |
| `suppress_campaign` | Suppress a campaign and all its contributing alerts at once |
| `get_ai_alerts` | All AI Guard alerts for the last 24 h (credential, boundary, injection) |
| `scan_text` | Check untrusted text for prompt injection before your AI tool acts on it |

**Slash commands** (`.claude/commands/`): `/security-check`, `/threat-hunt <query>`, `/alerts`.

---

## Uninstall

### Homebrew

```bash
brew uninstall --cask maccrab
```

The cask's uninstall block deactivates the System Extension via `systemextensionsctl` and removes MacCrab.app, the CLI binaries, and any pre-1.3 LaunchDaemon artefacts.

### Manual / source build

```bash
sudo ./scripts/uninstall.sh
```

The uninstall script stops the daemon (if running from a dev build), removes binaries, deactivates the System Extension, and asks before deleting your data (events, rules, logs). Pass `-y` to skip the prompt.

To remove user-level data as well:

```bash
rm -rf ~/Library/Application\ Support/MacCrab
rm -f ~/Library/Preferences/com.maccrab.app.plist
```

---

## Detection Stack

MacCrab evaluates events through a 5-tier detection hierarchy:

| Tier | Description |
|------|-------------|
| **1. Rules** | Sigma-compatible YAML rules compiled to JSON. Category-indexed for O(1) dispatch; rules exceeding 50 ms are logged for profiling. |
| **2. Anomaly** | Welford z-score statistical anomaly; 2nd-order Markov chain process trees; behavioral scoring with weighted indicators and feedback-adjusted weights. |
| **3. Sequences** | Temporal multi-step rules with process lineage correlation, 10K partial match cap, LRU regex cache. |
| **4. Campaigns** | Kill chain, alert storm, AI compromise, coordinated attack, and lateral movement detection with incremental O(1) indexes. |
| **5. Cross-process** | Correlation across the full process lineage graph with trusted-helper and unresolved-destination sentinels. |

<details>
<summary><strong>Event Sources (click to expand)</strong></summary>

MacCrab ingests from 19 real-time event sources, covering kernel-level process activity through application-layer permissions. The top-level collectors include:

| Source | What it captures |
|--------|------------------|
| **Endpoint Security framework** | 90+ kernel event types: process exec/fork/exit, file create/write/rename/unlink, signal delivery, kext loading, mmap, iokit operations |
| **Unified Log** | Real-time streaming from 18 subsystems (`com.apple.securityd`, `com.apple.authd`, `com.apple.xpc`, `com.apple.install`, Bluetooth, Wi-Fi, AirDrop, and more) |
| **TCC permission monitor** | Watches system and user TCC databases for grants/revocations to accessibility, full disk access, screen recording, camera, microphone, and more |
| **Network connection collector** | Outbound TCP/UDP connections with destination IP, port, hostname resolution, and owning process attribution |
| **DNS collector** | DNS query/response monitoring via BPF for DGA detection, tunneling, and domain reputation checks |
| **Event Tap monitor** | CGEvent tap monitoring for keylogger detection and suspicious input recording |
| **System Policy monitor** | Gatekeeper, XProtect, SIP, MDM, and auth-plugin enforcement activity |
| **FSEvents fallback** | File system event stream for coverage when ES file events are unavailable |
| **eslogger / kdebug** | Fallback ES event streams when the native ES client is unavailable |

See the Monitors and Collectors table below for the full list including USB, clipboard, ultrasonic, rootkit, browser extension, MCP, EDR/RMM, and TEMPEST/SDR monitors.

</details>

<details>
<summary><strong>Monitors and Collectors (click to expand)</strong></summary>

| Monitor | Purpose | Poll Interval |
|---------|---------|--------------|
| ESCollector | Endpoint Security framework events | Real-time |
| UnifiedLogCollector | System log (18 subsystems incl. Bluetooth, Wi-Fi, AirDrop) | Real-time |
| NetworkCollector | TCP/UDP connections | 5s |
| DNSCollector | DNS queries (BPF) | Real-time |
| TCCMonitor | Privacy permission changes | Real-time |
| FSEventsCollector | File system events (non-root fallback) | Real-time |
| EDRMonitor | EDR/RMM/insider threat/remote access tool scanning | 120s |
| USBMonitor | USB device connect/disconnect | 10s |
| ClipboardMonitor | Clipboard content + injection detection | 2s |
| UltrasonicMonitor | DolphinAttack/NUIT audio injection | Configurable |
| RootkitDetector | Dual-API process cross-reference | 120s |
| EventTapMonitor | Keylogger detection | Real-time |
| SystemPolicyMonitor | SIP, XProtect, MDM, auth plugins | 300s |
| BrowserExtensionMonitor | Chrome/Firefox/Brave/Edge/Arc extensions | Startup |
| MCPMonitor | MCP server configs across AI tools | Startup |
| TEMPESTMonitor | Van Eck phreaking: SDR devices + display anomalies | 60s |

</details>

<details>
<summary><strong>Analysis Engines (click to expand)</strong></summary>

| Engine | Description |
|--------|-------------|
| **Baseline anomaly detection** | Learned model of normal process behavior, network destinations, and file access patterns; alerts on deviation after a configurable learning period |
| **Statistical anomaly detector** | Welford's online algorithm for rolling mean/stddev per process; flags z-score deviations that fixed-weight scoring misses |
| **Behavioral scoring** | Accumulates weighted suspicion indicators per process with time-decay; fires composite alerts when score crosses configurable thresholds, even if no single rule matched at critical severity |
| **Incident grouper** | Clusters related alerts into attack timelines by process lineage, time proximity, and MITRE tactic progression; generates narrative summaries |
| **Entropy analysis** | Shannon entropy calculation for command lines, domain names, and payloads to detect obfuscation, DGA domains, and DNS tunneling |
| **Rootkit detector** | Cross-references `proc_listallpids()` and `sysctl(KERN_PROC_ALL)` to find hidden processes indicating userland rootkit activity |
| **Crash report miner** | Scans DiagnosticReports for exploitation indicators (EXC_BAD_ACCESS, buffer overflows, ASan faults, use-after-free) |
| **Power anomaly detector** | Monitors power assertions and thermal pressure to detect crypto mining and sustained C2 beaconing |

</details>

<details>
<summary><strong>AI Guard (click to expand)</strong></summary>

Monitors AI coding tool processes for unsafe behavior. Identifies Claude Code, Codex, OpenClaw, Cursor, Aider, Copilot, Continue.dev, and Windsurf by executable path and process ancestry.

| Component | Description |
|-----------|-------------|
| **AI process tracker** | Identifies and tracks AI tool processes and their child process trees |
| **Credential fence** | Alerts when AI tool children access any of 28 sensitive path patterns (SSH keys, `.env` files, AWS credentials, keychains, browser credential stores, kubeconfig, and more) |
| **Project boundary enforcement** | Detects when AI tools read or write files outside the current project directory |
| **Prompt injection scanner** | Scans for injection patterns in files read by AI tools using forensicate.ai analysis |
| **Activity by tool** | Dashboard AI Guard tab shows a live per-tool alert breakdown (credential / injection / boundary / other) sorted by severity |

22 dedicated AI safety detection rules in `Rules/ai_safety/`. Use the `scan_text` MCP tool to proactively check untrusted input before your AI tool acts on it.

</details>

<details>
<summary><strong>LLM Reasoning Backends (click to expand)</strong></summary>

MacCrab integrates pluggable LLM backends for threat hunting, investigation summaries, and adaptive rule generation. All features degrade gracefully when no backend is configured. Cloud providers receive automatic privacy sanitization (usernames, private IPs, and hostnames are redacted before transmission).

| Backend | Config | Use case |
|---------|--------|----------|
| **Ollama** (recommended) | `MACCRAB_LLM_PROVIDER=ollama` | Fully local, zero cloud dependency -- best for privacy-sensitive environments |
| **Claude API** | `MACCRAB_LLM_PROVIDER=claude` + `MACCRAB_LLM_CLAUDE_KEY` | Anthropic's Claude models via API |
| **OpenAI-compatible** | `MACCRAB_LLM_PROVIDER=openai` + `MACCRAB_LLM_OPENAI_KEY` | OpenAI or any compatible endpoint (LM Studio, vLLM, etc.) |
| **Gemini** | `MACCRAB_LLM_PROVIDER=gemini` | Google Gemini via API |
| **Mistral** | `MACCRAB_LLM_PROVIDER=mistral` | Mistral AI via API |

LLM-powered features:

| Feature | Command / Trigger |
|---------|-------------------|
| **Natural language threat hunting** | `maccrabctl hunt "<query>"` or AI Analysis tab in dashboard |
| **Investigation summaries** | Auto-generated when a campaign fires; stored as `maccrab.llm.investigation-summary` alert |
| **Active defense recommendations** | Generated alongside campaign alerts; stored as `maccrab.llm.defense-recommendation` alert |
| **AI-generated detection rules** | Auto-generated from observed campaigns using `RuleGenerator.generateFromCampaignEnhanced()` |

All LLM settings can be configured in **Settings > AI Backend** in the dashboard, or via `daemon_config.json`.

</details>

<details>
<summary><strong>Threat Intelligence (click to expand)</strong></summary>

| Feed | IOC type | Update interval |
|------|----------|:---------------:|
| **abuse.ch Feodo Tracker** | C2 IP addresses | 4 hours |
| **abuse.ch URLhaus** | Malicious URLs and domains | 4 hours |
| **abuse.ch MalwareBazaar** | Malicious file hashes (SHA-256) | 4 hours |
| **Custom IOC lists** | User-provided hashes, IPs, domains | On change |

</details>

<details>
<summary><strong>Enrichment Pipeline (click to expand)</strong></summary>

Every event passes through enrichment before rule evaluation:

| Enricher | What it adds |
|----------|--------------|
| **Process lineage DAG** | Sliding-window directed acyclic graph of parent-child relationships; survives parent exit; full ancestor chain reconstruction |
| **Code signing cache** | Signer type (Apple, App Store, Developer ID, ad-hoc, unsigned), team ID, signing ID, notarization status, platform binary flag |
| **Quarantine origin** | Download URL, downloading application, and timestamp from macOS QuarantineEventsV2 database |
| **Certificate Transparency** | Flags connections to domains with newly issued certs (<24h), unusual CAs, or typosquatting patterns |
| **YARA scanner** | On-demand YARA rule matching for files referenced in high-severity alerts |
| **Threat intel lookup** | Checks file hashes, destination IPs, and domains against cached IOC feeds |
| **Entropy analysis** | Shannon entropy scoring for command arguments and domain names |

</details>

<details>
<summary><strong>Self-Defense (8 layers) (click to expand)</strong></summary>

The daemon protects its own integrity with continuous tamper detection:

1. **Binary integrity** -- SHA-256 hash at startup, periodic recheck
2. **Rules integrity** -- directory hash of compiled rules
3. **Config file monitoring** -- dispatch source watches for modification
4. **Database tamper detection** -- integrity checks on event/alert stores
5. **Anti-debug** -- detects debugger attachment via `sysctl` checks
6. **Signal interception** -- monitors SIGKILL/SIGTERM from non-system sources
7. **LaunchDaemon plist watch** -- alerts on plist removal or modification
8. **Process injection detection** -- detects attempts to inject into the daemon

</details>

<details>
<summary><strong>Suppression Manager (click to expand)</strong></summary>

Per-rule process allowlists loaded from `suppressions.json`. Operators can suppress known false positives without disabling rules entirely:

```json
{
    "maccrab.deep.event-tap-keylogger": ["/usr/libexec/universalaccessd"],
    "rule-id": ["/path/to/safe/process"]
}
```

The CLI (`maccrabctl suppress`) writes to the same file. The daemon checks suppressions before emitting alerts.

</details>

<details>
<summary><strong>Response Actions (click to expand)</strong></summary>

Rules can trigger configurable response actions ranging from passive to active:

| Action | Description |
|--------|-------------|
| `log` | Always on -- write to alert store and JSONL |
| `notify` | macOS notification banner |
| `kill` | Terminate the process that triggered the alert |
| `quarantine` | Move the triggering file to a quarantine vault |
| `script` | Run a custom shell script with alert context as environment variables |
| `blockNetwork` | Block the network connection (requires Network Extension) |

</details>

---

## Rule Coverage by MITRE ATT&CK Tactic

Rules live under `Rules/<tactic>/` as Sigma-compatible YAML. Run
`find Rules -name "*.yml" | wc -l` for the current total, or `ls
Rules/` for the tactic directories. Coverage spans every MITRE
ATT&CK tactic relevant to macOS — Defense Evasion, Credential
Access, Persistence, Supply Chain, Execution, Discovery,
Privilege Escalation, AI Safety, Command and Control, Lateral
Movement, Collection, Exfiltration, Initial Access, TCC Abuse,
Container, Impact — plus temporal multi-step detections under
`Rules/sequences/`. Counts fluctuate release-to-release as rules
get added, tightened, or deprecated; the repository tree is the
source of truth.

---

## Output Targets

| Target | Format |
|--------|--------|
| **CLI stdout** | Human-readable colored output with severity indicators |
| **JSONL file** | One JSON object per line, suitable for log ingestion pipelines |
| **macOS notifications** | Native `UserNotifications` alerts for high and critical severity |
| **Webhook** | JSON POST to a configurable URL for integration with Slack, Teams, PagerDuty |
| **Syslog** | RFC 5424 structured data over UDP/TCP for forwarding to any syslog receiver |
| **Fleet telemetry** | Optional enrollment with a fleet server for centralized multi-host visibility |

---

## SwiftUI Dashboard

A native status bar application with a sidebar navigation layout across 15 views:

<details>
<summary><strong>All dashboard views (click to expand)</strong></summary>

| View | Description |
|------|-------------|
| **Overview** | At-a-glance stats: events/sec, alert counts by severity, top processes, threat intel status |
| **Alerts** | Real-time alert dashboard with severity filtering, bulk suppression, and incident grouping |
| **Campaigns** | Higher-order attack chain detections: kill chains, alert storms, coordinated attacks |
| **Events** | Live event stream with search, category filters, and process ancestry drill-down |
| **Rules** | Rule browser with enable/disable toggles, MITRE tactic grouping, and rule wizard |
| **Prevention** | Active response actions: kill, quarantine, network block, DNS sinkhole |
| **AI Guard** | AI coding tool activity: credential fence alerts, boundary violations, MCP server monitoring |
| **Browser Extensions** | Installed extension inventory with dangerous-permission risk scoring |
| **Threat Intel** | abuse.ch feed status, IOC counts, custom intel import |
| **Package Freshness** | Manual supply-chain risk check (npm, PyPI, Homebrew, Cargo) + supply-chain alerts |
| **AI Analysis** | LLM-powered threat hunting, investigation summaries, defense recommendations |
| **Integrations** | MISP, webhook, syslog, fleet configuration |
| **Permissions** | TCC permission timeline visualization |
| **ES Health** | Daemon status, database health, collector checklist, event throughput |
| **Docs** | Built-in documentation and reference |

Additional views: Settings > AI Backend (LLM provider configuration), Response Actions log.

</details>

---

## What's New

<details>
<summary><strong>v1.3 — native Endpoint Security via SystemExtension (2026-04)</strong></summary>

v1.3 is the biggest architectural change since v1.0. MacCrab now runs as a native Endpoint Security **System Extension** activated from inside `MacCrab.app` -- matching the architecture every commercial macOS EDR uses (CrowdStrike, SentinelOne, Jamf Protect, Microsoft Defender). On macOS Catalina+, AMFI grants `com.apple.developer.endpoint-security.client` only to binaries loaded via `OSSystemExtensionRequest` from an approved `.systemextension` bundle -- LaunchDaemons are categorically rejected regardless of profile validity.

- **SystemExtension activation** -- no more `sudo maccrabd`; open MacCrab.app and click Enable Protection. `sysextd` manages the lifecycle from there.
- **Native ES client** -- `com.apple.developer.endpoint-security.client` approved under bundle ID `com.maccrab.agent`. The 3-level fallback chain (eslogger → kdebug → FSEvents) is still first-class for developer builds.
- **Network-convergence hardening (1.3.4)** -- unresolved destination IPs no longer bucket benign HTTPS traffic under `:443`; new trusted-helper fan-out gate; 49-entry trusted-cloud suffix list.
- **False-positive regression harness** -- every real FP observed in a live install now has a one-line `@Test`. **643 tests in 138 suites**, FP regressions blocked at CI.
- **Noise reduction arc (1.2.1 → 1.2.4)** -- reference workstation dropped from 2,856 alerts/24h to ~3/day (99.9% reduction) without degrading detection fidelity.
- **Notarized Developer ID distribution** -- signed DMG, Homebrew cask tap (`peterhanily/maccrab`), reproducible release pipeline.
- **Sparkle auto-update (1.3.5)** -- EdDSA-signed `appcast.xml` served from Cloudflare Pages at `maccrab.com`; "Check for Updates…" in the status-bar menu and Settings.
- **Manual response actions in the dashboard (1.3.9)** -- Kill Process / Quarantine File / Block Destination buttons on `AlertDetailView` do real work: `kill(SIGTERM)` with `pkill -f` fallback; move-to-vault with `com.apple.quarantine` xattr + `chmod 000` + forensic sidecar; PF anchor write via `osascript` admin-privileges prompt. Typed errors distinguish "root-owned" from "already exited" from "not found".
- **Hardened DB permissions (1.3.9)** -- SQLite WAL/SHM sidecars are 0o640 (group-readable for the dashboard) instead of world-readable. Closes a cross-user read of recent events.
- **Self-allowlist (1.3.8)** -- MacCrab no longer alerts on its own activity (brew upgrades, xpcproxy, FDA grants).

See [CHANGELOG.md](CHANGELOG.md) for the full version history.

</details>

<details>
<summary><strong>v1.0.0 — initial release</strong></summary>

- 5-tier detection hierarchy (rules, sequences, anomaly, campaigns, cross-process)
- LLM reasoning backends: Ollama, Claude, OpenAI-compatible, Gemini, Mistral
- NL threat hunting, LLM investigation summaries, active defense recommendations
- AI Guard monitoring 8 coding tools + MCP servers
- Package freshness checking (npm, PyPI, Homebrew, Cargo)
- Ultrasonic attack detection (DolphinAttack, NUIT, SurfingAttack)
- Clipboard, browser extension, USB monitoring
- TLS fingerprinting and C2 beacon detection
- Auto rule generation from observed attacks (template + LLM-enhanced)
- Encrypted database (AES-256)
- HTML incident reports
- Rootkit detection via cross-referenced process enumeration
- Crash report mining for exploitation indicators
- Power/thermal anomaly detection (crypto mining, C2 beacons)
- CDHash extraction for process integrity verification
- TEMPEST / Van Eck phreaking detection (17 SDR devices, display anomaly monitoring)
- EDR/RMM tool discovery (30+ tools across 5 categories)
- 14 language localizations for the dashboard

</details>

---

## Development

<details>
<summary><strong>dev.sh (click to expand)</strong></summary>

The `scripts/dev.sh` script is the primary development driver. It builds, codesigns with the ES entitlement, compiles rules, and restarts the daemon in one step:

```bash
./scripts/dev.sh              # Full cycle (sudo for ES)
./scripts/dev.sh --no-es      # Without root (limited event sources)
./scripts/dev.sh --build      # Build + sign only, don't start
./scripts/dev.sh --restart    # Restart daemon without rebuilding
./scripts/dev.sh --stop       # Stop daemon and app
./scripts/dev.sh --status     # Show daemon status
```

</details>

### Make targets

```
make dev              Build + restart daemon + open app (one command)
make restart          Restart daemon (no rebuild)
make stop             Stop daemon and app
make status           Show daemon status
make watch            Live stream alerts

make build            Build debug binaries
make release          Build release binaries
make compile-rules    Compile YAML rules to JSON
make clear-data       Delete local events/alerts
make new-rule         Create rule from template
make bundle-app       Package the SwiftUI app into .app bundle

make install          Install system-wide (sudo)
make uninstall        Remove system install (sudo)
make run-root         Run with Endpoint Security (sudo)
```

### Test suite

```bash
make test              # Run tests (summary)
make test-full         # Full test suite with verbose output
make test-fp           # False positive tests against benign system activity
make test-detection    # Detection tests -- triggers all categories safely
make test-integration  # Integration tests (daemon + CLI + rules)
make test-stress       # 60-second stress test for event throughput
make lint-rules        # Lint all YAML rules for format, UUID uniqueness, tags
```

<details>
<summary><strong>Test files (click to expand)</strong></summary>

| File | Scope |
|------|-------|
| `Tests/MacCrabCoreTests/MacCrabCoreTests.swift` | Core engine unit tests |
| `Tests/MacCrabCoreTests/PipelineTests.swift` | End-to-end pipeline tests |
| `Tests/MacCrabCoreTests/DeepMacOSTests.swift` | macOS-specific integration tests |
| `Tests/MacCrabCoreTests/AIGuardTests.swift` | AI Guard subsystem tests |
| `Tests/MacCrabCoreTests/SuppressionTests.swift` | Suppression manager tests |
| `Tests/MacCrabCoreTests/ForensicTests.swift` | Forensic component tests (rootkit, crash, power, CDHash, threat hunter) |
| `scripts/false-positive-test.sh` | FP regression tests against real system events |
| `scripts/detection-test.sh` | Safe trigger tests for every detection category |
| `scripts/rule-lint.sh` | YAML validation, UUID uniqueness, ATT&CK tag checks |
| `scripts/stress-test.sh` | High-throughput event flooding for performance validation |

</details>

### Red team simulation

```bash
make test-detection              # 15 detection categories (~2 min)
make test-campaign               # 5-wave kill chain simulation (~5 min)
make test-campaign SUSTAINED=1   # Slow burn (~12 min, more realistic)
make test-fp                     # False positive validation (105 system processes)
make test-stress 120             # Sustained operation monitor (120s)
```

All tests are safe -- artifacts in `/tmp`, localhost connections, cleanup on exit.

---

## Detection Rules

### Format

MacCrab uses a Sigma-compatible YAML format. Single-event rules follow the [standard Sigma specification](https://sigmahq.io/docs/). Temporal sequence rules extend the format with `type: sequence`, `steps`, `window`, and `correlation` fields.

Rules are compiled from YAML to an optimized JSON predicate format by `Compiler/compile_rules.py` before being loaded by the detection engine at runtime.

<details>
<summary><strong>Example: single-event rule (click to expand)</strong></summary>

```yaml
title: Shell Spawned by Browser Process
id: d1a2b3c4-0001-4000-a000-000000000001
status: stable
description: >
    Detects a shell interpreter spawned as a child of a browser process,
    which may indicate exploitation or malicious download execution.
author: MacCrab Community
date: 2026/03/31
references:
    - https://attack.mitre.org/techniques/T1059/004/
tags:
    - attack.execution
    - attack.t1059.004
logsource:
    category: process_creation
    product: macos
detection:
    selection_parent:
        ParentImage|endswith:
            - '/Safari'
            - '/Google Chrome'
            - '/Firefox'
            - '/Microsoft Edge'
            - '/Arc'
            - '/Brave Browser'
    selection_child:
        Image|endswith:
            - '/sh'
            - '/bash'
            - '/zsh'
    condition: selection_parent and selection_child
falsepositives:
    - Browser extensions that legitimately invoke shell scripts
    - Web development tools
level: high
```

</details>

<details>
<summary><strong>Example: temporal sequence rule (click to expand)</strong></summary>

Sequence rules define multi-step attack chains with time windows, ordering constraints, and process lineage correlation:

```yaml
title: Download to Persistence to C2 Attack Chain
id: e1f2a3b4-0001-4000-b000-000000000001
status: experimental
description: >
    Detects a complete attack chain: file downloaded to Downloads/tmp,
    executed as unsigned binary, installs persistence via LaunchAgent/Daemon,
    then makes outbound network connection (C2 callback).
author: MacCrab Community
date: 2026/03/31
tags:
    - attack.execution
    - attack.persistence
    - attack.command_and_control

type: sequence
window: 120s
correlation: process.lineage
ordered: true

steps:
    - id: execute
      logsource:
          category: process_creation
          product: macos
      detection:
          selection:
              Image|contains:
                  - '/Downloads/'
                  - '/tmp/'
          filter_signed:
              SignerType:
                  - 'apple'
                  - 'appStore'
                  - 'devId'
          condition: selection and not filter_signed

    - id: persist
      logsource:
          category: file_event
          product: macos
      detection:
          selection_la:
              TargetFilename|contains: '/LaunchAgents/'
              TargetFilename|endswith: '.plist'
          selection_ld:
              TargetFilename|contains: '/LaunchDaemons/'
              TargetFilename|endswith: '.plist'
          condition: selection_la or selection_ld
      process: execute.descendant

    - id: c2
      logsource:
          category: network_connection
          product: macos
      detection:
          selection:
              DestinationIsPrivate: 'false'
          condition: selection
      process: execute.descendant

trigger: persist and c2
level: critical
```

</details>

<details>
<summary><strong>Sequence rule fields (click to expand)</strong></summary>

| Field | Description |
|-------|-------------|
| `type: sequence` | Marks the rule as a temporal sequence (processed by `SequenceEngine`) |
| `window` | Maximum time span from first to last step (e.g., `120s`, `5m`, `1h`) |
| `correlation` | How steps relate: `process.lineage`, `process.same`, `file.path`, `network.endpoint`, or `none` |
| `ordered` | Whether steps must occur in the listed order (`true`) or in any order (`false`) |
| `steps[].process` | Process relationship to another step: `<step_id>.descendant`, `<step_id>.ancestor`, `<step_id>.same`, `<step_id>.sibling` |
| `trigger` | Boolean expression over step IDs that must be satisfied for the rule to fire |

</details>

### Writing custom rules

1. Create a new `.yml` file in the appropriate `Rules/<tactic>/` directory
2. Follow the Sigma YAML format with `logsource.product: macos`
3. Assign a unique UUID as the rule `id`
4. Tag with MITRE ATT&CK techniques (e.g., `attack.t1059.004`)
5. Document known false positives
6. Compile and test:

```bash
make compile-rules
maccrabctl rules list | grep "your rule title"
make lint-rules       # Validates format, UUID uniqueness, and tags
make test-fp          # Verify no false positives against normal activity
```

---

## Configuration

<details>
<summary><strong>Environment variables (click to expand)</strong></summary>

| Variable | Default | Description |
|----------|---------|-------------|
| `MACCRAB_RULES_DIR` | `~/Library/Application Support/MacCrab/compiled_rules/` | Compiled JSON rule directory |
| `MACCRAB_LOG_DIR` | `~/Library/Application Support/MacCrab/logs/` | JSONL alert and event log directory |
| `MACCRAB_WEBHOOK_URL` | *(none)* | URL for JSON POST webhook delivery |
| `MACCRAB_SYSLOG_HOST` | *(none)* | Syslog receiver hostname or IP |
| `MACCRAB_SYSLOG_PORT` | `514` | Syslog receiver port |
| `MACCRAB_SYSLOG_PROTO` | `udp` | Syslog transport (`udp` or `tcp`) |
| `MACCRAB_MIN_SEVERITY` | `low` | Minimum output severity (`informational`, `low`, `medium`, `high`, `critical`) |

</details>

<details>
<summary><strong>Baseline engine (click to expand)</strong></summary>

The baseline anomaly engine builds a profile of normal activity over a configurable learning period. Configuration is stored in `~/Library/Application Support/MacCrab/baseline_config.json`:

```json
{
    "learningPeriodDays": 7,
    "processFrequencyThreshold": 0.01,
    "networkDestinationThreshold": 0.005,
    "fileAccessPathThreshold": 0.01,
    "updateIntervalMinutes": 60,
    "excludedProcesses": [
        "/usr/libexec/xpcproxy",
        "/usr/sbin/mDNSResponder"
    ]
}
```

</details>

<details>
<summary><strong>Alert deduplication (click to expand)</strong></summary>

| Setting | Default | Description |
|---------|---------|-------------|
| Suppression window | 300 seconds | Time before the same (rule, process, context) tuple can fire again |
| Max alerts per rule per hour | 50 | Hard cap on alert volume per rule |
| Dedup key fields | rule ID, process path, file path or destination IP | Fields used to compute the deduplication key |

</details>

---

## Requirements

| Requirement | Details |
|-------------|---------|
| **macOS** | 13.0+ (Ventura or later) |
| **Swift** | 5.9+ |
| **SystemExtension approval** | One-time user approval in System Settings → General → Login Items & Extensions → Endpoint Security Extensions (release builds). Dev builds skip this via the fallback chain. |
| **ES entitlement** | `com.apple.developer.endpoint-security.client` -- ships in release DMGs via an approved provisioning profile; dev builds use the `eslogger` / `kdebug` / FSEvents fallback chain |
| **Full Disk Access** | Grant to MacCrab.app (release) or your terminal emulator (dev) for TCC database monitoring |
| **Python** | 3.9+ with PyYAML (`pip install pyyaml`) for the rule compiler |

---

## Signing and Distribution

<details>
<summary><strong>Local development (click to expand)</strong></summary>

Apple restricts the Endpoint Security entitlement to binaries loaded via `OSSystemExtensionRequest` from an approved `.systemextension` bundle -- LaunchDaemons and standalone binaries are rejected by AMFI regardless of profile validity. For local development, MacCrab's daemon has a 3-level fallback chain (`eslogger` subprocess → `kdebug` → FSEvents), so dev builds work fully without your own ES entitlement approval.

### Quick dev cycle

```bash
make dev          # build, ad-hoc codesign, compile rules, restart
make dev-no-es    # same without sudo (no eslogger proxy)
make status       # daemon status
make stop         # stop daemon and app
```

### Approving the ad-hoc-signed daemon

On first launch, macOS may block the ad-hoc-signed `maccrabd` binary. Go to **System Settings → Privacy & Security** and click **Allow Anyway**. Grant **Full Disk Access** to your terminal (or to MacCrab.app for production installs) for TCC database monitoring.

</details>

<details>
<summary><strong>Production release builds (click to expand)</strong></summary>

Release DMGs are produced by `scripts/build-release.sh` (gitignored -- contains local paths and identities). The pipeline:

1. Compile rules to JSON with `Compiler/compile_rules.py`
2. Build all 5 SPM targets (`MacCrabCore`, `maccrabd`, `maccrabctl`, `MacCrabApp`, `maccrab-mcp`, `MacCrabAgent`) with `swift build -c release`
3. Wrap `MacCrabAgent` into a `.systemextension` bundle with `Info.plist` carrying `CFBundlePackageType=SYSX` and `NSSystemExtensionPointIdentifier=com.apple.system_extension.endpoint_security`
4. Sign the sysext with Developer ID Application + embedded provisioning profile carrying the ES entitlement
5. Sign `MacCrab.app` with hardened runtime; notarize and staple the DMG
6. Update appcast entry, bump Homebrew cask

If you have your own approved ES entitlement (Apple Developer Program required), you can re-sign `MacCrabAgent` with your own provisioning profile.

</details>

---

## Project Structure

<details>
<summary><strong>Full directory layout (click to expand)</strong></summary>

```
maccrab/
├── Package.swift
├── Makefile
├── entitlements.plist
├── LICENSE                              # Apache 2.0
├── CONTRIBUTING.md
│
├── Sources/
│   ├── MacCrabCore/                     # Core detection library
│   │   ├── Events/                      # Unified event model
│   │   │   ├── Event.swift
│   │   │   ├── EventEnums.swift
│   │   │   ├── ProcessInfo.swift
│   │   │   ├── FileInfo.swift
│   │   │   ├── NetworkInfo.swift
│   │   │   └── TCCInfo.swift
│   │   ├── Collectors/                  # 8 event source implementations
│   │   │   ├── ESCollector.swift        #   Endpoint Security client
│   │   │   ├── ESHelpers.swift          #   ES type conversion
│   │   │   ├── UnifiedLogCollector.swift #  Unified Log stream
│   │   │   ├── TCCMonitor.swift         #   TCC database watcher
│   │   │   ├── NetworkCollector.swift   #   Network connections
│   │   │   ├── DNSCollector.swift       #   DNS query monitor
│   │   │   ├── EventTapMonitor.swift    #   CGEvent tap monitor
│   │   │   ├── SystemPolicyMonitor.swift #  Gatekeeper/XProtect
│   │   │   └── FSEventsCollector.swift  #   FSEvents fallback
│   │   ├── Enrichment/                  # Event enrichment pipeline
│   │   │   ├── EventEnricher.swift      #   Orchestrator
│   │   │   ├── ProcessLineage.swift     #   Process ancestry DAG
│   │   │   ├── CodeSigningCache.swift   #   Code signing info
│   │   │   ├── QuarantineEnricher.swift #   Download provenance
│   │   │   ├── CertTransparency.swift   #   CT log monitoring
│   │   │   ├── ThreatIntelFeed.swift    #   abuse.ch IOC feeds
│   │   │   ├── YARAEnricher.swift       #   YARA file scanning
│   │   │   └── CDHashExtractor.swift    #   Process CDHash extraction
│   │   ├── Detection/                   # Rule evaluation and analysis
│   │   │   ├── RuleEngine.swift         #   Single-event Sigma engine
│   │   │   ├── SequenceEngine.swift     #   Temporal sequence engine
│   │   │   ├── BaselineEngine.swift     #   Anomaly baseline
│   │   │   ├── StatisticalAnomaly.swift #   Welford's z-score detector
│   │   │   ├── BehaviorScoring.swift    #   Per-process suspicion scoring
│   │   │   ├── IncidentGrouper.swift    #   Attack timeline clustering
│   │   │   ├── EntropyAnalysis.swift    #   Shannon entropy / DGA detection
│   │   │   ├── AlertDeduplicator.swift  #   Dedup and rate limiting
│   │   │   ├── SuppressionManager.swift #   Per-rule process allowlists
│   │   │   ├── ResponseAction.swift     #   Kill, quarantine, script, etc.
│   │   │   ├── SelfDefense.swift        #   8-layer tamper protection
│   │   │   ├── RootkitDetector.swift    #   Hidden process detection
│   │   │   ├── CrashReportMiner.swift   #   Exploitation indicator mining
│   │   │   ├── PowerAnomalyDetector.swift # Power/thermal anomaly detection
│   │   │   └── ThreatHunter.swift       #   Natural language threat hunting
│   │   ├── AIGuard/                     # AI coding tool safety
│   │   │   ├── AIToolRegistry.swift     #   Tool identification
│   │   │   ├── AIProcessTracker.swift   #   Process tree tracking
│   │   │   ├── CredentialFence.swift    #   Sensitive file access alerts
│   │   │   ├── ProjectBoundary.swift    #   Directory escape detection
│   │   │   └── PromptInjectionScanner.swift # Injection pattern scanning
│   │   ├── Fleet/                       # Optional fleet telemetry
│   │   │   ├── FleetClient.swift        #   Fleet server enrollment
│   │   │   └── FleetTelemetry.swift     #   Telemetry serialization
│   │   ├── Storage/                     # Persistence and output
│   │   │   ├── AlertStore.swift         #   SQLite alert storage
│   │   │   ├── EventStore.swift         #   SQLite event ring buffer
│   │   │   ├── CommandSanitizer.swift   #   Input sanitization
│   │   │   ├── NotificationOutput.swift #   macOS notification delivery
│   │   │   ├── WebhookOutput.swift      #   JSON POST webhook
│   │   │   └── SyslogOutput.swift       #   RFC 5424 syslog sender
│   │   ├── Output/                      # Report generation
│   │   │   └── ReportGenerator.swift    #   HTML incident reports
│   │   └── Models/
│   │       └── Alert.swift              #   Alert model
│   │
│   ├── MacCrabAgentKit/                 # Shared daemon bootstrap library
│   ├── MacCrabAgent/                    # SystemExtension executable (ships in .systemextension bundle)
│   │   └── main.swift
│   ├── maccrabd/                        # Legacy standalone daemon (dev-only fallback)
│   │   └── main.swift
│   ├── maccrabctl/                      # CLI control tool
│   │   └── main.swift
│   ├── maccrab-mcp/                     # MCP server for AI agent integration
│   │   └── main.swift
│   └── MacCrabApp/                      # SwiftUI menubar app + SystemExtension activator
│       ├── MacCrabApp.swift
│       ├── AppState.swift
│       ├── Views/
│       │   ├── MainView.swift           #   Tab navigation
│       │   ├── AlertDashboard.swift     #   Alert list + detail
│       │   ├── EventStream.swift        #   Live event stream
│       │   ├── RuleBrowser.swift        #   Rule list + toggles
│       │   ├── RuleWizard.swift         #   Rule authoring wizard
│       │   ├── TCCTimeline.swift        #   Permission timeline
│       │   ├── AIActivityView.swift     #   AI tool monitoring
│       │   ├── SettingsView.swift       #   Configuration
│       │   ├── ResponseActionsView.swift #  Response action config
│       │   ├── DocsView.swift           #   Built-in docs
│       │   ├── StatusBarMenu.swift      #   Menu bar interface
│       │   └── Components.swift         #   Shared UI components
│       └── ViewModels/
│           └── ViewModels.swift
│
├── Rules/                               # Sigma-compatible detection rules
│   ├── defense_evasion/
│   ├── credential_access/
│   ├── persistence/
│   ├── supply_chain/
│   ├── execution/
│   ├── discovery/
│   ├── privilege_escalation/
│   ├── ai_safety/
│   ├── command_and_control/
│   ├── lateral_movement/
│   ├── collection/
│   ├── exfiltration/
│   ├── initial_access/
│   ├── tcc/
│   ├── container/
│   ├── impact/
│   └── sequences/
│
├── Compiler/
│   └── compile_rules.py                 # Sigma YAML to JSON compiler
│
├── scripts/
│   ├── dev.sh                           # Development cycle driver
│   ├── bundle-app.sh                    # .app bundle creator
│   ├── install.sh / uninstall.sh        # System-wide install/remove
│   ├── detection-test.sh                # Safe detection trigger tests
│   ├── false-positive-test.sh           # FP regression tests
│   ├── rule-lint.sh                     # YAML rule validation
│   ├── stress-test.sh                   # Event throughput stress test
│   ├── integration-test.sh              # Daemon + CLI integration
│   ├── test.sh                          # Test runner wrapper
│   ├── check_duplicate_ids.py           # UUID uniqueness check
│   ├── coverage_matrix.py               # ATT&CK coverage report
│   └── validate_rules.py               # Rule schema validator
│
├── fleet/                               # Optional fleet server
│   ├── server.py
│   └── requirements.txt
│
└── Tests/
    └── MacCrabCoreTests/
        ├── MacCrabCoreTests.swift       # Core engine tests
        ├── PipelineTests.swift          # Pipeline integration tests
        ├── DeepMacOSTests.swift         # macOS-specific tests
        ├── AIGuardTests.swift           # AI Guard tests
        ├── SuppressionTests.swift       # Suppression manager tests
        └── ForensicTests.swift          # Forensic component tests
```

</details>

---

## Contributing

We welcome contributions of both detection rules and code. See [CONTRIBUTING.md](CONTRIBUTING.md) for full guidelines.

### Rules

Detection rule contributions are especially welcome. Rules are licensed under the [Detection Rule License 1.1](https://github.com/SigmaHQ/Detection-Rule-License) (DRL 1.1). To contribute a rule:

1. Write your rule in Sigma YAML format
2. Place it in the appropriate `Rules/<tactic>/` directory
3. Ensure it has a unique UUID, MITRE ATT&CK tags, and documented false positives
4. Run `make lint-rules` to validate
5. Run `make test-fp` to check for false positives
6. Open a pull request

### Code

Code contributions are licensed under the [Apache License 2.0](LICENSE). We use Swift's structured concurrency model with actors for thread safety. See [CONTRIBUTING.md](CONTRIBUTING.md) for code style guidelines and testing expectations.

---

## License

- **Code**: [Apache License 2.0](LICENSE)
- **Detection Rules** (`Rules/`): [Detection Rule License 1.1 (DRL 1.1)](https://github.com/SigmaHQ/Detection-Rule-License)

---

## Acknowledgments

- [**SigmaHQ**](https://github.com/SigmaHQ/sigma) -- for the Sigma detection rule format and the community-driven rule repository that inspired this project's rule structure
- [**Objective-See Foundation**](https://objective-see.org/) -- for pioneering open-source macOS security research, tools, and reference implementations that informed MacCrab's design
- [**coreSigma (Nebulock)**](https://github.com/nebulock/coreSigma) -- for the pySigma macOS ESF pipeline work that demonstrated Sigma rule evaluation against Endpoint Security events
- [**abuse.ch**](https://abuse.ch/) -- for the open threat intelligence feeds (Feodo Tracker, URLhaus, MalwareBazaar) that power MacCrab's threat intel enrichment
- **Apple Endpoint Security framework** -- for providing the kernel-level visibility that makes real-time detection possible on macOS
