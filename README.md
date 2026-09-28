# MacCrab

**Open, local-first macOS detection & investigation — with first-class visibility into what AI coding agents do on your Mac.** For developers, researchers, and Mac security practitioners.

[![Status](https://img.shields.io/badge/status-alpha-f59e0b)]()
[![Validation](https://img.shields.io/badge/release%20qualification-see%20evidence-blue)](docs/UPGRADE_QUALIFICATION.md)
[![Tests](https://img.shields.io/badge/tests-4853%20passing-brightgreen)]()
[![Rules](https://img.shields.io/badge/rules-486%20(stable%20tier%20on%20by%20default)-blueviolet)](docs/COVERAGE.md)
[![Version](https://img.shields.io/badge/version-1.22.1-blue)](https://github.com/peterhanily/maccrab/releases)
[![Website](https://img.shields.io/badge/site-maccrab.com-e04820)](https://maccrab.com)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![macOS](https://img.shields.io/badge/macOS-13%2B%20(Ventura)-lightgrey)]()
[![Swift](https://img.shields.io/badge/Swift-5.9%2B-F05138)]()

> [!WARNING]
> **Alpha software under active development.** MacCrab ships in public
> alpha and is iterating rapidly on detection quality, UX, and the
> release pipeline. Since v1.21.4 the daemon defaults to the
> curated **stable** rule tier (the broader experimental corpus is
> opt-in via `rule_profile: all` in `daemon_config.json`), so expect
> fewer false positives than earlier alphas — but still occasional rule
> changes and frequent updates. Run it on a Mac you're comfortable debugging
> on. Issue reports and field data are very welcome — they're driving
> most of the current release cadence. See
> [CHANGELOG.md](CHANGELOG.md) for what's shipped recently.

MacCrab is an on-device security engine that monitors your Mac in real time using Apple's Endpoint Security framework, a library of Sigma-compatible detection rules, behavioral scoring, and temporal sequence analysis. Detection runs locally as a native Endpoint Security System Extension with a SwiftUI menubar dashboard -- no cloud console or vendor lock-in. Optional outbound features and the release build's signed update check are documented below. It draws on the same lineage as Sysmon + Sigma on Windows -- rich endpoint telemetry plus transparent, readable detection rules -- adapted to macOS's Endpoint Security framework.

A distinguishing focus is **AI-coding-agent observability**: MacCrab's AI Guard and tamper-evident **Agent Traces** attribute file reads, config writes, MCP calls, and network egress to the specific agent session that caused them -- so when an AI coding tool (Claude Code, Codex, and the like), or a compromised one, touches something sensitive, you have a signed, replayable record. The Endpoint Security detection engine underneath gives that attribution teeth.

It's a tool for reading and operating your own detection logic, not a managed EDR: there's no global adversary telemetry, no managed response, the experimental tier of the rule corpus is opt-in (the daemon defaults to the curated **stable** tier -- see [coverage](docs/COVERAGE.md)), and it ships from a **single-maintainer supply chain** (see [docs/SUPPLY_CHAIN_SECURITY.md](docs/SUPPLY_CHAIN_SECURITY.md)).

**Releases:** Signed, notarized, auto-updating builds ship via Sparkle through [maccrab.com/appcast.xml](https://maccrab.com/appcast.xml). See [CHANGELOG.md](CHANGELOG.md) for the release history.

---

## Quick Start

### Option A: Homebrew (recommended)

```bash
# 1. Install
brew install --cask peterhanily/maccrab/maccrab

# 2. Open the dashboard
open /Applications/MacCrab.app

# 3. Click "Enable Protection" on the Overview screen, then approve the
#    extension in System Settings → General → Login Items & Extensions →
#    Endpoint Security Extensions.
```

> **Homebrew 6.0+:** the fully-qualified cask name (`peterhanily/maccrab/maccrab`) auto-taps the official [`homebrew-maccrab`](https://github.com/peterhanily/homebrew-maccrab) tap and trusts this cask in one step. The bare `--cask maccrab` fails with `Refusing to load cask … from untrusted tap`.

> **Tapped the app repo before?** If you previously ran `brew tap … https://github.com/peterhanily/maccrab` and now hit a `could not apply …` rebase error on update — or `brew install` reports `Cask 'maccrab' is unreadable` / `syntax errors found` — your cached tap clone is stale. Switch to the clean tap, then re-run the install:
>
> ```bash
> brew untap peterhanily/maccrab
> brew install --cask peterhanily/maccrab/maccrab
> ```

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
- **A customizable SwiftUI menubar dashboard** with 10 workspaces -- a security Overview you arrange to taste (show/hide, drag, and resize panels; your layout persists across updates), alert triage with bulk actions, live event stream, campaign timelines, rule browser, AI Guard status, and more
- **CLI threat hunting** -- `maccrabctl hunt "show processes connecting to unusual ports"` for natural-language queries against your event data
- **Behavioral scoring** -- even if no single rule fires at critical severity, accumulated suspicious indicators across a process tree will still trigger an alert
- **Campaign detection** -- multi-step attack chains (download, execute, persist, call home) are correlated across process lineage and time windows
- **AI coding tool guardrails** -- monitors Claude Code, Codex, Cursor, and 6 other AI tools for credential access, project boundary escapes, and prompt injection
- **Forensic plugins + the Rave store** -- run built-in forensic scanners on this Mac, or install signed community plugins from the [Rave store](https://rave.maccrab.com). Every plugin runs sandboxed and declares its read-set + network access for your consent before install
- **Out-of-band rule updates** *(built, not yet provisioned)* -- the signed, anti-rollback channel is implemented end-to-end (`maccrabctl rules update`; pushed rules are detection-only and can never override a built-in rule), but **no rule-channel signing key ships yet**, so the command fails closed on every current build. Detection rules ship with the app until the channel is provisioned — see [`docs/RULE_CHANNEL.md`](docs/RULE_CHANNEL.md)
- **No product analytics by default** -- detection data stays in local SQLite stores; release builds check the signed Sparkle update feed, and opt-in outbound features are documented below

---

## Privacy

MacCrab sends no product-analytics or diagnostic telemetry by default. Detection data is collected and stored locally in SQLite. Signed release builds do make a daily Sparkle feed request to check for updates (development candidates disable automatic checks); that request does not upload detection data. Detection data leaves your machine only when you explicitly enable an outbound feature (a cloud or remote LLM backend, threat-intel feed, fleet telemetry, or a third-party forensic plugin whose declared network access you approve). Cloud/remote LLM traffic uses `SecureURLSession`, a TLS 1.2 floor, configured SPKI pins, and best-effort `LLMSanitizer` redaction. Other opt-in integrations have their own documented payload and transport policies; they do not pass through the LLM sanitizer. The LLM redaction scope is documented under [Detection Stack → LLM Reasoning Backends](#detection-stack).

**Network threat-intel enrichment is off by default.** The feeds that make outbound requests -- abuse.ch (URLhaus / MalwareBazaar / Feodo Tracker), OSV / npm package checks, package-freshness lookups, and Certificate-Transparency lookups -- are **opt-in** and require explicit enablement (`threat_intel_enabled`, `vuln_scan_enabled`, `package_freshness_enabled`, `cert_transparency_enabled`; all default `false`). The bundled IOCs work offline until you turn a feed on, and local detection (rules, sequences, campaigns) is unaffected by these toggles.

Read the full [Privacy Policy](PRIVACY.md).

---

## Security

MacCrab's detection engine runs as a System Extension (a sandboxed userspace process managed by `sysextd`, as required for Endpoint Security). The CLI and dashboard run as your user with read-only database access. The engine protects its own integrity with 8 layers of tamper detection including binary integrity checks, anti-debug, and process injection detection.

To report a vulnerability, **do not open a public issue** -- email maccrab@peterhanily.com instead.

**Supply chain.** Releases are a single-maintainer pipeline: one Developer ID signing identity and one Sparkle EdDSA auto-update key, both in the maintainer's keychain. That's a real single point of failure — [docs/SUPPLY_CHAIN_SECURITY.md](docs/SUPPLY_CHAIN_SECURITY.md) documents the current state honestly, the post-compromise incident playbook, and the hardening roadmap; [docs/TRUST.md](docs/TRUST.md) shows how to independently verify any release.

Read the full [Security Policy](SECURITY.md).

---

## Storage Footprint and Performance

MacCrab keeps detection data locally, and on an actively-used machine that adds up. Be aware of the on-disk footprint before you run it on a space-constrained Mac.

**Disk (default steady-state database-family budgets):**

| Store | Cap | Notes |
|-------|----:|-------|
| `events.db` | 376 MiB | Event journal and search projection. The default hot tier is 30 minutes; recent process events have a soft 60-minute retention floor. |
| `alerts.db` | 200 MiB | Alerts, analyst metadata, and new trigger evidence; includes the 100 MiB evidence allocation. |
| `campaigns.db` | 50 MiB | Detected attack campaigns. |
| `tracegraph.db` | 250 MiB | Causal-graph entity/edge substrate. |
| `traces.db` | 100 MiB | Agent/OTLP spans when enabled. |

These budgets total **976 MiB**, with smaller actual use on light workloads.
Database-family accounting includes SQLite sidecars. An upgrade may retain
up to another 100 MiB temporarily while legacy evidence remains in `events.db`.
An unfinished legacy event-store upgrade can also use a fixed temporary
allowance measured before migration. The same allowance survives restarts;
startup restores the configured cap and proves write readiness before monitoring
starts. Physical free-space checks and protected-history limits still apply.
Forensic cases, exported bundles, reports, and logs are additional storage, so
976 MiB is not a cap on the entire support directory. Budgets are tunable under
the `storage` block in `daemon_config.json`; size pressure can shorten retention.
See [KNOWN_LIMITS.md](KNOWN_LIMITS.md) for transition and admission behavior and
[upgrade qualification](docs/UPGRADE_QUALIFICATION.md) for the migration contract.

> **History:** Before v1.18, `tracegraph.db` had no retention sweep and could grow without bound — it was **field-observed at 17 GB**. v1.18 added time-based retention, a size cap, and an orphan sweep; v1.19 made all caps configurable. If you ran a pre-v1.18 build, a one-time prune reclaims the space on first launch.

**Power and CPU:** the engine is event-driven and idles cheaply, but on a busy host the Unified Log collector, periodic SQLite WAL checkpoints, and FTS5 re-indexing do real work. MacCrab gates background-intensive work under battery/thermal pressure (`PowerGate`). On a battery-critical or low-disk Mac you can disable optional monitors (clipboard, USB, ultrasonic, EDR scan, etc.) in `daemon_config.json`.

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
| [docs/AUTHORIZATION_MODEL.md](docs/AUTHORIZATION_MODEL.md) | Daemon control-plane authorization — inbox IPC, who can mutate the engine, audit log, self-protection alerts |
| [docs/SUPPORTED_OS.md](docs/SUPPORTED_OS.md) | Supported macOS matrix — minimum (Ventura 13), tested target (macOS 26), macOS 27 risks |
| [docs/DATA_SCHEMA_STABILITY.md](docs/DATA_SCHEMA_STABILITY.md) | On-disk SQLite schema stability statement — use the export interfaces, not direct DB reads |
| [docs/PLUGIN_AUTHORING.md](docs/PLUGIN_AUTHORING.md) | Authoring a sandboxed forensic plugin for the Rave store — manifest, least-privilege read-set, signing |
| [docs/TRUST.md](docs/TRUST.md) | End-user verification — SHA256, code signature, notarization, Sparkle signature, and the plugin trust chain |
| [docs/SUPPLY_CHAIN_SECURITY.md](docs/SUPPLY_CHAIN_SECURITY.md) | How releases and plugins are signed, and the supply-chain threat model |
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
maccrabctl mcp list                     # MCP server inventory (user-scope configs)
maccrabctl extensions --suspicious      # Browser extension scan
```

---

## MCP Server

MacCrab ships a built-in [Model Context Protocol](https://modelcontextprotocol.io/) server (`maccrab-mcp`) that lets AI coding tools query your security data directly from the editor.

**Setup — installed build (Homebrew / DMG).** `maccrab-mcp` ships inside
`MacCrab.app` and is symlinked onto your `$PATH` by the cask and the installer,
so there is nothing to build. Register it with Claude Code:

```bash
claude mcp add maccrab -- "$(which maccrab-mcp)"
```

For Claude Desktop, add the same command to
`~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "maccrab": { "command": "/usr/local/bin/maccrab-mcp" }
  }
}
```

**Setup — source checkout.** Build the binary with
`swift build --target maccrab-mcp`, then copy `.mcp.json` from the repo root
into your project; it points at the local `.build/debug/maccrab-mcp`.

**Available tools — 67 built-in** (including the 20 always-present `forensics_*` case/plugin meta-tools) **plus per-plugin tools contributed by installed forensic plugins** (31 on a default install: `launchd_*`, `tcc_*`, `safari_*`, `mail_*`, `imessage_*`, `*_analyze_path`, …) **— 98 total here.** Neither `maccrabctl mcp list` (which inventories MCP *server configs*, not tools) nor `agent_capabilities` (which reports control-plane capability tiers) prints a tool list; ask your MCP client for its tool inventory. A representative slice:

| Tool | Purpose |
|------|---------|
| `get_alerts` | Query alerts with severity, time, and suppression filters |
| `get_alert_detail` | Full detail for one alert: LLM investigation, d3fend techniques, remediation hint |
| `cluster_alerts` | Group recent alerts by rule + process fingerprint for triage |
| `get_events` | Search events by category, keyword, or time window |
| `get_campaigns` | List detected attack campaigns with contributing alerts |
| `suppress_alert` | Suppress a false-positive alert by ID (audit-logged) |
| `suppress_campaign` | Suppress a campaign and all its contributing alerts at once |
| `get_ai_alerts` | AI Guard alerts (credential / boundary / injection / MCP) |
| `scan_text` | Check untrusted text for prompt injection before your AI tool acts on it |
| `get_status` | Daemon status, rule count, uptime, database size |
| `hunt` | Natural-language threat hunting across all stored events |
| `get_security_score` | Security posture score (0–100) with per-factor breakdown |
| `get_traces` | (v1.10) List recent causal traces from the TraceGraph store |
| `get_trace_detail` | (v1.10) Full trace with anchor + members + hash chain |
| `hunt_trace` | (v1.10) Substring search across traces |
| `verify_bundle` | (v1.10) Verify a `.maccrabtrace` bundle (schema, Merkle, signature) |
| `trace_from_event` | (v1.10) Pivot from an event id to its containing trace |
| `list_rules` | (v1.21.6) The compiled Sigma corpus, annotated with whether each rule is actually loaded under the active profile and whether it has ever been evaluated |
| `explain_alert` | (v1.21.6) Why one alert fired: the rule, its compiled predicate, logsource and status |
| `get_vulns` | (v1.21.6) Vulnerability findings from the osv.dev lookup (off by default) |
| `get_privacy_alerts` | (v1.21.6) Privacy-auditor findings: bulk egress, domain spikes, tracker contacts |
| `get_browser_extensions` | (v1.21.6) Installed extensions with risk score, dangerous permissions and dev-mode status |
| `check_typosquat_score` | (v1.12) Score a package name against bundled top corpora (Damerau-Levenshtein + Unicode confusable fold) |
| `scan_package_content` | (v1.12) Walk an installed package dir for obfuscation markers / single-line bundles / Mach-O drops |
| `analyze_package_metadata` | (v1.12) Inspect a package's registry metadata (versions, maintainer age, download anomalies) |
| `verify_package_attestation` | (v1.12) Check Sigstore / PEP 740 provenance attestations |
| `classify_package_intent` | (v1.12) LLM-backed verdict over a package-install BehaviorBrief |
| `predict_next_technique` | (v1.12) Markov-1 forecast over MITRE tactics |
| `score_text_style` | (v1.12) Stylometric / urgency / LLM-tells score on a commit message or PR body |
| `get_intent_posterior` | (v1.12) Bayesian posterior over attacker goals for a process tree — reads the daemon-recorded `maccrab.intent.bayesian-posterior` alerts from the last 30 days, matching the tree key (`<root executable>@<pid>`) by substring |
| `list_response_actions` | List configured per-rule response actions and their current settings |
| `set_response_action` | Adjust a rule's response action (audit-logged; requires the matching capability tier) |
| `forensics_*` | Built-in case/plugin meta-tools, always present — e.g. `forensics_run_collector`, `forensics_run_analyzer`, `forensics_enrich`, `forensics_search_artifacts`, `forensics_timeline`, `forensics_explain_case` (underscore-named since v1.19.1; legacy `forensics.*` dotted names still accepted as aliases) |
| `launchd_*` / `tcc_*` / `safari_*` / `mail_*` / `imessage_*` / `*_analyze_path` | Per-plugin tools registered dynamically from installed forensic plugins — the actual variable-count family; present only when the corresponding plugin is installed |

**Slash commands** (`.claude/commands/`): `/security-check`, `/threat-hunt <query>`, `/alerts`.

---

## Uninstall

### Homebrew

```bash
brew uninstall --cask maccrab
```

Before uninstalling, use **Remove System Extension** in MacCrab's Settings and
approve the macOS request. Wait for removal to complete; reboot first if macOS
requires it. `systemextensionsctl list` should no longer show a MacCrab
extension entry, including a pending-removal entry. Then run the Homebrew command above. The cask removes the app and CLI
binaries but does not itself request extension deactivation, since the same
uninstall steps also run during upgrades.

### Manual / source build

```bash
sudo ./scripts/uninstall.sh
```

The script requests deactivation through the installed app and verifies that
macOS has removed the extension before stopping development processes or
removing binaries. Pending approval, cancellation, reboot, or an unverifiable
status leaves the app and data intact; complete removal and rerun the script.
It then asks before deleting support data. `-y` skips that data-deletion prompt,
but cannot bypass extension-removal verification.

Only after extension removal is complete and development daemons, the dashboard,
and MCP clients have stopped, user-level data can also be removed:

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

MacCrab ingests from 16 real-time collectors (the full list, with poll intervals, is in the [Monitors and Collectors](#monitors--collectors) table below), covering kernel-level process activity through application-layer permissions. The primary sources:

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

See the Monitors and Collectors table below for the full list including USB, clipboard, ultrasonic, rootkit, browser extension, MCP, EDR/RMM, and an SDR-device monitor.

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
| ClipboardMonitor | Clipboard content + injection detection | 3s |
| UltrasonicMonitor | DolphinAttack/NUIT audio injection | Configurable |
| RootkitDetector | Dual-API process cross-reference | 120s |
| EventTapMonitor | Keylogger detection | 30s |
| SystemPolicyMonitor | SIP, XProtect, MDM, auth plugins | 300s |
| BrowserExtensionMonitor | Chrome/Firefox/Brave/Edge/Arc extensions | Startup, then 120s |
| MCPMonitor | MCP server configs across AI tools | Startup, then 60s |
| GitSecurityMonitor | Git credential-helper abuse, SSH-agent hijack, malicious git hooks | Real-time |
| SDRDeviceMonitor | SDR USB devices + rapid display hotplug (no electromagnetic analysis) | 60s |

Poll intervals are the defaults from `DaemonConfig.swift`; most are tunable in
`daemon_config.json`. All of them are stretched under battery or thermal
pressure by `PowerGate.adjustedInterval`, so observed latency can exceed the
figure above on an unplugged or hot machine.

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

Monitors AI coding tool processes for unsafe behavior. Identifies Claude Code, Codex, OpenClaw, Cursor, Aider, Copilot, Continue.dev, Windsurf, and Kiro IDE by executable path and process ancestry.

| Component | Description |
|-----------|-------------|
| **AI process tracker** | Identifies and tracks AI tool processes and their child process trees |
| **Credential fence** | Alerts when AI tool children access any of 29 sensitive path patterns (SSH keys, `.env` files, AWS credentials, keychains, browser credential stores, kubeconfig, and more) |
| **Project boundary enforcement** | Detects when AI tools read or write files outside the current project directory |
| **Prompt injection scanner** | Native structural scan of files AI tools read — invisible/zero-width unicode, bidi overrides (Trojan Source), and Unicode tag-character smuggling. No external dependency. |
| **Activity by tool** | Dashboard AI Guard tab shows a live per-tool alert breakdown (credential / injection / boundary / other) sorted by severity |

32 dedicated AI safety detection rules in `Rules/ai_safety/`. Use the `scan_text` MCP tool to proactively check untrusted input before your AI tool acts on it.

</details>

<details>
<summary><strong>Agent Traces — intent ↔ effect correlation (click to expand)</strong></summary>

Agent Traces (v1.9, expanded in v1.10) closes the gap between what an AI coding agent *said* it was doing (its LLM prompts, tool calls, and OpenTelemetry spans) and what its child processes *actually* did at the kernel level (Endpoint Security exec / file / network events).

This brings AgentSight-style correlation ([arXiv:2508.02736](https://arxiv.org/abs/2508.02736), which implements the idea on Linux via eBPF) to macOS via the Endpoint Security framework plus a built-in OTLP receiver.

**How it works:**

1. **TRACEPARENT in process env** — when an AI coding tool spawns a child, MacCrab's ES collector reads the `TRACEPARENT` W3C trace-context value from the exec env block. The trace ID binds every descendant process to the originating LLM turn.
2. **Loopback OTLP receiver** — MacCrab listens on `127.0.0.1:4318` (the OTel-canonical OTLP/HTTP port) for spans emitted by the AI tool's instrumentation. Loopback only — never routable from off-host. Off by default; enable from **Settings → Agent Traces** in the dashboard, or set `receiverEnabled: true` in `<supportDir>/agent_traces_config.json`.
3. **Span sanitisation** — incoming OTLP spans pass through `OTLPAttributeSanitizer` before storage: prompt text, file paths, command output, and any value matching a credential / API-key shape gets redacted. Span IDs + structural attributes survive so correlation still works.
4. **Causal graph storage** — spans + bound kernel events land in `tracegraph.db` (SQLite, AES-GCM column-level encryption, `0o660`). Each materialized trace appends one entry to an **append-only continuity hash chain** in the DB (`verifyHashChain()` flags a mutated, deleted, reordered, or inserted ledger row), and each exported bundle gets a **daemon-signed Merkle root** over its members. This is tamper-**evident**: it is forgery-resistant against a non-root attacker and verifiable by a party holding an out-of-band pinned key — local root can rewrite and re-sign and is out of scope (see [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) and [`docs/maccrabtrace.v1.spec.md` §6.4](docs/maccrabtrace.v1.spec.md)). An optional macOS unified-log record of each signed chain head acts as an independent witness (wired; its cross-run read-back is pending on-device verification).
5. **Investigation surface** — the dashboard's Investigation → TraceGraph workspace renders the trace as a hub-and-spoke graph (anchor in centre, members on a ring); each member shows what kernel side-effect ran under that span. The `maccrabctl trace export` CLI emits a signed `.maccrabtrace` bundle that `verify_bundle` (MCP) or `maccrabctl trace verify` can re-check offline. Signing reads key material from `<supportDir>/keys/`, which is root-owned (`drwx------`) on a release install: run the export under `sudo`, or export from MacCrab.app, for a **daemon-signed** bundle. Without root the CLI falls back to a user-domain signing key under `~/Library/Application Support/MacCrab/keys/` — the bundle still exports and self-verifies, but it is not signed by the daemon identity a relying party would have pinned; if that key is unusable too the export carries the honest `UNSIGNED` placeholder, which `maccrabctl trace verify` rejects.

**Five MCP tools** (`get_traces`, `get_trace_detail`, `hunt_trace`, `verify_bundle`, `trace_from_event`) let an AI assistant pivot from any single event back to its containing trace and the agent turn that produced it.

</details>

<details>
<summary><strong>LLM Reasoning Backends (click to expand)</strong></summary>

MacCrab integrates optional LLM backends for structured alert investigations, campaign summaries, defense recommendations, package-intent refinement, and CLI threat-hunt translation. Model output is advisory; it never executes a response action. Features fall back or remain unavailable when no backend is configured.

**Outbound traffic posture** — every cloud-LLM request goes through `SecureURLSession`, which enforces a **TLS 1.2 minimum** floor and applies **SPKI certificate pinning by default** for providers that ship pins, validating the SHA-256 SPKI hash of the leaf or intermediate cert. Set `MACCRAB_TLS_PINNING=off` or `=warn` to downgrade to warn-only (OS trust store) for stale-pin recovery; `=strict` is a no-op for hosts without configured pins. TLS 1.2 enforcement remains on for every provider regardless of the pinning mode.

**Sanitiser scope** — `LLMSanitizer.sanitize(_:)` runs before a cloud or remote LLM payload leaves the box and redacts:

- **API keys / bearer tokens** — Anthropic (`sk-ant-…`), OpenAI (`sk-…`), Stripe-style (`pk_…`/`sk_…`), generic high-entropy 32–64 char tokens, `Bearer <token>` headers
- **User paths** — `/Users/<name>/…` → `/Users/<redacted>/…`; same for `~`-form paths
- **Computer + host names** — local `gethostname()` value + any `*.local` / `*.lan` reference
- **IP addresses** — private, link-local, loopback, and remaining public IPv4/IPv6 literals (safe over-redaction is preferred to leaking an IOC)
- **Email addresses** — RFC-5322 shape
- **CDHashes** — 40-char hex strings (over-redacts but preferred to leaking process identity)

The sanitiser runs for every cloud or remote endpoint. It is intentionally skipped only for a trusted, explicitly local loopback Ollama configuration; a remote Ollama URL or a loopback URL delivered over the untrusted control plane is sanitized too.

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
| **Natural language threat hunting** | `maccrabctl hunt "<query>"` against the local event and alert stores |
| **Structured alert investigations** | At most one post-commit investigation per triggering event, attached to a stored HIGH/CRITICAL alert |
| **Campaign summaries** | Optional advisory summary stored as `maccrab.llm.investigation-summary` when a campaign fires |
| **Active defense recommendations** | Generated alongside campaign alerts; stored as `maccrab.llm.defense-recommendation` alert |
| **Package-intent refinement** | Bounded asynchronous tie-breaker for ambiguous AI-attributed package installs |

Campaign-to-rule candidate generation exists as experimental code, but it is not a production LLM feature or an automatic install path. Generated source is never trusted or enabled without compilation and the normal rule-install controls.

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
| `blockNetwork` | Writes a temporary destination rule into the dedicated `com.maccrab.response` PF anchor (requires the privileged engine / root). **Not enforcing by default** — PF must be enabled and the active main ruleset must reference that anchor. MacCrab configures neither. Failed or unverified actions report failure; expiry retries independently of new alerts. See [PREVENTION_RESEARCH.md](PREVENTION_RESEARCH.md#maccrab-current-usage), including the legacy shared-anchor migration requirement. |
| `escalateNotification` | Send a high-priority macOS notification with the alert's action details |

</details>

---

## Rule Coverage by MITRE ATT&CK Tactic

<!-- COVERAGE-START -->
<!-- Auto-generated by `scripts/coverage_matrix.py --update-readme`.
     Edit the rule YAML, then run `make readme-coverage` to regenerate. -->

Rules live under `Rules/<tactic>/` as Sigma-compatible YAML. The current
release ships **486 rules** (438 single-event + 41 sequence + 7 graph)
covering **170 unique MITRE ATT&CK techniques** across the macOS-relevant
tactics:

| MITRE ID | Tactic | Rule count |
|---|---|---:|
| `TA0001` | Initial Access | 101 |
| `TA0002` | Execution | 94 |
| `TA0003` | Persistence | 103 |
| `TA0004` | Privilege Escalation | 43 |
| `TA0005` | Defense Evasion | 127 |
| `TA0006` | Credential Access | 85 |
| `TA0007` | Discovery | 37 |
| `TA0008` | Lateral Movement | 25 |
| `TA0009` | Collection | 38 |
| `TA0010` | Exfiltration | 34 |
| `TA0011` | Command and Control | 53 |
| `TA0040` | Impact | 27 |
| — | **Sequences** (temporal multi-step) | **41** |
| — | **Graph** (multi-entity TraceGraph) | **7** |
| — | **Total** | **486** |

Counts are derived from the YAML tree at release time — see
[`docs/COVERAGE.md`](docs/COVERAGE.md) for the rule-by-technique
breakdown. To regenerate this section after editing rules: `make readme-coverage`.
<!-- COVERAGE-END -->

---

## Output Targets

| Target | Format |
|--------|--------|
| **CLI stdout** | Human-readable colored output with severity indicators |
| **JSONL file** | One JSON object per line, suitable for log ingestion pipelines |
| **macOS notifications** | Native `UserNotifications` alerts for high and critical severity |
| **Webhook** | JSON POST to a configurable URL for integration with Slack, Teams, PagerDuty |
| **Syslog** | RFC 5424 structured data over UDP/TCP for forwarding to any syslog receiver |
| **Fleet telemetry** | Optional enrollment with a fleet server for centralized multi-host visibility (self-hosted prototype; outbound-only) |

---

## SwiftUI Dashboard

A native status bar application whose dashboard is a workspace shell — a sidebar, top bar, and workspace area with a command bar / palette and a UIMode density toggle (**Basic / Standard / Advanced**) across 10 workspaces. The **Overview is customizable**: click *Customize* to show/hide, drag-reorder, and resize panels; your layout is saved and persists across app updates.

<details>
<summary><strong>All dashboard workspaces (click to expand)</strong></summary>

| Workspace | Description |
|------|-------------|
| **Overview** | At-a-glance system posture and shortcuts — a customizable panel grid (show/hide, drag, resize; layout persists) |
| **Alerts** | Triage and route findings — multi-select, bulk suppress, inline actions |
| **Events** | Live event stream with filter / search / drill-in |
| **Investigation** | Trace graph + AI analysis |
| **Forensics** | Scan this Mac, browse plugins, export evidence |
| **Detection** | Rules, AI Guard, browser extensions, MCP |
| **Prevention** | DNS sinkhole, network blocker, persistence guard, response actions |
| **Intelligence** | IOC context, feeds, packages, integrations |
| **System** | Platform health, permissions (TCC), trust, settings |
| **Docs** | In-app documentation |

</details>

---

## Forensic Plugins & the Rave Store

Beyond live detection, MacCrab's **Forensics** workspace runs forensic scanners on
this Mac — built-in collectors and analyzers plus optional community plugins.

- **[Rave store](https://rave.maccrab.com)** — browse and install signed community
  forensic plugins. Every plugin is Ed25519-signed, runs **fully sandboxed**
  (a least-privilege `sandbox_init` profile + a brokered file-descriptor model),
  and declares its read-set + network access so you consent **before** install.
- **[maccrab-plugin-reference](https://github.com/peterhanily/maccrab-plugin-reference)**
  — what a good plugin looks like: reproducible, least-privilege, author-signed.
  Copy it to start your own.
- **[maccrab-rave-submissions](https://github.com/peterhanily/maccrab-rave-submissions)**
  — the community submission + vetting path. Submit a plugin there for review.

The trust model is the same one MacCrab applies to itself: signed, anti-rollback,
revocable, and sandboxed. See [docs/PLUGIN_AUTHORING.md](docs/PLUGIN_AUTHORING.md)
and [docs/TRUST.md](docs/TRUST.md).

---
## What's New

This source tree targets **v1.22.1**. See [CHANGELOG.md](CHANGELOG.md) for the full
dated version history and [RELEASE_NOTES/](RELEASE_NOTES/) for per-release detail.
Recent milestones:

- **v1.22.1** — fixes legacy event-store upgrades blocked by a lowered storage
  cap, using a fixed temporary allowance that survives Mac restarts and is
  retired before monitoring starts, and an event-processing crash on macOS 14;
  shows migration progress
  and a visible menu-bar warning when protection is not confirmed; distinguishes
  queued rule reloads from confirmed completion and reconnects the dashboard
  automatically after migration. Preserves the predecessor's default
  50-row allowance for legacy alert evidence during background cleanup.
- **v1.22.0** — fixed a crash on the enrichment-timeout path; event storage now
  reclaims already-freed space and expired events are reliably reclaimed;
  the notification channel now starts without a window open; network-blocking
  reports whether it is actually enforcing; honest collector-health reporting.
- **v1.21.5** — sequence and graph rules now honor the rule profile (six must-fire
  kill-chain sequences promoted to the stable tier); a verified first-run setup
  checklist with a workspace-density picker; Package Freshness and the intent MCP
  tool report real data instead of placeholders; fleet telemetry is strictly
  outbound-only over HTTPS.
- **v1.21.4** — the daemon now defaults to the curated **stable** rule tier (fewer
  false positives; the experimental corpus is opt-in via `rule_profile: all`);
  bulk alert actions with undo; full-history event-category filtering; a real
  causal Investigation graph; and prevention-module toggles.
- **v1.21.3** — a broker-client SDK so sandboxed store plugins read their declared
  files; catalog Installed/Update state; and one-click Run for installed store
  plugins.
- **v1.21.0** — customizable masonry Overview with new Protection Coverage, Top
  Firing Rules, and companion-crab widgets; Forensics CLI ↔ MCP parity; honest
  engine-health reporting on the dashboard.
- **v1.20** — customizable Overview dashboard, the signed out-of-band rule channel
  (`maccrabctl rules update` — implemented, not yet provisioned with a signing key),
  and the live [Rave plugin store](https://rave.maccrab.com).
- **v1.12** — supply-chain detection wave (Shai-Hulud worm class), a Bayesian
  intent posterior, and a ~1000× faster daemon cold start.
- **v1.10** — workspace dashboard, visual TraceGraph, Agent Traces (intent ↔
  effect correlation), and hardened mutation IPC.
- **v1.3** — native Endpoint Security via System Extension (the architecture every
  commercial macOS EDR uses).

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
make clear-data       Delete all local data (events, alerts, campaigns, traces)
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
make test-burst        # Burst benchmark -- fails on priority-stream event drops
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
2. Build all 8 SPM targets (`MacCrabCore`, `MacCrabForensics`, `MacCrabAgentKit`, `MacCrabAgent`, `maccrabd`, `maccrabctl`, `maccrab-mcp`, `MacCrabApp`) with `swift build -c release`
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
│   │   │   ├── NotificationOutput.swift #   daemon notification gate (logging only; app delivers banners)
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
- **AgentSight** ([arXiv:2508.02736](https://arxiv.org/abs/2508.02736)) -- for demonstrating that an AI coding agent's intent (LLM prompts, tool calls, OTel spans) can be correlated against the kernel events its child processes produce. AgentSight implements this on Linux via eBPF; MacCrab v1.9.0's Agent Traces feature brings the same correlation idea to macOS via the Endpoint Security framework plus a loopback OTLP receiver
- **Apple Endpoint Security framework** -- for providing the kernel-level visibility that makes real-time detection possible on macOS
