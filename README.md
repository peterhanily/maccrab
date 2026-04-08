# MacCrab

**Local-first macOS threat detection engine -- Sigma rules, temporal sequences, AI safety, and behavioral scoring with no cloud required**

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)]()
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-macOS%2013%2B-lightgrey)]()
[![Rules](https://img.shields.io/badge/detection%20rules-343-orange)]()
[![Version](https://img.shields.io/badge/version-v1.0.0-blue)]()
[![Swift](https://img.shields.io/badge/Swift-5.9%2B-F05138)]()

---

MacCrab is an on-device security detection engine for macOS. It evaluates 343 Sigma-compatible detection rules against real-time kernel events, Unified Log streams, TCC permission changes, DNS queries, and network connections -- entirely on your machine, with no SIEM, no cloud infrastructure, and no telemetry leaving the host.

What sets it apart from other open-source macOS tools:

- **Temporal-causal sequence detection** -- correlate ordered chains of events (download, execute, persist, call home) within time windows and across process lineage, not just individual indicators.
- **AI coding tool guardrails** -- monitor Claude Code, Codex, Cursor, and other AI agents for credential access, project boundary escapes, and prompt injection patterns.
- **Behavioral scoring** -- accumulate weighted suspicion per process so that sophisticated attacks distributed across many small actions still trigger alerts, even when no single rule fires at critical severity.
- **Threat intelligence enrichment** -- match file hashes, IPs, and domains against abuse.ch feeds (Feodo, URLhaus, MalwareBazaar) in real time.

Think of it as what Sysmon + Sigma + a lightweight SIEM provides on Windows -- but native to macOS, running as a single daemon with a SwiftUI dashboard.

---

## What's New in v1.0.0

- 343 Sigma-compatible detection rules (316 single-event + 27 sequences)
- 5-tier detection hierarchy (rules, sequences, anomaly, campaigns, cross-process)
- LLM reasoning backends: Ollama, Claude, OpenAI-compatible, Gemini, Mistral
- NL threat hunting, LLM investigation summaries, active defense recommendations
- AI Guard monitoring 8 coding tools + MCP servers
- Zero-entitlement kernel events via eslogger proxy
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

---

## Architecture

```
                             MacCrab Detection Pipeline

 +--------------------+     +---------------------+     +----------------------+
 |   Event Sources    |     |    Enrichment       |     |     Detection        |
 |                    |     |                     |     |                      |
 | ES Framework  ----------> Process Lineage DAG  |     | Single-Event Rules   |
 | Unified Log   ----------> Code Signing Cache   |     |   (282 Sigma YAML)   |
 | TCC Monitor   ----------> Quarantine Origin    +---->| Sequence Rules (22)  |
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

## Event Sources

MacCrab ingests from eight real-time event sources, covering kernel-level process activity through application-layer permissions:

| Source | What it captures |
|--------|------------------|
| **Endpoint Security framework** | 90+ kernel event types: process exec/fork/exit, file create/write/rename/unlink, signal delivery, kext loading, mmap, iokit operations |
| **Unified Log** | Real-time streaming from 12 subsystems (`com.apple.securityd`, `com.apple.authd`, `com.apple.xpc`, `com.apple.install`, and 8 more) |
| **TCC permission monitor** | Polls system and user TCC databases for grants/revocations to accessibility, full disk access, screen recording, camera, microphone, and more |
| **Network connection collector** | Outbound TCP/UDP connections with destination IP, port, hostname resolution, and owning process attribution |
| **DNS collector** | DNS query/response monitoring for DGA detection, tunneling, and domain reputation checks |
| **Event Tap monitor** | CGEvent tap monitoring for keylogger detection and suspicious input recording |
| **System Policy monitor** | Gatekeeper, XProtect, and notarization enforcement activity |
| **FSEvents fallback** | File system event stream for coverage when ES file events are unavailable |

---

## Detection Stack

### Rules (343 compiled)

| Layer | Count | Description |
|-------|:-----:|-------------|
| **Single-event Sigma rules** | 316 | Standard Sigma YAML compiled to JSON predicates, evaluated per event in real time |
| **Temporal sequence rules** | 27 | Multi-step ordered rules with time windows, process lineage correlation, and causal chaining |

### Analysis Engines

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

### AI Guard

Monitors AI coding tool processes for unsafe behavior. Identifies Claude Code, Codex, OpenClaw, Cursor, Aider, Copilot, Continue.dev, and Windsurf by executable path and process ancestry.

| Component | Description |
|-----------|-------------|
| **AI process tracker** | Identifies and tracks AI tool processes and their child process trees |
| **Credential fence** | Alerts when AI tool children access any of 28 sensitive path patterns (SSH keys, `.env` files, AWS credentials, keychains, browser credential stores, kubeconfig, and more) |
| **Project boundary enforcement** | Detects when AI tools read or write files outside the current project directory |
| **Prompt injection scanner** | Scans for injection patterns in files read by AI tools |

19 dedicated AI safety detection rules in `Rules/ai_safety/`.

### LLM Reasoning Backends

MacCrab integrates pluggable LLM backends for threat hunting, investigation summaries, and adaptive rule generation. All features degrade gracefully when no backend is configured. Cloud providers receive automatic privacy sanitization (usernames, private IPs, and hostnames are redacted before transmission).

| Backend | Config | Use case |
|---------|--------|----------|
| **Ollama** (recommended) | `MACCRAB_LLM_PROVIDER=ollama` | Fully local, zero cloud dependency — best for privacy-sensitive environments |
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

All LLM settings can be configured in **Settings → AI Backend** in the dashboard, or via `daemon_config.json`.

### Threat Intelligence

| Feed | IOC type | Update interval |
|------|----------|:---------------:|
| **abuse.ch Feodo Tracker** | C2 IP addresses | 4 hours |
| **abuse.ch URLhaus** | Malicious URLs and domains | 4 hours |
| **abuse.ch MalwareBazaar** | Malicious file hashes (SHA-256) | 4 hours |
| **Custom IOC lists** | User-provided hashes, IPs, domains | On change |

### Enrichment Pipeline

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

### Self-Defense (8 layers)

The daemon protects its own integrity with continuous tamper detection:

1. **Binary integrity** -- SHA-256 hash at startup, periodic recheck
2. **Rules integrity** -- directory hash of compiled rules
3. **Config file monitoring** -- dispatch source watches for modification
4. **Database tamper detection** -- integrity checks on event/alert stores
5. **Anti-debug** -- detects debugger attachment via `sysctl` checks
6. **Signal interception** -- monitors SIGKILL/SIGTERM from non-system sources
7. **LaunchDaemon plist watch** -- alerts on plist removal or modification
8. **Process injection detection** -- detects attempts to inject into the daemon

### Suppression Manager

Per-rule process allowlists loaded from `suppressions.json`. Operators can suppress known false positives without disabling rules entirely:

```json
{
    "maccrab.deep.event-tap-keylogger": ["/usr/libexec/universalaccessd"],
    "rule-id": ["/path/to/safe/process"]
}
```

The CLI (`maccrabctl suppress`) writes to the same file. The daemon checks suppressions before emitting alerts.

### Response Actions

Rules can trigger configurable response actions ranging from passive to active:

| Action | Description |
|--------|-------------|
| `log` | Always on -- write to alert store and JSONL |
| `notify` | macOS notification banner |
| `kill` | Terminate the process that triggered the alert |
| `quarantine` | Move the triggering file to a quarantine vault |
| `script` | Run a custom shell script with alert context as environment variables |
| `blockNetwork` | Block the network connection (requires Network Extension) |

---

## Rule Coverage by MITRE ATT&CK Tactic

| Tactic | Directory | Single-Event | Sequences | Total |
|--------|-----------|:------------:|:---------:|:-----:|
| Defense Evasion | `defense_evasion/` | 55 | -- | 55 |
| Credential Access | `credential_access/` | 32 | -- | 32 |
| Supply Chain | `supply_chain/` | 31 | -- | 31 |
| Persistence | `persistence/` | 30 | -- | 30 |
| Execution | `execution/` | 28 | -- | 28 |
| AI Safety | `ai_safety/` | 19 | -- | 19 |
| Command and Control | `command_and_control/` | 17 | -- | 17 |
| Privilege Escalation | `privilege_escalation/` | 16 | -- | 16 |
| Lateral Movement | `lateral_movement/` | 16 | -- | 16 |
| Discovery | `discovery/` | 16 | -- | 16 |
| Collection | `collection/` | 15 | -- | 15 |
| Exfiltration | `exfiltration/` | 11 | -- | 11 |
| Initial Access | `initial_access/` | 10 | -- | 10 |
| Container | `container/` | 8 | -- | 8 |
| TCC Abuse | `tcc/` | 6 | -- | 6 |
| Impact | `impact/` | 6 | -- | 6 |
| Temporal Sequences | `sequences/` | -- | 27 | 27 |
| **Total** | | **316** | **27** | **343** |

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

Additional views: Settings → AI Backend (LLM provider configuration), Response Actions log.

---

## Quick Start

### Install via Homebrew

```bash
brew install --cask maccrab
```

### Build and run

```bash
# One command: build, codesign, compile rules, restart daemon, open app
make dev

# Or step by step:
swift build
python3 Compiler/compile_rules.py --input-dir Rules/ \
    --output-dir ~/Library/Application\ Support/MacCrab/compiled_rules/
sudo .build/debug/maccrabd
```

### Control and query

```bash
.build/debug/maccrabctl status                       # Daemon status
.build/debug/maccrabctl alerts                       # Recent alerts
.build/debug/maccrabctl events tail 20               # Live event stream
.build/debug/maccrabctl watch                        # Streaming alert tail
.build/debug/maccrabctl rules list                   # Loaded rules
.build/debug/maccrabctl hunt "show critical alerts"  # NL threat hunting
.build/debug/maccrabctl report --hours 48            # Incident report
.build/debug/maccrabctl cdhash 1234                  # CDHash lookup
.build/debug/maccrabctl tree-score 20                # Behavioral scoring
.build/debug/maccrabctl mcp list                     # MCP server inventory
.build/debug/maccrabctl extensions --suspicious      # Browser extension scan
```

### Open the dashboard

```bash
make app
```

---

## Development

### dev.sh

The `scripts/dev.sh` script is the primary development driver. It builds, codesigns with the ES entitlement, compiles rules, and restarts the daemon in one step:

```bash
./scripts/dev.sh              # Full cycle (sudo for ES)
./scripts/dev.sh --no-es      # Without root (limited event sources)
./scripts/dev.sh --build      # Build + sign only, don't start
./scripts/dev.sh --restart    # Restart daemon without rebuilding
./scripts/dev.sh --stop       # Stop daemon and app
./scripts/dev.sh --status     # Show daemon status
```

### Make targets

```
make dev              Build + restart daemon + open app (one command)
make restart          Restart daemon (no rebuild)
make stop             Stop daemon and app
make status           Show daemon status
make watch            Live stream alerts
make app              Open the GUI dashboard

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

Test files:

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

---

## Detection Rules

### Format

MacCrab uses a Sigma-compatible YAML format. Single-event rules follow the [standard Sigma specification](https://sigmahq.io/docs/). Temporal sequence rules extend the format with `type: sequence`, `steps`, `window`, and `correlation` fields.

Rules are compiled from YAML to an optimized JSON predicate format by `Compiler/compile_rules.py` before being loaded by the detection engine at runtime.

### Example: single-event rule

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

### Example: temporal sequence rule

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

### Sequence rule fields

| Field | Description |
|-------|-------------|
| `type: sequence` | Marks the rule as a temporal sequence (processed by `SequenceEngine`) |
| `window` | Maximum time span from first to last step (e.g., `120s`, `5m`, `1h`) |
| `correlation` | How steps relate: `process.lineage`, `process.same`, `file.path`, `network.endpoint`, or `none` |
| `ordered` | Whether steps must occur in the listed order (`true`) or in any order (`false`) |
| `steps[].process` | Process relationship to another step: `<step_id>.descendant`, `<step_id>.ancestor`, `<step_id>.same`, `<step_id>.sibling` |
| `trigger` | Boolean expression over step IDs that must be satisfied for the rule to fire |

### Writing custom rules

1. Create a new `.yml` file in the appropriate `Rules/<tactic>/` directory
2. Follow the Sigma YAML format with `logsource.product: macos`
3. Assign a unique UUID as the rule `id`
4. Tag with MITRE ATT&CK techniques (e.g., `attack.t1059.004`)
5. Document known false positives
6. Compile and test:

```bash
make compile-rules
.build/debug/maccrabctl rules list | grep "your rule title"
make lint-rules       # Validates format, UUID uniqueness, and tags
make test-fp          # Verify no false positives against normal activity
```

---

## Configuration

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MACCRAB_RULES_DIR` | `~/Library/Application Support/MacCrab/compiled_rules/` | Compiled JSON rule directory |
| `MACCRAB_LOG_DIR` | `~/Library/Application Support/MacCrab/logs/` | JSONL alert and event log directory |
| `MACCRAB_WEBHOOK_URL` | *(none)* | URL for JSON POST webhook delivery |
| `MACCRAB_SYSLOG_HOST` | *(none)* | Syslog receiver hostname or IP |
| `MACCRAB_SYSLOG_PORT` | `514` | Syslog receiver port |
| `MACCRAB_SYSLOG_PROTO` | `udp` | Syslog transport (`udp` or `tcp`) |
| `MACCRAB_MIN_SEVERITY` | `low` | Minimum output severity (`informational`, `low`, `medium`, `high`, `critical`) |

### Baseline engine

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

### Alert deduplication

| Setting | Default | Description |
|---------|---------|-------------|
| Suppression window | 300 seconds | Time before the same (rule, process, context) tuple can fire again |
| Max alerts per rule per hour | 50 | Hard cap on alert volume per rule |
| Dedup key fields | rule ID, process path, file path or destination IP | Fields used to compute the deduplication key |

---

## Requirements

| Requirement | Details |
|-------------|---------|
| **macOS** | 13.0+ (Ventura or later) |
| **Swift** | 5.9+ |
| **Root access** | Required for the Endpoint Security framework (`es_new_client` requires euid 0) |
| **ES entitlement** | `com.apple.developer.endpoint-security.client` (provisioning profile for production; self-signed for development) |
| **Full Disk Access** | Grant to Terminal.app or your terminal emulator for TCC database monitoring |
| **Python** | 3.9+ with PyYAML (`pip install pyyaml`) for the rule compiler |

---

## Self-Signing for Development

Apple restricts the Endpoint Security entitlement to signed binaries. For local development:

### 1. Create an entitlements file

Create `maccrabd.entitlements`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.developer.endpoint-security.client</key>
    <true/>
</dict>
</plist>
```

### 2. Sign the binary

```bash
swift build
codesign --sign - --entitlements maccrabd.entitlements \
    --force .build/debug/maccrabd
```

### 3. Approve in System Settings

On first launch, macOS will block the unsigned binary. Go to **System Settings > Privacy & Security** and click **Allow Anyway**. Add Terminal (or your terminal emulator) to **Full Disk Access** for TCC monitoring.

### 4. Production signing

For distribution, sign with a Developer ID certificate and a provisioning profile that includes the ES entitlement:

```bash
codesign --sign "Developer ID Application: Your Name (TEAM_ID)" \
    --entitlements maccrabd.entitlements \
    --options runtime \
    .build/release/maccrabd
```

---

## Project Structure

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
│   ├── maccrabd/                        # Daemon executable
│   │   └── main.swift
│   ├── maccrabctl/                      # CLI control tool
│   │   └── main.swift
│   └── MacCrabApp/                      # SwiftUI status bar app
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
├── Rules/                               # 343 Sigma-compatible detection rules
│   ├── defense_evasion/    (55)
│   ├── credential_access/  (32)
│   ├── supply_chain/       (31)
│   ├── persistence/        (30)
│   ├── execution/          (28)
│   ├── ai_safety/          (19)
│   ├── command_and_control/ (17)
│   ├── discovery/          (16)
│   ├── privilege_escalation/ (16)
│   ├── lateral_movement/   (16)
│   ├── collection/         (15)
│   ├── exfiltration/       (11)
│   ├── initial_access/     (10)
│   ├── container/          (8)
│   ├── tcc/                (6)
│   ├── impact/             (6)
│   └── sequences/          (27)
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

---

## How It Compares

| Capability | MacCrab | coreSigma | osquery | Santa | Commercial EDR |
|------------|:-------:|:---------:|:-------:|:-----:|:--------------:|
| Real-time ES events | Yes | Yes | Scheduled | Exec only | Yes |
| Sigma rule format | Yes | Yes | No | No | Varies |
| Temporal sequence rules | **Yes** | No | No | No | Some |
| Behavioral scoring | **Yes** | No | No | No | Yes |
| AI coding tool guardrails | **Yes** | No | No | No | No |
| Threat intel feeds | **Yes** | No | No | No | Yes |
| Baseline anomaly detection | **Yes** | No | No | No | Yes |
| TCC permission monitoring | **Yes** | No | Partial | No | Some |
| Process lineage DAG | **Yes** | Limited | Partial | No | Yes |
| Incident grouping | **Yes** | No | No | No | Yes |
| Certificate Transparency | **Yes** | No | No | No | Some |
| Self-defense / tamper protection | **Yes** | No | No | No | Yes |
| Response actions | **Yes** | No | No | Block only | Yes |
| Runs entirely local | **Yes** | **Yes** | **Yes** | **Yes** | No |
| Open source | **Yes** | **Yes** | **Yes** | **Yes** | No |
| macOS ES framework depth | 90+ types | ~20 types | Limited | Exec only | Varies |
| Infrastructure required | **None** | None | Fleet server | Sync server | Cloud console |
| Native macOS UI | **Yes** | No | No | Yes | Agent only |

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
