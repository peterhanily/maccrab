# HawkEye

**Local-first macOS threat detection engine with Sigma-compatible rules**

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)]()
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-macOS%2013%2B-lightgrey)]()
[![Rules](https://img.shields.io/badge/detection%20rules-165-orange)]()
[![Swift](https://img.shields.io/badge/Swift-5.9%2B-F05138)]()

---

## What is HawkEye?

HawkEye is an on-device security detection engine for macOS that evaluates Sigma-compatible detection rules against real-time Endpoint Security framework events, Unified Log entries, TCC permission changes, and network connections -- with no SIEM, no cloud, and no infrastructure required. Its key differentiator is **temporal-causal sequence detection**: the ability to correlate ordered chains of events (e.g., download, then execute, then persist, then call home) within time windows and across process lineage, combined with a **baseline anomaly learning** engine that adapts to your machine's normal behavior. Think of it as what Sysmon + Sigma + a lightweight SIEM provides on Windows -- but native to macOS, running entirely on your machine.

---

## Features

### Event Sources

| Source | Description |
|--------|-------------|
| **Endpoint Security framework** | 90+ kernel-level event types including process exec/fork/exit, file create/write/rename/unlink, signal delivery, and kext loading |
| **Unified Log** | Real-time streaming from 12 subsystems including `com.apple.securityd`, `com.apple.authd`, `com.apple.xpc`, and `com.apple.install` |
| **TCC permission monitor** | Polls system and user TCC databases for permission grants and revocations to accessibility, full disk access, screen recording, and more |
| **Network connection collector** | Captures outbound TCP/UDP connections with destination IP, port, hostname resolution, and owning process attribution |

### Detection Layers

| Layer | Description | Count |
|-------|-------------|-------|
| **Single-event Sigma rules** | Standard Sigma YAML rules compiled to JSON predicates, evaluated against individual events in real time | 150 rules |
| **Temporal sequence rules** | Multi-step ordered rules with time windows, process lineage correlation, and causal chaining | 15 rules |
| **Baseline anomaly detection** | Learned model of normal process behavior, network destinations, and file access patterns; alerts on deviation | Adaptive |

### Enrichment Engines

| Engine | Description |
|--------|-------------|
| **Process lineage DAG** | Sliding-window directed acyclic graph of parent-child relationships, surviving parent exit, enabling full ancestor chain reconstruction |
| **Code signing cache** | Caches and exposes signer type (Apple, App Store, Developer ID, ad-hoc, unsigned), team ID, signing ID, notarization status, and platform binary flag |
| **YARA file scanning** | On-demand YARA rule matching for files referenced in high-severity alerts |

### Output Targets

| Target | Format |
|--------|--------|
| **CLI stdout** | Human-readable colored output with severity indicators |
| **JSONL file** | One JSON object per line, suitable for log ingestion pipelines |
| **macOS notifications** | Native `UserNotifications` alerts for high and critical severity |
| **Webhook** | JSON POST to a configurable URL for integration with Slack, Teams, PagerDuty, etc. |
| **Syslog** | RFC 5424 structured data over UDP/TCP for forwarding to any syslog receiver |

### Native SwiftUI App

A status bar application providing:
- Real-time alert dashboard with severity filtering
- Live event stream with search and category filters
- Rule browser with enable/disable toggles
- TCC permission timeline visualization
- Baseline deviation indicators

---

## Architecture

```
                          HawkEye Detection Pipeline

 +-----------------+    +------------------+    +------------------+
 |  Event Sources  |    |   Enrichment     |    |   Detection      |
 |                 |    |                  |    |                  |
 | ES Framework -------->  Process Lineage |    | Single-Event     |
 | Unified Log  -------->  Code Signing    +--->| Rules (150)      |
 | TCC Monitor  -------->  YARA Scanner    |    | Sequence Rules   |
 | Network Coll.-------->                  |    | (15)             |
 |                 |    |                  |    | Baseline Anomaly |
 +-----------------+    +------------------+    +--------+---------+
                                                         |
                                                         v
                                                +--------+---------+
                                                |  Deduplication   |
                                                |  & Suppression   |
                                                +--------+---------+
                                                         |
                              +-------------+------------+----------+-----------+
                              |             |            |          |           |
                              v             v            v          v           v
                          +-------+   +---------+  +--------+  +-------+  +--------+
                          | stdout|   |  JSONL  |  | macOS  |  |Webhook|  | Syslog |
                          |  CLI  |   |  File   |  | Notif. |  | POST  |  |RFC 5424|
                          +-------+   +---------+  +--------+  +-------+  +--------+
```

---

## Quick Start

### Build

```bash
swift build
```

### Compile Detection Rules

```bash
python3 Compiler/compile_rules.py \
    --input-dir Rules/ \
    --output-dir ~/Library/Application\ Support/HawkEye/compiled_rules/
```

### Run the Daemon

The daemon requires root privileges for the Endpoint Security framework:

```bash
# Start the detection daemon
sudo .build/debug/hawkeyed
```

### Control and Query

In another terminal:

```bash
# Check daemon status
.build/debug/hawkctl status

# View recent alerts
.build/debug/hawkctl alerts

# Tail the live event stream
.build/debug/hawkctl events tail 20
```

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

Apple restricts the Endpoint Security entitlement to binaries signed with a provisioning profile that explicitly includes `com.apple.developer.endpoint-security.client`. For local development without an Apple Developer Program membership, you can self-sign:

### 1. Create an entitlements file

Create `hawkeyed.entitlements`:

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
codesign --sign - --entitlements hawkeyed.entitlements \
    --force .build/debug/hawkeyed
```

### 3. Approve in System Settings

On first launch, macOS will block the unsigned binary. Go to **System Settings > Privacy & Security** and click **Allow Anyway**. You may also need to add Terminal (or your terminal emulator) to **Full Disk Access** for the TCC monitor to read the TCC databases.

### 4. Production signing

For distribution, you need an Apple Developer account with the Endpoint Security entitlement approved. Create a provisioning profile in the Apple Developer portal that includes the `com.apple.developer.endpoint-security.client` entitlement, then sign with your Developer ID certificate:

```bash
codesign --sign "Developer ID Application: Your Name (TEAM_ID)" \
    --entitlements hawkeyed.entitlements \
    --options runtime \
    .build/release/hawkeyed
```

---

## Detection Rules

### Format

HawkEye uses a Sigma-compatible YAML format for detection rules. Single-event rules follow the [standard Sigma specification](https://sigmahq.io/docs/). Temporal sequence rules extend the format with `type: sequence`, `steps`, `window`, and `correlation` fields.

Rules are compiled from YAML to an optimized JSON predicate format before being loaded by the detection engine at runtime.

### Rule Coverage by MITRE ATT&CK Tactic

| Tactic | Directory | Single-Event | Sequences | Total |
|--------|-----------|:------------:|:---------:|:-----:|
| Execution | `execution/` | 22 | 4 | 26 |
| Persistence | `persistence/` | 26 | 5 | 31 |
| Defense Evasion | `defense_evasion/` | 16 | 3 | 19 |
| Credential Access | `credential_access/` | 15 | 2 | 17 |
| Command and Control | `command_and_control/` | 15 | 2 | 17 |
| Discovery | `discovery/` | 11 | 1 | 12 |
| Collection | `collection/` | 10 | 1 | 11 |
| Privilege Escalation | `privilege_escalation/` | 6 | 1 | 7 |
| Exfiltration | `exfiltration/` | 6 | 1 | 7 |
| Initial Access | `initial_access/` | 5 | 1 | 6 |
| TCC Abuse | `tcc/` | 6 | 2 | 8 |
| Lateral Movement | `lateral_movement/` | 3 | 1 | 4 |
| **Total** | | **150** | **15** | **165** |

Sequence rules are stored separately in `sequences/` but are categorized above by their primary tactic.

### Example: Single-Event Rule

```yaml
title: Shell Spawned by Browser Process
id: d1a2b3c4-0001-4000-a000-000000000001
status: stable
description: >
    Detects a shell interpreter spawned as a child of a browser process,
    which may indicate exploitation or malicious download execution.
author: HawkEye Community
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

### Example: Temporal Sequence Rule

Sequence rules are HawkEye's novel extension to the Sigma format. They define multi-step attack chains with time windows, ordering constraints, and process lineage correlation:

```yaml
title: Download to Persistence to C2 Attack Chain
id: e1f2a3b4-0001-4000-b000-000000000001
status: experimental
description: >
    Detects a complete attack chain: file downloaded to Downloads/tmp,
    executed as unsigned binary, installs persistence via LaunchAgent/Daemon,
    then makes outbound network connection (C2 callback).
author: HawkEye Community
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

Key sequence rule fields:

| Field | Description |
|-------|-------------|
| `type: sequence` | Marks the rule as a temporal sequence (processed by `SequenceEngine`) |
| `window` | Maximum time span from first to last step (e.g., `120s`, `5m`, `1h`) |
| `correlation` | How steps relate: `process.lineage`, `process.same`, `file.path`, `network.endpoint`, or `none` |
| `ordered` | Whether steps must occur in the listed order (`true`) or in any order (`false`) |
| `steps[].process` | Process relationship to another step: `<step_id>.descendant`, `<step_id>.ancestor`, `<step_id>.same`, `<step_id>.sibling` |
| `trigger` | Boolean expression over step IDs that must be satisfied for the rule to fire |

### Writing Custom Rules

1. Create a new `.yml` file in the appropriate `Rules/<tactic>/` directory
2. Follow the Sigma YAML format with `logsource.product: macos`
3. Assign a unique UUID as the rule `id`
4. Tag with MITRE ATT&CK techniques (e.g., `attack.t1059.004`)
5. Document known false positives
6. Compile and test:

```bash
# Compile your new rule
python3 Compiler/compile_rules.py --input-dir Rules/ \
    --output-dir ~/Library/Application\ Support/HawkEye/compiled_rules/

# Verify it loaded
.build/debug/hawkctl rules list | grep "your rule title"
```

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HAWKEYE_RULES_DIR` | `~/Library/Application Support/HawkEye/compiled_rules/` | Directory containing compiled JSON rule files |
| `HAWKEYE_LOG_DIR` | `~/Library/Application Support/HawkEye/logs/` | Directory for JSONL alert and event log files |
| `HAWKEYE_WEBHOOK_URL` | *(none)* | URL for JSON POST webhook delivery of alerts |
| `HAWKEYE_SYSLOG_HOST` | *(none)* | Syslog receiver hostname or IP |
| `HAWKEYE_SYSLOG_PORT` | `514` | Syslog receiver port |
| `HAWKEYE_SYSLOG_PROTO` | `udp` | Syslog transport protocol (`udp` or `tcp`) |
| `HAWKEYE_MIN_SEVERITY` | `low` | Minimum severity level for output (`informational`, `low`, `medium`, `high`, `critical`) |

### Baseline Engine

The baseline anomaly engine builds a profile of normal activity over a configurable learning period. Configuration is stored in `~/Library/Application Support/HawkEye/baseline_config.json`:

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

After the learning period, the engine alerts when it observes processes, network destinations, or file access patterns that fall outside the learned baseline.

### Alert Deduplication

To prevent alert fatigue, HawkEye deduplicates alerts using a configurable suppression window. Alerts with the same rule ID, process executable, and (where applicable) file path or network destination are suppressed for a configurable duration after the first firing:

| Setting | Default | Description |
|---------|---------|-------------|
| Suppression window | 300 seconds | Time before the same (rule, process, context) tuple can fire again |
| Max alerts per rule per hour | 50 | Hard cap on alert volume per rule |
| Dedup key fields | rule ID, process path, file path or destination IP | Fields used to compute the deduplication key |

---

## Project Structure

```
hawkeye/
├── Package.swift                          # Swift Package Manager manifest
├── LICENSE                                # Apache 2.0 (code)
├── README.md                              # This file
├── CONTRIBUTING.md                        # Contribution guide
│
├── Sources/
│   ├── HawkEyeCore/                      # Core detection library
│   │   ├── Events/                        # Event model types
│   │   │   ├── Event.swift                #   Unified event struct
│   │   │   ├── EventEnums.swift           #   Category, type, severity enums
│   │   │   ├── ProcessInfo.swift          #   Process metadata + code signature
│   │   │   ├── FileInfo.swift             #   File event metadata
│   │   │   ├── NetworkInfo.swift          #   Network connection metadata
│   │   │   └── TCCInfo.swift              #   TCC permission event metadata
│   │   ├── Collectors/                    # Event source implementations
│   │   │   ├── ESCollector.swift          #   Endpoint Security framework client
│   │   │   ├── ESHelpers.swift            #   ES type conversion helpers
│   │   │   ├── TCCMonitor.swift           #   TCC database watcher
│   │   │   ├── UnifiedLogCollector.swift  #   Unified Log stream reader
│   │   │   └── NetworkCollector.swift     #   Network connection monitor
│   │   ├── Enrichment/                    # Event enrichment pipeline
│   │   │   ├── EventEnricher.swift        #   Enrichment orchestrator
│   │   │   ├── ProcessLineage.swift       #   Process ancestry DAG
│   │   │   └── CodeSigningCache.swift     #   Code signing info cache
│   │   ├── Detection/                     # Rule evaluation engines
│   │   │   ├── RuleEngine.swift           #   Single-event Sigma rule engine
│   │   │   ├── SequenceEngine.swift       #   Temporal sequence rule engine
│   │   │   └── BaselineEngine.swift       #   Anomaly baseline detection
│   │   ├── Storage/                       # Persistence layer
│   │   │   ├── AlertStore.swift           #   Alert storage and querying
│   │   │   └── EventStore.swift           #   Event ring buffer storage
│   │   ├── Output/                        # Alert delivery targets
│   │   │   ├── OutputManager.swift        #   Output routing and formatting
│   │   │   ├── WebhookOutput.swift        #   JSON POST webhook
│   │   │   └── SyslogOutput.swift         #   RFC 5424 syslog sender
│   │   └── Models/                        # Shared model types
│   │       └── Alert.swift                #   Alert model
│   │
│   ├── hawkeyed/                          # Daemon executable
│   │   └── main.swift                     #   Entry point, signal handling, pipeline setup
│   │
│   ├── hawkctl/                           # CLI control tool
│   │   └── main.swift                     #   Status, alerts, events, rule management
│   │
│   └── HawkEyeApp/                       # SwiftUI status bar app (Xcode project)
│       ├── HawkEyeApp.swift               #   App entry point
│       ├── AppState.swift                 #   Observable app state
│       ├── Views/
│       │   ├── MainView.swift             #   Primary window
│       │   ├── StatusBarMenu.swift        #   Menu bar interface
│       │   └── Components.swift           #   Reusable UI components
│       └── ViewModels/
│           └── ViewModels.swift           #   View model layer
│
├── Rules/                                 # Sigma-compatible detection rules (YAML)
│   ├── execution/                         #   Execution tactic rules
│   ├── persistence/                       #   Persistence tactic rules
│   ├── defense_evasion/                   #   Defense evasion tactic rules
│   ├── credential_access/                 #   Credential access tactic rules
│   ├── command_and_control/               #   C2 tactic rules
│   ├── discovery/                         #   Discovery tactic rules
│   ├── collection/                        #   Collection tactic rules
│   ├── privilege_escalation/              #   Privilege escalation tactic rules
│   ├── exfiltration/                      #   Exfiltration tactic rules
│   ├── initial_access/                    #   Initial access tactic rules
│   ├── tcc/                               #   TCC-specific abuse rules
│   ├── lateral_movement/                  #   Lateral movement tactic rules
│   └── sequences/                         #   Temporal sequence rules
│
├── Compiler/
│   └── compile_rules.py                   # Sigma YAML to JSON predicate compiler
│
└── Tests/
    └── HawkEyeCoreTests/                  # Unit and integration tests
```

---

## How It Compares

| Capability | HawkEye | coreSigma | osquery | Santa | Commercial EDR |
|------------|:-------:|:---------:|:-------:|:-----:|:--------------:|
| Real-time ES events | Yes | Yes | Scheduled | Exec only | Yes |
| Sigma rule format | Yes | Yes | No | No | Varies |
| Temporal sequence rules | **Yes** | No | No | No | Some |
| Baseline anomaly detection | **Yes** | No | No | No | Yes |
| TCC permission monitoring | **Yes** | No | Partial | No | Some |
| Process lineage DAG | **Yes** | Limited | Partial | No | Yes |
| Runs entirely local | **Yes** | **Yes** | **Yes** | **Yes** | No |
| Open source | **Yes** | **Yes** | **Yes** | **Yes** | No |
| macOS ES framework depth | 90+ types | ~20 types | Limited | Exec only | Varies |
| Infrastructure required | **None** | None | Fleet server | Sync server | Cloud console |
| Native macOS UI | **Yes** | No | No | Yes | Agent only |
| YARA integration | Yes | No | Yes | No | Proprietary |

---

## Contributing

We welcome contributions of both detection rules and code. See [CONTRIBUTING.md](CONTRIBUTING.md) for full guidelines.

### Rules

Detection rule contributions are especially welcome. Rules are licensed under the [Detection Rule License 1.1](https://github.com/SigmaHQ/Detection-Rule-License) (DRL 1.1). To contribute a rule:

1. Write your rule in Sigma YAML format
2. Place it in the appropriate `Rules/<tactic>/` directory
3. Ensure it has a unique UUID, MITRE ATT&CK tags, and documented false positives
4. Test it with the rule compiler
5. Open a pull request

### Code

Code contributions are licensed under the [Apache License 2.0](LICENSE). We use Swift's structured concurrency model with actors for thread safety. See [CONTRIBUTING.md](CONTRIBUTING.md) for code style guidelines and testing expectations.

---

## License

- **Code**: [Apache License 2.0](LICENSE)
- **Detection Rules** (`Rules/`): [Detection Rule License 1.1 (DRL 1.1)](https://github.com/SigmaHQ/Detection-Rule-License)

---

## Acknowledgments

- [**SigmaHQ**](https://github.com/SigmaHQ/sigma) -- for the Sigma detection rule format and the community-driven rule repository that inspired this project's rule structure
- [**Objective-See Foundation**](https://objective-see.org/) -- for pioneering open-source macOS security research, tools, and reference implementations that informed HawkEye's design
- [**coreSigma (Nebulock)**](https://github.com/nebulock/coreSigma) -- for the pySigma macOS ESF pipeline work that demonstrated Sigma rule evaluation against Endpoint Security events
- **Apple Endpoint Security framework** -- for providing the kernel-level visibility that makes real-time detection possible on macOS
