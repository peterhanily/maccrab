# CLAUDE.md -- MacCrab Development Guide

## Build Commands

```bash
swift build                    # Debug build
swift build -c release         # Release build
make dev                       # Build + codesign + compile rules + restart daemon
make dev-no-es                 # Dev without sudo (no Endpoint Security)
make build                     # Build only (no start)
make compile-rules             # Compile YAML rules to JSON
```

## Test Commands

```bash
swift test                     # Unit tests (628 tests in 135 suites)
make test                      # Unit tests (summary only)
make test-full                 # Full test suite
make test-integration          # Integration test (starts daemon, triggers actions)
make test-detection            # Detection coverage test (15 categories)
make test-campaign             # Multi-tactic kill chain simulation (5 waves)
make test-fp                   # False positive test (105 system processes)
make test-stress               # Sustained operation monitor (60s default)
make lint-rules                # Rule linting
```

## Architecture

MacCrab is a local-first macOS threat detection engine. Since v1.3 (April 2026), the detection engine ships as a native Endpoint Security **System Extension** activated from inside `MacCrab.app`. Seven SPM targets:

- **MacCrabCore** (`Sources/MacCrabCore/`) -- Shared library: detection engines, collectors, enrichment, storage, prevention
- **MacCrabAgentKit** (`Sources/MacCrabAgentKit/`) -- Shared daemon bootstrap wrapping the event loop, monitors, timers, and signal handlers. Linked by both the sysext and the legacy standalone daemon
- **MacCrabAgent** (`Sources/MacCrabAgent/`) -- System Extension executable. Wrapped into `com.maccrab.agent.systemextension` bundle by `scripts/build-release.sh` and activated via `OSSystemExtensionRequest`. Ships in release DMGs
- **maccrabd** (`Sources/maccrabd/`) -- Legacy standalone daemon. Kept for `swift run maccrabd` development when no ES entitlement is available — falls back through `eslogger` → `kdebug` → FSEvents
- **maccrabctl** (`Sources/maccrabctl/`) -- CLI tool for status, events, alerts, threat hunting, reports
- **maccrab-mcp** (`Sources/maccrab-mcp/`) -- MCP server exposing 7 tools for AI agent integration
- **MacCrabApp** (`Sources/MacCrabApp/`) -- SwiftUI menubar app + dashboard + SystemExtension activator. Reads from the engine's SQLite DB

### Key Directories

```
Sources/MacCrabCore/
  Collectors/     Event sources (ES, Unified Log, network, DNS, TCC, EDR monitor, etc.)
  Detection/      Rule engine, sequence engine, baseline, campaign detector
  Enrichment/     Process lineage, code signing, threat intel, CDHash
  Prevention/     DNS sinkhole, network blocker, persistence guard, etc.
  Fleet/          Fleet telemetry client and data models
  AIGuard/        AI coding tool monitoring
  LLM/            LLM backends (Ollama, Claude, OpenAI, Mistral, Gemini), prompts, cache, sanitizer
  Storage/        SQLite event and alert stores
  Models/         Core data types (Event, Alert, Severity, etc.)
  Output/         Notifications, webhooks, syslog, reports
  Integrations/   SecurityToolIntegrations (CrowdStrike, SentinelOne log ingestion)

Rules/            417 Sigma-compatible YAML detection rules (17 tactic directories)
  sequences/      38 multi-step sequence rules
Compiler/         Python rule compiler (YAML -> JSON) with duplicate key and field validation
fleet/            Python fleet collector server
scripts/          Build, test, install, red team simulation, and CI scripts
Tests/            Swift Testing unit tests (628 tests in 135 suites)
```

## Detection Stack (5 tiers)

1. **Rules** -- 379 single-event Sigma-compatible YAML rules compiled to JSON predicates. Category-indexed for O(1) dispatch. Rules >50ms logged for profiling.
2. **Anomaly** -- Welford z-score statistical anomaly; 2nd-order Markov chain process trees; behavioral scoring (70+ weighted indicators with feedback-adjusted weights).
3. **Sequences** -- 38 temporal multi-step rules with process lineage correlation, 10K partial match cap.
4. **Campaigns** -- Kill chain, alert storm, AI compromise, coordinated attack, lateral movement detection. Incremental tactic/user indexes for O(1) lookups.
5. **Cross-process** -- Correlation across process lineage graph.

## Rule Workflow

1. Write YAML rules in `Rules/<tactic>/`
2. Compile: `make compile-rules`
3. Detection engine loads compiled JSON from `<support-dir>/compiled_rules/`
4. Send SIGHUP to reload rules without restart:
   - Dev (standalone `maccrabd`): `pkill -HUP maccrabd`
   - Release (System Extension): `pkill -HUP com.maccrab.agent`

### Rule Compiler Validation

The compiler (`Compiler/compile_rules.py`) validates:
- **Duplicate YAML keys** -- warns when a key appears twice in a mapping (second overwrites first)
- **Unmapped Sigma fields** -- warns when a field name isn't in SIGMA_FIELD_MAP or known passthroughs
- **Boolean values** -- warns when `true`/`false` is used as a selection value (likely a bug)
- **Aggregation expressions** -- warns when `count(field) by X > N` is used (not supported, silently dropped)

Known passthrough fields (resolved via RuleEngine enrichments): `SignerType`, `ParentSignerType`, `XPCServiceName`, `TCCService`, `TCCAllowed`, `TCCClient`, `DestinationIsPrivate`, `FileAction`, `FileContent`, `NotarizationStatus`, `Architecture`.

## Monitors & Collectors

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

## EDR/RMM Tool Detection

The EDRMonitor proactively scans for 30+ tools across 5 categories:

- **EDR**: CrowdStrike Falcon, SentinelOne, Carbon Black, MS Defender ATP, Tanium, Velociraptor, Osquery, Sophos, ESET, Cortex XDR
- **Insider Threat/UAM**: Proofpoint/ObserveIT, ForcePoint InnerView, Teramind, ActivTrak, Veriato, Hubstaff, Securonix
- **MDM**: Jamf Pro, Kandji, Mosyle, Hexnode, Absolute/Computrace, Addigy, FileWave, Munki
- **Remote Access**: TeamViewer, AnyDesk, ScreenConnect, Splashtop, BeyondTrust, LogMeIn, RustDesk, VNC

Each discovery includes vendor, category, and capability list. Insider threat tools push OS notifications.

## TEMPEST / Van Eck Phreaking Detection

The TEMPESTMonitor detects indicators of electromagnetic eavesdropping (Van Eck phreaking) against display output:

- **17 known SDR devices**: RTL-SDR, HackRF, USRP B200/B210, BladeRF, Airspy, LimeSDR, SDRplay, FunCube
- **Display anomaly detection**: Phantom hotplug, rapid connect/disconnect cycling (HDMI tap insertion)
- **LLM EMSEC analysis**: Auto-generated electromagnetic security assessment with countermeasures

References: Deep-TEMPEST (arXiv:2407.09717), NATO SDIP-27 TEMPEST zones.

## LLM Agent Integration

MacCrab supports 5 pluggable LLM backends for enhanced threat analysis:

```bash
# Ollama (local, recommended — fully private)
export MACCRAB_LLM_PROVIDER=ollama
export MACCRAB_LLM_OLLAMA_MODEL=llama3.1:8b

# Claude API
export MACCRAB_LLM_PROVIDER=claude
export MACCRAB_LLM_CLAUDE_KEY=sk-ant-...

# OpenAI-compatible
export MACCRAB_LLM_PROVIDER=openai
export MACCRAB_LLM_OPENAI_KEY=sk-...

# Mistral
export MACCRAB_LLM_PROVIDER=mistral
export MACCRAB_LLM_MISTRAL_KEY=...

# Gemini
export MACCRAB_LLM_PROVIDER=gemini
export MACCRAB_LLM_GEMINI_KEY=...
```

Or configure via `daemon_config.json` or Settings > AI Backend in the dashboard.

### LLM Features

| Feature | Trigger | Temperature |
|---------|---------|-------------|
| Investigation summary | Campaign detected | 0.3 |
| Deep campaign analysis | Campaign (HIGH/CRITICAL, ≥3 tactics), Opus 4 only | extended thinking |
| Defense recommendation | Campaign (HIGH/CRITICAL) | 0.1 |
| Rule generation | Campaign detected | 0.4 |
| Alert analysis | Individual HIGH/CRITICAL alert | 0.2 |
| EDR tool context | EDR/RMM tool discovered | 0.2 |
| Behavioral analysis | Behavioral score threshold | 0.2 |
| Sequence analysis | Sequence rule fires | 0.2 |
| Security score | Hourly (if score < 90) | 0.3 |
| Baseline anomaly | Novel process lineage | 0.3 |
| TEMPEST analysis | SDR device or display anomaly detected | 0.2 |
| Threat hunting | `maccrabctl hunt "query"` | 0.1 |
| Report narrative | `maccrabctl report` | 0.3 |

All LLM features degrade gracefully when no backend is configured. Cloud APIs get automatic privacy sanitization (usernames, private IPs, hostnames redacted). Responses are **never auto-executed** — always advisory/informational.

**Safety**: Circuit breaker (3 failures → 5min cooldown), rate limiting (5s min interval), response size cap (50KB), SQL mutation prevention, prompt injection mitigation.

**Files:** `Sources/MacCrabCore/LLM/` (11 files — backend protocol, 5 providers, service orchestrator, cache, sanitizer, prompts)

## MCP Server (AI Agent Integration)

MacCrab includes an MCP (Model Context Protocol) server that lets AI agents query security data directly.

**Binary:** `maccrab-mcp` (5th executable target in Package.swift)

**Tools exposed:**

| Tool | Purpose |
|------|---------|
| `get_alerts` | Query alerts with severity/time/suppression filtering |
| `get_events` | Query events with category/search/time filtering |
| `get_campaigns` | List detected attack campaigns |
| `get_status` | Daemon status, rule count, DB size |
| `hunt` | Full-text threat hunting across events |
| `get_security_score` | Security posture (0-100) with factors |
| `suppress_alert` | Suppress false positive alerts |

**Registration:** `.mcp.json` at project root configures it for Claude Code. Build with `swift build --target maccrab-mcp`.

**Slash commands** (`.claude/commands/`):
- `/security-check` — Full security posture report via MCP
- `/threat-hunt <query>` — Natural language threat hunting
- `/alerts` — Review and triage recent alerts

## Dashboard (MacCrabApp)

15-view SwiftUI menubar app organized into 4 groups:

- **Monitor**: Overview, Alerts (multi-select, bulk suppress, inline actions), Campaigns (expandable with guidance + contributing alerts), Events, Rules
- **Protection**: Prevention, AI Guard, Browser Extensions
- **Intelligence**: Threat Intel, Package Freshness, AI Analysis, Integrations
- **System**: Permissions (TCC), ES Health, Docs

Key UX features:
- Auto-refresh via configurable poll timer (default 5s)
- Severity-specific SF Symbols for high-contrast accessibility
- Dark mode support (system-aware)
- "What To Do" actionable guidance on alerts and campaigns
- Campaign dismiss/restore workflow
- 14 language localizations (~60-70% complete)
- WCAG AA contrast compliance (documented in code)

## Daemon Configuration

Optional `daemon_config.json` in the support directory overrides defaults:

```json
{
  "behavior_alert_threshold": 10.0,
  "behavior_critical_threshold": 20.0,
  "statistical_z_threshold": 3.0,
  "statistical_min_samples": 50,
  "usb_poll_interval": 10,
  "clipboard_poll_interval": 3,
  "rootkit_poll_interval": 120,
  "max_database_size_mb": 500,
  "retention_days": 30
}
```

All keys are optional — missing keys use defaults from `DaemonConfig.swift`.

## Data Locations

- **System Extension / root daemon:** `/Library/Application Support/MacCrab/` (release builds use this via sysextd-granted privileges; dev `sudo maccrabd` writes here too)
- **Non-root dev daemon:** `~/Library/Application Support/MacCrab/` (dev `swift run maccrabd` without sudo)
- Database: `events.db` (SQLite with WAL mode, 64MB cache, 256MB mmap)
- Compiled rules: `compiled_rules/*.json` (0o700 permissions)
- Auto-generated rules: `compiled_rules/auto_generated/`

## Code Conventions

- Swift 5.9+, macOS 13+ minimum
- Actors for thread-safe components
- `os.log` Logger for subsystem logging
- Tests use Swift Testing framework (`import Testing`, `@Test`, `#expect`)
- 14 localization bundles in `Sources/MacCrabApp/Resources/`
- ANSI colors in CLI output (auto-disabled when piped)
- Symlink-safe file writes in privileged paths (O_NOFOLLOW pattern)

## Red Team Simulation

```bash
make test-detection              # 15 detection categories (~2 min)
make test-campaign               # 5-wave kill chain simulation (~5 min)
make test-campaign SUSTAINED=1   # Slow burn (~12 min, more realistic)
make test-fp                     # False positive validation (105 system processes)
make test-stress 120             # Sustained operation monitor (120s)
```

All tests are safe — artifacts in `/tmp`, localhost connections, cleanup on exit.
