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
swift test                     # Unit tests (2165 tests in 403 suites)
make test                      # Unit tests (summary only)
make test-full                 # Full test suite
make test-integration          # Integration test (starts daemon, triggers actions)
make test-detection            # Detection coverage test (15 categories)
make test-campaign             # Multi-tactic kill chain simulation (5 waves)
make test-fp                   # False positive test (~50 system processes)
make test-stress               # Sustained operation monitor (60s default)
make lint-rules                # Rule linting
```

## Architecture

MacCrab is a local-first macOS threat detection engine. Since v1.3 (April 2026), the detection engine ships as a native Endpoint Security **System Extension** activated from inside `MacCrab.app`. Eight SPM targets:

- **MacCrabCore** (`Sources/MacCrabCore/`) -- Shared library: detection engines, collectors, enrichment, storage, prevention
- **MacCrabAgentKit** (`Sources/MacCrabAgentKit/`) -- Shared daemon bootstrap wrapping the event loop, monitors, timers, and signal handlers. Linked by both the sysext and the legacy standalone daemon
- **MacCrabAgent** (`Sources/MacCrabAgent/`) -- System Extension executable. Wrapped into `com.maccrab.agent.systemextension` bundle by `scripts/build-release.sh` and activated via `OSSystemExtensionRequest`. Ships in release DMGs
- **maccrabd** (`Sources/maccrabd/`) -- Legacy standalone daemon. Kept for `swift run maccrabd` development when no ES entitlement is available — falls back through `eslogger` → `kdebug` → FSEvents
- **MacCrabForensics** (`Sources/MacCrabForensics/`) -- Mac Context Plugin Platform: forensic case/collector/plugin library. Linked by `maccrabctl`, `MacCrabApp`, and `maccrab-mcp`; intentionally not linked by the sysext or `maccrabd`
- **maccrabctl** (`Sources/maccrabctl/`) -- CLI tool for status, events, alerts, threat hunting, reports
- **maccrab-mcp** (`Sources/maccrab-mcp/`) -- MCP server exposing ~78 tools for AI agent integration (v1.10 trace tools, v1.12.0 supply-chain / intent tools, and `forensics.*` plugin tools)
- **MacCrabApp** (`Sources/MacCrabApp/`) -- SwiftUI menubar app + dashboard + SystemExtension activator. Reads from the engine's SQLite DB

### Key Directories

```
Sources/MacCrabCore/
  Events/         Unified event model: Event, EventEnums, ProcessInfo, FileInfo, NetworkInfo, TCCInfo
  Models/         Alert model and other top-level data types
  Collectors/     Event sources (ES, Unified Log, network, DNS, TCC, EDR monitor, etc.)
  Detection/      Rule engine, sequence engine, baseline, campaign detector, behavior scoring, response actions
  Enrichment/     Process lineage, code signing, threat intel, CDHash, cert transparency, file hasher
  Prevention/     DNS sinkhole, network blocker, persistence guard, response-action safety validators
  Fleet/          Fleet telemetry client and data models
  AIGuard/        AI coding tool monitoring (AIToolRegistry, MCPAttributor, AgentLineageService)
  LLM/            LLM backends (Ollama, Claude, OpenAI, Mistral, Gemini), prompts, cache, sanitizer
  Storage/        SQLite event/alert/campaign stores, schema migrator, suppressions, encryption
  Output/         Notifications, webhooks, syslog, reports, OCSF mapper, S3, SFTP, stream sinks
  Network/        SecureURLSession (TLS 1.2 floor, optional SPKI pinning) used by all outbound HTTP
  Deception/      Honeyfile manager (canary credential paths)
  Utilities/      LockedCounter, PowerGate (battery/thermal gating), shared primitives
  Integrations/   SecurityToolIntegrations (CrowdStrike, SentinelOne log ingestion)

Rules/            436 single-event Sigma-compatible YAML rules (19 tactic directories)
  sequences/      41 multi-step sequence rules
  graph/          6 multi-entity TraceGraph rules (v1.12.0)
Compiler/         Python rule compiler (YAML -> JSON) with duplicate key and field validation
fleet/            Python fleet collector server
scripts/          Build, test, install, red team simulation, and CI scripts
Tests/            Swift Testing unit tests (2165 tests in 403 suites)
```

## Detection Stack (5 tiers)

1. **Rules** -- 436 single-event Sigma-compatible YAML rules compiled to JSON predicates, plus 41 sequence rules across 19 tactic dirs, plus 6 graph rules (Rules/graph/*.json) evaluated against materialized TraceGraph traces. Category-indexed for O(1) dispatch. Rules >50ms logged for profiling.
2. **Anomaly** -- Welford z-score statistical anomaly; 2nd-order Markov chain process trees; behavioral scoring (70+ weighted indicators with feedback-adjusted weights).
3. **Sequences** -- 41 temporal multi-step rules with process lineage correlation, 10K partial match cap.
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
| GitSecurityMonitor | Git credential-helper abuse, SSH-agent hijack, malicious git hooks | Real-time |
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

**Files:** `Sources/MacCrabCore/LLM/` (16 files — backend protocol, 5 providers, service orchestrator, consensus + triage services, investigators, cache, sanitizer, prompts, shared types)

## MCP Server (AI Agent Integration)

MacCrab includes an MCP (Model Context Protocol) server that lets AI agents query security data directly.

**Binary:** `maccrab-mcp` (5th executable target in Package.swift)

**Tools exposed (~78 live in this build; varies with installed plugins):** (table below is illustrative; the full set also includes the v1.12.0 supply-chain / intent tools and the `forensics.*` plugin tools)

| Tool | Purpose |
|------|---------|
| `get_alerts` | Query alerts with severity/time/suppression filtering |
| `get_alert_detail` | Full alert detail incl. LLM investigation + D3FEND mitigations |
| `cluster_alerts` | Group recent alerts by rule + process fingerprint |
| `get_events` | Query events with category/search/time filtering |
| `get_campaigns` | List detected attack campaigns |
| `suppress_alert` | Suppress false positive alerts (audit-logged) |
| `suppress_campaign` | Suppress a campaign + all contributing alerts |
| `get_ai_alerts` | AI Guard alerts (credential / boundary / injection / MCP) |
| `scan_text` | Scan text for prompt-injection (Forensicate.ai, 87+ rules) |
| `get_status` | Daemon status, rule count, DB size |
| `hunt` | Full-text threat hunting across events |
| `get_security_score` | Security posture (0-100) with factors |
| **`get_traces`** | (v1.10) List recent causal traces from TraceGraph |
| **`get_trace_detail`** | (v1.10) Full trace with anchor + members + hash chain |
| **`hunt_trace`** | (v1.10) Substring search across traces |
| **`verify_bundle`** | (v1.10) Verify a .maccrabtrace bundle (schema, Merkle, signature) |
| **`trace_from_event`** | (v1.10) Pivot from an event id to its containing trace |

**Registration:** `.mcp.json` at project root configures it for Claude Code. Build with `swift build --target maccrab-mcp`.

**Slash commands** (`.claude/commands/`):
- `/security-check` — Full security posture report via MCP
- `/threat-hunt <query>` — Natural language threat hunting
- `/alerts` — Review and triage recent alerts

## Dashboard (MacCrabApp)

SwiftUI menubar app whose dashboard is the V2 workspace shell (`Sources/MacCrabApp/V2/`): `V2RootView` mounts `V2DashboardShell` (sidebar + top bar + workspace area) with a command bar / palette and a UIMode density toggle (Basic / Standard / Advanced).

Ten workspaces (`V2Workspace` enum):

- **Overview** — at-a-glance system posture and shortcuts
- **Alerts** — triage and route findings (multi-select, bulk suppress, inline actions)
- **Events** — live event stream with filter / search / drill-in
- **Investigation** — trace graph + AI analysis
- **Forensics** — scan this Mac, browse plugins, export evidence
- **Detection** — rules, AI Guard, browser extensions, MCP
- **Prevention** — DNS sinkhole, network blocker, persistence guard, response actions
- **Intelligence** — IOC context, feeds, packages, integrations
- **System** — platform health, permissions (TCC), trust, settings
- **Docs** — in-app documentation

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
  "storage": {
    "events_hot_tier_minutes": 30,
    "events_max_size_mb": 200,
    "events_size_cap_interval_minutes": 60,
    "aggregate_days": 90,
    "alerts_retention_days": 365,
    "alerts_max_size_mb": 100,
    "campaigns_retention_days": 365,
    "campaigns_max_size_mb": 50,
    "tracegraph_retention_days": 90,
    "tracegraph_max_size_mb": 250,
    "traces_retention_days": 90,
    "traces_max_size_mb": 100,
    "reports_retention_days": 90,
    "auto_generated_rules_max": 200
  }
}
```

All keys are optional — missing keys use defaults from `DaemonConfig.swift`. Since v1.8 the per-tier retention/size knobs live under `storage{}`; the legacy v1.7 top-level keys (`retention_days`, `max_database_size_mb`) still decode and are folded onto the storage block at load time. Since v1.18 the `tracegraph_*` and `traces_*` caps (previously hardcoded in `DaemonTimers`) are tunable here, and `tracegraph.db`'s global entity/edge substrate gets its own orphan-aware retention sweep (`SQLiteCausalGraphStore.pruneOrphanedGraph` / `pruneOldestGraph`) — before v1.18 nothing pruned `trace_edges` / `trace_entities`, so the file grew unbounded. Forensic-scan (`Cases/`) retention is an app-side setting (`forensics.retentionDays`, default 365d), enforced by `CaseManager.pruneCases` at dashboard launch and via Settings → "Run cleanup now".

## Data Locations

- **System Extension / root daemon:** `/Library/Application Support/MacCrab/` (release builds use this via sysextd-granted privileges; dev `sudo maccrabd` writes here too)
- **Non-root dev daemon:** `~/Library/Application Support/MacCrab/` (dev `swift run maccrabd` without sudo)
- Database: `events.db` (SQLite with WAL mode, 64MB cache, 256MB mmap)
- Compiled rules: `compiled_rules/*.json` (dir `0o755`, files `0o644` — world-readable: the non-root MacCrab.app reads them for rule display + integrity hashing; this is intentional, not `0o700`)
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
make test-fp                     # False positive validation (~50 system processes)
make test-stress 120             # Sustained operation monitor (120s)
```

All tests are safe — artifacts in `/tmp`, localhost connections, cleanup on exit.
