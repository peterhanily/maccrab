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
swift test                     # Unit tests (250 tests)
make test                      # Unit tests (summary only)
make test-full                 # Full test suite
make test-integration          # Integration test (starts daemon, triggers actions)
make test-detection            # Detection coverage test
make test-fp                   # False positive test
make lint-rules                # Rule linting
```

## Architecture

MacCrab is a local-first macOS threat detection engine with four targets:

- **MacCrabCore** (`Sources/MacCrabCore/`) -- Shared library: detection engines, collectors, enrichment, storage, prevention
- **maccrabd** (`Sources/maccrabd/`) -- Detection daemon. Runs the event loop, processes events through the pipeline
- **maccrabctl** (`Sources/maccrabctl/`) -- CLI tool for status, events, alerts, threat hunting, reports
- **MacCrabApp** (`Sources/MacCrabApp/`) -- SwiftUI menubar app + dashboard. Reads from the daemon's SQLite DB

### Key Directories

```
Sources/MacCrabCore/
  Collectors/     Event sources (ES, Unified Log, network, DNS, TCC, etc.)
  Detection/      Rule engine, sequence engine, baseline, campaign detector
  Enrichment/     Process lineage, code signing, threat intel, CDHash
  Prevention/     DNS sinkhole, network blocker, persistence guard, etc.
  Fleet/          Fleet telemetry client and data models
  AIGuard/        AI coding tool monitoring
  Storage/        SQLite event and alert stores
  Models/         Core data types (Event, Alert, Severity, etc.)
  Output/         Notifications, webhooks, syslog, reports

Rules/            304 Sigma-compatible YAML detection rules
  sequences/      22 multi-step sequence rules
Compiler/         Python rule compiler (YAML -> JSON)
fleet/            Python fleet collector server
scripts/          Build, test, install, and CI scripts
Tests/            Swift Testing unit tests
```

## Rule Workflow

1. Write YAML rules in `Rules/<tactic>/`
2. Compile: `make compile-rules`
3. Daemon loads compiled JSON from `<support-dir>/compiled_rules/`
4. Send SIGHUP to daemon to reload rules without restart: `pkill -HUP maccrabd`

## LLM Agent Integration

MacCrab supports pluggable LLM backends for enhanced threat hunting, investigation summaries, rule generation, and active defense recommendations.

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
```

Or configure via `daemon_config.json`:
```json
{"llm": {"provider": "ollama", "ollama_model": "llama3.1:8b"}}
```

All LLM features degrade gracefully when no backend is configured. Cloud APIs get automatic privacy sanitization (usernames, private IPs, hostnames redacted).

**Files:** `Sources/MacCrabCore/LLM/` (9 files — backend protocol, 3 providers, service orchestrator, cache, sanitizer, prompts)

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

- **Root daemon:** `/Library/Application Support/MacCrab/`
- **Non-root daemon:** `~/Library/Application Support/MacCrab/`
- Database: `events.db` (SQLite with WAL mode)
- Compiled rules: `compiled_rules/*.json`

## Code Conventions

- Swift 5.9+, macOS 13+ minimum
- Actors for thread-safe components
- `os.log` Logger for subsystem logging
- Tests use Swift Testing framework (`import Testing`, `@Test`, `#expect`)
- 16 localization bundles in `Sources/MacCrabApp/Resources/`
