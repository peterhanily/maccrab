# Privacy Policy

MacCrab is a **local-first** security tool. Your data stays on your machine by default.

## What MacCrab Collects

All data is collected and stored **locally** in `~/Library/Application Support/MacCrab/` (user mode) or `/Library/Application Support/MacCrab/` (root mode):

| Data Type | Purpose | Storage |
|-----------|---------|---------|
| Process executions | Detect malicious processes | SQLite `events.db` |
| File operations | Detect unauthorized file access | SQLite `events.db` |
| Network connections | Detect C2 callbacks, exfiltration | SQLite `events.db` |
| DNS queries | Detect DGA, tunneling | SQLite `events.db` |
| TCC permission changes | Detect privacy violations | SQLite `events.db` |
| Detection alerts | Security findings | SQLite `events.db` |
| Behavioral baselines | Anomaly detection | In-memory only |

## What Leaves Your Machine

**By default: nothing.** MacCrab has zero telemetry and no phone-home behavior.

The following **optional** features communicate externally only when explicitly enabled:

### LLM Reasoning Backends (opt-in)

Enabled by setting `MACCRAB_LLM_PROVIDER` environment variable.

| What is sent | What is NOT sent |
|-------------|-----------------|
| Event metadata (process names, file paths) | Usernames (redacted to `[USER]`) |
| Alert summaries | Private IP addresses (redacted to `[PRIVATE_IP]`) |
| Detection context | Hostnames (redacted to `[HOST]`) |
| | Email addresses (redacted to `[EMAIL]`) |
| | API keys, passwords, tokens (redacted) |

Sanitization is performed by `LLMSanitizer.swift` before any data leaves the machine. See `Sources/MacCrabCore/LLM/LLMSanitizer.swift` for the full implementation.

**Supported providers:** Ollama (fully local — no data leaves machine), Claude, OpenAI, Mistral, Gemini.

### Threat Intelligence Feeds (opt-in)

When threat intel enrichment is active:

- **Queried:** File hashes (SHA-256), IP addresses, domain names
- **Not sent:** Process names, command lines, user context, file contents
- **Sources:** abuse.ch (URLhaus, MalwareBazaar, ThreatFox)

### Fleet Telemetry (opt-in)

When enrolled in fleet management:

- **Sent:** Machine ID, event counts, alert summaries, security score
- **Not sent:** Process names, command lines, user data, file paths

### Third-Party Forensic Plugins (opt-in)

If you install a forensic plugin from the rave marketplace (or sideload one), it
is **third-party code** and runs **only under a deny-default sandbox**. It can
read **only** the files its signed manifest declares, and the install consent
sheet shows you the exact read-set, derived from those declared capabilities (a
plugin cannot under-declare). Specifics:

- **Personal-comms stores** (Messages `chat.db`, Mail, Safari history, …) are
  never read live — MacCrab snapshots them into a plugin-unwritable copy and the
  plugin reads the snapshot. The plugin never inherits your Full Disk Access.
- A plugin sends data off your machine **only** if its manifest declares network
  egress AND you consent — a plugin that both reads personal data and has network
  is surfaced as a high-friction "disclosed exfil surface" in the consent sheet.
- You can revoke a publisher's trust, freeze the catalog, or locally disable all
  third-party plugin execution at any time.

By default no third-party plugins are installed and the marketplace ships
fail-closed.

## Data Retention

Retention is bounded by **both** a time horizon and a size cap under the
`storage{}` block of `daemon_config.json` (all keys optional; missing keys use
the defaults below):

| Data | Default Retention | Configurable |
|------|-------------------|-------------|
| Raw events | ~30 min hot tier, then rolled into aggregates | `storage.events_hot_tier_minutes` |
| Event aggregates | 90 days | `storage.aggregate_days` |
| Alerts | 365 days | `storage.alerts_retention_days` |
| Campaigns | 365 days | `storage.campaigns_retention_days` |
| Causal traces / TraceGraph | 90 days | `storage.traces_retention_days` / `storage.tracegraph_retention_days` |
| Behavioral baselines | In-memory (lost on restart) | No |
| Threat intel cache | 24 hours | No |

(The legacy top-level `retention_days` / `max_database_size_mb` keys from v1.7
still decode and are folded onto the `storage{}` block at load.)

## Data Encryption

- **At rest:** Optional AES-256 field-level encryption for the SQLite database. Enable with `MACCRAB_ENCRYPTION_DB=1`. Encryption key is stored in the macOS Keychain.
- **In transit:** All HTTPS connections use TLS 1.2+ minimum. Optional SPKI certificate pinning for LLM providers.

## Deleting Your Data

```bash
# Delete all events and alerts
maccrabctl clear-data

# Full uninstall (removes all data and binaries)
sudo ./scripts/uninstall.sh

# Or via Homebrew
brew uninstall maccrab
```

The uninstall script will ask before deleting data and preserves it if you decline.

## Third-Party Services

MacCrab does **not** use any analytics, tracking, or advertising services. There are no cookies, no user accounts, and no cloud infrastructure.

## Changes to This Policy

Changes to this privacy policy will be documented in release notes and committed to this repository. The git history of this file serves as the changelog.
