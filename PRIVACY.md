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

## Data Retention

| Data | Default Retention | Configurable |
|------|-------------------|-------------|
| Events | 30 days | `retention_days` in `daemon_config.json` |
| Alerts | 90 days | Yes |
| Behavioral baselines | In-memory (lost on restart) | No |
| Threat intel cache | 24 hours | No |

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
