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

**With default settings, MacCrab makes no enrichment network calls.** There is
zero telemetry and no phone-home behavior. The four network-enrichment feeds are
**off by default** (opt-in, as of v1.19.1); the only outbound connection a stock
install makes is the signed software-update check.

### What MacCrab connects to

Every outbound destination, its trigger, default state, what is sent, and how to
turn it off:

| Destination | Trigger | Default | What is sent | What it reveals | Turn off |
|---|---|---|---|---|---|
| **abuse.ch** (URLhaus / MalwareBazaar / Feodo) | IOC feed refresh, every ~4h | **Off** | Nothing about your machine — **download only** | Nothing (GET of public IOC lists) | Settings → Network enrichment, or `threatIntelEnabled` |
| **osv.dev** | CVE lookup, hourly when enabled | **Off** | Your installed-software inventory (anonymous) | Your installed software list | `vulnScanEnabled` |
| **npm / PyPI / Homebrew / crates** registries | Package-freshness check, on install | **Off** | The package name being installed | The package **name** you install | `packageFreshnessEnabled` |
| **crt.sh** | Certificate-Transparency lookup, on an observed destination domain | **Off** | The domain being looked up | The **domain** you connect to | `certTransparencyEnabled` |
| **maccrab.com** (Sparkle appcast) | Update check (standard auto-update) | **On** | Nothing but the request itself; the update is EdDSA-signed | Your IP address only | Disable auto-update |

Toggle the four enrichment feeds in **Settings → Network enrichment**, by
`maccrabctl config set`, or by hand in `daemon_config.json` (keys
`threat_intel_enabled`, `vuln_scan_enabled`, `package_freshness_enabled`,
`cert_transparency_enabled`). Changes are honored live on `SIGHUP` — disabling a
feed stops its egress without a restart. Local detection (rules, sequences,
campaigns, bundled IOCs) is unaffected by these toggles and never makes a network
request.

The local typosquat check is **not** in this table because it runs entirely
on-device and makes no network request.

### Config-gated integrations (no setup → no calls)

The following make **no** network calls unless you, the operator, explicitly
configure a key or endpoint for them — there is no default destination:

- **LLM reasoning backends** — Claude, OpenAI, Mistral, Gemini (Ollama is fully
  local). See the section below.
- **VirusTotal**, **Shodan**, **MISP** — IOC enrichment; require an API
  key/endpoint.
- **Fleet telemetry** — requires enrollment in a fleet server (see below).
- **SIEM / webhook outputs** — Splunk HEC, Elastic, Datadog, syslog, S3, SFTP,
  custom webhooks; require an explicit endpoint in `daemon_config.json`.

The remaining **optional** features below communicate externally only when
explicitly enabled or configured:

### LLM Reasoning Backends (opt-in, OFF by default)

Cloud AI analysis is **off by default** and must be explicitly opted into by
setting the `MACCRAB_LLM_PROVIDER` environment variable (or choosing a cloud
provider in Settings → AI Backend). With no provider configured, **nothing is
sent anywhere** and all LLM features degrade gracefully. For full privacy, use
the local **Ollama** backend — it runs on your machine and no prompt data
leaves it.

When a cloud backend is enabled, the data sent is **sanitized alert context**:
rule titles, MITRE ATT&CK techniques, process trees, and redacted file paths.

| What is sent (sanitized) | What is redacted (best-effort) |
|-------------|-----------------|
| Rule titles & detection context | Usernames — real account names + `/Users/<name>/` paths → `[USER]` |
| MITRE ATT&CK techniques | Private **and** public IP addresses → `[PRIVATE_IP]` / `[PUBLIC_IP]` |
| Process trees (names, redacted paths) | Hostnames & computer names → `[HOSTNAME]` / `[COMPUTER_NAME]` |
| Alert summaries | Email addresses → `[EMAIL]` |
| | API keys, passwords, tokens, CDHashes (redacted) |

Sanitization is performed by `LLMSanitizer.swift` before any data leaves the
machine. See `Sources/MacCrabCore/LLM/LLMSanitizer.swift` for the full
implementation.

> **Best-effort, not a guarantee.** The sanitizer is a heuristic scrubber that
> redacts the patterns above; it cannot guarantee that every sensitive token in
> a free-form log line is caught. If you require an absolute no-leak boundary,
> use the local Ollama backend instead of a cloud provider.

**Supported providers:** Ollama (fully local — no data leaves machine), Claude
(Anthropic), OpenAI, Mistral, Gemini (Google).

#### Cloud sub-processors

When you enable a cloud LLM backend, your chosen provider acts as a
sub-processor for the sanitized alert context you send. You select exactly one
at a time:

- **Anthropic** (Claude API)
- **OpenAI** (or any OpenAI-compatible endpoint you configure, incl. Azure OpenAI)
- **Google** (Gemini API)
- **Mistral AI**

These providers' standard APIs do not train on inputs/outputs by default, but
none expose a per-request HTTP header to assert zero-data-retention or
no-training — those are account/enrollment-level arrangements with the provider,
not something MacCrab can set on the wire. MacCrab sends only the sanitized
context above; review your provider's data-usage and retention terms before
enabling, and prefer the local Ollama backend if you cannot accept any
third-party data processing.

### Threat Intelligence Feeds (opt-in, off by default)

The bundled abuse.ch feeds (`threatIntelEnabled`, off by default) are
**download-only** — MacCrab fetches public IOC lists; nothing about your machine
is uploaded. When optional, key-gated reputation lookups (VirusTotal, Shodan,
MISP) are configured, they additionally:

- **Query:** File hashes (SHA-256), IP addresses, domain names
- **Do NOT send:** Process names, command lines, user context, file contents
- **Sources:** abuse.ch (URLhaus, MalwareBazaar, Feodo) for the download-only
  feeds; VirusTotal / Shodan / MISP only when you supply an API key

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
