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
| Detection alerts and trigger evidence | Security findings | SQLite `alerts.db`; upgrades may retain older evidence in `events.db` |
| Correlated campaigns | Multi-event investigations | SQLite `campaigns.db` |
| Causal traces and agent spans | Process/session attribution | SQLite `tracegraph.db` and `traces.db` |
| Forensic cases, when created | Operator-requested investigations | User support directory under `Cases/<case-id>/` |
| Behavioral baselines | Anomaly detection | JSON files in the support dir — `baseline.json`, `process_tree_model.json`, `mcp_baselines.json` |

In v1.22.0, `events.db` contains the checksummed event journal and a sparse
search projection. Journal checksums detect damage; they do not encrypt its
contents. The event and alert database families include their SQLite WAL and
shared-memory sidecars. Case directories may also contain snapshots, blob
vaults, manifests, and invocation logs. Exported reports and bundles remain
where you choose to save them.

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
| **abuse.ch** (URLhaus / MalwareBazaar / Feodo) | IOC feed refresh, every ~4h | **Off** | Download request for IOC lists; no observed events uploaded | Your source IP, MacCrab version, ordinary request metadata, and Auth-Key for authenticated exports | Settings → Network enrichment, or `threatIntelEnabled` |
| **osv.dev** | CVE lookup, hourly when enabled | **Off** | Your installed-software inventory (anonymous) | Your installed software list | `vulnScanEnabled` |
| **npm / PyPI / Homebrew / crates** registries | Package-freshness check, on install — **and on demand** via the MCP tools `analyze_package_metadata` / `verify_package_attestation` | **Off** | The package name (and, for attestation, the version) being looked up | The package **name** you install or ask about | `packageFreshnessEnabled` for the automatic check. The two MCP tools are a separate path and require the `config` agent capability, which a human must turn on in Settings → Agent Control (off by default) |
| **crt.sh** | Certificate-Transparency lookup, on an observed destination domain | **Off** | The domain being looked up | The **domain** you connect to | `certTransparencyEnabled` |
| **maccrab.com** (Sparkle appcast) | Update check (standard auto-update) | **On** | Feed request; the default user agent includes the app and Sparkle versions | Your source IP, app/version information, and ordinary request metadata; no detection data | Disable automatic update checks in Settings; manual checks still make a request |

Toggle the four enrichment feeds in **Settings → Network enrichment**. That
writes `~/Library/Application Support/MacCrab/user_overrides.json` — a file in
your own home, **no `sudo`** — and asks the running engine to re-read it. Because
it is an ordinary JSON file you own, it is also the hand-edit path if you prefer
a text editor; the keys there are `threatIntelEnabled`, `vulnScanEnabled`,
`packageFreshnessEnabled`, `certTransparencyEnabled` (the `threat_intel_enabled`
snake_case spellings are accepted too). One caveat worth stating because it is
otherwise silent: the engine only honours an overrides file in the home directory
of an account in the **admin** group, so that a standard user on a shared Mac
cannot weaken the operator's configuration. On a managed Mac, ask an admin — or
use the root file below.

From a terminal, `maccrabctl config set` turns any of the four **off**:

```bash
maccrabctl config set cert_transparency_enabled false
maccrabctl config set threat_intel_enabled false
maccrabctl config set vuln_scan_enabled false
maccrabctl config set package_freshness_enabled false
```

No `sudo` is needed. The CLI queues a request; the running engine applies it
when it drains the inbox, normally within about five seconds. A queued request
is not confirmation that the change has taken effect.

These four are the only keys the CLI accepts in one direction only: it will
refuse `true`. Use **Settings → Network enrichment** or the root configuration
file to enable a feed after reviewing its payload above. Certificate
Transparency lookups disclose queried domains to the service; OSV lookups
disclose installed-software information. These settings and the user-owned
override file are local configuration controls, not proof that each change was
made by a person.

The engine's own `daemon_config.json` (same four snake_case keys) works as well,
but on a release install it is root-owned `0600`, so editing it requires `sudo`.
`maccrabctl config get` will tell you when the root file exists but your account
cannot read it, rather than reporting "defaults".

Changes are honored live — disabling a feed stops its egress without a restart,
whether you used Settings, the CLI, or a `SIGHUP` after a root edit. Local
detection (rules, sequences, campaigns, bundled IOCs) is unaffected by these
toggles and never makes a network request.

The local typosquat check is **not** in this table because it runs entirely
on-device and makes no network request.

### Config-gated integrations (no setup → no calls)

The following make **no** network calls unless you, the operator, explicitly
configure a key or endpoint for them — there is no default destination:

- **LLM reasoning backends** — Claude, OpenAI, Mistral, Gemini, and Ollama
  (local when configured to use a server on this Mac). See the section below.
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
provider in Settings → AI Backend). With no provider configured, no LLM request
is sent. To keep prompts on this Mac, use **Ollama** with a local server;
configuring a remote Ollama endpoint sends prompts to that endpoint.

When a cloud backend is enabled, the data sent is **sanitized alert context**:
rule titles, MITRE ATT&CK techniques, process trees, and redacted file paths.

| What is sent (sanitized) | What is redacted (best-effort) |
|-------------|-----------------|
| Rule titles & detection context | Usernames — real account names + `/Users/<name>/` paths → `[USER]` |
| MITRE ATT&CK techniques | Private **and** public IP addresses → `[PRIVATE_IP]` / `[PUBLIC_IP]` |
| Process trees (names, redacted paths) | Hostnames & computer names → `[HOSTNAME]` / `[COMPUTER_NAME]` |
| Alert summaries | Email addresses → `[EMAIL]` |
| | API keys, passwords, tokens, CDHashes (redacted) |

Cloud LLM prompt sanitization is performed by `LLMSanitizer.swift`. Other
outbound integrations have their own payload policies and do not pass through
this sanitizer. See `Sources/MacCrabCore/LLM/LLMSanitizer.swift` for the
implementation.

> **Best-effort, not a guarantee.** The sanitizer is a heuristic scrubber that
> redacts the patterns above; it cannot guarantee that every sensitive token in
> a free-form log line is caught. To avoid sending prompts off this Mac, leave
> cloud analysis disabled and use a local Ollama server if desired.

**Known gaps (best-effort mode).** The sanitizer can miss: custom / non-vendor
API-key shapes not in its pattern set; secrets at line boundaries inside long
multi-paragraph context; base64 / certificate-chain blobs; and internationalized
usernames. Past releases have fixed real misses here (e.g. bare usernames and
public IPs in v1.6.7), which is exactly why it is documented as best-effort.

**Strict mode (opt-in, additional heuristic screening).** Set
`"strictSanitize": true` under the `llm` block in `daemon_config.json`. When on,
MacCrab refuses a cloud LLM prompt when its additional detector flags residual
high-entropy, secret-shaped content after sanitization. This can skip analysis
of some alerts and reduce disclosure risk. It remains a heuristic: passing the
check does not establish that a prompt contains no sensitive information.

**Supported providers:** Ollama (local or operator-configured remote), Claude
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
**download-only**: MacCrab fetches IOC lists and does not upload observed
events or the software inventory. Requests disclose your IP address, the
MacCrab version, and ordinary request metadata. URLhaus and MalwareBazaar
require an abuse.ch Auth-Key, stored in the shared macOS Keychain; their
export APIs receive that credential in the HTTPS URL path. Feodo uses a public
export without that credential. Saving a key does not enable network refresh.
A missing or unreadable key leaves those two feeds unavailable while retaining
previously cached indicators. Manually launched engines also retain the legacy
`MACCRAB_ABUSECH_AUTH_KEY` fallback when no Keychain item exists; environment
variables are not encrypted storage. When optional, key-gated reputation lookups (VirusTotal, Shodan,
MISP) are configured, they additionally:

- **Query:** File hashes (SHA-256), IP addresses, domain names
- **Do NOT send:** Process names, command lines, user context, file contents
- **Sources:** abuse.ch (URLhaus, MalwareBazaar, Feodo) for the download-only
  feeds; VirusTotal / Shodan / MISP only when you supply an API key

### Fleet Telemetry (opt-in)

When enrolled in fleet management, each push carries exactly the fields of the
`FleetTelemetry` payload — nothing more, nothing less:

- **Sent:** a pseudonymous host ID (SHA-256 of hostname + hardware UUID); the
  timestamp; the MacCrab version; per-alert `{rule ID, rule title, severity,
  process path, MITRE techniques}`; IOC sightings `{type, the matched value —
  including domains, IPs and hashes — plus a short context string}`; and top
  behavioral scores `{process path, score, indicators}`.
- **Not sent:** command lines, file contents, raw event bodies, event counts,
  security score.
- **Process paths and matched IOC values do leave your machine.** Paths and
  context strings are scrubbed by the same best-effort sanitizer used for cloud
  LLM calls (usernames, hostnames, private IPs) — heuristics, not a guaranteed
  no-leak boundary, so treat a fleet collector as a system that will eventually
  see some path fragments. The IOC value itself is deliberately **not**
  redacted: sharing it is the entire point of the feature.

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
| Behavioral baselines | Persisted to disk and rebuilt continuously — **no retention limit and no size cap** | No |
| Threat intel cache | 24 hours | No |

(The legacy top-level `retention_days` / `max_database_size_mb` keys from v1.7
still decode and are folded onto the `storage{}` block at load.)

## Data Encryption

- **At rest:** AES-GCM **column** encryption, **on by default**, with the key in
  the macOS Keychain. The scope is narrow and worth stating plainly: it covers
  only specific JSON columns in `traces.db` / `tracegraph.db` (TraceStore /
  SQLiteCausalGraphStore). **`events.db` (including `alert_evidence`),
  `alerts.db` and `campaigns.db` are stored in plaintext** — this includes the
  event journal and new trigger evidence stored in `alerts.db`.
  Whole-database encryption for those detection stores is not shipped.
  Forensic cases have a separate encryption setting: encrypted cases use
  SQLCipher for `case.sqlite` and a blob vault; case metadata and logs can remain
  readable without unlocking. `MACCRAB_ENCRYPT_DB=0` disables the
  column encryption (an escape hatch for tests and bisects). There is no
  `MACCRAB_ENCRYPTION_DB` variable — an earlier version of this document named
  one, and setting it did nothing at all.
- **What actually protects the plaintext stores:** file permissions, not
  cryptography. The support directory is root-owned and the databases are
  `0640 root:admin`, so the boundary is same-machine admin-or-root. If you do
  not run FileVault, turn it on — and exclude
  `/Library/Application Support/MacCrab/` from your backup set, because the
  event store holds sanitized argv, every file path touched, every network
  destination, working directories and usernames for the whole retention
  window. MacCrab does **not** set a backup-exclusion flag for you.
- **In transit:** All HTTPS connections use TLS 1.2+ minimum. Optional SPKI certificate pinning for LLM providers.

## Deleting Your Data

There is no single `maccrabctl` command that erases all product data. Release
detection stores are root-owned under `/Library/Application Support/MacCrab/`,
so deleting those stores requires administrator access. **Quitting MacCrab.app does not stop its
System Extension.** Before removing data, use **Remove System Extension** in
MacCrab's Settings, approve the macOS request, and wait for removal to complete.
If macOS reports that removal requires a reboot, reboot first. Confirm the
extension is no longer active with `systemextensionsctl list`, stop any
separately launched development daemon, then quit the dashboard and MCP clients.
Do not erase data while removal is pending or the engine is still running.

```bash
# Only after the engine has stopped and extension removal has completed:
# delete the support directories, including forensic cases saved there.
sudo rm -rf "/Library/Application Support/MacCrab/"   # system data (release install)
rm -rf "$HOME/Library/Application Support/MacCrab/"   # dev / non-root data
rm -f  "$HOME/Library/Preferences/com.maccrab.app.plist"  # app preferences

# Full uninstall from a source checkout (asks before deleting data).
# Complete extension removal first using the steps above.
sudo ./scripts/uninstall.sh

# Or via Homebrew
brew uninstall --cask maccrab
```

The uninstall script asks before deleting data and preserves it if you decline.
If extension removal is still pending, decline data deletion and finish removal
first. Homebrew's ordinary uninstall preserves support data; `--zap` also removes
the configured data directories, so use it only after the engine has stopped.
Reports, bundles, or backups saved outside these directories are separate copies
and are not removed by these commands.

## Third-Party Services

MacCrab does not send product analytics or advertising telemetry by default.
The update service and optional destinations listed above receive requests when
their corresponding features run. Their infrastructure and logging policies
are separate from the local detection stores.

## Changes to This Policy

Changes to this privacy policy will be documented in release notes and committed to this repository. The git history of this file serves as the changelog.
