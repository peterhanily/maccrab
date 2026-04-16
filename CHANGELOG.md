# Changelog

All notable changes to MacCrab. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [SemVer](https://semver.org/spec/v2.0.0.html).

## [1.2.1] — 2026-04-16

Patch release focused on false-positive reduction on real dev workstations.
No schema or config changes — safe to upgrade from 1.2.0 in place.

### Changed

**Detection tuning (false-positive reduction):**
- `LibraryInventory` now allowlists Homebrew (`/opt/homebrew`,
  `/usr/local/Cellar`, `/usr/local/opt`), MacPorts (`/opt/local`), and
  Nix (`/nix/store`) roots, and gates any dylib in an unexpected
  location on `SecStaticCodeCheckValidity` against `anchor apple
  generic`. Signed libraries are skipped regardless of location. Per-path
  signature cache avoids re-evaluation cost.
- `SystemPolicyMonitor.scanDownloadsForMissingQuarantine` now dedups
  per path (was re-alerting every 5-min poll), skips files validly
  signed under an Apple anchor, and ignores `.dmg`/`.iso` containers
  (Gatekeeper re-evaluates them on mount).
- `TLSFingerprinter` beacon allowlist expanded from browsers-only to
  cover chat (Slack, Discord, Signal, Telegram), meeting (Zoom, Teams),
  dev tools (GitHub Desktop, VS Code, JetBrains, Docker), and AI
  helpers (Claude, Codex, Cursor, ChatGPT Atlas). `node`/`deno`/`bun`
  skipped outright.
- `PowerAnomalyDetector` legitimate-holder set expanded
  (`screensharingd`, `bluetoothd`, `rapportd`, `mediaremoted`, Xcode,
  Docker, OrbStack, etc.) with per-process-name dedup so a single poll
  re-entry can't double-fire.
- `CrossProcessCorrelator` now suppresses network-convergence alerts
  when every contacting process shares a `.app` bundle, an exact
  executable path, or a tool-version directory. Additionally suppresses
  by destination for well-known cloud CDNs (Anthropic, OpenAI, Google,
  Cloudflare, GitHub) — multi-process fan-out to those is architecture.
- `AINetworkSandbox` falls back to a cloud IP-prefix list when DNS
  correlation is absent, so repeated AI-tool calls to the same backend
  IP don't fire one violation per unique IP.
- `BehaviorScoring` now applies a 120s per-indicator cooldown per
  process. A single chatty signal can no longer walk a score to
  threshold alone.
- `AlertDeduplicator.normalizePath` regex now also strips
  version-like segments at end-of-path (`/v?\d+\.\d+(\.\d+)*$`) so
  `/.../versions/2.1.111` and `/.../versions/2.1.112` deduplicate.
- `RuleEngine` via `EventLoop` now drops non-critical rule matches
  when the event has no attributable process (`process.name == "unknown"`
  or empty executable). File-event rules with `Image|contains` filters
  fail open on FSEvents without process info, which produced
  unattributable mediums we couldn't triage.
- New warm-up window: non-critical rule matches are suppressed for the
  first 60s after daemon start. Inventory scans (browser extensions,
  quarantine state, process-tree baseline) complete in this window.
  `DaemonState.isWarmingUp` gates the event loop; critical matches
  still fire so a ransomware note at T+10s isn't missed.

**Rule updates (YAML):**
- `command_and_control/c2_beacon_pattern.yml`: new `filter_dev_tools`
  and `filter_homebrew_node` exclusions.
- `defense_evasion/invisible_unicode_in_source.yml` and
  `trojan_source_bidi_code.yml`: exempt `.lproj/`, `.strings`,
  `.xliff`, `.po`, `/locales/`, `/_locales/`, `/i18n/`,
  `/translations/` paths (legitimate RTL text and zero-width joiners
  in localization files).

### Added

**Feedback loop (self-tuning severity):**
- `AlertDeduplicator.recordDismissal(alertId:ruleId:)` +
  `dismissalCount` + `dismissalRate` + `effectiveSeverity`. Tracks
  user dismissals idempotently by alert ID. Rules with ≥3 dismissals
  at ≥70% rate auto-downgrade one severity level on future firings
  (e.g. `high` → `medium`). `critical` is never downgraded and no rule
  goes below `medium`.
- `AlertStore.listSuppressed(limit:)` returns `(id, ruleId)` pairs for
  alerts the user has dismissed in the dashboard.
- New 60-second `DaemonTimers.feedbackTimer` sweeps the AlertStore
  for new dismissals and feeds each into the deduplicator.
- `EventLoop` consults `effectiveSeverity` when persisting the alert
  and only surfaces OS notifications when the downgraded severity is
  still `high` or `critical`.

**Browser extensions dashboard:**
- `BrowserExtensionsView` rows are now buttons that open a detail
  sheet with full manifest metadata: description, version, manifest
  version, author, homepage URL, update URL (flagged non-Web-Store),
  host permissions, content scripts with match patterns, background
  service worker / script list.
- 0–100 risk score + 4-tier label (Low risk / Caution / Suspicious /
  High risk) replaces the binary "Suspicious" flag.
- Per-risk-factor breakdown explains why a rule scored.
- Every permission carries a category (network / data / execution /
  device / host / meta) and a plain-English description from an
  internal dictionary; dangerous permissions visually distinguished.
- On-disk facts: install date (manifest mtime), size on disk
  (recursive), extension path. Quick actions: Reveal in Finder,
  deep-link to `chrome://extensions/?id=…` / `brave://…` /
  `edge://…`, open homepage.
- `__MSG_*` locale tokens in `manifest.json` now resolve against
  `_locales/<locale>/messages.json` instead of displaying raw.

### Impact (measured)

Reference workstation, 24-hour observation:

- Before: **2,856 alerts / 24h**, top 5 rules accounted for ~95%.
- After: **3 alerts / 11min** across two full forensic scan cycles
  post-restart, with the remaining 3 being legitimate singletons.

### Migration

Drop-in upgrade from 1.2.0. No schema changes, no config changes.
Existing per-alert suppressions from 1.2.0 continue to work and now
feed the auto-tune.

## [1.2.0] — 2026-04-16

Minor release. Models, exports, integrations, and agentic triage land
alongside the existing v1 detection stack. No destructive schema
changes; earlier installs upgrade automatically via `PRAGMA user_version`.

### Added

**Foundation (Phase 1):**
- Forward-only SQLite schema migrator (`SchemaMigrator`) wired into
  every store. Earlier DBs auto-migrate on first 1.2.0 open.
- `FileHasher` actor: SHA-256 with LRU cache keyed on path+mtime+size,
  256 MB cap, skips network mounts via `URL.volumeIsLocalKey`.
- `ProcessHasher` combines SHA-256 (FileHasher) with CDHash
  (CDHashExtractor) concurrently via `async let`.
- `ProcessInfo` gains `ProcessHashes`, `SessionInfo`, opt-in env capture.
- `CodeSignatureInfo` gains `issuerChain`, `certHashes`,
  `isAdhocSigned`, `entitlements` — populated by `CodeSigningCache`.
- `Alert` gains `campaignId`, `hostContext`, `analyst` metadata,
  `d3fendTechniques`, `remediationHint`, `llmInvestigation`.
- `CampaignStore` — persistent campaigns table, survives daemon
  restarts with suppression + analyst notes.
- `OCSFMapper` — maps `Event` → OCSF 1.3 `process_activity` (1007) /
  `file_activity` (1001) / `network_activity` (4001); `Alert` →
  `security_finding` (2004) with MITRE ATT&CK attacks block.

**Enrichment wiring (Phase 1 second wave):**
- `SessionEnricher` infers `LaunchSource` from ancestor chain (sshd →
  `.ssh`, Terminal/iTerm/Ghostty → `.terminal`, Finder → `.finder`,
  cron → `.cron`, etc.).
- `EnvCapture` reads target-process environment via
  `sysctl(KERN_PROCARGS2)`, gated on `MACCRAB_CAPTURE_ENV=1`. Secret-
  bearing keys (AWS_SECRET_*, *_TOKEN, *_PASSWORD) denied by default.

**Detection (Phase 2):**
- 16 new rule selectors in `RuleEngine.resolveField` + compiler
  passthroughs: `ProcessSHA256`, `ProcessCDHash`, `SigningCertIssuer`,
  `SessionTTY`, `SessionSSHRemoteIP`, `LaunchSource`, `IsSSHLaunched`,
  `IsAdhocSigned`, `AncestorDepth`, `EnvVarsFlat`, etc.
- `falsepositives` annotations on every sequence rule (26 rules).
- Three new hash/session-aware rules:
  `persistence/adhoc_signed_launchagent_write`,
  `defense_evasion/dyld_insert_libraries_env`,
  `credential_access/ssh_launched_security_dump`.

**Deception (Phase 3):**
- `HoneyfileManager` deploys canary files at standard credential paths
  (~/.aws/credentials.bak, ~/.ssh/id_rsa.old, ~/.kube/config.backup,
  ~/.netrc.backup, ~/.docker/config.json.bak, ~/.gcp-service-account
  .json.bak, keychain + browser-password backups). Opt-in via
  `MACCRAB_DECEPTION=1`. Maps to MITRE D3FEND D3-DF.
- `Rules/persistence/honeyfile_accessed.yml`: critical severity with
  self-read filter.
- `maccrabctl deception {deploy, status, remove}` CLI.

**Allowlist v2 (Phase 3):**
- TTL expiration (`expiresAt`), scope kinds (`rule_path`, `rule_hash`,
  `rule`, `path`, `host`), source tagging, required reason field.
- v1 flat-dict → v2 versioned-file migration on load, rewritten on
  next save.
- Append-only audit log at `suppressions_audit.jsonl`.
- Daemon sweep every 5 min prunes expired entries.
- `maccrabctl allow {add, list, remove, stats}` CLI with `--ttl`,
  `--scope`, `--reason`, `--expired` flags.
- `SuppressionManagerView` overhauled with scope filter chips,
  expiry countdowns, live reload from disk.

**Agentic LLM triage (Phase 4):**
- Structured `LLMInvestigation` schema: `Verdict` enum, `Evidence`
  chain, `SuggestedAction` (8 kinds with D3FEND ref + blast radius +
  `requiresConfirmation`), `MITREMap`, confidence penalties.
- `LLMService.investigate(alert:event:)` — rigid JSON-only prompt,
  temperature 0.1, single retry on malformed output, markdown code-
  fence stripping, missing-id backfill.
- `AlertStore` schema v2 persists the investigation (`llm_investigation
  _json` column); `updateInvestigation(alertId:)` for in-place update.
- EventLoop auto-triggers on HIGH/CRITICAL alerts in a detached Task —
  model latency never blocks detection.
- Dashboard `InvestigationSection` renders verdict + confidence bar +
  evidence chain + MITRE reasoning + suggested-action rows with
  **Preview / Confirm / Dismiss** controls. Nothing auto-executes.

**UI complexity modes (Phase 5):**
- Basic / Standard / Advanced modes filter the sidebar. Settings >
  Appearance tab exposes the toggle. Default stays Advanced so
  upgrades preserve current UX.
- D3FEND technique references attached to all 9 Prevention modules +
  HoneyfileManager, with a shared `D3FENDMapping` catalog.

**Exports (Phase 7):**
- `Output` protocol unifies all alert sinks (`send(alert:event:)`,
  `flush()`, `outputStats()`, `health()`). Existing
  WebhookOutput / SyslogOutput / NotificationOutput retrofit.
- `FileOutput`: NDJSON writer with size + age rotation, N-archive
  retention, 0o600 permissions. OCSF by default; native-envelope
  alternative.
- `StreamOutput`: Splunk HEC, Elasticsearch Bulk API, Datadog Logs.
  Per-SIEM body framing, exponential-backoff retry, token resolution
  from env (never from on-disk config).
- `daemon_config.json.outputs[]` schema drives factory-based
  instantiation; `additionalOutputs: [any Output]` on DaemonState.

**SIEM integration bundles (Phase 8):**
- `integrations/wazuh/` — JSON decoder + 10 rules mapping MacCrab
  severities and MITRE tactics to Wazuh levels 1–14. Honeyfile
  access escalates to level 14.
- `integrations/elastic/` — typed index template for every OCSF field
  + starter Kibana saved-objects (index pattern + dashboard).
- `integrations/osquery/packs/maccrab.conf` — 12 macOS posture
  queries (listening ports, unsigned LaunchAgents, kexts, DYLD-
  injected processes, quarantined executables, etc.).

**Behaviour analytics (Phase 9):**
- `UEBAEngine` with per-user baseline (login hour histogram, SSH
  source IPs, tool usage). Emits anomalies after a cold-start gate
  (default 100 observations). Kinds: `unusualLoginHour`,
  `newSSHSource`, `novelTool`.

**Test hardening (Phase 6):**
- PanicButton / TravelMode coverage (previously greenfield).
- `ResponseActionCoverageTests` covers blockNetwork / script /
  escalateNotification plus Codable round-trip for every
  `ResponseActionType`.
- Test count grew from 326 (1.1.1 cut) to 535 (1.2.0 cut).

### Changed

- `Alert.llmInvestigation` type moved from a Phase 1 placeholder to
  the rich `LLMInvestigation` schema in `Sources/MacCrabCore/LLM/`.
  Verdict now an enum; old String-valued verdict values still decode.
- `RuleTestHelpers.ensureRulesCompiled()` now mtime-aware; adding a
  rule no longer requires `rm -rf /tmp/maccrab_v3` before tests.
- `SuppressionManager` v1 → v2 schema migration happens silently on
  first load and the file is rewritten in v2 shape on next save.
- About tagline: "Made with love and tokens in Ireland."

### Deferred to v2.1

- `S3Output` (hand-rolled SigV4 or AWS SDK for Swift dependency).
- `SFTPOutput` via NSTask `sftp`.
- `WazuhOutput` direct-to-manager API push (beyond file-tail).
- Osquery **producer** extension — exposing `maccrab_alerts`,
  `maccrab_events`, `maccrab_campaigns` as virtual tables so analysts
  can JOIN in `osqueryi`. Consumer (`OsqueryCollector`) still planned.
- Executing confirmed `SuggestedAction`s from the Investigation panel
  (currently UI-only).
- LLM eval harness with 50 labeled scenarios per backend.
- Native macOS 15.4+ `ES_EVENT_TYPE_NOTIFY_TCC_MODIFY` for TCC monitor
  (requires ES entitlement release builds don't carry).
- UEBA baseline persistence across daemon restarts.

### Security

- Every opt-in feature is default OFF:
  `MACCRAB_DECEPTION`, `MACCRAB_CAPTURE_ENV`,
  `daemon_config.json.outputs[]` array.
- Secrets never written to disk: StreamOutput tokens resolved from
  env (`tokenEnv:` in config); EnvCapture deny-list blocks
  AWS_SECRET_*, *_TOKEN, *_PASSWORD even if allowlisted.
- CommandSanitizer still wraps every outbound payload across all
  Output sinks.
- Files written by new outputs land at 0o600 (FileOutput) and 0o400
  (honeyfiles — matches real credential-file mode).

### Migration notes

- Schema migrations applied by 1.2.0 are one-way. After a 1.2.0
  daemon opens `events.db` or `suppressions.json`, downgrading to
  1.1.x is unsupported. Take a backup if you plan to roll back.
- `daemon_config.json` keys remain additive — every new 1.2.0 option
  has a default so existing files keep working.
- Existing shell environment variables (`MACCRAB_WEBHOOK_URL`,
  `MACCRAB_SYSLOG_HOST`, `MACCRAB_SYSLOG_PORT`) still work as before
  and coexist with the new `outputs[]` array.

## [1.1.1] — 2026-04-08

See git history for pre-1.2 entries. Individual 1.1.x releases were
tracked in `RELEASE_NOTES.md` and commit messages rather than this
changelog.
