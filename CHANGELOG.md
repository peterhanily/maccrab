# Changelog

All notable changes to MacCrab. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [SemVer](https://semver.org/spec/v2.0.0.html).

## [1.20.0] — 2026-06-26

A dashboard-customization and rule-delivery release.

### Dashboard
- The Overview is now a customizable dashboard: show or hide any panel, drag to rearrange, and resize panels to a 1–4 column width. Your layout is saved and persists across app updates (and is resilient to a corrupted preferences file). The protection-status banner stays pinned. The Event Rate and Threat Intel panels are back.

### Forensics
- "Run a scan" is simplified to two clear lists — Built-in scanners and Installed plugins — each collapsible and expanded by default. The kit picker was removed.
- Forensic plugins now show their provenance at a glance: Built-in, Store, or Sideloaded.

### Detection
- Detection rules can be updated out-of-band from a signed channel, separately from the app, so new rules ship without an app update or restart. Pushed rules are Ed25519 signature-verified, anti-rollback protected, and strictly detection-only — they never trigger response actions and never override a built-in rule (`maccrabctl rules update`).

### Privacy & hardening
- Cloud LLM backends gain a strict no-leak mode that refuses a request if any sensitive content survives sanitization.
- A false-positive-rate benchmark harness lets the per-rule FP rate be measured on a real machine.

## [1.19.3] — 2026-06-25

A plugin-lifecycle and signal-quality release.

### Plugin updates
- `maccrabctl plugin update <id>` updates an installed plugin through the full signature-verified path; patch updates apply directly, minor/major require confirmation. Forward-only — downgrades are refused.
- The dashboard shows an "Update available" badge and an Update button for installed plugins in Run a scan.
- New `maccrabctl plugin check-updates` reports installed plugins with a newer catalog version; `maccrabctl plugin pin <id>` freezes a plugin at its installed version (a pin never blocks a revocation).

### Detection
- Routine developer-tooling activity (bundlers, package-manager runtimes, language toolchains, AI coding tools) is down-weighted to low severity for review instead of raising high/critical noise. Credential and keychain access, ransomware, security-tool tampering, persistence, and AI-tool credential exfiltration still escalate at full severity, including on developer paths.
- MacCrab's own background processes no longer generate alerts about themselves.

### Forensics
- Installed plugins are managed in one place (Run a scan): run, verify, update, or uninstall. The separate "My Plugins" tab was removed.
- Fixed a case where an installed store plugin had no Run control.

## [1.19.2] — 2026-06-25

A plugin-store and forensics-fidelity release.

### Plugin store
- Installing signed first-party plugins from the catalog now works end to end — browse, install, signature-verify, and trust in one step.
- New `maccrabctl plugin search` lists the signed catalog.

### Forensics
- **Evidence export.** `maccrabctl scan export` and `evidence export` write a `.maccrabevidence` bundle — the case's artifacts plus an integrity hash, verifiable offline.
- **Built-in collector fixes.** FSEvents now reads the modern Data-volume store location (it was looking at a path that no longer exists on current macOS); the plist / DMG-PKG / Office file-analyzers honor an operator-supplied path; Office documents now extract their created/modified timestamps; Biome enumerates the current stream layout.
- Forensic artifact tables render their fields correctly across the dashboard.

## [1.19.1] — 2026-06-23

A forensic-insight, parity, and polish release. The detection engine now
surfaces what it computes — to the dashboard, the CLI, and AI agents alike —
and every interface can drive the core security operations.

### Added
- Forensic findings now carry their full detail (severity, explanation, backing
  evidence, TCC risk score) through the MCP tools, the dashboard, and the new
  `maccrabctl scan findings` / `scan explain` / `scan timeline` commands.
- Response actions are now configurable from the CLI (`maccrabctl actions`) and
  MCP (`list_response_actions` / `set_response_action`), not just the dashboard.
- New CLI commands for parity with the MCP surface: `package` (supply-chain
  analysis), `ai-alerts`, `scan-text`, `config get/set`, `rule delete` /
  `rule severity`, `session` (signed agent-session export/verify), and
  `evidence search` / `evidence show`.
- AI-Guard "tools observed" table, a live prevention-status strip, and humanized,
  clickable MITRE ATT&CK + D3FEND references on alerts.
- Forensic enrichers (threat-intel, code-signing, reputation) are now runnable
  via MCP (`forensics_enrich`) and the CLI, and analyzers via
  `forensics_run_analyzer`.

### Changed
- MCP forensic tools are now underscore-named (`forensics_run_collector`, …) for
  compatibility with strict MCP clients; the legacy dotted names still work.
- Dashboard severity now reflects the engine's computed values instead of a flat
  heuristic; eight high-traffic dashboard surfaces are fully localizable.
- Alert counts are exact (no longer capped/undercounted on busy hosts); several
  dashboard refresh paths are gated so the auto-refresh tick is cheaper.

### Fixed
- Response actions set via any interface now reliably take effect (a config-decode
  edge previously dropped them on reload).
- File-analysis collectors are bounded (size cap + streaming hash) and never
  follow symlinks.
- Campaign correlation no longer labels routine developer tooling (node_modules
  CLIs, the Xcode/Swift toolchain, Homebrew, AI coding agents) as multi-stage
  attacks, and a single alert carrying several MITRE tags is no longer titled a
  "kill chain" — a chain now requires at least two contributing alerts. Genuine
  multi-stage activity and critical-severity events still escalate.
- Supply-chain package detection no longer mints alerts from the word "install"
  appearing inside an unrelated command (e.g. `python3 -c "…"`); extracted
  package names are validated before any registry lookup.
- The canonical `scan` namespace now dispatches `findings` / `explain` /
  `timeline` / `artifacts` (previously only the deprecated `case` alias did).
- `maccrabctl scan new` now creates a case out of the box: the CLI defaults to a
  plaintext (metadata-tier) case — encrypted cases need the dashboard app's
  keychain — with a clear note, and `--encrypt` gives actionable guidance instead
  of a raw `-34018`.
- The MCP server keeps stdout to pure JSON-RPC frames (plugin consent lines now
  go to stderr), so strict hosts no longer desync.
- `maccrabctl campaigns` / `tree-score` no longer crash on a negative count
  argument; `rollup` reports storage deltas correctly; CLI `hunt` searches
  network destination IPs; error paths in `cdhash` / `why` / `allow add` exit
  non-zero for scripting.
- The Security Score's "active alerts" factor reflects the real recent
  critical/high volume instead of a placeholder; `report` humanizes ATT&CK
  technique names and separates non-MITRE extensions from the official taxonomy.

### Security
- Plugin uninstall is now confirmation-gated; forensic tool error messages are
  sanitized; daemon status reports liveness from heartbeat recency.

### Removed
- Unused Objective-See log-ingestion readers (BlockBlock / KnockKnock /
  Little Snitch / LuLu) from the security-tool integration layer. Detection of
  those tools (name + version) is unchanged; only the never-wired log parsers
  were removed. The `.lsrules` threat-intel export is retained.

## [1.19.0] — 2026-06-17

A detection-quality and trust release: far fewer false alerts, an
end-to-end-verified plugin catalog, and bounded storage.

### Added

- **Plugin catalog trust floor.** The rave catalog now verifies trust
  before install: publisher-key pinning bound to the signed catalog
  entry, a signed revocation list (revoked plugins are refused;
  installed-then-revoked plugins are quarantined, never deleted),
  minimum-version floors, anti-rollback on stale catalog/revocation
  replays, and a signed, offline-verifiable install receipt. The
  in-app catalog browser is live behind this verified path.
- **Forensic evidence integrity.** Collected case artifacts carry a
  signed, append-only chain-of-custody verifiable offline.
- **Plugin provenance labels.** The dashboard, CLI, and agent surfaces
  label each plugin as built-in (first-party), third-party
  (operator-trusted publisher key), or store (catalog-installed, with a
  signed install receipt), so a scanner's origin is always clear.
- **CI + provenance.** SHA-pinned continuous integration with SLSA
  build provenance; the release pipeline is decomposed into
  reproducible stages; key-rotation runbooks.

### Changed

- **Trusted-signer criticals are no longer a blanket filter bypass.** A
  critical-severity match on an Apple platform binary or notarized
  Developer-ID app is now trust-filtered like any other match; the
  curated must-fire set (ransomware, SIP/Gatekeeper/AMFI tampering,
  revoked certs, C2, credential theft) still always fires.
- **Attack-campaign correlation applies a consistent severity floor +
  benign-process filter across BOTH correlators** (kill-chain and
  coordinated-attack), so build helpers, test runners, AI coding tools,
  and local dev runtimes that trip a few low/medium tactic rules stop
  minting false multi-stage / "Persistent Threat Actor" campaigns.
  Genuine medium-and-above, multi-rule activity still correlates
  (high/critical from trusted or agent tooling included).
- Rule-count surfaces are consistent across the app, README, and site
  (483 Sigma rules + 46 built-in detections).
- **Honest first-run dashboard.** Before the engine has produced data
  (a fresh install, or before the system extension is approved), the
  dashboard shows an empty/offline state instead of sample data.
- **Plugin catalog shows only active, installable plugins**, with the
  in-app browser verifying trust end to end.
- **Bundled threat-intelligence set curated to verified indicators**;
  current indicators are delivered by the live feeds, reducing false
  positives.

### Fixed

- Apple background remediators (XProtect) are no longer mis-attributed
  as AI-coding-tool activity (removes spurious credential-access alerts).
- Trace-graph and trace databases now honor their size caps (the
  trace-graph file could previously grow past its limit).
- The built-in rule severity control reflects the active override
  instead of always showing "Default."
- Dashboard tables no longer flash empty for one frame on open.
- Coordinated-attack correlation no longer mints a critical "Persistent
  Threat Actor" from a benign dev runtime that trips a couple of
  low/medium tactic rules on one process — the coordinated-attack path
  now carries the same severity floor and benign-process filter the
  kill-chain path already had.
- The events database stays within an honest size cap (the default was
  raised to account for the full-text search index and captured evidence
  the file also holds, which it previously overshot).
- `maccrabctl rules list` / `rules count` no longer miscount the
  rule-bundle manifest as a rule (now a consistent 436 single-event).

## [1.18.1] — 2026-06-11

A dashboard quality release: localization, triage UX, rendering
performance, and accessibility.

### Added

- **Inline rule controls.** Enable/disable a detection from the rules
  table's status dot, and override severity (Critical → Info, or back to
  Default) from the severity chip's menu — no YAML editing required, for
  built-in detections and Sigma rules alike. The rule inspector gains the
  same severity control; severity and disable overrides now compose
  instead of overwriting each other.
- **Accessibility:** command-palette selection/result announcements and
  header semantics; chart summaries for VoiceOver (event histograms +
  forensic charts); sidebar header traits and an adjustable resize
  handle; `docs/ACCESSIBILITY.md` checklist.
- `TRANSLATION.md` translation policy + per-key provenance tracking
  (`translation-state.json`).

### Changed

- **13 languages now 93–97% translated** (from ~35%): de, es, fr, it,
  ja, ko, nl, pl, pt-BR, ru, sv, zh-Hans, zh-Hant. Hardcoded-English
  dashboard section headers localize; detection content stays English by
  design.
- **Alert actions reflowed** into a compact action bar (primary on top,
  secondary paired); the alert notification popover got a
  severity-tinted visual refresh; History-tab row actions use the shared
  button component.
- **Table hover no longer re-sorts.** The shared dashboard table cached
  its filter/sort result and isolated row hover, eliminating up-to-1,000-row
  re-sorts on every pointer movement across Alerts, Rules, Intelligence,
  and System.

### Fixed

- A memory-leak class in the Events aggregate view (parking on >24h
  ranges accumulated layout constraints).
- A suppressed recent alert could appear twice in the History tab.
- The prerelease localization check mis-counted when zero keys were
  missing.

### Build

- Release pipeline: hard-fail if the localization bundle would ship
  incomplete; toolchain recorded in `release.json`; releases pinned to
  Xcode 26.x with source guards against two known Xcode-27 hazards.

## [1.18.0] — 2026-06-10

A detection-quality release. A corpus-wide review of every rule, sequence,
graph, and campaign detection recovered detections that could never fire,
removed the largest false-positive sources, and fixed a filter-negation bug
that could miss real threats. It also adds an agent-session timeline,
tightens MCP-server privacy, and includes reliability and hardening fixes.

### Added

- **Agent session timeline.** A session-keyed timeline of an AI agent's
  activity — events, alerts, configuration changes, and tool calls on one
  rail — with a cryptographically signed, verifiable evidence-bundle export
  and a session list in the dashboard.
- **Deprecated detections are labeled.** Rules that ship disabled now show a
  clear "Deprecated" badge in the Detection list and detail view.

### Changed

- **Recovered detections that could never fire.** A class of rules carried a
  predicate that the engine can never satisfy, so they silently never fired —
  including the Claude Code project-config hook-RCE detection
  (CVE-2025-59536 / CVE-2026-21852), several execution and credential rules,
  and multi-step sequence rules dropped at load. These now fire correctly, and
  a build-time guard fails if a sequence rule is ever silently dropped again.
- **Far fewer false positives.** AI-tool detections now require an actual
  AI-agent ancestor instead of firing machine-wide; TCC permission-grant
  detections resolve the requesting app's real code signature, so a signed
  app outside `/Applications` is no longer flagged as unsigned; severity is
  recalibrated so a chatty rule can no longer mint an unsuppressible critical
  alert.
- **Command-and-control detections catch the common case.** A filter that was
  excluding shell-launched processes — exactly the lineage of a reverse shell
  or `curl | bash` — was removed, so those now fire while developer noise is
  handled by the noise filter.
- **Credential-read detections are active.** Reads of Safari, Notes, and
  password-manager databases and the system shadow-hash store are now
  observed, so the rules that watch them can fire.

### Dashboard, localization & accessibility

- **Localization now applies.** Bundled language packs load across the dashboard
  (severity labels, navigation, and more) and Settings opens in every language;
  coverage is partial and expanding.
- **Density modes work.** The Basic / Standard / Advanced toggle gates which
  workspaces appear in the sidebar; every detection stays active regardless.
- **Restore suppressed campaigns** from the dashboard (Alerts → Suppressed
  campaigns), not only the CLI.
- **Reduce Motion** is honored across workspace inspectors and the trace graph.
- **Command palette** "Create Detection Rule" opens the rule editor.

### Fixed

- **Filter-negation correctness.** A multi-condition exclusion (`not (A and B)`)
  compiled to an over-broad form that could suppress real detections; it now
  negates correctly, closing a class of false negatives.
- **MCP-server privacy.** The MCP server no longer exposes the operator's
  username or home-directory paths to a connected agent.
- **No hung scorers.** Every Security Score subprocess is now bounded by a
  hard-deadline watchdog, so a stuck helper can't stall scoring.
- **CLI polish.** Corrected a rule-count off-by-one, froze CLI vocabulary, and
  added a `modules` command; refreshed documented rule/test counts to a single
  source of truth.
- **Storage diagnostics.** Storage-health reporting now uses a rolling recent
  window instead of a cumulative since-boot total, so a long-past incident no
  longer shows indefinitely.

### Security

- **Custom rules install through the privileged inbox.** User rules + overrides
  are written to a root-owned directory by the daemon (which the engine loads),
  not a group-writable directory it refused — so a dashboard-saved rule takes
  effect.
- **Self-protection alerts.** High-impact privileged-inbox actions now raise an
  observe-only self-protection alert.
- **Signed session evidence.** Exported session bundles are cryptographically
  signed and verified on import; path traversal in bundle handling is blocked.
- **Release hygiene.** The release build aborts if a private key would ship in
  the bundle, and the documentation on compiled-rule file permissions was
  corrected.

### Upgrade

- **Sparkle:** accept the in-app update prompt and relaunch.
- **Homebrew:** `brew upgrade --cask maccrab`
- **Manual:** download the DMG from the release page and replace MacCrab.app.

## [1.17.6] — 2026-06-06

A usability, control, and hardening release on top of v1.17.5: makes the
built-in detections visible and tunable, enriches alerts with what
actually happened, cuts notification noise, makes dashboard rule creation
install rules directly, recovers event sources after an update, adds an
opt-in agent control surface to the MCP server, and tightens the
built-in-rule settings file permissions.

### Added

- **Agent control for the MCP server.** A Claude/Codex session can tune
  detection, author rules, and adjust engine config through three opt-in
  capability tiers (tune / author / defense-affecting), **all off by
  default** and enabled only from Settings → Agent Control. Every change
  is routed through the privileged inbox and audit-logged; response
  actions still never auto-execute. Ships a `maccrab` skill and a
  `/maccrab-control` command.
- **Built-in detections in the Rules list.** The built-in `maccrab.*`
  detections (campaigns, behavioral, sequence/graph, correlation,
  forensic, and more) now appear in Detection → Rules and can be muted or
  have their severity overridden — the detection keeps running when an
  alert is muted.
- **Richer alert detail.** An alert now leads with what actually happened
  (the triggering process, full command, destination, code-signing,
  hashes) rather than only the rule's generic text, and the Events view
  shows which alerts an event triggered.

### Changed

- **Quieter notifications.** New installs and a one-time migration use a
  sensible **High** notification floor, with a warning when the floor is
  set low; several developer-routine AI-tool detections were recalibrated
  to Medium so they're still recorded without posting a banner at the
  High floor. (Notification volume is driven by the floor, not by any
  response-action override.)
- **Seamless rule creation.** The dashboard rule wizard now validates,
  compiles, and installs a new rule directly into the engine — it appears
  in the Rules list and fires immediately — instead of exporting a file.

### Fixed

- **Event sources recovering after an update.** Event sources that
  stalled at 0 ev/s following an in-place update now recover
  automatically instead of needing a restart.
- **Built-in-rule settings hardening.** The built-in-rule settings file is
  now written read-only to non-root users (it's set only by the engine
  through the audited control path), so a local process can't mute a
  detection by editing it directly.
- **Detection-rule validation + docs.** Rule validation now accepts the
  standard Sigma / MITRE tag namespaces (including D3FEND); a malformed
  rule identifier was corrected and the documented rule/test counts were
  refreshed.

## [1.17.5] — 2026-06-04

A feature and hardening release on top of v1.17.4: adds ClickFix
detection and three dashboard improvements, closes a local exfiltration
gap in the engine's LLM-configuration path, completes credential-read
coverage, sharpens several rules against evasion and false positives,
and fixes a Homebrew upgrade that could disturb the system extension.

### Added

- **ClickFix detection.** Flags when a shell command pasted from the
  clipboard (e.g. `curl … | bash`) is then executed — the dominant 2026
  macOS infostealer delivery technique, which sidesteps Gatekeeper
  because nothing is downloaded and launched. The app bridges the GUI
  clipboard to the root engine over the privileged inbox so the
  notify-only system extension can correlate paste→exec.
- **Sortable / filterable tables.** Any table header sorts; a search
  field filters rows — across Alerts, Detection rules, Intelligence, and
  the other tabular views.
- **Tunable built-in detections.** The built-in `maccrab.*` detections
  now appear in the Rules list and can be muted (alert suppressed) or
  have their severity overridden from the dashboard, without editing the
  rule body.
- **Surrounding events survive pruning.** An alert's detail shows the
  events captured when it fired, falling back to the alert's stored
  evidence even after the originating events have aged out of the live
  store.

### Fixed

- **LLM endpoint hardening.** The engine now strictly validates that a
  configured local LLM endpoint is genuinely loopback (IPv4-literal parse,
  not a textual prefix) before trusting it, so a hostname crafted to look
  local can't redirect the engine's LLM traffic to an external host or
  bypass prompt sanitization.
- **Homebrew upgrades no longer disturb the system extension.** The cask
  uninstall step previously ran on `brew upgrade` and could tear down the
  Endpoint Security extension mid-upgrade; it no longer does. Deactivation
  on a true uninstall is handled by the in-app control or the bundled
  uninstall script.
- **Cryptocurrency-wallet read coverage.** Credential-read detection now
  covers the full set of wallets the rule targets (MetaMask, Phantom,
  Atomic, Coinomi, and others) rather than a subset; a build-time check
  keeps the open-monitoring allowlist in sync with the rule.
- **Credential reads in the trace graph.** File-open/read events now map
  into the causal graph, so multi-step credential-access traces
  materialize.

### Improved

- **Detection precision.** Shell-nesting and keychain/`sudo` lineage
  filters now match at path-component boundaries (closing an evasion gap
  such as staging under a `node_modules` path and removing collisions like
  `screen` vs `screensharingd`); the Wi-Fi extraction rule again matches
  `security find-generic-password -ga`; keychain open-monitoring drops the
  high-volume platform-binary (`securityd`) opens.
- **MCP error reporting.** Tool failures / invalid arguments across the
  hunt, cluster, trace, package, and forensics tools now report as errors.
- **Engine open-event handling** no longer builds process metadata for the
  discarded majority of file opens before the credential-path check.
- **Dashboard.** The Investigation view reads engine LLM health off the
  main thread.

## [1.17.4] — 2026-06-03

A reliability and detection-quality release: bounds runaway disk/CPU
growth, cuts alert noise on developer/AI-tool activity, revives several
detection paths that had silently stopped firing, and makes the
engine-side AI backend actually reachable.

### Fixed

- **Unbounded disk growth.** The causal-graph store (`tracegraph.db`)
  could grow without limit (field-observed at 17 GB) because its
  entity/edge data was never pruned. It now has time-based retention, a
  size cap, and an orphan sweep, with the caps configurable.
- **Sustained CPU.** The detection engine no longer feeds every event
  into the causal graph — it applies the same noise filter as the event
  store and batches each event's graph writes into a single transaction.
- **False "coordinated attack" campaigns on legitimate tooling.** Deep
  shell nesting and keychain/`sudo` rules no longer flood alerts on
  routine developer / AI-agent activity (full process-lineage filtering,
  severity recalibration, and an AI-attribution campaign guard).
- **Credential-file READ detection.** Rules that detect reads of SSH
  keys, cloud credentials, and crypto-wallet data can now fire — the
  engine observes file *opens* for those specific paths (previously it
  only saw writes/closes, so the read rules were dead).
- **14 content-scanning rules revived.** A collector/enricher action
  mismatch had silently disabled every `FileContent` rule (AI skill /
  MCP / workflow poisoning detections); fixed and covered by tests.
- **6 permanently-dead rules** (wrong event category) are now correctly
  marked deprecated, and a new compiler check fails the build if a rule
  ships under a category the engine never dispatches.
- **MCP server transport** is now spec-conformant newline-delimited JSON
  (was LSP-style framing), fixing interop with MCP clients, plus a fixed
  input-parsing bug that could drop or corrupt back-to-back messages.

### Added / Improved

- **Configurable storage caps.** `tracegraph`, OTLP `traces`, generated
  `reports/`, and auto-generated rules now have retention/size knobs in
  `daemon_config.json`; the events write-ahead log is now size-bounded.
- **Engine-side AI backend now works.** Settings → AI Backend now reaches
  the detection engine (via the privileged control channel); the engine
  verifies the configured local model is actually installed before
  enabling LLM features (no more silent 404 loops), and rejects
  non-loopback endpoints by default.
- **Forensic-scan retention** is now enforced automatically.

### Changed (upgrade notes)

- **Forensic scans now auto-delete after 1 year by default** (was:
  never). Set Settings → Scan retention → *Never* to keep everything.
- **The default `alerts.jsonl` tail is no longer written.** Alerts remain
  in the queryable alert store; configure a `file` output in
  `daemon_config.json` if you want a local NDJSON copy.
- **Credential-path file-open monitoring is on by default.** Set
  `subscribe_file_open_events: false` in `daemon_config.json` to disable.

## [1.17.3] — 2026-06-02

A maintenance release: two navigation/notification fixes, a rule-search
improvement, and update-process resilience hardening.

### Fixed

- **Tapping a notification opens the alert.** Clicking a MacCrab
  notification banner now reliably navigates to that alert in the
  dashboard (it previously could report that the link couldn't be opened).
- **"Open rule" on a multi-step detection** (sequence and trace-graph
  rules) now shows an explanation instead of an empty rule list, matching
  the behavior for MacCrab's other built-in detections.

### Improved

- **Rule search matches descriptions** — the Detection rule search now
  searches rule descriptions in addition to id, name, category, and MITRE
  technique.
- **Smoother updates** — the app no longer briefly double-posts
  notifications during the detection-engine handover on update, and the
  dashboard self-recovers if it connected before the updated engine
  finished starting (no manual restart needed).

## [1.17.2] — 2026-06-01

A maintenance release: a security-dependency bump, four operator-reported
fixes, and detection-quality hardening.

### Fixed

- **Notifications won't double-post.** A configured "escalate" response action
  no longer posts its own banner through the legacy "System Events" path — the
  MacCrab app is the single, correctly-attributed notification source.
- **"Open rule" on a built-in alert** (e.g. forensic scanners, cross-process
  correlation) now shows an explanation instead of an empty rule list.
- **The triggering event is preserved with each alert,** so an alert reviewed
  long after the live event was pruned still shows what actually fired (new
  "Triggering event" section in the alert inspector).
- **A revoked-Developer-ID binary is now caught on first execution** — software
  whose Apple certificate was revoked (the typical post-takedown state for
  macOS stealers) is flagged critical even though it still carries a
  structurally-valid signature.
- **Installs no longer trigger a spurious admin prompt** on first launch, and
  `brew` installs now include the graph-detection rules.
- **Uninstall** removes MacCrab's privacy (TCC) grants on a full wipe.
- Fewer false positives: the credential-access monitor now matches credential
  files precisely (no more flagging `.env.example`, `Cookies.tsx`, or public
  SSH keys), and developer-tool builds are recognized reliably.

### Changed

- **Updated Sparkle to 2.9.2,** which addresses two security advisories in the
  auto-update framework. The release pipeline now also self-checks that every
  update is signed with the correct key before publishing.
- The Investigation workspace is now focused on trace analysis; forensic case
  browsing lives entirely in the dedicated Forensics workspace.
- Hardened signer classification so a third-party binary cannot impersonate
  Apple by self-naming its code-signature identifier, and rule overrides are
  no longer honored from a directory writable by non-root accounts.

Universal (Apple silicon + Intel), Developer ID signed and notarized.
Minimum macOS 13.

## [1.17.1] — 2026-05-31

Fast-follow fixing notifications (GitHub issue #2) and two operator-reported
bugs in v1.17.0.

### Fixed

- **Notifications are attributed to MacCrab and stop on uninstall.** They
  were posted via `osascript` and showed up under macOS "System Events"
  (so there was no "MacCrab" entry to turn off), and a lingering system
  extension could keep firing them after an uninstall. Delivery now comes
  from the signed app via `UNUserNotificationCenter`: banners appear as
  **MacCrab** with a controllable entry in System Settings > Notifications,
  and stop when the app is removed. If notification permission is denied,
  the Notifications settings tab now says so and links to System Settings.
- **Reload rules** no longer reports "Daemon not running" when the engine
  is alive — the dashboard now reaches the root system extension through
  its privileged inbox instead of an ineffective cross-user signal.
- **Rule search** returns results immediately instead of briefly showing
  an empty list while the rule index finishes loading.
- **Far fewer false-positive alerts.** A quality pass cut the dominant
  noise sources that fired on normal developer/system activity:
  Developer-ID-signed CLI tools (Homebrew/npm/pip/cargo — `uv`, `node`,
  `python`, `esbuild`, etc.) no longer trip the "not notarized" rule;
  Apple's own platform binaries (e.g. `/usr/libexec/nehelper`) are now
  classified correctly and no longer fire as unsigned network extensions;
  MacCrab's own maintenance operations no longer trip self-tamper /
  cross-process alerts; and normal JS bundler builds no longer match the
  "fetched-then-executed" rule.
- **Recalibrated the CRITICAL alert tier.** CRITICAL is now reserved for
  detections we're confident are intrinsically malicious — known-malware
  IOCs, ransomware/disk-wipe, SIP/Gatekeeper/AMFI/XProtect disable, exact
  reverse-shell syntax, honeypot trips, and the full credential→persistence→C2
  campaign. Heuristic, dual-use, and capability-presence detections (and the
  weaker campaign/beacon signals) are now HIGH: still recorded and shown in
  the dashboard, but no longer forcing a banner. The self-protection
  "tamper" detection in particular no longer raises a false CRITICAL during
  MacCrab's own install / update / reload — genuine tampering is still caught
  by the always-on self-defense layer (integrity hashing + file monitor).
- Searching the rules for an alert whose ID comes from a built-in engine
  (AI Guard, campaign correlation, behavioral scoring, threat intel) now
  shows an explanation instead of an empty list — those aren't Sigma rules.
- **Uninstall now removes your user data with `--yes`.** Run under `sudo`,
  the script resolved `$HOME` to `/var/root`, so `~/Library/Application
  Support/MacCrab` (including forensic Cases/) was silently left behind on a
  full wipe. It now resolves the invoking user's home correctly and also
  clears the out-of-tree tamper forensic logs.
- **Hardening.** The privileged rule-sync no longer breaks (or could be
  abused) when MacCrab.app is installed under a path containing a quote;
  automatic network blocking can no longer block loopback / gateway / DNS /
  Apple infrastructure from a bad feed entry; and the non-root collector no
  longer crashes on malformed system telemetry.

### Changed

- OS notification banners are now delivered by the MacCrab app while it's
  running (it's a normally-always-on menu-bar app). Detections are always
  recorded to the dashboard regardless.

Universal (Apple silicon + Intel), Developer ID signed and notarized.
Minimum macOS 13.

## [1.17.0] — 2026-05-31

First public release since v1.12.9. The headline is the on-demand
Forensics workspace and the on-device forensic-plugin engine behind
it; the detection engine and dashboard also pick up refinements from
the v1.13–v1.16 development cycle.

### Added

- **Forensics workspace** — a four-tab workspace (Run a scan, Past
  scans, Findings, Catalog) for running curated scan kits (incident
  response, phishing triage, comms forensics, supply-chain audit,
  browser activity, Mac data overview, and more) and reviewing results.
- **Forensic-plugin engine** — per-case encrypted evidence stores plus
  first-party collectors and analyzers: launchd, TCC, Safari, Mail and
  iMessage metadata, KnowledgeC, quarantine, FaceTime/Biome discovery,
  and Mach-O / DMG / PKG / Office / PDF / plist / image / archive
  analyzers.
- **Evidence viewers** — tables, day-grouped timelines, message
  transcripts, and charts, selected per artifact type (JSON-tree
  fallback for anything else).
- **Export** — save a scan's evidence as CSV or JSON.
- **Retention and deletion** — auto-delete scans by age, per-scan disk
  size, multi-select bulk delete, and a permanent-delete action.
- **Full Disk Access guidance** — in-app prompts with a direct link to
  the right System Settings pane when a scan needs access.

### Changed

- `maccrabctl` gains `case` and `plugin` subcommands for running and
  managing forensic scans from the command line.

### Fixed

- **Threat-intel feeds** — a line-ending (CRLF) bug made the abuse.ch
  feeds (URLhaus, MalwareBazaar, Feodo Tracker) parse zero records, so
  indicator counts never refreshed. Feeds now parse correctly, report
  honestly when a fetch fails or is stale, and the Intelligence
  workspace surfaces recent indicator matches.
- **Critical notifications** — criticals always notify at their true
  severity; the confusing "Allow critical notifications" toggle was
  removed (older config files still load).

Universal (Apple silicon + Intel), Developer ID signed and notarized.
Minimum macOS 13.

## [1.12.9] — 2026-05-19

Single-purpose patch on top of v1.12.7. SwiftUI layout code only
— no schema migrations, no new entitlements, no new external
network paths, no rule changes.

**Window minimum unified.** The dashboard's outer window minimum
and inner content minimum were two different values (950 × 600
on the WindowGroup, 1280 × 800 inside `V2DashboardShell`), so
dragging the window into the gap forced the inner HStack to lay
out at 1280 pt regardless of actual window width and pushed the
top bar's trailing icon cluster (theme / Help / Settings) past
the right edge. Both frames now agree on 1180 × 760 declared
once at the WindowGroup, and the trailing icon cluster picks up
`.layoutPriority(1)` as a defensive guard against future layout
shifts squeezing it out.

**Detail inspector floats instead of pushing.** The Alerts,
Detection, Intelligence, and Investigation workspaces all
rendered their 340 pt detail inspector via an
`HStack [content | inspector]` push-layout. At the new 1180
minimum the table's natural width plus the inspector plus the
sidebar exceeded the window, so opening an inspector clipped
either the rightmost table columns or the inspector itself. Each
of those four workspaces now wraps its content in
`ZStack(alignment: .topTrailing)` and the inspector floats over
the rightmost ~340 pt of the workspace with a soft left-edge
shadow and a slide-in transition. The table keeps its natural
width and the overall layout stays stable as the user opens and
closes the inspector. The Investigation workspace's "Show
details" re-open rail gets the same overlay treatment so
toggling the trace inspector no longer reflows the graph canvas
underneath.

See `RELEASE_NOTES/v1.12.9.md` for the full layout breakdown.

## [1.12.7] — 2026-05-18

Single-purpose patch on top of v1.12.6. Fixes two field-reported
dashboard responsiveness bugs on hosts with a large alerts.db /
campaigns.db:

**Wave 9P — auto-refresh staleness.** The Alerts, Campaigns, and
Metrics panels stopped refreshing until the user closed and
reopened the menubar window. Same `.task(id:)` cancellation race
Wave 9G fixed in v1.12.6 RC2 for the Intelligence tab, but in five
more workspaces (Overview / Alerts / System / Detection /
Investigation). Each gated all `@State` writes behind one trailing
`MainActor.run` after several sequential SQLite reads — on a busy
host the combined load could exceed the 5-second refreshTick,
which cancelled the body before any state landed. Fix: split into
one `MainActor.run` per await so faster queries always land even
if the slowest one is cancelled. V2EventsWorkspace and
V2PreventionWorkspace audited as not vulnerable.

**Wave 9Q + 9R — mutation lag.** Clicking Suppress / Unsuppress /
Delete / etc. on an alert or campaign sat for ~5 s before the row
visibly changed, because the mutation went through the file-IPC
inbox (Wave 9A's read-only-dashboard model), the daemon's inbox
poller runs at a 5s cadence, and the dashboard's reload was
blocked behind that round-trip. 9Q added optimistic local @State
flips on click; 9R adds a five-set pending-mutation overlay that
`reload()` merges on top of the DB read so the optimistic flip
survives until the daemon catches up. Mutations patched:
`suppress`, `suppressCampaign`, `bulkSuppress`,
`bulkSuppressCampaigns`, `unsuppressAlert`, `deleteAlert`,
`liftSuppression`. User-visible mutation latency drops from ~5 s
to one SwiftUI frame.

Known limitations: pending overlay entries have no TTL (daemon-
crash edge case bounded by dashboard close/reopen); bulk-suppress
partial-failure can leak pending entries (rare); cross-workspace
overlay not shared (Overview's Recent Activity may briefly show
an alert that's been suppressed on the Alerts tab — bounded by
the 5 s daemon poll). All documented in `RELEASE_NOTES/v1.12.7.md`.

**Opsec status**: clean. No new schema migrations, no new bundled
credentials, no new external network paths, no new entitlements,
no new provisioning profile fields. SwiftUI refresh-binding code
only. 8 files changed; 5 V2 workspace `.swift` + `V2MockData.swift`
+ 3 docs.

## [1.12.6] — 2026-05-18

Refinement release. Seven internal waves on top of v1.12.5 hardening
storage discipline, attribution schema, AI-tool guard coverage, and
audit-script enforcement, plus 12 new detection rules for the
2026 supply-chain incident wave (SANDWORM_MODE / OpenClaw /
Mini Shai-Hulud / TanStack / node-ipc / Brew Hijack). No public
behavior changes from v1.12.5; this is an internal-quality release
that also lights up 21 previously-silent Sigma rules (Architecture,
NotarizationStatus, FileAction resolver cases).

**Storage + perf foundations (Wave 1)**:

- `events.db` size-cap timer cadence is now **user-configurable** via
  the new `eventsSizeCapIntervalMinutes` field (default 60 min, can
  be set via `daemon_config.json` or `user_overrides.json`).
  Pre-v1.12.6 the timer was hardcoded at 6 hours, so on a heavy host
  ingesting ~170K events/hour the file gained ~17 GB between sweeps.
  A non-configurable 60-second early-fire watchdog also fires the
  sweep when the DB exceeds 1.5× the cap. Closes a Wave 6 finding
  that traced back to v1.6.x size-cap pattern.
- Adaptive cutoff ladder no longer collapses to a single rung at
  `hotTierMinutes ≤ 15` (was the v1.8.0 design's edge case).
- `SelfDefense.directoryHash()` migrated from `/usr/bin/shasum`
  subprocess spawns to in-process CryptoKit `FileHasher`. Removes
  **~1,704 perl subprocesses/minute** (~2.5M/day) on every host
  because shasum is a perl script. Backward-compatible: the combined-
  hash output is byte-equal to the previous shasum-based path
  (verified by a dedicated test that runs both paths and asserts
  equality), so no false `.rulesModified .high` alert fires on
  first upgrade.
- `EventStore.insert(event:)` enforces a **64 KB cap on per-event
  raw_json**. Sets `payload.truncated="true"` and
  `payload.original_bytes=N` enrichments on truncated events. Stops
  ~1 MB outlier events (appcast-publish base64 payloads, etc.) from
  poisoning the database and inflating the FTS index.

**Schema enrichment (Wave 2)** — 30 indexed columns added across
the three stores. Additive only; pre-v1.12.6 rows have NULL in new
columns. Backward-compat for rule matching is automatic — the rule
engine works against the in-memory Event struct (rehydrated from
raw_json on SQL read).

- `events.db` v5 → v6: user_id, user_name, group_id,
  working_directory, responsible_pid, architecture,
  is_platform_binary, is_notarized, process_sha256, parent_name,
  parent_executable, parent_signer_type, ai_tool, ai_tool_child,
  session_launch_source, tcc_decision. RuleEngine gains 16 Sigma
  aliases (Architecture, IsNotarized, NotarizationStatus, User,
  UserId, AiTool, ParentName, ...). **6 dead Sigma rules unblocked**
  (rosetta detection × 3, notarization detection × 3).
- `alerts.db` v4 → v5: user_id, user_name, working_directory,
  ai_tool, parent_executable, process_sha256, host_name. AlertSink
  populates from the triggering Event at construction time.
- `campaigns.db` v1 → v2: affected_users, affected_executables,
  first_seen, last_seen, process_tree_depth, techniques, ai_tools.
  CampaignDetector computes aggregates over contributing alerts at
  persist time.

**Wire-the-orphans cleanup (Wave 3)**:

- `state.intentClassifier` (LLM-aware IntentClassifier) was
  constructed in DaemonState but never called. Now wired as a
  tie-breaker for AI-triggered installs when heuristic confidence
  is below 0.7. Runs in `Task.detached(priority: .utility)` so the
  hot path never blocks on LLM latency. Per-tree-key cooldown via
  new `IntentRefinementCache` (LRU 256 / TTL 10 min) prevents burst
  fan-out.
- PASS 1 of `scripts/pre-release-audit.sh` DAEMON_BINDINGS list
  refreshed for the 8 new @AppStorage keys added since v1.6.18.
  Two keys (`alertNotifications`, `minAlertSeverity`) were
  misclassified as UI-only since v1.11.0 — corrected.

**Detection (Wave 4 + Wave 7B)**:

- New `FileAction` Sigma alias in RuleEngine (one-line change
  activates 15+ AI-safety / supply-chain rules that referenced the
  field but had no resolver case).
- `ProjectBoundary.swift` rejects `"/"` as a project root (was
  silently making every AI-tool write a "boundary violation" —
  312 alerts on the dev sample). Adds `/dev/null`, `/dev/urandom`,
  `/dev/random`, `/dev/zero` to globalExceptions.
- `CrossProcessCorrelator.swift` adds three paths to
  `ignoredPathSubstrings`: Claude Code shell snapshots, MacCrab's
  own release-build tmp dir, MacCrab's own compiled_rules dir.
  Closes ~280 self-FP alerts on the dev sample.
- `GitSecurityMonitor.swift` filters writes to `.git/config` under
  SwiftPM / Xcode / DerivedData checkout dirs.
- Three rule edits: `ai_tool_reads_ssh_keys.yml` adds
  swiftpm-testing-helper filter; `developer_credential_bulk_harvest.yml`
  deprecated until count-aggregation lands in the rule engine;
  `persona_takeover_fingerprint_drift.yml` adds SwiftPM-checkout
  filter.
- **12 new Sigma rules** covering the Feb-May 2026 supply-chain
  incident wave (Wave 6.6 research + Wave 7B):
  - `mcp_server_config_injection_by_non_ai_tool` —
    SANDWORM_MODE / Shai-Hulud rogue MCP server pattern
  - `binary_dropped_into_claude_dir` — SafeDep SessionStart hijack
  - `fake_keychain_dialog_from_install_lineage` —
    OpenClaw / GhostLoader iCloud-Keychain phishing
  - `package_manager_downloads_bun_runtime` — Mini Shai-Hulud
    Node-EDR-bypass pattern
  - `gh_token_monitor_plist_dropped` — TanStack CVE-2026-45321 IOC
  - `workflow_drop_with_self_hosted_runner` — TanStack
    discussion.yaml registration pattern
  - `process_reads_other_process_memory_macos` — TanStack OIDC
    theft macOS analog (task_for_pid / mach_vm_read)
  - `npm_module_require_then_bulk_credential_read` (sequence) —
    node-ipc require()-time credential burst
  - `gh_token_revocation_polling_loop` (sequence) — TanStack
    dead-man's-switch handoff
  - `node_ipc_compromised_versions` — node-ipc 9.1.6/9.2.3/12.0.1
    pinned IOC
  - `c2_azurestaticprovider_net` — Mini Shai-Hulud C2 IOC
  - `c2_trackpipe_dev` — OpenClaw / GhostLoader C2 IOC

**Audit infrastructure (Wave 5 + Wave 7A)**:

- 4 new audit passes from the v1.12.x release-marathon lessons:
  Pass A (codesign entitlement isolation), Pass B (SwiftPM resource
  bundle Info.plist), Pass C (permission-paired integration test),
  Pass D (self-defense Sigma filter symmetry).
- 4 new passes from Wave 6 wire-the-orphans audit recommendations:
  Pass E (KNOWN_PASSTHROUGH_FIELDS resolver coverage — caught
  XPCServiceName + FileAction as real latent orphans), Pass F
  (DaemonState field consumer audit), Pass G (Detection actor reader
  audit), Pass H (MCP-tool handler / daemon-state coverage).
- Pass 1 unclassified @AppStorage warn → err. Pass 3 support-dir
  extractor made path-agnostic. Pass 7 (dead since dashboard moved
  to V2 workspaces) revived with V2 workspace globbing. Pass 8
  eviction-evidence regex tightened.
- `AIToolRegistry` extended for **Kiro / Continue.dev / Windsurf**
  config paths — closes the Wave 6.6 gap where node-ipc + SANDWORM_MODE
  targeted AI-tool surfaces MacCrab didn't recognize.

**Numbers**:

- 475 compiled rules (424 single-event + 39 sequence + 6 graph +
  6 new sigma rule additions baked in; 12 net new rules total
  across Wave 7B).
- 1589 tests in 291 suites (+99 from v1.12.5's 1490).
- Audit script: PASSED with 6 warnings (down from 8); all
  warnings are tracked latent findings for v1.13 with allowlist
  entries documenting why.
- Schema migrations: events.db v5 → v6, alerts.db v4 → v5,
  campaigns.db v1 → v2. All additive, no destructive changes.
- Universal binary. Min macOS 13 Ventura through macOS 26 Tahoe.

**Performance regression check** (Wave 6.8): events.db insert
throughput drops ~10% (1025 → 919 ev/s) and per-event storage
grows ~43% (1791 → 2563 B) — the expected price of promoting 16
fields from raw_json into indexed columns. Live load (47 ev/s on a
dev host) is ~5% of measured insert capacity; no headroom risk.
SelfDefense hash latency drops ~220× (6 s → 27 ms per call) —
substantial net steady-state CPU saving that more than offsets the
schema cost.

**Deferred to v1.13** (the strategic-wiring release):

- Production-side wiring of v1.12.0 supply-chain immune-system actors
  (`PackageContentAnalyzer`, `AttestationEnricher`,
  `PackageMetadataAnalyzer`, `TyposquatDatabase`,
  `BayesianIntentEngine`). These exist as on-demand MCP tools but
  the daemon's `EventEnricher` never invokes them on live `npm install`
  events — Wave 6.6's strategic finding. v1.13 will turn the v1.12
  conceptual wedge into an active immune-system layer.
- Sigma date format normalization (YYYY/MM/DD → YYYY-MM-DD
  corpus-wide) for strict Sigma 2.x spec compliance.
- `CDHashExtractor` migration from private SPI (`csops` syscall
  + `proc_pidinfo` flavor 17) to public `SecCodeCopySigningInformation`.
- `notarize.sh` migration to `xcrun notarytool store-credentials`
  for Tahoe 26.x compatibility.

**Opsec status**: clean. No credentials, internal hosts, or signing
material in the diff. Schema migrations are non-destructive and
forward-only.

### RC1 → RC2 fix wave (Wave 9)

RC1 (`463272560b4c…`) was field-tested by the maintainer and surfaced
three compounding bugs that together broke the entire Wave 1
storage-discipline story. RC2 fixes the root causes — not cosmetic.

- **9A — Dashboard-side stores held the DB open RW, blocking the
  daemon's VACUUM.** `V2LiveDataProvider` was opening EventStore,
  AlertStore, CampaignStore, and SQLiteCausalGraphStore in
  read/write mode. The daemon's "Reduce events.db now" handler ran
  `VACUUM` against the same file — SQLite needs an exclusive lock,
  the dashboard's RW connection refused to drop, the vacuum
  silently no-op'd and the file kept growing. Field-confirmed via
  `lsof`. Added `forceReadOnly: true` plumbing through all four
  stores; `V2LiveDataProvider` and `AppState` (which also opens
  stores from the dashboard side) both pass it now.
- **9B — Size-cap enforcer had no fallback when full VACUUM
  couldn't run.** A full `VACUUM` needs ~1.3× DB-size free disk.
  On a host where events.db has grown past the cap, the user is
  almost by definition disk-pressured. The size-cap timer now
  tries `PRAGMA incremental_vacuum` first (releases freelist
  pages, needs ~0× extra disk) and falls back to full VACUUM
  only if mode allows.
- **9B.1 — PRAGMA order bug meant `incremental_vacuum` was a no-op
  on every DB ever shipped.** `PRAGMA auto_vacuum = INCREMENTAL`
  must be applied BEFORE `PRAGMA journal_mode = WAL`. SQLite
  silently refuses to flip auto_vacuum once WAL setup has dirtied
  the DB header — no error, just stays in mode 0. Every store
  across every release has been running in mode 0, making 9B's
  incremental_vacuum a no-op. Field-confirmed via runtime PRAGMA
  inspection on the RC1 user machine: tracegraph.db at 11 GB in
  mode 0. RC2 reorders the PRAGMA sequence across
  `StoragePragmas.swift`, `CampaignStore.swift`, `TraceStore.swift`,
  and `SQLiteCausalGraphStore.swift`. **Critical comment block
  added at top of `applyEventStorePragmas` so the constraint can't
  be regressed.** New DBs ship in mode 2 (INCREMENTAL); pre-existing
  mode-0 DBs need a one-shot manual `VACUUM` (or rm + recreate) to
  convert.
- **9C — `ai_tool` column landed NULL despite raw_json populated.**
  Wave 2A's EventStore writer read the `agent_tool` enrichment
  key, but the production writer uses `ai_tool`. RC2 reads
  `ai_tool` first and falls back to `agent_tool` so both code
  paths populate.
- **9D — Silent insert failures.** During the disk-full incident
  the dashboard showed "0 ev/s" because every events.db insert
  failed — but the failure path logged nothing. RC2 adds a 3-tier
  escalation ladder (`StorageErrorTracker`) — first failure logs,
  logarithmic ladder follows (10, 100, 1000, …), plus heartbeat
  fields `event_insert_errors_total / _rate / _last_kind` exposed
  in `maccrabctl status`.
- **9E — Threat intel feeds didn't auto-load on dashboard mount.**
  `V2IntelligenceWorkspace`'s `.task(id:)` deferred to the data
  provider; on first fire `V2MockDataProvider` won the race and
  returned fixture data. RC2's new
  `V2LiveDataProvider.loadFeedsFromCache(preferring:)` static
  helper probes a prioritized cache-dir list directly.
- **9F — Bundled IOCs weren't persisted on cold start.** Field-
  confirmed gap on top of 9E: the dashboard correctly read
  `feed_cache.json` via 9E's helper, but on a fresh install the
  file didn't exist until the daemon's first `updateAllFeeds()`
  finished (~14 min across abuse.ch feeds on the RC2 user
  machine). `BundledThreatIntel.loadInto` added IOCs to in-memory
  actor state via `addCustomIOCs` but never wrote the cache file.
  RC2: `ThreatIntelFeed.start()` is now async-await so it awaits
  `loadCachedFeeds()` + `loadCustomIOCFiles()` inline (periodic
  network loop split into background Task). New
  `persistCacheNow()` public method; `DaemonSetup` calls it
  immediately after `BundledThreatIntel.loadInto(...)` so the
  dashboard sees bundled IOCs on first Intelligence-tab mount.
  Warm-boot safety preserved: prior cached IOCs hydrate first, so
  the post-bundled persist writes the union — never a
  bundled-only overwrite.

New test files: `StoreReadOnlyTests`, `IncrementalVacuumTests`,
`EventStoreAiToolFallbackTests`, `InsertFailureEscalationTests`,
`V2IntelligenceFeedsLoaderTests`, `ThreatIntelColdStartPersistTests`. 55/55 Wave 9 tests pass. Full
suite has 4 pre-existing timing-related failures in
`SchemaMigrationIntegrationTests.reopenIsIdempotent` (passes in
isolation 0.27s, fails under parallel test-runner contention) —
tracked for v1.13 tolerance adjustment, not an RC2 regression.

## [1.12.5] — 2026-05-17

Self-FP cleanup wave + Threat Intel directory-permissions fix.
Twelve targeted fixes for issues surfaced by v1.12.4 field testing
plus a polish-audit pass. All v1.12.0–v1.12.4 releases are now
marked Pre-release on GitHub and yanked from the Sparkle appcast;
v1.12.5 is the canonical install target for the v1.12 line across
the supported macOS range (13 Ventura through 26 Tahoe).

**The headline fix**: Threat Intel feeds=0 / iocs=0 on field
machines. Root cause has been latent since v1.11.0 RC2 — a
"tightening" audit set `/Library/Application Support/MacCrab/threat_intel/`
to `0o700`. The cache file inside was `0o644` (world-readable), but
without traverse (`x`) on the directory the user-context dashboard
couldn't open files inside; `ThreatIntelFeed.cachedIOCs(at:)`
silently failed at the directory level. Reverted to `0o755` +
chmod-existing-dir on init so pre-existing installs heal on
first start.

**Self-defense (sysext-side) regressions from v1.12.4**:

- `Binary Modified` tamper alert during in-place upgrade —
  `SelfDefense.integrityCheck()` was hashing
  `CommandLine.arguments[0]` (the bundle-relative loader path)
  instead of `self.binaryPath` (proc_pidpath-resolved). Fixed.
- DispatchSource `.write` on the binary path had no
  sentinel/signer gate — added.
- Periodic 15s `integrityCheck()` rules-hash branch had no
  sentinel gate — would re-fire `.rulesModified .high` every
  cycle after a Sparkle rule push. Added the same gate the
  DispatchSource path has.
- `integrityCheck()` rules-dir lookup uses `self.rulesDir`
  directly (was fishing via description-match against
  `monitoredPaths`).
- `checkForImpersonation` was `pgrep -x maccrabd` — never
  matched the release sysext executable name `com.maccrab.agent`,
  so the impersonation protection was silently disabled in
  production. Now matches both names with `pgrep -f`.

**Self-defense (rules-side) — `Attempted Tamper` Sigma rule**:

- Fired on `/bin/rm`, `/usr/bin/pkill`, `/bin/launchctl` spawned
  by MacCrab itself at startup. `filter_maccrab_self` was AND-style
  (Image AND ParentImage both needed to match MacCrab); didn't
  catch the common case where MacCrab spawns a system helper.
  Added Parent-only `filter_maccrab_parent`.
- Fired during brew/cask in-place upgrade. Extended
  `filter_installer` with `/Updater` and `/Autoupdate`. Added
  `filter_upgrade_installer` matching ParentImage `/brew`,
  `/osascript`, `/sysextd`, `/launchctl`. Added
  `filter_brew_lineage` matching CommandLine `/Homebrew/`,
  `/Cellar/maccrab/`, `Caskroom/maccrab/`.

**AI Guard — `AI Tool Child Process Uploads Data` Sigma rule**:

- Title says "AI Tool Child Process" but the pre-fix condition
  didn't enforce it. Any `curl -X POST` to an unknown destination
  tripped it. Added `selection_ai_parent` requiring ParentImage
  to be a known AI tool.

**Dashboard**:

- Integrations panel was showing
  `ModifiedContent<Text, _ForegroundStyleModifier<Color>>(...)`
  debug dump because of a `Text("foo \(Text("bar").bold())")`
  interpolation pattern that SwiftUI doesn't render correctly.
  Switched to markdown `**bold**`.
- Integrations panel was empty despite Objective-See tools
  installed. `SecurityToolIntegrations.writeSnapshot()` was
  correctly writing `integrations_snapshot.json` but the dashboard
  never read it. Wired it in; expanded Objective-See coverage
  (RansomWhere, ReiKey, DoNotDisturb, TaskExplorer, Netiquette,
  WhatsYourSign, ProcessMonitor, FileMonitor).

**Typosquat scoring**:

- `pip` was flagged as a typosquat of `pipx` with score 80. The
  exact-match-is-popular check at the top of `score(...)` only
  handled the homoglyph case; ASCII `pip` fell through to the
  distance loop. Added ASCII membership check before the
  homoglyph branch. Locked in by `pipIsNotTyposquatOfPipx`
  regression test.

**maccrabctl**:

- `intel refresh` was exiting 1. Missing `-f`, wrong signal
  (SIGHUP vs SIGUSR1), plus EPERM when user-context tries to
  signal uid-0 sysext. Fixed signal + flag; on EPERM, prints
  informational message and exits 0.

No new Swift source files. No schema migrations. 469 rules,
1490 tests, 284 suites. Universal binary, min macOS 13.

DMG SHA-256: `cda5ecb7a62c57198ff20a977611ee5ae991cd9492167e2e3758b21cfdef252f`

## [1.12.4] — 2026-05-16

Fifth release of the day. Focused fix for a macOS 26 Tahoe
SwiftPM-resource-bundle crash that fired on the first click of
the Intelligence workspace. v1.12.4 bundles every feature and
hardening from v1.12.0 → v1.12.3 plus the macOS 26 fix.

**The bug**: macOS 26 tightened `Bundle(url:)` validation.
SwiftPM-generated resource bundles ship a stripped `Info.plist`
containing only `CFBundleDevelopmentRegion`, which macOS ≤ 25
accepted. macOS 26 rejects this minimal plist, `Bundle(url:)`
returns nil, and SwiftPM's auto-generated `Bundle.module`
accessor hits its own `fatalError("unable to find bundle named
MacCrab_MacCrabCore")`. The crash fires on first reach to
`Bundle.module` — in MacCrab, `PackageScanner` lazily instantiates
`TyposquatDatabase` the first time `V2IntelligenceWorkspace`
evaluates `state.provider.packages()`, which happens the first
time a user clicks the Intelligence tab. Re-opening the app
lands back on Intelligence (persisted last workspace) so the
crash loops.

**Two fixes**:

1. `TyposquatDatabase.loadBundledCorpus(name:)` no longer reaches
   `Bundle.module`. It probes the canonical SPM resource-bundle
   search paths directly with `Data(contentsOf:)`. `Data` doesn't
   care whether the directory validates as a CFBundle — it just
   reads bytes off disk. Falls through to the in-source starter
   corpus if all paths miss. Bulletproof to any future Bundle
   validation changes.

2. `build-release.sh` now overwrites the SPM-stub `Info.plist`
   inside `MacCrab_MacCrabCore.bundle` with a complete CFBundle
   plist (`CFBundleIdentifier`, `CFBundleInfoDictionaryVersion`,
   `CFBundleName`, `CFBundlePackageType` = `BNDL`, version keys).
   Defense in depth — any future SPM-resource consumer using
   `Bundle.module` still works on macOS 26+.

**The release-trail housekeeping**:

- v1.12.0 → v1.12.3 GitHub releases all marked **Pre-release** and
  yanked from the Sparkle appcast. Comprehensive warning banners
  prepended to each.
- Sparkle appcast advertises only v1.12.4.
- `RELEASE_NOTES/v1.12.4.md` carries the full rollup upgrade matrix
  (macOS 26 vs ≤ 25, source-version × dest-version) plus the
  detailed v1.12.x change descriptions, copied from the v1.12.3
  rollup with v1.12.4 fixes layered on top.

No new Swift source vs v1.12.3 except the TyposquatDatabase fix.
Same 469 rules, 1490 tests, 284 suites. Universal binary, min
macOS 13.

## [1.12.3] — 2026-05-16

Consolidated v1.12 rollup release. **No new code vs v1.12.2** —
same binary, fresh canonical install target with comprehensive
release notes for users coming from v1.11.x or earlier. The four
v1.12.x same-day releases (v1.12.0 → v1.12.3) are now collapsed
into a single recommended upgrade path:

- **v1.11.x or earlier** → Sparkle in-place upgrade to v1.12.3
  works directly. Or `brew upgrade --cask maccrab`.
- **v1.12.0 / v1.12.1** → manual upgrade required
  (`brew upgrade --cask maccrab` or download the v1.12.3 DMG).
  Their nested Sparkle helpers are baked broken and cannot
  auto-update.
- **v1.12.2** → Sparkle in-place upgrade to v1.12.3 works
  directly.

The headline contents (rolled up from v1.12.0):

- 36 new single-event Sigma rules + 6 sequence rules + 6
  multi-entity TraceGraph rules covering Shai-Hulud /
  Mini Shai-Hulud / Lightning PyPI / TanStack CVE-2026-45321.
- Bayesian intent posterior over attacker goals per process tree
  + LLM-backed `IntentClassifier` on `npm install` / `pip install`
  exec events. Heuristic fallback alone catches worm
  self-propagation when no LLM is configured.
- 8 new MCP tools (25 total): `check_typosquat_score`,
  `scan_package_content`, `analyze_package_metadata`,
  `verify_package_attestation`, `classify_package_intent`,
  `predict_next_technique`, `score_text_style`,
  `get_intent_posterior`.
- Daemon cold start: 114 s → 118 ms (~1000× faster). Seven sources
  of synchronous main-thread work deferred behind `Task.detached`
  after the first heartbeat; 14 `boot_phase` breadcrumbs for
  regression visibility.
- In-dashboard Sigma YAML editor (read-only viewer + Save flow
  piped through bundled `compile_rules.py`, writes
  user-rules overlay).

The hotfix substance (from v1.12.1):

- Self-defense FP fix for Sparkle/cask in-place upgrades. Sentinel
  file under the data dir + `codesign --verify --` signer-validity
  check on hash-mismatched binaries. Trust posture unchanged for
  actual tampering.

The build-pipeline fix (from v1.12.2):

- Dropped `--deep` from the outer `.app` codesign pass. Was
  propagating MacCrab's main-app entitlements onto Sparkle's
  `Installer.xpc`, which made macOS refuse to launch the updater.
  CodeResources still seals `Resources/*` without `--deep`.

See `RELEASE_NOTES/v1.12.3.md` for the full upgrade matrix +
detailed change descriptions targeted at v1.11.x users.

## [1.12.2] — 2026-05-16

Same-day hotfix-of-the-hotfix. v1.12.1 shipped a broken Sparkle
auto-updater because the v1.12.0 RC28 build-release.sh change that
added `--deep --entitlements <APP_ENT> --force` to the outer .app
codesign pass also propagated MacCrab's main-app entitlements
(`com.apple.developer.system-extension.install` +
`keychain-access-groups`) into every nested Sparkle helper —
Autoupdate, Updater.app, Downloader.xpc, **Installer.xpc**. macOS
refused to launch Installer.xpc with that entitlement combo and
surfaced it as the generic "An error occurred while running the
updater" on every Sparkle in-place upgrade.

**Fix**: add `--preserve-metadata=entitlements` to the outer
`codesign --deep` pass so nested Mach-Os keep the entitlements they
were signed with at their own (earlier) step — empty/Sparkle-default
for the Sparkle helpers, APP_ENT for the inner MacCrab executable.
Resources sealing (the original RC28 goal) is unchanged.

Verified post-build: `codesign -d --entitlements -
Sparkle.framework/Versions/B/XPCServices/Installer.xpc` now returns
no entitlements (correct); the outer MacCrab executable still
carries `com.apple.developer.system-extension.install` (correct).

**Existing v1.12.0 / v1.12.1 installs** carry the broken nested
entitlements on their OWN Sparkle helpers, so their Sparkle can't
install v1.12.2 either. Affected users must upgrade via
`brew upgrade --cask maccrab` or download the v1.12.2 DMG manually
from https://github.com/peterhanily/maccrab/releases/tag/v1.12.2.
Once on v1.12.2, future Sparkle upgrades will work normally because
v1.12.2's Sparkle helpers carry the correct (empty) entitlements.

No Swift source changes from v1.12.1 — pure build-pipeline fix.

## [1.12.1] — 2026-05-16

Same-day self-defense FP hotfix for the two tamper alerts a v1.11.1 →
v1.12.0 in-place Sparkle/cask upgrade fires against MacCrab itself:

- **`MacCrab Tamper Detection: File Deleted` on
  `/Library/Application Support/MacCrab/compiled_rules`.**
  `RuleBundleInstaller.copyRulesWithElevation` (dashboard side) runs
  `osascript … rm -rf <compiled_rules> && cp -R …` to refresh the
  installed rule corpus when the bundled `.bundle_version` /
  manifest.json content is newer. The sysext's `SelfDefense` actor
  watches that dir via a `DispatchSource` file-system source and
  fires a critical "File Deleted" tamper alert on every Sparkle/cask
  upgrade. **Fix**: RuleBundleInstaller now drops a sentinel file at
  `/Library/Application Support/MacCrab/.maccrab_self_update_in_progress`
  at the start of the elevated session (created `root:admin 0644`,
  removed at end). `SelfDefense` checks for this sentinel before
  firing delete / rename / write alerts inside the data dir — if it's
  fresh (mtime within 90 s), the alert is suppressed and a re-baseline
  is scheduled 5 s later, once the new tree has been written.
  90 s TTL bounds the suppression window if the sentinel ever gets
  orphaned by a mid-flight failure.

- **`MacCrab Tamper Detection: Binary Modified` on `maccrabd`.**
  Sparkle's in-place .app replacement legitimately swaps the binary
  on disk while the old version is still running in memory. The
  sysext's periodic 15 s `integrityCheck()` then sees the on-disk
  SHA-256 ≠ its startup baseline and fires a critical
  "binary_modified" alert. **Fix**: before alerting on binary hash
  mismatch, `SelfDefense.isSignedByMacCrabTeam(at:)` shells to
  `codesign -dvv --verify --` and checks the output contains
  `TeamIdentifier=79S425CW99`. Valid MacCrab Developer ID signature
  → silent re-baseline. A real tamper can't forge the signature
  without the private key, so the gate is safe. Applied in the
  `integrityCheck()` mismatch branch; the DispatchSource `.delete`
  on the binary path is already non-critical and silently dropped.

Other safe-by-construction touches:

- The periodic `integrityCheck()` `fileDeleted` branch also consults
  the sentinel, so the 15 s re-fire loop doesn't re-emit the same
  alert while the elevated `cp -R` is still mid-flight.
- The elevated shell command in `copyRulesWithElevation` now uses
  `; rm -f '<sentinel>'` (not `&&`) for the cleanup step, so the
  sentinel clears even if an earlier step fails — defence-in-depth
  against partial-success states.

No new rules, no schema changes, no behavior changes outside the
self-defense suppression path. Existing v1.12.0 installs will get
v1.12.1 via Sparkle auto-update; the v1.12.0 install itself will
fire one final tamper-on-self alert during the swap (the v1.12.0
daemon is the one that's running while v1.12.1 replaces it) — that
is the last time you should see this class of FP.

## [1.12.0] — 2026-05-16

### Release-week fix wave (RC25 → RC30)

Two pre-ship audit cycles
(round 9: 6 parallel domains, round 10: 5 parallel domains) surfaced
a long tail of BLOCKERs/HIGHs/MEDIUMs across security, performance,
detection FP, integration, release engineering, data safety, secrets,
resiliency, stability, and UX. ~24 fixes landed across RCs 25–30
before this tag; the highlights:

- **Daemon cold-start: 114 s → 118 ms (~1000×).** A perf re-audit on
  the v1.12.0 baseline found seven distinct sources of synchronous
  main-thread work that the v1.11.1 deferral pass had missed: a
  `quick_check` on a 7 GB `tracegraph.db` (now skipped via
  `SchemaMigrator.skipQuickCheck:`), `SelfDefense` SHA-256ing its own
  binary + rules manifest at init (now lazy, computed in `start()`),
  `BaselineEngine.load`, `ThreatIntelFeed`, `BundledThreatIntel`,
  `ESClientMonitor`, and a half-dozen polled monitors (USB / clipboard
  / browser-extension / rootkit / EDR / TEMPEST). All deferred behind
  a `Task.detached` after the first heartbeat. `boot_phase` breadcrumbs
  are now stamped at 14 milestones in `DaemonSetup.swift` so future
  regressions surface immediately.
- **In-dashboard Sigma YAML editor.** The Detection workspace now
  ships a read-only viewer + a TextEditor save flow that pipes the
  edited YAML through the bundled `compile_rules.py` and writes the
  resulting JSON to `/Library/Application Support/MacCrab/user_rules/<uuid>.json`.
  Daemon picks up the change via a `.reload_tick` mtime watcher; no
  restart needed. Disable / re-enable actions write the same overlay
  with `enabled=false`. First write fires a single AppleScript admin
  prompt to create the override directory `root:admin 0775`; subsequent
  edits don't prompt.
- **Rule sync correctness (RC18).** `RuleBundleInstaller` was
  short-circuiting on a same-version string check — every RC between
  RC11 and RC17 silently failed to deliver fixes because the bundled
  `.bundle_version` matched the installed one. Now also compares
  `manifest.json` byte-for-byte before declaring "no sync needed".
- **AppleScript `do shell script` parser fix (RC12).** The override-
  directory bootstrap used `find -exec ... \;`, which AppleScript
  parsed as an escape and returned `-2741`. Replaced with
  `chmod -R u=rwX,go=rX` (no escapes) so the password prompt actually
  runs.
- **Disable-rule UUID lookup (RC30).** `loadBundledCompiledRule(id:)`
  was looking up `compiled_rules/<uuid>.json`, but build-release.sh
  bundles JSONs under their *slug* name (only YAMLs were duplicated
  under both keys). Added a fallback directory scan keyed by each
  JSON's internal `id` field; one-time ~100 ms hit on first Disable
  click after launch, then cached.
- **OpenAI host allowlist bypass (RC27).** The cloud-LLM backend
  used `hasSuffix("api.openai.com")` for the host check, which let
  `evilapi.openai.com` through. Replaced with a dot-anchored exact-
  host Set plus `.openai.azure.com` dot-suffix with a
  `count > suffix.count` guard. Gemini and Ollama got companion
  fixes (regex model-name allowlist; explicit nil-host check on
  plaintext-remote detection).
- **CampaignStore tamper-check skip (RC27).** RC23's quick_check
  skip landed for EventStore / AlertStore / SQLiteCausalGraphStore
  but missed CampaignStore. Caught by the round-10 perf re-pass.
- **`try!` force-unwraps removed from recovery paths.** EventStore
  and AlertStore's "DB quarantine + re-open" path used `try!` on
  the second open — a transient failure between probe and re-open
  would hard-crash the daemon. Now returns gracefully and logs.
- **Privacy: webhook + syslog default hostname.** Both stop leaking
  the machine hostname by default; overrideable via
  `MACCRAB_WEBHOOK_HOSTNAME` / `MACCRAB_SYSLOG_HOSTNAME` env vars.
- **MCP `get_alerts` / `get_alert_detail` / `scan_text` payloads**
  now route through `LLMSanitizer.sanitize()` before returning to
  the agent, matching the redaction guarantees of the LLM backends.
- **Pipe-deadlock fix in YAML editor.** The compile subprocess could
  fill its 64 KB stderr pipe and block before
  `waitUntilExit()` returned. Now drains in real time via
  `readabilityHandler` with a 10-second SIGTERM / SIGKILL timeout.
- **False-positive suppression on 5 task_for_pid / mach_port rules.**
  `/bin/ls`, `/bin/chmod`, `grep`, Claude Code, and other AI/dev
  tools were tripping the Mach-port-injection family. Added
  `filter_text_tools` / `filter_shells` / `filter_apple_paths` /
  `filter_dev_ai_tools` blocks per rule.
- **PromptInjectionScanner force-unwrap removed (RC29).**
  Single-init-context `found!` pattern was logically safe but
  fragile to future concurrency refactors.
- **Sigma reference link** added to the YAML editor sheet, pointing
  at `sigmahq.io/docs/basics/rules.html`.

Two audit rounds, ~24 fixes, opsec scan clean — see below for the
feature substance shipped earlier in the v1.12.0 cycle.

### Feature substance (cycle-open work, 2026-05-14)

**Supply-chain detection wave + intent posterior**. v1.12.0 ships
detection coverage for the September 2025 Shai-Hulud worm class and
the April–May 2026 follow-on incidents (Mini Shai-Hulud, Lightning
PyPI, TanStack CVE-2026-45321). It also adds an intent-based
detection layer on top of the rule layer: a Bayesian belief network
maintains a per-process-tree posterior over attacker goals, and an
LLM-backed `IntentClassifier` produces a categorical verdict on
`npm install` / `pip install` exec events. Both are detection-only;
single-event Sigma rules continue to fire on the same events.
Wave-5 components (counterfactual reasoning, stylometric maintainer
drift, honey-prompt deception, prompt-intent bridging) ship today
behind their respective entry points; some are reachable only via
MCP for v1.12.0 and will get fuller daemon-side wiring in v1.12.x.

**Schema**: no migrations. EventStore stays at schema v5, alerts.db
and tracegraph.db unchanged from v1.11.x. Upgrade is non-destructive
— Sparkle in-place upgrade preserves all history and settings.

### Wave 5 — Innovative-research layer (new Swift actors + 6 rules + 8 MCP tools)

**`IntentClassifier`** (Sources/MacCrabCore/Enrichment/) — LLM-
driven structured-intent classifier. Takes a `BehaviorBrief`
(package name + installer lineage + credential reads + network
egress + content anomaly flags + AI-agent attribution) and returns
a calibrated `IntentLabel` (benign / credentialHarvest /
exfiltration / persistence / destructive / reconnaissance /
lateralMovement / unknown) + confidence + ranked reasons. Routes
through the existing `LLMService` (Ollama / Claude / OpenAI /
Mistral / Gemini) with sanitization + caching + circuit breaker.
Falls back to a deterministic heuristic classifier when no LLM is
configured — the heuristic alone catches the worm self-propagation
shape (credentialRead + publish-endpoint egress = lateralMovement
verdict). Per NDSS 2025 "Mind the Gap", Llama 3.3 70B local hits
F1 0.77 / GPT-4.1 cloud hits F1 0.99 on this task; our scaffolding
supports both with the user picking which provider to trust.

**`PromptIntentBridge`** (Sources/MacCrabCore/Enrichment/) —
correlates an AI agent's behavior with its recently-read context to
classify installs as `.userInitiated` / `.autonomous` /
`.slopsquat` / `.vagueDestructive` / `.injectionContext`. Reads
the existing AgentLineageService snapshot for the AI tool's recent
`.fileRead` events, builds a context corpus from the actually-read
files (CLAUDE.md / project README / Cursor rules / etc.), extracts
package-name tokens, and decides:
- If the installed package name is **explicitly mentioned** in
  recent context → `.userInitiated` (low risk).
- If the agent context mentions a name within
  Damerau-Levenshtein 2 of the installed name → `.slopsquat`
  (the Lasso huggingface-cli / Aikido react-codeshift pattern).
- If the context has none → `.autonomous` (the LLM hallucinated
  this package; the user didn't ask).
- If the context contains injection markers ("ignore previous",
  "act as", etc.) AND the action is destructive → `.injectionContext`.
- If the prompt was very short relative to the destructive blast
  radius → `.vagueDestructive`.

No new privacy surface — we never read raw LLM prompts; we read
the *files the agent read*, which is the same privilege level we
already use for the AIGuard subsystem.

**`BayesianIntentEngine`** (Sources/MacCrabCore/Enrichment/) —
4-node belief network maintaining a posterior over
`Goal ∈ {benign, credentialHarvest, exfiltration, persistence,
destructive, reconnaissance, lateralMovement}` per process tree.
Each observed evidence type (credentialRead, registryEgress,
nonRegistryEgress, launchAgentWrite, shellRcWrite, workflowWrite,
destructiveCmd, vmDetectionProbe, localeProbe, obfuscatedContent,
runtimeDrop, configFileTampered) updates the posterior via a
stationary `LikelihoodTable` shipped inside the binary. Math is
deliberately minimal — no online learning, no neural net — so the
actor is cheap, reproducible, and explainable. Initial prior is
0.95 benign / 0.05 spread across malicious goals; two strong
matching observations are sufficient to flip the dominant goal.
EventLoop emits an alert when the top non-benign goal probability
crosses 0.85 with ≥3 distinct evidence types accumulated.

**`HoneyPromptManager`** (Sources/MacCrabCore/Deception/) —
Honey-prompt extension of the deception tier. Plants
`CLAUDE.md.canary`, `~/.claude/skills/maccrab-decoy/SKILL.md`, and
`~/.cursorrules.canary` files containing instructions to install
the impossible-to-publish canary package names
`maccrab-canary-do-not-install`, `maccrab-honey-do-not-fetch`,
`maccrab-decoy-skill`. Two trigger primitives:
- **Context-read trip** — any process reading a canary
  (`canary_skill_or_rules_read.yml`).
- **Canary-install trip** — any `npm/pip install` of a canary
  package name (`honeyprompt_canary_package_install.yml`).
Per Snyk ToxicSkills (early 2026), 36% of public Claude skills
already contained injection payloads; this puts MacCrab on the
defending side of that attack surface with zero-FP-by-design
canaries.

**`NextTechniquePredictor`** (Sources/MacCrabCore/Enrichment/) —
Inspired by KillChainGraph (arXiv 2508.18230). Given a sequence
of ATT&CK tactics observed for a process tree, returns the top-N
most-likely next tactics from a hand-calibrated 14×14 transition
prior shipped inside the binary. Markov-1 for v1.12.0; longer
context deferred to v1.13.x once we have a deployable training
corpus.

**`CounterfactualReasoner`** (Sources/MacCrabCore/Enrichment/) —
Given a fired sequence rule's partial-match chain, walks back to
identify the earliest step where an available prevention
capability (DNSSinkhole, NetworkBlocker, PersistenceGuard,
SupplyChainGate) could have aborted. Surfaces
"Blocking X at T-Ns via DNSSinkhole would have aborted this chain"
copy intended for the dashboard. v1.12.0 ships the actor + tests;
the dashboard render path is queued for v1.12.x.

**`StylometricFingerprinter`** (Sources/MacCrabCore/Enrichment/)
— 32-feature stylometric fingerprint for code / commit messages /
PR descriptions. Three uses:
- **Maintainer drift detection** — cosine distance against a
  per-author rolling baseline; the XZ-Utils Jia Tan signal.
- **LLM-text scoring** — em-dash density + hedge-phrase density +
  sentence-length-variance, per arXiv 2603.27006 "The Last
  Fingerprint" (em-dash markers degraded but still useful as a
  prior).
- **Urgency-lexicon scoring** — XZ-Utils "Jigar Kumar" /
  polyfill.io social-engineering text pattern.

### Wave 5 — 6 new YAML rules

- **`ai_safety/honeyprompt_canary_package_install.yml`** (critical)
  — any pkg-mgr install of a HoneyPromptManager canary name.
  Zero-FP-by-design.
- **`ai_safety/canary_skill_or_rules_read.yml`** (critical) —
  any process reads a `.canary`-suffixed AI-agent context file.
- **`ai_safety/llm_classifier_high_risk_intent.yml`** (high) —
  downstream alert that fires when `IntentClassifier` returns
  credentialHarvest / exfiltration / destructive / lateralMovement
  with confidence ≥ 0.5. The threshold matches the heuristic's
  "moderate-confidence" tier (single-label paths cap at 4–5 / 8
  → confidence 0.5–0.625); the credential-harvest worm shape
  clears the gate at 0.5.
- **`defense_evasion/persona_takeover_fingerprint_drift.yml`**
  (medium) — single git-config fingerprint field flipped in
  isolation. The XZ-Utils Jia Tan mockingbird shape.
- **`supply_chain/urgency_lexicon_in_install_lineage_pr.yml`**
  (medium) — urgency keywords ("merge now", "critical hotfix",
  "zero day") in install-time fetched README / CHANGELOG content.
- **`persistence/maintainer_publish_hour_anomaly.yml`** (medium)
  — pkg publish from non-tty parent; v1.12 heuristic, v1.13.x
  will compute a real Welford histogram per-maintainer.

### Wave 5 — 8 new MCP tools

`check_typosquat_score`, `scan_package_content`,
`analyze_package_metadata`, `verify_package_attestation`,
`classify_package_intent`, `predict_next_technique`,
`score_text_style`, `get_intent_posterior`. AI agents (Claude
Code, Cursor, Cline, Continue, Windsurf) can now query MacCrab's
package-intelligence and intent-classification surface directly,
including from an LLM in agent-mode reasoning over a suspicious
package decision.

### Supply-chain detection coverage for the npm / PyPI / Homebrew
worm class — including "Shai-Hulud" (Sept 2025), "Sha1-Hulud: The
Second Coming" (Nov 2025), the April 2026 Lightning PyPI compromise,
and the May 2026 Mini Shai-Hulud Wave 4 (TanStack / CVE-2026-45321).
Ships in four waves within a single v1.12.0 release:

- **Wave 1** — worm-loop kill-chain wedge (graph rule + sequence rule +
  9 single-event rules covering the read-cred → enumerate-pkgs →
  publish loop, Homebrew tap MITM, Bun-from-node_modules, the
  `~/.claude/settings.json` hook injection, and the dead-man's-switch
  literal).
- **Wave 2** — dependency confusion + content anomaly (11 single-event
  rules: Birsan-class scope confusion, `.npmrc`/`.pypirc` tampering,
  cross-ecosystem language smuggle, native-binary drop in pure-JS
  packages, obfuscator-signature detection, leaked-secret-in-tarball,
  GitHub Actions workflow planting, VS Code `tasks.json` hook
  injection, and registry OIDC token exchange abuse).
- **Wave 3** — dead-man's-switch design space (8 single-event rules
  closing the TanStack token-revocation watchdog, mass-unlink
  payload, distant-future launchd time-bomb, AppleLanguages locale
  skip, sysctl/ioreg VM-detection probe, EDR self-protection,
  staged fetch-then-exec, and openssl-decrypt-in-install-lineage).
- **Wave 4** — macOS app threat surface (8 single-event rules
  covering fake Apple bundle in user dir, MAS receipt access by
  non-sandboxed reader, post-install codesign re-signing, ad-hoc
  app from user-writable path, Little Snitch / Lulu / Radio Silence
  prefs tampering, post-install Info.plist mutation, URL-scheme
  handler collision, and bulk quarantine-xattr strip).

Plus four new Swift enrichment actors — pulled forward from the
planned v1.13.x roadmap because the user authorised the larger RC
scope: **`TyposquatDatabase`** (Damerau-Levenshtein + Unicode TR39
confusable fold, with starter top-50 bundled corpora for npm / PyPI),
**`PackageContentAnalyzer`** (size / language fingerprint / single-line
bundle / Mach-O / obfuscator / bundled-runtime detection on an
on-disk package tree), **`PackageMetadataAnalyzer`** (one registry
JSON GET per package, scores description / homepage / version history
/ maintainer signals with 24h cache and injectable fetcher),
**`AttestationEnricher`** (Sigstore / PEP 740 / OIDC verifier with
publishing-method-mismatch detection vs. a supplied prior builder).

Plus the **`HoneyfileManager` extension** — five new credential-shaped
bait types (`.npmrc.bak`, `.pypirc.bak`, `.gitconfig.bak`,
`.config/gh/hosts.yml.bak`, `.cargo/credentials.toml.bak`) deployed
at the exact paths the Shai-Hulud worm family scrapes. Wires into
the existing `Rules/persistence/honeyfile_accessed.yml` decoy-read
rule automatically via the `IsHoneyfile: 'true'` enrichment.

Detection-only — every new rule emits an alert; no auto-response.
FPs will be baselined against the developer devloop in RC1/RC2
before any later wedge wires in containment. AI-agent attribution
flows through every fire via the existing AIGuard plumbing.

### Detection — 9 new single-event rules

- **`supply_chain/homebrew_tap_mitm_cleartext_http.yml`** (high) —
  outbound port 80 from a `brew` lineage process. Catches the Koi
  "Brew Hijack" pattern (May 2026) where ~20 Homebrew Cask formulas
  used `http://` upstream URLs with `sha256 :no_check`, letting an
  on-path attacker substitute arbitrary binaries.
- **`supply_chain/homebrew_formula_no_check_sha.yml`** (medium) —
  brew loading a formula whose Ruby source contains
  `sha256 :no_check`. Modern Homebrew formulas pin a hash; a
  `:no_check` installation is itself the anomaly.
- **`supply_chain/bun_executes_from_node_modules.yml`** (high) —
  Bun runtime executing a script from a `node_modules/` tree while
  descended from npm/pnpm/yarn install. The May 2026 Mini Shai-Hulud
  Wave 4 dropped Bun specifically to evade Node-based introspection.
- **`ai_safety/claude_settings_hook_injection_by_non_claude.yml`**
  (high) — write to `~/.claude/settings.json` /
  `settings.local.json` / `CLAUDE.md` by anything not the Claude
  Code CLI. The May 2026 wave weaponised this file to inject
  SessionStart / PreToolUse hook entries, gaining code execution in
  the developer's AI agent context on every Claude Code session.
- **`supply_chain/github_user_repos_post_from_non_git.yml`**
  (critical) — outbound to `api.github.com` carrying `/user/repos`
  from a non-git client (anything not `/git`, `/gh`, `/hub`,
  `/git-credential-osxkeychain`). Catches the Shai-Hulud
  "dead-drop repo" pattern (the "Shai-Hulud" /
  "Sha1-Hulud: The Second Coming" / random-18-char public repos).
- **`supply_chain/npm_publish_self_propagation.yml`** (critical) —
  `npm publish` (or `oidc/token/exchange`) invoked by a parent that
  is not an interactive shell or a known CI agent. The defining
  Shai-Hulud worm signature: the worm calls publish from a
  postinstall context to republish itself into every package the
  stolen token can reach.
- **`supply_chain/pypi_twine_upload_from_non_interactive.yml`**
  (critical) — `twine upload` (or `python -m twine`) invoked by a
  non-interactive parent. The PyPI-lane cousin of the npm
  self-propagation signal; covers the April 2026 Lightning PyPI
  compromise where a wheel daemon-thread re-published the trojanised
  package.
- **`supply_chain/dead_mans_switch_literal_scanner.yml`** (critical)
  — process command line or written file content containing the
  literal string
  "IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner". That is
  the GitHub PAT description used by Shai-Hulud 2.0 to coerce
  victims into not revoking the stolen token; if the worm detects
  the token is gone, a polling loop fires `rm -rf $HOME`. The
  literal is diagnostic.
- **`supply_chain/package_runtime_drop_evasion.yml`** (high) —
  package-manager descendant (npm/pnpm/yarn/pip/uv/poetry) writing
  a Bun, Deno, or alternate Python interpreter binary into a
  user-writable location (`~/.bun/bin`, `~/.deno/bin`, `/tmp`,
  `/Library/Caches/`). Catches "bring-your-own-runtime" evasion.

### Detection — 11 more single-event rules (Wave 2: dep-confusion / content-anomaly)

**Dependency confusion / namespace collision (3):**

- **`supply_chain/pip_install_with_extra_index_url_to_public_pypi.yml`**
  (high) — pip invoked with `--extra-index-url` alongside public
  PyPI, or with both `--index-url` (private) and a `pypi.org/simple`
  extra. pip's resolver picks highest-version-across-indexes
  regardless of source (Birsan dependency-confusion primitive,
  reused in the AWS Lambda 24712-pl campaign (2025) and the
  alone5511 campaign (May 2026)). PEP 766 "index priority" was
  ratified Nov 2024 but pip has not shipped it as default by
  May 2026, so the resolver behavior is still unsafe.
- **`supply_chain/npmrc_pypirc_modified_by_non_package_manager.yml`**
  (high) — `.npmrc` / `.pypirc` / `pip.conf` / `.yarnrc*` /
  `.cargo/config.toml` / `.gem/credentials` written by anything
  that isn't a recognised package manager, dotfile manager, or
  editor. Catches registry-redirect attacks (silently swap the
  upstream index) and credential-theft staging.
- **`supply_chain/registry_oidc_token_exchange_from_non_interactive.yml`**
  (critical) — outbound to `registry.npmjs.org/-/npm/v1/oidc/token/
  exchange/` from a non-interactive, non-CI parent. The Shai-Hulud
  2.0 "Second Coming" lane that doesn't need a stolen `.npmrc` —
  the worm exchanges a captured GitHub Actions OIDC token for an
  npm publish token directly.

**Cross-ecosystem content anomaly (5):**

- **`supply_chain/package_drops_native_binary_in_pure_js_pkg.yml`**
  (high) — Mach-O / ELF / `.dylib` / `.so` / `.node` written under
  `node_modules/` during an npm install lineage. Catches the
  March 2026 axios npm compromise's bundled Mach-O dropper and
  the "ambar-src" family.
- **`supply_chain/pip_wheel_drops_javascript_runtime_files.yml`**
  (critical) — `.js` / `.mjs` written under `site-packages/`
  during a `pip install` lineage, including the specific Lightning
  PyPI filenames (`_runtime/router_runtime.js`, `setup_bun.js`,
  `router_init.js`, `execution.js`, `bun_environment.js`). The
  defining cross-ecosystem smuggle signature.
- **`supply_chain/webhook_exfil_url_in_install_content.yml`**
  (critical) — well-known no-auth exfil URLs (webhook.site,
  Discord webhooks, Telegram bot API, Pastebin, ngrok,
  trycloudflare, api.ipify.org, request-bin variants,
  `filev2.getsession.org`) inside files written during a
  package-install lineage. Legitimate packages have no reason
  to embed these.
- **`supply_chain/package_postinstall_fetches_alt_runtime.yml`**
  (high) — package-manager-descended process fetching from
  `bun.sh`, `github.com/oven-sh/bun/releases`, `deno.land`,
  `nodejs.org/dist`, or `github.com/denoland/deno/releases`.
  The runtime-drop evasion pattern as it happens at the network
  layer, complementing the file-event-side
  `package_runtime_drop_evasion.yml`.
- **`supply_chain/obfuscator_signature_in_package_payload.yml`**
  (medium) — obfuscator.io / javascript-obfuscator / PyArmor
  fingerprints (`__pyarmor__`, `pyarmor_runtime`, the literal
  `eval('quire'['replace']` greppable Mini Shai-Hulud uses to
  defeat static `require(` scanners, `var _0x[hex]` / `let _0x` /
  `const _0x`, webpack signatures) inside installed package
  files. Medium severity because some legitimate packages
  distribute minified code; high-confidence when correlated with
  another rule.

**Editor / CI persistence (3):**

- **`supply_chain/node_modules_contains_leaked_dotfile.yml`** (high)
  — `.env`, `.npmrc`, `.git/config`, `.aws/credentials`,
  `.ssh/id_rsa`, `credentials.json` created under `node_modules/`
  or `site-packages/` during an install. Either accidentally
  leaked by the maintainer or planted by the attacker for later
  exfiltration via a separate process (the staged-credential
  exfil dodge).
- **`supply_chain/package_install_drops_github_workflow.yml`**
  (critical) — write to `.github/workflows/*.yml` / `*.yaml` by a
  package-manager descendant. Catches Shai-Hulud's
  `shai-hulud-workflow.yml` planting and Mini Shai-Hulud Wave 4's
  `pull_request_target` command-injection sinks.
- **`ai_safety/vscode_tasks_json_modified_by_non_vscode.yml`**
  (high) — `.vscode/tasks.json` / `settings.json` / `launch.json`
  written by anything that isn't VS Code, Cursor, VSCodium,
  Windsurf, or a dotfile manager. May 2026 Mini Shai-Hulud Wave 4
  weaponised this file with `runOn: folderOpen` task injection.
  Editor-context persistence cousin of
  `claude_settings_hook_injection_by_non_claude`.

### Detection — sequence rule

- **`sequences/worm_self_propagation_signal.yml`** (critical) —
  three-step kill chain within a 120-second process-lineage window:
  (a) package-manager descendant spawns, (b) it reads a developer
  credential (`.npmrc`, `.pypirc`, `.aws/credentials`, `.ssh/id_*`,
  GitHub host config, gem / cargo / netrc creds), (c) it makes an
  outbound connection to a publish / maintainer-enumeration endpoint
  (`registry.npmjs.org`, `upload.pypi.org`, `api.github.com
  /user/repos`, OIDC token-exchange paths). Mirrors the graph rule
  below in the sequence-engine lane so engines that key off
  `process.lineage` instead of TraceGraph nodes still match.

### Detection — graph rule

- **`Rules/graph/maccrab_worm_self_propagation.json`** (critical) —
  three-node TraceGraph signature in the same 120-second window:
  a `process` whose `executable_name` is in a curated package-manager
  set (npm / pnpm / yarn / pip / uv / poetry / python / bun / deno /
  gem / cargo / twine / ...), a `file` of kind `credential_file`
  (resolved by `CredentialFence`), and a `network` node whose
  `reputation` is not `known_good` or `private_range`. Edges:
  `proc → cred` (read, ≥ weak_inferred), `proc → net`
  (connected_to, ≥ weak_inferred). `common_ancestor: proc`,
  `min_confidence: 0.7`. ATT&CK: T1195.001, T1555, T1567, T1098.
  **v1.12.0 wiring note**: pre-RC the GraphRuleEvaluator existed
  but had no daemon-side caller — graph rules fired only in unit
  tests. The post-audit fix wave wires the evaluator into EventLoop
  (against every materialized Trace) AND adds the staging step in
  `scripts/build-release.sh` that copies `Rules/graph/*.json` into
  the DMG's `compiled_rules/graph/` so the evaluator finds them at
  daemon start. Both fixes ship in the v1.12.0 tag; if you read
  earlier RC notes that talk about graph rules being unwired, those
  refer to pre-audit state.

### Rule-quality audit fixes

- **UUID collision fixed** — the initial Wave 1 sequence rule
  `worm_self_propagation_signal.yml` was authored with id
  `e1f2a3b4-0022-...` which already belonged to
  `vscode_extension_to_credential_theft.yml`. Reassigned to
  `e1f2a3b4-0040-...` before any compiled output left the dev
  machine. A new test
  (`sequenceRuleIdsAreUnique`) walks `Rules/sequences/` on
  every test run so this class of error fails the build going
  forward.
- **`claude_settings_hook_injection_by_non_claude.yml`** — dropped
  the redundant `/Claude` case variants from the filter. APFS is
  case-sensitive on the executable basename, so the second variant
  was unreachable.
- **`homebrew_formula_no_check_sha.yml`** — dropped `/ruby` from
  the `Image|endswith` set. Brew formulas are read by the `brew`
  binary itself, not by a bare `ruby` interpreter, so the second
  match was dead weight that could only widen FPs.
- **`npm_publish_self_propagation.yml`** — added a description
  paragraph documenting the deliberate overlap with the
  pre-existing `npm_publish_from_ci.yml`. Both rules are kept
  intentionally because they key off different signals (suspicious
  CWD/parent vs. absence of interactive/CI parent); a live worm
  fires both, and that redundancy is the desired property for a
  critical-severity detection.
- **Namespace check** — verified the `maccrab` name is currently
  free on `registry.npmjs.org`, `pypi.org`, and the Homebrew core
  taps as of 2026-05-14. Recommendation captured in memory:
  defensively register placeholder packages on npm and PyPI to
  prevent post-press squat.

### Tests

- **`WormSelfPropagationRuleCompilationTests`** (suite, 5 tests
  now) — smoke-tests that all 20 v1.12.0 single-event YAML rules
  + the worm sequence rule compile to JSON predicates, each
  compiled JSON carries the required top-level fields
  (`id`, `title`, `level`), the 8 critical-severity rules are
  tagged as such, and every sequence rule under
  `Rules/sequences/` has a unique id.
- **`GraphRuleEvaluatorTests`** — 4 new cases covering the worm
  graph rule: positive npm fixture, positive Python/.pypirc
  fixture, negative case where the process is not a package
  manager (the `executable_name` filter rejects), negative case
  where the network is `private_range` (the reputation filter
  rejects). The starter-rules-decode count was bumped from 5 to
  6 to include the worm rule.

### Detection — 16 more single-event rules (Waves 3 & 4)

**Dead-man's-switch / time-bomb / tripwire (8):**

- **`command_and_control/token_revocation_polling_loop.yml`** (high) —
  periodic api.github.com `/user` poll with `Authorization: token`
  from a non-tty parent (the TanStack watchdog itself).
- **`impact/mass_unlink_from_package_lineage.yml`** (critical) —
  `rm -rf`, `find -delete`, `dscl -delete /Users/...`, or
  `mv $HOME /tmp/...` invoked by a package-manager descendant.
- **`persistence/launchagent_with_distant_future_trigger.yml`**
  (medium) — LaunchAgent plist with `StartInterval ≥ 3600` /
  `StartCalendarInterval` and `RunAtLoad: false`. XCSSET /
  BlueNoroff RustBucket time-bomb pattern.
- **`discovery/locale_check_from_package_lineage.yml`** (medium) —
  `defaults read AppleLanguages` / `.GlobalPreferences.plist` read
  by package-manager descendant (Lazarus / Shai-Hulud CIS-skip).
- **`discovery/vm_detection_probe_from_package_lineage.yml`** (high)
  — `sysctl hw.model` / `ioreg -l` / `system_profiler` from package
  lineage (AMOS, KandyKorn).
- **`defense_evasion/maccrab_tamper_attempt.yml`** (critical) —
  non-MacCrab process trying to kill, unload, or delete MacCrab
  components. EDR-disable canary.
- **`execution/staged_fetch_then_exec_from_user_writable.yml`**
  (high) — exec of binary under `/tmp`, `/var/folders`,
  `~/Library/Caches/` whose lineage includes a fetch from a
  package install.
- **`defense_evasion/openssl_decrypt_in_install_lineage.yml`**
  (high) — `openssl enc -d` from npm / pip lineage (KandyKorn,
  NX worm multi-stage primitive).

**macOS app threat surface (8):**

- **`defense_evasion/fake_apple_bundle_in_user_dir.yml`** (high) —
  `.app/Info.plist` declaring `CFBundleIdentifier: com.apple.*`
  outside `/System/` or `/Applications/`.
- **`defense_evasion/mas_receipt_access_by_non_sandbox.yml`** (high)
  — read of `Contents/_MASReceipt/receipt` by a process that is not
  the owning sandboxed app, not Apple, not StoreKit.
- **`defense_evasion/binary_resigned_post_installation.yml`** (high)
  — `codesign` targeting `/Applications/*.app` or
  `/Library/Application Support/...` from a non-Xcode, non-Sparkle,
  non-installer parent. Trojanise-an-installed-app primitive.
- **`execution/adhoc_signed_app_execution_from_user_dir.yml`** (high)
  — ad-hoc-signed binary executing from `~/Downloads/`,
  `~/Desktop/`, `/tmp/`, `/Volumes/`. Atomic Stealer / Cthulhu /
  MacSync signature.
- **`defense_evasion/network_policy_plist_tampered.yml`** (high) —
  write to Little Snitch / Lulu / Radio Silence / Murus prefs by
  non-vendor, non-Apple process.
- **`defense_evasion/info_plist_modification_post_install.yml`**
  (medium) — write to `.app/Contents/Info.plist` of an installed
  bundle by non-Xcode / non-installer / non-Sparkle parent.
- **`initial_access/url_scheme_handler_collision.yml`** (medium) —
  `lsregister -f` or `defaults write LSHandlers` binding a
  well-known scheme (mailto, http, slack, zoommtg, vscode,
  cursor, git+) to a non-canonical bundle.
- **`defense_evasion/bulk_quarantine_strip.yml`** (high) — `xattr -cr`
  or `find ... -exec xattr -d com.apple.quarantine`. The ClickFix
  pattern for Sequoia-era Gatekeeper bypass.

### Swift actors (new — pulled forward from v1.13.x)

- **`Sources/MacCrabCore/Enrichment/TyposquatDatabase.swift`** —
  pure-local typosquat / slopsquat scorer. Damerau-Levenshtein
  with transposition cost 1, Unicode TR39 confusable fold
  covering high-value Cyrillic / Greek / fullwidth mappings,
  starter top-50 npm + top-50 PyPI corpora bundled (full
  top-1000s loadable via the test-friendly initializer).
- **`Sources/MacCrabCore/Enrichment/PackageContentAnalyzer.swift`**
  — on-disk package walker. Computes total size, file-extension
  census, single-line >100KB file count, Mach-O magic-byte
  detection (32/64-bit LE/BE + FAT universal), obfuscator-marker
  scan (PyArmor, javascript-obfuscator `_0x`, Mini Shai-Hulud
  `eval('quire'['replace'])` greppable, webpack), and bundled-
  runtime detection (Bun / Deno / Node / Python / Ruby / PHP
  binary 20-200MB by basename + magic). Returns 0-100 score plus
  per-factor reasons.
- **`Sources/MacCrabCore/Enrichment/PackageMetadataAnalyzer.swift`**
  — registry-JSON-driven scorer. One GET per package per 24h
  (cached). Scores: description length distribution, boilerplate
  phrase match, homepage host class (free-host vs corporate),
  repository URL, version-history burst (≥10 in 24h on
  previously-quiet package), top-version-squat (first publish
  ≥ 99.x.x), maintainer signals (`@users.noreply.github.com`).
  Injectable fetcher closure for testability.
- **`Sources/MacCrabCore/Enrichment/AttestationEnricher.swift`** —
  Sigstore + PEP 740 + OIDC provenance verifier. Detects
  publishing-method mismatch when supplied a prior builder
  identity. Status enum: `.verified` / `.absent` / `.mismatched`
  / `.fetchFailed`. Also injectable fetcher.

### HoneyfileManager extension

- New `HoneyfileType` cases: `.npmrc`, `.pypirc`, `.gitConfig`,
  `.githubHosts`, `.cargoCredentials`.
- Default deploy set extends to plant `.bak`-suffixed canaries
  at `~/.npmrc.bak`, `~/.pypirc.bak`, `~/.gitconfig.bak`,
  `~/.config/gh/hosts.yml.bak`, `~/.cargo/credentials.toml.bak`.
  Content uses the canonical `_authToken=npm_...` /
  `ghp_...` / `pypi-...` token shapes that Shai-Hulud family
  scrapes by-glob. Existing
  `Rules/persistence/honeyfile_accessed.yml` decoy-read rule
  fires on any read of these paths via the `IsHoneyfile`
  enrichment — no new rule needed.

### Tests

- **`WormSelfPropagationRuleCompilationTests`** — extended slug
  list now covers all 36 v1.12.0 single-event rules (Waves 1-4).
- **`TyposquatDatabaseTests`** (new suite, 8 tests) — Damerau-
  Levenshtein behaviour, Cyrillic/Greek confusable fold, axios /
  react / requests typosquat catches, homoglyph attack score 100,
  exact match not flagged.
- **`PackageContentAnalyzerTests`** (new suite, 6 tests) — Mach-O
  magic detection, obfuscator-marker scan, single-line bundle
  detection, PyPI cross-ecosystem mismatch, clean package
  scoring, obfuscated bundle scoring.
- **`PackageMetadataAnalyzerTests`** (new suite, 7 tests) — top-
  version squat heuristic, homepage host classification, full
  high-risk npm fixture, clean npm fixture, boilerplate match,
  PyPI high-risk, fetcher cache.
- **`AttestationEnricherTests`** (new suite, 6 tests) — npm
  verified / absent / fetch-failed / builder-mismatched, PyPI
  verified / absent.
- **`HoneyfileManagerExtensionTests`** (new suite, 5 tests) —
  five new HoneyfileType cases defined, default deploy set
  contains all v1.12.0 bait paths, deploy plants and
  `isHoneyfile` resolves them, `.npmrc.bak` uses the canonical
  worm-scrape token format.

### Numbers

- Rules: 463 YAML rules total under `Rules/` — that's 424
  single-event rules + 39 sequence rules (after Round-3
  deletions + Round-4 surgical fixes). Plus 6 graph rules
  under `Rules/graph/*.json`.
- Tests: 1490 (+87 over v1.11.1's 1404).
- Test suites: 284 (+18).
- New Swift LOC: ~3500 across 10 new actors (TyposquatDatabase,
  PackageContentAnalyzer, PackageMetadataAnalyzer,
  AttestationEnricher, IntentClassifier, PromptIntentBridge,
  BayesianIntentEngine, NextTechniquePredictor,
  CounterfactualReasoner, StylometricFingerprinter) plus
  HoneyfileManager / HoneyPromptManager extensions and 8 new
  MCP tools (~700 LOC of tool definitions + handlers).

### Pre-RC1 hardening pass

A five-domain audit (detection-quality, security, performance,
code-quality, test-quality) caught a number of issues across the
five-wave drop above. All blocker-class findings closed before
RC1:

**Security (5 fixes):**
- **SEC-01 CRITICAL (URL host-injection)** —
  `PackageMetadataAnalyzer` and `AttestationEnricher` previously
  used `CharacterSet.urlPathAllowed` for name encoding, which
  doesn't escape `/`, `:`, `@`, `;`. A package name `evil.com/x`
  produced an HTTP GET to `evil.com`. Replaced with a new
  `SafeRegistryURL` helper that regex-validates names against
  the registry's own rules (npm: `^@?[a-z0-9][a-z0-9._-]{0,213}
  (/...)?$`; PyPI: `^[a-zA-Z0-9][a-zA-Z0-9._-]{0,213}$`) before
  URL construction, then uses `URLComponents` so reserved
  characters get encoded.
- **SEC-02 HIGH (unrestricted HTTP redirects)** — both registry
  fetchers used default URLSession redirect-follow, so a 302
  from `registry.npmjs.org` to `localhost:9000/internal-api`
  would be followed silently. Replaced with a new
  `HardenedRegistrySession` factory whose
  `URLSessionTaskDelegate` validates the redirect host against
  a 4-entry allow-list (`registry.npmjs.org`, `pypi.org`,
  `files.pythonhosted.org`, `api.github.com`) and refuses
  anything else. Also: generic `User-Agent`, no cookies,
  response-size cap (16 MB).
- **SEC-03 HIGH (`PackageContentAnalyzer` path traversal)** —
  `analyze(packagePath:)` previously enumerated any URL, so
  the MCP `scan_package_content` handler could walk
  `~/.ssh/`, `/etc/`, or `/Library/Application Support/
  MacCrab/`. Added an `allowedScopes` parameter on the actor;
  callers pass `defaultPackageScopes` (`~/node_modules/`,
  `~/.npm/`, `~/Library/Python/`, `/opt/homebrew/Cellar/`,
  `/usr/local/Cellar/`, tmpdir). Out-of-scope paths return
  an empty result with `"path outside allowed scope"`
  reason. Also bounded: max 50K files, max 8 levels deep,
  max 2 GB total bytes scanned.
- **SEC-04 HIGH (`PromptIntentBridge` arbitrary read)** —
  `defaultFileReader` read any path appearing in agent
  fileRead events with no scope check. Now scoped to
  `NSHomeDirectory()` via `SecureFileIO.readBytes(scope:)`.
- **SEC-05 HIGH (`HoneyfileManager` / `HoneyPromptManager`
  TOCTOU)** — both used `FileManager.fileExists` + atomic
  write, a classic race. An attacker who wins a sub-ms race
  in `~/.aws/` could plant a symlink to `~/.aws/credentials`
  and have the bait write clobber the real credentials.
  Replaced with a new `SecureFileIO` helper that uses POSIX
  `open(2)` with `O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC`
  for writes (kernel-atomic existence+symlink check) and
  `O_RDONLY | O_NOFOLLOW` for reads.

**Detection (4 broken-rule rewrites + 3 FP-machine tightenings):**
- `adhoc_signed_app_execution_from_user_dir.yml` —
  `CodeSigningFlags|contains: 'ADHOC'` matched a stringified
  integer not a flag name. Switched to `IsAdhocSigned: 'true'`
  which RuleEngine actually resolves.
- `github_user_repos_post_from_non_git.yml` /
  `registry_oidc_token_exchange_from_non_interactive.yml` /
  `token_revocation_polling_loop.yml` — used
  `CommandLine|contains` on `network_connection` events to
  match HTTP URIs, but the engine populates CommandLine with
  process argv, not HTTP URIs. Rewrote each as hostname +
  node-class Image + parent-lineage filter.
- `llm_classifier_high_risk_intent.yml` declared
  `logsource.category: maccrab_internal` which RuleEngine
  cannot produce — rewritten to gate on
  `process_creation` for package-manager Images carrying the
  `IntentLabel` enrichment that the daemon-side
  `IntentClassifier` writes onto install lineage.
- `maintainer_publish_hour_anomaly.yml` description claimed
  00:00-05:00 time-of-day matching that the Sigma predicate
  doesn't implement; renamed + reframed as a
  drift-detection-input rule.
- `canary_skill_or_rules_read.yml` — bait was previously
  planted at `~/CLAUDE.md.canary` (Spotlight-indexed) and
  `~/.claude/skills/maccrab-decoy/SKILL.md` (Claude Code's
  own skill discovery path) — both self-tripping FP
  generators. Relocated all bait under `~/Library/
  Application Support/MacCrab/decoys/` (not indexed by
  default). Added `filter_apple_indexers` (mdworker_shared,
  mds, backupd, etc.) and `filter_backup_sync` (Backblaze,
  Carbon Copy Cloner, Arq, Dropbox, iCloud) so legitimate
  indexers don't fire.
- `pip_wheel_drops_javascript_runtime_files.yml` previously
  matched any `*.js` / `*.mjs` / `*.cjs` under
  `site-packages/` — continuous-fire on every Jupyter
  widget / Plotly / Bokeh wheel. Dropped the broad branch;
  kept only the specific Mini Shai-Hulud / Lightning IOC
  filenames.
- `package_drops_native_binary_in_pure_js_pkg.yml` — added
  a `filter_legitimate_native_addons` allowlist for
  bcrypt / sharp / sqlite3 / better-sqlite3 / canvas /
  esbuild / swc / vips / fsevents / node-gyp-build /
  keytar / zeromq / sodium-native (the long tail of
  every modern Node project's native addons). Severity
  dropped from high to medium.

**`FileContentEnricher` (new) — closes the 10-rule engine gap:**

The pre-RC audit caught that 10 rules use `FileContent|contains`
selectors but no enricher previously populated the field. The
new `Sources/MacCrabCore/Enrichment/FileContentEnricher.swift`
reads the first 64 KB of `close`-write events for a tight
allowlist of "interesting" file types (`Info.plist`, `CHANGELOG`,
`README.md`, `.gitconfig`, `*.rb` under `Library/Taps`, plist
files under `LaunchAgents/`, specific IOC filenames like
`bun_environment.js`). Uses `SecureFileIO` (O_NOFOLLOW) for the
read; size pre-flight via `lstat` so giant binaries are skipped.
Always-on (the allowlist is tight enough that the cost is
trivial vs the detection value).

Wired into `EventEnricher` alongside the existing honeyfile
enrichment path; `RuleEngine`'s default `resolveField` already
falls through to `event.enrichments[path]` so the existing
`FileContent|contains` predicates now match.

**`HoneyPromptManager` wired into daemon + maccrabctl:**

The audit caught that `HoneyPromptManager.deploy()` was never
called — bait files were never planted, so the
canary-package-install / canary-file-read rules could never
fire. Now wired alongside `HoneyfileManager` in `DaemonSetup`
under the same `MACCRAB_DECEPTION=1` gate, and exposed via
`maccrabctl deception deploy / status / remove`. Bait files
relocated under `~/Library/Application Support/MacCrab/decoys/`
to avoid self-tripping Claude Code's skill discovery and
Spotlight indexing.

**Performance:**
- `PromptIntentBridge.packageNameRegex` is now a
  `nonisolated static let` instead of being recompiled per
  call (audit caught the ~1 ms-per-call hit).
- `PackageContentAnalyzer` walk is bounded (50K files, 8
  levels deep, 2 GB total) as part of the SEC-03 fix.

**Test additions:**

`HoneyPromptManagerTests` updated to verify the new decoy-
relocation invariant: no bait under `~/.claude/skills/` or
at `~/CLAUDE.md.canary`; all under `~/Library/Application
Support/MacCrab/decoys/`. All 1490 tests in 284 suites pass.

**Deliberately deferred to v1.13.x (documented in memory):**
- Full daemon-side wiring of `BayesianIntentEngine` +
  `IntentClassifier` into the rule-fire path (currently
  reachable only via MCP tools — the v1.12.0 surface is
  honest about this).
- `PackageContentAnalyzer` / `PackageMetadataAnalyzer` /
  `AttestationEnricher` integration into `PackageScanner`
  for the dashboard's Package Freshness tab (still serves
  stub data).
- `StylometricFingerprinter` single-pass optimization
  (current implementation is correct but allocates
  ~5 MB transient per 100 KB input — low daily call rate
  makes it non-blocking).
- Full top-1000 npm + PyPI typosquat corpora as bundled
  JSON resources (currently ships starter top-50;
  initializer accepts explicit corpora).

### Pre-RC1 rule-quality audit (round 2)

A methodology-driven 470-rule audit using a 10-question
rubric (synthesised from SigmaHQ spec + Palantir ADS +
Florian Roth + SpecterOps + Chuvakin alert-fatigue
research) caught additional surgical issues missed by the
first audit pass. Fixes:

**Rule-corpus fixes:**
- `sequences/rosetta_download_execute_c2.yml` missed
  `attack.t1027` (Obfuscated Files) + `attack.t1059.004`
  (Unix Shell) sub-technique tags despite covering both
  techniques. Added.
- **10 rules demoted from `status: stable` to
  `status: test`** — they had recent dates (2026-04 /
  2026-05) inconsistent with the "battle-tested"
  semantics the Sigma spec attaches to "stable". The
  rules are correct, but the status was over-claimed.
  Affected: `ai_safety/ai_tool_spawns_shell`,
  `ai_safety/ai_tool_reads_env_file`,
  `ai_safety/agent_traceparent_credential_access`,
  `ai_safety/mcp_server_suspicious_command`,
  `ai_safety/ai_tool_prompt_injection`,
  `ai_safety/mcp_server_tool_poisoning`,
  `ai_safety/ai_tool_modifies_shell_profile`,
  `ai_safety/ai_tool_writes_persistence`,
  `ai_safety/ai_tool_downloads_script`,
  `collection/usb_mass_storage_connected`.
- **Graph rules: caught unwired by Round-2 audit, fixed
  in the same release.** The audit caught that the 6
  graph rules in `Rules/graph/` (including
  `maccrab_worm_self_propagation`) compiled and decoded in
  tests but had no production caller. The post-audit fix
  wave (see "v1.12.0 wiring note" in the Wave-1 graph-
  rule listing above) wires `GraphRuleEvaluator` into
  `EventLoop` against every materialized Trace AND adds
  the staging step in `scripts/build-release.sh` that
  copies `Rules/graph/*.json` into the DMG. Both fixes
  ship in the v1.12.0 tag. The earlier audit-deferral
  text said graph rules would land in v1.13.x — that
  text is stale; the deferral was closed in the same
  release.

**Full 470-rule rubric audit (Round 3):**

Seven parallel auditors applied a 10-question rubric (Q1 goal
clarity / Q2 logsource correctness / Q3 capability abstraction /
Q4 selector specificity / Q5 condition correctness / Q6 FP
discipline / Q7 severity calibration / Q8 ATT&CK tag discipline /
Q9 actionability / Q10 validation evidence) to every YAML rule
across the 19 tactic directories. Distribution across the corpus:

- **KEEP (score ≥18/20)**: ~200 rules. Solid as shipped.
- **FIX (14-17/20)**: ~200 rules. One identified weakness each
  — most commonly: missing test fixture (Q10), generic FP
  scenarios (Q6), or filter list incompleteness on dev-tool
  parents (Q4). These do not block RC1; queued for v1.13.x.
- **QUARANTINE (9-13/20)**: ~60 rules. Already at `status:
  experimental` or being demoted there. Detection is loose, but
  the threat model is right; rewrites pending.
- **REWRITE / DELETE (≤8/20)**: 7 rules. Surgical action below.

Per-tactic averages: **17.4/20** for impact/privilege_escalation
(strongest), **15.8/20** for discovery (weakest — daily admin
commands like `ps`, `lsof`, `defaults read` are over-rated).

**Surgical Round-3 fixes (Tier 1: structural):**

- **4 rules DELETED** — broken-by-construction, unsalvageable:
  - `collection/clipboard_sensitive_data.yml` —
    `process_creation` logsource can't inspect clipboard
    content; rule never fires.
  - `collection/usb_hid_keyboard_emulation.yml` — matches the
    string `IOHIDDevice` in CommandLine; fires on every USB
    keyboard.
  - `tcc/multiple_tcc_grants_rapid.yml` — title claims "rapid"
    but Sigma has no temporal evaluator; rule fires on any
    single grant.
  - `defense_evasion/endpoint_security_slot_exhaustion.yml`
    — text-matches `IOServiceOpen` / `es_new_client` in
    CommandLine; the strings appear in source code and docs,
    not actual API events.

**Surgical Round-3 fixes (Tier 2: severity calibration):**

- **7 rules dropped one severity tier** because their own FP
  sections admit dev / admin overlap incompatible with the
  declared severity (per the rubric's <1/quarter critical /
  <1/month high / <1/week medium / <1/day low table):
  - `credential_access/password_manager_db.yml`:
    critical → high
  - `credential_access/messages_database_access.yml`:
    critical → high
  - `supply_chain/npm_publish_from_ci.yml`: critical → high
  - `credential_access/token_files_accessed.yml`:
    high → medium
  - `credential_access/ssh_key_file_read.yml`:
    high → medium (git operations legitimately read
    `~/.ssh/`)
  - `execution/curl_wget_download_execute.yml`:
    high → medium (`curl | bash` is daily for Homebrew,
    Rustup, NVM)
  - `discovery/mdm_enrollment_check.yml`: medium → low
    (`profiles status` is daily IT admin work)

The audit's broader **~60 FIX-tier and ~60 QUARANTINE-tier**
findings are tracked but not all applied in this RC. They
fall into three recurring patterns the v1.13.x cycle will
address systematically:

1. **Dev-tool parent allowlist** — many discovery + execution
   rules need a global "package-manager descendant" filter
   to skip Homebrew / npm / pip / yarn child processes. Add
   once, apply broadly.
2. **Network-event HTTP-URI matching** — multiple rules try
   to match HTTP URIs in `CommandLine` on `network_connection`
   logsources; that field doesn't carry HTTP URIs. v1.12.0
   fixed 3 such rules; v1.13.x audit found 2 more
   (`dns_over_https_manual.yml`, `tor_proxy_connection.yml`
   marginal) — fix in next pass.
3. **Single-event detection of inherently-temporal threats**
   — `auth_brute_force.yml` title says "brute force" but
   fires on single commands; `mass_ssh_from_single_process.yml`
   claims "mass" but is single-event. These need either
   sequence-engine implementation or honest title rewrites.

Final v1.12.0 corpus: **463 YAML rules total** — 424 single-
event + 39 sequence. Plus 6 graph rules. Tests still pass:
**1490 / 1490 green across 284 suites**.

**Round 4 — surgical fix pass on every QUARANTINE / FIX-tier
finding (~80 rules touched):**

After the Round-3 audit identified 70+ rules needing surgical
work, a follow-up pass attempted to repair every one (with
deletion only as last resort). Eight parallel fix agents
worked across the corpus by tactic, applying the rubric's
prescribed remedies: tighter selectors, dev-tool parent
filters, severity calibration, title/description alignment,
sub-technique tagging.

**Net rule-corpus changes this round:**
- ~80 rules **TIGHTENED** with stronger filters / context
- **3 rules DELETED** (all because a superior implementation
  of the same detection already shipped):
  - `defense_evasion/code_sign_adhoc.yml` — fired on every
    Xcode build / Swift build / `make dev`. The proper
    detection (executing ad-hoc-signed binary from
    user-writable path) is already implemented as
    `execution/adhoc_signed_app_execution_from_user_dir.yml`
    via the engine's `IsAdhocSigned: 'true'` selector.
  - `defense_evasion/rogue_mdm_profile.yml` — duplicate of
    `mdm_profile_installed_unexpected.yml` which has the
    richer MDM-agent allowlist (Jamf, Mosyle, Kandji,
    Hexnode, Munki, Addigy, FileWave, SimpleMDM,
    mdmclient).
  - `persistence/at_job_created.yml` — duplicate of
    `at_job_creation.yml` (which was hardened in this
    round and promoted to severity high since modern macOS
    effectively never invokes `at(1)`).
- **2 rules DEPRECATED** (status: deprecated; kept as stubs
  preserving rule ids for legacy suppressions):
  - `exfiltration/airdrop_file_transfer.yml` — AirDrop
    invocation happens through NSSharingService XPC, never
    via CLI. `collection/airdrop_file_staging.yml` covers
    the actual file-event signal.
  - `privilege_escalation/sandbox_escape_indicators.yml` —
    detected API call NAMES in CommandLine
    (`mach_port_allocate`, `IOServiceOpen`) but those
    strings only appear in compiled binary segments, never
    in argv. v1.13.x ES-based sandbox-violation detection
    will replace it.

**Common patterns established across the fix pass:**

1. **Dev-tool ancestry filter** — the dominant FP source in
   discovery + execution + persistence rules. Added a
   shared filter pattern across ~25 rules covering shells
   (bash/zsh/sh/fish/dash), terminals (Terminal /
   iTerm2 / Alacritty / kitty / WarpTerminal / Ghostty /
   Hyper / tmux / screen / zellij), editors (Cursor / Code
   / VS Code / nvim / vim / emacs / JetBrains), runtimes
   (node / ruby / python / python3), package managers
   (brew / npm / yarn / pnpm / pip / pip3 / uv / poetry /
   bun / deno / cargo / rustup), CI runners (runner /
   buildkite-agent / circleci / Runner.Listener /
   gitlab-runner), env managers (asdf / mise / nvm / pyenv
   / rbenv / direnv), and dotfile managers (chezmoi /
   stow / yadm / dotbot).

2. **PlatformBinary > SignerType** — switched the Apple-
   filter idiom in ~10 rules. `SignerType` returns nil for
   short-lived processes (launchctl, system_profiler);
   `PlatformBinary` comes from the kernel and is reliable.

3. **High-signal-token discipline** — multiple
   over-broad-selector rules tightened. Examples:
   `defaults_read_sensitive` no longer matches
   `com.apple.dock` / `com.apple.finder` / Spotlight
   queries; `mdfind_spotlight_recon` no longer matches
   bare `password` / `ssh` / `wallet` which collide with
   product names; `ioreg_hardware_enum` no longer matches
   bare `model` or `-rd1` (the most common output flag).

4. **Title/body alignment** — multiple rules with
   misleading titles were renamed to match what they
   actually detect:
   - `mass_ssh_from_single_process.yml` → "Suspicious
     SSH from Script-like or Non-Interactive Parent"
     (Sigma single-event rules can't detect "mass");
   - `auth_brute_force.yml` → "Sudo Stdin Password or
     Keychain Unlock by Non-Apple Process";
   - `developer_credential_bulk_harvest.yml` →
     "Developer Credential File Read by Untrusted
     Process";
   - `system_enumeration_burst.yml` description now
     explicitly states burst-style detection belongs in
     the sequence engine, not this rule;
   - `kernel_exploit_crash_indicator.yml` →
     "Crash Reporter Invoked Against Kernel or
     Privileged Subsystem (Precursor)";
   - `xpc_service_enumeration.yml` → "Privileged XPC
     Service Enumeration (Discovery Precursor)";
   - `browser_extension_suspicious.yml` → "Browser
     Extension Manifest or Package Modified Outside
     Browser Process".

5. **Severity recalibration** — ~15 rules dropped one tier
   per the rubric's severity table (critical <1/quarter,
   high <1/month, medium <1/week, low <1/day). Examples:
   `csrutil_status_check`: low → informational;
   `file_flag_hidden`: medium → low; `process_suspension`:
   medium → low; `osascript_from_non_apple`: medium → low;
   `shell_spawned_by_browser`: medium → low;
   `dmg_mounted_from_suspicious_location`: medium → low;
   `xpc_service_enumeration`: medium → low;
   `ai_tool_prompt_injection`: high → low;
   `ai_tool_spawns_shell`: low → informational.

6. **Allowlist taxonomy** — cross-app FP-suppression
   classes that recur across rules:
   - `filter_conferencing` (Zoom, Teams, Slack, Webex,
     Discord, browsers — Q audio/video/screencap context)
   - `filter_password_managers` (1Password, Bitwarden,
     Dashlane, NordPass, KeePassXC, RoboForm, LastPass,
     ProtonPass — credential-store reads)
   - `filter_backup_sync` (Backblaze, Carbon Copy
     Cloner, SuperDuper!, Arq, Time Machine, Migration
     Assistant — sensitive-file reads)
   - `filter_sync_clients` (Dropbox, iCloud Drive,
     OneDrive, Google Drive, Box, iCloudPhotos)
   - `filter_secret_scanners` (gitleaks, trufflehog,
     detect-secrets, ggshield, talisman, whispers — for
     `find -name "*.pem"`-style queries)
   - `filter_mdm` (Jamf, Mosyle, Kandji, Hexnode,
     Addigy, Munki, FileWave, ManagedClient)

**Validation:** all 463 rules compile cleanly (`make
compile-rules` returns OK on every rule). The full Swift
test suite (1490 tests in 284 suites) still passes green
with the new rule corpus.

**`MACCRAB_DEV_MODE=1` env-var gate (new):**

Per the audit, `CampaignDetector` + `BehaviorScoring`
thresholds were calibrated for production attacker
signals, and the v1.4.1 / v1.4.2 / v1.6.4 CHANGELOG
entries documented reactive fixes for developer-machine
false positives. The new gate is a formal opt-in:

- `CampaignDetector.minTacticsForKillChain` lifts from
  4 to 5 when set. A developer running CI tests, build
  pipelines, or `make test-campaign` touches 4 tactics
  in 10 minutes routinely; 5 is closer to a real attack
  signature.
- `CampaignDetector.campaignDedupWindow` lifts from
  600 s to 1200 s — iterative test runs of similar
  tactic patterns no longer generate repeated alerts.
- `BehaviorScoring` halves the contribution of
  `ai_tool_*` indicators when set. Rationale: Claude
  Code / Cursor / Cline / Continue / Windsurf legitimately
  spawn shells, run sudo, install packages, and modify
  shell rc files all day on a developer's machine. Full
  weights walk the score past the 10/20 alert/critical
  thresholds in normal operation. Halved weights still
  catch genuinely adversarial AI-agent behavior
  (cumulative 2-3 hits) but don't fire on the operator's
  everyday agent use.

Set in the daemon's launchd plist or the shell where
`maccrabd` is launched. Off by default (production
defaults preserved); developers running MacCrab on their
own workstation should turn it on.

### Scope deliberately *not* in this release

- No auto-response. Every new rule fires an alert; freezing
  `.npmrc` / `.pypirc`, killing descendants, or sinkholing the
  registry are explicit non-goals for v1.12.0 so the FP rate
  can be measured against real devloops first.
- No tarball pre-flight scan, no Sigstore / SLSA / PEP 740
  attestation verification, no Levenshtein-based slopsquat DB —
  those are the next wedges, planned for v1.13.x as the
  `PackageContentAnalyzer`, `AttestationEnricher`, and
  `TyposquatDatabase` actors respectively.
- No fleet-wide IOC broadcast — also a later wedge.

## [1.11.1] — 2026-05-13

First-launch beachball hotfix. Three things ran on the main thread
before SwiftUI rendered the dashboard's first frame; all three are
now deferred:

- **`RuleBundleInstaller.syncIfNeeded()` moved off `MacCrabApp.init()`** —
  on first install / Sparkle update the sync did SHA-256 manifest
  verification + copied 427 rule files to `/Library/Application
  Support/MacCrab/compiled_rules/` (cold-cache: 200 ms – 2 s). Now
  runs detached from the WindowGroup's `.onAppear` after first
  frame; daemon SIGHUP at sync completion picks up the new corpus.
- **`V2LiveDataProvider()` SQLite opens parallelized + detached** —
  alerts.db / events.db / campaigns.db / tracegraph.db previously
  opened serially on @MainActor. Now four parallel `async let` +
  `Task.detached` opens; cold open drops from sum to ~max + actor
  hop.
- **`AppState.loadSuppressPatterns()` + `loadSuppressedIDs()` deferred** —
  two small UI-state file reads in `AppState.init()` moved to a
  `Task { @MainActor in ... }` so init returns immediately.

Net result: dashboard window should paint in well under 200 ms on
cold launch. 1404 / 1404 unit tests still pass; pure deferral, no
behavior changes.

Full notes: `RELEASE_NOTES/v1.11.1.md`.

## [1.11.0] — 2026-05-12

Feature release combined with a sustained audit-fix pass. A six-domain
pre-release audit (security / stability / performance / functionality /
scalability+UX-L10n / ship-readiness) on the v1.10.1 baseline surfaced
8 BLOCKERs + 24 HIGHs + 25 MEDIUMs + 22 LOWs (79 findings total).
v1.11.0 closes every BLOCKER, the high-impact HIGHs, the wire-the-orphans
HIGHs (alertNotifications + inbox poller reentrancy), the bulk of the
MEDIUMs, AND ships the deferred v1.10.x backlog: M2 live data wiring
across collectors / permissions / packages / integrations, AlertStore
phantom-field schema migration, force-directed TraceGraph canvas, YAML
compilation for graph rules, `maccrabctl trace replay --compare-rules`,
and sidebar consolidation.

### Security

- **Inbox file-IPC now gates on UID** (BLOCKER) — the v1.10.1 hotfix
  introduced `/Library/Application Support/MacCrab/inbox/` mode `1777`
  with handlers for `suppress-alert-*` / `unsuppress-alert-*` /
  `delete-alert-*` / `suppress-campaign-*`. The handlers logged the
  request UID but did not gate on it, so any local user on a multi-user
  / kiosk / compromised-guest Mac could blind the EDR. Each handler now
  rejects requests whose owning UID is not root or the GUI console
  user (`SCDynamicStoreCopyConsoleUser`); rejections + outcomes are
  written to `<supportDir>/dashboard_audit.log` for forensics.
- **`llm_config.json` now writes `0o600`** (HIGH) — previously inherited
  user umask (`0o644`), leaving Claude / OpenAI / Mistral / Gemini API
  keys readable by every local user. The keychain copy was always the
  primary store; this closes the legacy JSON copy that
  `AppState.ensureLLMService` still consumes.

### Stability + performance

- **`EventLoop` autoreleasepool gap closed** (BLOCKER) — the central
  hot loop (~200-1000 events/s sustained) had no per-iteration drain
  point. Foundation temporaries from enricher / ruleEngine / JSON
  encode / sanitize accumulated between implicit yields; field reports
  showed 1+ GB sawtooth growth after 24h on busy hosts. Added an
  `await Task.yield()` at iteration end to force a cooperative drain
  (`autoreleasepool {}` can't natively wrap `await` blocks, mirror of
  v1.7.7-v1.7.9 fixes).
- **Inbox poller reentrancy guard** (HIGH) — the v1.10.1 inbox file-IPC
  poller fired a fresh Task every 5 s; if a campaign-suppress fan-out
  was still draining (worst case 30 s at 5K alerts × 6 ms / write),
  the next tick spawned a parallel Task that re-listed the dir + raced
  for the same files. New `OSAllocatedUnfairLock<Bool>` on
  `DaemonState.inboxPollerLock` makes the poller skip ticks while
  draining — matches the `snapshotWriteInFlight` pattern v1.7.4
  introduced for telemetry writers.
- **`CampaignDetector.recordForStormDetection` now bounds its per-rule
  timestamp array inline** (MEDIUM) — pre-fix only the 5-min sweep
  ran `purgeStaleStormCounts`, so a high-volume rule accumulated
  thousands of timestamps between sweeps. Cap at 2× `stormCriticalThreshold`.
- **`AlertStore.alerts(forEventId:)` adds `LIMIT 1000`** (MEDIUM) —
  bounds against rule-storm scenarios where many alerts pin the same
  event_id.
- **`AlertStore` + `CampaignStore` enable `auto_vacuum = INCREMENTAL`**
  (MEDIUM) — pre-fix retention prune deleted rows but freed pages
  stayed in the file. Existing DBs need a one-shot manual `VACUUM`
  to convert; fresh installs flip immediately.
- **MonitorTasks autoreleasepool gap** documented as v1.11.1 follow-up
  — 13 secondary `for await` loops, lower volume than EventLoop, same
  shape; quick mechanical follow-up.

### Functionality (phantom subcommands + MCP enum drift)

- **`maccrabctl rule show <id>` was a phantom subcommand** (BLOCKER) —
  V2 Detection workspace error toast pointed users at a subcommand
  that doesn't exist (only `maccrabctl rules list | grep` does).
  Same class as the v1.10.1 dashboard-suppress hotfix.
- **`maccrabctl ai tools` and `maccrabctl ai lineage` were phantom
  subcommands** (BLOCKER) — V2 AI Guard panel told users to run them
  to inspect AI tool inventory / lineage chains. Replaced with
  concrete pointers to `~/Library/Application Support/MacCrab/agent_lineage.json`.
- **MCP `get_events` advertised non-existent `EventCategory` values**
  (BLOCKER) — schema enum included `auth` and `dns` which return nil
  via `EventCategory(rawValue:)`, silently dropping the filter. Now
  matches the real categories (`process / file / network /
  authentication / tcc / registry`); DNS guidance documents the
  `category=network` + `search=:53` pivot.
- **V2 alerts table no longer renders "pid 0" for every row** (HIGH) —
  pid sub-label gates on `> 0`, mirroring the inspector. Real pid
  persistence is a v1.11.0 schema task.
- **`OTLPOutput` ModuleStatus demoted to `.experimental`** (HIGH) — the
  actor exists but `DaemonSetup.buildOutput(spec:)` does not yet
  accept `{"type":"otlp"}` config entries. Receiver half (Agent
  Traces) remains stable. Re-promotion tracked for v1.11.0.

### Ship pipeline / version-drift hardening

- **`homebrew/maccrab.rb` re-synced to `Casks/maccrab.rb`** (BLOCKER) —
  the legacy doc copy had drifted by 40+ lines, missing v1.10.0's
  inbox-dir mkdir, in-app CLI symlink fix, and v1.7.11 SIGTERM block.
  Bodies now byte-equal modulo `version` + `sha256` lines.
- **`.github/workflows/release.yml` now bumps both cask files**
  (BLOCKER) — CI release path silently bumped `homebrew/maccrab.rb`
  only, leaving the canonical `Casks/maccrab.rb` (what the tap reads)
  pinned. Also removed `|| true` / `|| echo "..."` failure-swallowing
  patterns. Same shape as the v1.6.5→v1.6.13 9-stale-release class
  that `release.sh` already fixed locally.
- **`scripts/release.sh` final-hint URL now points at `Casks/maccrab.rb`**
  (HIGH).
- **`pre-release-audit.sh` Pass 6 / Pass 12 / Pass 14 hardened** (BLOCKER)
  — applied the v1.9.0 Pass 15 "fail loud if zero matches" guard so a
  typo in a curated key list, a missing snapshot file, or a renamed
  type can no longer silent-green.
- **9 version-drift sites resolved through `MacCrabVersion.current`**
  (HIGH × 5 + others) — `BundleExporter.maccrabVersion` (was "1.10.0"),
  `ReplayEngine.engineVersion` (was "1.10.0"), `OtelEncoder` scope
  version (was "1.10.0"), `TraceMaterializer` `daemonVersion` +
  `rulesetVersion` defaults (CLI path baked "1.10.0"), `WebhookOutput`
  / `NotificationIntegrations` / `ThreatIntelFeed` / `ThreatIntelAPIs`
  / `PackageFreshnessChecker` User-Agent strings (drift values from
  `MacCrab/1.0` to `MacCrab/0.5.0`), `AlertExporter` SARIF tool driver
  version (was "1.0.0").

### Functionality wire-the-orphans

- **`alertNotifications` + `minAlertSeverity` Settings now reach the
  daemon** (HIGH) — pre-fix the AppStorage keys wrote nowhere the
  daemon read; the picker silently did nothing. SettingsView now
  writes `<supportDir>/alert_notifications.json` on toggle/picker
  change and SIGHUPs the sysext; `DaemonSetup` reads the file at
  init via `loadAlertNotificationConfig`; the SIGHUP handler calls
  `notifier.setMinimumSeverity(...)` for live reload.
- **MCP `get_events` / V2 alerts pid-0 / phantom subcommand fixes**
  rolled up in the BLOCKERs section above.

### Live data wiring (v1.10.x M2 backlog, partial)

- **V2 collectors workspace** now reads from `heartbeat_rich.json`
  (the System workspace already consumed it) — surface name, status,
  throughput (eventCount / uptime), lag (now − lastTick), lastEvent.
- **V2 permissions workspace** now reads from `tcc_snapshot.json`
  (TCCMonitor already publishes it) — surface service / client /
  granted / required (FDA + ES Client are flagged required).
- **M2 packages + integrations** remain empty — packages needs a
  new `PackageScanner` (brew/npm/pip subprocess); integrations needs
  the `DaemonConfig` integration list exposed via a public read API.
  Both deferred to v1.11.1.

### UX / accessibility

- **V2 Sidebar protection-status accessibility label tracks real state**
  (HIGH) — pre-fix VoiceOver said "active" even when degraded / inactive.
- **V2 KPI card a11y** — value `"—"` previously read as "em dash";
  now reads as "pending".
- **V2 InvestigationWorkspace + AlertsWorkspace RTL fix** —
  `chevron.right` / `arrow.right.circle.fill` switched to `.forward`
  variants so they mirror under Arabic / Hebrew.
- **V2 trace list and detail no longer render misleading "0n / 0e"**
  — gated on `> 0` so rows that haven't been per-trace-loaded omit
  the chip rather than imply zero.
- **V2 campaign card no longer renders "0 entities"** — suffix
  removed entirely (matched data was always 0; real entity counting
  is a future enrichment).
- **L10n** — 14 `Localizable.strings` files updated: stale "348
  detection rules" string replaced with locale-stable "Hundreds of
  detection rules"; orphan `welcome.setup.rulesLoaded` key dropped.
  `SettingsView` "424 rules" hardcode → "hundreds of rules".

### Audit-script hardening

- **`pre-release-audit.sh` Pass 14** — now recognizes both snake_case
  and Sigma CamelCase forms when checking rule references (rules use
  `MachineAgentConfidence`, audit was greppging only for
  `machine_agent_confidence`); broadened producer-side grep to also
  accept SQL-column + Swift-constant patterns. Pruned info-only keys
  (`agent_trace_id`, `agent_span_id`, `agent_tool`) from
  `PASS14_KEYS` — they're analyst context surfaced in TraceStore +
  alert detail, not rule predicates, and don't fit Pass 14's
  contract.

### Misc audit fixes

- **WebhookOutput SSRF** — extended `blockedMetadata` to cover Azure
  IMDSv2 IPv6 brackets, OCI v2 (`192.0.0.192`), IBM Cloud
  (`metadata.softlayer.com`), GCP DNS host, and the all-zeroes
  literals (`0.0.0.0`, `::`).
- **`TrustSubstrateStorage.loadFilesystemPrivateKey`** — `lstat` +
  refuse-on-symlink before `Data(contentsOf:)`, so a symlink in the
  keys dir can't redirect a read.
- **`ThreatIntelFeed` cache dir** — created with explicit `0o700`.
- **`NotificationOutput.swift`** header comment — corrected to
  reflect the `osascript` shell-out implementation (was misleadingly
  claiming `NSUserNotificationCenter`).

### Tests

- **63 new V2 dashboard tests** — V2DeepLink, V2NavigationHistory,
  V2HeartbeatSnapshot, V2DashboardState, V2LiveDataProvider mappers
  (`toV2Alert`, `toV2Trace`). Closes the F46 zero-coverage gap
  flagged in the v1.10.0 RC saga.
- **1404 / 1404 tests pass** in 266 suites (was 1355 / 261 baseline).
- New `MacCrabAppTests` SPM test target alongside `MacCrabCoreTests`.
- **L10n coverage: 100%** across all 14 bundles (was 89% / 377/420
  in 13 non-English bundles).

### Additional fixes folded into v1.11.0

After the first hand-off, every remaining item from the initial
"deferred to v1.11.1" list was reviewed and closed:

#### Schema + data layer

- **AlertStore schema v3 migration** — persists `d3fend_techniques`,
  `remediation_hint`, and `analyst_metadata_json` columns. V2 inspector
  sections survive daemon restart. Pre-v3 alert rows decode safely with
  the new columns NULL.
- **`AlertStore.suppress(campaignId:)`** — single SQL `UPDATE alerts
  SET suppressed = 1 WHERE campaign_id = ?`. Replaces the MCP
  suppress_campaign N-serial-write fan-out (worst case 30 s at 5K
  alerts).
- **`AlertStore.aiAlerts(since:limit:)`** — SQL `rule_id LIKE` prefix
  chain replacing the 8-keyword Swift substring scan over 10K rows.
- **`SQLiteCausalGraphStore.memberCount(traceId:)` + `traceContaining(entityId:)` + `listTraces(limit:status:)` + `huntTraces(query:limit:)`** —
  closes 4 MCP N+1 query patterns. `trace_from_event` drops from
  200 × 2 SQL queries + 200 × M deserializations to 1 SQL union.
- **`TraceStore.insertSpans(_:)`** — batch-insert with single
  BEGIN/COMMIT. OTLP receiver no longer pays N fsyncs per request body.

#### Live data wiring

- **M2 packages** — new `Sources/MacCrabCore/Enrichment/PackageScanner.swift`
  probes `brew list --versions`, `npm ls -g --depth=0 --json`,
  `pip3 list --format=json`. 5-min cache; Intelligence → Package
  Freshness panel populates. Latest-version + vulnCount placeholders
  pending registry HTTP integration (v1.11.x).
- **M2 integrations** — `V2LiveDataProvider.integrations()` reads
  `daemon_config.json.outputs[]`, `notifications.json` webhook URLs,
  and `alert_notifications.json` OS-notification state. Surfaces
  configured Slack / Teams / Discord / PagerDuty / Splunk HEC /
  Elastic Bulk / Datadog / Wazuh / S3 / SFTP / file outputs with
  redacted URLs.

#### Performance

- **MonitorTasks autoreleasepool** — `await Task.yield()` added at the
  end of all 13 secondary `for await` loops (browser ext, USB,
  clipboard, ultrasonic, rootkit, TEMPEST, EDR, DNS, mcp baseline,
  mcp monitor, system policy, event tap, fs events). Matches the
  EventLoop pattern; addresses BLOCKER 2's secondary.
- **`ProcessLineage.drainPendingPromotions()` wired** — called from
  `DaemonTimers.maintenance` every 5 min. Surfaces drain counts so
  PID-recycle storm saturation is observable; persisting drained
  skeletons to `CompactPersistentLineage` is the v1.11.x next step.
- **ISO8601DateFormatter hoisted** — `maccrab-mcp/main.swift` (file-
  scope `let isoFormatter`), `AlertExporter.swift` (`Self.isoFormatter`),
  `V2AlertsWorkspace.swift` (`V2AlertsWorkspace.isoFormatter`).
  Removes ~20 per-call instantiations (~0.5 ms each).
- **`AppState.loadRules` mtime cache** — `(rulesCacheDirPath,
  rulesCacheDirMtime)` short-circuits repeat calls when the
  compiled-rules dir hasn't changed. Repeat `loadRules` from a
  recompile or dashboard reload skips the 427-file decode.
- **`CampaignDetector.recordForStormDetection`** — bounds per-rule
  timestamp arrays inline at 2× `stormCriticalThreshold` instead of
  waiting for the 5-min sweep.

#### Compiler + CLI

- **YAML graph rule compiler** — new
  `Compiler/compile_graph_rules.py`. Reads `Rules/graph/*.yml`,
  validates against the v1.10 schema (node types, edge references,
  severity, required fields), writes canonical JSON siblings. Wired
  into `make compile-rules` step 2. Authors can now write graph
  rules in YAML for readability; JSON remains the daemon-loaded form.
- **`maccrabctl trace replay --compare-rules <a> <b>`** — runs replay
  twice with two ruleset identifiers, diffs the resulting alert
  sets, surfaces only-in-A / only-in-B / common counts plus the
  result_sha256 divergence. Until a real RuleEngine-backed
  `RulesetReplayer` lands (v1.11.x), the echo replayer makes the
  alert diff empty + only result_sha256 differs — infrastructure
  in place for the v1.11.x landing.

#### UX

- **Sidebar visual grouping** — 4 task buckets (Monitor / Investigate
  / Configure / System) with uppercase section labels. Reduces
  visual clutter without restructuring workspaces. The full 9 → 7
  workspace collapse (`plans/2026-05-07-dashboard-overhaul.md`)
  stays as a v1.11.x design proposal.
- **Force-directed TraceGraph canvas** — already shipped in v1.10.0
  as the `.force` layout option in the Investigation workspace's
  toolbar (full Verlet-style simulation with spring + repulsion,
  drag support, hover-highlight). Originally flagged in the audit
  as deferred; on review the capability was already complete.

#### L10n

- **L10n drift cleared** — every non-English bundle now carries the
  full 420-key set. 44 missing keys × 13 languages = 572 entries
  appended with English fallback values + an "awaiting translation"
  banner so future translators can find them. Runtime behaviour
  unchanged (English fallback already worked); the keys are now
  discoverable in the .strings files.

#### Deferred to v1.11.x (intentional)

- **9 → 7 workspace consolidation** — design proposal in
  `plans/2026-05-07-dashboard-overhaul.md`. v1.11.1 ships the
  lighter visual-grouping fix; the structural fold (Events into
  Investigation tabs, Prevention into Detection tabs) ships
  separately after design review.
- **Real RuleEngine-backed `RulesetReplayer`** — `--compare-rules`
  infrastructure is in; the meaningful diff requires hooking
  RuleEngine into RulesetReplayer.
- **PackageScanner registry integration** — latest-version + OSV.dev
  vulnCount lookups (Homebrew API, npm registry, PyPI JSON).
- **`SecurityScorer` dedicated DispatchSource** — flagged but the
  per-tick `timeIntervalSince()` check is essentially free; keeping
  the elapsed-time gate, revisit if profiling ever shows otherwise.
- **`CampaignStore` indexed-column read path** — would require
  changing the `Record` decode contract; defer until a v1.11.x
  store-design pass.

Full audit findings: `plans/2026-05-11-v1.11.0-audit-findings.md`
(gitignored — local file with file:line cites for every BLOCKER /
HIGH / MEDIUM / LOW).
Full notes: `RELEASE_NOTES/v1.11.0.md`.

### v1.11.0 RC2 ship-blocker fixes (operator-relevant)

A second 6-agent audit on the RC1 commit (`75e96c6`) surfaced 5
ship-blockers + 7 HIGHs + 4 MEDIUMs that the v1.11.0 RC1 tag would
have shipped broken. The RC2 commit (`6774fb5`) closes them all
before the v1.11.0 tag landed; ship-readiness checks (DMG sha256 +
codesign + stapler + Gatekeeper notarization) all green.

Behavior-changing RC2 fixes (worth knowing about for upgrade planning):

- **AlertStore schema v4** — adds `campaign_id` column + index.
  Without this the new `suppress(campaignId:)` SQL errored on every
  invocation ("no such column") AND the dashboard's suppress-campaign
  fan-out silently no-op'd because `Alert.campaignId` was never
  restored from disk. The migration is forward-only and idempotent;
  upgrades from v1.10.x / v1.11.0 RC1 run it automatically on first
  boot.
- **alertNotifications config path probe** — the daemon (root,
  reads `/Library/...`) now also probes `/Users/*/Library/...` with
  UID validation, mirroring the `NotificationIntegrations` walker.
  Pre-fix the dashboard's writes never reached the production sysext.
  Mute toggles + severity changes now actually take effect on SIGHUP.
- **Inbox UID gate hardened** — `lstat()` (not `stat()`) + S_IFLNK
  refusal + hardlink (`st_nlink>1`) refusal. Pre-fix an attacker with
  sticky-bit-write access could symlink a request file → root-owned
  file → forge `st_uid=0` → blind the EDR. Inbox audit-log fields
  also sanitize `\n`/`\r`/non-printable bytes to prevent log-line
  forgery.
- **NotificationOutput hard-mute** — `enabled=false` now actually
  mutes (was previously folded into `Severity.critical`, which still
  let critical alerts through).
- **MCP `get_ai_alerts` SQL extended** — adds `rule_title LIKE`
  patterns + `agent_%` / `maccrab.mcp.%` prefixes. Pre-fix the
  v1.11.0 RC1 prefix-only filter missed every YAML-defined AI rule
  (UUID rule_ids don't match prefix LIKE).
- **MCP `get_events` description corrected** — pre-fix it advised a
  `category=network search=:53` pivot for DNS observability that
  returns no rows (DNS lookups aren't stored as events; FTS doesn't
  index port). Now points operators at `get_alerts` + DNS rules.
- **V2 dashboard wire-ups** — Intelligence → Integrations and
  Intelligence → Package Freshness panels now consume
  `state.provider.integrations()` / `.packages()`. Pre-fix RC1
  shipped the data layer but the panels were placeholders / unwired.
- **`syncAlertNotificationConfig` debounced 500 ms** — rapid
  Picker scrolls used to fire one SIGHUP per onChange (DoS surface
  via the daemon's expensive retroactive scan).
- **`V2LiveDataProvider.permissions()` + `.integrations()` detached
  off `@MainActor`** — pre-fix sync file I/O on the main queue
  produced 1-3ms jitter per dashboard refresh tick.
- **`V2LiveDataProvider.suppressCampaign` uses single-SQL fan-out**
  — adopts the same `AlertStore.suppress(campaignId:)` rewrite as
  the MCP path; no more 30s wedge under storm.
- **`ThreatIntelFeed` cache dir** explicit `chmod 0o700` on
  EXISTING dirs (createDirectory's `attributes:` parameter doesn't
  chmod existing — RC2 adds the explicit setAttributes after).
- **Sidebar group headers localized** ("Investigate" / "Configure"
  / "System") via `String(localized:)` keys added to all 14
  `.strings` bundles.
- **`maccrabctl --help`** master block now lists `--compare-rules
  <a> <b>`.
- **`docs/TRUST.md`** sample DMG filenames bumped to v1.11.0.
- **`build-release.sh`** rule count excludes `manifest.json` (was
  miscounting build-time metadata as a rule, producing
  `release.json: "rules": 428` when the actual count is 427).

The full RC1 → RC2 fix wave commit is `6774fb5` (30 files,
+463 / −93). 1404 / 1404 tests still pass; both prerelease scripts
green; DMG sha256 matches release.json after re-build.

## [1.10.1] — 2026-05-11

Hotfix release. Dashboard suppress / unsuppress / delete actions and
campaign suppress all silently failed on every notarized release install
since v1.3 because the System Extension owns alerts.db as root and the
dashboard runs as the user — the direct SQLite writes hit
`SQLITE_READONLY`. The error toast pointed at `maccrabctl alerts
suppress <id>` and `sudo open MacCrab.app`, neither of which works.

Fix: route mutations through the existing
`/Library/Application Support/MacCrab/inbox/` file-IPC channel that v1.10
introduced for the "Reduce events.db now" button. The sysext poller now
recognizes `suppress-alert-*.json`, `unsuppress-alert-*.json`,
`delete-alert-*.json`, and `suppress-campaign-*.json` request files
(JSON `{"id":"<uuid>"}` payloads). Poll interval drops 30 s → 5 s so
suppress clicks feel interactive. The campaign-suppress fan-out moves
server-side — one inbox file per campaign instead of N.

Also: auto-generates the README rule-count table from the YAML tree
(`make readme-coverage`, wired into `release.sh` step 2b) so README
never ships stale tactic counts; ships `RELEASE_PROCESS.md` documenting
the operator-side signing / notarization / Sparkle appcast pipeline;
fixes `Package.swift` tail comment to reflect the xcodegen-based build
model; credits AgentSight (arXiv:2508.02736) in README acknowledgments.

Full notes: `RELEASE_NOTES/v1.10.1.md`.

## [1.10.0] — 2026-05-10

The dashboard-rewrite release. Replaces the v1 SwiftUI dashboard with
a workspace-based V2 design (Overview / Alerts / Investigation /
Intelligence / Protection / System), adds a real visual TraceGraph,
and ships causal trace analysis end-to-end. Bundles `maccrabctl` and
`maccrab-mcp` inside `MacCrab.app` so Sparkle in-place updates keep
the terminal CLI current. Includes a 280+ finding pre-ship audit-fix
pass across security, performance, scalability, localization, and
daemon correctness. Full notes: `RELEASE_NOTES/v1.10.0.md`.

### Added
- **V2 dashboard** — six workspaces with tab strips, multi-select
  alert triage, bulk-suppress, campaign suppress, suppression viewer
  with lift-suppression, threat-intel feed refresh button, custom
  feeds + LLM key reveal-folder shortcuts, package inspector,
  prevention live data, "Create rule" wizard.
- **Visual TraceGraph view** — hub-and-spoke layout with the trace
  anchor at centre, members radiating on concentric rings, edges
  drawn from anchor, hover-to-highlight, two-ring overflow at >12
  members, Graph/List toggle for accessibility.
- **`tracegraph.db`** — new SQLite causal-graph store (entities,
  edges, trace memberships) with the same column-level AES-GCM
  encryption + chmod-0o660 + auto-vacuum=incremental as the other
  stores.
- **5 new MCP trace tools**: `get_traces`, `get_trace_detail`,
  `hunt_trace`, `verify_bundle`, `trace_from_event`.
- **Bundled CLI** — `maccrabctl` and `maccrab-mcp` ship inside
  `MacCrab.app/Contents/Resources/bin/`. Both Cask postflight and
  `install.sh` symlink the brew-bin entries to the in-app paths so
  Sparkle in-place updates keep the terminal CLIs in sync without
  requiring `brew upgrade maccrab`.
- **Trace bundle export/verify** — `.maccrabtrace` signed bundles via
  the new `maccrabctl trace export` / `verify` subcommands; the V2
  Investigation workspace exposes both.

### Changed
- **Cask uninstall** now runs `systemextensionsctl uninstall` as an
  `early_script` (`must_succeed: false`) so sysextd's ledger is
  cleared before the .app is removed — eliminates the "pending"
  entry that lingered post-uninstall pre-fix.
- **`scripts/install.sh`** moved app-install to step 3, CLI symlinks
  to step 4 — the symlinks now resolve into the just-installed
  bundle. Apple Silicon detection auto-replaces stale brew-cask
  symlinks (which pointed at v1.8 binaries inside the Caskroom).
- **`scripts/uninstall.sh`** rewritten for the v1.3+ sysext model:
  deactivates via `OSSystemExtensionRequest`, kills app + agent,
  cleans both `/usr/local/bin/` and `/opt/homebrew/bin/`, optional
  data-dir + Keychain wipe with safe-by-default prompts.
- **`Localizable.stringsdict`** — 8 plural rules
  (alerts.suppressedCount, alerts.unsuppressedCount,
  overview.eventsRate, overview.high.count, overview.critical.count,
  generic.{campaign,rule,item}.count) so counts pluralise correctly
  in CLDR-compliant locales.

### Fixed
- **`scripts/prerelease-check.sh`** lines 68 / 78: `grep -c | echo 0`
  produced a two-line `"0\n0"` value when grep found zero matches.
  Bash's `[[ -lt ]]` couldn't parse it, fell through to the `else
  ok` branch, and silently shipped stale project.yml versions.
  Replaced with `cmd || VAR=0` form.
- **`Casks/maccrab.rb`** postflight: `binary` stanza created a
  symlink at `$HOMEBREW_PREFIX/bin/maccrabctl` pointing into the
  caskroom's version-pinned copy. After a Sparkle in-place update,
  the symlink kept resolving to the old CLI. Postflight now replaces
  the symlink with one pointing at the in-app CLI, which Sparkle
  DOES update atomically.
- **AlertStore phantom fields** — V2 dashboard's "What to do" hint,
  D3FEND chips, and analyst pills all use `if let / !isEmpty`
  guards so unpersisted optional fields don't render empty pills.
  Real schema migration to persist them is a v1.11 follow-up.
- 280+ findings from the pre-ship audit waves (security, perf,
  L10n, a11y, daemon correctness). Highlights: TLS 1.2 floor on all
  outbound HTTP, SPKI pinning available for cloud LLM endpoints,
  sanitizer extended to OCSF/syslog/SFTP sinks, TraceMaterializer
  guards against missing entities, post-migration integrity_check
  per store, atomic heartbeat writes, retention enforcement actually
  deletes (not just marks), storage cap high-water alert, LLMService
  priority queue.

## [1.9.0] — 2026-05-06

The Agent Traces release. W3C TRACEPARENT correlation between AI
coding-agent activity and macOS kernel events, plus a sustained
audit-fix pass: dynamic version sourcing, sysext deactivate state
machine, span-identity sanitisation, per-store dashboard cache TTLs,
threat-intel multi-tenant suffix guard, "awaiting daemon" timeout, and
a deeper pre-release audit pipeline. Full notes: `RELEASE_NOTES/v1.9.0.md`.

### Added
- Loopback OTLP/HTTP receiver on `127.0.0.1:4318` with body-cap +
  slow-loris deadline + connection-count cap. Default-off.
- `traces.db` SQLite store with column-level AES-GCM encryption on
  `attributes_json`, sharing the keychain key with `events.db` /
  `alerts.db`.
- Agent Traces dashboard panel: trace list, span hierarchy with
  parent-depth indent, pretty-printed attributes JSON, in-panel
  receiver toggle with status pill (running / stopped / awaiting /
  failed), reattribute thumbs UI, and "Show in Agent Traces"
  cross-link from alert detail.
- Three new `ai_safety` rules: agent filesystem-violation (high-conf +
  probable) and agent TRACEPARENT credential-access.
- `Settings → Manual event prune`: SIGUSR2-driven on-demand events.db
  size-cap sweep, complementing the hourly enforcer.
- `Settings → System Extension`: clean removal via
  `OSSystemExtensionRequest.deactivationRequest`, no SIP-disable
  required, with a confirmation sheet so misclicks don't unregister
  a working sysext.
- `Sources/MacCrabCore/MacCrabVersion.swift` — single source of
  truth for runtime version strings. Replaces four hardcoded
  literals across StartupBanner, DaemonBootstrap, maccrabctl,
  OTLPOutput.
- `pre-release-audit.sh` Pass 12-15 — traces.db single-opener,
  env-block secret-leak prevention, enrichment-key↔enricher coverage,
  TraceStore + DatabaseEncryption pairing.

### Changed
- Database column-level encryption is now ON by default for the
  daemon. The `MACCRAB_ENCRYPT_DB=0` escape hatch remains for tests.
- OTLP outbound `service.version` and User-Agent now read
  `MacCrabVersion.current` instead of the v1.8.0 hardcoded literal.
- Threat intel: explicit multi-tenant platform suffix guard
  (`pages.dev`, `vercel.app`, `firebaseapp.com`, etc.) so a single
  malicious URL doesn't blanket-flag the host. Anchored URL match
  (exact OR `hasPrefix`). Optional `MACCRAB_ABUSECH_AUTH_KEY` env
  raises feed rate-limit ceiling.
- AppState dashboard cache: per-store mtime TTLs so a probe of one
  DB no longer suppresses the others' freshness check for 30 s.
- Span identity fields (`service.name`, `span.name`,
  `gen_ai.provider.name`, `gen_ai.system`) now pass through the
  attribute sanitiser before persistence — matches the wire-boundary
  sanitisation guarantee for `attributes_json`.
- `traceStoreOrNil()` picks the dir with the freshest `traces.db`
  mtime instead of the first readable one — consistent with the
  eventStore / alertStore probe.
- `OTLPReceiver`: 64-connection concurrent cap; new connections past
  the cap close immediately with HTTP 503.
- `ConnectionBuffer` deinit defensively cancels its slow-loris timer
  to satisfy `DispatchSourceTimer.cancel()`-before-dealloc invariant.
- Sanitiser entropy fallback no longer splits on `/`, so URL paths
  and absolute filesystem paths with high-entropy session IDs aren't
  over-redacted.
- `SignalHandlers` SIGUSR2: `enforceDatabaseSizeCapNow` now reports
  whether the prune ran or was skipped (reentrancy); the status
  snapshot is written only on a real run.
- `AppState.requestStorageFlush` safety auto-clear extended from
  90 s → 180 s (multi-GB DBs on slow disks can outrun the prior
  window).
- Dashboard "Awaiting daemon" pill now flips to a red "Daemon not
  responding" state after 30 s with a hover-help describing the
  recovery steps (start the daemon / re-activate the sysext).
- AI Activity timeline session label uses ICU pluralisation via
  `String(localized:defaultValue:)` instead of manual `s.count == 1
  ? "" : "s"`.

### Fixed
- `Xcode/project.yml` CFBundleVersion / CFBundleShortVersionString
  bumped to 1.9.0 (was 1.7.5; would have shipped a stale Info.plist
  on the next xcodegen).
- `DaemonBootstrap.writeStartupMarker` no longer hardcodes
  `version: "1.7.12"`. Reads `MacCrabVersion.current`.
- `maccrabctl --version` reports the current build (was `v1.5.1`).
- StartupBanner version-line padding now computes against the actual
  cell width (42 chars), so the closing `║` doesn't shift on launch
  regardless of the version-string length.
- `SystemExtensionManager` deactivation result now maps to
  `.notActivated` instead of `.activated` — the badge no longer says
  "Active" right after the user removes the extension.
- `SettingsView` sysext failed-state badge gains a `.help(...)`
  tooltip with the full error string (the truncated visible label
  is now informative, not opaque).
- Storage-flush row shows "Last run: never" on first install instead
  of an empty caption.
- `pre-release-audit.sh` Pass 15 grep no longer matches zero call
  sites: rewritten to use a 5-line awk window so multi-line
  `TraceStore(directory: …, encryption: …)` constructions are seen.
- README.md tests-passing badge bumped to 1106; version badge bumped
  to 1.9.0. `release.json` test count corrected to 1106.
- `docs/AGENT_TRACES.md` enabling section updated — receiver now
  starts from the dashboard toggle in v1.9.0, not "v1.9.1+".
- `CLAUDE.md` rule count line now says 389 single-event + 38 sequence
  rules (was the v1.5-era "382").

## [1.8.1] — 2026-05-04

External-review-driven trust hardening. AES-GCM authenticated DB
encryption, shared keychain access group between .app and sysext, four
new trust/threat-model/response-safety/coverage docs, and website
auto-fetch of release metadata. Full notes: `RELEASE_NOTES/v1.8.1.md`.

### Added
- `docs/TRUST.md`, `docs/THREAT_MODEL.md`, `docs/RESPONSE_SAFETY.md`,
  `docs/MODULES.md`, `docs/COVERAGE.md` — full trust-surface docs.
- `Sources/MacCrabCore/ModuleStatus.swift` — 41-entry stable /
  experimental / opt-in catalog.
- `scripts/build-release.sh` writes `release.json`;
  `scripts/publish-release-json.sh` ships it to maccrab-site.
- Site `index.html` auto-fetches `release.json` for version + rules +
  tests display — eliminates manual version drift.
- `make coverage-doc` regenerates rule-to-ATT&CK coverage matrix.

### Changed
- AES-CBC + PKCS7 → AES-GCM (authenticated). New writes use `ENC2:`
  prefix; legacy `ENC:` decrypt still works.
- SecretsStore + DatabaseEncryption keychain items now use shared
  access group `79S425CW99.com.maccrab.shared` so the sysext can read
  what the dashboard wrote. Self-healing migration on first read.
- README + maccrab.com lede: "open, local-first detection and
  investigation for developers, researchers, and Mac security
  practitioners." No more "EDR replacement" framing.

### Fixed
- Overview Security grade hover popover dismissed when cursor crossed
  into the popover. Dual-hover tracking with 250ms grace period now
  keeps it open while either trigger or content is hovered.

## [1.8.0] — 2026-05-04

Per-tier storage redesign, OpenTelemetry export, dashboard polish.
Full notes: `RELEASE_NOTES.md`.

### Added
- Per-tier storage budgets — events / alerts / campaigns with independent
  retention + size caps. Heavy event volume can no longer evict alert or
  campaign history.
- Three new ai_safety rules: SKILL.md poisoning install, Claude Code
  project-config RCE (CVE-2025-59536), agent dotfile persistence.
- OpenTelemetry Protocol (OTLP) HTTP/JSON output sink.
- Activity timeline on Overview tab with severity-stacked bars + campaign
  markers; SQL-side event histogram with hover tooltips and variable
  granularity; Security grade hover popover with point breakdown.
- AI Guard timeline search, CSV/JSON export, scroll container, spawn
  cluster rollup.
- Keyset pagination + database-side search across Alerts and Events.
- `maccrabctl rollup` command + `make breakdown` diagnostic.

### Changed
- AlertStore moved from `events.db` to its own `alerts.db`. One-shot
  startup migration; idempotent on re-run.
- Notification severity default lowered from "medium" to "critical" for
  fresh installs. Existing preferences preserved.
- Event hot-tier default 30 minutes (slider 15 min – 24 h, floor 15 min).
- Alert-evidence capture bounded: ±30 s window, 50 rows per alert,
  severity-prioritized.
- MCP tool limits aligned with declared schema (max 100).

### Fixed
- TLS floor + scheme validation on `StreamOutput` / `S3Output` outputs.
- SSRF policy applied to Slack / Teams / Discord / PagerDuty webhooks.
- Database encryption key + secrets store pinned to
  `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.
- `runScript` response action enforces root-owned allowlisted script
  paths (local privilege-escalation fix).
- Bulk-suppress crash from `%@` / `%lld` format mismatch in
  Localizable.strings.

### Removed
- Two long-deprecated rules: `invisible_unicode_in_source.yml`,
  `trojan_source_bidi_code.yml`.

### Migration
- Legacy `retentionDays` / `maxDatabaseSizeMB` config keys still parsed
  and folded onto the new `storage` block automatically.
- No reboot or extension re-approval required.

## [1.7.12] — 2026-04-30

Resolves [#1](https://github.com/peterhanily/maccrab/issues/1) reported by
[@jjdresselhaus](https://github.com/jjdresselhaus) — thank you for the
field reproduction. After uninstalling MacCrab via
`brew uninstall --cask maccrab`, the launch-at-login LaunchAgent
persisted under `~/Library/LaunchAgents/`, causing launchd to retry a
missing binary on every subsequent login.

### Fixed — defensive LaunchAgent file sweep on launch-at-login disable

`Sources/MacCrabApp/LaunchAtLogin.swift` now sweeps both possible
`~/Library/LaunchAgents/` paths after `SMAppService.mainApp.unregister()`:
- `com.maccrab.app.plist` (legacy SMAppService write path)
- `79S425CW99.com.maccrab.app.plist` (modern team-id-prefixed path that
  most macOS 13+ systems actually create)

`SMAppService.unregister()` removes the registration from the system
database but on some macOS versions doesn't delete the underlying
`.plist` file. Without the explicit sweep, the file persisted across
toggle-off, app deletion, and `brew uninstall`. v1.7.12 catches all
three paths (toggle-off, startup self-heal when preference is
disabled, and via the cask uninstall stanza shipped on April 30 in
the v1.7.11 cask-only patch).

### Added — startup self-heal

`LaunchAtLogin.reconcile(preferenceEnabled:)` (called once at app
startup from `MacCrabApp.swift`) now sweeps stale `.plist` files when
the preference is disabled and the API status agrees. Previously this
was a no-op when both said "disabled" — but the file could still be
on disk if something orphaned it. Belt-and-suspenders.

### Cask side (already shipped April 30, no version bump there)

The cask's `uninstall` stanza was patched on April 30 (commits
`30974a2` + `6f585b2`, both pure formula changes — no DMG rebuild)
to also handle the user-context LaunchAgent. The two changes
together close the bug class from both directions: app-side cleanup
when the user disables launch-at-login through Settings, plus
cask-side cleanup when the user runs `brew uninstall` while still
having launch-at-login enabled.

### Compatibility

Patch-only. Daemon code unchanged from v1.7.11. No data migration.
No reboot or extension re-approval required. Existing installs that
previously had launch-at-login enabled get the stale `.plist` swept
on first launch of v1.7.12 (via the new `reconcile()` self-heal path).

## [1.7.11] — 2026-04-30

Dashboard memory hot-fix. Field-reproduced: parking the dashboard on
the Events tab grew daemon-process retained memory ~1.5 GB/day via
1+ million NSLayoutConstraint + NSISRestrictedToZeroMarkerVariable
allocations. **Different process, different bug class** from the
v1.7.6-v1.7.10 daemon-side leaks — this one is in the SwiftUI app
target, retained (not autoreleased), driven by NSTableView
constraint inflation.

### Fixed — `EventStream` memoizes its filtered list

`Sources/MacCrabApp/Views/EventStream.swift`: replaced the computed
`filteredEvents` and `timeFilteredEvents` properties with a `@State`
cache that recomputes only when an actual input changes (the events
list, filter category, filter text, time range, sort order). The
body reads the cache directly. Previously the body re-filtered AND
re-sorted the entire `appState.events` list on every body
re-evaluation, AND read `timeFilteredEvents` twice per body call
(count badge + Table data) — so each unrelated `@Published` mutation
in AppState (heartbeat, agentLineage, mcpBaselines, etc.) drove a
double recomputation followed by a fresh `Table` rebind. Each
rebind inflated Auto Layout constraints in NSTableView's solver
that aren't released until the view is dismantled. Field-reproduced
rate: ~333 constraints/sec.

### Fixed — `AppState.refresh()` no-op `@Published` writes

Three high-frequency refresh functions (`refreshHeartbeat`,
`refreshStorageHealth`, `refreshRuleTamper`) re-read their backing
JSON file every poll and unconditionally re-published their snapshot,
even when neither the file nor the parsed value had changed. Each
unconditional write fired SwiftUI body re-evaluations across every
view bound to AppState. v1.7.11 adds mtime short-circuit guards
mirroring the existing pattern in `refreshAgentLineage`,
`refreshMCPBaselines`, and `refreshTCCSnapshot`. The functions now
skip the parse + assignment entirely when the file hasn't been
re-written since the last successful refresh.

### Fixed — equality-checked `@Published` Bool writes in `refresh()`

`isConnected`, `appHasFDA`, `sysextHasFDA`, and `fullDiskAccessGranted`
change at most once per session in normal operation (daemon up/down,
FDA grant/revoke). Pre-fix the unconditional assignment at every
poll fired `@Published` regardless. Now wrapped:
`if x != newValue { x = newValue }`. Reduces SwiftUI body re-eval
pressure across every view, not just Events.

### Added — Pass 9 extended to scan `Sources/MacCrabApp/`

`scripts/pre-release-audit.sh` Pass 9's directory list now includes
the dashboard target. The current leak shape (constraint retention)
isn't catchable by the existing `while-let / for-await + autoreleasing
Foundation API` regex, but extending the directory list:
- Catches future polling-path code that lands in a streaming-loop
  shape with autoreleasing Foundation calls
- Forces future authors to think about Foundation pool drainage when
  adding to MacCrabApp's hot paths

### Compatibility

Dashboard target only. Daemon code unchanged from v1.7.10. No data
migration. No reboot or extension re-approval required.

### Expected steady-state

For a dashboard parked on the Events tab:
- `NSLayoutConstraint` count: **stable around 5-15K** (normal
  SwiftUI layout churn), instead of climbing at ~333/sec
- Daemon-process RSS: **~120-250 MB**, stable indefinitely
- 24-hour soak should add < 50 MB of resident memory, vs the ~1.5 GB
  growth seen on v1.7.10

## [1.7.10] — 2026-04-29

UX hot-fix on top of v1.7.9: the Settings → About tab version label
read "v1.3.4" — hardcoded ~20 releases ago and never updated.

### Fixed — About page version label dynamic

`Sources/MacCrabApp/Views/SettingsView.swift`: replaced the hardcoded
`Text("v1.3.4")` with `Text(verbatim: "v\(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "?")")`.
Now tracks `Info.plist` automatically — every future release is
correctly self-reported in the About panel without a manual edit.

The adjacent stats line ("7 event sources | 8 detection layers | 304
rules") was also updated to current values: 19 event sources | 5
detection layers | 424 rules. Still hardcoded (these counts only
change when the architecture changes), but at least current.

### v1.7.9 release rollout

v1.7.9 was published to GitHub but its Sparkle appcast and Homebrew
tap were intentionally held pending verification of the memory fix
on a second test machine. Verification confirmed the fix; v1.7.10
bundles the About-page fix and rolls v1.7.9's content out to all
channels in one shipping action.

## [1.7.9] — 2026-04-29

Memory hot-fix (round 2) + 3 new detection rules + observability +
audit codification + UX cleanup. Bigger than a typical patch but
targeted: every change is patch-scope (no new architecture, no new
training data, no design redesign).

### Fixed — autorelease pool drain extended to OUTER collector loops

v1.7.7 wrapped the inner per-LINE body of `EsloggerCollector` and
`UnifiedLogCollector` in `autoreleasepool`, draining JSON-parser
temporaries. v1.7.8 field reproduction on a different machine
showed 2.07 GB private heap dominated by **135,689 × 16 KB
NSConcreteData buffers** — the per-CHUNK `fileHandle.availableData`
return value was still autoreleased and accumulating in the OUTER
loop's pool. v1.7.7's fix was incomplete.

v1.7.9 wraps the OUTER `while true` body so the chunk Data drains
every iteration. Inner pool retained as belt-and-suspenders for
peak memory on chunks containing many lines. Same pattern applied
to `KdebugCollector` (caught by the new Pass 9 audit) and
`FileHasher.computeSHA256` (file-hash chunked reads via
`handle.read(upToCount:)` — likely the dominant leak source on
the field machine, called from per-file-event IOC matching).

### Added — Pass 9 + Pass 10 audits

`scripts/pre-release-audit.sh`:
- **Pass 9**: autoreleasing Foundation calls (`JSONSerialization`,
  `NSRegularExpression`, `DateFormatter`, `ISO8601DateFormatter`,
  `fileHandle.availableData`, `fileHandle.readDataOfLength`,
  `handle.read(upToCount:)`, `Data(contentsOf:)`) inside `while
  true`/`while let`/`for await` bodies without a surrounding
  `autoreleasepool` block fail the audit. Found 2 sites the v1.7.7
  fix had missed (`KdebugCollector.swift`, `FileHasher.swift`).
- **Pass 10**: when ≥ 2 stores share a `.db` file, each store's
  migrations must be runnable independent of the global
  `user_version` counter — verified via `SchemaMigrator.run()` call
  + no direct `PRAGMA user_version` manipulation. Codifies the
  v1.7.6 SchemaMigrator multi-store fix.

### Fixed — heartbeat per-collector counters

`event_count: 0` for every primary collector while
`events_processed: 1M+` was a broken telemetry signal: pre-fix,
only secondary collectors with their own MonitorTask `for await`
loop (TCC, USB, Clipboard, etc.) called `recordTick`. Primary
collectors (ESCollector, NetworkCollector, DNSCollector,
UnifiedLogCollector) feed the merged stream consumed by EventLoop
which lacked source attribution. Now EventLoop attributes each
event to a representative primary collector by `event_category`
and increments its tick. Operators can finally trust the
per-collector health flag.

### Added — three new detection rules

- `Rules/persistence/xpc_service_replacement.yml` — writes to
  `/Library/LaunchDaemons/*.plist` or `/Library/LaunchAgents/*.plist`
  by unsigned/ad-hoc-signed processes. Severity: **high**. T1543.004.
- `Rules/defense_evasion/network_extension_unsigned.yml` — unsigned
  `NEPacketTunnelProvider` / `NEDNSProxyProvider` /
  `NEAppProxyProvider` / `NEFilterDataProvider` installs. These
  providers can intercept every packet leaving the device.
  Severity: **critical**. T1556.
- `Rules/credential_access/crypto_wallet_data_access.yml` — reads
  of native cryptocurrency wallet directories (Electrum, Exodus,
  Atomic, Coinomi, Daedalus, Trezor Suite, Ledger Live) AND
  browser-extension wallet storage (MetaMask, Phantom, Coinbase,
  Trust Wallet, Binance Chain) by anything other than the wallet
  app or browser itself. Targets Atomic Stealer (AMOS), Banshee,
  similar macOS infostealers. Severity: **critical**. T1555.

The `c2_beacon_pattern.yml` timing-variance rewrite was descoped —
Sigma sequence engine doesn't support "step A repeated N times in
a window" (only "step A then step B"). Substituted with the
crypto-wallet rule which fills a real coverage gap.

### Added — `maccrabctl repair --fix-storage` schema check

`PRAGMA integrity_check` passes for the v1.7.5 → v1.7.6 bug shape
(alerts table missing `llm_investigation_json` column from a
silently-skipped migration) — the file is valid SQLite, just
schema-stale. v1.7.9 adds a `PRAGMA table_info(alerts)` column-
presence sanity check that fingerprints the v1.7.5 bug shape and
recommends installing v1.7.6+ instead of a destructive backup.

### Added — `ESCollector` defensive autoreleasepool

The per-event ES kernel callback isn't a `while let`/`for await`
shape so Pass 9 doesn't flag it, but the same Foundation autorelease
accumulation that bit Eslogger/UnifiedLog could happen here too.
Wrapped defensively to keep the discipline holding across collectors.

### Added — brew ↔ Sparkle drift detection

`MacCrabApp.isBrewInstalled` checks `Bundle.main.bundleURL.path` for
`/Caskroom/`. When true:
- `SPUStandardUpdaterController` initialised with `startingUpdater:
  false` and `automaticallyChecksForUpdates = false`
- Settings → AI Backend (next to "Check for Updates") shows a
  caption: "Installed via Homebrew. Background auto-update is off;
  upgrade with `brew upgrade --cask maccrab`. Manual checks above
  still work."

Stops the v1.6.13 → v1.7.5 channel-drift incident from recurring:
without this, Sparkle silently bumps the .app to v1.7.x while brew
still thinks it owns v1.6.x, then `brew upgrade` overwrites the
newer Sparkle binary with the older brew-formula one.

### Changed — metrics export format (schema 2)

`/var/tmp/maccrab.metrics.json`:
- Added `resident_memory_mb` (via `mach_task_basic_info`, no sudo
  required) — continuous RSS visibility so the next leak shape is
  caught at 100 MB rather than 1+ GB
- Added `events_dropped_total` and `events_per_sec_lifetime`
- Schema bumped 1 → 2

### Removed — zombie-sysext banner

The reboot-recommendation banner (introduced v1.7.5, restyled
v1.7.8) is gone. Showed every dashboard launch on installs with
leftover sysexts queued for uninstall, with no productive action
available from the dashboard. The diagnostic + recommendation
already lives in `maccrabctl repair`, which is the right surface.

Removed: the `.safeAreaInset(.top)` banner block in `MainView.swift`,
the `@AppStorage("dismissedZombieSysextCount")` declaration, the
`AppState.zombieSysextCount` published property, the
`refreshZombieSysextCount()` method, and the per-poll-cycle call.
Net deletion: ~50 lines.

### Changed — sidebar layout (Mail.app pattern)

v1.7.8's column-width-constraint + `.balanced` style still showed
the sidebar visibly narrowing on resize before snapping. The
cleaner UX, matching Mail.app and Calendar.app: enforce a generous
window minimum so the user simply can't drag the window into the
awkward state.

`MainView.swift`:
- `.navigationSplitViewStyle(.prominentDetail)` (replaces `.balanced`)
- `.frame(minWidth: 1100, minHeight: 600)` (up from 950)
- Removed `.navigationSplitViewColumnWidth(min: 200, ideal: 220,
  max: 280)` — let the system pick the sidebar default at the
  now-guaranteed comfortable window width

### Compatibility

No data migration. Existing v1.7.8 installs upgrade in place via
manual download, `brew upgrade --cask maccrab`, or Sparkle when
that channel is published. No reboot or extension re-approval
required.

Tests: 929/929 passing. Pre-release audit: 10/10 passes green.

## [1.7.8] — 2026-04-29

Dashboard UX hot-fix: zombie-sysext banner styling + sidebar layout.

### Fixed — zombie-sysext banner now opaque + dismissible

The reboot-recommendation banner (added v1.7.5, shown when 3+ prior
sysexts are queued for uninstall) used `Color.orange.opacity(0.12)`
as its background — translucent enough that the underlying content
showed through, and on tall windows it visually overlapped the
daemon-disconnect banner stacked above it. It also had no way to
dismiss.

Fix in `Sources/MacCrabApp/Views/MainView.swift`:
- Background: `.regularMaterial` (opaque, system-blur appearance)
- Visual cue: a 3-pt orange leading edge stripe instead of full-tint
- Dismiss: `xmark.circle.fill` button on the right, persisted via
  `@AppStorage("dismissedZombieSysextCount")`. Hides the banner once
  the user has acknowledged the count, but **re-appears** if a future
  upgrade adds MORE zombies (because the comparison is `current >
  dismissed`, not equality).

### Fixed — sidebar no longer overlays content on narrow windows

`NavigationSplitView`'s default `.automatic` style collapses the
sidebar into an overlay (sliding over the detail content) once the
window narrows past a threshold. Combined with no width constraint
on the sidebar column, this caused the sidebar to obscure detail
content during normal window-resizing rather than letting the detail
area scroll.

Fix:
- `.navigationSplitViewColumnWidth(min: 200, ideal: 220, max: 280)`
  on the sidebar column constrains its width range
- `.navigationSplitViewStyle(.balanced)` keeps both columns visible
  side-by-side; sidebar collapses only when explicitly toggled via
  the toolbar, never as a side-effect of window resize

### Compatibility

UX-only. No data migration. Same install path as v1.7.7.

## [1.7.7] — 2026-04-29

Memory hot-fix: 1.31 GB private heap → bounded steady state. Field-reproduced
on a v1.7.6 install where the daemon climbed from 50 MB → 1.52 GB RSS over
~1 hour at 197 events/sec sustained. Heap dump pinpointed 2.34M each of
`NSDictionary` / `NSError` / `_NSJSONReader` (1:1:1 ratio = one matched
triplet per parse) and 692 MB of `NSConcreteData` buffers — Foundation
objects autoreleased by `JSONSerialization.jsonObject(with:)` accumulating
in the autorelease pool of long-running async Tasks that never drain.

### Fixed — autorelease pool drained per event in collector hot loops

`EsloggerCollector.readLoop` and `UnifiedLogCollector` both stream NDJSON
through `JSONSerialization.jsonObject(with:)` per line, in `while` loops
that run for the lifetime of the daemon. Swift async Tasks don't carry
an implicit `@autoreleasepool` — Foundation autoreleased objects (the
parser's `NSDictionary`, `NSError`, `_NSJSONReader`, plus the input
`NSConcreteData` buffer for each chunk) accumulate until the Task ends,
which for these collectors is "never".

Fix: wrap each per-line iteration body in `autoreleasepool { ... }`.
The inner `continuation.yield` is synchronous (AsyncStream.yield doesn't
suspend), so the pool unwinds cleanly per event with zero behavior change.

Cost: one autoreleasepool entry/exit per event (~nanoseconds).
Benefit: at the field-reproduction rate (197 events/sec, 75% file events
streamed through these collectors), this prevents the ~1 GB/hour Swift
heap growth that v1.7.6 exposed.

The leak was masked in v1.7.5 because the daemon was crash-looping in
storage init (the SchemaMigrator bug that v1.7.6 fixed). With v1.7.6
keeping the daemon alive, both collector loops finally ran long enough
to reveal the autorelease accumulation. So v1.7.7 doesn't introduce a
new fix — it surfaces and patches a latent bug that pre-dates v1.7.0.

### Compatibility

No data migration. Existing v1.7.6 installs upgrade in place via Sparkle
or `brew upgrade --cask maccrab`. The new daemon takes over from sysextd
on next launch with bounded heap behaviour from the first event onwards.

No reboot or extension re-approval required.

## [1.7.6] — 2026-04-28

Hot-fix for a v1.7.5 daemon-init crash-loop reproduced in the field.
Root cause: a long-standing `SchemaMigrator` bug where co-resident
stores sharing a single SQLite file silently skipped each other's
migrations. Surfaced now because both EventStore and AlertStore hit
version 2 in this release. Field DB had `events` table fully migrated
but no `alerts.llm_investigation_json` column → AlertStore prepare
crashed on every boot, daemon exited in 127 ms, launchd respawned
every 10 s, dashboard showed "Detection engine appears silent".

### Fixed — SchemaMigrator multi-store user_version skip (the actual bug)

`PRAGMA user_version` is a single per-database counter, but EventStore
and AlertStore both run their own migration chains against `events.db`.
Pre-fix logic (`pending = migrations.filter { $0.version > current }`)
meant whichever store opened first set the counter, and the second
store's `pending` was empty even though its `ADD COLUMN` migration had
never run.

Fix in `Sources/MacCrabCore/Storage/SchemaMigrator.swift`: always
re-apply this store's migrations idempotently, in version order.
Bump `user_version` only on a forward step (`m.version > current`);
never lower the counter. Broadened `apply()`'s already-applied
detector from `duplicate column name` only to also include
`already exists` for `CREATE TABLE` / `CREATE INDEX` re-runs.

Cost: a few cheap fail-fast SQLite calls per store init. Benefit:
the second store's schema actually gets applied on existing DBs
that pre-date the new migration, with **no data loss** — events
and alerts history is preserved (probe-verified: 448 events + 182
alerts retained on the field-broken DB).

New regression test `Co-resident store: second store's migrations
apply when counter is at-or-ahead` in `SchemaMigratorTests.swift`
reproduces the exact two-store sequence that was failing in prod.

### Added — visible storage-init errors (defense in depth)

`DaemonSetup.swift` logs storage-init failures with `.public` privacy
so console diagnostics surface the actual SQLite error instead of
`<private>`. Pre-v1.7.6 logs read `Failed to initialize storage: <private>`,
leaving operators no way to diagnose without entitled `private_data:on`
log profile (which SIP-protected machines reject).

### Added — auto-recovery on storage-init failure

`DaemonSetup.recoverEventStore` / `recoverAlertStore`: on init
exception, back up `events.db{,-wal,-shm}` to a timestamped sibling
(`events.db.corrupt-<unix-ts>`) and retry init from scratch. On
retry-failure, writes `last_crash.json` with the original error
and exits, halting the launchd respawn loop after the second
consecutive failure. Used as a defense-in-depth fallback; for the
v1.7.5 issue specifically, the SchemaMigrator fix above means
recovery never triggers and history is preserved.

### Added — startup marker before storage init

`DaemonBootstrap.runForever` now writes
`/Library/Application Support/MacCrab/sysext_started.json` as its
very first action — synchronous, no actors, no storage. Mtime
distinguishes "launched but crashed in init" (banner: storage
recovery hint) from "never launched" (banner: reactivate extension).

### Added — `maccrabctl repair --fix-storage`

Operator escape hatch: backs up corrupt `events.db` files and lets
the daemon recreate them on next launch. Includes `PRAGMA integrity_check`
probe to skip the destructive backup if the DB is healthy.
`--force-fix-storage` overrides the integrity gate. For users hit
by the v1.7.5 SchemaMigrator bug specifically, this command is **not**
needed — installing v1.7.6 is sufficient and preserves history.

### Compatibility

No data migration required. Existing v1.7.5 installs: launching
v1.7.6 applies the missing `ADD COLUMN llm_investigation_json` to
the existing alerts table on first boot. No events or alerts lost.

No reboot or system extension re-approval required. sysextd swaps
the binary in-place when MacCrab.app reactivates the extension
(via Sparkle auto-update or `brew upgrade --cask maccrab`).

## [1.7.5] — 2026-04-28

Architectural improvements driven by a real v1.7.3 silent-heartbeat
incident. Three additions: split heartbeat (liveness vs rich
payload), `maccrabctl repair` self-diagnostic command, dashboard
zombie-sysext banner.

### Added — heartbeat split (`heartbeat.json` + `heartbeat_rich.json`)

New `livenessTimer` in `DaemonTimers.swift` runs **synchronously**
on the dispatch queue every 30 s and writes a minimal
`heartbeat.json` with only `written_at_unix`, `uptime_seconds`,
`sysext_has_fda`, `events_processed`, `alerts_emitted`. No actor
hops, no queries, no async work — cannot deadlock. The dashboard's
"engine silent" banner is gated on this file.

The rich payload (per-event-category counts, collector health,
drop counter) now lives in `heartbeat_rich.json` written by the
existing async heartbeat Task. Decoupling means a future stall
in EventStore queries or snapshot writes can never cause the
dashboard to show "engine silent" when the engine is actually
alive.

`AppState.refreshHeartbeat` reads `heartbeat.json` for liveness
and merges in fields from `heartbeat_rich.json` if present.
Backward-compatible: pre-v1.7.5 daemons wrote everything inline,
those fields still decode from `heartbeat.json` directly.

### Added — `maccrabctl repair`

New `Sources/maccrabctl/RepairCommand.swift`. Diagnose + auto-fix
common install issues. Six phases:

1. Daemon process liveness (`pgrep`)
2. Heartbeat staleness (mtime check)
3. System-extension state (`systemextensionsctl list`)
4. Orphaned writeSnapshot `.tmp` files (cleaned up)
5. SIGHUP daemon to reload config + rules
6. Operator-action recommendations for issues needing reboot /
   re-approval / FDA grant

`--dry-run` shows what would be done without taking action.

### Added — zombie-sysext banner

`AppState.refreshZombieSysextCount()` runs `systemextensionsctl
list` each poll tick and counts MacCrab entries in `[terminated
waiting to uninstall on reboot]` state. When ≥3, MainView shows a
top banner: "N prior MacCrab versions queued for uninstall —
reboot to clear them." Distinguishes the "needs reboot" case from
the generic "engine offline" case so operators see the right fix
immediately.

### Tests

926 in 188 suites pass (same as v1.7.4). v1.7.5 changes are
file-format split + new CLI + AppState property — covered by
existing snapshot-writer tests + manual `maccrabctl repair`
verification.

### Updated cadence

→ **1.7.5** (heartbeat split + repair tooling — defense against
the v1.7.x silent-heartbeat class)

### Updated key design lessons

- **Liveness signals must be on the simplest path possible.** The
  v1.7.0–v1.7.4 history shows that any async work in the heartbeat
  body is a future deadlock waiting to happen. v1.7.5 puts the
  liveness write on the dispatch thread itself — no Tasks, no
  actors, no queries. The richer signals live separately and can
  fail without affecting "is the daemon alive."
- **Operator self-service tooling reduces support load.** Without
  `maccrabctl repair`, every "engine silent" report required the
  user to run pgrep / stat / systemextensionsctl manually and
  paste output. With it, one command produces the full picture +
  attempts safe auto-repair + tells the operator exactly what's
  required.
- **The dashboard should distinguish reboot-needed from engine-
  hung.** Same symptom (no fresh heartbeat) but different fixes.
  The zombie-sysext banner surfaces a specific, actionable
  message instead of a generic warning.

## [1.7.4] — 2026-04-28

Follow-up hotfix to v1.7.3. The v1.7.3 memory fix combined two
changes that produced a new failure mode: any blocked snapshot
writer held the outer heartbeat-overlap-guard lock indefinitely,
every subsequent 30 s tick was dropped, and the dashboard showed
"Detection engine appears silent" after 120 s.

### Fixed — heartbeat-silent regression

Per-resource guards, not per-caller guards. Each snapshot writer
that lacked one (`MCPBaselineService.writeSnapshot`,
`RuleEngine.writeTelemetrySnapshot`, `TCCMonitor.writeSnapshot`)
now has a `snapshotWriteInFlight: Bool` matching the v1.6.6
`AgentLineageService` pattern. Concurrent writeSnapshot calls
no-op gracefully instead of queueing on the actor.

### Changed — `DaemonTimers.swift` heartbeat back to fire-and-forget

Removed the `HeartbeatInFlight` class and the outer overlap guard
introduced in v1.7.3. The four snapshot writes are once again
`Task { await ... }` fire-and-forget. The heartbeat write itself
is back on the critical fast path — no longer gated on snapshot
completion.

### Why this works

The v1.7.0–v1.7.2 leak was actor-queue buildup at the *writer*
level (concurrent writeSnapshot calls queueing on a busy actor's
mailbox). v1.7.3 cured it by serialising at the *caller* level
(one heartbeat Task at a time). v1.7.4 cures it at the right
level: the writer's own guard. Now the queue can't form because
the second call returns early before reaching the work.

### Tests

926 in 188 suites pass (was 922). +4 net (`V174GuardTests.swift`):
each writer round-trips a real snapshot file; 50 concurrent
`writeSnapshot` calls don't crash and at least one succeeds.

### Updated cadence

→ **1.7.4** (heartbeat-silent regression hotfix —
[[v174-heartbeat-fix]])

### Updated key design lessons

- **Don't add overlap guards at multiple layers.** v1.7.3 added a
  layer at the heartbeat scope on top of the existing per-writer
  guard at AgentLineageService. If even one inner writer lacks
  its own guard and blocks, the outer guard becomes a deadlock.
  Per-resource guards are the right level — each writer protects
  its own work, each caller doesn't need to know about the
  protection.
- **The heartbeat write is the critical path.** It's what the
  dashboard reads to determine "is the daemon alive." If the
  heartbeat write blocks on anything else (slow query, slow
  snapshot, slow lock), the operator sees "engine silent." The
  heartbeat must NEVER block on auxiliary work.
- **Fix at the right scope.** v1.7.3 was a real fix for a real
  leak, but applied at the wrong scope. The fix-the-fix in v1.7.4
  preserves the leak cure (no actor-queue buildup) while
  restoring the heartbeat fast path (writers can no-op if busy
  without blocking the heartbeat). Same shape as the v1.6.22
  audit chain — the real bug was 1 layer deeper than the first
  fix attempt.

## [1.7.3] — 2026-04-28

Memory regression hotfix. The v1.6.22 perf reduction (2.76 GB →
50 MB resident) had regressed back to 2.31 GB on a v1.7.2 test
host. This release restores the cap.

### Fixed — Heartbeat detached-Task accumulation (v1.7.1 cause)

The heartbeat-every-30s body in `DaemonTimers.swift` was wrapped in
`Task { ... }` to allow `await` across actor isolation, then
spawned 4 nested fire-and-forget `Task { ... }` calls for snapshot
writers (lineage, MCP baseline, rule telemetry, TCC). When any
snapshot write stalled (slow disk, contention, busy actor), the
next tick spawned 4 more — Tasks accumulated holding strong
`state: DaemonState` captures.

Fix: new `HeartbeatInFlight` class (NSLock + Bool) wraps the entire
heartbeat body. `tryAcquire()` returns false if a previous tick is
still running, dropping the new tick with one `WARN` log line. The
4 snapshot writes are now serialised via plain `await` inside the
outer Task. Hard cap: 1 outstanding heartbeat Task at any time.

### Fixed — `CollectorRegistry.entries` uncapped (v1.7.2 cause)

`recordTick(name:)` lazy-registered unknown names without an upper
bound. Any variance in collector name strings (PIDs, paths,
timestamps embedded in names) grew the dictionary indefinitely.

Fix: `init(maxEntries: Int = 64)` parameter floored at 16. When
`recordTick` lazy-registers and the cap is reached, evict
oldest-by-lastTick — preferring never-ticked entries first. One
`WARN` log per eviction surfaces missing `register()` calls.

### Fixed — `MCPAttributor.cache` non-deterministic eviction (v1.7.0 cause)

`cache.keys.first` removes an arbitrary entry from a Swift
Dictionary on overflow — not LRU. Frequently-accessed entries got
evicted; stale negative-cache entries persisted; re-walk pressure
grew.

Fix: new `accessSeq: [pid_t: UInt64]` parallel map bumped on every
cache hit and miss. Eviction picks the entry with the lowest seq.
Same pattern as v1.6.21 `RuleEngine.regexAccessSeq`.

### Added — `pre-release-audit.sh` Pass 8

Every `private var <field>: [...]` or `private var <field>: Set<...>`
declaration in actor source files (`MacCrabCore` +
`MacCrabAgentKit`) must show evidence of bounding:

- explicit cap-and-evict logic in the same file
  (`removeValue(forKey:)`, `removeFirst`, `removeAll`, `count >=`),
- an inline `// bounded:` comment, or
- an entry in the audit's `BOUNDED_FIELD_ALLOWLIST` with rationale.

A v1.7.3 baseline allowlist documents 22 pre-existing fields
(`MCPMonitor.knownServers`, `USBMonitor.knownDevices`,
`SystemPolicyMonitor.knownPlugins`, ...) where the bound is
external. New unbounded actor maps fail the audit and the release
pipeline. Catches the v1.7.2 regression class going forward.

### Tests

922 in 187 suites pass (was 918). +4 net (`V173HotfixTests.swift`):
CollectorRegistry cap eviction (oldest-tick), never-ticked-first
eviction, cap floor, MCPAttributor LRU eviction.

### Updated cadence

→ **1.7.3** (memory regression hotfix + Pass 8 codification —
[[v173-memory-hotfix]])

### Updated key design lessons

- **Detached `Task { ... }` calls inside a periodic timer
  accumulate.** Each tick that spawns a fire-and-forget Task creates
  a new captured-state graph. If the work doesn't complete before
  the next tick, the captures pile up. Pre-v1.7.3 the v1.7.1
  heartbeat spawned 5 Tasks per tick (1 outer + 4 nested). Fix:
  one Task per tick + serialise inner writes + overlap guard.
- **Every actor map needs a cap.** v1.7.2 added two unbounded
  collections (`CollectorRegistry.entries`,
  `MCPAttributor.accessSeq`) that grew with name-variance and
  eviction-skew respectively. Pass 8 codifies the cap-or-leak
  invariant — every `[K: V]` field on an actor needs bounding,
  documented or explicit.
- **Audit-then-fix beats reactive triage.** The 2 GB regression was
  caught from real Activity Monitor data, then localised by an
  Explore-agent audit before the fix bundle started. Same shape as
  v1.6.22.

## [1.7.2] — 2026-04-28

The 8-item carry-over queue from v1.7.0 + v1.7.1, all in one release.
Pre-ship deep-dive review found 2 HIGH + 3 MEDIUM issues (and
correctly rejected 1 falsely-reported BLOCKER and 1 falsely-reported
HIGH after verification) — all real findings fixed before push.

### Added — `CollectorRegistry` + heartbeat schema v4

New `Sources/MacCrabAgentKit/CollectorRegistry.swift` actor. Tracks
per-collector last-tick timestamps, event counts, error counts,
last-error strings, derived health. 16 collectors pre-registered at
daemon startup with characteristic intervals + event-driven flags.
Heartbeat schema bumped v3 → v4 with `collector_health` array +
aggregate `events_dropped` counter. Backward-compatible: older
dashboards see legacy fields unchanged.

`MonitorTasks` event-stream consumers call `recordTick(name:)` once
per emitted event — 12 single-line insertions across the existing
`for await event in state.<collector>.events` loops. Lazy-
registration default after pre-ship review fix:
`eventDriven: false, expected: 300s` + warning log so a forgotten
explicit `register()` surfaces.

### Added — `ESHealthView` daemon-driven collector list

Replaces the previous hardcoded 10-entry list with the
`heartbeat.collectorHealth` array. Per-row: name, healthy badge,
event count, error count, last-tick relative time, last-error inline.
Drop counter surfaces as a top banner when non-zero.

### Added — Search across 4 panels (AI Analysis, Prevention, Package Freshness, Integrations)

All four newly added `searchText` `@State`. Filtering applies before
the existing categorization splits (Investigations / Recommendations,
risky / safe, suspicious / non-suspicious, etc.).

### Added — Prevention per-mechanism drill sheet

Tap any "Recent Prevention Activity" row → sheet showing every
alert attributed to the inferred mechanism (DNS sinkhole, supply
chain gate, persistence guard, sandbox analysis, AI containment,
network blocker, TCC revocation, Other). Mechanism inference uses
rule-title token matching; pre-ship review added an explicit
`.other` enum case so unknown alert titles no longer mis-bucket
into AI Containment.

### Added — Integrations per-tool drill sheet

Tap any installed tool card → sheet showing path, log path, version,
running status, and full capabilities list. New
`ToolSelection: Identifiable` wrapper over the core
`InstalledTool` type so `.sheet(item:)` accepts it without
retroactive `Identifiable` conformance.

### Added — Aider / Codex MCP spawn-shape matchers

`MCPAttributor.looksLikePackageToken` recognizes `aider_mcp_*`
(Python module flag form), `@openai/codex` (NPM scope), and
`openai-codex-mcp-*` (Codex CLI MCP server form). Category
extraction supports the new prefixes. Two new tests cover each
shape. Carry from v1.7.0's deferred matcher list.

### Added — Rule engine P50 / P95 / P99 execution percentiles

`RuleEngine.RuleStats` gains an `execSamplesNs: [UInt64]` reservoir
(256 samples × 8 B × 420 rules ≈ 860 KB worst case). Sampling uses
Vitter Algorithm R: under reservoirSize append; once full replace
at a uniform-random index in `[0, reservoirSize)` with probability
`reservoirSize / evaluationCount`. Computed properties
`p50ExecNs` / `p95ExecNs` / `p99ExecNs` derive from the reservoir.
`RuleRow` shows p95 inline when ≥50 samples exist (threshold raised
from 20 → 50 in pre-ship review).

### Added — EventStore schema migration v2

Migration v2 promotes MCP attribution from `raw_json` only (v1.7.0)
to top-level indexed columns: `mcp_server_name`,
`mcp_server_category`, `ai_tool_session_id`. Composite index
`idx_events_mcp_server` on `(timestamp, mcp_server_name)`.
Insert SQL bumped from 21 → 24 bind columns; missing attributions
bind NULL. Migration runs inside `SchemaMigrator`'s existing
BEGIN/COMMIT wrapper with idempotent ADD COLUMN re-run support.

### Pre-ship deep-dive review

Five-axis review (perf / security / stability / functionality /
UX-accessibility) ran against v1.7.2 changes before push. 11
candidate findings; 2 falsely-reported (Vitter R correctness was
mathematically valid; SchemaMigrator already wrapped each migration
in a transaction with rollback). Real fixes applied:

- **HIGH**: CollectorRegistry lazy-register default
  (`eventDriven: false`, log warning).
- **HIGH**: AppState heartbeat decoder logs malformed
  `collector_health` entry drops via `os.log` warning.
- **MEDIUM**: PreventionView `.other` mechanism enum case
  (eliminates `.aiContainment` mis-bucketing of unknown titles).
- **MEDIUM**: RuleRow p95 threshold 20 → 50 samples.
- **MEDIUM**: ESHealthView empty state `.tertiary` → `.secondary`
  (WCAG AA on dark mode).

### Tests

918 in 185 suites pass (was 905 in v1.7.1). +13 net
(`V172Tests.swift` + extended `MCPAttributorTests`):
- CollectorRegistry: initial state, tick, lazy register, health
  decay, error tracking, drop counter (6)
- RuleEngine percentile: empty / single sample / sorted (3)
- EventStore schema v2: fresh insert with attribution / without (2)
- MCPAttributor: Aider + Codex shape (2)

### Deferred (not blocking ship)

Pre-ship review MEDIUMs not fixed: button styling consistency in
PreventionView, IntegrationsView Scan button visibility under
search, hardcoded collector name strings (refactor not regression).
Future scope: per-call LLM telemetry, daemon CPU/memory in
heartbeat, more MCP spawn shapes (await field reports).

## [1.7.1] — 2026-04-28

Track 2 panel-richness audit. The carry-over from v1.6.19 → v1.6.20 →
v1.6.21 → v1.6.22 → v1.7.0. Four primary panels (Rules, Browser
Extensions, Permissions, ES Health) gain the v1.6.17 Threat Intel
rebuild template: search + per-row metadata + per-source health +
multi-view modes for the panels where one list view didn't tell the
whole story.

### Added — RuleBrowser per-rule telemetry

- `RuleEngine.RuleStats` Codable type tracks per-rule fire count,
  total exec ns, last-fired Date. Updated on every `evaluate(_:)`
  call (fired or not). `writeTelemetrySnapshot(to:)` +
  `readTelemetrySnapshot(at:)` follow the same atomic temp+rename
  pattern as `AgentLineageService.writeSnapshot`.
- Daemon writes `<supportDir>/rule_telemetry.json` on the heartbeat
  tick. ~35 KB at 420 rules.
- Dashboard `AppState.refreshRuleTelemetry()` polls on the 10 s
  refresh cycle with mtime-skip optimization.
- `RuleRow` (in `Components.swift`) takes an optional `stats`
  parameter and renders fire count + last-fired + mean exec ms below
  the existing technique badges. `SLOW` row badge appears on rules
  whose mean exec exceeds the daemon's 50 ms slow-rule threshold.
- `RuleBrowser` adds a "Slow only" toggle and a "Most fires" sort
  mode alongside the existing alphabetical sort.

### Added — BrowserExtensionsView search + collapsible per-browser sections

- Cross-browser search by name, extension ID, or permission token.
- Per-browser collapsible sections via chevron click. Per-browser
  "N flagged" badge surfaces suspicious-extension count without
  expanding the section.

### Added — TCCTimeline three view modes (Permissions panel)

- New `TCCMonitor.PublicEntry` + `PermissionSnapshot` Codable types
  expose the previously-private current-state matrix to the
  dashboard.
- `TCCMonitor.writeSnapshot(to:)` + `readSnapshot(at:)` — atomic
  temp+rename to `<supportDir>/tcc_snapshot.json`.
- `AppState.refreshTCCSnapshot()` polls on the 10 s refresh cycle.
- `TCCTimeline.ViewMode` enum: `Timeline` (existing), `Services`
  (new, per-service group → list of apps with status), `Apps` (new,
  per-app group → list of services with status). Segmented picker
  in the header.

### Added — ESHealthView event-rate sparkline + per-category breakdown

- Rolling 60-point event-rate window (10 s × 60 = 10 min) rendered
  with `Charts.LineMark` + `AreaMark`.
- Per-event-category breakdown horizontal bar chart from the new
  heartbeat field.
- New `EventStore.eventCountsByCategory(since:)` indexed query over
  `idx_events_ts_category` returning `[String: Int]`.
- Heartbeat schema bumped v2 → v3: new `event_type_counts_1h` field.
  Backward-compatible: older readers ignore the new field.
- `heartbeatTimer.setEventHandler` body wrapped in a `Task` so the
  EventStore query can await across actor isolation. Failure is
  swallowed — heartbeat write must succeed even if the EventStore
  query times out under contention.

### Added — `pre-release-audit.sh` Pass 7

Primary panel view richness invariant. Every panel in
`Sources/MacCrabApp/Views/` listed in `PRIMARY_PANELS` must declare:

- A search-state (`@State` named `searchText` / `query` /
  `filterText` / `searchQuery`)
- A drill-down hook (`.sheet` / `.popover` / `NavigationLink` /
  `HSplitView` / multi-view `Picker` bound to a `viewMode` /
  `selectedSection` / `selectedTab` / `selectedMode` state)

`ESHealthView` is exempt on the strength of its sparkline + breakdown
+ collector list. Codifies the v1.6.17 Threat Intel rebuild template
as an architectural invariant. Add a new entry to `PRIMARY_PANELS`
when shipping a new primary panel.

### Tests

905 in 182 suites pass (was 898). +7 net (`Panel171SnapshotTests.swift`):
- `RuleEngine.TelemetrySnapshot` JSON round-trip
- `RuleStats.meanExecNs` zero-divisor guard
- Live `RuleEngine` write produces a readable empty snapshot
- `TCCMonitor.PermissionSnapshot` lossless encode/decode
- Missing-path returns nil (both telemetry + TCC readers)
- Malformed-JSON returns nil
- `EventStore.eventCountsByCategory` empty-store coverage

### Deferred to v1.7.2

- Drop-count + collector health registry on the heartbeat
- Rule engine P50/P95/P99 exec percentiles (mean is enough for the
  slow-rule filter)
- Aider / Codex MCP spawn-shape matchers (carry from v1.7.0)
- AI Analysis / Prevention / Package Freshness / Integrations panel
  rebuilds (P1/P2)

## [1.7.0] — 2026-04-28

First feature minor since v1.6.0. Closes the longest-standing
"wire-the-orphans" gap: `MCPBaselineService` (`Sources/MacCrabCore/
AIGuard/MCPBehavioralBaseline.swift`) has carried a complete
learning/enforcing API and `BaselineDeviation` AsyncStream since
v1.6.6, but the **producer half** that feeds it observations from
real events was never built. v1.7.0 builds it.

### Added — `MCPAttributor` actor

New `Sources/MacCrabCore/AIGuard/MCPAttributor.swift`. Walks each
AI-child event's process ancestry and matches each ancestor's
commandline against the AI tool's configured MCP servers (parsed by
`MCPMonitor` from the user's claude/cursor/etc. config files). On
match, returns an `Attribution` with server name, category,
boundary PID, and confidence (`high` / `medium` / `low`).

Cached by PID with a 5000-entry LRU. Negative results are also
cached — events from non-MCP processes pay one walk and zero
re-walks. Hot-path lookup is O(1) on cached PIDs;
O(ancestors × configured-servers) on first encounter (typically
< 50 work units).

### Added — per-event MCP attribution wiring

`EventLoop.swift` calls `MCPAttributor.attribute(...)` inside the
existing AI-child detection branch (only paying the cost on events
under an AI tool). On a positive match, three new keys are added to
`Event.enrichments`:

- `mcp_server_name`
- `mcp_server_category`
- `mcp_attribution_confidence`

These flow through the standard event pipeline and persist in
`raw_json` — no schema migration. (Indexed columns deferred to
v1.7.1 if/when the panel needs faster queries.)

### Added — MCP behavioral baseline observation feed

For each high/medium-confidence attributed event, EventLoop now
calls `MCPBaselineService.observe(...)` with a populated
`MCPBaselineObservation`. The dormant baseline service is now
fully wired into `DaemonState`: the dispatch loop in
`MonitorTasks.swift` consumes the `deviations` AsyncStream and
submits `Alert`s through the existing `AlertSink` chokepoint with
ruleId pattern `maccrab.mcp.baseline-anomaly.<tool>.<server>.
<kind>`, severity `medium`, MITRE-mapped to `attack.initial_access`
and `attack.command_and_control`.

Baselines need both 20 observations AND 5 minutes of wall-clock
before promoting from learning → enforcing.

### Added — `MCPBaselineService.writeSnapshot/readSnapshot`

The dormant baseline now also writes
`<supportDir>/mcp_baselines.json` on the 30 s heartbeat tick (same
cadence and atomic temp+rename pattern as
`AgentLineageService.writeSnapshot`). New `BaselineSnapshot`
Codable type wraps the snapshot for cross-process consumption.

### Added — `MCPActivityView` dashboard panel

New `Sources/MacCrabApp/Views/MCPActivityView.swift`. Lives in the
Intelligence sidebar group between AI Analysis and Integrations.
Per-server rows with name, AI tool, observation count, and
learning/enforcing badge. Click a row to see the full fingerprint
— every file basename, domain, and child process basename the
baseline has learned. Recent Baseline Drift alerts surface as a
banner above the list.

`AppState.refreshMCPBaselines()` polls
`<dataDir>/mcp_baselines.json` on the same 10 s dashboard refresh
cycle as the lineage snapshot, with mtime-skip optimization.

### Added — `MCPMonitor.serversForTool(_:)` + `allConfiguredServers()`

Public accessors over the previously-private `knownServers` map.
Used by `MCPAttributor` to look up the configured-server list for
an AI tool without re-parsing config files. New
`MCPMonitor.ConfiguredServer` struct is the public copy-by-value
shape.

### Added — `pre-release-audit.sh` Pass 6

Every public Codable snapshot type exposed by a daemon-side writer
(`AgentLineageService.LineageSnapshot`,
`MCPBaselineService.BaselineSnapshot`) must have at least one
`MacCrabApp` consumer. Fails release on regression. Catches the
snapshot variant of the wire-the-orphans pattern. Add a new pair
to `SNAPSHOT_PAIRS` when shipping a new daemon snapshot writer.

### Tests

898 in 181 suites pass (was 892). +6 net:
- `MCPAttributor` package-token match (high confidence)
- Negative-cache reuse on non-MCP processes
- Server-category derivation from `@modelcontextprotocol/server-X`
  and `mcp-server-X` package tokens
- No-match returns nil
- `MCPBaselineService` snapshot round-trip (with and without
  baselines)

### Updated cadence

→ **1.7.0** (MCP attribution producer half + behavioral baseline
deviation alerts + MCP Server Activity panel + Pass 6 audit
codification)

### Deferred

- v1.7.1 panel-richness audit (Rules / Browser Extensions /
  Permissions / ES Health) — carry-over from v1.6.19 → v1.6.20 →
  v1.6.21.
- AI tool spawn-shape matchers for Aider, Codex (Phase 1 covers
  Node-via-npx and Python-via-`-m`).

## [1.6.22] — 2026-04-28

Endpoint footprint reduction. Production observation on a v1.6.21
test host showed the sysext at 2.76 GB Real / 2.65 GB Private /
416 GB Virtual / 27 M Unix syscalls / 15 M Mach syscalls / 128 ports
over a 7-min CPU window. v1.6.22 retargets to ~800 MB resident,
~5 M syscalls per equivalent window through six structural cuts and
one bug fix the audit surfaced. Zero feature, detection-rule, or
dashboard changes.

### Fixed — `CampaignStore` opened `events.db` (third long-lived handle)

Pre-v1.6.22 `CampaignStore.init` called
`dir.appendingPathComponent("events.db")` and created its `campaigns`
table inside the shared events database — the third long-lived
SQLite connection on one file (EventStore + AlertStore + this).
Each handle carries its own page cache plus busy-timeout buffer; the
extra connection contributed unnecessarily to the daemon's resident
memory. CampaignStore now opens `campaigns.db`. The previous
`campaigns` table inside `events.db` is left in place; the next
size-cap-driven VACUUM reclaims the (small) space. Campaign history
persisted before v1.6.22 will reappear as the detector re-derives
campaigns from current alerts.

### Changed — SQLite per-connection memory pragmas

Centralized in `Sources/MacCrabCore/Storage/StoragePragmas.swift`.

- `EventStore` — `mmap_size` 256 MB → 64 MB; `cache_size` 64 MB →
  16 MB. Saves ~190 MB virtual + ~48 MB heap.
- `AlertStore` — `mmap_size` 256 MB → 16 MB; `cache_size` 64 MB →
  4 MB. Alerts table is 2–3 orders of magnitude smaller than events;
  the previous mmap was ~99 % wasted. Saves ~240 MB virtual +
  ~60 MB heap.
- `wal_autocheckpoint` 10 000 pages → 1 000 pages on both stores —
  drains the `.db-wal` file at ~4 MB instead of ~40 MB, reducing
  transient memory and the per-checkpoint stall length.

### Changed — outbound HTTP routes through `SecureURLSession.shared`

Pre-v1.6.22 the daemon-target callers (`ThreatIntelFeed`,
`MISPClient`, `FleetClient`, `CertTransparency`,
`NotificationIntegrations`, `PackageFreshnessChecker`) used
`URLSession.shared`. That session uses
`URLSessionConfiguration.default`, which writes a disk cache to
`~/Library/Caches/<bundle>/Cache.db` (+ WAL + SHM) and an HSTS /
cookie store to `httpstorages.sqlite`. When the daemon runs as root
those files land under `/private/var/root/Library/Caches/com.maccrab.agent/`
and accumulate forever — observed on a v1.6.21 test host alongside
the 2.76 GB resident spike.

`SecureURLSession.shared` (new module-shared singleton) uses
`URLSessionConfiguration.ephemeral`: no disk cache, no cookies,
no credential storage, TLS 1.2+ enforced. Same connection-pool
semantics as `URLSession.shared`, none of the side effects.

### Changed — heap caps tightened

- `AgentLineageService` per-session ring 10 000 → 2 000 events.
  At 32 sessions × 10 000 × ~300 B/event the worst case was
  ~96 MB resident; new worst case is ~19 MB.
- `CampaignDetector.recentAlerts` cap 50 000 → 5 000. Kill-chain
  detection runs on the recent campaign window (`campaignWindow`,
  default 600 s); beyond that, alerts are time-evicted anyway. The
  larger cap was ~100 MB heap with no detection benefit.
- `ProcessLineage.maxProcessCount` cap 50 000 → 10 000. LRU
  eviction prefers exited processes; a busy machine has ~200–800
  live PIDs, so 10 000 covers the live set plus a 1-hour retention
  window of recently-exited ones. ~30 MB heap.
- `ThreatIntelFeed` per-IOC-type defaults: hashes 200 K → 100 K;
  IPs 25 K → 10 K; domains 100 K → 50 K; URLs 75 K → 25 K. ~55 MB
  heap. Age-based eviction (30-day TTL) keeps coverage current.

### Changed — syscall volume per equivalent CPU window

- `LibraryInventory.getLoadedLibraries` per-process region cap
  10 000 → 2 000. Empirically every common process has fewer than
  800 distinct memory regions; 2 000 covers Xcode and Electron
  outliers with margin. The 10 000 cap dominated the 27 M
  Unix-syscall total at ~200 PIDs × up to 10 K `proc_pidinfo` calls
  per scan, every 5 minutes.
- `LibraryInventory` scan now actually runs every-other forensic-
  timer cycle (10 min cadence) instead of every cycle (5 min). The
  v1.6.21 inline comment promised "every other cycle" but no skip
  logic existed.
- `NetworkCollector` default poll 2 s → 10 s. Each sweep walks every
  PID with `proc_pidinfo(PROC_PIDLISTFDS)` + `proc_pidfdinfo` per
  FD. 5× interval = 5× syscall reduction. ES gives us real-time
  spawn context for the spawning process; the per-PID FD scan
  doesn't need 2 s resolution.
- `RootkitDetector` base interval 60 s → 120 s + PowerGate-gated.
  The dual-API discrepancy detection is not latency-sensitive — a
  true rootkit hides processes for the full daemon lifetime, not
  for sub-minute windows.

### Changed — hot-path stdout removed

18 `print()` calls on the alert hot path in
`Sources/MacCrabAgentKit/EventLoop.swift` removed. They were stdout
duplicates of work already going through the proper
`notifier.notify(alert:)` + `alertSink.submit(...)` paths. Net win
is small (~10–50 µs per call × 100 alerts/s ≈ 1–5 ms/s) but real,
and the orphan removal cleaned up unused severity-icon and
rule-result locals along the way.

### Added — `pre-release-audit.sh` Pass 4 + Pass 5

Two new architectural invariants enforced at release time:

- **Pass 4 — URLSession discipline.** Every outbound HTTP call in
  `Sources/MacCrabCore`, `Sources/MacCrabAgentKit`,
  `Sources/MacCrabAgent`, `Sources/maccrabd` must use
  `SecureURLSession.shared`. `URLSession.shared` fails the release.
  `MacCrabApp` is exempt because Sparkle and AppKit internals
  depend on it.
- **Pass 5 — `events.db` long-lived handle count.** Counts actors
  that BOTH open `events.db` (via `appendingPathComponent("events.db")`)
  AND declare a long-lived `private var db: OpaquePointer?`. The
  audited target is 2 (EventStore + AlertStore); 3+ fails the
  release. This is the pass that caught the CampaignStore bug
  fixed in this release.

### Tests

892 in 179 suites pass — same count as v1.6.21. No new test files;
all changes are behavioral / structural and covered by existing
storage, threat-intel, and HTTP suites.

## [1.6.21] — 2026-04-28

Surface completion + comprehensive multi-domain audit pass. Three small
surface fixes complete v1.6.x threads (no new features); a five-axis
review of v1.6.0–v1.6.20 found 6 BLOCKERs and 6 HIGHs, all fixed
before push.

### Audit fixes (BLOCKER)

- **TOCTOU in EventLoop network-convergence path** — was using legacy
  split `shouldSuppress()` + `recordAlert()` pair; under sustained
  cross-process convergence two threads could both pass the check
  and emit duplicate alerts. Now uses atomic
  `shouldSuppressAndRecord` (`EventLoop.swift:455-460`).
- **TOCTOU in EventLoop rule-engine match path** — same shape
  (`EventLoop.swift:986-987`).
- **Notify-after-suppress regression in 23 emission sites** — across
  EventLoop + MonitorTasks, `notifier.notify(alert:)` was firing
  unconditionally after `alertSink.submit` regardless of return
  value. Operators received notification banners for duplicates
  even though the alert was correctly suppressed from the store.
  All 23 sites now gate `notify` on `inserted == true`.
- **`SafeBlockableIP` IPv6 CIDR coverage** — pre-fix only exact-
  match IPv6 was supported, so `2001:4860:4860::8889` (one byte off
  Google DNS `::8888`) bypassed and blocking it would silently break
  IPv6 DNS. Added IPv6 CIDR matching for Cloudflare, Google, Quad9,
  OpenDNS DNS prefixes, plus loopback / link-local / multicast.
- **`MISPClient.fetchCategorized` validator gap** — extracted IPs/
  domains/hashes from MISP feeds without running them through the
  v1.6.18 validators that custom imports use. A compromised MISP
  server could push `127.0.0.1` as an IP and have it sinkholed.
  Now every value passes `ThreatIntelFeed.validate*`.
- **`SystemPolicyMonitor` PowerGate gap** — 5-min poll ignored
  battery / thermal pressure. Now uses `PowerGate.adjustedInterval`
  for the same throttling as other collectors.

### Audit fixes (HIGH)

- **`AlertDeduplicator.normalizePath` regex pre-compile** — was
  re-compiling 4 NSRegularExpression patterns per call (~0.9 ms ×
  100 alerts/sec ≈ 9 % CPU). Now pre-compiled once at class load.
- **`SafeQuarantinePathValidator` regex → string slicing** — replaced
  24 regex evals per call with O(1) `userHomeRemainder` + 12
  `hasPrefix` checks. ~10× faster, identical semantics.
- **`SafeBlockableIP.currentDefaultGateway` 30 s TTL cache** —
  pre-fix every `isSafeToBlock` call shelled out to `route -n get
  default` (~5–10 ms). Under PF block storms that was 5 % CPU. Now
  cached with 30-second TTL.
- **`ResponseEngine.executionLog` cap** — was unbounded; under
  sustained action firing it grew memory indefinitely. Now capped
  at 50 K entries with 5 K LRU evict on overflow.
- **`SettingsView.scheduleWebhookSync` cancellation handling** —
  `try? await Task.sleep(...)` swallowed CancellationError; partial
  writes possible under rapid keystrokes. Now catches explicitly
  and bails on cancel.
- **`ResponseActionsView` "Daemon reloaded" banner truthfulness** —
  banner said "Daemon reloaded." regardless of whether `pkill`
  succeeded. Now checks `terminationStatus` and shows
  "Saved. Daemon will reload on next start." when the sysext
  isn't reachable.

### Surface completion (no new features)

- **Pending Actions surface (completes v1.6.20's `requireConfirmation`
  thread).** When `ResponseEngine.execute` skips an action because
  `requireConfirmation = true`, it now also emits a synthetic
  `.informational` alert via AlertSink with rule ID
  `maccrab.pending-action.<action>`. Existing AlertsView / AlertDetailView
  manual-action buttons (kill / quarantine / blockNetwork via
  ManualResponse) become the "Run now" surface; existing alert-
  suppression UI becomes "Dismiss." No new SwiftUI view; reuses
  every existing piece.
- **LLM "Test Connection" button in Settings → AI Backend.** Calls
  `LLMService.makeFromConfig` against the current editor state
  (transient — does not write to disk). Inline status indicator:
  green check with provider name on success, red X with reason on
  failure (missing API key, unreachable backend, etc.). Resets to
  untested on any config edit so a stale OK doesn't mislead.
  Completes Tier 3 #15 from the v1.6.0 best-in-show roadmap.
- **AI Guard timeline surface** — verified already shipped in
  v1.6.15 (`AIActivityView.swift:130` already invokes
  `AIActivityTimelineView`). Listed as planned but no-op.

### Tests

892 in 179 suites pass — same count as v1.6.20 (no new test files;
all fixes are behavioral changes covered by existing suites).

## [1.6.20] — 2026-04-27

Response-action surface follow-up to v1.6.19's safety-hardening pass.
Same audit pattern applied to the per-rule auto-actions; five issues
found, all fixed.

### Added — quarantine system-path safety guard

`SafeQuarantinePathValidator` (new, `Sources/MacCrabCore/Prevention/`)
refuses to quarantine files in:

- System code: `/System/`, `/Library/Apple/`, `/Library/Frameworks/`,
  `/Library/PrivilegedHelperTools/`, `/Library/SystemExtensions/`,
  `/Library/LaunchDaemons/`, `/Library/LaunchAgents/`, `/usr/`,
  `/sbin/`, `/bin/`
- Runtime state: `/private/var/db/`, `/private/var/folders/`,
  `/etc/`, `/Library/Application Support/MacCrab/`
- Per-user data: Mail, Calendar, Contacts, Reminders, Keychain,
  Safari, iCloud, Photos, Time Machine, MacCrab user-home support

Symlink-safe (resolves via `resolvingSymlinksInPath` before prefix
match). Wired into both `ResponseEngine.quarantineFile` and
`ManualResponse.quarantineFile`. Quarantine remains opt-in by default
(built-in defaults are `notify` + `log` only).

### Added — `blockNetwork` protected-IP allowlist

`SafeBlockableIP` (new) refuses to PF-block public DNS (1.1.1.1,
8.8.8.8, 9.9.9.9, 208.67.222.222 + IPv6), Apple's 17.0.0.0/8 range,
loopback, link-local, multicast, carrier-grade NAT, and the current
default gateway (resolved at runtime via `route -n get default`).
Wired into `ResponseEngine.blockNetworkDestination` and
`ManualResponse.blockDestination`.

### Fixed — `requireConfirmation` now actually checked

Pre-v1.6.20 the `ResponseActionConfig.requireConfirmation: Bool`
field was decoded from `actions.json` and ignored by `ResponseEngine.
execute`. Operator who set it expecting a confirmation gate got
instant execution. Now: actions with `requireConfirmation = true`
are logged as pending and skipped. Surfaced as a per-action checkbox
in the Response Actions tab; destructive actions (kill / quarantine
/ blockNetwork) default to `true` when added from the editor with a
warning-icon visual marker.

### Fixed — `actions.json` user-home overlay + SIGHUP reload

Pre-v1.6.20 the dashboard tried to write `actions.json` to the
system path `/Library/Application Support/MacCrab/actions.json` —
which the user app can't write without root. `try?` swallowed the
EPERM and the "Saved." banner lied. Same pattern as the v1.6.19
webhook fix.

Now: dashboard always writes to user-home; `ResponseEngine.
loadConfig` walks `/Users/*` (with file-ownership validation) and
prefers the most-recent copy. SIGHUP triggers reload — no daemon
restart required. Save banner correctly says "Saved. Daemon reloaded."

### Fixed — `ManualResponse.killProcess` defense-in-depth

User-initiated kill path now uses `SafePIDValidator` for parity with
auto-kill. Practically safe before because the app runs unprivileged
and `kill()` would EPERM on system PIDs anyway, but explicit refusal
gives a better error message and protects against a future signed-
installer flow.

### Added — `pre-release-audit.sh` Pass 1b: Codable Config field consumer audit

Catches the `requireConfirmation`-shaped bug class for the future.
Walks public fields on `ResponseActionConfig` and
`NotificationIntegrations.Config`, counts `.fieldName` references
across `Sources/` minus trivial `self.fieldName = fieldName` init
self-assignments, errors when count is zero (decoded but never
read). Wired into `release.sh` Step 0b. Adding a new decoded-config
field without a runtime consumer now fails the release pipeline
before push.

### Tests

892 in 179 suites pass (was 860). +32 net:
SafeQuarantinePathValidator (17), SafeBlockableIP (15).

## [1.6.19] — 2026-04-26

A safety + architecture release. The bigger of the two threads.

### Added — safety guards (4 paths the audit found could damage the user's machine)

- `SafePIDValidator` refuses to kill PID ≤ 1, MacCrab itself, the
  critical-system-process list (kernel_task / launchd / WindowServer /
  loginwindow / securityd / opendirectoryd / cfprefsd / coreaudiod /
  bluetoothd / mDNSResponder / ...), or anything running from
  `/System/`, `/usr/libexec/`, `/sbin/`, `/usr/sbin/`. Wired into
  `ResponseEngine.killProcess` and `SupplyChainGate.gate`.
- `SupplyChainGate` now also requires the installer PID to descend from
  a known package manager (npm / pnpm / yarn / pip / brew / cargo /
  ...) within 5 hops, AND re-checks the path before the delayed
  SIGKILL so a recycled PID can't hit a different process.
- `DNSSinkhole` protected-domain allowlist refuses to sinkhole anything
  matching `apple.com`, `*.icloud.com`, `ocsp.apple.com`, `github.com`,
  `googleapis.com`, `microsoft.com`, `aws.amazon.com`, `stripe.com`,
  `jetbrains.com`, `slack.com`, `digicert.com`, `sectigo.com`,
  `letsencrypt.org`, `maccrab.com` itself, etc. (75+ patterns) plus
  IP literals. A poisoned threat-intel feed can no longer brick
  code-signing or strand the user.
- `PanicButton.activate` takes `disableBluetoothInPanic: Bool = false`
  so a wireless-only user with Magic Keyboard/Trackpad isn't stranded
  mid-panic. Panic is opt-in for BT now. (`PanicButton` itself was
  removed from `DaemonState` — `activate()` had zero callers.)

### Added — `AlertSink` chokepoint (closes the v1.6.9 NoiseFilter-layering bug class)

- New `AlertSink` actor: every alert reaches `AlertStore` through one
  point that applies `AlertDeduplicator` first. 39 direct
  `alertStore.insert` call sites in `EventLoop` / `MonitorTasks` /
  `DaemonTimers` / `SignalHandlers` migrated to `alertSink.submit`.
  Two audited exceptions in `DaemonSetup` (self-defense + ES-health)
  carry inline justification.
- `AlertDeduplicator.shouldSuppressAndRecord` is a new atomic actor
  method. It closes a TOCTOU window between the previous
  `shouldSuppress` + `recordAlert` pair: 50 concurrent submits with
  the same key now insert exactly one (test pins the contract).

### Added — institutional audit (`scripts/pre-release-audit.sh`)

Three architectural invariants enforced at release time:

- **Pass 1 — orphan audit.** Every Settings `@AppStorage` that affects
  daemon behavior must declare a sync function. Catches the
  wire-the-orphans pattern that produced four bugs in seven releases.
- **Pass 2 — single-sink.** Zero direct `alertStore.insert` outside
  `AlertSink` plus the two audited `DaemonSetup` exceptions.
- **Pass 3 — duplicate-source.** Cross-file constants (default
  support directory, sysext launchd label) must agree.

Wired into `release.sh` as Step 0b, fails the release on regression.

### Added — extended `prerelease-check.sh` manifest equality

Cask version (`Casks/maccrab.rb` ↔ `homebrew/maccrab.rb`), Sparkle
appcast URL (project.yml ↔ Info.plist), Sparkle EdDSA public key,
app + sysext `CFBundleIdentifier`, Apple Team ID with cask references.
Five new drift checks layered on the v1.6.18 short-version catch.

### Added — webhook config wiring

Pre-v1.6.19 the Settings → Slack/Teams/Discord/PagerDuty fields wrote
to UserDefaults but no daemon code consumed them. Configured webhooks
silently never fired. Now: SettingsView writes
`~/Library/Application Support/MacCrab/notifications.json`,
SIGHUP triggers `NotificationIntegrations.reloadConfig()`, alerts
fire to the configured services. 500 ms debounce on `onChange` so
typing the URL doesn't SIGHUP per keystroke.

### Removed — `autoQuarantine` / `autoKill` / `autoBlock` toggles

Same wire-the-orphans pattern: toggles wrote to UserDefaults, no daemon
code consumed them. Per-rule auto-actions live in the Response Actions
tab, which IS wired into `ResponseEngine`. 181 dead translation lines
swept across 14 locale files at the same time.

### Fixed (pre-push review)

- Webhook URL secrets no longer leak via Unified Logging on HTTP 4xx
  (added `privacy: .private` to `NotificationIntegrations` log lines).
- `SupplyChainGate`'s 2-second-delayed SIGKILL closure no longer
  captures the actor's logger (uses a fresh `Logger` inline) so it
  can't dangle if the actor were deallocated.

### Tests

860 in 177 suites pass (was 807). +53 net: SafePIDValidator (9),
SupplyChainGate safety (13), DNSSinkhole allowlist (22 — including
the BLOCKER-fix protected-domain coverage), AlertSink contract (9 —
including a 50-concurrent-submit TOCTOU pin).

## [1.6.18] — 2026-04-25

Three-issue follow-up to v1.6.17.

### Fixed

- **FP on own daemon at install.** v1.6.17's Refresh Now button sends
  `pkill -USR1 com.maccrab.agent` / `maccrabd`, which tripped the
  `security_tool_killed` rule (had `maccrabd` in target list and no
  non-fatal-signal filter). Removed `maccrabd` from both rules
  (`security_tool_killed.yml` and `defense_evasion_kill_persist.yml`),
  added `filter_nonfatal_signal` (`-HUP`, `-USR1`, `-USR2`,
  `SIGHUP`, `SIGUSR1`, `SIGUSR2`) and `filter_maccrab_self` (excludes
  command lines naming our own daemons). Other security tools still
  alert as before.
- **Custom-import IOC validation.** `addCustomIOCs` /
  `loadCustomFile` accepted any string — a user pasting "TODO" got
  it inserted as a domain. Five new public validators
  (`validateHash`, `validateIP`, `validateDomain`, `validateURL`)
  reject malformed entries. Both import APIs now return an
  `ImportResult { accepted, rejected }`. Dashboard import flow shows
  "Imported N of M. Rejected K malformed: ..." status.
- **CFBundleShortVersionString drift.** `Xcode/project.yml` had been
  stuck at `1.6.4` since that release. `prerelease-check.sh` only
  validated `CFBundleVersion` so the drift went unnoticed for 13
  releases. Bumped to 1.6.18 + added `prerelease-check.sh` guard.

### New

- `ThreatIntelFeed.ImportResult` struct + return values from
  `addCustomIOCs(...)` and `loadCustomFile(path:type:)`.
- Public validators: `validateHash`, `validateIP`, `validateDomain`,
  `validateURL`. Used by both the daemon-side imports and the
  dashboard's local pre-validation.

### Tests

**807 pass (up from 801).** Six new in `ThreatIntelValidatorTests`.
Two existing cache tests updated to use real 64-hex-char SHA-256
fixtures.

## [1.6.17] — 2026-04-25

Threat Intelligence panel rebuilt for context. The v1.6.16 browser
exposed bare strings; v1.6.17 carries source / firstSeen / malware
family / tags / fileType per IOC, switches feeds from "_recent"
endpoints to full CSV exports (10–100× more IOCs), adds per-feed
health badges, a Refresh Now button (SIGUSR1 to daemon), and
per-category caps with 30-day age-based eviction.

### New

- **`ThreatIntelFeed.IOCRecord`** — per-IOC metadata struct replaces
  `Set<String>` storage. New `recordFor*` accessors return the full
  record for alert enrichment.
- **CSV-backed feeds** — Feodo full `ipblocklist.csv`, URLhaus
  `csv_online/`, MalwareBazaar `csv/recent/`. Brings family + tag +
  first-seen metadata that the txt endpoints don't carry.
- **Rich Browse IOCs rows** — color source chip, family pill, tags,
  fileType, first-seen date, hash compaction. Search matches across
  all fields. Picker shows per-category counts.
- **Per-feed health row** — green/orange/red badges + tooltip with
  last-success / last-error timestamp + reason.
- **Refresh Now button** — SIGUSR1 to the daemon triggers a one-shot
  feed refresh; AppState invalidates the mtime gate and re-decodes
  on the next poll.
- **Per-category caps + age eviction** — 200K hashes / 25K IPs /
  100K domains / 75K URLs hard caps, 30-day stale eviction. Custom
  imports pinned through both.
- **`SIGUSR1` handler** in `SignalHandlers` calls
  `state.threatIntel.refreshNow()`.

### Schema

`feed_cache.json` changed shape. Daemon rewrites within hours of
upgrade; dashboard may show "no cache yet" briefly until the first
v1.6.17 refresh completes.

### Tests

**801 pass.** Two existing `ThreatIntelFeedCachedStatsTests` cases
updated to drive a real `ThreatIntelFeed` actor through the new
encoder.

## [1.6.16] — 2026-04-25

Makes the Threat Intelligence panel actually inspectable. v1.6.15
wired `threatIntelStats` end-to-end, but the counts were the *only*
thing visible — no way to see what the loaded IOCs actually were or
what the IOC list had been catching.

### New

- **Browse IOCs tab** — category picker (Hashes / IPs / Domains /
  URLs), substring search, source attribution per category, capped
  virtualized list.
- **Recent Matches panel** — alerts from `maccrab.threat-intel.hash-match`
  and `maccrab.dns.threat-intel-match` rendered with kind chip,
  process, matched-value description, timestamp.
- **`ThreatIntelFeed.cachedIOCs(at:)`** static accessor exposes the
  full on-disk IOC set for the dashboard.
- Empty-state differentiates "no cache file yet" from "loaded zero
  IOCs" — points to Feeds tab for manual refresh.

### Tests

**801 pass** (up from 799). Two new in `ThreatIntelFeedCachedStatsTests`.

## [1.6.15] — 2026-04-25

A four-bundle audit-driven release. Closes the same "intent-vs-reality"
gap that bit v1.6.9 / v1.6.12 / v1.6.14 — every shipped feature now
has daemon code consuming or producing it. Adds the agent-activity
timeline view that substantiates the "MacCrab sees what your agents
actually did" positioning that has been aspirational since v1.6.7.

### Bundle A — Wire the orphans

- **`TriageService`, `LLMConsensusService`, `AgenticInvestigator`** were
  declared in `DaemonState` but had zero callers. Moved to `AppState` —
  outbound HTTPS with vendor API keys does not belong at root
  privilege when the dashboard already owns the LLM config.
  `TriageService` is now wired to `AlertDetailView` as a one-click
  "Get AI Triage Recommendation" with `suppress` / `keep` / `escalate`
  / `inconclusive` disposition + rationale.
- **`threatIntelStats`** was a published property nothing wrote to.
  `ThreatIntelView` rendered "Malicious Hashes/IPs/Domains/URLs: 0"
  forever. Wired to `ThreatIntelFeed.cachedStats(at:)` reading the
  daemon's IOC cache.
- **`alertClusterService` + `mcpBaselineService`** instantiated on
  `DaemonState` but never invoked. Removed — `ClusterSheet` already
  creates per-render copies and `MCPBaselineService` lacks its
  producer half.

### Bundle B — Cache eviction perf

- **`LLMCache`**: O(n log n) full-dict sort on every overflow → O(n)
  min-scan over existing `accessSeq` counter. Header doc now matches
  implementation.
- **`RuleEngine` + `SequenceEngine` regex caches**: the same O(n)
  `lastIndex+remove+append` LRU pattern that commit `de5ed04`
  replaced in `LLMCache` was still in both engines. At the 2048-entry
  cap and 420 rules under burst this was the dominant rule-eval cost.
  Both rewritten to O(1) hit promotion via sequence-number sidecar.

### Bundle C — Stop double-scanning

- **`SecurityToolIntegrations`**: daemon now writes
  `integrations_snapshot.json` at startup and refreshes hourly.
  `IntegrationsView` reads the snapshot first, falls back to a local
  scan when missing. `BrowserExtensionsView` left intentionally
  unchanged — the sysext can't reliably read user-home paths so the
  dashboard's local scan is the authoritative producer.

### Bundle D — Agent activity timeline

- **`AgentEvent` + `AgentSessionSnapshot` Codable**, new
  `LineageSnapshot` wrapper. Daemon writes
  `agent_lineage.json` every 30 s on the heartbeat tick.
- **New `AIActivityTimelineView`** rendered under AI Guard: session
  picker chips, per-session kind-counts, chronological event rows
  with kind-specific SF Symbols and severity-colored alert rows,
  inline cap with "Show all" disclosure. Empty-state lists the 8
  supported tools.

### Stability hardening

- In-flight guard on `AgentLineageService.writeSnapshot` so a slow
  disk can't pile up Tasks under the heartbeat timer.
- Atomic-swap race fixed: `moveItem` first, fall back to
  `removeItem + moveItem` only on conflict (matches the existing
  heartbeat-write pattern).
- mtime gate on `AppState.refreshAgentLineage` so the dashboard's
  10 s poll doesn't re-decode an unchanged 30 s file 2/3 of the time.
- Orphan `.tmp` cleanup on encoder error in both writers.

### Tests

**799 pass (up from 783).** Sixteen new across:

- `LLMServiceFactoryTests` (3) — disabled / claude-no-key /
  openai-no-key paths.
- `ThreatIntelFeedCachedStatsTests` (3).
- `SecurityToolIntegrationsSnapshotTests` (4).
- `AgentLineageSnapshotTests` (4) — full round-trip across all 6
  event kinds, plus the in-flight guard regression.
- `LLMCacheTests.evictsBulkOverflow` (1).

## [1.6.14] — 2026-04-24

Closes the end-to-end gap on the size-cap path: v1.6.12 wired the
daemon, v1.6.13 hardened it, v1.6.14 actually connects the dashboard
slider to the daemon and fixes two silent-decode bugs in
`daemon_config.json` parsing that had been voiding operator configs
for many releases.

### Surfaced bugs

- **Settings slider was inert.** `@AppStorage("maxDatabaseSizeMB")`
  and `@AppStorage("retentionDays")` wrote to the app's
  `UserDefaults` (`~/Library/Preferences/com.maccrab.app.plist`).
  Nothing copied those values to `daemon_config.json`, which is what
  the sysext reads. Operators who moved the slider got no behavior
  change — the sysext kept the 500 MB / 30 d defaults.
- **`daemon_config.json` decoder was silently broken.** Two
  compounding hazards: `JSONDecoder.keyDecodingStrategy =
  .convertFromSnakeCase` mangles trailing-uppercase abbreviations
  (`max_database_size_mb` → `maxDatabaseSizeMb`, but the property is
  `maxDatabaseSizeMB`), and Swift's auto-synthesized `Decodable`
  ignores stored-property defaults — every non-Optional field must
  be present. Either hazard caused a full decode failure, which
  `load()` swallowed via `try?` and returned `DaemonConfig()`. Any
  operator-supplied `daemon_config.json` (snake_case or partial) has
  been silently reverting to all defaults on every field since the
  feature shipped.
- **Size cap ignored WAL.** Enforcer measured only the main `.db`
  file. A 480 MB main + 40 MB WAL presented as "under cap" while
  consuming 520 MB on disk.
- **Orphan user-domain DB from pre-sysext dev runs.** After a
  reinstall, the sysext writes to `/Library/.../events.db` while
  old `~/Library/.../events.db` (sometimes hundreds of MB) lingered
  untouched. Dashboard's mtime-based DB picker could select the
  orphan.

### Fixes

- `SettingsView.swift`: slider `onChange` writes to
  `~/Library/Application Support/MacCrab/user_overrides.json` and
  sends `pkill -HUP com.maccrab.agent`.
- `DaemonConfig.decode()`: overlays the user's JSON dict onto a
  freshly-encoded defaults dict (handles partial configs) and
  rewrites known snake_case keys to exact camelCase before decode
  (handles trailing-uppercase mismatches). `applyUserOverrides()`
  merges the dashboard's overrides file, bounded to the two
  storage keys and gated by home-dir uid ownership.
- `SignalHandlers.swift`: SIGHUP now reloads `DaemonConfig` and
  kicks an immediate size-cap sweep when `maxDatabaseSizeMB` or
  `retentionDays` changed.
- `DaemonTimers.swift`: `measureDatabaseFootprintMB()` sums
  `db + db-wal + db-shm`. Prune and size-cap timers read the cap /
  retention live from `state` each tick so SIGHUP reloads are
  honored on the next sweep.
- `DaemonSetup.swift`: orphan-DB reaper renames stale (>24h)
  `/Users/*/Library/Application Support/MacCrab/events.db*` to
  `events.db.orphan-<stamp>*` at sysext startup — forensic
  evidence preserved, dashboard picker stops selecting the orphan.

### Tests

**783 tests pass (up from 776).** New suites:

- `DaemonConfigOverridesTests` — snake_case, camelCase, partial,
  and defaults decode paths all lock in.
- `DatabaseFootprintTests` — db-only, db+wal+shm, and missing-files
  footprint math.

### Upgrading

Install v1.6.14, open Settings → Storage Limit, set the cap you want.
The slider now writes to disk and SIGHUP triggers an immediate
sweep. `log show --predicate 'subsystem == "com.maccrab.agent"'
--last 5m | grep -i "storage config\|size-cap"` confirms the sysext
received the new value. No data migration.

## [1.6.13] — 2026-04-24

Hardens the size-cap enforcer landed in v1.6.12 against real-world
failure modes (low disk, WAL-invisible shrinks, concurrent
invocations). No detection-engine or user-visible-feature changes.

### Changed

- **Pre-flight disk-space check** — VACUUM requires scratch space
  ~= DB size; enforcer now queries
  `volumeAvailableCapacityForImportantUsage` and skips VACUUM with
  an explicit warning log when free disk < 1.3× current DB size.
  Row prune still happens; file shrink deferred to next tick once
  disk frees.
- **Single VACUUM per sweep** — moved out of the prune loop, so
  a big DB gets one full-file rewrite per hour instead of up to
  8×.
- **50% per-sweep deletion cap** — a misestimated overage can
  never wipe more than half the rows in one pass. DB converges to
  target across a few hours on heavily over-cap installs.
- **WAL checkpoint pair** — `wal_checkpoint(PASSIVE)` runs before
  and after VACUUM so the main `.db` file (what Settings reads)
  reflects the shrink. PASSIVE never blocks; escalates to RESTART
  only if the passive pass couldn't drain the WAL.
- **Reentrancy guard** — `EventStore.beginSizeCapPrune()` /
  `endSizeCapPrune()`. Hourly timer + on-demand entry points
  can't double-invoke. Enforcer uses `defer` for the release.
- **First-sweep delay 10 min → 15 min** — lets collectors,
  inventory scans, and baseline hydration settle before the
  enforcer competes for IO. Hourly cadence unchanged.
- **Startup confirmation log** — daemon now emits a single line
  on boot confirming the cap is armed, the target, and the
  current DB size. Operators can grep to verify.

### Tests

776 pass (up from 769). +7 hardening tests: reentrancy guard,
walCheckpoint safety + drainage, VACUUM+checkpoint interaction,
guard lifecycle with defer, concurrent-acquire honor, pruneOldest
independence from the guard.

## [1.6.12] — 2026-04-24

### Fixed

- **`maxDatabaseSizeMB` now actually caps the database size.** The
  field had been defined in `DaemonConfig` and surfaced in Settings
  since forever, but no code ever read it — retention was time-only
  (`retentionDays`). A field report showed the SQLite file at
  18.95 GB against a 500 MB configured cap. Fixed by:
  - Adding `EventStore.pruneOldest(count:)` — batch-deletes oldest
    events + FTS rows, 100K per batch with `Task.yield()` between.
  - Adding `EventStore.vacuum()` — runs `VACUUM` to reclaim pages
    into on-disk file size (without this, `DELETE` doesn't shrink
    the file).
  - New hourly `sizeCapTimer` in `DaemonTimers` that checks the
    `events.db` file size and iteratively prunes + vacuums until
    the file drops below 80% of the configured cap.
  - `DaemonState.maxDatabaseSizeMB` plumbed through from
    `DaemonConfig` (clamped at 50 MB minimum).

### Tests

769 tests pass (up from 764). +5 tests cover the new `pruneOldest`
and `vacuum` APIs including cumulative disk-usage shrinkage.

## [1.6.11] — 2026-04-24

Pre-publication hygiene release. No detection-engine changes — just
the release pipeline and CI posture being honest about what they do.

### Fixed

- **`MacCrab-v*.pkg` was broken in every release.** `productbuild`'s
  distribution XML referenced `#maccrab.pkg` while the actual
  component pkg is named `maccrab-component-$$.pkg`. Result: a
  valid-looking 1.9 KB xar archive that installed nothing. Fixed by
  removing the PKG path entirely — `scripts/release.sh` and
  `.github/workflows/release.yml` no longer call `build-pkg.sh` and
  the asset is dropped from GitHub release uploads. DMG + Homebrew
  are the supported install paths.

### Changed

- **PR workflow permissions hardened.** `.github/workflows/build.yml`
  and `rules.yml` now declare `permissions: contents: read` at the
  workflow level. Previously inherited the default `contents: write`
  scope which gave fork-PR runners more than they needed.
- **Release scripts checked in.** `scripts/release.sh`,
  `scripts/build-release.sh`, and `scripts/notarize.sh` are now
  tracked so CI and fresh clones can run the release pipeline.
  Configuration is read from environment variables at runtime.
  `scripts/build-pkg.sh` remains gitignored and was removed locally.

## [1.6.10] — 2026-04-24

Three FP patterns surfaced by an overnight soak after v1.6.9 shipped.
Each one has a structural fix rather than an allowlist addition — the
same pattern: anchor on something the vendor can't rename around.

### Fixed

- **`hidden_file_created.yml` re-scoped to unsigned/adhoc only.**
  v1.6.5's Logitech vendor allowlist kept failing as Logitech renamed
  its binaries. Replaced with `selection_signer: SignerType in
  [unsigned, adHoc]` — every developer-ID-signed vendor peripheral
  agent is now excluded at the selection stage, no allowlist needed.
  Terminal-launched editors writing dotfiles still bypass via a
  `filter_terminal_parent`.
- **`c2_beacon_pattern.yml` filters developer-ID-signed
  `/Applications/` apps.** "Keynote Creator Studio" (3rd-party paid
  app) fired 3× in 5h because its 1-hour dedup window expired between
  beacons. Added `filter_devid_applications` — drops matches where
  the process is devId-signed AND installed in `/Applications/`.
  Covers paid app licensing / analytics / update HTTPS without
  allowlisting each vendor by name. Unsigned dropper-staged binaries
  still fire.
- **`PowerAnomalyDetector.knownLegitimate` adds `dasd`.** Duet
  Activity Scheduler is macOS's background-task scheduler; power
  assertions are its entire job. Added `dasd` + companions
  (`xpcproxy`, `ScheduleProxy`, `BackgroundTask`,
  `signpost_reporter_activity`) plus always-on cloud-sync clients
  (`Dropbox`, `OneDrive`, `Google Drive`, `iCloud Drive`, `Box`,
  `Boxclient`) that were missed in the v1.4.5 pass.

### Tests

764 tests pass (up from 761). +3 regression tests covering the
compiled-rule signer anchor, the devId+Applications filter
translation, and the live-scan dasd suppression.

## [1.6.9] — 2026-04-24

The architectural FP fix that ends the v1.6.x `networkserviceproxy`
thread, plus a security + performance audit pass on the v1.6.6 AI
Suite.

### Fixed

- **NoiseFilter now applies to every detection layer.** The
  longstanding `networkserviceproxy` credential-exfil FP was
  caused by `EventLoop` calling `NoiseFilter.apply` ONLY against
  Layer 1 (Sigma) matches — Layer 2 (Sequence) and Layer 3
  (Baseline / Behavioral Composite) matches were appended to the
  match list AFTER the filter ran, bypassing every gate we'd
  added since v1.6.2. Moved the call to after all three layers
  append.

### Added (security hardening — from audit)

- **`MCPBaselineService` DoS caps.** New `maxBaselines` (default
  256) and `maxSetSize` (default 512) parameters. Rotating
  `serverName` spoofing now triggers LRU eviction at the service
  level; per-server file/domain/child sets cap at `maxSetSize`.
- **`AgenticInvestigator` input validation.** `extractParam` caps
  values at 256 chars; `isSafeRuleId` rejects path separators and
  shell meta-characters; `isSafeProcessPath` rejects path traversal
  and control characters; `alert_descriptions` caps batch size at
  20 rule IDs per call.

### Changed (performance — from audit)

- **NoiseFilter gate reorder.** Gate 7 (Apple platform binary —
  O(1) bool check) runs first instead of seventh. Majority of Mac
  events short-circuit at the cheapest gate, bypassing the O(N-
  ancestors) Gate 6. Estimated ~40% CPU cut under burst.
- **NoiseFilter short-circuits.** `guard !matches.isEmpty` and
  `allSatisfy(.critical)` exits before the first gate in the
  cases where no gate could possibly change the outcome.
- **EventLoop AI-child fast path.** `AIProcessTracker.hasActiveSessionsHint`
  — a nonisolated, lock-protected Bool mirror of `sessions.isEmpty`.
  When no AI tools are running the whole AI-child detection block
  is skipped, saving ~3 actor hops per event on idle machines.
- **`AgentLineageService` ring buffer.** Replaced `[AgentEvent]` +
  `removeFirst(n)` with a fixed-capacity circular `EventRing`. O(1)
  append, O(1) overflow drop. Old code memmoved the entire tail on
  every overflow.

### Tests

761 tests pass (up from 748). +13 new tests covering the sequence
match regression, MCPBaseline cap enforcement under DoS-style
input, AgenticInvestigator input validation, and NoiseFilter
short-circuits.

## [1.6.8] — 2026-04-24

FP backstop closing out the v1.6.x discovery-rule thread, first AI
Suite dashboard surface, and two UI fixes for the allowlist manager
and campaign-card tap behavior.

### Fixed

- **NoiseFilter Gate 7: Apple platform binary backstop.** The recurring
  `/bin/ps`, `/usr/bin/defaults`, `/usr/bin/csrutil`, `/usr/bin/sw_vers`,
  and `/usr/sbin/system_profiler` FPs now suppress at the engine level
  regardless of rule-level filters. Gate 7 fires when the event's
  subject is flagged `isPlatformBinary`, code-sig-enriched as Apple,
  or running from a SIP-protected path prefix. Critical rules still
  fire.
- **`c2_beacon_pattern.yml` filter_apple_signed.** Keynote, Pages,
  Numbers, Mail, and every other Apple-bundled `/Applications/` app
  no longer fires the regular-interval beacon pattern when they make
  their routine iCloud syncs. Added `filter_apple_signed: SignerType:
  'apple'` to the rule.
- **Allowlist "Manage" button count vs content mismatch.** Button
  label previously used `AppState.suppressionPatterns.count` (v1
  legacy pattern list), dialog rendered v2 `SuppressionManager` entries
  from disk. Now `AppState.allowlistEntryCount` is authoritative and
  sourced from the same `SuppressionManager` the dialog uses;
  refreshed on every poll and on dialog dismiss.
- **Campaign row tap doesn't expand.** Only the header-HStack button
  toggled expand; clicking the summary text or tactics pills did
  nothing. Wrapped the collapsed-region VStack in `.contentShape(Rectangle())`
  + `.onTapGesture { onToggle() }` so every pixel toggles. Expanded-
  area buttons (Dismiss / Restore / Copy Details) sit outside the
  tap block so they retain their own hit regions.

### Added

- **`ClusterSheet`** — first UI surface for the v1.6.6 `AlertClusterService`.
  Opened from AlertDashboard's toolbar ("Clusters" button), groups the
  current alert list by `ruleId::processName` fingerprint, shows size
  + max severity + tactics union + first/last-seen per cluster.
  Expanded rows show contributing alerts; "Suppress all in cluster"
  bulk-silences every member in one click.

### Tests

748 tests pass (up from 741). +7 new tests for Gate 7 including
counter-tests (critical-on-ps still fires; non-Apple `/tmp/evil`
still fires at medium). Two pre-existing Gate 5 tests updated to
reflect Gate 7 interplay.

## [1.6.7] — 2026-04-24

Follow-up to v1.6.6's AI Suite: credential-audit hardening, EventLoop
wiring for the new services, first MCP tool for the Suite.

### Added

- **`LLMSanitizer` now redacts every known API-key shape** — Anthropic
  (`sk-ant-…`), OpenAI (`sk-…` / `sk-proj-…`), Google (`AIza…`), AWS
  (`AKIA…`/`ASIA…`/`AGPA…`/etc.), GitHub (`ghp_…`/`gho_…`/`ghu_…`/
  `github_pat_…`), Slack (`xox[aboprs]-…`), and generic `Bearer` tokens
  — regardless of surrounding context. Previously these were only
  caught when embedded in a recognized flag (`--api-key=…`).
- **IPv6 private-range redaction** — link-local (`fe80::/10`) and
  unique-local (`fc00::/7`) now redact to `[PRIVATE_IPV6]`. Public
  `2001:db8::` is preserved.
- **Mac `ComputerName` redaction** — `Peters-MacBook-Pro`,
  `Corp-Ops-iMac`, etc. redact to `[COMPUTER_NAME]`. Scoped to Mac
  product keywords so ordinary hyphenated prose passes through.
- **`OllamaBackend.isPlaintextRemote` guard** — refuses to send a
  Bearer token to a non-loopback host over plain `http://`, logs a
  diagnostic explaining how to fix (use `https://` or drop the key).
- **`cluster_alerts` MCP tool** — stateless alert clustering over the
  persisted alert DB, exposed to AI agents via the MCP server. Takes
  `hours` and `min_severity` filters, returns clusters with size,
  max severity, MITRE tactics union, first/last-seen timestamps.

### Changed

- **`LLMConfig` gains `CustomStringConvertible`/`debugDescription`**
  that masks API keys as `<len=N,first=X,last=Y>`. Accidental
  `print(config)` or `String(describing: config)` no longer dumps
  secrets via Mirror reflection.
- **`EventLoop` now routes AI-child events into `AgentLineageService`**
  automatically — file I/O, network connections, and process spawns
  under an AI-tool ancestor populate the timeline without any
  caller action. Fresh sessions start when an AI-tool process is
  seen; process spawns in its subtree record chronologically.
- **`DaemonState` gains six fields for the v1.6.6 AI Suite services**
  so EventLoop, polling timers, and MCP handlers can reach them
  through the standard `state.*` plumbing.

### Tests

**741 tests pass (up from 719).** +22 new tests covering
`LLMSanitizer` API-key redaction, IPv6 private ranges, Mac
ComputerName matching, `LLMConfig` description masking, and the
`OllamaBackend` plaintext-remote guard.

## [1.6.6] — 2026-04-23

The biggest AI push in the codebase yet. Six independent services
land in this release — every one covered by unit tests, every one
feature-flaggable, every one designed around MacCrab's unique kernel
vantage: **what agents actually do on the machine**, not just what
they say to the model.

### Added

- **`AlertClusterService`** (`Sources/MacCrabCore/Detection/`) —
  Deterministic-first alert clustering by `ruleId::processName`
  fingerprint. Optional on-demand LLM rationale pass for clusters
  the analyst expands. 11 unit tests.

- **`LLMConsensusService`** (`Sources/MacCrabCore/LLM/`) — Fan out
  a classification prompt to N configured backends in parallel;
  declare consensus only when ≥ threshold backends agree on a
  non-inconclusive label. Per-backend timeouts prevent the slowest
  from gating the result. 17 unit tests.

- **`TriageService`** (`Sources/MacCrabCore/LLM/`) — Single-backend
  disposition recommender. Produces one of `suppress / keep /
  escalate / inconclusive` with a one-sentence rationale. Advisory
  only; no auto-action. 12 unit tests.

- **`MCPBaselineService`** (`Sources/MacCrabCore/AIGuard/`) —
  Runtime behavioral fingerprint per MCP server (file basenames,
  DNS domains, child-process basenames). Dual-gate promotion
  (observation count AND wall-clock window) from `learning` to
  `enforcing`. Broadcasts `BaselineDeviation` via AsyncStream. 9
  unit tests.

- **`AgentLineageService`** (`Sources/MacCrabCore/AIGuard/`) —
  Chronological timeline of LLM API calls, process spawns, file
  I/O, network connections, and alerts per AI tool session.
  Per-session ring buffer, LRU session eviction. 9 unit tests.

- **`AgenticInvestigator`** (`Sources/MacCrabCore/LLM/`) — Bounded
  multi-round loop over a campaign with three tool calls
  (`describe_rule`, `alert_descriptions`, `process_children`) the
  LLM can issue to pull local context. Returns a structured
  `InvestigationReport` (verdict, summary, up to 5 findings,
  recommended action). 12 unit tests.

### Tests

**719 tests pass (up from 649).** +70 new tests across six feature
suites. Zero modifications to existing public APIs; each service
wires in as an opt-in dependency.

## [1.6.5] — 2026-04-23

Continuation of the v1.6.x FP-reduction thread. Eight distinct noise
patterns surfaced by overnight test-machine soak; four are fixed at the
engine level (new ancestor-walk gate), four at the rule level.

### Fixed

- **New NoiseFilter Gate 6: auto-updater ancestor walk.** v1.6.4's
  per-rule `ParentImage|contains 'GoogleUpdater'` filters only caught
  the immediate parent. Real chains nest deeper —
  Chrome → GoogleUpdater → launcher → GoogleUpdater → profiles — so
  `profiles`'s parent is the second GoogleUpdater but MDM-enrollment
  still fires. The new gate walks the full ancestor list, dropping
  non-critical matches whenever the subject or any ancestor is a
  known auto-updater (Sparkle, GoogleUpdater/Keystone, Microsoft
  AutoUpdate, `softwareupdated`, Homebrew). Critical still fires.

- **`isKnownBenignProcess` split into `isAutoUpdater` + daemon check.**
  The previous single helper mixed Apple-system-daemon paths with
  auto-updater paths; using it for ancestor-walk filtering swept in
  Terminal.app as "benign" and would silently disable detection for
  anything launched from a terminal. The narrower `isAutoUpdater`
  variant excludes Apple system paths and is the one used by
  Gate 6. Campaign detector continues to use the broader
  `isKnownBenignProcess` where "is this an OS component or updater?"
  is the right question.

- **TCC bypass rule allow-lists auto-updaters.** GoogleUpdater
  spawned from `/Applications/Google Chrome.app/` matched
  `selection_bundle_path` but the updater binary lives under
  `~/Library/Application Support/Google/…`, so
  `filter_developer_signed: Image|startswith '/Applications/'`
  didn't apply. Added explicit `filter_auto_updater_image` and
  `filter_auto_updater_endswith` covering GoogleUpdater, Sparkle,
  Keystone, Microsoft AutoUpdate, and the `launcher` basename.

- **Credential-theft sequence rule adds Apple-daemon basename
  filter.** `/usr/libexec/networkserviceproxy` fired
  `credential_theft_exfil` at CRITICAL despite the existing
  `filter_system_path`. The sequence engine's per-step filter
  evaluation can race with SignerType enrichment, so the cred_read
  step now also anchors on 16 well-known Apple daemon basenames
  (nsurlsessiond, trustd, apsd, accountsd, identityservicesd,
  cloudd, bird, fileproviderd, keychainsharingmessagingd, …).

- **Discovery-rule platform-path backstop.**
  `process_listing_by_unsigned.yml`, `defaults_read_sensitive.yml`,
  `system_enumeration_burst.yml`, and `csrutil_status_check.yml` now
  carry a `filter_system_path: Image|startswith` list covering
  `/bin/`, `/sbin/`, `/usr/bin/`, `/usr/sbin/`, `/usr/libexec/`,
  `/System/`. This is belt-and-braces with `filter_platform`
  (`PlatformBinary: true`) — field data showed PlatformBinary
  enrichment isn't always populated when ES events arrive before
  code-sig resolution settles. Since these paths are SIP-protected
  on a healthy system, a hard path anchor is a safe guarantee.

- **Hidden-file rule hardware-vendor allow-list.** Logitech Options+
  (`logioptionsplus_agent`) writes per-user dotfiles for state.
  Added `filter_hw_vendor_bundle: Image|startswith` for
  `/Library/Application Support/` subdirs Logitech, Razer, Elgato,
  Corsair, SteelSeries, Blackmagic, plus `/Applications/Logi Options+
  .app/` and `/Applications/Logitech*`. Vendor binaries rename
  frequently (`logi_agent` → `LogiMgrDaemon` → `logioptionsplus_agent`)
  so anchoring on install path is more durable than basename matching.

### Tests

649 tests pass (up from 643). New `AutoUpdaterAncestorGateTests`
suite (6 tests) locks in Gate 6: GoogleUpdater-as-subject suppressed,
`profiles` under 4-deep GoogleUpdater chain suppressed, Sparkle
Autoupdate ancestor suppressed, critical-under-updater still fires
(counter-test), non-updater ancestors NOT suppressed (counter-test),
public API exposed for detector reuse.

## [1.6.4] — 2026-04-23

Field-driven FP reduction in alerts and campaigns. Three structural bugs
and two rule-content fixes surfaced by user dogfooding after v1.6.2 shipped.

### Fixed

- **Coordinated-attack campaign no longer fires on single alerts with
  multi-tactic tags.** A rule carrying both `attack.discovery` and
  `attack.defense_evasion` (e.g., csrutil-status) counted as "2 tactics
  from 1 process" and triggered `Coordinated Attack from single process`
  despite only a single underlying event. The detector now requires ≥2
  distinct rule IDs before cross-tactic correlation kicks in.
  (`CampaignDetector.swift` — both PID and path branches.)

- **Campaign detector allow-list broadened to cover auto-updaters and
  package managers.** New `isKnownBenignProcess` helper covers Sparkle's
  `Autoupdate` binary (any path containing `Sparkle.framework/` or
  `.sparkle-project.Sparkle/Installation/`), Google's `GoogleUpdater` /
  `GoogleSoftwareUpdate` / `Keystone`, Microsoft AutoUpdate, macOS
  `softwareupdated` / `SoftwareUpdateNotificationManager`, and Homebrew.
  Previously those binaries produced repeated `Coordinated Attack` and
  `Kill Chain` campaigns during routine update cycles.

- **Kill-chain threshold raised 3 → 4.** Three distinct tactics within
  a 10-minute window was trivially hit on developer machines running
  everyday admin commands (ps / lsof / find + csrutil status + curl).
  Four tactics is a materially stronger signal while still matching
  real multi-stage attack shapes (discovery → credential_access →
  persistence → exfiltration).

- **`csrutil_status_check.yml` restricted to status-like commands.**
  The rule previously fired on any csrutil invocation; when a user ran
  `csrutil disable`, BOTH that rule AND `sip_check_before_tampering.yml`
  fired on the same event, producing two alerts tagged `discovery` and
  `defense_evasion` respectively. Now only fires on `status`, `netboot`,
  `authenticated-root status`, `--help`.

- **`mdm_enrollment_check.yml` excludes auto-updater processes.** Google's
  Updater runs `profiles status -type enrollment` as a legitimate
  MDM-awareness check before applying a Chrome/Drive update. Added filters
  for GoogleUpdater, GoogleSoftwareUpdate, Sparkle, SoftwareUpdate, and
  `launcher` parent processes.

### Tests

643 tests pass (up 5) — new `CampaignDetectorFPRegressionTests` locks in
the single-alert-multi-tag gate, the Sparkle + GoogleUpdater allow-list,
and the kill-chain threshold. Counter-test proves two distinct alerts on
the same process still fire coordinated-attack (the detector isn't just
turned off).

## [1.6.3] — 2026-04-23

Bring back the 🦀 menu-bar icon after immediate user feedback on v1.6.2.

### Fixed

- **Menu-bar icon is a crab again.** v1.6.2 replaced the emoji 🦀 with a
  template-rendered `shield.lefthalf.filled` SF Symbol for "proper" macOS
  styling — but the crab is the brand. Restored the emoji; kept the
  accessibility label ("MacCrab" / "MacCrab — protection degraded") and
  the degraded-state variant (⚠️🦀). Severity flash now prepends a
  colored severity dot to the crab (🔴🦀 for critical, 🟠🦀 for high)
  instead of replacing it with a shield.

## [1.6.2] — 2026-04-23

Dashboard polish release. Adds a theme system matching maccrab.com, proper
About panel with a website link, SF Symbol statusbar icon, and a set of
smaller fixes surfaced by three parallel specialist review agents
(SwiftUI architecture, macOS-native UX, a11y+performance).

### Added

- **`MacCrabTheme`** (new `Sources/MacCrabApp/Theme/MacCrabTheme.swift`) —
  ports maccrab.com's CSS custom properties verbatim: base/elevated/card
  backgrounds, border pairs, text primary/dim/mute, `accent`/`accentHot`/
  `accentDim`, `accentGhost` overlays, and severity palette. Each value
  ships Light + Dark variants via an `NSColor` dynamic provider so the
  dashboard tracks the system appearance setting. Applied via
  `.tint(MacCrabTheme.accent)` at the scene root so every native control
  (buttons, links, toggles, progress views, date pickers) picks up the
  brand orange automatically.

- **About MacCrab panel with maccrab.com link** — new
  `CommandGroup(replacing: .appInfo)` invokes a styled About panel with
  a clickable maccrab.com link in the credits, version + build, and
  CaddyLabs copyright. Plus a new Help menu with "Visit maccrab.com",
  "MacCrab Documentation", and "Report an Issue…" entries.

- **SF Symbol status-bar icon** — replaces the emoji 🦀 with template-
  rendered `shield.lefthalf.filled` (healthy) or
  `shield.lefthalf.filled.trianglebadge.exclamationmark` (degraded), so
  the icon adapts to light/dark menu bar automatically. Severity flash
  uses palette-rendered red/orange system shields.

### Fixed

- **Alert popover `.white` background** — `MacCrabApp.swift:284` now uses
  `NSColor.windowBackgroundColor` so the critical-alert NSPanel respects
  Dark Mode instead of floating bright white.
- **Hardcoded RGB severity colors in OverviewDashboard** — replaced with
  `MacCrabTheme.severityCritical` / `.severityHigh` / `.ok`.
- **`eventsPerSecond` churn** — idle polls no longer re-publish the same
  value; full-app view invalidation on a quiet system drops from "every
  10 s" to "when it actually changes."
- **AlertDashboard filter churn** — single-pass lazy filter replaces the
  three-stage `.filter → .map → .filter → .filter` chain. Each keystroke
  in the search box now does ~1× array traversal instead of 3–4×, and
  the intermediate AlertViewModel allocation on every pass is gone.
- **Poll timer lifecycle** — `AppState.startPolling()` / `.stopPolling()`,
  wired to `.onChange(of: scenePhase)`. Closing the dashboard window (or
  backgrounding the app) now pauses the 10-second DB poll.
- **Reduce Motion parity** — `CampaignView.swift:158, 181` and
  `AIAnalysisView.swift:243` expand/collapse now respect
  `\.accessibilityReduceMotion`.

### Changed

- `Info.plist` gains `LSApplicationCategoryType`, `NSHumanReadableCopyright`,
  `NSFullDiskAccessUsageDescription`, `NSLocalNetworkUsageDescription`,
  and an expanded `NSMicrophoneUsageDescription` — Security & Privacy
  panel now shows meaningful strings for every permission.
- `SuppressionManagerView` migrated from `.onAppear { Task { await ... } }`
  to `.task { await ... }` (auto-cancels on view dismount).
- Alert popover's `DispatchQueue.main.async` call site migrated to
  `Task { @MainActor in ... }` idiom.

## [1.6.1] — 2026-04-23

Field-driven noise reduction. v1.6.0 user dogfood showed 19 identical alerts
per 48h on a developer machine — all Xcode-session false positives. This
release fixes the structural and content issues behind that pattern.

### Fixed

- **Forensic-loop alerts now go through the AlertDeduplicator.** CrashReportMiner,
  PowerAnomalyDetector, and LibraryInventory in `DaemonTimers.swift` were
  inserting directly into AlertStore, bypassing `shouldSuppress(ruleId:processPath:)`.
  A long-lived process emitting the same finding on every forensic scan now
  suppresses correctly after the first alert.

- **LibraryInventory skips legitimate debug/build workflows.** Process allow-list
  (`lldb-rpc-server`, `lldb`, `debugserver`, `Instruments`, `xctest`, `XCTRunner`)
  + Xcode.app path prefix + build-artifact pattern match (`.debug.dylib`,
  `/DerivedData/`, `/.build/debug/`, `/target/debug/`). Also an internal
  `(pid, library)` pair dedup so the same loaded dylib can't re-alert across
  scan cycles even if the outer dedup window expires.

- **`c2_beacon_pattern.yml` filters developer tools.** Added `/usr/bin/` (where
  curl/wget/git/python live), `/Applications/Xcode.app/Contents/Developer/`,
  `/Library/Developer/CommandLineTools/`, and `/sbin/` to `filter_system`.
  Severity downgraded medium → low (timing-variance analysis not actually
  implemented in a Sigma rule; flagged in description for a future sequence
  rule). Eliminates the Xcode-git-pull "alert storm" campaign trigger.

- **CrossProcessCorrelator: dev-workflow allow-list.** New `allEventsAreDevWorkflow`
  gate in `evaluateNetworkChain` — skips convergence alerts when every
  contributing process is under `/Applications/GitHub Desktop.app/`,
  `/Applications/Xcode.app/`, `/Library/Developer/CommandLineTools/`,
  `/opt/homebrew/`, or is one of a small allow-list of exact paths
  (`/usr/bin/git`, `/usr/bin/curl`, `/usr/bin/wget`, `/usr/bin/ssh`). Also
  wires dedup around the convergence-alert emission path in `EventLoop.swift`.

- **Six high-FP-likelihood Sigma rules gained `filter_terminal` + `filter_apple_parent`.**
  `command_and_control/curl_to_raw_ip.yml`, `command_and_control/python_http_server.yml`,
  `command_and_control/netcat_listener.yml`, `command_and_control/ngrok_or_tunnel.yml`,
  `discovery/sensitive_file_search.yml`, `credential_access/ssh_key_file_read.yml`.
  Also added IDE + backup-tool filters to the SSH key rule.

### Tests

638 tests pass (up from 636) — 2 new regression tests in
`LibraryInventoryAllowlistTests.swift` that compile-time-lock the allowlist
members so a future refactor can't silently remove them.

## [1.6.0] — 2026-04-23

Minor release: new shape-based detection class + battery-aware polling +
analyst-triage CLI + three new detection rules + metrics export.

### Added

- **TopologyAnomalyDetector** (`Sources/MacCrabCore/Detection/TopologyAnomalyDetector.swift`).
  A new detection class, complementary to the existing Markov-chain
  `ProcessTreeAnalyzer`: shape-based categorical invariants over process
  lineage. Fires on `launchd_spawned_shell`, `system_process_spawning_
  staged_binary`, `anomalous_process_fanout` (20+ children from one parent
  in ≤10s), and `deep_process_descent` (depth > 15). No commercial macOS
  EDR does this class of detection — it catches attacks that use
  legitimate tools in illegitimate shapes. Emits via BehaviorScoring so
  the scoring / alert fan-out / suppression pipelines work unchanged.

- **PowerGate** (`Sources/MacCrabCore/Utilities/PowerGate.swift`).
  Battery + thermal state gate for poll-based collectors. Exposes
  `PowerGate.adjustedInterval(base:)` / `adjustedInterval(base:aggressiveness:)`
  that stretches poll intervals under low-power mode or thermal pressure.
  Wired into `ClipboardMonitor` (aggr 2.0), `USBMonitor` (aggr 2.0),
  `NetworkCollector` (aggr 1.0), `EDRMonitor` (aggr 1.0). Expected 15–25%
  battery-day improvement on laptops in low-power mode.

- **`maccrabctl why <alert_id>`** — new CLI subcommand that prints the
  compiled rule's predicates alongside the alert's captured fields so
  an analyst can see exactly why a rule fired without spelunking through
  YAML. Also handles synthetic alerts (`maccrab.behavior.*`,
  `maccrab.topology.*`, `maccrab.campaign.*`, `maccrab.self-defense.*`)
  by explaining the indicator family.

- **Metrics export** — sysext now writes `/var/tmp/maccrab.metrics.json`
  every 30 s alongside the heartbeat. Prometheus-textfile-style counters
  (`events_total`, `alerts_total`, `uptime_seconds`, `sysext_has_fda`,
  `power_state`) for external scraping.

### New detection rules

- `persistence/system_launchdaemon_plist_replaced.yml` — writes to
  `/System/Library/LaunchDaemons/` by non-Apple-signed processes (classic
  rootkit persistence after SIP bypass).
- `defense_evasion/network_extension_unsigned_install.yml` — unsigned
  NEPacketTunnelProvider / NEDNSProxyProvider installs. Allow-lists the
  major legitimate VPN and endpoint-security vendors.
- `persistence/dock_persistence_entry_written.yml` — non-terminal process
  running `defaults write com.apple.dock persistent-apps` (Dock-injection
  persistence).

Total rule count: **420** (378 single-event + 38 sequences + 4 topology
invariants emitted as synthetic alerts).

### Changed

- CLAUDE.md: rule count 417 → 420, test count 628/135 → 636/136.
- README.md: test badge 628 → 636.

## [1.5.5] — 2026-04-23

FDA banner fix v4 — architectural redesign + manual dismiss escape hatch.

### Fixed

- **Sysext FDA state is now reported by the sysext, not inferred by the app.**
  v1.5.2 through v1.5.4 all tried to detect sysext FDA by reading TCC.db
  from the app process. That approach is fundamentally broken: the system
  TCC.db (`/Library/Application Support/com.apple.TCC/TCC.db`, where the
  sysext's FDA grant actually lives) is mode `600 root:wheel` PLUS TCC-gated
  — a non-root process cannot open it regardless of its own FDA.

  The sysext runs as root and CAN reliably probe its own FDA by trying to
  read the system TCC.db (TCC gates the open, so success implies FDA). It
  now does this on every 30 s heartbeat tick and writes the result into
  `heartbeat.json` as `sysext_has_fda`. The app reads that field as the
  authoritative signal. The v1.5.2–1.5.4 TCC.db probe + WAL heuristic are
  kept as fallbacks for legacy sysexts that haven't written a schema v2
  heartbeat yet.

- **"Dismiss — I've granted access" button added to the FDA banner.**
  Escape hatch so the user is never stuck behind a stale banner if our
  detection fails again. The dismissal is persisted to UserDefaults and
  auto-cleared once detection later confirms both principals have FDA,
  so a future FDA revocation still re-surfaces the banner.

- Heartbeat schema bumped to version 2 (adds `sysext_has_fda` and
  `fda_checked_at_unix` fields). App handles v1 heartbeats gracefully via
  the fallback path.

## [1.5.4] — 2026-04-23

Install UX + hardening: suppress false tamper alert on first launch,
harden TCC.db probe, tighten FDA client match, correct documentation drift.

### Fixed

- **No more `rules_modified` tamper alert on fresh install.** SelfDefense
  now suppresses rules-directory write alerts during a 60-second startup
  grace window, covering the RuleBundleInstaller copy and DaemonSetup's
  `sequences/` subdir creation. Each write rebaselines the hash silently
  during the window; writes after the window keep the original hash
  comparison + critical-alert behavior. Also added a public
  `SelfDefense.snapshotRules()` entry point for a future Sparkle-upgrade
  sentinel flow.

- **TCC.db probe now rejects symlinks.** `querySysextFDAInDB` in AppState
  now calls `lstat` before `sqlite3_open_v2` (matching the existing pattern
  in EventStore / AlertStore). Closes a theoretical read-redirect attack
  where an attacker with write access to `/Library/Application Support/com.apple.TCC/`
  could swap the DB for a symlink.

- **FDA client match tightened.** Replaced the broad `LIKE 'com.maccrab.agent%'`
  clause with an explicit `IN ('com.maccrab.agent', 'com.maccrab.agent.systemextension')`
  set so future bundle IDs under that prefix don't get silently treated as
  the sysext.

### Changed

- Documentation: DocsView tactic count 16→17 (adds missing "Wireless" row),
  CLAUDE.md tactic directory count 18→17, README test count badge alignment
  (588 → 628 in body text).

## [1.5.3] — 2026-04-23

Fix sysext FDA detection: query both user and system TCC.db; widen WAL fallback to 30 min.

### Fixed

- `sysextHasFDA` detection now checks `/Library/Application Support/com.apple.TCC/TCC.db`
  (system-level) in addition to the user-level TCC.db — macOS stores the
  Endpoint Security extension FDA grant in the system DB on some builds.
  A `LIKE 'com.maccrab.agent%'` clause handles any `.systemextension` suffix
  variant seen across OS versions. Either database matching clears the banner.
- WAL mtime fallback window extended from 5 minutes to 30 minutes for the
  case where neither TCC.db is readable (app hasn't been granted FDA yet).
  A quiet system with no recent events no longer incorrectly shows the
  sysext as needing FDA.

## [1.5.2] — 2026-04-22

Dashboard UX fixes: reliable Full Disk Access detection and drag-to-install DMG.

### Fixed

- **Full Disk Access banner now clears immediately after both grants.**
  The sysext FDA check was using a WAL file mtime heuristic that tested
  whether the sysext was actively writing to disk, not whether it actually
  had FDA. When the app gains FDA it now queries `TCC.db` directly for the
  sysext's `auth_value` row — authoritative and instant. The banner updates
  within one 10-second poll cycle after each grant.

- **FDA banner redesigned as a two-row checklist.**
  Instead of switching between three paragraphs of text, the banner now
  shows "MacCrab ○/✓" and "MacCrab Endpoint Security Extension ○/✓" so
  users can see at a glance which grant is still pending after completing
  one of the two steps. The "Reveal MacCrab in Finder" button is now
  conditional — only shown when the app itself needs FDA (dragging from
  Finder is useful for the app; for the sysext entry, the list already
  contains it automatically).

- **DMG now shows the classic drag-to-Applications install window.**
  The release DMG was missing an `/Applications` symlink in the staging
  directory, so Finder opened it as a plain folder. Added the symlink so
  users see the standard side-by-side drag install UI.

## [1.5.1] — 2026-04-22

False positive fixes in 6 detection rules. No new detections, no Swift
source changes, no schema changes. 628 tests pass.

### Fixed

- `ssh_agent_access_suspicious`: condition changed from OR to AND — now
  fires only when python3/curl/wget/node specifically open `SSH_AUTH_SOCK`,
  not on any file access by those processes. Was the source of spurious HIGH
  alerts and cascading campaign noise on developer machines.
- `csrutil_status_check`: removed `attack.defense_evasion` tag. A single
  csrutil execution was contributing two MITRE tactics, triggering a
  "Coordinated Attack from single process" campaign on its own.
- `mdm_enrollment_check`: added `filter_terminal` so `profiles status` run
  interactively from any shell no longer fires.
- `hidden_file_created`: added image-path filter for Logitech Options+
  (`logioptionsplus_agent`, `LogiMgr`) which legitimately writes dotfiles
  in the user home directory.
- `process_listing_by_unsigned`: expanded terminal filter to include Cursor,
  VS Code, node, and ruby as known benign parents.
- `system_enumeration_burst`: same terminal filter expansion plus new
  `filter_apple_child: SignerType: apple` to suppress Apple-signed system
  tools (e.g. `system_profiler`, `scutil`) launched by non-terminal parents
  such as software installers.

## [1.5.0] — 2026-04-22

Major detection expansion: 37 new rules (417 total), 3 new sequence rules
(38 total), 2 new CLI commands, 18 new tests (628 total), and deep LLM
analysis for high-severity campaigns.

### Added

- **37 new Sigma-compatible rules** across exfiltration (rclone, cloud
  provider CLI, messaging API data upload, ICMP tunnel, paste service),
  lateral movement (Bonjour/mDNS host discovery, AirPlay to non-Apple
  receiver), and wireless/container/impact/supply chain tactics.
- **3 new sequence rules**: archive-then-cloud-exfil chain (T1560+T1567),
  LLM API key harvest+exfil (CanisterWorm pattern, T1552+T1041), and
  TEMPEST prep chain (SDR launch + outbound transfer, T1125+T1048).
- **`maccrabctl vulns`** — dedicated subcommand surfacing CVE scanner
  alerts (`maccrab.vuln.*`) with CVE ID, severity, affected app, and
  remediation detail. Supports `--hours` and `--severity` filters.
- **`maccrabctl privacy`** — dedicated subcommand surfacing egress
  anomaly alerts (`maccrab.privacy.*`) with human-readable labels
  (Bulk Egress / Domain Spike / Tracker Contact). Supports `--hours`.
- **Extended thinking** (`LLMBackend.completeWithExtendedThinking`):
  Claude Opus 4 backend uses `interleaved-thinking-2025-05-14` for
  deep campaign analysis. All other backends fall back to regular
  `complete()` transparently. `EventLoop` activates deep analysis for
  HIGH/CRITICAL campaigns with ≥3 distinct tactics.
- **UEBA weekday/weekend split**: per-user hour buckets are now
  maintained separately for weekdays and weekends. Off-hours severity
  escalation (0–4h and 22–23h = high, 5–6h and 19–21h = medium,
  7–18h = low). Backward-compatible Codable; existing profiles load
  with zeros for new fields.
- **VulnerabilityScanner → alert store**: critical/high CVEs emit
  `Alert` objects with deterministic IDs (`vuln-<cveId>`) that
  deduplicate via `INSERT OR REPLACE` across hourly scans.
- **AppPrivacyAuditor → alert store**: hourly egress anomaly checks
  emit medium alerts with deterministic IDs (`privacy-<process>-<kind>`).
- **DoH resolver expansion**: 28 IPs now detected (was 16). Added
  Cloudflare for Families (1.1.1.2/1.1.1.3), Quad9 IPv6, OpenDNS IPv6,
  AdGuard IPv6, Mullvad, ControlD, DNS.SB, and Comodo Secure DNS.
- **AppPrivacyAuditor tracking domains** expanded from 20 to 70+
  (Amplitude, Heap, Pendo, PostHog, Braze, Datadog, New Relic, Firebase,
  FullStory, LogRocket, LaunchDarkly, and more).

### Changed

- Three supply chain rules with unsupported count aggregation
  (`developer_credential_bulk_harvest`, `pip_install_triggers_credential_harvest`,
  `process_scans_for_llm_tools`) have the count expression removed
  (silently dropped by compiler). Replaced with stronger process filters.
  Severity reduced from critical → high/medium to reflect single-access
  detection threshold.
- Two sequence rules fixed for invalid `|not|` Sigma modifier
  (`keylogger_install_and_persist`, `package_typosquat_full_chain`).

## [1.4.9] — 2026-04-22

Same-day hotfix for a CampaignDetector FP surfaced after 1.4.8.

### Fixed

- **`CampaignDetector.checkCoordinatedAttack` skips trusted
  browser helpers.** Google Chrome Helper was triggering a
  HIGH "Coordinated Attack from single process" campaign
  spanning `credential_access` + `exfiltration` tactics during
  normal Chrome sync (reading its own Cookies / Login Data
  DBs and uploading to Google). Individual rule matches were
  already suppressed by NoiseFilter Gate 3, but the campaign
  path counted tactics one tier up. Added early-return for
  `NoiseFilter.isTrustedBrowserHelper(path:)` parallel to the
  existing `isAppleSystemDaemon` skip.

## [1.4.8] — 2026-04-22

Discovery-rule filter-gap fix, USB hub noise, CTK error-line
parsing.

### Added

- **`PlatformBinary` Sigma field** mapped to
  `process.is_platform_binary` in `Compiler/compile_rules.py`.
  Directly reads the ES-framework-provided platform bit without
  depending on the code-signing enrichment path (which returns
  nil for short-lived Apple CLI tools and silently breaks
  `SignerType: 'apple'` filters).

### Fixed

- **Discovery rules firing on Apple CLI tools from shell
  parents.** `filter_platform: PlatformBinary: 'true'` added
  to `system_enumeration_burst`, `xpc_service_enumeration`,
  `csrutil_status_check`, `process_listing_by_unsigned`, and
  `defaults_read_sensitive`. The existing `filter_apple:
  SignerType: 'apple'` silently failed when code-sign
  enrichment returned nil, allowing launchctl / system_profiler
  / defaults / ps / csrutil to fire when run from a Terminal
  shell.

- **USB device class `0x09` (hub) suppressed for
  informational.** Third-party USB hubs (Realtek, VIA, Intel
  chipsets) are not a credible exfil vector and churned on
  every replug and USB-C mode change. Mass-storage still
  surfaces regardless of vendor.

- **`SystemPolicyMonitor` skips pluginkit error lines.**
  `match: Connection invalid` and similar pluginkit status
  output was being parsed as CTK plugin bundle IDs and
  surfacing as informational alerts. New filter on
  `Connection invalid`, `Operation not permitted`, `No such`,
  `error`.

## [1.4.7] — 2026-04-22

Alert detail now surfaces the triggering event, and two more
v1.4.6-field-test FPs close.

### Added

- **Triggering Event panel in AlertDetailView.** The detail
  view now fetches the originating `Event` by id (via new
  `AppState.fetchEvent(id:)`) and renders command line, PID,
  signer + team id, parent process, ancestor chain, file path,
  destination endpoint, and TCC service fields. `AlertViewModel`
  gained an `eventId` field. Tamper / USB / clipboard alerts
  with no backing Event omit the section.

### Fixed

- **`SelfDefense` no longer flags attrib changes on non-critical
  paths.** sysextd stamps xattrs on the sysext executable every
  install + activation cycle, triggering "MacCrab Tamper
  Detection: Config Modified" at HIGH on the daemon's own
  binary. Only the LaunchDaemon plist and compiled-rules
  directory still escalate on attrib.
- **`plist_written_to_library.yml` filters browser helpers and
  Developer-ID-signed processes.** `filter_apple_signed`
  broadened to `apple | appStore | devId`. New
  `filter_browser_helper` covers Chrome / Chromium / Firefox /
  Safari / Edge / Arc / Brave / Opera / Vivaldi bundles.
  Fixes the Google-Chrome-from-`/var/folders/` → `~/Library/
  Google/Chrome/.../*.plist` FP.

## [1.4.6] — 2026-04-22

Same-day FP hotfix after v1.4.5 landed. Six false positives
observed on a real MacBook Pro — all six closed. No new
detection added; each change removes one specific FP class.

### Fixed

- **`credential_theft_exfil.yml` no longer fires on Apple system
  daemons.** Added step-level `filter_apple` (SignerType=apple)
  and `filter_system_path` to the `cred_read` step. Previously
  `networkserviceproxy` (Apple-signed, `/usr/libexec/`) was
  firing Critical on legitimate cred-path reads followed by the
  daemon's normal network activity.
- **`CrossProcessCorrelator` ignores rotated system logs.**
  New `hasRotatedLogSuffix` helper recognises `*.log.N`,
  `*.log.N.gz`, `*.log.N.bz2`. `/private/var/log/` and
  `/var/log/` added to `ignoredPathSubstrings`. `.log.bz2`
  added alongside `.log.gz`. Fixes the 3-process chain on
  `newsyslog` rotating `wifi.log.0`.
- **Apple VID 0x5AC USB events suppressed entirely for
  non-mass-storage.** Built-in keyboard, trackpad, camera,
  touchbar, T2 churn on every sleep/wake — filtered upstream
  of the rate limiter. Mass storage still surfaces regardless
  of vendor.
- **`csrutil_status_check.yml` adds `filter_terminal` step.**
  Previously filtered only `ParentImage|startswith /System/`;
  shell-parent csrutil from Terminal now suppressed.
- **`system_enumeration_burst.yml` adds `filter_terminal`
  step.** Covers shell-launched `whoami` / `uname` / `sw_vers`
  / `ifconfig` / `launchctl` from Terminal, which the
  `SignerType apple AND /System/ parent` filter missed.
- **`process_listing_by_unsigned.yml` filter_terminal includes
  shell basenames.** Added bash / zsh / sh / fish / dash
  alongside the existing Terminal.app bundle list.

## [1.4.5] — 2026-04-21

Waves B and C of the 1.4.x quality pass, shipped together. Wave B
addresses noise sources observed on a real MacBook Pro developer
workstation running v1.4.4. Wave C is a noise-severity rebalance
and a set of correctness fixes across the rule pack, sequence
engine, and UI-state persistence.

### Changed

- **Severity recalibration sweep.** 16 single-event rules moved
  from `level: critical` to `level: high` because their current
  selectors produce too many false positives on a developer
  workstation for a pager-level signal. Still actionable at HIGH,
  still aggregatable into a campaign. Rules affected:
  `memory_dump_credential_tools`, `ai_tool_downloads_script`,
  `crypto_miner_process`, `wifi_attack_tool`, `keychain_cli_extract`,
  `git_credential_helper_abuse`, `sensitive_file_read_untrusted`,
  `microphone_access_unsigned`, `pkg_downloads_and_executes`,
  `ai_tool_prompt_injection`, `rosetta_binary_from_downloads`,
  `endpoint_security_slot_exhaustion`, `shadow_hash_access`,
  `ssh_launched_security_dump`, `ai_tool_writes_persistence`,
  `keylogger_event_tap_active`. Total critical-level rules drops
  from 81 → 65.
- **`trojan_source_bidi_code.yml` deprecated.** The rule fires on
  any source-file write (`.py`, `.js`, …) without actually
  inspecting content for Unicode bidi overrides — no `FileContent`
  field reference. Status flipped to `deprecated`; compiler marks
  the rule `enabled: false` so it keeps its id/suppressions but
  the engine skips it. File kept for future reimplementation once
  the collector exposes content.
- **Four sequence rules now declare correlation explicitly.**
  `cron_install_then_exec`, `download_then_cryptominer`,
  `ransomware_kill_chain` get `correlation: process.lineage`.
  `usb_drop_then_exec` gets `correlation: file.path`. Rule-level
  correlation for `process.lineage` is loose (accepts all,
  precision comes from step-level `processRelation`); the
  declaration documents intent and locks the contract so future
  rule-engine tightening applies cleanly.

### Fixed

- **`CampaignDetector.checkLateralMovement` requires a real
  lateral-movement alert.** Previous trigger was ≥2 user contexts
  in the campaign window, which fires on every dev workstation
  (root daemon alert + user process alert = 2 user contexts). Now
  requires at least one contributing alert tagged with
  `lateral_movement` tactic *and* ≥2 user contexts. Real SSH /
  VNC / ARD launches across users still fire; idle dual-context
  noise stops.
- **`AppState.writeUIState` uses temp + rename.** The UI state
  writer (suppressions, suppressed IDs) previously wrote in place
  — a crash between open and close left a half-written JSON file
  that silently wiped the user's suppressions on next read. Now
  writes to `<filename>.tmp` and renames into place, matching the
  pattern DaemonTimers already uses for `heartbeat.json`.
- **`PowerAnomalyDetector.knownLegitimate` expanded.** Added
  `useractivityd`, `appleh13camerad`, `applecamerad`, `Signal`,
  `nsurlsessiond`, `AssetCacheLocatorService`, `AssetCache`,
  `mobileassetd`, `assetsubscriptiond`, `SEPAuthSession`,
  `SmartCardServices`, plus meeting apps `Google Meet`, `Zoom`,
  `Cisco Webex`. Every entry validated against observed field FPs.
- **`SystemPolicyMonitor` CryptoTokenKit alerts no longer fire
  HIGH on legitimate auth hardware.** New `trustedCTKProviders`
  substring list covers Yubico, 1Password, OneSpan, Thales,
  Entrust, Gemalto, OpenSC, mTrust. Unknown CTK extensions drop
  from HIGH to `.informational`.
- **USB alert rate limiting** via new `USBRateLimiter` actor in
  `MacCrabAgentKit`. Tracks `(vid:pid:direction)` tuples and
  suppresses duplicates within 24h per session. Mass-storage
  bypasses the limiter. Eliminates the per-hub-replug spam.
- **`BehaviorScorer.addRuleMatch` skips contributions from trusted
  browser helpers.** `NoiseFilter.isTrustedBrowserHelper(path:)`
  check at the scoring source. Fixes the "Google Chrome Helper
  accumulated suspicious behavior score of 10.8" HIGH alert
  driven by false `sigma_rule_match_critical` contributions.
- **NoiseFilter Gate 5 recognizes shell-binary ancestors as
  interactive.** New `shellAncestorBasenames` set (bash/zsh/sh/
  fish/dash/ksh/tcsh/csh) added to `isInteractiveTerminalAncestor`.
  Covers cases where the ES ancestor chain doesn't reach
  Terminal.app but the immediate parent is a shell.
- **`ssh_agent_access_suspicious.yml` adds `filter_terminal`.**
  Excludes parents of `/bash`, `/zsh`, `/sh`, `/fish`, `/dash`
  so dev work (Paramiko, Ansible, Fabric, `git clone` via ssh)
  stops firing HIGH alerts.

## [1.4.4] — 2026-04-21

Same-day hotfix for v1.4.3 — a user on v1.4.3 immediately saw the new
storage-error banner fire on a single transient `SQLITE_BUSY` during
WAL checkpoint, which is too noisy. Two changes close the gap.

### Fixed

- **`PRAGMA busy_timeout = 5000`** added in `EventStore.openDatabase`,
  `AlertStore.openDatabase`, `CampaignStore.openDatabase`. Default was
  0 (no retry), so any transient lock contention — e.g., a background
  WAL autocheckpoint briefly holding the write lock while an event
  insert queued — returned `SQLITE_BUSY` immediately. With 5s the
  insert waits for the checkpoint to complete and proceeds cleanly.
  Standard SQLite multi-writer best practice.
- **Storage-error banner threshold tuned.** New
  `AppState.hasConcerningStorageError(snap)` replaces the v1.4.3
  `hasRecentStorageError`. Requires ≥5 total write failures AND the
  most recent within 120s (was: any failure within 600s). Keeps the
  banner a signal for real persistent issues — disk full,
  permissions, corruption — without firing on single transients.

## [1.4.3] — 2026-04-21

Wave A of the 1.4.x quality pass — "fail loud, not silent". Five
protection-guarantee failure modes where MacCrab looked fine while
not actually protecting the user get made visible: zero-rules-loaded,
sysext crashed/hung, storage writes failing, sysext silently replaced
by a no-op, rules tampered post-install.

### Added

- **`DetectionHealthBanner`** (`Sources/MacCrabApp/Views/OverviewDashboard.swift`)
  — reusable critical/warning banner shared by four new protection-health
  states. Keeps the Overview from accumulating bespoke one-off banners
  when new health signals land.
- **`AppState.isProtectionDegraded`** aggregates health signals. The
  statusbar crab flips between `🦀` (healthy) and `⚠️🦀` (degraded)
  via a 5s-cadence timer in AppDelegate.
- **Heartbeat timer in sysext** (`DaemonTimers.swift`). Writes
  `/Library/Application Support/MacCrab/heartbeat.json` every 30s
  via a temp+rename pattern so readers never catch a half-written
  file. Payload: written_at, uptime, events/alerts counters.
- **`refreshHeartbeat`, `refreshStorageHealth`, `refreshRuleTamper`**
  in `AppState.refresh()`. Three sysext-written JSON snapshots
  polled every 10s.
- **Watchdog callback** wired from MacCrabApp.onAppear →
  `AppState.sysextWatchdogActivate`. When heartbeat has been stale
  ≥120s and we haven't retried in the last 5min, AppState calls
  `sysextManager.activate()` to respawn via OSSystemExtensionRequest.
  Idempotent; cooldowned.
- **Rule-manifest SHA-256 verification** in `RuleBundleInstaller`.
  `build-release.sh` now generates `manifest.json` listing SHA-256
  of every compiled rule. `verifyManifest(at:)` runs on both the
  bundled and installed trees on every launch; mismatch → refuse to
  sync (bundled tampered) or auto-resync (installed tampered) plus
  a `rule_tamper.json` snapshot the dashboard polls.
- **Fail-loud banners** surface all four signals on Overview:
  zero-rules, stale heartbeat, storage errors, rule tamper. Each
  with actionable body text and an appropriate SF Symbol icon.

### Changed

- **`StorageErrorTracker.writeSnapshot()`** persists every storage
  failure to `/Library/Application Support/MacCrab/storage_errors.json`.
  Before v1.4.3 these only hit os_log, invisible to anyone not
  running `sudo log show`.
- **`DaemonTimers.Handles`** gains `heartbeatTimer: DispatchSourceTimer`.
  Seven periodic timers total now (was six).

### Developer notes

- `scripts/build-release.sh` post-`compile_rules` step emits
  `compiled_rules/manifest.json` with SHA-256 hashes. Every release
  DMG from now forward will ship a manifest; pre-v1.4.3 bundles
  without one are accepted by `verifyManifest` to preserve upgrade
  paths.
- Three new snapshot files to be aware of under
  `/Library/Application Support/MacCrab/`: `heartbeat.json`,
  `storage_errors.json`, `rule_tamper.json`. All sysext-written, all
  user-readable. Safe to delete on support calls — they're
  regenerated on the next tick.

## [1.4.2] — 2026-04-21

Fixes the update-channel gap that prevented v1.3.11-v1.4.1 rule
improvements from reaching Sparkle-updated users. Ships five
noise-reduction gates validated against v1.4.1 field data.

### Fixed

- **Compiled rules now ship inside `MacCrab.app/Contents/Resources/
  compiled_rules/`.** New `RuleBundleInstaller.syncIfNeeded()` runs
  at app launch (before `AppState` init). It compares the bundled
  `.bundle_version` marker against
  `/Library/Application Support/MacCrab/compiled_rules/.bundle_version`;
  when bundled is newer it removes the installed tree, copies the
  bundled one in place, and `pkill -HUP`'s the detection engine so
  the new rule JSON takes effect without relaunching. Fixes the
  root cause of v1.4.1 field data showing pre-v1.3.11 rule bugs —
  the Homebrew cask's postflight, which used to be the only copy
  path, doesn't run on Sparkle updates.
- **`CrossProcessCorrelator` new shell-utility gate.** Chains where
  ≥80% of participants are small shell helpers (bash / ruby / curl /
  git / dirname / readlink / env / locale / cat / 30 others) AND
  ≥4 distinct utilities AND no `execute` action are dropped at
  evaluation time. A `brew reinstall` fired 3,000+ chain events
  in 30 seconds in v1.4.1 field data; this gate drops them. A
  real curl→bash download-and-run attack has only 2 utilities +
  execute action so it still fires.
- **`CrossProcessCorrelator.ignoredPathSubstrings` expanded.**
  Added `/dev/tty`, `/dev/pts/`, `/dev/ttys` (the "sudo+zsh
  touched /dev/ttys000" 62-hit FP is a shell writing your
  password prompt to your terminal). Also `/private/tmp/homebrew-`,
  `/private/tmp/brew-`, `/private/tmp/d20`, `/opt/homebrew/var/`,
  `/opt/homebrew/Cellar/`, `/usr/local/Homebrew/`,
  `/usr/local/Cellar/`.
- **`CampaignDetector.checkKillChain` excludes USB and
  crypto-token-kit alerts from tactic contribution.** Plugging in
  a YubiKey produced "5 tactics, 14 alerts Multi-Stage Attack"
  campaigns in field data. `maccrab.usb.*` and
  `maccrab.deep.crypto_token_extension` no longer count.
- **`CampaignDetector.checkCoordinatedAttack` skips Apple system
  daemons.** Processes under `/usr/libexec/`, `/System/Library/`,
  `/System/Applications/Utilities/` don't emit coordinated-attack
  campaigns even when they span multiple tactics. User's 24h
  field window had 15+ bogus campaigns — all xpcproxy,
  mobileassetd, usernoted, rtcreportingd, nsurlsessiond.
- **`credential_theft_exfil` sequence rule lowered from critical
  to high.** Critical bypasses NoiseFilter Gate 3 (trusted-
  browser-helper suppression), so every Chrome Helper reading its
  own Cookies DB and uploading to Google fired at critical. At
  high, Gate 3 drops the match on browsers — a non-browser doing
  credential-read→upload still fires at high. 22 critical FPs
  eliminated in field data.

### Added

- **Three new CrossProcessCorrelator regression tests** lock the
  new behaviour: brew-install shell-utility chain suppressed,
  curl→evil-binary chain still fires, `/dev/ttys000` terminal
  I/O not correlated.

## [1.4.1] — 2026-04-21

Hotfix: Sparkle update sheets rendered v1.4.0's Markdown release notes as
raw text. Sparkle's `<description>` field is HTML, not Markdown. Also
adds diagnostic logging to suppression save/load paths so a user report
that survived the v1.3.12/v1.4.0 fix has a trail to follow.

### Fixed

- **Sparkle update sheet renders release notes as HTML.**
  `scripts/generate-appcast-entry.sh` now runs `RELEASE_NOTES/vX.Y.Z.md`
  through a pure-Python Markdown→HTML converter (`scripts/_md_to_html.py`)
  before embedding the result in the appcast's CDATA `<description>`.
  GitHub releases keep rendering the same file as Markdown.
  Converter handles headings, paragraphs, bulleted lists, **bold**,
  *italic*, `code`, [links](#), and horizontal rules — the subset we
  use. Extend the script if new constructs appear.

### Added

- **Suppression persistence diagnostics.** `saveSuppressedIDs`,
  `loadSuppressedIDs`, `saveSuppressPatterns`, `loadSuppressPatterns`,
  `readUIState`, `writeUIState`, and `suppressAlert` now emit
  `os_log` info/notice/error records under subsystem
  `com.maccrab.app` category `ui-state`. Showing path chosen, bytes
  written/read, and counts loaded on every save/load. Users reporting
  "suppressions come back after update" can run
  `sudo log show --subsystem com.maccrab.app --predicate
  'category == "ui-state"' --last 1h` to produce a diagnostic trail.
- **One-shot on-load migration.** `loadSuppressedIDs` now rewrites
  the state to `uiStateDir` immediately if it found the file only at
  the legacy `dataDir` location. Next launch hits the stable path on
  the first try.

## [1.4.0] — 2026-04-21

Broad quality-of-life release. Noise-reduction pass, stability fixes,
new UX surfaces, enterprise MDM profile template, and a reproducible
release-hygiene checklist. v1.3.12 is rolled in rather than shipped
independently — its suppression-persistence fix is the first item
below.

### Fixed

- **Dashboard UI state survives app upgrades.** Suppression IDs and
  rule/process suppression patterns are now anchored to a stable
  user-home directory (`uiStateDir`) instead of the volatile
  `dataDir` that flips between user and system paths after every
  sysext write. Previously every upgrade silently discarded
  suppressions because the non-root dashboard couldn't write to the
  root-owned system dir. Legacy state is read from the old location
  on first launch and migrated automatically.
- **CampaignStore now rejects symlink DB paths.** Matching the guard
  EventStore and AlertStore already had; closes a privilege-
  escalation path where a swapped DB symlink could redirect
  root-owned writes.
- **Sysext crash-write failures are logged, not swallowed.** 14
  `try?` call sites in `MonitorTasks.swift` now route failures
  through `StorageErrorTracker.shared.recordAlertError` so a crash
  mid-alert leaves a forensic trail in Unified Log.
- **PRAGMA failures are logged across EventStore / AlertStore /
  CampaignStore.** A failed `journal_mode = WAL` used to silently
  drop the store to rollback-journal mode; operators now see the
  return code + error message under `sudo log show`.
- **dataDir fail-loud when both DBs are unreadable.** New `isReadableFile`
  checks replace `fileExists` so dataDir doesn't return a path the
  dashboard can't actually read. Logs a warning when permissions
  problems are evident (system DB exists but non-root app can't read).
- **Flaky `CollectorTests` lifecycle race.** 10 monitor lifecycle
  tests routed through a new `withStartedMonitor` helper that
  guarantees `stop()` runs even if the body throws. Previously a
  cancelled `Task.sleep` left the monitor running and polluted
  later test state — the "1 issue" flake reported on first runs.

### Added

- **NoiseFilter Gate 5: interactive admin CLI.** Drops non-critical
  matches on a curated set of admin binaries (ps, lsof, defaults,
  dscl, csrutil, system_profiler, spctl, profiles, etc.) when any
  process ancestor is a desktop terminal emulator (Terminal, iTerm,
  Warp, Alacritty, kitty, WezTerm, Hyper, Tabby, Ghostty) or a
  multiplexer (tmux, screen, byobu, zellij). 5 new regression tests
  in `InteractiveAdminGateTests`.
- **Alert retention control.** Settings → Detection Engine →
  Retention exposes `AlertStore.prune(olderThan:)` as a one-click
  "Clear alerts older than N days" (7 / 30 / 90 / 365).
- **Copy as Markdown.** `AlertDetailView` gains a Copy-as-Markdown
  button alongside Copy Details. Formats severity as bold, wraps
  identifiers in code spans, links MITRE technique IDs to
  attack.mitre.org, and uses ATX-style headings for paste into
  tickets / Slack / incident docs.
- **Keyboard Shortcuts reference.** New section in DocsView
  enumerates every in-app keyboard shortcut.
- **One-click sysext activation in WelcomeView.** Step 3's button
  now reads "Enable Protection" (instead of "Get Started") when the
  sysext isn't activated yet, and kicks off
  `OSSystemExtensionRequest` directly instead of sending the user
  to the Overview tab to find the button themselves.
- **`maccrabctl rule enable|disable <id>`.** CLI subcommand to
  toggle a compiled rule's `enabled` flag without rebuilding or
  deleting the YAML. Writes the JSON and prompts SIGHUP.
- **MacCrab.mobileconfig template for MDM deployment** (`deploy/`).
  Pre-authorizes the sysext, grants FDA to both app + sysext,
  registers MacCrab as a managed login item. Full deployment
  walkthrough in `deploy/README.md`.
- **`RELEASE_CHECKLIST.md` + `scripts/prerelease-check.sh`.** The
  release pipeline now runs the checklist as step 0: version sync
  across project.yml / plists / README / CHANGELOG, RELEASE_NOTES/
  file presence + non-trivial content, rule compile success,
  localization coverage per locale, SPM pin discipline. Release.sh
  refuses to sign if any hard check fails.

### Changed

- **Cross-process correlator suppresses more vendor paths.** Added
  Adobe / Creative Cloud / JetBrains / Zoom / 1Password / Firefox /
  Notion / Obsidian / iCloud Drive (Mobile Documents) / Time Machine
  volumes / Homebrew temp / dev-tool fan-outs (`.npm`, `.yarn`,
  `.gradle`, `.m2`, `.venv`, `__pycache__`) to `ignoredPathSubstrings`.
- **evaluateFileChain now applies the same homogeneity gates
  evaluateNetworkChain had.** Chains where every event shares the
  same executable path, app bundle, tool-version directory, trusted
  helper lineage, or process name are dropped at evaluation time.
  Belt-and-braces over v1.3.10's path filter.
- **Kill-chain detection ignores Low-severity tactics.** Previously
  `Multi-Stage Attack` fired when `recentAlerts` spanned three
  distinct MITRE tactics — easily triggered by three Low-severity
  discovery rules. Now only medium+ severity alerts contribute to
  the tactic set.
- **Discovery-rule severity recalibration.** 6 discovery rules
  dropped from Medium / High to Low: `bluetooth_scanning_tool`,
  `dscl_user_enumeration`, `ioreg_hardware_enum`, `lsof_network_enum`,
  `process_listing_by_unsigned`, `debugger_evasion_check`.
  `edr_remote_session_active` dropped from High to Medium.
- **Compiler honours `status: deprecated`.** Rules marked deprecated
  still compile (so rule browser + existing suppressions keep
  working) but ship `enabled: false` so the engine skips them.
- **"Daemon" → "Detection Engine"** in three remaining UI strings
  missed in the v1.3.9 rename sweep: Settings Response Actions
  save toast, status-bar fallback label, Integrations fleet-help
  copy.
- **`.mcp.json` now carries an explicit comment** explaining the
  dev-vs-release path split so end users understand the file is
  pointed at a local build and need to edit it when registering
  the Homebrew-installed binary.

## [1.3.12] — 2026-04-21

Hotfix: suppressions reset after upgrade.

### Fixed

- **Dashboard UI state no longer lives in `dataDir`.** `saveSuppressedIDs`,
  `loadSuppressedIDs`, `saveSuppressPatterns`, `loadSuppressPatterns`,
  and the LLM-config-detected read in `AppState.swift` all went through
  `dataDir`, which resolves to either `~/Library/Application Support/MacCrab/`
  (user home, dashboard-writable) or `/Library/Application Support/MacCrab/`
  (system, root-only, sysext-writable) depending on which `events.db` was
  most recently modified. After each sysext upgrade the system DB's
  modification time jumps, `dataDir` flips to the system path, and every
  `try? json.write(...)` from the non-root dashboard silently fails.
  Next app launch reads from the flipped-to directory, finds no
  suppressions file, and wipes the in-memory set. All previously dismissed
  alerts reappear on every upgrade. Anchored UI state to a new
  `uiStateDir` that is always the user-home MacCrab subdir; added a
  legacy-path fallback in the read path so existing users migrate
  automatically on first load.

### Added

- **`RELEASE_NOTES/v{VERSION}.md` convention.** Polished user-facing
  release notes now live in a dedicated directory and are the default
  source for Sparkle update sheets and GitHub release descriptions.
  The CHANGELOG remains the authoritative developer history;
  `scripts/generate-appcast-entry.sh` prefers the polished file over
  the CHANGELOG extract when it exists.

## [1.3.11] — 2026-04-21

Major noise-reduction release driven by field data from a real workstation:
one user reported 1,144 cross-process alerts and a flood of ~32 wifi-attack /
22 invisible-unicode / 14 EDR-remote-session alerts over 24 hours, all
false positives. Root cause turned out to be a **Sigma compiler bug** that
collapsed `selection_A or selection_B` into a flat `any_of` across every
predicate, so any command with `-s` / `scan` / `connect` / `live-response`
in its argv fired rules it had no business firing. Plus two UX bugs and a
bulk-action gap.

### Fixed

- **Sigma compiler preserves intra-selection AND semantics** under OR.
  `_needs_condition_tree` in `Compiler/compile_rules.py` now forces the
  hierarchical-tree compilation path when any clause of a pure `or`
  condition references a selection with more than one field/value pair.
  Previously those rules compiled to a flat `"condition": "any_of"` list
  which matched on ANY single predicate — so:
  - `wifi_attack_tool` at **critical** matched every commandline
    containing `-s` or `scan` (spctl, Chrome Helper, GoogleUpdater).
  - `edr_remote_session_active` at **high** matched every commandline
    containing `connect` (xpcproxy, every `ssh` invocation).
  - `gatekeeper_override` at **high** matched every spctl invocation
    regardless of `--add` / `--master-disable` flag context.
  After the fix the compiled JSON emits a proper nested
  `condition_tree: or → group[all_of]` structure that the runtime
  already knew how to evaluate. All 380 rules recompiled; 3 noisy
  rules now fire only in their intended narrow contexts.
- **Sidebar Alerts badge no longer counts campaigns twice.**
  `AppState.swift` had five separate `dashboardAlerts.filter { … }`
  recomputes of `totalAlerts` and `recentAlerts`, none of which
  excluded campaign-prefixed ruleIds. Campaigns ship as alerts
  with `ruleId: maccrab.campaign.*` and have their own sidebar
  badge. All five call sites consolidated into a single
  `refreshAlertBadges()` helper that also filters out the
  campaign prefix. Net: Alerts badge is now alert-only;
  Campaigns badge unchanged.
- **CrossProcessCorrelator file chains get the same homogeneity
  gates network chains had.** `evaluateFileChain` now also skips
  chains where `allEventsShareExecutable`, `allEventsShareAppBundle`,
  `allEventsShareToolDirectory`, or `allEventsAreTrustedHelpers`
  is true, plus a new `allEventsShareProcessName` check. This is
  the belt-and-braces defense underneath v1.3.10's path filter —
  even if a new vendor-dir path slips past the substring list, a
  chain where every event comes from the same process identity is
  worker fan-out, not attacker convergence.

### Changed

- **`invisible_unicode_in_source` rule marked `status: deprecated`.**
  Rule claimed to detect zero-width characters in source writes, but
  its YAML selectors only checked filename extension — there was no
  `FileContent|matches` regex. Every JSON/YAML/py/md write by a
  non-Apple-signed process was firing it at medium. Re-enable when
  the compiler supports content-based regex matching.
- **Compiler honours Sigma `status: deprecated`.** Deprecated rules
  still compile (so the rule browser and suppression state keep
  working for existing alerts) but ship with `enabled: false` so
  the RuleEngine's hot-path loop skips them.

### Added

- **Bulk-dismiss for campaigns.** `CampaignView` gains a Select /
  Cancel toggle; in select mode each active campaign card shows
  a checkbox. A "Dismiss N Selected" toolbar action pipes to a
  new `AppState.suppressAlerts(Set<String>)` batch method — one
  DB loop, one badge refresh, no flicker on 20-item dismisses.
  Delete-key dismisses selected, Escape cancels.
- **UPGRADE.md documents manual DMG upgrade semantics.** Clarifies
  that drag-n-drop replace triggers `OSSystemExtensionRequest`
  `.replace` automatically on next launch; recommends Sparkle /
  Homebrew for cleaner coordinated handover.

### Rule browser

- Top 3 rules by flat-`any_of` hit count pre-fix, by actual process
  (24h on one machine): `wifi_attack_tool` → spctl (8), GoogleUpdater
  (6), Chrome Helper (4); `edr_remote_session_active` → xpcproxy (8),
  GoogleUpdater (6); `gatekeeper_override` → spctl (8), GoogleUpdater
  (6). All drop to zero hits on the new compiler output because the
  intra-selection AND is restored.

## [1.3.10] — 2026-04-20

Noise-reduction hotfix for a v1.3.9 false positive. Field testing
turned up "13 processes, 140 events, 106s" cross-process chain alerts
fired by `GoogleUpdater` repeatedly writing to its own
`~/Library/Application Support/Google/GoogleUpdater/updater.log` from
multiple worker PIDs. Every event in the chain was a write or
close_modified against a log file inside a single vendor's own
state directory — indistinguishable from attack convergence to the
correlator, but semantically nothing more than a noisy logger.

### Fixed

- **CrossProcessCorrelator ignores `.log`/`.crash`/`.ips` files.** Log
  files don't carry payloads; an attack doesn't propagate through a
  log write. Adding these as ignored path suffixes at the correlator's
  ingress gate stops the 100-plus-event chains that legitimate vendor
  loggers were producing. New `ignoredPathSuffixes` set in
  `CrossProcessCorrelator.swift`.
- **CrossProcessCorrelator ignores noisy vendor app-support + cache
  paths.** Added a substring-match list covering
  `Library/Application Support/Google/`, `/Microsoft/`,
  `/CrashReporter/`, `/Code/` (VSCode), `/Slack/`, `/Spotify/`,
  `/Dropbox/`, `/iCloud/`, `/MobileSync/`; plus user-home
  `/Library/Caches/`, `/Library/Logs/`, `/Library/Preferences/`,
  `/Library/HTTPStorages/`, `/Library/WebKit/`,
  `/Library/Saved Application State/`, `/Library/Cookies/`, and
  `/Library/Metadata/CoreSpotlight/`. Also dev-tooling fan-outs
  `/.git/`, `/node_modules/`, `/.pnpm/`, `/.cargo/`, `/.rustup/`. New
  `ignoredPathSubstrings` set — substring rather than prefix so
  `/Users/<u>/Library/...` matches without per-user variants.
- **Four regression tests in `CrossProcessCorrelatorTests`** lock the
  behaviour: the exact GoogleUpdater 13-process scenario, a generic
  `.log` suffix, a sweep across Caches/Preferences/WebKit, and a
  positive control that `/tmp/payload.bin` write→execute from
  different PIDs *still* fires. 592 tests in 131 suites.

## [1.3.9] — 2026-04-18

Polish bundle: closes three findings from the v1.3.8 post-release audit
plus two long-standing UX gaps. No new features, no schema changes,
backwards-compatible DB — ships through the validated Sparkle pipeline.

### Security

- **SQLite WAL/SHM no longer world-readable.** `EventStore`,
  `AlertStore`, and `CampaignStore` now open their databases under
  `umask(0o027)` and explicitly `chmod 0o640` the main DB plus its
  `-wal` / `-shm` sidecars. v1.3.8 and earlier used `umask(0o022)` so
  the SQLite WAL — which contains recent event and alert inserts
  before checkpoint — was readable by any local user. `0o640` lets
  the dashboard (user in `admin` group) keep reading while closing
  the cross-user exposure. Tightening to `0o600` would have broken
  the dashboard, which runs as the user while the sysext runs as root.
- **SPM dependencies pinned to exact versions.** `Package.swift` now
  uses `.exact("2.9.1")` for Sparkle instead of `from: "2.6.4"`, and
  `swift-testing` is pinned to a specific revision instead of a
  branch. `Package.resolved` is now committed. Sparkle runs
  privileged update installs, so a compromised upstream release
  could push code to every MacCrab user on auto-update; exact pins
  mean a version bump is always explicit.

### Added

- **Dashboard response actions now do real work.** Kill Process,
  Quarantine File, and Block Destination buttons in `AlertDetailView`
  previously called `osascript display notification` stubs — no
  actual process was killed, no file was quarantined, no PF rule
  was written. New `Sources/MacCrabCore/Prevention/ManualResponse.swift`
  provides three typed-throw helpers the dashboard invokes:
  - **Kill Process**: `kill(SIGTERM)` by PID with `pkill -f` fallback;
    distinguishes `EPERM` (root-owned — prompts user toward
    `sudo kill`), `ESRCH` (already exited), and launch failure.
  - **Quarantine File**: moves the offending binary to
    `~/Library/Application Support/MacCrab/quarantine/<iso-ts>_<name>`,
    stamps `com.apple.quarantine` xattr, `chmod 000` the copy so
    accidental re-execution is blocked, writes a JSON sidecar with
    rule id/title/alert id for forensics.
  - **Block Destination**: extracts IPv4/IPv6 from the alert
    description, validates via `inet_pton`, writes to a per-user
    persistent block list, calls
    `osascript do shell script "pfctl ..." with administrator privileges`
    so the user authorizes once and the block takes effect in the
    kernel immediately. Uses a dedicated `com.maccrab.dashboard`
    anchor to not collide with the sysext's automated
    `com.maccrab` blocks.
  All three surface descriptive error messages (permissionDenied,
  notFound, cancelled, invalidInput) as the `actionFeedback` toast
  so the user knows whether the action succeeded, why it didn't,
  and what to do next.

### Changed

- **"Daemon" renamed to "Detection Engine" in the UI.** Post-1.3.0
  the detection runtime moved from a LaunchDaemon to an Endpoint
  Security system extension, but the dashboard still called it
  "Daemon" in the Settings tab, Overview health row, status-bar
  not-running label, and a few help strings in Threat Intel,
  Integrations, and Response Actions. Updated `defaultValue:` in
  every `String(localized:)` call plus the base English
  `Localizable.strings` file. Non-English locales keep their
  existing translation until re-localized.
- **README version badge bumped to 1.3.8** (was stuck at 1.3.4 through
  the v1.3.5 → v1.3.8 release run) plus a line pointing at the
  Sparkle-signed release channel.

## [1.3.8] — 2026-04-20

Quality-of-life release following field testing of v1.3.5–v1.3.7. Seven
fixes grouped around the rough edges a real end-to-end install flow
surfaced: cask wiping user data on every upgrade, MacCrab's own install
firing its own tamper-detection rules, the Sparkle "Check for Updates…"
menu item being unreachable on a menubar-only app, and a handful of
false-positive alert patterns on everyday Mac activity.

### Fixed

- **Cask preserves user data on upgrade.** The `uninstall` stanza in
  `Casks/maccrab.rb` and `homebrew/maccrab.rb` no longer lists
  `/Library/Application Support/MacCrab` in its `delete:` block. Every
  `brew upgrade --cask maccrab` through v1.3.7 was wiping alerts,
  baselines, suppressions, and LLM keys — a clean reinstall disguised
  as an upgrade. The `zap` stanza still removes the directory on an
  explicit `brew uninstall --zap maccrab` for users who really want
  a clean slate.
- **MacCrab no longer alerts on its own activity.** New gate in
  `NoiseFilter.apply` and a `NoiseFilter.isMacCrabSelf(event:)` helper
  drop non-`.critical` matches whose subject is a MacCrab binary
  (`com.maccrab.app`, `com.maccrab.agent`, `maccrabd`, `maccrabctl`,
  `maccrab-mcp`) or a file under `/Library/Application Support/
  MacCrab/` or `~/Library/Application Support/MacCrab/`. Critical
  matches still survive so a real integrity compromise against our
  binaries still fires. 5 new `FPRegressionTests` encode the
  scenarios that were noisy in the field: tamper-detection against
  our own rules directory during `brew upgrade`, xpcproxy events
  from our sysext firing EDR-remote-session rules, TCC-rate alerts
  when the user grants FDA to MacCrab.
- **Power-anomaly allowlist widened.** `AddressBookSourceSync` (normal
  iCloud contacts sync), `CalendarAgent`, `ContactsAgent`, `NotesMigratorService`,
  `ReportCrash`, `diagnosticd`, plus the WebKit networking helpers are
  all added to the `knownLegitimate` set in `PowerAnomalyDetector`. None
  of these are threat signal; all of them held sleep assertions on a
  typical Mac and produced Medium alerts every hour.
- **USB hub + non-mass-storage device alerts are now Informational, not
  Medium.** A USB hub or HID (keyboard/mouse) connecting is completely
  benign; severity floor reserved for mass-storage events where an
  attacker could be exfiltrating. Change is in `MonitorTasks.swift`'s
  USB handler.
- **SQLite error messages are visible under `sudo log show`.** The
  `.localizedDescription` interpolation in `StorageErrorTracker` was
  default-redacted to `<private>` by Foundation. Marked `.public` so
  operators diagnosing a broken install can see the actual SQLite
  return code without needing an Apple developer configuration
  profile. The message content is SQLite return codes + paths —
  never user secrets — so `.public` is safe.

### Added

- **Check for Updates… in the statusbar menu AND Settings.** Previously
  the v1.3.7 Sparkle integration wired the menu item via SwiftUI's
  `CommandGroup(after: .appInfo)`, which doesn't render for menubar-
  only apps (`LSUIElement=true`) — users had no in-UI way to trigger
  a manual update check. v1.3.8 wires the updater into
  `AppDelegate` and exposes it via two accessible entry points: the
  🦀 statusbar dropdown ("Check for Updates…" above the separator
  before Quit), and Settings → Daemon → Actions (a button alongside
  Reload Rules / Refresh Connection).
- **Launch at login defaults to on and is actually wired up.** The
  `@AppStorage("launchAtLogin")` preference has existed in
  `SettingsView` since v1.0 but never called anything — the toggle
  was dead. New `LaunchAtLogin` helper uses macOS 13+'s
  `SMAppService.mainApp.register()` / `.unregister()` to do the
  real work. Preference default flipped from `false` to `true`:
  MacCrab protects the system, so auto-starting after every login
  matches the product's intent. Users who'd rather start it manually
  can still flip it off; preference is honoured. On first launch,
  `LaunchAtLogin.reconcile(preferenceEnabled:)` aligns the SMAppService
  registration state with the stored preference.
- **FDA banner is principal-aware.** Previously the banner's body text
  was one generic "MacCrab needs FDA" message regardless of which of
  the two principals (`com.maccrab.app` or `com.maccrab.agent`)
  actually lacked the grant — both are separate TCC subjects on macOS.
  v1.3.8 probes both via `AppState.appHasFDA` and
  `AppState.sysextHasFDA` (inferred from WAL-write recency) and surfaces
  which one the user needs to add, naming the exact principal string
  as it appears in System Settings.
- **"Reveal MacCrab in Finder" link on the FDA banner.** Next to the
  existing Open Settings button. Opens Finder with MacCrab.app
  selected so users can drag it directly into the FDA settings pane
  — less ceremony than navigating to /Applications/ themselves.

### Infrastructure

- No sysext provisioning-profile, entitlement, or signing changes.
  v1.3.7 infrastructure carries forward unchanged.

### Known not-yet-fixed

Remaining items from the v1.3.7 field-test report that aren't in
this release:

- **Signed `.mobileconfig` for one-click FDA** — needs an MDM-signed
  profile for `SystemPolicyAllFiles` to auto-grant on personal Macs;
  lives in the v1.4 MDM / enterprise scope.
- **More rule-precision pass** — the spctl / csrutil / system_profiler /
  Wi-Fi-tool rules need parent-process anchoring. Scheduled for
  v1.4.x rule tuning.

## [1.3.7] — 2026-04-20

Cosmetic hotfix for v1.3.6's Overview banner — users saw the literal
string `^[1 high-severity alert](inflect: true) to review` instead of
a rendered English pluralization.

### Fixed

- **Overview alert-count banner no longer renders the Apple inflection
  markdown verbatim.** The `^[...](inflect: true)` syntax only resolves
  correctly when backed by a matching `.xcstrings` / `.stringsdict`
  entry with grammatical-agreement rules for the target locale. With
  just an in-source `String(localized:defaultValue:)` default, the
  Foundation localization layer falls through without processing the
  markdown, and the raw text lands in the UI. Replaced with plain
  English singular/plural branching. The localization keys
  (`overview.critical.count`, `overview.high.count`) are unchanged so
  existing translations keep working; only the English default value
  was wrong.

## [1.3.6] — 2026-04-20

Critical hotfix: v1.3.5 shipped with a broken binary that aborted on
launch with `dyld: Library not loaded: @rpath/Sparkle.framework`.
Anyone who installed v1.3.5 has an app that won't open — reinstall
v1.3.6 to recover.

### Fixed

- **`Sparkle.framework` now embedded in `MacCrab.app/Contents/Frameworks/`.**
  The Wave 1 Sparkle integration (v1.3.5) added the SPM dependency + the
  link-time requirement but the private release script never copied the
  framework into the output bundle. SPM lacks Xcode's automatic
  Copy-Files build phase; the framework must be manually staged. The
  release pipeline now detects the xcframework at
  `.build/artifacts/sparkle/Sparkle/Sparkle.xcframework/macos-arm64_x86_64/Sparkle.framework`,
  copies it with symlink-preserving `-R`, re-signs Sparkle's XPC
  services + Autoupdate + the framework itself with the Developer ID,
  then signs the outer app bundle last as before.
- **Sparkle keys added to the release-path `Info.plist`.** `SUFeedURL`,
  `SUPublicEDKey`, `SUEnableAutomaticChecks`, `SUScheduledCheckInterval`,
  `SUAutomaticallyUpdate` had been added to the checked-in
  `Xcode/Resources/MacCrabApp-Info.plist` in v1.3.5 but the release
  script writes its own `Info.plist` via heredoc — it didn't pick up
  the new keys. Now both paths carry the same Sparkle config.

Both issues are in the private build pipeline, not in source code.
Users with v1.3.5 should `brew uninstall --cask maccrab && brew install
--cask maccrab` to land on v1.3.6, or download the v1.3.6 DMG directly
from the GitHub Release.

### Infrastructure

- v1.3.5 appcast entry has been pulled so new installs don't pick up
  the broken build. v1.3.6 is the first working Sparkle-enabled
  release.

## [1.3.5] — 2026-04-19

First release after the v1.3 SystemExtension migration settled. Lands
the auto-update channel via Sparkle, moves API keys out of
world-readable preferences into the macOS Keychain, and sweeps up a
backlog of UX safety rails, localization gaps, documentation, and
runtime hardening flagged by a post-v1.3.4 multi-domain audit. From
this version onward, `brew upgrade --cask maccrab` is optional — the
app checks for updates itself and offers them via the application
menu's *Check for Updates…* item.

### Added

- **Auto-update channel via Sparkle 2.** MacCrab now polls
  `https://maccrab.com/appcast.xml` daily (configurable) and surfaces
  new versions through the app menu. Updates are verified with EdDSA
  signatures against a public key embedded in the app bundle —
  downgrade or tampered-DMG attacks can't install on existing
  installs. Sysext updates cascade via
  `OSSystemExtensionRequest(.replace)` on relaunch, so no
  re-approval prompt for same-team-ID upgrades.
- **MonitorSupervisor for clean shutdown.** All 12 background monitor
  tasks now register with a supervisor that SIGTERM cancels and
  awaits cleanly before process exit, with a 3-second deadline. The
  Sparkle "Install and Relaunch" flow now unwinds collectors without
  losing in-flight SQLite writes.
- **API keys move to the macOS Keychain.** A new `SecretsStore`
  (`Sources/MacCrabCore/Storage/SecretsStore.swift`) wraps
  `SecItemAdd/Copy/Delete` with a typed `SecretKey` enum covering
  every secret the dashboard handles (5 LLM providers + 7 threat-
  intel APIs + 3 output transports). Keys are encrypted at rest
  under your login password; the Settings UI reads and writes
  through it transparently.
- **Full Disk Access warning banner** on the Overview tab. Clicks
  through to System Settings via three URL variants that cover
  macOS 13 / 14 / 15 pane reshuffles. Closes the #1 UX failure mode
  from the audit — "protection enabled but TCCMonitor is blind".
- **Undo button on suppression toast.** 5-second window, bound to
  ⌘Z, with a monotonic-token pattern so rapid double-suppresses
  don't cancel each other's timers.
- **Filter persistence.** Alert dashboard severity filter and "show
  suppressed" toggle now survive tab switches and app restarts via
  `@AppStorage`.
- **Severity differentiator via SF Symbol.** Filter chips and
  menubar status dots now carry a shape, not just color.
  Colourblind and VoiceOver users can distinguish severity levels
  without relying on hue.
- **Webhook SSRF policy.** `MACCRAB_WEBHOOK_URL` now requires
  `https` (loopback `http` excepted), blocks cloud metadata IPs
  unconditionally (AWS `169.254.169.254`, AWS IPv6
  `fd00:ec2::254`, Alibaba `100.100.100.200`), and rejects RFC1918
  / IPv6 link-local / unique-local unless
  `MACCRAB_WEBHOOK_ALLOW_PRIVATE=1` is set. 10-test suite in
  `WebhookValidationTests.swift`.
- **Rule compiler archive.** `Compiler/compile_rules.py` snapshots
  the previous `compiled_rules/` into
  `compiled_rules.archive/<YYYYMMDD-HHMMSS>/` (keeps last 5) before
  overwriting. Rollback on a bad compile is `cp -R` — no git
  history required.
- **Release pipeline scripts** in `scripts/`:
  `generate-appcast-entry.sh` (signs a DMG with `sign_update` and
  emits a Sparkle `<item>`), `publish-appcast-entry.sh` (PUT's the
  item into the the site repo repo via a scoped PAT),
  `bump-cask.sh` (syncs `version` + `sha256` across both cask
  files).
- **User-facing documentation.** `TROUBLESHOOTING.md` covers
  sysext approval hangs with the real rejection signatures from
  1.3.0–1.3.3, FDA silent drops, compile failures, webhook
  rejections, and Homebrew upgrade cleanup. `UPGRADE.md` explains
  the v1.2 → v1.3 migration. `FAQ.md` has 14 common questions.
- **Annotated example configs.** `docs/daemon_config.example.json`
  and `docs/suppressions.example.json` document every tunable and
  every output-sink type with `_comment_*` keys the decoder
  ignores.
- **Module-level doc headers** on `AlertStore.swift` (schema table,
  concurrency notes, read-only degradation) and `ESCollector.swift`
  (ASCII event-pipeline diagram, required-privileges block).
- Localization catch-up: 40 new `en.lproj` keys covering
  destructive-action confirmations (kill / quarantine / block),
  the `SystemExtensionPanel` end-to-end, Overview stray strings
  (with Apple's automatic inflection syntax for locale-safe
  pluralization), and the ThreatIntel API-key UX refactored 7→1.
- CLI secret resolution now prefers the Keychain over
  `llm_config.json` + env vars (env still wins as the override for
  CI and one-off invocations).

### Fixed

- **Retention policy now honors `config.retentionDays`.** Previously
  hardcoded to 30 days regardless of `daemon_config.json`. Clamped
  to [1, 3650] at the timer site so a typo (`"retentionDays": 0`)
  can't wipe the database on next tick.
- **`EventStore` and `AlertStore` reject symlinks on the DB path +
  `-wal` / `-shm` / `-journal` sidecars** before `sqlite3_open_v2`.
  Closes the symlink-redirect attack class the rules directory
  already had protection against.
- **Merged event stream now uses `.bufferingNewest(100 000)`** —
  previously unbounded. Under pathological burst the oldest events
  drop instead of the resident set growing without limit.
- **Destructive-action confirmation dialogs localize.** The
  kill / quarantine / block prompts no longer render in English
  only for the 14 locales MacCrab ships.
- **SystemExtensionPanel fully localized** (15 keys covering
  headlines, body states, state chips, buttons).
- **`LLMSanitizer` regex compilations hoisted to `static let`.**
  Previously recompiled on every sanitize call; now compiled once
  at module load.
- **`KdebugCollector` force-unwrap guarded.** `parts.last!` at
  line 202 now uses a safe `guard let`. No crash path under any
  observed input.
- **`maccrabctl suppress` JSON decode now logs parse errors**
  instead of silently treating a corrupt `suppressions.json` as
  empty. `unsuppressRule` refuses to write on parse failure to
  avoid overwriting user state.
- **Stale "sudo maccrabd" guidance replaced** in 6 user-visible
  strings: `StatusCommand`, `SecurityScorer`, `ESHealthView`,
  `MainView`, `WelcomeView`, and the `DaemonSetup` startup
  banner — now point at "Open MacCrab.app → Enable Protection"
  which is the v1.3+ shipping path.

### Changed

- **`WebhookOutput` uses `SecureURLSession.makeGeneric`** for the
  same TLS 1.2+ floor, ephemeral config, and cookie/credential
  scrubbing as the LLM + threat-intel sessions. Pinning doesn't
  apply to user-supplied URLs, but everything else does.
- Bundle versions bumped 1.3.0 → 1.3.5 across
  `MacCrabApp-Info.plist`, `MacCrabAgent-Info.plist`, and
  `Xcode/project.yml`. `CFBundlePackageType` corrected from `SYEX`
  → `SYSX` in the checked-in `MacCrabAgent-Info.plist` (the
  release build pipeline had been overriding this; now the checked-
  in file matches).
- `ThreatIntelView` API-key boxes refactored from seven
  copy-pasted `GroupBox` blocks into a single `apiKeyRow(...)`
  helper — ~50 lines of duplication removed.

### Infrastructure

- Security contact: `maccrab@peterhanily.com` (was
  `security@maccrab.dev`; the former never resolved).
- Distribution domain: `maccrab.com` (Cloudflare Pages serving
  the site repo). Permanent URLs:
  `https://maccrab.com/appcast.xml`,
  `https://maccrab.com/maccrab.mobileconfig` (the MDM profile
  ships in v1.4).
- **Apple Developer Team ID**: 79S425CW99 (unchanged).
- **Sparkle EdDSA public key**:
  `de+dzPjBve7LP5qxoE7nR6shThsjubkVasi+i8ehT4E=`.
- **Minimum macOS**: 13.0 Ventura (unchanged).
- Detection rules: 380 total (353 single-event + 27 sequences)
  across 17 MITRE tactic directories.
- Tests: **583 in 130 suites passing**.

### Upgrade notes

- Users on v1.3.0–v1.3.4 upgrading via Homebrew cask or manual DMG
  will see the sysext replace itself silently on first launch
  (same team ID — no System Settings re-approval needed).
- API keys previously stored in `llm_config.json` continue to work
  unchanged; newly-entered keys via Settings → AI Backend land in
  the Keychain. Until the shared `keychain-access-groups`
  entitlement ships (targeted for v1.4), the sysext still reads
  API keys from `llm_config.json` — the Dashboard writes both.
- Env vars (`MACCRAB_LLM_*_KEY` etc.) continue to override Keychain
  and JSON, so CI / automation flows are unchanged.

## [1.3.4] — 2026-04-18

Fixes a flood of `maccrab.correlator.network-convergence` alerts on
hosts with active Chrome / Electron usage. Field diagnosis from a
noisy box showed every alert description read `N unrelated processes
contacted :443 over Ns` — no IP, just the port. Network events that
arrived before DNS / flow enrichment carried an empty
`destinationIp`, which the correlator keyed under `":443"`, collapsing
every HTTPS flow on the host into one artifact bucket. `syspolicyd`,
`Google Chrome Helper`, `WeatherWidget`, `mDNSResponder`, and
`Keynote` all got lumped together as "convergence" simply because
they opened HTTPS before the IP resolved.

### Fixed

- `CrossProcessCorrelator.shouldIgnoreNetworkDestination` now rejects
  empty, whitespace-only, `0.0.0.0`, `::`, and any string that
  doesn't look like an IP. This is the fix that actually stops the
  flood — no cloud-prefix list could match an absent IP.
- Expanded `trustedCloudDomains` from 15 → 49 suffixes to cover
  Google's full browser/update/media stack (`gvt1.com`,
  `googleusercontent.com`, `youtube.com`, `doubleclick.net`, …) plus
  Microsoft, Mozilla, Apple CDN, and Slack/Discord/Zoom. These help
  the domain-keyed path when DNS *is* attached.
- New `allEventsAreTrustedHelpers` gate reuses
  `NoiseFilter.trustedBrowserPrefixes` to suppress cross-bundle
  fan-out (Chrome Helper + Slack Helper + Code Helper all to one
  destination) — the existing bundle-identity filter couldn't see
  across bundles.

### Tests

Four new regressions in `CrossProcessCorrelatorTests`:
`emptyDestinationIPIgnored`, `chromeFamilyFanOutSuppressed`,
`unrelatedProcessesStillConverge`, `googleUpdateDomainSuppressed`.
All 7 correlator tests pass.

## [1.3.3] — 2026-04-18

Second hotfix for the same sysext categorization error. 1.3.2 added
`NSSystemExtensionPointIdentifier` but `sysextd` still rejected
activation with "does not appear to belong to any extension
categories". The real bug was a `CFBundlePackageType` typo: I wrote
`SYEX` back in 1.3.0 and carried it through every release. `sysextd`
specifically checks for `DEXT` (DriverKit) or `SYSX` (system
extension) and silently fails anything else.

### Fixed

- `CFBundlePackageType = SYEX` → `SYSX` in the sysext Info.plist
  template in `build-release.sh`.

The diagnostic log is unambiguous:

    sysextd: ...com.maccrab.agent.systemextension: package type not `DEXT`
    sysextd: ...com.maccrab.agent.systemextension: package type not `SYSX`
    sysextd: system extension does not appear to belong to any extension categories

1.3.2's `NSSystemExtensionPointIdentifier` change was a no-op —
`sysextd` rejects the bundle at the package-type check before
looking at the category key. Both keys are technically required, so
1.3.2's change stays.

## [1.3.2] — 2026-04-18

Hotfix for 1.3.1. The system extension bundled correctly and signed
correctly, but macOS refused to activate it:

    Invalid extension configuration in Info.plist and/or entitlements:
    System extension com.maccrab.agent.systemextension does not
    appear to belong to any extension categories

Missing `NSSystemExtensionPointIdentifier` key in the sysext's
Info.plist. Without it macOS can't categorize the bundle as an
Endpoint Security extension, so `sysextd` rejects activation.

### Fixed

- `scripts/build-release.sh` now emits
  `NSSystemExtensionPointIdentifier =
  com.apple.system_extension.endpoint_security` in the sysext's
  Info.plist. This is the category key every commercial ES
  product sets; omitting it was an oversight on my part when I
  wrote the 1.3.0 bundle template.

Drop-in upgrade. `brew upgrade --cask maccrab` → relaunch
MacCrab.app → Enable Protection. Extension should now activate
cleanly through the System Settings approval flow.

## [1.3.1] — 2026-04-18

Hotfix for 1.3.0. The Overview tab hid the "Enable Protection"
activation control behind a `!appState.isConnected` spinner that
told the user to run `sudo maccrabd` — but 1.3.0 removed that
command entirely. The activation card became unreachable in
exactly the state it was meant for (first launch after install).

### Fixed

- `OverviewDashboard` now shows `SystemExtensionPanel` at the top
  unconditionally when `sysextManager.state != .activated`.
  Previously the panel was nested inside the `isConnected` branch,
  so on a fresh install (no connection, no rules yet) the user
  saw only the obsolete "Start the daemon: sudo maccrabd" message
  and could never reach the Enable Protection button.
- Replaced "Start the daemon: sudo maccrabd" with a message
  pointing at the activation panel. The follow-up "Connecting to
  the detection engine…" state only appears after the sysext is
  actively running but the dashboard hasn't read its first rows
  yet — a genuinely brief window, not a deadlock.

Drop-in upgrade over 1.3.0. No schema/config changes.

## [1.3.0] — 2026-04-18

Native Endpoint Security via a proper system extension. Ends the
1.1.1 → 1.2.5 investigation arc — the daemon now runs where Apple's
AMFI expects, and the `-413 "No matching profile found"` error is
gone.

### What changed architecturally

The detection engine no longer runs as a LaunchDaemon. On macOS Catalina
and later, Apple's AMFI refuses the
`com.apple.developer.endpoint-security.client` entitlement on any
binary that isn't loaded through `OSSystemExtensionRequest`. This was
the root cause of the SIGKILL + `-413` error on every 1.2.4/1.2.5
install. Every commercial ES product (CrowdStrike, SentinelOne, Jamf
Protect, Microsoft Defender, Objective-See LuLu/BlockBlock) ships as
a `.systemextension` for exactly this reason.

1.3.0 follows that pattern:

```
/Applications/MacCrab.app/
  Contents/
    MacOS/MacCrab                                       (dashboard + activator)
    embedded.provisionprofile
    Library/SystemExtensions/
      com.maccrab.agent.systemextension/
        Contents/
          Info.plist                                    (SYEX, ES entitlement)
          embedded.provisionprofile
          MacOS/com.maccrab.agent                       (the daemon)
          _CodeSignature/
```

The app bundle signs with `system-extension.install`; the sysext
signs with `endpoint-security.client`. AMFI matches the sysext
identifier against the provisioning profile automatically.

### User-facing flow

- Install (via Homebrew cask or DMG): `MacCrab.app` is copied to
  `/Applications`.
- First launch of the app: the new "Enable Protection" card on the
  Overview tab invokes `OSSystemExtensionRequest.activationRequest`.
- macOS prompts the user to approve the extension in **System
  Settings > General > Login Items & Extensions > Endpoint Security
  Extensions**.
- After approval the sysext becomes active. The activation card
  disappears; detection starts.
- Subsequent app launches: no prompt, no user action.

### Changed (internal restructure)

- New `MacCrabAgentKit` SPM library target holds the daemon bootstrap
  (DaemonSetup, DaemonState, EventLoop, MonitorTasks, DaemonTimers,
  SignalHandlers, StartupBanner, Globals, DaemonBootstrap). Extracted
  out of `Sources/maccrabd/` so both the legacy `maccrabd` executable
  and the new `MacCrabAgent` sysext can share identical logic — only
  `main.swift` differs between the two.
- New `MacCrabAgent` SPM executable target — compiles to the binary
  that gets wrapped into the `.systemextension` bundle by
  `build-release.sh`. Thin `main.swift` calls
  `DaemonBootstrap.runForever()`.
- `Xcode/project.yml` + `Xcode/Resources/*.entitlements` added as an
  alternative build path for anyone with full Xcode installed.
  `scripts/build-release.sh` uses SPM + manual bundle assembly so
  full Xcode isn't required.

### Added

- `SystemExtensionManager` in `Sources/MacCrabApp/` — ObservableObject
  wrapping `OSSystemExtensionRequest` with `@Published state`.
  Handles the full delegate protocol: `actionForReplacingExtension`
  (always `.replace` on upgrade), `requestNeedsUserApproval`
  (transitions to `.awaitingApproval`), `didFinishWithResult`,
  `didFailWithError`.
- `SystemExtensionPanel` in `Sources/MacCrabApp/Views/` — banner-style
  card on the Overview tab that shows the activation state with
  plain-English body text, state icon, and contextual actions:
  "Enable Protection" initially, "Open System Settings" while
  awaiting approval (falls through three URL variants because Apple
  has moved the pane between macOS 13/14/15), "Try again" for
  failures. Hides itself once the extension is active.

### Removed

- LaunchDaemon path. `com.maccrab.agent.plist` is no longer shipped
  in the DMG or installed to `/Library/LaunchDaemons/`. `launchctl`
  doesn't manage MacCrab anymore — `sysextd` does.
- Standalone `maccrabd` binary from the installed layout. The SPM
  target still builds (useful for `swift run maccrabd` during local
  development without ES), but it isn't part of the release DMG
  and isn't symlinked into `$HOMEBREW_PREFIX/bin/`.
- System-wide provisioning profile install. 1.2.4/1.2.5 copied the
  profile to `/Library/MobileDevice/Provisioning Profiles/` —
  1.3.0's upgrade path actively removes any MacCrab-related
  profile from that directory since the sysext embeds its own copy.

### Upgrade path

Automated in both the Homebrew cask postflight and `install.sh`:

1. Unload + remove `/Library/LaunchDaemons/com.maccrab.daemon.plist`
2. Unload + remove `/Library/LaunchDaemons/com.maccrab.agent.plist`
3. Remove stale `/opt/homebrew/bin/maccrabd` and
   `/usr/local/bin/maccrabd` symlinks
4. Remove any `com.maccrab.*` provisioning profile from
   `/Library/MobileDevice/Provisioning Profiles/`
5. Install the 1.3.0 rules + CLI tools + `MacCrab.app`

Users upgrading from 1.2.x need to **launch `MacCrab.app` and
approve the extension** in System Settings after the upgrade, since
the old LaunchDaemon is gone.

For a clean uninstall of the extension:

```bash
systemextensionsctl uninstall 79S425CW99 com.maccrab.agent
```

### Known limitations

- **No MDM silent-approve path yet.** Every fresh user sees the
  System Settings prompt. A future MDM configuration profile would
  pre-authorize the team ID + bundle ID combination; not shipping
  that in 1.3.0.
- **First-launch-from-Downloads gotcha.** On macOS 15+ the
  extension activation silently fails with code 4 if `MacCrab.app`
  is opened from `~/Downloads/` instead of `/Applications/`. The
  installer handles this; Homebrew cask users are covered
  automatically. Manual DMG installers need to drag the app to
  `/Applications` before first launch.
- **Dashboard ↔ daemon IPC still file-based.** The sysext writes
  SQLite under `/Library/Application Support/MacCrab/`; the
  dashboard reads from there. A proper XPC control plane is v1.4.0
  work.

## [1.2.5] — 2026-04-17

Hotfix for 1.2.4. The 1.2.4 daemon was signed with the ES entitlement
but AMFI refused to honour it because the binary sat outside an app
bundle — macOS only discovers `embedded.provisionprofile` inside an
`.app`. 1.2.5 moves the daemon into `MacCrab.app/Contents/Library/
LaunchDaemons/` so the profile is findable.

### Fixed

- **Daemon SIGKILL on 1.2.4 install** — AMFI emitted `Error
  Domain=AppleMobileFileIntegrityError Code=-413 "No matching profile
  found"` when launching `/opt/homebrew/bin/maccrabd`. Relocated the
  daemon binary into `MacCrab.app/Contents/Library/LaunchDaemons/
  maccrabd`; AMFI walks up from any contained Mach-O and finds the
  app's `embedded.provisionprofile`. This is the canonical Apple
  pattern used by Little Snitch, Objective-See tools, and every other
  Developer-ID-signed ES daemon on macOS.
- **LaunchDaemon plist path** updated from `/usr/local/bin/maccrabd`
  to `/Applications/MacCrab.app/Contents/Library/LaunchDaemons/
  maccrabd`. No per-install path rewriting; the plist is now
  Homebrew-prefix-independent.
- **Cask postflight UUID extraction** (carried over from
  mid-1.2.4-release hotfix): `security cms | PlistBuddy /dev/stdin`
  was unreliable in Ruby backticks; replaced with temp-file
  round-trip and UUID regex validator.

### Added

- **App icon bundled** — `AppIcon.icns` now copies into
  `MacCrab.app/Contents/Resources/` with `CFBundleIconFile` and
  `CFBundleIconName` keys set in `Info.plist`. The generic macOS app
  icon that was shipping in 1.2.1-1.2.4 is replaced with the real
  MacCrab crab icon.
- **Upgrade-path cleanup** in cask + `install.sh`: any stale
  `/opt/homebrew/bin/maccrabd` or `/usr/local/bin/maccrabd` symlinks
  from 1.2.4 are removed before installing 1.2.5. Any running
  `com.maccrab.agent` LaunchDaemon pointing at the defunct path is
  unloaded first.

### Internal

- `scripts/build-release.sh`: new signing order — sign bin/
  CLI tools, relocate `maccrabd` into app bundle, sign the daemon
  inside the app with ES entitlement + `com.maccrab.agent` identifier,
  sign inner app executable, sign outer app bundle (seals the
  provisioning profile).
- Cask no longer declares `binary "bin/maccrabd"` — the daemon lives
  in the app now. `maccrabctl` and `maccrab-mcp` still symlink into
  `$HOMEBREW_PREFIX/bin/`.

## [1.2.4] — 2026-04-17

Native Endpoint Security unlock. Apple approved the ES client
entitlement under bundle ID `com.maccrab.agent`; this release adopts
the new identifier, embeds the provisioning profile, and ships the
daemon signed with the real ES entitlement instead of relying on the
eslogger/kdebug/FSEvents fallback chain.

### Changed

- **LaunchDaemon label renamed** `com.maccrab.daemon` → `com.maccrab.agent`.
  Apple bound the Endpoint Security entitlement to the new identifier
  during their approval process, so we moved to match. All code paths,
  scripts, plist filenames, Homebrew cask actions, and log-stream
  subsystem names updated. The plist filename is now
  `com.maccrab.agent.plist`.
- **Daemon is now signed with `com.apple.developer.endpoint-security.client`.**
  `build-release.sh` picks up the provisioning profile from
  `~/.maccrab-signing/MacCrab.provisionprofile` (override via
  `PROVISION_PROFILE`) and signs `maccrabd` with `--entitlements
  entitlements.plist --identifier com.maccrab.agent`. Other binaries
  (`maccrabctl`, `maccrab-mcp`) stay unentitled.
- **Provisioning profile shipped in two places:**
  `MacCrab.app/Contents/embedded.provisionprofile` for app-scope
  verification + `/Library/MobileDevice/Provisioning Profiles/
  <UUID>.provisionprofile` for the standalone
  `/usr/local/bin/maccrabd` invocation.

### Added

- **Upgrade-path migration** in `install.sh` and the Homebrew cask:
  detects a pre-1.2.4 `com.maccrab.daemon.plist` on disk, unloads it,
  and removes it before installing the new `com.maccrab.agent.plist`.
  No duplicate competing daemons.
- **`scripts/verify-profile.sh`** — operator utility that inspects a
  `.provisionprofile` file (team, bundle ID, expiry, entitlements,
  profile type, provisioned devices) so you can confirm before
  shipping.
- **Hardened `.gitignore`** — broader coverage for private keys
  (every format), certs, env files in every variant, cloud vendor
  credential caches, SSH keys, keychain dumps, release artifacts,
  coverage data, crash dumps, scratch files.

### User-visible

- Daemon startup banner now reads "Endpoint Security: native client"
  on clean installs instead of "eslogger proxy".
- Dashboard ES Health view stops showing the "degraded" banner on
  fresh installs.
- `log stream --predicate 'subsystem=="com.maccrab.agent"'` replaces
  the previous `com.maccrab.daemon` predicate. Old predicate will
  stop matching after upgrade.

### Upgrade notes

- Drop-in over 1.2.3 via `brew upgrade --cask maccrab`. The cask
  `postflight` handles the plist migration and profile install.
- Manual installs (DMG + `install.sh`): run the 1.2.4 installer; it
  detects the old plist and removes it before proceeding.
- **If you're already running 1.2.3 with `com.maccrab.daemon.plist`
  loaded**: the 1.2.4 install gracefully unloads + replaces it, no
  user action needed.

## [1.2.3] — 2026-04-17

24-hour observation hotfix. Four specific noise sources identified by
running 1.2.2 against a real dev workstation overnight.

### Fixed

- **FSEvents path bypassed the noise filters.** `MonitorTasks` runs a
  separate rule-evaluation loop for FSEvents-sourced events (non-root
  fallback) that didn't go through `EventLoop`'s unknown-process /
  warm-up / trusted-browser filters, so Sigma rules fired on every
  file event even when the event had no process attribution. Extracted
  the filter logic into `EventLoop.applyNoiseFilters` and call it from
  both paths. Eliminates the 34 overnight alerts for invisible-unicode,
  trojan-source, cookie-DB-access, and contacts-DB-access firing on
  file writes from unknown processes.
- **RootkitDetector dual-API race.** `proc_listallpids()` and
  `sysctl(KERN_PROC_ALL)` are called sequentially, so any process that
  exits or spawns in the 1–2 ms gap appears in one set but not the
  other. That race was producing 100% of the `hidden-process`
  detections on a busy machine (46 in one day). Added second-chance
  verification: after a 300 ms delay we re-query both APIs and only
  alert when the discrepancy persists. A userland rootkit hides a
  process for its entire lifetime; an exit-timing race does not.
- **AI-guard cloud IP prefix list was incomplete.** Google serves
  several user-facing APIs from `74.125./16` and `172.253./16` ranges
  that weren't in the allowlist (only `142.250`, `142.251`, `172.217`,
  `209.85`, `216.58` were). Added the full Google-owned block set from
  gstatic.com/ipranges/goog.json (64.233, 66.102, 66.249, 72.14,
  74.125, 108.177, 172.253, 173.194, 216.239) to both the
  `AINetworkSandbox` fallback and the `CrossProcessCorrelator` cloud
  filter.
- **`runningboardd` missing from PowerAnomalyDetector allowlist.** Core
  macOS daemon that manages process lifecycles and holds power
  assertions on behalf of other processes. Added alongside
  `assertiond` and `ContextStoreAgent` for completeness.

## [1.2.2] — 2026-04-16

Hotfix on top of 1.2.1 targeting OS-notification floods. Drop-in
upgrade — no schema or config changes.

### Fixed

- **SelfDefense tamper alerts no longer re-fire every 15 seconds.** The
  periodic integrity check correctly re-evaluates every cycle, but
  firing a fresh critical alert each time turned a single real event
  (e.g. a local rebuild) into 100+ identical notifications. Added a
  per-type `alertedTamperTypes` gate — each tamper type alerts exactly
  once per daemon lifetime. Subsequent cycles still write to the
  forensic log (`~/.maccrab_tamper.log`, `/var/log/maccrab_tamper.log`,
  `$TMPDIR/maccrab_tamper.log`) but don't produce new alerts.
- **SUSTAINED TAMPERING summary fires exactly once** at the 3-failure
  mark, not every cycle thereafter. Counter still climbs internally.
- **Notifier dedup window: 5 min → 1 hour, per-key.** The previous
  `sweepKeysIfNeeded` cleared *all* dedup keys every 5 minutes, so a
  persistent condition produced a fresh OS banner every 5 min.
  Replaced with a `[String: Date]` map that expires individual keys on
  their own schedule. A single rule firing repeatedly from the same
  process now produces one banner per hour max.

### Added

- **Trusted browser/Electron-helper short circuit** in the event loop.
  Chromium-based apps (Chrome, Edge, Brave, Arc, Opera, Vivaldi,
  Firefox, Safari) and Electron apps (Slack, Discord, Teams, VS Code,
  Cursor, Claude, ChatGPT Atlas, Codex, GitHub Desktop, Signal,
  Telegram, WhatsApp) have large helper trees that fire individual
  Sigma rules on benign activity — reading their own cookie DB,
  writing to their own cache, opening long-lived HTTPS, spawning
  child tools for profile migration. Any process whose executable
  path sits under one of these bundles has its non-critical rule
  matches dropped at the event loop. Critical still fires. This
  complements the per-detector allowlists in TLSFingerprinter,
  PowerAnomalyDetector, CrossProcessCorrelator with a single
  short-circuit that covers rules we haven't individually hardened.

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
