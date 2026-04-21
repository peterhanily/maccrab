# Changelog

All notable changes to MacCrab. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [SemVer](https://semver.org/spec/v2.0.0.html).

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
