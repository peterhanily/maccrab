# MacCrab 1.2.2 — Ship Notes

**Hotfix for the 1.2.1 notification flood on fresh installs.**

1.2.1 users: drop-in upgrade. No schema changes, no config changes.
Upgrade specifically addresses the two noise sources observed on
real-world deployments after 1.2.1 shipped.

## What changed

### Tamper-detection alert storm, fixed

On any machine where the `maccrabd` binary changed after the daemon
started (a local rebuild, a Homebrew upgrade while the daemon is
running, a signed re-notarization) the 1.2.1 SelfDefense periodic
check fired the same `binary_modified` critical alert every 15
seconds — 240 alerts per hour. Dashboard accurate; Apple
Notification Center a disaster.

Fix:

- Per-type `alertedTamperTypes` gate in `SelfDefense`. Each tamper
  type (`binary_modified`, `rules_modified`, `database_modified`,
  `debugger_attached`, `plist_removed`, `process_kill_attempt`,
  `file_deleted`, `signal_received`, `config_modified`) alerts
  **exactly once** per daemon lifetime.
- The "SUSTAINED TAMPERING DETECTED: N consecutive failures" escalation
  summary also fires only once (at the 3-failure mark).
- Subsequent cycles keep running and keep writing to the forensic
  logs (`~/.maccrab_tamper.log` + `/var/log/maccrab_tamper.log` +
  `$TMPDIR/maccrab_tamper.log`) — but no longer produce new alerts
  or OS banners.

### Notifier dedup, tightened

`NotificationOutput` previously wiped its entire dedup set every 5
minutes, so any persistent condition produced a fresh banner every
5 minutes indefinitely.

Fix:

- Per-key timestamps (`[String: Date]` instead of `Set<String>`). A
  given `(ruleId, processPath)` combination is dedup'd for its own
  one-hour window, not for the daemon's next bulk sweep.
- Dedup window widened from 5 minutes to 1 hour. A banner storm
  caused by a single rule is now capped at 24/day maximum per
  `(rule, process)` combination.

### Chrome Helper / Electron-helper noise, short-circuited

Users reported a flood of alerts on fresh installs involving
Google Chrome Helper, Microsoft Edge helpers, Slack, Discord, and
similar Electron apps. These all share a Chromium-based helper tree
that does a lot of activity individual Sigma rules flag on their
own — reading its own cookie DB, writing to its own cache, opening
long-lived HTTPS connections, spawning child binaries for profile
migration.

Fix:

- New `EventLoop.trustedBrowserPrefixes` covering every major Chromium
  browser (Chrome, Canary, Chromium, Edge family, Brave, Arc, Opera,
  Vivaldi, Firefox family, Safari, Orion) and commonly-deployed
  Electron apps (Slack, Discord, Teams, VS Code, Cursor, Claude,
  ChatGPT Atlas, Codex, GitHub Desktop, Signal, Telegram, WhatsApp).
- When the event's executable path lives under one of those bundles,
  the event loop drops non-critical rule matches before they become
  alerts. Critical rules (ransomware, SIP disabled,
  known-malicious-hash) still fire.
- Complements the per-detector allowlists shipped in 1.2.1 with a
  single short-circuit that also covers rules we haven't individually
  hardened.

## Upgrade notes

- Drop-in upgrade over 1.2.1. No schema or config changes.
- Universal build (arm64 + x86_64), Developer ID signed, Apple
  notarized, ticket stapled.
- `brew upgrade --cask maccrab` picks up the new DMG.

## Credits

Shipped by @peterhanily with Claude (Opus 4.7, 1M context) as
co-author. See `CHANGELOG.md` for the full entry.
