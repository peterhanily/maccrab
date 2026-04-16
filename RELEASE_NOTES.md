# MacCrab 1.2.1 — Ship Notes

**Patch release: false-positive reduction on real dev workstations,
plus a self-tuning feedback loop and a much richer browser-extension
detail view.**

1.2.0 users: drop-in upgrade. No schema changes, no config changes,
existing suppressions continue to work.

## Why this release

On a reference developer workstation running MacCrab 1.2.0, a single
24-hour observation period produced **2,856 alerts** — the vast
majority from five detectors that shipped with conservative
allowlists. After this patch landed and the daemon restarted with a
fresh DB, the same workstation produced **3 alerts in 11 minutes**
across two full forensic scan cycles, with the remaining 3 being
legitimate singletons worth a look. ~99% noise reduction, zero loss
of real signal.

## What changed

### Detection tuning

| Detector | Fix |
|----------|-----|
| `LibraryInventory` | Homebrew / MacPorts / Nix / `/usr/local` prefixes allowlisted. Any dylib in an unexpected location now gates on `SecStaticCodeCheckValidity` against `anchor apple generic` — validly signed libraries skipped regardless of path. |
| `SystemPolicyMonitor` (quarantine) | Per-path dedup set (was re-alerting every 5-min poll on the same file). Apple-anchor signature check skips signed apps (Gatekeeper still evaluates them). `.dmg`/`.iso` skipped entirely. |
| `TLSFingerprinter` (beacon) | Allowlist expanded from browsers-only to cover chat, meeting, sync, dev tools, AI helpers, package managers. `node`/`deno`/`bun` skipped outright. |
| `PowerAnomalyDetector` | Comprehensive legitimate-holder allowlist (`screensharingd`, `bluetoothd`, `rapportd`, Xcode, Docker, etc.) + per-process-name dedup. |
| `CrossProcessCorrelator` | Skip convergence when all events share a `.app` bundle, an exact executable, or a tool-version directory. Additionally skip by destination for well-known cloud CDNs (Anthropic, Google, Cloudflare, GitHub) — architecture, not attack. |
| `AINetworkSandbox` | Cloud IP-prefix fallback when DNS correlation is absent. |
| `BehaviorScoring` | 120s per-indicator cooldown per process — one chatty benign signal can no longer walk a score to threshold alone. |
| `AlertDeduplicator.normalizePath` | End-of-path version regex added; `/.../versions/2.1.111` and `/.../versions/2.1.112` now dedup correctly. |
| `EventLoop` | Drop non-critical rule matches when the event has no attributable process (FSEvents without process info). |
| `EventLoop` warm-up | Suppress non-critical matches for the first 60s after daemon start. Inventory scans complete in this window; critical still fires. |

### Rule updates

- `c2_beacon_pattern.yml`: new `filter_dev_tools` + `filter_homebrew_node`
  exclusions covering GitHub Desktop, Claude, Codex, Cursor, Code,
  JetBrains, Docker, and `node`/`deno`/`bun`/`python`/`ruby`/`ollama`
  under Homebrew/MacPorts/user paths.
- `invisible_unicode_in_source.yml` + `trojan_source_bidi_code.yml`:
  exempt localization paths (`.lproj/`, `.strings`, `.xliff`, `.po`,
  `/locales/`, `/_locales/`, `/i18n/`, `/translations/`) — legitimate
  RTL text and zero-width joiners live here.

### Feedback loop (new — self-tuning severity)

Dismissing an alert in the dashboard now does more than mark a row.
A 60-second sweep feeds user dismissals into the deduplicator, which
tracks per-rule dismissal rates. After ≥3 dismissals at a ≥70%
dismissal rate, the rule's future alerts auto-downgrade one severity
level (e.g. `high` → `medium`). `critical` is never touched — a user
cannot mute ransomware or SIP-disabled alerts by muting their
dashboard — and no rule goes below `medium`.

OS notifications now respect the downgraded severity: noisy rules
stop flashing banners after the user indicates they don't care,
without the rule itself being disabled.

### Browser extensions — detail drill-in

The Browser Extensions tab now gets a proper detail sheet per
extension:

- **0–100 risk score** + 4-tier label (Low risk / Caution /
  Suspicious / High risk), replacing the binary "Suspicious" flag.
- **Per-risk-factor breakdown** — one line per reason the rule scored
  ("Declares webRequestBlocking — can modify requests in-flight",
  "Update URL is not the Chrome Web Store — sideloaded").
- **Every permission explained** — categorized (network / data /
  execution / device / host / meta) with a plain-English description
  of what it permits; dangerous permissions visually distinguished.
- **Full manifest metadata** — description, version, manifest
  version, author, homepage URL, update URL (flagged when
  non-Web-Store), host permissions, content scripts with match
  patterns, background service worker / script list.
- **On-disk facts** — install date (manifest mtime), size on disk
  (recursive), full extension path.
- **Quick actions** — Reveal in Finder, deep-link to the browser's
  own extension settings (`chrome://extensions/?id=…`,
  `brave://…`, `edge://…`), open homepage.
- **`__MSG_*` locale token resolution** — manifest name and
  description now show the real localized value from
  `_locales/<locale>/messages.json` instead of the raw token.

## Upgrade notes

- Drop-in over 1.2.0. No schema changes, no config changes.
- Existing per-alert suppressions from 1.2.0 continue to work and now
  contribute to the auto-tune.
- 380 Sigma-compatible rules (unchanged count), all compiling clean.
- 535 Swift Testing tests pass, no regressions.
- Homebrew users: `brew upgrade --cask maccrab` picks up the new
  notarized DMG.

## Credits

Shipped by @peterhanily with Claude (Opus 4.7, 1M context) as
co-author. See `CHANGELOG.md` for the full changelog entry and
commit `c089185` for the diff.
