# MacCrab 1.2.3 — Ship Notes

**24-hour observation hotfix.** Four noise sources that survived 1.2.2
and fired on normal workstation activity overnight.

1.2.x users: drop-in upgrade. No schema changes, no config changes.

## What changed

Twelve-hour observation of 1.2.2 on a real dev workstation produced
94 alerts — not a flood, but four specific offenders accounted for
~95% of it, all from code paths that didn't go through the noise
filters we added in 1.2.1 / 1.2.2.

### FSEvents bypass fixed

`MonitorTasks.swift` runs a separate rule-evaluation loop for
FSEvents (the non-root fallback file source) that didn't consult the
unknown-process / warm-up / trusted-browser gates added in 1.2.1.
That meant Sigma rules fired on every file write even when the
event had no process attribution — including `/Codex/sentry/*.json`,
`/AddressBook/Metadata/.info`, and Firefox profile state files.

Extracted the filter logic into `EventLoop.applyNoiseFilters` and
call it from both paths. Also re-used it for the SIGHUP retroactive
scan, so re-detection after a rule reload applies the same gates.

### RootkitDetector dual-API race fixed

The rootkit detector compares two snapshots of the process table
(`proc_listallpids()` vs. `sysctl(KERN_PROC_ALL)`). Those calls
aren't atomic — any process that exits or spawns in the 1–2 ms gap
appears in one set but not the other. On a busy workstation that
produced **46 false-positive hidden-process alerts in one day**, all
with the same `sysctl_only` marker (process exited between the two
calls).

Added second-chance verification: after a 300 ms delay, re-query both
APIs. Only alert when the discrepancy persists. A real userland
rootkit hides a process for its entire lifetime; an exit-timing race
doesn't.

### AI sandbox: Google IP ranges completed

11 alerts for "AI tool connected to unapproved IP" on `74.125.x` and
`172.253.x` — both Google-owned ranges we hadn't listed in
`AINetworkSandbox.wellKnownCloudPrefixes`. Added the full Google
IP block list from `gstatic.com/ipranges/goog.json`:

```
64.233  66.102  66.249  72.14
74.125  108.177  172.217  172.253
173.194  209.85  216.58  216.239
```

Synced the identical list into `CrossProcessCorrelator.trustedCloudPrefixes`.

### `runningboardd` added to power allowlist

Core macOS daemon that manages process lifecycles and holds power
assertions on behalf of other processes. Fires
`maccrab.forensic.power-preventing_sleep` on every poll. Added
alongside `assertiond` and `ContextStoreAgent` for completeness.

## Measured impact (reference workstation)

| Rule | 1.2.2 (24h) | 1.2.3 (expected) |
|------|-----------:|-----------------:|
| `forensic.hidden-process` | 46 | 0 (race-verified) |
| `invisible_unicode_in_source` | 12 | 0 (FSEvents filter) |
| `ai-guard.network-sandbox` | 11 | ≤1 (Google ranges) |
| `browser_cookie_access` | 8 | 0 (FSEvents filter) |
| `contacts_database_access` | 8 | 0 (FSEvents filter) |
| `trojan_source_bidi_code` | 6 | 0 (FSEvents filter) |
| `power-preventing_sleep` | 3 | 0 (runningboardd) |

## Upgrade notes

Drop-in over 1.2.2. `brew upgrade --cask maccrab` picks up the new
notarized DMG.

## Credits

Shipped by @peterhanily with Claude (Opus 4.7, 1M context) as
co-author. See `CHANGELOG.md` for the full entry.
