# Response Action Safety

MacCrab can take active response actions when alerts fire — kill a
process, quarantine a file, block a network destination, run a script,
revoke TCC, etc. These are powerful and risky. This page documents the
safety validators on each action and the tests that pin them.

**Defaults are safe.** All response actions are off by default. Each
must be explicitly wired per-rule via `actions.json` in the support
directory. The dashboard's Response Actions tab lets you configure
this with explicit consent.

## Defense layers

```
  alert fires
       │
       ▼
  ┌────────────────────┐
  │ Per-rule           │  # actions.json must explicitly list
  │ actions.json gate  │    this rule + this action
  └────────────────────┘
       │
       ▼
  ┌────────────────────┐
  │ Action-specific    │  # see table below
  │ validators         │
  └────────────────────┘
       │
       ▼
  ┌────────────────────┐
  │ Audit log          │  # every fire logged to unified log
  │ (.public privacy)  │    with action + target + outcome
  └────────────────────┘
       │
       ▼
   action executes
```

## Per-action safety

| Action | Validator | What it rejects | Test file |
|---|---|---|---|
| **kill (signal)** | `SafePIDValidator` | PID 0/1, daemons (launchd, kernel_task, WindowServer, loginwindow, hidd, mds, syslogd, etc.), processes signed by Apple unless explicitly allowed | `SafePIDValidatorTests.swift` |
| **quarantine** | `SafeQuarantinePathValidator` | Paths under `/System/`, `/usr/`, `/bin/`, `/sbin/`, `/Library/`, `/Applications/`, symlinks, paths the user can't write, paths whose parent is not user-owned | `SafeQuarantinePathValidatorTests.swift` |
| **networkBlock** | `SafeBlockableIPValidator` | Loopback (127.0.0.0/8, ::1), link-local (169.254.0.0/16, fe80::), reserved (0.0.0.0/8, multicast/broadcast), Apple infrastructure (gateway.icloud.com et al.) | `SafeBlockableIPTests.swift` |
| **runScript** | `ResponseAction.validateScriptPath` | Scripts not in `/Library/Application Support/MacCrab/scripts/` or `/usr/local/maccrab/scripts/`; symlinks; non-root-owned; group-writable; world-writable | Coverage in `ResponseActionCoverageTests.swift` |
| **TCC revoke** | TCC service name allowlist | TCC services not in known list; rejects anything that would brick the dashboard's own permissions | `PreventionTests.swift` |
| **DNS sinkhole** | Domain shape + reserved-zone check | Shorter-than-3-label domains; reserved TLDs (.local, .arpa, .test); IP literals | `PreventionTests.swift` |
| **Persistence guard** | LaunchAgent / LaunchDaemon path + signer check | Apple-signed installers writing under `/Library/LaunchDaemons/`; user-allowlisted apps; recently-modified-via-System-Settings preferences | `PreventionTests.swift` |
| **Supply-chain gate** | Compound `SupplyChainGate` | Rejects unsigned/unnotarized binaries from suspicious origins; tested against known-bad and known-benign supply-chain scenarios | `SupplyChainGateSafetyTests.swift` |
| **Panic button** | All-of-the-above + audit | Aggregates kill + networkBlock for a process tree. Same individual validators apply per-action; the panic button itself just orchestrates | `PreventionTests.swift` |

## Why each validator looks the way it does

### `SafePIDValidator` — process kill

**Threat:** A response action that kills a PID can be weaponized by an
attacker who can plant a malicious rule (or convince the operator to
import one). Killing PID 1 reboots the machine; killing `mds` breaks
Spotlight; killing `loginwindow` logs the user out.

**Mitigation:** Explicit denylist of system PIDs and well-known daemons.
Apple-signed processes get an extra check (typically rejected unless
the rule explicitly opts into killing Apple binaries — rare and
intentional).

**Residual risk:** A novel Apple daemon not in the denylist could be
killed. Test corpus tracks the list against `/usr/libexec/` and
`/System/Library/LaunchDaemons/` reasonably comprehensively.

### `SafeQuarantinePathValidator` — file quarantine

**Threat:** Quarantine moves a file to `~/.Trash/MacCrab-quarantine/`.
A bad path argument could quarantine `/usr/bin/sh` (system breakage)
or `~/Documents/important.docx` (user data loss).

**Mitigation:** Reject system paths, reject symlinks (defeats
TOCTOU/swap attack), require parent dir to be user-owned. The
quarantine destination has an O_NOFOLLOW write so a symlink swap
between path validation and move-time can't redirect into a
privileged path.

**Test scenarios pinned:** symlink-to-system, symlink-to-user-other,
relative-path traversal, parent-not-owned-by-user, system-prefix
check, paths-with-..-components.

### `SafeBlockableIPValidator` — network block

**Threat:** Blocking the wrong IP can wedge the operator's machine.
Blocking `127.0.0.1` breaks every local service. Blocking
`169.254.169.254` is fine on a laptop but wedges a cloud VM trying
to read instance metadata. Blocking the gateway breaks all networking.

**Mitigation:** Loopback and reserved ranges always rejected.
Link-local IP literals rejected. Apple infrastructure (iCloud,
gateway domains) rejected so MacCrab can't accidentally cut the
machine off from Apple update infrastructure.

**Residual risk:** An attacker who can spoof DNS to make a critical
domain resolve to 8.8.8.8 could trick a network-block on an "attacker
IP" into blocking 8.8.8.8 itself. Mitigation: the check runs at
DNS-result time, so a transient resolution doesn't become permanent.

### `validateScriptPath` — run script

**Threat:** This was the v1.8.0 LPE class. The sysext runs as root.
Pre-fix, `runScript` in `actions.json` accepted any path. A non-root
user could write a malicious script to a path they own, point a rule
at it, and have it execute as root with sensitive event metadata in
env vars.

**Mitigation:** Allowlisted directories only
(`/Library/Application Support/MacCrab/scripts/`,
`/usr/local/maccrab/scripts/`), both root-owned 0o755 at install time.
Reject symlinks (lstat-based check). Reject group-writable +
world-writable. Owner must be uid 0.

**Residual risk:** A user with sudo can plant scripts under either
allowlisted dir as root and weaponize them — but a user with sudo
already has root, so this is moot.

### TCC service name allowlist — TCC revoke

**Threat:** Revoking arbitrary TCC permissions can lock the operator
out of their own permission grants. Revoking the dashboard's
Full Disk Access in response to an alert about the dashboard would
permanently break detection.

**Mitigation:** Allowlist of TCC service names that response actions
can touch. The dashboard's own bundle is excluded from the allowed
target set.

### DNS sinkhole — domain reject rules

**Threat:** Sinkholing the wrong domain can wedge networking. A typo
sinkholing `apple.com` breaks the App Store / iCloud / Sparkle
updates.

**Mitigation:** Reserved TLDs rejected. IP literals rejected. The
sinkhole is implemented as a per-process `/etc/hosts` overlay, not a
global one — minimizes blast radius.

### Persistence guard — LaunchAgent/Daemon write block

**Threat:** Aggressively blocking LaunchAgent writes can prevent
legitimate installers (Adobe, Zoom, etc.) from completing. Blocking
during a System Settings preferences-pane interaction can leave the
user thinking their click didn't work.

**Mitigation:** Apple-signed installers get a soft pass. Recently
user-interacted System Settings activity is whitelisted (the heuristic
isn't perfect — flagged in `PreventionTests.swift` known-FP cases).

### Supply-chain gate — compound

**Threat:** A bad supply-chain decision (block-on-pkg-install) can
break developer machines mid-build. False positives in this category
are very visible.

**Mitigation:** Multi-signal — signing identity, notarization status,
origin (homebrew vs. arbitrary curl|sh), file size sanity. Test corpus
includes known-good (homebrew install, App Store install, Sparkle
update) and known-bad (typosquat brewe.sh, curl|sh from random
domain) scenarios.

## Operator checklist before enabling response actions

1. Read `actions.json.example` first.
2. Enable in **alert-only** mode and watch for a week.
3. Review false-positive rate per rule via the dashboard's
   "What fired and what was suppressed" view.
4. Enable response actions ONE rule at a time, starting with
   the most clearly malicious patterns.
5. Keep sudo/recovery access available — if a response action
   wedges your machine, you'll need it.

## Audit trail

Every response action fire is logged via `os_log` with `.public` privacy:

- subsystem: `com.maccrab.detection`
- category: `response`

To inspect:

```bash
log show --predicate 'subsystem=="com.maccrab.detection" AND category=="response"' --last 1h
```

The unified log is the canonical record. The dashboard surfaces a
filtered view, but the underlying log is what an incident review will
read.

## Reporting

Found a way to bypass any of the safety validators above? That's a
critical-class issue — please open a private security advisory at
[github.com/peterhanily/maccrab/security/advisories](https://github.com/peterhanily/maccrab/security/advisories).

## Related docs

- [`THREAT_MODEL.md`](THREAT_MODEL.md) — what attackers MacCrab does and doesn't defend against
- [`TRUST.md`](TRUST.md) — release verification: signing, notarization, Sparkle signatures
- [`MODULES.md`](MODULES.md) — stable vs experimental subsystem labels (response actions are experimental)
