# Troubleshooting

Common issues and how to diagnose them. If your problem isn't here, check
[FAQ.md](FAQ.md) and open a GitHub issue with the output of `maccrabctl status`.

---

## Protection won't activate — System Extension stays stuck

**Symptom:** You click *Enable Protection* in MacCrab.app, the panel goes to
"Approval required" (or stays on "Activating"), and nothing happens.

**Fix:**

1. Open **System Settings → General → Login Items & Extensions → Endpoint
   Security Extensions**. (On macOS 13, the pane is under
   **Privacy & Security → Security**.)
2. Toggle **MacCrab** on.
3. Authenticate when prompted.

**Diagnostic commands:**

```bash
# List system extensions — look for com.maccrab.agent
systemextensionsctl list

# Watch sysextd's opinion in real time while you click Enable Protection
log stream --predicate 'subsystem == "com.apple.sysextd"' --info
```

If `systemextensionsctl list` shows the extension as `[activated waiting for
user]`, the approval prompt was dismissed. Click *Try again* in the MacCrab
panel to re-present it.

### Known rejection signatures (from v1.3.x)

If `sysextd` logs say:

| sysextd log | Cause | Fix |
|---|---|---|
| `package type not 'DEXT' ... not 'SYSX'` | Stale bundle with `CFBundlePackageType = SYEX` (v1.3.0–v1.3.2) | Upgrade to v1.3.3+ |
| `does not appear to belong to any extension categories` | Missing `NSSystemExtensionPointIdentifier` | Upgrade to v1.3.2+ |
| `Error Code=-413 "No matching profile found"` | Running a v1.2 LaunchDaemon build with the ES entitlement — AMFI rejects | Upgrade to v1.3+ (sysext architecture) |
| Activation code 4 (validation failed) on macOS 15+ | App launched from `~/Downloads/` | Move `MacCrab.app` to `/Applications/` and relaunch |

---

## "Protection active" but no alerts fire

**Symptom:** Overview says all clear. Events/sec is zero or very low. You can
trigger test activity and nothing shows up.

**Most likely cause: Full Disk Access not granted.**

Without FDA, MacCrab can monitor process events but **silently drops** any
file event on a TCC-protected path — which is most of `~/`. The FDA banner
at the top of the Overview catches this; if you cleared the banner, check:

```bash
# TCC.db readable means FDA is granted; permission denied means it isn't.
ls -la ~/Library/Application\ Support/com.apple.TCC/TCC.db
```

**Fix:**

1. Open **System Settings → Privacy & Security → Full Disk Access**.
2. Add `MacCrab.app` (drag it from `/Applications/` if necessary).
3. Quit and reopen MacCrab.app.

### Other causes for silent detection

- **No rules loaded.** Check `maccrabctl status` — the `Rules:` line reports
  `<active> active / <loaded> loaded standard`, 109 active of 438
  compiled under the default stable rule profile (set `rule_profile: all` in
  `daemon_config.json` to activate the rest). `rules list | wc -l` is *not*
  this number: it counts every compiled rule plus four header lines,
  irrespective of profile. If the active count is zero, run
  `make compile-rules` and look for errors.
- **Warm-up window.** Non-critical alerts are suppressed in the first 60
  seconds of daemon start, to avoid floods during replay of backlogged
  events. Critical matches always survive.
- **Suppression leak.** Check `maccrabctl rules list --suppressed` and
  `~/Library/Application Support/MacCrab/suppressions.json` — an overly
  broad suppression pattern silences legitimate alerts too.

---

## Dashboard stuck on "Disconnected"

**Symptom:** Menubar app shows the red offline dot, and the Overview banner
says "Enable protection above…" even though the extension is active.

**Diagnostic:**

```bash
# Is the sysext actually running?
pgrep -l com.maccrab.agent

# Is the database being written to?
ls -la ~/Library/Application\ Support/MacCrab/events.db*
# WAL file timestamp should be recent
```

**Common causes:**

- Extension crashed silently. Restart it: toggle off/on in System Settings
  or `systemextensionsctl uninstall 79S425CW99 com.maccrab.agent` then
  re-activate via the app.
- Database location mismatch — release installs write to
  `/Library/Application Support/MacCrab/`; dev `swift run maccrabd`
  writes to `~/Library/Application Support/MacCrab/`. Running both on the
  same machine is supported, but the dashboard reads the system path when
  the sysext is active. Stop the dev daemon with `make stop` if confused.

---

## `make compile-rules` fails

**Symptom:** `python3 Compiler/compile_rules.py` prints errors and exits
non-zero.

**Fix order:**

1. `pip install pyyaml` — the compiler needs PyYAML.
2. `make lint-rules` — surfaces YAML syntax errors with file + line.
3. Look for **duplicate YAML keys** warnings: `mapping has duplicate key
   'selection' ...` means two selection blocks shadow each other; rename
   one.
4. **Unmapped Sigma fields** warnings: the compiler prints the field name.
   If it's a real field you need, add it to `SIGMA_FIELD_MAP` in
   `Compiler/compile_rules.py`; if it's a typo, fix the YAML.

---

## "Webhook URL rejected" on daemon start

**Symptom:** Daemon startup prints `ERROR: MACCRAB_WEBHOOK_URL rejected:
...`, webhook output disabled.

**Cause:** The webhook SSRF policy (shipped in v1.3.5) rejects:

- Non-`https` schemes, except `http://localhost` / `http://127.0.0.1`
- RFC1918 and link-local addresses (10.x, 192.168.x, 172.16–31.x, 169.254.x)
- Cloud metadata IPs (169.254.169.254, fd00:ec2::254, 100.100.100.200) — always blocked
- IPv6 unique-local (fc00::/7) and link-local (fe80::/10)

**Fix:**

- **Public HTTPS endpoint** (Slack/Teams/PagerDuty): use it as-is.
- **Intranet webhook on a private IP**: set
  `MACCRAB_WEBHOOK_ALLOW_PRIVATE=1` before starting the daemon. This opts
  into the private-address path but still blocks metadata IPs.
- **Local testing**: use `http://localhost:8080/hook` — loopback is allowed
  without the escape hatch.

---

## Homebrew upgrade leaves old state around

**Symptom:** After `brew upgrade --cask maccrab`, you still see a pre-1.3
`maccrabd` LaunchDaemon running, or the dashboard reports an old version.

**Fix:**

```bash
# Stop any legacy daemon and clear the old plist
sudo launchctl unload /Library/LaunchDaemons/com.maccrab.daemon.plist 2>/dev/null || true
sudo rm -f /Library/LaunchDaemons/com.maccrab.daemon.plist

# Remove any old provisioning profiles from the system location
sudo find /Library/MobileDevice/Provisioning\ Profiles -name 'com.maccrab.*' -delete 2>/dev/null || true

# Reactivate the sysext
systemextensionsctl reset 2>/dev/null || true
open /Applications/MacCrab.app
# Click Enable Protection
```

The cask's `postflight` runs this cleanup automatically. If it didn't run
(because you installed from source or did a partial upgrade), the commands
above do the same work.

---

## "Operation not permitted" errors in dev

**Symptom:** Running `swift run maccrabd` without sudo prints a pile of
`Operation not permitted` errors, or the daemon immediately exits.

**Cause:** Without root, the Endpoint Security framework is unavailable.
MacCrab's `maccrabd` target falls back to `eslogger` + `kdebug` + FSEvents,
but `eslogger` also requires root.

**Fix choices:**

- Run as root for full dev coverage: `sudo make dev` (or `sudo
  .build/debug/maccrabd`).
- Accept the FSEvents-only fallback: `make dev-no-es`. File events still
  work; process exec/fork don't.
- For the full release experience, install the notarized DMG and let the
  sysext handle it.

---

## Installed-host qualification aborts before 900 seconds

**Symptom:** `candidate-qualification.py record-runtime` exits during
readiness/prewarm instead of starting or completing the 900-second timer.

This is intentional fail-fast behavior. A cumulative loss, shed, eviction,
failed-write, blocked/over-budget store, free-space-floor breach, non-writable
TraceStore, or failed/open LLM state cannot become a zero-loss epoch by waiting.
The adjacent `.runtime.json.capture.json` records the failing phase, reason,
readiness observations, and any samples already captured. Preserve it together
with `maccrabctl status`, the rich heartbeat, and relevant unified logs before
changing the running process.

Use this order:

1. Confirm that the exact candidate DMG is installed, Agent Traces and its
   loopback receiver are enabled, and an alert-investigation LLM is configured.
   A never-used LLM may initially be unhealthy only because it has no successful
   request; the recorder's exact alert prewarm is designed to establish health.
   A failure streak, open circuit, rejected response, or backend failure is not
   an uninitialized state.
2. If the capture shows only historical process-lifetime counters from an older
   candidate or earlier out-of-contract load, retain the diagnostics and
   gracefully deactivate/reactivate Protection (or reinstall/activate the exact
   candidate). Confirm that the engine PID changed, allow startup recovery to
   finish, and retry once.
3. Keep the shipping configuration and retained databases. Do not increase a
   cap, disable the LLM/TraceStore, delete SQLite files, run `make clear-data`,
   or pass `--sqlite-cap` for a shipping database. `make clear-data` is unsafe
   while the installed system extension still owns open database handles. A
   wiped store is a separate clean-install test, not evidence that a dirty
   retained-state candidate can recover.
4. Treat any storage/backend fault that remains after restart, or any loss that
   recurs during prewarm or the bounded workload, as a candidate defect. Fix it
   and build a new candidate; do not reinterpret or reset the failed evidence.

The expected recorder order is storage/loss/conservation readiness, bounded
queue drain, exact alert-only LLM prewarm, full healthy/drained readiness, then
t0. At minute 5 the bulk pressure stays under a unique
`/Users/Shared/MacCrabQualificationRuntime-<run-id>` tree while a separate small
shell probe tests sequence continuity. The workload must exit by 390 seconds
and all queues drain by 450 seconds. The causal alert proof queries
`alerts.db` read-only/no-follow for the exact unique executable and trigger
boundary; unrelated alert investigations cannot satisfy it.

TraceGraph physical-write suppression is not reported as loss when it is
proof-safe. Its event/row counters must be monotonic, and row conservation is
`entity observations + edge observations = attempted + coalesced + physically
suppressed + pending`. The minute-5 deltas must both be positive and equal under
the current one-row-per-event suppression contract. Zero or mismatched deltas
are blocking because they would leave the write-volume repair unexercised.

---

## Collecting diagnostics for a bug report

If you're opening an issue, include the output of:

```bash
maccrabctl status
systemextensionsctl list | grep maccrab
sw_vers
log show --last 5m --predicate 'subsystem BEGINSWITH "com.maccrab"' > ~/maccrab-log.txt
```

Attach `~/maccrab-log.txt` and the `maccrabctl status` output to the issue.
Scrub anything sensitive — alert descriptions can contain file paths under
`/Users/<you>/`.
