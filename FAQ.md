# MacCrab FAQ

Quick answers to the most common questions. If your question is about a
specific error or unexpected behavior, see
[TROUBLESHOOTING.md](TROUBLESHOOTING.md) instead.

---

### Why am I not seeing any alerts?

The most common cause is **Full Disk Access not granted to MacCrab.app**.
Without it, MacCrab silently drops file events for TCC-protected paths
(which covers most of your home directory). The Overview banner catches
this now — if it's showing, click *Open Settings* and grant access.

Other possibilities: the System Extension isn't activated (check *Overview
→ Protection active*), no rules are compiled (`maccrabctl rules list | wc
-l` should be ~380), or you're inside the 60-second startup warm-up
window that suppresses non-critical alerts.

Full diagnostic walkthrough in [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

---

### Can I write my own detection rules?

Yes. MacCrab uses a Sigma-compatible YAML format. Drop a `.yml` file in
the appropriate `Rules/<tactic>/` directory, run `make compile-rules`, and
the detection engine picks it up on next SIGHUP or restart.

See [Rules/README.md](Rules/README.md) for the full format reference,
including the extended sequence-rule syntax (`type: sequence`) for
multi-step attack chains. `make lint-rules` catches syntax errors and
duplicate UUIDs; `make test-fp` verifies your rule doesn't flag benign
system activity.

---

### What data leaves my machine?

**By default, zero.** MacCrab has no telemetry, no phone-home, and no
cloud console. All events, alerts, and rules stay in a local SQLite
database at `/Library/Application Support/MacCrab/events.db`.

Optional features that make outbound calls (only when you enable them):

| Feature | What it sends | Sanitization |
|---|---|---|
| Threat intel feeds | Periodic pulls from abuse.ch for IOC lists | Read-only pull, nothing about you sent |
| LLM reasoning backends (Claude/OpenAI/Gemini/Mistral) | Sanitized alert/event text for investigation summaries | Usernames, private IPs, hostnames, emails redacted before send |
| Ollama backend | Same as above, but to a local process | N/A — never leaves the machine |
| Webhook output (`MACCRAB_WEBHOOK_URL`) | Alert JSON payloads to your configured URL | URL policy rejects RFC1918 unless opt-in, blocks cloud metadata IPs unconditionally |
| Syslog output (`MACCRAB_SYSLOG_HOST`) | Alert RFC 5424 syslog messages to your configured host | None (your infrastructure) |
| Fleet telemetry (`MACCRAB_FLEET_URL`) | Alert summaries and IOC sightings to your fleet server | Username + private IP redaction; opt-in per-host |

See [PRIVACY.md](PRIVACY.md) for the full inventory.

---

### Can I disable specific rules?

Three options, from least to most surgical:

1. **Suppress a specific alert:** click *Suppress* in the dashboard, or
   `maccrabctl suppress <alertID>`. Per-alert; fastest.
2. **Suppress a rule for a specific process:** add to
   `suppressions.json` (see `docs/suppressions.example.json`) or use
   `maccrabctl suppress <ruleID> <processPath>`.
3. **Disable a rule entirely:** delete the YAML file from `Rules/<tactic>/`
   and re-run `make compile-rules`. (Or use the Rules tab toggle in the
   dashboard, which sets a per-rule disable flag without deleting the
   YAML.)

The *Suppress All Like This* button on an alert's detail panel adds a
`(ruleTitle, processName)` pattern that auto-hides future matches.

---

### Does it work offline / in air-gapped environments?

**Yes.** MacCrab's core detection pipeline needs zero network access. All
380 rules are compiled at install time. Behavioral scoring, sequence
correlation, campaign detection, and the SQLite store are fully local.

Features that need network:
- Threat intel feeds (abuse.ch pulls)
- Cloud LLM backends (Claude/OpenAI/Gemini/Mistral)
- Webhook/syslog/fleet outputs
- `brew upgrade` for updates

You can run MacCrab with all network features disabled (it's the default)
— use the Ollama LLM backend if you want AI reasoning on an air-gapped box.

---

### How do I update MacCrab?

**Homebrew:** `brew upgrade --cask maccrab`. Restart `MacCrab.app` after
the upgrade completes. Within-family upgrades (v1.3.0 → v1.3.5) don't
require re-approval of the System Extension; major-version upgrades might
(see [UPGRADE.md](UPGRADE.md)).

**DMG:** download the new DMG from the GitHub Releases page and drag
`MacCrab.app` over the old one in `/Applications/`. The app handles sysext
replacement via `OSSystemExtensionRequest(.replace)` on next launch.

**Automatic in-app update** via Sparkle is planned for v1.4.

---

### Is MacCrab free? What's the license?

**Yes, free.** Apache 2.0 for the code, Detection Rule License 1.1 (DRL
1.1) for the Sigma rules in `Rules/`. You can use it commercially, fork
it, embed it — standard Apache terms. The detection rules have their own
license because DRL 1.1 is the SigmaHQ standard for community rule
redistribution.

No paid tier, no enterprise SKU, no hidden usage limits. The optional
cloud LLM backends bill against *your* API key — MacCrab never sees them.

---

### Does MacCrab work on Apple Silicon *and* Intel Macs?

Yes. The shipped binaries are universal (`arm64` + `x86_64`). Tested on
both architectures in CI.

---

### What macOS versions are supported?

**macOS 13 Ventura and later.** The Endpoint Security improvements that
MacCrab relies on (specifically the `es_event_exec_t.args` path and
several TCC event types) landed in 13. Older versions won't compile the
Swift 5.9 target; and even if they did, key events would be missing.

---

### Do I need to run MacCrab as root?

The **System Extension** runs with elevated privileges granted by
`sysextd` — that's the whole point of the sysext architecture. You don't
see it as root because Apple hides that implementation detail.

The **dashboard app** (`MacCrab.app`) runs as your regular user. It only
reads the database.

The **CLI** (`maccrabctl`) runs as your regular user. It reads the
database; actions like `suppress` and `unsuppress` write to a user-writable
file.

For local development without the sysext, you can `sudo maccrabd` to run
the legacy daemon directly — but release builds don't use that path.

---

### What's the difference between MacCrab and Santa / osquery / commercial EDR?

- **Santa** is about *execution control* — it allowlists / blocklists
  binaries from running. MacCrab *detects* suspicious activity but
  doesn't by default block execution. The two are complementary.
- **osquery** lets you *query* system state on a schedule. MacCrab
  *streams* events in real-time and runs rules against them as they
  happen. osquery is SQL-shaped; MacCrab is event-driven.
- **Commercial EDR** (CrowdStrike / SentinelOne / Jamf Protect) gives
  you the same ES streaming detection MacCrab does, plus a cloud console,
  fleet management, 24/7 SOC, and a sales rep. MacCrab is free, local-
  only, and you are the SOC.

See the comparison table in [README.md](README.md) for a feature-by-
feature breakdown.

---

### Can I feed MacCrab alerts to my SIEM?

Yes. Four output formats ship out of the box:

| Format | How |
|---|---|
| JSONL | Default — `~/Library/Application Support/MacCrab/alerts.jsonl` |
| Syslog RFC 5424 (UDP/TCP) | `MACCRAB_SYSLOG_HOST=...` / `MACCRAB_SYSLOG_PORT=...` |
| Webhook (JSON POST) | `MACCRAB_WEBHOOK_URL=...` |
| OCSF-formatted JSON | Dashboard → Alerts → Export |

Splunk HEC, Elastic Bulk, Datadog Logs, and S3/SFTP can be configured via
`daemon_config.json`'s `outputs[]` block (see
`docs/daemon_config.example.json`).

CEF export is planned for a future release.

---

### How do I completely uninstall MacCrab?

**Homebrew:** `brew uninstall --cask maccrab`. The cask's `uninstall` block
deactivates the System Extension and cleans up the app bundle, binaries,
LaunchDaemons (if any), and provisioning profiles.

**Manual data wipe (if desired):**

```bash
sudo rm -rf /Library/Application\ Support/MacCrab/    # system data
rm -rf ~/Library/Application\ Support/MacCrab/        # dev / non-root data
rm -f ~/Library/Preferences/com.maccrab.app.plist     # app preferences
```

The uninstall does *not* delete your data by default — the data paths are
left intact so you can reinstall without losing alert history. Remove them
manually if you want a clean slate.

---

### Where do I report a bug / security issue / feature request?

- **Bugs:** [GitHub Issues](https://github.com/peterhanily/maccrab/issues)
  — include the output of `maccrabctl status` and the diagnostic log
  command from [TROUBLESHOOTING.md](TROUBLESHOOTING.md#collecting-diagnostics-for-a-bug-report).
- **Security issues:** do NOT open a public issue. Email
  maccrab@peterhanily.com. See [SECURITY.md](SECURITY.md) for the disclosure
  policy.
- **Feature requests:** GitHub Issues with the `enhancement` label.
- **Detection rule contributions:** pull requests to `Rules/` are very
  welcome. See [Rules/README.md](Rules/README.md) for the format and
  submission checklist.
