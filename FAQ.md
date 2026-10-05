# MacCrab FAQ

Quick answers to the most common questions. If your question is about a
specific error or unexpected behavior, see
[TROUBLESHOOTING.md](TROUBLESHOOTING.md) instead.

---

### Why am I not seeing any alerts?

The most common cause is **Full Disk Access not granted to MacCrab.app**.
Without it, MacCrab silently drops file events for TCC-protected paths
(which covers most of your home directory). **System → Permissions** in the
dashboard shows whether the engine has Full Disk Access.

Other possibilities: the System Extension isn't activated (check
**System → Health**), no rules are compiled (run `maccrabctl status`: it
prints `Rules: <active> active / <loaded> loaded standard` plus the sequence
rules, which on a stock install reads 98 active of 438 single-event rules and
11 active of 41 sequence rules under the default **stable** profile.
Do *not* use `rules list | wc -l` — that enumerates every compiled rule
regardless of profile, plus four header lines), or
you're inside the 60-second startup warm-up window that suppresses
non-critical alerts.

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

**By default, no detection data.** MacCrab has no telemetry and no cloud
console. Events, alerts, and rules stay in local SQLite databases under
`/Library/Application Support/MacCrab/`. The one request a release build
makes by default is the daily Sparkle update check to `maccrab.com`, which
sends app-version information and no detection data. The app has no setting
to turn automatic update checks off.

Optional features that make outbound calls (only when you enable them):

| Feature | What it sends | Sanitization |
|---|---|---|
| Threat intel feeds | Periodic pulls from abuse.ch for IOC lists | Download-only; receives IP, version and request metadata, plus Auth-Key for authenticated exports |
| LLM reasoning backends (Claude/OpenAI/Gemini/Mistral) | Sanitized alert/event text for investigation summaries | Usernames, private IPs, hostnames, emails redacted before send |
| Ollama backend | Same as above, but to a local process | N/A — never leaves the machine |
| Webhook output (`MACCRAB_WEBHOOK_URL`) | Alert JSON payloads to your configured URL | URL policy rejects RFC1918 unless opt-in, blocks cloud metadata IPs unconditionally |
| Syslog output (`MACCRAB_SYSLOG_HOST`) | Alert RFC 5424 syslog messages to your configured host | None (your infrastructure) |
| Fleet telemetry (`MACCRAB_FLEET_URL`) | Alert summaries and IOC sightings to your fleet server (outbound-only; use `https://` — plain `http://` is accepted only for loopback hosts) | Username + private IP redaction; opt-in per-host |
| Rave store (Forensics → Catalog) | Catalog and signed revocation-list requests to `rave.maccrab.com` when you open the Catalog or have a store plugin installed; the plugin download when you install one | No detection data is sent |
| Forensic plugins (Rave store or sideloaded) | Only if a plugin you install declares network egress **and** you consent | Store plugins today are first-party and run unsandboxed with MacCrab's access. Plugins from other publishers run sandboxed and read only their declared files (personal-comms served as snapshots, never live); the consent sheet flags any reads-personal-data + has-network combo |

See [PRIVACY.md](PRIVACY.md) for the full inventory.

---

### Is it safe to install third-party forensic plugins from the store?

Every plugin in the Rave store today is **first-party**: signed with the
publisher key compiled into MacCrab and run **without a sandbox**, with
MacCrab's own access (including Full Disk Access when granted). Trust them as
you trust MacCrab itself.

A plugin signed by any other publisher (sideloaded, or a future community
store entry) is **untrusted code**, so MacCrab runs it in a way that assumes it
might be hostile:

- They execute **only** inside a deny-default sandbox (a signed trampoline
  applies the OS sandbox before the plugin's code runs).
- They can read **only** the files their signed manifest declares — requested
  through a broker, so a symlink trick or an undeclared path can't be opened.
- Protected stores (Messages, Mail, Safari history, …) are handed to the plugin
  as a **snapshot copy**, never the live store, and the plugin never inherits
  your Full Disk Access.
- The install consent sheet shows the real read-set + network access, derived
  from the plugin's enforced capabilities (a plugin can't lie about what it
  touches). A plugin that both reads personal data and has network egress is
  flagged as a high-friction exfil surface.
- You can revoke a publisher, freeze the catalog, or locally disable all
  third-party execution at any time.

Third-party plugin execution is **on by default but gated**: a third-party
plugin runs only after you install it (an install from the official catalog
trusts the signer key the signed catalog names; a sideload needs
`--trust-on-install` or `maccrabctl plugin trust`), and only when the sandbox
runtime is available. Creating
`~/Library/Application Support/MacCrab/tierb_third_party_disabled` turns the
third-party lane off; first-party plugins still run. The technical detail is in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) §8.

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

**Yes.** MacCrab's core detection pipeline needs zero network access. The
486 rules ship precompiled in the app; the default stable profile loads 116 of
them. Behavioral scoring, sequence correlation, campaign detection, and the
SQLite store are fully local.

Features that need network:
- Threat intel feeds (abuse.ch pulls)
- Cloud LLM backends (Claude/OpenAI/Gemini/Mistral)
- Webhook/syslog/fleet outputs
- The Rave plugin store
- Update checks (Sparkle, on by default in release builds) and `brew upgrade`

Every network feature above except the update check is off by default. The
update check fails harmlessly without a network. Use the Ollama LLM backend if
you want AI reasoning on an air-gapped box.

---

### How do I update MacCrab?

**Homebrew:** `brew upgrade --cask maccrab`. Restart `MacCrab.app` after
the upgrade completes. Within-family upgrades (v1.3.0 → v1.3.5) don't
require re-approval of the System Extension; major-version upgrades might
(see [UPGRADE.md](UPGRADE.md)).

**DMG:** download the new DMG from the GitHub Releases page and drag
`MacCrab.app` over the old one in `/Applications/`. The app handles sysext
replacement via `OSSystemExtensionRequest(.replace)` on next launch.

**Automatic in-app update** via Sparkle is built in — accept the update prompt and the app replaces itself (and the system extension) on relaunch.

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

The shipped binaries are universal (`arm64` + `x86_64`), and the release
build refuses to ship if either architecture fails to compile. Testing is not
symmetric: there is no hosted CI, and the automated test suite runs locally on
Apple Silicon only. Intel builds are compiled but not covered by automated
tests; see [docs/SUPPORTED_OS.md](docs/SUPPORTED_OS.md).

---

### What macOS versions are supported?

**macOS 13 Ventura and later.** The Endpoint Security improvements that
MacCrab relies on (specifically the `es_event_exec_t.args` path and
several TCC event types) landed in 13. Older versions won't compile the
Swift 5.9 target; and even if they did, key events would be missing.

---

### Do I need to run MacCrab as root?

The **System Extension** runs as root, launched and managed by `sysextd` —
that's the whole point of the sysext architecture. You don't start it
yourself; approving the extension once in System Settings is enough.

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

See [README.md](README.md) for what MacCrab does and does not cover.

---

### Can I feed MacCrab alerts to my SIEM?

Yes. None is on by default; configure the one you need:

| Format | How |
|---|---|
| JSONL file (OCSF 1.3 or native) | A `file` entry in `daemon_config.json`'s `outputs[]` block, with `"format": "ocsf"` (the default) or `"native"` |
| Syslog RFC 5424 (UDP/TCP) | `MACCRAB_SYSLOG_HOST=...` / `MACCRAB_SYSLOG_PORT=...` |
| Webhook (JSON POST) | `MACCRAB_WEBHOOK_URL=...` |
| MacCrab JSON Lines, on demand | Dashboard → Alerts → Export (visible alerts, MacCrab's own fields, not OCSF) |

Splunk HEC, Elastic Bulk, Datadog Logs, and S3/SFTP can be configured via
`daemon_config.json`'s `outputs[]` block (see
`docs/daemon_config.example.json`).

---

### How do I completely uninstall MacCrab?

**Homebrew:** `brew uninstall --cask maccrab` removes the app bundle and
binaries, but intentionally leaves the Endpoint Security System Extension
registered. Before uninstalling, use **Remove System Extension** in the app's
Settings and approve the macOS request. Wait for removal to complete, rebooting
first if required; check `systemextensionsctl list` for the final state.
Quitting the dashboard alone does not stop the extension. `--zap` removes
configured data directories as well; it does not replace this deactivation step.

**Manual data wipe (if desired):** only after extension removal completes and
any development daemon, dashboard, and MCP clients have stopped:

```bash
sudo rm -rf /Library/Application\ Support/MacCrab/    # system data
rm -rf ~/Library/Application\ Support/MacCrab/        # dev / non-root data
rm -f ~/Library/Preferences/com.maccrab.app.plist     # app preferences
```

The uninstall does *not* delete your data by default — the data paths are
left intact so you can reinstall without losing alert history. Remove them
manually if you want a clean slate.

---

### What is the MacCrab MCP server and how do I use it?

MacCrab ships a built-in [Model Context Protocol](https://modelcontextprotocol.io/)
server (`maccrab-mcp`) that exposes 67 built-in security tools (including the
20 always-present `forensics_*` meta-tools), plus per-plugin tools, to AI coding
tools like Claude Code. Once wired up, your AI sessions can query alerts, hunt
threats, and scan untrusted input — without leaving the editor.

**Setup:** on a Homebrew or DMG install, `maccrab-mcp` is already on your
`PATH`; register it with `claude mcp add maccrab -- "$(which maccrab-mcp)"`.
From a source checkout, build it with `swift build --target maccrab-mcp` and
copy `.mcp.json` from the repo root into your project.

Key tools: `get_alerts`, `get_campaigns`, `hunt`, `get_security_score`,
`get_alert_detail`, `suppress_campaign`, `get_ai_alerts`, and `scan_text`.

Pre-built slash commands in `.claude/commands/` give you `/security-check`,
`/threat-hunt <query>`, and `/alerts` as one-liners.

---

### What does `scan_text` do and when should I use it?

`scan_text` is the MacCrab MCP tool for **prompt-injection marker
scanning**. It runs MacCrab's native heuristic (the same detector AI Guard
applies to AI-tool command lines): 24 literal, case-insensitive signatures
across 7 categories (instruction override, jailbreak, prompt extraction, role
manipulation, tool poisoning, structural injection, exfiltration) plus an
invisible-Unicode check. It reports whether a known marker matched, the
matched pattern names, and an uncalibrated heuristic score. It is **not** a
safety verdict: base64, homoglyph, and split-token payloads pass, and a clean
result only means no known marker was found.

Use it **before acting on content from external sources** — files cloned from
the internet, output from third-party APIs, user-supplied prompts, or anything
else that an attacker might craft to hijack your AI tool's behavior.

```
scan_text: { text: "<paste suspicious content here>" }
```

The check is synchronous, local, and needs nothing else installed. Input must
be 10 to 10,000 characters; shorter text is not evaluated.

---

### What does AI Guard actually monitor — and what triggers an alert?

AI Guard tracks 9 AI coding tools (Claude Code, Codex, Cursor, Copilot,
Aider, Windsurf, Continue, OpenClaw, Kiro IDE) and their entire child
process trees.

Built-in checks that alert on a default install:

- **Credential fence** (MEDIUM): a child process opens a file matching one of
  27 sensitive path patterns — SSH keys, `.env` files, AWS credentials,
  keychains, browser credential stores, kubeconfig, `.npmrc`, `.pypirc`, etc.
- **Project boundary** (MEDIUM): a child process writes a file outside the
  directory the AI tool was launched in.
- **Prompt injection** (HIGH or CRITICAL): the native marker scanner matches
  an AI child's command line.
- **Hidden text in files**: invisible Unicode, bidi overrides, or tag
  characters in a file the tool reads.

Stable rules in `Rules/ai_safety/` add, among others: an AI tool running
`sudo` (MEDIUM), writing a LaunchAgent, LaunchDaemon, or cron entry (HIGH),
downloading a script (MEDIUM), and MCP-server tampering. Shell spawns and
package installs from an AI tool feed the behavioral score; their dedicated
rules are outside the stable profile (`rule_profile: all` loads them).

The **AI Guard tab** in the dashboard shows a live per-tool breakdown of
credential / injection / boundary / other alert counts, sorted by worst
severity, so you can see at a glance which tool is the noisiest.

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
