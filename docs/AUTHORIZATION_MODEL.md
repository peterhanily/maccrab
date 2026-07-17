# Daemon Control-Plane Authorization Model

This document describes how MacCrab's detection engine (the Endpoint Security
**System Extension**, or the legacy `maccrabd` daemon in dev) authorizes
control-plane requests that change its behaviour — suppressing alerts, reloading
rules, installing rules, changing daemon config, granting MCP capabilities, etc.

It is written for security reviewers and SOC teams who need to understand who can
mutate the engine's state, what each mutation can do, and what the residual risks
are. It reflects the code as shipped, including the gate's known limitations.

> Source of truth: `Sources/MacCrabAgentKit/DaemonTimers.swift`
> (`consoleUserUID()`, `isAuthorizedInboxRequest(uid:)`, `requestOwnerUID(at:)`,
> the per-verb `handle*Requests` functions, and `emitSelfProtectionAlert(...)`).

---

## Why a file-drop IPC exists

The detection engine runs as **root** and owns its SQLite stores
(`alerts.db`, `events.db`, `campaigns.db`, …) mode `0o640` (owner
read-write, group read-only, no other). The dashboard
(`MacCrab.app`) and the CLI run as the **logged-in user** (uid 501 on a typical
single-user Mac). That user cannot mutate the engine's state directly:

- A direct write to the root-owned DB fails with `SQLITE_READONLY`.
- A POSIX signal from a user process to the root sysext returns `EPERM`.
- `/tmp` is not a shared namespace between the user and the sysext sandbox.

So control actions are issued as **request files dropped into a privileged
inbox** that the engine drains. This is the only supported user → engine
control channel.

### The inbox directory

- Path: `<support-dir>/inbox/` — for release builds,
  `/Library/Application Support/MacCrab/inbox/`.
- Mode: **`1777`** (world-writable + sticky). World-writable so *any* local user
  can drop a request; the sticky bit prevents one user from deleting another
  user's request file.
- The engine polls the directory every **5 seconds**, partitions the files by
  request-type prefix, processes them in a defined order (mutations first, the
  expensive storage flush last), and **deletes each request file after handling**
  it (regardless of accept/reject).
- A per-tick in-flight lock prevents overlapping drains (a campaign-suppress
  fan-out can take tens of seconds).

Because the inbox is world-writable, the *authorization decision happens at the
handler*, not at the filesystem layer. Every verb runs the same gate before
acting.

---

## The authorization gate

For each request file, the engine determines the **UID of whoever dropped it**
and decides whether that UID is authorized.

### Establishing the requester's UID — `requestOwnerUID(at:)`

The owner UID is read from the request file with **`lstat()`** (not `stat()`),
and the file is rejected outright if:

- it is a **symlink** (`S_IFLNK`) — otherwise an attacker could symlink a
  root-owned file into the `1777` inbox and have its request authorized *as
  root*; or
- it is **hard-linked** (`st_nlink > 1`) — same forgery via a hardlink to a
  root-owned inode.

On any stat failure or rejection condition the function returns `-1`, which can
never satisfy the gate.

### The decision — `isAuthorizedInboxRequest(uid:)`

A request is authorized **only if** the dropping UID is:

1. **root (uid 0)** — launchd / `sudo` flows and the engine itself; or
2. **the live GUI console user *who is also an admin*** — the human physically
   at the keyboard running `MacCrab.app`, resolved via
   `SCDynamicStoreCopyConsoleUser` (`consoleUserUID()`) **and** confirmed to be a
   member of the macOS `admin` group (gid 80) via `isAdminUID()`
   (`getgrouplist`). A console result of `loginwindow`, empty, or nil means "no
   one is logged in" and the gate falls back to **root-only**.

Anything else — a **standard (non-admin) user even while at the keyboard**, a
guest user, a backgrounded session user under fast user switching, or a
UID-forged file — is **rejected and audit-logged**.

> **v1.19.1 (audit):** the admin-group requirement is now **enforced** in
> `isAuthorizedInboxRequest(uid:)`. Pre-fix, any foreground console user — incl.
> a standard non-admin user on a shared/managed Mac — could suppress/delete
> alerts, suppress campaigns, install rules, or weaken config via the `1777`
> inbox. Now the console user must be in the `admin` group. A second,
> pre-existing defense ships at the rules-directory layer: `DaemonSetup` refuses
> to load rules from any group- or world-writable rules directory
> (`Sources/MacCrabAgentKit/DaemonSetup.swift`), and the override overlay now
> also enforces **per-file** daemon ownership (`requireOwnerUID`). Detection-
> weakening config writes are additionally **clamped** to safe ranges and raise
> a self-protection meta-alert.

---

## What each verb can do

Every verb runs the same UID gate, validates its payload, and writes an audit
line. The mutating verbs:

| Request prefix | Effect | Notes |
|---|---|---|
| `suppress-alert-*` | Marks an alert suppressed | `{ "id": "<uuid>" }` |
| `unsuppress-alert-*` | Un-suppresses an alert | |
| `delete-alert-*` | Deletes an alert row | |
| `suppress-campaign-*` | Suppresses a campaign **and fans out** to every contributing alert | Can suppress thousands of alerts in one request |
| `refresh-intel-*` | Forces a threat-intel feed refresh | |
| `reload-rules-*` | Reloads compiled detection rules | |
| `install-rule-*` | Writes a user rule (`<support-dir>/user_rules/<id>.yml`+`.json`) and triggers a reload | id sanitized to `[a-z0-9-_]`, no path traversal; JSON ≤256 KB, YAML ≤64 KB; dir clamped to `0755` daemon-owned |
| `remove-rule-*` | Deletes a user rule and triggers a reload | |
| `builtin-rule-setting-*` | Enables/disables a built-in rule or overrides its severity | id must start with `maccrab.` |
| `set-daemon-config-*` | Sets one **whitelisted** `daemon_config.json` key | Only keys in an allow-list (thresholds, poll intervals, ES subscription toggles, etc.); value type-checked; effective on next config reload/restart |
| `llm-config-*` | Updates LLM backend config (non-secret keys only) | Non-loopback endpoints **default-denied** unless `allow_remote_endpoint=true`; only the newest authorized request applies; written `0600` root-owned |
| `set-agent-capabilities-*` | Sets the human's MCP agent capability grants (`config` / `authoring` / `response`) | Engine is the **only** writer of `mcp_capabilities.json` (root-owned `0644`), so an agent running as the console user cannot grant *itself* a tier |
| `record-clipboard-*` | Records a clipboard payload captured in user context (ClickFix correlation) | |
| `flush-request-*` | Forces a storage size-cap sweep | Processed last (slow) |

Notes on the sharper edges:

- **`set-daemon-config`** is key-whitelisted and type-checked. It cannot set
  arbitrary keys, secrets, or file paths.
- **`llm-config`** never accepts API keys/secrets, and a non-loopback endpoint
  is refused unless the requester explicitly sets `allow_remote_endpoint=true`
  (a strict loopback validator rejects tricks like `127.0.0.1.evil.com`).
- **`set-agent-capabilities`** is the only path that grants MCP agent power, and
  the engine — not the agent — owns the grants file. The MCP server trusts that
  file *solely because it is root-owned*.

---

## Audit logging

Every inbox request — accepted or rejected — appends one line to
`<support-dir>/dashboard_audit.log` (the same file the MCP control path writes
to, so operators have a single "who changed alert state" tail target). Format is
ISO-8601 timestamp + space-separated `key=value` pairs:

```
2026-06-24T... source=inbox prefix=suppress-alert id=<uuid> uid=501 result=ok
2026-06-24T... source=inbox prefix=set-agent-capabilities id=- uid=502 result=rejected_uid
```

Attacker-controlled fields (request id, result detail) are **sanitized** before
logging — newlines/CR/control chars are replaced and length is capped — so a
crafted request id cannot forge additional "ok" audit lines (log injection).

`result` values distinguish rejection reasons: `rejected_uid` (failed the gate),
`rejected_key` / `rejected_type` (config validation), `rejected_malformed`,
`url_rejected_nonloopback`, `ok`, `installed`, `removed`, etc.

---

## Self-protection meta-alert on detection-weakening actions

When an authorized request makes a **high-impact change to MacCrab's own
detection posture**, the engine records a self-protection alert
(`emitSelfProtectionAlert`, rule id `maccrab.self-defense.config_modified`,
severity **high**, MITRE `T1562.001` Defense Evasion). It fires on:

- **Granting an MCP agent capability tier** (false→true transition only);
- **Disabling an Endpoint Security event subscription**
  (`subscribe_file_open_events` / `subscribe_introspection_events` → false),
  which blinds a class of kernel telemetry; and
- **Enabling a remote (non-loopback) LLM endpoint**, after which engine prompt
  traffic may leave the host.

This alert is:

- **Observe-only** — the verb has *already* executed; the alert never blocks it.
  The model is: post-compromise, malware running as the console user *can* drive
  these UID-gated verbs, and MacCrab cannot prevent that without user-presence
  attestation — but it can make the change **loud**.
- Inserted **directly into the alert store** (visible in dashboard/CLI/MCP) and
  **bypasses the noise filter**, but is **not** OS-notified, to avoid spamming
  the operator on their own legitimate dashboard changes.

---

## Multi-user, fast-user-switching, and shared-Mac considerations

The gate's "console user" notion has explicit edge-case behaviour:

- **No one logged in (early boot, login window):** `consoleUserUID()` returns
  nil, and the gate falls back to **root-only**. Requests from any logged-out
  user UID are rejected.
- **Locked screen:** the console user is still the same UID as far as
  `SCDynamicStoreCopyConsoleUser` is concerned, so a process already running as
  that user can still drive verbs while the screen is locked. The gate is a
  *UID* check, not a *user-presence/unlock* check.
- **Fast user switching (FUS):** only the **foreground/active** GUI session's
  user is the "console user." A user switched to the **background** is *not*
  authorized — their dropped requests are rejected and audit-logged. This is the
  intended behaviour: the EDR should answer only to the human currently at the
  keyboard (or root).
- **Standard / guest / kiosk users:** a non-console standard user, a guest, or a
  kiosk account **cannot** suppress alerts, disable rules, or otherwise blind
  the engine — they fail the gate. This is the specific class of attack the gate
  was added to close (a `1777` inbox with no handler-level UID check would have
  let any local user silence the EDR).
- **Shared Macs (multiple admins):** today, *whichever* admin (or non-admin)
  is the live console user is treated as a trusted operator. The planned
  admin-group requirement (above) is aimed primarily at multi-user / shared-Mac
  deployments, where "at the keyboard" should not by itself confer the right to
  weaken detection.

### Residual risk (state plainly)

Code running **as the console user** (e.g. post-compromise malware, or a
malicious helper the user launched) can issue any inbox verb that the user could
issue from the dashboard, because the gate authenticates the *UID*, not user
presence or intent. MacCrab's compensating controls are **detection, not
prevention**: every action is audit-logged, and detection-weakening actions
raise a high-severity, noise-filter-bypassing self-protection alert. Operators
and SOC teams should monitor `dashboard_audit.log` and the
`maccrab.self-defense.*` alert class.

---

## Scope: single-host by design; no RBAC (out of scope this release)

MacCrab is a **single-host** endpoint tool. Its authorization model is
deliberately binary — **root, or the live admin console user** — and it has, by
design, **no role-based access control (RBAC), no multi-user role separation,
and no notion of "operator A may suppress but not author rules."** Every
authorized principal has the full control-plane surface documented above.

This is an intentional non-goal for this release, not an oversight:

- The product's unit of protection and administration is **one Mac**. There is
  no central console, no fleet server, and no shared operator directory that an
  RBAC policy could be scoped against — so a role model would be structure with
  nothing to enforce it over.
- The gate that *does* exist (root / admin-console-user) already matches the
  macOS trust boundary for a device its user administers. On a single-admin Mac
  — the overwhelmingly common case — RBAC would add no separation the OS doesn't
  already draw.
- Accountability, not role separation, is how this release bounds an authorized
  principal: **every** mutation is audit-logged (`dashboard_audit.log`) and
  detection-weakening changes raise a self-protection alert (see above).

**RBAC / role separation would only be required if a fleet console ships** — a
multi-operator, multi-host management plane where distinct humans need distinct,
enforceable authority (e.g. "the SOC tier may triage alerts fleet-wide but may
not disable detections"). That console does not exist in this release; if and
when it does, RBAC becomes an explicit requirement for it, enforced at that
plane. It is out of scope here.
