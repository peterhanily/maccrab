# Threat Model

MacCrab is a local-first macOS detection and investigation tool. This
page makes its threat model explicit so reviewers and operators can
judge what it does and doesn't defend against, and where residual
risk lives.

## Defender stance

A typical operator runs MacCrab on their own Mac (developer workstation,
researcher's box, security practitioner's daily driver). They:

- Are the local admin (or the box has a single user who can authorize
  System Extension activation).
- Want visibility into process, file, network, and TCC-permission
  activity in real time.
- Want some protection against detected threats — alerting always,
  optional response actions case by case.
- Want all this without sending event data to a vendor cloud, a SOC, or
  a SIEM by default.

MacCrab's detection and prevention are scoped to that operator and that
machine. Fleet management, multi-tenant isolation, and SOC workflows are
out of scope.

## In-scope attackers

Each row lists what MacCrab tries to defend, what's mitigated, and what
residual risk remains.

### 1. Malware running as the local user

**Goal:** persistence, credential theft, lateral movement, exfiltration.

**MacCrab defenses:**
- Endpoint Security captures process exec/fork/exit, file create/write/
  rename/unlink, network connect, and TCC permission changes in real
  time.
- 483 Sigma-style rules match adversary-known patterns (LaunchAgent
  drops, suspicious process trees, AMOS/Atomic Stealer wallet paths,
  XCSSET clipboard injection, etc.).
- Sequence rules correlate multi-step kill chains within bounded
  windows (longest is `ransomware_kill_chain.yml` at 10 minutes).
- Behavioral scoring + baseline anomaly detection flags novel process
  lineages and suspicious behavioral aggregates.
- AI Guard subsystem watches for prompt-injection abuse and AI tool
  guardrail bypasses.

**Residual risk:**
- Rules can be evaded by sufficiently novel attacker behavior.
- A patient attacker can pace activity to fall outside sequence
  windows.
- Rules with no `filter` block produce false positives at higher rates,
  which can train operators to ignore them. The audit script flags
  these.
- Detection coverage is documented in
  [`COVERAGE.md`](COVERAGE.md) — gaps are explicit, not pretended away.

### 2. Local user attempting privilege escalation against the daemon

**Goal:** subvert MacCrab itself — disable detection, suppress alerts,
escalate to root via the System Extension.

**MacCrab defenses:**
- The sysext runs as root via `sysextd`; its binary is signed by
  Apple-issued Developer ID + notarized + stapled. macOS refuses to
  activate a tampered or unsigned replacement.
- Response actions that take a user-supplied path (most importantly
  `runScript`) require the script to live in a root-owned allowlisted
  directory and reject symlinks, group-writable, and world-writable
  paths.
- Database, compiled rules, and config files are written 0o640 / 0o700
  with O_NOFOLLOW symlink-safe writes.
- Self-defense layer monitors the sysext's own state and logs
  tampering attempts to the unified log.

**Residual risk:**
- A user with sudo can `csrutil disable` (defeats SIP), `systemextensionsctl
  uninstall`, or chmod the support directory. MacCrab can't survive
  legitimate root rollback. The threat model assumes the attacker doesn't
  already have root via a separate path.
- macOS itself remains the trust root: a kernel-level rootkit below SIP
  is out of scope.

### 3. Malicious / corrupt config file

**Goal:** weaponize `daemon_config.json`, `actions.json`, or
`user_overrides.json` to disable detection or weaponize response actions.

**MacCrab defenses:**
- `daemon_config.json` and `actions.json` in `/Library/Application
  Support/MacCrab/` are root-owned. A non-root user can't write them.
- The user-writable overlay (`~/Library/.../user_overrides.json`)
  is restricted to a small list of storage-tuning keys
  (`storage.*`). Security-sensitive settings (thresholds, output
  destinations, LLM provider) are NOT overlaid from user-writable
  files.
- Storage values are clamped to safe floors (15 min hot tier, 50 MB
  caps, 1 day retention) so a hostile config can't immediately wipe
  history.

**Residual risk:**
- A user with sudo who edits the system-side config can do anything
  the daemon can do. Root is root.

### 4. Malicious webhook / output destination

**Goal:** trick MacCrab into POSTing alert data (potentially with
embedded credentials) to an attacker-controlled URL.

**MacCrab defenses:**
- All HTTP outputs use `SecureURLSession` with TLS 1.2 floor. Cleartext
  HTTP is rejected unless the host is loopback.
- SSRF policy validates URLs before request: rejects RFC1918 ranges,
  link-local, cloud-metadata addresses (169.254.169.254, fd00::/8,
  AWS/GCP/Azure metadata IPs).
- Slack / Teams / Discord / PagerDuty notification webhooks share the
  same SSRF policy as the generic webhook output.
- API tokens for output sinks are read from environment variables or
  Keychain, not stored cleartext in config files (see secret
  hardening discussion in v1.8.1).

**Residual risk:**
- Operators who set `MACCRAB_NOTIFICATION_ALLOW_PRIVATE=1` opt out of
  the SSRF policy for intranet webhook targets — that's a deliberate
  bypass and the operator owns the consequences.
- DNS rebinding — the SSRF check resolves the URL hostname at request
  time, but doesn't pin the IP for the duration of the connection.
  Allowlist-first egress for production targets is on the v1.9 roadmap.
- Redirect-following hasn't been audited. If an output URL responds
  with a 302 to a private IP, that's a gap.

### 5. Compromised LLM backend

**Goal:** A cloud LLM provider (or an attacker who has compromised one)
returns adversarial output that MacCrab acts on.

**MacCrab defenses:**
- LLM responses are **never auto-executed**. Triage suggestions,
  defense recommendations, and rule generations are advisory — the
  operator decides whether to apply them.
- LLM output is size-capped (50 KB), SQL-mutation-keyword-filtered, and
  prompt-injection-mitigation-prefixed.
- All cloud LLM requests go through automatic privacy sanitization
  (usernames, private IPs, hostnames redacted).
- Circuit breaker (3 failures → 5min cooldown) prevents an LLM that
  starts misbehaving from cascading.
- Local backends (Ollama) are recommended; cloud is opt-in.

**Residual risk:**
- An LLM that returns subtly wrong advice can bias an operator's
  triage. Operators should treat LLM output as one input, not as the
  conclusion.
- Privacy sanitization is best-effort regex; novel patterns might leak.

### 6. Tampered events.db / alerts.db / campaigns.db

**Goal:** A local user with database write access modifies historical
events to suppress evidence post-compromise.

**MacCrab defenses (current):**
- Files are root-owned 0o640. A non-root user can't open them
  read-write.
- Database key is encrypted at rest in Keychain with
  `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` (no iCloud
  Keychain roaming).
- AlertStore is a separate file (`alerts.db`) from the high-churn
  events table, so size-cap pruning of one can't evict the other.

**Residual risk (acknowledged):**
- Encryption is currently AES-256-CBC + PKCS7 — confidentiality only,
  not authenticity. A privileged attacker who can rewrite
  `events.db` to a forged ciphertext gets undetected tampering.
  Authenticated encryption (AES-GCM) is on the v1.9 roadmap; once
  shipped, MAC verification on every page read will catch tamper.
- The threat model treats local root as out-of-scope for tamper
  protection. With root, an attacker can do anything.

### 7. Sparkle auto-update channel hijack

**Goal:** ship a malicious "update" to existing installs.

**MacCrab defenses:**
- Sparkle's appcast is signed with an EdDSA key. The public half is
  embedded in the signed app bundle (`SUPublicEDKey` in `Info.plist`),
  so a tampered update server can't substitute its own key.
- The DMG download URL points to GitHub release assets — a separate
  trust path.
- Sparkle verifies the EdDSA signature **before** unpacking.
- The release pipeline notarizes + staples the DMG before publishing.
  An unstapled or unnotarized DMG fails Gatekeeper at install time.

**Residual risk:**
- Compromise of Peter Hanily's Apple Developer account would let an
  attacker sign a malicious update with the same identity. This is the
  single largest non-Apple supply-chain risk.
- Compromise of the EdDSA private key would do the same for Sparkle
  signature verification. The key is generated and held outside CI.

### 8. Malicious third-party forensic plugin (the rave marketplace lane)

**Goal:** a third-party plugin the operator installs from the rave store (or
sideloads) is hostile — it tries to escape its sandbox, exfiltrate the operator's
data (Messages, Mail, Keychains, SSH keys), or abuse the host's Full Disk Access
/ TCC grants. This is the one place MacCrab runs code it does **not** author, on
an FDA/TCC host.

**MacCrab defenses:**
- **Two disjoint lanes.** A first-party (MacCrab-signed) plugin runs unsandboxed
  only after a byte-match to a compiled-in publisher anchor; an untrusted
  third-party plugin runs **only** sandboxed. The lanes never cross and both
  fail-closed — a plugin that isn't provably first-party can never reach the
  unsandboxed lane.
- **Deny-default sandbox.** The third-party plugin runs under `(deny default)`
  SBPL applied post-startup by the signed `maccrab-tierb-sandbox-host` trampoline
  (`sandbox_init` then `execv`). There is **no** global `mach-lookup` — the
  plugin can reach only a documented named runtime-service base plus its
  manifest-declared services; fork/exec/network and every file outside the base
  are denied unless the signed manifest declares them.
- **The broker is the file boundary (Model B).** File reads are not granted in
  the SBPL. To read a declared file the plugin asks a per-invocation broker over
  fd 3, which opens it safely (every path component `O_NOFOLLOW`, single-link
  regular file only) and passes back a read-only fd — a symlink/hardlink/TOCTOU
  race or an undeclared path can never be opened.
- **Brokered personal-comms, never live.** A TCC-protected store (chat.db, Mail,
  Safari, TCC.db, knowledgeC, …) is snapshotted into a plugin-unwritable dir and
  the broker serves the SNAPSHOT; the untrusted child never opens the live store
  and never inherits the host's FDA. The broker re-checks TCC on the **served**
  path, so a broad ancestor read root (`~/Library`) cannot coax out a live store.
- **No metadata / process / mach side channels.** `stat()` of user crown-jewels
  (Keychains, `.ssh`, personal-comms) is denied even though their content is
  brokered; `process-info*` is scoped to self; mach-lookup is the named base +
  manifest allowlist only.
- **Authoritative consent.** The install sheet shows a consent summary DERIVED
  from the manifest's enforced capabilities (not author labels), so a plugin
  cannot under-declare what it reads or where it sends.
- **Trust + revocation + kill-switches.** Plugins are Ed25519-signed; the catalog
  is signed with an offline key and carries a `frozen` install kill-switch; a
  runtime re-verify quarantines plugins a fresh signed revocation list revokes;
  the operator has a local execution kill-switch.
- **Containment is proved, not asserted.** An adversarial corpus
  (`make test-corpus`) runs the EXACT shipped runner + broker + trampoline on a
  real macOS host and asserts the OS denies undeclared read / network / fork /
  metadata-stat / mach-lookup for both a C and a Swift fixture.

**Residual risk:**
- The runnable third-party lane is **GA-gated and ships fail-closed** until: the
  publisher anchor is set (offline ceremony), the corpus passes against the exact
  signed release build, and an **independent external pentest** of the lane
  clears it. Until then no third-party plugin executes.
- A check→spawn TOCTOU on the trampoline binary remains (same-uid only — no
  privilege crossing); an fd-pinned (`fexecve`-style) spawn is a tracked
  hardening.
- Runtime revocation is staleness-driven; a runtime fetch of a fresh signed
  revocation list (so a post-install revocation is enforced within minutes, not
  by the staleness ceiling) is a tracked hardening.
- A sandboxed plugin can still consume CPU/memory within its rlimits and emit
  misleading artifacts; the operator reviews plugin output.
- The brokered-snapshot scheme rests on the snapshot dir being plugin-unwritable;
  a same-uid foothold that already holds the operator's privileges is out of
  scope (the sandbox keeps a fooled trust contained, but local root / same-uid is
  the documented trust boundary, as elsewhere).

## Out-of-scope attackers

MacCrab does not try to defend against any of these:

- **Firmware / silicon-level attacks.** Below SIP / outside macOS's
  control.
- **Kernel rootkit with SIP disabled.** If the operator has booted
  to Recovery and turned off SIP, MacCrab is no more privileged than
  the rootkit.
- **Apple-signed compromise.** A real Apple-signed binary that does
  bad things bypasses much of MacCrab's filtering by design (we trust
  Apple's signature). Detection here is pattern-based on what the
  binary does, not on its origin.
- **Targeted nation-state with physical access.** Out of scope; assume
  hardware confidentiality.
- **Multi-user fleet management.** MacCrab is per-machine. There is
  no central console, no policy push, no remote response.
- **24/7 SOC response.** No human is responding to alerts on the
  operator's behalf.

## Documented limitations

The reviewer-facing summary, in plain terms:

- **Detection-quality evidence is documented coverage, not executed
  benchmark.** [`COVERAGE.md`](COVERAGE.md) lists what each rule
  matches; we don't yet publish executed false-positive rates against
  a labeled corpus.
- **Database tamper-resistance is on the v1.9 roadmap.** Today is
  confidentiality-only.
- **Fleet management isn't here.** Operators who want fleet rollout
  should treat MacCrab as a single-host tool inside their own
  deployment infrastructure.

## Reporting

Found a way for a non-root attacker to bypass any of the in-scope
defenses above? Please open a private security advisory at
[github.com/peterhanily/maccrab/security/advisories](https://github.com/peterhanily/maccrab/security/advisories).

## Related docs

- [`TRUST.md`](TRUST.md) — release verification: signing, notarization, Sparkle signatures
- [`RESPONSE_SAFETY.md`](RESPONSE_SAFETY.md) — what each response action does and what it validates
- [`COVERAGE.md`](COVERAGE.md) — rule-to-MITRE-ATT&CK coverage
