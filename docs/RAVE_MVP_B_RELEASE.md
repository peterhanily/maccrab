# Rave Forensic-Plugin Store — MVP-B Release Runbook (app side)

**Branch:** `feat/rave-mvp-b` (off `main`, NOT pushed).
**Scope:** the full third-party marketplace ("MVP-B"), APP SIDE. The site + rave
server are a separate session.

This documents (1) what the app build delivers, (2) the operator / keyholder /
on-device steps a code session **cannot** do — these are the "RC test", and (3)
how to verify the RC.

---

## 1. What the app build delivers (done + on the branch)

The marketplace's hard part — **running untrusted third-party code on an FDA/TCC
host, contained** — is built, wired LIVE, and **proven on-device by a passing
adversarial corpus**.

- **Containment substrate** (Streams 0–2): the signed `maccrab-tierb-sandbox-host`
  trampoline (`sandbox_init` post-startup → deny-default SBPL → `execv`), the
  SCM_RIGHTS file broker (Model B — the broker is the file boundary; reads are
  never granted in the SBPL), brokered-TCC (manifest TCC sources snapshotted into
  a plugin-unwritable dir; the child reads the snapshot, never the live store).
- **Live routing** (`TierBCollectorExecutor`): first-party → sandboxed dispatch,
  fail-closed, across `maccrabctl plugin run`, the dashboard "Run on this Mac"
  (`KitRunner`), and MCP `forensics.run_collector`. `PluginRunner` still refuses
  Tier-B in-process (correct).
- **Containment corpus** (`ContainmentCorpusTests`, gated): proves on macOS 26
  that a benign plugin runs + emits, a declared read is brokered, and undeclared
  file/network/fork are denied. **Passes on this host for C plugins.**
- **Contributor SDK**: `maccrabctl plugin keygen | sign | test`; the reference
  collector `maccrab-tierb-example`; `docs/PLUGIN_AUTHORING.md`.
- **Consent**: signed-manifest consent fields + a **derived** `consentSummary`
  (a plugin can't under-declare); shown at sideload and in `plugin test`.
- **Trust-floor**: sideload (`install --local`) TOFU + namespace hard-refuse;
  signed catalog **kill-switch** (`frozen`); **revocation re-verify timer**
  (install-once boxes self-heal); trust-mutation audit log.
- **Release**: `build-release.sh` stages, **signs (Developer-ID, own signature)**,
  and bundles the trampoline + reference plugin into `MacCrab.app/Contents/Resources/bin`.

Full unit suite green; the lane is runtime-fail-closed until the operator steps
below are done.

---

## 2. Operator / keyholder / on-device steps (the RC test — NOT code)

These cannot be done by a code session. They are the gates between "code complete"
and "store live".

### 2a. On-device containment proof (run the corpus on macOS 26)
The corpus passed for C plugins on the dev host. Re-run it against the **release**
build and a **Swift** plugin (a real plugin is Swift; the runtime base may need
extra tuning):
```
make test-corpus      # MACCRAB_CORPUS=1 MACCRAB_BIN_DIR=$(swift build --show-bin-path) swift test --filter ContainmentCorpus
```
This is the **REQUIRED** containment gate and must be recorded in the release
checklist. CI runs the same corpus as an **advisory** job (`corpus`) so a
host-independent regression (broker/SBPL/trampoline) turns a check red, but a
hosted runner's VM is not the launch-proof environment — only the on-device run
is the gate. The corpus now also asserts an undeclared **mach-service** lookup
and a **stat()** of a metadata-denied crown-jewel are both OS-denied (audit #4).
If a Swift plugin SIGABRTs at startup, the deny-default base in
`SandboxProfileBuilder.compileDenyDefault` needs more allow rules (iterate: add a
base rule → rebuild → re-run). The C fixtures already pass; the Swift base is the
remaining iteration. **Do not open runnable contrib until the corpus passes
against the exact shipped runner.**

### 2b. Independent human security review + pentest (MANDATORY)
Brokered personal-comms (chat.db/Mail) is in scope from v0. Before opening
runnable third-party plugins, get an independent review/pentest of untrusted-code
execution: confirm the gate is fail-closed across every bypass, the broker is
TOCTOU/symlink/hardlink-proof (it was reviewed + a reproduced escape fixed), no
host FDA/TCC leaks. The code-side adversarial reviews are in this session's
history; feed them in. **This calendar gate is a dependency — book the reviewer now.**

### 2c. Keyholder ceremony (offline)
- Set `FirstPartyTrustRoot.publisherKeyFingerprint` (currently the unset sentinel)
  to the lowercase-hex SHA-256 of the first-party plugin-signing key's raw public
  key. This flips the first-party (unsandboxed) Tier-B lane on. Build-time
  constant only — never read from a file/env.
- Sign the rave catalog entries + the kill-switch field with the offline catalog
  key (cross-repo: maccrab-rave). Set real entry hashes + `min_maccrab_version` =
  the trust-floor GA version. The signing key stays air-gapped.

### 2d. Release build (operator, keychain)
```
VERSION=x.y.z ./scripts/build-release.sh        # signs the trampoline + everything; keychain clicks; notarytool
```
Verify after: the trampoline at `MacCrab.app/Contents/Resources/bin/maccrab-tierb-sandbox-host`
is Developer-ID-signed (`codesign -dv`), and `isRuntimeAvailable` accepts it WITHOUT
any dev override.

### 2e. The dev override — production hygiene
`MACCRAB_TIERB_DEV_TRAMPOLINE` / `MACCRAB_CORPUS` make `isRuntimeAvailable` accept
an unsigned (dev) trampoline. They MUST NEVER be set in a shipped/production
environment (no launchd plist, no parent-shell export). In production the trampoline
must pass the real Developer-ID + team signature check.

### 2f. Cross-repo (separate session)
- maccrab-rave: emit the `frozen`/`freeze_reason` catalog field; the reproducible-
  build Stage-3 CI; real signed v0.1.0 binaries; the operator flip (RAVE_PUBLIC,
  CF token rotation, min_maccrab_version).

### 2g. trusted-keys.json tamper-proofing (hardening)
A trusted key now gates sandboxed execution. The trust-mutation **audit log**
(`<pluginsRoot>/trust_audit.log`) gives tamper-evidence; full tamper-PROOFING
against a same-uid foothold needs an offline / Secure-Enclave signer (the sandbox
keeps a fooled trust contained). Decide custody before opening contrib.

---

## 3. Verify the RC

- `maccrabctl plugin keygen` → `sign <bundle>` → `test <bundle>` runs the plugin
  CONTAINED and prints its consent summary.
- `maccrabctl plugin install --local <bundle>` shows the TOFU consent + refuses
  `com.maccrab.*` impersonation.
- Run an installed third-party plugin against a case (`plugin run --case`) → it
  dispatches to the sandboxed lane.
- The revocation reconcile runs at app launch + every 30 min (self-heal).
- Corpus (2a) passes against the release build.

---

## 3a. Security review status (live-routing adversarial review)

A 3-lens adversarial review of the now-live execution routing ran before this
runbook. **All must-fix (1 CRITICAL + 3 HIGH) fail-opens are FIXED** (see the
`fix(tierb): close the live-routing review's must-fixes` commit): the trampoline
dev-override is now DEBUG-only + value-pinned (M1), the team-pin fails closed in
release (M2), MCP routing gates on registration not error-type (M3), `plugin
test` uses an in-process flag not a leaky `setenv` (M4), plus an operator
kill-switch (S4), staleness reconcile on CLI runs (S2-lite), the staging-override
gate (S5), and kill-switch-blocks-sideload (S1-local).

**Remaining should-fix (recommend landing this RC cycle; not fail-open):**
- **S2-full** — fetch a fresh signed `revocations.json` on a runtime timer (not
  just install-time); today runtime reconcile is staleness-only. A plugin revoked
  AFTER install is caught by the staleness sweep + quarantine-before-verify, but
  an explicit-revocation runtime refresh would be tighter.
- **S3-full** — validate the trampoline once by fd (O_NOFOLLOW) and spawn from
  that fd (fexecve-style) to close the check→spawn TOCTOU. The argv[0] vector is
  already removed and the signature is team-pinned; this closes the residual race.
- **Nits (accept for RC):** the deny-default base allows `file-read-metadata`
  globally (a `stat()` side channel — content still brokered); `--local` is a
  documented no-op (routing is auto-detected). Feed these to the pentest (§2b).

## 4. Remaining app-side work

The storefront UX polish is **done**: in-place install/update refresh (the
Installed badge updates without a manual reload), the update diff + re-vetting
disclosure (vOLD → vNEW), and the revocation-freshness panel; plus two
consent-correctness fixes (the sheet no longer says plugins run with "full
access" / are "not yet sandboxed" — it states the sandboxed model).

The only remaining app-side item is the **localization translation pass** (the
new + a number of pre-existing storefront strings are now `String(localized:)`
with English defaults; translating them across the 13 locales + the on-device
locale eyeball is the operator/translator pass). Strings ship correctly in
English until then.

Lower-priority storefront enhancement (deferred, not blocking): the consent sheet
rendering catalog-declared capability CHIPS for not-yet-installed third-party
entries (needs the resolver to surface catalog-entry capabilities; the CLI
sideload + `plugin test` already show the full manifest-derived consent).
