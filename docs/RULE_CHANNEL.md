# Signed Rule-Update Channel

This document is for operators. It describes the **out-of-band, signed
detection-rule update channel** — how MacCrab fetches and verifies new detection
rules without an app release, how to verify a manifest, how to roll back, and
what a signed-but-hostile rule corpus can and cannot do.

The codebase contains a design for distributing detection rules as signed data
without a notarized app build. **That production channel is disabled in this
release.** The CLI refuses before key lookup or any network request, the app
ships no `rules.pub`, and the engine preserves but does not read or evaluate an
existing `compiled_rules/pushed/` corpus. The dormant verifier accepts at most
an 8 MiB manifest containing at most 2,048 decoded rules.

> Source of truth:
> `Sources/maccrabctl/RuleChannelFetch.swift` (client fetch + verify),
> `Sources/maccrabctl/RuleChannelCommands.swift` (`maccrabctl rules …`),
> `Sources/MacCrabCore/Detection/RuleEngine.swift` (`loadPushedRules`),
> `Sources/MacCrabCore/Detection/ResponseAction.swift` (`detectionOnlyRuleIDs`),
> and `scripts/build-rules-manifest.sh` (the sender/keyholder side).
>
> Related: [TRUST.md](TRUST.md) (app / DMG verification),
> [SUPPLY_CHAIN_SECURITY.md](SUPPLY_CHAIN_SECURITY.md) (the plugin-catalog trust
> chain this channel mirrors but simplifies).

---

## What is on the wire

If a future owner-approved release enables the design, two files are expected at
the channel base URL (the currently configured default is
`https://rave.maccrab.com/rules/`, override with `MACCRAB_RULES_BASE_URL`):

| File | Contents |
|---|---|
| `rules-manifest.json` | `{ serial, corpus_version, min_maccrab_version?, rules: [ …inline compiled rules… ] }` |
| `rules-manifest.json.sig` | Raw **Ed25519** signature (64 bytes) over the exact bytes of `rules-manifest.json` |

The detection rules are **inline** in the manifest — there is no separate
tarball. That removes the untar / TOCTOU / partial-extract attack surface a
side-loaded archive would add: the single signature covers the entire payload.

Operationally, the configured default is not a live distribution channel: a
direct check of `rules-manifest.json` returned HTTP 404 at 2026-08-02 00:57Z.
There is no automatic update path; the manual CLI commands are release-gated and
currently refuse without contacting that endpoint.

Manifest fields:

- **`serial`** (integer, **required**) — a monotonic counter for anti-rollback.
  A manifest with no serial is refused.
- **`corpus_version`** (string) — a human label (e.g. a date) for the ruleset.
- **`min_maccrab_version`** (string, optional) — a **version floor**; the engine
  refuses rules that need a newer build than the one running.
- **`rules`** (array) — each element is one compiled rule's JSON, exactly as
  `Compiler/compile_rules.py` emits it.

## The trust key

> **STATUS: DISABLED, no trusted anchor.** The prior 32-byte `rules.pub` had no
> owner-approved key ceremony, custody record, signed manifest, or public release
> provenance. Pinning its bytes would preserve unknown authority, not establish
> trust. It has therefore been removed from source and release artifacts. The
> channel may be enabled only after the owner performs an offline key rotation,
> records custody/provenance, and explicitly approves a release carrying the new
> public anchor.

The future design verifies manifests against a **separate `rules.pub`** key —
**not** the app-signing key and **not** the plugin-catalog key. No such key is
trusted or bundled in this release.

If re-enabled, note the packaging path: SPM emits
`Sources/MacCrabApp/Resources/**` into the resource bundle, so the key would land at
`…/MacCrab.app/Contents/Resources/MacCrab_MacCrabApp.bundle/rules.pub` — the same
place the sibling `catalog.pub` actually ships. The loader also probes the legacy
`…/Contents/Resources/rave-keys/rules.pub`, but **no built bundle has ever
contained that directory**, so a key placed only there would not be found. A debug
build may point at a throwaway key via `MACCRAB_RAVE_RULES_PUB_PATH` (DEBUG-only).

### Release and keyholder invariants

Do **not** restore the removed `rules.pub` or casually run `keygen`. Enabling the
channel is an owner-approved cryptographic ceremony, not a repository-local code
change. The deterministic source and final-artifact guard currently proves the
safe disabled state: one shared policy literal is false, no anchor ships, and no
production call site loads a pushed corpus:

```bash
scripts/check-rules-trust-anchor.sh
scripts/test-rules-trust-anchor.sh
```

A future separate key would **bound the blast radius**: a leaked rules key can only push
detection-only, additive rules (see containment below). It cannot sign an app,
a plugin, or a revocation list. The matching private key **must** be controlled by
the designated offline keyholder; source control contains only the public half
and cannot attest to private-key custody.

---

## How verification works (client side)

The production path currently stops at step 0. The remaining steps describe the
dormant verifier retained for a future approved channel; **any** failure is
fail-closed and leaves a previously staged corpus untouched:

0. **Release gate.** `RuleChannelPolicy.productionEnabled` is `false`. Both CLI
   construction and the fetch boundary refuse before key lookup or any network
   request. The runtime has the same central default and no production loader
   call sites, so preserved pushed files remain inert.
1. **Fetch** `rules-manifest.json` and `.sig` over `SecureURLSession` (TLS 1.2
   floor, ephemeral no-disk cache, SSRF-redirect re-validation). The request is
   explicitly no-cache so a stale cached copy can't mask a just-published update
   (the anti-rollback serial only works if the client sees the newest manifest).
2. **Enforce streaming byte ceilings.** `Content-Length` over the limit is
   rejected immediately, and chunked/undeclared bodies are accumulated through
   `bytes(for:)` with a hard cap. A manifest over **8 MiB** is refused before
   signature work, JSON parsing, or staging; `.sig` must be exactly **64 bytes**
   and its network body is capped at that size.
3. **Verify the Ed25519 signature** over the manifest bytes against `rules.pub`.
   Because the rules are inline, this one signature over the exact bytes is the
   integrity pin for the whole payload — there is no separate artifact to
   sha256-pin (unlike the plugin catalog, which pins a tarball's sha256). The
   sender's `build-rules-manifest.sh` prints the manifest's sha256 so an operator
   can record and compare it out of band if they wish.
4. **Require a serial.** A signature-verified manifest with no `serial` is
   refused (anti-rollback needs one).
5. **Bound and validate every rule.** A manifest containing more than **2,048**
   decoded rule objects is refused before per-rule decoding. Each entry must
   decode as a `CompiledRule`; serial must be a nonnegative JSON integer, and
   rule ids must be unique, nonempty, and free of path separators or `..`. A
   **single** bad rule refuses the **whole** manifest.
6. **Anti-rollback and serial uniqueness.** A lower serial is rejected. A
   signature-valid manifest with the **equal** already-accepted serial is an
   idempotent success with **no file or trust-state changes**, so different bytes
   cannot replace a corpus by reusing its serial. Only a greater serial can stage
   new content.
7. **Version floor.** If `min_maccrab_version` is set, the running engine must
   satisfy it or the manifest is refused.
8. **Atomic swap.** The validated rules are written to a sibling temp directory,
   then that directory replaces `compiled_rules/pushed/`. A failed write never
   disturbs the prior corpus. Only after the swap succeeds is the serial
   high-water mark advanced.

The staged rules load on the engine's next reload (SIGHUP or reload tick).

---

## Operator commands

```bash
# Currently refuses before network because the release gate is disabled
maccrabctl rules check-updates
maccrabctl rules check-updates --json

# Currently refuses before network/filesystem changes
maccrabctl rules update
maccrabctl rules update --rules-base https://your.host/rules/

# What is installed right now?
maccrabctl rules status
```

When the channel is enabled, `check-updates` reports the installed serial, the available serial, the corpus
version, the rule count, and whether an update is available — **without**
writing anything, so it is a safe way to verify a freshly published manifest
before installing it. In the current release,
`scripts/test-rule-channel-e2e.sh` proves that both network-facing commands
refuse without reaching a local request sentinel.

> Permissions note: on a release build the engine's `compiled_rules/` directory
> is root-owned (it belongs to the System Extension), so a non-root
> `maccrabctl rules update` cannot write it — run it with `sudo`, or route the
> verified rules through the privileged daemon path.

---

## Rolling back

While the channel is disabled, do **not** delete an existing pushed directory:
it is preserved for inspection but ignored by every production runtime path.

If a future approved release enables the channel, the anti-rollback rule means
you **cannot** roll back by re-publishing an older
serial — the client refuses any serial at or below the last-accepted one. Roll
back one of two ways:

- **Drop the pushed corpus entirely.** Delete the staged directory and reload:

  ```bash
  sudo rm -rf "/Library/Application Support/MacCrab/compiled_rules/pushed"
  sudo pkill -HUP com.maccrab.agent      # release System Extension
  # dev standalone daemon: pkill -HUP maccrabd
  ```

  This removes all pushed rules; the bundled + user rules are unaffected. Note
  the serial high-water mark persists, so re-installing later still requires a
  manifest with a **higher** serial than the last one accepted.

- **Publish a corrected manifest with a higher serial.** Rebuild the intended
  ruleset (dropping or fixing the offending rule) and publish it with
  `serial` greater than the last one, via `build-rules-manifest.sh build`. This
  is the forward-only path and the one to prefer when the channel is live.

`maccrabctl rules status` shows the accepted serial and how many pushed rules
are currently installed, so you can confirm the rollback took effect.

---

## Risk model: what a hostile corpus can and cannot do

This is a design analysis for a future enabled channel, not the current release
state. Assume its signing authority is compromised and an attacker publishes a
**validly signed** manifest.
Even then, the pushed corpus is **contained** by two independent boundaries in
the engine, enforced regardless of the signature:

- **Additive-only.** Pushed rules are loaded *after* the bundled + user rules
  (`RuleEngine.loadPushedRules`). A pushed rule whose id **already exists** — any
  built-in or user rule — is **ignored** (and logged). A signed-but-hostile
  corpus therefore **cannot shadow, override, disable, or re-severity an existing
  detection.** It can only add *new* ids. The rule's origin is tagged `.pushed`
  by the loader and is **not** decoded from the JSON, so a pushed rule cannot
  forge a `.bundled` origin.

- **Detection-only.** Every pushed rule id is added to the response engine's
  `detectionOnlyRuleIDs` set. `ResponseActionEngine.execute` returns early for
  any alert whose rule id is in that set — so a pushed rule can raise an alert
  but can **never arm a response action** (kill / quarantine / blockNetwork /
  script), **not even the global default action.**

So a compromised rules key cannot silence a built-in detection, weaken response
posture, arm a destructive action, or touch the app/plugin trust chains (different
keys sign those). It can still add broad, high-volume detections and therefore
create alert noise and availability pressure. The 8 MiB / 2,048-rule ceilings
bound a single accepted corpus; they do not make signer compromise harmless.
Combined with strict serial progression, version floors, per-rule validation and
the response-action gate, the intended failure domain is detection quality and
resource pressure rather than code execution or destructive response.
