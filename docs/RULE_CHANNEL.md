# Signed Rule-Update Channel

This document is for operators. It describes the **out-of-band, signed
detection-rule update channel** — how MacCrab fetches and verifies new detection
rules without an app release, how to verify a manifest, how to roll back, and
what a signed-but-hostile rule corpus can and cannot do.

Detection rules are **data**, so distributing them does not require a notarized
app build or a Sparkle update. The channel delivers an Ed25519-signed manifest;
the client verifies it and stages the rules into `compiled_rules/pushed/`, where
the engine loads them **additively** and **detection-only**.

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

Two files are served at the channel base URL (default
`https://rave.maccrab.com/rules/`, override with `MACCRAB_RULES_BASE_URL`):

| File | Contents |
|---|---|
| `rules-manifest.json` | `{ serial, corpus_version, min_maccrab_version?, rules: [ …inline compiled rules… ] }` |
| `rules-manifest.json.sig` | Raw **Ed25519** signature (64 bytes) over the exact bytes of `rules-manifest.json` |

The detection rules are **inline** in the manifest — there is no separate
tarball. That removes the untar / TOCTOU / partial-extract attack surface a
side-loaded archive would add: the single signature covers the entire payload.

Manifest fields:

- **`serial`** (integer, **required**) — a monotonic counter for anti-rollback.
  A manifest with no serial is refused.
- **`corpus_version`** (string) — a human label (e.g. a date) for the ruleset.
- **`min_maccrab_version`** (string, optional) — a **version floor**; the engine
  refuses rules that need a newer build than the one running.
- **`rules`** (array) — each element is one compiled rule's JSON, exactly as
  `Compiler/compile_rules.py` emits it.

## The trust key

The manifest is verified against a **separate `rules.pub`** key — **not** the
app-signing key and **not** the plugin-catalog key. It is a 32-byte Curve25519
public key bundled into the app at
`…/MacCrab.app/Contents/Resources/rave-keys/rules.pub` (in a dev checkout,
`Sources/MacCrabApp/Resources/rave-keys/rules.pub`; a debug build may point at a
throwaway key via `MACCRAB_RAVE_RULES_PUB_PATH`).

A separate key **bounds the blast radius**: a leaked rules key can only push
detection-only, additive rules (see containment below). It cannot sign an app,
a plugin, or a revocation list. The matching private key is generated and kept
**offline** by the keyholder (`build-rules-manifest.sh keygen`).

---

## How verification works (client side)

`maccrabctl rules update` runs this pipeline; **any** failure is fail-closed and
leaves the previously installed pushed corpus untouched:

1. **Fetch** `rules-manifest.json` and `.sig` over `SecureURLSession` (TLS 1.2
   floor, ephemeral no-disk cache, SSRF-redirect re-validation). The request is
   explicitly no-cache so a stale cached copy can't mask a just-published update
   (the anti-rollback serial only works if the client sees the newest manifest).
2. **Verify the Ed25519 signature** over the manifest bytes against `rules.pub`.
   Because the rules are inline, this one signature over the exact bytes is the
   integrity pin for the whole payload — there is no separate artifact to
   sha256-pin (unlike the plugin catalog, which pins a tarball's sha256). The
   sender's `build-rules-manifest.sh` prints the manifest's sha256 so an operator
   can record and compare it out of band if they wish.
3. **Require a serial.** A signature-verified manifest with no `serial` is
   refused (anti-rollback needs one).
4. **Validate every rule.** Each entry must decode as a `CompiledRule`; a rule
   id containing a path separator, `..`, or that is empty is rejected. A **single**
   bad rule refuses the **whole** manifest — there is never a partial corpus.
5. **Anti-rollback.** The signed serial must be **greater than** the
   last-accepted serial (a high-water mark persisted in the rave trust-state
   store). An equal or older serial is rejected as stale/replay.
6. **Version floor.** If `min_maccrab_version` is set, the running engine must
   satisfy it or the manifest is refused.
7. **Atomic swap.** The validated rules are written to a sibling temp directory,
   then that directory replaces `compiled_rules/pushed/`. A failed write never
   disturbs the prior corpus. Only after the swap succeeds is the serial
   high-water mark advanced.

The staged rules load on the engine's next reload (SIGHUP or reload tick).

---

## Operator commands

```bash
# Is a newer corpus available? (read-only: fetch + verify, never writes)
maccrabctl rules check-updates
maccrabctl rules check-updates --json

# Fetch → verify → anti-rollback → version-floor → validate → install
maccrabctl rules update
maccrabctl rules update --rules-base https://your.host/rules/

# What is installed right now?
maccrabctl rules status
```

`check-updates` reports the installed serial, the available serial, the corpus
version, the rule count, and whether an update is available — **without**
writing anything, so it is a safe way to verify a freshly published manifest
before installing it. To dry-run the whole fetch+verify path against a throwaway
key and server, use `scripts/test-rule-channel-e2e.sh`.

> Permissions note: on a release build the engine's `compiled_rules/` directory
> is root-owned (it belongs to the System Extension), so a non-root
> `maccrabctl rules update` cannot write it — run it with `sudo`, or route the
> verified rules through the privileged daemon path.

---

## Rolling back

The anti-rollback rule means you **cannot** roll back by re-publishing an older
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

Assume the worst case an operator should reason about: the `rules.pub` private
key is compromised, and an attacker publishes a **validly signed** manifest.
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

So the ceiling on a compromised rules key is: **add noise / add benign
detections.** It cannot silence a built-in detection, cannot weaken response
posture, cannot arm a destructive action, and cannot touch the app or
plugin trust chains (a different key signs those). Combined with the client-side
anti-rollback, version floor, per-rule validation, and fail-closed atomic swap,
the channel's failure mode is "no update / stale update," never "hostile takeover
of detection."
