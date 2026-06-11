# Runbook — Sparkle EdDSA key rotation (dual-key transition)

**Audience:** release operator. **Execute manually.** Nothing in this
document is run by CI or by any script automatically — Sparkle private
key custody is operator-only (RELEASE_PROCESS.md "Inventory of secrets").

**When to run:**
- The Sparkle EdDSA private key is suspected leaked (catastrophic — see
  below), OR
- Scheduled key hygiene / handing custody to a new build Mac.

> **Why this is the most dangerous key in the project.** Installed
> `MacCrab.app` binaries verify every auto-update's `edSignature`
> against the `SUPublicEDKey` baked into THEIR OWN Info.plist at install
> time. That public key cannot be changed on an already-installed copy
> except by shipping a new bundle. So a naïve rotation (swap the key,
> ship the next release) **bricks auto-update for every existing user**:
> their installed app still trusts only the OLD key, the new appcast is
> signed with the NEW key, verification fails, and they silently stop
> receiving updates. The dual-key transition below is the only safe path.

---

## The dual-key transition, in one sentence

Ship at least one "bridge" release whose appcast is signed with the
**old** key but whose bundle embeds the **new** `SUPublicEDKey`, so
existing users update once under the old trust and land on a binary
that trusts the new key — only THEN retire the old key.

Sparkle has no built-in multi-key appcast support, so the bridge is the
mechanism: the appcast entry is whatever the installed clients can
verify (old key); the embedded key is what they'll trust next time.

---

## Pre-flight

1. Confirm the current key is reachable and note its public half:
   ```bash
   ~/Tools/bin/sign_update --print-keys      # prints the current public key
   ```
   This MUST equal `SUPublicEDKey` in `Xcode/project.yml` and both
   Info.plists (prerelease-check.sh asserts this equality).
2. Record the live release version. The bridge release is `N+1`.
3. Back up the current keychain item (you keep the old key until the
   tail of installed clients has migrated — months, realistically).

## Step 1 — generate the new key pair

```bash
~/Tools/bin/generate_keys      # Sparkle's tool; writes the NEW private key to login Keychain
~/Tools/bin/generate_keys -p   # prints the NEW public key (base64) — call it NEW_PUB
```

`generate_keys` will refuse to overwrite an existing key. Sparkle stores
the private key under a distinct Keychain account; keep BOTH old and new
present during the transition. Confirm both are listed:

```bash
security find-generic-password -s 'https://sparkle-project.org' -g 2>&1 | grep -c acct
```

## Step 2 — cut the BRIDGE release (`N+1`): new key embedded, OLD key signs

This is the load-bearing step. The bridge release's BUNDLE must embed
`NEW_PUB`, but its APPCAST entry must be signed with the OLD key.

1. Update the single source of truth — `Xcode/project.yml` — to
   `SUPublicEDKey: "NEW_PUB"`. build-release.sh derives the shipped
   Info.plist key from project.yml (one source, no drift), and
   prerelease-check.sh asserts project.yml == both Info.plists.
2. Build + sign + notarize the DMG as usual (the DMG / code signature is
   the Developer ID cert, unrelated to the Sparkle key):
   ```bash
   VERSION=N+1 scripts/build-release.sh        # or the staged flow
   ```
3. **Sign the appcast entry with the OLD key.** This is the override —
   normally `generate-appcast-entry.sh` uses whatever `sign_update`
   defaults to. During the bridge you must force the old key. Point
   `sign_update` at the OLD private key explicitly (Sparkle's
   `--account` / `-f` selector, depending on your storage), verify the
   emitted `edSignature` validates against the OLD public key, and only
   then publish:
   ```bash
   # Generate the item, forcing the OLD signing key:
   SPARKLE_SIGN_KEY=old scripts/generate-appcast-entry.sh \
       --dmg .build/MacCrab-vN+1.dmg --version N+1 > /tmp/bridge-item.xml
   # SANITY: the signature in /tmp/bridge-item.xml MUST verify against OLD_PUB,
   # because that is what installed clients hold. If you can, verify with a
   # client built on the OLD key before publishing.
   ```
   > If `generate-appcast-entry.sh` has no key selector yet, add one for
   > the duration of the transition rather than hand-editing the XML —
   > a hand-signed entry that silently used the new key is exactly the
   > brick this runbook exists to prevent.
4. Publish the bridge appcast entry + release.json normally
   (`publish-appcast-entry.sh`, `publish-release-json.sh`).
5. **Verify on a real installed client:** take a machine running version
   `N` (old key embedded), let it auto-update. It must accept `N+1`
   (old-key signature verifies) and install the bundle that now embeds
   `NEW_PUB`.

After Step 2, every client that updates to `N+1` trusts the new key.

## Step 3 — cut `N+2` onward signed with the NEW key

From the release AFTER the bridge:

1. `Xcode/project.yml` already carries `NEW_PUB` (Step 2.1) — no change.
2. Sign the appcast entry with the NEW key (the normal default once the
   bridge override is removed):
   ```bash
   scripts/generate-appcast-entry.sh --dmg .build/MacCrab-vN+2.dmg --version N+2
   ```
3. Clients on `N+1` (new key embedded) verify and update. Clients still
   on `N` or earlier will NOT — they never crossed the bridge. That tail
   is expected; you keep the old key (Step 4) precisely so you can cut
   ANOTHER old-key-signed bridge for them if the tail is large.

## Step 4 — retire the old key (only after the tail has migrated)

Do NOT delete the old key until telemetry / download stats show the
population on `< N+1` is negligible and you accept stranding it.

1. Delete the old Sparkle private key from the login Keychain.
2. Note in CHANGELOG that the old key is retired.
3. The stranded tail can only migrate by manual reinstall from GitHub
   (`brew reinstall --cask maccrab` or DMG download). Publish a one-line
   advisory if the tail is non-trivial.

---

## Failure / recovery

- **You shipped `N+1` signed with the NEW key by mistake (the brick).**
  Existing clients reject it; they're stuck on `N` but NOT broken — the
  app keeps running, only auto-update is dead for them. Recover by
  publishing a corrected appcast entry for `N+1` signed with the OLD
  key (re-run Step 2.3 against the same DMG). Installed clients re-poll
  within `SUScheduledCheckInterval` (24h) and pick it up.
- **You deleted the old key before retiring it (Step 4 too early).**
  You can no longer sign a bridge for the tail. The tail must reinstall
  manually. There is no recovery beyond the advisory.

## Post-rotation checklist

- [ ] `~/Tools/bin/sign_update --print-keys` == `SUPublicEDKey` in
      `Xcode/project.yml`.
- [ ] `scripts/prerelease-check.sh <next-version>` Manifest-equality
      passes (project.yml SUPublicEDKey == both Info.plists).
- [ ] An old-key client successfully auto-updated to the bridge release.
- [ ] A bridge-or-later client successfully auto-updated to a new-key
      release.
- [ ] Old key retained until the tail migrates; retirement noted when done.

## Related

- `RELEASE_PROCESS.md` — secret inventory, Step 6 (appcast publish).
- `docs/runbooks/rave-catalog-key-rotation.md` — the analogous Ed25519
  rotation for the plugin catalog (different blast radius, air-gapped).
- `docs/runbooks/cloudflare-token-rotation.md` — the token that publishes
  the appcast to Cloudflare Pages.
