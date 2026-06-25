# Operator Ceremonies

This document describes the periodic security ceremonies that only the MacCrab maintainer can perform. These are operator-only tasks for managing cryptographic keys, tokens, and infrastructure credentials. Consult `RELEASE_PROCESS.md` for the end-to-end release flow context.

All secrets live in `~/.maccrab-release-env` (chmod 600, gitignored) on the build Mac and are never committed to version control.

---

## 1. Annual Sparkle EdDSA Key-Rotation Ceremony

**Schedule:** As needed for hygiene, or immediately if private key is suspected leaked.
**Duration:** ~2 hours for the bridge release cycle.
**Artifact Location:** `Xcode/project.yml` (SUPublicEDKey), `Xcode/Resources/MacCrabApp-Info.plist`, `Xcode/Resources/MacCrabAgent-Info.plist`.

### Why this matters

The Sparkle EdDSA private key is the **highest-risk secret** in MacCrab. Every installed client verifies auto-update signatures against the public key baked into their Info.plist at install time. A naïve key swap (new key, new signature) **bricks auto-update for existing users** — their app never accepts the new-key-signed appcast because it trusts only the embedded old key. The dual-key transition below is the only safe path.

**Pre-flight: Verify current key parity**

```bash
# 1. Check the Sparkle private key is reachable on the build Mac
~/Tools/bin/sign_update --print-keys
# Expected: prints the public key matching SUPublicEDKey in project.yml

# 2. Verify all three sources agree (project.yml, app plist, sysext plist)
scripts/prerelease-check.sh <any-version>
# Look for the "Manifest equality" section — all three SUPublicEDKey values
# must match exactly, or key drift has already occurred.
```

### Step 1 — Generate the new keypair

```bash
~/Tools/bin/generate_keys      # writes NEW private key to login Keychain
NEW_PUB=$(~/Tools/bin/generate_keys -p)   # prints the base64 public key
echo "New public key: $NEW_PUB"
```

Sparkle refuses to overwrite an existing key. Both old and new must coexist during the transition:

```bash
security find-generic-password -s 'https://sparkle-project.org' -g 2>&1 | grep -c acct
# Expected: 2 (one for old key, one for new)
```

### Step 2 — Cut the BRIDGE release (`N+1`): new key embedded, old key signs appcast

This is the load-bearing step. Existing clients install a bundle that trusts the new key while verifying the appcast entry with the old key.

**2a. Update project.yml (single source of truth)**

```bash
# Edit Xcode/project.yml: change SUPublicEDKey to $NEW_PUB (both targets)
# Only one source — Info.plists are derived from this during build.
```

**2b. Build and sign the DMG as usual**

```bash
VERSION=<next-version> scripts/build-release.sh
# Output: .build/MacCrab-v<version>.dmg (signed + notarized + stapled)
```

**2c. Generate appcast entry signed with the OLD key**

The bridge entry MUST verify against the old public key that existing clients hold:

```bash
# Force sign_update to use the OLD private key (mechanism depends on your
# Sparkle keychain configuration; you may have --account or -f selector).
# If generate-appcast-entry.sh lacks a selector yet, edit the script or
# manually ensure the signature uses the old key.
SPARKLE_SIGN_KEY=old scripts/generate-appcast-entry.sh \
    --dmg .build/MacCrab-v<version>.dmg \
    --version <version> > /tmp/bridge-item.xml

# CRITICAL SANITY CHECK: Verify the signature in /tmp/bridge-item.xml
# matches the OLD public key. If you can test on a client running the
# old version, do so before publishing.
```

**2d. Publish the bridge appcast entry**

```bash
scripts/publish-appcast-entry.sh \
    --item /tmp/bridge-item.xml \
    --version <version> \
    --site-repo peterhanily/maccrab-site
```

**2e. Verify on a real installed client**

- Take a machine running version `N` (old key embedded).
- Enable auto-update check or wait for the scheduled 24-hour poll.
- Confirm it accepts the bridge version `N+1` (old-key signature verifies).
- Confirm the installed bundle now carries `NEW_PUB` in its Info.plist:

```bash
strings /Applications/MacCrab.app/Contents/Info.plist | grep -A1 SUPublicEDKey
```

### Step 3 — Cut `N+2` onward signed with the NEW key

From the release after the bridge, all future releases sign with the new key (the normal default):

```bash
VERSION=<next-version> scripts/build-release.sh
scripts/generate-appcast-entry.sh \
    --dmg .build/MacCrab-v<next-version>.dmg \
    --version <next-version> > /tmp/item.xml
scripts/publish-appcast-entry.sh --item /tmp/item.xml --version <next-version>
```

Clients on `N+1` (new key embedded) verify and auto-update. Clients still on `N` or earlier will NOT — they never crossed the bridge. That is expected and safe.

### Step 4 — Retire the old key (only after tail migration)

Do NOT delete the old key until download telemetry / version-distribution stats show the population on `< N+1` is negligible and you accept stranding any remainder.

```bash
# Delete old key from login Keychain
security delete-generic-password -s 'https://sparkle-project.org' -a <old-account>

# Document the retirement in CHANGELOG.md
# The stranded tail can only migrate by manual reinstall from GitHub or Homebrew.
```

**Post-rotation checklist:**

- [ ] Both old and new keys present in Keychain during transition.
- [ ] `project.yml` carries `NEW_PUB` in both targets (app + sysext).
- [ ] `prerelease-check.sh` Manifest-equality passes for bridge release.
- [ ] Bridge `N+1` appcast entry signed with OLD key; verified by old-version client.
- [ ] Release `N+2` signed with NEW key; verified by bridge-version client.
- [ ] Old key retained in Keychain until version distribution shows `< N+1` is negligible.
- [ ] Old key deleted once tail migration complete; retirement noted in CHANGELOG.

**Failure recovery:**

- **Shipped `N+1` signed with the NEW key by mistake (the brick):** Publish a corrected appcast entry for `N+1` signed with the OLD key against the same DMG. Clients re-poll within 24 hours and pick it up.
- **Deleted old key too early:** You cannot sign a bridge for the tail. The tail must reinstall manually. Publish an advisory.

---

## 2. Air-gapped Rave Catalog Ed25519 Key-Rotation Ceremony

**Schedule:** As needed for hygiene, or immediately if private key is suspected leaked.
**Duration:** ~1–2 hours (depends on air-gap logistics).
**Status (v1.19.0):** Planned, not yet executed. This runbook documents the procedure for future rotation.

### Why this matters

The rave plugin catalog (`catalog.json`) is signed with an Ed25519 key. Unlike Sparkle (which is embedded in every binary), the catalog key is bundled at install time but can be rotated via the same dual-key bridge pattern.

**Blast radius:** smaller than Sparkle. A leaked catalog key lets an attacker sign a malicious catalog, but installs are also gated by signer-pinning, per-plugin attestation, and version floors. Still a stop-ship event.

### Pre-flight

1. Confirm the current private key lives on your air-gapped signer.
2. Verify `maccrab-site/rave/keys/catalog.pub` (32 bytes, raw binary) equals the public half:

```bash
wc -c maccrab-site/rave/keys/catalog.pub    # must print 32
```

3. Note the current `catalog_serial` from `maccrab-site/rave/catalog.json`.

### Step 1 — Generate new keypair (air-gapped)

On your air-gapped signer, generate a Curve25519 signing key:

```bash
# Use your offline keygen (e.g., cryptography library).
# Output must be exactly 32 raw bytes (no encoding).
python3 - <<'PY'
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
priv = Ed25519PrivateKey.generate()
open('catalog-NEW.key', 'wb').write(priv.private_bytes(
    serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
    serialization.NoEncryption()))
open('catalog-NEW.pub', 'wb').write(priv.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw))
PY

# Verify exactly 32 bytes
wc -c catalog-NEW.pub     # must print 32
```

### Step 2 — Staging verification (before production)

The code ships a debug-only staging-key seam. Verify the new key end-to-end without touching the bundled production key:

1. On the air-gapped signer, sign a test catalog (incremented serial) with the NEW private key.
2. Move test catalog + NEW public key across the air gap.
3. Verify with explicit key path (no rebuild):

```bash
MACCRAB_RAVE_CATALOG_PUB_PATH=/path/to/catalog-NEW.pub \
  maccrabctl plugin catalog --base file:///path/to/test-catalog/
# Must succeed. Corrupt one byte of the test catalog and re-run — must fail.
```

### Step 3 — Bridge release: new key embedded, old key signs live catalog

Installed clients hold the OLD `catalog.pub`. To migrate:

1. Replace `Sources/MacCrabApp/Resources/rave-keys/catalog.pub` with `catalog-NEW.pub`.
2. Cut a normal release through the Sparkle pipeline. After users auto-update the app, they trust the NEW catalog key.
3. **Until the app population migrates, keep signing the live `catalog.json` with the OLD private key.** The single-signature model means the app update is the bridge.

### Step 4 — Cut over the live catalog to the NEW key

Once sufficient app population embeds `catalog-NEW.pub`:

1. On the air-gapped signer, sign the production `catalog.json` (serial strictly greater than the last published serial) with the NEW private key.
2. Move `catalog.json` + `catalog.json.sig` across the air gap and publish to `maccrab-site/rave/`.
3. Verify: a migrated client installs a plugin end-to-end; an un-migrated client rejects the catalog (expected — it must update the app).

### Step 5 — Retire the old key

Once un-migrated clients are negligible:

1. Destroy the OLD private key on the air-gapped signer (or archive for forensic signature verification).
2. Record the retirement and the serial at which cutover happened.

**Post-rotation checklist:**

- [ ] `wc -c catalog-NEW.pub == 32`.
- [ ] Staging-seam verification passed; corrupted catalog failed.
- [ ] App release embedding new key shipped; population migrating.
- [ ] Live `catalog.json` serial strictly increased at cutover.
- [ ] Migrated client installs a plugin; un-migrated client fails.
- [ ] Old private key retired/archived once tail is negligible.

---

## 3. Cloudflare / GitHub Token Rotation Ceremony

**Schedule:** Before expiry. **HARD DEADLINE: 2026-06-30** (current token).
**Duration:** ~30 minutes.
**Token Location:** `~/.maccrab-release-env` (SITE_REPO_TOKEN).

### What this token is

`SITE_REPO_TOKEN` is a GitHub fine-grained PAT scoped to `contents:write` on `peterhanily/maccrab-site`. It is used by:

- `scripts/publish-appcast-entry.sh` — publishes new Sparkle appcast entries.
- `scripts/publish-release-json.sh` — publishes `release.json`.
- (forthcoming) rave catalog publish — writes `catalog.json` / `catalog.json.sig`.

**Loss impact:** an attacker with this token can rewrite `appcast.xml` to advertise a malicious DMG (still gated by Sparkle EdDSA signature) or tamper with the catalog (still gated by catalog Ed25519 signature). Store it only on the build Mac.

### Step 0 — Generate the new token (do this BEFORE 2026-06-30)

1. GitHub → Settings → Developer settings → Fine-grained tokens → Generate.
2. Resource owner: `peterhanily`. Repository access: **only** `peterhanily/maccrab-site`.
3. Permissions: **Repository → Contents → Read and write**. Nothing else.
4. Expiration: set the next expiry date. **Update the deadline banner at the top of `docs/runbooks/cloudflare-token-rotation.md`** and set a calendar reminder 2 weeks before.
5. Copy the token value once (GitHub shows it only at creation).

### Step 1 — Publish dry-run (prove the token works before switching)

Do NOT replace the live token until the new one authenticates AND has write scope. The dry-run is read-only:

```bash
NEW_TOKEN='github_pat_...'
SITE_REPO='peterhanily/maccrab-site'

# 1. Auth + read access to appcast.xml
curl -sS -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $NEW_TOKEN" \
  "https://api.github.com/repos/${SITE_REPO}/contents/appcast.xml"
#   EXPECT: 200 (401 = bad token; 403 = wrong scope)

# 2. Confirm write scope (contents:write maps to push on the repo)
curl -sS -H "Authorization: Bearer $NEW_TOKEN" \
  "https://api.github.com/repos/${SITE_REPO}" \
  | python3 -c 'import sys,json; d=json.load(sys.stdin); print("push:", d.get("permissions",{}).get("push"))'
#   EXPECT: push: True

# 3. Confirm read access to release.json + catalog paths
for p in release.json rave/catalog.json rave/keys/catalog.pub; do
  code=$(curl -sS -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer $NEW_TOKEN" \
    "https://api.github.com/repos/${SITE_REPO}/contents/${p}")
  echo "$p -> $code"      # 200 if present, 404 if not yet created (ok)
done
```

All three must pass (200 / push:True / sane codes) before proceeding. If any fail, fix the PAT — do NOT switch.

### Step 2 — Swap the token in

```bash
# Edit ~/.maccrab-release-env (chmod 600, gitignored)
# export SITE_REPO_TOKEN="<old>"
export SITE_REPO_TOKEN="<new>"

# If the token is also stored as a login-Keychain git credential,
# update or remove the stale entry:
git credential-osxkeychain erase <<EOF
protocol=https
host=github.com
EOF
```

### Step 3 — End-to-end verification (one real, reversible publish)

Prove the new token can actually WRITE:

```bash
# Publish release.json (idempotent, easy to re-run)
SITE_REPO_TOKEN="$SITE_REPO_TOKEN" scripts/publish-release-json.sh

# Confirm the commit landed and Cloudflare redeployed
curl -s https://maccrab.com/release.json | python3 -m json.tool | head
```

### Step 4 — Revoke the old token

Only after Step 3 confirms the new token writes successfully:

1. GitHub → Fine-grained tokens → delete the old `maccrab-rave-cf-token`.
2. Confirm a publish still works (it must be using the new token).
3. **Update the deadline banner at the top of `docs/runbooks/cloudflare-token-rotation.md`** with the new expiry.

**Post-rotation checklist:**

- [ ] Dry-run GET on `appcast.xml` returned 200.
- [ ] `permissions.push == true` for new token.
- [ ] `~/.maccrab-release-env` updated; still chmod 600, gitignored.
- [ ] Stale Keychain git-credential fallback cleared.
- [ ] One real publish (release.json) landed + Cloudflare redeployed.
- [ ] OLD token revoked on GitHub.
- [ ] Deadline banner in `docs/runbooks/cloudflare-token-rotation.md` updated.
- [ ] Calendar reminder set ~2 weeks before new expiry.

**If token already expired (missed 2026-06-30):**

1. Generate a new token (Step 0) — expiry does not block replacement.
2. Run the PUBLISH DRY-RUN (Step 1) to confirm.
3. Swap it in (Step 2), then republish lagging artifacts:

```bash
scripts/publish-release-json.sh
scripts/publish-appcast-entry.sh --item <(scripts/generate-appcast-entry.sh \
    --dmg .build/MacCrab-v<ver>.dmg --version <ver>)
```

---

## 4. Offline Key Backup Protocol

All three signing keys (Sparkle EdDSA, rave catalog Ed25519, and the Apple Developer ID certificate) must be backed up offline with careful labeling and retention windows.

**Scope:** Private keys only. Public keys are committed to the repo and are not secrets.

### Sparkle EdDSA Private Key

- **Current location:** Login Keychain on the build Mac (account name determined by Sparkle's key generator).
- **Backup procedure:** Use `security find-generic-password` to export the private key bytes in a portable format (e.g., base64-encoded raw bytes).
- **Storage:** Encrypted external drive or secure air-gapped storage.
- **Label:** `maccrab-sparkle-ed25519-<timestamp>`, note the base64 public key for verification.
- **Retention:** Until the key is formally retired (see Sparkle key-rotation Step 4), keep the most recent backup + at least one prior backup (in case the most recent is corrupted). Once retired, archive offline for ~7 years for forensic signature verification if a compromised release is suspected retroactively.

### Rave Catalog Ed25519 Private Key

- **Current location:** Air-gapped signer machine (your offline keygen tool).
- **Backup procedure:** Export the private key bytes in your keygen tool's format (likely already encrypted).
- **Storage:** Encrypted external drive, kept with the Sparkle backup if both are at the same facility.
- **Label:** `maccrab-rave-catalog-ed25519-<timestamp>`, note the 32-byte hex/base64 public key for verification.
- **Retention:** Until formally retired, keep the most recent + one prior backup. Once retired, archive offline for ~7 years.

### Apple Developer ID Certificate

- **Current location:** Login Keychain on the build Mac (under "Certificates").
- **Backup procedure:** Export from Keychain as `.p12` (with private key).
- **Storage:** Encrypted external drive with the other keys.
- **Label:** `maccrab-apple-devid-<team-id>-<timestamp>`, note the team ID (`79S425CW99`) and certificate fingerprint.
- **Retention:** Until the certificate expires or is revoked. Keep current + one prior backup. After expiry, archive offline indefinitely (needed to verify signatures on old releases).

### Backup checklist (annual)

- [ ] Sparkle EdDSA private key exported and encrypted.
- [ ] Rave catalog Ed25519 private key exported and encrypted (if air-gapped key exists).
- [ ] Apple Developer ID certificate exported as `.p12` with private key.
- [ ] All three files labeled with timestamp and public key/fingerprint for verification.
- [ ] Backups stored on encrypted external drive, kept offline or in a secure facility.
- [ ] At least one prior backup of each key retained.
- [ ] Backup integrity tested (decrypt, verify format, confirm public-key match).

---

## 5. Operator Ceremonies Calendar

| Ceremony | Frequency | Effort | Preconditions | Runbook |
|---|---|---|---|---|
| **Sparkle EdDSA key rotation** | As needed (hygiene every 1–2 years, or immediately if leak suspected) | 2–3 hours | Current key + new Keychain entry + test machines | `docs/runbooks/sparkle-key-rotation.md` |
| **Rave catalog key rotation** | As needed (hygiene every 1–2 years, or immediately if leak suspected) | 1–2 hours | Air-gapped signer + new key pair + staging key seam | `docs/runbooks/rave-catalog-key-rotation.md` |
| **GitHub token rotation** | **HARD DEADLINE: 2026-06-30** (current token); then annually | 30 minutes | GitHub fine-grained PAT creation + dry-run test | `docs/runbooks/cloudflare-token-rotation.md` |
| **Key backup** | Annual (or after any key ceremony) | 30 minutes | Encrypted external drive + labeling template | This document (Section 4) |
| **Release (normal)** | Per-release (1–2 weeks cadence in active period) | 2–3 hours | All secrets present in `~/.maccrab-release-env` + prerelease checks passing | `RELEASE_PROCESS.md` + `scripts/release.sh` |

---

## Appendix: Quick reference for `~/.maccrab-release-env`

Create this file on your build Mac with `chmod 600`. Source it before running `release.sh`:

```bash
# ~/.maccrab-release-env
export DEVELOPER_ID="Developer ID Application: Peter Hanily (79S425CW99)"
export APPLE_ID="your.email@example.com"
export APPLE_TEAM_ID="79S425CW99"
export NOTARIZE_PASSWORD="xxxx-xxxx-xxxx-xxxx"  # app-specific password from appleid.apple.com
export SITE_REPO_TOKEN="github_pat_..."          # GitHub fine-grained PAT, contents:write on peterhanily/maccrab-site
```

Do not commit this file. Do not sync to iCloud or any cloud service. The file should not be backed up except by the offline key-backup procedure above.

---

## Related documents

- `RELEASE_PROCESS.md` — End-to-end release pipeline and secret inventory.
- `docs/runbooks/sparkle-key-rotation.md` — Detailed Sparkle EdDSA dual-key transition.
- `docs/runbooks/rave-catalog-key-rotation.md` — Detailed rave catalog Ed25519 rotation.
- `docs/runbooks/cloudflare-token-rotation.md` — GitHub token rotation with 2026-06-30 deadline.
- `RELEASE_CHECKLIST.md` — Pre-release manifest sync and audit items.
- `scripts/prerelease-check.sh` — Automated verification of version parity across all sources.
