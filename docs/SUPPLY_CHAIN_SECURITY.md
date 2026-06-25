# Supply Chain Security & Incident Playbook

## 1. Scope

This document describes MacCrab's release and auto-update supply chain, the vulnerabilities that exist today, incident response procedures, and the hardening roadmap.

**What this covers:**
- Developer ID signing (binary integrity, Apple notarization)
- Sparkle EdDSA appcast signatures (auto-update verification)
- Release artifact distribution (GitHub releases, Homebrew tap, Sparkle appcast at maccrab.com)
- The operator's local environment and key custody

**What this does NOT cover:**
- MacCrab's detection/prevention rules and their accuracy
- Runtime vulnerabilities in the macOS kernel or third-party dependencies
- System Extension entitlement vetting or Apple's ES framework security
- Homebrew/GitHub infrastructure security (we trust their authentication and transport)
- Client-side attacks (e.g., someone physically accessing a machine with MacCrab installed)

---

## 2. Current State: Honest Assessment

### 2.1 Signing and distribution chain

**Single Developer ID identity:** Every MacCrab release DMG is signed with the same Developer ID Application certificate — Peter Hanily, team ID `79S425CW99` — stored in the operator's macOS login Keychain on the build machine.

**Apple notarization:** The signed DMG is submitted to Apple's notarization service (`xcrun notarytool`) which performs malware scanning. Upon acceptance, a notarization ticket is stapled to the DMG. The ticket is valid for the lifetime of the Developer ID certificate.

**Code signature verification:** End users (and automated tooling) can verify the code signature with:
```bash
codesign -dvv ~/Downloads/MacCrab-v<version>.dmg
```
Expected fragments: `Authority=Developer ID Application: Peter Hanily (79S425CW99)` and `TeamIdentifier=79S425CW99`.

**Sparkle appcast signature:** Installed MacCrab instances check for updates once per day (`SUScheduledCheckInterval=86400` seconds in Info.plist) by polling `https://maccrab.com/appcast.xml`. Each `<item>` carries an `sparkle:edSignature` attribute — an EdDSA signature over the DMG bytes. Sparkle verifies this signature **before** downloading or unpacking the update.

The public verification key is embedded in every shipped MacCrab Info.plist as `SUPublicEDKey`:
```
de+dzPjBve7LP5qxoE7nR6shThsjubkVasi+i8ehT4E=
```

This is confirmed in:
- `Xcode/project.yml` (the canonical source; all other copies derive from here)
- `Xcode/Resources/MacCrabApp-Info.plist` (embedded in the app bundle at build time)
- `Xcode/Resources/MacCrabAgent-Info.plist` (embedded in the system extension)

### 2.2 The Sparkle EdDSA private key: single point of catastrophic failure

The matching private key lives in the operator's macOS login Keychain, stored by Sparkle's `generate_keys` tool under the account name `https://sparkle-project.org`. There is **one private key** for the entire v1.x release series.

**Blast radius if leaked:**
- An attacker with the private key can forge a valid EdDSA signature for any DMG.
- They can advertise a malicious DMG in the appcast XML (either by compromising the site repo or by publishing their own).
- Every installed MacCrab instance will verify the signature against the embedded public key and accept the malicious update.
- Because Sparkle only verifies against a single embedded public key per app version, **there is no rotation path** without shipping a new bundle and convincing every existing user to manually reinstall.

**Current mitigation:** The key is locked behind the login Keychain, secured by the build machine's local authentication. It is not backed up, synced, or copied elsewhere.

### 2.3 Secondary secrets

| Secret | Blast radius if leaked |
|---|---|
| **Developer ID Application certificate + password** | An attacker can sign and notarize any Mach-O under the team ID `79S425CW99`, distributing malicious binaries that appear legitimate. Revocation at appleid.apple.com stops new notarizations but not already-stapled tickets. Combined with Sparkle key compromise, it's game over. |
| **GitHub PAT (SITE_REPO_TOKEN)** | An attacker can modify `appcast.xml` to advertise a malicious DMG. If the Sparkle key is also compromised, they can forge a valid signature. If NOT compromised, a swapped DMG will fail signature verification before unpacking. |
| **Build machine access** | An attacker with local access to the build Mac can extract all four secrets from the login Keychain, then distribute a malicious release signed with the real cert and real Sparkle key. This is why the build Mac must be kept isolated and un-touched by general browsing / email. |

### 2.4 No key rotation has been performed

Both the Developer ID certificate and the Sparkle EdDSA key are at their original state since inception. Neither has been rotated, backed up offline, or held in escrow.

### 2.5 Verification chain for end users

MacCrab provides `docs/TRUST.md`, which documents the four verification links:
1. **SHA256 checksum** — published in `Casks/maccrab.rb` and GitHub release notes.
2. **Code signature** — verifiable with `codesign -dvv` (identity: Peter Hanily, team `79S425CW99`).
3. **Notarization ticket** — verifiable with `spctl -a -t open` and `xcrun stapler validate`.
4. **Sparkle EdDSA signature** — verified automatically by Sparkle before update; manually inspectable from `https://maccrab.com/appcast.xml`.

End users who are suspicious can perform all four checks. A compromised release will fail at least one.

---

## 3. Why This Is Hard for a One-Person Project

MacCrab is developed and released by a single operator. This creates hard constraints:

1. **No second signer:** Every release is signed by one person with one certificate, one Sparkle key, one set of credentials. There is no "require 2 of 3 signatures" pattern.

2. **No cloud HSM or key escrow:** The keys live in a local Keychain. There is no hardware security module, key recovery service, or offline backup in case of catastrophic loss. Losing the Sparkle key is game over — recovery is manual reinstall only.

3. **No CI signing:** The build machine must be trusted absolutely — signing and notarization **never** run in GitHub Actions (see `RELEASE_PROCESS.md` step 3). This keeps secrets off GitHub infrastructure but means the build Mac is the single point of failure.

4. **Operator rotation is brittle:** If the current operator wants to hand off the project, they must extract their private key from their Keychain and transfer it to the successor — a manual, risky process with no rollback.

Given these constraints, the playbook below is designed for **honest incident response**, not prevention of all attacks.

---

## 4. Post-Compromise Incident Playbook

### Scenario: Sparkle EdDSA private key is suspected leaked or compromised

**Detection triggers:**
- A security researcher reports that a malicious signature validates against a known-bad DMG.
- You lose control of the build Mac and suspect keychain access.
- You receive a report of clients auto-updating to an unexpected version.
- Telemetry / logs show an appcast entry was published with a valid signature but no corresponding GitHub release.

**Actions — execute in order:**

#### Phase 1: Immediate containment (within 1 hour)

1. **Assume the key is compromised.** Do not wait for absolute confirmation. Begin a new Sparkle key generation immediately.

2. **Issue a public security advisory** via GitHub (`peterhanily/maccrab/security/advisories`) and email `maccrab@peterhanily.com`:
   - "Sparkle EdDSA key may have been compromised. Do not auto-update for the next 48 hours. A patched release with new signing keys is in progress."
   - Do NOT name the specific leaked key or provide the public key — that would help attackers forge signatures against old clients.

3. **Notify Homebrew:** If the key is in the wild and someone publishes a malicious Homebrew formula, you want Homebrew awareness early. File an issue on homebrew/homebrew-casks or contact `security@brew.sh` with the advisory.

4. **Revoke the Developer ID certificate** (optional but recommended if you believe it's also compromised):
   - Log into `appleid.apple.com`, navigate to Developer Certificates, and revoke the `Developer ID Application` cert for team `79S425CW99`.
   - This stops new notarizations under the team ID but does NOT invalidate already-stapled tickets.
   - If you revoke the cert, you cannot publish a bridge release under the old cert — you must generate a new Developer ID certificate as well (requires Apple dev account; may take 24 hours).

#### Phase 2: Build a new release (within 24 hours)

1. **Generate a new Sparkle EdDSA key pair** on the build Mac:
   ```bash
   ~/Tools/bin/generate_keys       # generates new private key, stored in Keychain
   ~/Tools/bin/generate_keys -p    # prints the NEW public key (base64)
   ```

2. **Optionally, generate a new Developer ID certificate** (if you revoked the old one). This requires manual intervention at `appleid.apple.com` and may take 24 hours. If you do NOT revoke the old cert, you can ship the Sparkle-key-only fix below.

3. **Cut a "recovery" release:**
   - Version: e.g., `v1.19.4-security` or `v1.19.4+spark-rotate` (whatever version number comes next).
   - Update `Xcode/project.yml` with the NEW `SUPublicEDKey`.
   - Build, sign, and notarize the DMG as usual.
   - **Do NOT publish the appcast entry yet** — see Phase 3.

4. **Confirm key pairing** before publishing:
   ```bash
   ./scripts/generate-appcast-entry.sh --dmg .build/MacCrab-v<version>.dmg --version <version>
   ```
   This will verify that the NEW private key in the Keychain pairs with the NEW public key you embedded in the bundle. It will abort if they don't match (catch-all gate).

#### Phase 3: Force-gate the new release (immediately after build)

Sparkle supports `minimumAutoupdateVersion` and `minimumSystemVersion` XML attributes in appcast items. We use these to **mandate** the update:

1. In `scripts/generate-appcast-entry.sh` (or by hand-editing the `<item>` snippet), set:
   ```xml
   <sparkle:minimumAutoupdateVersion>0.0.0</sparkle:minimumAutoupdateVersion>
   ```
   This forces Sparkle to treat the new release as mandatory, even if an older version is already installed. Clients cannot skip it.

   (Confirm that Sparkle 2.9.1 supports this attribute by checking `https://sparkle-project.org/documentation/`. As of June 2026, it does.)

2. Publish the appcast entry:
   ```bash
   scripts/publish-appcast-entry.sh --item /tmp/recovery-item.xml --version <version>
   ```

3. Verify the appcast went live:
   ```bash
   curl -s https://maccrab.com/appcast.xml | grep '<sparkle:version>'
   ```

#### Phase 4: Notify users and monitor

1. **Post a detailed incident report** on the GitHub repo and `maccrab@peterhanily.com`:
   - Timeline: when the compromise was detected, when the fix was released.
   - Impact: how many installed clients were at risk; what changes they should make.
   - Remediation: confirm that the recovery release signed with the new key is live, and Sparkle will auto-update clients within 24 hours.

2. **Monitor Sparkle downloads and client reports:**
   - Check GitHub release download stats to estimate how many clients are updating.
   - Watch for new issues/emails reporting auto-update failures or signature mismatches.

3. **Confirm the fix is working:**
   - On a test Mac running the old version, wait for the auto-update to fire (or force a check via MacCrab's update UI).
   - Verify that the update accepts the new appcast signature and installs the recovery build.
   - Verify that the recovery build's Info.plist contains the NEW `SUPublicEDKey` and that Sparkle recognizes it.

#### Phase 5: Long-term cleanup (within 2 weeks)

1. **Delete the compromised key** from the build Mac's Keychain:
   ```bash
   security delete-generic-password -s 'https://sparkle-project.org' -a '<old-account-name>'
   ```

2. **Document what happened** in a new CHANGELOG section and a post-mortem (if necessary).

3. **Perform a security audit** of the build Mac:
   - Check login history and Keychain access logs for suspicious activity.
   - Verify that only the current user accessed the Keychain secrets.
   - Consider re-imaging the machine if the compromise origin is unclear.

4. **Establish a schedule** for future key rotation (see Section 5, Tier 2).

### Scenario: Appcast corruption (SITE_REPO_TOKEN leaked, but Sparkle key safe)

If only the Cloudflare/GitHub appcast access is compromised (e.g., the PAT was leaked but the Sparkle key is safe):

1. **Immediately rotate SITE_REPO_TOKEN** (see `docs/runbooks/cloudflare-token-rotation.md`).
   - Revoke the old PAT on GitHub.
   - Generate a new fine-grained PAT with the same scope.
   - Update `~/.maccrab-release-env` on the build Mac.

2. **Check the appcast for malicious entries:**
   ```bash
   curl -s https://maccrab.com/appcast.xml | less
   ```

3. **Remove any suspicious `<item>` entries** by editing `peterhanily/maccrab-site` directly (GitHub Web UI or git push).

4. **No new release is needed** — existing clients will fail to verify any signature that doesn't match the real Sparkle key.

---

## 5. Hardening Roadmap

### Tier 1: Do now (release integrity, no external dependencies)

**Owner: Release operator**

- [ ] **Test:** Add a pre-release gate in `scripts/prerelease-check.sh` that:
  - Reads `SUPublicEDKey` from `Xcode/project.yml` (the canonical source).
  - Confirms that both `Xcode/Resources/MacCrabApp-Info.plist` and `Xcode/Resources/MacCrabAgent-Info.plist` contain **identical** values.
  - Fails loudly and halts the release if any key doesn't match.
  - (This test already exists; confirm it runs on every release.)

- [ ] **Runbook:** Document the Sparkle EdDSA key rotation procedure in full:
  - Write `docs/runbooks/sparkle-key-rotation.md` (exists as of June 2026; confirm it matches this playbook).
  - Include pre-flight checklist (key is reachable, public key matches shipped value), bridge release steps (cut with NEW key embedded, OLD key signed), and rollback instructions.

- [ ] **Verify the appcast signature verification code in Sparkle:**
  - Confirm that `sign_update --verify <dmg> <signature>` returns 0 if the signature is valid against the DMG.
  - Confirm that `generate_keys -p` prints the PUBLIC key for the Keychain-stored private key.
  - Ensure the operator can run these commands before every release.

**Success criteria:** Operator can execute the key rotation runbook without trial-and-error.

---

### Tier 2: Operator discipline (manual, scheduled rotation)

**Owner: Release operator, scheduled annually**

- [ ] **Annual key rotation ceremony:**
  - Once per year (e.g., January), execute the Sparkle key rotation runbook:
    1. Generate a new key pair.
    2. Cut a bridge release with the new key embedded, old key signed.
    3. Verify on a test client.
    4. Publish the bridge release.
    5. Delete the old key after the tail migrates (30-60 days later).

- [ ] **Offline key backup (before rotation):**
  - Before cutting the bridge release, export the CURRENT private key to an encrypted USB drive or air-gapped machine (not iCloud, not GitHub, not any sync service).
  - Secure the backup in a safe, separate from the build Mac.
  - If the build Mac is lost/stolen, the backup allows recovery without bricking existing clients (cut another bridge release using the backed-up key).

- [ ] **Build Mac security hardening:**
  - Designate the build Mac as release-only (no general development, browsing, or email).
  - Use a separate user account for email so phishing on the development account doesn't compromise the build identity.
  - Enable FileVault full-disk encryption.
  - Disable iCloud Keychain sync.
  - Audit login Keychain access once per month (e.g., `security dump-keychain -d login.keychain` and spot-check for unexpected entries).

**Success criteria:** Operator has a documented, repeatable annual rotation process; backup is secure and tested annually.

---

### Tier 3: External hardening (future, requires infrastructure)

**Owner: Future maintainer or team**

These require architectural changes and are not urgent for a single-maintainer project today, but they reduce the blast radius if implemented:

- [ ] **Multi-signer model (future):**
  - Require 2-of-3 developer signatures on releases (e.g., Developer ID cert + Sparkle key both held by multiple people or on separate hardware).
  - Use Sigstore or another transparency log to publish signing events.
  - Sparkle does not natively support multi-key appcast validation, so this would require:
    1. Fork Sparkle or vendor a custom validation layer.
    2. Embed multiple `SUPublicEDKey` entries in the bundle (or a hash of a quorum threshold).
    3. Require all signatures to verify before accepting the update.

- [ ] **Sparkle key transparency log (future):**
  - Publish every Sparkle key rotation event and every appcast signature to a public log (similar to Certificate Transparency for SSL certs).
  - Clients can periodically verify that their embedded public key is the same one being used to sign the appcast.
  - This catches a silent key swap (e.g., an attacker replaces the key in the project.yml without cutting a bridge release).

- [ ] **Hardware security module (future):**
  - Move the Sparkle private key to a YubiKey or cloud HSM (e.g., AWS CloudHSM, Google Cloud KMS).
  - Reduces the blast radius if the build Mac is compromised — the key never leaves the hardware.
  - Increases operational latency (must contact the HSM to sign updates).
  - Requires careful secret management for the HSM access credential.

- [ ] **Third-party escrow (future):**
  - Deposit the Sparkle private key with a trusted third party (e.g., a security firm, an escrow service, or a group of core maintainers) such that any single person's loss is recoverable.
  - Requires legal agreement on access conditions and recovery procedures.

**Success criteria:** Infrastructure and team are in place to support multi-signer or transparency-log verification; build process is updated to accommodate.

---

## 6. Detection: How to spot a compromised release

### For end users

If you suspect a MacCrab update is malicious:

1. **Before installing:** Verify the appcast signature manually:
   ```bash
   curl -s https://maccrab.com/appcast.xml | grep -A5 '<sparkle:version>v<version>'
   # Extract the sparkle:edSignature attribute value (base64)
   # and the download URL
   
   # Download the DMG and verify the signature with the public key
   # (this requires Sparkle tools; easier to just not update and report the issue)
   ```

2. **Do NOT auto-update.** Disable auto-update temporarily:
   - MacCrab UI → Settings → Disable auto-update.
   - Or edit `~/Library/Preferences/com.maccrab.app.plist` and set `SUEnableAutomaticChecks: false`.

3. **Report the suspicious version** to `maccrab@peterhanily.com` with:
   - The version number and appcast signature.
   - The GitHub URL if you downloaded from there.
   - Any error messages from Sparkle or the update process.

### For the operator

Before every release, verify:

```bash
# 1. The Sparkle key pairing
~/Tools/bin/generate_keys -p | tr -d '[:space:]' > /tmp/actual_pub.txt
grep 'SUPublicEDKey:' Xcode/project.yml | sed -E 's/.*"([^"]+)".*/\1/' > /tmp/expected_pub.txt
diff /tmp/actual_pub.txt /tmp/expected_pub.txt || exit 1

# 2. The Developer ID cert is who you expect
security find-identity -v -p codesigning | grep "Developer ID Application: Peter Hanily"

# 3. The appcast entry verifies before publishing
scripts/generate-appcast-entry.sh --dmg .build/MacCrab-v<version>.dmg --version <version> || exit 1
```

---

## 7. Recovery and business continuity

### Single-maintainer project loss

If the sole operator becomes unavailable (incapacitation, departure, loss of build Mac):

1. **Sparkle auto-update channel is dead.** Existing clients will check the appcast but no new entries will be signed (the key is inaccessible).

2. **Recovery path:**
   - A new maintainer must generate a new Sparkle key pair (destroying the old key's recovery chain).
   - Cut a recovery release with the new key, published at a NEW feed URL (because existing clients won't trust the new key in the old appcast).
   - Use GitHub releases as the distribution mechanism until appcast publishing is restored.
   - Publish a migration advisory so users update manually.

3. **Mitigation (today):**
   - Store an encrypted backup of the Sparkle private key in a secure location (not on the build Mac, not in cloud sync).
   - Document the location and recovery procedure in a sealed envelope or shared with a trusted collaborator.
   - Clarify in the project README who has access to the recovery process.

---

## References

- [`RELEASE_PROCESS.md`](RELEASE_PROCESS.md) — full end-to-end release pipeline and secret inventory.
- [`docs/TRUST.md`](docs/TRUST.md) — end-user verification procedures (SHA256, code signature, notarization, Sparkle signature).
- [`docs/runbooks/sparkle-key-rotation.md`](docs/runbooks/sparkle-key-rotation.md) — detailed Sparkle key rotation procedure (dual-key bridge release).
- [`docs/runbooks/cloudflare-token-rotation.md`](docs/runbooks/cloudflare-token-rotation.md) — GitHub PAT rotation for appcast publishing.
- [`SECURITY.md`](SECURITY.md) — vulnerability reporting policy and threat model.
- [`Xcode/project.yml`](../Xcode/project.yml) — canonical source for Developer ID, Sparkle key, and version.
