# Trust & Release Verification

This page documents how to verify that a MacCrab build came from this
project, hasn't been tampered with, and is the version it claims to be.
The chain has four independent links: code signature, notarization
ticket, Sparkle EdDSA appcast signature, and SHA256 checksum. Any one
failing means don't trust the artifact.

If you're security-reviewing MacCrab before deploying it, this is the
page to start from.

## Identities

| Field | Value |
|---|---|
| Apple Developer ID | `Developer ID Application: Peter Hanily (79S425CW99)` |
| Apple Team ID | `79S425CW99` |
| App bundle ID | `com.maccrab.app` |
| System Extension bundle ID | `com.maccrab.agent` |
| Sparkle appcast feed | `https://maccrab.com/appcast.xml` |
| Sparkle EdDSA public key | First 8 chars: `de+dzPjB`. Full key in `Xcode/Resources/MacCrabApp-Info.plist` under `SUPublicEDKey`. |
| GitHub release page | `https://github.com/peterhanily/maccrab/releases` |
| Homebrew tap | `peterhanily/homebrew-maccrab` — install with `brew install --cask peterhanily/maccrab/maccrab` |
| Security contact | `maccrab@peterhanily.com` (see `SECURITY.md`) |

## Verifying a downloaded DMG

After downloading `MacCrab-v<version>.dmg` from the GitHub releases page
(or from `https://github.com/peterhanily/maccrab/releases/download/v<version>/MacCrab-v<version>.dmg`):

### 1. SHA256 checksum

Each release's checksum is published in two places:
- The `Casks/maccrab.rb` file in the main repo (search for `sha256 "..."`)
- The GitHub release notes (when published with `--notes-file`; the
  checksum is included in the release commit that bumps the cask)

```bash
shasum -a 256 ~/Downloads/MacCrab-v1.12.5.dmg
# Compare to the value in Casks/maccrab.rb on main
```

If they don't match, **stop**. Don't open the DMG.

### 2. Code signature

Apple's `codesign` confirms the DMG was signed by Peter Hanily's
Developer ID and hasn't been mutated since signing:

```bash
codesign -dvv ~/Downloads/MacCrab-v1.12.5.dmg
```

Expected fragments in the output:
- `Authority=Developer ID Application: Peter Hanily (79S425CW99)`
- `TeamIdentifier=79S425CW99`

### 3. Notarization ticket

Apple's notarization confirms the binary passed Apple's malware scan and
the ticket has been stapled to the DMG:

```bash
spctl -a -t open --context context:primary-signature ~/Downloads/MacCrab-v1.12.5.dmg
```

Expected: `accepted` and `source=Notarized Developer ID`.

To verify the staple itself:

```bash
xcrun stapler validate ~/Downloads/MacCrab-v1.12.5.dmg
```

Expected: `The validate action worked!`.

### 4. Verify the .app inside

After mounting the DMG, repeat steps 2 + 3 against the `.app` bundle:

```bash
codesign -dvv "/Volumes/MacCrab v1.12.5/MacCrab.app"
spctl -a -t exec -vv "/Volumes/MacCrab v1.12.5/MacCrab.app"
```

The System Extension nested inside the app
(`Contents/Library/SystemExtensions/com.maccrab.agent.systemextension`)
is signed with the same Developer ID and inherits notarization from the
parent bundle. Apple's `sysextd` will refuse to activate it if the
signature/notarization chain is broken.

## Verifying Sparkle auto-updates

Existing installs receive updates via Sparkle from the appcast at
`https://maccrab.com/appcast.xml`. Each `<item>` carries an
`sparkle:edSignature` attribute computed over the DMG bytes with the
private half of the EdDSA key listed above.

Sparkle inside MacCrab.app verifies the signature **before** unpacking
the update. A swapped DMG fails verification and the update aborts. To
inspect the appcast manually:

```bash
curl -sS https://maccrab.com/appcast.xml | head -60
```

Find the `<sparkle:edSignature="...">` and `length="..."` attributes for
the version you're checking. The download URL in the same `<item>`
points to the GitHub release asset.

The Sparkle EdDSA public key in `MacCrabApp-Info.plist` is set at
build time and is part of the signed app bundle, so a tampered
update server can't substitute its own key.

## Endpoint Security entitlement status

MacCrab's System Extension is signed with the
`com.apple.developer.endpoint-security.client` entitlement, granted by
Apple to MacCrab's developer account. You can confirm:

```bash
codesign -d --entitlements - "/Library/SystemExtensions/<UUID>/com.maccrab.agent.systemextension"
```

Without this entitlement, the sysext can't subscribe to ES events and
detection collapses to the fallback collectors (Unified Log, FSEvents,
network tap, BPF DNS). The entitlement is real Apple-issued — if a
fork strips it, the fork won't have ES coverage.

## Plugin trust tiers & catalog governance

The verification above covers the **app** (the signed, notarized MacCrab
build). Forensic **plugins** are a separate trust chain with three tiers. In
all three the plugin runs the same way at the OS level — trust gates *whether
a plugin runs*, not *what it can reach*; the sandbox + fd-broker gate what it
can reach (see [`PLUGIN_AUTHORING.md`](PLUGIN_AUTHORING.md)).

| Tier | Who vouches | How it runs | Provenance shown |
|---|---|---|---|
| **First-party** | The app publisher key. The `com.maccrab.*` id namespace is **reserved** and impersonation is refused. | Unsandboxed, with Full Disk Access. | first-party |
| **Curated store (rave catalog)** | The rave catalog vets the plugin and signs its entry (Ed25519); the client verifies the signature, the artifact SHA-256, and the signed anti-rollback revocation list before install. | **Sandboxed, deny-default** (reads brokered over fd 3). | third-party · store |
| **Sideload (operator TOFU)** | You, the operator: `maccrabctl plugin trust <hex>` or `install --trust-on-install` / `install --local`. | **Sandboxed, deny-default.** | third-party · sideloaded · unverified |

**Where third-party catalog moderation/governance lives:** the curated-store
tier — which plugins are accepted, how submissions are vetted, and how a key
is revoked — is governed in the **separate `maccrab-rave` repository**, not in
this repo. This repo carries only the **client** side: signature/SHA/revocation
verification, the reserved-namespace guard, and quarantine-on-revoke (see
[`SUPPLY_CHAIN_SECURITY.md`](SUPPLY_CHAIN_SECURITY.md) for the release/update
supply chain, and [`INCIDENT_RESPONSE.md`](INCIDENT_RESPONSE.md) §3 for
handling a revoked plugin). The catalog key that signs store entries is
distinct from the app-signing key and the rule-channel key, so a compromise of
one does not extend to the others.

## Reporting trust issues

If you see a downloaded artifact whose checksum, signature, notarization,
or appcast signature doesn't match what's published — that's a
supply-chain incident, not a normal bug. Open an issue at
[github.com/peterhanily/maccrab/issues](https://github.com/peterhanily/maccrab/issues)
with the artifact's `shasum -a 256` and the URL you fetched it from.

## Related docs

- [`THREAT_MODEL.md`](THREAT_MODEL.md) — what attackers MacCrab does and doesn't defend against
- [`RESPONSE_SAFETY.md`](RESPONSE_SAFETY.md) — what response actions are gated by what validators
- [`COVERAGE.md`](COVERAGE.md) — rule-to-MITRE-ATT&CK coverage matrix
- [`CHANGELOG.md`](../CHANGELOG.md) — what changed in each release
