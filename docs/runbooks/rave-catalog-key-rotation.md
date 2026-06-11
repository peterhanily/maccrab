# Runbook — air-gapped rave catalog Ed25519 key rotation

**Audience:** release operator. **Execute manually.** No script and no
CI job rotates this key. The catalog signing **private** key is intended
to live OFFLINE / air-gapped; this runbook assumes you sign the catalog
on an air-gapped machine and move only public artifacts and signatures
across the air gap.

> **Decision (v1.19.0):** no catalog-key rotation is performed this
> cycle. This runbook is written so a future rotation is a procedure,
> not an improvisation.

---

## What this key is

The rave plugin catalog (`catalog.json`) served from the site repo
(`maccrab-site/rave/`) is signed with an **Ed25519 (Curve25519.Signing)**
key. Clients verify `catalog.json` against `catalog.json.sig` using the
**public** key `catalog.pub` (32 raw bytes), which is:

- sourced from `maccrab-site/rave/keys/catalog.pub` at build time,
- bundled into `MacCrab.app` (`Resources/MacCrab_MacCrabApp.bundle/catalog.pub`
  and `Resources/rave-keys/catalog.pub`),
- loaded by `PluginCatalogFetch.loadCatalogPublicKey()` (see
  `Sources/maccrabctl/PluginCatalogFetch.swift`). It enforces exactly
  32 bytes and a valid Curve25519 representation.

Anti-rollback: the catalog carries a monotonic `catalog_serial`;
`RaveTrustState` keeps a high-water mark and rejects a validly-signed
but older serial as a replay. **A key rotation MUST keep the serial
monotonic** — do not reset it.

**Blast radius vs. Sparkle:** smaller than the Sparkle key. A leaked
catalog key lets an attacker sign a malicious catalog, but installs are
ALSO gated by signer-pinning (`RaveSignerPin`), per-plugin attestation,
the signed revocation list (O2), and the version-floor + signed install
receipt (O3). It is still a stop-ship event — rotate promptly.

**Same dual-key shape as Sparkle.** Like `SUPublicEDKey`, the bundled
`catalog.pub` is fixed at install time. An installed client trusts only
the key it shipped with, so a clean swap strands every installed client
until they update the app. The transition below is the catalog analogue
of the Sparkle bridge.

---

## Pre-flight

1. On the air-gapped signer, confirm the CURRENT private key is present
   and note its public half (32-byte raw, base64 or hex as you store it).
2. Confirm `maccrab-site/rave/keys/catalog.pub` equals that public half.
3. Note the live `catalog_serial` (the rotation must continue from it).
4. Decide the transition window. As with Sparkle, you generally need a
   bridge so installed clients migrate before the old key is retired.

## Step 1 — generate the new key pair (air-gapped)

On the air-gapped machine, generate a fresh Curve25519 signing key. Keep
the private key offline. Export ONLY the 32-byte raw public key.

```bash
# Illustrative — use your offline keygen. Output must be 32 raw bytes.
# python3 - <<'PY'
# from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
# from cryptography.hazmat.primitives import serialization
# priv = Ed25519PrivateKey.generate()
# open('catalog-NEW.key','wb').write(priv.private_bytes(
#     serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
#     serialization.NoEncryption()))
# open('catalog-NEW.pub','wb').write(priv.public_key().public_bytes(
#     serialization.Encoding.Raw, serialization.PublicFormat.Raw))
# PY
```

Verify the public key is exactly 32 bytes (the client rejects anything
else):

```bash
wc -c catalog-NEW.pub      # must print 32
```

## Step 2 — staging verification BEFORE production (use the staging seam)

The code ships a debug-only staging-key seam so you can verify a new key
end-to-end without touching the bundled production key:

- `RaveStagingPubOverride` / `MACCRAB_RAVE_STAGING_PUB` — a DEBUG build
  verifies against the staging key instead of the bundled production key
  (compiled out / always nil on release builds).
- `MACCRAB_RAVE_CATALOG_PUB_PATH` — points `maccrabctl` at an explicit
  `catalog.pub` file (local-dev override; wins over everything).

Procedure:

1. On the air-gapped signer, sign a TEST catalog (incremented serial)
   with the NEW private key → `catalog.json` + `catalog.json.sig`.
2. Move the test catalog + the NEW public key across the air gap.
3. Verify with an explicit key path (no rebuild needed):
   ```bash
   MACCRAB_RAVE_CATALOG_PUB_PATH=/path/to/catalog-NEW.pub \
     maccrabctl plugin catalog --base file:///path/to/test-catalog/
   ```
   The fetch must succeed (signature verifies, serial accepted). A
   1-byte corruption of the test `catalog.json` must make it FAIL.

## Step 3 — the bridge: ship the new public key in the app, keep signing with OLD

Installed clients hold the OLD `catalog.pub`. To migrate them:

1. Replace `maccrab-site/rave/keys/catalog.pub` in the SOURCE that
   build-release.sh bundles (`Sources/MacCrabApp/Resources/rave-keys/catalog.pub`
   and the MacCrabApp resource bundle) with `catalog-NEW.pub`. The next
   app release will embed the new key.
2. Ship that app release through the normal Sparkle/DMG pipeline. After
   users update the app, they trust the NEW catalog key.
3. **Until the app population has migrated, keep signing the LIVE
   `catalog.json` with the OLD private key** so not-yet-updated clients
   keep verifying. (If your catalog format / client supported dual
   signatures you could sign with both; today it is single-signature, so
   the app update is the bridge.)

## Step 4 — cut over the live catalog to the NEW key

Once the app population embeds `catalog-NEW.pub`:

1. On the air-gapped signer, sign the production `catalog.json`
   (serial strictly greater than the last published serial) with the
   NEW private key.
2. Move `catalog.json` + `catalog.json.sig` across the air gap and
   publish to `maccrab-site/rave/`.
3. Verify a migrated client installs a plugin end-to-end; verify a
   not-yet-migrated client now FAILS verification (expected — it must
   update the app).

## Step 5 — retire the old key

After the tail of un-migrated app installs is negligible:

1. Destroy the OLD private key on the air-gapped signer (or move to cold
   archive if you must retain it for forensic signature verification).
2. Record the retirement + the serial at which cutover happened.

---

## Invariants the rotation must NOT break

- `catalog.pub` is **exactly 32 bytes** (client hard-rejects otherwise).
- `catalog_serial` is **strictly monotonic** across the rotation — never
  reset; a lower serial is treated as a rollback/replay and rejected.
- The bundled key, the site `keys/catalog.pub`, and the signing private
  key are the SAME key pair at all times the live catalog is signed.
- Production release builds never trust the staging key
  (`RaveStagingPubOverride` is compiled out of release).

## Post-rotation checklist

- [ ] `wc -c` on the new `catalog.pub` == 32.
- [ ] Staging-seam verification (Step 2) passed AND a corrupted catalog
      failed.
- [ ] App release embedding the new key shipped; population migrating.
- [ ] Live `catalog.json` serial strictly increased at cutover.
- [ ] Migrated client installs a plugin; un-migrated client fails closed.
- [ ] Old private key retired/archived once the tail is negligible.

## Related

- `Sources/maccrabctl/PluginCatalogFetch.swift` — key load + 32-byte +
  Curve25519 enforcement, anti-rollback gate.
- `Sources/MacCrabForensics/TierB/RaveTrustState.swift` — serial
  high-water mark.
- `Sources/MacCrabForensics/TierB/RaveStagingPubOverride.swift` — debug
  staging seam.
- `docs/runbooks/sparkle-key-rotation.md` — the analogous Sparkle bridge.
