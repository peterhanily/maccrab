# Runbook — `maccrab-rave-cf-token` rotation (Cloudflare publish path)

**Audience:** release operator. **Execute manually.**

> ## ⏰ HARD DEADLINE: 2026-06-30
>
> The current publish token (`maccrab-rave-cf-token` /
> `SITE_REPO_TOKEN`) **expires 2026-06-30**. After that timestamp the
> appcast + release.json + rave-catalog publish steps stop working with
> no warning other than a 401 mid-release. Rotate BEFORE the deadline.
> Once the rave catalog depends on this token for catalog publish, an
> expiry becomes a supply-chain availability outage, not just a stale
> appcast. **Do the PUBLISH DRY-RUN (below) before any catalog cutover
> relies on the new token.**

---

## What this token is

`SITE_REPO_TOKEN` is a **GitHub fine-grained PAT** scoped to
`contents:write` on `peterhanily/maccrab-site` (the source repo for the
Cloudflare-Pages-served `maccrab.com`). It is used by:

- `scripts/publish-appcast-entry.sh` — GET then PUT `appcast.xml` via
  the GitHub Contents API.
- `scripts/publish-release-json.sh` — GET then PUT `release.json`.
- (forthcoming) the rave catalog publish, which writes `catalog.json` /
  `catalog.json.sig` under `maccrab-site/rave/`.

Cloudflare Pages auto-deploys the site repo on push (typically 30-60s),
so "publish" = a GitHub Contents-API commit authenticated by this token.
The token lives in `~/.maccrab-release-env` (chmod 600, gitignored) and,
when absent there, `release.sh` falls back to the login-Keychain git
credential (`git credential fill`).

**Loss impact:** an attacker with this token can rewrite `appcast.xml`
to advertise a malicious DMG (still gated by the Sparkle EdDSA signature)
or tamper with the rave catalog (still gated by the catalog Ed25519
signature). It is a real exposure — store it only on the build Mac.

---

## Step 0 — generate the new token (DO THIS FIRST, well before 2026-06-30)

1. GitHub → Settings → Developer settings → Fine-grained tokens → Generate.
2. Resource owner: `peterhanily`. Repository access: **only**
   `peterhanily/maccrab-site`.
3. Permissions: **Repository → Contents → Read and write**. Nothing else.
4. Expiration: set the NEXT expiry and **record it at the top of this
   runbook** so the future operator gets the same warning you did. Prefer
   a calendar reminder 2 weeks before expiry.
5. Copy the token value once (GitHub shows it only at creation).

## Step 1 — PUBLISH DRY-RUN (read-only, prove the new token works BEFORE switching)

Do NOT replace the live token until the new one is proven to
authenticate AND have write scope on the site repo. The dry-run is a
read-only Contents-API GET — it exercises the exact auth path the
publish scripts use, without writing anything.

```bash
NEW_TOKEN='github_pat_...'          # the just-generated token
SITE_REPO='peterhanily/maccrab-site'

# 1. Auth + read access to appcast.xml (publish-appcast-entry.sh GET path):
curl -sS -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $NEW_TOKEN" \
  "https://api.github.com/repos/${SITE_REPO}/contents/appcast.xml"
#   EXPECT: 200. A 401 = bad token; 404 = wrong repo/path; 403 = scope.

# 2. Confirm the token's recorded scope includes contents:write.
#    Fine-grained PATs expose their permissions via this endpoint:
curl -sS -H "Authorization: Bearer $NEW_TOKEN" \
  "https://api.github.com/repos/${SITE_REPO}" \
  | python3 -c 'import sys,json; d=json.load(sys.stdin); print("push:", d.get("permissions",{}).get("push"))'
#   EXPECT: push: True   (contents:write maps to push on the repo object)

# 3. Confirm read access to release.json + the rave catalog dir
#    (so the catalog publish path won't 404 after cutover):
for p in release.json rave/catalog.json rave/keys/catalog.pub; do
  code=$(curl -sS -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer $NEW_TOKEN" \
    "https://api.github.com/repos/${SITE_REPO}/contents/${p}")
  echo "$p -> $code"      # 200 if present, 404 if not yet created (ok for catalog files)
done
```

All three must pass (200 / push:True / sane codes) before you proceed.
If any fail, the new token is misconfigured — fix the PAT, DO NOT switch.

> **Why a dry-run gate exists at all.** The historical failure mode is a
> token that silently expired or had the wrong scope, surfacing only as
> a 401 at minute ~12 of a release after notarization burned. `release.sh`
> Step 0a already hard-fails on a *missing* token; this dry-run extends
> that to a *present-but-broken* token, and crucially does it BEFORE the
> rave catalog starts depending on the token for availability.

## Step 2 — swap the token in

1. Edit `~/.maccrab-release-env`:
   ```bash
   # was: export SITE_REPO_TOKEN="<old>"
   export SITE_REPO_TOKEN="<new>"
   ```
   Keep `chmod 600`. Do not commit. Do not place in any cloud-sync path.
2. If the token is also stored as a login-Keychain git credential (the
   `release.sh` fallback), update or remove the stale entry so the
   fallback doesn't resurrect the old token.

## Step 3 — end-to-end verification (one real, reversible publish)

Prove the new token can actually WRITE, with a no-op-ish change:

1. Run a release publish (or just the release.json publish, which is
   idempotent and easy to re-run):
   ```bash
   SITE_REPO_TOKEN="$SITE_REPO_TOKEN" scripts/publish-release-json.sh
   ```
2. Confirm the commit landed and Cloudflare redeployed:
   ```bash
   curl -s https://maccrab.com/release.json | python3 -m json.tool | head
   ```
3. For appcast, the safest live check is the next real release; the
   script's idempotency guard refuses to double-publish a version.

## Step 4 — revoke the old token

Only after Step 3 confirms the new token writes successfully:

1. GitHub → Fine-grained tokens → delete the OLD `maccrab-rave-cf-token`.
2. Confirm a publish still works (it now must be using the new token).
3. Update this runbook's deadline banner with the new expiry date.

---

## If the token already expired (you missed 2026-06-30)

Symptoms: `release.sh` Step 0a passes (token present) but step 6 publish
returns 401, OR the dry-run GET returns 401. Recovery:

1. Generate a new token (Step 0) — the expiry doesn't block creating a
   replacement.
2. Run the PUBLISH DRY-RUN (Step 1) to confirm the replacement.
3. Swap it in (Step 2), then republish the lagging artifacts:
   ```bash
   scripts/publish-release-json.sh
   scripts/publish-appcast-entry.sh --item <(scripts/generate-appcast-entry.sh \
       --dmg .build/MacCrab-v<ver>.dmg --version <ver>)
   ```
   Existing users re-poll the appcast within 24h and catch up.

## Post-rotation checklist

- [ ] Dry-run GET on `appcast.xml` returned 200 with the NEW token.
- [ ] Repo `permissions.push == true` for the NEW token (contents:write).
- [ ] `~/.maccrab-release-env` updated; still chmod 600, still gitignored.
- [ ] Stale Keychain git-credential fallback cleared/updated.
- [ ] One real publish (release.json) landed + Cloudflare redeployed.
- [ ] OLD token revoked on GitHub.
- [ ] Deadline banner at the top of THIS file updated to the new expiry.
- [ ] Calendar reminder set ~2 weeks before the new expiry.

## Related

- `scripts/publish-appcast-entry.sh`, `scripts/publish-release-json.sh`
  — the token consumers.
- `scripts/release.sh` Step 0a — missing-token hard fail + Keychain
  fallback.
- `RELEASE_PROCESS.md` — secret inventory (`SITE_REPO_TOKEN` row).
- `docs/runbooks/rave-catalog-key-rotation.md` — the catalog whose
  publish availability depends on this token after cutover.
