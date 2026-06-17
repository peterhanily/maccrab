# v1.19.0 release checklist (operator)

Agent work for v1.19.0 is complete and committed on branch `v1.19.0` (NOT pushed).
This is the operator/keyholder handoff — the steps that need your keychain, Apple
credentials, Cloudflare/GitHub access, or a release decision.

## State going in (2026-06-17)
- Branch `v1.19.0`, full suite **2408 tests / 437 suites green**, working tree
  clean at HEAD `33a69aa`. 4 commits past the prior RC state (NOT pushed): prod
  fake-data purge (`7e5b6c1`), drop fixture label (`d02323a`), hide pre-release
  catalog entries (`d670922`), release-docs (`33a69aa`).
- **rc.9** (`.build/MacCrab-v1.19.0-rc.9.dmg`, notarized, installed) live-verified:
  the fake-data purge is clean on the installed release binaries, and the plugin
  catalog now shows **"Coming Soon"** (matching the website) instead of demo plugins.
- `scripts/prerelease-check.sh 1.19.0` → **PASSED**; all version strings agree on
  1.19.0; CHANGELOG + RELEASE_NOTES document the new work.
- ⚠️ `Casks/maccrab.rb` + `homebrew/maccrab.rb` sha256 still point at the **v1.18.0**
  DMG — the GA `build-release.sh` publish stage auto-rewrites both to the real
  v1.19.0 DMG (confirm after build). `release.json` dmg sha/size are zero
  placeholders, finalized at publish.

## GA verdict
**Ship v1.19.0 as an App GA now with the rave store in "Coming Soon" — do NOT wait
for the store.** The app is honest pre-launch (catalog → Coming Soon, install
fail-closed, dashboard empty/offline default), the 4 new commits touch no
detection/rule/sequence/campaign/collector code, and the trust-floor infra must
ship first to become the store's `min_maccrab_version`. The two rave containment
gaps (Section B) only matter for opening third-party submissions — not at launch.

## A. App GA (v1.19.0) — operator/keyholder; needs your explicit go-ahead to push
Agent prep is done (docs + `prerelease-check` + full suite green). Every step below
needs your keychain / Apple notary / Sparkle key / GitHub + site push.

1. **GA signed + notarized build:** `VERSION=1.19.0 ./scripts/build-release.sh`
   (keychain clicks for Developer-ID + Sparkle EdDSA; notarization auto via
   `~/.maccrab-release-env`). Codesigns all Mach-Os, signs the sysext with the ES
   entitlement, builds + notarizes + staples the DMG, rewrites `release.json`
   dmg sha/size, and **auto-fixes both casks' sha256** to the GA DMG (closing the
   v1.18.0-pinned-sha gap). Output: `.build/MacCrab-v1.19.0.dmg`.
2. **Idle FP soak — STILL OWED, the one real gate never measured.** Install the GA
   DMG (or rc.9) on a normally-used but NOT agent-saturated Mac for a multi-hour
   window; confirm <30 single-event false alerts/day on an *idle* machine. Every
   prior live test ran during an active agent session, so idle noise is unmeasured.
   The code-side FP fixes (AI-tool + workerd) landed and held up live, so this
   verifies the headline — but treat it as the last gate, not a formality.
3. **Verify the Sparkle EdDSA path end to end** on the signing host before
   publishing the appcast (the generate-appcast-entry guard checks the keychain
   key pairs with the shipped `SUPublicEDKey` and the signature verifies). A
   wrong/regenerated key bricks auto-update for every installed user.
4. **Re-gate:** `scripts/prerelease-check.sh 1.19.0` green at the tag HEAD.
5. **Tag (manual):** `git tag v1.19.0` on branch `v1.19.0` @ HEAD.
6. **GitHub release (manual):** `gh release create v1.19.0
   .build/MacCrab-v1.19.0.dmg --notes-file RELEASE_NOTES/v1.19.0.md`.
7. **Publish appcast + release.json to the site repo:**
   `scripts/generate-appcast-entry.sh --dmg .build/MacCrab-v1.19.0.dmg
   --version 1.19.0 > /tmp/item.xml`, then `SITE_REPO_TOKEN=… \
   scripts/publish-appcast-entry.sh --item /tmp/item.xml --site-repo
   peterhanily/maccrab-site --version 1.19.0`, then `scripts/publish-release-json.sh`.
   Push `maccrab-site` (it has staged S7 edits). Expect Cloudflare edge-cache lag —
   verify with `curl` and allow for TTL.
8. **Merge to main (manual):** `git checkout main && git merge v1.19.0 &&
   git push origin main`, then `git push origin v1.19.0`.

⚠️ **Do NOT use `scripts/release.sh`** — it auto-runs `git tag` + `git push origin
main --tags` + `gh release create` with no confirmation, and pushes `main`'s ref
while the work is on branch `v1.19.0` (wrong ref + violates the no-push gate).
Drive the BUILD with `build-release.sh`, then tag / release / appcast / merge by
hand.

## B. Rave catalog + services go-live (currently RED — not installable)
The server code + security are release-ready (92 tests green, hardened, deployed,
valid TLS). It is NOT a shippable store yet because **nothing is installable** —
all catalog entries ship placeholder hashes and the client correctly refuses.
Full runbook: `maccrab-rave/docs/runbooks/go-live.md` (its launch-flip baseline
was just corrected — commit `dfe36ac`, local, unpushed).

Display is already honest in both surfaces while RED: the website (`site/build.sh`
status:active filter) and the GA app (`V2RaveCatalogBrowserView` active-only filter,
shipped `d670922`) both render **"Coming Soon"** — the 18 `com.maccrab.forensics.*`
`pre-release` entries are intentional machine-catalog drafts (kept to flip `active`
at launch; the `storefront-honesty` tests require `catalog.json` to retain them).
Purging the public `catalog.json` of the drafts is OPTIONAL/deferred (it conflicts
with those Phase-0 tests and needs an offline re-sign); it is NOT needed for GA.

Keyholder/operator gates before flipping any entry to `active`:
1. **Air-gapped re-sign ceremony** with REAL signed plugin binaries + matching
   catalog `artifact_sha256` + a real install-and-verify proof on a clean host
   (the accept/happy-path has never executed on real bytes). Runbook P.
2. **Push the hardened rave HEAD** (`git push origin main` — the FULL chain, per
   the corrected go-live.md; do NOT push the stale `96c76d2`).
3. **Rotate `CLOUDFLARE_API_TOKEN`** — hard deadline ~2026-06-30; on expiry all
   CI deploy/backup paths break.
4. **Branch protection** on `maccrab-rave` (make `rave-test.yml` a required check).
5. **`RAVE_PUBLIC=1`** + CF Pages deploy (`docs/runbooks/go-live.md` flip sequence).
6. Adopt the client trust-floor as `min_maccrab_version` in a **GA** (not RC) app
   release before any entry goes `active`.
