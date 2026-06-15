# v1.19.0 release checklist (operator)

Agent work for v1.19.0 is complete and committed on branch `v1.19.0` (NOT pushed).
This is the operator/keyholder handoff — the steps that need your keychain, Apple
credentials, Cloudflare/GitHub access, or a release decision.

## State going in
- Branch `v1.19.0`, full suite **2348 tests / 430 suites green** at HEAD.
- rc.3 was built/notarized/installed and live-tested (see RELEASE_NOTES/v1.19.0.md).
- Post-rc.3 fixes landed: workerd coordinated-attack FP, plugin provenance,
  CLI rule-count, release.json bump, accurate notes.
- `release.json` is `1.19.0` with placeholder dmg sha/size (zeros) — the publish
  stage finalizes them at build.

## A. App GA (v1.19.0)
1. **Cut rc.4** for a clean retest of the post-rc.3 fixes:
   `VERSION=1.19.0-rc.4 ./scripts/build-release.sh` (keychain clicks for signing +
   Sparkle EdDSA; notarization auto via `~/.maccrab-release-env`). Stays local.
2. **Idle FP soak (still owed)** — the release gate is daily single-event
   <30/day, measured on an *idle* machine (every live test so far ran during an
   active agent session, which can't measure idle noise). Leave rc.4 installed
   on a normally-used-but-not-agent-saturated machine for a multi-hour window and
   confirm the count.
3. **Gate on `scripts/prerelease-check.sh 1.19.0`** before tagging (it asserts
   version/stats/rule-count consistency; the publish stage writes the real dmg
   sha into release.json).
4. **GA build + publish:** `VERSION=1.19.0 ./scripts/build-release.sh` →
   `git tag v1.19.0` → `gh release create v1.19.0 .build/MacCrab-v1.19.0.dmg
   --notes-file RELEASE_NOTES/v1.19.0.md`.
5. **Appcast (EdDSA) — verify end to end on the signing host** before publish; a
   wrong/restored Sparkle key bricks auto-update for every installed user.
6. **Homebrew cask** sha256 is synced by the publish stage; confirm it points at
   the real v1.19.0 DMG (the cask previously pinned 1.19.0 to a not-yet-built DMG).
7. **Push the site** (`maccrab-site` — has staged S7 edits) so release.json/version
   surfaces update.
8. **Merge `v1.19.0` → `main`** and push.

## B. Rave catalog + services go-live (currently RED — not installable)
The server code + security are release-ready (92 tests green, hardened, deployed,
valid TLS). It is NOT a shippable store yet because **nothing is installable** —
all catalog entries ship placeholder hashes and the client correctly refuses.
Full runbook: `maccrab-rave/docs/runbooks/go-live.md` (its launch-flip baseline
was just corrected — commit `dfe36ac`, local, unpushed).

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
