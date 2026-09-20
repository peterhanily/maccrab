# Release Rollback Runbook

Operator steps for pulling a bad MacCrab release back after it has been
published. Companion to `CI-ARCHITECTURE.md` (the build/release pipeline) and
`RULE_CHANNEL.md` (the separate signed rule-update channel — this doc is about
the **app** release, not rules).

## Reality check first

Sparkle **cannot auto-downgrade** a client that already installed the bad
build — there is no "push the old version back down" button. Rollback is
therefore two things:

1. **Stop the bleeding** — halt further distribution so no *new* client picks
   up the bad version.
2. **Forward-fix** — cut the next version with the fix and ship it (use
   `--immediate` so it reaches 100% at once; see below).

**Database upgrades are not reversible by reinstalling an older app.**
v1.22 changes the event-store format; there is no qualified downgrade target
for a migrated store. Preserve the complete database families and required key
material with the engine stopped before an upgrade. Any proposed restoration
must use a compatible, consistent predecessor backup and be qualified separately;
do not open migrated history with an older engine or delete history to force it
to start. Prefer a qualified forward fix for affected installations.

Preserve the failed DMG, its hashes, candidate manifests and qualification
evidence before changing distribution. Keep them intact for diagnosis.

Phased rollout (`sparkle:phasedRolloutInterval`, on by default for non-critical
releases — see `scripts/generate-appcast-entry.sh`) is what buys you time here:
a staggered rollout means only a fraction of users have the bad build when you
catch it, so halting distribution actually limits the blast radius.

## The three surfaces that advertise a release

A published release is announced in three independent places. Decide whether
the action is a Sparkle-only pause or a wider withdrawal, and record which
channels remain available. Each is served differently:

| Surface | What it drives | Where it lives |
| --- | --- | --- |
| `appcast.xml` | Sparkle in-app auto-update | `maccrab-site` repo → `https://maccrab.com/appcast.xml` |
| `release.json` | Website version pill + JSON-LD | `maccrab-site` repo → `https://maccrab.com/release.json` |
| GitHub release + Homebrew cask | Direct download + `brew install` | `peterhanily/maccrab` release assets + `peterhanily/homebrew-maccrab` tap |

Use configured Git/GitHub authentication for checkout edits. Publisher scripts
use the protected release environment (`SITE_REPO_TOKEN` for the site and
`TAP_REPO_TOKEN` for the tap). Never put credential values in command arguments,
remote URLs, shell history or trace output, and never source the private
environment file as shell code.

## Step 1 — Halt the Sparkle rollout (appcast.xml)

Remove the bad `<item>` from the site repo's `appcast.xml`. With the bad item
gone, the previous good version's retained `<item>` becomes the newest offer.
Clients already on the bad build are not downgraded.

`publish-appcast-entry.sh` **only inserts** (and refuses to double-publish a
version), so removal is a manual edit of the site repo. Use a clean checkout
based on freshly fetched remote `main`, not a stale local branch:

```bash
# In a clean maccrab-site checkout; stop if status shows existing changes:
git status --short
git fetch origin main
git switch --create "pause-v<BAD_VERSION>" origin/main
# Delete only the item whose sparkle:version matches the bad full build ID.
# Preserve every other item, especially the previous good release.
$EDITOR appcast.xml
git diff -- appcast.xml
git add -- appcast.xml
git commit -m "Roll back appcast: pull v<BAD_VERSION>"
git push origin HEAD:main
# Cloudflare Pages redeploys in ~30–60s.
```

If the push rejects because remote `main` advanced, fetch and reapply the one-item
removal on the new remote state. Do not force-push. Verify the live feed has no
bad build and still contains the previous good item (use full build identities):

```bash
curl -fsS https://maccrab.com/appcast.xml | grep -Fc '<sparkle:version>BAD_BUILD</sparkle:version>'
# expect: 0
curl -fsS https://maccrab.com/appcast.xml | grep -Fc '<sparkle:version>GOOD_BUILD</sparkle:version>'
# expect: 1
```

## Step 2 — Revert release.json (website version)

`release.json` at the repo root is the site's source of truth for the version
pill and JSON-LD. Restore the previous good `release.json` and re-publish so the
website stops advertising the bad build:

```bash
# In a clean maccrab (app) checkout — restore the prior release.json:
git checkout "v<GOOD_VERSION>" -- release.json
# Bash subshell: load only publisher values through the trusted parser.
(
  set +x
  source scripts/release-env.sh
  load_maccrab_env_file publisher "$HOME/.maccrab-release-env" || exit 1
  export SITE_REPO_TOKEN
  scripts/publish-release-json.sh
)
```

Verify:

```bash
curl -s https://maccrab.com/release.json | grep '"version"'
# expect: the GOOD version
```

## Step 3 — Address GitHub discovery and the Homebrew cask

The GitHub release asset and the cask serve `brew install` and direct
downloads; neither goes through Sparkle. Preserve the failed release asset by
default. Marking a release as a prerelease and not-latest removes its latest
designation; **it does not revoke existing direct download URLs**. Record that
remaining exposure. Asset removal requires a separate withdrawal decision after
preserving its exact bytes and evidence.

```bash
# Remove the bad build from latest-release discovery; direct URLs remain live:
gh release edit "v<BAD_VERSION>" --prerelease --latest=false

# Revert both cask copies to the previous good version and push:
git checkout "v<GOOD_VERSION>" -- Casks/maccrab.rb homebrew/maccrab.rb
git commit -am "Roll back cask to v<GOOD_VERSION>"
git push
# Publish the restored cask to the separate tap using protected credentials:
(
  set +x
  source scripts/release-env.sh
  load_maccrab_env_file publisher "$HOME/.maccrab-release-env" || exit 1
  export TAP_REPO_TOKEN
  scripts/publish-cask.sh
)
```

The `peterhanily/maccrab` tap reads `Casks/maccrab.rb` from the separate
`peterhanily/homebrew-maccrab` repository. Verify that live tap's version and
hash; changing the app repository alone is insufficient. Reverting the cask
does not downgrade an already-installed app or its migrated databases.

## Step 4 — Forward-fix (the actual remedy)

Cut and fully qualify the next version with the fix. The release pipeline first
preserves a candidate, then publishes those exact bytes only after installed
qualification. For a security or critical regression, use immediate rollout:

```bash
# Force 100% rollout for the hotfix (omits phasedRolloutInterval):
MACCRAB_APPCAST_IMMEDIATE=1 scripts/release.sh "<NEW_VERSION>"
# or, generating the appcast item by hand:
scripts/generate-appcast-entry.sh --dmg "<dmg>" --version "<NEW_VERSION>" \
  --build-number "<FULL_BUILD_ID>" --immediate
```

Clients already on the bad build pick up the hotfix on their next Sparkle
check; clients that never got the bad build skip straight to the fix.

## Post-rollback consistency check

`release.sh` Step 6c cross-checks that `release.json`, `Casks/maccrab.rb`, and
the GitHub release asset all report the same DMG SHA. After a manual rollback,
re-run that comparison by hand so the three surfaces don't disagree:

```bash
grep -oE '"sha256":\s*"[a-f0-9]{64}"' release.json
grep -oE 'sha256\s+"[a-f0-9]{64}"' Casks/maccrab.rb
gh release view v<GOOD_VERSION> --json assets --jq '.assets[0].digest'
# all three must reference the GOOD build's SHA.
```
