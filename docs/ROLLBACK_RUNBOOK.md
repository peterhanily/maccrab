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

Phased rollout (`sparkle:phasedRolloutInterval`, on by default for non-critical
releases — see `scripts/generate-appcast-entry.sh`) is what buys you time here:
a staggered rollout means only a fraction of users have the bad build when you
catch it, so halting distribution actually limits the blast radius.

## The three surfaces that advertise a release

A published release is announced in three independent places. To fully pull a
release you must revert **all three** — each is served differently:

| Surface | What it drives | Where it lives |
| --- | --- | --- |
| `appcast.xml` | Sparkle in-app auto-update | `maccrab-site` repo → `https://maccrab.com/appcast.xml` |
| `release.json` | Website version pill + JSON-LD | `maccrab-site` repo → `https://maccrab.com/release.json` |
| GitHub release + Homebrew cask | Direct download + `brew install` | `peterhanily/maccrab` release assets + `Casks/maccrab.rb` |

All site-repo edits authenticate with `SITE_REPO_TOKEN` (the same PAT the
publish scripts use — see `scripts/publish-appcast-entry.sh`).

## Step 1 — Halt the Sparkle rollout (appcast.xml)

Remove the bad `<item>` from the site repo's `appcast.xml`. With the bad item
gone, the previous version's `<item>` is once again the newest, so every new
Sparkle check offers the previous good version instead of the bad one.

`publish-appcast-entry.sh` **only inserts** (and refuses to double-publish a
version), so removal is a manual edit of the site repo:

```bash
# In a checkout of the maccrab-site repo, on main:
#   delete the entire <item>…</item> block whose
#   <sparkle:version>BAD_VERSION</sparkle:version> matches, then commit.
$EDITOR appcast.xml
git commit -am "Roll back appcast: pull v<BAD_VERSION>"
git push
# Cloudflare Pages redeploys in ~30–60s.
```

Verify the bad version is gone from the live feed:

```bash
curl -s https://maccrab.com/appcast.xml | grep -c '<sparkle:version>BAD_VERSION</sparkle:version>'
# expect: 0
```

## Step 2 — Revert release.json (website version)

`release.json` at the repo root is the site's source of truth for the version
pill and JSON-LD. Restore the previous good `release.json` and re-publish so the
website stops advertising the bad build:

```bash
# In the maccrab (app) repo — restore the prior release.json:
git checkout v<GOOD_VERSION> -- release.json
SITE_REPO_TOKEN=<pat> scripts/publish-release-json.sh
```

Verify:

```bash
curl -s https://maccrab.com/release.json | grep '"version"'
# expect: the GOOD version
```

## Step 3 — Pull the GitHub release + Homebrew cask (direct + brew)

The GitHub release asset and the cask serve `brew install` and direct
downloads; neither goes through Sparkle, so they must be reverted separately.

```bash
# Make the bad GitHub release un-served (choose one):
gh release edit v<BAD_VERSION> --prerelease      # hide from "latest", or
gh release delete-asset v<BAD_VERSION> MacCrab-v<BAD_VERSION>.dmg   # remove the DMG

# Revert both cask copies to the previous good version and push:
git checkout v<GOOD_VERSION> -- Casks/maccrab.rb homebrew/maccrab.rb
git commit -am "Roll back cask to v<GOOD_VERSION>"
git push
```

`brew` reads `Casks/maccrab.rb` via the `peterhanily/maccrab` tap, so reverting
it makes `brew install`/`upgrade` serve the good version again.

## Step 4 — Forward-fix (the actual remedy)

Cut the next version with the fix. For a security or critical regression, ship
it to everyone immediately rather than phasing:

```bash
# Force 100% rollout for the hotfix (omits phasedRolloutInterval):
MACCRAB_APPCAST_IMMEDIATE=1 scripts/release.sh <NEW_VERSION>
# or, generating the appcast item by hand:
scripts/generate-appcast-entry.sh --dmg <dmg> --version <NEW_VERSION> --immediate
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
