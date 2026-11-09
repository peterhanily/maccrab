# Release Rollback Runbook

Operator steps for pulling a bad MacCrab release back after it has been
published. Companion to `CI-ARCHITECTURE.md` (the build/release pipeline) and
`RULE_CHANNEL.md` (the separate signed rule-update channel — this doc is about
the **app** release, not rules).

A publication that stopped after its tag push, with no GitHub release, appcast,
`release.json` or cask published (v1.22.2's failed branch push), is not a
rollback. Keep the tag and finish it with `scripts/release.sh <version>
--resume-publish`; see "Stranded publication" in `RELEASE_PROCESS.md`.

## Reality check first

Sparkle **cannot auto-downgrade** a client that already installed the bad
build — there is no "push the old version back down" button. Rollback is
therefore two things:

1. **Stop the bleeding** — halt further distribution so no *new* client picks
   up the bad version.
2. **Forward-fix** — cut the next version with the fix and ship it (use
   `--immediate` so it skips the phased rollout and every install is offered
   it at its next scheduled check; see below).

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
catch it, so halting distribution actually limits the blast radius. Sparkle
puts each Mac in one of 7 groups at random; with the default 86400-second
interval, group g becomes eligible g days after the item's `pubDate`, and the
offer then arrives at that Mac's next daily check. Phasing applies only to
scheduled checks: *Check for Updates…* offers the newest item at once. Installs
older than 1.22.0 are the exception: every item the release generator writes
is critical for them (`CRITICAL_UPDATE_FLOOR` in `scripts/_appcast_xml.py`), so
Sparkle offers it to them at their next scheduled check without waiting for a
phase.

## The three surfaces that advertise a release

A published release is announced in three independent places. Decide whether
the action is a Sparkle-only pause or a wider withdrawal, and record which
channels remain available. Each is served differently:

| Surface | What it drives | Where it lives |
| --- | --- | --- |
| `appcast.xml` | Sparkle in-app auto-update | `maccrab-site` repo → `https://maccrab.com/appcast.xml` |
| `release.json` | Homepage `data-release` elements: version text, rule and built-in counts, release-notes and DMG links | `maccrab-site` repo → `https://maccrab.com/release.json` |
| GitHub release + Homebrew cask | Direct download + `brew install` | `peterhanily/maccrab` release assets + `peterhanily/homebrew-maccrab` tap |

Use configured Git/GitHub authentication for checkout edits. Publisher scripts
use the protected release environment (`SITE_REPO_TOKEN` for the site and
`TAP_REPO_TOKEN` for the tap). Never put credential values in command arguments,
remote URLs, shell history or trace output, and never source the private
environment file as shell code.

## Step 1 — Halt the Sparkle rollout and revert release.json (one site commit)

Remove the bad `<item>` from the site repo's `appcast.xml`. With the bad item
gone, the previous good version's retained `<item>` becomes the newest offer.
Clients already on the bad build are not downgraded. Restore the previous good
`release.json` in the **same commit**: the site deploys each commit separately
and builds can finish out of order, so two commits seconds apart can leave the
older tree live (v1.22.1's `release.json` served the previous build for six
days that way).

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
# Restore the previous good release.json from the app repo's release tag.
# Write a temporary file first: a failed `git show` must not leave an empty
# release.json to be committed with the appcast change.
git -C <APP_CHECKOUT> show "v<GOOD_VERSION>:release.json" > release.json.new
python3 -c 'import json; print(json.load(open("release.json.new"))["version"])'
# expect: <GOOD_VERSION>
mv release.json.new release.json
git diff -- appcast.xml release.json
git add -- appcast.xml release.json
git commit -m "Roll back v<BAD_VERSION>: pull the appcast item and restore release.json"
git push origin HEAD:main
# Cloudflare Workers Builds redeploys in ~30–60s.
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

## Step 2 — Verify release.json (website version)

`release.json` drives only the homepage elements marked `data-release` (version
text, rule and built-in counts, release-notes and DMG links), which the page
rewrites from it after loading. Step 1 restored it together with the appcast.
Only if it could not be included there, publish it separately as below, then
re-check **both** live files once every deploy has finished, because the
separate commit reintroduces the race:

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

The homepage's JSON-LD, its no-JavaScript fallback text and links,
`sitemap.xml`, the release-evidence panel and the `/release/<version>/` records
are static files that `release.json` does not change. Once every deploy above
has finished, run `bump.sh` in a clean, freshly fetched `maccrab-site` checkout
to bring the JSON-LD, the fallbacks and `sitemap.xml` back in line with the
restored `release.json`, then commit and push the result to `main` as its own
commit:

```bash
bash scripts/bump.sh --write   # JSON-LD, fallback text and links, sitemap, manifest
git diff
```

`bump.sh` lists the prose it does not edit; fix that by hand. It does not touch
the release-evidence panel or the records: point the panel back at the previous
good release's record, and withdraw or relabel any `/release/<BAD_VERSION>/`
record.

## Step 3 — Address GitHub discovery and the Homebrew cask

The GitHub release asset and the cask serve `brew install` and direct
downloads; neither goes through Sparkle. Preserve the failed release asset by
default. Marking a release as a prerelease and not-latest removes its latest
designation; **it does not revoke existing direct download URLs**. Record that
remaining exposure. Asset removal requires a separate withdrawal decision after
preserving its exact bytes and evidence.

Reverting the cask downgrades Homebrew installs. The cask has no
`auto_updates` stanza, and Homebrew treats a cask as outdated whenever the
installed version differs from the tap's, with no downgrade guard: the next
routine `brew upgrade` installs v<GOOD_VERSION> over a Homebrew-managed copy of
v<BAD_VERSION>, and the older app then activates its older engine on the stores
v<BAD_VERSION> wrote. Before reverting, establish that v<BAD_VERSION> added no
schema migration (the forward-only `Migration` steps keyed on
`PRAGMA user_version` in each store) and no other storage-format change. If it
did, or you cannot establish this, leave the cask on v<BAD_VERSION> and
forward-fix (Step 4).

```bash
# Remove the bad build from latest-release discovery; direct URLs remain live:
gh release edit "v<BAD_VERSION>" --prerelease --latest=false

# Only after the storage check above: revert both cask copies and push:
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
hash; changing the app repository alone is insufficient.

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
