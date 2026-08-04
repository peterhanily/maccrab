# CI Architecture

**MacCrab runs its CI locally. There are no GitHub Actions workflows.**

The gate is `scripts/ci-local.sh`, invoked automatically by the version-controlled
`.githooks/pre-push` hook. Activate it once per clone:

```bash
make hooks      # sets core.hooksPath=.githooks — a fresh clone has NO gate until this runs
make ci         # run the gate by hand
make ci-clean   # same, from a wiped .build (what a tag push runs automatically)
```

## Why local, not GitHub Actions

Three independent reasons, any one of which is sufficient:

1. **The repository is public.** A self-hosted runner would let anyone opening a
   pull request from a fork execute code on the trusted build Mac — the machine
   holding the Developer ID identity, the Sparkle EdDSA key and the rule-channel
   private key. GitHub documents this as a hazard; for a security product it is
   disqualifying.
2. **Hosted runners cannot satisfy the toolchain pin.** Releases build on the
   pinned Xcode major, which the hosted macOS images do not ship. The retired
   `ci.yml` failed on exactly this from 2026-07-18 — an infrastructure mismatch,
   never a code defect, but it left the required check red across two GA releases.
3. **The self-hosted half never ran at all.** `reproducible-build.yml` was
   cancelled at its 24-hour queue timeout on 10 of 10 tag runs, waiting for a
   runner that was never registered.

## Design principle: signing stays on the trusted Mac

Signing, notarisation, Sparkle appcast signing and rule-manifest signing happen
only on the machine holding those identities. Dependency resolution, SwiftPM,
package plugins, rule compilation, tests, and unsigned assembly run only after
conventional signing/publisher variables are removed. Fixed credential-bearing
phases do not invoke SwiftPM or dependency discovery.

## What the gate covers

`scripts/ci-local.sh` — 19 checks, ~150s warm:

| Group | Checks |
|---|---|
| Build | `swift build`, `swift build --build-tests` |
| Tests | full `swift test` suite |
| Rules | YAML→JSON compile, rule-count consistency, rule lint (filter coverage), rule trust-anchor fixtures |
| Required gates | broker fd fuzz (ASan/UBSan), deterministic architectural audit, release-dependency provenance, release supply-chain fixtures, SQLCipher provenance fixtures, secret/host-path diff scan, release-artifact lifecycle regression |
| Assessment harness | builds, tests, and stays out of the shipped build |
| Code quality | no force unwraps in `Sources`, no TODO/FIXME in `Sources` |

This is a **superset** of what the retired hosted workflow gated: the secret scan,
the harness-isolation check and the code-quality passes had no GitHub equivalent.

## The tradeoff, stated plainly

Hosted CI ran on a **clean image**. Local CI runs on a machine that already has
the toolchain, a warm `.build` and resolved dependencies, so it cannot see
environment drift the way a fresh runner could. This project has been bitten by
that class before — a poisoned `/tmp` cache, Xcode integer-literal arithmetic
inside `#expect`, and `runner` colliding with a sanitizer reserved word.

The mitigation is `--clean`, which records the exact DMG name/SHA manifest,
requires every member to be a non-empty regular file, renames each signed
release DMG into a private sibling directory on the **same filesystem**, wipes
`.build`, re-resolves, and restores only after explicit type/symlink,
same-device, destination-absence, and whole-manifest checks. It never uses `mv`'s cross-device copy/delete fallback
and never overwrites an existing restore target.
`.githooks/pre-push` applies this automatically to a release-tag push and binds
the gate to the captured source commit/tree, exact final metadata tree/commit,
annotated tag object, committed/executing hook blob, and pre-tag DMG SHA supplied
by `release.sh`. The hook and release-mode CI reject hidden
`assume-unchanged`/`skip-worktree` index state, force a refresh, compare both
tracked worktree and index, and hash every critical executor directly against
its committed blob before and after CI. `release.sh` refuses to
start—and checks again immediately before the tag push—unless Git's configured,
executable hook is the versioned `.githooks/pre-push` file. Deterministic fixtures
cover resolve failure, zero-byte artifacts, partial staging failure, device
mismatch, staged deletion, `.build` symlink redirection, real-Git `h`/`S`
mutations, wrong source/tree metadata, and extra metadata paths.

`release.sh` also runs `ci-local.sh --clean` before constructing the artifact,
so a later clean tag check is not asked to retroactively prove the signed bytes
came from fresh release outputs. Release-mode CI removes the nested Assessment
Harness build cache. Artifact construction then occurs in a private workspace
exported directly from the captured commit's Git blob objects: it has no `.git`,
repository-local `.swiftpm`, ignored inputs, live index, attributes, archive
filters, or live-checkout bytes. For a GA, a private temporary index seeded from
the exact source tree admits only `release.json` and the two casks; `commit-tree`
creates the exact one-parent metadata commit and `update-ref` advances the branch
atomically. RCs retain the exact source tree.

After the tag gate, `release.sh` requires the restored DMG and private snapshot
to remain non-empty, copies the validated DMG into a private random upload
snapshot, and gives that pathname—not `.build`—to `gh`. That same snapshot is
rehashed through appcast and every downstream publisher. It immediately
creates a nonce-marked draft with `--verify-tag`, captures its immutable release
ID, selects the named asset from that ID, and compares GitHub's recorded SHA-256
with the pre-tag hash. The release flow never issues a GitHub DELETE: failed or
ambiguous create/digest/PATCH state is retained with immutable ID/title/state
and a manual-recovery URL. Only after digest and remote-tag verification is the
exact draft ID published; downstream failure never rolls back that verified
public release.

Release executors are themselves committed inputs. `release.sh`, the hook, and
CI share a drift-tested critical-path list and compare raw worktree hashes to
the bound Git blobs. Git, signing/notarisation tools, and the GitHub CLI use
fixed absolute paths under a system-only `PATH`; the publisher clears ambient
GitHub repo/host overrides, requires the canonical `origin`, and explicitly
addresses `peterhanily/maccrab` on `github.com`. A blocking deep/strict codesign
verification seals an embedded input record containing source commit/tree,
dependency and PyYAML hashes, provisioning-profile hash/metadata, source and
bundled corpus hashes, and Xcode/Swift versions. `release.json` records the hash
of that signed evidence.

An RC is build-only unless `--publish-rc` is explicit. The explicit path creates
only a non-latest GitHub prerelease and leaves production appcast,
`release.json`, and both casks unchanged.

## Local same-UID threat boundary

Git/object/hash/path checks make release drift and races observable, but they do
not sandbox malicious code already running as the release user. The same UID can
read mode-0600 data, rewrite the checkout between checks, and request operations
from Keychain identities authorized to that account. Releases therefore assume
a dedicated, quiescent operator account with no concurrent editor, agent,
package experiment, or unrelated process. A stronger boundary requires a
separate ephemeral build identity/host plus offline or hardware-backed signing.

## Provenance: no SLSA attestation is produced

Earlier revisions of this document claimed SLSA Build Level 2 provenance. **That
claim was never true in practice** — the workflow that would have produced it
never completed a single run, so no release from v1.19.3 through v1.21.5 carries
a signed in-toto/Sigstore statement. The workflow and the claim have both been
removed rather than left standing as unbacked assurance.

What MacCrab *does* provide for artifact integrity:

- **Notarised, Developer-ID-signed** app, system extension and CLI binaries
- **`release.json`** publishing the DMG SHA-256, cross-checked against the
  Homebrew cask and formula, plus the source commit/tree and hash of the signed
  embedded release-input evidence
- **Ed25519-signed rule manifests** with anti-rollback serials, verified against
  a public key pinned in the app bundle
- **Signed plugin catalogue + revocation list** for the Rave store

Re-introducing provenance would require a build host that is *not* the signing
host. That is a change in topology, not a workflow file.

`pre-release-audit.sh` **PASS J** audits stored GitHub Actions secrets against
the workflows that could consume them, and reports the two cases separately:

- **No workflows in the repo** (today's state): any stored Actions secret is
  unusable by construction, so PASS J warns and tells you to delete it. A
  credential nothing can consume is exposure with no compensating benefit. It is
  quiet only when zero Actions secrets are stored — which is the case now.
- **Workflows present**: each stored secret must be referenced by at least one
  of them; the unreferenced ones are reported as orphans.

An earlier version of this paragraph claimed PASS J "has nothing to scan and
stays clean" with no workflows. It did not: an empty reference set made the
per-secret `grep -qx` fail for every secret, so it would have accused all of
them at once. The code now matches this description.

## Trust map

| Asset | Location | Leaves the trusted Mac? |
|---|---|---|
| Developer ID signing identity | trusted Mac keychain | **no** |
| Apple notarisation credentials | trusted Mac keychain | **no** |
| Sparkle EdDSA private key | trusted Mac keychain | **no** |
| Rule-channel private key (`rules.key`) | offline keyholder storage | **no** |
| Rave catalogue Ed25519 private key | air-gapped, local | **no** |
| `SITE_REPO_TOKEN` (appcast/catalog publish) | `~/.maccrab-release-env` | **no** |
| Rule-channel public key (`rules.pub`) | **none trusted or shipped; channel disabled** | n/a — a future owner-approved public anchor may ship only after an offline key ceremony |

## Related

- `scripts/ci-local.sh` — the gate
- `.githooks/pre-push` — how it is enforced (`make hooks` to activate)
- `scripts/pre-release-audit.sh` — the deeper pre-release audit, incl. advisory passes
- `RELEASE_PROCESS.md` — the full local sign / notarise / publish flow
