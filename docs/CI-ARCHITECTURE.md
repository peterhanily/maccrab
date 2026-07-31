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

Unchanged, and now unconditional. Signing, notarisation, Sparkle appcast signing
and rule-manifest signing happen only on the machine holding those identities.
Nothing in the build or release path executes third-party-supplied code.

## What the gate covers

`scripts/ci-local.sh` — 13 checks, ~150s warm:

| Group | Checks |
|---|---|
| Build | `swift build`, `swift build --build-tests` |
| Tests | full `swift test` suite |
| Rules | YAML→JSON compile, rule lint (filter coverage) |
| Required gates | broker fd fuzz (ASan/UBSan), deterministic architectural audit, secret/host-path diff scan |
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

The mitigation is `--clean`, which wipes `.build` and re-resolves first.
`.githooks/pre-push` applies it automatically to any **tag** push, so every
release is gated on a from-scratch build even though ordinary pushes are not.
A deliberate trade: fast feedback on commits, strict verification where it counts.

## Provenance: no SLSA attestation is produced

Earlier revisions of this document claimed SLSA Build Level 2 provenance. **That
claim was never true in practice** — the workflow that would have produced it
never completed a single run, so no release from v1.19.3 through v1.21.5 carries
a signed in-toto/Sigstore statement. The workflow and the claim have both been
removed rather than left standing as unbacked assurance.

What MacCrab *does* provide for artifact integrity:

- **Notarised, Developer-ID-signed** app, system extension and CLI binaries
- **`release.json`** publishing the DMG SHA-256, cross-checked against the
  Homebrew cask and formula
- **Ed25519-signed rule manifests** with anti-rollback serials, verified against
  a public key pinned in the app bundle
- **Signed plugin catalogue + revocation list** for the Rave store

Re-introducing provenance would require a build host that is *not* the signing
host. That is a change in topology, not a workflow file.

`pre-release-audit.sh` **PASS J** detects orphan GitHub Actions secrets (stored
but referenced by no workflow). With no workflows present it has nothing to scan
and stays clean; if Actions are ever reintroduced, it resumes meaning.

## Trust map

| Asset | Location | Leaves the trusted Mac? |
|---|---|---|
| Developer ID signing identity | trusted Mac keychain | **no** |
| Apple notarisation credentials | trusted Mac keychain | **no** |
| Sparkle EdDSA private key | trusted Mac keychain | **no** |
| Rule-channel private key (`rules.key`) | offline keyholder storage | **no** |
| Rave catalogue Ed25519 private key | air-gapped, local | **no** |
| `SITE_REPO_TOKEN` (appcast/catalog publish) | `~/.maccrab-release-env` | **no** |
| Rule-channel public key (`rules.pub`) | committed; ships in the app bundle | n/a — public by design |

## Related

- `scripts/ci-local.sh` — the gate
- `.githooks/pre-push` — how it is enforced (`make hooks` to activate)
- `scripts/pre-release-audit.sh` — the deeper pre-release audit, incl. advisory passes
- `RELEASE_PROCESS.md` — the full local sign / notarise / publish flow
