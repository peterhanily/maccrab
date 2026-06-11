# CI Architecture

How MacCrab's continuous integration and release build pipeline is
structured, why it is split the way it is, and what each piece is
trusted (or not trusted) to do.

Companion docs: `RELEASE_PROCESS.md` (the end-to-end signing/notarize
pipeline), `RELEASE_CHECKLIST.md` (pre-flight gates), and the rotation
runbooks under `docs/runbooks/`.

## Design principle: signing stays on the trusted Mac

MacCrab is a security tool. Its two catastrophic-if-leaked secrets —
the **Sparkle EdDSA private key** (auto-update trust, no rotation path)
and the **Developer ID Application certificate** (code-signing trust) —
plus the Apple **notary credentials** live ONLY in the build Mac's login
Keychain and never leave it (`RELEASE_PROCESS.md` "Inventory of
secrets"). The decision for the v1.18/v1.19 pipeline is **self-hosted /
hybrid CI**: those secrets stay on the trusted Mac; everything that does
NOT need them runs on disposable GitHub-hosted runners.

Consequence: **no GitHub-hosted runner ever signs, notarizes, or
publishes a release.** A hosted runner that held the Developer ID cert or
the Sparkle key would widen the blast radius to "anyone who can compromise
a hosted runner or a tagged third-party action." So we don't.

## The two halves

```
                         ┌──────────────────────────────────────────┐
   PR / push             │  GitHub-hosted runners (untrusted, fresh) │
   ─────────────────────▶│  .github/workflows/ci.yml                 │
                         │    build-and-test  (REQUIRED)             │
                         │    rules           (REQUIRED)             │
                         │    audit           (ADVISORY)             │
                         └──────────────────────────────────────────┘

                         ┌──────────────────────────────────────────┐
   tag v* / dispatch     │  Self-hosted runner = the trusted Mac     │
   ─────────────────────▶│  .github/workflows/reproducible-build.yml │
                         │    unsigned-build  (ADVISORY)             │
                         │      → build-release.sh unsigned-build    │
                         │      → SLSA v1 provenance (Build L2)       │
                         └──────────────────────────────────────────┘
                                          │
                                          │ operator runs LOCALLY (never in CI):
                                          ▼
                         build-release.sh sign  →  publish   (or release.sh)
                         codesign + notarize + appcast + cask + tag
```

### Half 1 — application CI (GitHub-hosted) — `ci.yml`

Proves the source compiles and is green on a clean machine. Runs on
`push`/`pull_request` to `main` and `v*` branches, and on demand.

| Job | Criticality | What it does |
|---|---|---|
| `build-and-test` | **REQUIRED** | `swift package resolve` + `swift build` + `swift build --build-tests` + `swift test`. Selects Xcode 26.x first (PASS-K pin). |
| `rules` | **REQUIRED** | `compile_rules.py` with 0-skips enforced + `rule-lint.sh`. |
| `audit` | ADVISORY | `pre-release-audit.sh` (architectural invariants + PASS-L Xcode-27 source-compat guards). `continue-on-error: true`. |

Why `audit` is advisory, not required: it bundles release-time gates
(e.g. PASS-L Xcode-27 hazards, some `// bounded:` allowlist warnings)
that are meaningful at release but should not block an in-progress PR.
It still runs on every PR so regressions are visible in the checks UI.

**Toolchain pin reconciliation (PASS-K / PASS-L).** Releases are pinned
to **Xcode 26.x** until the macOS 27 design-QA gate passes (the 27 SDK
ignores `UIDesignRequiresCompatibility` and carries the TN3211 `@State`
and Swift Charts hazards). `ci.yml`'s `build-and-test` selects Xcode 26.x
explicitly and **fails loud if no Xcode 26 is present** on the runner —
it will not silently build on 27. `pre-release-audit.sh` PASS-K enforces
the same pin at release time; PASS-L statically guards the two Xcode-27
source patterns so the eventual SDK bump can't ship either regression.

### Half 2 — reproducible build + provenance (self-hosted) — `reproducible-build.yml`

Runs on `tag v*` and on demand, on a self-hosted runner = the trusted
build Mac (labels `[self-hosted, macOS, maccrab-release]`).

| Job | Criticality | What it does |
|---|---|---|
| `unsigned-build` | ADVISORY | Verifies the Xcode 26.x pin, `swift package resolve`, then `build-release.sh unsigned-build` (compile both arches + lipo + compile rules + manifest). Uploads the unsigned artifacts and emits a **signed SLSA v1 provenance** attestation over the four compiled binaries. |

It is **advisory** because it is a provenance PRODUCER, not a merge gate:
a failure means the next release's provenance needs attention, not that
a PR is bad.

It runs the **`unsigned-build` stage ONLY** of the composable
`build-release.sh` (S5-T6). The `sign` and `publish` stages — which need
the Developer ID cert + notary creds — are run by the operator on the
Mac afterward (or the whole `release.sh` flow is run locally). The same
script, the same stages, just split by trust boundary.

## SLSA provenance — what level, and the honest caveat

Target: **SLSA Build Level 2** — provenance exists, is authenticated,
and is produced by a build process distinct from the artifact author.
`actions/attest-build-provenance` produces a Sigstore-signed in-toto
SLSA v1 provenance statement, recorded in the public Rekor transparency
log, bound to the artifact digests.

**Caveat (do not over-claim):** the build runs on a **self-hosted**
runner, so the "hosted/isolated, ephemeral build service" property that
SLSA Build **L3** requires is **NOT** claimed. The runner is
operator-managed. To keep the L2 claim honest, the self-hosted runner is
hardened:

- dedicated to MacCrab release builds (those labels only; not a shared
  general-purpose self-hosted pool);
- the runner work directory is treated as ephemeral (clean checkout each
  run; `fetch-depth: 0` only for `git describe`);
- it has no inbound path to the signing secrets during the
  `unsigned-build` stage (that stage never references a signing identity);
- the actual signing happens in a SEPARATE, operator-initiated local
  step, so a CI-runner compromise cannot reach the Developer ID cert or
  Sparkle key.

The provenance subject is the UNSIGNED artifact. The operator then signs
those exact binaries locally and records the final signed-DMG sha256 in
`release.json` (`build-release.sh publish`), which is cross-checked
against the Cask + GitHub release asset (`release.sh` Step 6c).

## Action pinning (S5-T4)

Every `uses:` in every workflow is pinned to a **full commit SHA** with a
trailing `# vX.Y.Z` comment for human review:

| Action | Pin | Purpose |
|---|---|---|
| `actions/checkout` | `df4cb1c…` (v6.0.3) | source checkout |
| `actions/setup-python` | `e797f83…` (v6.0.0) | PyYAML for rule compile |
| `actions/upload-artifact` | `043fb46…` (v7.0.1) | unsigned artifact upload |
| `actions/attest-build-provenance` | `a2bbfa2…` (v4.1.0) | SLSA provenance |

A moving tag (`@v6`) is a supply-chain hole: the tag owner can repoint it
to malicious code that then runs with whatever permissions the job has.
Refresh a pin deliberately — resolve the new release tag to its commit
SHA, keep the `# vX.Y.Z` comment, and review the diff.

`pre-release-audit.sh` **PASS J** detects orphan GitHub Actions secrets
(stored but referenced by no workflow). Neither workflow references any
`secrets.*` (signing is local), so there is no secret to orphan; PASS J
stays clean.

## Local mirror

`scripts/ci-local.sh` runs the same build / test / rule / quality checks
locally without GitHub. It predates these workflows and remains the
fastest pre-push gate. The hosted `ci.yml` is the authoritative,
clean-machine version of the same checks.

## What lives where (trust map)

| Capability | Location | Reachable by hosted CI? |
|---|---|---|
| `swift build` / `swift test` | hosted + self-hosted | yes (no secret) |
| rule compile / lint | hosted | yes (no secret) |
| unsigned universal build | self-hosted Mac | runs there, no signing secret |
| SLSA provenance signing (Sigstore OIDC) | hosted-side of self-hosted job | yes — OIDC, not a long-lived secret |
| Developer ID code-sign | **local Mac only** | **no** |
| Apple notarization creds | **local Mac only** | **no** |
| Sparkle EdDSA private key | **local Mac only** | **no** |
| `SITE_REPO_TOKEN` (appcast/catalog publish) | local Mac `~/.maccrab-release-env` | **no** |
| rave catalog Ed25519 private key | **air-gapped, local** | **no** |

## Related

- `RELEASE_PROCESS.md` — the full local signing/notarize/publish flow.
- `RELEASE_CHECKLIST.md` — pre-flight gates, incl. toolchain pin.
- `docs/runbooks/sparkle-key-rotation.md`
- `docs/runbooks/rave-catalog-key-rotation.md`
- `docs/runbooks/cloudflare-token-rotation.md`
