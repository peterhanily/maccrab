# Release Process

This document describes the end-to-end signing, notarization, and
distribution pipeline for MacCrab releases. It is the operator-side
companion to `docs/TRUST.md` (which covers end-user verification),
`docs/CI-ARCHITECTURE.md` (which covers the hosted/self-hosted CI split
and SLSA provenance), and `SECURITY.md` (which covers the
vulnerability-disclosure path).

Required reading for anyone who plans to cut a release tag.

Key-rotation procedures live in `docs/runbooks/`:
- `sparkle-key-rotation.md` — Sparkle EdDSA dual-key transition (bridge release).
- `rave-catalog-key-rotation.md` — air-gapped rave catalog Ed25519 rotation.
- `cloudflare-token-rotation.md` — `SITE_REPO_TOKEN` rotation, **with a hard
  2026-06-30 expiry deadline** and a publish dry-run gate.

## Why this document exists

MacCrab is a security tool. Users who install it are extending the
amount of trust they place in the project beyond just "this binary
runs the code I see in the repo." They also need to trust:

- The Mac that built the release. Both the toolchain (Xcode + macOS
  notary client) and the operator's local environment.
- The Apple Developer ID certificate stored in that Mac's login
  Keychain. If it leaks, an attacker can sign + ship a malicious
  build that all existing Sparkle clients will auto-accept.
- The Sparkle EdDSA private key, also in that Mac's login Keychain.
  Same exposure profile — losing it bricks the auto-update channel
  for every installed v1.x client (no rotation path).
- The site repo (`peterhanily/maccrab-site`) hosting `appcast.xml`.
  An attacker with write access there can advertise a malicious DMG
  to existing Sparkle clients.
- GitHub repo access (push to `main` + tag-create permission).

This document inventories what depends on what, so a future operator
(or a security reviewer) can reason about the trust chain without
reverse-engineering it from `scripts/release.sh`.

## Inventory of secrets

All four live in the operator's macOS login Keychain on the build
machine. None are committed; none are ever copied off the build Mac.

| Secret | Used by | Loss impact |
|---|---|---|
| Developer ID Application certificate (Peter Hanily, team `79S425CW99`) | `codesign` during build, `notarytool` for Apple submission | Until revoked: attacker can sign any Mach-O as MacCrab. Apple revocation is the only mitigation. |
| App-specific password for the Apple ID associated with team `79S425CW99` | `notarytool submit --password ...` | Attacker can submit other binaries for notarization under this team. Limited blast radius — revoke at appleid.apple.com. |
| Sparkle EdDSA private key (matching `SUPublicEDKey` baked into shipped Info.plist) | `sign_update` during appcast entry generation | **Catastrophic.** Existing v1.x Sparkle clients verify against the embedded public key. If the private key leaks, an attacker can sign a malicious appcast XML and `MacCrab.app` will auto-update to a malicious DMG. **No rotation path** without shipping a new bundle (and convincing every existing user to install it manually). |
| GitHub fine-grained PAT (`SITE_REPO_TOKEN`), scoped to `contents:write` on `peterhanily/maccrab-site` | `publish-appcast-entry.sh` to commit the appcast entry | Attacker with this token can modify `appcast.xml` to advertise a malicious DMG. Mitigated because the DMG itself still needs a valid EdDSA signature (above), but combined with that key it's a complete supply-chain compromise. |

These four secrets are stored in `~/.maccrab-release-env`, which is
gitignored and `chmod 600`. The release script sources it on
invocation. The file is not backed up to iCloud or any sync service.

## End-to-end release pipeline

`scripts/release.sh <version>` orchestrates all of the below. Run
on the build Mac (Apple Silicon, macOS 14+).

### Step 0 — preconditions

- `SITE_REPO_TOKEN` set (or `SKIP_APPCAST=1` for internal-only
  releases). Hard-fails before any work if missing — added in
  v1.10.0 after a field-observed silent-fail that left existing
  users on v1.9 because the appcast never published.
- `scripts/prerelease-check.sh <version>` — manifest equality:
  `Xcode/project.yml` CFBundleVersion + CFBundleShortVersionString
  match across both targets; both Info.plists match project.yml;
  `Casks/maccrab.rb` + `homebrew/maccrab.rb` agree on version;
  README badge points at the version; `CHANGELOG.md` has a
  `## [<version>] — <date>` entry; `RELEASE_NOTES/v<version>.md`
  exists; Sparkle public key + appcast URL identical across
  project.yml and Info.plist; team ID consistent in Casks; rules
  compile cleanly with 0 skips; `Package.resolved` is committed.
- `scripts/pre-release-audit.sh` — 15 architectural-invariant
  passes covering AlertSink-bypass regressions, schema-migrator
  call sites, encryption pairings, env-block accessor confinement,
  unbounded-actor-collection bounds. Failure here blocks ship.

### Step 1 — tests

`swift test`. 1490 tests across 284 suites (v1.12.0 baseline). Failure blocks ship.

### Step 1b — false-positive baseline (detection quality gate)

Detection content is code — a rule that regresses into a false-positive storm
ships a real problem. Before a GA, collect a per-rule FP baseline on **≥3 benign
machines** (varied macOS versions / workloads), run for a measurement window
(detection-only), then `make benchmark-fp` on each (see
[BENCHMARK.md](BENCHMARK.md)). Compare per-rule rates to the prior release: any
rule that materially regresses (e.g. >50% higher FP/day) without a root-cause
explanation **blocks the release** or is documented in `CHANGELOG.md` with the
mitigation. After GA, publish the aggregated baseline as `docs/FP_BASELINES_<ver>.md`.
This is the gate that makes "we measured the FP rate" a fact, not a claim.

### Step 2 — rule compilation

`python3 Compiler/compile_rules.py --input-dir Rules/ --output-dir .build/compiled_rules`.
Reads 463 Sigma-compatible YAML rules (424 single-event + 39 sequence)
and emits JSON predicates. Graph rules under `Rules/graph/*.json` (6
in v1.12.0) ship as-is via `scripts/build-release.sh`.
Compiler validates duplicate YAML keys, unmapped Sigma fields, and
boolean-as-value bugs. 0 skips required.

### Step 3 — binary build

`VERSION=<version> scripts/build-release.sh`:

> **Composable stages (v1.19.0 / S5-T6):** `build-release.sh` is now
> decomposed into four ordered stages — `unsigned-build`, `assemble`,
> `sign`, `publish` — each callable individually
> (`scripts/build-release.sh <stage>`). Running it with no argument (or
> `all`) executes all four in one process, byte-for-byte identical to
> the prior linear flow, which is what `release.sh` Step 3 does. The
> self-hosted reproducible-build CI runs the **`unsigned-build` stage
> only** and emits SLSA provenance; the operator then runs `sign` +
> `publish` locally (or the whole `release.sh`). See
> `docs/CI-ARCHITECTURE.md`. Single-stage mode persists the staging
> tree at `.build/maccrab-stage` and carries `VERSION` / `BUILD_NUMBER`
> / Sparkle config across invocations so the stamped Info.plist matches
> the signed bundle.

> **Toolchain pin:** release builds use **Xcode 26.x** until the
> macOS 27 design-QA gate passes (the 27 SDK ignores
> `UIDesignRequiresCompatibility`, so a 27-SDK build cannot render
> the 26-era design, and Xcode 27 carries the TN3211 `@State` and
> Swift Charts (174168981) source/runtime hazards). Enforced
> mechanically by `pre-release-audit.sh` PASS K; the toolchain used
> is stamped into `release.json` for provenance. Bump the pin
> deliberately, with the design QA done — not as a side effect of
> updating Xcode.

1. `swift build -c release` for ALL targets (MacCrabCore,
   maccrabctl, maccrab-mcp, maccrabd, MacCrabApp, MacCrabAgent)
   twice — once each for arm64 and x86_64. Lipo'd into universal
   binaries. (`Xcode/project.yml` is IDE-only; nothing in the
   release pipeline runs `xcodebuild` or `xcodegen`.)
2. `MacCrab.app` is hand-assembled by the script: app binary,
   top-level `*.lproj` (must find exactly 14 — the copy aborts
   otherwise), bundled rule compiler + PyYAML, compiled rules, SPM
   resource bundles, and the system extension bundle staged under
   `MacCrab.app/Contents/Library/SystemExtensions/`.
3. CLIs bundled under `MacCrab.app/Contents/Resources/bin/` so
   Sparkle in-place updates keep the terminal CLI current.
4. `codesign` each Mach-O with the Developer ID Application cert:
   - Hardened runtime
   - Sparkle.framework (Downloader.xpc, Installer.xpc, Autoupdate,
     Updater.app) each signed under the same identity
   - The .systemextension bundle signed with the ES entitlement
   - The outer .app signed with the system-extension.install
     entitlement
5. `hdiutil create` builds the DMG.
6. `codesign` the DMG.
7. `xcrun notarytool submit ... --wait` blocks until Apple either
   accepts (typically 1-5 minutes) or rejects (failed checks
   surface in `notarytool log`).
8. `xcrun stapler staple` embeds the notarization ticket into the
   DMG so offline machines can verify without phoning Apple.
9. `release.json` is written with version, release date, rule
   count, test count, DMG filename, URL, and sha256.

Output: `.build/MacCrab-v<version>.dmg`, signed + notarized +
stapled.

CFBundleVersion (build number) is stamped as `<version>.<unix-time>`
so sysextd reliably recognizes rebuilds of the same marketing
version as distinct binaries and replaces the cached active sysext.
CFBundleShortVersionString stays at the clean `<version>` for
user-visible display. Override with the `BUILD_NUMBER` env var if
the build pipeline needs a specific value (e.g. CI run number).

### Step 4 — homebrew formula bump

The DMG's sha256 is sed-bumped into both `Casks/maccrab.rb` (what
the `peterhanily/maccrab` brew tap publishes) and
`homebrew/maccrab.rb` (in-repo documentation copy — kept in
lockstep with the cask because a v1.6.5 → v1.6.13 drift episode
shipped stale formulae for 9 releases). A `chore: update Homebrew
formula to v<version>` commit lands locally.

### Step 5 — GitHub publish

`git tag v<version>`, `git push origin main --tags`,
`gh release create v<version>` with the DMG attached and notes
auto-generated from `RELEASE_NOTES/v<version>.md`.

### Step 6 — Sparkle appcast publish

The release flow that delivers v<version> to existing v(N-1) users
via Sparkle auto-update:

1. `scripts/generate-appcast-entry.sh --dmg <path> --version <version>`
   produces a `<sparkle:item>` snippet:
   - Reads the DMG bytes.
   - Calls `sign_update <dmg>` (Sparkle's CLI tool) which retrieves
     the EdDSA private key from login Keychain and emits an
     `edSignature="<base64>" length="<bytes>"` line.
   - Wraps it in the appcast item XML with `<pubDate>`, version
     fields, release notes (from RELEASE_NOTES/v<version>.md),
     download URL, and minimum macOS version.

2. `scripts/publish-appcast-entry.sh --item <xml> --site-repo
   peterhanily/maccrab-site --version <version>` commits the
   updated `appcast.xml` to the site repo via the GitHub Contents
   API, using `SITE_REPO_TOKEN`. The script refuses to double-
   publish a version already in the appcast (idempotency guard).

3. Cloudflare Pages auto-deploys the site repo, typically within
   30-60 seconds.

4. Existing v(N-1) clients with auto-update on poll `appcast.xml`
   once per day (`SUScheduledCheckInterval=86400`). On finding a
   newer `<sparkle:version>`, Sparkle:
   - Downloads the DMG.
   - Verifies the `<sparkle:edSignature>` against the public key
     baked into the running app's Info.plist (`SUPublicEDKey`).
     A swapped DMG fails verification and the update aborts BEFORE
     unpacking.
   - Mounts the DMG, replaces `/Applications/MacCrab.app` atomically,
     prompts the user to relaunch.
   - On relaunch, `OSSystemExtensionRequest.activationRequest`
     fires from MacCrabApp's startup. Because CFBundleVersion is
     distinct per build (`<version>.<unix-time>`), sysextd treats
     the new .systemextension bundle as a different version,
     deactivates the old sysext, and activates the new one — no
     user re-approval prompt unless the team-id changed (it never
     should).

## Continuous integration (hosted) + provenance (self-hosted)

Two GitHub Actions workflows back the local flow (full detail in
`docs/CI-ARCHITECTURE.md`):

- **`.github/workflows/ci.yml`** — GitHub-hosted application CI on
  every push / PR. `build-and-test` (swift build + test) and `rules`
  (compile + lint) are **required**; `audit` (pre-release-audit incl.
  PASS-L Xcode-27 guards) is **advisory**. CI selects Xcode 26.x
  explicitly (PASS-K) and fails loud if absent — it never builds on 27.
- **`.github/workflows/reproducible-build.yml`** — self-hosted, on
  `tag v*`. Runs `build-release.sh unsigned-build` ONLY and emits a
  signed SLSA v1 provenance attestation (Build **L2** target; the
  self-hosted runner means the L3 hosted-builder property is not
  claimed). **Signing + notarization never run in CI** — the Developer
  ID cert, notary creds, and Sparkle key stay on the trusted Mac.

Every `uses:` is SHA-pinned with a `# vX.Y.Z` comment; refresh
deliberately. Neither workflow references any `secrets.*` (signing is
local), so `pre-release-audit.sh` PASS J (orphan-secret detector)
stays clean.

## Verifying the chain end-to-end

Before each release, the operator can manually verify the chain by:

```bash
# 1. Confirm the build Mac has the right cert
security find-identity -v -p codesigning | grep "Developer ID Application: Peter Hanily"

# 2. Confirm the EdDSA private key is reachable (sign_update prints
#    the matching public key as a sanity check)
~/Tools/bin/sign_update --print-keys

# 3. Confirm SITE_REPO_TOKEN works
curl -s -H "Authorization: Bearer $SITE_REPO_TOKEN" \
  https://api.github.com/repos/peterhanily/maccrab-site/contents/appcast.xml \
  | jq -r '.size'  # non-empty integer expected

# 4. After release: every user can verify the chain on their side
#    per docs/TRUST.md (shasum, codesign, spctl, stapler validate)
```

## Rollback

If a shipped release turns out to be malicious or catastrophically
broken:

1. **GitHub release** — delete the release at
   `https://github.com/peterhanily/maccrab/releases/tag/v<version>`
   (the tag stays for git history). Existing direct-download links
   break.
2. **Cask** — `git revert` the formula bump commit + push. New
   `brew install` attempts get the previous version's DMG.
3. **Sparkle appcast** — edit `peterhanily/maccrab-site/appcast.xml`
   to remove the `<item>` for the bad version. Existing clients on
   the bad version stay on it until they manually re-install (no
   downgrade mechanism in Sparkle), but new updates from earlier
   versions will land on the prior good release.
4. **Sysext** — clients can manually run
   `sudo systemextensionsctl uninstall 79S425CW99 com.maccrab.agent`
   (requires SIP disabled, see Cask uninstall stanza for the
   automated path). New install of the prior version then
   activates a clean sysext.

There is no over-the-air kill switch. If the EdDSA key is
compromised, the only safe action is to publish a "v<next>.x —
SECURITY: do not use, regenerated signing keys, manually re-install
from GitHub" advisory and accept that auto-update channel is dead
until users reinstall.

## Key custody recommendations

- Login Keychain on the build Mac, with explicit ACLs restricting
  access to the operator's account only.
- The build Mac is not used for general browsing. Email goes through
  a separate account to reduce phishing-on-build-Mac risk.
- `~/.maccrab-release-env` is `chmod 600`, gitignored, and excluded
  from any cloud-sync paths.
- After each release, verify the appcast publish landed (curl the
  live URL). A soft-fail in the publish step can silently leave
  existing users un-updated, so release.sh hard-fails on a missing
  token to prevent that.

## Provenance

`release.json` is regenerated on every `build-release.sh` run and
committed by `release.sh` step 4. Inspect any historical release's
`release.json` to find:

- Exact version + release date
- Test count at release time
- Rule count at release time
- SHA-256 of the shipped DMG

Reproducing a historical build requires the matching source tag
(`git checkout v<version>`) plus the same Xcode + macOS version
present on the build Mac at release time.
