# Release Process

This document describes the end-to-end signing, notarization, and
distribution pipeline for MacCrab releases. It is the operator-side
companion to `docs/TRUST.md` (which covers end-user verification),
`docs/CI-ARCHITECTURE.md` (which covers the local-only CI trust boundary), and
`SECURITY.md` (which covers the vulnerability-disclosure path).

Required reading for anyone who plans to cut a release tag.

Key and token rotation (Sparkle EdDSA, rave catalog Ed25519, the site publish
token) is handled by the release operator following internal runbooks kept
outside this public repo.

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

The signing identities/private keys live in the operator's macOS Keychain;
short-lived account credentials and publisher tokens are stored as mode-0600
data on the build machine. None are committed or copied into build outputs.

| Secret | Used by | Loss impact |
|---|---|---|
| Developer ID Application certificate (Peter Hanily, team `79S425CW99`) | `codesign` during build, `notarytool` for Apple submission | Until revoked: attacker can sign any Mach-O as MacCrab. Apple revocation is the only mitigation. |
| App-specific password for the Apple ID associated with team `79S425CW99` | `notarytool submit --password ...` | Attacker can submit other binaries for notarization under this team. Limited blast radius — revoke at appleid.apple.com. |
| Sparkle EdDSA private key (matching `SUPublicEDKey` baked into shipped Info.plist) | `sign_update` during appcast entry generation | **Catastrophic.** Existing v1.x Sparkle clients verify against the embedded public key. If the private key leaks, an attacker can sign a malicious appcast XML and `MacCrab.app` will auto-update to a malicious DMG. **No rotation path** without shipping a new bundle (and convincing every existing user to install it manually). |
| GitHub fine-grained PAT (`SITE_REPO_TOKEN`), scoped to `contents:write` on `peterhanily/maccrab-site` | `publish-appcast-entry.sh` to commit the appcast entry | Attacker with this token can modify `appcast.xml` to advertise a malicious DMG. Mitigated because the DMG itself still needs a valid EdDSA signature (above), but combined with that key it's a complete supply-chain compromise. |

The non-Keychain values are stored in `~/.maccrab-release-env`, which is
gitignored, owned by the release user, `chmod 600`, and excluded from sync.
Release scripts never source or evaluate it as shell code. An allowlisted parser
opens it without following symlinks and exposes disjoint `signing` and
`publisher` projections. Conventional secret names are removed before local CI,
SwiftPM, rule compilation, unsigned assembly, and documentation generation;
each fixed signing or publishing child receives only the values it needs.

## End-to-end release pipeline

`scripts/release.sh <version>` orchestrates all of the below as a two-phase
operation on the build/reference Mac (Apple Silicon, macOS 14+). The first
invocation builds and preserves one exact candidate, then exits before any
GitHub or distribution publication. Building the candidate necessarily submits
its signed bytes to Apple's notarization service; it does not move a Git ref or
publish a downloadable artifact. After that DMG passes the installed-host and
containment gates, the second invocation reuses those exact bytes and may
publish.

### Step 0 — preconditions

- v1.22.0 needs a disposable installed upgrade rehearsal with preserved event
  history and a consistent pre-upgrade backup. It has no qualified database
  downgrade target. Also reconcile any legacy temporary PF rules in the shared
  `com.maccrab` anchor before publication: the new dedicated response anchor
  deliberately cannot erase potentially unrelated legacy rules. See
  `KNOWN_LIMITS.md` and `PREVENTION_RESEARCH.md` for the boundaries.
- `gh` installed, authenticated, and authorized to write this repository before
  the qualified second phase. Publisher credentials are deliberately not read
  and no GitHub/distribution mutation is attempted by the first-phase artifact
  build. It still performs the required Apple notarization submission, and the
  existing read-only tag/ancestry check queries `origin`.
- For a GA, `SITE_REPO_TOKEN` set before the qualified second phase. The optional
  `SKIP_APPCAST=1` skips only Sparkle; site `release.json` verification and the
  Homebrew tap remain mandatory because `release.sh` creates a public release.
  For an internal/local artifact, use `scripts/build-release.sh` and do not run
  the publisher.
- `scripts/prerelease-check.sh <version>` — manifest equality:
  `Xcode/project.yml` CFBundleVersion + CFBundleShortVersionString
  match across both targets; both Info.plists match project.yml;
  `Casks/maccrab.rb` + `homebrew/maccrab.rb` agree on version;
  README badge points at the version; `CHANGELOG.md` has a
  `## [<version>] — <date>` entry; `RELEASE_NOTES/v<version>.md`
  exists; Sparkle public key + appcast URL identical across
  project.yml and Info.plist; team ID consistent in Casks; rules
  compile cleanly with 0 skips; `Package.resolved` is committed.
- `scripts/pre-release-audit.sh` — a suite of architectural-invariant
  passes covering AlertSink-bypass regressions, schema-migrator
  call sites, encryption pairings, env-block accessor confinement,
  unbounded-actor-collection bounds. Failure here blocks ship.
- The worktree, index, and untracked-file set must be empty. `release.sh`, the
  tag hook, and release-mode CI reject `assume-unchanged` (`h`) and
  `skip-worktree` (`S`) index entries, force an index refresh, and compare both
  the worktree and index to the bound commit. Every critical release executor
  is then hashed directly against its committed blob, without clean/smudge
  filters. The three shipped entitlement manifests under `Xcode/Resources/`
  must be tracked and identical to `HEAD`; a source tag must describe every
  capability granted to shipped code.
- `/usr/bin/git`, the signing/notarisation tools, and the fixed
  `/opt/homebrew/bin/gh` publisher are invoked through pinned absolute paths
  under a system-only `PATH`. `origin` must be exactly the canonical
  `peterhanily/maccrab` SSH or HTTPS URL; `GH_REPO`/`GH_HOST` are cleared and
  every GitHub operation is explicitly bound to `peterhanily/maccrab` on
  `github.com`.
- `scripts/candidate-qualification.py` passes at the non-bypassable publication
  boundary. It verifies the source commit/tree, signed embedded input
  attestation, exact DMG SHA-256/size, Developer ID and Team ID, accepted notary
  submission UUID, staple/Gatekeeper result, complete mounted payload inventory,
  uninterrupted 900-second runtime report, and on-device containment report.
  The candidate manifest also binds the phase-1 `ci-local.sh --clean`
  transcript. The installed-host recorder reuses that receipt and never runs a
  Swift build/test or the process-heavy rule linter inside the daemon process
  epoch being qualified.
  `--skip-prerelease-check`, `--respin`, and `--publish-rc` do not bypass it.

Release candidates are isolated by default. A standalone development-only RC
can still be built with:

```bash
VERSION=1.2.3-rc.1 ALLOW_UNNOTARIZED=1 MACCRAB_BUILD_CHANNEL=dev \
  ./scripts/build-release.sh
```

`release.sh 1.2.3-rc.1` refuses publication unless `--publish-rc` is explicit.
That explicit path creates only a verified GitHub prerelease (`latest=false`);
it does not modify or publish the production appcast, `release.json`, or either
Homebrew cask.

For a publishable RC, run `release.sh 1.2.3-rc.1 --publish-rc`. The first
invocation creates the tracked-object candidate and stops. Install that exact
DMG, enable Agent Traces/the loopback OTLP receiver, configure a working
alert-investigation LLM, keep ordinary browser/terminal/dashboard work active,
and run the printed recorder command (do not hand-edit the incomplete template):

```bash
sudo /usr/bin/python3 -I scripts/candidate-qualification.py record-runtime \
  --candidate-manifest .qualification-evidence/MacCrab-v1.2.3-rc.1.candidate.json \
  --dmg .build/MacCrab-v1.2.3-rc.1.dmg --source-root . \
  --output .qualification-evidence/MacCrab-v1.2.3-rc.1.runtime.json
```

Then run `VERSION=1.2.3-rc.1 make test-corpus` and repeat the release command.
The second invocation validates and publishes the preserved DMG without
rebuilding it. The recorder fails quickly, before the 900-second epoch, if the
installed engine omits any required producer conservation ledger, if TraceStore
is not an enabled full writer, if any cumulative loss/storage failure makes a
zero-loss epoch impossible, or if the LLM is disabled or failed. A configured,
never-used schema-2 LLM may initially be `healthy=false`: before t0 the recorder
runs an exact alert-only prewarm and requires one uniquely identified committed
alert row, valid investigation JSON on that same stable alert ID, accepted
telemetry, full LLM health, and a complete drain. Only then does it establish
the epoch baseline, so prewarm work is excluded from epoch deltas.

During the minute-5 window it runs the source-bound fixed workload, sends one
bounded OTLP span, and generates one harmless high-severity command-line alert
(no network connection). The bulk file/process pressure is confined to a
rule-neutral, per-run `/Users/Shared/MacCrabQualificationRuntime-<run-id>` tree;
a separate small non-networking shell invocation proves sequence journal
continuity. The pressure path is source-checked against stable sequence
filename predicates before use. Both ingress lanes must reach the predeclared
1,274 offered-events/s rate and fully drain through persistence with zero shed,
and the span must advance and drain the TraceStore ledger. The workload must
exit by offset 390 and all queues must drain by offset 450; failure terminates
and reaps the dedicated process group. TraceGraph's additive physical-write
suppression counters are proof-safe rather than loss only when monotonic and
when observations equal attempted plus coalesced plus physically suppressed
plus pending rows at every sample. Both minute-5 suppression deltas must be
positive and, under the current one-row-per-event contract, equal.

The alert trigger runs from a per-run unique copy of `/bin/echo`, so the
one-hour rule/executable alert-deduplication window cannot suppress a retry. A
read-only/no-follow, parameter-bound query of the installed `alerts.db` must
find exactly one new row for that path after the trigger boundary. That same
row must acquire schema-valid investigation JSON while the LLM ledger advances
by one or more starts with `accepted == started`, zero rejected/unattributed
work, and no unfinished operation. Unrelated legitimate investigations may run
concurrently, but cannot substitute for this causal proof. At minute 7.5 the
recorder sends SIGHUP and later requires the installed engine's
log transcript to show a successful non-empty rule reload with no rejection or
error; this is not represented as a live restart test. The recorder rechecks
the exact source commit/tree and clean checkout after the 900-second capture.

If preflight reports historical cumulative loss from an earlier candidate or
an out-of-contract workload, first preserve the failed `.capture.json`, current
heartbeat/status, and relevant logs. Then gracefully deactivate/reactivate
Protection (or install and activate the exact candidate), verify a new engine
PID, wait for retained-store recovery, and retry once with shipping defaults.
That is a clean process epoch, not a clean database. Do not delete stores, run
`make clear-data`, raise caps, disable required features, or apply
`--sqlite-cap` to a shipping family; those actions mask the condition under
test, and deleting files while the installed system extension owns them is
unsafe. A fresh-data run is a separate clean-install lane and cannot turn a
failed retained-state qualification into a publication pass. A storage/backend
fault or any loss that persists or recurs after the documented restart is a
candidate defect: repair it and build a new candidate.

`make test-corpus` is also a recorder, not a success-label writer: it verifies
the full candidate and clean exact checkout before and after execution, runs
the two source-bound adversarial probe builds in a fresh private SwiftPM scratch
path under a fixed sanitized environment,
mounts the exact DMG read-only, and executes the shipped `maccrabctl`, its
statically linked runner/broker, and its signed sibling trampoline against the
shipped example plus the C and Swift probes. It records the candidate binary
hashes/signing identities and complete build/control/sign/run transcripts. A
fixed loopback listener and throwaway file sentinel remain live while the same
freshly built C/Swift binaries first demonstrate every expected `leak.*`
operation unsandboxed. PASS then requires those exact bytes to run through the
candidate sandboxed lane with one expected broker artifact and zero `leak.*`
artifacts. Its CLI accepts no
caller-supplied start/end timestamps. Synthetic Python fixtures use a distinct
capture mode and are rejected by `verify-release`.

### Step 1 — tests

Each `release.sh` phase runs `scripts/ci-local.sh --clean`, including a fresh
dependency resolution, builds, the full test suite, and all 20 local gates. The
first run does this before artifact construction. The qualified second run does
it before publication, and the later tag hook repeats clean CI against the exact
source commit/tree and exact final metadata tree. Release-mode clean CI also
removes `Tools/AssessmentHarness/.build`. Failure blocks ship.

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
Reads 479 Sigma-compatible YAML rules (438 single-event + 41 sequence)
and emits JSON predicates. Graph rules under `Rules/graph/*.json` (7)
ship as-is via `scripts/build-release.sh`, for 486 rules total.
Compiler validates duplicate YAML keys, unmapped Sigma fields, and
boolean-as-value bugs. 0 skips required.

### Step 3 — binary build

`VERSION=<version> scripts/build-release.sh`:

> **Composable stages (v1.19.0 / S5-T6):** `build-release.sh` is now
> decomposed into four ordered stages — `unsigned-build`, `assemble`,
> `sign`, `publish` — each callable individually
> (`scripts/build-release.sh <stage>`). Running it with no argument (or
> `all`) executes all four in one process, byte-for-byte identical to
> the prior linear flow. `release.sh` invokes the four stages explicitly so
> credentials can be introduced only at the fixed signing/notary boundaries. Stage
> separation is still useful for iterating locally — e.g. `unsigned-build`
> + `assemble` + `sign` to produce a signed app without notarising or
> publishing. See `docs/CI-ARCHITECTURE.md`. Single-stage mode persists the staging
> tree at `.build/maccrab-stage` and carries `VERSION` / `BUILD_NUMBER`
> / Sparkle config across invocations so the stamped Info.plist matches
> the signed bundle.

When orchestrated by `release.sh`, all four stages run in a private
`/private/tmp/maccrab-release-build.*` workspace exported directly from the
captured source commit's Git blob objects. The exporter does not consult the
live index, attributes, filters, archive machinery, `.git`, or repository-local
`.swiftpm`; ignored files and live-checkout substitutions cannot become build
inputs. Only the finished DMG and, for a GA, the three generated metadata files
are copied back to the checkout.

> **Toolchain pin:** release builds use **Xcode 26.x** until the
> macOS 27 design-QA gate passes (the 27 SDK ignores
> `UIDesignRequiresCompatibility`, so a 27-SDK build cannot render
> the 26-era design, and Xcode 27 carries the TN3211 `@State` and
> Swift Charts (174168981) source/runtime hazards). Enforced
> mechanically by `pre-release-audit.sh` PASS K; the toolchain used
> is stamped into `release.json` for provenance. Bump the pin
> deliberately, with the design QA done — not as a side effect of
> updating Xcode.

The exact qualification identity is also locked in
`scripts/swift-toolchain.json`: Xcode 26.4.1 (17E202) and Apple Swift 6.3.1
(swiftlang-6.3.1.1.2, clang-2100.0.123.102). CI and the unsigned release stage
verify these complete version/build values before compilation and print a
retained toolchain-evidence log directory. The host Target line is not pinned.
A toolchain upgrade requires a deliberate lock update and a new clean build,
full serial suite, and candidate qualification; the Xcode-major design gate
above still applies. `Testing` comes from that toolchain rather than an
independently resolved source package.

1. `swift build -c release` for ALL release targets (MacCrabCore,
   MacCrabAgentKit, maccrabctl, maccrab-mcp, maccrabd, MacCrabApp,
   MacCrabAgent, and the Tier-B sandbox host `maccrab-tierb-sandbox-host`)
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
   - A blocking `codesign --verify --deep --strict --verbose=2` check must pass;
     diagnostic output is retained and a failed verification aborts the build.
5. `hdiutil create` builds the DMG.
6. `codesign` the DMG.
7. `xcrun notarytool submit ... --wait` blocks until Apple either
   accepts (typically 1-5 minutes) or rejects (failed checks
   surface in `notarytool log`).
8. `xcrun stapler staple` embeds the notarization ticket into the
   DMG so offline machines can verify without phoning Apple.
9. Before code signing, the app receives
   `Contents/Resources/release-input-attestation.txt`, recording the exact
   source commit/tree, `Package.resolved`, dependency-lock and PyYAML-manifest
   hashes, stable provisioning-profile hash/metadata, source and bundled corpus
   hashes, and Xcode/Swift versions. The app signature seals this evidence. For
   a GA only, `release.json` records its hash alongside version, release date,
   rule count, test count, source commit/tree, DMG filename, URL, and sha256. RC
   builds leave production metadata and casks byte-for-byte unchanged.

Output: `.build/MacCrab-v<version>.dmg`, signed + notarized +
stapled.

For `release.sh`, CFBundleVersion is deterministic:
`<numeric-base-version>.<git-commit-count>`. For example, marketing version
`1.22.0-rc.2` at commit count 1121 uses build `1.22.0.1121`. Sparkle ignores
everything after a dash, so putting `-rc.N` in the build would discard the
revision during comparison. Rebuilding the same source commit therefore
reuses its identity instead of creating another system-extension zombie.
RC and GA builds share this numeric sequence. A GA following an RC of the same
base version needs a later descendant source commit; renaming the same commit
does not create a newer build. Publication also checks ancestry and the existing
feed's build ordering. These checks do not attest a particular installed update.
Standalone development builds default to `<numeric-base-version>.<unix-time>` so changed
bytes at the same marketing version still force sysextd to replace the active
extension. CFBundleShortVersionString remains `<version>`.

### Step 4 — homebrew formula bump

For a GA, the DMG's sha256 is sed-bumped into both `Casks/maccrab.rb` (what
the `peterhanily/maccrab` brew tap publishes) and
`homebrew/maccrab.rb` (in-repo documentation copy — kept in
lockstep with the cask because a v1.6.5 → v1.6.13 drift episode
shipped stale formulae for 9 releases). `release.sh` writes only those two files
and `release.json` into a private temporary index seeded from the captured
source tree. It verifies the exact three-path diff and blob identities, creates
an exact one-parent commit with `git commit-tree`, and atomically advances the
branch with `git update-ref`. No repository hook or live-index side effect can
alter that metadata commit. RCs retain the exact source commit/tree.

### Step 5 — GitHub publish

Create an annotated (signed when configured) `v<version>` tag, push that one tag
and then the release branch. `release.sh` refuses to start unless Git is
configured to execute the repository's versioned pre-push hook, and rechecks
that invariant immediately before the tag push. A created/moved version tag is
rejected unless `release.sh` supplies one complete manifest: DMG path + SHA-256,
source commit/tree, final metadata tree, final commit object, annotated tag
object, and committed hook blob. The hook requires either the exact source tree
(RC) or an exact one-parent GA metadata commit whose only changed paths are
`release.json` and the two casks. The peeled tag commit, `HEAD`, committed hook,
executing hook, and every critical executor blob must all match. Through the
configured hook and `release.sh` path, lightweight tags and multi-tag pushes
fail closed. This is a local policy boundary, not server-side enforcement:
manual/API publication or `--no-verify` can bypass a client hook and is outside
the release policy.

The tag hook runs clean local CI from that exact commit. It stages the notarized DMG by a
same-filesystem rename into a private sibling of `.build`. Restoration requires
the exact original manifest/hash and rejects missing or zero-byte files, partial
copies, existing destinations, or `.build` symlink redirection.

After the push, `release.sh` rechecks that the DMG is a non-empty regular file,
re-hashes it, copies those exact bytes into a private random upload snapshot,
requires that snapshot to remain non-empty, and passes only that snapshot to
`gh`. An authenticated HTTP 404 first proves that the version has no existing
GitHub release. Publication begins as a nonce-named **draft** with
`--verify-tag`. The draft is captured by immutable GitHub release ID; every
later digest query and PATCH addresses that exact ID. The named asset digest and
remote tag object are verified before the exact draft is made public.

The publisher issues **no GitHub DELETE requests** and performs no automatic
remote rollback. Partial create, missing/different digest, failed or ambiguous
PATCH, and unexpected remote state all fail closed while retaining whatever
draft or release exists. The error prints the immutable ID, nonce title, known
state, and canonical releases page for manual inspection and recovery.

### Step 6 — downstream distribution and verification

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

   The `<path>` is the same private post-gate upload snapshot used for GitHub,
   not a reopened `.build` file. Its type, non-zero length, and SHA-256 are
   rechecked after GitHub publication, before appcast/downstream publication,
   and at completion; the private tracked-source build workspace remains the
   source of the publisher executors throughout.

2. `scripts/publish-appcast-entry.sh --item <xml> --site-repo
   peterhanily/maccrab-site --version <version>` commits the
   updated `appcast.xml` to the site repo via the GitHub Contents
   API, using `SITE_REPO_TOKEN`. The script refuses to double-
   publish a version already in the appcast (idempotency guard).

3. If appcast publication fails, the generated XML is retained at the printed
   temporary path for an exact manual retry. `SKIP_APPCAST=1` is the only
   intentional Sparkle bypass.

4. `scripts/publish-release-json.sh` publishes the built manifest to the site.
   The release script polls the live `https://maccrab.com/release.json` until
   its version and DMG SHA match the local artifact, then cross-checks that SHA
   against both `Casks/maccrab.rb` and the GitHub release asset digest.

5. `scripts/publish-cask.sh` publishes the validated cask to
   `peterhanily/homebrew-maccrab`.

6. Cloudflare Pages auto-deploys the site repo, typically within
   30-60 seconds.

7. Existing v(N-1) clients with auto-update on poll `appcast.xml`
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
     distinct for a later source revision (`<numeric-base-version>.<commit-count>`),
     sysextd can distinguish the new .systemextension bundle. Verify the running
     engine identity after activation; an OS approval or reboot requirement
     must be resolved before claiming the update completed.

All attempted downstream failures are accumulated so later publishers still
run. Any failure ends with `RELEASE INCOMPLETE` and a non-zero exit; the full
`Released!` banner is printed only when every non-skipped surface succeeded.
The already digest-verified public GitHub release is intentionally not rolled
back after a downstream outage; its immutable ID and URL are printed for repair.

## Continuous integration

MacCrab's build/test/release CI runs **locally**. No GitHub Actions workflow is
installed, so the project does not claim an independent hosted test or
attestation signal. See `docs/CI-ARCHITECTURE.md` for this trust boundary and
its compensating controls.

- **`scripts/ci-local.sh`** — the gate. 20 checks: build, full test suite,
  rule compile + lint, broker fd fuzz (ASan/UBSan), deterministic
  architectural audit, secret/host-path diff scan, assessment-harness
  build/test/isolation, exact-candidate qualification fixtures,
  release-artifact lifecycle regression, and the code-quality passes.
- **`.githooks/pre-push`** — runs it automatically. A **tag** push runs it
  with `--clean`, the exact source commit/tree, final metadata tree/commit, and
  expected DMG SHA (same-filesystem staging,
  `.build` wiped, dependencies re-resolved, manifest-verified restoration), so
  every release is gated on a from-scratch build without risking the sole DMG.
- **`make hooks`** — activates the hook. Required once per clone: git does not
  track `.git/hooks/`, so a fresh checkout has no gate until this is run.
  `release.sh` enforces this precondition and will not build or push otherwise.

**No SLSA provenance is produced.** The workflow that would have emitted it
never completed a single run, so no release from v1.19.3 onward carries an
attestation; the claim has been withdrawn rather than left unbacked. Artifact
integrity rests on notarised Developer-ID signing, the `release.json` SHA-256
cross-checked against the Homebrew cask and formula, and Ed25519-signed rule
manifests. Current builds do carry the signed, embedded release-input evidence
described above, but that local evidence is not an independently signed SLSA
statement. Signing and notarisation have always been local-only and remain so.

With no workflows present, `pre-release-audit.sh` PASS J (orphan GitHub
Actions secret detector) has nothing to scan and stays clean.

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

## Local same-UID threat boundary

These controls defend against accidental drift, stale artifacts, malformed
release invocations, untracked inputs, subprocess secret inheritance, and
remote publication races. They do **not** establish isolation from malicious
code already running as the release operator. A process with the same macOS UID
can rewrite the checkout or hook between checks, read ordinary environment and
mode-0600 files, invoke Keychain-authorized operations, or attach to cooperating
processes. File-owner/mode, path, hash, and Git-object checks are integrity
guards inside that trust boundary—not a sandbox against the owner account.

Cut releases only from a dedicated, quiescent operator account and machine. Do
not run editors, AI tools, package experimentation, browsers, or unrelated
agents concurrently with a release. Stronger resistance requires a separate
ephemeral build identity/host and offline signing or hardware-backed keys.

## Provenance

`release.json` is regenerated on every GA `build-release.sh` run and
committed by `release.sh`; RCs deliberately leave it on the current GA. Inspect any historical GA release's
`release.json` to find:

- Exact version + release date
- Test count at release time
- Rule count at release time
- Exact source commit and tree
- SHA-256 of the signed app's embedded release-input attestation
- SHA-256 of the shipped DMG

Reproducing a historical build requires the matching source tag
(`git checkout v<version>`) plus the same Xcode + macOS version
present on the build Mac at release time.
