# MacCrabForensics/TierB

**Status (2026-06-22 — third-party sandboxed lane WIRED LIVE + containment proven
on-device):** untrusted third-party / sideload Tier-B plugins execute through a
deny-default sandbox, routed live from the CLI, the dashboard, and MCP. The lane
is **trust-gated** (not open to runnable contrib until the operator/keyholder
gates below) but it is no longer inert. The old XPC approach is SUPERSEDED.

## Third-party sandboxed lane (LIVE)

Untrusted third-party / sideload Tier-B plugins run ONLY under a deny-default
sandbox applied by the signed **`maccrab-tierb-sandbox-host`** trampoline
(`Sources/maccrab-tierb-sandbox-host/main.c`): it sets rlimits, applies the
manifest-derived `(deny default)` SBPL to itself via `sandbox_init` AFTER startup,
then `execv`s the verified plugin (the Stream-0 spike-validated mechanism —
exec-time `sandbox-exec` deny-default aborts the target; post-startup
`sandbox_init` does not). Cardinal invariant: it NEVER execs without a successful,
deny-default `sandbox_init` (contained-or-nothing).

Two DISJOINT lanes, never crossed:
- first-party (unsandboxed) → `FirstPartyExecutionGate` + `FirstPartyTierBRunner`
- third-party (sandboxed)   → `ThirdPartyExecutionGate` + `SandboxedTierBRunner`
  behind `TierBRegistry.resolveForSandboxedExecution` (sets `isSandboxed`, never
  `isFirstParty`; fail-closed if the sandbox runtime is unavailable).

**Live routing:** `TierBCollectorExecutor.runInstalled` dispatches first-party →
sandboxed, fail-closed, from `maccrabctl plugin run`, the dashboard "Run on this
Mac" (`KitRunner`), and MCP `forensics.run_collector`. (`PluginRunner` still
refuses Tier-B in-process — correct; out-of-process is the only path.)

**The broker is the file boundary (Model B):** file reads are NOT granted in the
SBPL. `SandboxedTierBRunner.run` creates a socketpair, dups the broker end onto
the child's fd 3, and serves `TierBFileBroker` on a dedicated thread (every path
component `O_NOFOLLOW`, single-link regular file only), tearing it down after
reap. TCC-protected sources are snapshotted into a plugin-unwritable dir
(`BrokeredTCC.prepare`) and the broker re-checks TCC on the **served** path, so a
broad ancestor read root can't reach a live store.

**Containment is PROVEN on-device** by `ContainmentCorpusTests` (`make
test-corpus`) against the EXACT shipped runner + broker + trampoline, for both a C
fixture and a Swift fixture (Swift runtime + Foundation): a declared read is
brokered; undeclared file / network / fork+exec / metadata-stat / mach-lookup are
all OS-denied (zero `leak.*` artifacts).

### Remaining gates (operator / keyholder / external — NOT code)

The runnable third-party lane ships **fail-closed** until:
- `FirstPartyTrustRoot.publisherKeyFingerprint` is set (offline keyholder
  ceremony) — until then first-party execution is disabled and the catalog has no
  live entries.
- `make test-corpus` passes against the EXACT signed release build.
- an **independent external pentest** of the lane clears it.

Tracked hardenings (not fail-open): fd-pinned (`fexecve`-style) trampoline spawn
to close the check→spawn TOCTOU; a runtime fetch of a fresh signed revocation
list (today runtime revocation is staleness-driven).

## Files

- `TierBManifest.swift` — signed manifest format + the derived `consentSummary`.
- `SandboxProfileBuilder.swift` — declarative spec → SBPL; `compileDenyDefault`
  (Model B base: named mach services, no global lookup, crown-jewel metadata
  denies) + `compileTrampolineDenyDefault` (adds the self-exec grant).
- `ThirdPartyExecutionGate.swift` / `SandboxedTierBRunner.swift` — the sandboxed
  lane authority + runner.
- `TierBFileBroker.swift` + `CTierBBroker` — the SCM_RIGHTS file broker.
- `BrokeredTCC.swift` — TCC source → snapshot + redirect.
- `TierBCollectorExecutor.swift` — the two-lane live dispatch + kill-switch.
- `PluginSignatureVerifier.swift` / `PluginInstaller.swift` / `TierBRegistry.swift`
  / `TierBBootstrap.swift` / `CryptoSigning.swift` — install / verify / trust.
- `RevocationReverify*.swift` — runtime revocation staleness policy.
- `docs/tier-b-research/` — the research write-up.

## What works today

- `maccrabctl plugin keygen | sign | test` — the contributor SDK; `test` runs a
  plugin CONTAINED and prints its derived consent summary.
- `maccrabctl plugin install [--local] <bundle>` — install / sideload (TOFU
  consent + reserved-namespace refusal).
- `maccrabctl plugin run <id>` — dispatches an installed third-party plugin to the
  **sandboxed lane** (subject to the trust/GA gates above).
- `maccrabctl plugin trust | revoke | trust-list | verify | status` — trust mgmt.
- Dashboard "Run on this Mac" + MCP `forensics.run_collector` — same routing.

## Promotion-condition tracker

| # | Condition | Status |
|---|---|---|
| 1 | Sandbox profile generator emits profiles macOS accepts | ✅ `compileDenyDefault` / `compileTrampolineDenyDefault`; the `sandbox_init` trampoline + `SandboxedTierBRunner` + `ThirdPartyExecutionGate` are LIVE and **corpus-proven on-device** (C + Swift). Re-confirm on the exact signed release build. |
| 2 | Out-of-process IPC contract stable | ✅ TierBIPC stdin/stdout + the SCM_RIGHTS broker on fd 3 (XPC approach SUPERSEDED by the trampoline). |
| 3 | Signing + revocation infrastructure wired | ✅ verifier + installer + maccrabctl + runtime revocation re-verify, validated against the rave catalog. |
| 4 | Plan-level commitment | ✅ platform plan §12 + the third-party marketplace plan. |

**Where we are right now:** the execution mechanism is built, live-routed, and
on-device corpus-proven. What remains is operator/keyholder/external (the
publisher-key ceremony, the release-build corpus run, and the mandatory external
pentest) — see "Remaining gates" above.
