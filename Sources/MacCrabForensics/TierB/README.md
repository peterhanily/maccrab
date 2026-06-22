# MacCrabForensics/TierB

**Status (2026-06-22 update — third-party sandboxed lane, writable core landed INERT):**
the third-party execution mechanism is decided and its writable core is built (still
fail-closed; nothing routes to it). The XPC approach below is SUPERSEDED — see
"Third-party sandboxed lane" near the bottom.

> ## Third-party sandboxed lane (Streams 0–2 core — built, INERT, fail-closed)
>
> Untrusted third-party / sideload Tier-B plugins run ONLY under a deny-default
> sandbox applied by the signed **`maccrab-tierb-sandbox-host`** trampoline
> (`Sources/maccrab-tierb-sandbox-host/main.c`, a separate C executable target):
> it sets rlimits, applies the manifest-derived `(deny default)` SBPL to itself via
> `sandbox_init` AFTER startup, then `execv`s the verified plugin (the Stream-0
> spike-validated mechanism — exec-time `sandbox-exec` deny-default aborts the
> target; post-startup `sandbox_init` does not). Cardinal invariant: it NEVER
> execs without a successful, deny-default `sandbox_init` (contained-or-nothing).
>
> Two DISJOINT lanes, never crossed:
> - first-party (unsandboxed) → `FirstPartyExecutionGate` + `FirstPartyTierBRunner`
> - third-party (sandboxed)   → `ThirdPartyExecutionGate` + `SandboxedTierBRunner`
>   behind `TierBRegistry.resolveForSandboxedExecution` (sets `isSandboxed`, never
>   `isFirstParty`; fail-closed if the sandbox runtime is unavailable).
>
> New/changed files this lane: `ThirdPartyExecutionGate.swift`,
> `SandboxedTierBRunner.swift`, `SandboxProfileBuilder.compileTrampolineDenyDefault`,
> `TierBRegistry.{VerifiedPlugin.isSandboxed, resolveForSandboxedExecution}`,
> `Sources/maccrab-tierb-sandbox-host/main.c`.
>
> DEFERRED (operator/on-device, NOT in this build): the SCM_RIGHTS file broker
> (fd 3 is reserved) + TOCTOU/inode hardening; brokered-TCC scratch snapshots;
> live routing (`PluginRunner` still throws `tierBExecutionUnsupported`); the
> minimal SBPL base for a full Swift plugin + exact rlimits; and the adversarial
> containment corpus AS A CLIENT TEST. See `plans/2026-06-17-thirdparty-marketplace.md`.

**Status (2026-05-25 — SUPERSEDED by the above):** the install + verify + trust + discovery surface is live and exercised by the rave catalog (see launch rehearsal at `peterhanily/maccrab-site:rave-prototypes/launch-rehearsal/hosts-collector/`). The subprocess-spawn path was historically scoped to NSXPCConnection + XPC service bundling on `research/post-v15`; that approach is no longer the plan (App-Sandbox/XPC is ruled out by the no-in-app-re-signing + FDA-host constraints) — the trampoline above replaces it.

Tier B = subprocess-sandboxed plugin runtime. Plan §3.9 + §12. The §12 commitment was made on 2026-05-24 — see `plans/2026-05-19-plugin-platform-plan.md` §12 + the rave plan v4.5 at `~/Documents/claude_code/maccrab-future-planning/2026-05-20-plugin-site-plan.md`.

## Promotion-condition tracker

| # | Condition | Status |
|---|---|---|
| 1 | Sandbox profile generator emits profiles macOS accepts | ⚠ partial — emits SBPL (`SandboxProfileBuilder.swift`, incl. `compileDenyDefault` + `compileTrampolineDenyDefault`). The `sandbox_init` trampoline (`maccrab-tierb-sandbox-host`) + `SandboxedTierBRunner` + `ThirdPartyExecutionGate` are now **built (inert)**. C smoke test (2026-06-22) confirms the mechanism + self-exec allow (execv SUCCEEDS under deny-default, vs pure deny-default which blocks it) and every fail-closed guard. Remaining: minimal SBPL base for a real Swift plugin (a stock `/usr/bin/true` SIGABRTs under the spike base — the macOS-version base-tuning) is **pending the corpus client-test** — see `plans/2026-06-17-thirdparty-marketplace.md`. |
| 2 | XPC service IPC contract stable + reuses MCP JSON-RPC | partial — `XPCPluginLoader.swift` exists; subprocess spawn on `research/post-v15` |
| 3 | Signing CA + revocation infrastructure wired | ✅ `PluginSignatureVerifier.swift` + `PluginInstaller.swift` + maccrabctl integration verified end-to-end against rave catalog |
| 4 | Plan-level commitment via new chapter | ✅ platform plan §12 updated 2026-05-24; rave plan v4.5 published |

**Where we are right now**: condition 4 done; conditions 1 + 3 done; condition 2 partial. v1.16.0-rc.21 ships the install + verify + trust + discovery surface (validated against a real Ed25519-signed plugin from the rave catalog on 2026-05-25). The remaining spawn-path work is on the research/post-v15 branch.

## Files

- `TierBManifest.swift` — flat manifest format consumed by `SandboxProfileBuilder` + `PluginInstaller`.
- `SandboxProfileBuilder.swift` — declarative DSL → SBPL text profile. Used at spawn time once the spawn path lands.
- `XPCPluginLoader.swift` — daemon-side loader (alongside the existing Tier A in-process loader).
- `PluginSignatureVerifier.swift` — Ed25519 verifier. Live in v1.16-rc.21.
- `PluginInstaller.swift` — install/trust/revoke flow. Live in v1.16-rc.21.
- `TierBRegistry.swift` — runtime registry. Live in v1.16-rc.21.
- `TierBBootstrap.swift` — process-startup auto-verify. Live in v1.16-rc.21.
- `CryptoSigning.swift` — Ed25519 glue.
- `Reference/` — reference Tier B plugin (FixturePlugin re-implemented as an XPC service).
- `docs/tier-b-research/` — the actual research write-up.

## What works today (as of v1.16.0-rc.21, validated 2026-05-25)

- `maccrabctl plugin install <bundle-dir>` — accepts a flat-directory plugin bundle (`<id>/{manifest.json, binary, signature, signing.key.pub}`); verifies Ed25519 signature against `canonicalSignedPayload` = `"maccrab-tierb-plugin-v1\n" || SHA-256(manifest) || SHA-256(binary)`; stores under `~/Library/Application Support/MacCrab/plugins/tier-b/`.
- `maccrabctl plugin trust <key-hex>` — adds the 64-hex-char publisher public key to `trusted-keys.json`.
- `maccrabctl plugin revoke <key-hex>` — adds to `revoked-keys.json`; pre-empts trust.
- `maccrabctl plugin trust-list` — shows trusted + revoked keys.
- `maccrabctl plugin verify` — walks installed bundles, runs `TierBRegistry.verifyAll()`, reports per-plugin verified/failed.
- `maccrabctl plugin status` — `TierBBootstrap.status()` summary.

## What does NOT work today

- `maccrabctl plugin run <id>` — the subprocess-spawn path is on `research/post-v15`. `TierBRegistry.resolve()` produces a verified binary path, but `runCollectAndCommit` (the actual spawn) ships when NSXPCConnection + XPC service bundling lands.
- `maccrabctl plugin info <id>` for Tier B plugins — currently only queries the in-process Tier A `PluginRegistry`. Tier B plugins are visible via `verify` / `status` / `list --filter installed` but not `info` — that's a small follow-up.

## What is NOT here

Anything user-facing UI past the dashboard's Investigation → Forensics → Tier B tab (which exists per v1.16.0-rc.21). The full operator UX for hot-update + capability summary at install ships alongside the spawn path.
