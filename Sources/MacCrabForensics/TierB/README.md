# MacCrabForensics/TierB

**Status (2026-05-25 update — partial promotion to first-class):** the install + verify + trust + discovery surface is live and exercised by the rave catalog (see launch rehearsal at `peterhanily/maccrab-site:rave-prototypes/launch-rehearsal/hosts-collector/`). The subprocess-spawn path remains on the `research/post-v15` branch pending NSXPCConnection + XPC service bundling work; until that lands, Tier B plugins install and verify but cannot be run via `maccrabctl plugin run`.

Tier B = subprocess-sandboxed plugin runtime. Plan §3.9 + §12. The §12 commitment was made on 2026-05-24 — see `plans/2026-05-19-plugin-platform-plan.md` §12 + the rave plan v4.5 at `~/Documents/claude_code/maccrab-future-planning/2026-05-20-plugin-site-plan.md`.

## Promotion-condition tracker

| # | Condition | Status |
|---|---|---|
| 1 | Sandbox profile generator emits profiles macOS accepts | ✅ `SandboxProfileBuilder.swift` |
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
