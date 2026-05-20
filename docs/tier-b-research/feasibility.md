# Tier B Feasibility

**Status:** research, mostly delivered as `research-post-v15-rc.3`. Plan §3.9 + §12.

## What landed in rc.2 + rc.3

This memo originally framed Tier B as "1-2 are research prototypes; 3-5 are out of scope." rc.2 + rc.3 closed substantially more of that scope while keeping the work on the research branch:

| Pillar | Status as of rc.3 | Detail |
|---|---|---|
| 1. Sandbox profile generator (`SandboxProfileBuilder`) | **shipped + enforced** | Now compiles to SBPL with `(allow default)` baseline + targeted denies (Keychains, /etc, /var/db, Mail/Messages/Safari stores, .ssh/.aws/.config, network). Manifest allows emitted last so they override on overlap (SBPL last-match-wins). Used live by `TierBSubprocessLoader`. |
| 2. Daemon-side loader (`XPCPluginLoader` stub) | **stub for XPC; real subprocess path in `TierBSubprocessLoader`** | The subprocess loader actually spawns plugins via `/usr/bin/sandbox-exec -f <profile.sb>` and proves end-to-end JSON-RPC IPC. NSXPCConnection still deferred (see "Gap" below). |
| 3. Signing CA + revocation list | **shipped (research-grade)** | `PluginSignatureVerifier` (Ed25519 sign/verify), `PluginInstaller` (trusted-keys.json + revoked-keys.json), revocation pre-empts trust at both install + load. Live-verified end-to-end. |
| 4. Operator trust model | **shipped via CLI** | `maccrabctl plugin {install, uninstall, installed-list, trust, revoke, trust-list, verify-all, run-installed}` exposes the trust model to operators. |
| 5. Plan-level commitment | **still open** | Tier B remains a research chapter. No release chapter has been committed; the work above is the foundation that lets a release chapter focus narrowly on the gaps in §"Remaining gap" below. |

## Remaining gap: NSXPCConnection

`TierBSubprocessLoader` proves the IPC + commit + sandbox-enforcement contract using a `Process` + stdio pipes + `sandbox-exec`. This is **research-acceptable** but not production-acceptable for two reasons:

1. **`sandbox-exec` is private.** Apple has marked the binary `__SANDBOX_INTERNAL` since macOS 10.14. It still works on 10.15 → 15.x (verified rc.3 on macOS 25.3), but Apple could remove it without warning. A production Tier B plugin store cannot depend on it.
2. **`sandbox-exec` doesn't get the full hardening App Sandbox + XPC services receive.** TCC inheritance, mach service quotas, dyld closure caching — these need the launchd-spawned XPC service path.

The production move is to bundle each Tier B plugin's binary as an XPC service inside a parent `.app` (or `.framework`) bundle, with:

- `Info.plist` declaring `XPCService.ServiceType = Application` + Tier B-specific entitlements
- `com.apple.security.app-sandbox = YES`
- The sandbox profile applied via the service's Info.plist `com.apple.security.*` entitlement set + a paired `.sb` file referenced via `XPCService.RunLoopType` overrides

The Swift wiring is straightforward (`NSXPCConnection(machServiceName:options:)` + `exportedInterface` + `remoteObjectInterface`). The non-code blockers are:

- An Apple Developer-ID team certificate registered for XPC service signing
- Notarization for distributed Tier B plugins
- App-shape decision (do Tier B plugins live in `MacCrab.app/Contents/XPCServices/`, or in operator-installed external `.app` bundles?)

These are the items a release chapter would have to absorb.

## What "shipped end to end" looks like

The full chain demonstrated live in rc.3:

```bash
# Build, sign, install (with trust-on-install).
$ maccrabctl plugin install <bundle> --trust-on-install
Installed Tier B plugin 'com.research.tier-b-fixture'
  Publisher key:   8b202a1fba07b32a…
  Trusted:         yes (added on install)

# Verify every installed bundle against the current trust + revocation set.
$ maccrabctl plugin verify-all
Tier B plugin verification (1 installed)
Verified (1):
  com.research.tier-b-fixture  v0.1.0  key=8b202a1fba07b32a…

# Run the verified plugin under its manifest-declared sandbox profile.
# The plugin tries to read /private/etc/hosts; the sandbox blocks it.
$ maccrabctl plugin run-installed com.research.tier-b-fixture \
    --case <case-id> --probe-read /private/etc/hosts
Artifacts committed:  2
Probed path:          /private/etc/hosts (see artifacts for result)

# The committed probe artifact reports readable=false — the sandbox is real.
$ maccrabctl case artifacts <case-id> --limit 1
  tier_b_fixture.probe_read — probe-read /private/etc/hosts: readable=false

# Operator-driven revocation immediately invalidates the plugin.
$ maccrabctl plugin revoke 8b202a1fba07b32a...
$ maccrabctl plugin run-installed com.research.tier-b-fixture --case <id>
Error: TierBRegistry: verification failed: publisher key ... is on the revocation list
```

Five unit tests in `TierBRegistryTests` assert each step machine-checkable.

## TL;DR

Apple's App Sandbox + XPC services + a sandbox-profile generator is the viable Tier B path. Direct `sandbox-exec(8)` is unsupported (Apple has marked it private for >5 years). The infrastructure needed to ship Tier B as a release feature is:

1. **Sandbox profile generator** (this RC: `SandboxProfileBuilder`) — declarative DSL → SBPL text. ✓ done as research prototype.
2. **XPC service template** + daemon-side loader (this RC: `XPCPluginLoader` stub).
3. **Signing CA + revocation list** (plan §12 §F + §G).
4. **Operator-facing trust model**: how third-party plugins get vetted before promotion to Tier A.
5. **Plan-level commitment**: Tier B work needs a new chapter that names the audience + threat model.

Items 1-2 are research artifacts in this directory. Items 3-5 are out of scope for any single research chapter.

## Why App Sandbox + XPC, not `sandbox-exec`

`sandbox-exec(8)` from macOS 10.5 is the cleanest API to launch a profile-constrained subprocess from arbitrary code. Apple has marked it `__SANDBOX_INTERNAL` since macOS 10.14 and printed `__deprecated` warnings since 10.15. Per Apple's WWDC '21 + '22 security sessions, the supported path is:

- For third-party-loadable code: **App Sandbox + XPC services**. The host process spawns an XPC service whose `Info.plist` declares `com.apple.security.app-sandbox = YES` + entitlement set; macOS's launchd sandboxes the service at spawn time.
- For host-loaded plugin code: **NSExtension**. Heavier integration surface; not pursued for MacCrab.

XPC + App Sandbox give us the security property we want (process isolation, capability-restricted file access, no inherited TCC grants) without leaning on an unsupported API.

## How the IPC contract aligns with plan §3.6

Plan §3.6 commits to "MCP wire format = plugin↔host IPC contract. Tier B (future) speaks the same JSON-RPC-over-stdio." Tier B's XPC service implements the same four methods as the MCP server's plugin-facing surface:

- `collect(case, window, output)` for Collectors
- `enrich(subject, stage)` for Enrichers
- `fingerprint(target)` for Fingerprinters
- `analyze(case, scope)` for Analyzers

The JSON-RPC envelope (`TierBJSONRPCRequest` / `TierBJSONRPCResponse`) matches MCP's `application/jsonrpc+json` shape. Authors who already wrote MCP plugins can target Tier B with minor changes.

## What the sandbox profile generator emits

`SandboxProfileBuilder.compile(_:)` emits SBPL text. Example for a hypothetical Safari-readonly Tier B plugin:

```scheme
(version 1)

(deny default)

;; Apple-standard inherits — process-info, sysctl-read,
;; mach-issue-extension, IOKit-open for the small reads
;; that every binary needs.
(allow process-info-pidinfo (target self))
(allow process-info-pidfdinfo (target self))
(allow sysctl-read)
(allow iokit-open (iokit-user-client-class "IOSurfaceRootUserClient"))
(allow file-read-metadata)
(allow file-read-data (subpath "/usr/lib"))
(allow file-read-data (subpath "/System/Library"))

(allow file-read* (subpath "/Users/operator/Library/Safari"))
```

The plugin's manifest declares the `SandboxProfileSpec`; the daemon-side loader compiles it at spawn time + applies via the XPC service's entitlements. The plugin never gets broader reach than its manifest declares.

## Trust model

Three trust tiers. Plan §3.9 + this memo:

| Tier | Trust source | Loaded as | Process boundary | File access |
|---|---|---|---|---|
| **A** | first-party only (`com.maccrab.*` namespace) | in-process Swift | none (shares the host process) | inherited from host (FDA) |
| **B** | signed by a verified-community key OR project key | subprocess XPC service | macOS sandbox enforcement | manifest-declared subpaths only |
| **A-promoted** | community plugin reviewed + adopted into the first-party catalog | in-process Swift | none | inherited from host (FDA) |

Default trust rule when the plugin store ships: every third-party plugin is Tier B. Promotion to Tier A is an explicit human-curated review.

## Gaps before Tier B can ship

1. **Signing CA infrastructure** (plan §12). MacCrab needs a CA that signs verified-community plugins; revocation list at `maccrab.com/plugins/revocation.json` for compromised authors.
2. **`PluginManifest` schema additions**:
   - `xpcServiceIdentifier: String?` — required for Tier B; nil for Tier A.
   - `sandboxProfileSpec: SandboxProfileSpec?` — required for Tier B.
   - `signatureBlob: Data?` — required for Tier B; verified at install + load.
3. **Audit Pass 2026-E** (plan §3.8 future): "Every store-installed plugin verifies against the project signing key OR the verified-community key, at install time AND on every plugin load."
4. **Audit Pass 2026-F**: "Plugin not on revocation list at install time AND on every appcast check."
5. **Operator-facing affordance**: `maccrabctl plugin install <url>` + Dashboard "Plugins → Add" that walks the signing-CA verification + the per-plugin trust prompt.

## Recommended next chapter

If Tier B graduates from research to a release chapter:

- v1.17.0 — `PluginManifest` Tier B fields + the signing CA + the loader real impl. Reference Tier B fixture plugin in a separate `Reference-Tier-B/` subdirectory.
- v1.18.0 — Plugin store at `maccrab.com/plugins/`; signed appcast for installs. Audit Passes 2026-E + 2026-F.
- v1.19.0 — `maccrabctl plugin install` + Dashboard "Plugins → Add". Operator trust prompts.

Each is an independent release chapter; v1.18 doesn't have to ship before v1.17 produces real signal.

## What is NOT in this research

- **Apple Notarization for plugins.** Open question whether the store ships notarized plugins or just signed ones; out of scope for the design memo.
- **Live runtime monitoring of Tier B plugin behavior.** A future research item: should the host process gate-check IPC messages for anomalies?
- **Memory isolation.** XPC subprocess is OS-isolated; no further sandboxing needed unless paranoid (which this section explicitly is not).

## Reference

- Apple WWDC 2021 Session 10042 — "Discover how Apple platforms can run external code without breaking security guarantees"
- Apple Sandbox Profile Language reference (TN2266, deprecated but accurate)
- Plan §3.9 — Trust model + Tier B (deferred-with-shape-defined)
- Plan §3.6 — Discovery, loading, signing
- Plan §12 — Future direction: third-party plugin store
- Plan §3.8 — Pre-release audit Passes 2026-E + 2026-F (future)
