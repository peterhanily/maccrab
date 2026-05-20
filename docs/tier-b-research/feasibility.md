# Tier B Feasibility

**Status:** research, not committed. Plan §3.9 + §12.

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
