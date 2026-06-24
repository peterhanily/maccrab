# Supported macOS Matrix

This document states which macOS versions MacCrab supports, what is actively
tested, and the known version-specific risks and caveats. It is written for an
acquisition / SOC audience that needs to understand the deployment envelope and
its sharp edges.

> Source of truth: `Package.swift` (the `.macOS(.v13)` floor), plus
> macOS-version-specific code paths and comments cited inline below.

---

## Summary matrix

| macOS | Marketing | Status | Notes |
|---|---|---|---|
| 12 Monterey and earlier | — | **Not supported** | Below the SPM platform floor; will not run. |
| 13 Ventura | macOS 13 | **Minimum supported** | The `.macOS(.v13)` floor in `Package.swift`. APIs gate to 13+ (e.g. dyld shared cache under the Cryptexes paths is a macOS-13+ layout). |
| 14 Sonoma | macOS 14 | Supported | One `if #available(macOS 14.0, *)` path exists in `MacCrabApp` for a 14+ UI affordance; everything else degrades gracefully on 13. |
| 15 Sequoia | macOS 15 | Supported | No version-specific gating beyond the 13 floor. |
| 26 Tahoe | macOS 26 | **Actively tested** | The current development/validation target. Several caveats are already encoded in code comments (below). |
| 27 (next) | — | **Untested horizon** | See risks below. There is **no runtime upper-version gate** (stated as a known limitation). |

- **Minimum supported macOS: Ventura 13.** Enforced structurally by the
  SwiftPM platform declaration `platforms: [.macOS(.v13)]` — the toolchain will
  not build or run the product below this floor.
- **Active test target: macOS 26 (Tahoe).** The Tier-B sandbox containment
  corpus and on-device validation are run here; multiple code comments are tagged
  "Corpus finding, macOS 26."

---

## Known macOS 26 (Tahoe) caveats already handled in code

These are *fixed/worked-around in the shipping code*, but they document the
fragility of the macOS API surface MacCrab depends on, and are worth surfacing
to an auditor:

1. **`Bundle.module` resource-bundle crash (fixed in v1.12.4).** macOS 26's
   `Bundle(url:)` rejects SwiftPM's stripped-down resource-bundle `Info.plist`
   (which contains only `CFBundleDevelopmentRegion`), returning nil; SwiftPM's
   auto-generated `Bundle.module` accessor then `fatalError`s. The crash
   surfaced when a user first clicked the Intelligence tab (which lazily
   instantiates `TyposquatDatabase`). The fix avoids `Bundle.module` entirely and
   builds the resource URL by probing SwiftPM's canonical layouts with
   `Data(contentsOf:)`, which reads bytes without validating the `.bundle` as a
   CFBundle. (`Sources/MacCrabCore/Enrichment/TyposquatDatabase.swift`.)

2. **Deny-default sandbox cannot be applied at exec time (sandbox-exec
   SIGABRT).** A deny-default profile applied at process exec via `sandbox-exec`
   aborts the target before the profile is evaluated (`SIGABRT` /
   `execvp() … Operation not permitted`). MacCrab's Tier-B plugin sandbox
   therefore applies the profile **post-startup** via `sandbox_init` from a
   signed trampoline (`maccrab-tierb-sandbox-host`), after dyld/exec are done.
   This is validated on-device on macOS 26.
   (`Sources/maccrab-tierb-sandbox-host/main.c`,
   `Sources/MacCrabForensics/TierB/SandboxProfileBuilder.swift`,
   `Sources/MacCrabForensics/TierB/SandboxedTierBRunner.swift`.)

3. **dyld shared-cache paths under the sandbox base (Corpus finding, macOS 26).**
   On macOS 13+ the dyld shared cache lives under the Cryptexes paths
   (`/System/Volumes/Preboot/Cryptexes`, `/private/preboot/Cryptexes`,
   `/System/Cryptexes`), **not** `/usr/lib`. Without read access to these the
   contained binary SIGABRTs at startup, so the sandbox runtime base must allow
   them. These are device-tuned: if a Swift plugin SIGABRTs at startup needing
   another system service or path, the runtime base is extended and the corpus
   re-run — the global `(allow mach-lookup)` is never restored.
   (`Sources/MacCrabForensics/TierB/SandboxProfileBuilder.swift`.)

---

## macOS 27 horizon and known risks

MacCrab leans heavily on two macOS subsystems whose contracts have historically
shifted between major releases — both are the highest-risk areas for a future
macOS:

- **Endpoint Security (ES) framework.** The detection engine is an ES System
  Extension. New macOS major versions periodically change ES event types,
  message semantics, entitlement gating, and System Extension activation flows.
  A macOS 27 that changes the ES API or its entitlement requirements is the most
  likely source of a "protection active but no events" regression and would
  require re-validation of the sysext activation path.

- **Sandbox surface (`sandbox_init` / SBPL).** The Tier-B plugin sandbox uses
  `sandbox_init` with a hand-built SBPL profile whose required runtime base
  (Mach services + dyld cache paths) was *empirically tuned against macOS 26*.
  Apple does not treat the SBPL or the set of services a process needs at
  startup as a stable contract, and `sandbox_init` itself is a long-deprecated
  API kept deliberately in a binary MacCrab owns and signs. A macOS 27 that
  changes the base set of services/paths a sandboxed process needs would
  manifest as plugin-startup SIGABRTs and require re-tuning the runtime base
  against the corpus on a 27 device. (The first-party / sideload execution lanes
  are independently trust-gated, so this risk is scoped to third-party plugin
  execution, not core detection.)

Because both subsystems are validated empirically per-OS rather than via a stable
API contract, **macOS 27 should be treated as untested until the corpus and
sysext activation are re-run on a 27 device.**

---

## Known limitation: no runtime upper-version gate

MacCrab enforces a **lower** bound (macOS 13 via the SPM platform floor) but has
**no runtime upper-version guard** — it does not refuse to run, warn, or degrade
on a macOS newer than its tested target. On an untested future macOS the engine
will attempt to start normally; any ES- or sandbox-surface incompatibility would
surface as a runtime failure (silent telemetry gaps, sysext activation failure,
or plugin-startup aborts) rather than a clean "unsupported OS" message. This is a
deliberate, stated limitation: operators upgrading to a not-yet-validated macOS
should verify detection is live (e.g. via `make test-detection` / the dashboard
heartbeat) after the OS upgrade.
