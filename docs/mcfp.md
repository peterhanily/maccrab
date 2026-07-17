# MCFP v1 — MacCrab Process Fingerprint specification

**Status:** v1 (static-only). Tags first shipping artifact: v1.14.0-rc.1.

MCFP is a per-process behavioral / structural descriptor attached to an identity. v1 ships the static components — properties computed without touching the live process or the dyld telemetry layer.

## Scheme

```
mcfp1/static/<arch>/<lc>/<cs>/<ent>
```

Each component is a 12-character hex prefix of a SHA-256, except `arch`, which is a short enum string.

A consumer trusts components individually. The dashboard / Analyzer / Sigma rule can match against `mcfp1/static/cs/<hex>` to assert "binary signed with this exact codesign posture" without committing to the full multi-component string.

## Components

### `arch`

Enumerated string for the Mach-O's primary architecture. Reads the binary's first four bytes (magic number) and / or `lipo -info`.

Values:
- `arm64` (CPU_TYPE_ARM64, single-arch)
- `arm64e` (CPU_TYPE_ARM64 + CPU_SUBTYPE_ARM64E, with PAC)
- `x86_64` (CPU_TYPE_X86_64)
- `universal` (fat binary containing multiple slices)
- `unknown` (none of the above)

The arch enum is short on purpose — it's part of the human-readable head of the fingerprint string. Multi-arch binaries collapse to `universal`; consumers that need slice-level detail re-fingerprint per-slice.

### `lc`

SHA-256 (12-hex prefix) of every `LC_LOAD_DYLIB` load command's name, joined by `\n` in load-command order.

Implementation: `otool -L <path>` and parse the resulting list. The list intentionally preserves load order — re-ordering load commands changes the fingerprint, but real binaries rarely have their load order shuffled without a rebuild.

### `cs`

SHA-256 (12-hex prefix) of `<team_id>|<flags>|<sealed_hash_alg>|<requirement>`, where each subfield is read from `SecCodeCopySigningInformation`. Already cached by `MacCrabCore.CodeSigningCache`; MCFP reuses the cache.

Subfields:
- `team_id` — Apple Developer Team Identifier. Empty for unsigned.
- `flags` — `kSecCodeInfoFlags` integer (CS_VALID, CS_RUNTIME, CS_ADHOC, etc.).
- `sealed_hash_alg` — page-level hash algorithm (sha256 / sha384). Default sha256 on modern macOS.
- `requirement` — designated requirement string from `SecCodeCopyDesignatedRequirement`.

The `cs` component is the strongest single signal in the static set — codesign team_id changes only with deliberate rebuild + re-sign.

### `ent`

SHA-256 (12-hex prefix) of the binary's entitlements: keys sorted alphabetically, joined by `\n`, hashed.

Implementation: `codesign -d --entitlements - <path>` returns the embedded entitlement plist; parse the keys via PropertyListSerialization. Values are intentionally dropped from the hash because some entitlements carry values that change across system updates (e.g. `com.apple.security.app-sandbox` is a Bool, but `keychain-access-groups` is an array that may shift).

## Stability contract

MCFP v1's static-only form must achieve, on representative binaries:

- **≥95% same-binary stability across reboots** (plan §6.4 R1 kill criterion).
- **≥80% different-family separation** (plan §6.4 R2 ship criterion, evaluated in v1.15).

These percentages are **targets / kill criteria**, not yet-validated results — the R1/R2 milestones the static form must clear before it can be relied on. They are to be checked empirically against a representative binary corpus; that corpus and its measured results are not yet committed to this repo.

## What v1 does NOT include

Per `docs/mcfp-research/R0.md`:

- `mcfp1/runtime/...` — ES NOTIFY_MMAP-derived components. Future v1.15 candidate if R2 selects option (b).
- `mcfp1/dyld/...` — dyld image-order component. Deferred indefinitely under SIP constraints (option d selected in R0).

The scheme is forward-compatible — adding a new component at `mcfp1/<namespace>/<component>` is purely additive; consumers of `mcfp1/static/...` ignore unknown namespaces.

## API surface

```swift
// Sources/MacCrabForensics/MCFP/MCFPStatic.swift
public enum MCFPStatic {
    public static func fingerprint(path: String) async throws -> MCFPStaticResult
}

public struct MCFPStaticResult {
    public let scheme: String                  // "mcfp1"
    public let archToken: String               // "arm64" / "arm64e" / "x86_64" / "universal"
    public let lc: String                       // 12-hex prefix
    public let cs: String                       // 12-hex prefix
    public let ent: String                      // 12-hex prefix
    public var canonical: String               // "mcfp1/static/<arch>/<lc>/<cs>/<ent>"
}
```

CLI:

```
maccrabctl fingerprint <pid-or-path>            # Print the canonical mcfp1/static/... string
maccrabctl fingerprint <pid-or-path> --json     # Emit per-component JSON
```

## References

- Plan §6 — MCFP — MacCrab Process Fingerprint
- Plan §6.3 — Proposed hash inputs
- Plan §6.4 — Research milestones (R0 / R1 / R2)
- `docs/mcfp-research/R0.md` — dyld+SIP+library-validation paradox decision
