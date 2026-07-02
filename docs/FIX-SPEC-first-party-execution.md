# FIX SPEC — first-party plugin execution (Tier-B lane selection)

**Status:** proposed · **Component:** MacCrabForensics/TierB + MacCrabApp Forensics · **Repro'd on:** MacCrab v1.21.1 (installed app + sysext), plugin `com.maccrab.forensics.posture-pro` v0.3.0 · **Applies to:** current `main`.

A signed **first-party** forensic plugin (`posture-pro`) runs, commits **0 rows**, and looks like an empty scan. Root cause: the first-party execution anchor was never configured (the GA signing-ceremony step was skipped), so the plugin is refused on the first-party lane and silently falls through to the sandboxed third-party lane, which fail-closes. This spec is self-contained and reproducible straight from the commands below.

> **Two things to call out explicitly:**
>
> 1. **Fix 1 is a deliberate keyholder / security decision — and this spec says so plainly.** It is the GA signing-ceremony step that was skipped (`FirstPartyTrustRoot.publisherKeyFingerprint` left at the unset sentinel), and it is the one change that actually makes the first-party plugin runnable. It authorizes **UNSANDBOXED / full-FDA first-party execution** — see §2.3. Whoever applies it is performing the ceremony.
> 2. **The stale "gap-C" story is corrected.** The sandbox is **not** the blocker — the SBPL/broker faithfully grants the manifest's declared read + exec paths (§4). **Lane selection is the blocker.** Don't chase the sandbox.

---

## §0 — Empirical proof (reproduction)

**Setup:** `com.maccrab.forensics.posture-pro` v0.3.0 is installed at
`~/Library/Application Support/MacCrab/plugins/com.maccrab.forensics.posture-pro/`
(bundle: `binary`, `manifest.json`, `signature`, `signing.key.pub` — see Appendix A.1).

**Reproduce (the exact command + output):**

```
$ maccrabctl plugin run com.maccrab.forensics.posture-pro --case e7ef1001-1659-4ad2-9245-c746597e8300
Ran sandboxed third-party Tier-B collector com.maccrab.forensics.posture-pro on case e7ef1001-1659-4ad2-9245-c746597e8300
  Invocation id:        2
  Status:               error
  Artifacts committed:  0
  Artifacts rejected:   0
  Notes:
    - plugin emitted no terminal result
```

**The one line that pins it:** `Ran sandboxed third-party Tier-B collector …`.
The plugin id is in the **first-party** namespace (`com.maccrab.forensics.*`) and ships as a signed first-party bundle — yet it executed on the **sandboxed third-party** lane and committed **0 artifacts** with `plugin emitted no terminal result`.

**Contrast — the same binary works when it reads directly** (Appendix A.3): given a valid `TierBCollectRequest` on stdin, the standalone `posture-pro` binary emits **220 artifacts** (`status: partial`; the count is host-state-dependent, ~218–220). The collector is functional; the failure is *which lane the host routes it down*, not the plugin.

---
## §1 ROOT CAUSE — the two-lane execution model + full traced chain

### (a) The two execution lanes and where the lane is chosen

MacCrab runs an installed Tier-B collector through **one shared entry point** — `TierBCollectorExecutor.runInstalled` — which implements two *disjoint* execution lanes. The header comment states the dispatch contract exactly:

```
// Dispatch (Plan §3.1, disjoint lanes):
//   1. Try the UNSANDBOXED first-party lane — a byte-match to the compiled-in
//      FirstPartyTrustRoot anchor. If it resolves, run via FirstPartyTierBRunner.
//   2. Otherwise (firstPartyExecutionRefused) → the SANDBOXED third-party lane:
//      resolveForSandboxedExecution (fail-closed if the signed trampoline is
//      unavailable — never run untrusted code uncontained) → SandboxedTierBRunner.
```
(`Sources/MacCrabForensics/TierB/TierBCollectorExecutor.swift:6-13`)

**Lane 1 — first-party = UNSANDBOXED / direct FDA reads.** A first-party plugin runs as a *trusted* subprocess spawned directly (`executable: verified.binaryPath`) with **no sandbox and no file broker**, inheriting the host's Full-Disk-Access / TCC. `FirstPartyTierBRunner.run` documents this: *"First-party: spawn the verified binary directly (no sandbox, no broker)."* (`Sources/MacCrabForensics/TierB/FirstPartyTierBRunner.swift:69-82`). The keystone comment says the same: a first-party plugin *"runs as a TRUSTED subprocess with NO sandbox profile (it inherits the host's Full-Disk-Access / TCC)"* (`Sources/MacCrabForensics/TierB/FirstPartyTrustRoot.swift:5-7`).

**Lane 2 — third-party = SANDBOXED / brokered reads.** A third-party plugin is *never* handed the plugin binary directly; instead `SandboxedTierBRunner.run` launches a signed trampoline that applies a manifest-derived deny-default SBPL and then `execv`s the plugin, and the plugin's file reads are served indirectly over an fd-3 socket broker rather than granted by the SBPL:

```
// Brokered file access (Model B): the SBPL grants NO manifest reads. The
// host snapshots manifest-declared TCC sources into a host-owned,
// plugin-UNWRITABLE dir and the broker serves read-fds over fd 3 ...
```
(`Sources/MacCrabForensics/TierB/SandboxedTierBRunner.swift:325-330`)

**Where the lane is chosen** — the `do/catch` in `runInstalled` is the single decision point:

```swift
do {
    verified = try await registry.resolveForFirstPartyExecution(
        pluginID: pluginID, officialSource: officialSource, catalogOverrideActive: catalogOverrideActive)
    sandboxed = false
} catch let e as TierBRegistry.RegistryError {
    guard case .firstPartyExecutionRefused = e else { throw e }   // notInstalled/quarantined/verify → propagate
    verified = try await registry.resolveForSandboxedExecution(
        pluginID: pluginID,
        sandboxRuntimeAvailable: sandboxRunner.isRuntimeAvailable,
        hasValidCuratedReceipt: false,   // operator-trust (install) authorizes the contained lane
        catalogOverrideActive: catalogOverrideActive)
    sandboxed = true
}
```
(`Sources/MacCrabForensics/TierB/TierBCollectorExecutor.swift:67-79`)

The lane is thus purely *outcome-driven*: try first-party first; **only** if that throws `firstPartyExecutionRefused` does it fall through to the sandboxed lane. Any other resolve error (`notInstalled` / `quarantined` / `verificationFailed`) re-propagates (`:72`). Crucially, the lane is **not** decided by the plugin's id namespace — nothing in this dispatch inspects `com.maccrab.forensics.*`; the identity signal is purely the cryptographic fingerprint match inside `resolveForFirstPartyExecution`.

### (b) The exact chain for `posture-pro` (id `com.maccrab.forensics.posture-pro`)

**Step 1 — CLI entry.** `maccrabctl plugin run com.maccrab.forensics.posture-pro --case <id>` finds no Tier-A (built-in) registration, so it takes the Tier-B path via `runTierBCollector`, which calls the shared executor:

```swift
exec = try await TierBCollectorExecutor.runInstalled(
    pluginID: id, scratchDir: scratch, windowStartUnix: startU, windowEndUnix: endU,
    officialSource: ctx.officialSource, catalogOverrideActive: ctx.catalogOverrideActive)
```
(`Sources/maccrabctl/PluginCommands.swift:689-691`; entry fall-through at `:573-581`)

**Step 2 — first-party resolve is attempted.** `runInstalled` calls `registry.resolveForFirstPartyExecution` (`TierBCollectorExecutor.swift:68-69`). The public overload pins the anchor to the compiled-in trust root:

```swift
try await resolveForFirstPartyExecution(
    ...
    expectedPublisherFingerprint: FirstPartyTrustRoot.publisherKeyFingerprint,
    anchorConfigured: FirstPartyTrustRoot.isConfigured)
```
(`Sources/MacCrabForensics/TierB/TierBRegistry.swift:231-237`)

**Step 3 — the first-party EXECUTION gate REFUSES (root cause).** `resolveForFirstPartyExecution` runs the full crypto resolve, then calls `FirstPartyExecutionGate.evaluate(...)` and throws on any non-`allow`:

```swift
let decision = FirstPartyExecutionGate.evaluate(
    bundleSigningKeyPubSHA256: verified.publicKeySHA256,
    expectedPublisherFingerprint: expectedPublisherFingerprint,
    anchorConfigured: anchorConfigured,
    catalogOverrideActive: catalogOverrideActive,
    officialSource: officialSource)
guard case .allow = decision else {
    cleanupVerifiedBinary(verified)
    ...
    throw RegistryError.firstPartyExecutionRefused(pluginID: pluginID, reason: reason)
}
```
(`Sources/MacCrabForensics/TierB/TierBRegistry.swift:252-265`)

The **very first clause** of the gate denies because the anchor is unconfigured:

```swift
guard anchorConfigured else {
    return .deny(reason: "first-party publisher key not configured (fail-closed)")
}
```
(`Sources/MacCrabForensics/TierB/FirstPartyExecutionGate.swift:41-43`)

`anchorConfigured` is `FirstPartyTrustRoot.isConfigured`, which is **false** because `publisherKeyFingerprint` is still the unset sentinel (64 zero-hex):

```swift
public static let publisherKeyFingerprint: String = unsetSentinel
...
public static var isConfigured: Bool {
    let f = publisherKeyFingerprint.lowercased()
    return f.count == 64 && f != unsetSentinel && f.allSatisfy { $0.isHexDigit }
}
```
(`Sources/MacCrabForensics/TierB/FirstPartyTrustRoot.swift:38,42-45`; `unsetSentinel = String(repeating: "0", count: 64)` at `:33`)

So `isConfigured == false` → gate returns `.deny("first-party publisher key not configured (fail-closed)")` → `resolveForFirstPartyExecution` throws `firstPartyExecutionRefused`. **This is why the first-party plugin never runs on its own lane:** the byte-match to the publisher key is *unreachable* — the gate short-circuits on the unconfigured anchor before it ever compares `posture-pro`'s fingerprint (which would be `07e39eb1…8aaae3`) against the anchor. The correct namespace id is irrelevant to the gate; only the (currently-zeroed) fingerprint is.

**Step 4 — fall-through to the sandboxed third-party lane.** Back in `runInstalled`, the `catch` matches `firstPartyExecutionRefused` (`TierBCollectorExecutor.swift:71-72`) and re-resolves via `resolveForSandboxedExecution` with `sandboxed = true` (`:73-78`). The first-party plugin is now being treated as untrusted sideloaded code. Two outcomes are possible from here, and both yield 0 artifacts:

- **If the signed trampoline is present + trusted** (`sandboxRunner.isRuntimeAvailable == true`, `:75`), `ThirdPartyExecutionGate.evaluate` can allow (operator-trusts the install key), and `SandboxedTierBRunner.run` spawns `posture-pro` under a **deny-default SBPL with brokered reads** (`SandboxedTierBRunner.swift:294-419`). posture-pro was authored for the *unsandboxed first-party lane*: its manifest declares direct `fileReadSubpaths` (`/Library/LaunchDaemons`, `/Library/LaunchAgents`, XProtect.bundle, `/Library/Application Support/com.apple.TCC`) and `processExecPaths` (fdesetup, spctl, socketfilterfw, systemextensionsctl, kmutil, profiles, sfltool) expecting to inherit host FDA. Under the sandboxed lane the SBPL grants **no** manifest reads (broker-only) — matching the observed *"Ran sandboxed third-party ... Status: error ... plugin emitted no terminal result"*, i.e. the contained plugin cannot do its work and exits without an IPC terminal result.

- **If the trampoline is unavailable**, `ThirdPartyExecutionGate` denies first: *"sandbox runtime unavailable — refusing to run third-party code uncontained (fail-closed)"* (`Sources/MacCrabForensics/TierB/ThirdPartyExecutionGate.swift:73-75`), and `resolveForSandboxedExecution` throws `sandboxedExecutionRefused` — which surfaces as a thrown error, not a printed "Status: error" line.

Because the established symptom shows the CLI *did* print `Ran sandboxed third-party Tier-B collector … Status: error … Artifacts committed: 0`, the run reached the *spawn* branch: `runInstalled` returned normally with `lane == .sandboxed` (`TierBCollectorExecutor.swift:93-100`), and the outcome had no terminal result.

**Step 5 — why 0 artifacts / "plugin emitted no terminal result".** The printed status + note are produced by `TierBArtifactBridge.commit`. When the spawned (sandboxed) plugin produces no artifacts and no terminal IPC result, `outcome.artifacts` is empty (so `committed` stays 0, `:86-99`) and `outcome.result == nil`, hitting:

```swift
} else {
    status = .error; notes.append("plugin emitted no terminal result")
}
```
(`Sources/MacCrabForensics/TierB/TierBArtifactBridge.swift:103-108`; `TierBRunOutcome.result` is an optional `TierBCollectResult?` at `FirstPartyTierBRunner.swift:28`)

The CLI then prints these verbatim:

```swift
print("Ran \(exec.lane.rawValue) Tier-B collector \(id) on case \(handle.caseID)")
...
print("  Status:               \(result.status.rawValue)")
print("  Artifacts committed:  \(result.artifactsCommitted)")
```
(`Sources/maccrabctl/PluginCommands.swift:717-724`; `TierBExecutionLane.sandboxed = "sandboxed third-party"` at `TierBCollectorExecutor.swift:23`)

### Summary of the root cause

The first-party plugin ends up sandboxed **solely because `FirstPartyTrustRoot.publisherKeyFingerprint` is still the unset sentinel** (`FirstPartyTrustRoot.swift:38`) → `isConfigured == false` (`:42-45`) → `FirstPartyExecutionGate.evaluate`'s first `guard anchorConfigured` clause denies (`FirstPartyExecutionGate.swift:41-43`) → `resolveForFirstPartyExecution` throws `firstPartyExecutionRefused` (`TierBRegistry.swift:259-265`) → `runInstalled`'s catch falls through to the sandboxed lane (`TierBCollectorExecutor.swift:71-78`). The lane decision is purely fingerprint-gated, not namespace-gated, so a `com.maccrab.forensics.*` id gives it no special treatment while the anchor is zeroed. Once sandboxed, the plugin — authored for direct FDA reads/exec — is run under a deny-default SBPL with broker-only reads, cannot complete, and emits no terminal result, so `TierBArtifactBridge.commit` records `status=error`, `committed=0`, note *"plugin emitted no terminal result"* (`TierBArtifactBridge.swift:107`). This is fail-closed-by-design (the anchor comment mandates the sentinel until the GA keyholder ceremony, `FirstPartyTrustRoot.swift:19-24`); the Fix-1 remedy is to set `publisherKeyFingerprint` to `07e39eb12c15b8052f5249134ea3337a0789ebc799d1c58d097aaa548a8aaae3`, which makes `isConfigured` true and lets the gate reach and pass the fingerprint byte-match, routing posture-pro down the unsandboxed first-party lane.
---

## §2 — FIX 1 (PRIMARY): configure the first-party publisher anchor

### 2.1 The one-line change

**File:** `Sources/MacCrabForensics/TierB/FirstPartyTrustRoot.swift:38`

Current (ships fail-closed — the unset sentinel):

```swift
    public static let publisherKeyFingerprint: String = unsetSentinel
```

Change to (bake in the real posture-pro publisher fingerprint):

```swift
    public static let publisherKeyFingerprint: String = "07e39eb12c15b8052f5249134ea3337a0789ebc799d1c58d097aaa548a8aaae3"
```

Nothing else in this file changes. `unsetSentinel` (line 33), `isConfigured` (lines 42-45), and `fingerprint(ofSigningKey:)` (lines 49-51) all continue to work as-is: once line 38 holds a well-formed 64-char lowercase-hex non-sentinel value, `isConfigured` flips to `true` automatically:

```swift
    public static var isConfigured: Bool {
        let f = publisherKeyFingerprint.lowercased()
        return f.count == 64 && f != unsetSentinel && f.allSatisfy { $0.isHexDigit }
    }
```
(`FirstPartyTrustRoot.swift:42-45`) — the target value is 64 hex chars and not all-zeros, so `isConfigured == true` after the edit.

### 2.2 Why this exact value

The value is `sha256(posture-pro bundle's signing.key.pub)` — the SHA-256 (lowercase hex) of the raw 32-byte Ed25519 public-key bytes of the first-party plugin-signing key. It is the exact value the gate compares against at runtime, computed by the same function on both sides:

- The anchor side is a build-time constant (`publisherKeyFingerprint`).
- The bundle side is computed at resolve time from the installed bundle's `signing.key.pub`:

```swift
            resolvedPublisherFingerprint = FirstPartyTrustRoot.fingerprint(ofSigningKey: pubKeyData)
```
(`TierBRegistry.swift:143`), where `fingerprint(ofSigningKey:)` is:

```swift
    public static func fingerprint(ofSigningKey raw: Data) -> String {
        SHA256.hash(data: raw).map { String(format: "%02x", $0) }.joined()
    }
```
(`FirstPartyTrustRoot.swift:49-51`).

Because both sides run the identical SHA-256-lowercase-hex transform, and the established facts confirm the installed posture-pro bundle's `signing.key.pub` hashes to exactly `07e39eb1…aaae3`, baking that string into line 38 makes the anchor byte-equal the bundle fingerprint. The gate's final comparison `got == want` (`FirstPartyExecutionGate.swift:56`) then passes, and `resolveForFirstPartyExecution` returns a `VerifiedPlugin` with `isFirstParty = true` (`TierBRegistry.swift:266`) — routing posture-pro down the UNSANDBOXED first-party lane instead of the sandboxed third-party fallback in `TierBCollectorExecutor.runInstalled` (`TierBCollectorExecutor.swift:67-79`).

Namespace (`com.maccrab.forensics.*`) is deliberately **not** what authorizes execution — `RaveNamespaceGuard` (`RaveNamespaceGuard.swift`) only defends install/display against impersonation and is not an input to the execution gate (see the gate header, `FirstPartyExecutionGate.swift:11-13`). The publisher-key fingerprint match is the sole positive authority; that is precisely why the current sentinel makes the correctly-namespaced posture-pro plugin fall through to the sandboxed lane.

### 2.3 SECURITY KEYSTONE warning (keyholder / offline-ceremony)

**This change authorizes UNSANDBOXED, full-FDA first-party execution and MUST be treated as an offline keyholder ceremony, not a routine code edit.** A first-party Tier-B plugin runs as a **TRUSTED subprocess with NO sandbox profile — it inherits the host's Full-Disk-Access / TCC** (`FirstPartyTrustRoot.swift:4-6`). The authority to run it must be unforgeable AND immutable, which is why the fingerprint is a constant baked into the SIGNED app binary at build time and MUST NEVER be read from a file or env (that re-introduces the catalog-trust-root swap attack this anchor exists to close — `FirstPartyTrustRoot.swift:22-24`).

The in-file OPERATOR/KEYHOLDER instructions say to generate the Ed25519 keypair **OFFLINE** at the GA signing ceremony and set this fingerprint then — the code explicitly references **Runbook P / Q**:

```swift
    /// SHA-256 (lowercase hex) of the first-party plugin-signing public key.
    /// OPERATOR: replace the sentinel with the real fingerprint at the GA signing
    /// ceremony (Runbook P / Q). Build-time constant ONLY.
```
(`FirstPartyTrustRoot.swift:35-37`), and the header notes "its custody equals the trust of the app binary itself" (`FirstPartyTrustRoot.swift:20-21`).

`TierB/README.md` lists this same step as the first of the operator/keyholder gates that keep the lane fail-closed until GA:

```
- `FirstPartyTrustRoot.publisherKeyFingerprint` is set (offline keyholder
  ceremony) — until then first-party execution is disabled and the catalog has no
  live entries.
```
(`TierB/README.md:48-50`).

**Implication for this spec:** whoever applies Fix 1 is performing the ceremony step. The value must come from the offline-held first-party signing key's public component (the same key whose `signing.key.pub` ships inside the posture-pro bundle), not from any on-disk or catalog source.

### 2.4 Gate preconditions STILL enforced after Fix 1 (not a blanket authorization)

Fix 1 flips only the `anchorConfigured` clause from fail-closed to satisfiable. The gate `FirstPartyExecutionGate.evaluate` (`FirstPartyExecutionGate.swift:34-60`) is fail-closed at every clause; after Fix 1 a plugin still needs ALL of the following to reach `.allow`:

1. **`anchorConfigured` == true** — now true after Fix 1, but still guarded: `guard anchorConfigured else { return .deny(...) }` (`FirstPartyExecutionGate.swift:41-43`).
2. **No catalog-trust-root override** (defense-in-depth) — `if catalogOverrideActive { return .deny(...) }` (`FirstPartyExecutionGate.swift:44-46`). A pub-path override or the staging-pub override voids first-party execution (`TierBCollectorExecutor.swift:110-111`).
3. **Official catalog source** (defense-in-depth) — `guard officialSource else { return .deny(...) }` (`FirstPartyExecutionGate.swift:47-49`); `officialSource` is derived from `MACCRAB_RAVE_BASE_URL` being empty or the production host (`TierBCollectorExecutor.swift:112-114`).
4. **Well-formed fingerprints on BOTH sides** — 64 chars, all hex, else `.deny(reason: "malformed fingerprint")` (`FirstPartyExecutionGate.swift:52-55`).
5. **Exact publisher-key match** — `guard got == want else { return .deny(reason: "bundle is not signed by the first-party publisher key") }` (`FirstPartyExecutionGate.swift:56-58`). Only posture-pro's key matches; every third-party/sideload key still denies.

Additionally, the gate is only reached AFTER the full crypto chain and quarantine check that the caller runs first — `resolve()` enforces, in order: not-quarantined (`TierBRegistry.swift:106-109`), signature verification via `PluginSignatureVerifier.verify` with the trust/revocation store (`TierBRegistry.swift:110-134`), a TOCTOU re-verify of the snapshotted binary bytes (`TierBRegistry.swift:135-155`), manifest decode from the signature-covered bytes (`TierBRegistry.swift:162-166`), and a fresh 0o500 verified-binary temp (`TierBRegistry.swift:182-205`). Only then does `resolveForFirstPartyExecution` call the gate (`TierBRegistry.swift:251-265`), and on ANY deny it deletes the verified temp and throws `firstPartyExecutionRefused` so no runnable binary is left behind (`TierBRegistry.swift:259-264`). So Fix 1 authorizes exactly one bundle (posture-pro, signed by the anchor key, from the official source, with no override, passing the crypto+quarantine chain) — not "all first-party" and certainly not any third-party plugin.

### 2.5 Required test updates (EXACTLY two) and the pure-gate assertions to KEEP

Grepping `Tests/` for the ship-state assertions (`== FirstPartyTrustRoot.unsetSentinel`, `FirstPartyTrustRoot.isConfigured == false`) yields exactly two sites that HARD-BREAK once `isConfigured` becomes `true`. Both are documentation-of-ship-default assertions and must be updated to reflect the configured anchor.

**Update 1 — `Tests/MacCrabForensicsTests/FirstPartyExecutionGateTests.swift:93-100`** (the `shipsUnconfigured` test):

```swift
    @Test("ships fail-closed: the compiled-in anchor is the unset sentinel until the operator configures it")
    func shipsUnconfigured() {
        // This documents the GA prerequisite: isConfigured must be made true (by
        // baking in the real publisher fingerprint) before first-party execution
        // can ever be authorized.
        #expect(FirstPartyTrustRoot.publisherKeyFingerprint == FirstPartyTrustRoot.unsetSentinel)
        #expect(FirstPartyTrustRoot.isConfigured == false)
    }
```

After Fix 1 both `#expect`s (lines 98-99) are false. Update to assert the anchor is now CONFIGURED (a well-formed, non-sentinel fingerprint):

```swift
    @Test("ships configured: the compiled-in first-party publisher anchor is set")
    func shipsConfigured() {
        // Post-ceremony state: the real publisher fingerprint is baked in, so
        // first-party execution can be authorized (subject to the gate clauses).
        #expect(FirstPartyTrustRoot.publisherKeyFingerprint != FirstPartyTrustRoot.unsetSentinel)
        #expect(FirstPartyTrustRoot.isConfigured == true)
    }
```
(Optionally also `#expect(FirstPartyTrustRoot.publisherKeyFingerprint == "07e39eb1…aaae3")` to pin the exact ceremony value.)

**Update 2 — `Tests/MacCrabForensicsTests/FirstPartyExecutionGateInvariantTests.swift:95-111`** (inside `unsetSentinelDeniesEvenWhenBundleKeyMatchesIt`). This test has TWO parts:

- Lines 102-105 are a PURE-GATE assertion (gate logic independent of the baked-in fingerprint): with `configured=false` and a sentinel key/anchor, the gate short-circuits on the not-configured guard. **KEEP UNCHANGED:**
  ```swift
        let sentinel = FirstPartyTrustRoot.unsetSentinel
        let d = decide(key: sentinel, anchor: sentinel, configured: false)
        #expect(d == .deny(reason: "first-party publisher key not configured (fail-closed)"))
        #expect(!d.isAllowed)
  ```
- Lines 109-110 assert the SHIP state (`publisherKeyFingerprint == sentinel`, `isConfigured == false`) — these break after Fix 1 and must be updated to the configured state:
  ```swift
        #expect(FirstPartyTrustRoot.publisherKeyFingerprint == sentinel)
        #expect(FirstPartyTrustRoot.isConfigured == false)
  ```
  Change to:
  ```swift
        #expect(FirstPartyTrustRoot.publisherKeyFingerprint != sentinel)
        #expect(FirstPartyTrustRoot.isConfigured == true)
  ```
  (and reword the trailing comment on lines 106-108 which says "production cannot be tricked into the allow path until the operator configures it" — post-Fix-1 it now IS configured; the pure-gate part above still proves the not-configured branch fails closed).

**PURE-GATE assertions that MUST be KEPT (gate logic independent of the baked-in fingerprint) — do NOT touch these:**

- All of `FirstPartyExecutionGateTests.swift` EXCEPT `shipsUnconfigured`: `allowHappyPath` (21-28), `denyWrongKey` (30-37), `denyUnconfiguredAnchor` (39-48, passes `anchorConfigured: false` explicitly), `denyCatalogOverride` (50-57), `denyNonOfficialSource` (59-66), `denyMalformed` (68-80), `caseInsensitive` (82-89), `fingerprintMatchesSHA256` (102-115). These call `evaluate` with explicit local anchors (`Self.publisher` / `Self.other`) and do not read `FirstPartyTrustRoot.publisherKeyFingerprint`, so they are unaffected.
- All of `FirstPartyExecutionGateInvariantTests.swift` EXCEPT the two ship-state lines above: `exhaustiveAllowSpaceIsExactlyOne` (57-91), the not-configured short-circuit lines 102-105, `sentinelAnchorWithMatchingKeyConfiguredTrue` (113-125, pure-gate — proves the gate itself is pure and the sole defense against a sentinel anchor is `isConfigured`), `hostileHexVariantsAllDeny` (129-150), `caseAndWhitespaceNormalization` (152-163), `defenseInDepthRefusalsDominateMatch` (167-179), `realFingerprintRoundTrip` (183-190). All use injected local anchors and remain valid unchanged.

**No change needed (verify, do not edit) — `Tests/MacCrabForensicsTests/TierBRegistryTests.swift`:** the first-party exec tests (`firstPartyAllow` 151-161, `firstPartyDenyUnconfigured` 163-172, `firstPartyDenyWrongKey` 174-183, `firstPartyDenyNonOfficial` 185-194, `firstPartyDenyOverride` 196-205) all install bundles signed with a **throwaway random key** (`Curve25519.Signing.PrivateKey()` at `TierBRegistryTests.swift:43`). Because those fixture fingerprints never equal the real posture-pro fingerprint, they still pass after Fix 1. Note however that `firstPartyDenyUnconfigured` (163-172) uses the PUBLIC overload (which now pins the configured anchor) and still throws — but the throw reason shifts from "not configured" to "bundle is not signed by the first-party publisher key". The `#expect(throws: RegistryError.self)` assertion is reason-agnostic so it still passes, but the test's name/comment become semantically stale (see caveats).

---

## §3 FIX 2 (OBSERVABILITY) — KitRunner swallows the real refusal reason

### 3.1 The bug (verbatim)

The dashboard "Run kit" path routes any non-Tier-A plugin through `KitRunner.runInstalledTierB`, whose return type is a bare `Bool`. Every failure mode is collapsed into `false`, and — worse — a run that *did* execute (down the sandboxed lane) but produced no artifacts still returns `true`, so its terminal-error status/notes are never surfaced. This is why a first-party-namespaced plugin that hit the fail-closed first-party gate and fell to the sandboxed lane looks to the operator like "a scanner that just didn't run" (or nothing at all), never showing WHY.

The swallowing branch is the `catch` in `runInstalledTierB` — `Sources/MacCrabApp/V2/Forensics/KitRunner.swift:221-223`:

```swift
            return true
        } catch {
            return false
        }
    }
```

The `Bool` result is then mapped into a generic skip reason at the call site — `Sources/MacCrabApp/V2/Forensics/KitRunner.swift:89-97`:

```swift
                    let ranTierB = await Self.runInstalledTierB(
                        pluginID: pref.pluginID, store: handle.store, caseID: handle.caseID)
                    if !ranTierB {
                        skipped.append(SkippedPlugin(
                            pluginID: pref.pluginID,
                            reason: "not a built-in and not an installed Tier-B plugin"
                        ))
                    }
                    continue
```

Two distinct losses of information here:

1. **The `catch` discards the typed error.** `TierBCollectorExecutor.runInstalled` throws rich, human-readable errors — `TierBRegistry.RegistryError.firstPartyExecutionRefused(pluginID:reason:)` (which for the §0 repro reads e.g. `refusing first-party execution of com.maccrab.forensics.posture-pro: first-party publisher key not configured (fail-closed)` — see `Sources/MacCrabForensics/TierB/TierBRegistry.swift:40` and `Sources/MacCrabForensics/TierB/FirstPartyExecutionGate.swift:42`), `sandboxedExecutionRefused`, `quarantined`, `verificationFailed`, `notInstalled`, and `TierBCollectorExecutorError.thirdPartyExecutionDisabled` (`Sources/MacCrabForensics/TierB/TierBCollectorExecutor.swift:32-43`). All of these are flattened to `false` → the generic "not a built-in and not an installed Tier-B plugin" string, which is actively misleading (the plugin *is* installed; it was *refused*).

2. **A `true` return hides an errored run.** On the success path (`Sources/MacCrabApp/V2/Forensics/KitRunner.swift:204-220`) the method commits the outcome via `TierBArtifactBridge.commit(...)` and returns `true` **unconditionally**, ignoring `result.status` and `result.notes`. When the sandboxed lane spawns but the plugin emits no terminal result, `TierBArtifactBridge.commit` sets `status = .error` and appends `"plugin emitted no terminal result"` (`Sources/MacCrabForensics/TierB/TierBArtifactBridge.swift:106-107`). That status/notes pair is exactly the §0 symptom (`Status: error … Artifacts committed: 0 … plugin emitted no terminal result`), yet `runInstalledTierB` throws it away and reports success — so the plugin is neither added to `skipped` nor flagged, and a 0-artifact errored run is indistinguishable from a clean empty scan in the done banner.

Contrast the CLI, which already surfaces the reason at `Sources/maccrabctl/PluginCommands.swift:692-700` (`catch let e as TierBRegistry.RegistryError { … throw CaseCommandError.underlying("\(e)") }`) and prints `result.status` + `result.notes` at lines 717-725. The dashboard KitRunner is the one surface that drops it.

### 3.2 The fix — typed outcome instead of `Bool`

Replace the `Bool` return with a typed `KitRunOutcome` that names each lane result, and have the caller surface refusals/failures into the existing `SkippedPlugin` list (already rendered in the done banner by `V2ForensicsScansView.skippedList`, `Sources/MacCrabApp/V2/Workspaces/V2ForensicsScansView.swift:665-685`, which shows `SkippedPlugin.reason` verbatim). No new UI is required — the reason string just stops being generic.

**Step A — define the outcome enum** (add to `KitRunner`, alongside `SkippedPlugin` at `Sources/MacCrabApp/V2/Forensics/KitRunner.swift:35-38`):

```swift
    /// The result of attempting to run one INSTALLED Tier-B plugin. Unlike a
    /// bare Bool, this carries WHY a plugin didn't contribute artifacts so the
    /// done banner can show a real reason (a refused first-party plugin looks
    /// nothing like an unknown one).
    enum KitRunOutcome: Sendable {
        /// Ran and committed. `rows` is what the bridge committed.
        case ran(rows: Int)
        /// The plugin isn't a built-in and isn't an installed Tier-B plugin.
        case notInstalled
        /// The first-party execution gate refused it (e.g. publisher anchor
        /// unset → fail-closed, non-official source, or key mismatch).
        case refusedFirstParty(reason: String)
        /// The sandboxed third-party lane refused or failed (runtime
        /// unavailable, kill-switch, quarantined/revoked, verify failed).
        case sandboxFailed(reason: String)
        /// It ran but produced an error / no-terminal-result / 0 useful rows.
        case ranWithError(reason: String)
    }
```

**Step B — rewrite `runInstalledTierB` to return `KitRunOutcome`** (replaces the body at `Sources/MacCrabApp/V2/Forensics/KitRunner.swift:199-224`). Note `notInstalled` must be distinguished from other `RegistryError` cases because that is the *only* case whose message ("not a built-in and not an installed Tier-B plugin") is still accurate; everything else must carry the real error text:

```swift
    static func runInstalledTierB(pluginID: String, store: ArtifactStore, caseID: String) async -> KitRunOutcome {
        let ctx = TierBCollectorExecutor.catalogContextFromEnv()
        let scratch = NSTemporaryDirectory() + "maccrab-tierb-scratch-\(UUID().uuidString)"
        try? FileManager.default.createDirectory(atPath: scratch, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: scratch) }
        let exec: TierBExecutionResult
        do {
            exec = try await TierBCollectorExecutor.runInstalled(
                pluginID: pluginID, scratchDir: scratch,
                officialSource: ctx.officialSource, catalogOverrideActive: ctx.catalogOverrideActive)
        } catch let e as TierBRegistry.RegistryError {
            switch e {
            case .notInstalled:                        return .notInstalled
            case .firstPartyExecutionRefused(_, let r): return .refusedFirstParty(reason: r)
            case .sandboxedExecutionRefused(_, let r):  return .sandboxFailed(reason: r)
            default:                                    return .sandboxFailed(reason: "\(e)")
            }
        } catch let e as SandboxedTierBRunner.RunnerError {
            return .sandboxFailed(reason: "\(e)")
        } catch let e as TierBCollectorExecutorError {
            return .sandboxFailed(reason: "\(e)")
        } catch {
            return .sandboxFailed(reason: shortReasonStatic(error))
        }

        let enc = ((try? await store.fetchCase(id: caseID)) ?? nil)?.encryptionState ?? .plaintext
        let invID = (try? await store.recordInvocationStart(
            caseID: caseID, pluginID: pluginID, pluginVersion: exec.manifest.version, inputsJSON: "{}")) ?? ""
        let result = await TierBArtifactBridge.commit(
            outcome: exec.outcome, caseID: caseID, manifest: exec.manifest,
            caseAllowsSensitive: enc != .plaintext, output: StoreCollectorOutput(store: store))
        if !invID.isEmpty {
            try? await store.recordInvocationEnd(
                id: invID, exitStatus: result.status.rawValue,
                artifactsCommitted: Int64(result.artifactsCommitted),
                artifactsRejected: Int64(result.artifactsRejected),
                errorMessage: result.notes.isEmpty ? nil : result.notes.joined(separator: "; "),
                snapshotHash: nil)
        }
        // A run that committed nothing AND reported error/partial is NOT a
        // success — surface the terminal note ("plugin emitted no terminal
        // result", "plugin timed out", …) instead of a silent empty scan.
        if result.status == .error && result.artifactsCommitted == 0 {
            return .ranWithError(reason: result.notes.first ?? "run failed")
        }
        return .ran(rows: result.artifactsCommitted)
    }
```

(`shortReasonStatic` mirrors the existing instance helper `shortReason` at `Sources/MacCrabApp/V2/Forensics/KitRunner.swift:185-193`; since `runInstalledTierB` is `static`, either promote `shortReason` to `static` or inline `String("\(error)".split(separator: "\n").first ?? "")`. Keep whichever matches surrounding style — the file already has the instance version.)

**Step C — update the call site** (replaces `Sources/MacCrabApp/V2/Forensics/KitRunner.swift:89-97`) so refusals/failures become real skip reasons and only a genuine unknown keeps the old string:

```swift
                    let outcome = await Self.runInstalledTierB(
                        pluginID: pref.pluginID, store: handle.store, caseID: handle.caseID)
                    switch outcome {
                    case .ran:
                        break   // committed — tallied from the store below
                    case .notInstalled:
                        skipped.append(SkippedPlugin(
                            pluginID: pref.pluginID,
                            reason: "not a built-in and not an installed Tier-B plugin"))
                    case .refusedFirstParty(let r):
                        skipped.append(SkippedPlugin(
                            pluginID: pref.pluginID,
                            reason: "first-party execution refused: \(r)"))
                    case .sandboxFailed(let r):
                        skipped.append(SkippedPlugin(
                            pluginID: pref.pluginID,
                            reason: "sandboxed run failed: \(r)"))
                    case .ranWithError(let r):
                        skipped.append(SkippedPlugin(
                            pluginID: pref.pluginID,
                            reason: r))
                    }
                    continue
```

### 3.3 Why this is the right/minimal shape

- The done banner already iterates `skipped` and renders each `reason` verbatim (`V2ForensicsScansView.swift:670-680`), so no view change is needed — the fix is purely "stop feeding it a generic string / stop swallowing the errored run."
- No existing code or test calls `runInstalledTierB` (only the one internal call site at `KitRunner.swift:89`; a repo-wide grep finds no other callers and no test references), so changing its return type from `Bool` to `KitRunOutcome` is a self-contained, non-breaking edit.
- The `enum` names the exact three lanes the executor dispatches (`TierBCollectorExecutor` docstring, `Sources/MacCrabForensics/TierB/TierBCollectorExecutor.swift:6-13`), plus a `notInstalled` case so the *one* previously-accurate generic message is preserved and a `ranWithError` case so a spawned-but-empty errored run (the literal §0 tail) is no longer reported as success.
- **This is an observability fix only.** It changes *what the operator sees*, not the trust decision. The plugin still legitimately does not run until FIX 1 sets `FirstPartyTrustRoot.publisherKeyFingerprint` (`Sources/MacCrabForensics/TierB/FirstPartyTrustRoot.swift:38`); after this fix the banner will say "first-party execution refused: first-party publisher key not configured (fail-closed)" instead of "not a built-in and not an installed Tier-B plugin," which is the honest diagnosis.
---

## §4 — FIX 3 (CONTEXT): the sandbox trampoline is correct; only LANE SELECTION is wrong

### 4.1 Correction to the stale "gap-C" story

An earlier reading blamed the symptom (`Status: error … Artifacts committed: 0 … plugin emitted no terminal result`) on the sandbox being unable to read the paths posture-pro needs. **That is wrong.** The SBPL profile *does* consume the manifest's declared capabilities, and the sandboxed lane runs the plugin correctly for a genuine third-party plugin. The bug is upstream: **posture-pro is being routed down the sandboxed third-party lane at all**, because Fix 1's first-party anchor is unconfigured. Fix 3 is therefore purely *context* — it explains why the sandbox path is a red herring and what the sandboxed lane legitimately needs — and requires **no code change of its own**; the actual repair is Fix 1 (configure the anchor so lane selection picks the first-party lane).

### 4.2 The SBPL / broker DOES grant the manifest's capabilities

**Manifest → SBPL spec.** For the sandboxed lane, `SandboxedTierBRunner.run` derives the profile spec straight from the plugin's own manifest:

```swift
// SandboxedTierBRunner.swift:348-349
let spec = verified.manifest.toBrokeredSandboxProfileSpec(scratchDir: scratchDir)
let profile = SandboxProfileBuilder.compileTrampolineDenyDefault(spec, selfExecPath: canonicalExec)
```

`toBrokeredSandboxProfileSpec` faithfully carries `networkConnectAllowlist`, `machServiceConnects`, `processExecPaths`, and `allowProcessFork` from the manifest into the spec (only file *reads* are deliberately emptied — they are served by the broker, not the SBPL):

```swift
// TierBManifest.swift:162-172
public func toBrokeredSandboxProfileSpec(scratchDir: String) -> SandboxProfileSpec {
    SandboxProfileSpec(
        allowAllByDefault: false,
        fileReadSubpaths: [],                                  // brokered — never in the SBPL
        fileWriteSubpaths: fileWriteSubpaths + [scratchDir],
        networkConnectAllowlist: networkConnectAllowlist,
        machServiceConnects: machServiceConnects,
        processExecPaths: processExecPaths,
        allowProcessFork: allowProcessFork
    )
}
```

**SBPL emission consumes those fields.** `SandboxProfileBuilder.compileDenyDefault` (the base of the trampoline profile) emits an explicit `(allow …)` clause for each manifest-declared capability — including the exact `processExecPaths` and `allowProcessFork` posture-pro declares (`fdesetup`, `spctl`, `socketfilterfw`, `systemextensionsctl`, `kmutil`, `profiles`, `sfltool`; `allowProcessFork=true`):

```swift
// SandboxProfileBuilder.swift:282-289
if !spec.processExecPaths.isEmpty {
    lines.append(";; Manifest exec allowlist (else exec stays denied).")
    for p in spec.processExecPaths { lines.append("(allow process-exec (literal \(quoted(p))))") }
}
if spec.allowProcessFork {
    lines.append(";; Manifest opted into fork/posix_spawn.")
    lines.append("(allow process-fork)")
}
```

**File reads are brokered, not blocked.** posture-pro's `fileReadSubpaths` (`/Library/LaunchDaemons`, `/Library/LaunchAgents`, the two `XProtect.bundle` paths, `/Library/Application Support/com.apple.TCC`) are not silently dropped — they are snapshotted and served over fd 3 by the file broker:

```swift
// SandboxedTierBRunner.swift:333-337
let readPlan = BrokeredTCC.prepare(
    manifestReadPaths: verified.manifest.fileReadSubpaths,
    snapshotDir: snapshotDir,
    home: NSHomeDirectory())
let brokerPolicy = readPlan.brokerPolicy(scratchDir: scratchDir)
```

So the "sandbox can't read the paths" story is refuted: reads are brokered, execs/fork/network/mach are emitted into the SBPL verbatim from the manifest. **The sandbox is not the blocker.**

### 4.3 The trampoline itself is faithful (keep it)

The signed `maccrab-tierb-sandbox-host` trampoline (`Sources/maccrab-tierb-sandbox-host/main.c`) does exactly one job: validate + apply the host-written deny-default SBPL to itself via `sandbox_init`, then `execv` the verified plugin. It adds no policy of its own beyond the load-bearing content assertion that the profile is genuinely deny-default:

```c
// main.c:214, 232
int rc = sandbox_init(profile, 0, &sb_err);
...
execv(exec_path, child_argv);
```

The `--exec` target is the host-canonicalised verified-binary temp, not any attacker-named path:

```swift
// SandboxedTierBRunner.swift:344, 371-376
let canonicalExec = Self.canonicalPath(verified.binaryPath)
...
let argvStrings = Self.trampolineArguments(
    trampolinePath: trampolinePath,
    profilePath: profilePath,
    execPath: canonicalExec,
    limits: limits
)
```

This entire path is **correct for a genuinely third-party / sideloaded plugin** and must be kept. The FIX 3 conclusion is *don't touch the trampoline* — a first-party plugin simply must not enter this lane.

### 4.4 Why posture-pro wrongly enters the sandboxed lane (the real blocker = lane selection)

`TierBCollectorExecutor.runInstalled` tries the first-party lane first and only falls back to the sandboxed lane on `firstPartyExecutionRefused`:

```swift
// TierBCollectorExecutor.swift:67-79
do {
    verified = try await registry.resolveForFirstPartyExecution(...)
    sandboxed = false
} catch let e as TierBRegistry.RegistryError {
    guard case .firstPartyExecutionRefused = e else { throw e }
    verified = try await registry.resolveForSandboxedExecution(...)
    sandboxed = true
}
```

The first-party gate fail-closes on the very first clause because the compiled-in anchor is `unsetSentinel` (`FirstPartyTrustRoot.isConfigured == false`, per the established facts), so `anchorConfigured` is false:

```swift
// FirstPartyExecutionGate.swift:41-43
guard anchorConfigured else {
    return .deny(reason: "first-party publisher key not configured (fail-closed)")
}
```

That deny becomes `firstPartyExecutionRefused` (TierBRegistry.swift:259-264), which the executor catches and re-routes into `resolveForSandboxedExecution`. There, because the anchor is unconfigured, the disjoint-lane "is this the first-party publisher?" check evaluates false and the plugin is *permitted* to run sandboxed:

```swift
// TierBRegistry.swift:332-334
let anchorMatch = firstPartyAnchorConfigured
    && got.count == 64 && want.count == 64
    && got.allSatisfy({ $0.isHexDigit }) && got == want
```

Net effect: a `com.maccrab.forensics.*` first-party plugin runs down the sandboxed lane (`lane == .sandboxed`, TierBCollectorExecutor.swift:100), which is exactly the observed symptom. **Fix 1 (setting `FirstPartyTrustRoot.publisherKeyFingerprint` to the real fingerprint) flips `anchorConfigured` true, the first-party gate's fingerprint match then succeeds (FirstPartyExecutionGate.swift:56-59), and posture-pro takes the unsandboxed first-party lane via `FirstPartyTierBRunner` (TierBCollectorExecutor.swift:96-97).** No change to Fix 3's surface is needed.

### 4.5 What the trampoline lane needs from the request wiring (TierBCollectRequest on stdin)

Both lanes speak the same frozen TierBIPC contract: the host writes **one `TierBCollectRequest` JSON line to stdin, then closes stdin**, and the plugin replies with zero-or-more `artifact` JSONL lines and exactly one terminal `result` line (TierBIPC.swift:5-11). The stdin delivery is identical for first-party and sandboxed lanes because both go through `TierBSubprocess.spawnAndStream(request:)`:

```swift
// TierBSubprocess.swift:190-196
let reqEncoder = JSONEncoder()
reqEncoder.outputFormatting = [.withoutEscapingSlashes]
if let reqData = try? reqEncoder.encode(request) {
    try? inWrite.write(contentsOf: reqData)
    try? inWrite.write(contentsOf: Data([0x0A]))
}
try? inWrite.close()
```

The request the sandboxed lane sends is built in `SandboxedTierBRunner.run`:

```swift
// SandboxedTierBRunner.swift:403-408
request: TierBCollectRequest(
    pluginID: verified.pluginID,
    pluginVersion: verified.manifest.version,
    scratchDir: scratchDir,
    windowStartUnix: windowStartUnix,
    windowEndUnix: windowEndUnix),
```

The stdin fds survive the trampoline: `TierBSubprocess` dups the pipe onto fd 0 of the child (TierBSubprocess.swift:92), and the trampoline inherits fds 0/1/2 (plus the reserved broker fd 3) across its `execv` — documented in the trampoline's own contract header (`stdin/stdout/stderr (fds 0/1/2) and the reserved broker fd 3 are inherited across execv unchanged`, main.c:26-28) and preserved by `close_inherited_fds()` which closes only fds ≥ 4 (main.c:159-162, 230). So the request reaches the plugin unchanged whether or not the trampoline is in the path.

**This is the operational meaning of "the standalone binary prints `no valid TierBCollectRequest on stdin` when run bare, and emits its full artifact set when given a proper request":** the plugin is request-driven. When invoked directly with no stdin frame it has nothing to act on; when the host feeds it a well-formed `TierBCollectRequest` line it produces its artifacts + terminal `result`. The reference collector in-repo shows the stdout side of the same contract (a `kind:"artifact"` line followed by a single `kind:"result"` line):

```c
// maccrab-tierb-example/main.c:26-31
fputs("{\"kind\":\"artifact\",\"artifact\":{"
      "\"contentType\":\"example.heartbeat\",\"privacyClass\":\"metadata\","
      "\"summary\":\"reference collector ran\",\"data\":{\"ok\":true}}}\n", stdout);
fputs("{\"kind\":\"result\",\"result\":{\"status\":\"ok\","
      "\"notes\":[\"maccrab-tierb-example: nothing to collect, all good\"]}}\n", stdout);
```

Because the request wiring is shared and lane-agnostic, Fix 3 needs nothing here either — the request already reaches posture-pro correctly on whichever lane it runs. The only remaining action is Fix 1's lane correction so posture-pro runs unsandboxed (its declared `processExecPaths` then run natively rather than through the contained profile).

---

## §5 — Build / sign / notarize

Fix 1 changes a source constant that is baked into the **signed** app binary, so its custody equals the app binary's — it must be set at the offline ceremony and built on the trusted Mac (never read from file/env; see §2.3).

1. Apply Fix 1 (§2.1) + the two test updates (§2.5); optionally Fix 2 (§3) and Fix 3's context note (§4).
2. `swift test` → green. The suite is 2706 tests / 483 suites; the only expected changes are the two §2.5 assertions flipping from "unconfigured" to "configured".
3. `scripts/prerelease-check.sh <version>` → 0 errors.
4. `VERSION=<version> ./scripts/build-release.sh` (local RC) or `./scripts/release.sh <version>` (GA) → Developer-ID sign + notarize + staple. (release.sh derives the site token from the login-Keychain git credential; the stapling fix is already in `notarize.sh`.)
5. Install the DMG, then re-run the §0 command and confirm §6.

---

## §6 — Acceptance criteria

- **CLI lane + rows:** `maccrabctl plugin run com.maccrab.forensics.posture-pro --case <id>` prints **`Ran first-party Tier-B collector …`** (not "sandboxed third-party"), `Status: ok` (or `partial`), and **`Artifacts committed: N` with N > 0**.
- **App scan commits rows:** a Forensics scan that includes posture-pro commits its artifacts to the case (the case shows posture rows, not an empty result).
- **Refusals are legible (Fix 2):** when first-party execution *is* legitimately refused (non-official source, mismatched key, override active), the dashboard skipped-plugins banner shows the real reason (e.g. `first-party publisher key not configured (fail-closed)` / `bundle is not signed by the first-party publisher key`) — not the generic "not a built-in and not an installed Tier-B plugin".
- **Third-party unaffected:** an actual third-party / sideloaded plugin still runs sandboxed (or is refused fail-closed). Fix 1 authorizes exactly the one posture-pro publisher key (§2.4) — it is not a blanket first-party authorization.
- **Tests:** the two §2.5 updates applied; every pure-gate invariant kept and green.

---
## Appendix A — Evidence

### A.1 Install-dir inspection

```
$ ls -la ~/Library/Application\ Support/MacCrab/plugins/com.maccrab.forensics.posture-pro/
-rwxr-xr-x   671656   binary            # the collector executable (has a `--run` stdin-collect mode)
-rw-r--r--     1239   manifest.json     # kind=collector; reads /Library/LaunchDaemons, LaunchAgents,
                                        #   XProtect.bundle ×2, /Library/Application Support/com.apple.TCC;
                                        #   exec fdesetup/spctl/socketfilterfw/systemextensionsctl/kmutil/
                                        #   profiles/sfltool; network denied; allowProcessFork=true
-rw-r--r--       64   signature         # Ed25519 signature over manifest+binary
-rw-r--r--       32   signing.key.pub   # Ed25519 publisher public key (raw 32 bytes)
```

### A.2 Fingerprint derivation — why `07e39eb1…` (the Fix-1 value)

```
$ shasum -a 256 ~/Library/Application\ Support/MacCrab/plugins/com.maccrab.forensics.posture-pro/signing.key.pub
07e39eb12c15b8052f5249134ea3337a0789ebc799d1c58d097aaa548a8aaae3
```

This is exactly `FirstPartyTrustRoot.fingerprint(ofSigningKey:)` — SHA-256 lowercase-hex of the raw public-key bytes (`FirstPartyTrustRoot.swift:49-51`) — i.e. the value the gate compares against (`FirstPartyExecutionGate.swift:56`, via `TierBRegistry.swift:143`). Baking this into `FirstPartyTrustRoot.swift:38` (§2.1) makes the compiled-in anchor byte-equal the installed bundle's fingerprint, so the gate's `got == want` passes and posture-pro takes the first-party lane.

### A.3 Standalone-emits-220-artifacts proof (the plugin works; the lane is the blocker)

```
$ echo '{"protocolVersion":1,"pluginID":"com.maccrab.forensics.posture-pro","pluginVersion":"0.3.0","scratchDir":"/tmp/pp-scratch"}' \
    | ~/Library/Application\ Support/MacCrab/plugins/com.maccrab.forensics.posture-pro/binary --run \
    | grep -c '"kind":"artifact"'
220
```

- **Standalone (direct reads):** 220 artifacts, terminal `status: partial`.
- **Via `maccrabctl plugin run` (sandboxed fallback lane):** 0 artifacts, `plugin emitted no terminal result`.

Same binary, same host — the only difference is the execution lane. Run bare (no stdin request) the binary correctly prints `no valid TierBCollectRequest on stdin`, confirming it honors the frozen `TierBIPC` request-on-stdin contract that both lanes use.

---

*Spec grounded by: live reproduction on the installed build (§0, Appendix A) + a read-only multi-agent code trace of the TierB execution path (§1–§4), each finding cited to exact `file:line`. Fix 1 is a keyholder ceremony action, not a routine edit — see §2.3.*
