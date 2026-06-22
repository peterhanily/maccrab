# Authoring a MacCrab Tier-B Forensic Plugin

A contributor guide for writing, signing, testing, and shipping a third-party
**Tier-B** forensic collector for MacCrab.

Everything below is grounded in the actual wire contract and CLI. The
load-bearing source files are:

| Concern | File |
|---------|------|
| Frozen IPC contract | `Sources/MacCrabForensics/TierB/TierBIPC.swift` |
| Manifest schema | `Sources/MacCrabForensics/TierB/TierBManifest.swift` |
| Reference collector | `Sources/maccrab-tierb-example/main.c` |
| File broker (host side) | `Sources/MacCrabForensics/TierB/TierBFileBroker.swift` |
| Broker SCM_RIGHTS transport | `Sources/CTierBBroker/` |
| Signed payload | `Sources/MacCrabForensics/TierB/PluginSignatureVerifier.swift` |
| CLI authoring loop | `Sources/maccrabctl/PluginCommands.swift` |
| Containment corpus | `Tests/MacCrabForensicsTests/ContainmentCorpusTests.swift` |

---

## 1. Overview

A **Tier-B plugin** is a standalone executable that MacCrab spawns
**out-of-process** to collect forensic artifacts into a case. Distinguishing
properties:

- **Collector-only.** A Tier-B bundle declares `kind: "collector"`. The
  `analyzer` kind exists in the enum but **analyzer execution is not
  supported** — there is no analyzer runner today, so only collectors are
  dispatched (`TierBManifest.swift`, `TierBPluginKind`).
- **Runs sandboxed, deny-default ("Model B").** A third-party plugin runs under
  a `(deny default)` macOS sandbox profile. It gets **no** ambient file reads,
  **no** network, **no** fork/exec — nothing it did not declare *and* the
  operator did not consent to. Capabilities are added by allowlist only; omit a
  capability and it is denied.
- **Talks a frozen JSONL contract.** The host writes one request to your
  plugin's stdin and reads artifact + result lines from its stdout. That is the
  entire interface for a metadata-only collector.
- **Files come from a broker, not `open()`.** Because reads are not in the
  sandbox profile, a plugin that needs a file asks the **file broker** over
  **fd 3** and receives an already-open descriptor. A metadata-only collector
  (like the reference example) never touches fd 3.

### Trust model

Your plugin runs only if its publisher key is trusted. Two paths:

1. **Operator-trusts-your-key (sideload).** You publish your Ed25519 public key;
   an operator runs `maccrabctl plugin trust <hex>` (or
   `install --trust-on-install`) and TOFU-vouches for your code. It still runs
   sandboxed. Provenance is shown as *third-party · sideloaded · unverified*.
2. **Rave-catalog-curated.** You submit to the rave catalog, which vets and
   countersigns the bundle; operators install by plugin-id and the install path
   verifies the catalog signature + artifact hash before delegating to the local
   install. (Catalog submission lives in the separate `maccrab-rave` repo and is
   out of scope here — see §8.)

Either way the **sandbox is the same**. Trust gates *whether it runs*, not *what
it can reach*; the sandbox + broker gate that.

---

## 2. The bundle layout

A signed plugin bundle is a **directory** with these files
(`PluginSignatureVerifier.BundleLayout`):

```
my-plugin/
  manifest.json     # the Tier-B manifest (you write this)
  binary            # your compiled executable, named exactly "binary"
  signature         # raw 64-byte Ed25519 signature   (written by `plugin sign`)
  signing.key.pub   # 32-byte Ed25519 public key       (written by `plugin sign`)
```

You author `manifest.json` and `binary`. The last two are produced by
`maccrabctl plugin sign`. The executable **must be named `binary`** — the
verifier looks for exactly that name.

> Keep `signing.key` (your private key) **out of the bundle and offline.**
> `keygen` writes it `0600` and the help text repeats: never commit it, never
> place it in a bundle.

---

## 3. The `manifest.json` schema

From `TierBManifest`. Decode is lenient: only
`id`, `displayName`, `version`, `schemaVersion`, `description` are **required**.
Every capability array and consent field is optional.

### Identity (required)

| Field | Type | Notes |
|-------|------|-------|
| `id` | string | Reverse-DNS, e.g. `com.acme.chathistory`. The `com.maccrab.*` namespace is **reserved** for first-party — installing under it is refused (`RaveNamespaceGuard`). |
| `displayName` | string | Human label. A name confusable with a first-party plugin is refused. |
| `version` | string | Semver, e.g. `"1.0.0"`. |
| `schemaVersion` | int | Manifest schema version. Use `1`. |
| `description` | string | One-line purpose. |
| `kind` | `"collector"` \| `"analyzer"` | Optional; absent ≈ collector. Only `collector` executes. |

### The six capability fields — **omit = deny**

These are the *enforced* capabilities. They are mapped faithfully into the
sandbox profile (`toSandboxProfileSpec` / `toBrokeredSandboxProfileSpec`). If you
omit a field, the array defaults to `[]` (deny); `allowProcessFork` defaults to
`false` (deny). There is no permissive default anywhere — `allowAllByDefault` is
hardcoded `false` for Tier B.

| Field | Type | Default | Effect |
|-------|------|---------|--------|
| `fileReadSubpaths` | `[string]` | `[]` | Read roots. **Served via the broker**, never placed in the SBPL (see §5). |
| `fileWriteSubpaths` | `[string]` | `[]` | Write roots (in addition to the host-owned scratch dir, which is always writable). |
| `networkConnectAllowlist` | `[string]` | `[]` | `ip:port` endpoints the plugin may connect to. Empty = deny all network. |
| `machServiceConnects` | `[string]` | `[]` | Mach services the plugin may look up. Empty = deny all. |
| `processExecPaths` | `[string]` | `[]` | Executables the plugin may spawn. Empty = deny exec. |
| `allowProcessFork` | bool | `false` | Whether `fork`/`posix_spawn` is allowed at all. |

> **Historical note (so you trust the default):** `allowProcessFork` used to be
> hardcoded `true` and `machServiceConnects` / `processExecPaths` were discarded
> — the "decorative capability" gap. That is fixed: all six fields are now
> enforced and fork defaults FALSE.

### Consent disclosure fields (author labels)

| Field | Type | Notes |
|-------|------|-------|
| `privacyClass` | string | Highest class you *claim* to emit: `metadata`, `content`, `personalComms`, `credentialAdjacent`, `secret`. |
| `dataSources` | `[string]` | Human read-set labels, e.g. `["Messages chat.db"]`. |
| `tccRequirements` | `[string]` | TCC services needed, e.g. `["FullDiskAccess"]`. |

**Consent is DERIVED, not declared — you cannot under-declare.** The consent
sheet the storefront/CLI renders comes from `consentSummary()`, which is computed
from the **enforced** `fileReadSubpaths` / `networkConnectAllowlist` /
`processExecPaths` / `allowProcessFork`, *not* from your `privacyClass` label:

- Any `fileReadSubpaths` entry that resolves to a TCC-protected store
  (e.g. `chat.db`) is classified `personalComms` regardless of what you wrote.
- A non-empty read set with no TCC paths derives `content`.
- An empty read set derives `metadata`.
- If your declared `privacyClass` is *lower* than the derived class, the summary
  sets `privacyUnderdeclared = true` and the UI shows the derived class plus a
  `⚠ author under-declared` flag.
- A personal-comms reader that *also* declares network egress is flagged
  `isDisclosedExfilSurface` and requires a separate confirmation.

Because the consent surface is derived from the **signed** manifest, a tampered
catalog cannot soften it either.

### Worked example: a Messages history collector that reads `chat.db`

```json
{
  "id": "com.acme.imessage-urls",
  "displayName": "iMessage URL Extractor",
  "version": "1.0.0",
  "schemaVersion": 1,
  "description": "Extracts URLs shared in Messages from chat.db.",
  "kind": "collector",
  "fileReadSubpaths": [
    "/Users/me/Library/Messages/chat.db"
  ],
  "networkConnectAllowlist": [],
  "machServiceConnects": [],
  "processExecPaths": [],
  "allowProcessFork": false,
  "privacyClass": "personalComms",
  "dataSources": ["Messages chat.db"],
  "tccRequirements": ["FullDiskAccess"]
}
```

Here the derived consent class is `personalComms` (a TCC-protected read), so the
declared `personalComms` matches and nothing is flagged. The read is **brokered**
— served as a snapshot, not the live store (§5).

---

## 4. The IPC contract (frozen, `protocolVersion = 1`)

`TierBIPC.swift` is the single source of truth and is **frozen** — both the host
and your plugin build to exactly this.

**Flow:**

1. The host spawns your verified binary with a scrubbed environment (PATH + HOME).
2. The host writes **one** `TierBCollectRequest` JSON line to stdin, then closes
   stdin.
3. Your plugin emits zero or more `artifact` JSON lines, then **exactly one**
   `result` line, one JSON object per line (JSONL), on stdout.
4. Your plugin exits. The host streams + caps stdout, commits artifacts, cleans up.

### Request (host → plugin, stdin)

`TierBCollectRequest`, one JSON line:

```json
{"protocolVersion":1,"pluginID":"com.acme.imessage-urls","pluginVersion":"1.0.0","scratchDir":"/var/folders/…/maccrab-tierb-scratch-XXXX","windowStartUnix":1718000000,"windowEndUnix":null}
```

| Field | Type | Notes |
|-------|------|-------|
| `protocolVersion` | int | Always `1` in this build. Echo it if you emit it; a mismatch is a host hard error. |
| `pluginID`, `pluginVersion` | string | Identity for your own logging. |
| `scratchDir` | string | A host-owned scratch directory you **may write into**. Write **nowhere else**. |
| `windowStartUnix`, `windowEndUnix` | int64? | Optional collection window (unix seconds); `null` = unbounded. Honor it. |

You may ignore the request entirely if you have nothing to parse (the host
tolerates a plugin that never reads stdin — see the example). A real collector
parses it for `scratchDir` and the window.

### Output lines (plugin → host, stdout)

Each stdout line is exactly one `TierBOutputLine`, tagged by `kind`:

**Artifact line** — `kind:"artifact"` wrapping a `TierBArtifactDTO`
(**content only** — the host stamps identity):

| Field | Type | Notes |
|-------|------|-------|
| `contentType` | string | **Required.** Your artifact type, e.g. `"imessage.url"`. |
| `summary` | string? | Short human summary. |
| `data` | object | Arbitrary JSON payload. Defaults to `{}`. |
| `privacyClass` | string | `metadata`/`content`/`personalComms`/`credentialAdjacent`/`secret`. Defaults `"metadata"`. The host validates it against the case encryption state (a non-metadata artifact is rejected in a plaintext case). |
| `confidence` | string? | `observed`/`derived`/`heuristic`. Anything else or absent → `observed`. |
| `sourcePath` | string? | Untrusted free-text the host records but **never opens**. |
| `observedAtUnix`, `capturedAtUnix` | int64? | Timestamps. |
| `blobScratchName` | string? | **RESERVED — not implemented.** The host opens no plugin-named file and always sets `blobRelpath=nil`. Do **not** rely on it; the hero path is all-metadata. |

The host stamps `caseID`, `pluginID`, `pluginVersion`, `schemaVersion`,
`sizeBytes`, and `blobRelpath` itself from the verified manifest — the DTO
**cannot** carry them, so a plugin cannot spoof which case/plugin an artifact
belongs to.

**Result line** — `kind:"result"` wrapping a `TierBCollectResult`, the single
terminal line that closes the stream:

| Field | Type | Notes |
|-------|------|-------|
| `status` | string | **Required.** `ok` / `partial` / `error` / `cancelled`. |
| `notes` | `[string]` | Optional; defaults `[]`. |

### Worked example output

```jsonl
{"kind":"artifact","artifact":{"contentType":"imessage.url","privacyClass":"personalComms","summary":"https://example.com shared 2026-06-10","data":{"url":"https://example.com","handle":"+15551234567"},"confidence":"observed","observedAtUnix":1718052000}}
{"kind":"result","result":{"status":"ok","notes":["scanned 1 chat.db snapshot, 1 URL"]}}
```

### Host-enforced caps (you cannot opt out)

From `TierBIPC`: max **64 MB** total stdout, **4 MB** per line, **100 000**
artifacts per invocation, JSON nesting depth **64**, default timeout **120 s**.
The host streams and caps the whole time — it never buffers unbounded.

### The reference "hello world" (`Sources/maccrab-tierb-example/main.c`)

The simplest possible collector. It needs nothing but stdout, so it never reads
stdin and never touches fd 3 — which is also why it serves as the corpus ALLOW
fixture (F1):

```c
#include <stdio.h>
int main(void) {
    // One metadata artifact + the terminal result. Host stamps identity + re-hashes.
    fputs("{\"kind\":\"artifact\",\"artifact\":{"
          "\"contentType\":\"example.heartbeat\",\"privacyClass\":\"metadata\","
          "\"summary\":\"reference collector ran\",\"data\":{\"ok\":true}}}\n", stdout);
    fputs("{\"kind\":\"result\",\"result\":{\"status\":\"ok\","
          "\"notes\":[\"maccrab-tierb-example: nothing to collect, all good\"]}}\n", stdout);
    fflush(stdout);
    return 0;
}
```

Copy this, change the `contentType`/`data`, and you have a working metadata
collector. Always `fflush(stdout)` before exit.

---

## 5. Reading files under the sandbox: the fd-3 broker

A third-party plugin runs deny-default, so **direct `open()` of a declared path
is denied** — file reads are *not* in the SBPL
(`toBrokeredSandboxProfileSpec` sets `fileReadSubpaths: []` deliberately). The
broker is the file boundary. This is by design: it closes symlink/TOCTOU races
(a path can't be redirected out from under an already-open fd) and means the
sandbox never has to grant a read path at all.

**If your collector only emits metadata, you need none of this — skip fd 3.**

### How to request a file

The host attaches the host end of a socketpair as **fd 3** in the sandboxed lane.
To read a manifest-declared path, the plugin (over fd 3):

1. **Sends a request frame:** a **2-byte big-endian length** followed by that
   many UTF-8 path bytes (`TierBFileBroker.readRequest` / `encodeRequest`). The
   path must be absolute, NUL-free, contain no `.` or `..` component, and be ≤ the
   byte cap (`isValidRequestPath`).
2. **Receives a response** via `recvmsg`: a 1-byte status, with a file descriptor
   attached **only** on status `ok` (the `SCM_RIGHTS` transport in
   `Sources/CTierBBroker/broker.c`). Status bytes (`TierBFileBroker.Status`):

   | Byte | Meaning |
   |------|---------|
   | `0` `ok` | fd attached — read from it. |
   | `1` `denied` | not on the allowlist. |
   | `2` `openFailed` | allowlisted but safe-open failed (symlink / missing / not a regular file). |
   | `3` `badRequest` | malformed request frame. |

3. **Reads from the received fd** — an already-open descriptor, no `open()`
   syscall. Then `close()` it.

The reference C transport is `maccrab_tierb_recv_fd(int sock, int *out_fd)` in
`Sources/CTierBBroker/`: it reads the status byte and, if a descriptor was
attached, returns it via `*out_fd` (you own it and must close it). Link
`CTierBBroker` (or replicate its three `CMSG_*` calls) so the alignment math is
the platform's, not hand-rolled.

### What the broker guarantees on the host side

`TierBFileBroker.serve` validates every request against the manifest allowlist,
then `safeOpenReadOnly` opens each path component with `O_NOFOLLOW` beneath the
allowed root (a symlink anywhere in the relative path fails `ELOOP`), `fstat`s
the final fd for a single-link **regular file** (no dir/fifo/device/symlink, and
`st_nlink == 1` to reject hardlink escapes), and only then passes the fd back.
The serve loop is bounded on **count** (`maxRequests`, default 4096), **path
size** (`maxPathBytes`, 4096), per-read **time** (`SO_RCVTIMEO`, 30 s), and an
absolute **serve budget** (`maxServeSeconds`, 120 s) against slow-drip attacks. A
plugin that closes its read end mid-send cannot SIGPIPE-kill the host
(`SO_NOSIGPIPE`).

### TCC-protected sources are served as snapshots

If you declare a TCC-protected read (e.g. `chat.db`), the broker applies a
**redirect**: your request for the live path is served from a scratch
**snapshot** (`TierBFileBroker.Redirect`), so the plugin never names — and never
opens — the real protected store. You declare the natural path; the host hands
you an fd to a copy. (The live-snapshot extension is staged; declare the path as
above and the broker handles the redirect.)

---

## 6. The authoring loop

`maccrabctl plugin` is the contributor SDK. The loop is **keygen → write →
sign → test**.

### Step 1 — generate a signing keypair (once)

```console
$ maccrabctl plugin keygen --out ./keys
Generated Tier-B signing keypair:
  Private key:  ./keys/signing.key  (0600 — KEEP OFFLINE; never commit or place in a bundle)
  Public key:   ./keys/signing.key.pub
  Public hex:   3b9a…<64 hex chars>…f1
  Operators trust your plugins with:  maccrabctl plugin trust 3b9a…f1
```

This writes an Ed25519 keypair: `signing.key` (32-byte private, `0600`) and
`signing.key.pub`. Keep `signing.key` **offline**. The 64-char hex is your
publisher identity — operators trust it with `plugin trust <hex>`.

### Step 2 — write the bundle

```
my-plugin/
  manifest.json    # §3
  binary           # compiled, named exactly "binary"
```

For a C collector: `cc -O2 -o my-plugin/binary collector.c`.

### Step 3 — sign the bundle

```console
$ maccrabctl plugin sign ./my-plugin --key ./keys/signing.key
Signed bundle ./my-plugin
  Wrote signature + signing.key.pub.
  Publisher key: 3b9a…f1
```

`sign` writes `signature` (raw 64-byte Ed25519) and `signing.key.pub` into the
bundle. The signed payload is canonical and version-prefixed
(`PluginSignatureVerifier.canonicalSignedPayload`):

```
"maccrab-tierb-plugin-v1\n" || SHA-256(manifest.json) || SHA-256(binary)
```

Hash-then-sign keeps the large binary out of the signer; the verifier re-hashes
both files to verify. **Any** edit to `manifest.json` or `binary` after signing
invalidates the signature — re-sign after every change.

### Step 4 — test under the real sandbox

```console
$ maccrabctl plugin test ./my-plugin
Testing com.acme.imessage-urls v1.0.0
  Declared reads:   /Users/me/Library/Messages/chat.db
  TCC (brokered):   /Users/me/Library/Messages/chat.db
  Network:          deny
  Privacy class:    personalComms
Ran under the sandboxed lane:
  Exit code:    0
  Result:       ok
  Artifacts:    1
    - imessage.url: https://example.com shared 2026-06-10
  ✓ ran CONTAINED (deny-default sandbox; file reads brokered over fd 3).
```

`plugin test` installs the bundle into a throwaway plugins root, prints the
**derived** consent summary (flagging any under-declaration with
`⚠ author under-declared!`), then runs the binary under the **real** sandbox via
the sandboxed lane and shows containment. The `✓ ran CONTAINED` line confirms it
executed deny-default with reads brokered over fd 3. (`test` opts the dev
trampoline in via `MACCRAB_TIERB_DEV_TRAMPOLINE=1` because `swift build`
binaries are ad-hoc-signed.)

A metadata-only example would simply show `Declared reads: (none)`,
`Network: deny`, `Privacy class: metadata`, and one artifact.

---

## 7. Capability + privacy declaration honesty

Two checks make under-declaration ineffective:

1. **Capabilities are enforced, not advisory.** The six fields drive the actual
   sandbox profile. Omit `networkConnectAllowlist` → the OS denies the connect.
   Omit `allowProcessFork` → the OS denies the fork. You cannot reach a resource
   you did not declare, regardless of what your code attempts.
2. **Consent is derived from the enforced caps, not your labels.** As in §3, the
   consent summary is computed from `fileReadSubpaths` etc. Declare
   `privacyClass: "metadata"` while reading `chat.db` and `privacyUnderdeclared`
   trips; `plugin test`, sideload install, and the storefront all render the
   **derived** class plus a warning. A personal-comms reader with network egress
   is additionally flagged as a disclosed exfil surface.

The honest move is to declare the minimum caps you truly need and let the derived
class match your `privacyClass`. Over-broad declarations raise the consent
friction the operator sees; under-declaration is detected and flagged.

---

## 8. Shipping

### Operator sideload (TOFU)

You hand an operator the signed bundle directory. They run:

```console
$ maccrabctl plugin install ./my-plugin --trust-on-install
⚠ Sideloading UNVETTED third-party plugin 'com.acme.imessage-urls' v1.0.0
  Operator-vouched code with NO rave-catalog vetting. It runs sandboxed; review its access:
    File reads:     /Users/me/Library/Messages/chat.db
    ⚠ Personal/TCC: /Users/me/Library/Messages/chat.db  (served as brokered snapshots)
    Network:        deny
    Exec/fork:      deny
    Privacy class:  personalComms
  Type 'sideload' to proceed (or anything else to cancel): sideload
Installed (sideloaded) plugin 'com.acme.imessage-urls' — provenance: third-party · sideloaded · unverified
```

Notes:
- `install <bundle-dir>` is the **sideload** path (anything with a `/` or
  leading `.`/`~` is treated as a local path; a bare reverse-DNS id is treated as
  a catalog id).
- `--trust-on-install` adds your publisher key to the trust list in one step;
  otherwise the operator runs `maccrabctl plugin trust <hex>` separately.
- A bundle in the reserved `com.maccrab.*` namespace, or with a display name
  confusable with a first-party plugin, is **refused**.
- The sideload prints the **derived** consent (with the under-declared flag if
  applicable) and requires the operator to type `sideload` to proceed.
- It runs sandboxed regardless of trust; provenance stays
  *third-party · sideloaded · unverified*.

Operators run it against a case with:

```console
$ maccrabctl plugin run com.acme.imessage-urls --case CASE-123 --window 7d
```

and manage trust with `plugin trust` / `plugin revoke` / `plugin trust-list` /
`plugin verify` / `plugin status`.

### Submitting to the rave catalog (curated)

For a curated, install-by-id experience
(`maccrabctl plugin install com.acme.imessage-urls`), submit to the rave
catalog. The catalog vets the bundle, countersigns it, and serves
`catalog.json` + per-plugin entries; the install path verifies the catalog's
Ed25519 signature and the `artifact_sha256` before delegating to the local
install + verify path. **Catalog submission is handled in the separate
`maccrab-rave` repo and is out of scope for this guide.** (In this build,
`plugin search` / `update` / `pin` are stubs pending the catalog fetcher.)

---

## 9. Containment guarantees & limits

What the runtime guarantees about your (or any) Tier-B plugin:

- **Deny-default sandbox.** The base profile is `(deny default)`, never
  `(allow default)`. No fork, exec, or network unless declared **and** consented.
  (`SandboxDenyDefaultTests`: empty spec denies fork/exec/network by omission;
  fork stays denied unless declared even when other caps are present.)
- **Reads are brokered.** File reads are not in the SBPL; the broker opens each
  path component `O_NOFOLLOW` beneath the allowlisted root, serves regular files
  only, rejects hardlinks (`st_nlink == 1`), and applies TCC snapshot redirects.
  A symlink/TOCTOU race cannot escape the allowed root.
- **No identity spoofing.** Host-authoritative fields (case/plugin/version/size/
  blob path) are stamped by the host from the verified manifest; the artifact DTO
  cannot carry them.
- **Blob ingest is absent.** `blobScratchName` is decoded but the host opens no
  plugin-named file — the riskiest IPC surface stays off until a hardened,
  traversal-validating ingest lands.
- **Resource limits.** stdout ≤ 64 MB, line ≤ 4 MB, ≤ 100 000 artifacts, JSON
  depth ≤ 64, 120 s default timeout; the broker is bounded on request count,
  path size, per-read time, and total serve time. The host can't be
  SIGPIPE-killed by a plugin closing a pipe.

**The corpus that proves it** —
`Tests/MacCrabForensicsTests/ContainmentCorpusTests.swift`:

- **ALLOW F1** — a benign plugin (the reference example) runs and emits its
  result under the deny-default sandbox.
- **ALLOW F2** — a declared read is served through the broker over fd 3.
- **DENY F4 / F9 / F11** — an undeclared file open, undeclared network egress,
  and a fork are all denied by the OS; the host commits **zero** `leak.*`
  artifacts.

Supporting suites: `SandboxDenyDefaultTests`, `SandboxedTierBRunnerTests`,
`TierBFileBrokerTests`, `TierBBrokeredTCCTests`, `TierBIPCTests`,
`PluginSignatureVerifierTests`, `ThirdPartyExecutionGateTests`.

### Limits to design around

- **Collector-only.** Analyzers don't execute. Emit findings as artifacts.
- **All-metadata is the hero path.** No blob ingest yet — return your evidence as
  structured `data` on artifacts, not as files via `blobScratchName`.
- **Write only to `scratchDir`** (and any declared `fileWriteSubpaths`).
- **Honor the window** (`windowStartUnix` / `windowEndUnix`) — collect only
  within it when provided.
- **Re-sign after every edit** — any change to `manifest.json` or `binary`
  invalidates the signature.
