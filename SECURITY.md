# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |
| < 1.0   | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in MacCrab, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

1. Email **maccrab@peterhanily.com** with:
   - A description of the vulnerability
   - Steps to reproduce
   - Affected versions
   - Potential impact
   - Suggested fix (optional)

2. You will receive an acknowledgment within **48 hours**.
3. We aim to provide a fix or mitigation within **7 days** for critical issues.
4. We will coordinate disclosure timing with you.

### What Qualifies

- Bypass of detection rules or prevention mechanisms
- Privilege escalation via MacCrab components
- Data exposure (events, alerts, API keys)
- Denial of service against the detection pipeline
- MCP server vulnerabilities
- Rule injection or tampering
- **Sandbox escape from the third-party forensic-plugin lane** — any way an
  untrusted plugin reads outside its brokered allowlist, reaches the live TCC
  stores, escapes the deny-default sandbox, or abuses the host's Full Disk Access

### What Does NOT Qualify

- Issues requiring physical access to an unlocked machine
- Social engineering attacks
- Denial of service via system resource exhaustion (macOS-level)
- Issues in third-party dependencies not shipped by MacCrab

## Threat Model

MacCrab assumes the following trust boundaries:

### Trusted

- The macOS kernel and Endpoint Security framework
- Apple-signed system binaries (`/System/`, `/usr/libexec/`)
- The user who installed and configured MacCrab
- System Extension bundle integrity (enforced by AMFI + notarization ticket; the `.systemextension` is signed with Developer ID and an embedded provisioning profile)

### Untrusted

- All user-space processes (monitored by the detection engine)
- Network traffic (monitored by collectors)
- External threat intelligence feeds (validated before use)
- LLM API responses (never auto-executed, always advisory)
- Clipboard content, browser extensions, USB devices
- **Third-party forensic plugins** (rave marketplace) — executed **only** under a
  deny-default sandbox with file reads brokered over a fd; TCC-protected stores
  (Messages, Mail, Safari, …) are served as host-made snapshots, never the live
  store; see the full lane in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) §8

### Out of Scope

MacCrab does **not** protect against:

- Kernel-level rootkits or bootkits
- DMA attacks (Thunderbolt/PCIe)
- Physical tampering with hardware
- Attacks by users with existing root access
- Nation-state adversaries with zero-day kernel exploits

## Security Architecture

### Privilege Model

- **MacCrabAgent** (System Extension) runs under `sysextd` with the ES entitlement, in a sandboxed userspace context elevated by Apple. On release builds this replaces the legacy root-daemon model
- **maccrabd** (legacy) runs as root — retained only for local development when no ES entitlement is available; falls back through `eslogger` → `kdebug` → FSEvents
- **maccrabctl** runs as the invoking user (reads database only)
- **MacCrab.app** runs as the logged-in user (reads database; activates and replaces the System Extension)
- **maccrab-mcp** runs as the invoking user (reads database, can suppress alerts)

### Data Protection

- SQLite databases use WAL mode with `0o660` permissions (admin-group
  read-write: the root sysext writes them and the admin-group dashboard reads /
  suppresses — **not** world-readable). The key is encrypted at rest in Keychain
- Optional AES-256 field-level encryption (key stored in macOS Keychain)
- Compiled rules are **world-readable by design** (`0o755` dir / `0o644` files):
  the non-root app reads them for rule display + integrity hashing. They carry no
  secrets; this is intentional, not `0o700`
- Symlink validation (`O_NOFOLLOW`) on all privileged file writes

### LLM Safety

- All LLM features are **optional** and degrade gracefully when disabled
- Cloud API calls sanitize: usernames, private IPs, hostnames, email addresses
- LLM responses are **never auto-executed** — always advisory/informational
- Circuit breaker: 3 failures trigger 5-minute cooldown
- Rate limiting: minimum 5-second interval between queries
- Response size cap: 50KB maximum

### MCP Server Security

- Communicates via stdio (scoped to the launching process)
- Parent process identity logged at startup
- State-modifying operations (suppress_alert) are audit-logged
- Input validation on all parameters (length limits, format checks)
- Parse errors return generic messages (no request body leakage)

### Third-Party Plugin Execution (rave marketplace)

The forensic-plugin marketplace runs code MacCrab does not author on an
FDA/TCC host. It is the most security-sensitive surface in the product and is
documented in full as in-scope attacker #8 in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). In brief:

- First-party (MacCrab-signed) and untrusted third-party plugins run in **two
  disjoint lanes**; untrusted code runs **only** under a deny-default sandbox.
- A signed trampoline applies the `(deny default)` SBPL post-startup; a
  per-invocation **broker** is the file boundary (reads brokered over a fd, every
  component `O_NOFOLLOW`); TCC stores are served as **snapshots**, never live; no
  global mach-lookup, no metadata side channel on crown-jewels.
- Containment is **proved** by an adversarial corpus (`make test-corpus`) against
  the exact shipped runner, for both C and Swift fixtures.
- The runnable third-party lane ships **fail-closed** and is GA-gated on the
  publisher-key ceremony + an independent external pentest.

### Release & Distribution Chain

How MacCrab releases reach end-users is itself part of the trust
boundary — see `RELEASE_PROCESS.md` for the full operator-side
pipeline.

- Each release DMG is signed with **Developer ID Application: Peter Hanily (`79S425CW99`)**, notarized by Apple, and the notarization ticket is stapled to the DMG before publication.
- Sparkle auto-updates are gated by an **EdDSA signature** over the DMG bytes. The matching public key (`de+dzPjB…`) is embedded in every shipped `MacCrabApp` Info.plist under `SUPublicEDKey`. A swapped DMG fails verification BEFORE unpacking.
- The appcast XML is hosted at `https://maccrab.com/appcast.xml` (Cloudflare Pages, source repo `peterhanily/maccrab-site`).
- End-user verification — `shasum`, `codesign -dvv`, `spctl -a`, `xcrun stapler validate` — is documented step-by-step in `docs/TRUST.md`.
- Key custody, rollback procedures, and the operator's release preconditions are documented in `RELEASE_PROCESS.md`. Reviewers evaluating the supply-chain posture should start there.
