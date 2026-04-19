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

- SQLite database uses WAL mode with `0600` file permissions
- Optional AES-256 field-level encryption (key stored in macOS Keychain)
- Compiled rules directory uses `0700` permissions
- Symlink validation on all privileged file writes

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
