# macOS Endpoint Prevention Capabilities Research

Research date: 2026-04-05 | macOS 26.3 (Apple Silicon M4) | MacCrab context

This document surveys every practical mechanism available on macOS for **blocking
threats before they execute**, as opposed to detecting them after the fact.
Each section covers what it prevents, requirements, performance impact, and
what MacCrab could use it for.

---

## Table of Contents

1. [ES AUTH Events](#1-endpoint-security-auth-events)
2. [PF Packet Filter](#2-macos-packet-filter-pf)
3. [File System Protection](#3-file-system-protection)
4. [Binary Authorization (Santa model)](#4-binary-authorization)
5. [Network Extension Framework](#5-network-extension-framework)
6. [TCC Management](#6-tcc-management)
7. [MDM / Configuration Profiles](#7-mdm--configuration-profiles)
8. [Application Sandbox](#8-application-sandbox)
9. [Launch Constraints](#9-launch-constraints-macos-13)
10. [macOS Sequoia (15) / macOS 26 New Features](#10-macos-1526-new-security-features)
11. [Summary: What MacCrab Can Use Today vs With Entitlement](#11-practical-summary-for-maccrab)

---

## 1. Endpoint Security AUTH Events

### Overview

The Endpoint Security (ES) framework distinguishes between two event categories:

- **NOTIFY events** (105 types on macOS 26): Inform the subscriber after an
  operation has already occurred. Asynchronous -- the operation proceeds
  regardless of subscriber processing time.
- **AUTH events** (44 types on macOS 26): Block the operation in the kernel until
  the subscriber responds with ALLOW or DENY. Synchronous -- the syscall is held
  until a verdict is issued.

AUTH events are the **only userspace mechanism on macOS for pre-execution blocking**
of arbitrary operations. This is what CrowdStrike, SentinelOne, and Santa use to
prevent threats.

### Complete AUTH Event Catalog (macOS 26.3 SDK)

**Process control:**
| Event | What it blocks |
|-------|---------------|
| `AUTH_EXEC` | Process execution (the primary prevention event) |
| `AUTH_SIGNAL` | Sending signals between processes |
| `AUTH_PROC_CHECK` | Process inspection operations |
| `AUTH_PROC_SUSPEND_RESUME` | Suspending/resuming processes |
| `AUTH_GET_TASK` | Getting task port (full control of another process) |
| `AUTH_GET_TASK_READ` | Getting read-only task port |

**File system operations:**
| Event | What it blocks |
|-------|---------------|
| `AUTH_OPEN` | Opening files (uses flags-based response for R/W/RW) |
| `AUTH_CREATE` | Creating new files/directories |
| `AUTH_RENAME` | Renaming files |
| `AUTH_UNLINK` | Deleting files |
| `AUTH_LINK` | Creating hard links |
| `AUTH_TRUNCATE` | Truncating files |
| `AUTH_CLONE` | Cloning files (APFS clonefile) |
| `AUTH_EXCHANGEDATA` | Atomically exchanging file data |
| `AUTH_COPYFILE` | Copying files via copyfile(2) |
| `AUTH_READLINK` | Reading symlink targets |
| `AUTH_READDIR` | Reading directory contents |
| `AUTH_SEARCHFS` | Searching the file system catalog |
| `AUTH_FSGETPATH` | Getting path from file descriptor |
| `AUTH_FCNTL` | File control operations |

**File metadata operations:**
| Event | What it blocks |
|-------|---------------|
| `AUTH_SETATTRLIST` | Setting file attributes |
| `AUTH_SETEXTATTR` | Setting extended attributes |
| `AUTH_GETEXTATTR` | Reading extended attributes |
| `AUTH_LISTEXTATTR` | Listing extended attributes |
| `AUTH_DELETEEXTATTR` | Deleting extended attributes |
| `AUTH_GETATTRLIST` | Reading file attributes |
| `AUTH_SETFLAGS` | Setting file flags (chflags) |
| `AUTH_SETMODE` | Setting file permissions (chmod) |
| `AUTH_SETOWNER` | Changing file ownership (chown) |
| `AUTH_SETACL` | Setting ACLs |
| `AUTH_UTIMES` | Setting file timestamps |
| `AUTH_SETTIME` | Setting system time |

**Mount/filesystem operations:**
| Event | What it blocks |
|-------|---------------|
| `AUTH_MOUNT` | Mounting volumes |
| `AUTH_REMOUNT` | Remounting volumes |
| `AUTH_KEXTLOAD` | Loading kernel extensions |
| `AUTH_IOKIT_OPEN` | Opening IOKit user clients |

**Directory operations:**
| Event | What it blocks |
|-------|---------------|
| `AUTH_CHDIR` | Changing working directory |
| `AUTH_CHROOT` | Changing root directory |

**IPC operations:**
| Event | What it blocks |
|-------|---------------|
| `AUTH_UIPC_BIND` | Binding Unix domain sockets |
| `AUTH_UIPC_CONNECT` | Connecting Unix domain sockets |

**Memory operations:**
| Event | What it blocks |
|-------|---------------|
| `AUTH_MMAP` | Memory mapping files |
| `AUTH_MPROTECT` | Changing memory protection |

**File Provider operations:**
| Event | What it blocks |
|-------|---------------|
| `AUTH_FILE_PROVIDER_MATERIALIZE` | CloudKit/file provider materialization |
| `AUTH_FILE_PROVIDER_UPDATE` | CloudKit/file provider updates |

### How AUTH Blocking Works

```c
// In AUTH event handler:
es_respond_auth_result(client, msg, ES_AUTH_RESULT_DENY, false);
// OR for AUTH_OPEN specifically (flags-based):
es_respond_flags_result(client, msg, 0, true);  // Deny all open modes
```

Key mechanics:
- Each AUTH message has a **deadline** (absolute Mach time). You MUST respond
  before the deadline or your process is killed by the kernel.
- If deadline is missed: implicit ALLOW is applied (fail-open).
- Multiple ES clients: **most restrictive** response wins.
- Response caching is available but "best effort" -- entries can expire at any time.
- Cache is global, shared across all ES clients.
- Cache is automatically invalidated on file writes/truncates/deletes.

### Performance Impact of AUTH vs NOTIFY

AUTH events are inherently more expensive than NOTIFY:

1. **Kernel blocks the syscall** until response arrives -- adds latency to every
   matched operation system-wide.
2. **Cannot be processed asynchronously** -- you must respond before deadline,
   so you cannot batch or defer work.
3. **Subscribing to high-volume AUTH events (AUTH_OPEN, AUTH_READDIR, AUTH_GETATTRLIST)
   can severely degrade system performance** -- every file open on the system waits
   for your verdict.
4. **CrowdStrike/SentinelOne approach**: Subscribe to a small set of critical AUTH
   events (primarily AUTH_EXEC, AUTH_MMAP, AUTH_KEXTLOAD) and use NOTIFY for
   everything else. Use aggressive caching and process muting to minimize the
   hot path.

Mitigations:
- **Process muting**: `es_mute_process()` / `es_mute_path_prefix()` to exclude
  known-good high-volume processes (Spotlight, Finder, Time Machine).
- **Caching**: Set cache=true on `es_respond_auth_result()` for stable decisions.
- **Path muting**: `es_mute_path()` with `ES_MUTE_PATH_TYPE_TARGET_PREFIX` to
  exclude entire directory trees from AUTH events.
- **Muting inversion** (macOS 13+): Only receive events for specific paths of
  interest instead of everything.

### How CrowdStrike/SentinelOne Use AUTH Events

Based on public documentation and reverse engineering:

- **Primary AUTH subscriptions**: AUTH_EXEC (block malicious executables),
  AUTH_MMAP (block malicious libraries being loaded), AUTH_KEXTLOAD (block
  unauthorized kernel extensions).
- **Secondary AUTH subscriptions**: AUTH_OPEN, AUTH_RENAME, AUTH_UNLINK for
  ransomware protection (blocking rapid file encryption patterns).
- **Everything else via NOTIFY**: Process forks, exits, network connections,
  file creates/writes -- all monitored post-hoc for behavioral analysis.
- **System extension deployment**: Runs as a system extension with SIP
  integration, auto-restart on crash, early boot blocking.
- **ML-based decision making**: AUTH_EXEC handler runs a local ML model against
  the binary's features (code signing, entropy, file size, path) to make
  sub-millisecond allow/deny decisions.

### Requirements

- **Entitlement**: `com.apple.developer.endpoint-security.client` (restricted;
  requires Apple Developer Program membership and Apple approval)
- **Full Disk Access**: User must grant FDA in System Settings
- **Root**: ES client creation requires root (or the system extension context)
- **System Extension**: For production deployment, the ES client should be
  packaged as a system extension (additional entitlement required)
- **MDM**: Can auto-approve system extensions and FDA via MDM payloads

### MacCrab Applicability

**Without ES entitlement (current state):**
- Cannot use ANY AUTH events. Cannot block anything via ES.
- Can use eslogger for NOTIFY events (current approach via EsloggerCollector).
- Detection-only; response actions (kill, quarantine, PF block) are reactive.

**With ES entitlement (after Apple Developer Program approval):**
- This is the single most impactful capability MacCrab could gain.
- Priority AUTH subscriptions for MacCrab:
  1. `AUTH_EXEC` -- Block known-malicious binaries, unsigned code, anomalous
     executables.
  2. `AUTH_MMAP` -- Block malicious dylib injection (DYLD_INSERT_LIBRARIES
     attacks).
  3. `AUTH_KEXTLOAD` -- Block unauthorized kernel extension loading.
  4. `AUTH_OPEN` (targeted) -- Protect sensitive directories from unauthorized
     access (~/Documents, ~/.ssh, credential stores).
  5. `AUTH_RENAME` / `AUTH_UNLINK` -- Ransomware protection (detect rapid
     rename/delete patterns and block).
  6. `AUTH_GET_TASK` -- Block unauthorized process debugging/injection.

---

## 2. macOS Packet Filter (PF)

### Overview

PF is the BSD packet filter firewall built into macOS. It operates at layers 3-4
(IP/TCP/UDP) and can block, pass, or match packets based on network headers.
macOS uses PF via an anchor system -- the base `/etc/pf.conf` defines anchor
points, and subsystems (including third-party tools) load rules into named
anchors.

### What PF Can Block

- **By IP address**: Individual IPs, CIDR ranges, tables of addresses
- **By port**: Source/destination ports, port ranges
- **By protocol**: TCP, UDP, ICMP, and others
- **By direction**: Inbound, outbound, or both
- **By interface**: Specific network interfaces (en0, en1, utun0, etc.)
- **By TCP flags**: SYN, ACK, FIN, RST combinations
- **By user/group**: Socket ownership-based filtering (TCP/UDP only)
- **Stateful filtering**: Connection tracking with state tables

### Per-Process Filtering

PF supports **per-user** filtering but NOT per-process (per-PID):

```
# Block all outbound TCP from user "malware_user":
block out proto tcp user malware_user

# Allow only specific users to make outbound connections:
block out proto { tcp, udp } all
pass  out proto { tcp, udp } all user { < 1000, admin }
```

The `log (user)` option captures the UID and PID of the socket owner, but PID
cannot be used as a filter criterion -- only user/group.

**Limitation**: User/group filtering only works for TCP and UDP. Other protocols
are ignored. Forwarded packets have unknown user/group.

### DNS/Domain-Based Blocking

PF operates at IP level and **cannot filter by domain name** at rule evaluation
time. However:

1. **Hostname resolution at rule load time**: Table entries can be hostnames --
   all resolved IPs are added to the table. But this is static; DNS changes
   are not tracked.
   ```
   table <blocked_domains> persist { malware-c2.example.com evil.net }
   block out to <blocked_domains>
   ```

2. **DNS-level blocking** requires a separate mechanism:
   - Run a local DNS resolver (e.g., dnsmasq, unbound) that returns NXDOMAIN
     for blocked domains, then force all DNS through it via PF redirect.
   - Use a Network Extension DNS proxy (see section 5).
   - Modify `/etc/hosts` (crude but effective for static lists).

### Anchors

Anchors allow modular rule management without touching the main ruleset:

```bash
# Load rules into a named anchor:
sudo pfctl -a com.maccrab -f /path/to/maccrab_rules.conf

# Enable PF with reference counting (safe for multi-user):
sudo pfctl -E

# Release reference when done:
sudo pfctl -X <token>
```

The main `/etc/pf.conf` on macOS already defines `com.apple/*` anchor points.
Third-party anchors like `com.maccrab` need to be added to the main ruleset
or loaded into existing anchor points.

### Requirements

- **Root required**: All pfctl operations require root
- **No entitlement needed**: PF is a standard BSD subsystem
- **No MDM needed**: Works on any Mac

### Performance Impact

- PF rule evaluation is O(n) per packet for linear rulesets, but **table lookups
  are O(log n)** -- tables should be used for large blocklists.
- Stateful filtering (default for TCP) means only the first packet of a
  connection is evaluated against rules; subsequent packets match state entries.
- Minimal overhead for typical rulesets (hundreds of rules). Degrades with
  tens of thousands of explicit rules (use tables instead).

### MacCrab Current Usage

MacCrab already implements PF-based network blocking in `ResponseAction.swift`:
- Writes block rules to `com.maccrab` anchor
- Uses `pfctl -a com.maccrab -f <anchor_file>` to reload
- Supports timed blocks with automatic expiration
- IP validation via `inet_pton()` prevents injection

### MacCrab Improvements Possible (no entitlement needed)

1. **Block by user** in addition to IP -- isolate suspicious user accounts
2. **DNS sinkhole**: Run a local DNS resolver with blocklists, redirect DNS
   through it via PF rdr rules
3. **Table-based blocking**: Replace individual block rules with PF tables for
   O(log n) lookup with thousands of blocked IPs
4. **Anchor auto-registration**: Add `anchor "com.maccrab"` to `/etc/pf.conf`
   during installation
5. **Bidirectional blocking**: Current rules only block outbound; add inbound
   blocking for C2 server IPs
6. **Rate limiting**: PF supports rate limiting via queueing/dummynet -- could
   throttle suspicious connections instead of hard-blocking
7. **All-interface blocking**: Current implementation only blocks en0/en1;
   should use `on egress` or no interface qualifier to block on all interfaces

---

## 3. File System Protection

### chflags (BSD File Flags)

The `chflags` system provides immutability flags at the filesystem level:

| Flag | Who can set | Who can unset | Effect |
|------|------------|--------------|--------|
| `uchg` (user immutable) | Owner or root | Owner or root | Prevents modification/deletion |
| `uappnd` (user append-only) | Owner or root | Owner or root | Only appending allowed |
| `schg` (system immutable) | Root only | Root only (requires securelevel < 1) | Cannot be modified even by root |
| `sappnd` (system append-only) | Root only | Root only (requires securelevel < 1) | Append-only even for root |
| `hidden` | Owner or root | Owner or root | Hidden from GUI |

```bash
# Make a file immutable (even root can't delete without clearing flag first):
sudo chflags schg /path/to/protected/file

# Make a directory and contents immutable:
sudo chflags -R uchg /path/to/protected/dir/

# Clear the flag:
sudo chflags noschg /path/to/protected/file
```

**Limitations**:
- On macOS, securelevel is not typically enforced (unlike OpenBSD), so root can
  always clear system flags. The `schg` flag adds a speed bump but not true
  protection against root attackers.
- Does not prevent reading, only writing/deleting.
- Does not apply to newly created files in the directory automatically.

### ACLs (Access Control Lists)

macOS supports fine-grained POSIX ACLs on APFS and HFS+:

```bash
# Deny everyone write access to a directory:
chmod +a "everyone deny write,delete,add_file,add_subdirectory,delete_child" /path/to/dir

# Deny a specific user:
chmod +a "user:_spotlight deny write,delete" /path/to/dir

# List ACLs:
ls -le /path/to/dir
```

Available permissions: `read`, `write`, `execute`, `delete`, `append`,
`readattr`, `writeattr`, `readextattr`, `writeextattr`, `readsecurity`,
`writesecurity`, `chown`, `list`, `search`, `add_file`, `add_subdirectory`,
`delete_child`.

ACL inheritance: `file_inherit`, `directory_inherit`, `limit_inherit`.

**Strengths**:
- More granular than Unix permissions
- Can deny specific users/groups while allowing others
- Inheritance means new files in protected directories get ACLs automatically

**Limitations**:
- Root can override ACLs (root bypasses most access checks)
- Not enforced across volumes consistently

### Sandbox Profiles (SBPL)

macOS has 500+ system sandbox profiles in `/System/Library/Sandbox/Profiles/`.
Custom profiles can be applied to processes:

```bash
# Block all network access:
sandbox-exec -p '(version 1)(allow default)(deny network*)' /path/to/program

# Block all file writes:
sandbox-exec -p '(version 1)(allow default)(deny file-write*)' /path/to/program

# Block all file writes except to /tmp:
sandbox-exec -n no-write-except-temporary /path/to/program
```

SBPL (Sandbox Profile Language) supports:
- `file-read*`, `file-write*`, `file-write-data`, `file-write-create`
- `network*`, `network-outbound`, `network-inbound`
- `process-exec`, `process-fork`
- `mach-lookup`, `mach-register`
- `ipc-posix-shm`
- `signal`
- `sysctl-read`, `sysctl-write`
- `system-socket`
- Path filters: `literal`, `subpath`, `regex`
- Process filters: `process-path`
- Require-all/require-any combinators

**Important**: `sandbox-exec` is deprecated but still functional on macOS 26.
The sandbox kernel enforcement is not deprecated -- only the CLI tool and the
`sandbox_init()` API.

### SIP-like Protection

System Integrity Protection (SIP) protects system directories, but custom SIP
paths are not possible without Apple-signed components in the trust cache.
However, you can achieve similar protection via:

1. **chflags schg** + process monitoring (detect flag removal attempts)
2. **ACLs** with ES NOTIFY monitoring for unauthorized access
3. **AUTH_OPEN / AUTH_UNLINK / AUTH_RENAME** (with ES entitlement) to block
   writes to specific paths

### Requirements

- **chflags**: Root for system flags; owner for user flags
- **ACLs**: Owner or root to set ACLs
- **Sandbox profiles**: No special privileges to sandbox child processes
- **No entitlement needed** for any of these

### MacCrab Applicability

**Without ES entitlement:**
- Use `chflags uchg` to protect MacCrab's own files (rules, database, config)
  from tampering -- self-defense mechanism.
- Use ACLs to protect sensitive user directories and detect ACL changes via
  FSEvents monitoring.
- Use `sandbox-exec` to launch suspicious downloads in a sandboxed environment
  for behavioral analysis before allowing full execution.
- Monitor for `chflags` changes via Unified Log or eslogger NOTIFY events.

**With ES entitlement:**
- Use `AUTH_OPEN` to block writes to protected paths (credential stores, SSH
  keys, browser profiles).
- Use `AUTH_SETFLAGS` to prevent attackers from clearing protection flags.
- Use `AUTH_SETACL` to prevent ACL modifications on protected files.

---

## 4. Binary Authorization

### Google Santa Model

Santa is the reference implementation of binary authorization on macOS, using
the ES framework's `AUTH_EXEC` event to allow or deny every binary execution.

**Architecture**:
- `santad` (root daemon): Makes allow/deny decisions using ES `AUTH_EXEC`
- Santa GUI: Displays block notifications to users
- `santactl`: CLI management tool
- `santasyncservice`: Syncs rules from a central server

**Rule types** (evaluated in order of precedence):
1. **CDHash**: Code directory hash -- most specific, version-pinned
2. **Binary hash**: SHA-256 of the complete binary file
3. **Signing ID**: Reverse-domain identifier from code signature
4. **Certificate hash**: SHA-256 of the leaf signing certificate
5. **Team ID**: Apple-issued 10-character developer identifier
6. **Compiler/Transitive rules**: Auto-allow files created by trusted compilers

**Operating modes**:
- **Monitor**: Block known-bad binaries, allow everything else (default)
- **Lockdown**: Block everything not explicitly allowed (allowlist mode)

**Safety mechanisms**:
- Cannot block Apple system binaries (immutable certificate rules at startup)
- Cannot block itself (self-protection rules)
- Protects launchd (PID 1) from being blocked

### Apple's Own Binary Authorization

**Gatekeeper**:
- Checks code signing and notarization on first launch of downloaded apps
- Can be configured to only allow App Store apps
- Randomized read-only launch locations prevent plugin injection
- Revocable: Apple can revoke signing certificates remotely

**Notarization**:
- Apple scans submitted binaries for malware before issuing a notarization ticket
- Required for apps distributed outside the App Store (macOS 10.15+)
- Notarization can be revoked server-side
- Limitation: Does not catch all threats (e.g., 3CX supply chain attack passed
  notarization)

**XProtect**:
- YARA-based signature scanning
- Automatic updates via background daemon
- Can quarantine/remediate known malware
- ES events: `NOTIFY_XP_MALWARE_DETECTED`, `NOTIFY_XP_MALWARE_REMEDIATED`

### Requirements

- **Santa**: Requires ES entitlement (uses AUTH_EXEC)
- **Gatekeeper**: Built into macOS, configurable via MDM or spctl
- **Notarization**: Automatic for distributed software
- **XProtect**: Automatic, no configuration needed

### MacCrab Applicability

**Without ES entitlement:**
- Cannot implement Santa-style blocking (no AUTH_EXEC access).
- Can monitor for Gatekeeper overrides via `NOTIFY_GATEKEEPER_USER_OVERRIDE`
  ES event (via eslogger).
- Can check binary notarization status post-execution and alert on unsigned/
  un-notarized binaries.
- Can maintain a local hash database and alert on known-bad hashes (detection,
  not prevention).

**With ES entitlement:**
- Implement Santa-like AUTH_EXEC blocking with MacCrab's own rule engine.
- Priority: Block binaries matching YARA rules, known-bad hashes, or failing
  code signing checks.
- Could implement "lockdown mode" for high-security environments.

---

## 5. Network Extension Framework

### Overview

The Network Extension framework provides four types of network interception,
all running as system extensions in userspace:

### Content Filter (NEFilterDataProvider / NEFilterPacketProvider)

**What it can do:**
- Intercept all TCP/UDP flows at the socket layer
- See flow metadata: source/destination endpoints, protocol, direction
- **Per-process identification on macOS**: `sourceAppAuditToken` (macOS 10.15+),
  `sourceProcessAuditToken` (macOS 13+) -- can identify exactly which process
  initiated each connection
- Allow/drop/defer decisions on each flow
- Read flow data (but cannot modify it)
- Packet-level filtering via NEFilterPacketProvider for non-TCP/UDP protocols
- Apply filtering rules via NEFilterSettings + NENetworkRules
- Default action (allow or drop) for unmatched flows

**What it cannot do:**
- Cannot modify packet contents (read-only for content filters)
- Cannot redirect connections (use transparent proxy for that)

### DNS Proxy (NEDNSProxyProvider)

**What it can do:**
- Intercept ALL DNS queries system-wide
- Handle each DNS query programmatically
- Block queries (return NXDOMAIN or REFUSED)
- Redirect queries to encrypted DNS (DoH/DoT)
- Implement domain-based blocklists at DNS resolution time
- System-wide: affects all applications

**This is the proper way to do domain-based blocking on macOS.**

### Transparent Proxy (NEAppProxyProvider)

**What it can do:**
- Intercept TCP/UDP flows matching specified NENetworkRules
- Full read/write access to flow data
- Multiplex flows, cache resources, apply transformations
- Per-app or system-wide scope

### Packet Tunnel (NEPacketTunnelProvider)

**What it can do:**
- Create VPN tunnels handling raw IP packets
- Route all traffic or per-app traffic through the tunnel
- IncludeAllNetworks mode: forces ALL traffic through VPN (drops if unavailable)
- ExcludeLocalNetworks: allows LAN access while tunneling

### DNS Settings Manager (NEDNSSettingsManager)

**What it can do:**
- Configure system DNS settings programmatically (macOS 11+)
- Set DNS-over-HTTPS or DNS-over-TLS servers
- Apply On Demand rules (activate on specific networks)
- User must enable in System Settings

### Requirements

- **Entitlement**: `com.apple.developer.networking.networkextension` (requires
  Apple Developer Program membership -- but this is a DIFFERENT entitlement from
  the ES entitlement; it may be easier to obtain)
- **System Extension**: Must be packaged as a system extension inside an app bundle
- **User Approval**: User must approve the system extension and network filter in
  System Settings > Privacy & Security
- **MDM**: Can auto-approve via MDM profiles (ContentFilterPayload,
  SystemExtensionPayload)
- **No root required** for the network extension itself (runs as system extension)

### Performance Impact

- Content filters add latency to connection establishment (similar to AUTH events)
- DNS proxy adds latency to every DNS resolution
- Impact is moderate for flow-level filtering; more significant for packet-level
- System extensions are managed by launchd and auto-restarted on crash

### MacCrab Applicability

**This is highly relevant and may be obtainable before the ES entitlement.**

The Network Extension entitlement is separate from the ES entitlement and may
be easier to obtain from Apple. With it, MacCrab could:

1. **Content Filter**: Block network connections by process identity -- enforce
   that AI coding tools can only reach approved APIs (the AINetworkSandbox
   feature, currently detection-only, could become enforcement).
2. **DNS Proxy**: Implement domain-based blocking at the DNS level -- block
   known C2 domains, malware distribution sites, cryptocurrency mining pools.
   This is far more effective than IP-based PF blocking because it catches
   domain-based C2 that uses rotating IPs.
3. **Per-process network control**: Using `sourceAppAuditToken` and
   `sourceProcessAuditToken`, MacCrab could enforce process-specific network
   policies (e.g., only allow curl/wget to reach specific domains when launched
   by an AI coding tool).

**Without any entitlement:**
- Cannot use Network Extension framework at all.
- Current PF-based blocking is the only option.
- DNS-level blocking requires running a local DNS resolver and PF redirection.

---

## 6. TCC Management

### Overview

Transparency, Consent, and Control (TCC) manages access to sensitive resources:
Contacts, Calendar, Photos, Camera, Microphone, Location, Full Disk Access,
Automation (AppleEvents), Accessibility, Screen Recording, etc.

### Programmatic TCC Control

**What `tccutil` can do:**
- `tccutil reset <service>` -- Reset all decisions for a service
- `tccutil reset <service> <bundle_id>` -- Reset for a specific app
- `tccutil reset All <bundle_id>` -- Reset all services for an app

**What tccutil CANNOT do:**
- Grant permissions programmatically (must be user-approved or MDM-managed)
- Revoke a specific app's permission without resetting the entire service
- Intercept new permission requests
- Query current permission state (no read API)

### TCC Database

The TCC database is at `/Library/Application Support/com.apple.TCC/TCC.db`
(system-level) and `~/Library/Application Support/com.apple.TCC/TCC.db`
(user-level). It is SIP-protected; direct modification requires Full Disk
Access or SIP disabled.

### ES TCC Events

- `NOTIFY_TCC_MODIFY`: Fires when a TCC permission is granted, denied, or
  modified. Available via eslogger without the ES entitlement.

### MDM TCC Management

MDM profiles can pre-approve TCC permissions using the Privacy Preferences
Policy Control payload (PPPC):
- Grant Full Disk Access, Accessibility, Screen Recording, etc. silently
- Cannot revoke user-granted permissions; can only pre-grant

### Requirements

- `tccutil reset`: Root for system-level; user for user-level
- Direct database modification: SIP disabled or FDA
- MDM PPPC: Requires MDM enrollment

### MacCrab Applicability

**Without ES entitlement:**
- Monitor `NOTIFY_TCC_MODIFY` via eslogger to detect unauthorized permission
  grants (e.g., malware granting itself Accessibility access via social
  engineering).
- Use `tccutil reset` as a response action to revoke suspicious permissions.
- Alert when new apps gain sensitive permissions (Screen Recording, Accessibility,
  Full Disk Access).

**With ES entitlement:**
- Same capabilities (TCC events are NOTIFY-only; no AUTH variant exists).

---

## 7. MDM / Configuration Profiles

### Security Policies Available via MDM

**Application control:**
- Restrict app installation sources (App Store only, identified developers, etc.)
- Allowlist/blocklist specific apps by bundle ID
- Managed app distribution and removal

**System extension management:**
- Allow specific system extensions by team ID and bundle ID
- Auto-approve system extensions (no user prompt)
- Block unauthorized system extensions

**Kernel extension management:**
- Allow specific kernel extensions by team ID
- Block unauthorized kext loading

**Network restrictions:**
- VPN enforcement (always-on VPN, per-app VPN)
- Web content filtering (managed content filter)
- Wi-Fi network restrictions
- Proxy configuration

**Firewall:**
- Enable/configure the application firewall via profile
- Block all incoming connections
- Allow/block specific applications

**Password policy:**
- Minimum length, complexity, expiration
- Maximum failed attempts before device wipe

**FileVault:**
- Force encryption
- Escrow recovery keys

**Software Update:**
- Defer updates for testing
- Force minimum OS version

### Configuration Profile Installation

```bash
# Install a profile (requires user/admin approval):
sudo profiles install -path /path/to/profile.mobileconfig

# List installed profiles:
sudo profiles list

# Remove a profile:
sudo profiles remove -identifier com.example.profile
```

### Requirements

- Some profiles can be installed locally by root
- Full enforcement requires MDM enrollment (supervised mode)
- User-approved MDM enrollment is available (no Apple Business Manager required)
- Some restrictions only apply to supervised/managed devices

### MacCrab Applicability

**Without MDM (current state):**
- MacCrab could generate and install local configuration profiles for:
  - Enabling the application firewall
  - Restricting kernel extension loading
  - Setting password policies
- Limited effectiveness without MDM enforcement

**With MDM integration:**
- MacCrab fleet management could push security profiles to managed devices
- Auto-approve MacCrab's own system extension
- Pre-grant TCC permissions (PPPC payload)
- Enforce always-on VPN through MacCrab's network filter

---

## 8. Application Sandbox

### sandbox-exec (Deprecated but Functional)

`sandbox-exec` launches a process with a custom sandbox profile. The process
and all its children inherit the sandbox restrictions.

```bash
# Launch with no network access:
sandbox-exec -p '(version 1)(allow default)(deny network*)' /path/to/untrusted

# Launch with no file writes:
sandbox-exec -p '(version 1)(allow default)(deny file-write*)' /path/to/untrusted

# Launch with minimal privileges (pure computation):
sandbox-exec -n pure-computation /path/to/untrusted
```

### Pre-defined Profiles

- `kSBXProfileNoInternet` -- No TCP/IP networking
- `kSBXProfileNoNetwork` -- No socket-based networking at all
- `kSBXProfileNoWrite` -- No file system writes
- `kSBXProfileNoWriteExceptTemporary` -- Writes only to /var/tmp and temp dirs
- `kSBXProfilePureComputation` -- No OS services at all

### Custom SBPL Profiles

Custom profiles use the Sandbox Profile Language (SBPL), a Scheme-like DSL:

```scheme
(version 1)
(deny default)                              ; Deny everything by default
(allow process-exec)                         ; Allow executing
(allow file-read* (subpath "/usr"))          ; Allow reading /usr
(allow file-read* (subpath "/System"))       ; Allow reading /System
(allow file-read-data (literal "/dev/null")) ; Allow reading /dev/null
(allow file-write-data (subpath "/tmp"))     ; Allow writing to /tmp
(allow mach-lookup (global-name "com.apple.system.logger")) ; Allow syslog
; Deny all network access (implicit from deny default)
```

### Applying Sandbox to Running Processes

**You cannot sandbox an already-running process.** The sandbox can only be
applied at process creation time (via `sandbox-exec`, `sandbox_init()`, or
the `posix_spawn` POSIX_SPAWN_SETSANDBOX attribute).

### Sandbox Inheritance

Child processes inherit their parent's sandbox. A sandboxed process cannot
create children with fewer restrictions than its own sandbox.

### Requirements

- **No special privileges needed** to sandbox child processes
- Sandbox enforcement is in the kernel (MAC framework) and cannot be bypassed
  from userspace
- `sandbox-exec` is deprecated but works on macOS 26.3
- The kernel sandbox enforcement is NOT deprecated

### MacCrab Applicability

**Without ES entitlement (highly practical):**

1. **Sandboxed analysis**: When MacCrab detects a suspicious download, offer to
   run it in a sandbox with no network and limited filesystem access for
   behavioral analysis. Observe what it tries to do without letting it actually
   exfiltrate data or modify the system.

2. **AI tool sandboxing**: Launch AI coding tools (or their subprocesses) under
   a sandbox profile that restricts network access to approved domains and
   prevents file access outside the project directory.

3. **Self-protection**: MacCrab could sandbox its own child processes
   (enrichment modules, YARA scanning, script execution) to prevent
   exploitation of those components from compromising the system.

4. **Quarantine execution**: Instead of just quarantining files, offer
   "detonation" -- run the quarantined file in a sandbox and observe its
   behavior via NOTIFY events.

---

## 9. Launch Constraints (macOS 13+)

### Overview

Launch constraints are a macOS 13 Ventura+ feature that restricts WHEN and HOW
binaries can be launched, based on properties of the binary and its parent/
responsible process chain. They are enforced by AMFI (Apple Mobile File
Integrity) at process creation time.

### How They Work

Launch constraints are embedded in the **static trust cache** alongside each
binary's CDHash. When AMFI validates a binary at launch time, it checks:

1. **Self constraints**: Properties the binary itself must have (e.g., must be
   platform binary, must have specific signing ID, must have specific team ID)
2. **Parent constraints**: Properties the parent process must have (e.g., must
   be launchd, must be a specific Apple binary)
3. **Responsible process constraints**: Properties the responsible process
   (ultimate ancestor) must have

### Constraint Categories

Each constraint is a dictionary of requirements:
- `signing-identifier`: Must match specific signing ID
- `team-identifier`: Must match specific team ID
- `cdhash`: Must match specific CDHash
- `is-init-proc`: Must be launchd (PID 1)
- `validation-category`: Code signing validation requirements
- `on-authorized-authapfs-volume`: Must be on the signed system volume

### What They Prevent

- **Process injection attacks**: A system daemon cannot be launched by an
  unauthorized parent. For example, `logd` has parent constraints requiring
  it to be launched by launchd -- malware cannot spawn logd as a child
  process to inherit its entitlements.
- **Binary replacement attacks**: Even if you replace a binary with the same
  name, the CDHash won't match the trust cache constraint.
- **Privilege escalation**: System binaries cannot be launched from unexpected
  contexts.

### Third-Party Usage

**Launch constraints are NOT available to third-party developers.**

- Constraints are defined in the static trust cache, which is built and signed
  by Apple during OS compilation.
- Third-party binaries are not in the static trust cache (they're in loadable
  trust caches or validated via certificate chains).
- There is no API to define custom launch constraints.
- MDM cannot define launch constraints.

### Requirements

- macOS 13 Ventura or later
- Apple Silicon (trust cache is Apple silicon specific)
- SIP must be enabled for enforcement
- Only applies to binaries in Apple's trust cache

### MacCrab Applicability

**Cannot use launch constraints** (Apple-only mechanism). However:

- MacCrab can **detect violations of expected launch patterns** by monitoring
  process parent chains via eslogger and alerting when system binaries are
  launched from unexpected parents.
- This is behavioral detection, not prevention, but it catches the same attack
  patterns that launch constraints are designed to prevent.

---

## 10. macOS Sequoia (15) / macOS 26 New Security Features

### macOS 15 Sequoia

**Local Network Access Control (new to macOS):**
- Apps must now request permission to access the local network (Bonjour, multicast,
  broadcast, unicast to LAN)
- User sees a prompt similar to iOS
- Apps need `NSLocalNetworkUsageDescription` in Info.plist

**Extension Transparency:**
- System notifications when new extensions are installed
- All login items and extensions visible in System Settings > General > Login
  Items & Extensions
- Users can disable any extension from this central location
- **Cron is off by default** (can be re-enabled)
- Legacy QuickLook plugins no longer supported
- `com.apple.loginitems.plist` no longer supported
- ES events: `NOTIFY_BTM_LAUNCH_ITEM_ADD`, `NOTIFY_BTM_LAUNCH_ITEM_REMOVE`

**App Group Container Protection:**
- App Sandbox protections extended to shared containers
- Prompts when apps from other developers access group containers

**MAC Address Rotation:**
- Wi-Fi MAC address rotation on macOS (previously iOS only)
- Rotates approximately every 2 weeks

### macOS 26.3 (Current) ES Event Types

The current SDK includes these notable NOTIFY-only events (no AUTH variant):

| Event | Information |
|-------|------------|
| `NOTIFY_AUTHENTICATION` | User authentication events (password, Touch ID, Apple Watch) |
| `NOTIFY_XP_MALWARE_DETECTED` | XProtect malware detection |
| `NOTIFY_XP_MALWARE_REMEDIATED` | XProtect malware remediation |
| `NOTIFY_LW_SESSION_LOGIN/LOGOUT` | Login window sessions |
| `NOTIFY_LW_SESSION_LOCK/UNLOCK` | Screen lock/unlock |
| `NOTIFY_SCREENSHARING_ATTACH/DETACH` | Screen sharing sessions |
| `NOTIFY_OPENSSH_LOGIN/LOGOUT` | SSH login/logout |
| `NOTIFY_LOGIN_LOGIN/LOGOUT` | Console login/logout |
| `NOTIFY_BTM_LAUNCH_ITEM_ADD/REMOVE` | Background task management |
| `NOTIFY_PROFILE_ADD/REMOVE` | Configuration profile install/remove |
| `NOTIFY_SU` | su command usage |
| `NOTIFY_SUDO` | sudo command usage |
| `NOTIFY_AUTHORIZATION_PETITION/JUDGEMENT` | Authorization plugin events |
| `NOTIFY_OD_*` (10 events) | Open Directory user/group management |
| `NOTIFY_XPC_CONNECT` | XPC service connections |
| `NOTIFY_GATEKEEPER_USER_OVERRIDE` | User bypassing Gatekeeper |
| `NOTIFY_TCC_MODIFY` | TCC permission changes |
| `NOTIFY_CS_INVALIDATED` | Code signature invalidated at runtime |
| `NOTIFY_TRACE` | Process being debugged |
| `NOTIFY_REMOTE_THREAD_CREATE` | Remote thread injection |

### macOS 26 Observed Changes

Based on macOS 26.3 system behavior:
- eslogger supports all NOTIFY events and is the recommended tool for security
  monitoring without the ES entitlement
- Background Task Management is more strictly enforced -- all persistence
  mechanisms are tracked and visible to the user
- Configuration profiles generate ES events on installation/removal

### What's NOT Yet Available

- No AUTH variant for network connection events (cannot block TCP/UDP connections
  via ES -- must use Network Extension or PF)
- No AUTH variant for DNS queries
- No AUTH variant for XPC connections
- No AUTH variant for TCC changes
- No AUTH variant for authentication events
- No API for custom launch constraints

---

## 11. Practical Summary for MacCrab

### Tier 1: Available NOW (No Entitlement, Root Only)

| Mechanism | Prevention Capability | MacCrab Use Case |
|-----------|----------------------|------------------|
| **PF firewall** | Block IP addresses/ranges/ports | Block C2 IPs, rate-limit suspicious connections |
| **PF user filtering** | Block network by user ID | Isolate compromised user accounts |
| **chflags** | Make files immutable | Self-defense (protect MacCrab rules/DB) |
| **ACLs** | Fine-grained file permission control | Protect sensitive directories |
| **sandbox-exec** | Sandbox child processes (no net/no write) | Sandboxed analysis of suspicious files |
| **kill(2)** | Kill suspicious processes | Already implemented in ResponseAction |
| **File quarantine** | Move suspicious files to vault | Already implemented in ResponseAction |
| **Application firewall** | Block incoming connections per-app | `socketfilterfw --blockapp` |
| **DNS sinkhole** | Block domains via local resolver + PF redirect | C2 domain blocking |
| **tccutil reset** | Revoke TCC permissions | Response action for suspicious permission grants |

### Tier 2: With Network Extension Entitlement

| Mechanism | Prevention Capability | MacCrab Use Case |
|-----------|----------------------|------------------|
| **Content Filter** | Block network by process identity + destination | AI tool network enforcement |
| **DNS Proxy** | Block DNS resolution of malicious domains | Domain-based C2 blocking |
| **Transparent Proxy** | Intercept and inspect network traffic | Deep packet inspection |

### Tier 3: With ES Entitlement (Highest Impact)

| Mechanism | Prevention Capability | MacCrab Use Case |
|-----------|----------------------|------------------|
| **AUTH_EXEC** | Block binary execution | Binary authorization, malware prevention |
| **AUTH_MMAP** | Block library loading | Prevent dylib injection |
| **AUTH_KEXTLOAD** | Block kernel extension loading | Prevent rootkits |
| **AUTH_OPEN** | Block file access | Protect credentials, SSH keys |
| **AUTH_RENAME/UNLINK** | Block file modification/deletion | Ransomware protection |
| **AUTH_GET_TASK** | Block process debugging | Anti-injection, anti-debugging |
| **AUTH_MOUNT** | Block volume mounting | Prevent USB-based attacks |
| **AUTH_SIGNAL** | Block inter-process signaling | Prevent process manipulation |

### Recommended Implementation Priority

**Phase 1 (Now -- no entitlement needed):**
1. Enhance PF blocking: tables, all-interface, bidirectional, user-based
2. Implement sandboxed file analysis via sandbox-exec
3. Add chflags-based self-protection for MacCrab's own files
4. Add DNS sinkhole with threat intelligence feed integration
5. Add TCC permission monitoring and revocation response action

**Phase 2 (After Apple Developer Program enrollment):**
1. Apply for Network Extension entitlement (likely easier to get than ES)
2. Implement NEFilterDataProvider for per-process network blocking
3. Implement NEDNSProxyProvider for domain-based blocking
4. This alone would make MacCrab competitive with LuLu for network security

**Phase 3 (After ES entitlement approval):**
1. Implement AUTH_EXEC handler with rule-based binary authorization
2. Implement AUTH_MMAP for dylib injection prevention
3. Implement AUTH_OPEN for credential store protection
4. Implement AUTH_RENAME/AUTH_UNLINK for ransomware prevention
5. Deploy as system extension with early boot support
6. This makes MacCrab competitive with CrowdStrike/SentinelOne for endpoint
   prevention

### Key Architectural Insight

The most important architectural decision for MacCrab's prevention roadmap:

**The ES entitlement is the single gate that separates "detection tool" from
"prevention tool."** Without it, MacCrab can only react to threats after they
occur. With it, MacCrab can block threats before they execute.

However, there is a significant middle ground available TODAY:
- PF-based network blocking is already implemented and can be greatly enhanced
- sandbox-exec enables behavioral analysis without any entitlement
- DNS sinkholes can block C2 communication at the resolution layer
- chflags and ACLs provide filesystem hardening
- The application firewall can be programmatically managed

The Network Extension entitlement (separate from ES) opens another major
capability tier -- per-process network blocking and DNS-level domain blocking --
that should be pursued as an independent workstream from the ES entitlement.
