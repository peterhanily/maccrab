# MacCrab 1.2.4 — Ship Notes

**Native Endpoint Security on every machine.** Apple approved the ES
client entitlement; this release ships the daemon signed with it
instead of falling back to `eslogger` / `kdebug` / `FSEvents`.

1.2.3 users: drop-in upgrade. Installer handles the identifier rename
and provisioning-profile install automatically.

## What changed

### The daemon now runs as a real ES client

All previous releases (1.1.1 – 1.2.3) shipped with the ES entitlement
stripped because signing it into the binary without a provisioning
profile caused macOS to SIGKILL on launch. The daemon compensated by
falling back through three alternative kernel-event sources:
`eslogger` proxy, `kdebug` via `fs_usage`, and `FSEvents`.

With the entitlement approved, `maccrabd` is now signed directly with
`com.apple.developer.endpoint-security.client` and runs the real
`es_new_client` path. Benefits:

- **Faster detection loop.** ES events arrive synchronously from the
  kernel; no subprocess parse latency.
- **AUTH-class events available.** Detect + authoritatively block an
  exec before it runs, rather than observing after the fact.
- **Richer event attribution.** No more `process.name == "unknown"`
  FSEvents fallbacks — every event carries full process lineage.
- **No Terminal-FDA dance on install.** The eslogger path required a
  one-time Full Disk Access grant to Terminal; the native ES client
  doesn't.

### LaunchDaemon renamed: `com.maccrab.daemon` → `com.maccrab.agent`

Apple bound the ES entitlement to `com.maccrab.agent` during their
approval flow, so we moved the daemon label + plist filename + code-
signing identifier + `os.log` subsystem strings to match. The change
is purely organisational — behaviour is identical — but every moving
part had to move together.

**If you filter logs by subsystem**:
```
log stream --predicate 'subsystem=="com.maccrab.agent"'
```
The old `com.maccrab.daemon` predicate stops matching after upgrade.

### Upgrade path is handled automatically

Both the Homebrew cask and the DMG installer detect a pre-1.2.4
`/Library/LaunchDaemons/com.maccrab.daemon.plist`, unload it, and
remove it before installing the new `com.maccrab.agent.plist`. No
user action needed; no duplicate competing daemons.

### Provisioning profile shipped in both canonical locations

- **Inside the `.app` bundle** at
  `MacCrab.app/Contents/embedded.provisionprofile` — picked up by the
  dashboard app's entitlement check.
- **System-wide** at
  `/Library/MobileDevice/Provisioning Profiles/<UUID>.provisionprofile`
  — picked up when the standalone `/usr/local/bin/maccrabd` tries to
  assert its ES entitlement grant.

Belt-and-braces — some AMFI code paths check each location, so shipping
both is strictly safer than choosing one.

### Operator tooling

New `scripts/verify-profile.sh` takes a path to a `.provisionprofile`
and prints the team, bundle ID, expiry, type (development / distribution /
Developer ID), and the full entitlements list. Run it on any profile
before wiring it into a build.

### Hardened `.gitignore`

Broader coverage for anything that could accidentally leak:

- Private keys in every format (`*.key`, `*.pem`, `*.p12`, `*.pfx`,
  `*.pkcs12`, `id_rsa*`, `id_ecdsa*`, `id_ed25519*`)
- Certificates (`*.cer`, `*.crt`, `*.der`)
- `.env` files in every variant (with `.env.example` allowlist)
- Cloud credential caches (`.aws/`, `.gcloud/`, `.netrc`, `.npmrc`,
  `.pypirc`, `service-account*.json`, `firebase-adminsdk*.json`)
- SSH (`.ssh/`, `known_hosts`)
- Keychain dumps, release artifacts, notarization state, coverage
  data, crash dumps, scratch files

## Upgrade

```bash
brew upgrade --cask maccrab
```

or grab `MacCrab-v1.2.4.dmg` from the release page and run `install.sh`.

## Credits

Shipped by @peterhanily with Claude (Opus 4.7, 1M context) as
co-author. See `CHANGELOG.md` for the full entry.
