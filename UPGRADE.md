# Upgrading MacCrab

Short notes per release family. See [CHANGELOG.md](CHANGELOG.md) for the
full, dated log.

---

## v1.2.x → v1.3.x

**This is the biggest architectural shift in MacCrab's history.** The
detection engine moved from a root `LaunchDaemon` to a native Endpoint
Security **System Extension** activated from inside `MacCrab.app`. The
upgrade itself is automatic, but it does require a one-time user
interaction.

### What changes

| Subject | Before (v1.2) | After (v1.3+) |
|---|---|---|
| Startup | `sudo maccrabd` (LaunchDaemon on `/Library/LaunchDaemons/com.maccrab.daemon.plist`) | Click *Enable Protection* in `MacCrab.app` → approve in System Settings |
| Running process | `maccrabd` (root) | `com.maccrab.agent` (sysext, managed by `sysextd`) |
| ES entitlement | Loaded from a standalone provisioning profile | Embedded in the `.systemextension` bundle |
| Shipped binary | `/usr/local/bin/maccrabd` | Inside `MacCrab.app/Contents/Library/SystemExtensions/com.maccrab.agent.systemextension/` |
| Legacy `maccrabd` target | Primary shipping path | Dev-only fallback; still builds for `swift run maccrabd` |

### What you need to do

**Homebrew users:**

```bash
brew upgrade --cask maccrab
open /Applications/MacCrab.app
# Click "Enable Protection" and approve in System Settings when prompted.
```

The cask's `postflight` automatically:
1. Stops any legacy `com.maccrab.daemon` LaunchDaemon.
2. Removes `/Library/LaunchDaemons/com.maccrab.*.plist`.
3. Clears any old provisioning profiles from
   `/Library/MobileDevice/Provisioning Profiles/`.
4. Leaves your data (events, alerts, rules, suppressions) intact at
   `/Library/Application Support/MacCrab/`.

**DMG users (manual install):**

Run the bundled `install.sh` — it performs the same cleanup. Or do it
manually:

```bash
sudo launchctl unload /Library/LaunchDaemons/com.maccrab.daemon.plist 2>/dev/null || true
sudo rm -f /Library/LaunchDaemons/com.maccrab.*.plist
sudo rm -f /Library/MobileDevice/Provisioning\ Profiles/com.maccrab.*
```

Then launch `MacCrab.app`, click *Enable Protection*, and approve the
extension.

### First-launch approval is unavoidable

Apple requires user consent for every new Endpoint Security extension on
every machine. MacCrab has no way to pre-authorize this on a personal Mac
— you'll see a prompt in System Settings even though you're upgrading, not
installing fresh. This is identical to the flow CrowdStrike, SentinelOne,
Jamf Protect, and Microsoft Defender use.

For fleet deployments with UAMDM, a `.mobileconfig` with a
`SystemExtensionPolicy` payload can pre-authorize the extension. A signed
profile is planned for a future release; see the roadmap for status.

### Manual DMG upgrade path (v1.3 → newer v1.3.x)

If you installed via DMG and want to upgrade manually (no Homebrew, no
Sparkle), the drag-n-drop path works:

1. Mount the new DMG.
2. Drag `MacCrab.app` onto `/Applications`. macOS will ask if you want
   to replace the existing copy — click Replace.
3. Launch the replaced app. `OSSystemExtensionRequest` fires on first
   launch; because our team ID and bundle ID haven't changed, `sysextd`
   treats this as an upgrade request and the
   `SystemExtensionManager.actionForReplacingExtension` delegate returns
   `.replace`. The new sysext version is installed and activated without
   a new approval prompt in System Settings.
4. Quit and relaunch MacCrab.app to let the new sysext take over event
   collection. (The old sysext stays active until the new activation
   completes, so there's no detection gap — but a single relaunch
   cleanly hands over.)

**Recommended over manual drag:** use *Check for Updates…* from the
status-bar menu (Sparkle), or `brew upgrade --cask maccrab`. Both
coordinate quit + replace + relaunch so there's zero visible downtime
and zero chance of the old sysext lingering alongside the new one.

### What does NOT change

- **Your data.** Events, alerts, rules, and suppressions live at the same
  paths (`/Library/Application Support/MacCrab/`) and are preserved across
  the upgrade.
- **Your `daemon_config.json`.** Same schema, same location.
- **Your compiled rules.** `compiled_rules/` survives; the sysext loads the
  same JSON the LaunchDaemon did.
- **Your CLI workflow.** `maccrabctl` commands are unchanged.
- **Your webhook / syslog / fleet config.** Environment variables still
  work, though MacCrab.app is not a login shell so config that relied on
  `~/.zshrc` export order needs to move to the cask's wrapper or the
  optional `daemon_config.json` outputs block.

### What to confirm after upgrading

```bash
# Should show v1.3.x and "Sysext: active"
maccrabctl status

# Should list com.maccrab.agent as [activated enabled]
systemextensionsctl list | grep maccrab
```

If either command shows a stale v1.2 artifact, see the "Homebrew upgrade
leaves old state around" section of [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

### Rolling back to v1.2 (discouraged)

v1.2 had two hard blockers that drove v1.3:

- AMFI rejected the ES entitlement on LaunchDaemons after macOS Sequoia,
  so native ES didn't actually work.
- The noise-reduction arc (2,856 → ~3 alerts/day) that shipped in v1.2.1–
  v1.2.4 depends on `NoiseFilter` extraction that v1.2 lacks in older
  form.

If you really need to downgrade, `brew install
peterhanily/maccrab/maccrab@1.2.4` followed by a reinstall of the legacy
provisioning profile is the path. Ask first on GitHub Issues — there's
usually a better fix.

---

## Within-family upgrades (v1.3.0 → v1.3.4, etc.)

Standard `brew upgrade --cask maccrab` is sufficient. The sysext bundle
replaces itself via `OSSystemExtensionRequest(.replace)` — no user
approval required for a same-team-ID upgrade. Your data, config, and
suppressions carry forward untouched.

If Sparkle auto-update ships in v1.4 (planned), even the `brew upgrade`
step goes away for DMG-installed users.
