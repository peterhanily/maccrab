# MacCrab 1.3.0 — Native Endpoint Security

**The ES entitlement actually works now.** 1.2.4 and 1.2.5 shipped
with Apple's Endpoint Security entitlement in the signed binary, but
macOS's AMFI refused it with `-413 "No matching profile found"`
because the LaunchDaemon architecture stopped being a supported
launch context for ES clients on macOS Catalina+. 1.3.0 ships the
detection engine as a proper `.systemextension`, which is the only
deployment shape Apple honours.

## What changed

### The daemon is now a system extension

Structural move:

```
/Applications/MacCrab.app/
  Contents/
    MacOS/MacCrab                                       ← dashboard + activator
    embedded.provisionprofile
    Library/SystemExtensions/
      com.maccrab.agent.systemextension/
        Contents/
          Info.plist                                    ← SYEX type, ES entitlement
          embedded.provisionprofile
          MacOS/com.maccrab.agent                       ← the detection engine
          _CodeSignature/
```

AMFI now finds the provisioning profile by walking up from the
sysext Mach-O to the enclosing `.app`, matches it against the
signed identifier, and honours
`com.apple.developer.endpoint-security.client`.

### First launch UX

There's a new **Enable Protection** card on the Overview tab.
Clicking it calls `OSSystemExtensionRequest.activationRequest`,
which causes macOS to prompt the user to approve the extension in
**System Settings > General > Login Items & Extensions > Endpoint
Security Extensions**.

Once approved, detection starts. The activation card disappears
until the next re-install or explicit deactivation.

### Legacy cleanup on install/upgrade

Both the Homebrew cask postflight and `install.sh` detect and remove
leftovers from any 1.2.x install:

- `/Library/LaunchDaemons/com.maccrab.daemon.plist` (unloaded + deleted)
- `/Library/LaunchDaemons/com.maccrab.agent.plist` (unloaded + deleted)
- `/opt/homebrew/bin/maccrabd` and `/usr/local/bin/maccrabd` symlinks
- Any MacCrab-related `*.provisionprofile` under
  `/Library/MobileDevice/Provisioning Profiles/`

After install, users upgrading from 1.2.x **must launch MacCrab.app
once and approve the extension** in System Settings — the old
LaunchDaemon was removed and there's no automatic silent approval
without MDM.

## Upgrade instructions

### From 1.2.x via Homebrew

```bash
brew upgrade --cask maccrab
open /Applications/MacCrab.app
```

Then click **Enable Protection** on the Overview tab and follow
the System Settings prompt.

### From 1.2.x via direct DMG

```bash
# Download MacCrab-v1.3.0.dmg, mount, then:
sudo ./install.sh
open /Applications/MacCrab.app
```

### Fresh install

Same as upgrade — the cleanup steps are no-ops if there's nothing
to clean.

## Post-install verification

```bash
# Is the extension registered and running?
systemextensionsctl list
# Expect a row with [activated enabled] and com.maccrab.agent

# Are CLI tools on PATH?
maccrabctl --version
# Expect: MacCrab Detection Engine v1.3.0
```

You should see `Endpoint Security: native client` in the daemon
logs:

```bash
log stream --predicate 'subsystem == "com.maccrab.agent"' --info
```

## If something goes wrong

**Extension isn't listed in System Settings.** Open MacCrab.app and
look for the orange "Approval required" card on the Overview tab —
the "Open System Settings" button will land you on the right pane.

**`systemextensionsctl list` shows `[activated waiting for user]`.**
The approval prompt timed out. Toggle the extension off and on in
System Settings, or re-click "Enable Protection" in the app.

**`[terminated waiting for user reboot]`.** macOS occasionally
requires a reboot after approval on fresh installs. Reboot and
re-check.

**Full uninstall:**

```bash
systemextensionsctl uninstall 79S425CW99 com.maccrab.agent
brew uninstall --cask maccrab       # (if installed via Homebrew)
sudo rm -rf "/Library/Application Support/MacCrab"
```

## Known limitations

- **No silent MDM approval path.** Every fresh user sees the System
  Settings prompt at least once. MDM approval via a `System
  Extension Policy` payload is v1.4.0 work.
- **macOS 15+ gotcha:** activation silently fails if `MacCrab.app`
  is launched from `~/Downloads/` rather than `/Applications/`.
  The installer + cask handle this automatically; direct manual
  installers need to drag the app to `/Applications` before first
  launch.
- **Dashboard ↔ daemon IPC is still file-based.** A proper XPC
  control plane becomes v1.4.0.

## Credits

Shipped by @peterhanily with Claude (Opus 4.7, 1M context) as
co-author. See `CHANGELOG.md` for the full entry and branch
`v1.3.0-sysext` for the five-phase refactor history.
