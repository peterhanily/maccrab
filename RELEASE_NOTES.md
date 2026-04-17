# MacCrab 1.2.5 — Ship Notes

**Hotfix: the 1.2.4 daemon couldn't actually use the ES entitlement.**
macOS AMFI only discovers `embedded.provisionprofile` when the binary
lives inside an `.app` bundle; a standalone daemon at
`/opt/homebrew/bin/maccrabd` failed with `Error Code=-413 "No matching
profile found"` and got SIGKILLed on launch.

1.2.4 users will see install failures when `sudo maccrabd` is invoked
(or silently — the LaunchDaemon retries and fails, logs show
`LastExitStatus = 9`). 1.2.5 restructures the install so this works.

## What changed

### The daemon binary moved into `MacCrab.app`

Before (1.2.4): `/opt/homebrew/bin/maccrabd` (symlink) → `/opt/homebrew/Caskroom/maccrab/.../bin/maccrabd`

After (1.2.5): `/Applications/MacCrab.app/Contents/Library/LaunchDaemons/maccrabd`

The daemon lives inside the `.app` bundle so AMFI can walk up the
filesystem, find `MacCrab.app/Contents/embedded.provisionprofile`,
and honour the ES entitlement. This is the canonical Apple pattern
used by Little Snitch, Objective-See tools, and every other
Developer ID-signed ES daemon.

### LaunchDaemon plist path updated

`com.maccrab.agent.plist` now hard-codes
`/Applications/MacCrab.app/Contents/Library/LaunchDaemons/maccrabd`.
No per-install path rewriting; same plist works on every Homebrew
prefix and direct-DMG install.

### Homebrew cask cleanup

- Dropped the `binary "bin/maccrabd"` declaration (daemon no longer
  standalone)
- Postflight removes any stale `/opt/homebrew/bin/maccrabd` or
  `/usr/local/bin/maccrabd` from 1.2.4 before loading the new plist
- `maccrabctl` and `maccrab-mcp` still symlink into
  `$HOMEBREW_PREFIX/bin/`

### App icon bundled

The generic macOS app icon that was showing in every release from
1.2.1 to 1.2.4 is replaced with the real MacCrab crab icon.
`build-release.sh` now copies `AppIcon.icns` into
`MacCrab.app/Contents/Resources/` and sets `CFBundleIconFile` /
`CFBundleIconName` keys in `Info.plist`.

### Cask postflight UUID extraction (mid-1.2.4 hotfix)

The provisioning-profile UUID extraction was piping
`security cms -D` into `PlistBuddy /dev/stdin`. That's unreliable in
Ruby backticks — PlistBuddy sometimes emits
`"Error Reading File: /dev/stdin"` to stdout, which then
contaminated the target filename. Replaced with a temp-file
round-trip plus a UUID regex validator so nothing but a real UUID
can reach a filesystem operation.

## Upgrade from 1.2.4

```bash
brew uninstall --cask maccrab --force   # removes the broken 1.2.4 install
brew update
brew install --cask maccrab
```

The `--force` is because brew treats the failed 1.2.4 state as
"still installed" and normal uninstall sometimes balks.

After install, verify ES is actually running:

```bash
sudo launchctl list com.maccrab.agent
# Expect: "LastExitStatus" = 0 (not 9), and a numeric PID field
tail -5 "/Library/Application Support/MacCrab/maccrabd.log"
# Expect: "Endpoint Security: native client"
```

If you see `LastExitStatus = 9` or `eslogger proxy` in the log,
check:

```bash
log show --last 2m --predicate 'sender == "amfid"' --info | tail -5
```

A "No matching profile found" line here means the profile install
still failed — tell me and I'll dig in.

## Credits

Shipped by @peterhanily with Claude (Opus 4.7, 1M context) as
co-author.
