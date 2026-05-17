cask "maccrab" do
  version "1.12.5"
  sha256 "cda5ecb7a62c57198ff20a977611ee5ae991cd9492167e2e3758b21cfdef252f"

  url "https://github.com/peterhanily/maccrab/releases/download/v#{version}/MacCrab-v#{version}.dmg"
  name "MacCrab"
  desc "Local-first macOS threat detection engine with Sigma-compatible rules"
  homepage "https://github.com/peterhanily/maccrab"

  depends_on macos: ">= :ventura"

  app "MacCrab.app"
  binary "bin/maccrabctl"
  binary "bin/maccrab-mcp"

  postflight do
    # ── Clean up pre-1.3.0 artefacts ────────────────────────────────
    # 1.2.x shipped maccrabd as a LaunchDaemon with a system-wide
    # provisioning profile. 1.3.0 moved the detection engine into a
    # SystemExtension activated from inside MacCrab.app on first
    # launch. Strip the old plumbing so the two models don't fight.
    ["/Library/LaunchDaemons/com.maccrab.daemon.plist",
     "/Library/LaunchDaemons/com.maccrab.agent.plist"].each do |plist|
      if File.exist?(plist)
        label = File.basename(plist, ".plist")
        system_command "/bin/launchctl", args: ["unload", plist], sudo: true, must_succeed: false
        system_command "/bin/rm", args: ["-f", plist], sudo: true
        _ = label
      end
    end

    # Legacy standalone maccrabd symlinks
    ["#{HOMEBREW_PREFIX}/bin/maccrabd", "/usr/local/bin/maccrabd"].each do |path|
      if File.symlink?(path) || File.exist?(path)
        system_command "/bin/rm", args: ["-f", path], sudo: true
      end
    end

    # Legacy system-wide provisioning profile — the sysext embeds its
    # own copy inside MacCrab.app, so we don't need one at the system
    # location any more.
    profile_dir = "/Library/MobileDevice/Provisioning Profiles"
    if Dir.exist?(profile_dir)
      Dir.glob("#{profile_dir}/*.provisionprofile").each do |profile|
        tmp = "/tmp/maccrab-cask-profile-#{Process.pid}.plist"
        system("/usr/bin/security cms -D -i '#{profile}' -o '#{tmp}' 2>/dev/null")
        next unless File.exist?(tmp)
        app_id = `/usr/libexec/PlistBuddy -c 'Print :Entitlements:application-identifier' '#{tmp}' 2>/dev/null`.strip
        File.delete(tmp) rescue nil
        if app_id.include?("com.maccrab.")
          system_command "/bin/rm", args: ["-f", profile], sudo: true
        end
      end
    end

    # ── Install rules ───────────────────────────────────────────────
    system_command "/bin/mkdir",
                   args: ["-p", "/Library/Application Support/MacCrab/compiled_rules/sequences"],
                   sudo: true
    # v1.10.0 audit fix: cross-UID IPC drop point for the dashboard's
    # "Reduce events.db now" button. 1777 = sticky+world-write.
    system_command "/bin/mkdir",
                   args: ["-p", "/Library/Application Support/MacCrab/inbox"],
                   sudo: true
    system_command "/bin/chmod",
                   args: ["1777", "/Library/Application Support/MacCrab/inbox"],
                   sudo: true
    Dir.glob("#{staged_path}/compiled_rules/*.json").each do |f|
      system_command "/bin/cp", args: [f, "/Library/Application Support/MacCrab/compiled_rules/"], sudo: true
    end
    Dir.glob("#{staged_path}/compiled_rules/sequences/*.json").each do |f|
      system_command "/bin/cp", args: [f, "/Library/Application Support/MacCrab/compiled_rules/sequences/"], sudo: true
    end

    # The system extension itself is not installed here. It ships
    # inside MacCrab.app/Contents/Library/SystemExtensions/ and is
    # registered with sysextd the first time the user opens the app
    # and clicks "Enable Protection" (see SystemExtensionPanel.swift).

    # ── CLI symlink: point at the in-app binary, not the caskroom one
    # ───────────────────────────────────────────────────────────────────
    # The `binary` stanza above made brew install
    # /opt/homebrew/bin/maccrabctl as a symlink to the cask's
    # version-pinned copy in $HOMEBREW_PREFIX/Caskroom/maccrab/X.Y.Z/.
    # That copy is frozen at install time. When Sparkle updates
    # MacCrab.app in-place to v1.10+, the terminal CLI keeps
    # resolving to the v1.8 binary in the Caskroom path — and any
    # CLI subcommand added since then ("intel refresh", "trace ...",
    # "unsuppress --id") fails with "Unknown command". Replace the
    # symlink so it points at the CLI bundled inside MacCrab.app,
    # which Sparkle DOES update atomically.
    ["maccrabctl", "maccrab-mcp"].each do |cli|
      target = "/Applications/MacCrab.app/Contents/Resources/bin/#{cli}"
      link   = "#{HOMEBREW_PREFIX}/bin/#{cli}"
      next unless File.executable?(target)
      system_command "/bin/rm", args: ["-f", link], must_succeed: false
      system_command "/bin/ln", args: ["-s", target, link], must_succeed: false
    end
  end

  # v1.7.11 cask-only patch: clean up the user-context LaunchAgent that
  # SMAppService.mainApp.register() creates when a user enables
  # launch-at-login (Settings → General). Pre-fix the cask only handled
  # system-level LaunchDaemons (the ES sysext + legacy maccrabd plists),
  # so the SMAppService-registered agent persisted post-uninstall and
  # launchd kept trying to launch a now-missing binary on every login.
  # Two registration-name variants because SMAppService writes either:
  #   - ~/Library/LaunchAgents/com.maccrab.app.plist (legacy path)
  #   - ~/Library/LaunchAgents/79S425CW99.com.maccrab.app.plist (modern,
  #     team-id-prefixed; what most macOS 13+ systems actually create)
  uninstall quit:         ["com.maccrab.app"],
            # Belt-and-suspenders: if `quit` doesn't fully terminate the
            # menubar app within Homebrew's grace window (SwiftUI menubar
            # apps don't always respond to the quit AppleEvent if a
            # dialog or modal is up), force-signal SIGTERM. Field-
            # observed: post-uninstall a running process at PID-N kept
            # showing in `launchctl list` as `application.com.maccrab.app.X.Y`
            # because `quit` returned before the app actually exited.
            signal:        [["TERM", "com.maccrab.app"]],
            # Deactivate the system extension BEFORE the .app is removed.
            # Without this step sysextd's ledger keeps a "pending" entry
            # forever (visible via `systemextensionsctl list`) since the
            # bundle it references gets deleted out from under it. The
            # script may prompt for the user's password — that's fine
            # for an uninstall flow.
            early_script:  {
              executable:   "/usr/bin/systemextensionsctl",
              args:         ["uninstall", "79S425CW99", "com.maccrab.agent"],
              must_succeed: false,
              sudo:         true,
            },
            launchctl:     [
              "com.maccrab.agent",
              "com.maccrab.daemon",
              "com.maccrab.app",
              "79S425CW99.com.maccrab.app",
            ],
            delete:        [
              "/Library/LaunchDaemons/com.maccrab.agent.plist",
              "/Library/LaunchDaemons/com.maccrab.daemon.plist",
              "~/Library/LaunchAgents/com.maccrab.app.plist",
              "~/Library/LaunchAgents/79S425CW99.com.maccrab.app.plist",
            ]

  # /Library/Application Support/MacCrab is *deliberately* NOT in the
  # uninstall delete: list above. `brew upgrade` calls the uninstall
  # stanza between versions, so listing it there would wipe alerts,
  # baselines, suppressions, and LLM keys on every upgrade — which is
  # what bit v1.3.5 → v1.3.6 testers. The `zap` stanza below removes
  # it only on `brew uninstall --zap maccrab` for users who really
  # want a clean slate.
  zap trash: [
    "/Library/Application Support/MacCrab",
    "~/Library/Application Support/MacCrab",
    "~/Library/Preferences/com.maccrab.app.plist",
    "~/Library/Preferences/com.maccrab.agent.plist",
  ]

  caveats <<~EOS
    MacCrab protects the system via an Endpoint Security system
    extension. To activate:

      1. Open /Applications/MacCrab.app
      2. Click "Enable Protection" on the Overview tab
      3. Approve the extension in System Settings > General >
         Login Items & Extensions > Endpoint Security Extensions

    For full detection coverage also grant Full Disk Access to
    MacCrab.app in System Settings > Privacy & Security > Full
    Disk Access.

    After upgrading from v1.2.x: your prior install's LaunchDaemon
    was removed automatically. Approve the new extension in System
    Settings to restart protection.

    To uninstall the extension completely:
      systemextensionsctl uninstall 79S425CW99 com.maccrab.agent
  EOS
end
