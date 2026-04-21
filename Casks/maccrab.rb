cask "maccrab" do
  version "1.4.3"
  sha256 "1e948e8eb0aa1767fe3e96d3442f4ea089ff2e5821541b2a41840effdc74f81b"

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
  end

  uninstall launchctl: ["com.maccrab.agent", "com.maccrab.daemon"],
            delete:    [
              "/Library/LaunchDaemons/com.maccrab.agent.plist",
              "/Library/LaunchDaemons/com.maccrab.daemon.plist",
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
