cask "maccrab" do
  version "1.2.3"
  sha256 "0b0cac0470fa9ccf7bb0e3732bec1877f07b2238649d3c24af6b3c54135efad7"

  url "https://github.com/peterhanily/maccrab/releases/download/v#{version}/MacCrab-v#{version}.dmg"
  name "MacCrab"
  desc "Local-first macOS threat detection engine with Sigma-compatible rules"
  homepage "https://github.com/peterhanily/maccrab"

  depends_on macos: ">= :ventura"

  app "MacCrab.app"
  binary "bin/maccrabd"
  binary "bin/maccrabctl"
  binary "bin/maccrab-mcp"

  postflight do
    # Upgrade path from pre-1.2.4: the daemon was labelled com.maccrab.daemon
    # before Apple bound the ES entitlement to com.maccrab.agent. Unload +
    # remove the old plist so the new one isn't shadowed.
    old_plist = "/Library/LaunchDaemons/com.maccrab.daemon.plist"
    if File.exist?(old_plist)
      system_command "/bin/launchctl", args: ["unload", old_plist], sudo: true, must_succeed: false
      system_command "/bin/rm", args: ["-f", old_plist], sudo: true
    end

    # Install compiled rules
    system_command "/bin/mkdir", args: ["-p", "/Library/Application Support/MacCrab/compiled_rules/sequences"], sudo: true
    Dir.glob("#{staged_path}/compiled_rules/*.json").each do |f|
      system_command "/bin/cp", args: [f, "/Library/Application Support/MacCrab/compiled_rules/"], sudo: true
    end
    Dir.glob("#{staged_path}/compiled_rules/sequences/*.json").each do |f|
      system_command "/bin/cp", args: [f, "/Library/Application Support/MacCrab/compiled_rules/sequences/"], sudo: true
    end

    # Install provisioning profile (Endpoint Security entitlement grant).
    # macOS indexes profiles by UUID under /Library/MobileDevice/... — the
    # embedded copy inside MacCrab.app is also honoured, but shipping both
    # is belt-and-braces so the daemon's standalone /usr/local/bin/maccrabd
    # invocation can also prove the entitlement grant.
    profile_src = "#{staged_path}/MacCrab.provisionprofile"
    if File.exist?(profile_src)
      system_command "/bin/mkdir", args: ["-p", "/Library/MobileDevice/Provisioning Profiles"], sudo: true
      uuid = `security cms -D -i "#{profile_src}" 2>/dev/null | /usr/libexec/PlistBuddy -c "Print :UUID" /dev/stdin 2>/dev/null`.strip
      unless uuid.empty?
        system_command "/bin/cp", args: [profile_src, "/Library/MobileDevice/Provisioning Profiles/#{uuid}.provisionprofile"], sudo: true
        system_command "/usr/sbin/chown", args: ["root:wheel", "/Library/MobileDevice/Provisioning Profiles/#{uuid}.provisionprofile"], sudo: true
        system_command "/bin/chmod", args: ["644", "/Library/MobileDevice/Provisioning Profiles/#{uuid}.provisionprofile"], sudo: true
      end
    end

    # Install LaunchDaemon for auto-start on boot
    plist_src = "#{staged_path}/com.maccrab.agent.plist"
    if File.exist?(plist_src)
      system_command "/bin/cp", args: [plist_src, "/Library/LaunchDaemons/com.maccrab.agent.plist"], sudo: true
      # Fix binary path for this machine's Homebrew prefix
      maccrabd_path = "#{HOMEBREW_PREFIX}/bin/maccrabd"
      system_command "/usr/bin/sed", args: ["-i", "", "s|/usr/local/bin/maccrabd|#{maccrabd_path}|g", "/Library/LaunchDaemons/com.maccrab.agent.plist"], sudo: true
      system_command "/usr/sbin/chown", args: ["root:wheel", "/Library/LaunchDaemons/com.maccrab.agent.plist"], sudo: true
      system_command "/bin/chmod", args: ["644", "/Library/LaunchDaemons/com.maccrab.agent.plist"], sudo: true
      system_command "/bin/launchctl", args: ["load", "/Library/LaunchDaemons/com.maccrab.agent.plist"], sudo: true
    end
  end

  uninstall launchctl: ["com.maccrab.agent", "com.maccrab.daemon"],
            delete:    [
              "/Library/Application Support/MacCrab",
              "/Library/LaunchDaemons/com.maccrab.agent.plist",
              "/Library/LaunchDaemons/com.maccrab.daemon.plist",
            ]

  zap trash: [
    "~/Library/Application Support/MacCrab",
    "~/Library/Preferences/com.maccrab.app.plist",
  ]

  caveats <<~EOS
    MacCrab daemon starts automatically on boot.

    Quick start:
      open /Applications/MacCrab.app   # Open dashboard
      maccrabctl status                # Check status

    Grant Full Disk Access for complete detection coverage:
      1. Open System Settings > Privacy & Security > Full Disk Access
      2. Click + and add /opt/homebrew/bin/maccrabd (or /usr/local/bin/maccrabd)
      3. Restart: sudo launchctl unload /Library/LaunchDaemons/com.maccrab.agent.plist
                  sudo launchctl load /Library/LaunchDaemons/com.maccrab.agent.plist

    Without FDA, MacCrab detects ~70% of threats. With FDA, 100%.
  EOS
end
