cask "maccrab" do
  version "1.2.4"
  sha256 "c14f5d16748facf97bab762164bbeee228655efa139b8a579514b29a7f53be52"

  url "https://github.com/peterhanily/maccrab/releases/download/v#{version}/MacCrab-v#{version}.dmg"
  name "MacCrab"
  desc "Local-first macOS threat detection engine with Sigma-compatible rules"
  homepage "https://github.com/peterhanily/maccrab"

  depends_on macos: ">= :ventura"

  app "MacCrab.app"
  binary "bin/maccrabctl"
  binary "bin/maccrab-mcp"

  postflight do
    # Upgrade path: the 1.2.4 install (and earlier) shipped maccrabd as a
    # standalone binary at $HOMEBREW_PREFIX/bin/maccrabd. macOS AMFI
    # couldn't discover the embedded provisioning profile for a binary
    # outside a .app bundle, so ES attempts resulted in SIGKILL. 1.2.5
    # relocated the daemon to MacCrab.app/Contents/Library/LaunchDaemons/
    # — remove the stale symlinks / plist paths that pointed at the old
    # location before starting the new daemon.
    ["#{HOMEBREW_PREFIX}/bin/maccrabd",
     "/usr/local/bin/maccrabd"].each do |path|
      if File.symlink?(path) || File.exist?(path)
        system_command "/bin/rm", args: ["-f", path], sudo: true
      end
    end

    # Upgrade path from pre-1.2.4: the daemon was labelled com.maccrab.daemon
    # before Apple bound the ES entitlement to com.maccrab.agent. Unload +
    # remove the old plist so the new one isn't shadowed.
    old_plist = "/Library/LaunchDaemons/com.maccrab.daemon.plist"
    if File.exist?(old_plist)
      system_command "/bin/launchctl", args: ["unload", old_plist], sudo: true, must_succeed: false
      system_command "/bin/rm", args: ["-f", old_plist], sudo: true
    end

    # Also unload any running 1.2.4 com.maccrab.agent daemon that was
    # trying to launch the now-gone /opt/homebrew/bin/maccrabd binary.
    stale_agent = "/Library/LaunchDaemons/com.maccrab.agent.plist"
    if File.exist?(stale_agent)
      system_command "/bin/launchctl", args: ["unload", stale_agent], sudo: true, must_succeed: false
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
      # Extract UUID via a temp plist file — piping `security cms | PlistBuddy
      # /dev/stdin` is unreliable in Ruby backticks (PlistBuddy reads
      # "/dev/stdin" literally and frequently emits "Error Reading File"
      # into stdout, which would then contaminate the destination filename).
      tmp_plist = "/tmp/maccrab-profile-#{Process.pid}.plist"
      system("/usr/bin/security cms -D -i '#{profile_src}' -o '#{tmp_plist}' 2>/dev/null")
      uuid = ""
      if File.exist?(tmp_plist)
        uuid = `/usr/libexec/PlistBuddy -c "Print :UUID" "#{tmp_plist}" 2>/dev/null`.strip
        File.delete(tmp_plist) rescue nil
      end
      # Sanity-check: real UUIDs are 36 chars in the 8-4-4-4-12 pattern.
      # Anything else (including stderr leakage) is rejected before we let
      # it reach a filesystem operation.
      if uuid.match?(/\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\z/)
        system_command "/bin/cp", args: [profile_src, "/Library/MobileDevice/Provisioning Profiles/#{uuid}.provisionprofile"], sudo: true
        system_command "/usr/sbin/chown", args: ["root:wheel", "/Library/MobileDevice/Provisioning Profiles/#{uuid}.provisionprofile"], sudo: true
        system_command "/bin/chmod", args: ["644", "/Library/MobileDevice/Provisioning Profiles/#{uuid}.provisionprofile"], sudo: true
      end
    end

    # Install LaunchDaemon for auto-start on boot. The plist's
    # ProgramArguments already points at
    # /Applications/MacCrab.app/Contents/Library/LaunchDaemons/maccrabd
    # — no path rewriting needed regardless of Homebrew prefix.
    plist_src = "#{staged_path}/com.maccrab.agent.plist"
    if File.exist?(plist_src)
      system_command "/bin/cp", args: [plist_src, "/Library/LaunchDaemons/com.maccrab.agent.plist"], sudo: true
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
