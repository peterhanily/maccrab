cask "maccrab" do
  version "1.1.1"
  sha256 "5120258ad253548d2daed57d92c46ad45a10ae6605385b1253e9906ff2d5c6b8"

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
    # Install compiled rules
    system_command "/bin/mkdir", args: ["-p", "/Library/Application Support/MacCrab/compiled_rules/sequences"], sudo: true
    Dir.glob("#{staged_path}/compiled_rules/*.json").each do |f|
      system_command "/bin/cp", args: [f, "/Library/Application Support/MacCrab/compiled_rules/"], sudo: true
    end
    Dir.glob("#{staged_path}/compiled_rules/sequences/*.json").each do |f|
      system_command "/bin/cp", args: [f, "/Library/Application Support/MacCrab/compiled_rules/sequences/"], sudo: true
    end

    # Install LaunchDaemon for auto-start on boot
    plist_src = "#{staged_path}/com.maccrab.daemon.plist"
    if File.exist?(plist_src)
      system_command "/bin/cp", args: [plist_src, "/Library/LaunchDaemons/com.maccrab.daemon.plist"], sudo: true
      # Fix binary path for this machine's Homebrew prefix
      maccrabd_path = "#{HOMEBREW_PREFIX}/bin/maccrabd"
      system_command "/usr/bin/sed", args: ["-i", "", "s|/usr/local/bin/maccrabd|#{maccrabd_path}|g", "/Library/LaunchDaemons/com.maccrab.daemon.plist"], sudo: true
      system_command "/usr/sbin/chown", args: ["root:wheel", "/Library/LaunchDaemons/com.maccrab.daemon.plist"], sudo: true
      system_command "/bin/chmod", args: ["644", "/Library/LaunchDaemons/com.maccrab.daemon.plist"], sudo: true
      system_command "/bin/launchctl", args: ["load", "/Library/LaunchDaemons/com.maccrab.daemon.plist"], sudo: true
    end
  end

  uninstall launchctl: "com.maccrab.daemon",
            delete:    [
              "/Library/Application Support/MacCrab",
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
      3. Restart: sudo launchctl unload /Library/LaunchDaemons/com.maccrab.daemon.plist
                  sudo launchctl load /Library/LaunchDaemons/com.maccrab.daemon.plist

    Without FDA, MacCrab detects ~70% of threats. With FDA, 100%.
  EOS
end
