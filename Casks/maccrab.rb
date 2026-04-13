cask "maccrab" do
  version "1.1.1"
  sha256 "ee86897427e1b4818a498fec4c537951bd3af37b451f2205a98e238ded8c5ab1"

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
    Quick start:
      sudo maccrabd                    # Start detection daemon
      open /Applications/MacCrab.app   # Open dashboard
      maccrabctl status                # Check status

    IMPORTANT — Grant Full Disk Access for complete detection coverage:
      1. Open System Settings > Privacy & Security > Full Disk Access
      2. Click + and add /usr/local/bin/maccrabd
      3. Restart: sudo killall maccrabd && sudo maccrabd

    Without FDA, MacCrab detects ~70% of threats. With FDA, 100%.
  EOS
end
