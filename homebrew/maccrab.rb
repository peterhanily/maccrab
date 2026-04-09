cask "maccrab" do
  version "1.0.0"
  sha256 :no_check  # Updated per release

  url "https://github.com/peterhanily/maccrab/releases/download/v#{version}/MacCrab-v#{version}.dmg"
  name "MacCrab"
  desc "Local-first macOS threat detection engine with Sigma-compatible rules"
  homepage "https://github.com/peterhanily/maccrab"

  depends_on macos: ">= :ventura"

  app "MacCrab.app"
  binary "bin/maccrabd"
  binary "bin/maccrabctl"

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
    MacCrab requires root to access kernel events:
      sudo maccrabd

    For full Endpoint Security coverage, grant Full Disk Access to Terminal:
      System Settings → Privacy & Security → Full Disk Access → Terminal.app

    Quick start:
      sudo maccrabd                    # Start detection daemon
      open /Applications/MacCrab.app   # Open dashboard
      maccrabctl status                # Check status
  EOS
end
