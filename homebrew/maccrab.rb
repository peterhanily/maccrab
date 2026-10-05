cask "maccrab" do
  version "1.22.5"
  sha256 "d04fd517004ba5f349248aa789cde65e4e858b3b77d33121a47248d1e9f76ce9"

  url "https://github.com/peterhanily/maccrab/releases/download/v#{version}/MacCrab-v#{version}.dmg"
  name "MacCrab"
  desc "Local-first macOS threat detection engine with Sigma-compatible rules"
  homepage "https://github.com/peterhanily/maccrab"

  depends_on macos: :ventura

  app "MacCrab.app"
  binary "#{appdir}/MacCrab.app/Contents/Resources/bin/maccrabctl"
  binary "#{appdir}/MacCrab.app/Contents/Resources/bin/maccrab-mcp"

  # Homebrew 7 deprecates the Ruby `postflight` block ("Calling `postflight`
  # is deprecated! Use `postflight_steps` instead"), and the deprecation is a
  # hard error whenever HOMEBREW_DEVELOPER is set — which brew switches on by
  # itself after any developer command, so ordinary users hit it (issue #9).
  # `postflight_steps` is the structured replacement: literal DSL calls only,
  # no Ruby. The pre-1.3.0 provisioning-profile sweep needed Ruby and now
  # lives in scripts/install.sh only; a leftover system profile is inert
  # because the sysext embeds its own copy inside MacCrab.app.
  postflight_steps do
    # ── Clean up pre-1.3.0 artefacts ────────────────────────────────
    # 1.2.x shipped maccrabd as a LaunchDaemon. 1.3.0 moved the detection
    # engine into a SystemExtension activated from inside MacCrab.app on
    # first launch. Strip the old plumbing so the two models don't fight.
    if_path_exists "/Library/LaunchDaemons/com.maccrab.daemon.plist" do
      run "/bin/launchctl",
          args:         ["unload", "/Library/LaunchDaemons/com.maccrab.daemon.plist"],
          sudo:         true,
          must_succeed: false
      remove "/Library/LaunchDaemons/com.maccrab.daemon.plist", sudo: true
    end
    if_path_exists "/Library/LaunchDaemons/com.maccrab.agent.plist" do
      run "/bin/launchctl",
          args:         ["unload", "/Library/LaunchDaemons/com.maccrab.agent.plist"],
          sudo:         true,
          must_succeed: false
      remove "/Library/LaunchDaemons/com.maccrab.agent.plist", sudo: true
    end

    # Legacy standalone maccrabd symlinks. Missing paths are skipped.
    remove ["{{HOMEBREW_PREFIX}}/bin/maccrabd", "/usr/local/bin/maccrabd"], sudo: :if_needed

    # ── Prepare support directories ────────────────────────────────
    # v1.10.0 audit fix: inbox/ is the cross-UID IPC drop point for the
    # dashboard's "Reduce events.db now" button. 1777 = sticky+world-write.
    run "/bin/mkdir",
        args: ["-p",
               "/Library/Application Support/MacCrab/compiled_rules/sequences",
               "/Library/Application Support/MacCrab/compiled_rules/graph",
               "/Library/Application Support/MacCrab/inbox"],
        sudo: true
    run "/bin/chmod", args: ["1777", "/Library/Application Support/MacCrab/inbox"], sudo: true
    # Never update compiled_rules file-by-file in cask postflight. That can
    # destroy the previous verified corpus on ENOSPC/interruption and makes
    # upgrades needlessly double rule-storage use. The root System Extension
    # verifies its own code-sealed corpus and atomically publishes it before
    # starting any rule reader. Existing rules therefore survive upgrades
    # untouched until that transaction succeeds.

    # The system extension itself is not installed here. It ships
    # inside MacCrab.app/Contents/Library/SystemExtensions/ and is
    # registered with sysextd the first time the user opens the app
    # and clicks "Enable Protection" (see SystemExtensionPanel.swift).
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
            # NOTE: system-extension deactivation is intentionally NOT driven
            # from this uninstall stanza. Homebrew runs the uninstall steps on
            # `brew upgrade`/`brew reinstall` too (only `signal:` is skipped),
            # so deactivating here would tear down the live ES extension on
            # every routine upgrade — dropping real-time protection and popping
            # an approval modal mid-upgrade. On upgrade the freshly-installed
            # app re-activates idempotently, so no teardown is needed. On a
            # true uninstall, deactivate via the app's own "Disable Protection"
            # flow or the bundled scripts/uninstall.sh (which submits the
            # signed OSSystemExtensionRequest the same way the app does); a
            # leftover sysextd ledger entry is cosmetic and reconciles once the
            # bundle is gone. See caveats.
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

    `brew uninstall maccrab` removes the app and its launch services but
    intentionally leaves the Endpoint Security extension registered (Homebrew
    runs the same uninstall steps on every `brew upgrade`, so forcing a
    deactivate here would drop protection on routine upgrades). To fully
    remove the extension, click "Disable Protection" on MacCrab's
    Overview tab before uninstalling. Any leftover entry clears after a reboot (confirm with
    `systemextensionsctl list`).

    Your data (alerts, baselines, settings) is preserved at
    /Library/Application Support/MacCrab so upgrades don't wipe it. To
    remove it too:  brew uninstall --zap maccrab
  EOS
end
