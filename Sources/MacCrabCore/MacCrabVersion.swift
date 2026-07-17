// MacCrabVersion.swift
// MacCrabCore
//
// Single source of truth for the MacCrab version string at runtime.
//
// History: through v1.9.0 we shipped four separate hardcoded version
// literals — StartupBanner ("v1.3.4" → drifted to "v1.7.5"),
// DaemonBootstrap ("1.7.12"), maccrabctl ("v1.5.1"), OTLPOutput
// ("1.8.0"). Each had to be remembered on every release; each drifted
// independently. The v1.9.0 ship audit caught all four.
//
// Resolution order:
//   1. `Bundle.main.infoDictionary["CFBundleShortVersionString"]` — the
//      MacCrab.app and the .systemextension bundle both carry this in
//      their Info.plist (sourced from `Xcode/project.yml`). When code
//      runs inside either, this is the canonical answer.
//   2. The enclosing MacCrab.app's Info.plist — the bundled CLIs ship at
//      `MacCrab.app/Contents/Resources/bin/<tool>`, where `Bundle.main`
//      resolves to the bare CLI binary (no Info.plist), so step 1 misses.
//      We walk up from the executable to `<exec_dir>/../../Info.plist`
//      (i.e. `Contents/Info.plist`) and read `CFBundleShortVersionString`
//      so `maccrabctl version` / the MCP serverInfo track the installed
//      app version instead of the compiled-in literal.
//   3. `MacCrabVersion.fallback` — the build-time string baked into
//      MacCrabCore.framework. Used when neither bundle is present (bare
//      daemon binary launched via `swift run maccrabd`, the maccrabctl
//      CLI symlinked into /usr/local/bin, the test bundle).
//
// Updating: bump `fallback` below whenever the project version changes.
// `scripts/prerelease-check.sh` enforces parity between this constant
// and `release.json`/`Casks/maccrab.rb`.

import Foundation

public enum MacCrabVersion {

    /// Build-time version string. Bumped manually each release; the
    /// prerelease-check script verifies this matches `release.json`,
    /// the cask, and the Info.plist values.
    public static let fallback: String = "1.21.4-rc.6"

    /// Best available version string. Reads `CFBundleShortVersionString`
    /// from the host bundle (or the enclosing MacCrab.app for bundled
    /// CLIs) when present, otherwise returns `MacCrabVersion.fallback`.
    public static var current: String {
        if let v = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String,
           !v.isEmpty {
            return v
        }
        if let v = enclosingAppVersion(), !v.isEmpty {
            return v
        }
        return fallback
    }

    /// For binaries that are bundled CLIs inside MacCrab.app
    /// (`MacCrab.app/Contents/Resources/bin/<tool>`), `Bundle.main` is the
    /// bare executable and carries no Info.plist. Walk up from the running
    /// executable to `Contents/Info.plist` (two directories above the
    /// `bin/` dir) and read its short version string. Cheap (one stat +
    /// small plist read), and safe: returns nil if anything is missing or
    /// malformed rather than crashing, so dev/standalone runs fall through
    /// to `fallback`.
    private static func enclosingAppVersion() -> String? {
        let execURL = Bundle.main.executableURL ?? URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath()
        // <exec_dir>/../../Info.plist  i.e.  Contents/Resources/bin/.. /.. /Info.plist
        let plistURL = execURL
            .deletingLastPathComponent()   // bin/
            .deletingLastPathComponent()   // Resources/
            .deletingLastPathComponent()   // Contents/
            .appendingPathComponent("Info.plist")
        guard let data = try? Data(contentsOf: plistURL),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let v = plist["CFBundleShortVersionString"] as? String else {
            return nil
        }
        return v
    }
}
