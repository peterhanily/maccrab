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
//   2. `MacCrabVersion.fallback` — the build-time string baked into
//      MacCrabCore.framework. Used when Bundle.main has no Info.plist
//      (bare daemon binary launched via `swift run maccrabd`, the
//      maccrabctl CLI symlinked into /usr/local/bin, the test bundle).
//
// Updating: bump `fallback` below whenever the project version changes.
// `scripts/prerelease-check.sh` enforces parity between this constant
// and `release.json`/`Casks/maccrab.rb`.

import Foundation

public enum MacCrabVersion {

    /// Build-time version string. Bumped manually each release; the
    /// prerelease-check script verifies this matches `release.json`,
    /// the cask, and the Info.plist values.
    public static let fallback: String = "1.12.4"

    /// Best available version string. Reads `CFBundleShortVersionString`
    /// from the host bundle when present, otherwise returns
    /// `MacCrabVersion.fallback`.
    public static var current: String {
        if let v = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String,
           !v.isEmpty {
            return v
        }
        return fallback
    }
}
