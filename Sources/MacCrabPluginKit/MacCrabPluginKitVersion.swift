// MacCrabPluginKitVersion.swift
// MacCrabPluginKit
//
// Version marker for the plugin-author SDK. This is deliberately its OWN
// version, independent of the MacCrab app/engine version
// (`MacCrabCore.MacCrabVersion`): a plugin author pins against the SDK's
// API contract, not against whatever app build happens to embed it. The
// app can ship many releases without changing this string, and this string
// changes only when the SDK's public surface changes.
//
// SemVer intent:
//   • MAJOR — a breaking change to the public surface below (a removed or
//     renamed symbol, or a changed signature/semantics an author must react
//     to). A plugin built against an older MAJOR may need edits.
//   • MINOR — a backwards-compatible addition (a new helper). Existing
//     plugins keep working unchanged.
//   • PATCH — a behaviour-preserving fix. No source change for authors.
//
// Public API surface (v1.0.0), all under `TierBBroker`:
//   • `brokerFDEnv`  — the env var name carrying the broker socket fd
//   • `brokerFD`     — the broker socket fd when sandboxed, else nil
//   • `isSandboxed`  — true on the community/store (brokered) lane
//   • `openHandle(_:)`   — open a DECLARED read path as a read-only FileHandle
//   • `readDeclared(_:)` — read a DECLARED path's full contents
//
// Stability intent: the v1.x surface above is the supported contract for
// Tier-B plugin authors. Additions land as MINOR bumps; the listed symbols
// will not be removed or have their meaning changed within v1.x without a
// MAJOR bump and a CHANGELOG entry. First shipped in the MacCrab v1.21.3 app.
//
// Read this string at runtime to log/report the SDK your plugin was built
// against; see `CHANGELOG.md` in this directory for the per-version history.

public enum MacCrabPluginKitVersion {

    /// The SDK API-contract version this build of MacCrabPluginKit implements.
    /// Bumped only when the public surface changes (see the SemVer intent
    /// above), NOT on every app release.
    public static let current: String = "1.0.0"
}
