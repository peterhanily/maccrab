// MacCrabForensicsBootstrap — central registration of built-in
// plugins. Called at module init from each top-level binary
// (maccrabctl, MacCrabApp, maccrab-mcp).
//
// Future plugin landings extend `registerBuiltins(into:)` with
// one more `try await registry.register(...)` line. Pass 2026-A
// audits the source-tree set against the registered set so
// nothing slips through.

import Foundation

public enum MacCrabForensicsBootstrap {

    /// Register every built-in plugin into the supplied registry.
    /// Idempotent on plugin id — re-registration replaces. The
    /// shared `PluginRegistry.shared` is the canonical target.
    public static func registerBuiltins(into registry: PluginRegistry = .shared) async throws {
        try await registry.register(PluginRegistration(
            manifest: FixturePlugin.manifest,
            factory: { try await FixturePlugin() }
        ))
        try await registry.register(PluginRegistration(
            manifest: CodesignResolveEnricher.manifest,
            factory: { try await CodesignResolveEnricher() }
        ))
        try await registry.register(PluginRegistration(
            manifest: TCCLitePlugin.manifest,
            factory: { try await TCCLitePlugin() }
        ))
    }
}
