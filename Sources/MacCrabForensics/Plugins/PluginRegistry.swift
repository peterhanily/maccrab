// PluginRegistry — the static registry that holds every plugin
// the runtime knows about.
//
// In v1.13a, all plugins are first-party Swift code compiled into
// MacCrabForensics and registered at module bootstrap. The future
// Tier B (subprocess) plugins will register via a separate path
// once that lands (post-v1.15).
//
// Plan reference: §3.5 (lifecycle), §3.6 (discovery + loading).

import Foundation

/// One plugin's registration in the static registry. The factory
/// closure type-erases the plugin's ForensicPlugin conformance —
/// Swift existentials around static-requirement protocols are
/// awkward; the closure shape keeps the registry simple.
public struct PluginRegistration: Sendable {
    public let manifest: PluginManifest
    public let factory: @Sendable () async throws -> any ForensicPlugin

    public init(
        manifest: PluginManifest,
        factory: @escaping @Sendable () async throws -> any ForensicPlugin
    ) {
        self.manifest = manifest
        self.factory = factory
    }
}

/// Actor-isolated registry. The default shared instance is what
/// MacCrabForensicsBootstrap.registerBuiltins() populates; tests
/// can construct their own to avoid sharing state across cases.
public actor PluginRegistry {

    /// Shared instance — module-bootstrap fills this at MacCrabForensics
    /// init time so the rest of the codebase doesn't have to
    /// pass a registry around.
    public static let shared = PluginRegistry()

    private var entries: [String: PluginRegistration] = [:]

    public init() {}

    /// Register a plugin. Idempotent on plugin id — registering the
    /// same id twice replaces the previous entry. Throws if the
    /// manifest fails validation (catches authoring bugs at
    /// registration rather than first invocation).
    public func register(_ entry: PluginRegistration) throws {
        try entry.manifest.validate()
        entries[entry.manifest.id] = entry
    }

    /// All registered manifests, ordered alphabetically by id.
    public func manifests() -> [PluginManifest] {
        entries.values
            .map { $0.manifest }
            .sorted { $0.id < $1.id }
    }

    /// Filter by plugin kind.
    public func manifests(ofType type: PluginType) -> [PluginManifest] {
        manifests().filter { $0.type == type }
    }

    /// Look up a registration by id.
    public func registration(forID id: String) -> PluginRegistration? {
        entries[id]
    }

    /// Drop a registration. Used by tests; not exposed to release
    /// callers.
    func unregister(_ id: String) {
        entries.removeValue(forKey: id)
    }
}
