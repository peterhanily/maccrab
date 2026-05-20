// TierBManifest — the on-disk JSON manifest format installed
// Tier B plugins carry alongside their binary. Distinct from the
// in-process PluginManifest (which Tier A uses) because Tier B
// has different fields:
//   - xpcServiceIdentifier (deferred — release chapter)
//   - sandboxProfileSpec (consumed by TierBSubprocessLoader)
//   - schemaVersion + version (mirrors PluginManifest)
//
// Plan §3.6 + §3.9.

import Foundation

public struct TierBManifest: Codable, Sendable {
    public let id: String
    public let displayName: String
    public let version: String
    public let schemaVersion: Int
    public let description: String

    /// Subpaths the plugin reads. Used to populate
    /// SandboxProfileSpec.fileReadSubpaths at spawn time.
    public let fileReadSubpaths: [String]

    /// Subpaths the plugin writes. Default empty.
    public let fileWriteSubpaths: [String]

    /// Network endpoints the plugin connects to. Default empty
    /// (deny all network).
    public let networkConnectAllowlist: [String]

    public init(
        id: String,
        displayName: String,
        version: String,
        schemaVersion: Int,
        description: String,
        fileReadSubpaths: [String] = [],
        fileWriteSubpaths: [String] = [],
        networkConnectAllowlist: [String] = []
    ) {
        self.id = id
        self.displayName = displayName
        self.version = version
        self.schemaVersion = schemaVersion
        self.description = description
        self.fileReadSubpaths = fileReadSubpaths
        self.fileWriteSubpaths = fileWriteSubpaths
        self.networkConnectAllowlist = networkConnectAllowlist
    }

    /// Produce the SandboxProfileSpec this manifest declares.
    /// allowAllByDefault is always false for Tier B — we never
    /// ship a Tier B plugin with permissive defaults.
    public func toSandboxProfileSpec() -> SandboxProfileSpec {
        SandboxProfileSpec(
            allowAllByDefault: false,
            fileReadSubpaths: fileReadSubpaths,
            fileWriteSubpaths: fileWriteSubpaths,
            networkConnectAllowlist: networkConnectAllowlist,
            machServiceConnects: [],
            processExecPaths: [],
            allowProcessFork: true
        )
    }

    public static func load(fromBundlePath bundlePath: String) throws -> TierBManifest {
        let url = URL(fileURLWithPath: bundlePath).appendingPathComponent("manifest.json")
        let data = try Data(contentsOf: url)
        return try JSONDecoder().decode(TierBManifest.self, from: data)
    }
}
