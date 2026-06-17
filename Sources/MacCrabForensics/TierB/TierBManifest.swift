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

/// Plugin role for a Tier B bundle (B1). Deliberately a 2-case enum — NOT the
/// 4-case Tier-A PluginType — because only these two are meaningful for the
/// out-of-process runtime. Optional on the wire: a manifest without `kind`
/// decodes to nil (treated as a collector by the runner for back-compat).
/// `.analyzer` execution is DEFERRED (no analyzer runner yet); only `.collector`
/// is dispatched to the TierBIPC subprocess today.
public enum TierBPluginKind: String, Codable, Sendable {
    case collector
    case analyzer
}

public struct TierBManifest: Codable, Sendable {
    public let id: String
    public let displayName: String
    public let version: String
    public let schemaVersion: Int
    public let description: String

    /// Plugin role (B1). Optional — absent decodes to nil (≈ collector).
    public let kind: TierBPluginKind?

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
        kind: TierBPluginKind? = nil,
        fileReadSubpaths: [String] = [],
        fileWriteSubpaths: [String] = [],
        networkConnectAllowlist: [String] = []
    ) {
        self.id = id
        self.displayName = displayName
        self.version = version
        self.schemaVersion = schemaVersion
        self.description = description
        self.kind = kind
        self.fileReadSubpaths = fileReadSubpaths
        self.fileWriteSubpaths = fileWriteSubpaths
        self.networkConnectAllowlist = networkConnectAllowlist
    }

    // Lenient decode: only id/displayName/version/schemaVersion/description are
    // required. kind + the three capability arrays are optional (arrays absent →
    // [], kind absent → nil) so a minimal plugin manifest isn't brittle. Encode
    // stays synthesized. An unknown `kind` value is rejected (fail-closed).
    private enum CodingKeys: String, CodingKey {
        case id, displayName, version, schemaVersion, description, kind
        case fileReadSubpaths, fileWriteSubpaths, networkConnectAllowlist
    }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        displayName = try c.decode(String.self, forKey: .displayName)
        version = try c.decode(String.self, forKey: .version)
        schemaVersion = try c.decode(Int.self, forKey: .schemaVersion)
        description = try c.decode(String.self, forKey: .description)
        kind = try c.decodeIfPresent(TierBPluginKind.self, forKey: .kind)
        fileReadSubpaths = try c.decodeIfPresent([String].self, forKey: .fileReadSubpaths) ?? []
        fileWriteSubpaths = try c.decodeIfPresent([String].self, forKey: .fileWriteSubpaths) ?? []
        networkConnectAllowlist = try c.decodeIfPresent([String].self, forKey: .networkConnectAllowlist) ?? []
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
