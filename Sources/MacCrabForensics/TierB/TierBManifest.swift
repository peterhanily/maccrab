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

    /// Mach services the plugin may look up. Default empty (deny all).
    public let machServiceConnects: [String]

    /// Executables the plugin may spawn. Default empty (deny exec).
    public let processExecPaths: [String]

    /// Whether the plugin may fork / posix_spawn. Default FALSE — third-party
    /// code gets no fork unless it declares an exec allowlist AND the operator
    /// consents. (Previously this was hardcoded `true` in toSandboxProfileSpec,
    /// ignoring the manifest entirely — the "decorative capability" gap.)
    public let allowProcessFork: Bool

    // MARK: - Consent disclosure (signature-bound author labels)
    //
    // These are AUTHOR-DECLARED human-readable labels for the consent sheet. They
    // are NOT the authority — the authoritative read-set / network-set / TCC
    // exposure is DERIVED from the ENFORCED capability fields above (see
    // `consentSummary`), so a plugin cannot under-declare here while its enforced
    // caps read chat.db. Because they live in the signed manifest, a tampered
    // catalog cannot soften them either.

    /// Declared highest privacy class emitted ("metadata"|"content"|
    /// "personalComms"|"credentialAdjacent"|"secret"); nil = undeclared.
    public let privacyClass: String?
    /// Declared human-readable read-set, e.g. ["Messages chat.db", "Safari history"].
    public let dataSources: [String]
    /// Declared TCC services / protected stores required, e.g. ["FullDiskAccess"].
    public let tccRequirements: [String]

    public init(
        id: String,
        displayName: String,
        version: String,
        schemaVersion: Int,
        description: String,
        kind: TierBPluginKind? = nil,
        fileReadSubpaths: [String] = [],
        fileWriteSubpaths: [String] = [],
        networkConnectAllowlist: [String] = [],
        machServiceConnects: [String] = [],
        processExecPaths: [String] = [],
        allowProcessFork: Bool = false,
        privacyClass: String? = nil,
        dataSources: [String] = [],
        tccRequirements: [String] = []
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
        self.machServiceConnects = machServiceConnects
        self.processExecPaths = processExecPaths
        self.allowProcessFork = allowProcessFork
        self.privacyClass = privacyClass
        self.dataSources = dataSources
        self.tccRequirements = tccRequirements
    }

    // Lenient decode: only id/displayName/version/schemaVersion/description are
    // required. kind + the three capability arrays are optional (arrays absent →
    // [], kind absent → nil) so a minimal plugin manifest isn't brittle. Encode
    // stays synthesized. An unknown `kind` value is rejected (fail-closed).
    private enum CodingKeys: String, CodingKey {
        case id, displayName, version, schemaVersion, description, kind
        case fileReadSubpaths, fileWriteSubpaths, networkConnectAllowlist
        case machServiceConnects, processExecPaths, allowProcessFork
        case privacyClass, dataSources, tccRequirements
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
        machServiceConnects = try c.decodeIfPresent([String].self, forKey: .machServiceConnects) ?? []
        processExecPaths = try c.decodeIfPresent([String].self, forKey: .processExecPaths) ?? []
        // Fail-closed default: a manifest that omits the field gets NO fork.
        allowProcessFork = try c.decodeIfPresent(Bool.self, forKey: .allowProcessFork) ?? false
        privacyClass = try c.decodeIfPresent(String.self, forKey: .privacyClass)
        dataSources = try c.decodeIfPresent([String].self, forKey: .dataSources) ?? []
        tccRequirements = try c.decodeIfPresent([String].self, forKey: .tccRequirements) ?? []
    }

    /// Produce the SandboxProfileSpec this manifest declares.
    /// allowAllByDefault is always false for Tier B — we never ship a Tier B
    /// plugin with permissive defaults. ALL six capability fields are now
    /// mapped faithfully from the manifest (previously machServiceConnects /
    /// processExecPaths / allowProcessFork were discarded and fork was forced
    /// on — the capability manifest was decorative). Default fork is FALSE.
    public func toSandboxProfileSpec() -> SandboxProfileSpec {
        SandboxProfileSpec(
            allowAllByDefault: false,
            fileReadSubpaths: fileReadSubpaths,
            fileWriteSubpaths: fileWriteSubpaths,
            networkConnectAllowlist: networkConnectAllowlist,
            machServiceConnects: machServiceConnects,
            processExecPaths: processExecPaths,
            allowProcessFork: allowProcessFork
        )
    }

    /// Model-B sandbox spec for the SANDBOXED third-party lane: file READS are
    /// NOT granted in the SBPL — the broker is the file boundary (the plugin
    /// requests read-fds over fd 3, so a symlink/TOCTOU race or an undeclared
    /// path can never be opened directly). Only the plugin's own writes (its
    /// host-owned scratch + any declared write subpaths) plus network/exec/fork
    /// (when declared) are in the profile. (Plan §3.1 file-access decision.)
    public func toBrokeredSandboxProfileSpec(scratchDir: String) -> SandboxProfileSpec {
        SandboxProfileSpec(
            allowAllByDefault: false,
            fileReadSubpaths: [],                                  // brokered — never in the SBPL
            fileWriteSubpaths: fileWriteSubpaths + [scratchDir],
            networkConnectAllowlist: networkConnectAllowlist,
            machServiceConnects: machServiceConnects,
            processExecPaths: processExecPaths,
            allowProcessFork: allowProcessFork
        )
    }

    public static func load(fromBundlePath bundlePath: String) throws -> TierBManifest {
        let url = URL(fileURLWithPath: bundlePath).appendingPathComponent("manifest.json")
        let data = try Data(contentsOf: url)
        return try JSONDecoder().decode(TierBManifest.self, from: data)
    }

    /// The AUTHORITATIVE consent disclosure, DERIVED from the enforced capability
    /// fields (not the declared labels). The storefront consent sheet renders
    /// this so a user always sees the real read-set / network-set / TCC exposure.
    /// `home` resolves which declared reads are TCC-protected (brokered, never
    /// read live).
    public func consentSummary(home: String = NSHomeDirectory()) -> TierBConsentSummary {
        // Uses the SAME classifier as the broker's served-path TCC guard
        // (TierBFileBroker.guardTCC), so disclosure can't drift from enforcement:
        // a declared path AT/UNDER a TCC store (e.g. the exact chat.db) is a
        // brokered personal-comms read (snapshotted) and shows here; a broad
        // ANCESTOR root (e.g. ~/Library) is NOT a TCC read because the broker
        // fail-closes its TCC subtrees, so it honestly classifies as "content".
        let tcc = fileReadSubpaths.filter { TCCProtectedPaths.isProtected($0, home: home) }
        let derived: String
        if !tcc.isEmpty { derived = "personalComms" }            // conservative: TCC read → high friction
        else if !fileReadSubpaths.isEmpty { derived = "content" }
        else { derived = "metadata" }
        let underdeclared = TierBConsentSummary.privacyRank(privacyClass) < TierBConsentSummary.privacyRank(derived)
        return TierBConsentSummary(
            fileReads: fileReadSubpaths,
            tccReads: tcc,
            networkEndpoints: networkConnectAllowlist,
            execPaths: processExecPaths,
            allowsFork: allowProcessFork,
            derivedHighestPrivacy: derived,
            declaredPrivacyClass: privacyClass,
            declaredDataSources: dataSources,
            declaredTccRequirements: tccRequirements,
            privacyUnderdeclared: underdeclared)
    }
}

/// Authoritative, signature-bound consent disclosure derived from a Tier-B
/// manifest's ENFORCED capabilities — the storefront renders this, never an
/// under-declared author label.
public struct TierBConsentSummary: Sendable, Equatable {
    public let fileReads: [String]
    public let tccReads: [String]
    public let networkEndpoints: [String]
    public let execPaths: [String]
    public let allowsFork: Bool
    public let derivedHighestPrivacy: String
    public let declaredPrivacyClass: String?
    public let declaredDataSources: [String]
    public let declaredTccRequirements: [String]
    /// True when the declared class is LOWER than what the caps actually expose —
    /// the UI shows the derived class and flags the mismatch.
    public let privacyUnderdeclared: Bool

    public var readsPersonalComms: Bool { !tccReads.isEmpty }
    public var hasNetwork: Bool { !networkEndpoints.isEmpty }
    /// The high-friction grant (binding decision): a personal-comms reader that
    /// ALSO declares network egress is a disclosed exfil surface — consent must
    /// show read-set + network-set together and require a separate confirmation.
    public var isDisclosedExfilSurface: Bool { readsPersonalComms && hasNetwork }

    static func privacyRank(_ c: String?) -> Int {
        switch (c ?? "metadata").lowercased() {
        case "secret": return 4
        case "credentialadjacent": return 3
        case "personalcomms": return 2
        case "content": return 1
        default: return 0
        }
    }

    public init(
        fileReads: [String], tccReads: [String], networkEndpoints: [String],
        execPaths: [String], allowsFork: Bool, derivedHighestPrivacy: String,
        declaredPrivacyClass: String?, declaredDataSources: [String],
        declaredTccRequirements: [String], privacyUnderdeclared: Bool
    ) {
        self.fileReads = fileReads
        self.tccReads = tccReads
        self.networkEndpoints = networkEndpoints
        self.execPaths = execPaths
        self.allowsFork = allowsFork
        self.derivedHighestPrivacy = derivedHighestPrivacy
        self.declaredPrivacyClass = declaredPrivacyClass
        self.declaredDataSources = declaredDataSources
        self.declaredTccRequirements = declaredTccRequirements
        self.privacyUnderdeclared = privacyUnderdeclared
    }
}
