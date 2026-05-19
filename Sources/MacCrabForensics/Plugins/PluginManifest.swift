// PluginManifest — the single Codable record every plugin advertises
// to the runtime, the dashboard, the MCP server, and the audit
// scripts.
//
// Plan reference: §3.3 (schema), §3.8 audit Pass 2026-A (manifest
// integrity checks).

import Foundation

/// Single source of truth about a plugin's identity, version,
/// declared TCC scope, IO contract, and MCP surface.
///
/// Loaded:
///   - statically at app launch for first-party plugins (registered
///     by `PluginRegistry`),
///   - from disk for store-installed plugins once Tier B + the
///     plugin registry ship (post-v1.15, plan §12).
///
/// Validated by `PluginManifest.validate()` AND by `scripts/
/// pre-release-audit.sh` Pass 2026-A. The two paths intentionally
/// duplicate checks: the runtime gates loading, the audit script
/// gates release.
public struct PluginManifest: Codable, Sendable {

    /// Reverse-DNS-style identifier. `com.maccrab.*` reserved for
    /// first-party. Examples:
    ///   - `com.maccrab.forensics.tcc-lite`
    ///   - `com.maccrab.forensics.launchd-lite`
    ///   - `com.maccrab.enricher.codesign-resolve`
    ///   - `com.maccrab.fingerprinter.mcfp`            (v1.15 conditional)
    ///   - `com.maccrab.forensics.posture-analyzer`    (v1.15)
    ///
    /// Uniqueness enforced at register-time AND by Pass 2026-A
    /// across the source tree.
    public let id: String

    /// SemVer string. Schema-bump = major version bump.
    public let version: String

    /// Human-readable label shown in dashboard + MCP tool list.
    public let displayName: String

    /// Concise operator-facing description; shown in `plugin info`.
    public let description: String

    /// Which plugin kind this is. Drives which protocol the
    /// implementing type conforms to.
    public let type: PluginType

    /// Trust tier. `.tierA` only in v1.13a. `.tierB` is reserved
    /// (post-store).
    public let runtime: PluginRuntime

    /// TCC services this plugin requires. Loading binary's
    /// `Info.plist` must declare matching usage-description strings
    /// (Pass 2026-A audit invariant).
    public let tccRequirements: [TCCService]

    /// Operator-supplied input parameters. May be empty.
    public let inputs: [InputSpec]

    /// Declared output content types + their privacy classes. May be
    /// empty for Enrichers (which return values rather than commit
    /// artifacts) — see `Enrichment` for that shape.
    public let outputs: [OutputSpec]

    /// MCP tools auto-registered when the plugin loads. Empty array
    /// is fine — the plugin may be CLI-only.
    public let mcpTools: [MCPToolDescriptor]

    /// Internal schema version of the plugin's emitted artifacts.
    /// Increment when the JSON shape of a `contentType` changes
    /// incompatibly. Stored on every committed artifact so the
    /// dashboard can render multi-version case stores.
    public let schemaVersion: Int

    /// Maturity label.
    public let stability: Stability

    public init(
        id: String,
        version: String,
        displayName: String,
        description: String,
        type: PluginType,
        runtime: PluginRuntime,
        tccRequirements: [TCCService],
        inputs: [InputSpec],
        outputs: [OutputSpec],
        mcpTools: [MCPToolDescriptor],
        schemaVersion: Int,
        stability: Stability
    ) {
        self.id = id
        self.version = version
        self.displayName = displayName
        self.description = description
        self.type = type
        self.runtime = runtime
        self.tccRequirements = tccRequirements
        self.inputs = inputs
        self.outputs = outputs
        self.mcpTools = mcpTools
        self.schemaVersion = schemaVersion
        self.stability = stability
    }

    // MARK: - Validation

    /// Errors `validate()` can produce. The runtime maps these to
    /// log entries; the audit script (Pass 2026-A) maps them to
    /// release-blocking failures with the manifest location cited.
    public enum ValidationError: Error, Equatable, CustomStringConvertible {
        case emptyID
        case malformedIDFormat(String)
        case firstPartyIDOutsideReservedNamespace(String)
        case unsupportedRuntime(PluginRuntime)
        case emptyVersion
        case malformedSemVer(String)
        case schemaVersionMustBePositive(Int)
        case duplicateContentType(String)
        case contentTypeNamespaceMismatch(contentType: String, pluginID: String)
        case duplicateMCPToolName(String)
        case inputRequiredButHasNoDefault(String)
        case duplicateInputName(String)

        public var description: String {
            switch self {
            case .emptyID:
                return "PluginManifest.id is empty"
            case .malformedIDFormat(let id):
                return "PluginManifest.id '\(id)' must be reverse-DNS-style (lowercase, dots, hyphens, at least three segments)"
            case .firstPartyIDOutsideReservedNamespace(let id):
                return "PluginManifest.id '\(id)' starts with com.maccrab but is not under com.maccrab.{forensics,enricher,fingerprinter,analyzer}.*"
            case .unsupportedRuntime(let r):
                return "PluginManifest.runtime '\(r.rawValue)' is not accepted in this build (v1.13a accepts .tierA only)"
            case .emptyVersion:
                return "PluginManifest.version is empty"
            case .malformedSemVer(let v):
                return "PluginManifest.version '\(v)' is not SemVer (expected MAJOR.MINOR.PATCH, integers only)"
            case .schemaVersionMustBePositive(let n):
                return "PluginManifest.schemaVersion must be >= 1; got \(n)"
            case .duplicateContentType(let ct):
                return "PluginManifest.outputs contains duplicate contentType '\(ct)'"
            case .contentTypeNamespaceMismatch(let ct, let pid):
                return "PluginManifest.outputs contentType '\(ct)' must share a namespace prefix with plugin id '\(pid)'"
            case .duplicateMCPToolName(let n):
                return "PluginManifest.mcpTools contains duplicate tool name '\(n)'"
            case .inputRequiredButHasNoDefault(let n):
                return "PluginManifest.inputs entry '\(n)' is required=true but supplies no default (acceptable only if the CLI / MCP path enforces value supply at invocation; explicit declaration preferred)"
            case .duplicateInputName(let n):
                return "PluginManifest.inputs contains duplicate name '\(n)'"
            }
        }
    }

    /// In-source validation. The audit script re-runs the same
    /// invariants against committed YAML / Codable representations.
    public func validate() throws {
        // id
        let id = self.id
        guard !id.isEmpty else { throw ValidationError.emptyID }
        try Self.checkIDShape(id)
        if id.hasPrefix("com.maccrab.") {
            try Self.checkFirstPartyNamespace(id)
        }

        // runtime
        guard runtime == .tierA else {
            throw ValidationError.unsupportedRuntime(runtime)
        }

        // version
        guard !version.isEmpty else { throw ValidationError.emptyVersion }
        try Self.checkSemVer(version)

        // schemaVersion
        guard schemaVersion >= 1 else {
            throw ValidationError.schemaVersionMustBePositive(schemaVersion)
        }

        // outputs: unique contentTypes; each shares a namespace prefix
        var seenCT = Set<String>()
        for o in outputs {
            if !seenCT.insert(o.contentType).inserted {
                throw ValidationError.duplicateContentType(o.contentType)
            }
            try Self.checkContentTypeNamespace(o.contentType, againstID: id)
        }

        // mcpTools: unique names
        var seenTool = Set<String>()
        for t in mcpTools {
            if !seenTool.insert(t.name).inserted {
                throw ValidationError.duplicateMCPToolName(t.name)
            }
        }

        // inputs: unique names; required + no default invariant
        var seenInput = Set<String>()
        for i in inputs {
            if !seenInput.insert(i.name).inserted {
                throw ValidationError.duplicateInputName(i.name)
            }
            if i.required && i.default == nil {
                // Allowed but flagged. The CLI / MCP layer must
                // enforce supply. We surface as an error so authors
                // are forced to either set required=false (with a
                // default) or document the runtime enforcement.
                // Concrete plugins can call this out in their own
                // validate-extra paths; the global check stays
                // strict.
                throw ValidationError.inputRequiredButHasNoDefault(i.name)
            }
        }
    }

    // MARK: - Validation helpers

    private static func checkIDShape(_ id: String) throws {
        // Lowercase reverse-DNS: at least three segments, each
        // composed of [a-z0-9-]+, joined by dots. Restrictive on
        // purpose — keeps audit Pass 2026-A regex simple.
        let segments = id.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count >= 3 else {
            throw ValidationError.malformedIDFormat(id)
        }
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789-")
        for s in segments {
            guard !s.isEmpty else {
                throw ValidationError.malformedIDFormat(id)
            }
            if s.unicodeScalars.contains(where: { !allowed.contains($0) }) {
                throw ValidationError.malformedIDFormat(id)
            }
        }
    }

    private static let firstPartyAllowedRoots: [String] = [
        "com.maccrab.forensics",
        "com.maccrab.enricher",
        "com.maccrab.fingerprinter",
        "com.maccrab.analyzer",
    ]

    private static func checkFirstPartyNamespace(_ id: String) throws {
        for root in firstPartyAllowedRoots {
            if id == root || id.hasPrefix(root + ".") {
                return
            }
        }
        throw ValidationError.firstPartyIDOutsideReservedNamespace(id)
    }

    private static func checkSemVer(_ v: String) throws {
        let parts = v.split(separator: ".")
        guard parts.count == 3 else {
            throw ValidationError.malformedSemVer(v)
        }
        for p in parts {
            if Int(p) == nil {
                throw ValidationError.malformedSemVer(v)
            }
        }
    }

    /// A `contentType` must share its first dot-segment with one of
    /// the plugin id's segments excluding the `com.maccrab.<kind>`
    /// prefix. Examples that pass:
    ///   plugin id `com.maccrab.forensics.tcc-lite` →
    ///     contentType `tcc.grant`  (shares 'tcc' with 'tcc-lite')
    ///     contentType `tcc.grant_added`
    /// Examples that fail:
    ///   plugin id `com.maccrab.forensics.tcc-lite` →
    ///     contentType `launchd.entry`  (no shared segment)
    ///
    /// The rule keeps `pluginID → contentType` traceable by eye.
    /// Pass 2026-A audits the same shape against committed manifests.
    private static func checkContentTypeNamespace(
        _ contentType: String,
        againstID id: String
    ) throws {
        let ctSegments = contentType.split(separator: ".").map(String.init)
        guard let ctRoot = ctSegments.first, !ctRoot.isEmpty else {
            throw ValidationError.contentTypeNamespaceMismatch(
                contentType: contentType,
                pluginID: id
            )
        }
        // Strip the `com.maccrab.<kind>.` prefix to extract the
        // plugin's leaf-identifying segments.
        let idSegments = id.split(separator: ".").map(String.init)
        guard idSegments.count >= 4 else {
            // Non-first-party id — looser check: any id segment
            // shared with ctRoot passes. Validator doesn't strictly
            // enforce structure for third-party ids.
            if idSegments.contains(ctRoot) { return }
            throw ValidationError.contentTypeNamespaceMismatch(
                contentType: contentType,
                pluginID: id
            )
        }
        // Match against the post-`com.maccrab.<kind>.` segments.
        let leafSegments = Array(idSegments.dropFirst(3))
        // Tolerate hyphen / underscore mismatch: `tcc-lite` → `tcc`.
        let normalizedLeaves = leafSegments.flatMap { leaf -> [String] in
            var out: [String] = [leaf]
            out.append(contentsOf: leaf.split(whereSeparator: { $0 == "-" || $0 == "_" }).map(String.init))
            return out
        }
        if normalizedLeaves.contains(ctRoot) { return }
        throw ValidationError.contentTypeNamespaceMismatch(
            contentType: contentType,
            pluginID: id
        )
    }
}
