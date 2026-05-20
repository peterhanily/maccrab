// CodesignResolveEnricher — com.maccrab.enricher.codesign-resolve.
//
// Thin Enricher wrapper around MacCrabCore.CodeSigningCache. For
// any exec event / alert / on-demand path, returns the binary's
// signing posture as a flat field bag:
//
//   codesign.team_id              Apple Developer Team Identifier
//   codesign.bundle_id            declared bundle identifier
//   codesign.signing_status       unsigned / adhoc / developer_id / apple / appstore / invalid / unknown
//   codesign.notarized            bool — stapled ticket present
//   codesign.hardened_runtime     bool — CS_RUNTIME flag set
//
// Plan reference: §5.3.
//
// Pass 2026-C invariant: `enrich(subject, stage)` MUST be
// byte-identical across re-runs on the same subject. This wrapper
// is idempotent because (a) CodeSigningCache caches by path,
// (b) the path → fields mapping is pure, (c) no time / random /
// network input is consulted. The idempotency test (lands with
// Pass 2026-C in v1.13a-2.3) re-runs the enricher and diffs the
// Enrichment.fields dictionaries.

import Foundation
import MacCrabCore

public struct CodesignResolveEnricher: Enricher {

    public static let manifest = PluginManifest(
        id: "com.maccrab.enricher.codesign-resolve",
        version: "1.0.0",
        displayName: "Codesign Resolve",
        description: "Resolves codesign posture (team id, signing status, notarization, hardened runtime, bundle id) for a binary at a given path. Caches by (path, mtime, size); idempotent.",
        type: .enricher,
        runtime: .tierA,
        tccRequirements: [],
        inputs: [],
        outputs: [],
        mcpTools: [
            MCPToolDescriptor(
                name: "codesign_resolve",
                description: "Return the codesign posture (team_id, signing_status, notarized, hardened_runtime, bundle_id) for a binary at a path.",
                exposesPrivacyClass: .metadata
            ),
        ],
        schemaVersion: 1,
        stability: .preview
    )

    public var stages: Set<EnrichmentStage> { [.preDetection, .onDemand] }

    /// CodeSigningCache instance, shared across all enrichments
    /// produced by this enricher. NSCache evicts under memory
    /// pressure; the actor wrapper keeps Swift concurrency happy.
    private let cache: CodeSigningCache

    public init() async throws {
        self.cache = CodeSigningCache()
    }

    public func enrich(
        _ subject: EnrichmentSubject,
        stage: EnrichmentStage
    ) async throws -> Enrichment {
        let path = Self.path(from: subject)
        let fields = await Self.fields(for: path, using: cache)
        return Enrichment(
            pluginID: Self.manifest.id,
            pluginVersion: Self.manifest.version,
            schemaVersion: Self.manifest.schemaVersion,
            producedAt: Date(),
            fields: fields,
            confidence: .observed,
            privacyClass: .metadata
        )
    }

    // MARK: - Subject resolution

    private static func path(from subject: EnrichmentSubject) -> String? {
        switch subject {
        case .event(let p):
            return p.processExecutablePath
        case .alert(let p):
            return p.processExecutablePath
        case .path(let url):
            return url.path
        }
    }

    // MARK: - Field extraction

    /// Map a CodeSignatureInfo to the flat field bag the plan
    /// names. `nil` path produces a single `codesign.signing_status
    /// = "unknown"` field so consumers always see consistent shape.
    private static func fields(
        for path: String?,
        using cache: CodeSigningCache
    ) async -> [String: EnrichmentValue] {
        guard let path = path, !path.isEmpty else {
            return [
                "codesign.signing_status": .string(SigningStatusToken.unknown.rawValue),
            ]
        }

        // Guard against unreadable / nonexistent paths up front so
        // we don't pay the SecStaticCode cost just to fail.
        guard FileManager.default.fileExists(atPath: path) else {
            return [
                "codesign.signing_status": .string(SigningStatusToken.unknown.rawValue),
                "codesign.error": .string("path_not_found"),
                "codesign.path": .string(path),
            ]
        }

        let info = await cache.evaluate(path: path)
        var fields: [String: EnrichmentValue] = [:]

        fields["codesign.signing_status"] = .string(signingStatusToken(for: info).rawValue)

        if let teamID = info.teamId, !teamID.isEmpty {
            fields["codesign.team_id"] = .string(teamID)
        }
        if let bundleID = info.signingId, !bundleID.isEmpty {
            fields["codesign.bundle_id"] = .string(bundleID)
        }
        fields["codesign.notarized"] = .bool(info.isNotarized)

        // CS_RUNTIME flag (hardened runtime). Bit value matches
        // Apple's cs_blobs.h definition (CS_RUNTIME = 0x10000).
        let CS_RUNTIME: UInt32 = 0x10000
        let hardened = (info.flags & CS_RUNTIME) != 0
        fields["codesign.hardened_runtime"] = .bool(hardened)

        return fields
    }

    /// Normalized signing-status token. Maps the multi-axis
    /// SignerType + isAdhocSigned + isValid surface from
    /// CodeSignatureInfo to the small string set declared in plan
    /// §5.3.
    private static func signingStatusToken(for info: CodeSignatureInfo) -> SigningStatusToken {
        switch info.signerType {
        case .apple:
            return .apple
        case .appStore:
            return .apple  // App Store distribution shares the Apple anchor
        case .devId:
            return .developerID
        case .adHoc:
            return .adhoc
        case .unsigned:
            return (info.isAdhocSigned ?? false) ? .adhoc : .unsigned
        }
    }
}

/// Normalized signing-status token per plan §5.3. Exposed at file
/// scope so tests + the Pass 2026-C idempotency check can reference
/// it by name.
enum SigningStatusToken: String {
    case unsigned
    case adhoc
    case developerID = "developer_id"
    case apple
    case invalid
    case unknown
}
