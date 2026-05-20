// CodesigningAnomalyEnricher — com.maccrab.enricher.codesigning-anomaly.
//
// Plan §13.8. Flags surprising codesign postures on a path: an
// unsigned binary in a SIP-protected system directory; a
// Developer-ID-signed binary placed where only Apple-signed
// binaries should live; a binary whose path doesn't match any
// known framework / app bundle layout.
//
// Pure function on path. Pass 2026-C idempotency.

import Foundation
import MacCrabCore

public struct CodesigningAnomalyEnricher: Enricher {

    public static let manifest = PluginManifest(
        id: "com.maccrab.enricher.codesigning-anomaly",
        version: "1.0.0",
        displayName: "Codesigning Anomaly",
        description: "Flags surprising codesign postures: unsigned in /usr/, Developer-ID in /System/, mismatched anchor/path heuristics. Pure on path; idempotent per Pass 2026-C.",
        type: .enricher,
        runtime: .tierA,
        tccRequirements: [],
        inputs: [],
        outputs: [],
        mcpTools: [],
        schemaVersion: 1,
        stability: .preview
    )

    public var stages: Set<EnrichmentStage> { [.postEmission, .onDemand] }

    public init() async throws {}

    public func enrich(
        _ subject: EnrichmentSubject,
        stage: EnrichmentStage
    ) async throws -> Enrichment {
        let pathOpt: String? = {
            switch subject {
            case .path(let url): return url.path
            case .event(let p): return p.processExecutablePath
            case .alert(let p): return p.processExecutablePath
            }
        }()
        guard let path = pathOpt, !path.isEmpty, FileManager.default.fileExists(atPath: path) else {
            return Enrichment(
                pluginID: Self.manifest.id,
                pluginVersion: Self.manifest.version,
                schemaVersion: Self.manifest.schemaVersion,
                producedAt: Date(),
                fields: ["codesigning_anomaly.path_present": .bool(false)],
                confidence: .observed,
                privacyClass: .metadata
            )
        }

        let cache = CodeSigningCache()
        let info = await cache.evaluate(path: path)
        var anomalies: [String] = []

        // Anomaly: unsigned binary in a system-managed path.
        if info.signerType == .unsigned {
            if path.hasPrefix("/usr/bin/")
                || path.hasPrefix("/usr/sbin/")
                || path.hasPrefix("/System/") {
                anomalies.append("unsigned_in_system_path")
            }
        }
        // Anomaly: Developer-ID-signed binary in /System/.
        if info.signerType == .devId, path.hasPrefix("/System/") {
            anomalies.append("developer_id_in_system_dir")
        }
        // Anomaly: ad-hoc signed in /Applications/ or /usr/bin/.
        if info.isAdhocSigned == true {
            if path.hasPrefix("/Applications/")
                || path.hasPrefix("/usr/bin/")
                || path.hasPrefix("/usr/sbin/") {
                anomalies.append("adhoc_signed_outside_dev_tree")
            }
        }
        // Anomaly: notarized=false on a Developer-ID-signed app
        // outside dev directories.
        if info.signerType == .devId,
           !info.isNotarized,
           !path.hasPrefix("/Users/")
            && !path.hasPrefix("/private/tmp/") {
            anomalies.append("dev_id_unnotarized_in_system_area")
        }

        var fields: [String: EnrichmentValue] = [
            "codesigning_anomaly.path": .string(path),
            "codesigning_anomaly.has_anomalies": .bool(!anomalies.isEmpty),
            "codesigning_anomaly.flags": .stringArray(anomalies),
        ]
        if let teamID = info.teamId {
            fields["codesigning_anomaly.team_id"] = .string(teamID)
        }
        fields["codesigning_anomaly.signer_type"] = .string(info.signerType.rawValue)

        return Enrichment(
            pluginID: Self.manifest.id,
            pluginVersion: Self.manifest.version,
            schemaVersion: Self.manifest.schemaVersion,
            producedAt: Date(),
            fields: fields,
            confidence: .derived,
            privacyClass: .metadata
        )
    }
}
