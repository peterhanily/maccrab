// ThreatIntelDomainEnricher — com.maccrab.enricher.threatintel-domain.
//
// Plan §13.8. Annotates an enrichment subject with threat-intel
// reputation for any domains observed in the subject's payload.
// v1.16.0-rc.8 ships a static-built-in IOC set; future iterations
// can pivot to live MacCrabCore.ThreatIntelFeed reads.
//
// Pure function on subject → byte-identical-on-re-run is the
// Pass 2026-C invariant; the paired test verifies.

import Foundation

public struct ThreatIntelDomainEnricher: Enricher {

    public static let manifest = PluginManifest(
        id: "com.maccrab.enricher.threatintel-domain",
        version: "1.0.0",
        displayName: "Threat-Intel Domain",
        description: "Annotates the subject's payload domains with built-in threat-intel reputation labels (known-malicious / known-phishing / known-benign). Pure function on subject — Pass 2026-C idempotency.",
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

    /// Built-in static IOC set. Future iteration: read from
    /// MacCrabCore.ThreatIntelFeed.cachedIOCs() so updates land
    /// without recompiling. Holding small + static here keeps the
    /// idempotency contract trivially provable.
    private static let knownMalicious: Set<String> = [
        "evil.example.com",
        "phishing.example.net",
    ]
    private static let knownPhishing: Set<String> = [
        "phishing.example.net",
        "credentials-grab.example.org",
    ]

    public init() async throws {}

    public func enrich(
        _ subject: EnrichmentSubject,
        stage: EnrichmentStage
    ) async throws -> Enrichment {
        let domain = Self.extractDomain(from: subject)
        var fields: [String: EnrichmentValue] = [:]
        if let d = domain {
            fields["threatintel.domain"] = .string(d)
            fields["threatintel.is_known_malicious"] = .bool(Self.knownMalicious.contains(d))
            fields["threatintel.is_known_phishing"] = .bool(Self.knownPhishing.contains(d))
        } else {
            fields["threatintel.domain_present"] = .bool(false)
        }
        return Enrichment(
            pluginID: Self.manifest.id,
            pluginVersion: Self.manifest.version,
            schemaVersion: Self.manifest.schemaVersion,
            producedAt: Date(),  // not part of the byte-identical guarantee
            fields: fields,
            confidence: .observed,
            privacyClass: .metadata
        )
    }

    static func extractDomain(from subject: EnrichmentSubject) -> String? {
        switch subject {
        case .path(let url):
            return url.host
        case .event(let p):
            return p.processExecutablePath.flatMap { URL(string: $0)?.host }
        case .alert(let p):
            return p.processExecutablePath.flatMap { URL(string: $0)?.host }
        }
    }
}
