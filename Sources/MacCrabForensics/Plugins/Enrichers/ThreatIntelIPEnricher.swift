// ThreatIntelIPEnricher — com.maccrab.enricher.threatintel-ip.
//
// Plan §13.8. Annotates the subject's IP addresses with built-in
// threat-intel reputation labels. Mirrors the shape of
// ThreatIntelDomainEnricher but operates on IPs instead.
// Static IOC set for v1.16.0-rc.12; live feed integration is the
// natural follow-up.

import Foundation

public struct ThreatIntelIPEnricher: Enricher {

    public static let manifest = PluginManifest(
        id: "com.maccrab.enricher.threatintel-ip",
        version: "1.0.0",
        displayName: "Threat-Intel IP",
        description: "Annotates the subject's payload IPs with built-in threat-intel reputation. Static IOC set; live feed integration deferred. Pass 2026-C idempotent.",
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

    private static let knownMaliciousIPs: Set<String> = [
        "192.0.2.66",       // RFC 5737 documentation prefix used as test marker
        "203.0.113.99",
    ]
    private static let knownC2IPs: Set<String> = [
        "198.51.100.42",
    ]

    public init() async throws {}

    public func enrich(_ subject: EnrichmentSubject, stage: EnrichmentStage) async throws -> Enrichment {
        let ip = GeoIPASNEnricher.extractIP(from: subject)
        var fields: [String: EnrichmentValue] = [:]
        if let addr = ip {
            fields["threatintel.ip"] = .string(addr)
            fields["threatintel.ip_is_known_malicious"] = .bool(Self.knownMaliciousIPs.contains(addr))
            fields["threatintel.ip_is_known_c2"] = .bool(Self.knownC2IPs.contains(addr))
        } else {
            fields["threatintel.ip_present"] = .bool(false)
        }
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
}
