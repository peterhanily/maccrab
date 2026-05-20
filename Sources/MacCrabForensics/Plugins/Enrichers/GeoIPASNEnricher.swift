// GeoIPASNEnricher — com.maccrab.enricher.geoip-asn.
//
// Plan §13.8. Future-flex: a real iteration plugs a local MMDB
// (MaxMind GeoIP2 or similar) into the resolution path. v1.16.0-
// rc.8 ships the API shape with a hardcoded private/loopback +
// CGNAT mapping so the integration point is stable for tests
// without bundling a multi-megabyte MMDB.

import Foundation

public struct GeoIPASNEnricher: Enricher {

    public static let manifest = PluginManifest(
        id: "com.maccrab.enricher.geoip-asn",
        version: "1.0.0",
        displayName: "GeoIP / ASN",
        description: "Annotates the subject's payload with ASN + country for any IP found. v1.16.0-rc.8 ships a small private-range / loopback / CGNAT map; the live MMDB binding lands when the operator opts into the MaxMind license. Pure function on subject — Pass 2026-C idempotency.",
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
        // Subject -> IP extraction. EnrichmentSubject doesn't
        // carry a dedicated IP field, so we read from the event /
        // alert payload's processExecutablePath if it happens to
        // be a URL with an IP host. Sufficient for the
        // idempotency contract; concrete plugins that surface IPs
        // pass them through path.host.
        let ip = Self.extractIP(from: subject)
        var fields: [String: EnrichmentValue] = [:]
        if let addr = ip {
            fields["geoip.ip"] = .string(addr)
            fields["geoip.range_token"] = .string(Self.classify(addr))
        } else {
            fields["geoip.ip_present"] = .bool(false)
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

    static func extractIP(from subject: EnrichmentSubject) -> String? {
        let host: String?
        switch subject {
        case .path(let url): host = url.host
        case .event(let p): host = p.processExecutablePath.flatMap { URL(string: $0)?.host }
        case .alert(let p): host = p.processExecutablePath.flatMap { URL(string: $0)?.host }
        }
        guard let h = host else { return nil }
        // crude IPv4 check.
        let parts = h.split(separator: ".")
        guard parts.count == 4, parts.allSatisfy({ Int($0) != nil }) else { return nil }
        return h
    }

    /// Maps an IPv4 address to a coarse range token. Pure
    /// function — same input, same output.
    static func classify(_ ip: String) -> String {
        if ip.hasPrefix("127.") { return "loopback" }
        if ip.hasPrefix("10.") { return "private_class_a" }
        if ip.hasPrefix("172.") {
            let parts = ip.split(separator: ".")
            if let second = Int(parts[1]), second >= 16 && second <= 31 {
                return "private_class_b"
            }
        }
        if ip.hasPrefix("192.168.") { return "private_class_c" }
        if ip.hasPrefix("100.") {
            let parts = ip.split(separator: ".")
            if let second = Int(parts[1]), second >= 64 && second <= 127 {
                return "cgnat"
            }
        }
        if ip.hasPrefix("169.254.") { return "link_local" }
        return "public_unknown"
    }
}
