// GeoIPASNEnricher — com.maccrab.enricher.geoip-asn.
//
// Classifies an IPv4 address into its RFC address-range type (loopback / private
// A-B-C / CGNAT / link-local / public) — a cheap "is this internal or routable"
// signal with no external dependency. It does NOT resolve ASN or geo-country: that
// needs a bundled MaxMind GeoIP2/ASN MMDB, which we deliberately do not ship. The
// previous build advertised ASN+country it never emitted; this is the honest shape.
// Pure function on subject — Pass 2026-C idempotency.

import Foundation

public struct GeoIPASNEnricher: Enricher {

    public static let manifest = PluginManifest(
        id: "com.maccrab.enricher.geoip-asn",
        version: "1.1.0",
        displayName: "IP Range Classifier",
        description: "Classifies an IPv4 address into its address-range type — loopback, private (class A/B/C), CGNAT, link-local, or public — a no-dependency internal-vs-routable signal. Does not resolve ASN or geo-country (no MaxMind MMDB is bundled). Pure function on subject — Pass 2026-C idempotency.",
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
        // A process event/alert carries no network destination in the enrichment
        // payload; IP-range classification runs on URL/path subjects (on-demand).
        case .event, .alert: host = nil
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
