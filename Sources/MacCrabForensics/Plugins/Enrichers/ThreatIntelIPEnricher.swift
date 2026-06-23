// ThreatIntelIPEnricher — com.maccrab.enricher.threatintel-ip.
//
// Mirrors ThreatIntelDomainEnricher for IPs: checks an IP in the subject against
// the LIVE threat-intel IOC cache (<app-support>/MacCrab/threat_intel/
// feed_cache.json) and labels a known-malicious match with its feed source +
// malware family. Previously shipped a static fixture set of RFC-5737
// documentation IPs (192.0.2.66, …) that never route — i.e. it never fired.

import Foundation
import MacCrabCore

public struct ThreatIntelIPEnricher: Enricher {

    public static let manifest = PluginManifest(
        id: "com.maccrab.enricher.threatintel-ip",
        version: "1.1.0",
        displayName: "Threat-Intel IP",
        description: "Checks an IP in the subject against the live threat-intel IOC cache (URLhaus / MalwareBazaar / Feodo, refreshed by the daemon) and labels a known-malicious match with its feed source + malware family. Reports no IOCs loaded honestly when the feed cache is empty.",
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

    private let malicious: [String: ThreatIntelDomainEnricher.Match]   // ip → match

    public init() async throws { self.init(cacheDir: ThreatIntelDomainEnricher.defaultCacheDir()) }

    public init(cacheDir: String) {
        var map: [String: ThreatIntelDomainEnricher.Match] = [:]
        if let ioc = ThreatIntelFeed.cachedIOCs(at: cacheDir) {
            for r in ioc.ips { map[r.value] = .init(source: r.source, family: r.malwareFamily) }
        }
        self.malicious = map
    }

    public func enrich(_ subject: EnrichmentSubject, stage: EnrichmentStage) async throws -> Enrichment {
        var fields: [String: EnrichmentValue] = [:]
        if let addr = GeoIPASNEnricher.extractIP(from: subject) {
            fields["threatintel.ip"] = .string(addr)
            if let m = malicious[addr] {
                fields["threatintel.ip_is_known_malicious"] = .bool(true)
                fields["threatintel.ip_source"] = .string(m.source)
                if let fam = m.family { fields["threatintel.ip_malware_family"] = .string(fam) }
            } else {
                fields["threatintel.ip_is_known_malicious"] = .bool(false)
            }
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
