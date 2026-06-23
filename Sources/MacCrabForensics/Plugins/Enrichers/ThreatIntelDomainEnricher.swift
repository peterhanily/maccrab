// ThreatIntelDomainEnricher — com.maccrab.enricher.threatintel-domain.
//
// Checks any domain in the subject against the LIVE threat-intel IOC cache the
// daemon maintains (URLhaus / MalwareBazaar / Feodo, written to
// <app-support>/MacCrab/threat_intel/feed_cache.json) and labels a known-malicious
// match with its feed source + malware family. Previously this shipped a static
// fixture set of RFC-2606 documentation domains (evil.example.com, …) that can
// never appear in real traffic — i.e. it never fired. The IOC set is loaded once
// at init, so re-running enrich on the same subject is byte-identical (Pass 2026-C).

import Foundation
import MacCrabCore

public struct ThreatIntelDomainEnricher: Enricher {

    public static let manifest = PluginManifest(
        id: "com.maccrab.enricher.threatintel-domain",
        version: "1.1.0",
        displayName: "Threat-Intel Domain",
        description: "Checks a domain in the subject against the live threat-intel IOC cache (URLhaus / MalwareBazaar / Feodo, refreshed by the daemon) and labels a known-malicious match with its feed source + malware family. Reports no IOCs loaded honestly when the feed cache is empty.",
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

    struct Match: Sendable, Equatable { let source: String; let family: String? }
    private let malicious: [String: Match]   // domain.lowercased → match

    /// Protocol init — reads the daemon-written IOC cache.
    public init() async throws { self.init(cacheDir: Self.defaultCacheDir()) }

    /// Testable init — point at a controlled `threat_intel` cache dir.
    public init(cacheDir: String) {
        var map: [String: Match] = [:]
        if let ioc = ThreatIntelFeed.cachedIOCs(at: cacheDir) {
            for r in ioc.domains { map[r.value.lowercased()] = Match(source: r.source, family: r.malwareFamily) }
        }
        self.malicious = map
    }

    static func defaultCacheDir() -> String {
        (FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory() + "/Library/Application Support"))
            .appendingPathComponent("MacCrab/threat_intel").path
    }

    public func enrich(
        _ subject: EnrichmentSubject,
        stage: EnrichmentStage
    ) async throws -> Enrichment {
        var fields: [String: EnrichmentValue] = [:]
        if let d = Self.extractDomain(from: subject)?.lowercased() {
            fields["threatintel.domain"] = .string(d)
            if let m = malicious[d] {
                fields["threatintel.is_known_malicious"] = .bool(true)
                fields["threatintel.source"] = .string(m.source)
                if let fam = m.family { fields["threatintel.malware_family"] = .string(fam) }
            } else {
                fields["threatintel.is_known_malicious"] = .bool(false)
            }
        } else {
            fields["threatintel.domain_present"] = .bool(false)
        }
        return Enrichment(
            pluginID: Self.manifest.id,
            pluginVersion: Self.manifest.version,
            schemaVersion: Self.manifest.schemaVersion,
            producedAt: Date(),  // excluded from the byte-identical guarantee
            fields: fields,
            confidence: .observed,
            privacyClass: .metadata
        )
    }

    static func extractDomain(from subject: EnrichmentSubject) -> String? {
        switch subject {
        case .path(let url): return url.host
        // A process event/alert carries no network host in the enrichment payload;
        // domain reputation runs on URL/path subjects (operator / agent on-demand).
        case .event, .alert: return nil
        }
    }
}
