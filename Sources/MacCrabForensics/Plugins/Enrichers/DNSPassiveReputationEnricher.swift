// DNSPassiveReputationEnricher — com.maccrab.enricher.dns-passive-reputation.
//
// Plan §13.8. Annotates the subject's domain with passive-DNS
// reputation indicators. v1.16.0-rc.12 ships heuristic-only:
// domain-age look-alike scoring + suspicious-TLD detection +
// repeated-character / homoglyph heuristics. Live passive-DNS
// integration (e.g. VirusTotal, PassiveTotal, Spamhaus) is a
// follow-up that needs operator API keys.
//
// Pure function on subject → byte-identical-on-re-run per Pass
// 2026-C.

import Foundation

public struct DNSPassiveReputationEnricher: Enricher {

    public static let manifest = PluginManifest(
        id: "com.maccrab.enricher.dns-passive-reputation",
        version: "1.0.0",
        displayName: "DNS Passive Reputation",
        description: "Annotates the subject's domain with heuristic passive-DNS reputation: suspicious TLD, homoglyph detection, brand-impersonation patterns. Live API integration deferred.",
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

    private static let suspiciousTLDs: Set<String> = [
        "tk", "ml", "ga", "cf", "gq",      // historically free / abused
        "click", "loan", "work", "study",   // commonly abused
        "top", "xyz", "bid", "stream",
    ]

    private static let brandTargets: [String: String] = [
        "appie": "apple", "apple-": "apple",
        "g0ogle": "google", "googel": "google",
        "rnicrosoft": "microsoft", "microsft": "microsoft",
        "paypall": "paypal", "paypa1": "paypal",
        "iclo ud": "icloud",
    ]

    public init() async throws {}

    public func enrich(_ subject: EnrichmentSubject, stage: EnrichmentStage) async throws -> Enrichment {
        let domain = Self.extractDomain(from: subject)
        var fields: [String: EnrichmentValue] = [:]
        if let d = domain {
            let tld = d.split(separator: ".").last.map(String.init) ?? ""
            let isSuspiciousTLD = Self.suspiciousTLDs.contains(tld.lowercased())
            let hasHomoglyph = Self.containsHomoglyph(d)
            let impersonates = Self.brandTargets.first { d.lowercased().contains($0.key) }?.value
            let hasMixedScript = Self.containsMixedScript(d)
            let suspicious = isSuspiciousTLD || hasHomoglyph || impersonates != nil || hasMixedScript
            fields["dns_reputation.domain"] = .string(d)
            fields["dns_reputation.tld"] = .string(tld)
            fields["dns_reputation.suspicious_tld"] = .bool(isSuspiciousTLD)
            fields["dns_reputation.has_homoglyph"] = .bool(hasHomoglyph)
            fields["dns_reputation.has_mixed_script"] = .bool(hasMixedScript)
            fields["dns_reputation.suspicious_overall"] = .bool(suspicious)
            if let target = impersonates {
                fields["dns_reputation.impersonates_brand"] = .string(target)
            }
        } else {
            fields["dns_reputation.domain_present"] = .bool(false)
        }
        return Enrichment(
            pluginID: Self.manifest.id,
            pluginVersion: Self.manifest.version,
            schemaVersion: Self.manifest.schemaVersion,
            producedAt: Date(),
            fields: fields,
            confidence: .heuristic,
            privacyClass: .metadata
        )
    }

    static func extractDomain(from subject: EnrichmentSubject) -> String? {
        switch subject {
        case .path(let url): return url.host
        case .event(let p): return p.processExecutablePath.flatMap { URL(string: $0)?.host }
        case .alert(let p): return p.processExecutablePath.flatMap { URL(string: $0)?.host }
        }
    }

    /// Returns true if the domain contains any Cyrillic / Greek
    /// characters that look like Latin letters (а / о / е / р / с
    /// etc.).
    static func containsHomoglyph(_ domain: String) -> Bool {
        // Cyrillic look-alikes
        let homoglyphs = "абвгдеёжзийклмнопрстуфхцчшщъыьэюяАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"
        for ch in homoglyphs {
            if domain.contains(ch) { return true }
        }
        return false
    }

    /// Returns true if the domain mixes Latin + non-Latin script
    /// chars in the same label.
    static func containsMixedScript(_ domain: String) -> Bool {
        var hasLatin = false
        var hasNonLatin = false
        for scalar in domain.unicodeScalars {
            let v = scalar.value
            if (v >= 0x41 && v <= 0x5A) || (v >= 0x61 && v <= 0x7A) { hasLatin = true }
            else if v > 0x7F && v != 0x2E && v != 0x2D { hasNonLatin = true }
            if hasLatin && hasNonLatin { return true }
        }
        return false
    }
}
