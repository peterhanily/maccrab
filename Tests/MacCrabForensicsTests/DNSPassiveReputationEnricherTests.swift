// DNSPassiveReputationEnricher — Pass 2026-C idempotency +
// heuristic checks.

import Foundation
import Testing
@testable import MacCrabForensics

@Suite("DNSPassiveReputationEnricher")
struct DNSPassiveReputationEnricherTests {

    @Test("Idempotent on a path-subject")
    func idempotent() async throws {
        let e = try await DNSPassiveReputationEnricher()
        let s = EnrichmentSubject.path(URL(string: "https://example.tk/foo")!)
        let a = try await e.enrich(s, stage: .postEmission)
        let b = try await e.enrich(s, stage: .postEmission)
        #expect(a.fields == b.fields)
    }

    @Test("Suspicious TLD .tk flags")
    func suspiciousTLD() async throws {
        let e = try await DNSPassiveReputationEnricher()
        let r = try await e.enrich(.path(URL(string: "https://something.tk/")!), stage: .onDemand)
        #expect(r.fields["dns_reputation.suspicious_tld"] == .bool(true))
    }

    @Test("Apple-impersonating domain flags")
    func brandImpersonation() async throws {
        let e = try await DNSPassiveReputationEnricher()
        let r = try await e.enrich(.path(URL(string: "https://apple-id-verification.example.com/")!), stage: .onDemand)
        #expect(r.fields["dns_reputation.impersonates_brand"] == .string("apple"))
    }

    @Test("Homoglyph detection (Cyrillic а in 'аpple')")
    func homoglyph() {
        // mixing Cyrillic 'а' with Latin 'pple'
        #expect(DNSPassiveReputationEnricher.containsHomoglyph("аpple.com") == true)
    }

    @Test("Mixed-script detection")
    func mixedScript() {
        #expect(DNSPassiveReputationEnricher.containsMixedScript("аpple.com") == true)
        #expect(DNSPassiveReputationEnricher.containsMixedScript("apple.com") == false)
    }

    @Test("Clean domain doesn't flag suspicious_overall")
    func cleanDomainDoesntFlag() async throws {
        let e = try await DNSPassiveReputationEnricher()
        let r = try await e.enrich(.path(URL(string: "https://www.apple.com/")!), stage: .onDemand)
        #expect(r.fields["dns_reputation.suspicious_overall"] == .bool(false))
    }
}
