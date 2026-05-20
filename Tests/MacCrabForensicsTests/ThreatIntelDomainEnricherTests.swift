// ThreatIntelDomainEnricher — Pass 2026-C idempotency + the
// known-malicious lookup contract.

import Foundation
import Testing
@testable import MacCrabForensics

@Suite("ThreatIntelDomainEnricher")
struct ThreatIntelDomainEnricherTests {

    @Test("Idempotent on a path-subject across re-runs")
    func idempotent() async throws {
        let e = try await ThreatIntelDomainEnricher()
        let subject = EnrichmentSubject.path(URL(string: "https://evil.example.com/path")!)
        let a = try await e.enrich(subject, stage: .postEmission)
        let b = try await e.enrich(subject, stage: .postEmission)
        #expect(a.fields == b.fields)
    }

    @Test("Known-malicious domain flips the flag")
    func malicious() async throws {
        let e = try await ThreatIntelDomainEnricher()
        let r = try await e.enrich(.path(URL(string: "https://evil.example.com/foo")!), stage: .onDemand)
        #expect(r.fields["threatintel.is_known_malicious"] == .bool(true))
    }

    @Test("Unknown domain does not flip flag")
    func unknown() async throws {
        let e = try await ThreatIntelDomainEnricher()
        let r = try await e.enrich(.path(URL(string: "https://google.com/")!), stage: .onDemand)
        #expect(r.fields["threatintel.is_known_malicious"] == .bool(false))
    }
}
