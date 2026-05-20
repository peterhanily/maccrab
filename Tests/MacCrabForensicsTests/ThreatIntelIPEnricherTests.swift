// ThreatIntelIPEnricher — Pass 2026-C idempotency.

import Foundation
import Testing
@testable import MacCrabForensics

@Suite("ThreatIntelIPEnricher")
struct ThreatIntelIPEnricherTests {

    @Test("Idempotent on path-subject")
    func idempotent() async throws {
        let e = try await ThreatIntelIPEnricher()
        let s = EnrichmentSubject.path(URL(string: "https://192.0.2.66/foo")!)
        let a = try await e.enrich(s, stage: .postEmission)
        let b = try await e.enrich(s, stage: .postEmission)
        #expect(a.fields == b.fields)
    }

    @Test("Known-malicious IP flips flag")
    func knownMalicious() async throws {
        let e = try await ThreatIntelIPEnricher()
        let r = try await e.enrich(.path(URL(string: "https://192.0.2.66/")!), stage: .onDemand)
        #expect(r.fields["threatintel.ip_is_known_malicious"] == .bool(true))
    }

    @Test("Unknown IP doesn't flip flag")
    func unknown() async throws {
        let e = try await ThreatIntelIPEnricher()
        let r = try await e.enrich(.path(URL(string: "https://10.0.0.1/")!), stage: .onDemand)
        #expect(r.fields["threatintel.ip_is_known_malicious"] == .bool(false))
    }
}
