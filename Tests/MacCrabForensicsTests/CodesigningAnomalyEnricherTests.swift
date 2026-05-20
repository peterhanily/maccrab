// CodesigningAnomalyEnricher — Pass 2026-C idempotency.

import Foundation
import Testing
@testable import MacCrabForensics

@Suite("CodesigningAnomalyEnricher")
struct CodesigningAnomalyEnricherTests {

    @Test("Idempotent on /usr/bin/true")
    func idempotent() async throws {
        let e = try await CodesigningAnomalyEnricher()
        let s = EnrichmentSubject.path(URL(fileURLWithPath: "/usr/bin/true"))
        let a = try await e.enrich(s, stage: .postEmission)
        let b = try await e.enrich(s, stage: .postEmission)
        #expect(a.fields == b.fields)
    }

    @Test("Apple-signed system binary produces no anomalies")
    func appleSystemNoAnomalies() async throws {
        let e = try await CodesigningAnomalyEnricher()
        let r = try await e.enrich(.path(URL(fileURLWithPath: "/usr/bin/true")), stage: .onDemand)
        #expect(r.fields["codesigning_anomaly.has_anomalies"] == .bool(false))
    }

    @Test("Missing path -> path_present=false")
    func missingPath() async throws {
        let e = try await CodesigningAnomalyEnricher()
        let r = try await e.enrich(.path(URL(fileURLWithPath: "/var/empty/no-binary-\(UUID().uuidString)")), stage: .onDemand)
        #expect(r.fields["codesigning_anomaly.path_present"] == .bool(false))
    }
}
