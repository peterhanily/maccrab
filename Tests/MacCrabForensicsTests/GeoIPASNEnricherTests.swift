// GeoIPASNEnricher — Pass 2026-C idempotency + range classification.

import Foundation
import Testing
@testable import MacCrabForensics

@Suite("GeoIPASNEnricher")
struct GeoIPASNEnricherTests {

    @Test("Idempotent on a path-subject")
    func idempotent() async throws {
        let e = try await GeoIPASNEnricher()
        let s = EnrichmentSubject.path(URL(string: "https://127.0.0.1/")!)
        let a = try await e.enrich(s, stage: .postEmission)
        let b = try await e.enrich(s, stage: .postEmission)
        #expect(a.fields == b.fields)
    }

    @Test("Loopback classification")
    func loopback() {
        #expect(GeoIPASNEnricher.classify("127.0.0.1") == "loopback")
    }

    @Test("Class A private classification")
    func classA() {
        #expect(GeoIPASNEnricher.classify("10.0.0.1") == "private_class_a")
    }

    @Test("Class B private classification")
    func classB() {
        #expect(GeoIPASNEnricher.classify("172.16.0.1") == "private_class_b")
        #expect(GeoIPASNEnricher.classify("172.31.255.255") == "private_class_b")
    }

    @Test("Class C private classification")
    func classC() {
        #expect(GeoIPASNEnricher.classify("192.168.1.1") == "private_class_c")
    }

    @Test("CGNAT classification")
    func cgnat() {
        #expect(GeoIPASNEnricher.classify("100.64.0.1") == "cgnat")
    }

    @Test("Public-unknown classification fallback")
    func publicUnknown() {
        #expect(GeoIPASNEnricher.classify("8.8.8.8") == "public_unknown")
    }
}
