// StylometricSupplyChainEnricher — Pass 2026-C idempotency +
// stat-extraction.

import Foundation
import Testing
@testable import MacCrabForensics

@Suite("StylometricSupplyChainEnricher")
struct StylometricSupplyChainEnricherTests {

    @Test("Idempotent on a known-path subject")
    func idempotent() async throws {
        let e = try await StylometricSupplyChainEnricher()
        let s = EnrichmentSubject.path(URL(fileURLWithPath: "/etc/hosts"))
        let a = try await e.enrich(s, stage: .onDemand)
        let b = try await e.enrich(s, stage: .onDemand)
        #expect(a.fields == b.fields)
    }

    @Test("Eval marker detection")
    func evalMarker() {
        let stats = StylometricSupplyChainEnricher.analyze("eval(atob('aGVsbG8='))")
        #expect(stats.evalMarkers >= 2)
        #expect(stats.isSuspicious)
    }

    @Test("Long base64 run detection")
    func base64Run() {
        let s = String(repeating: "A", count: 100)
        let stats = StylometricSupplyChainEnricher.analyze(s)
        #expect(stats.base64Runs >= 1)
    }

    @Test("Long hex blob detection")
    func hexBlob() {
        let s = String(repeating: "a", count: 70)
        let stats = StylometricSupplyChainEnricher.analyze(s)
        #expect(stats.hexBlobs >= 1)
    }

    @Test("Benign text doesn't fire")
    func benign() {
        let stats = StylometricSupplyChainEnricher.analyze("Hello, world. This is a sentence with normal punctuation.")
        #expect(!stats.isSuspicious)
    }
}
