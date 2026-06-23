// ThreatIntelIPEnricher — now reads the LIVE IOC cache (no fixture IPs).

import Foundation
import Testing
import MacCrabCore
@testable import MacCrabForensics

@Suite("ThreatIntelIPEnricher")
struct ThreatIntelIPEnricherTests {

    @Test("an IP in the live IOC cache flips the flag + labels source")
    func knownMalicious() async throws {
        let dir = try ThreatIntelDomainEnricherTests.seed(domains: [], ips: ["198.51.100.42"])
        defer { try? FileManager.default.removeItem(atPath: (dir as NSString).deletingLastPathComponent) }
        let e = ThreatIntelIPEnricher(cacheDir: dir)
        let r = try await e.enrich(.path(URL(string: "https://198.51.100.42/")!), stage: .onDemand)
        #expect(r.fields["threatintel.ip_is_known_malicious"] == .bool(true))
        #expect(r.fields["threatintel.ip_source"] == .string("URLhaus"))
    }

    @Test("an unlisted IP doesn't flip the flag")
    func unknown() async throws {
        let dir = try ThreatIntelDomainEnricherTests.seed(domains: [], ips: ["198.51.100.42"])
        defer { try? FileManager.default.removeItem(atPath: (dir as NSString).deletingLastPathComponent) }
        let e = ThreatIntelIPEnricher(cacheDir: dir)
        let r = try await e.enrich(.path(URL(string: "https://10.0.0.1/")!), stage: .onDemand)
        #expect(r.fields["threatintel.ip_is_known_malicious"] == .bool(false))
    }

    @Test("idempotent on a path-subject")
    func idempotent() async throws {
        let dir = try ThreatIntelDomainEnricherTests.seed(domains: [], ips: ["198.51.100.42"])
        defer { try? FileManager.default.removeItem(atPath: (dir as NSString).deletingLastPathComponent) }
        let e = ThreatIntelIPEnricher(cacheDir: dir)
        let s = EnrichmentSubject.path(URL(string: "https://198.51.100.42/foo")!)
        let a = try await e.enrich(s, stage: .postEmission)
        let b = try await e.enrich(s, stage: .postEmission)
        #expect(a.fields == b.fields)
    }
}
