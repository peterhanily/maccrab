import Foundation
import Testing
@testable import MacCrabCore

@Suite("BPF capture record ABI")
struct BPFHeaderLayoutTests {
    @Test("production iteration reads consecutive records aligned to four bytes")
    func consecutiveRecords() {
        let first = DNSCapturePacketFixture.bpfRecord(
            packet: DNSCapturePacketFixture.packet(),
            seconds: 1_700_000_000, microseconds: 125_000
        )
        #expect(first.count % 8 == 4)
        let second = DNSCapturePacketFixture.bpfRecord(
            packet: DNSCapturePacketFixture.packet(name: "b.example", answerType: 1),
            seconds: 1_700_000_001, microseconds: 250_000
        )
        var results: [DnsQuery] = []
        (first + second).withUnsafeBytes { buffer in
            DNSCollector.forEachCapturedDNS(in: buffer) { results.append($0) }
        }
        #expect(results.map(\.queryName) == ["a.example", "b.example"])
        #expect(results.map(\.resolvedIPs) == [[], ["192.0.2.1"]])
        #expect(results.map(\.timestamp) == [
            Date(timeIntervalSince1970: 1_700_000_000.125),
            Date(timeIntervalSince1970: 1_700_000_001.25),
        ])
    }
}
