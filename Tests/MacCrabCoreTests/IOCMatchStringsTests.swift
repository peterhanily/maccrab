import Testing
import Foundation
@testable import MacCrabAgentKit
import MacCrabCore

/// v1.17 threat-intel match capture: `EventLoop.iocMatchStrings` is the
/// shared formatter that turns a matched `IOCRecord` into the alert
/// description + machine-parseable remediation hint. These guard the
/// contract the Intelligence workspace + `maccrabctl intel matches`
/// read back (type=/source=/family=/tags= prefixes).
@Suite("IOC match strings")
struct IOCMatchStringsTests {

    @Test("full record surfaces source, family, first-seen, and tagged hint")
    func fullRecord() {
        let first = Date(timeIntervalSince1970: 1_700_000_000) // 2023-11-14 UTC
        let rec = ThreatIntelFeed.IOCRecord(
            value: "203.0.113.7",
            source: "Feodo",
            firstSeen: first,
            malwareFamily: "Emotet",
            tags: ["botnet", "c2"]
        )
        let (desc, hint) = EventLoop.iocMatchStrings(
            record: rec, value: "203.0.113.7", type: "IP", hit: "Outbound connection to")

        #expect(desc.contains("Outbound connection to 203.0.113.7"))
        #expect(desc.contains("Feodo IOC"))
        #expect(desc.contains("family Emotet"))
        #expect(desc.contains("first seen 2023-11-14"))

        #expect(hint.contains("type=IP"))
        #expect(hint.contains("source=Feodo"))
        #expect(hint.contains("family=Emotet"))
        #expect(hint.contains("tags=botnet,c2"))
    }

    @Test("nil record falls back to raw indicator + type, no source noise")
    func nilRecord() {
        let (desc, hint) = EventLoop.iocMatchStrings(
            record: nil, value: "evil.example.com", type: "Domain", hit: "DNS query for")

        #expect(desc.contains("DNS query for evil.example.com"))
        #expect(desc.contains("known-malicious Domain"))
        #expect(hint.contains("type=Domain"))
        #expect(!hint.contains("source="))
        #expect(!hint.contains("family="))
    }

    @Test("empty family and tags are omitted, not emitted blank")
    func emptyOptionals() {
        let rec = ThreatIntelFeed.IOCRecord(
            value: "abc123", source: "URLhaus", firstSeen: nil,
            malwareFamily: "", tags: [])
        let (desc, hint) = EventLoop.iocMatchStrings(
            record: rec, value: "abc123", type: "Hash", hit: "Executed file")

        #expect(desc.contains("URLhaus IOC"))
        #expect(!desc.contains("family "))
        #expect(!desc.contains("first seen"))
        #expect(hint.contains("source=URLhaus"))
        #expect(!hint.contains("family="))
        #expect(!hint.contains("tags="))
    }
}
