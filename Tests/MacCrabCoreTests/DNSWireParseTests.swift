// DNSWireParseTests.swift
// MacCrabCoreTests
//
// DNSCollector.parseDomainName decodes RFC-1035 wire-format names, including
// compression pointers, from adversarial packet data. It is 100% pure (Data
// in, (name, bytesConsumed) out) but was only ever exercised by a live BPF
// tap. The load-bearing invariant: a self-referential / cyclic compression
// pointer must TERMINATE (the jumpCount guard), never hang the read loop.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("DNS wire-format name parser")
struct DNSWireParseTests {

    /// Encode a sequence of labels as RFC-1035 wire format (length-prefixed,
    /// zero-terminated). No compression.
    private func encodeName(_ labels: [String]) -> [UInt8] {
        var out: [UInt8] = []
        for l in labels {
            let bytes = Array(l.utf8)
            out.append(UInt8(bytes.count))
            out.append(contentsOf: bytes)
        }
        out.append(0)
        return out
    }

    @Test("Parses a well-formed name and reports bytes consumed")
    func wellFormed() {
        let wire = encodeName(["www", "example", "com"])  // 17 bytes
        let result = DNSCollector.parseDomainName(Data(wire), offset: 0)
        #expect(result?.0 == "www.example.com")
        #expect(result?.1 == 17)
    }

    @Test("Follows a compression pointer back to an earlier name")
    func compressionPointer() {
        // [0..16] www.example.com, then at 17 a 2-byte pointer -> offset 0.
        var wire = encodeName(["www", "example", "com"])
        wire.append(0xC0)  // pointer high byte
        wire.append(0x00)  // -> offset 0
        let result = DNSCollector.parseDomainName(Data(wire), offset: 17)
        #expect(result?.0 == "www.example.com")
        #expect(result?.1 == 2)  // only the 2 pointer bytes are consumed at this offset
    }

    @Test("Self-referential pointer terminates (no hang) and returns nil")
    func selfReferentialPointer() {
        // A pointer at offset 0 that points to offset 0 — an infinite loop
        // without the jumpCount guard. Must return nil promptly.
        let wire: [UInt8] = [0xC0, 0x00]
        let result = DNSCollector.parseDomainName(Data(wire), offset: 0)
        #expect(result == nil)
    }

    @Test("Two-pointer A->B->A cycle terminates and returns nil")
    func twoPointerCycle() {
        // offset 0: pointer -> 2 ; offset 2: pointer -> 0
        let wire: [UInt8] = [0xC0, 0x02, 0xC0, 0x00]
        let result = DNSCollector.parseDomainName(Data(wire), offset: 0)
        #expect(result == nil)
    }

    @Test("Rejects a label length that runs past the buffer")
    func truncatedLabel() {
        // Claims a 5-byte label but only 2 bytes follow.
        let wire: [UInt8] = [5, 0x61, 0x62]
        #expect(DNSCollector.parseDomainName(Data(wire), offset: 0) == nil)
    }

    @Test("Rejects an over-length (>63) label")
    func overLengthLabel() {
        // 0x40 = 64: not a pointer (needs 0xC0), but exceeds the 63 max.
        var wire: [UInt8] = [64]
        wire.append(contentsOf: [UInt8](repeating: 0x61, count: 64))
        wire.append(0)
        #expect(DNSCollector.parseDomainName(Data(wire), offset: 0) == nil)
    }

    @Test("Truncated pointer (high byte at end of buffer) returns nil")
    func truncatedPointer() {
        let wire: [UInt8] = [0xC0]  // pointer high byte with no low byte
        #expect(DNSCollector.parseDomainName(Data(wire), offset: 0) == nil)
    }
}
