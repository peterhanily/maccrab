// ESIngestRobustnessTests.swift
// v1.18 — robustness tests for the Endpoint Security ingest path that runs on
// every shipping host but was previously untested:
//   • esStringToSwift — the native es_string_token_t decoder. A mis-decode
//     here poisons every downstream detection. Fuzz the boundary cases the ES
//     framework can actually hand us (embedded NUL, no terminator, zero/length
//     mismatch, nil data, non-UTF-8) and assert it never over-reads or crashes.
//   • EsloggerCollector.sequenceGap — the global_seq_num drop math, lifted out
//     of the FileHandle read loop so it can be exercised directly.

import Testing
import Foundation
import EndpointSecurity
@testable import MacCrabCore

@Suite("ESHelpers: es_string_token_t decode robustness (v1.18)")
struct ESHelpersDecodeTests {

    /// Run esStringToSwift over `bytes`, presenting `length` (defaults to the
    /// real count) — the buffer stays alive for the call, which copies the bytes.
    private func decode(_ bytes: [UInt8], length: Int? = nil) -> String {
        bytes.withUnsafeBufferPointer { buf in
            let cchar = UnsafeRawPointer(buf.baseAddress!).assumingMemoryBound(to: CChar.self)
            return esStringToSwift(es_string_token_t(length: length ?? bytes.count, data: cchar))
        }
    }

    @Test("nil data pointer returns empty string (no deref)")
    func nilData() {
        #expect(esStringToSwift(es_string_token_t(length: 10, data: nil)) == "")
    }

    @Test("zero length returns empty string")
    func zeroLength() {
        #expect(decode([0x61, 0x62, 0x63], length: 0) == "")
    }

    @Test("decodes exactly `length` bytes — a trailing byte past length is never read")
    func exactLengthNoTerminator() {
        // length=3 over a 4-byte buffer: the 0x7F must NOT appear.
        #expect(decode([0x61, 0x62, 0x63, 0x7F], length: 3) == "abc")
    }

    @Test("an embedded NUL is preserved (not treated as a C terminator)")
    func embeddedNul() {
        let s = decode([0x61, 0x00, 0x62], length: 3)
        #expect(Array(s.utf8) == [0x61, 0x00, 0x62])
    }

    @Test("invalid UTF-8 falls back to U+FFFD and never crashes")
    func invalidUTF8() {
        let s = decode([0xFF, 0xFE, 0xFF], length: 3)   // not valid UTF-8 starts
        #expect(!s.isEmpty)
        #expect(s.contains("\u{FFFD}"))
    }

    @Test("a large buffer decodes fully without over-reading")
    func largeBuffer() {
        let s = decode([UInt8](repeating: 0x41, count: 8192), length: 8192)
        #expect(s.count == 8192)
    }
}

@Suite("EsloggerCollector: sequence-gap drop math (v1.18)")
struct EsloggerSequenceGapTests {

    @Test("first observation reports no drop")
    func firstObservation() {
        #expect(EsloggerCollector.sequenceGap(previous: 0, current: 1) == 0)
        #expect(EsloggerCollector.sequenceGap(previous: 0, current: 9_999) == 0)
    }

    @Test("contiguous sequence reports no drop")
    func contiguous() {
        #expect(EsloggerCollector.sequenceGap(previous: 1, current: 2) == 0)
    }

    @Test("a hole of one (…1,2,4) reports exactly one dropped event")
    func gapOfOne() {
        #expect(EsloggerCollector.sequenceGap(previous: 2, current: 4) == 1)
    }

    @Test("a larger hole reports the full drop count")
    func largerGap() {
        #expect(EsloggerCollector.sequenceGap(previous: 5, current: 10) == 4)
    }

    @Test("duplicate or out-of-order arrivals never underflow to a huge count")
    func noUnderflow() {
        #expect(EsloggerCollector.sequenceGap(previous: 10, current: 10) == 0)   // duplicate
        #expect(EsloggerCollector.sequenceGap(previous: 10, current: 5) == 0)    // out of order
    }
}

@Suite("ESHelpers: native ES process field mapping (v1.18)")
struct ESProcessMappingTests {

    private func fields(
        pid: Int32 = 1234, ppid: Int32 = 1, rpid: Int32 = 0, euid: uid_t = 501,
        exe: String = "/tmp/x", signingId: String = "", teamId: String = "",
        flags: UInt32 = 0, platform: Bool = false
    ) -> ESProcessFields {
        ESProcessFields(pid: pid, ppid: ppid, rpid: rpid, euid: euid,
                        executablePath: exe, signingId: signingId, teamId: teamId,
                        codesigningFlags: flags, isPlatformBinary: platform)
    }

    @Test("responsible pid propagates — the parity fix the native path lost (was rpid: 0)")
    func rpidPropagates() {
        let pi = esProcessInfo(from: fields(ppid: 1, rpid: 9999))
        #expect(pi.rpid == 9999)
        #expect(pi.ppid == 1)          // distinct from the responsible pid
    }

    @Test("ppid is recorded as a placeholder ancestor (name/path enriched later)")
    func ppidAncestor() {
        let pi = esProcessInfo(from: fields(ppid: 42))
        #expect(pi.ancestors.first?.pid == 42)
    }

    @Test("executable basename becomes the name; euid becomes userId")
    func basicFields() {
        let pi = esProcessInfo(from: fields(euid: 777, exe: "/usr/bin/curl"))
        #expect(pi.name == "curl")
        #expect(pi.executable == "/usr/bin/curl")
        #expect(pi.userId == 777)
    }

    @Test("codeSignature fields wire through; empty team/signing → nil; platform flag propagates")
    func codesigFlows() {
        let pi = esProcessInfo(from: fields(signingId: "com.x", teamId: "ABC123", flags: 0x2000, platform: true))
        #expect(pi.codeSignature?.teamId == "ABC123")
        #expect(pi.codeSignature?.signingId == "com.x")
        #expect(pi.codeSignature?.flags == 0x2000)
        #expect(pi.isPlatformBinary == true)

        let empty = esProcessInfo(from: fields(signingId: "", teamId: ""))
        #expect(empty.codeSignature?.teamId == nil)
        #expect(empty.codeSignature?.signingId == nil)
        #expect(empty.isPlatformBinary == false)
    }
}
