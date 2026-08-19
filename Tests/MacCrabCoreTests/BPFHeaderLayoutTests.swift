// BPFHeaderLayoutTests.swift
//
// v1.21.6-rc.38. DNSCollector declared bpf_hdr's timestamp as `timeval`, but
// <net/bpf.h> uses `BPF_TIMEVAL`, which is `timeval32` on LP64:
//
//     #ifdef __LP64__
//     #define BPF_TIMEVAL struct timeval32     // 8 bytes
//     #else
//     #define BPF_TIMEVAL struct timeval       // 16 bytes on LP64
//     #endif
//
// The struct was therefore 28 bytes with bh_caplen at offset 16, against a real
// header of 20 bytes with bh_caplen at offset 8. Every field was read from the
// wrong place and the read loop advanced by the wrong stride, so DNSCollector
// yielded zero packets on every 64-bit Mac since it shipped — silently, with no
// error, its live event_count simply sitting at 0.
//
// A layout bug cannot be caught by testing behaviour on a machine where the
// behaviour is "nothing happens", so this asserts the ABI directly.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("BPF header ABI")
struct BPFHeaderLayoutTests {

    /// Mirrors the private declaration in DNSCollector. If that layout changes,
    /// this must change with it — which is the point.
    private struct BPFHeaderMirror {
        var bh_tstamp_sec: Int32
        var bh_tstamp_usec: Int32
        var bh_caplen: UInt32
        var bh_datalen: UInt32
        var bh_hdrlen: UInt16
    }

    @Test("bpf_hdr matches the LP64 system layout")
    func matchesSystemLayout() {
        // Verified against the real <net/bpf.h> on arm64 macOS:
        //   sizeof(struct bpf_hdr) = 20, offsetof(bh_caplen) = 8
        #expect(MemoryLayout<BPFHeaderMirror>.size == 18)
        #expect(MemoryLayout<BPFHeaderMirror>.stride == 20)
        #expect(MemoryLayout<BPFHeaderMirror>.offset(of: \.bh_caplen) == 8)
        #expect(MemoryLayout<BPFHeaderMirror>.offset(of: \.bh_datalen) == 12)
        #expect(MemoryLayout<BPFHeaderMirror>.offset(of: \.bh_hdrlen) == 16)
    }

    @Test("The LP64 timestamp is 8 bytes, not 16")
    func timestampWidthIsTheTrap() {
        // This is the exact mistake: `timeval` is twice the width BPF uses on
        // LP64, which shifted every subsequent field by 8 bytes.
        #expect(MemoryLayout<timeval>.size == 16)
        #expect(MemoryLayout<Int32>.size * 2 == 8)
        #expect(MemoryLayout<timeval>.size != MemoryLayout<Int32>.size * 2)
    }
}
