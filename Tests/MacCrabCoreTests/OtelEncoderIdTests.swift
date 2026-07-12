// OtelEncoderIdTests.swift
// A3-06(b): synthesized OTLP span_id / trace_id must derive from a
// cryptographic hash, not a 64-bit FNV-1a. The old FNV path only had
// ~64 bits of entropy (the 32-hex trace_id was two halves both derived
// from the same 64-bit hash), so two distinct entities could be steered
// onto a shared id. These tests pin a REAL FNV-1a-64 collision to show
// the old scheme aliased those inputs and the new SHA-256 scheme does not.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("TraceGraph: OtelEncoder deterministic ids (A3-06(b))")
struct OtelEncoderIdTests {

    // A genuine FNV-1a-64 collision between two DISTINCT ASCII strings,
    // found offline via a cycle-detection search. Both map to the same
    // 64-bit FNV hash 0x5e08d54d78217e0e, so the OLD deterministicHexId
    // produced identical span_ids AND trace_ids for them.
    private let collidingA = "bf13eaba83dea434"
    private let collidingB = "b3b828bb3655e2a7"

    /// Reference implementation of the OLD (pre-fix) FNV-1a id, kept here
    /// only as an oracle to document the collision the fix removes.
    private func oldFnvId(_ source: String, length: Int) -> String {
        var h: UInt64 = 0xcbf29ce484222325
        for byte in source.utf8 {
            h ^= UInt64(byte)
            h &*= 0x100000001b3
        }
        var out = String(format: "%016x", h)
        while out.count < length {
            var h2: UInt64 = h
            h2 ^= 0xdeadbeefcafebabe
            out += String(format: "%016x", h2)
        }
        return String(out.prefix(length))
    }

    @Test("The pinned inputs really did collide under the OLD FNV scheme")
    func oldSchemeCollided() {
        #expect(collidingA != collidingB)
        // span_id width (16 hex) — full 64-bit FNV output.
        #expect(oldFnvId(collidingA, length: 16) == oldFnvId(collidingB, length: 16))
        // trace_id width (32 hex) — old scheme derived the second half from
        // the first, so a single 64-bit collision aliased the whole id.
        #expect(oldFnvId(collidingA, length: 32) == oldFnvId(collidingB, length: 32))
    }

    @Test("A3-06(b): SHA-256-derived ids do NOT collide on the previously-colliding inputs")
    func newSchemeSeparatesCollidingInputs() {
        // span_id (16 hex)
        #expect(OtelEncoder.deterministicHexId(from: collidingA, length: 16)
             != OtelEncoder.deterministicHexId(from: collidingB, length: 16))
        // trace_id (32 hex)
        #expect(OtelEncoder.deterministicHexId(from: collidingA, length: 32)
             != OtelEncoder.deterministicHexId(from: collidingB, length: 32))
    }

    @Test("Ids are deterministic, correct length, and valid lowercase hex")
    func idShapeIsCorrect() {
        for source in ["entity-abc", collidingA, "/usr/bin/curl", ""] {
            for length in [16, 32] {
                let id1 = OtelEncoder.deterministicHexId(from: source, length: length)
                let id2 = OtelEncoder.deterministicHexId(from: source, length: length)
                #expect(id1 == id2, "id must be deterministic for \(source)/\(length)")
                #expect(id1.count == length)
                #expect(id1.allSatisfy { Set("0123456789abcdef").contains($0) })
            }
        }
    }

    @Test("No collisions across a large batch of distinct inputs (both widths)")
    func batchIsCollisionFree() {
        for length in [16, 32] {
            var seen = Set<String>()
            for i in 0 ..< 20_000 {
                let id = OtelEncoder.deterministicHexId(from: "entity-\(i)", length: length)
                #expect(seen.insert(id).inserted, "unexpected id collision at index \(i), length \(length)")
            }
        }
    }
}
