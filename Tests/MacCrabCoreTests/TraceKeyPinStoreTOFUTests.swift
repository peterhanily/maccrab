// TraceKeyPinStoreTOFUTests.swift
// storage-01 follow-up regression: the TOFU contract the maccrab-mcp
// verify_bundle path now relies on. First verify of an unseen trace_id is
// trusted (no pin yet); once a key is pinned, a swapped fingerprint is the
// one BundleVerifier.Options.pinnedKeyFingerprint would reject, and an
// existing pin is never silently overwritten.

import Foundation
import Testing
@testable import MacCrabCore

@Suite("TraceKeyPinStore TOFU (storage-01 mcp parity)")
struct TraceKeyPinStoreTOFUTests {

    private func tempStore() -> (TraceKeyPinStore, URL) {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-pin-\(UUID().uuidString)")
            .appendingPathComponent("trace_key_pins.json")
        return (TraceKeyPinStore(fileURL: url), url)
    }

    @Test("unseen trace_id has no pin (first use is trusted)")
    func firstUseHasNoPin() {
        let (store, dir) = tempStore()
        defer { try? FileManager.default.removeItem(at: dir.deletingLastPathComponent()) }
        #expect(store.pinnedFingerprint(forTraceId: "trace-A") == nil)
    }

    @Test("pin-on-first-use records the observed fingerprint")
    func pinOnFirstUse() {
        let (store, dir) = tempStore()
        defer { try? FileManager.default.removeItem(at: dir.deletingLastPathComponent()) }
        store.pinIfAbsent(traceId: "trace-A", fingerprint: "fp-original")
        #expect(store.pinnedFingerprint(forTraceId: "trace-A") == "fp-original")
    }

    @Test("existing pin is never overwritten (key-change is caught, not absorbed)")
    func pinIsImmutable() {
        let (store, dir) = tempStore()
        defer { try? FileManager.default.removeItem(at: dir.deletingLastPathComponent()) }
        store.pinIfAbsent(traceId: "trace-A", fingerprint: "fp-original")
        // Simulate a rewrite-and-resign with an attacker key.
        store.pinIfAbsent(traceId: "trace-A", fingerprint: "fp-attacker")
        // The pin the mcp verify path would hand BundleVerifier is still the
        // original; the attacker fingerprint never becomes the trusted anchor.
        #expect(store.pinnedFingerprint(forTraceId: "trace-A") == "fp-original")
    }

    @Test("pins survive a fresh store instance over the same file (cross-MCP-call persistence)")
    func pinPersistsAcrossInstances() {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-pin-\(UUID().uuidString)")
            .appendingPathComponent("trace_key_pins.json")
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        TraceKeyPinStore(fileURL: url).pinIfAbsent(traceId: "trace-A", fingerprint: "fp-original")
        #expect(TraceKeyPinStore(fileURL: url).pinnedFingerprint(forTraceId: "trace-A") == "fp-original")
    }
}
