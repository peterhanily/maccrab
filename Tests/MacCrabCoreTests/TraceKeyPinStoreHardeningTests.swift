// TraceKeyPinStoreHardeningTests.swift
// A3-03 — the pin store's O_NOFOLLOW / non-user-writable hardening. Behavior
// (TOFU pin/read/persist) is covered by TraceKeyPinStoreTOFUTests; here we
// assert the symlink-refusal read and the 0o600 write mode that make the
// pinned trust anchor harder to poison.

import Testing
import Foundation
import Darwin
@testable import MacCrabCore

@Suite("TraceKeyPinStore hardening (A3-03)")
struct TraceKeyPinStoreHardeningTests {

    private func tempDir() -> URL {
        let d = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-pinhard-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        return d
    }

    @Test("a symlink planted at the pin path is refused on read (fails safe to no pins)")
    func symlinkRefusedOnRead() throws {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        // Attacker plants a map at a file they control...
        let evil = dir.appendingPathComponent("evil_pins.json")
        try #"{"trace-A":"fp-attacker"}"#.data(using: .utf8)!.write(to: evil)

        // ...and points the pin path at it via a symlink.
        let pinPath = dir.appendingPathComponent("trace_key_pins.json")
        try FileManager.default.createSymbolicLink(at: pinPath, withDestinationURL: evil)

        // The O_NOFOLLOW read refuses the symlink → no pins loaded → the
        // attacker's fingerprint never becomes the trusted anchor.
        let store = TraceKeyPinStore(fileURL: pinPath)
        #expect(store.pinnedFingerprint(forTraceId: "trace-A") == nil)
    }

    @Test("the pin file is written 0o600 (owner-only)")
    func writeModeIsOwnerOnly() throws {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let pinPath = dir.appendingPathComponent("trace_key_pins.json")

        let store = TraceKeyPinStore(fileURL: pinPath)
        store.pinIfAbsent(traceId: "trace-A", fingerprint: "fp-original")

        let attrs = try FileManager.default.attributesOfItem(atPath: pinPath.path)
        let perms = (attrs[.posixPermissions] as? NSNumber)?.uint16Value ?? 0
        #expect(perms & 0o777 == 0o600)
        // And the pin round-trips through the hardened read/write path.
        #expect(store.pinnedFingerprint(forTraceId: "trace-A") == "fp-original")
    }

    @Test("hardened overwrite replaces a symlink target rather than writing through it")
    func overwriteReplacesSymlink() throws {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let outside = dir.appendingPathComponent("outside.json")
        try Data("{}".utf8).write(to: outside)
        let pinPath = dir.appendingPathComponent("trace_key_pins.json")
        try FileManager.default.createSymbolicLink(at: pinPath, withDestinationURL: outside)

        // Writing a pin must NOT follow the symlink to clobber `outside`; the
        // rename replaces the symlink name with a fresh regular file.
        TraceKeyPinStore(fileURL: pinPath).pinIfAbsent(traceId: "t", fingerprint: "fp")

        // `outside` is untouched...
        #expect(try String(contentsOf: outside, encoding: .utf8) == "{}")
        // ...and the pin path is now a real file with the pin.
        var st = stat()
        #expect(lstat(pinPath.path, &st) == 0)
        #expect((st.st_mode & S_IFMT) == S_IFREG)
        #expect(TraceKeyPinStore(fileURL: pinPath).pinnedFingerprint(forTraceId: "t") == "fp")
    }
}
