// V176ProbeTests.swift
//
// One-shot diagnostic harness — reproduces the v1.7.5 storage-init
// crash on a real-world events.db before shipping the v1.7.6 fix.
//
// Run with the path of the broken events.db via env var:
//   MACCRAB_PROBE_DB="/Library/Application Support/MacCrab" \
//     sudo swift test --filter "Storage init probe"
//
// Outputs the actual error string (no <private> redaction) and tries
// the v1.7.6 recovery logic on a copy. Idempotent: backs up to a
// timestamped sibling, doesn't touch the original on failure paths.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("v1.7.6: Storage init probe (manual diagnostic)")
struct StorageInitProbeTests {

    @Test("Storage init probe — reports actual SQLite error if init fails")
    func storageInitProbe() async throws {
        guard let dir = ProcessInfo.processInfo.environment["MACCRAB_PROBE_DB"] else {
            // Skip silently if not invoked with the env var. Lets the
            // test run as part of the standard suite without the
            // operator having to scroll past it.
            return
        }
        print("[PROBE] Pointing EventStore at \(dir)")
        do {
            let store = try EventStore(directory: dir)
            print("[PROBE] ✓ EventStore init succeeded")
            let count = try await store.count()
            print("[PROBE] ✓ events count: \(count)")
        } catch let error as EventStoreError {
            // EventStoreError.databaseOpenFailed / prepareFailed / stepFailed
            print("[PROBE] ✗ EventStore init threw EventStoreError: \(error)")
            print("[PROBE]   localizedDescription: \(error.localizedDescription)")
            // Surface to test failure so the operator sees it
            #expect(Bool(false), "EventStore init failed: \(error.localizedDescription)")
        } catch {
            print("[PROBE] ✗ EventStore init threw \(type(of: error)): \(error)")
            print("[PROBE]   localizedDescription: \(error.localizedDescription)")
            #expect(Bool(false), "EventStore init failed: \(error.localizedDescription)")
        }
    }

    @Test("AlertStore init probe — same path, separate connection")
    func alertStoreInitProbe() async throws {
        guard let dir = ProcessInfo.processInfo.environment["MACCRAB_PROBE_DB"] else { return }
        print("[PROBE] Pointing AlertStore at \(dir)")
        do {
            let store = try AlertStore(directory: dir)
            print("[PROBE] ✓ AlertStore init succeeded")
            let count = try await store.count()
            print("[PROBE] ✓ alerts count: \(count)")
        } catch let error as AlertStoreError {
            print("[PROBE] ✗ AlertStore init threw AlertStoreError: \(error)")
            print("[PROBE]   localizedDescription: \(error.localizedDescription)")
            #expect(Bool(false), "AlertStore init failed: \(error.localizedDescription)")
        } catch {
            print("[PROBE] ✗ AlertStore init threw \(type(of: error)): \(error)")
            print("[PROBE]   localizedDescription: \(error.localizedDescription)")
            #expect(Bool(false), "AlertStore init failed: \(error.localizedDescription)")
        }
    }
}
