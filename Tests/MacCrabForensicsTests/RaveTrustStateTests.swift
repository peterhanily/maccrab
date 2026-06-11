// RaveTrustState (S2-AR) anti-rollback high-water-mark store tests.
//
// Covers:
//   - first-seen accepts any serial and records it
//   - a newer/equal serial is accepted and advances the mark
//   - an older serial is a rollback (rejected; mark unchanged)
//   - record() never lowers the mark (idempotent / monotonic)
//   - persistence round-trips through the on-disk JSON
//   - revocations high-water mark is independent of the catalog one
//   - missing/garbage file degrades to empty (first-seen)

import Testing
import Foundation
@testable import MacCrabForensics

@Suite("RaveTrustState (S2-AR anti-rollback)")
struct RaveTrustStateTests {

    static func freshStore() -> RaveTrustStateStore {
        let path = (NSTemporaryDirectory() as NSString)
            .appendingPathComponent("rave-trust-state-\(UUID().uuidString).json")
        return RaveTrustStateStore(path: path)
    }

    @Test("first-seen catalog serial is accepted")
    func firstSeenAccepted() {
        let store = Self.freshStore()
        #expect(store.evaluateCatalog(incoming: 7) == .firstSeen)
        // A negative-looking 0 is still first-seen on a fresh store.
        #expect(store.evaluateCatalog(incoming: 0) == .firstSeen)
    }

    @Test("newer serial accepted, equal serial accepted")
    func acceptNewerAndEqual() throws {
        let store = Self.freshStore()
        try store.recordCatalog(serial: 5)
        #expect(store.evaluateCatalog(incoming: 6) == .accepted)
        #expect(store.evaluateCatalog(incoming: 5) == .accepted) // equal: not a rollback
        #expect(store.evaluateCatalog(incoming: 100) == .accepted)
    }

    @Test("older serial is a rollback (rejected)")
    func rejectOlder() throws {
        let store = Self.freshStore()
        try store.recordCatalog(serial: 10)
        #expect(store.evaluateCatalog(incoming: 9) == .rollback(stored: 10, incoming: 9))
        #expect(store.evaluateCatalog(incoming: 0) == .rollback(stored: 10, incoming: 0))
    }

    @Test("recordCatalog never lowers the high-water mark")
    func recordIsMonotonic() throws {
        let store = Self.freshStore()
        try store.recordCatalog(serial: 10)
        try store.recordCatalog(serial: 3)   // attempt to lower — must be ignored
        #expect(store.load().catalogSerial == 10)
        try store.recordCatalog(serial: 11)  // raise — must advance
        #expect(store.load().catalogSerial == 11)
    }

    @Test("state persists across store instances")
    func persists() throws {
        let path = (NSTemporaryDirectory() as NSString)
            .appendingPathComponent("rave-trust-state-\(UUID().uuidString).json")
        let a = RaveTrustStateStore(path: path)
        try a.recordCatalog(serial: 42)
        // Fresh instance, same path — must read the persisted mark.
        let b = RaveTrustStateStore(path: path)
        #expect(b.load().catalogSerial == 42)
        #expect(b.evaluateCatalog(incoming: 41) == .rollback(stored: 42, incoming: 41))
    }

    @Test("on-disk file is locked 0o600")
    func fileMode() throws {
        let store = Self.freshStore()
        try store.recordCatalog(serial: 1)
        let attrs = try FileManager.default.attributesOfItem(atPath: store.filePath)
        let perms = (attrs[.posixPermissions] as? NSNumber)?.intValue ?? 0
        #expect(perms == 0o600)
    }

    @Test("revocations mark is independent of catalog mark")
    func revocationsIndependent() throws {
        let store = Self.freshStore()
        try store.recordCatalog(serial: 5)
        // Revocations never set yet → first-seen even though catalog is at 5.
        #expect(store.evaluateRevocations(incoming: 0) == .firstSeen)
        try store.recordRevocations(serial: 3)
        #expect(store.evaluateRevocations(incoming: 2) == .rollback(stored: 3, incoming: 2))
        #expect(store.evaluateRevocations(incoming: 4) == .accepted)
        // Catalog mark unchanged by revocations writes.
        #expect(store.load().catalogSerial == 5)
        #expect(store.load().revocationsSerial == 3)
    }

    @Test("missing file degrades to empty (first-seen)")
    func missingFileEmpty() {
        let store = RaveTrustStateStore(path:
            (NSTemporaryDirectory() as NSString)
                .appendingPathComponent("does-not-exist-\(UUID().uuidString).json"))
        #expect(store.load() == RaveTrustState())
        #expect(store.evaluateCatalog(incoming: 999) == .firstSeen)
    }

    @Test("garbage file degrades to empty (no wedge)")
    func garbageFileEmpty() throws {
        let path = (NSTemporaryDirectory() as NSString)
            .appendingPathComponent("garbage-\(UUID().uuidString).json")
        try Data("not json {{{".utf8).write(to: URL(fileURLWithPath: path))
        let store = RaveTrustStateStore(path: path)
        #expect(store.load() == RaveTrustState())
        #expect(store.evaluateCatalog(incoming: 1) == .firstSeen)
    }
}
