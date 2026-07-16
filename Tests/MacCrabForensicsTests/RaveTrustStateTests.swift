// RaveTrustState (S2-AR) anti-rollback high-water-mark store tests.
//
// Covers:
//   - first-seen accepts any serial and records it
//   - a newer/equal serial is accepted and advances the mark
//   - an older serial is a rollback (rejected; mark unchanged)
//   - record() never lowers the mark (idempotent / monotonic)
//   - persistence round-trips through the on-disk JSON
//   - revocations high-water mark is independent of the catalog one
//   - missing file degrades to empty (first-seen)
//   - A1-03: present-but-unsigned/tampered/forged file fails CLOSED (not first-seen)
//   - A1-03 upgrade: a legacy FLAT file migrates ONCE on a no-host-key host, but
//     a flat file written AFTER a seal is a downgrade and still fails closed

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

    @Test("v1.19.0: current{Catalog,Revocations}Serial expose the high-water mark (nil until seen)")
    func currentSerialAccessors() throws {
        let store = Self.freshStore()
        // nil → never accepted a serial; the browse-path regression rule lets a
        // serial-less (pre-ceremony) catalog through as first-seen.
        #expect(store.currentCatalogSerial() == nil)
        #expect(store.currentRevocationsSerial() == nil)
        try store.recordCatalog(serial: 4)
        try store.recordRevocations(serial: 9)
        // non-nil → a serial was accepted, so a later absent serial is a
        // pre-serial replay and the regression rule rejects it.
        #expect(store.currentCatalogSerial() == 4)
        #expect(store.currentRevocationsSerial() == 9)
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

    // MARK: - A1-03: present-but-untrusted state fails CLOSED (not first-seen)

    static func tmpPath() -> String {
        (NSTemporaryDirectory() as NSString)
            .appendingPathComponent("rave-ts-a103-\(UUID().uuidString).json")
    }

    /// Any present file that isn't a valid host-signed envelope must NOT read as
    /// first-seen — that would re-open the anti-rollback window a reset targets.
    /// It fails closed to a maximal mark so `decide()` rejects any real serial.
    private func expectFailClosed(_ store: RaveTrustStateStore, _ what: String) {
        let d = store.evaluateCatalog(incoming: 1)
        #expect(d != .firstSeen, "\(what): must not be first-seen")
        #expect(d != .accepted, "\(what): must not be accepted")
        if case .rollback = d {} else { Issue.record("\(what): expected fail-closed rollback, got \(d)") }
        #expect(store.load() != RaveTrustState(), "\(what): must not degrade to empty")
    }

    @Test("A1-03: garbage present file fails closed (was: degraded to first-seen)")
    func garbageFileFailsClosed() throws {
        let path = Self.tmpPath()
        try Data("not json {{{".utf8).write(to: URL(fileURLWithPath: path))
        expectFailClosed(RaveTrustStateStore(path: path), "garbage")
    }

    @Test("A1-03: legacy flat file MIGRATES on first upgrade (no host key yet), then re-seals")
    func legacyFlatFileMigrates() throws {
        let path = Self.tmpPath()
        // Pre-A1-03 shape on a host that has never sealed here (no `.signkey`) — a
        // genuine upgrade. Its marks are adopted (NOT fail-closed) and re-sealed,
        // so the store/revocation/plugin-exec paths keep working across upgrade.
        try Data(#"{"schema_version":1,"catalog_serial":5,"revocations_serial":2}"#.utf8)
            .write(to: URL(fileURLWithPath: path))
        let store = RaveTrustStateStore(path: path)
        #expect(store.load().catalogSerial == 5)          // carried across the upgrade
        #expect(store.currentRevocationsSerial() == 2)
        // The carried marks still enforce anti-rollback (a lower serial is stale).
        #expect(store.evaluateCatalog(incoming: 4) == .rollback(stored: 5, incoming: 4))
        // load() re-sealed the flat file into a host-signed envelope.
        let obj = try JSONSerialization.jsonObject(
            with: Data(contentsOf: URL(fileURLWithPath: path))) as! [String: Any]
        #expect(LocalTrustSigner.isEnvelope(obj))
    }

    @Test("A1-03: a flat file written AFTER a seal is a downgrade → fails closed (not migrated)")
    func flatDowngradeAfterSealFailsClosed() throws {
        let path = Self.tmpPath()
        let store = RaveTrustStateStore(path: path)
        try store.recordCatalog(serial: 5)   // seals → this host's `.signkey` now exists
        // A same-uid attacker rewrites the sealed envelope as a flat LOW mark to
        // reset the high-water mark. A host key now exists, so this is a
        // downgrade/tamper — NOT a legacy upgrade — and must be rejected. This is
        // the reset-attack the migration must never re-open on an established mark.
        try Data(#"{"schema_version":1,"catalog_serial":0}"#.utf8)
            .write(to: URL(fileURLWithPath: path))
        expectFailClosed(store, "flat downgrade after seal")
    }

    @Test("A1-03: a FLAT file claiming schema_version >= 2 is a forged downgrade → fails closed")
    func flatSchemaV2FailsClosed() throws {
        let path = Self.tmpPath()
        // A v2 state is REQUIRED to be a sealed envelope; a flat object claiming
        // v2 is a forgery, not a legacy file — reject even with no key present.
        try Data(#"{"schema_version":2,"catalog_serial":0}"#.utf8)
            .write(to: URL(fileURLWithPath: path))
        expectFailClosed(RaveTrustStateStore(path: path), "flat schema_version 2")
    }

    @Test("A1-03: a body mutated after signing is detected and rejected")
    func mutatedBodyRejected() throws {
        let path = Self.tmpPath()
        let store = RaveTrustStateStore(path: path)
        try store.recordCatalog(serial: 5)
        #expect(store.evaluateCatalog(incoming: 4) == .rollback(stored: 5, incoming: 4)) // verifies clean
        // Flip the sealed body's catalog_serial to 999 without re-signing.
        var obj = try JSONSerialization.jsonObject(
            with: Data(contentsOf: URL(fileURLWithPath: path))) as! [String: Any]
        var body = obj["body"] as! [String: Any]
        body["catalog_serial"] = 999
        obj["body"] = body
        try JSONSerialization.data(withJSONObject: obj, options: [.prettyPrinted])
            .write(to: URL(fileURLWithPath: path))
        #expect(store.currentCatalogSerial() != 999)   // forged mark not honored
        expectFailClosed(store, "mutated body")
    }

    @Test("A1-03: an envelope signed by a foreign key is rejected (pin)")
    func foreignKeyRejected() throws {
        let path = Self.tmpPath()
        // Seal with an unrelated key, drop it at the store path. The store's own
        // signkey differs, so the embedded pubkey fails the pin.
        let foreign = LocalTrustSigner(keyPath: URL(fileURLWithPath: Self.tmpPath() + ".signkey"))
        let envelope = try foreign.seal(body: ["catalog_serial": 1])
        try JSONSerialization.data(withJSONObject: envelope, options: [.prettyPrinted])
            .write(to: URL(fileURLWithPath: path))
        expectFailClosed(RaveTrustStateStore(path: path), "foreign key")
    }

    @Test("A1-03: record refuses to launder a tampered file (no-op, not overwrite)")
    func recordRefusesTampered() throws {
        let path = Self.tmpPath()
        let store = RaveTrustStateStore(path: path)
        try store.recordCatalog(serial: 5)
        try Data("garbage".utf8).write(to: URL(fileURLWithPath: path))
        // record* must THROW rather than re-sign a fresh attacker-chosen baseline.
        #expect(throws: RaveTrustStateError.self) { try store.recordCatalog(serial: 6) }
        #expect(throws: RaveTrustStateError.self) { try store.recordRevocations(serial: 6) }
        #expect(throws: RaveTrustStateError.self) { try store.recordRulesManifest(serial: 6) }
    }

    @Test("A1-03: signed state round-trips + verifies across instances")
    func signedRoundTrip() throws {
        let path = Self.tmpPath()
        let a = RaveTrustStateStore(path: path)
        try a.recordCatalog(serial: 7)
        try a.recordRevocations(serial: 3, verifiedAt: Date(timeIntervalSince1970: 1_700_000_000))
        let b = RaveTrustStateStore(path: path)   // same path → same signkey → verifies
        #expect(b.load().catalogSerial == 7)
        #expect(b.currentRevocationsSerial() == 3)
        #expect(b.evaluateCatalog(incoming: 6) == .rollback(stored: 7, incoming: 6))
    }

    // MARK: - C-E revocation freshness / staleness ceiling

    @Test("C-E: recordRevocations stamps + round-trips the freshness clock")
    func revocationClockRoundTrips() throws {
        let path = (NSTemporaryDirectory() as NSString)
            .appendingPathComponent("rave-trust-state-\(UUID().uuidString).json")
        let a = RaveTrustStateStore(path: path)
        #expect(a.lastRevocationsVerifiedAt() == nil)
        let t = Date(timeIntervalSince1970: 1_700_000_000)
        try a.recordRevocations(serial: 5, verifiedAt: t)
        // Persists across instances (ISO8601 round-trip, ~second precision).
        let b = RaveTrustStateStore(path: path)
        let got = try #require(b.lastRevocationsVerifiedAt())
        #expect(abs(got.timeIntervalSince(t)) < 1.0)
        #expect(b.currentRevocationsSerial() == 5)
    }

    @Test("C-E: re-verifying the SAME serial refreshes the clock but never lowers the mark")
    func revocationClockRefreshesWithoutAdvancing() throws {
        let store = Self.freshStore()
        let t1 = Date(timeIntervalSince1970: 1_700_000_000)
        let t2 = t1.addingTimeInterval(3600)
        try store.recordRevocations(serial: 7, verifiedAt: t1)
        try store.recordRevocations(serial: 7, verifiedAt: t2) // same serial, later time
        #expect(store.currentRevocationsSerial() == 7)
        let got = try #require(store.lastRevocationsVerifiedAt())
        #expect(abs(got.timeIntervalSince(t2)) < 1.0)          // clock advanced to t2
    }

    @Test("C-E: revocation freshness policy — never / fresh / stale / future-clamp")
    func revocationFreshnessPolicy() {
        let ceiling: TimeInterval = 7 * 24 * 3600
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        // never verified → .never (treated as stale by the UI)
        #expect(RaveTrustStateStore.revocationFreshness(lastVerified: nil, now: now, ceiling: ceiling) == .never)
        // within ceiling → fresh
        if case .fresh(let age) = RaveTrustStateStore.revocationFreshness(
            lastVerified: now.addingTimeInterval(-3600), now: now, ceiling: ceiling) {
            #expect(abs(age - 3600) < 1.0)
        } else { Issue.record("expected fresh") }
        // older than ceiling → stale
        #expect(RaveTrustStateStore.revocationFreshness(
            lastVerified: now.addingTimeInterval(-(ceiling + 86400)), now: now, ceiling: ceiling).isStale)
        // future timestamp (clock skew/tamper) clamps to age 0 → fresh, not stale
        if case .fresh(let age) = RaveTrustStateStore.revocationFreshness(
            lastVerified: now.addingTimeInterval(99_999), now: now, ceiling: ceiling) {
            #expect(age == 0)
        } else { Issue.record("expected fresh (clamped)") }
    }

    @Test("C-E: store.revocationFreshness reads the persisted clock")
    func storeFreshnessReadsDisk() throws {
        let store = Self.freshStore()
        #expect(store.revocationFreshness().isStale)  // never verified → warn
        try store.recordRevocations(serial: 1, verifiedAt: Date())
        #expect(!store.revocationFreshness().isStale) // just verified → fresh
    }

    // MARK: - Rules-manifest channel (rule-update channel anti-rollback)

    @Test("rules-manifest serial: first-seen accepted, monotonic, rollback rejected, persisted")
    func rulesManifestSerial() throws {
        let store = Self.freshStore()
        #expect(store.evaluateRulesManifest(incoming: 5) == .firstSeen)
        try store.recordRulesManifest(serial: 5)
        #expect(store.evaluateRulesManifest(incoming: 6) == .accepted)
        #expect(store.evaluateRulesManifest(incoming: 5) == .accepted)         // equal: not a rollback
        #expect(store.evaluateRulesManifest(incoming: 4) == .rollback(stored: 5, incoming: 4))
        try store.recordRulesManifest(serial: 4)                               // record never lowers
        #expect(store.load().rulesManifestSerial == 5)
        try store.recordRulesManifest(serial: 9)
        #expect(store.load().rulesManifestSerial == 9)
    }

    @Test("rules-manifest serial is independent of the catalog serial (separate channels)")
    func rulesSerialIndependentOfCatalog() throws {
        let store = Self.freshStore()
        try store.recordCatalog(serial: 100)
        try store.recordRulesManifest(serial: 3)
        // Advancing one channel must not move the other.
        #expect(store.load().catalogSerial == 100)
        #expect(store.load().rulesManifestSerial == 3)
        #expect(store.evaluateRulesManifest(incoming: 2) == .rollback(stored: 3, incoming: 2))
        #expect(store.evaluateCatalog(incoming: 50) == .rollback(stored: 100, incoming: 50))
    }
}
