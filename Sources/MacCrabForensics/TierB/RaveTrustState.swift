// RaveTrustState — persisted client-side anti-rollback high-water marks for
// the rave plugin catalog (S2-AR). Records the highest catalog_serial and
// revocations serial the client has ever accepted from a *signature-verified*
// document, so a later validly-signed-but-stale document (rollback / replay)
// can be rejected.
//
// Both monotonic counters live in one small JSON file so the revocations
// high-water mark (Stage 2) can land alongside the catalog one without a
// second store. Written atomically, locked 0o600 — the *integrity* of these
// counters is part of the trust boundary (a downgraded counter re-opens the
// rollback window the signed serials are meant to close).
//
//   <supportDir>/rave_trust_state.json
//     {
//       "schema_version": 1,
//       "catalog_serial": <int>,        // highest accepted catalog_serial
//       "revocations_serial": <int>,    // highest accepted revocations serial
//       "updated_at": "<ISO8601>"
//     }
//
// Semantics: a missing counter is "never seen" (any serial is accepted and
// becomes the new high-water mark). Once a counter is set, a strictly lower
// serial on a validly-signed document is a rollback and is rejected by the
// caller; an equal-or-higher serial is accepted and advances the mark.

import Foundation

public struct RaveTrustState: Sendable, Equatable {
    /// Highest catalog_serial ever accepted from a signature-verified catalog.
    /// `nil` means no catalog has been accepted yet (first-seen).
    public var catalogSerial: Int?
    /// Highest revocations serial ever accepted from a signature-verified
    /// revocations.json. `nil` means first-seen. (Wired in Stage 2.)
    public var revocationsSerial: Int?

    public init(catalogSerial: Int? = nil, revocationsSerial: Int? = nil) {
        self.catalogSerial = catalogSerial
        self.revocationsSerial = revocationsSerial
    }
}

/// Result of checking a freshly-verified serial against the persisted
/// high-water mark.
public enum RaveSerialDecision: Sendable, Equatable {
    /// No prior mark — this is the first serial we've seen; accept + record.
    case firstSeen
    /// `incoming >= stored` — fresh or same; accept (and advance if greater).
    case accepted
    /// `incoming < stored` — stale/rolled-back; reject, keep the prior state.
    case rollback(stored: Int, incoming: Int)
}

public struct RaveTrustStateStore: Sendable {
    private let path: String

    /// `path` is the full path to the state JSON file. Callers that want the
    /// default location should use `default(supportDir:)`.
    public init(path: String) {
        self.path = path
    }

    /// Default store at `<supportDir>/rave_trust_state.json`.
    public static func `default`(supportDir: String) -> RaveTrustStateStore {
        let full = (supportDir as NSString).appendingPathComponent("rave_trust_state.json")
        return RaveTrustStateStore(path: full)
    }

    public var filePath: String { path }

    /// Load the persisted state. A missing or unreadable/garbage file is
    /// treated as empty (first-seen) — fail-open is correct here because an
    /// absent file legitimately means "fresh install, nothing accepted yet".
    /// A *present* file that fails to parse also degrades to empty: we'd
    /// rather re-accept the current signed catalog than wedge the client.
    public func load() -> RaveTrustState {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return RaveTrustState()
        }
        // JSONSerialization decodes integers as NSNumber; pull as Int.
        let cat = (obj["catalog_serial"] as? NSNumber)?.intValue
        let rev = (obj["revocations_serial"] as? NSNumber)?.intValue
        return RaveTrustState(catalogSerial: cat, revocationsSerial: rev)
    }

    /// Atomically persist the state, locking the file to 0o600.
    public func save(_ state: RaveTrustState) throws {
        var payload: [String: Any] = [
            "schema_version": 1,
            "updated_at": ISO8601DateFormatter().string(from: Date()),
        ]
        if let c = state.catalogSerial { payload["catalog_serial"] = c }
        if let r = state.revocationsSerial { payload["revocations_serial"] = r }
        let data = try JSONSerialization.data(
            withJSONObject: payload,
            options: [.prettyPrinted, .sortedKeys]
        )
        // Ensure the parent dir exists.
        let dir = (path as NSString).deletingLastPathComponent
        try? FileManager.default.createDirectory(
            atPath: dir, withIntermediateDirectories: true
        )
        try data.write(to: URL(fileURLWithPath: path), options: .atomic)
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: path
        )
    }

    /// Pure decision: is `incoming` acceptable against the persisted catalog
    /// high-water mark? Does NOT persist — the caller advances the mark only
    /// after it has fully accepted the catalog.
    public func evaluateCatalog(incoming: Int) -> RaveSerialDecision {
        Self.decide(stored: load().catalogSerial, incoming: incoming)
    }

    /// Pure decision against the revocations high-water mark. (Stage 2.)
    public func evaluateRevocations(incoming: Int) -> RaveSerialDecision {
        Self.decide(stored: load().revocationsSerial, incoming: incoming)
    }

    /// Advance the persisted catalog high-water mark to `serial` if it is
    /// greater than the stored value (idempotent; never lowers the mark).
    public func recordCatalog(serial: Int) throws {
        var state = load()
        if let stored = state.catalogSerial, stored >= serial { return }
        state.catalogSerial = serial
        try save(state)
    }

    /// Advance the persisted revocations high-water mark. (Stage 2.)
    public func recordRevocations(serial: Int) throws {
        var state = load()
        if let stored = state.revocationsSerial, stored >= serial { return }
        state.revocationsSerial = serial
        try save(state)
    }

    /// Highest catalog_serial ever accepted from a signature-verified catalog,
    /// or nil if none has been seen. v1.19.0: lets a consumer reject a
    /// serial→serial-less REGRESSION (an old, pre-serial signed catalog replayed
    /// after a serial'd one was already accepted) without forging a lower serial.
    public func currentCatalogSerial() -> Int? { load().catalogSerial }

    /// Highest revocations serial ever accepted, or nil. Same regression guard
    /// as `currentCatalogSerial` — closes the replay of a pre-serial signed
    /// revocations.json that would otherwise silently un-revoke a plugin.
    public func currentRevocationsSerial() -> Int? { load().revocationsSerial }

    static func decide(stored: Int?, incoming: Int) -> RaveSerialDecision {
        guard let stored = stored else { return .firstSeen }
        if incoming < stored { return .rollback(stored: stored, incoming: incoming) }
        return .accepted
    }
}
