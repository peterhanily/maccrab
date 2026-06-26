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
    /// When the client last successfully verified a revocations.json (C-E).
    /// `nil` means a revocations list has never been verified on this client.
    /// Re-verifying the SAME serial still refreshes this clock — it is freshness,
    /// not the anti-rollback mark. Drives the staleness ceiling: install-time
    /// consent warns when the only revocation data we hold is older than the
    /// ceiling (we may not know a plugin was revoked since).
    public var revocationsVerifiedAt: Date?
    /// Highest serial ever accepted from a signature-verified rules manifest
    /// (the detection rule-update channel — separate anti-rollback mark from the
    /// plugin catalog so the two channels can't replay against each other).
    /// `nil` means first-seen.
    public var rulesManifestSerial: Int?

    public init(
        catalogSerial: Int? = nil,
        revocationsSerial: Int? = nil,
        revocationsVerifiedAt: Date? = nil,
        rulesManifestSerial: Int? = nil
    ) {
        self.catalogSerial = catalogSerial
        self.revocationsSerial = revocationsSerial
        self.rulesManifestSerial = rulesManifestSerial
        self.revocationsVerifiedAt = revocationsVerifiedAt
    }
}

/// Result of evaluating how old the client's revocation data is against a
/// staleness ceiling (C-E). Pure value type so the policy is unit-testable.
public enum RaveRevocationFreshness: Sendable, Equatable {
    /// A revocations list has never been verified on this client.
    case never
    /// Verified within the ceiling — trustworthy.
    case fresh(age: TimeInterval)
    /// Verified, but older than the ceiling — we may have missed a revocation.
    case stale(age: TimeInterval)

    /// True when the data is older than the ceiling or was never fetched —
    /// i.e. the UI should warn before treating "not revoked" as authoritative.
    public var isStale: Bool {
        switch self {
        case .fresh: return false
        case .stale, .never: return true
        }
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
        // C-E: round-trip the revocations freshness clock (a malformed/absent
        // timestamp degrades to "never verified" → the staleness ceiling warns).
        let verifiedAt = (obj["revocations_verified_at"] as? String)
            .flatMap { ISO8601DateFormatter().date(from: $0) }
        let rulesSerial = (obj["rules_manifest_serial"] as? NSNumber)?.intValue
        return RaveTrustState(catalogSerial: cat, revocationsSerial: rev, revocationsVerifiedAt: verifiedAt, rulesManifestSerial: rulesSerial)
    }

    /// Atomically persist the state, locking the file to 0o600.
    public func save(_ state: RaveTrustState) throws {
        var payload: [String: Any] = [
            "schema_version": 1,
            "updated_at": ISO8601DateFormatter().string(from: Date()),
        ]
        if let c = state.catalogSerial { payload["catalog_serial"] = c }
        if let r = state.revocationsSerial { payload["revocations_serial"] = r }
        if let v = state.revocationsVerifiedAt {
            payload["revocations_verified_at"] = ISO8601DateFormatter().string(from: v)
        }
        if let rm = state.rulesManifestSerial { payload["rules_manifest_serial"] = rm }
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

    /// Pure decision against the rules-manifest high-water mark (rule-update
    /// channel anti-rollback). Does NOT persist; caller advances only after fully
    /// accepting the manifest.
    public func evaluateRulesManifest(incoming: Int) -> RaveSerialDecision {
        Self.decide(stored: load().rulesManifestSerial, incoming: incoming)
    }

    /// Advance the persisted rules-manifest high-water mark (idempotent; never
    /// lowers). Call only after the manifest has been fully verified + accepted.
    public func recordRulesManifest(serial: Int) throws {
        var state = load()
        if let stored = state.rulesManifestSerial, stored >= serial { return }
        state.rulesManifestSerial = serial
        try save(state)
    }

    /// Advance the persisted catalog high-water mark to `serial` if it is
    /// greater than the stored value (idempotent; never lowers the mark).
    public func recordCatalog(serial: Int) throws {
        var state = load()
        if let stored = state.catalogSerial, stored >= serial { return }
        state.catalogSerial = serial
        try save(state)
    }

    /// Advance the persisted revocations high-water mark AND refresh the
    /// freshness clock (C-E). The serial mark only ever moves upward (monotonic
    /// anti-rollback); but `revocationsVerifiedAt` is updated on EVERY accepted
    /// verification — including a re-fetch of the same serial — because that is
    /// still a successful refresh and must reset the staleness ceiling. The
    /// caller has already accepted the document (via `evaluateRevocations`)
    /// before calling this, so a rollback serial never reaches here. (Stage 2.)
    public func recordRevocations(serial: Int, verifiedAt: Date = Date()) throws {
        var state = load()
        if state.revocationsSerial == nil || serial > state.revocationsSerial! {
            state.revocationsSerial = serial
        }
        state.revocationsVerifiedAt = verifiedAt
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

    /// When the client last verified a revocations list, or nil if never. (C-E.)
    public func lastRevocationsVerifiedAt() -> Date? { load().revocationsVerifiedAt }

    /// Default staleness ceiling for revocation data: 7 days. Beyond this the
    /// install-consent UI warns that the client may not yet know about a recent
    /// revocation. Callers may pass a stricter ceiling (e.g. for third-party).
    public static let defaultRevocationStalenessCeiling: TimeInterval = 7 * 24 * 3600

    /// Pure freshness policy (C-E): classify `lastVerified` against `ceiling` as
    /// of `now`. A future timestamp (clock skew / tamper) clamps to age 0 so a
    /// skewed-forward clock can never read as "fresh forever" past the ceiling —
    /// it reads as just-verified, which is the safe direction for a warning.
    public static func revocationFreshness(
        lastVerified: Date?,
        now: Date,
        ceiling: TimeInterval
    ) -> RaveRevocationFreshness {
        guard let last = lastVerified else { return .never }
        let age = max(0, now.timeIntervalSince(last))
        return age <= ceiling ? .fresh(age: age) : .stale(age: age)
    }

    /// Freshness of the persisted revocation data as of `now` (reads from disk).
    public func revocationFreshness(
        now: Date = Date(),
        ceiling: TimeInterval = RaveTrustStateStore.defaultRevocationStalenessCeiling
    ) -> RaveRevocationFreshness {
        Self.revocationFreshness(lastVerified: load().revocationsVerifiedAt, now: now, ceiling: ceiling)
    }

    static func decide(stored: Int?, incoming: Int) -> RaveSerialDecision {
        guard let stored = stored else { return .firstSeen }
        if incoming < stored { return .rollback(stored: stored, incoming: incoming) }
        return .accepted
    }
}
