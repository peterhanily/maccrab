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
// A1-03: the file is now a HOST-SIGNED envelope (LocalTrustSigner) rather than
// a bare flat object. A same-uid attacker who deletes/corrupts/forges it can no
// longer silently reset the marks to "first-seen" — a present-but-unverifiable
// file fails CLOSED (the marks read as maximal, so any real serial is rejected
// as a rollback) instead of re-opening the rollback window. A *missing* file is
// still a legitimate first-run bootstrap.
//
// A1-03 upgrade path: a user upgrading FROM a pre-A1-03 build has a legacy FLAT
// file (counters at the top level, no envelope) and NO host `.signkey`. Reading
// that as `.tampered` would fail-close a legitimate upgrade — breaking the store,
// revocation refresh, and installed-plugin execution with no self-heal. So a flat
// file is migrated ONCE — but only when no host key has ever sealed here (the
// unforgeable "first upgrade" signal): its marks are adopted and immediately
// re-sealed into an envelope. After any successful seal a flat file is a
// downgrade/tamper again and fails closed, so the migration cannot reset a mark
// that was ever sealed. A flat file that claims schema_version ≥ 2 (a forged
// downgrade) is rejected, not migrated.
//
//   <supportDir>/rave_trust_state.json
//     {
//       "schema_version": 2,
//       "body": {
//         "catalog_serial": <int>,        // highest accepted catalog_serial
//         "revocations_serial": <int>,    // highest accepted revocations serial
//         "rules_manifest_serial": <int>, // highest accepted rules manifest serial
//         "updated_at": "<ISO8601>"
//       },
//       "signature": "<base64 DER ECDSA-P256-SHA256 over canonical(body)>",
//       "public_key_der": "<base64 SPKI DER of this host's signing key>"
//     }
//   <supportDir>/rave_trust_state.json.signkey   // the 0o600 host signing key
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

/// Raised by the `record*` paths when the on-disk state is present but fails its
/// integrity check (A1-03). Recording is refused so a tampered file is never
/// "laundered" into a freshly-signed one; callers use `try?`, so this degrades to
/// a no-op rather than advancing/overwriting a compromised mark.
public enum RaveTrustStateError: Error, Equatable {
    case tampered
}

public struct RaveTrustStateStore: Sendable {
    private let path: String
    /// Signs/verifies the on-disk state so a same-uid reset (delete/corrupt/forge)
    /// is detectable and rejected rather than silently read as first-seen (A1-03).
    private let signer: LocalTrustSigner

    /// `path` is the full path to the state JSON file. Callers that want the
    /// default location should use `default(supportDir:)`. `signer` defaults to a
    /// per-host key sitting next to the state file (`<path>.signkey`, 0o600) — so
    /// every distinct state file gets an independent key, and the CLI + app that
    /// share one state path also share its key.
    public init(path: String, signer: LocalTrustSigner? = nil) {
        self.path = path
        self.signer = signer ?? LocalTrustSigner(keyPath: URL(fileURLWithPath: path + ".signkey"))
    }

    /// Default store at `<supportDir>/rave_trust_state.json`.
    public static func `default`(supportDir: String) -> RaveTrustStateStore {
        let full = (supportDir as NSString).appendingPathComponent("rave_trust_state.json")
        return RaveTrustStateStore(path: full)
    }

    public var filePath: String { path }

    /// Outcome of reading the state file with its integrity check.
    private enum LoadOutcome {
        /// No file — a legitimate fresh install (bootstrap → first-seen).
        case missing
        /// A present file that verified against this host's signing key.
        case verified(RaveTrustState)
        /// A legacy pre-A1-03 FLAT file on a host that has never sealed an
        /// envelope here — a one-time upgrade. The caller adopts these marks and
        /// re-seals them into an envelope (never `.tampered`).
        case legacyMigration(RaveTrustState)
        /// A present file that is unsigned, corrupt, or forged with another key.
        case tampered
    }

    /// Read + integrity-check the state file. A *missing* file is bootstrap
    /// (first-seen). A *present* file that is a host-signed envelope must verify
    /// (mutated body / foreign key / missing host key → `.tampered`, unchanged).
    /// A *present* file that is NOT an envelope is either a legacy pre-A1-03 FLAT
    /// file to migrate once (A1-03: recognizable flat shape AND no host signing
    /// key has ever sealed here) or genuine garbage/tamper (`.tampered`).
    private func loadOutcome() -> LoadOutcome {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
            return .missing
        }
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            warnTampered()
            return .tampered
        }
        // NEW format (A1-03): a sealed host-signed envelope. It MUST open + verify
        // against this host's key; anything else (mutated body, foreign key,
        // missing host key) is genuine tamper and fails closed. This path is
        // unchanged — the legacy migration below never reaches or weakens it.
        if LocalTrustSigner.isEnvelope(obj) {
            guard let body = signer.open(obj) else {
                warnTampered()
                return .tampered
            }
            return .verified(Self.state(fromBody: body))
        }
        // NOT an envelope. Distinguish a legacy pre-A1-03 FLAT file (one-time
        // upgrade) from genuine garbage/tamper. Gate the migration on the ABSENCE
        // of a host signing key: a pre-A1-03 build had no LocalTrustSigner, so a
        // genuine first upgrade has never sealed anything here (no `.signkey`).
        // Once this host HAS sealed an envelope, a subsequent flat file is a
        // downgrade/tamper and still fails closed — so the migration can never be
        // abused to reset a mark that was ever sealed.
        if signer.pinnedPublicKeyDER() == nil, let legacy = Self.legacyFlatBody(obj) {
            FileHandle.standardError.write(Data(
                "MacCrab: migrating legacy (pre-A1-03) rave trust-state at \(path) into a host-signed envelope (A1-03 one-time upgrade)\n".utf8
            ))
            return .legacyMigration(Self.state(fromBody: legacy))
        }
        warnTampered()
        return .tampered
    }

    private func warnTampered() {
        FileHandle.standardError.write(Data(
            "MacCrab: rave trust-state integrity check FAILED (unsigned/tampered) at \(path) — refusing to trust it (A1-03)\n".utf8
        ))
    }

    /// Parse a state body (the verified envelope body, or a migrated legacy flat
    /// object — both carry the counters under the same keys). JSONSerialization
    /// decodes integers as NSNumber; pull as Int.
    private static func state(fromBody body: [String: Any]) -> RaveTrustState {
        let cat = (body["catalog_serial"] as? NSNumber)?.intValue
        let rev = (body["revocations_serial"] as? NSNumber)?.intValue
        // C-E: round-trip the revocations freshness clock (a malformed/absent
        // timestamp degrades to "never verified" → the staleness ceiling warns).
        let verifiedAt = (body["revocations_verified_at"] as? String)
            .flatMap { ISO8601DateFormatter().date(from: $0) }
        let rulesSerial = (body["rules_manifest_serial"] as? NSNumber)?.intValue
        return RaveTrustState(catalogSerial: cat, revocationsSerial: rev, revocationsVerifiedAt: verifiedAt, rulesManifestSerial: rulesSerial)
    }

    /// Recognize a legacy pre-A1-03 FLAT state file: the counters live at the TOP
    /// level (no `body`/`signature`/`public_key_der` envelope) and the file is
    /// schema_version 1 or older. Returns the flat object (usable directly as a
    /// body) for a one-time migration, or nil when it isn't the legacy shape — in
    /// which case the caller fails closed (`.tampered`) rather than laundering
    /// random JSON into an accepted state. A FLAT object claiming schema_version
    /// ≥ 2 is a forged downgrade, not a legacy file, and is rejected here.
    private static func legacyFlatBody(_ obj: [String: Any]) -> [String: Any]? {
        if let sv = (obj["schema_version"] as? NSNumber)?.intValue,
           sv >= LocalTrustSigner.schemaVersion {
            return nil
        }
        let hasCounter = obj["catalog_serial"] != nil
            || obj["revocations_serial"] != nil
            || obj["rules_manifest_serial"] != nil
            || obj["revocations_verified_at"] != nil
        return hasCounter ? obj : nil
    }

    /// Load the persisted state. A missing file is empty (first-seen) — a fresh
    /// install legitimately has nothing accepted yet. A *present* file that fails
    /// its integrity check (A1-03) does NOT silently degrade to first-seen (which
    /// would re-open the anti-rollback window a reset attack is aiming at);
    /// instead it fails CLOSED to a MAXIMAL high-water mark, so every real
    /// (finite) incoming serial reads as a rollback and the caller refuses.
    /// Recovery from a genuine corruption is to delete the file (→ clean
    /// first-seen bootstrap) — a deliberate operator action, not a silent reset.
    public func load() -> RaveTrustState {
        switch loadOutcome() {
        case .missing: return RaveTrustState()
        case .verified(let s): return s
        case .legacyMigration(let s):
            // A1-03 one-time upgrade: re-seal the adopted legacy marks into a
            // host-signed envelope so the flat file is replaced (and a `.signkey`
            // generated — after which a flat file reads as tamper). Best-effort:
            // a read must never throw. If the seal fails the flat file stays and a
            // later load re-migrates; the marks returned here are correct either
            // way. (Residual: if the seal generates the key but the envelope write
            // fails, the still-flat file then reads as `.tampered` — fail-closed
            // and recoverable by deleting the file; the two writes hit the same
            // dir, so this is a near-impossible correlated failure.)
            try? save(s)
            return s
        case .tampered: return Self.tamperedSentinel
        }
    }

    /// Fail-closed baseline for a present-but-untrusted state: treat the marks as
    /// maxed so `decide()` rejects any real serial as a rollback. `nil`
    /// verifiedAt → freshness reads `.never` (stale → the UI warns).
    private static let tamperedSentinel = RaveTrustState(
        catalogSerial: Int.max, revocationsSerial: Int.max, revocationsVerifiedAt: nil, rulesManifestSerial: Int.max
    )

    /// State to advance from on a `record*` write. Missing → empty base; verified
    /// → that state; tampered → THROW so a compromised file is never laundered
    /// into a freshly-signed one (callers use `try?`, so this is a safe no-op).
    private func loadForRecord() throws -> RaveTrustState {
        switch loadOutcome() {
        case .missing: return RaveTrustState()
        case .verified(let s): return s
        // A1-03 one-time upgrade: adopt the legacy marks; the subsequent save()
        // re-seals them into an envelope (record* only ever advances the mark).
        case .legacyMigration(let s): return s
        case .tampered: throw RaveTrustStateError.tampered
        }
    }

    /// Atomically persist the state as a host-signed envelope, locking the file
    /// to 0o600 (A1-03). The signature covers the canonical body, so a later
    /// same-uid edit that isn't re-signed by this host is rejected on load.
    public func save(_ state: RaveTrustState) throws {
        var body: [String: Any] = [
            "updated_at": ISO8601DateFormatter().string(from: Date()),
        ]
        if let c = state.catalogSerial { body["catalog_serial"] = c }
        if let r = state.revocationsSerial { body["revocations_serial"] = r }
        if let v = state.revocationsVerifiedAt {
            body["revocations_verified_at"] = ISO8601DateFormatter().string(from: v)
        }
        if let rm = state.rulesManifestSerial { body["rules_manifest_serial"] = rm }
        let envelope = try signer.seal(body: body)
        let data = try JSONSerialization.data(
            withJSONObject: envelope,
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
        var state = try loadForRecord()
        if let stored = state.rulesManifestSerial, stored >= serial { return }
        state.rulesManifestSerial = serial
        try save(state)
    }

    /// Advance the persisted catalog high-water mark to `serial` if it is
    /// greater than the stored value (idempotent; never lowers the mark).
    public func recordCatalog(serial: Int) throws {
        var state = try loadForRecord()
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
        var state = try loadForRecord()
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
