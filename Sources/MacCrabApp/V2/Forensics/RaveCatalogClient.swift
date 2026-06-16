// RaveCatalogClient.swift
//
// rc.7 — dashboard-side fetch + Ed25519-verify of the rave
// plugin catalog at rave.maccrab.com. Mirrors the maccrabctl
// PluginCatalogFetch path the parallel rave session wired in:
//   1. GET <base>/catalog.json + .sig
//   2. Verify against bundled catalog.pub
//   3. Return parsed plugin list
//
// Install action stays in the CLI side for now; the dashboard
// is browse-only in rc.7. Click-through "Install" copies the
// matching `maccrabctl plugin install <plugin-id>` command to
// the clipboard with a hint, until the in-dashboard install
// flow lands in v1.18.

import Foundation
import CryptoKit
import MacCrabCore
import MacCrabForensics

public struct RaveCatalogEntry: Identifiable, Hashable, Sendable {
    public let id: String           // plugin id, e.g. com.maccrab.hosts-collector
    public let currentVersion: String
    public let channel: String      // "official" / "contrib"
    public let trustTier: String    // "first-party" / "verified-community" / "unverified"
    public let signerIdentity: String
    /// O1b: sha256 (hex-lower) of the publisher's bundle signing.key.pub as
    /// endorsed by the signed catalog. Empty when the catalog entry omits it
    /// (pre-ceremony catalogs / pre-release entries).
    public let signerPublicKeySHA256: String
    /// Entry maturity ("pre-release" vs official). Surfaced so the dashboard
    /// can badge pre-release entries and explain the unpinned-install caveat.
    public let status: String
    public let category: String?
    public let tags: [String]
    public let minMaccrabVersion: String?
}

public enum RaveCatalogError: Error, CustomStringConvertible {
    case noBaseURL
    case noCatalogKey
    case fetchFailed(url: URL, status: Int)
    case signatureMismatch
    case parseFailed(reason: String)
    case catalogRollback(stored: Int, incoming: Int)
    case catalogSerialMissing(lastAccepted: Int)
    case revocationsSignatureMismatch
    case revocationsParseFailed(reason: String)
    case revocationsRollback(stored: Int, incoming: Int)
    case revocationsSerialMissing(lastAccepted: Int)
    case versionFloor(reason: String)

    public var description: String {
        switch self {
        case .noBaseURL:            return "No catalog base URL configured (MACCRAB_RAVE_BASE_URL or default)."
        case .noCatalogKey:         return "Bundled catalog signing key (catalog.pub) is missing."
        case .fetchFailed(let url, let s): return "HTTP \(s) fetching \(url.absoluteString)"
        case .signatureMismatch:    return "Catalog signature does not verify against the bundled key. The catalog may be corrupted or the signing key has rotated."
        case .parseFailed(let r):   return "Catalog parse failed: \(r)"
        case .catalogRollback(let stored, let incoming):
            return "Catalog rollback rejected — signed catalog_serial \(incoming) is older than the last-accepted serial \(stored). Showing the prior trusted catalog (stale/replay)."
        case .catalogSerialMissing(let lastAccepted):
            return "Catalog freshness regression rejected — a serial-stamped catalog (serial \(lastAccepted)) was accepted before, but this signature-verified catalog carries no catalog_serial. An old pre-serial catalog is being replayed; keeping the prior trusted catalog."
        case .revocationsSerialMissing(let lastAccepted):
            return "Revocation-list freshness regression rejected — serial \(lastAccepted) was accepted before, but this signature-verified list carries no serial (a pre-serial list replayed to silently un-revoke). Keeping the prior revocation state."
        case .revocationsSignatureMismatch:
            return "Revocations signature does not verify against the bundled key. Keeping the prior revocation state."
        case .revocationsParseFailed(let r):
            return "Revocations parse failed: \(r). Keeping the prior revocation state (fail-closed)."
        case .revocationsRollback(let stored, let incoming):
            return "Revocations rollback rejected — signed serial \(incoming) is older than the last-accepted serial \(stored). Keeping the prior revocation state (un-revoke replay)."
        case .versionFloor(let reason):
            return reason
        }
    }
}

public actor RaveCatalogClient {

    /// S2-AR anti-rollback high-water-mark store. Default location is
    /// <app-support>/MacCrab/rave_trust_state.json; overridable for tests.
    private let trustState: RaveTrustStateStore

    public init(trustState: RaveTrustStateStore? = nil) {
        if let s = trustState {
            self.trustState = s
        } else {
            let support = FileManager.default.urls(
                for: .applicationSupportDirectory, in: .userDomainMask
            ).first
                .map { $0.appendingPathComponent("MacCrab").path }
                ?? (NSHomeDirectory() + "/Library/Application Support/MacCrab")
            self.trustState = RaveTrustStateStore.default(supportDir: support)
        }
    }

    /// Official production catalog. Anything else is "custom"
    /// and gets a warning banner in the dashboard.
    public static let officialBaseURL = URL(string: "https://rave.maccrab.com/")!

    /// rc.14 — Settings-driven catalog override key in UserDefaults.
    /// SettingsView writes this. Empty string means "use default".
    public static let userDefaultsBaseURLKey = "forensics.catalogBaseURL"

    /// Source priority: env var > UserDefaults > default.
    /// Env wins so CI / shell rehearsals don't have to wipe the
    /// dashboard's persistent setting.
    public var baseURL: URL {
        if let env = ProcessInfo.processInfo.environment["MACCRAB_RAVE_BASE_URL"],
           !env.isEmpty,
           let url = parse(env) {
            return url
        }
        let defaults = UserDefaults.standard.string(forKey: Self.userDefaultsBaseURLKey) ?? ""
        if !defaults.isEmpty, let url = parse(defaults) {
            return url
        }
        return Self.officialBaseURL
    }

    /// Whether the current catalog source is the official one.
    /// Dashboard surfaces a banner when this is false so the
    /// operator doesn't confuse a local-dev catalog for production.
    public var isUsingOfficialSource: Bool {
        baseURL == Self.officialBaseURL
    }

    /// O3a (S2-05) app-side TRUST FLOOR. The store refuses a real-binary
    /// install of any catalog entry whose declared `min_maccrab_version` is
    /// below this — even if the running build technically satisfies a lower
    /// declared floor. This is the version below which the trust-floor client
    /// will not vouch for a plugin's compatibility/provenance contract on this
    /// release line. Plugins published before this floor must be re-cut against
    /// a supported MacCrab before the dashboard will install them.
    public static let trustFloorMinVersion = "1.17.0"

    /// Evaluate the version-floor gate for a catalog entry against the running
    /// build. Throws `RaveCatalogError.versionFloor` when install must be
    /// refused; returns the resolved floor (for display) on success.
    ///
    /// Two gates, both fail-closed:
    ///   1. Trust floor — the entry's declared min_maccrab_version must be at
    ///      or above `trustFloorMinVersion` (the store won't install ancient
    ///      plugins on this release line).
    ///   2. Running floor — the running build must be at or above the entry's
    ///      declared min_maccrab_version (don't install a plugin newer than
    ///      this engine).
    /// An absent declared floor skips both gates (signer pin remains the trust
    /// gate); an unparseable declared floor is a fail-closed refusal.
    public nonisolated func checkVersionFloor(
        entry: RaveCatalogEntry
    ) throws {
        // Gate 1: trust-floor minimum (store-level refusal).
        if let declared = entry.minMaccrabVersion, !declared.isEmpty {
            switch MacCrabSemverCompare.satisfiesFloor(
                running: declared, floor: Self.trustFloorMinVersion
            ) {
            case .some(true):
                break
            case .some(false):
                throw RaveCatalogError.versionFloor(reason:
                    "Refusing to install \(entry.id): it targets MacCrab \(declared), which is below this release line's trust floor (\(Self.trustFloorMinVersion)). The plugin must be re-published against a supported MacCrab.")
            case .none:
                throw RaveCatalogError.versionFloor(reason:
                    "Refusing to install \(entry.id): its declared min_maccrab_version '\(declared)' is not a valid MAJOR.MINOR.PATCH version (fail-closed).")
            }
        }

        // Gate 2: running-version floor (shared policy with the CLI path).
        do {
            try RaveVersionFloor.enforce(
                pluginID: entry.id,
                floor: entry.minMaccrabVersion,
                running: MacCrabVersion.current
            )
        } catch let e as RaveVersionFloorError {
            throw RaveCatalogError.versionFloor(reason: e.description)
        }
    }

    private func parse(_ raw: String) -> URL? {
        let trimmed = raw.hasSuffix("/") ? raw : raw + "/"
        return URL(string: trimmed)
    }

    /// Fetch + verify + parse the catalog index.
    public func fetchEntries() async throws -> [RaveCatalogEntry] {
        let key = try loadCatalogPublicKey()
        let base = baseURL
        let catalogURL = base.appendingPathComponent("catalog.json")
        let sigURL = base.appendingPathComponent("catalog.json.sig")

        async let dataF = fetch(url: catalogURL)
        async let sigF = fetch(url: sigURL)
        let data = try await dataF
        let sig = try await sigF
        guard key.isValidSignature(sig, for: data) else {
            throw RaveCatalogError.signatureMismatch
        }

        // S2-AR anti-rollback gate on the now signature-verified catalog. A
        // validly-signed-but-older catalog_serial is a stale/replay; reject it
        // and keep the prior high-water mark. Missing serial = first-seen so
        // pre-ceremony catalogs still load.
        if let serial = parseCatalogSerial(data: data) {
            switch trustState.evaluateCatalog(incoming: serial) {
            case .rollback(let stored, let incoming):
                throw RaveCatalogError.catalogRollback(stored: stored, incoming: incoming)
            case .firstSeen, .accepted:
                try? trustState.recordCatalog(serial: serial)
            }
        } else if let lastAccepted = trustState.currentCatalogSerial() {
            // v1.19.0: a serial'd catalog was accepted before; an absent serial
            // now is a pre-serial catalog being replayed. Reject the regression.
            throw RaveCatalogError.catalogSerialMissing(lastAccepted: lastAccepted)
        }
        return try parseCatalog(data: data)
    }

    /// O2 — fetch + Ed25519-verify the signed revocation list, enforce the
    /// monotonic-serial anti-rollback high-water mark, and reconcile the
    /// quarantine set for every installed plugin the list now revokes
    /// (quarantine-not-delete). Returns the verified list so the dashboard can
    /// badge revoked catalog entries. Fail-closed: a bad signature / malformed
    /// list / older serial throws and the prior revocation state is kept.
    ///
    /// `installer` defaults to the standard plugins root; injectable for tests.
    public func fetchAndReconcileRevocations(
        installer: PluginInstaller = PluginInstaller()
    ) async throws -> RaveRevocationList {
        let key = try loadCatalogPublicKey()
        let base = baseURL
        let revURL = base.appendingPathComponent("revocations.json")
        let sigURL = base.appendingPathComponent("revocations.json.sig")

        async let dataF = fetch(url: revURL)
        async let sigF = fetch(url: sigURL)
        let data = try await dataF
        let sig = try await sigF
        guard key.isValidSignature(sig, for: data) else {
            throw RaveCatalogError.revocationsSignatureMismatch
        }

        let list: RaveRevocationList
        do {
            list = try RaveRevocationList.parse(data: data)
        } catch {
            throw RaveCatalogError.revocationsParseFailed(reason: "\(error)")
        }

        // Anti-rollback gate. A validly-signed-but-older serial is an
        // un-revoke replay; reject and keep the prior state + high-water mark.
        if let serial = list.serial {
            switch trustState.evaluateRevocations(incoming: serial) {
            case .rollback(let stored, let incoming):
                throw RaveCatalogError.revocationsRollback(stored: stored, incoming: incoming)
            case .firstSeen, .accepted:
                try? trustState.recordRevocations(serial: serial)
            }
        } else if let lastAccepted = trustState.currentRevocationsSerial() {
            throw RaveCatalogError.revocationsSerialMissing(lastAccepted: lastAccepted)
        }

        // Reconcile quarantine for everything already installed.
        let installed = try await installer.list()
        var refs: [RevocationEnforcer.InstalledRef] = []
        refs.reserveCapacity(installed.count)
        for p in installed {
            let version = (try? TierBManifest.load(fromBundlePath: p.installRoot))?.version ?? ""
            refs.append(.init(pluginID: p.pluginID, version: version))
        }
        let records = RevocationEnforcer.reconcileQuarantine(installed: refs, against: list)
        try await installer.applyQuarantine(records)
        return list
    }

    /// C-E: refresh + reconcile revocations only if the persisted freshness
    /// clock is older than `minInterval` (default 1h). The throttle reads the
    /// clock locally and reuses the pure freshness policy as the ceiling, so a
    /// tight poll loop costs a timestamp comparison, not a network round-trip —
    /// the actual fetch happens at most once per interval. Returns the verified
    /// list when a refresh occurred, or nil when skipped as still-fresh.
    ///
    /// Fail-closed like `fetchAndReconcileRevocations`: a bad signature /
    /// malformed list / rollback throws and the prior revocation + quarantine
    /// state is kept. A successful refresh advances the freshness clock (via
    /// `recordRevocations`), which is what later staleness checks read.
    public func refreshRevocationsIfStale(
        installer: PluginInstaller = PluginInstaller(),
        minInterval: TimeInterval = 3600
    ) async throws -> RaveRevocationList? {
        if case .fresh = trustState.revocationFreshness(ceiling: minInterval) {
            return nil
        }
        return try await fetchAndReconcileRevocations(installer: installer)
    }

    /// Extract the top-level monotonic catalog_serial (S2-AR). nil when absent
    /// or non-integer (pre-ceremony catalog) — treated as first-seen upstream.
    private func parseCatalogSerial(data: Data) -> Int? {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        return (json["catalog_serial"] as? NSNumber)?.intValue
    }

    private func fetch(url: URL) async throws -> Data {
        let (data, response) = try await URLSession.shared.data(from: url)
        guard let http = response as? HTTPURLResponse else {
            throw RaveCatalogError.fetchFailed(url: url, status: -1)
        }
        guard (200..<300).contains(http.statusCode) else {
            throw RaveCatalogError.fetchFailed(url: url, status: http.statusCode)
        }
        return data
    }

    private func loadCatalogPublicKey() throws -> Curve25519.Signing.PublicKey {
        // Local-dev override.
        if let path = ProcessInfo.processInfo.environment["MACCRAB_RAVE_CATALOG_PUB_PATH"], !path.isEmpty,
           let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
           data.count == 32,
           let key = try? Curve25519.Signing.PublicKey(rawRepresentation: data) {
            return key
        }
        // S2-13 debug-only staging-key seam: a debug build with
        // MACCRAB_RAVE_STAGING_PUB set verifies against the staging signing
        // key. Compiled out / always nil on release builds.
        if let raw = RaveStagingPubOverride.rawKeyData(),
           let key = try? Curve25519.Signing.PublicKey(rawRepresentation: raw) {
            return key
        }
        // Bundle key — shipped via Sources/MacCrabApp/Resources/rave-keys/catalog.pub
        let candidates: [URL?] = [
            Bundle.main.url(forResource: "catalog", withExtension: "pub"),
            Bundle.main.resourceURL?
                .appendingPathComponent("MacCrab_MacCrabApp.bundle")
                .appendingPathComponent("catalog.pub"),
            Bundle.main.resourceURL?
                .appendingPathComponent("rave-keys")
                .appendingPathComponent("catalog.pub"),
        ]
        for url in candidates.compactMap({ $0 }) {
            guard let data = try? Data(contentsOf: url), data.count == 32 else { continue }
            if let key = try? Curve25519.Signing.PublicKey(rawRepresentation: data) {
                return key
            }
        }
        throw RaveCatalogError.noCatalogKey
    }

    private func parseCatalog(data: Data) throws -> [RaveCatalogEntry] {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let plugins = json["plugins"] as? [String: [String: Any]] else {
            throw RaveCatalogError.parseFailed(reason: "missing top-level plugins map")
        }
        var entries: [RaveCatalogEntry] = []
        for (id, raw) in plugins {
            guard let current = raw["current_version"] as? String else { continue }
            let metadata = (raw["metadata"] as? [String: Any]) ?? [:]
            entries.append(RaveCatalogEntry(
                id: id,
                currentVersion: current,
                channel: (raw["channel"] as? String) ?? "official",
                trustTier: (raw["trust_tier"] as? String) ?? "unverified",
                signerIdentity: (raw["signer_identity"] as? String) ?? "",
                signerPublicKeySHA256: (raw["signer_public_key_sha256"] as? String)?.lowercased() ?? "",
                status: (raw["status"] as? String) ?? "official",
                category: metadata["category"] as? String,
                tags: (metadata["tags"] as? [String]) ?? [],
                minMaccrabVersion: metadata["min_maccrab_version"] as? String
            ))
        }
        return entries.sorted { $0.id < $1.id }
    }
}
