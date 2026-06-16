// RaveInstallConsent — O3c (S2-07) consent gate for `maccrab://install/...`
// deep links. The OS hands us a link carrying ONLY an id (RaveInstallLink); we
// resolve EVERYTHING else (signer hash, trust tier, version floor, current
// version) from the PINNED, signature-verified catalog, then present a consent
// sheet. No scheme-handoff install is ever silent — the operator must read the
// resolved facts and explicitly confirm.
//
// The model deliberately does NOT perform a silent in-process binary install
// on confirm: the dashboard's verified install path runs through the same
// PluginCatalogFetcher the CLI uses (signer pin + version floor + receipt). The
// confirm action hands the operator that verified path. What this gate
// guarantees is the part that matters for the scheme handler: the link cannot
// smuggle install parameters, and nothing happens without resolve-from-catalog
// + explicit confirm.

import Foundation
import MacCrabForensics

/// The facts the consent sheet shows, resolved from the verified catalog.
public struct RaveInstallConsentFacts: Equatable, Sendable {
    public let kind: RaveInstallLink.Kind
    public let id: String
    public let displayName: String
    public let resolvedVersion: String
    /// sha256 hex of the publisher's signing key, as endorsed by the catalog
    /// (the O1b pin). Empty when the catalog entry omits it.
    public let signerPublicKeySHA256: String
    public let signerIdentity: String
    public let trustTier: String
    public let declaredMinVersion: String?
    /// nil = floor passed; non-nil = the fail-closed refusal reason.
    public let versionFloorRefusal: String?
    /// True iff the catalog source is the official production one.
    public let officialSource: Bool
    /// C-B: first-party means the maccrab-maintainer-reviewed-and-signed tier
    /// served from the OFFICIAL catalog. Anything else — a community/unverified
    /// trust tier, or any unofficial source — extends trust to a publisher
    /// MacCrab did not author, and requires explicit operator acknowledgement.
    public let isFirstParty: Bool
    /// C-E: freshness of the client's revocation data at consent time. When
    /// stale/never, "not revoked" may be out of date and the sheet warns.
    public let revocationFreshness: RaveRevocationFreshness
    /// Mirrors the catalog browser's install gating (storefront honesty, S4-X2):
    /// true only when the entry has a real operator-signed binary, passes the
    /// version floor, is not pre-release, and is not a namespace/confusable
    /// impersonation. The maccrab://install consent path must NOT offer Confirm
    /// (or a "reviewed & signed" affirmation) otherwise.
    public let isInstallable: Bool
    /// Why the entry is not installable (operator-signed binary required /
    /// pre-release / version floor / impersonation), or nil when installable.
    public let installBlockReason: String?

    public init(
        kind: RaveInstallLink.Kind,
        id: String,
        displayName: String,
        resolvedVersion: String,
        signerPublicKeySHA256: String,
        signerIdentity: String,
        trustTier: String,
        declaredMinVersion: String?,
        versionFloorRefusal: String?,
        officialSource: Bool,
        isFirstParty: Bool,
        revocationFreshness: RaveRevocationFreshness,
        isInstallable: Bool,
        installBlockReason: String?
    ) {
        self.kind = kind
        self.id = id
        self.displayName = displayName
        self.resolvedVersion = resolvedVersion
        self.signerPublicKeySHA256 = signerPublicKeySHA256
        self.signerIdentity = signerIdentity
        self.trustTier = trustTier
        self.declaredMinVersion = declaredMinVersion
        self.versionFloorRefusal = versionFloorRefusal
        self.officialSource = officialSource
        self.isFirstParty = isFirstParty
        self.revocationFreshness = revocationFreshness
        self.isInstallable = isInstallable
        self.installBlockReason = installBlockReason
    }

    /// The operator may only confirm an install when the entry is actually
    /// installable — a real operator-signed binary, floor passes, not
    /// pre-release, not an impersonation (the SAME gate the catalog browser
    /// applies). `isInstallable` already encodes the version-floor result.
    /// (C-B's third-party acknowledgement is an additional UI-state gate layered
    /// on top of this in the sheet, not a property of the resolved facts.)
    public var canConfirm: Bool { isInstallable }

    /// C-B: a non-first-party (or unofficial-source) plugin requires the
    /// operator to explicitly acknowledge the elevated trust before confirming.
    public var requiresThirdPartyConsent: Bool { !isFirstParty }

    /// C-E: human-facing staleness warning, or nil when revocation data is fresh.
    public var revocationStalenessWarning: String? {
        switch revocationFreshness {
        case .fresh:
            return nil
        case .never:
            return "MacCrab hasn't verified a revocation list yet, so it can't confirm this plugin wasn't revoked. Connect to refresh before installing."
        case .stale(let age):
            let days = Int((age / 86400).rounded())
            return "Revocation data is ~\(days) day\(days == 1 ? "" : "s") old — a recently-revoked plugin could still look installable. Refresh before installing."
        }
    }

    /// The verified install command the confirm action surfaces. Resolved id
    /// only — never anything from the link.
    public var verifiedInstallCommand: String {
        switch kind {
        case .plugin: return "maccrabctl plugin install \(id)"
        case .kit:    return "maccrabctl plugin install \(id)"
        }
    }
}

public enum RaveInstallConsentError: Error, CustomStringConvertible {
    case notInCatalog(id: String)
    case catalog(String)

    public var description: String {
        switch self {
        case .notInCatalog(let id):
            return "\(id) is not in the signed catalog. Refusing to install from a deep link for an id the pinned catalog doesn't list."
        case .catalog(let m):
            return "Could not load the signed catalog: \(m)"
        }
    }
}

/// Resolves a parsed install link into consent facts by fetching + verifying
/// the catalog. Pure-ish: all trust state lives in the injected client.
public struct RaveInstallConsentResolver: Sendable {
    private let client: RaveCatalogClient

    public init(client: RaveCatalogClient = RaveCatalogClient()) {
        self.client = client
    }

    /// Fetch + verify the catalog, locate the link's id, and compute the
    /// consent facts (including the version-floor result). Throws when the id
    /// isn't in the verified catalog or the catalog can't be loaded/verified.
    public func resolve(_ link: RaveInstallLink) async throws -> RaveInstallConsentFacts {
        let entries: [RaveCatalogEntry]
        do {
            entries = try await client.fetchEntries()
        } catch {
            throw RaveInstallConsentError.catalog("\(error)")
        }
        guard let entry = entries.first(where: { $0.id == link.id }) else {
            throw RaveInstallConsentError.notInCatalog(id: link.id)
        }

        // Evaluate the version floor (shared policy). Capture the refusal
        // reason for display rather than throwing — the sheet shows WHY the
        // confirm button is disabled.
        var floorRefusal: String? = nil
        do {
            try client.checkVersionFloor(entry: entry)
        } catch let e as RaveCatalogError {
            floorRefusal = e.description
        }

        let official = await client.isUsingOfficialSource
        // C-B: first-party trust requires BOTH the first-party tier AND the
        // official catalog source — a first-party tier served from an unofficial
        // mirror does not earn the default-trusted posture.
        let isFirstParty = (entry.trustTier == "first-party") && official

        // C-E: refresh revocations if our local copy is stale (best-effort — a
        // failed refresh while offline keeps the prior state), then read the
        // freshness so the sheet can warn that "not revoked" may be out of date.
        _ = try? await client.refreshRevocationsIfStale()
        let freshness = await client.revocationFreshness()

        // Mirror the catalog browser's install gating (storefront honesty): the
        // deep-link path must NOT offer Confirm or a "reviewed & signed"
        // affirmation for a pre-release / awaiting-signed-binary / floor-blocked
        // / impersonating entry. Reuse the SAME pure policy the browser uses —
        // RaveCatalogEntryState.compute — which also applies the C-F
        // namespace/confusable guard the deep-link path previously skipped.
        // (Revocation stays enforced fail-closed downstream by the CLI install
        // path; the consent sheet keys honesty off availability + impersonation.)
        let firstPartyNames = entries
            .filter { $0.trustTier == "first-party" }
            .map { $0.displayName }
        let state = RaveCatalogEntryState.compute(
            entry: entry,
            revocations: nil,
            firstPartyDisplayNames: firstPartyNames,
            floorCheck: client.checkVersionFloor
        )

        return RaveInstallConsentFacts(
            kind: link.kind,
            id: entry.id,
            displayName: entry.displayName,
            resolvedVersion: entry.currentVersion,
            signerPublicKeySHA256: entry.signerPublicKeySHA256,
            signerIdentity: entry.signerIdentity,
            trustTier: entry.trustTier,
            declaredMinVersion: entry.minMaccrabVersion,
            versionFloorRefusal: floorRefusal,
            officialSource: official,
            isFirstParty: isFirstParty,
            revocationFreshness: freshness,
            isInstallable: state.showsInstallPill,
            installBlockReason: state.disabledReason
        )
    }
}
