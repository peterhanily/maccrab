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
        officialSource: Bool
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
    }

    /// The operator may only confirm an install when the version floor passed.
    public var canConfirm: Bool { versionFloorRefusal == nil }

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
            officialSource: official
        )
    }
}
