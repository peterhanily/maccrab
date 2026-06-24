// RaveCatalogEntryState — S4-X2 pure view-model for the in-dashboard catalog
// browser. Computes, for one signature-verified catalog index entry, the trust
// state the UI shows AND whether the dashboard may offer a live "Install" pill.
//
// The whole point of this type is that it is PURE (no SwiftUI, no network, no
// trust-state side effects) so the install-gating policy is unit-testable
// against the same fields the verified install path keys off:
//
//   - Signer pin  (signer_public_key_sha256) — the O1b publisher-key pin.
//   - Version floor — RaveCatalogClient.checkVersionFloor (shared policy).
//   - Revocation  — RaveRevocationList.entriesRevoking (id + version).
//   - Maturity    — status ("pre-release" vs official).
//
// Honesty model (storefront-honesty, S4-X2):
//   * The dashboard NEVER fakes an install. A live "Install" pill only appears
//     for an entry whose signed binary actually exists — which we read from the
//     same fail-closed signer-pin rule the verified install path enforces:
//     an official-channel entry with NO publisher-key pin is pre-ceremony
//     (the real operator-signed binary hasn't been cut yet), so its artifact
//     hash is still a placeholder. For those we show status, not a pill.
//   * When a live pill IS shown, the Install action drives the SAME verified
//     path the maccrab://install handler uses (RaveInstallConsentSheet →
//     RaveInstallConsentResolver → checkVersionFloor → consent-gated
//     `maccrabctl plugin install <id>` hand-off). No install path bypasses
//     verification; this type only decides whether to OFFER the pill.

import Foundation
import MacCrabForensics

/// Resolved install state for one catalog entry, computed from the index entry
/// + (optionally) the verified revocation list. Pure value type.
public struct RaveCatalogEntryState: Equatable, Sendable {

    /// Why a live Install pill is or isn't offered. Drives both the pill's
    /// enabled state and the explanatory caption.
    public enum Installability: Equatable, Sendable {
        /// Live pill — the entry has a real operator-signed binary (pinned
        /// publisher key) and the version floor passes.
        case installable
        /// No pill — the entry is pre-ceremony: official channel, no
        /// publisher-key pin, so the signed binary / artifact hash is still a
        /// placeholder. Shows "operator-signed binary required".
        case awaitingSignedBinary
        /// No pill — a pre-release / coming-soon entry. Shows its status, not
        /// a live Install pill (storefront honesty).
        case preRelease
        /// No pill — the running build doesn't meet the entry's version floor,
        /// or the floor is malformed. Carries the fail-closed reason.
        case versionFloorBlocked(reason: String)
        /// No pill — the entry is revoked by the signed revocation list.
        case revoked(reason: String)
        /// No pill — a non-first-party entry claims the reserved com.maccrab.*
        /// namespace (first-party impersonation). Never offered. (C-F)
        case impersonation(reason: String)
        /// No pill — a first-party built-in scanner that ships inside
        /// MacCrab.app. Already present; the live action is "Run on this Mac",
        /// never Install. (Synthesized for display; never enters compute().)
        case builtInLocal
    }

    public let entry: RaveCatalogEntry
    public let installability: Installability
    /// True iff a revocation entry covers this id + current version.
    public let isRevoked: Bool
    public let revocationReason: String?

    public init(
        entry: RaveCatalogEntry,
        installability: Installability,
        isRevoked: Bool,
        revocationReason: String?
    ) {
        self.entry = entry
        self.installability = installability
        self.isRevoked = isRevoked
        self.revocationReason = revocationReason
    }

    /// Whether the dashboard should render a live, clickable Install pill.
    public var showsInstallPill: Bool {
        if case .installable = installability { return true }
        return false
    }

    /// True iff the publisher-key pin is present (O1b). Surfaced as a badge.
    public var isSignerPinned: Bool {
        RaveSignerPin.isSHA256Hex(entry.signerPublicKeySHA256)
    }

    /// Short caption shown under a non-installable entry explaining why there's
    /// no live Install pill (operator-signed binary required / pre-release /
    /// floor / revoked). nil when installable.
    public var disabledReason: String? {
        switch installability {
        case .installable:
            return nil
        case .awaitingSignedBinary:
            return "Operator-signed binary required — this entry has no published signed release."
        case .preRelease:
            return "Pre-release — not available for one-click install."
        case .versionFloorBlocked(let reason):
            return reason
        case .revoked(let reason):
            return "Revoked: \(reason)"
        case .impersonation(let reason):
            return reason
        case .builtInLocal:
            return "Built-in scanner — already on this Mac. Use Run on this Mac."
        }
    }

    // MARK: - Compute

    /// Compute the install state for one entry. PURE — uses only the supplied
    /// catalog index fields, the shared version-floor policy (via `floorCheck`),
    /// and the optional verified revocation list.
    ///
    /// `floorCheck` is injected (not called on a network actor) so this stays
    /// synchronous + testable; production passes
    /// `RaveCatalogClient.checkVersionFloor`. It throws a `RaveCatalogError`
    /// describing the refusal when the floor blocks install.
    ///
    /// Precedence (first match wins): revoked → floor-blocked → pre-release →
    /// awaiting-signed-binary (no pin on official) → installable. Revocation is
    /// checked first because a revoked plugin must never look installable even
    /// if every other gate passes.
    public static func compute(
        entry: RaveCatalogEntry,
        revocations: RaveRevocationList?,
        firstPartyDisplayNames: [String] = [],
        floorCheck: (RaveCatalogEntry) throws -> Void
    ) -> RaveCatalogEntryState {
        // 0. Namespace impersonation (C-F) — a non-first-party entry must never
        //    claim the reserved com.maccrab.* id space, NOR wear a display name
        //    confusably close to a first-party one. Refuse before anything else.
        //    The caller passes the curated set of first-party display names from
        //    the verified catalog so the confusable check has something to match;
        //    an empty set degrades to the reserved-namespace check only.
        switch RaveNamespaceGuard.evaluate(
            id: entry.id,
            displayName: entry.displayName,
            isFirstParty: entry.trustTier == "first-party",
            firstPartyDisplayNames: firstPartyDisplayNames
        ) {
        case .reservedNamespaceImpersonation:
            return RaveCatalogEntryState(
                entry: entry,
                installability: .impersonation(reason: "Reserved namespace 'com.maccrab.*' used by a non-first-party publisher — refused to prevent first-party impersonation."),
                isRevoked: false,
                revocationReason: nil
            )
        case .confusableDisplayName(_, let matchesFirstParty):
            return RaveCatalogEntryState(
                entry: entry,
                installability: .impersonation(reason: "Display name is confusably close to the first-party plugin “\(matchesFirstParty)” — refused to prevent impersonation."),
                isRevoked: false,
                revocationReason: nil
            )
        case .ok:
            break
        }

        // 1. Revocation (highest precedence — never offer a revoked plugin).
        if let list = revocations {
            let hits = list.entriesRevoking(pluginID: entry.id, version: entry.currentVersion)
            if let first = hits.first {
                return RaveCatalogEntryState(
                    entry: entry,
                    installability: .revoked(reason: first.reason),
                    isRevoked: true,
                    revocationReason: first.reason
                )
            }
        }

        // 2. Version floor (fail-closed; reason surfaced for display).
        do {
            try floorCheck(entry)
        } catch let e as RaveCatalogError {
            return RaveCatalogEntryState(
                entry: entry,
                installability: .versionFloorBlocked(reason: e.description),
                isRevoked: false,
                revocationReason: nil
            )
        } catch {
            return RaveCatalogEntryState(
                entry: entry,
                installability: .versionFloorBlocked(reason: "\(error)"),
                isRevoked: false,
                revocationReason: nil
            )
        }

        // 3. Pre-release maturity — show status, not a live pill.
        if entry.status == "pre-release" {
            return RaveCatalogEntryState(
                entry: entry,
                installability: .preRelease,
                isRevoked: false,
                revocationReason: nil
            )
        }

        // 4. Signer pin. An official-channel entry with no publisher-key pin is
        //    pre-ceremony — its artifact hash is still a placeholder, so there
        //    is no real signed binary to install. This mirrors the fail-closed
        //    rule the verified install path (RaveSignerPin.enforce) uses.
        if !RaveSignerPin.isSHA256Hex(entry.signerPublicKeySHA256) {
            return RaveCatalogEntryState(
                entry: entry,
                installability: .awaitingSignedBinary,
                isRevoked: false,
                revocationReason: nil
            )
        }

        // 5. Installable — real signed binary + floor passes.
        return RaveCatalogEntryState(
            entry: entry,
            installability: .installable,
            isRevoked: false,
            revocationReason: nil
        )
    }
}
