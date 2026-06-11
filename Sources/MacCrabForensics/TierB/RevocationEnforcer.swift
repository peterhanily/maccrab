// RevocationEnforcer — pure decision layer that intersects a verified
// rave revocation list (RaveRevocationList) into:
//
//   (1) INSTALL-TIME trust: should an install of <plugin-id>@<version> be
//       refused because the signed list revokes it? (single_version /
//       version_range / all_versions scopes honored.)
//
//   (2) RUNTIME quarantine: which already-installed plugins have become
//       revoked and must be quarantined — marked, surfaced, and refused
//       load — WITHOUT being deleted (evidence preservation, per
//       PLATFORM-VISION).
//
// This type holds no state and does no I/O: it maps (list, installed set) →
// decisions so the whole policy is unit-testable. The catalog clients own
// fetch + Ed25519-verify + anti-rollback; PluginInstaller owns the
// quarantine.json persistence; TierBRegistry consults isQuarantined() at
// load. The remote signed list AUGMENTS the operator's local key-hex
// revoked-keys.json — it never replaces it.

import Foundation

public enum RevocationEnforcer {

    /// An installed plugin as seen on disk: its id + the version its manifest
    /// declares. (Version is what revocation scopes match against.)
    public struct InstalledRef: Sendable, Equatable {
        public let pluginID: String
        public let version: String
        public init(pluginID: String, version: String) {
            self.pluginID = pluginID
            self.version = version
        }
    }

    // MARK: - Install-time

    /// Decision for installing `pluginID`@`version` against `list`.
    public enum InstallDecision: Sendable, Equatable {
        /// No matching revocation — install may proceed (subject to the rest
        /// of the trust floor: signer pin, signature, local revoked-keys).
        case allowed
        /// A matching revocation refuses the install. Carries the entry so the
        /// caller can show the reason/code/advisory.
        case refused(RaveRevocation)
    }

    /// Should an install of `pluginID`@`version` be refused by the signed
    /// revocation list? Returns the FIRST matching revocation (a list may
    /// carry several scopes for one id; any match refuses).
    public static func evaluateInstall(
        pluginID: String,
        version: String,
        against list: RaveRevocationList
    ) -> InstallDecision {
        if let hit = list.revocations.first(where: { $0.revokes(pluginID: pluginID, version: version) }) {
            return .refused(hit)
        }
        return .allowed
    }

    // MARK: - Runtime quarantine

    /// Given the currently-installed plugins and a verified revocation list,
    /// produce the quarantine records for every installed plugin the list now
    /// revokes. The returned set is AUTHORITATIVE for reconciliation: an
    /// installed plugin NOT in the result is (re-)allowed — so a version that
    /// has escaped a `version_range`, or an id no longer in the list, is
    /// un-quarantined. Pure: the caller persists via
    /// PluginInstaller.applyQuarantine.
    public static func reconcileQuarantine(
        installed: [InstalledRef],
        against list: RaveRevocationList,
        now: Date = Date()
    ) -> [PluginInstaller.QuarantineRecord] {
        let iso = ISO8601DateFormatter()
        let stamp = iso.string(from: now)
        var out: [PluginInstaller.QuarantineRecord] = []
        for ref in installed {
            // First matching revocation wins for the operator-facing reason.
            guard let hit = list.revocations.first(where: {
                $0.revokes(pluginID: ref.pluginID, version: ref.version)
            }) else {
                continue
            }
            out.append(PluginInstaller.QuarantineRecord(
                pluginID: ref.pluginID,
                installedVersion: ref.version,
                reason: hit.reason,
                code: hit.code,
                advisoryURL: hit.advisoryURL,
                revocationsSerial: list.serial,
                quarantinedAt: stamp
            ))
        }
        return out
    }
}
