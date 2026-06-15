// TierBBootstrap — verify every installed Tier B plugin at
// process start and surface the result. Caches the verified set
// so subsequent runs in the same process don't re-verify (the
// verification is cheap but the file I/O is real).
//
// Plan §3.6 + §3.9 + §12. Lifts Tier B from "operator must
// remember to type `run-installed`" to a daemon citizen the
// system can rely on without per-call ceremony.
//
// Used by:
//   - maccrabctl plugin daemon-status (one-shot CLI surface)
//   - maccrabctl plugin run-all-installed (auto-discovers the
//     verified set before iterating)
//   - future forensics-daemon mode (out of scope this RC).

import Foundation
import os.log

public actor TierBBootstrap {

    public struct VerifiedSummary: Sendable {
        public let pluginID: String
        public let version: String
        public let bundleRoot: String
        public let publicKeyHex: String
        /// v1.19.0: where this installed plugin came from — `.store` (has a
        /// signed rave-catalog receipt) or `.thirdParty` (operator-trusted
        /// sideload). Built-in (Tier A) plugins are `.builtIn` elsewhere.
        public let provenance: PluginProvenance
    }

    public struct FailedSummary: Sendable {
        public let pluginID: String
        public let reason: String
    }

    /// An installed plugin quarantined by the signed rave revocation list
    /// (O2). On disk but refused load; surfaced so the operator sees WHY.
    public struct QuarantinedSummary: Sendable {
        public let pluginID: String
        public let installedVersion: String
        public let reason: String
        public let code: String
        public let advisoryURL: String?
        public let revocationsSerial: Int?
        public let quarantinedAt: String
    }

    public struct Status: Sendable {
        public let pluginsRoot: String
        public let verifiedAt: Date
        public let trustedKeyCount: Int
        public let revokedKeyCount: Int
        public let verified: [VerifiedSummary]
        public let failed: [FailedSummary]
        /// Plugins quarantined by a signed revocation (O2). Read offline from
        /// the persisted quarantine.json; populated by the catalog clients'
        /// revocation reconciliation, not by this bootstrap.
        public let quarantined: [QuarantinedSummary]

        public var allVerified: Bool { failed.isEmpty }

        public init(
            pluginsRoot: String,
            verifiedAt: Date,
            trustedKeyCount: Int,
            revokedKeyCount: Int,
            verified: [VerifiedSummary],
            failed: [FailedSummary],
            quarantined: [QuarantinedSummary]
        ) {
            self.pluginsRoot = pluginsRoot
            self.verifiedAt = verifiedAt
            self.trustedKeyCount = trustedKeyCount
            self.revokedKeyCount = revokedKeyCount
            self.verified = verified
            self.failed = failed
            self.quarantined = quarantined
        }
    }

    /// Returns the cached status, refreshing if either:
    ///   - never run before in this process
    ///   - `force` is true
    ///   - the cache is older than `maxAgeSeconds`
    public func status(force: Bool = false, maxAgeSeconds: TimeInterval = 60) async -> Status {
        if !force,
           let cached = cachedStatus,
           Date().timeIntervalSince(cached.verifiedAt) < maxAgeSeconds {
            return cached
        }
        return await refresh()
    }

    /// Force-refresh the bootstrap status by walking pluginsRoot,
    /// running verifyAll, and rebuilding the cache.
    @discardableResult
    public func refresh() async -> Status {
        let installer = self.installer
        let registry = TierBRegistry(installer: installer)
        let report = await registry.verifyAll()
        let trusted = await installer.currentTrustedKeys()
        let revoked = await installer.currentRevokedKeys()
        // Offline read of the persisted O2 quarantine set (populated by the
        // catalog clients' revocation reconciliation). Surfaced separately
        // from `failed` so an operator can tell "revoked" apart from "broke".
        let quarantineMap = await installer.currentQuarantine()
        // Receipts live next to the plugins dir: <supportDir>/plugin_receipts.
        let supportDir = (installer.pluginsRootPath as NSString).deletingLastPathComponent
        let receiptsDir = URL(fileURLWithPath: supportDir).appendingPathComponent("plugin_receipts")
        let verified = report.verified.map { p in
            VerifiedSummary(
                pluginID: p.pluginID,
                version: p.manifest.version,
                bundleRoot: p.bundleRoot,
                publicKeyHex: p.publicKeyHex,
                provenance: PluginProvenance.forInstalled(pluginID: p.pluginID, receiptsDir: receiptsDir)
            )
        }
        // After resolving, registry stamps temp binaries on disk.
        // Discard them; they were transient verification copies.
        for p in report.verified {
            registry.cleanupVerifiedBinary(p)
        }
        // A quarantined plugin fails resolve() (RegistryError.quarantined); pull
        // those out of `failed` into the dedicated `quarantined` bucket so the
        // failed bucket stays "genuinely broken" and quarantine reads cleanly.
        let failed = report.failed
            .filter { quarantineMap[$0.pluginID] == nil }
            .map { FailedSummary(pluginID: $0.pluginID, reason: $0.reason) }
        let quarantined = quarantineMap.values
            .sorted { $0.pluginID < $1.pluginID }
            .map { r in
                QuarantinedSummary(
                    pluginID: r.pluginID,
                    installedVersion: r.installedVersion,
                    reason: r.reason,
                    code: r.code,
                    advisoryURL: r.advisoryURL,
                    revocationsSerial: r.revocationsSerial,
                    quarantinedAt: r.quarantinedAt
                )
            }
        let s = Status(
            pluginsRoot: installer.pluginsRootPath,
            verifiedAt: Date(),
            trustedKeyCount: trusted.count,
            revokedKeyCount: revoked.count,
            verified: verified,
            failed: failed,
            quarantined: quarantined
        )
        cachedStatus = s
        Self.logger.info("TierBBootstrap refresh: \(report.verified.count) verified, \(report.failed.count) failed, plugins_root=\(installer.pluginsRootPath, privacy: .public)")
        return s
    }

    private let installer: PluginInstaller
    private var cachedStatus: Status? = nil
    private static let logger = Logger(subsystem: "com.maccrab.forensics", category: "TierBBootstrap")

    public init(installer: PluginInstaller? = nil) {
        self.installer = installer ?? PluginInstaller()
    }
}
