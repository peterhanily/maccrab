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
    }

    public struct FailedSummary: Sendable {
        public let pluginID: String
        public let reason: String
    }

    public struct Status: Sendable {
        public let pluginsRoot: String
        public let verifiedAt: Date
        public let trustedKeyCount: Int
        public let revokedKeyCount: Int
        public let verified: [VerifiedSummary]
        public let failed: [FailedSummary]

        public var allVerified: Bool { failed.isEmpty }
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
        let verified = report.verified.map { p in
            VerifiedSummary(
                pluginID: p.pluginID,
                version: p.manifest.version,
                bundleRoot: p.bundleRoot,
                publicKeyHex: p.publicKeyHex
            )
        }
        // After resolving, registry stamps temp binaries on disk.
        // Discard them; they were transient verification copies.
        for p in report.verified {
            registry.cleanupVerifiedBinary(p)
        }
        let failed = report.failed.map { f in
            FailedSummary(pluginID: f.pluginID, reason: f.reason)
        }
        let s = Status(
            pluginsRoot: installer.pluginsRootPath,
            verifiedAt: Date(),
            trustedKeyCount: trusted.count,
            revokedKeyCount: revoked.count,
            verified: verified,
            failed: failed
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
