// TierBRegistry — discovers installed Tier B plugin bundles via
// PluginInstaller, verifies each bundle's signature against the
// current trust + revocation lists, and exposes a `runCollect`
// surface the daemon/CLI use to spawn an installed Tier B
// plugin without the operator hand-passing a binary path.
//
// Distinct from PluginRegistry (which is Tier A only). Tier B
// runs out-of-process under a sandbox profile; its registry sees
// only verified installed bundles, not source-tree research
// binaries.
//
// Plan §3.6 + §3.9 + §12.

import Foundation

public actor TierBRegistry {

    public enum RegistryError: Error, CustomStringConvertible {
        case notInstalled(pluginID: String)
        case manifestUnreadable(pluginID: String, message: String)
        case verificationFailed(pluginID: String, reason: String)
        case binaryNotExecutable(pluginID: String, path: String)

        public var description: String {
            switch self {
            case .notInstalled(let id): return "TierBRegistry: not installed: \(id)"
            case .manifestUnreadable(let id, let m): return "TierBRegistry: manifest unreadable for \(id): \(m)"
            case .verificationFailed(let id, let r): return "TierBRegistry: verification failed for \(id): \(r)"
            case .binaryNotExecutable(let id, let p): return "TierBRegistry: binary not executable for \(id) at \(p)"
            }
        }
    }

    public struct VerifiedPlugin: Sendable {
        public let pluginID: String
        public let manifest: TierBManifest
        public let bundleRoot: String
        public let binaryPath: String
        public let publicKeyHex: String
    }

    public struct VerifyAllReport: Sendable {
        public let total: Int
        public let verified: [VerifiedPlugin]
        public let failed: [(pluginID: String, reason: String)]
    }

    private let installer: PluginInstaller

    public init(installer: PluginInstaller? = nil) {
        self.installer = installer ?? PluginInstaller()
    }

    /// Discover + verify a single installed plugin. The plugin's
    /// publisher key must be in the trust list AND not in the
    /// revocation list. Manifest is loaded + parsed.
    public func resolve(pluginID: String) async throws -> VerifiedPlugin {
        let installed = try await installer.list()
        guard let entry = installed.first(where: { $0.pluginID == pluginID }) else {
            throw RegistryError.notInstalled(pluginID: pluginID)
        }
        let trusted = await installer.currentTrustedKeys()
        let revoked = await installer.currentRevokedKeys()
        let trustStore = PluginSignatureVerifier.TrustStore(
            allowedKeyHexes: trusted,
            revokedKeyHexes: revoked
        )
        let bundleURL = URL(fileURLWithPath: entry.installRoot)
        do {
            _ = try PluginSignatureVerifier.verify(
                bundle: PluginSignatureVerifier.BundleLayout(bundleRoot: bundleURL),
                trustStore: trustStore
            )
        } catch {
            throw RegistryError.verificationFailed(
                pluginID: pluginID,
                reason: "\(error)"
            )
        }
        let manifest: TierBManifest
        do {
            manifest = try TierBManifest.load(fromBundlePath: entry.installRoot)
        } catch {
            throw RegistryError.manifestUnreadable(
                pluginID: pluginID,
                message: error.localizedDescription
            )
        }
        let binaryPath = bundleURL.appendingPathComponent("binary").path
        guard FileManager.default.isExecutableFile(atPath: binaryPath) else {
            throw RegistryError.binaryNotExecutable(
                pluginID: pluginID,
                path: binaryPath
            )
        }
        return VerifiedPlugin(
            pluginID: pluginID,
            manifest: manifest,
            bundleRoot: entry.installRoot,
            binaryPath: binaryPath,
            publicKeyHex: entry.publicKeyHex
        )
    }

    /// Walk all installed plugins + verify each. Caller uses
    /// this to audit the install state before a daemon boot or
    /// before a `maccrabctl plugin verify-all` run.
    public func verifyAll() async -> VerifyAllReport {
        var installed: [InstalledPlugin] = []
        do {
            installed = try await installer.list()
        } catch {
            return VerifyAllReport(total: 0, verified: [], failed: [])
        }
        var verified: [VerifiedPlugin] = []
        var failed: [(pluginID: String, reason: String)] = []
        for entry in installed {
            do {
                let v = try await resolve(pluginID: entry.pluginID)
                verified.append(v)
            } catch {
                failed.append((entry.pluginID, "\(error)"))
            }
        }
        return VerifyAllReport(
            total: installed.count,
            verified: verified,
            failed: failed
        )
    }

    /// Run a verified installed Tier B plugin against a case.
    /// Spawns under the manifest's sandbox profile. The daemon
    /// commits returned artifacts to the supplied ArtifactStore.
    public func runCollectAndCommit(
        pluginID: String,
        caseID: String,
        caseName: String,
        encryptionState: CaseEncryptionState,
        store: ArtifactStore,
        tickCount: Int = 1,
        probeRead: String? = nil
    ) async throws -> (committed: Int, rejected: Int, plugin: VerifiedPlugin) {
        let plugin = try await resolve(pluginID: pluginID)
        let loader = TierBSubprocessLoader()
        let (committed, rejected, _) = try await loader.runCollectAndCommit(
            binaryPath: plugin.binaryPath,
            pluginID: plugin.pluginID,
            pluginVersion: plugin.manifest.version,
            schemaVersion: plugin.manifest.schemaVersion,
            caseID: caseID,
            caseName: caseName,
            encryptionState: encryptionState,
            store: store,
            tickCount: tickCount,
            probeRead: probeRead,
            sandboxProfile: plugin.manifest.toSandboxProfileSpec()
        )
        return (committed, rejected, plugin)
    }
}
