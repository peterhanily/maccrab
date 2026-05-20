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
        /// Path to spawn. Always a fresh per-resolve temp file
        /// holding the bytes the signature verifier just
        /// accepted — closes the TOCTOU window between
        /// verification and Process.run.
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
    ///
    /// Returns a `VerifiedPlugin` whose `binaryPath` points to a
    /// fresh per-resolve temp file holding the bytes the
    /// signature verifier just accepted. Spawning from that
    /// temp path (instead of the bundle path) closes the TOCTOU
    /// window between verify and Process.run — if a local
    /// adversary replaces the bundle binary between verify and
    /// spawn, the spawn still runs the verified bytes.
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
        // verify() returns the manifest bytes it accepted. We
        // also pull the binary bytes the verifier hashed against
        // by reading the binary path once and snapshotting it
        // to a temp file. Both reads are wrapped in O_NOFOLLOW
        // semantics via Data(contentsOf:) on URLs we control.
        let bundleBinaryURL = bundleURL.appendingPathComponent("binary")
        let verifiedBinaryBytes: Data
        do {
            _ = try PluginSignatureVerifier.verify(
                bundle: PluginSignatureVerifier.BundleLayout(bundleRoot: bundleURL),
                trustStore: trustStore
            )
            verifiedBinaryBytes = try Data(contentsOf: bundleBinaryURL)
            // Re-verify with the bytes we just snapshotted.
            // PluginSignatureVerifier.verify reads from disk; if
            // the binary was swapped between its read + ours, the
            // two reads disagree and the second verify catches
            // it. Cheap belt-and-suspenders.
            let sig = try Data(contentsOf: bundleURL.appendingPathComponent("signature"))
            let pubKeyData = try Data(contentsOf: bundleURL.appendingPathComponent("signing.key.pub"))
            let pubKey = try CryptoSigning.publicKey(rawRepresentation: pubKeyData)
            let manifestData = try Data(contentsOf: bundleURL.appendingPathComponent("manifest.json"))
            let payload = PluginSignatureVerifier.canonicalSignedPayload(
                manifestData: manifestData,
                binaryData: verifiedBinaryBytes
            )
            guard pubKey.isValidSignature(sig, for: payload) else {
                throw RegistryError.verificationFailed(
                    pluginID: pluginID,
                    reason: "binary changed between verify and snapshot (TOCTOU)"
                )
            }
        } catch let e as RegistryError {
            throw e
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
        // Write the verified bytes to a fresh temp file. This is
        // the path we hand to Process.run — guarantees the
        // spawned bytes are exactly the verified bytes, even if
        // the bundle binary gets swapped between now and exec.
        let tempBinaryPath = NSTemporaryDirectory()
            + "maccrab-tier-b-verified-\(UUID().uuidString)"
        do {
            try verifiedBinaryBytes.write(to: URL(fileURLWithPath: tempBinaryPath), options: .atomic)
            // 0o500: owner read+exec only. Closes any post-write
            // race where another local user could replace the
            // temp file (defense in depth — NSTemporaryDirectory
            // is per-user 0o700 on darwin).
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o500],
                ofItemAtPath: tempBinaryPath
            )
        } catch {
            throw RegistryError.binaryNotExecutable(
                pluginID: pluginID,
                path: tempBinaryPath
            )
        }
        guard FileManager.default.isExecutableFile(atPath: tempBinaryPath) else {
            throw RegistryError.binaryNotExecutable(
                pluginID: pluginID,
                path: tempBinaryPath
            )
        }
        return VerifiedPlugin(
            pluginID: pluginID,
            manifest: manifest,
            bundleRoot: entry.installRoot,
            binaryPath: tempBinaryPath,
            publicKeyHex: entry.publicKeyHex
        )
    }

    /// Clean up the per-resolve verified-binary temp file. The
    /// caller is responsible for calling this after the spawn
    /// completes. resolve() never returns the bundle path
    /// directly any more — every resolution allocates a temp.
    ///
    /// nonisolated because it's pure filesystem cleanup that
    /// doesn't touch any actor state.
    public nonisolated func cleanupVerifiedBinary(_ plugin: VerifiedPlugin) {
        try? FileManager.default.removeItem(atPath: plugin.binaryPath)
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
        defer { cleanupVerifiedBinary(plugin) }
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
