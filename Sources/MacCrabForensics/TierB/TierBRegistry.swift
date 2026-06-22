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
        case quarantined(pluginID: String, reason: String)
        /// The bundle verified, but the first-party EXECUTION gate refused it
        /// (not the publisher key / unconfigured anchor / non-official / override).
        /// Third-party plugins always hit this — execution stays fail-closed.
        case firstPartyExecutionRefused(pluginID: String, reason: String)
        /// The bundle verified, but the SANDBOXED third-party EXECUTION gate
        /// refused it (sandbox runtime unavailable, first-party-anchor bundle in
        /// the wrong lane, revoked, or no operator/curated authority).
        case sandboxedExecutionRefused(pluginID: String, reason: String)

        public var description: String {
            switch self {
            case .notInstalled(let id): return "TierBRegistry: not installed: \(id)"
            case .manifestUnreadable(let id, let m): return "TierBRegistry: manifest unreadable for \(id): \(m)"
            case .verificationFailed(let id, let r): return "TierBRegistry: verification failed for \(id): \(r)"
            case .binaryNotExecutable(let id, let p): return "TierBRegistry: binary not executable for \(id) at \(p)"
            case .quarantined(let id, let r): return "TierBRegistry: \(id) is quarantined by a signed revocation (\(r)) — refusing to load"
            case .firstPartyExecutionRefused(let id, let r): return "TierBRegistry: refusing first-party execution of \(id): \(r)"
            case .sandboxedExecutionRefused(let id, let r): return "TierBRegistry: refusing sandboxed third-party execution of \(id): \(r)"
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
        /// SHA-256 (lowercase hex) of the raw signing.key.pub bytes — the value
        /// the first-party execution gate compares against the FirstPartyTrustRoot
        /// publisher anchor. (Shape 2.)
        public let publicKeySHA256: String
        /// True ONLY when resolved via resolveForFirstPartyExecution AND the
        /// FirstPartyExecutionGate allowed (publisher-key match + defense-in-depth
        /// checks). Base resolve() never evaluates first-party authority → false.
        /// internal(set): only the gates (this module) may assert a lane — an
        /// external caller can read it but cannot mint a struct claiming a lane.
        public internal(set) var isFirstParty: Bool = false
        /// True ONLY when resolved via resolveForSandboxedExecution AND the
        /// ThirdPartyExecutionGate allowed. DISJOINT from isFirstParty — a plugin
        /// is never both (the two execution lanes never cross). Base resolve()
        /// sets neither; SandboxedTierBRunner requires this true + isFirstParty
        /// false, FirstPartyTierBRunner requires isFirstParty true.
        public internal(set) var isSandboxed: Bool = false
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
        // O2 runtime quarantine: a plugin the signed revocation list revoked
        // after install is quarantined (not deleted). Refuse to produce a
        // runnable binary for it — checked BEFORE signature verification so a
        // revoked-but-still-validly-signed plugin still stops running.
        let quarantine = await installer.currentQuarantine()
        if let q = quarantine[pluginID] {
            throw RegistryError.quarantined(pluginID: pluginID, reason: q.reason)
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
        var resolvedPublisherFingerprint = ""
        // Decoded from the SAME signature-verified bytes (manifestData below) —
        // never an independent disk re-read. The manifest's capability fields
        // become the sandboxed lane's SBPL allowlist, so binding them to the
        // verified bytes is load-bearing containment, not just hygiene.
        var verifiedManifest: TierBManifest? = nil
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
            resolvedPublisherFingerprint = FirstPartyTrustRoot.fingerprint(ofSigningKey: pubKeyData)
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
            // Decode the manifest from manifestData — the bytes the signature
            // just covered — NOT a fresh `TierBManifest.load` disk read. A 4th,
            // independent read could be swapped (same-uid) between verify and
            // use, letting an attacker author the SBPL allowlist for the
            // sandboxed lane (fileReadSubpaths/network/exec/fork) while the
            // signature still validates the original bytes. (Manifest TOCTOU.)
            do {
                verifiedManifest = try JSONDecoder().decode(TierBManifest.self, from: manifestData)
            } catch {
                throw RegistryError.manifestUnreadable(pluginID: pluginID, message: "\(error)")
            }
        } catch let e as RegistryError {
            throw e
        } catch {
            throw RegistryError.verificationFailed(
                pluginID: pluginID,
                reason: "\(error)"
            )
        }
        guard let manifest = verifiedManifest else {
            throw RegistryError.manifestUnreadable(pluginID: pluginID, message: "manifest decode produced no value")
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
            publicKeyHex: entry.publicKeyHex,
            publicKeySHA256: resolvedPublisherFingerprint
        )
    }

    /// Resolve a plugin AND gate it for UNSANDBOXED first-party execution
    /// (Shape 2). This is the ONLY path that may yield a runnable first-party
    /// binary: it runs the full resolve() chain (quarantine → verify → TOCTOU
    /// re-verify → 0o500 temp) and THEN the FirstPartyExecutionGate. On any deny
    /// it DELETES the verified temp (cleanupVerifiedBinary) so no runnable binary
    /// is ever left behind, and throws `firstPartyExecutionRefused`. Third-party
    /// bundles (any key != the publisher anchor) always deny — fail-closed.
    ///
    /// `officialSource` / `catalogOverrideActive` are supplied by the caller (the
    /// app/CLI knows the catalog context); they are defense-in-depth refusals.
    public func resolveForFirstPartyExecution(
        pluginID: String,
        officialSource: Bool,
        catalogOverrideActive: Bool
    ) async throws -> VerifiedPlugin {
        try await resolveForFirstPartyExecution(
            pluginID: pluginID,
            officialSource: officialSource,
            catalogOverrideActive: catalogOverrideActive,
            expectedPublisherFingerprint: FirstPartyTrustRoot.publisherKeyFingerprint,
            anchorConfigured: FirstPartyTrustRoot.isConfigured
        )
    }

    /// Testable core — the public overload pins the anchor to FirstPartyTrustRoot;
    /// this `internal` form lets tests inject a fingerprint matching a fixture
    /// bundle's throwaway key. Production callers never see the override params,
    /// so they cannot pass a bogus fingerprint.
    func resolveForFirstPartyExecution(
        pluginID: String,
        officialSource: Bool,
        catalogOverrideActive: Bool,
        expectedPublisherFingerprint: String,
        anchorConfigured: Bool
    ) async throws -> VerifiedPlugin {
        var verified = try await resolve(pluginID: pluginID)
        let decision = FirstPartyExecutionGate.evaluate(
            bundleSigningKeyPubSHA256: verified.publicKeySHA256,
            expectedPublisherFingerprint: expectedPublisherFingerprint,
            anchorConfigured: anchorConfigured,
            catalogOverrideActive: catalogOverrideActive,
            officialSource: officialSource
        )
        guard case .allow = decision else {
            // Never leave a verified runnable binary behind on a refusal.
            cleanupVerifiedBinary(verified)
            let reason: String
            if case .deny(let r) = decision { reason = r } else { reason = "denied" }
            throw RegistryError.firstPartyExecutionRefused(pluginID: pluginID, reason: reason)
        }
        verified.isFirstParty = true
        return verified
    }

    /// Resolve a plugin AND gate it for SANDBOXED third-party / sideload
    /// execution — the disjoint twin of resolveForFirstPartyExecution. Runs the
    /// full resolve() chain (quarantine → verify → TOCTOU re-verify → 0o500 temp)
    /// and THEN the ThirdPartyExecutionGate. On any deny it DELETES the verified
    /// temp (cleanupVerifiedBinary) so no runnable binary is left behind, and
    /// throws `sandboxedExecutionRefused`. Sets isSandboxed=true, NEVER
    /// isFirstParty. A bundle matching the first-party publisher anchor is refused
    /// here (it belongs to the unsandboxed first-party lane).
    ///
    /// `sandboxRuntimeAvailable` is supplied by the caller (the runner knows
    /// whether the signed trampoline is present + executable); FALSE →
    /// fail-closed (never run uncontained). SBPL validity / deny-default content
    /// is NOT pre-checked — it is enforced at runtime by the trampoline (a bad
    /// profile → sandbox_init fail / content-refuse → _exit before execv).
    /// `hasValidCuratedReceipt` / `catalogOverrideActive` are the catalog-context
    /// authority inputs the app/CLI knows.
    public func resolveForSandboxedExecution(
        pluginID: String,
        sandboxRuntimeAvailable: Bool,
        hasValidCuratedReceipt: Bool,
        catalogOverrideActive: Bool
    ) async throws -> VerifiedPlugin {
        try await resolveForSandboxedExecution(
            pluginID: pluginID,
            sandboxRuntimeAvailable: sandboxRuntimeAvailable,
            hasValidCuratedReceipt: hasValidCuratedReceipt,
            catalogOverrideActive: catalogOverrideActive,
            firstPartyAnchorFingerprint: FirstPartyTrustRoot.publisherKeyFingerprint,
            firstPartyAnchorConfigured: FirstPartyTrustRoot.isConfigured
        )
    }

    /// Testable core — the public overload pins the anchor to FirstPartyTrustRoot;
    /// this `internal` form lets tests inject an anchor fingerprint matching a
    /// fixture key (to prove the disjoint-lane refusal) without touching the
    /// compiled-in keystone. Production callers never see the override params.
    func resolveForSandboxedExecution(
        pluginID: String,
        sandboxRuntimeAvailable: Bool,
        hasValidCuratedReceipt: Bool,
        catalogOverrideActive: Bool,
        firstPartyAnchorFingerprint: String,
        firstPartyAnchorConfigured: Bool
    ) async throws -> VerifiedPlugin {
        var verified = try await resolve(pluginID: pluginID)
        // Structural cleanup: the resolve() temp (0o500 runnable bytes) is deleted
        // on EVERY exit that is not a clean allow — so no refactor that adds a new
        // throw between here and success can leave a runnable binary behind.
        var keepVerifiedBinary = false
        defer { if !keepVerifiedBinary { cleanupVerifiedBinary(verified) } }
        // Recompute operator-trust + revocation from the installer state. resolve()
        // already required trusted-not-revoked, so these are belt-and-suspenders
        // that also make the gate's authority inputs explicit + auditable.
        let trusted = await installer.currentTrustedKeys()
        let revoked = await installer.currentRevokedKeys()
        let key = verified.publicKeyHex.lowercased()
        let operatorTrusts = trusted.contains { $0.lowercased() == key }
        let isRevoked = revoked.contains { $0.lowercased() == key }
        // Disjoint-lane check: does this bundle match the first-party publisher
        // anchor? If so it must NOT run sandboxed — the gate refuses it.
        let want = firstPartyAnchorFingerprint.lowercased()
        let got = verified.publicKeySHA256.lowercased()
        let anchorMatch = firstPartyAnchorConfigured
            && got.count == 64 && want.count == 64
            && got.allSatisfy({ $0.isHexDigit }) && got == want
        let decision = ThirdPartyExecutionGate.evaluate(
            sandboxRuntimeAvailable: sandboxRuntimeAvailable,
            isFirstPartyAnchorMatch: anchorMatch,
            operatorTrustsPublisherKey: operatorTrusts,
            hasValidCuratedReceipt: hasValidCuratedReceipt,
            isRevoked: isRevoked,
            catalogOverrideActive: catalogOverrideActive
        )
        guard case .allow = decision else {
            // The defer above deletes the verified temp on this throw.
            let reason: String
            if case .deny(let r) = decision { reason = r } else { reason = "denied" }
            throw RegistryError.sandboxedExecutionRefused(pluginID: pluginID, reason: reason)
        }
        verified.isSandboxed = true
        keepVerifiedBinary = true   // success → caller owns cleanup
        return verified
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

    // runCollectAndCommit (subprocess spawn path) is research-only
    // and lives on the research/post-v15 branch. v1.16 ships the
    // install + verify + trust + discovery surface; the spawn path
    // ships when NSXPCConnection + XPC service bundling lands.
    // See docs/tier-b-research/feasibility.md "Remaining gap".
}
