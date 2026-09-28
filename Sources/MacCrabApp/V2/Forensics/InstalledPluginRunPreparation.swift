import Foundation
import MacCrabForensics

/// Resolve privacy and source-selection disclosure from the signature-verified
/// installed bundle, independently of the asynchronously loaded inventory cache.
/// Execution still performs its own verification and execution-lane checks.
struct InstalledPluginRunPreparation {
    struct Intent: Equatable {
        let requestID = UUID()
        let pluginID: String
        let catalogPluginID: String?

        func isCurrent(active: Intent?, pendingCatalogPluginID: String?, cancelled: Bool) -> Bool {
            !cancelled && active == self
                && (catalogPluginID == nil || catalogPluginID == pendingCatalogPluginID)
        }
    }

    let manifest: TierBManifest
    let publicKeyHex: String

    var kit: Kit {
        let consent = manifest.consentSummary()
        // An author may declare sensitive output even without a file-read
        // capability. Neither that declaration nor enforced reads may downgrade.
        let encrypted = consent.derivedHighestPrivacy != "metadata"
            || (manifest.privacyClass.map { $0.lowercased() != "metadata" } ?? false)
        return .adHoc(pluginID: manifest.id, name: manifest.displayName, encrypted: encrypted)
    }

    func detail(provenance: PluginProvenance, installedLabel: String) -> PluginDetailModel {
        .thirdParty(pluginID: manifest.id, publicKeyHex: publicKeyHex,
                    manifest: manifest, provenance: provenance, installedLabel: installedLabel)
    }

    static func resolve(pluginID: String, registry: TierBRegistry = TierBRegistry()) async throws -> Self {
        let verified = try await registry.resolve(pluginID: pluginID)
        defer { registry.cleanupVerifiedBinary(verified) }
        guard verified.manifest.id == pluginID else {
            throw TierBRegistry.RegistryError.verificationFailed(pluginID: pluginID, reason: "installed manifest identity mismatch")
        }
        guard verified.manifest.kind != .analyzer else {
            throw TierBCollectorExecutorError.analyzerNotSupported(pluginID: pluginID)
        }
        return Self(manifest: verified.manifest, publicKeyHex: verified.publicKeyHex)
    }
}
