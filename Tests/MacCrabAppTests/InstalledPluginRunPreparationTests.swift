import Testing
import Foundation
import CryptoKit
import MacCrabForensics
@testable import MacCrabApp

@Suite("Verified installed-plugin run preparation")
struct InstalledPluginRunPreparationTests {
    @Test func cancelledOrSupersededCatalogPreparationCannotApply() {
        let earlier = InstalledPluginRunPreparation.Intent(pluginID: "first", catalogPluginID: "first")
        let current = InstalledPluginRunPreparation.Intent(pluginID: "second", catalogPluginID: "second")
        #expect(earlier.isCurrent(active: earlier, pendingCatalogPluginID: "first", cancelled: false))
        #expect(!earlier.isCurrent(active: earlier, pendingCatalogPluginID: "first", cancelled: true))
        // A new Catalog selection can arrive before its preparation starts.
        #expect(!earlier.isCurrent(active: earlier, pendingCatalogPluginID: "second", cancelled: false))
        #expect(!earlier.isCurrent(active: current, pendingCatalogPluginID: "second", cancelled: false))
        #expect(current.isCurrent(active: current, pendingCatalogPluginID: "second", cancelled: false))
        // Re-selecting the same plugin does not make an older request current.
        let repeated = InstalledPluginRunPreparation.Intent(pluginID: "second", catalogPluginID: "second")
        #expect(!current.isCurrent(active: repeated, pendingCatalogPluginID: "second", cancelled: false))
    }

    @Test func directDetailsDoNotRequireCatalogIntentAndRespectReplacement() {
        let details = InstalledPluginRunPreparation.Intent(pluginID: "selected", catalogPluginID: nil)
        let later = InstalledPluginRunPreparation.Intent(pluginID: "selected", catalogPluginID: nil)
        #expect(details.isCurrent(active: details, pendingCatalogPluginID: nil, cancelled: false))
        #expect(!details.isCurrent(active: later, pendingCatalogPluginID: nil, cancelled: false))
        #expect(!details.isCurrent(active: nil, pendingCatalogPluginID: nil, cancelled: false))
    }

    private struct Fixture {
        let root: URL
        let staged: URL
        let installer: PluginInstaller
        let registry: TierBRegistry
        let key = Curve25519.Signing.PrivateKey()
        let id = "com.maccrab.forensics.side-door"

        init() throws {
            root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).resolvingSymlinksInPath()
            staged = root.appendingPathComponent("verified")
            try FileManager.default.createDirectory(at: staged, withIntermediateDirectories: true)
            installer = PluginInstaller(pluginsRoot: root.appendingPathComponent("plugins"))
            registry = TierBRegistry(installer: installer, tempDirectory: staged.path)
        }

        func install(reads: [String] = [], privacy: String? = nil, version: String = "0.1.0",
                     kind: TierBPluginKind = .collector, force: Bool = false) async throws -> InstalledPlugin {
            let manifest = TierBManifest(id: id, displayName: "Verified Side Door", version: version,
                schemaVersion: 1, description: "Verified selected-source fixture.", kind: kind,
                fileReadSubpaths: reads, privacyClass: privacy)
            let bytes = try JSONEncoder().encode(manifest)
            // Never execute this fixture. Only admission, trust and preparation
            // are under test; no real sources or app Keychain entries are read.
            let binary = Data("non-executable signed fixture bytes".utf8)
            let signature = try key.signature(for: PluginSignatureVerifier.canonicalSignedPayload(manifestData: bytes, binaryData: binary))
            let bundle = try PluginBundleSnapshot(files: ["manifest.json": bytes, "binary": binary,
                "signature": signature, "signing.key.pub": key.publicKey.rawRepresentation])
            return try await installer.install(snapshot: bundle, trustOnInstall: true, force: force)
        }

        func cleanup() { try? FileManager.default.removeItem(at: root) }
        func assertNoStagedBinary() throws {
            #expect(try FileManager.default.contentsOfDirectory(atPath: staged.path).isEmpty)
        }
    }

    @Test func coldRunAndSelectedSourceDetailsUseVerifiedContentManifest() async throws {
        let fixture = try Fixture(); defer { fixture.cleanup() }
        _ = try await fixture.install(reads: ["/Users"], privacy: "content")
        // No inventory cache has been loaded, as on a first Catalog -> Scans handoff.
        let prepared = try await InstalledPluginRunPreparation.resolve(pluginID: fixture.id, registry: fixture.registry)
        #expect(prepared.kit.encrypted)
        #expect(prepared.kit.name == "Verified Side Door")
        let detail = prepared.detail(provenance: .store, installedLabel: "Installed")
        #expect(detail.version == "0.1.0")
        #expect(detail.reads == ["/Users"])
        #expect(detail.privacyLabel == "Content")
        #expect(SecretTrailScope.Profile(pluginID: detail.id) == .sideDoor)
        try fixture.assertNoStagedBinary()
    }

    @Test func replacementManifestCannotReuseCachedMetadataPrivacy() async throws {
        let fixture = try Fixture(); defer { fixture.cleanup() }
        _ = try await fixture.install()
        let earlier = try await InstalledPluginRunPreparation.resolve(pluginID: fixture.id, registry: fixture.registry)
        #expect(!earlier.kit.encrypted)
        _ = try await fixture.install(reads: ["/Users"], privacy: "content", version: "0.2.0", force: true)
        let current = try await InstalledPluginRunPreparation.resolve(pluginID: fixture.id, registry: fixture.registry)
        #expect(current.kit.encrypted)
        #expect(current.manifest.version == "0.2.0")
        #expect(current.detail(provenance: .store, installedLabel: "Installed").version == "0.2.0")
        try fixture.assertNoStagedBinary()
    }

    @Test func sensitiveDeclaredOutputWithoutReadCapabilitiesStillRequiresEncryption() async throws {
        let fixture = try Fixture(); defer { fixture.cleanup() }
        _ = try await fixture.install(privacy: "content")
        let prepared = try await InstalledPluginRunPreparation.resolve(pluginID: fixture.id, registry: fixture.registry)
        #expect(prepared.kit.encrypted)
        #expect(prepared.detail(provenance: .store, installedLabel: "Installed").privacyLabel == "Content")
        try fixture.assertNoStagedBinary()
    }

    @Test func declaredMetadataCannotLowerReadExposureInDetails() async throws {
        let fixture = try Fixture(); defer { fixture.cleanup() }
        _ = try await fixture.install(reads: ["/Users"], privacy: "metadata")
        let prepared = try await InstalledPluginRunPreparation.resolve(pluginID: fixture.id, registry: fixture.registry)
        #expect(prepared.kit.encrypted)
        #expect(prepared.detail(provenance: .store, installedLabel: "Installed").privacyLabel == "Content")
        try fixture.assertNoStagedBinary()
    }

    @Test func missingInstalledBundleCannotPrepareFallbackMetadataRun() async throws {
        let fixture = try Fixture(); defer { fixture.cleanup() }
        await #expect(throws: (any Error).self) {
            try await InstalledPluginRunPreparation.resolve(pluginID: fixture.id, registry: fixture.registry)
        }
        try fixture.assertNoStagedBinary()
    }

    @Test func tamperedManifestCannotDowngradePrivacyOrSupplyDetails() async throws {
        let fixture = try Fixture(); defer { fixture.cleanup() }
        let installed = try await fixture.install(reads: ["/Users"], privacy: "content")
        let path = URL(fileURLWithPath: installed.installRoot).appendingPathComponent("manifest.json")
        var object = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: path)) as? [String: Any])
        object["fileReadSubpaths"] = [String]()
        object["privacyClass"] = "metadata"
        try JSONSerialization.data(withJSONObject: object).write(to: path)
        await #expect(throws: (any Error).self) {
            try await InstalledPluginRunPreparation.resolve(pluginID: fixture.id, registry: fixture.registry)
        }
        try fixture.assertNoStagedBinary()
    }

    @Test func revokedPublisherCannotPrepareRun() async throws {
        let fixture = try Fixture(); defer { fixture.cleanup() }
        let installed = try await fixture.install(reads: ["/Users"], privacy: "content")
        try await fixture.installer.revokeKey(installed.publicKeyHex)
        await #expect(throws: (any Error).self) {
            try await InstalledPluginRunPreparation.resolve(pluginID: fixture.id, registry: fixture.registry)
        }
        try fixture.assertNoStagedBinary()
    }

    @Test func unsupportedAnalyzerIsRefusedBeforeCreatingCase() async throws {
        let fixture = try Fixture(); defer { fixture.cleanup() }
        _ = try await fixture.install(reads: ["/Users"], privacy: "content", kind: .analyzer)
        await #expect(throws: (any Error).self) {
            try await InstalledPluginRunPreparation.resolve(pluginID: fixture.id, registry: fixture.registry)
        }
        try fixture.assertNoStagedBinary()
    }
}
