// MacCrabForensicsBootstrap — central registration of built-in
// plugins. Called at module init from each top-level binary
// (maccrabctl, MacCrabApp, maccrab-mcp).
//
// Future plugin landings extend `registerBuiltins(into:)` with
// one more `try await registry.register(...)` line. Pass 2026-A
// audits the source-tree set against the registered set so
// nothing slips through.

import Foundation

public enum MacCrabForensicsBootstrap {

    /// Register every built-in plugin into the supplied registry.
    /// Idempotent on plugin id — re-registration replaces. The
    /// shared `PluginRegistry.shared` is the canonical target.
    public static func registerBuiltins(into registry: PluginRegistry = .shared) async throws {
        #if DEBUG
        // FixturePlugin (com.maccrab.forensics.fixture) is a no-op collector that
        // exists only to exercise the plugin lifecycle / serve as the PluginRunner
        // test fixture. It must NOT ship in a release build — it would otherwise
        // surface in the CLI `plugin list`, the MCP `forensics.list_plugins`, and
        // the live `fixture_emit_heartbeat` tool. Tests register it directly, so
        // gating it here doesn't affect them.
        try await registry.register(PluginRegistration(
            manifest: FixturePlugin.manifest,
            factory: { try await FixturePlugin() }
        ))
        #endif
        try await registry.register(PluginRegistration(
            manifest: CodesignResolveEnricher.manifest,
            factory: { try await CodesignResolveEnricher() }
        ))
        try await registry.register(PluginRegistration(
            manifest: TCCLitePlugin.manifest,
            factory: { try await TCCLitePlugin() }
        ))
        try await registry.register(PluginRegistration(
            manifest: LaunchdLitePlugin.manifest,
            factory: { try await LaunchdLitePlugin() }
        ))
        try await registry.register(PluginRegistration(
            manifest: PostureAnalyzer.manifest,
            factory: { try await PostureAnalyzer() }
        ))
        try await registry.register(PluginRegistration(
            manifest: AppleScriptRuntimePlugin.manifest,
            factory: { try await AppleScriptRuntimePlugin() }
        ))
        try await registry.register(PluginRegistration(
            manifest: SafariLitePlugin.manifest,
            factory: { try await SafariLitePlugin() }
        ))
        try await registry.register(PluginRegistration(
            manifest: ChromiumLitePlugin.manifest,
            factory: { try await ChromiumLitePlugin() }
        ))
        try await registry.register(PluginRegistration(
            manifest: MailLitePlugin.manifest,
            factory: { try await MailLitePlugin() }
        ))
        try await registry.register(PluginRegistration(
            manifest: iMessageMetadataPlugin.manifest,
            factory: { try await iMessageMetadataPlugin() }
        ))
        try await registry.register(PluginRegistration(
            manifest: KnowledgeCPlugin.manifest,
            factory: { try await KnowledgeCPlugin() }
        ))
        try await registry.register(PluginRegistration(
            manifest: QuarantinePlugin.manifest,
            factory: { try await QuarantinePlugin() }
        ))
        try await registry.register(PluginRegistration(
            manifest: FSEventsPlugin.manifest,
            factory: { try await FSEventsPlugin() }
        ))
        try await registry.register(PluginRegistration(
            manifest: MachOAnalyzerPlugin.manifest,
            factory: { try await MachOAnalyzerPlugin() }
        ))
        try await registry.register(PluginRegistration(
            manifest: ThreatIntelDomainEnricher.manifest,
            factory: { try await ThreatIntelDomainEnricher() }
        ))
        try await registry.register(PluginRegistration(
            manifest: GeoIPASNEnricher.manifest,
            factory: { try await GeoIPASNEnricher() }
        ))
        try await registry.register(PluginRegistration(
            manifest: CodesigningAnomalyEnricher.manifest,
            factory: { try await CodesigningAnomalyEnricher() }
        ))
        try await registry.register(PluginRegistration(
            manifest: PlistAnalyzerPlugin.manifest,
            factory: { try await PlistAnalyzerPlugin() }
        ))
        try await registry.register(PluginRegistration(
            manifest: MobileconfigPlugin.manifest,
            factory: { try await MobileconfigPlugin() }
        ))
        try await registry.register(PluginRegistration(
            manifest: ShortcutsAnalyzerPlugin.manifest,
            factory: { try await ShortcutsAnalyzerPlugin() }
        ))
        try await registry.register(PluginRegistration(
            manifest: ImageMetadataPlugin.manifest,
            factory: { try await ImageMetadataPlugin() }
        ))
        try await registry.register(PluginRegistration(
            manifest: DMGPKGAnalyzerPlugin.manifest,
            factory: { try await DMGPKGAnalyzerPlugin() }
        ))
        try await registry.register(PluginRegistration(
            manifest: ArchiveWalkerPlugin.manifest,
            factory: { try await ArchiveWalkerPlugin() }
        ))
        try await registry.register(PluginRegistration(
            manifest: DocumentAnalyzerPlugin.manifest,
            factory: { try await DocumentAnalyzerPlugin() }
        ))
        try await registry.register(PluginRegistration(
            manifest: DNSPassiveReputationEnricher.manifest,
            factory: { try await DNSPassiveReputationEnricher() }
        ))
        try await registry.register(PluginRegistration(
            manifest: StylometricSupplyChainEnricher.manifest,
            factory: { try await StylometricSupplyChainEnricher() }
        ))
        try await registry.register(PluginRegistration(
            manifest: ThreatIntelIPEnricher.manifest,
            factory: { try await ThreatIntelIPEnricher() }
        ))
        try await registry.register(PluginRegistration(
            manifest: CodesigningGraphPlugin.manifest,
            factory: { try await CodesigningGraphPlugin() }
        ))
        try await registry.register(PluginRegistration(
            manifest: OfficeDocumentPlugin.manifest,
            factory: { try await OfficeDocumentPlugin() }
        ))
        try await registry.register(PluginRegistration(
            manifest: iMessageBodiesPlugin.manifest,
            factory: { try await iMessageBodiesPlugin() }
        ))
        try await registry.register(PluginRegistration(
            manifest: MailBodiesPlugin.manifest,
            factory: { try await MailBodiesPlugin() }
        ))
        try await registry.register(PluginRegistration(
            manifest: SafariDeepPlugin.manifest,
            factory: { try await SafariDeepPlugin() }
        ))
        try await registry.register(PluginRegistration(
            manifest: FaceTimePlugin.manifest,
            factory: { try await FaceTimePlugin() }
        ))
        try await registry.register(PluginRegistration(
            manifest: BiomePlugin.manifest,
            factory: { try await BiomePlugin() }
        ))
    }
}
