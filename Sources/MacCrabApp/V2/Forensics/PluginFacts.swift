// PluginFacts.swift
//
// Single source of truth for the rich per-plugin capability chips shown by
// BOTH the rave store detail panel (V2RaveCatalogBrowserView) and the
// pre-install consent sheet (RaveInstallConsentSheet). Backed by
// ScannerCatalog (local, first-party, keyed by plugin id) so the two surfaces
// can't drift. Returns nil for ids with no local facts (third-party /
// not-yet-documented) so both call sites degrade to their friendly-name
// fallback. No network, no fetch — safe to call pre-install.

import Foundation

public struct PluginFacts: Sendable {
    public let purpose: String
    public let reads: [String]            // human-readable path strings it reads
    public let needs: [String]            // TCC requirements
    public let emits: [String]            // already label-resolved for display
    public let privacyLabel: String       // PrivacyClassDisplay.label
    public let isMetadataOnly: Bool       // drives green-shield vs lock affordance

    /// Truthful with NO new data: Tier B plugins default to deny-all network and
    /// there is no plugin sandbox yet (mirrors the consent sheet's C-D
    /// disclosure). Co-located here so the "network: none · not sandboxed"
    /// honesty stays consistent across both surfaces.
    public var networkChip: String { "Network: none (default-deny)" }
    public var sandboxChip: String { "Not sandboxed" }
}

public enum PluginFactsLookup {
    /// Rich facts for a catalog/plugin id, or nil when no local facts exist.
    /// Keyed by the exact id form on RaveCatalogEntry.id /
    /// RaveInstallConsentFacts.id (e.g. "com.maccrab.forensics.launchd-lite").
    public static func facts(forPluginID id: String) -> PluginFacts? {
        guard let f = ScannerCatalog.fact(forPluginID: id) else { return nil }
        return PluginFacts(
            purpose: f.purpose,
            reads: f.dataSources,
            needs: f.tccRequirements,
            emits: f.emits.map { ScannerDisplay.name(forContentType: $0) },
            privacyLabel: f.privacyClass.label,
            isMetadataOnly: f.privacyClass == .metadata
        )
    }
}
