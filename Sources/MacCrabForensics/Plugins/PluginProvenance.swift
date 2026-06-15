// PluginProvenance.swift
// MacCrabForensics
//
// Where a plugin came from. Surfaced in the dashboard / MCP / CLI so a
// first-party (built-in) plugin is visually distinct from an operator-trusted
// third-party sideload and from a rave-store-sourced install. (v1.19.0)

import Foundation

public enum PluginProvenance: String, Sendable, Codable, CaseIterable {
    /// Shipped inside MacCrab.app — Tier A built-in / first-party.
    case builtIn = "built-in"
    /// Installed Tier B plugin trusted via an operator-added publisher key with
    /// NO rave-catalog install receipt — a sideload the operator vouched for.
    case thirdParty = "third-party"
    /// Installed Tier B plugin carrying a signed rave-catalog install receipt
    /// (a catalog_serial) — sourced from the rave store.
    case store = "store"

    public var displayName: String {
        switch self {
        case .builtIn:    return "Built-in"
        case .thirdParty: return "Third-party"
        case .store:      return "Store"
        }
    }

    /// SF Symbol the dashboard renders next to the label.
    public var symbolName: String {
        switch self {
        case .builtIn:    return "shield.lefthalf.filled"
        case .thirdParty: return "person.badge.key"
        case .store:      return "bag"
        }
    }

    /// Classify an INSTALLED (Tier B) plugin from its install receipt. A valid,
    /// signature-verified receipt that carries a catalog_serial means the plugin
    /// was installed from the rave store; anything else (no receipt, an
    /// unverifiable/tampered receipt, or a receipt without a catalog serial) is
    /// an operator-trusted third-party sideload. A tampered "store" receipt thus
    /// safely DOWNGRADES to third-party, never the reverse. Built-in plugins are
    /// classified `.builtIn` at the Tier A registry, not here.
    public static func forInstalled(pluginID: String, receiptsDir: URL) -> PluginProvenance {
        let url = receiptsDir.appendingPathComponent("\(pluginID).receipt.json")
        if let body = try? PluginInstallReceiptStore.verify(at: url), body.catalogSerial != nil {
            return .store
        }
        return .thirdParty
    }
}
