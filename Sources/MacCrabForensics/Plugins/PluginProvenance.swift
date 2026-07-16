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

    /// Forensics-UI label — clearer about WHERE a plugin came from than the bare
    /// "Third-party" (which reads as ambiguous). A non-store install is an
    /// operator sideload, so we call it that.
    public var forensicsLabel: String {
        switch self {
        case .builtIn:    return "Built-in"
        case .thirdParty: return "Sideloaded"
        case .store:      return "Store"
        }
    }

    /// One-line explanation shown in the plugin detail sheet so a user knows
    /// exactly what the provenance means.
    public var explanation: String {
        switch self {
        case .builtIn:
            return "Ships inside MacCrab.app — first-party, verified at build time."
        case .store:
            return "Installed from the rave store — signature-verified against the signed catalog."
        case .thirdParty:
            return "Sideloaded — you trusted this publisher's key directly; not from the store."
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

    /// Classify an INSTALLED (Tier B) plugin from its install receipt. A `.store`
    /// classification grants real leniency (the 30-day revocation-staleness
    /// window), so it must come from a receipt signed by THIS host's install-
    /// receipt key — NOT any self-signed receipt an attacker dropped into
    /// `plugin_receipts/`. Verification is therefore PINNED to the host
    /// TrustSubstrate public key (mirroring the catalog Ed25519 pin). Anything
    /// that fails the pin or the tamper-check — no receipt, an unverifiable /
    /// self-signed / foreign-signed receipt, no host key yet, or a receipt
    /// without a catalog serial — safely DOWNGRADES to `.thirdParty`, never the
    /// reverse. Built-in plugins are classified `.builtIn` at the Tier A
    /// registry, not here.
    ///
    /// `pinnedPublicKeyDER` overrides the pin source (tests inject their
    /// substrate's key); in production it is nil and the host key is read from
    /// disk at the conventional sibling path.
    public static func forInstalled(
        pluginID: String,
        receiptsDir: URL,
        pinnedPublicKeyDER: Data? = nil
    ) -> PluginProvenance {
        let url = receiptsDir.appendingPathComponent("\(pluginID).receipt.json")
        // No host key ⇒ no genuine store receipt from this host can exist ⇒ we
        // cannot establish `.store`; downgrade rather than accept an unpinned one.
        guard let pinned = pinnedPublicKeyDER ?? hostReceiptSigningKeyDER(receiptsDir: receiptsDir) else {
            return .thirdParty
        }
        if let body = try? PluginInstallReceiptStore.verify(at: url, pinnedPublicKeyDER: pinned),
           body.catalogSerial != nil {
            return .store
        }
        return .thirdParty
    }

    /// This host's install-receipt signing key (TrustSubstrate public key, SPKI
    /// DER), used to PIN receipt verification. It is persisted by the
    /// TrustSubstrate storage at `<dataDir>/keys/trace-signing.pub` — a sibling of
    /// the `<dataDir>/plugin_receipts` receipts dir (the layout established by the
    /// receipt store + FilesystemTrustSubstrateStorage). Reading the public key
    /// from disk is the documented third-party-validator contract (see
    /// TrustSubstrate). Returns nil when no host key exists yet.
    private static func hostReceiptSigningKeyDER(receiptsDir: URL) -> Data? {
        let keyURL = receiptsDir
            .deletingLastPathComponent()
            .appendingPathComponent("keys")
            .appendingPathComponent("trace-signing.pub")
        return try? Data(contentsOf: keyURL)
    }
}
