// PluginVisibility — the SINGLE shared classifier for which installed plugins are
// dev/test/rehearsal RESIDUE versus operator-visible. Lives in MacCrabForensics
// (not the app GUI) so EVERY surface applies the same rule: the dashboard,
// `maccrabctl plugin list`, and the MCP `forensics.list_installed_plugins` tool.
//
// Previously the classifier lived only in the app's OperatorVisibilityFilter, so
// the CLI + MCP showed raw residue, and the rule was too narrow to catch real
// leftovers (com.acme.* test plugins, the launch-rehearsal com.maccrab.hosts-
// collector) — they passed through as legitimate "[Third-party]" installs.

import Foundation

public enum PluginVisibility {

    /// True iff `pluginID` is dev / test / rehearsal RESIDUE that must never appear
    /// in operator-facing surfaces.
    ///
    /// `builtinIDs` is the set of registered first-party built-in ids
    /// (`PluginRegistry.shared.manifests()`). When supplied (non-empty) the POSITIVE
    /// rule applies: the `com.maccrab.*` namespace is reserved for first-party
    /// built-ins (RaveNamespaceGuard refuses it for third-party / sideload), so ANY
    /// *installed* `com.maccrab.*` that is NOT a registered built-in is
    /// impersonation / leftover residue. The denylist below catches outside vendors
    /// and the known rehearsal id regardless of `builtinIDs`.
    public static func isResidue(pluginID: String, builtinIDs: Set<String> = []) -> Bool {
        // Non-plugin directory entries the installer can surface (trust JSON, etc.).
        if pluginID.hasSuffix(".json") { return true }
        // Outside-vendor test / research / fixture / example denylist.
        if pluginID.hasPrefix("com.acme.") { return true }        // test vendor (com.acme.tool / heartbeat)
        if pluginID.hasPrefix("com.test.") { return true }
        if pluginID.hasPrefix("com.research.") { return true }
        if pluginID.hasPrefix("com.example.") { return true }
        if pluginID.hasSuffix("-fixture") { return true }
        if pluginID.contains(".test.") { return true }
        if pluginID.contains(".example") { return true }
        // The launch-rehearsal example — first-party-namespaced but not a built-in.
        if pluginID == "com.maccrab.hosts-collector" { return true }
        // Positive rule (only when the built-in set is known): com.maccrab.* is
        // first-party-only; an installed com.maccrab.* that isn't registered is
        // residue / impersonation.
        if !builtinIDs.isEmpty, pluginID.hasPrefix("com.maccrab."), !builtinIDs.contains(pluginID) {
            return true
        }
        return false
    }

    public static func isOperatorVisible(pluginID: String, builtinIDs: Set<String> = []) -> Bool {
        !isResidue(pluginID: pluginID, builtinIDs: builtinIDs)
    }

    /// Operator-visible installed plugins (drops residue). `builtinIDs` enables the
    /// positive `com.maccrab.*` rule; the denylist applies regardless.
    public static func filterInstalled(_ installed: [InstalledPlugin], builtinIDs: Set<String> = []) -> [InstalledPlugin] {
        installed.filter { isOperatorVisible(pluginID: $0.pluginID, builtinIDs: builtinIDs) }
    }
}
