// OperatorVisibilityFilter.swift
//
// Hides dev / test residue from operator-facing dashboard
// surfaces. Filter is applied at every load — Scans, Plugins,
// Findings, Evidence. Filtered items are never shown but also
// never deleted; they remain on disk for engineering review
// via the CLI.
//
// Rationale: my dev sessions left real test data in
// ~/Library/Application Support/MacCrab/ that the dashboard
// reads at startup. Without this filter operators see
// "Tier B end-to-end smoke" + "com.test.daemon" + a JSON file
// rendered as a plugin and conclude MacCrab is broken.

import Foundation
import MacCrabForensics

public enum OperatorVisibilityFilter {

    /// Plugin ids that should never appear in operator-facing UI. Delegates to the
    /// shared MacCrabForensics classifier so the dashboard, CLI, and MCP agree.
    public static func isOperatorVisible(pluginID: String, builtinIDs: Set<String> = []) -> Bool {
        PluginVisibility.isOperatorVisible(pluginID: pluginID, builtinIDs: builtinIDs)
    }

    /// True iff the id is dev/test/rehearsal residue (for the Settings cleanup,
    /// which must offer to delete exactly what we hide).
    public static func isResidue(pluginID: String, builtinIDs: Set<String> = []) -> Bool {
        PluginVisibility.isResidue(pluginID: pluginID, builtinIDs: builtinIDs)
    }

    /// Filter applied to scan names. Hides scans whose name
    /// matches dev / smoke patterns.
    public static func isOperatorVisible(scanName: String) -> Bool {
        let lower = scanName.lowercased()
        if lower.hasSuffix("-smoke") || lower.hasSuffix(" smoke") { return false }
        if lower.contains("end-to-end smoke") { return false }
        if lower.hasPrefix("tier b ") { return false }
        if lower.hasPrefix("tier-b ") { return false }
        if lower.hasPrefix("daemon test") { return false }
        return true
    }

    /// Filter applied to artifacts. Hides anything from a
    /// non-operator-visible plugin OR with a fixture content type.
    public static func isOperatorVisible(contentType: String, pluginID: String) -> Bool {
        if !isOperatorVisible(pluginID: pluginID) { return false }
        if contentType.contains("fixture") { return false }
        return true
    }

    /// Filter for InstalledPlugin items returned by PluginInstaller.list().
    /// Delegates to the shared classifier. Pass `builtinIDs` (registry ids) to
    /// enable the positive `com.maccrab.*`-impersonation rule; the denylist
    /// (com.acme.*, the rehearsal id, .json trust files, …) applies regardless.
    public static func filter(_ installed: [InstalledPlugin], builtinIDs: Set<String> = [], trustedKeyHexes: Set<String> = []) -> [InstalledPlugin] {
        PluginVisibility.filterInstalled(installed, builtinIDs: builtinIDs, trustedKeyHexes: trustedKeyHexes)
    }

    /// Filter for CaseManifest entries. Used by Scans tab.
    public static func filter(_ scans: [CaseManifest]) -> [CaseManifest] {
        let hidden = HiddenScans.ids
        return scans.filter { scan in
            if hidden.contains(scan.id) { return false }
            return isOperatorVisible(scanName: scan.name)
        }
    }

    /// Filter for CommittedArtifact entries. Used by Evidence
    /// + Findings views.
    public static func filter(_ artifacts: [CommittedArtifact]) -> [CommittedArtifact] {
        artifacts.filter {
            isOperatorVisible(contentType: $0.record.contentType,
                              pluginID: $0.record.pluginID)
        }
    }
}

/// Operator-driven hide list for scans they've dismissed from
/// the past-scans timeline. UserDefaults-backed so it persists
/// across launches but never touches the on-disk case data —
/// the operator can always restore via maccrabctl or by clearing
/// the hide list from settings.
public enum HiddenScans {
    private static let key = "forensics.hiddenScanIDs"

    /// Comma-joined set of dismissed scan IDs.
    public static var ids: Set<String> {
        let raw = UserDefaults.standard.string(forKey: key) ?? ""
        return Set(raw.split(separator: ",").map(String.init))
    }

    public static func hide(_ scanID: String) {
        var set = ids
        set.insert(scanID)
        UserDefaults.standard.set(set.sorted().joined(separator: ","), forKey: key)
    }

    public static func restore(_ scanID: String) {
        var set = ids
        set.remove(scanID)
        UserDefaults.standard.set(set.sorted().joined(separator: ","), forKey: key)
    }

    public static func clearAll() {
        UserDefaults.standard.removeObject(forKey: key)
    }
}
