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

    /// Plugin ids that should never appear in operator-facing UI.
    /// Patterns:
    ///   com.test.*          — manual test plugins
    ///   com.research.*      — research / preview plugins
    ///   *-fixture           — test fixtures
    public static func isOperatorVisible(pluginID: String) -> Bool {
        if pluginID.hasPrefix("com.test.") { return false }
        if pluginID.hasPrefix("com.research.") { return false }
        if pluginID.hasSuffix("-fixture") { return false }
        if pluginID.contains(".test.") { return false }
        return true
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

    /// Filter for InstalledPlugin items returned by
    /// PluginInstaller.list(). PluginInstaller returns directory
    /// entries; some end up being trust/revocation JSON files
    /// rather than actual plugin directories. Skip those.
    public static func filter(_ installed: [InstalledPlugin]) -> [InstalledPlugin] {
        installed.filter { p in
            // Reject .json entries (trusted-keys.json etc.) that
            // the installer rendered as bogus plugin rows.
            if p.pluginID.hasSuffix(".json") { return false }
            // Apply name filter.
            return isOperatorVisible(pluginID: p.pluginID)
        }
    }

    /// Filter for CaseManifest entries. Used by Scans tab.
    public static func filter(_ scans: [CaseManifest]) -> [CaseManifest] {
        scans.filter { isOperatorVisible(scanName: $0.name) }
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
