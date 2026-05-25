// V2DeepLink.swift
// URL-scheme parser/builder for v2 dashboard deep links.
// Format: maccrab://<workspace>/<tab>?entity=<id>&<filterKey>=<value>...
//
// Examples:
//   maccrab://alerts/open?entity=alt-001
//   maccrab://detection/rules?modal=new
//   maccrab://investigation/tracegraph?entity=trc-001
//
// Phase 3 scope: parse + build. Wiring `onOpenURL` at the app
// scene level happens when MacCrabApp.swift mounts V2RootView in
// phase 5 (or via a feature flag in phase 4).

import Foundation

public enum V2DeepLink {
    public static let scheme = "maccrab"

    public static func url(for destination: V2NavigationDestination) -> URL? {
        var components = URLComponents()
        components.scheme = scheme
        components.host = destination.workspace.rawValue
        if let tab = destination.tab {
            components.path = "/" + tab.rawValue.lowercased()
        }
        var query: [URLQueryItem] = []
        if let id = destination.entityId {
            query.append(URLQueryItem(name: "entity", value: id))
        }
        for (k, v) in destination.filters.sorted(by: { $0.key < $1.key }) {
            query.append(URLQueryItem(name: k, value: v))
        }
        if !query.isEmpty { components.queryItems = query }
        return components.url
    }

    public static func parse(_ url: URL) -> V2NavigationDestination? {
        guard url.scheme == scheme else { return nil }
        let host = url.host ?? ""
        let path = url.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))

        // v1.17 — redirect legacy Forensics-under-Investigation
        // deep links to the new Forensics workspace. Operator
        // bookmarks + auto-generated incident-response URLs
        // shipped before v1.17 keep working without breakage.
        let (rWorkspaceRaw, rPath) = redirectLegacyForensicsPath(host: host, path: path)

        guard let workspace = V2Workspace(rawValue: rWorkspaceRaw) else { return nil }

        var tab: V2WorkspaceTab? = nil
        if !rPath.isEmpty {
            // Tabs are stored as camelCase enum cases; URL paths are lowercase.
            // Match by case-insensitive lookup against tabs of this workspace.
            tab = workspace.tabs.first { $0.rawValue.lowercased() == rPath.lowercased() }
        }

        var entity: String? = nil
        var filters: [String: String] = [:]
        if let comps = URLComponents(url: url, resolvingAgainstBaseURL: false),
           let items = comps.queryItems {
            for item in items {
                guard let v = item.value else { continue }
                if item.name == "entity" { entity = v }
                else { filters[item.name] = v }
            }
        }

        return V2NavigationDestination(
            workspace: workspace, tab: tab, entityId: entity, filters: filters
        )
    }

    /// v1.17 audit-D mitigation: map legacy Forensics-under-
    /// Investigation deep-link paths to their new Forensics-
    /// workspace equivalents. Returns (workspaceRaw, pathRaw).
    /// Non-legacy URLs pass through unchanged.
    ///
    /// Tested in V2DeepLinkTests.testLegacyForensicsRedirects.
    private static func redirectLegacyForensicsPath(
        host: String,
        path: String
    ) -> (workspaceRaw: String, pathRaw: String) {
        guard host == "investigation" else { return (host, path) }
        switch path.lowercased() {
        case "investigationforensicscases":     return ("forensics", "forensicsScans")
        case "investigationforensicsplugins":   return ("forensics", "forensicsPlugins")
        case "investigationforensicstierb":     return ("forensics", "forensicsPlugins")
        case "investigationforensicsartifacts": return ("forensics", "forensicsEvidence")
        case "investigationforensicsfindings":  return ("forensics", "forensicsScans")
        default:
            return (host, path)
        }
    }
}
