// ArtifactViewerDispatcher — picks the right viewer for a
// group of artifacts of the same content type. Looks up the
// plugin's ViewerHint from the registry; falls back to the
// generic JSON tree view when no hint exists.
//
// SwiftUI views can't await, so the dispatcher takes a pre-
// resolved [contentType: ViewerHint?] map from the calling
// scan-detail view, which fetched it asynchronously at load
// time. The view doesn't decode anything at render time.

import SwiftUI
import MacCrabForensics

struct ArtifactViewerDispatcher: View {
    let contentType: String
    let artifacts: [CommittedArtifact]
    let hint: ViewerHint?

    var body: some View {
        Group {
            if let hint {
                switch hint.viewer {
                case .table:      ArtifactTableView(artifacts: artifacts, hint: hint)
                case .timeline:   ArtifactTimelineView(artifacts: artifacts, hint: hint)
                case .keyvalue:   ArtifactKeyValueView(artifacts: artifacts, hint: hint)
                case .transcript: ArtifactTranscriptView(artifacts: artifacts, hint: hint)
                case .layout:     ArtifactLayoutView(artifacts: artifacts, hint: hint)
                }
            } else {
                JSONTreeView(artifacts: artifacts)
            }
        }
    }
}

/// Resolves ViewerHints from the plugin registry. Called by the
/// scan-detail view at load time (once); the resulting map is
/// passed to every dispatcher within that view's lifetime.
public enum ViewerHintResolver {

    /// For each contentType present in the case, fetch the
    /// plugin manifest's matching OutputSpec.viewerHint.
    /// Returns nil for any contentType whose plugin manifest
    /// doesn't declare a hint.
    public static func resolveAll(contentTypes: Set<String>) async -> [String: ViewerHint?] {
        var out: [String: ViewerHint?] = [:]
        let registry = PluginRegistry.shared
        for ct in contentTypes {
            out[ct] = await find(contentType: ct, in: registry)
        }
        return out
    }

    private static func find(contentType: String, in registry: PluginRegistry) async -> ViewerHint? {
        let manifests = await registry.manifests()
        for m in manifests {
            if let spec = m.outputs.first(where: { $0.contentType == contentType }) {
                return spec.viewerHint
            }
        }
        return nil
    }
}
