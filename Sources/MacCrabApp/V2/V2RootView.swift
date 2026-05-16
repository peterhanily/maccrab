// V2RootView.swift
// Top-level entry point for the v2 dashboard.
//
// MacCrabApp.swift constructs this with the shared AppState so that
// data-rich subviews (Events, Alerts, etc.) can pull from the live
// publisher graph rather than re-opening MacCrabCore stores.

import SwiftUI

struct V2RootView: View {
    @ObservedObject var appState: AppState

    init(appState: AppState) {
        self.appState = appState
    }

    var body: some View {
        V2DashboardShell(appState: appState)
            // v1.12.0 fix: cascade text selection to every workspace
            // and subview. SwiftUI Text views default to non-selectable
            // on macOS; without this modifier, users can't highlight
            // rule descriptions, event details, alert process paths,
            // etc. to copy them. Applying once at the root inherits
            // through the view hierarchy; per-view textSelection still
            // wins where it's set (e.g. workspaces that explicitly
            // disabled selection for tappable rows).
            .textSelection(.enabled)
    }
}
