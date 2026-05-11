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
    }
}
