// MainView.swift
// MacCrabApp
//
// Main dashboard window with tab navigation across the four primary views:
// Alerts, Events, Rules, and TCC Permissions.

import SwiftUI

// MARK: - MainView

struct MainView: View {
    @ObservedObject var appState: AppState

    var body: some View {
        VStack(spacing: 0) {
            // Top bar with connection status
            HStack {
                Text("🦀")
                    .font(.title2)
                Text("MacCrab")
                    .font(.title2)
                    .fontWeight(.bold)

                Spacer()

                ConnectionStatusBadge(isConnected: appState.isConnected)

                Button {
                    Task { await appState.refresh() }
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .buttonStyle(.borderless)
                .help("Refresh data")
            }
            .padding(.horizontal)
            .padding(.vertical, 8)
            .background(.bar)

            Divider()

            // Tab content
            TabView(selection: $appState.selectedTab) {
                AlertDashboard(appState: appState)
                    .tabItem {
                        Label("Alerts", systemImage: "exclamationmark.triangle")
                    }
                    .tag(AppState.Tab.alerts)
                    .keyboardShortcut("1", modifiers: .command)

                EventStream(appState: appState)
                    .tabItem {
                        Label("Events", systemImage: "list.bullet")
                    }
                    .tag(AppState.Tab.events)
                    .keyboardShortcut("2", modifiers: .command)

                RuleBrowser(appState: appState)
                    .tabItem {
                        Label("Rules", systemImage: "shield")
                    }
                    .tag(AppState.Tab.rules)
                    .keyboardShortcut("3", modifiers: .command)

                TCCTimeline(appState: appState)
                    .tabItem {
                        Label("Permissions", systemImage: "lock.shield")
                    }
                    .tag(AppState.Tab.tcc)
                    .keyboardShortcut("4", modifiers: .command)

                DocsView()
                    .tabItem {
                        Label("Docs", systemImage: "book")
                    }
                    .tag(AppState.Tab.docs)
                    .keyboardShortcut("5", modifiers: .command)
            }
        }
        .frame(minWidth: 900, minHeight: 600)
    }
}

