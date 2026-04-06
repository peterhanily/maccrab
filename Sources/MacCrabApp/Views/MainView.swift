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
                .accessibilityLabel("Refresh all data")
            }
            .padding(.horizontal)
            .padding(.vertical, 8)
            .background(.bar)

            Divider()

            // Tab content
            TabView(selection: $appState.selectedTab) {
                AlertDashboard(appState: appState)
                    .tabItem {
                        Label(String(localized: "tabs.alerts", defaultValue: "Alerts"), systemImage: "exclamationmark.triangle")
                    }
                    .tag(AppState.Tab.alerts)
                    .keyboardShortcut("1", modifiers: .command)

                EventStream(appState: appState)
                    .tabItem {
                        Label(String(localized: "tabs.events", defaultValue: "Events"), systemImage: "list.bullet")
                    }
                    .tag(AppState.Tab.events)
                    .keyboardShortcut("2", modifiers: .command)

                RuleBrowser(appState: appState)
                    .tabItem {
                        Label(String(localized: "tabs.rules", defaultValue: "Rules"), systemImage: "shield")
                    }
                    .tag(AppState.Tab.rules)
                    .keyboardShortcut("3", modifiers: .command)

                TCCTimeline(appState: appState)
                    .tabItem {
                        Label(String(localized: "tabs.permissions", defaultValue: "Permissions"), systemImage: "lock.shield")
                    }
                    .tag(AppState.Tab.tcc)
                    .keyboardShortcut("4", modifiers: .command)

                AIActivityView(appState: appState)
                    .tabItem {
                        Label(String(localized: "tabs.aiGuard", defaultValue: "AI Guard"), systemImage: "cpu")
                    }
                    .tag(AppState.Tab.aiGuard)
                    .keyboardShortcut("5", modifiers: .command)

                PreventionView(appState: appState)
                    .tabItem {
                        Label(String(localized: "tabs.prevention", defaultValue: "Prevention"), systemImage: "shield.checkered")
                    }
                    .tag(AppState.Tab.prevention)
                    .keyboardShortcut("6", modifiers: .command)

                DocsView()
                    .tabItem {
                        Label(String(localized: "tabs.docs", defaultValue: "Docs"), systemImage: "book")
                    }
                    .tag(AppState.Tab.docs)
                    .keyboardShortcut("7", modifiers: .command)
            }
        }
        .frame(minWidth: 900, minHeight: 600)
    }
}

