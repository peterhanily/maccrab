// MainView.swift
// MacCrabApp
//
// Main dashboard window with sidebar navigation layout.
// Uses NavigationSplitView with grouped sections.

import SwiftUI
import MacCrabCore

// MARK: - MainView

struct MainView: View {
    @ObservedObject var appState: AppState
    @State private var selectedSection: SidebarSection? = .overview
    @Environment(\.accessibilityReduceMotion) var reduceMotion
    @Environment(\.accessibilityShowButtonShapes) var showButtonShapes

    private var hasCriticalAlerts: Bool {
        appState.dashboardAlerts.contains { $0.severity == .critical && !$0.suppressed }
    }

    enum SidebarSection: String, CaseIterable, Hashable {
        case overview = "Overview"
        case alerts = "Alerts"
        case events = "Events"
        case rules = "Rules"
        // Protection
        case prevention = "Prevention"
        case aiGuard = "AI Guard"
        // Intelligence
        case threatIntel = "Threat Intel"
        case integrations = "Integrations"
        // System
        case permissions = "Permissions"
        case docs = "Docs"
    }

    var body: some View {
        NavigationSplitView {
            List(selection: $selectedSection) {
                Section("Monitor") {
                    Label("Overview", systemImage: "gauge.with.dots.needle.33percent")
                        .tag(SidebarSection.overview)
                    Label("Alerts", systemImage: "exclamationmark.triangle")
                        .badge(appState.totalAlerts)
                        .foregroundColor(hasCriticalAlerts ? .red : nil)
                        .tag(SidebarSection.alerts)
                    Label("Events", systemImage: "list.bullet.rectangle")
                        .tag(SidebarSection.events)
                    Label("Rules", systemImage: "shield.checkered")
                        .badge(appState.rulesLoaded)
                        .tag(SidebarSection.rules)
                }

                Section("Protection") {
                    Label("Prevention", systemImage: "hand.raised")
                        .tag(SidebarSection.prevention)
                    Label("AI Guard", systemImage: "brain")
                        .tag(SidebarSection.aiGuard)
                }

                Section("Intelligence") {
                    Label("Threat Intel", systemImage: "binoculars")
                        .tag(SidebarSection.threatIntel)
                    Label("Integrations", systemImage: "puzzlepiece.extension")
                        .tag(SidebarSection.integrations)
                }

                Section("System") {
                    Label("Permissions", systemImage: "lock.shield")
                        .tag(SidebarSection.permissions)
                    Label("Docs", systemImage: "book")
                        .tag(SidebarSection.docs)
                }
            }
            .listStyle(.sidebar)
            .navigationTitle("MacCrab")
        } detail: {
            switch selectedSection {
            case .overview:
                OverviewDashboard(appState: appState, selectedSection: $selectedSection)
            case .alerts:
                AlertDashboard(appState: appState)
            case .events:
                EventStream(appState: appState)
            case .rules:
                RuleBrowser(appState: appState)
            case .prevention:
                PreventionView(appState: appState)
            case .aiGuard:
                AIActivityView(appState: appState)
            case .threatIntel:
                ThreatIntelView(appState: appState)
            case .integrations:
                IntegrationsView(appState: appState)
            case .permissions:
                TCCTimeline(appState: appState)
            case .docs:
                DocsView()
            case nil:
                OverviewDashboard(appState: appState, selectedSection: $selectedSection)
            }
        }
        .frame(minWidth: 950, minHeight: 600)
        .toolbar {
            ToolbarItem(placement: .automatic) {
                HStack(spacing: 6) {
                    Circle()
                        .fill(appState.isConnected ? Color.green : Color.red)
                        .frame(width: 7, height: 7)
                    Text(appState.isConnected ? "\(appState.eventsPerSecond) ev/s" : "Offline")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                        .fixedSize()
                }
            }
            ToolbarItem(placement: .automatic) {
                Button {
                    Task { await appState.refresh() }
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .accessibilityLabel("Refresh")
                .keyboardShortcut("r", modifiers: .command)
            }
        }
    }
}
