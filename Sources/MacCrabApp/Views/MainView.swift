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
    @ObservedObject var sysextManager: SystemExtensionManager
    @State private var selectedSection: SidebarSection? = .overview
    @Environment(\.accessibilityReduceMotion) var reduceMotion
    @Environment(\.accessibilityShowButtonShapes) var showButtonShapes
    @AppStorage("pollIntervalSeconds") private var pollIntervalSeconds: Int = 5

    /// Timer-driven refresh so the dashboard updates automatically when the
    /// daemon writes new events/alerts to the database.
    @State private var pollTimer: Timer? = nil

    private var hasCriticalAlerts: Bool {
        appState.dashboardAlerts.contains {
            !$0.ruleId.hasPrefix("maccrab.campaign.") && $0.severity == .critical
            && !$0.suppressed && !appState.isPatternSuppressed($0)
        }
    }

    enum SidebarSection: String, CaseIterable, Hashable {
        case overview = "Overview"
        case alerts = "Alerts"
        case campaigns = "Campaigns"
        case events = "Events"
        case rules = "Rules"
        // Protection
        case prevention = "Prevention"
        case aiGuard = "AI Guard"
        case browserExtensions = "Browser Extensions"
        // Intelligence
        case threatIntel = "Threat Intel"
        case packageFreshness = "Package Freshness"
        case aiAnalysis = "AI Analysis"
        case integrations = "Integrations"
        // System
        case permissions = "Permissions"
        case esHealth = "ES Health"
        case docs = "Docs"

        /// Whether this section should be shown in the sidebar at the
        /// given complexity mode. Used by MainView to hide analyst-heavy
        /// views for Basic/Standard users while leaving Advanced untouched.
        func visible(in mode: UIMode) -> Bool {
            switch mode {
            case .basic:
                switch self {
                case .overview, .alerts, .prevention, .permissions, .docs:
                    return true
                default:
                    return false
                }
            case .standard:
                switch self {
                case .rules, .threatIntel, .packageFreshness, .aiAnalysis, .esHealth:
                    return false
                default:
                    return true
                }
            case .advanced:
                return true
            }
        }
    }

    @AppStorage(UIMode.storageKey) private var uiModeRaw: String = UIMode.advanced.rawValue

    private var uiMode: UIMode {
        UIMode(rawValue: uiModeRaw) ?? .advanced
    }

    /// True when at least one item in the group would be visible in the
    /// current mode — used to hide Section headers that would otherwise
    /// render empty.
    private func groupHasVisibleItems(_ items: [SidebarSection]) -> Bool {
        items.contains { $0.visible(in: uiMode) }
    }

    private var browserExtensionAlertCount: Int {
        appState.dashboardAlerts.filter {
            $0.ruleTitle.contains("Extension Installed") || $0.ruleTitle.contains("Extension Modified")
        }.count
    }

    private var campaignCount: Int {
        appState.dashboardAlerts.filter {
            $0.ruleId.hasPrefix("maccrab.campaign.")
            && !$0.suppressed
            && !appState.isPatternSuppressed($0)
        }.count
    }

    var body: some View {
        NavigationSplitView {
            List(selection: $selectedSection) {
                if groupHasVisibleItems([.overview, .alerts, .campaigns, .events, .rules]) {
                    Section(String(localized: "sidebar.monitor", defaultValue: "Monitor")) {
                        if SidebarSection.overview.visible(in: uiMode) {
                            Label(String(localized: "sidebar.overview", defaultValue: "Overview"), systemImage: "gauge.with.dots.needle.33percent")
                                .tag(SidebarSection.overview)
                        }
                        if SidebarSection.alerts.visible(in: uiMode) {
                            Label(String(localized: "sidebar.alerts", defaultValue: "Alerts"), systemImage: "exclamationmark.triangle")
                                .badge(appState.totalAlerts)
                                .foregroundColor(hasCriticalAlerts ? .red : nil)
                                .tag(SidebarSection.alerts)
                        }
                        if SidebarSection.campaigns.visible(in: uiMode) {
                            Label(String(localized: "sidebar.campaigns", defaultValue: "Campaigns"), systemImage: "link.circle")
                                .badge(campaignCount)
                                .tag(SidebarSection.campaigns)
                        }
                        if SidebarSection.events.visible(in: uiMode) {
                            Label(String(localized: "sidebar.events", defaultValue: "Events"), systemImage: "list.bullet.rectangle")
                                .tag(SidebarSection.events)
                        }
                        if SidebarSection.rules.visible(in: uiMode) {
                            Label(String(localized: "sidebar.rules", defaultValue: "Rules"), systemImage: "shield.checkered")
                                .badge(appState.rulesLoaded)
                                .tag(SidebarSection.rules)
                        }
                    }
                }

                if groupHasVisibleItems([.prevention, .aiGuard, .browserExtensions]) {
                    Section(String(localized: "sidebar.protection", defaultValue: "Protection")) {
                        if SidebarSection.prevention.visible(in: uiMode) {
                            Label(String(localized: "sidebar.prevention", defaultValue: "Prevention"), systemImage: "hand.raised")
                                .tag(SidebarSection.prevention)
                        }
                        if SidebarSection.aiGuard.visible(in: uiMode) {
                            Label(String(localized: "sidebar.aiGuard", defaultValue: "AI Guard"), systemImage: "brain")
                                .tag(SidebarSection.aiGuard)
                        }
                        if SidebarSection.browserExtensions.visible(in: uiMode) {
                            Label(String(localized: "sidebar.browserExtensions", defaultValue: "Browser Extensions"), systemImage: "puzzlepiece.extension.fill")
                                .badge(browserExtensionAlertCount)
                                .tag(SidebarSection.browserExtensions)
                        }
                    }
                }

                if groupHasVisibleItems([.threatIntel, .packageFreshness, .aiAnalysis, .integrations]) {
                    Section(String(localized: "sidebar.intelligence", defaultValue: "Intelligence")) {
                        if SidebarSection.threatIntel.visible(in: uiMode) {
                            Label(String(localized: "sidebar.threatIntel", defaultValue: "Threat Intel"), systemImage: "binoculars")
                                .tag(SidebarSection.threatIntel)
                        }
                        if SidebarSection.packageFreshness.visible(in: uiMode) {
                            Label(String(localized: "sidebar.packageFreshness", defaultValue: "Package Freshness"), systemImage: "shippingbox.fill")
                                .tag(SidebarSection.packageFreshness)
                        }
                        if SidebarSection.aiAnalysis.visible(in: uiMode) {
                            Label(String(localized: "sidebar.aiAnalysis", defaultValue: "AI Analysis"), systemImage: "brain.head.profile")
                                .badge(appState.aiAnalysisAlerts.count)
                                .tag(SidebarSection.aiAnalysis)
                        }
                        if SidebarSection.integrations.visible(in: uiMode) {
                            Label(String(localized: "sidebar.integrations", defaultValue: "Integrations"), systemImage: "puzzlepiece.extension")
                                .tag(SidebarSection.integrations)
                        }
                    }
                }

                if groupHasVisibleItems([.permissions, .esHealth, .docs]) {
                    Section(String(localized: "sidebar.system", defaultValue: "System")) {
                        if SidebarSection.permissions.visible(in: uiMode) {
                            Label(String(localized: "sidebar.permissions", defaultValue: "Permissions"), systemImage: "lock.shield")
                                .tag(SidebarSection.permissions)
                        }
                        if SidebarSection.esHealth.visible(in: uiMode) {
                            Label(String(localized: "sidebar.esHealth", defaultValue: "ES Health"), systemImage: "waveform.path.ecg.rectangle.fill")
                                .tag(SidebarSection.esHealth)
                        }
                        if SidebarSection.docs.visible(in: uiMode) {
                            Label(String(localized: "sidebar.docs", defaultValue: "Docs"), systemImage: "book")
                                .tag(SidebarSection.docs)
                        }
                    }
                }
            }
            .listStyle(.sidebar)
            .navigationTitle("MacCrab")
        } detail: {
            switch selectedSection {
            case .overview:
                OverviewDashboard(appState: appState, sysextManager: sysextManager, selectedSection: $selectedSection)
            case .alerts:
                AlertDashboard(appState: appState)
            case .campaigns:
                CampaignView(appState: appState)
            case .events:
                EventStream(appState: appState)
            case .rules:
                RuleBrowser(appState: appState)
            case .prevention:
                PreventionView(appState: appState)
            case .aiGuard:
                AIActivityView(appState: appState)
            case .browserExtensions:
                BrowserExtensionsView(appState: appState)
            case .threatIntel:
                ThreatIntelView(appState: appState)
            case .packageFreshness:
                PackageFreshnessView(appState: appState)
            case .aiAnalysis:
                AIAnalysisView(appState: appState)
            case .integrations:
                IntegrationsView(appState: appState)
            case .permissions:
                TCCTimeline(appState: appState)
            case .esHealth:
                ESHealthView(appState: appState)
            case .docs:
                DocsView()
            case nil:
                OverviewDashboard(appState: appState, sysextManager: sysextManager, selectedSection: $selectedSection)
            }
        }
        .frame(minWidth: 950, minHeight: 600)
        // Daemon-disconnect banner — shown when connection is lost after initial
        // data load. The overview tab has its own connecting spinner for the
        // "never connected" case, so this targets the subsequent-disconnect case.
        .safeAreaInset(edge: .top, spacing: 0) {
            if !appState.isConnected && appState.rulesLoaded > 0 {
                VStack(spacing: 4) {
                    HStack(spacing: 10) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundColor(.yellow)
                            .accessibilityHidden(true)
                        Text(String(localized: "status.daemonOffline", defaultValue: "Daemon offline \u{2014} data may be stale"))
                            .font(.subheadline)
                            .foregroundColor(.primary)
                        Spacer()
                        Button("Retry") {
                            Task { await appState.refresh() }
                        }
                        .controlSize(.small)
                    }
                    HStack(spacing: 4) {
                        Text(String(localized: "status.daemonHint", defaultValue: "Start with:"))
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Text("sudo maccrabd")
                            .font(.system(.caption, design: .monospaced))
                            .foregroundColor(.secondary)
                            .textSelection(.enabled)
                        Spacer()
                    }
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 8)
                .background(.regularMaterial)
                .overlay(alignment: .bottom) {
                    Divider()
                }
                .accessibilityElement(children: .combine)
                .accessibilityLabel("Daemon offline. Start with sudo maccrabd.")
            }
        }
        .toolbar {
            ToolbarItem(placement: .automatic) {
                HStack(spacing: 6) {
                    Circle()
                        .fill(appState.isConnected ? Color.green : Color.red)
                        .frame(width: 7, height: 7)
                        .accessibilityHidden(true)
                    Text(appState.isConnected ? "\(appState.eventsPerSecond) ev/s" : "Offline")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                        .fixedSize()
                    if appState.llmStatus.isConfigured {
                        Divider().frame(height: 12)
                        Image(systemName: "brain.head.profile")
                            .font(.caption)
                            .foregroundColor(.green)
                            .help("AI: \(appState.llmStatus.provider)")
                            .accessibilityLabel("AI assistant configured: \(appState.llmStatus.provider)")
                    }
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
        .onAppear { startPolling() }
        .onDisappear { stopPolling() }
        .onChange(of: pollIntervalSeconds) { _ in
            // Restart timer when user changes the poll interval in Settings
            stopPolling()
            startPolling()
        }
    }

    private func startPolling() {
        guard pollTimer == nil else { return }
        let interval = TimeInterval(max(pollIntervalSeconds, 1))
        pollTimer = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { _ in
            Task { @MainActor in
                await appState.refresh()
            }
        }
    }

    private func stopPolling() {
        pollTimer?.invalidate()
        pollTimer = nil
    }
}
