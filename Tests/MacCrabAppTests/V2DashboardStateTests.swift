// V2DashboardStateTests.swift
// MacCrabAppTests
//
// Pin the V2DashboardState contract for navigation and toasts. State
// is @MainActor + ObservableObject; tests run on MainActor and clear
// the UserDefaults persistence keys before each case so that one
// test's recents/tabs/workspace don't leak into the next.

import Testing
import Foundation
import SwiftUI
@testable import MacCrabApp

@MainActor
@Suite("V2DashboardState")
struct V2DashboardStateTests {

    private static let persistenceKeys = [
        "v2.dashboard.workspace",
        "v2.dashboard.selectedTabs",
        "v2.dashboard.recents",
    ]

    private func freshState() -> V2DashboardState {
        for key in Self.persistenceKeys {
            UserDefaults.standard.removeObject(forKey: key)
        }
        return V2DashboardState()
    }

    @Test("default workspace is .overview on a clean install")
    func initialState() {
        let s = freshState()
        #expect(s.currentWorkspace == .overview)
        #expect(s.paletteOpen == false)
        #expect(s.toast == nil)
    }

    @Test("selectTab updates currentWorkspace AND remembers tab choice per workspace")
    func selectTabPersistsSelection() {
        let s = freshState()
        s.selectTab(.alertsCampaigns)
        #expect(s.currentWorkspace == .alerts)
        #expect(s.selectedTabs[.alerts] == .alertsCampaigns)
    }

    @Test("switchWorkspace lands on the workspace's default tab on first visit")
    func switchWorkspaceUsesDefaultTab() {
        let s = freshState()
        s.switchWorkspace(.alerts)
        #expect(s.currentWorkspace == .alerts)
        #expect(s.selectedTabs[.alerts] == .alertsOpen)
    }

    @Test("switchWorkspace restores last-visited tab on return visit")
    func switchWorkspaceRestoresLastTab() {
        let s = freshState()
        s.selectTab(.alertsCampaigns)
        s.switchWorkspace(.overview)
        s.switchWorkspace(.alerts)
        #expect(s.selectedTabs[.alerts] == .alertsCampaigns)
    }

    @Test("goto with recordHistory=true pushes to the back/forward stack")
    func gotoRecordsHistory() {
        let s = freshState()
        let dest = V2NavigationDestination(workspace: .detection, tab: .detectionRules)
        s.goto(dest)
        #expect(s.currentWorkspace == .detection)
        #expect(s.history.canGoBack == true)
    }

    @Test("command-palette modal=new navigation opens the rule wizard (bumps presentNewRuleTick)")
    func modalNewBumpsRuleWizardTick() {
        let s = freshState()
        let before = s.presentNewRuleTick
        s.goto(V2NavigationDestination(workspace: .detection, tab: .detectionRules, filters: ["modal": "new"]))
        #expect(s.currentWorkspace == .detection)
        #expect(s.presentNewRuleTick == before + 1, "modal=new must bump the wizard tick (palette dead-end fix)")
    }

    @Test("goBack and goForward navigate the history stack")
    func backForwardNavigate() {
        let s = freshState()
        s.goto(V2NavigationDestination(workspace: .alerts, tab: .alertsOpen))
        s.goto(V2NavigationDestination(workspace: .detection, tab: .detectionRules))
        s.goBack()
        #expect(s.currentWorkspace == .alerts)
        s.goForward()
        #expect(s.currentWorkspace == .detection)
    }

    @Test("applyFilters via URL pre-fills the alerts severity + search query")
    func applyFiltersForAlerts() throws {
        let s = freshState()
        let url = try #require(URL(string: "maccrab://alerts/alertsopen?severity=high&q=ssh"))
        s.goto(url: url)
        #expect(s.currentWorkspace == .alerts)
        #expect(s.alertSeverityFilter == .high)
        #expect(s.alertSearchQuery == "ssh")
    }

    @Test("applyFilters via URL pre-fills the detection rules search query")
    func applyFiltersForDetectionRules() throws {
        let s = freshState()
        let url = try #require(URL(string: "maccrab://detection/detectionrules?q=credential"))
        s.goto(url: url)
        #expect(s.currentWorkspace == .detection)
        #expect(s.ruleSearchQuery == "credential")
    }

    @Test("goto with an invalid URL surfaces an error toast and does not crash")
    func invalidURLSurfacesToast() throws {
        let s = freshState()
        let url = try #require(URL(string: "https://example.com"))
        s.goto(url: url)
        let toast = try #require(s.toast)
        #expect(toast.kind == .error)
    }

    @Test("showToast sets toast and dismissToast clears it synchronously")
    func toastLifecycle() {
        let s = freshState()
        s.showToast(V2Toast(kind: .info, title: "hello"))
        #expect(s.toast?.title == "hello")
        s.dismissToast()
        #expect(s.toast == nil)
    }

    @Test("recordRecent dedupes and caps recent destinations at 12")
    func recentDestinationsDedupAndCap() {
        let s = freshState()
        // Push 15 distinct destinations — each must include a tab or
        // entityId so recordRecent counts it.
        let tabs: [V2WorkspaceTab] = [
            .alertsOpen, .alertsCampaigns, .alertsHistory, .alertsSuppressions,
            .investigationTraceGraph, .investigationAgentTraces, .investigationAIAnalysis,
            .detectionRules, .detectionAIGuard, .detectionBrowser, .detectionMCP,
            .intelligenceThreatIntel, .intelligencePackageFreshness, .intelligenceIntegrations,
            .systemHealth,
        ]
        for tab in tabs {
            s.goto(V2NavigationDestination(workspace: tab.workspace, tab: tab))
        }
        #expect(s.recentDestinations.count == 12)
        // Re-pushing an existing destination moves it to the front, no growth.
        let head = s.recentDestinations.first
        s.goto(V2NavigationDestination(workspace: .alerts, tab: .alertsOpen))
        #expect(s.recentDestinations.count == 12)
        #expect(s.recentDestinations.first?.tab == .alertsOpen)
        #expect(s.recentDestinations.first != head)
    }

    @Test("currentTab returns the workspace's default tab when none was explicitly chosen")
    func currentTabDefaults() {
        let s = freshState()
        s.switchWorkspace(.alerts)
        #expect(s.currentTab() == .alertsOpen)
    }
}
