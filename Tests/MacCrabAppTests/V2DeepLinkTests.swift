// V2DeepLinkTests.swift
// MacCrabAppTests
//
// Pin the V2DeepLink contract: maccrab://<workspace>/<tab>?entity=...&filters=...
// round-trips. Tests cover scheme rejection, unknown workspace, missing tab,
// filter ordering determinism, and the parse(url:) → goto(_:) pipeline used
// by the deep-link handler in V2RootView.

import Testing
import Foundation
@testable import MacCrabApp

@Suite("V2DeepLink")
struct V2DeepLinkTests {

    @Test("builds maccrab://alerts/open?entity=alt-001 for a tab + entity destination")
    func buildAlertsOpenWithEntity() throws {
        let dest = V2NavigationDestination(
            workspace: .alerts,
            tab: .alertsOpen,
            entityId: "alt-001"
        )
        let url = try #require(V2DeepLink.url(for: dest))
        #expect(url.scheme == "maccrab")
        #expect(url.host == "alerts")
        #expect(url.path == "/alertsopen")
        let comps = try #require(URLComponents(url: url, resolvingAgainstBaseURL: false))
        let items = comps.queryItems ?? []
        #expect(items.contains(URLQueryItem(name: "entity", value: "alt-001")))
    }

    @Test("builds workspace-only URL when no tab is supplied")
    func buildWorkspaceOnly() throws {
        let dest = V2NavigationDestination(workspace: .overview)
        let url = try #require(V2DeepLink.url(for: dest))
        #expect(url.scheme == "maccrab")
        #expect(url.host == "overview")
        #expect(url.path.isEmpty)
        #expect(url.query == nil)
    }

    @Test("query parameter ordering is deterministic (sorted by key)")
    func filterOrderingIsDeterministic() throws {
        let dest = V2NavigationDestination(
            workspace: .alerts,
            tab: .alertsOpen,
            entityId: "x",
            filters: ["z": "1", "a": "2", "m": "3"]
        )
        let url = try #require(V2DeepLink.url(for: dest))
        // entity is appended before sorted filters; sorted filters follow alphabetically.
        let query = try #require(url.query)
        // Expect a, m, z in that order (z is last).
        let aIdx = try #require(query.range(of: "a=2")).lowerBound
        let mIdx = try #require(query.range(of: "m=3")).lowerBound
        let zIdx = try #require(query.range(of: "z=1")).lowerBound
        #expect(aIdx < mIdx)
        #expect(mIdx < zIdx)
    }

    @Test("parses maccrab://alerts/alertsopen?entity=alt-001 into a destination")
    func parseAlertsOpen() throws {
        let url = try #require(URL(string: "maccrab://alerts/alertsopen?entity=alt-001"))
        let dest = try #require(V2DeepLink.parse(url))
        #expect(dest.workspace == .alerts)
        #expect(dest.tab == .alertsOpen)
        #expect(dest.entityId == "alt-001")
        #expect(dest.filters.isEmpty)
    }

    @Test("parses with filters AND entity together")
    func parseWithFiltersAndEntity() throws {
        let url = try #require(URL(string: "maccrab://alerts/alertsopen?entity=alt-1&severity=high&q=osascript"))
        let dest = try #require(V2DeepLink.parse(url))
        #expect(dest.entityId == "alt-1")
        #expect(dest.filters["severity"] == "high")
        #expect(dest.filters["q"] == "osascript")
    }

    @Test("rejects non-maccrab schemes")
    func rejectsForeignScheme() throws {
        let url = try #require(URL(string: "https://maccrab.com/alerts/open"))
        #expect(V2DeepLink.parse(url) == nil)
    }

    @Test("rejects unknown workspace host")
    func rejectsUnknownWorkspace() throws {
        let url = try #require(URL(string: "maccrab://made-up/whatever"))
        #expect(V2DeepLink.parse(url) == nil)
    }

    @Test("workspace-only URL parses with nil tab")
    func parseWorkspaceOnly() throws {
        let url = try #require(URL(string: "maccrab://overview"))
        let dest = try #require(V2DeepLink.parse(url))
        #expect(dest.workspace == .overview)
        #expect(dest.tab == nil)
        #expect(dest.entityId == nil)
    }

    @Test("round-trips a destination with all fields populated")
    func roundTrip() throws {
        let original = V2NavigationDestination(
            workspace: .detection,
            tab: .detectionRules,
            entityId: "rule.abc",
            filters: ["q": "credential"]
        )
        let url = try #require(V2DeepLink.url(for: original))
        let recovered = try #require(V2DeepLink.parse(url))
        #expect(recovered == original)
    }

    @Test("tab match is case-insensitive against the workspace's tab list")
    func tabMatchIsCaseInsensitive() throws {
        // The encoder writes lowercased paths, but parse should also
        // accept any case in case a human types the URL by hand.
        let url = try #require(URL(string: "maccrab://alerts/AlertsOpen"))
        let dest = try #require(V2DeepLink.parse(url))
        #expect(dest.tab == .alertsOpen)
    }

    // MARK: - v1.17 legacy Forensics redirects (audit-D)

    @Test("legacy investigation/forensicsCases redirects to forensics/forensicsScans")
    func testLegacyForensicsCasesRedirect() throws {
        let url = try #require(URL(string: "maccrab://investigation/investigationForensicsCases"))
        let dest = try #require(V2DeepLink.parse(url))
        #expect(dest.workspace == .forensics)
        #expect(dest.tab == .forensicsScans)
    }

    @Test("legacy investigation/forensicsPlugins lands on forensicsScans (rc.4 — Plugins tab removed)")
    func testLegacyForensicsPluginsRedirect() throws {
        let url = try #require(URL(string: "maccrab://investigation/investigationForensicsPlugins"))
        let dest = try #require(V2DeepLink.parse(url))
        #expect(dest.workspace == .forensics)
        #expect(dest.tab == .forensicsScans)
    }

    @Test("legacy investigation/forensicsTierB lands on forensicsScans (rc.4 — Tier B + Plugins tabs both removed)")
    func testLegacyForensicsTierBRedirect() throws {
        let url = try #require(URL(string: "maccrab://investigation/investigationForensicsTierB"))
        let dest = try #require(V2DeepLink.parse(url))
        #expect(dest.workspace == .forensics)
        #expect(dest.tab == .forensicsScans)
    }

    @Test("legacy investigation/forensicsArtifacts lands on forensicsScans (rc.4 — Evidence tab removed; lives in scan detail)")
    func testLegacyForensicsArtifactsRedirect() throws {
        let url = try #require(URL(string: "maccrab://investigation/investigationForensicsArtifacts"))
        let dest = try #require(V2DeepLink.parse(url))
        #expect(dest.workspace == .forensics)
        #expect(dest.tab == .forensicsScans)
    }

    @Test("legacy investigation/forensicsFindings redirects to forensics/forensicsFindings")
    func testLegacyForensicsFindingsRedirect() throws {
        let url = try #require(URL(string: "maccrab://investigation/investigationForensicsFindings"))
        let dest = try #require(V2DeepLink.parse(url))
        #expect(dest.workspace == .forensics)
        #expect(dest.tab == .forensicsFindings)
    }

    @Test("non-forensics investigation tabs pass through unchanged")
    func testInvestigationNonForensicsPassThrough() throws {
        let url = try #require(URL(string: "maccrab://investigation/investigationTraceGraph"))
        let dest = try #require(V2DeepLink.parse(url))
        #expect(dest.workspace == .investigation)
        #expect(dest.tab == .investigationTraceGraph)
    }
    // APPCORE-01: the scene .onOpenURL bridge hands OS-delivered URLs to
    // V2DashboardState.goto(url:). Pin that a valid link navigates and a
    // malformed link raises an error toast without crashing or moving the
    // workspace — the safe-handling contract the new wiring relies on.
    @Test("goto(url:) navigates on a valid maccrab:// deep link")
    @MainActor
    func testGotoURLNavigatesValidLink() throws {
        let state = V2DashboardState()
        let url = try #require(URL(string: "maccrab://alerts/alertsopen?entity=alt-001"))
        state.goto(url: url)
        #expect(state.currentWorkspace == .alerts)
        #expect(state.selectedTabs[.alerts] == .alertsOpen)
        #expect(state.toast?.kind != .error)
    }

    @Test("goto(url:) shows an error toast and does not navigate on a malformed link")
    @MainActor
    func testGotoURLMalformedLinkIsSafe() throws {
        let state = V2DashboardState()
        let before = state.currentWorkspace
        let url = try #require(URL(string: "maccrab://bogus/zzz"))
        state.goto(url: url)
        #expect(state.currentWorkspace == before)
        #expect(state.toast?.kind == .error)
    }
}
