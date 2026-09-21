// DashboardPublishGatingTests.swift
// v1.22.1: the dashboard's 5 s poll republished unchanged values.
//
// AppState is the @ObservedObject of V2DashboardShell, so every @Published write
// fires objectWillChange and forces a whole-tree SwiftUI transaction --
// V2FlowGridLayout then re-measures all 13 Overview widget subtrees. Sampling the
// installed 1.22.1.1156 app put 71-88% of non-idle main-thread samples in
// NSHostingView.beginTransaction -> GraphHost.flushTransactions ->
// LayoutEngineBox.sizeThatFits, against a measured 3.6% of one core.
//
// Two sites on the poll path wrote unconditionally:
//   - refreshRuleTelemetry(), the only refresher with no gate at all, while every
//     sibling (refreshStorageHealth, refreshRuleTamper, refreshHeartbeat,
//     refreshAgentLineage, refreshThreatIntelStats) carries the v1.7.11 mtime gate
//   - the fleet-status write, sourced from a process environment variable that
//     cannot change while the process lives
//
// The engine rewrites these snapshots every 30 s, so at a 5 s poll five of every
// six ticks published nothing new. These tests pin that a tick over unchanged
// inputs publishes nothing, and -- just as important -- that a real change still
// does, so the gate cannot be "fixed" into staleness.

import Combine
import MacCrabCore
import Foundation
import Testing
@testable import MacCrabApp

@Suite("Dashboard poll republishes only on change")
@MainActor
struct DashboardPublishGatingTests {
    private func temporaryDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-publish-gating-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true
        )
        return directory
    }

    /// Counts `objectWillChange` emissions, which is exactly what drives the
    /// SwiftUI transaction. Counting the publisher rather than the stored values
    /// is the point: assigning an equal value still emits.
    private func countingChanges(
        on state: AppState, _ body: () -> Void
    ) -> Int {
        var count = 0
        let token = state.objectWillChange.sink { _ in count += 1 }
        body()
        token.cancel()
        return count
    }

    @Test("A rule-telemetry refresh over an unchanged snapshot publishes nothing")
    func telemetryRefreshIsIdempotent() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let state = AppState(engineSource: .init(directory: directory.path),
                             startBackgroundWork: false)

        // First refresh establishes the baseline and is allowed to publish.
        state.refreshRuleTelemetry()

        // The engine rewrites this snapshot every 30 s; at a 5 s poll these are
        // the five ticks that previously republished identical values.
        let emissions = countingChanges(on: state) {
            for _ in 0..<5 { state.refreshRuleTelemetry() }
        }
        #expect(emissions == 0,
                "an unchanged snapshot must not dirty the view tree")
    }

    @Test("A changed rule-telemetry snapshot still publishes")
    func telemetryChangePublishes() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let state = AppState(engineSource: .init(directory: directory.path),
                             startBackgroundWork: false)
        state.refreshRuleTelemetry()

        // A gate that never republishes would be worse than the bug: the rule
        // browser would freeze at whatever it first read. Encode the real type
        // rather than hand-written JSON, so a schema change breaks this loudly
        // instead of silently producing an empty snapshot that compares equal.
        let stats = RuleEngine.RuleStats(
            ruleId: "publish-gating-fixture",
            evaluationCount: 7, fireCount: 3, totalExecNs: 1_234
        )
        let snapshot = RuleEngine.TelemetrySnapshot(
            writtenAt: Date(timeIntervalSince1970: 1_789_000_000),
            stats: [stats],
            loadedRuleIds: ["publish-gating-fixture"],
            enabledRuleIds: ["publish-gating-fixture"]
        )
        try JSONEncoder().encode(snapshot).write(
            to: directory.appendingPathComponent("rule_telemetry.json")
        )

        let emissions = countingChanges(on: state) {
            state.refreshRuleTelemetry()
        }
        #expect(emissions > 0,
                "a genuinely new snapshot must still reach the view")
    }

    @Test("Fleet status is Equatable so its poll write can be gated")
    func fleetStatusIsEquatable() {
        // The write is sourced from MACCRAB_FLEET_URL, which cannot change while
        // the process lives, so after the first tick it is always equal. Without
        // Equatable there is nothing to compare and the gate cannot exist.
        let a = AppState.FleetStatus(isConfigured: true, fleetURL: "https://fleet.example")
        let b = AppState.FleetStatus(isConfigured: true, fleetURL: "https://fleet.example")
        let c = AppState.FleetStatus(isConfigured: false, fleetURL: "")
        #expect(a == b)
        #expect(a != c)
    }

    // The poll-path refreshers must each decline to republish an unchanged
    // value. refreshRuleTelemetry was the one exception; this guards the class
    // rather than the single instance, since the cost is the publish, not the
    // read, and a new ungated refresher would reintroduce the whole-tree pass.
    @Test("Every poll-path snapshot refresher gates its publish")
    func pollPathRefreshersAreGated() throws {
        let source = try String(
            contentsOf: URL(fileURLWithPath: #filePath)
                .deletingLastPathComponent().deletingLastPathComponent()
                .deletingLastPathComponent()
                .appendingPathComponent("Sources/MacCrabApp/AppState.swift"),
            encoding: .utf8
        )
        let body = try #require(
            source.range(of: "func refreshRuleTelemetry()"),
            "refreshRuleTelemetry moved"
        )
        let window = String(source[body.lowerBound...].prefix(900))
        #expect(window.contains("if ruleTelemetry != context.statsByID"),
                "the telemetry dictionary write must be equality-gated")
        #expect(window.contains("if ruleTelemetryFreshness != context.freshness.rawValue"),
                "the freshness write must be equality-gated")
        // load() must still run every tick: freshness decays on wall time, so an
        // mtime early-return would pin a stopped engine at "current" forever.
        #expect(window.contains("RuleTelemetryContext.load(directory: dataDir)"),
                "freshness must keep being recomputed each tick")
    }

    @Test("The catalog's animated crab is gated on motion and window activity")
    func raveCrabAnimationIsGated() throws {
        let source = try String(
            contentsOf: URL(fileURLWithPath: #filePath)
                .deletingLastPathComponent().deletingLastPathComponent()
                .deletingLastPathComponent()
                .appendingPathComponent(
                    "Sources/MacCrabApp/V2/Workspaces/V2RaveCatalogBrowserView.swift"),
            encoding: .utf8
        )
        let view = try #require(
            source.range(of: "private struct RaveCrabView"),
            "RaveCrabView moved"
        )
        let window = String(source[view.lowerBound...].prefix(1400))
        // Strip comment lines: the prose below, and in the view itself, names the
        // very literal being banned.
        let code = window
            .split(separator: "\n", omittingEmptySubsequences: false)
            .filter { !$0.trimmingCharacters(in: .whitespaces).hasPrefix("//") }
            .joined(separator: "\n")
        // `.animation` runs at display refresh and dirties the AttributeGraph on
        // every tick, which V2CrabWidget measured at ~20-25% of a core.
        #expect(!code.contains("TimelineView(.animation)"),
                "the display-rate schedule must not come back")
        #expect(code.contains("TimelineView(.periodic("),
                "the bounded periodic schedule must be used")
        #expect(window.contains("controlActiveState == .inactive"),
                "animation must freeze when the window is not active")
        #expect(window.contains("reduceMotion"),
                "animation must honour Reduce Motion")
    }
}
