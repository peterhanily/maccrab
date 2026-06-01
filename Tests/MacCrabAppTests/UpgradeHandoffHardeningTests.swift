// UpgradeHandoffHardeningTests.swift
// MacCrabAppTests
//
// Pin the pure decision logic behind the v1.17.x upgrade-handoff
// hardening (commit 969eeb9). The lifecycle wiring (timers, sysext
// state observation, on-disk store probes) isn't hermetically testable,
// so the load-bearing decisions were extracted into nonisolated static
// functions and pinned here:
//   - AlertNotifier.isHandoffGated      — the fail-open banner gate
//   - V2DashboardState.bootPhaseDidBecomeReady — the reconnect edge
//   - V2DashboardState.shouldAdoptReprobe       — the provider-swap guard

import Testing
import Foundation
@testable import MacCrabApp

@Suite("Upgrade-handoff hardening (pure decisions)")
struct UpgradeHandoffHardeningTests {

    // MARK: - ITEM 1: banner gate (fail-open)

    private static let now = Date(timeIntervalSince1970: 1_000)

    @Test("nil deadline is never gated")
    func gateNilIsOpen() {
        #expect(AlertNotifier.isHandoffGated(suppressUntil: nil, now: Self.now) == false)
    }

    @Test("a future deadline gates")
    func gateFutureSuppresses() {
        let future = Date(timeIntervalSince1970: 1_030)
        #expect(AlertNotifier.isHandoffGated(suppressUntil: future, now: Self.now) == true)
    }

    @Test("FAIL-OPEN: a past deadline does NOT gate (posting resumes)")
    func gatePastIsFailOpen() {
        let past = Date(timeIntervalSince1970: 970)
        #expect(AlertNotifier.isHandoffGated(suppressUntil: past, now: Self.now) == false)
    }

    @Test("the deadline instant itself is not gated (now < until is strict)")
    func gateBoundaryIsOpen() {
        #expect(AlertNotifier.isHandoffGated(suppressUntil: Self.now, now: Self.now) == false)
    }

    // MARK: - ITEM 2: bootPhase non-ready→ready edge

    @Test("fires on the first reach of ready from any non-ready phase")
    func edgeFiresOnReachingReady() {
        #expect(V2DashboardState.bootPhaseDidBecomeReady(previous: nil, next: "ready"))
        #expect(V2DashboardState.bootPhaseDidBecomeReady(previous: "starting", next: "ready"))
        #expect(V2DashboardState.bootPhaseDidBecomeReady(previous: "stores_ready", next: "ready"))
    }

    @Test("does NOT fire on the steady ready→ready stream (no thrash)")
    func edgeIgnoresSteadyReady() {
        #expect(V2DashboardState.bootPhaseDidBecomeReady(previous: "ready", next: "ready") == false)
    }

    @Test("does NOT fire on non-ready transitions or leaving ready")
    func edgeIgnoresOthers() {
        #expect(V2DashboardState.bootPhaseDidBecomeReady(previous: nil, next: "starting") == false)
        #expect(V2DashboardState.bootPhaseDidBecomeReady(previous: "ready", next: "starting") == false)
        #expect(V2DashboardState.bootPhaseDidBecomeReady(previous: "ready", next: nil) == false)
        #expect(V2DashboardState.bootPhaseDidBecomeReady(previous: nil, next: nil) == false)
    }

    // MARK: - ITEM 2: provider-swap guard

    @Test("mock current always adopts the re-probe (mock→live)")
    func swapFromMock() {
        #expect(V2DashboardState.shouldAdoptReprobe(
            currentMode: .mock, currentDir: nil, currentDegraded: false,
            reprobeDir: "/Library/Application Support/MacCrab", reprobeDegraded: false))
    }

    @Test("healthy live on the SAME dir is a no-op (no thrash, no steady-state regression)")
    func noSwapWhenHealthySameDir() {
        #expect(V2DashboardState.shouldAdoptReprobe(
            currentMode: .live, currentDir: "/a", currentDegraded: false,
            reprobeDir: "/a", reprobeDegraded: false) == false)
    }

    @Test("a changed data directory adopts the re-probe (system⇄user-home)")
    func swapOnDirChange() {
        #expect(V2DashboardState.shouldAdoptReprobe(
            currentMode: .live, currentDir: "/a", currentDegraded: false,
            reprobeDir: "/b", reprobeDegraded: false))
    }

    @Test("MUST-FIX: a DEGRADED live provider is recovered by a clean re-probe")
    func swapRecoversDegraded() {
        // The empty-dashboard case: a store's DB was absent at the launch
        // probe (mode==.live but lastErrorDescription != nil, alerts()==[]).
        // A clean re-probe on the same dir MUST replace it.
        #expect(V2DashboardState.shouldAdoptReprobe(
            currentMode: .live, currentDir: "/a", currentDegraded: true,
            reprobeDir: "/a", reprobeDegraded: false))
    }

    @Test("a still-degraded re-probe is NOT adopted (keep current, wait for next edge)")
    func noSwapWhenReprobeStillDegraded() {
        #expect(V2DashboardState.shouldAdoptReprobe(
            currentMode: .live, currentDir: "/a", currentDegraded: true,
            reprobeDir: "/a", reprobeDegraded: true) == false)
    }

    @Test("a healthy current is never downgraded to a degraded re-probe")
    func noDowngradeOfHealthy() {
        #expect(V2DashboardState.shouldAdoptReprobe(
            currentMode: .live, currentDir: "/a", currentDegraded: false,
            reprobeDir: "/a", reprobeDegraded: true) == false)
    }
}
