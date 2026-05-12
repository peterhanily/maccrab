// V2NavigationHistoryTests.swift
// MacCrabAppTests
//
// Pin the V2NavigationHistory contract: bounded back/forward stack
// powering the v2 dashboard's nav undo (⌘[/⌘]). Tests cover cursor
// movement, forward-branch drop, cap eviction, and current accessor.

import Testing
import Foundation
@testable import MacCrabApp

@Suite("V2NavigationHistory")
struct V2NavigationHistoryTests {

    private func dest(_ ws: V2Workspace, _ tab: V2WorkspaceTab? = nil) -> V2NavigationDestination {
        V2NavigationDestination(workspace: ws, tab: tab)
    }

    @Test("empty history has no current and cannot go back or forward")
    func emptyState() {
        let history = V2NavigationHistory()
        #expect(history.current == nil)
        #expect(history.canGoBack == false)
        #expect(history.canGoForward == false)
    }

    @Test("push appends and cursor lands at the new entry")
    func pushAdvancesCursor() {
        var history = V2NavigationHistory()
        history.push(dest(.overview))
        #expect(history.current == dest(.overview))
        // A single entry is not enough to go back (need a prior one).
        #expect(history.canGoBack == false)
        #expect(history.canGoForward == false)

        history.push(dest(.alerts, .alertsOpen))
        #expect(history.current == dest(.alerts, .alertsOpen))
        #expect(history.canGoBack == true)
        #expect(history.canGoForward == false)
    }

    @Test("back/forward walk the stack without dropping entries")
    func backForwardWalk() {
        var history = V2NavigationHistory()
        history.push(dest(.overview))
        history.push(dest(.alerts, .alertsOpen))
        history.push(dest(.detection, .detectionRules))

        let back1 = history.back()
        #expect(back1 == dest(.alerts, .alertsOpen))
        #expect(history.canGoBack == true)
        #expect(history.canGoForward == true)

        let back2 = history.back()
        #expect(back2 == dest(.overview))
        #expect(history.canGoBack == false)
        #expect(history.canGoForward == true)

        let fwd1 = history.forward()
        #expect(fwd1 == dest(.alerts, .alertsOpen))
        let fwd2 = history.forward()
        #expect(fwd2 == dest(.detection, .detectionRules))
        #expect(history.canGoForward == false)
    }

    @Test("pushing after back drops the forward branch")
    func pushAfterBackDropsForward() {
        var history = V2NavigationHistory()
        history.push(dest(.overview))
        history.push(dest(.alerts, .alertsOpen))
        history.push(dest(.detection, .detectionRules))
        _ = history.back()
        _ = history.back()
        // Cursor now at .overview. A new push drops .alerts and .detection.
        history.push(dest(.investigation, .investigationTraceGraph))
        #expect(history.current == dest(.investigation, .investigationTraceGraph))
        #expect(history.canGoForward == false)
        #expect(history.entries.count == 2)
    }

    @Test("cap evicts the oldest entries and shifts the cursor")
    func capEvictsOldest() {
        var history = V2NavigationHistory(cap: 3)
        history.push(dest(.overview))
        history.push(dest(.alerts))
        history.push(dest(.detection))
        history.push(dest(.events))
        // .overview should have been dropped.
        #expect(history.entries.count == 3)
        #expect(history.entries.first == dest(.alerts))
        #expect(history.current == dest(.events))
    }

    @Test("back returns nil when at the front of the stack")
    func backAtFrontReturnsNil() {
        var history = V2NavigationHistory()
        history.push(dest(.overview))
        #expect(history.back() == nil)
        // Cursor unchanged.
        #expect(history.current == dest(.overview))
    }

    @Test("forward returns nil when at the end of the stack")
    func forwardAtEndReturnsNil() {
        var history = V2NavigationHistory()
        history.push(dest(.overview))
        history.push(dest(.alerts))
        #expect(history.forward() == nil)
        #expect(history.current == dest(.alerts))
    }
}
