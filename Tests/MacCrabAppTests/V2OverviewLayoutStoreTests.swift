// V2OverviewLayoutStoreTests.swift
// The customizable Overview dashboard's persisted layout model: defaults,
// reorder, resize (span cycling), hide/show, reset, persistence round-trip,
// and upgrade migration (unknown ids dropped, new widgets appended, invalid
// spans clamped).

import Testing
import Foundation
@testable import MacCrabApp

@MainActor
@Suite("V2OverviewLayoutStore")
struct V2OverviewLayoutStoreTests {

    /// A fresh, isolated UserDefaults so tests never touch the real domain or
    /// each other.
    private func freshDefaults() -> UserDefaults {
        let suite = "test.v2overview.\(UUID().uuidString)"
        let d = UserDefaults(suiteName: suite)!
        d.removePersistentDomain(forName: suite)
        return d
    }

    @Test("fresh install shows all widgets, in catalog order, at default spans")
    func defaults() {
        let store = V2OverviewLayoutStore(defaults: freshDefaults())
        #expect(store.items.count == V2OverviewWidget.allCases.count)
        #expect(store.items.allSatisfy { $0.visible })
        #expect(store.visibleOrdered.map { $0.widget } == V2OverviewWidget.allCases)
        for item in store.items {
            let w = V2OverviewWidget(rawValue: item.id)!
            #expect(item.span == w.defaultSpan)
        }
        #expect(store.hiddenWidgets.isEmpty)
        #expect(!store.allHidden)
    }

    @Test("hide removes from the grid and offers the widget for re-adding; show re-appends it")
    func hideAndShow() {
        let store = V2OverviewLayoutStore(defaults: freshDefaults())
        store.hide(V2OverviewWidget.kpiEventRate.rawValue)
        #expect(!store.visibleOrdered.contains { $0.widget == .kpiEventRate })
        #expect(store.hiddenWidgets.contains(.kpiEventRate))

        store.show(V2OverviewWidget.kpiEventRate.rawValue)
        #expect(store.visibleOrdered.contains { $0.widget == .kpiEventRate })
        // Re-shown widgets append to the end so they're easy to find.
        #expect(store.visibleOrdered.last?.widget == .kpiEventRate)
        #expect(store.hiddenWidgets.isEmpty)
    }

    @Test("move places a widget just before its target")
    func reorder() {
        let store = V2OverviewLayoutStore(defaults: freshDefaults())
        // Move forensics (last) to just before the first KPI.
        store.move(V2OverviewWidget.forensics.rawValue, before: V2OverviewWidget.kpiSecurityGrade.rawValue)
        #expect(store.visibleOrdered.first?.widget == .forensics)
        #expect(store.visibleOrdered.dropFirst().first?.widget == .kpiSecurityGrade)
    }

    @Test("cycleSpan walks the widget's allowed spans and wraps")
    func resize() {
        let store = V2OverviewLayoutStore(defaults: freshDefaults())
        // A KPI tile allows [1, 2]; default is 1.
        let id = V2OverviewWidget.kpiOpenAlerts.rawValue
        #expect(store.span(for: id) == 1)
        store.cycleSpan(id)
        #expect(store.span(for: id) == 2)
        store.cycleSpan(id)
        #expect(store.span(for: id) == 1)   // wrapped
    }

    @Test("reset restores the default layout")
    func reset() {
        let store = V2OverviewLayoutStore(defaults: freshDefaults())
        store.hide(V2OverviewWidget.forensics.rawValue)
        store.cycleSpan(V2OverviewWidget.kpiOpenAlerts.rawValue)
        store.move(V2OverviewWidget.forensics.rawValue, before: V2OverviewWidget.kpiSecurityGrade.rawValue)
        store.reset()
        #expect(store.visibleOrdered.map { $0.widget } == V2OverviewWidget.allCases)
        #expect(store.items.allSatisfy { $0.visible })
    }

    @Test("reorder persists only after commit (one write per drag, not per hover-step)")
    func reorderCommit() {
        let d = freshDefaults()
        let a = V2OverviewLayoutStore(defaults: d)
        a.move(V2OverviewWidget.forensics.rawValue, before: V2OverviewWidget.kpiSecurityGrade.rawValue)
        // Mid-drag (not committed) → a freshly-loaded store still sees defaults.
        #expect(V2OverviewLayoutStore(defaults: d).visibleOrdered.first?.widget == .kpiSecurityGrade)
        a.commit()   // drag ends
        #expect(V2OverviewLayoutStore(defaults: d).visibleOrdered.first?.widget == .forensics)
    }

    @Test("clampSpan picks the smaller span on a distance tie")
    func clampTie() throws {
        // alertHistogram allows [2, 4]; a stored span of 3 is equidistant — the
        // nearest-tie must resolve to the SMALLER span (2), not the larger.
        let d = freshDefaults()
        let stored: [V2OverviewLayoutStore.Item] = [
            .init(id: V2OverviewWidget.alertHistogram.rawValue, visible: true, span: 3),
        ]
        d.set(try JSONEncoder().encode(stored), forKey: "v2.overview.layout")
        let store = V2OverviewLayoutStore(defaults: d)
        #expect(store.span(for: V2OverviewWidget.alertHistogram.rawValue) == 2)
    }

    @Test("layout persists across store instances sharing the same defaults")
    func persistenceRoundTrip() {
        let d = freshDefaults()
        let a = V2OverviewLayoutStore(defaults: d)
        a.hide(V2OverviewWidget.quickActions.rawValue)
        a.cycleSpan(V2OverviewWidget.kpiThreatIntel.rawValue)   // 1 -> 2

        let b = V2OverviewLayoutStore(defaults: d)   // reloads from disk
        #expect(b.hiddenWidgets.contains(.quickActions))
        #expect(b.span(for: V2OverviewWidget.kpiThreatIntel.rawValue) == 2)
    }

    @Test("migration: drops unknown ids, appends new catalog widgets, clamps bad spans")
    func migration() throws {
        let d = freshDefaults()
        // A stored layout from a hypothetical older/forked build: one unknown
        // widget, an out-of-range span on a KPI, and missing the rest.
        let stored: [V2OverviewLayoutStore.Item] = [
            .init(id: "bogus.removed.widget", visible: true, span: 1),
            .init(id: V2OverviewWidget.kpiSecurityGrade.rawValue, visible: true, span: 7),  // KPI allows [1,2]
            .init(id: V2OverviewWidget.forensics.rawValue, visible: false, span: 2),
        ]
        d.set(try JSONEncoder().encode(stored), forKey: "v2.overview.layout")

        let store = V2OverviewLayoutStore(defaults: d)
        let ids = store.items.map { $0.id }
        #expect(!ids.contains("bogus.removed.widget"))                 // unknown dropped
        #expect(store.items.count == V2OverviewWidget.allCases.count)  // all catalog widgets present
        // Invalid span clamped to the nearest allowed (7 -> 2).
        #expect(store.span(for: V2OverviewWidget.kpiSecurityGrade.rawValue) == 2)
        // Preserved a stored "hidden" decision.
        #expect(store.hiddenWidgets.contains(.forensics))
        // A catalog widget the stored layout never knew about is present + visible.
        #expect(store.visibleOrdered.contains { $0.widget == .kpiAIGuard })
    }
}
