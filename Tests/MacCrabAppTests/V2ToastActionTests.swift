// V2ToastActionTests.swift
// v1.21.4: V2Toast gained an optional inline action (e.g. "Undo") — a labelled
// button + callback rendered next to Dismiss. These tests pin the model: the
// existing init still works with the action defaulted nil, the action stores
// its title, invoking the handler runs the callback, and Equatable stays
// identity-by-id after the custom `==` replaced the synthesized one.

import Testing
@testable import MacCrabApp

@Suite("V2Toast inline action model (v1.21.4)")
struct V2ToastActionTests {

    /// Reference box so the @Sendable handler has an observable side effect.
    private final class Counter: @unchecked Sendable { var count = 0 }

    @Test("existing init still compiles with no action and defaults it to nil")
    func defaultsToNil() {
        let toast = V2Toast(kind: .success, title: "Alert suppressed", detail: "rule.id")
        #expect(toast.action == nil)
    }

    @Test("action carries its title and its handler runs the callback")
    func actionTitleAndHandler() {
        let counter = Counter()
        let toast = V2Toast(
            kind: .success, title: "Bulk suppress", detail: "3 alerts suppressed",
            action: V2ToastAction(title: "Undo") { counter.count += 1 })
        #expect(toast.action?.title == "Undo")
        #expect(counter.count == 0, "handler must not fire until invoked")
        toast.action?.handler()
        #expect(counter.count == 1, "invoking the handler runs the callback exactly once")
    }

    @Test("Equatable is identity-by-id and ignores the action closure")
    func equatableByID() {
        let a = V2Toast(kind: .info, title: "x", action: V2ToastAction(title: "Undo") {})
        let b = V2Toast(kind: .info, title: "x", action: V2ToastAction(title: "Undo") {})
        #expect(a == a, "same instance is equal to itself")
        #expect(a != b, "distinct toasts have distinct ids and are unequal")
    }
}
