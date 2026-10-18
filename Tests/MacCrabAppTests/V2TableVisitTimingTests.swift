import AppKit
import SwiftUI
import Testing
@testable import MacCrabApp

/// Private unshown native hosts, inert text, injected clock/expiry/sink. These
/// exercise the actual host.layout callback, not pixels, rows or latency. No
/// AppState, provider, stores, live AX, preferences or background timers.
@MainActor
@Suite("Table host visit timing binding", .serialized)
struct V2TableVisitTimingTests {
    @MainActor private final class Fixture {
        let cache = V2TableHostCache(observeMemoryPressure: false, now: { 100 },
                                    scheduleExpiry: { _, _ in V2TableHostExpiry {} })
        let container = NSView(frame: NSRect(x: 0, y: 0, width: 640, height: 240))
        let window: NSWindow
        var summaries: [V2VisitTiming.Summary] = []
        var now: UInt64 = 100
        let modelRevision = UUID()
        var callbacks = 0
        var current = true
        var leases: [V2TableAttachmentLease] = []
        init() {
            window = NSWindow(contentRect: NSRect(x: -10000, y: -10000, width: 640, height: 240),
                              styleMask: [.borderless], backing: .buffered, defer: false)
            window.isReleasedWhenClosed = false
            window.contentView = container
        }
        func close() { cache.removeAll(); window.close() }
        func recorder() -> V2VisitTiming {
            V2VisitTiming(now: { [weak self] in self?.now ?? 0 },
                          emit: { [weak self] in self?.summaries.append($0) })
        }
        func input(_ lease: V2TableAttachmentLease) -> V2VisitTiming.AcceptedInput {
            .init(tableRevision: lease.inputRevision, modelRevision: modelRevision,
                  freshness: .fresh, content: .nonempty)
        }
        func observer(_ timing: V2VisitTiming, ticket: V2VisitTiming.Ticket) -> V2TableHostCache.NativeLayoutObserver {
            let revision = modelRevision
            return { [weak self, weak timing] lease in
                self?.callbacks += 1
                _ = timing?.nativeTableDidLayout(.init(tableRevision: lease.inputRevision,
                    modelRevision: revision, freshness: .fresh, content: .nonempty), for: ticket,
                    activeAttachment: lease.isActive, positiveViewport: true)
            }
        }
        func attach(key: Int = 1, timing: V2VisitTiming, ticket: V2VisitTiming.Ticket,
                    observer: V2TableHostCache.NativeLayoutObserver? = nil) throws -> V2TableHostCache.Attachment {
            let result = cache.attach(slot: .rules, key: key, scope: "inert-source", retainable: true,
                isCurrent: { [weak self] in self?.current == true }, environment: EnvironmentValues(),
                to: container, onNativeLayout: observer ?? self.observer(timing, ticket: ticket)) { lease in
                    leases.append(lease)
                    _ = timing.readAccepted(input(lease), for: ticket)
                    return Text("Synthetic table host")
                }
            return try #require(result)
        }
        func host() throws -> NSView { try #require(container.subviews.first) }
    }

    @Test("Same exact input root replacement keeps correlation but revokes the old attachment")
    func sameInputReplacement() throws {
        let fixture = Fixture(), timing = fixture.recorder()
        defer { fixture.close() }
        let ticket = timing.begin(.detection)
        let first = try fixture.attach(timing: timing, ticket: ticket)
        let host = try fixture.host(), old = try #require(fixture.leases.last)
        fixture.now = 110
        let second = try fixture.attach(timing: timing, ticket: ticket)
        let replacementHost = try fixture.host(), current = try #require(fixture.leases.last)
        #expect(host === replacementHost && first != second)
        #expect(old.inputRevision == current.inputRevision && !old.isActive && current.isActive)
        #expect(fixture.summaries.isEmpty)
        #expect(!timing.nativeTableDidLayout(fixture.input(old), for: ticket,
                                           activeAttachment: old.isActive, positiveViewport: true))
        fixture.cache.detach(first) // Late old dismantle must not remove the new host.
        #expect(host.superview === fixture.container)
        fixture.now = 120
        host.layout()
        #expect(fixture.callbacks == 1 && fixture.summaries.count == 1)
        #expect(fixture.summaries.first?.terminal == .nativeTableLayout)
        #expect(fixture.summaries.first?.readAcceptedNS == 0)
        #expect(fixture.summaries.first?.nativeTableLayoutNS == 20)
        host.layout()
        #expect(fixture.callbacks == 1, "Validated native delivery is one-shot, not every layout")
    }

    @Test("Changed full input keeps the active host but cannot complete the previous snapshot timing")
    func changedInputReplacement() throws {
        let fixture = Fixture(), timing = fixture.recorder()
        defer { fixture.close() }
        let ticket = timing.begin(.detection)
        _ = try fixture.attach(timing: timing, ticket: ticket)
        let host = try fixture.host(), old = try #require(fixture.leases.last)
        _ = try fixture.attach(key: 2, timing: timing, ticket: ticket)
        let replacementHost = try fixture.host(), current = try #require(fixture.leases.last)
        #expect(host === replacementHost && old.inputRevision != current.inputRevision)
        #expect(fixture.summaries.count == 1 && fixture.summaries.first?.terminal == .contextChanged)
        #expect(!timing.nativeTableDidLayout(fixture.input(old), for: ticket,
                                           activeAttachment: old.isActive, positiveViewport: true))
        host.layout()
        #expect(fixture.callbacks == 1 && fixture.summaries.count == 1)
        #expect(fixture.summaries.first?.nativeTableLayoutNS == nil)
    }

    @Test("Zero and unattached geometry remain pending; valid host layout delivers once")
    func nativeGeometryGuard() throws {
        let fixture = Fixture(), timing = fixture.recorder()
        defer { fixture.close() }
        let ticket = timing.begin(.detection)
        let attachment = try fixture.attach(timing: timing, ticket: ticket)
        let host = try fixture.host()
        host.frame.size = .zero
        host.layout()
        #expect(fixture.callbacks == 0 && fixture.summaries.isEmpty)
        host.frame = fixture.container.bounds
        fixture.window.contentView = nil
        #expect(host.window == nil)
        host.layout()
        #expect(fixture.callbacks == 0 && fixture.summaries.isEmpty)
        fixture.window.contentView = fixture.container
        host.frame = fixture.container.bounds
        #expect(host.window === fixture.window && host.bounds.width > 0 && host.bounds.height > 0)
        host.layout()
        #expect(fixture.callbacks == 1 && fixture.summaries.count == 1)
        fixture.cache.detach(attachment)
        host.layout()
        #expect(fixture.callbacks == 1 && host.superview == nil)
    }

    @Test("A detached retained host and saved callback cannot retain or resurrect its recorder")
    func weakRecorderAfterDetach() throws {
        let fixture = Fixture()
        defer { fixture.close() }
        var timing: V2VisitTiming? = fixture.recorder()
        weak let weakTiming = timing
        let ticket = timing!.begin(.detection)
        let callback = fixture.observer(timing!, ticket: ticket)
        let attachment = try fixture.attach(timing: timing!, ticket: ticket, observer: callback)
        let host = try fixture.host(), old = try #require(fixture.leases.last)
        #expect(weakTiming != nil && old.isActive)
        fixture.cache.detach(attachment)
        #expect(!old.isActive && host.superview == nil)
        timing = nil
        #expect(weakTiming == nil, "Neither native host nor stored callback owns the recorder")
        host.layout()
        #expect(fixture.callbacks == 0)
        callback(old) // Deliberately retained late callback, with its revoked lease.
        #expect(fixture.callbacks == 1 && fixture.summaries.isEmpty)
    }

    @Test("Full row-key equality is evaluated once per reused attachment, not twice")
    func singleKeyComparison() throws {
        final class Counter { var value = 0 }
        struct Key: Equatable {
            let counter: Counter
            let value: Int
            static func == (lhs: Key, rhs: Key) -> Bool {
                lhs.counter.value += 1
                return lhs.value == rhs.value
            }
        }
        let fixture = Fixture(), counter = Counter()
        defer { fixture.close() }
        func attach(observed: Bool = true, retainable: Bool = true) throws -> V2TableHostCache.Attachment {
            let observer: V2TableHostCache.NativeLayoutObserver?
            if observed { observer = { _ in } } else { observer = nil }
            let result = fixture.cache.attach(slot: .rules, key: Key(counter: counter, value: 1),
                scope: "inert-source", retainable: retainable, isCurrent: { true },
                environment: EnvironmentValues(), to: fixture.container,
                onNativeLayout: observer) { _ in Text("Synthetic") }
            return try #require(result)
        }
        _ = try attach()
        #expect(counter.value == 0)
        _ = try attach()
        #expect(counter.value == 1)
        let active = try attach(observed: false)
        #expect(counter.value == 1, "No full equality work for ordinary unobserved active updates")
        fixture.cache.detach(active)
        _ = try attach()
        #expect(counter.value == 2)
        _ = try attach(retainable: false)
        _ = try attach(retainable: false)
        #expect(counter.value == 2, "Timing never compares ineligible/oversized active payloads")
    }
}
