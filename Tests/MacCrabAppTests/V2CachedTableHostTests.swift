import AppKit
import SwiftUI
import Testing
@testable import MacCrabApp

@Suite("Window-owned table host cache", .serialized)
struct V2CachedTableHostTests {
    private struct Row: Identifiable, Hashable { let id: Int; var text: String }
    private struct Input: Equatable {
        var rows = [Row(id: 1, text: "inert")]
        var source = "fixture-a"
        var epoch = 1
        var query = ""
        var selected: Int? = nil
    }
    @MainActor private final class Clock {
        final class Job {
            let delay: TimeInterval
            let fire: @MainActor () -> Void
            var cancelled = false
            init(_ delay: TimeInterval, _ fire: @escaping @MainActor () -> Void) {
                self.delay = delay; self.fire = fire
            }
        }
        var now: TimeInterval = 100
        var jobs: [Job] = []
        func makeCache() -> V2TableHostCache {
            V2TableHostCache(observeMemoryPressure: false, now: { self.now }, scheduleExpiry: { delay, fire in
                let job = Job(delay, fire)
                self.jobs.append(job)
                return V2TableHostExpiry { job.cancelled = true }
            })
        }
    }
    @MainActor private final class Payload { var value = 0 }
    @MainActor private final class Observations {
        var made = 0
        var environments: [(ColorScheme, String)] = []
    }
    @MainActor private struct Probe: NSViewRepresentable {
        @Environment(\.colorScheme) private var colorScheme
        @Environment(\.locale) private var locale
        let observations: Observations
        func makeNSView(context: Context) -> NSView { observations.made += 1; return NSView() }
        func updateNSView(_ view: NSView, context: Context) {
            observations.environments.append((colorScheme, locale.identifier))
        }
    }
    @MainActor private func settle(_ host: NSView, until condition: () -> Bool) async throws {
        let clock = ContinuousClock(), deadline = clock.now.advanced(by: .seconds(2))
        repeat {
            host.needsLayout = true
            host.layoutSubtreeIfNeeded()
            if condition() { return }
            await Task.yield()
        } while clock.now < deadline
        try #require(condition(), "Private hosting fixture did not reach its boundary")
    }
    @MainActor private func window(_ container: NSView) -> NSWindow {
        let window = NSWindow(contentRect: NSRect(x: -10000, y: -10000, width: 640, height: 240),
                              styleMask: [.borderless], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.contentView = container
        return window
    }
    @MainActor private func attach(_ cache: V2TableHostCache, slot: V2TableHostCache.Slot = .rules,
        key: Input = Input(), retainable: Bool = true, current: @escaping @MainActor () -> Bool = { true },
        to container: NSView, observations: Observations? = nil) throws -> V2TableHostCache.Attachment {
        let observations = observations ?? Observations()
        return try #require(cache.attach(slot: slot, key: key, scope: "fixture", retainable: retainable, isCurrent: current,
            environment: EnvironmentValues(), to: container) { _ in Probe(observations: observations) })
    }

    @Test("Revocation clears live captures, old slots and binding reads, not merely their writes")
    @MainActor
    func revocableCallbacks() {
        var current = true
        let lease = V2TableAttachmentLease(isCurrent: { current })
        var object: Payload? = Payload()
        weak let released = object
        let original = object!
        var reads = 0
        let binding = lease.binding(slot: .selection, Binding(get: { reads += 1; return original.value },
            set: { original.value = $0 }), fallback: -1)
        let first = lease.action(slot: .primary) { (value: Int) in original.value = value }
        let replacement = lease.action(slot: .primary) { (value: Int) in original.value = value + 1 }
        first(100)
        #expect(original.value == 0, "Replacing a fixed action slot revokes its old callback")
        replacement(4)
        // Binding construction may eagerly invoke its getter. Count only the
        // explicit lookup, after both the original and gated binding exist.
        let beforeLookup = reads
        let activeValue = binding.wrappedValue
        #expect(activeValue == 5 && reads == beforeLookup + 1)
        let afterLookup = reads
        current = false
        binding.wrappedValue = 20
        replacement(30)
        #expect(binding.wrappedValue == -1 && original.value == 5 && reads == afterLookup)
        current = true
        lease.revoke()
        binding.wrappedValue = 50
        replacement(40)
        #expect(!lease.isActive && binding.wrappedValue == -1 && original.value == 5 && reads == afterLookup)
        object = nil
        // original remains an explicit local positive control here; the next
        // test proves clearing stored callbacks releases their sole captures.
        #expect(released != nil)
    }

    @Test("Detached cached content cannot retain live callback or predicate payloads")
    @MainActor
    func clearedCaptureStorage() throws {
        let clock = Clock(), cache = clock.makeCache(), container = NSView()
        defer { cache.removeAll() }
        weak var released: Payload?
        var action: ((Int) -> Void)?
        var binding: Binding<Int>?
        func make() throws -> V2TableHostCache.Attachment {
            let payload = Payload()
            released = payload
            return try #require(cache.attach(slot: .rules, key: Input(), scope: "fixture", retainable: true,
                isCurrent: { payload.value >= 0 }, environment: EnvironmentValues(), to: container) { lease in
                    action = lease.action(slot: .primary) { payload.value = $0 }
                    binding = lease.binding(slot: .selection,
                        Binding(get: { payload.value }, set: { payload.value = $0 }), fallback: -1)
                    return Text("Inert cached content")
                })
        }
        let attachment = try make()
        #expect(released != nil)
        cache.detach(attachment)
        #expect(released == nil, "Only inert fallback values may survive in detached callbacks")
        action?(3)
        binding?.wrappedValue = 4
        #expect(binding?.wrappedValue == -1)
    }

    @Test("Exact hits preserve host identity but refresh lease and full environment before attachment")
    @MainActor
    func exactHitRefreshesEnvironmentAndLease() async throws {
        let clock = Clock(), cache = clock.makeCache(), observations = Observations()
        let container = NSView(frame: NSRect(x: 0, y: 0, width: 640, height: 240))
        let window = window(container)
        defer { cache.removeAll(); window.contentView = nil; window.close() }
        var environment = EnvironmentValues()
        environment.colorScheme = .light; environment.locale = Locale(identifier: "en_GB")
        var oldLease: V2TableAttachmentLease?
        let old = try #require(cache.attach(slot: .rules, key: Input(), scope: "fixture", retainable: true,
            isCurrent: { true }, environment: environment, to: container) { lease in
                oldLease = lease; return Probe(observations: observations)
            })
        let host = try #require(container.subviews.first)
        try await settle(host) { observations.environments.last?.1 == "en_GB" }
        cache.detach(old)
        #expect(host.superview == nil && host.window == nil && oldLease?.isActive == false)
        environment.colorScheme = .dark; environment.locale = Locale(identifier: "fr_FR")
        var newLease: V2TableAttachmentLease?
        let new = try #require(cache.attach(slot: .rules, key: Input(), scope: "fixture", retainable: true,
            isCurrent: { true }, environment: environment, to: container) { lease in
                newLease = lease; return Probe(observations: observations)
            })
        #expect(container.subviews.count == 1 && container.subviews.first === host)
        try await settle(host) { observations.environments.last?.1 == "fr_FR" }
        #expect(observations.environments.last?.0 == .dark && observations.made == 1)
        #expect(newLease?.isActive == true && oldLease?.isActive == false)
        cache.detach(old) // Delayed dismantle must not revoke the replacement.
        #expect(container.subviews.first === host && newLease?.isActive == true)
        #expect(clock.jobs.count == 1 && clock.jobs[0].delay == 120)
        cache.detach(new)
        #expect(container.subviews.isEmpty && !window.isVisible)
    }

    @Test("Every changed immutable input rebuilds, including equal IDs with different payloads",
          arguments: 0..<5)
    @MainActor
    func completeEquality(change: Int) throws {
        let clock = Clock(), cache = clock.makeCache(), container = NSView()
        defer { cache.removeAll() }
        let first = try attach(cache, to: container)
        let oldHost = try #require(container.subviews.first)
        cache.detach(first)
        var replacement = Input()
        switch change {
        case 0: replacement.rows[0].text = "changed but same ID"
        case 1: replacement.source = "fixture-b"
        case 2: replacement.epoch += 1
        case 3: replacement.query = "new filter"
        default: replacement.selected = 1
        }
        _ = try attach(cache, key: replacement, to: container)
        #expect(container.subviews.count == 1 && container.subviews.first !== oldHost)
        #expect(oldHost.superview == nil && clock.jobs[0].cancelled)
    }

    @Test("Only one of two fixed slots attaches; stale context and stale detach cannot interfere")
    @MainActor
    func slotAndContextIsolation() throws {
        let clock = Clock(), cache = clock.makeCache()
        let rules = NSView(), alerts = NSView()
        defer { cache.removeAll() }
        var current = true
        let first = try attach(cache, current: { current }, to: rules)
        let rulesHost = try #require(rules.subviews.first)
        _ = try attach(cache, slot: .openAlerts, to: alerts)
        #expect(rules.subviews.isEmpty && rulesHost.window == nil && alerts.subviews.count == 1)
        current = false
        let refused = cache.attach(slot: .rules, key: Input(), scope: "fixture", retainable: true,
            isCurrent: { current }, environment: EnvironmentValues(), to: rules) { _ in Text("Must not attach") }
        #expect(refused == nil && rules.subviews.isEmpty && alerts.subviews.count == 1)
        cache.detach(first)
        #expect(alerts.subviews.count == 1)
        current = true
        _ = try attach(cache, current: { current }, to: rules)
        #expect(rules.subviews.first === rulesHost && alerts.subviews.isEmpty)
        #expect(clock.jobs.count == 2)
        cache.evictDetached(slot: .openAlerts)
        #expect(rules.subviews.first === rulesHost, "Slot-scoped pruning cannot blank another active table")
    }

    @Test("Absolute expiry is not renewed, and expired or over-budget content cannot be reused")
    @MainActor
    func expiryAndEphemeralContent() throws {
        let clock = Clock(), cache = clock.makeCache(), container = NSView()
        defer { cache.removeAll() }
        let first = try attach(cache, to: container)
        let oldHost = try #require(container.subviews.first)
        cache.detach(first)
        clock.now = 219
        let second = try attach(cache, to: container)
        #expect(container.subviews.first === oldHost && clock.jobs.count == 1)
        cache.detach(second)
        clock.now = 220 // Timer delivery is not required for the age guard.
        _ = try attach(cache, to: container)
        #expect(container.subviews.first !== oldHost && clock.jobs.count == 2)
        let active = try #require(container.subviews.first)
        clock.jobs[1].fire() // Active expiry disqualifies retention, not visible content.
        #expect(container.subviews.first === active)
        cache.evictDetached()
        #expect(container.subviews.first === active)
        let ephemeral = try attach(cache, retainable: false, to: container)
        cache.detach(ephemeral)
        #expect(container.subviews.isEmpty && active.superview == nil)
        #expect(clock.jobs.count == 2)
    }

    @Test("Detached expiry and window teardown release retained hosts and cancel their one-shot jobs")
    @MainActor
    func releaseAndExpiry() async throws {
        let clock = Clock(), cache = clock.makeCache(), container = NSView()
        defer { cache.removeAll() }
        let expired = WeakView()
        try autoreleasepool {
            let first = try attach(cache, to: container)
            expired.value = container.subviews.first
            cache.detach(first)
            #expect(expired.value != nil, "Positive control: detached, admitted content is still owned")
            clock.jobs[0].fire()
            #expect(container.subviews.isEmpty)
        }
        try await requireReleased(expired)
        let closed = WeakView()
        try autoreleasepool {
            _ = try attach(cache, to: container)
            closed.value = container.subviews.first
            #expect(closed.value != nil)
            cache.removeAll()
            #expect(container.subviews.isEmpty)
        }
        try await requireReleased(closed)
        #expect(clock.jobs[1].cancelled)
        clock.jobs[1].fire() // A cancelled/stale callback cannot resurrect a host.
        #expect(container.subviews.isEmpty)
    }

    @MainActor private final class WeakView { weak var value: NSView? }
    @MainActor private func requireReleased(_ view: WeakView) async throws {
        // AppKit/SwiftUI can defer native releases until a main-queue turn.
        // Do not call removeAll or mutate the cache here: a leaked entry must
        // still fail, with the cache and recorded timer jobs alive throughout.
        let clock = ContinuousClock(), deadline = clock.now.advanced(by: .seconds(2))
        repeat {
            await withCheckedContinuation { continuation in
                DispatchQueue.main.async { continuation.resume() }
            }
            if autoreleasepool(invoking: { view.value == nil }) { return }
        } while clock.now < deadline
        try #require(view.value == nil, "Native host remained owned after bounded lifecycle settling")
    }

    @Test("Initial loading can become retainable without renewing age or overriding pressure")
    @MainActor
    func activeAdmissionPromotion() throws {
        let clock = Clock(), cache = clock.makeCache(), container = NSView()
        defer { cache.removeAll() }
        _ = try attach(cache, retainable: false, to: container)
        let host = try #require(container.subviews.first)
        #expect(clock.jobs.count == 1)
        clock.now = 110
        cache.evictDetached(slot: .rules, disqualifyActive: false)
        let admitted = try attach(cache, to: container)
        #expect(container.subviews.first === host && clock.jobs.count == 1)
        cache.detach(admitted)
        let reattached = try attach(cache, to: container)
        #expect(container.subviews.first === host)
        cache.evictDetached() // Pressure is sticky for this allocation.
        _ = try attach(cache, to: container)
        #expect(container.subviews.first === host)
        cache.detach(reattached) // A stale token cannot detach the replacement.
        #expect(container.subviews.first === host)
        let current = try attach(cache, to: container)
        cache.detach(current)
        _ = try attach(cache, to: container)
        #expect(container.subviews.first !== host)
    }

    @MainActor private final class StateDriver {
        var values: [String] = []
        var mutate: (() -> Void)?
    }
    @MainActor private struct StateProbe: NSViewRepresentable {
        let driver: StateDriver
        @Binding var filter: String
        @Binding var descending: Bool
        @Binding var anchor: Int
        func makeNSView(context: Context) -> NSView { NSView() }
        func updateNSView(_ view: NSView, context: Context) {
            driver.values = [filter, String(descending), String(anchor)]
            driver.mutate = { filter = "synthetic filter"; descending = true; anchor = 9 }
        }
    }
    @MainActor private struct StatefulTable: View {
        let driver: StateDriver
        @State private var filter = ""
        @State private var descending = false
        @State private var anchor = 0
        private let rows = (0..<500).map { Row(id: $0, text: "Synthetic row \($0)") }
        var body: some View {
            V2DataTable(columns: [V2DataColumn(id: "text", title: "Text", width: .flexible(min: 200)) {
                V2TableCellText($0.text)
            }], items: rows, selection: .constant(nil))
            .background(StateProbe(driver: driver, filter: $filter, descending: $descending, anchor: $anchor))
        }
    }
    @MainActor private func scrollView(_ root: NSView) throws -> NSScrollView {
        var pending = [root], visited = 0
        while let view = pending.popLast() {
            visited += 1
            try #require(visited <= 4096, "Private native table exceeded traversal bound")
            if let scroll = view as? NSScrollView { return scroll }
            pending.append(contentsOf: view.subviews)
        }
        throw NSError(domain: "SyntheticTableFixture", code: 1)
    }

    @MainActor private final class BridgeDriver: ObservableObject {
        @Published var visible = true
        @Published var identity = 0
        var realized: Set<Int> = []
    }
    @MainActor private struct BridgeRowProbe: NSViewRepresentable {
        let driver: BridgeDriver
        let id: Int
        func makeNSView(context: Context) -> NSView { driver.realized.insert(id); return NSView() }
        func updateNSView(_ view: NSView, context: Context) {}
    }
    @MainActor private struct BridgeFixture: View {
        @ObservedObject var driver: BridgeDriver
        let cache: V2TableHostCache
        let rows = (0..<500).map { Row(id: $0, text: "Synthetic bridge row \($0)") }
        var body: some View {
            VStack(spacing: 0) {
                Text("Synthetic heading").frame(height: 40)
                if driver.visible {
                    V2CachedTableHost(cache: cache, slot: .rules, key: rows, scope: "fixture",
                                      retainable: true, isCurrent: { true }) { _ in
                        V2DataTable(columns: [V2DataColumn(id: "text", title: "Text", width: .flexible(min: 200)) {
                            V2TableCellText($0.text).background(BridgeRowProbe(driver: driver, id: $0.id))
                        }], items: rows, selection: .constant(nil))
                    }
                    .id(driver.identity)
                } else {
                    Color.clear.frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
            // Production applies this frame to the outer VStack, not the bridge.
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }
    @MainActor private func nativeViews(_ root: NSView) throws -> [NSView] {
        var pending = [root], result: [NSView] = []
        while let view = pending.popLast() {
            try #require(result.count < 4096, "Private bridge traversal exceeded its bound")
            result.append(view)
            pending.append(contentsOf: view.subviews)
        }
        return result
    }
    @MainActor private func bridgeBoundary(_ root: NSView) async {
        root.needsLayout = true
        root.layoutSubtreeIfNeeded()
        await withCheckedContinuation { continuation in
            DispatchQueue.main.async { continuation.resume() }
        }
        root.layoutSubtreeIfNeeded()
    }

    @Test("The real SwiftUI bridge fills a proposed viewport, stays lazy and survives replacement coordinators")
    @MainActor
    func representableViewportAndLifecycle() async throws {
        let clock = Clock(), cache = clock.makeCache(), driver = BridgeDriver()
        let root = NSHostingView(rootView: BridgeFixture(driver: driver, cache: cache))
        let window = window(root)
        defer { cache.removeAll(); window.contentView = nil; window.close() }
        await bridgeBoundary(root)
        try await settle(root) { !driver.realized.isEmpty }
        let hosts = try nativeViews(root).compactMap { $0 as? NSHostingView<AnyView> }
        try #require(hosts.count == 1)
        let host = try #require(hosts.first)
        func checkViewport(width: CGFloat, height: CGFloat) throws {
            let views = try nativeViews(root)
            #expect(views.compactMap { $0 as? NSHostingView<AnyView> }.count == 1)
            let scrolls = views.compactMap { $0 as? NSScrollView }
            try #require(scrolls.count == 1)
            let scroll = try #require(scrolls.first)
            let container = try #require(host.superview)
            #expect(abs(container.bounds.width - width) < 0.5)
            #expect(abs(container.bounds.height - height) < 0.5)
            #expect(host.frame == container.bounds)
            #expect(scroll.contentView.bounds.height > 0 && scroll.contentView.bounds.height <= height)
            #expect(!driver.realized.isEmpty && driver.realized.count < 500)
        }
        try checkViewport(width: 640, height: 200)
        driver.visible = false
        await bridgeBoundary(root)
        try await settle(root) { host.superview == nil }
        #expect(host.window == nil)
        #expect(try nativeViews(root).compactMap { $0 as? NSScrollView }.isEmpty)
        driver.visible = true
        await bridgeBoundary(root)
        try await settle(root) { host.window === window }
        try checkViewport(width: 640, height: 200)
        #expect(clock.jobs.count == 1, "A detached exact hit must not create a new host or deadline")
        driver.identity += 1 // SwiftUI replaces its coordinator and dismantles the old representable.
        await bridgeBoundary(root)
        try await settle(root) { host.window === window }
        try checkViewport(width: 640, height: 200)
        #expect(clock.jobs.count == 1, "A late old dismantle cannot evict the new attachment")
        window.setContentSize(NSSize(width: 820, height: 340))
        await bridgeBoundary(root)
        try await settle(root) { abs(host.bounds.width - 820) < 0.5 && abs(host.bounds.height - 300) < 0.5 }
        try checkViewport(width: 820, height: 300)
        cache.removeAll()
        #expect(host.superview == nil && host.window == nil && clock.jobs[0].cancelled)
        #expect(!window.isVisible)
    }

    @Test("Compatible active changes preserve synthetic SwiftUI state and the actual native table scroll view")
    @MainActor
    func activeUpdatesPreserveLocalState() async throws {
        let clock = Clock(), cache = clock.makeCache(), driver = StateDriver()
        let container = NSView(frame: NSRect(x: 0, y: 0, width: 640, height: 240))
        let window = window(container)
        defer { driver.mutate = nil; cache.removeAll(); window.contentView = nil; window.close() }
        func update(_ input: Input, scope: String = "fixture") throws {
            _ = try #require(cache.attach(slot: .rules, key: input, scope: scope, retainable: true,
                isCurrent: { true }, environment: EnvironmentValues(), to: container) { _ in StatefulTable(driver: driver) })
        }
        try update(Input())
        let host = try #require(container.subviews.first)
        try await settle(host) { driver.mutate != nil }
        driver.mutate?()
        try await settle(host) { driver.values == ["synthetic filter", "true", "9"] }
        let scroll = try scrollView(host)
        scroll.contentView.scroll(to: NSPoint(x: 0, y: 80))
        scroll.reflectScrolledClipView(scroll.contentView)
        host.layoutSubtreeIfNeeded()
        let position = scroll.contentView.bounds.origin
        #expect(position.y > 0)
        var input = Input()
        input.selected = 1; input.query = "active query"; input.rows[0].text = "updated payload"
        try update(input)
        try await settle(host) { driver.values == ["synthetic filter", "true", "9"] }
        #expect(container.subviews.first === host)
        #expect(try scrollView(host) === scroll)
        #expect(scroll.contentView.bounds.origin == position)
        cache.evictDetached() // Model/pressure invalidation must not force an active remount.
        input.selected = 2
        try update(input)
        #expect(container.subviews.first === host)
        #expect(driver.values == ["synthetic filter", "true", "9"])
        try update(input, scope: "different source")
        let replaced = try #require(container.subviews.first)
        #expect(replaced !== host)
        try await settle(replaced) { driver.values == ["", "false", "0"] }
        #expect(!window.isVisible)
        // This deliberately does not claim to exercise V2DataTable's private
        // sort/filter/shift-anchor controls. Its scroll view is real; the three
        // SwiftUI @State fields are an explicit synthetic persistence oracle.
    }
}
