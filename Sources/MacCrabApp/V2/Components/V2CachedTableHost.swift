import AppKit
import SwiftUI

/// Source identity is separate from normal active table input changes.
struct V2TableHostScope: Equatable {
    let provider: ObjectIdentifier
    let directory: String?
    let epoch: UInt64
    let engine: V2AlertsPresentationContext.Engine?
}

/// One attachment's callbacks. Detached content retains only inert snapshots:
/// revocation releases the live callbacks and the current-context predicate.
/// Register callbacks once while constructing a table, not from a cell body.
@MainActor
final class V2TableAttachmentLease {
    enum ActionSlot: Hashable { case primary, secondary }
    enum BindingSlot: Hashable { case selection, multiSelection }

    private protocol Revocable: AnyObject { func revoke() }
    private final class Action<Input>: Revocable {
        var callback: (@MainActor (Input) -> Void)?
        init(_ callback: @escaping @MainActor (Input) -> Void) { self.callback = callback }
        func revoke() { callback = nil }
    }
    private final class Value<ValueType>: Revocable {
        var get: (() -> ValueType)?
        var set: ((ValueType) -> Void)?
        init(_ binding: Binding<ValueType>) {
            get = { binding.wrappedValue }
            set = { binding.wrappedValue = $0 }
        }
        func revoke() { get = nil; set = nil }
    }
    private var current: (@MainActor () -> Bool)?
    private var actions: [ActionSlot: any Revocable] = [:]
    private var bindings: [BindingSlot: any Revocable] = [:]

    init(isCurrent: @escaping @MainActor () -> Bool) { current = isCurrent }
    var isActive: Bool { current?() == true }

    func action<Input>(slot: ActionSlot, _ callback: @escaping @MainActor (Input) -> Void) -> (Input) -> Void {
        let box = Action(callback)
        actions.removeValue(forKey: slot)?.revoke()
        if current != nil { actions[slot] = box } else { box.revoke() }
        return { [weak self, box] input in
            guard self?.isActive == true else { return }
            box.callback?(input)
        }
    }

    func binding<ValueType>(slot: BindingSlot, _ binding: Binding<ValueType>, fallback: ValueType) -> Binding<ValueType> {
        let box = Value(binding)
        bindings.removeValue(forKey: slot)?.revoke()
        if current != nil { bindings[slot] = box } else { box.revoke() }
        return Binding(get: { [weak self, box] in
            guard self?.isActive == true else { return fallback }
            return box.get?() ?? fallback
        }, set: { [weak self, box] value in
            guard self?.isActive == true else { return }
            box.set?(value)
        })
    }

    func revoke() {
        current = nil
        actions.values.forEach { $0.revoke() }
        bindings.values.forEach { $0.revoke() }
        actions.removeAll()
        bindings.removeAll()
    }
}

/// A cancellable one-shot expiry, also injectable in inert lifecycle tests.
final class V2TableHostExpiry {
    private var cancellation: (() -> Void)?
    init(_ cancellation: @escaping () -> Void) { self.cancellation = cancellation }
    func cancel() { cancellation?(); cancellation = nil }
    deinit { cancellation?() }
}

/// Window-owned, fixed two-slot native table cache. No provider, store, query,
/// page task or model is owned here. The caller must supply the complete
/// immutable table input and its existing model's retention-budget decision.
@MainActor
final class V2TableHostCache: ObservableObject {
    enum Slot: CaseIterable, Hashable { case rules, openAlerts }
    struct Attachment: Equatable {
        fileprivate let slot: Slot
        fileprivate let id: UUID
    }
    typealias ScheduleExpiry = @MainActor (TimeInterval, @escaping @MainActor () -> Void) -> V2TableHostExpiry
    @MainActor private final class Entry {
        let host: NSHostingView<AnyView>
        var matches: (Any) -> Bool
        let matchesScope: (Any) -> Bool
        let contentType: ObjectIdentifier
        let deadline: TimeInterval
        var retainable: Bool
        var retentionBlocked = false
        var expiry: V2TableHostExpiry?
        var attachment: Attachment?
        var lease: V2TableAttachmentLease?
        weak var container: NSView?
        init<Key: Equatable, Scope: Equatable, Content: View>(key: Key, scope: Scope, content: Content.Type,
            deadline: TimeInterval, retainable: Bool) {
            host = NSHostingView(rootView: AnyView(EmptyView()))
            matches = { ($0 as? Key) == key }
            matchesScope = { ($0 as? Scope) == scope }
            contentType = ObjectIdentifier(content)
            self.deadline = deadline
            self.retainable = retainable
        }
        func revoke() {
            lease?.revoke()
            lease = nil
            attachment = nil
            container = nil
            host.removeFromSuperview()
        }
    }
    private var entries: [Slot: Entry] = [:]
    private let now: @MainActor () -> TimeInterval
    private let scheduleExpiry: ScheduleExpiry
    private var pressureSource: DispatchSourceMemoryPressure?

    init(observeMemoryPressure: Bool = true,
         now: @escaping @MainActor () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
         scheduleExpiry: ScheduleExpiry? = nil) {
        self.now = now
        self.scheduleExpiry = scheduleExpiry ?? { delay, expire in
            let task = Task { @MainActor in
                do { try await Task.sleep(for: .seconds(delay)) }
                catch { return }
                guard !Task.isCancelled else { return }
                expire()
            }
            return V2TableHostExpiry { task.cancel() }
        }
        if observeMemoryPressure {
            let source = DispatchSource.makeMemoryPressureSource(eventMask: [.warning, .critical], queue: .main)
            source.setEventHandler { [weak self] in
                Task { @MainActor [weak self] in self?.evictDetached() }
            }
            pressureSource = source
            source.resume()
        }
    }
    deinit { pressureSource?.cancel() }

    /// Called on pressure/model invalidation: never remove the currently
    /// displayed table mid-frame, but do not retain it after it leaves.
    func evictDetached(slot selectedSlot: Slot? = nil, disqualifyActive: Bool = true) {
        for slot in Slot.allCases where selectedSlot == nil || selectedSlot == slot {
            guard let entry = entries[slot] else { continue }
            if entry.attachment == nil { remove(slot) }
            else if disqualifyActive {
                entry.retentionBlocked = true
                entry.retainable = false
                entry.expiry?.cancel()
                entry.expiry = nil
            }
        }
    }

    /// Window teardown; a stale representable's later dismantle is harmless.
    func removeAll() { Slot.allCases.forEach(remove) }

    private func remove(_ slot: Slot) {
        guard let entry = entries.removeValue(forKey: slot) else { return }
        entry.expiry?.cancel()
        entry.expiry = nil
        entry.retentionBlocked = true
        entry.revoke()
    }
    private func expire(_ slot: Slot, entry: Entry) {
        guard entries[slot] === entry else { return }
        entry.expiry = nil
        entry.retentionBlocked = true
        entry.retainable = false
        if entry.attachment == nil { remove(slot) }
    }

    func detach(_ attachment: Attachment) {
        guard let entry = entries[attachment.slot], entry.attachment == attachment else { return }
        entry.revoke()
        let instant = now()
        if !entry.retainable || !instant.isFinite || instant >= entry.deadline { remove(attachment.slot) }
    }

    /// Detached reuse requires complete input equality, not IDs/counts/hash.
    /// Normal same-source active updates retain SwiftUI's existing local state.
    /// Every update installs a new lease and current root/environment.
    func attach<Key: Equatable, Scope: Equatable, Content: View>(slot: Slot, key: Key, scope: Scope, retainable: Bool,
        isCurrent: @escaping @MainActor () -> Bool, environment: EnvironmentValues,
        to container: NSView, content: @MainActor (V2TableAttachmentLease) -> Content) -> Attachment? {
        guard isCurrent() else {
            if let old = entries[slot], old.container === container, let attachment = old.attachment {
                detach(attachment)
            }
            return nil
        }
        let instant = now()
        let validClock = instant.isFinite && instant >= 0 && (instant + 120).isFinite && instant + 120 > instant
        let canRetain = retainable && validClock
        if let old = entries[slot] {
            let compatible = old.contentType == ObjectIdentifier(Content.self) && old.matchesScope(scope)
            let activeUpdate = old.container === container && old.attachment != nil
            let detachedHit = canRetain && old.retainable && instant < old.deadline && old.matches(key)
            if !compatible || (!activeUpdate && !detachedHit) { remove(slot) }
        }
        // Only one host in this window may be attached, including old/new
        // representables that briefly overlap during a conditional swap.
        for otherSlot in Slot.allCases {
            guard let old = entries[otherSlot], let attachment = old.attachment else { continue }
            if otherSlot != slot || old.container !== container { detach(attachment) }
            else { old.lease?.revoke(); old.lease = nil }
        }
        let entry: Entry
        if let cached = entries[slot] { entry = cached }
        else {
            entry = Entry(key: key, scope: scope, content: Content.self,
                          deadline: instant + 120, retainable: canRetain)
            entry.retentionBlocked = !validClock
            entries[slot] = entry
            // Loading/empty active tables may become budget-eligible later.
            // Their original lifetime still expires; promotion never renews it.
            if validClock {
                entry.expiry = scheduleExpiry(120) { [weak self, weak entry] in
                    guard let self, let entry else { return }
                    self.expire(slot, entry: entry)
                }
            }
        }
        entry.matches = { ($0 as? Key) == key }
        // Pressure/model invalidation and age never regain eligibility from a
        // normal active update. The next detach discards that allocation.
        entry.retainable = !entry.retentionBlocked && canRetain && instant < entry.deadline
        let lease = V2TableAttachmentLease(isCurrent: isCurrent)
        let root = content(lease).environment(\.self, environment)
        guard lease.isActive else { lease.revoke(); remove(slot); return nil }
        entry.host.rootView = AnyView(root)
        entry.host.frame = container.bounds
        entry.host.autoresizingMask = [.width, .height]
        let attachment = Attachment(slot: slot, id: UUID())
        entry.lease = lease
        entry.attachment = attachment
        entry.container = container
        if entry.host.superview !== container { container.addSubview(entry.host) }
        return attachment
    }
}

/// Only a pure table belongs inside this bridge. The page and its tasks remain
/// in the ordinary conditional workspace tree. Never pass self/ObservedObject
/// captures into cached cell closures; use inert snapshots and revocable gates.
@MainActor
struct V2CachedTableHost<Key: Equatable, Scope: Equatable, Content: View>: NSViewRepresentable {
    let cache: V2TableHostCache
    let slot: V2TableHostCache.Slot
    let key: Key
    let scope: Scope
    let retainable: Bool
    let isCurrent: @MainActor () -> Bool
    @ViewBuilder let content: @MainActor (V2TableAttachmentLease) -> Content

    @MainActor final class Coordinator {
        var cache: V2TableHostCache
        var attachment: V2TableHostCache.Attachment?
        init(_ cache: V2TableHostCache) { self.cache = cache }
    }
    func makeCoordinator() -> Coordinator { Coordinator(cache) }
    func makeNSView(context: Context) -> NSView { NSView() }
    func updateNSView(_ view: NSView, context: Context) {
        if context.coordinator.cache !== cache {
            if let old = context.coordinator.attachment { context.coordinator.cache.detach(old) }
            context.coordinator.cache = cache
            context.coordinator.attachment = nil
        }
        if let old = context.coordinator.attachment, !isCurrent() {
            cache.detach(old)
            context.coordinator.attachment = nil
            return
        }
        context.coordinator.attachment = cache.attach(slot: slot, key: key, scope: scope, retainable: retainable,
            isCurrent: isCurrent, environment: context.environment, to: view, content: content)
    }
    static func dismantleNSView(_ view: NSView, coordinator: Coordinator) {
        if let attachment = coordinator.attachment { coordinator.cache.detach(attachment) }
        coordinator.attachment = nil
    }
}
