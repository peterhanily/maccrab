// BatchedEventWriter.swift
// MacCrabAgentKit
//
// v1.21.4 (F2 / A1): async batched writer for events.db.
//
// The event-loop consumer used to `await eventStore.insert(event:)` inline —
// one SQLite transaction per event. Under a flood (measured on-device: 120k+
// file writes) that serialized ~120k transactions behind the single consumer,
// so the consumer couldn't drain the merged stream fast enough and the
// AsyncStream buffer evicted the oldest events (the 400k `events_dropped`
// observed on the rc.1 sysext).
//
// This actor decouples the DB write from detection. The consumer calls the
// O(1) `enqueue`; a background drain flushes accumulated events through the
// existing batch transaction `EventStore.insert(events:)` — hundreds of
// transactions per burst instead of hundreds of thousands, and off the
// consumer's critical path entirely.
//
// Safety: nothing downstream in the loop reads the event back from events.db —
// detection runs on the in-memory enriched event, and alert evidence is
// snapshotted in memory by AlertSink — so deferring the write loses no
// detection fidelity. The only best-effort casualty is the ±60s
// surrounding-context window, which may miss the last < flush-interval of
// events under a flood. If the writer itself can't keep up, it drops the
// NEWEST event and bumps a DISTINCT counter (`droppedCount`) so a storage-write
// drop is never conflated with a detection-input (merged-stream) drop —
// detection still saw every event; only its events.db row was shed.

import Foundation
import MacCrabCore

actor BatchedEventWriter {
    private let store: EventStore
    /// Kick a background drain once the buffer reaches this depth.
    private let flushThreshold: Int
    /// Hard ceiling on the in-memory buffer; past it, `enqueue` drops the
    /// incoming event (O(1)) rather than growing the resident set unbounded.
    private let hardCap: Int

    private var buffer: [Event] = []
    private var draining = false
    private var flushLoop: Task<Void, Never>?
    /// Storage-write drops since start (writer-queue overflow). A `LockedCounter`
    /// (Sendable, lock-guarded) so `droppedCount` can be read `nonisolated` from
    /// the heartbeat without an actor hop.
    private let drops = LockedCounter()

    /// Storage-write drops since start. NOT a detection gap — the event was
    /// fully processed by the pipeline; only its events.db row was dropped.
    nonisolated var droppedCount: Int { drops.get() }

    init(store: EventStore, flushThreshold: Int = 1000, hardCap: Int = 250_000) {
        self.store = store
        // Floors only — the caller (DaemonConfig) is responsible for keeping
        // flushThreshold <= hardCap; we do NOT silently clamp one to the other
        // (that hid the overflow branch and papered over misconfig). Defaults
        // already satisfy 1000 <= 250_000.
        self.flushThreshold = max(1, flushThreshold)
        self.hardCap = max(1, hardCap)
    }

    /// O(1) hand-off from the hot consumer. Appends to the in-memory buffer and,
    /// once the batch threshold is crossed, kicks a background drain — it does
    /// NOT block the caller on SQLite. Drops the newest event if the buffer is
    /// already at the hard cap (writer can't keep up).
    func enqueue(_ event: Event) {
        if buffer.count >= hardCap {
            drops.increment()
            return
        }
        buffer.append(event)
        if buffer.count >= flushThreshold && !draining {
            draining = true
            Task { await self.drain() }
        }
    }

    /// Drain the buffer to SQLite in batch transactions until empty.
    /// Reentrancy-safe: each pass snapshots + clears the buffer BEFORE the
    /// `await`, so concurrent `enqueue`s append to a fresh buffer and a second
    /// drain sees it empty and stops. `defer` clears `draining` even on throw.
    private func drain() async {
        defer { draining = false }
        while !buffer.isEmpty {
            let batch = buffer
            buffer.removeAll(keepingCapacity: true)
            do {
                try await store.insert(events: batch)
            } catch {
                await StorageErrorTracker.shared.recordEventError(error)
            }
        }
    }

    /// Start the periodic partial-flush loop. Under a low event rate the buffer
    /// may never reach `flushThreshold`, so this timer flushes whatever has
    /// accumulated on a fixed cadence — bounding write latency to `intervalMs`.
    /// Idempotent.
    func startFlushLoop(intervalMs: UInt64 = 250) {
        guard flushLoop == nil else { return }
        flushLoop = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: intervalMs * 1_000_000)
                await self?.flushPartial()
            }
        }
    }

    /// Flush a below-threshold partial batch (called by the timer + on shutdown).
    func flushPartial() async {
        if !buffer.isEmpty && !draining {
            draining = true
            await drain()
        }
    }

    /// Stop the timer and flush anything still buffered. Call on graceful
    /// daemon teardown so the last partial batch reaches disk.
    func shutdown() async {
        flushLoop?.cancel()
        flushLoop = nil
        await flushPartial()
    }
}
