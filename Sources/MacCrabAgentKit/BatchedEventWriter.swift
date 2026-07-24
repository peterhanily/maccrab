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

/// The single events.db capability the batched writer needs. A protocol (rather
/// than the concrete `EventStore`) so tests can inject a fake that throws
/// `EventStoreError.busy` on demand to exercise the #13 transient-retry path.
/// `EventStore` (an actor) satisfies the async requirement via its isolation.
protocol EventBatchInserting: Sendable {
    func insert(events: [Event]) async throws
}

extension EventStore: EventBatchInserting {}

actor BatchedEventWriter {
    private let store: any EventBatchInserting
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
    /// Events re-queued after a TRANSIENT (SQLITE_BUSY/LOCKED) batch failure —
    /// retried rather than dropped (#13). Distinct from `drops` so a deferred
    /// retry is never conflated with a lost row.
    private let retries = LockedCounter()

    /// Storage-write drops since start. NOT a detection gap — the event was
    /// fully processed by the pipeline; only its events.db row was dropped.
    nonisolated var droppedCount: Int { drops.get() }

    /// Cumulative events re-queued after transient contention (#13 observability).
    nonisolated var retriedCount: Int { retries.get() }

    /// Event categories worth preserving over a file/write flood when the buffer
    /// is at the hard cap (#24): exec/network/tcc/auth/registry rows are rare and
    /// forensically valuable; file-write events ARE the flood.
    private static func isHighValue(_ e: Event) -> Bool {
        switch e.eventCategory {
        case .file: return false
        case .process, .network, .tcc, .authentication, .registry: return true
        }
    }

    /// - Note: In production `flushThreshold` / `hardCap` are FIXED at their
    ///   defaults — the sole caller (`DaemonState.init`) constructs this writer
    ///   with no arguments, and there is deliberately NO `daemon_config.json`
    ///   surface for them (unlike the upstream priority/file stream caps, which
    ///   ARE config-tunable via `DaemonConfig.storage`). The parameters exist
    ///   only so tests can inject small values to exercise the flush / hard-cap
    ///   overflow branches. Should a config surface ever be added, the caller —
    ///   not this initializer — must keep `flushThreshold <= hardCap`: we apply
    ///   floors only and do NOT silently clamp one to the other (clamping hid
    ///   the overflow branch and papered over misconfig). The defaults already
    ///   satisfy 1000 <= 250_000.
    init(store: any EventBatchInserting, flushThreshold: Int = 1000, hardCap: Int = 250_000) {
        self.store = store
        self.flushThreshold = max(1, flushThreshold)
        self.hardCap = max(1, hardCap)
    }

    /// O(1) hand-off from the hot consumer. Appends to the in-memory buffer and,
    /// once the batch threshold is crossed, kicks a background drain — it does
    /// NOT block the caller on SQLite. Drops the newest event if the buffer is
    /// already at the hard cap (writer can't keep up).
    func enqueue(_ event: Event) {
        if buffer.count >= hardCap {
            // #24: at the cap, don't blindly shed a high-value event to a file
            // flood. If the incoming event is high-value, evict the OLDEST
            // low-value (file) row to make room; only drop the incoming when the
            // buffer holds nothing cheaper to shed. A pure file flood still drops
            // in O(1) (the incoming is a file → the else branch).
            if Self.isHighValue(event),
               let idx = buffer.firstIndex(where: { !Self.isHighValue($0) }) {
                buffer.remove(at: idx)
                drops.increment()   // the evicted file row is the storage-write drop
            } else {
                drops.increment()   // nothing cheaper to shed — drop the incoming
                return
            }
        }
        buffer.append(event)
        if buffer.count >= flushThreshold && !draining {
            draining = true
            Task { await self.drain() }
        }
    }

    /// A retryable batch failure: SQLITE_BUSY / SQLITE_LOCKED contention, surfaced
    /// distinctly by EventStore as `.busy`. Everything else is permanent.
    private func isTransient(_ e: EventStoreError) -> Bool {
        if case .busy = e { return true }
        return false
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
            } catch let e as EventStoreError where isTransient(e) {
                // #13: TRANSIENT contention (SQLITE_BUSY/LOCKED) — typically a
                // reader pinning the WAL past the 5s busy_timeout. Retrying the
                // SAME batch succeeds once the contention clears, so DON'T drop it:
                // re-queue at the front and stop this pass. The periodic flush loop
                // retries after its interval (a natural backoff). Bounded by the
                // hard cap — if there's no room to hold the retry, shed as a last
                // resort. This is the leading (previously-misattributed) cause of
                // the external audit's get_events-returns-0 under WAL contention.
                if buffer.count + batch.count <= hardCap {
                    buffer.insert(contentsOf: batch, at: 0)
                    retries.add(batch.count)
                    return
                }
                await StorageErrorTracker.shared.recordEventError(e)
                drops.add(batch.count)
            } catch {
                // PERMANENT (disk full, corruption, encoding) — retrying the same
                // transaction would just fail again. Record the error AND count the
                // lost events as storage-write drops so they are not silently
                // uncounted: `droppedCount` reflects hard-cap overflow, an
                // unretryable transient, and permanent flush failures.
                await StorageErrorTracker.shared.recordEventError(error)
                drops.add(batch.count)
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
