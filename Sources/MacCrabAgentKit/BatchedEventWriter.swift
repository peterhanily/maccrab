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
import os.log

/// The single events.db capability the batched writer needs. A protocol (rather
/// than the concrete `EventStore`) so tests can inject a fake that throws
/// `EventStoreError.busy` on demand to exercise the #13 transient-retry path.
/// `EventStore` (an actor) satisfies the async requirement via its isolation.
protocol EventBatchInserting: Sendable {
    func insert(events: [Event]) async throws -> EventBatchInsertResult
}

extension EventStore: EventBatchInserting {}

actor BatchedEventWriter {
    struct TelemetrySnapshot: Sendable, Equatable {
        /// Rows permanently shed after the detection loop saw the event.
        let droppedCount: Int
        /// Cumulative retry attempts; a row can contribute more than once.
        let retriedCount: Int
        /// Rows reported committed at write time. This cumulative history is not
        /// decremented if a later corruption recovery quarantines that database.
        let persistedCount: Int
        /// Rows waiting in the actor's queue at snapshot time. A batch currently
        /// suspended inside `store.insert` is not part of this queue gauge; it is
        /// reported separately by `inFlightDepth`.
        let bufferDepth: Int
        /// Rows detached from the queue and currently owned by one asynchronous
        /// `store.insert` call. This closes the heartbeat reconciliation gap where
        /// the queue could read zero before the corresponding persisted/drop
        /// counters advanced.
        let inFlightDepth: Int
    }

    private let store: any EventBatchInserting
    /// Kick a background drain once the buffer reaches this depth.
    private let flushThreshold: Int
    /// Hard ceiling on the in-memory buffer; past it, `enqueue` drops the
    /// incoming event (O(1)) rather than growing the resident set unbounded.
    private let hardCap: Int
    /// Volume to probe for free space before writing, or nil to disable the
    /// admission check (tests, and any consumer with no on-disk store).
    private let volumePath: String?
    /// Free-space reserve the writer refuses to consume. The engine previously
    /// had NO free-space check on any write path — `statvfs` appeared only in
    /// VACUUM preflights — so the root daemon would write until the volume was
    /// 100% full, taking the whole machine with it. Disk-full was handled only
    /// reactively, in `drain`'s permanent-error arm, i.e. after the damage.
    private let freeSpaceFloorMB: Int
    /// Cached admission probe. `statvfs` is a syscall and `drain` loops per
    /// batch, so re-probe at most every 15s.
    private var lastFreeProbe: (at: ContinuousClock.Instant, freeMB: Int)?
    /// True once the floor has been breached, so the fault logs once per episode
    /// instead of once per batch.
    private var admissionBlocked = false

    private var buffer: [Event] = []
    /// Exactly one drain runs at a time, so this is either zero or the complete
    /// detached batch suspended in `store.insert(events:)`.
    private var inFlightDepth = 0
    /// Count of low-value (file) rows currently in `buffer`, maintained
    /// incrementally so the #24 cap-shedding can decide in O(1) whether there is
    /// anything cheaper than the incoming high-value event to evict — without an
    /// O(n) `firstIndex` scan on every high-value event during a high-value flood
    /// (rc.3-verify perf fix).
    private var lowValueCount = 0
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
    /// Rows confirmed durable by successful commits. Partial batch failures add
    /// only their committed prefix; filtered rows are neither persisted nor
    /// misreported as storage sheds.
    private let persisted = LockedCounter()

    /// Storage-write drops since start. NOT a detection gap — the event was
    /// fully processed by the pipeline; only its events.db row was dropped.
    nonisolated var droppedCount: Int { drops.get() }

    /// Cumulative events re-queued after transient contention (#13 observability).
    nonisolated var retriedCount: Int { retries.get() }

    nonisolated var persistedCount: Int { persisted.get() }

    /// One actor-consistent view for the rich heartbeat. Counter values are
    /// cumulative since process start; buffer depth is an instantaneous gauge.
    func telemetrySnapshot() -> TelemetrySnapshot {
        TelemetrySnapshot(
            droppedCount: drops.get(),
            retriedCount: retries.get(),
            persistedCount: persisted.get(),
            bufferDepth: buffer.count,
            inFlightDepth: inFlightDepth
        )
    }

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
    init(
        store: any EventBatchInserting,
        flushThreshold: Int = 1000,
        hardCap: Int = 250_000,
        volumePath: String? = nil,
        freeSpaceFloorMB: Int = 1024
    ) {
        self.volumePath = volumePath
        self.freeSpaceFloorMB = max(0, freeSpaceFloorMB)
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
            // flood. If the incoming event is high-value AND a cheaper file row
            // exists (lowValueCount > 0 — the O(1) guard so a high-value flood
            // doesn't pay an O(n) scan per event), evict the OLDEST file row to
            // make room; otherwise drop the incoming. A pure file flood still
            // drops in O(1) (the incoming is a file → the else branch).
            if Self.isHighValue(event), lowValueCount > 0,
               let idx = buffer.firstIndex(where: { !Self.isHighValue($0) }) {
                buffer.remove(at: idx)
                lowValueCount -= 1
                drops.increment()   // the evicted file row is the storage-write drop
            } else {
                drops.increment()   // nothing cheaper to shed — drop the incoming
                return
            }
        }
        buffer.append(event)
        if !Self.isHighValue(event) { lowValueCount += 1 }
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
    /// Admission control: may we consume more disk right now?
    ///
    /// Returns the free-space reading when the floor is breached, nil when the
    /// write is allowed. A failed probe (`freeDiskMB` returns 0) ALLOWS the write
    /// — refusing all telemetry because a `statvfs` call glitched would be a
    /// worse failure than the pressure this guards against.
    private func admissionBlockedFreeMB() -> Int? {
        guard let volumePath, freeSpaceFloorMB > 0 else { return nil }
        let now = ContinuousClock.now
        let freeMB: Int
        if let cached = lastFreeProbe, cached.at.duration(to: now) < .seconds(15) {
            freeMB = cached.freeMB
        } else {
            freeMB = freeDiskMB(forPath: volumePath)
            lastFreeProbe = (at: now, freeMB: freeMB)
        }
        guard freeMB > 0, freeMB < freeSpaceFloorMB else { return nil }
        return freeMB
    }

    private func drain() async {
        defer { draining = false }
        while !buffer.isEmpty {
            // Disk admission check BEFORE the write, not after SQLite fails. Shed
            // the batch and stop the pass; the periodic flush loop retries, so
            // ingestion resumes by itself once the retention sweeps free space.
            if let freeMB = admissionBlockedFreeMB() {
                let shed = buffer.count
                buffer.removeAll(keepingCapacity: true)
                lowValueCount = 0
                drops.add(shed)
                if !admissionBlocked {
                    admissionBlocked = true
                    Logger(subsystem: "com.maccrab.agentkit", category: "storage")
                        .fault("Storage admission BLOCKED: only \(freeMB, privacy: .public) MB free on the store volume (floor \(self.freeSpaceFloorMB, privacy: .public) MB). Event persistence is PAUSED and \(shed, privacy: .public) buffered events were shed to protect the volume. Detection continues in memory; the forensic record has a gap until space is reclaimed.")
                }
                return
            }
            if admissionBlocked {
                admissionBlocked = false
                Logger(subsystem: "com.maccrab.agentkit", category: "storage")
                    .notice("Storage admission restored — free space back above the floor; event persistence resumed.")
            }
            let batch = buffer
            buffer.removeAll(keepingCapacity: true)
            lowValueCount = 0   // buffer emptied; enqueues during the await re-accrue it
            inFlightDepth = batch.count
            do {
                let result = try await store.insert(events: batch)
                persisted.add(result.persistedCount)
                inFlightDepth = 0
            } catch let partial as EventBatchInsertFailure {
                persisted.add(partial.progress.persistedCount)
                let suffix = partial.uncommittedEvents
                if partial.replacementReadyForRetry {
                    // Corruption recovery quarantined the DB containing any
                    // earlier committed chunks. EventStore resets progress and
                    // returns the full filter-passing batch; the fresh DB is
                    // ready, so retry it instead of falsely counting the old
                    // prefix as durable or permanently shedding recoverable rows.
                    if buffer.count + suffix.count <= hardCap {
                        buffer.insert(contentsOf: suffix, at: 0)
                        lowValueCount += suffix.reduce(0) {
                            $0 + (Self.isHighValue($1) ? 0 : 1)
                        }
                        retries.add(suffix.count)
                        inFlightDepth = 0
                        return
                    }
                } else if let eventError = partial.underlyingError as? EventStoreError,
                   isTransient(eventError) {
                    // Only the rolled-back/unstarted suffix is retried. The
                    // committed prefix is already durable and must never be
                    // duplicated in retry/drop telemetry.
                    if buffer.count + suffix.count <= hardCap {
                        buffer.insert(contentsOf: suffix, at: 0)
                        lowValueCount += suffix.reduce(0) {
                            $0 + (Self.isHighValue($1) ? 0 : 1)
                        }
                        retries.add(suffix.count)
                        inFlightDepth = 0
                        return
                    }
                }
                // Complete the ownership transition before reporting the error:
                // StorageErrorTracker is an actor hop, and heartbeat snapshots
                // must never observe rows in neither in-flight nor drop/retry/
                // persisted accounting while that hop is suspended.
                drops.add(suffix.count)
                inFlightDepth = 0
                await StorageErrorTracker.shared.recordEventError(
                    partial.underlyingError
                )
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
                    lowValueCount += batch.reduce(0) { $0 + (Self.isHighValue($1) ? 0 : 1) }
                    retries.add(batch.count)
                    inFlightDepth = 0
                    return
                }
                drops.add(batch.count)
                inFlightDepth = 0
                await StorageErrorTracker.shared.recordEventError(e)
            } catch {
                // PERMANENT (disk full, corruption, encoding) — retrying the same
                // transaction would just fail again. Record the error AND count the
                // lost events as storage-write drops so they are not silently
                // uncounted: `droppedCount` reflects hard-cap overflow, an
                // unretryable transient, and permanent flush failures.
                drops.add(batch.count)
                inFlightDepth = 0
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
