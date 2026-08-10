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
// existing batch transaction `EventStore.insert(events:lane:)` — hundreds of
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
// detection still saw every event; only its events.db row was shed. At the
// shared cap, priority input may replace the newest queued file-lane row.

import Foundation
import MacCrabCore
import os.log

/// The single events.db capability the batched writer needs. A protocol (rather
/// than the concrete `EventStore`) so tests can inject a fake that throws
/// `EventStoreError.busy` on demand to exercise the #13 transient-retry path.
/// `EventStore` (an actor) satisfies the async requirement via its isolation.
protocol EventBatchInserting: Sendable {
    func insert(
        events: [Event],
        lane: EventPipelineLane
    ) async throws -> EventBatchInsertResult
}

extension EventStore: EventBatchInserting {}

actor BatchedEventWriter {
    private struct BufferedEvent: Sendable {
        let generation: UInt64
        let event: Event
    }

    struct TelemetrySnapshot: Sendable, Equatable {
        /// Every hand-off from EventLoop, including rows rejected at the hard
        /// cap. Together with the terminal counters and the two gauges below,
        /// this is an exact per-lane conservation ledger:
        /// offered = persisted + filtered + dropped + buffered + in-flight.
        let offeredByLane: [String: Int]
        /// Rows permanently shed after the detection loop saw the event.
        let droppedCount: Int
        let droppedByLane: [String: Int]
        /// Cumulative retry attempts; a row can contribute more than once.
        let retriedCount: Int
        let retriedByLane: [String: Int]
        /// Rows reported committed at write time. This cumulative history is not
        /// decremented if a later corruption recovery quarantines that database.
        let persistedCount: Int
        let persistedByLane: [String: Int]
        /// Intentional EventInsertFilter decisions. These are terminal storage
        /// outcomes, not writer sheds and not detection-input losses.
        let filteredCount: Int
        let filteredByLane: [String: Int]
        /// Rows waiting in the actor's queue at snapshot time. A batch currently
        /// suspended inside `store.insert` is not part of this queue gauge; it is
        /// reported separately by `inFlightDepth`.
        let bufferDepth: Int
        let bufferDepthByLane: [String: Int]
        /// Rows detached from the queue and currently owned by one asynchronous
        /// `store.insert` call. This closes the heartbeat reconciliation gap where
        /// the queue could read zero before the corresponding persisted/drop
        /// counters advanced.
        let inFlightDepth: Int
        let inFlightDepthByLane: [String: Int]
        /// Highest event accepted into the bounded writer and highest
        /// contiguous generation that reached a terminal persistence outcome.
        /// Evidence capture waits on this ledger instead of racing the 250 ms
        /// batch window.
        let admittedGeneration: UInt64
        let terminalGeneration: UInt64
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

    /// Separate queues make the storage policy explicit: priority rows are
    /// always detached before file-firehose rows, and every database batch is
    /// lane-homogeneous. The latter is what makes EventStore's aggregate
    /// persisted/filtered result attributable without guessing.
    private var buffers = [[BufferedEvent]](
        repeating: [], count: EventPipelineLane.allCases.count
    )
    /// Exactly one drain runs at a time, so this is either zero or the complete
    /// detached batch suspended in `store.insert(events:lane:)`.
    private var inFlightDepth = 0
    private var inFlightDepthByLane = [Int](
        repeating: 0, count: EventPipelineLane.allCases.count
    )
    private var admittedGeneration: UInt64 = 0
    private var terminalGeneration: UInt64 = 0
    /// Accepted generations without a terminal persistence outcome. This set
    /// is bounded by the writer hard cap plus its one detached batch; unlike an
    /// out-of-order terminal history, it cannot grow forever if a file-lane row
    /// remains behind sustained priority traffic.
    private var pendingGenerations: Set<UInt64> = []

    private var draining = false
    /// Joinable handle for both threshold-triggered and timer-triggered drains.
    /// Shutdown must not infer completion from `draining`: the actor can be
    /// suspended inside SQLite while that flag is true.
    private var drainTask: Task<Void, Never>?
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
    /// Actor-isolated lane ledgers. Totals above remain lock-backed for the
    /// existing nonisolated compatibility accessors.
    private var offeredByLane = [Int](
        repeating: 0, count: EventPipelineLane.allCases.count
    )
    private var droppedByLane = [Int](
        repeating: 0, count: EventPipelineLane.allCases.count
    )
    private var retriedByLane = [Int](
        repeating: 0, count: EventPipelineLane.allCases.count
    )
    private var persistedByLane = [Int](
        repeating: 0, count: EventPipelineLane.allCases.count
    )
    private var filteredByLane = [Int](
        repeating: 0, count: EventPipelineLane.allCases.count
    )

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
            offeredByLane: laneDictionary(offeredByLane),
            droppedCount: drops.get(),
            droppedByLane: laneDictionary(droppedByLane),
            retriedCount: retries.get(),
            retriedByLane: laneDictionary(retriedByLane),
            persistedCount: persisted.get(),
            persistedByLane: laneDictionary(persistedByLane),
            filteredCount: filteredByLane.reduce(0, +),
            filteredByLane: laneDictionary(filteredByLane),
            bufferDepth: bufferDepth,
            bufferDepthByLane: laneDictionary(buffers.map(\.count)),
            inFlightDepth: inFlightDepth,
            inFlightDepthByLane: laneDictionary(inFlightDepthByLane),
            admittedGeneration: admittedGeneration,
            terminalGeneration: terminalGeneration
        )
    }

    private var bufferDepth: Int {
        buffers.reduce(0) { $0 + $1.count }
    }

    private func laneDictionary(_ values: [Int]) -> [String: Int] {
        var result: [String: Int] = [:]
        for lane in EventPipelineLane.allCases {
            result[lane.key] = values[lane.rawValue]
        }
        return result
    }

    private func recordDrop(_ count: Int, lane: EventPipelineLane) {
        guard count > 0 else { return }
        drops.add(count)
        droppedByLane[lane.rawValue] += count
    }

    private func recordRetry(_ count: Int, lane: EventPipelineLane) {
        guard count > 0 else { return }
        retries.add(count)
        retriedByLane[lane.rawValue] += count
    }

    private func recordPersisted(_ count: Int, lane: EventPipelineLane) {
        guard count > 0 else { return }
        persisted.add(count)
        persistedByLane[lane.rawValue] += count
    }

    private func recordFiltered(_ count: Int, lane: EventPipelineLane) {
        guard count > 0 else { return }
        filteredByLane[lane.rawValue] += count
    }

    private func setInFlight(_ count: Int, lane: EventPipelineLane) {
        inFlightDepth = count
        inFlightDepthByLane[lane.rawValue] = count
    }

    private func clearInFlight(lane: EventPipelineLane) {
        inFlightDepth = 0
        inFlightDepthByLane[lane.rawValue] = 0
    }

    private func markTerminal(_ events: some Collection<BufferedEvent>) {
        for item in events {
            pendingGenerations.remove(item.generation)
        }
        if let oldestPending = pendingGenerations.min() {
            terminalGeneration = oldestPending > 0 ? oldestPending - 1 : 0
        } else {
            terminalGeneration = admittedGeneration
        }
    }

    /// Priority first. A batch is deliberately one lane only so the store's
    /// aggregate result remains exactly attributable.
    private func detachNextBatch() -> (
        lane: EventPipelineLane,
        events: [BufferedEvent]
    )? {
        for lane in [EventPipelineLane.priority, .file]
        where !buffers[lane.rawValue].isEmpty {
            let batch = buffers[lane.rawValue]
            buffers[lane.rawValue].removeAll(keepingCapacity: true)
            return (lane, batch)
        }
        return nil
    }

    private func prependForRetry(
        _ events: [BufferedEvent],
        lane: EventPipelineLane
    ) -> Bool {
        guard events.count <= hardCap else { return false }
        let available = max(0, hardCap - bufferDepth)
        if events.count > available {
            // The detached batch is older than everything admitted while its
            // SQLite write was suspended. Prefer it over newer work without
            // weakening the one-way lane policy: evict newest file rows first;
            // a priority retry may then evict newer priority rows, while a file
            // retry may never displace priority.
            let fileIndex = EventPipelineLane.file.rawValue
            let evictionCount = events.count - available
            let fileEvictionCount = min(
                evictionCount,
                buffers[fileIndex].count
            )
            let priorityEvictionCount = evictionCount - fileEvictionCount
            guard lane == .priority || priorityEvictionCount == 0 else {
                return false
            }
            let priorityIndex = EventPipelineLane.priority.rawValue
            guard buffers[priorityIndex].count >= priorityEvictionCount else {
                return false
            }

            if fileEvictionCount > 0 {
                let evictedFile = Array(
                    buffers[fileIndex].suffix(fileEvictionCount)
                )
                buffers[fileIndex].removeLast(fileEvictionCount)
                recordDrop(fileEvictionCount, lane: .file)
                markTerminal(evictedFile)
            }
            if priorityEvictionCount > 0 {
                let evictedPriority = Array(
                    buffers[priorityIndex].suffix(priorityEvictionCount)
                )
                buffers[priorityIndex].removeLast(priorityEvictionCount)
                recordDrop(priorityEvictionCount, lane: .priority)
                markTerminal(evictedPriority)
            }
        }
        buffers[lane.rawValue].insert(contentsOf: events, at: 0)
        recordRetry(events.count, lane: lane)
        return true
    }

    /// Reattach EventStore's exact filter-passing remainder to the writer's
    /// generation-bearing envelopes. Filtered rows can occur anywhere in the
    /// original batch, so a count-based array suffix is not an identity map.
    /// Match the complete immutable event value rather than UUID alone: callers
    /// may legally supply the same UUID on distinct values, and EventStore treats
    /// that identifier as a first-writer-wins persistence key. Scan from the end
    /// so truly identical duplicates retain candidate-suffix semantics, while
    /// counts preserve the complete multiset.
    private func partitionPartialFailure(
        _ batch: [BufferedEvent],
        uncommittedEvents: [Event]
    ) -> (terminal: [BufferedEvent], uncommitted: [BufferedEvent])? {
        guard uncommittedEvents.count <= batch.count else { return nil }
        var remainingByEvent: [Event: Int] = [:]
        for event in uncommittedEvents {
            remainingByEvent[event, default: 0] += 1
        }

        var terminalReversed: [BufferedEvent] = []
        var uncommittedReversed: [BufferedEvent] = []
        terminalReversed.reserveCapacity(batch.count - uncommittedEvents.count)
        uncommittedReversed.reserveCapacity(uncommittedEvents.count)
        for item in batch.reversed() {
            if let remaining = remainingByEvent[item.event], remaining > 0 {
                uncommittedReversed.append(item)
                if remaining == 1 {
                    remainingByEvent.removeValue(forKey: item.event)
                } else {
                    remainingByEvent[item.event] = remaining - 1
                }
            } else {
                terminalReversed.append(item)
            }
        }
        guard remainingByEvent.isEmpty else { return nil }

        let uncommitted = Array(uncommittedReversed.reversed())
        guard uncommitted.map(\.event) == uncommittedEvents else {
            return nil
        }
        return (
            terminal: Array(terminalReversed.reversed()),
            uncommitted: uncommitted
        )
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
    ///   satisfy 1000 <= 20_000. The former 250K default could itself retain
    ///   hundreds of MiB of Event object graphs, defeating the product RSS
    ///   budget before it ever became a useful backpressure boundary.
    init(
        store: any EventBatchInserting,
        flushThreshold: Int = 1000,
        hardCap: Int = 20_000,
        volumePath: String? = nil,
        freeSpaceFloorMB: Int = 1024
    ) {
        self.volumePath = volumePath
        self.freeSpaceFloorMB = max(0, freeSpaceFloorMB)
        self.store = store
        self.flushThreshold = max(1, flushThreshold)
        self.hardCap = max(1, hardCap)
    }

    /// O(1) hand-off from the hot consumer. The explicit pipeline lane is
    /// preserved through storage rather than re-inferred from a broader
    /// "file category = cheap" rule (credential OPEN is a file-category event
    /// that deliberately rides the priority lane).
    ///
    /// At the shared hard cap an incoming priority event evicts the newest file
    /// row, while a file event can never evict priority. This preserves the
    /// existing total memory bound; it does not raise or partition the cap.
    @discardableResult
    func enqueue(
        _ event: Event,
        lane explicitLane: EventPipelineLane? = nil
    ) -> UInt64? {
        let lane = explicitLane ?? EventPipelineLane.finalLane(for: event)
        offeredByLane[lane.rawValue] += 1

        if bufferDepth >= hardCap {
            if lane == .priority, !buffers[EventPipelineLane.file.rawValue].isEmpty {
                // O(1): evict the newest queued file row. `removeFirst()` shifts
                // up to the full queue on every priority arrival in exactly the
                // saturated-file episode this policy exists to survive. Keeping
                // the older prefix also preserves more chronological continuity.
                let evicted = buffers[EventPipelineLane.file.rawValue].removeLast()
                recordDrop(1, lane: .file)
                markTerminal(CollectionOfOne(evicted))
            } else {
                recordDrop(1, lane: lane)
                return nil
            }
        }
        guard admittedGeneration < UInt64.max else {
            recordDrop(1, lane: lane)
            return nil
        }
        admittedGeneration += 1
        let generation = admittedGeneration
        pendingGenerations.insert(generation)
        buffers[lane.rawValue].append(
            BufferedEvent(generation: generation, event: event)
        )
        if bufferDepth >= flushThreshold && !draining {
            startDrain()
        }
        return generation
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
        defer {
            draining = false
            drainTask = nil
        }
        while bufferDepth > 0 {
            // Disk admission check BEFORE the write, not after SQLite fails. Shed
            // the batch and stop the pass; the periodic flush loop retries, so
            // ingestion resumes by itself once the retention sweeps free space.
            if let freeMB = admissionBlockedFreeMB() {
                let priorityRows = buffers[EventPipelineLane.priority.rawValue]
                let fileRows = buffers[EventPipelineLane.file.rawValue]
                let priorityShed = priorityRows.count
                let fileShed = fileRows.count
                buffers[EventPipelineLane.priority.rawValue].removeAll(keepingCapacity: true)
                buffers[EventPipelineLane.file.rawValue].removeAll(keepingCapacity: true)
                recordDrop(priorityShed, lane: .priority)
                recordDrop(fileShed, lane: .file)
                markTerminal(priorityRows)
                markTerminal(fileRows)
                let shed = priorityShed + fileShed
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
            guard let detached = detachNextBatch() else { return }
            let lane = detached.lane
            let batch = detached.events
            setInFlight(batch.count, lane: lane)
            do {
                let result = try await store.insert(
                    events: batch.map(\.event),
                    lane: lane
                )
                recordPersisted(result.persistedCount, lane: lane)
                recordFiltered(result.filteredCount, lane: lane)
                markTerminal(batch)
                clearInFlight(lane: lane)
            } catch let partial as EventBatchInsertFailure {
                let transient = (partial.underlyingError as? EventStoreError)
                    .map(isTransient) ?? false
                let retryable = partial.replacementReadyForRetry || transient
                guard let disposition = partitionPartialFailure(
                    batch,
                    uncommittedEvents: partial.uncommittedEvents
                ), disposition.terminal.count
                    == partial.progress.persistedCount
                        + partial.progress.filteredCount else {
                    // Never guess at identity from malformed aggregate counts.
                    // Retrying the complete batch is safe on a transient or a
                    // fresh replacement because immutable event IDs make the
                    // already-durable portion duplicate no-ops.
                    if retryable, prependForRetry(batch, lane: lane) {
                        clearInFlight(lane: lane)
                        return
                    }
                    recordDrop(batch.count, lane: lane)
                    markTerminal(batch)
                    clearInFlight(lane: lane)
                    await StorageErrorTracker.shared.recordEventError(
                        partial.underlyingError
                    )
                    continue
                }
                recordPersisted(partial.progress.persistedCount, lane: lane)
                recordFiltered(partial.progress.filteredCount, lane: lane)
                markTerminal(disposition.terminal)
                if partial.replacementReadyForRetry {
                    // Corruption recovery quarantined the DB containing any
                    // earlier committed chunks. EventStore resets progress and
                    // returns every exact filter-passing candidate; filtered
                    // envelopes are terminal while those candidates retry.
                    if prependForRetry(disposition.uncommitted, lane: lane) {
                        clearInFlight(lane: lane)
                        return
                    }
                } else if transient {
                    // Only the exact rolled-back/unstarted identities retry.
                    // Arbitrarily-positioned filtered rows are already terminal
                    // and must never be substituted by a positional suffix.
                    if prependForRetry(disposition.uncommitted, lane: lane) {
                        clearInFlight(lane: lane)
                        return
                    }
                }
                // Complete the ownership transition before reporting the error:
                // StorageErrorTracker is an actor hop, and heartbeat snapshots
                // must never observe rows in neither in-flight nor drop/retry/
                // persisted accounting while that hop is suspended.
                recordDrop(disposition.uncommitted.count, lane: lane)
                markTerminal(disposition.uncommitted)
                clearInFlight(lane: lane)
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
                if prependForRetry(batch, lane: lane) {
                    clearInFlight(lane: lane)
                    return
                }
                recordDrop(batch.count, lane: lane)
                markTerminal(batch)
                clearInFlight(lane: lane)
                await StorageErrorTracker.shared.recordEventError(e)
            } catch {
                // PERMANENT (disk full, corruption, encoding) — retrying the same
                // transaction would just fail again. Record the error AND count the
                // lost events as storage-write drops so they are not silently
                // uncounted: `droppedCount` reflects hard-cap overflow, an
                // unretryable transient, and permanent flush failures.
                recordDrop(batch.count, lane: lane)
                markTerminal(batch)
                clearInFlight(lane: lane)
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

    /// Capture the writer generation admitted before an alert's evidence job.
    /// A generation is assigned only after the bounded queue accepts the row;
    /// queue-cap rejection remains visible through ordinary drop telemetry.
    func evidencePrefixGeneration() -> UInt64 {
        admittedGeneration
    }

    /// Wait a bounded interval for every admitted generation through `target`
    /// to reach persisted, filtered, or explicitly-dropped terminal state.
    /// This preserves batching: the wait joins the ordinary drain rather than
    /// issuing a per-alert SQLite transaction. False is an honest context gap;
    /// AlertSink still retains the request's bounded triggering-event snapshot.
    func awaitEvidencePrefix(
        through target: UInt64,
        timeout: Duration = .seconds(2)
    ) async -> Bool {
        guard target > terminalGeneration else { return true }
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: timeout)
        if !draining, bufferDepth > 0 {
            startDrain()
        }
        while terminalGeneration < target {
            guard !Task.isCancelled, clock.now < deadline else {
                return false
            }
            try? await Task.sleep(for: .milliseconds(10))
            if !draining, bufferDepth > 0 {
                startDrain()
            }
        }
        return true
    }

    /// Flush a below-threshold partial batch (called by the timer + on shutdown).
    func flushPartial() async {
        if let task = drainTask {
            await task.value
            return
        }
        if bufferDepth > 0 {
            startDrain()
            if let task = drainTask {
                await task.value
            }
        }
    }

    /// Stop the timer and flush anything still buffered. Call on graceful
    /// daemon teardown so the last partial batch reaches disk.
    func shutdown() async {
        let timer = flushLoop
        flushLoop = nil
        timer?.cancel()
        await timer?.value

        // A threshold-triggered drain is independent of the timer. Join it too
        // before the final partial pass, then capture anything queued between
        // those joins and this actor turn.
        if let task = drainTask {
            await task.value
        }
        await flushPartial()
    }

    private func startDrain() {
        guard !draining, drainTask == nil, bufferDepth > 0 else { return }
        draining = true
        drainTask = Task { [weak self] in
            await self?.drain()
        }
    }
}
