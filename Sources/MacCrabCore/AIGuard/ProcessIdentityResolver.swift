// ProcessIdentityResolver.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-6a) — resolves stable process identity before any
// graph operation per §15.1 of the v1.10.0 spec. Wraps the existing
// `ProcessIdentity` type with:
//
//   1. derivation of the canonical `processKey` string;
//   2. PID-recycle detection by comparing each fresh observation against
//      the most recent identity seen for the same pid;
//   3. emission of explicit `pid_recycle_detected` events for downstream
//      rule + alert handling.
//
// This is the third place that compares full `ProcessIdentity` for a
// given pid (after `TraceRegistry` and `MCPAttributor`); the recycle
// counter is shared semantics — surfaced separately here so the v1.10
// graph layer's recycle volume is observable without conflating it
// with v1.9 attribution-layer recycle volume.

import Foundation
import os.log

/// Outcome of identity resolution for a single observation.
public struct ProcessIdentityResolution: Sendable, Equatable {
    public let processKey: String
    public let identity: ProcessIdentity
    public let recycleDetected: Bool
    public let recycleEvent: PIDRecycleEvent?

    public init(
        processKey: String,
        identity: ProcessIdentity,
        recycleDetected: Bool,
        recycleEvent: PIDRecycleEvent?
    ) {
        self.processKey = processKey
        self.identity = identity
        self.recycleDetected = recycleDetected
        self.recycleEvent = recycleEvent
    }
}

/// Explicit record of a PID-recycle observation. Emitted whenever the
/// resolver sees a fresh `ProcessIdentity` for a pid that previously
/// carried a different identity.
public struct PIDRecycleEvent: Sendable, Equatable, Codable {
    public let pid: pid_t
    public let oldProcessKey: String
    public let newProcessKey: String
    public let oldPidversion: UInt32
    public let newPidversion: UInt32
    public let oldPathHash: UInt64
    public let newPathHash: UInt64
    public let detectedAt: Date

    public init(
        pid: pid_t,
        oldProcessKey: String,
        newProcessKey: String,
        oldPidversion: UInt32,
        newPidversion: UInt32,
        oldPathHash: UInt64,
        newPathHash: UInt64,
        detectedAt: Date
    ) {
        self.pid = pid
        self.oldProcessKey = oldProcessKey
        self.newProcessKey = newProcessKey
        self.oldPidversion = oldPidversion
        self.newPidversion = newPidversion
        self.oldPathHash = oldPathHash
        self.newPathHash = newPathHash
        self.detectedAt = detectedAt
    }
}

/// Actor that turns raw `ProcessIdentity` observations into resolved
/// graph-ready entities and surfaces PID-recycle events.
public actor ProcessIdentityResolver {

    // MARK: - Configuration

    /// Cap on the bounded recycle event buffer. Recycles are rare on a
    /// healthy host; the buffer exists so callers that don't drain on
    /// every observation (e.g. periodic flush) don't lose events on a
    /// recycle storm. Default chosen to match the v1.9 attribution-layer
    /// counter cadence (drained per status snapshot).
    private let recycleEventBufferCap: Int

    // MARK: - Storage

    /// Most recent canonical identity observed for each live pid. Keyed
    /// by pid because that's the kernel-given comparator we get from
    /// upstream collectors; equality is determined by full
    /// `ProcessIdentity` (auditIdentity + pathHash), so a recycle
    /// flips the value here even though the key stays the same.
    private var lastSeenByPid: [pid_t: ProcessIdentity] = [:]

    /// Counter incremented every time a recycle is detected. Independent
    /// of `TraceRegistry.pidRecycleRejected` so the v1.10 graph layer
    /// has its own surfaceable telemetry.
    private var pidRecycleRejected: UInt64 = 0

    /// Bounded buffer of recent recycle events for downstream consumers.
    private var recycleEventBuffer: [PIDRecycleEvent] = []

    private let logger = Logger(subsystem: "com.maccrab.tracegraph", category: "process-identity")

    // MARK: - Lifecycle

    public init(recycleEventBufferCap: Int = 256) {
        self.recycleEventBufferCap = max(16, recycleEventBufferCap)
    }

    // MARK: - API

    /// Resolve a fresh observation. If the pid was previously observed
    /// with a different `ProcessIdentity`, the resolver emits a recycle
    /// event and records the new identity as canonical.
    @discardableResult
    public func resolve(_ identity: ProcessIdentity, observedAt: Date = Date()) -> ProcessIdentityResolution {
        let newKey = identity.processKey
        if let prior = lastSeenByPid[identity.pid] {
            if prior == identity {
                return ProcessIdentityResolution(
                    processKey: newKey,
                    identity: identity,
                    recycleDetected: false,
                    recycleEvent: nil
                )
            }
            // Different identity for the same pid → recycle. The mismatch
            // can be on `pidversion`, on any other audit_token field, or
            // on `pathHash` (process exec'd a different binary). All
            // three are legitimate recycle signals.
            pidRecycleRejected &+= 1
            let event = PIDRecycleEvent(
                pid: identity.pid,
                oldProcessKey: prior.processKey,
                newProcessKey: newKey,
                oldPidversion: prior.auditIdentity.pidversion,
                newPidversion: identity.auditIdentity.pidversion,
                oldPathHash: prior.pathHash,
                newPathHash: identity.pathHash,
                detectedAt: observedAt
            )
            appendRecycleEvent(event)
            lastSeenByPid[identity.pid] = identity
            logger.debug("pid recycle detected for pid=\(identity.pid, privacy: .public) old_pidversion=\(prior.auditIdentity.pidversion, privacy: .public) new_pidversion=\(identity.auditIdentity.pidversion, privacy: .public)")
            return ProcessIdentityResolution(
                processKey: newKey,
                identity: identity,
                recycleDetected: true,
                recycleEvent: event
            )
        }

        lastSeenByPid[identity.pid] = identity
        return ProcessIdentityResolution(
            processKey: newKey,
            identity: identity,
            recycleDetected: false,
            recycleEvent: nil
        )
    }

    /// Drop the cached identity for a pid (called on NOTIFY_EXIT to keep
    /// the cache from growing under high fork rates).
    public func evict(pid: pid_t) {
        lastSeenByPid.removeValue(forKey: pid)
    }

    /// Drain the recycle event buffer for downstream emission. The
    /// buffer is cleared as a side effect; the caller is responsible
    /// for routing events into the rule engine / alert sink / unified
    /// log subsystem.
    public func drainRecycleEvents() -> [PIDRecycleEvent] {
        let drained = recycleEventBuffer
        recycleEventBuffer.removeAll(keepingCapacity: true)
        return drained
    }

    /// Snapshot of internal counters for status / dashboard surfaces.
    public func metrics() -> Metrics {
        Metrics(
            trackedPids: lastSeenByPid.count,
            pidRecycleRejected: pidRecycleRejected
        )
    }

    public struct Metrics: Sendable, Codable, Equatable {
        public let trackedPids: Int
        public let pidRecycleRejected: UInt64

        public init(trackedPids: Int, pidRecycleRejected: UInt64) {
            self.trackedPids = trackedPids
            self.pidRecycleRejected = pidRecycleRejected
        }
    }

    // MARK: - Internals

    private func appendRecycleEvent(_ event: PIDRecycleEvent) {
        recycleEventBuffer.append(event)
        if recycleEventBuffer.count > recycleEventBufferCap {
            recycleEventBuffer.removeFirst(recycleEventBuffer.count - recycleEventBufferCap)
        }
    }
}
