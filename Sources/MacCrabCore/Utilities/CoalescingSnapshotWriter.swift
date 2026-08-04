// CoalescingSnapshotWriter.swift
// MacCrabCore
//
// One lifecycle contract for daemon snapshots that are assembled on a service
// actor but encoded and published through synchronous file APIs. A synchronous
// `writeSnapshot` actor method makes its in-flight guard unreachable and stalls
// the feature's live mutations behind disk I/O. This writer moves persistence
// off the owner actor while retaining one active + one latest pending request.

import Foundation
import os.log

public struct CoalescingSnapshotWriterTelemetry: Sendable, Equatable {
    public let offered: UInt64
    public let started: UInt64
    public let completed: UInt64
    public let failed: UInt64
    public let superseded: UInt64
    public let inFlight: Int
    public let pending: Int

    public var conserved: Bool {
        offered == completed
            &+ failed
            &+ superseded
            &+ UInt64(inFlight)
            &+ UInt64(pending)
    }
}

/// Serial, bounded publication for an immutable `Sendable` snapshot.
///
/// `publish` is intentionally async. The caller that starts a generation stays
/// joined until that generation and the newest pending generation complete.
/// Concurrent callers merely replace the single pending value and return, so
/// a slow disk can never retain an unbounded queue of complete snapshots.
/// Persistence runs in a detached task whose handle is immediately awaited; it
/// is therefore owned, while the caller's feature actor is free to record live
/// state during the blocking encode/write.
actor CoalescingSnapshotWriter<Snapshot: Sendable> {
    typealias Persistence = @Sendable (Snapshot, String) -> String?

    private struct Request: Sendable {
        let generation: UInt64
        let path: String
        let snapshot: Snapshot
    }

    private let logger: Logger
    private let persistence: Persistence
    private var active = false
    private var pendingRequest: Request?
    private var nextGeneration: UInt64 = 0
    private var offered: UInt64 = 0
    private var started: UInt64 = 0
    private var completed: UInt64 = 0
    private var failed: UInt64 = 0
    private var superseded: UInt64 = 0

    init(category: String, persistence: @escaping Persistence) {
        self.logger = Logger(
            subsystem: "com.maccrab.core",
            category: String(category.prefix(64))
        )
        self.persistence = persistence
    }

    func publish(_ snapshot: Snapshot, to path: String) async {
        nextGeneration &+= 1
        offered &+= 1
        let request = Request(
            generation: nextGeneration,
            path: path,
            snapshot: snapshot
        )

        guard !active else {
            if pendingRequest != nil {
                superseded &+= 1
            }
            pendingRequest = request
            return
        }

        active = true
        var current = request
        while true {
            started &+= 1
            let persistence = self.persistence
            let requestToPersist = current
            let failure = await Task.detached(priority: .utility) {
                persistence(requestToPersist.snapshot, requestToPersist.path)
            }.value

            if let failure {
                failed &+= 1
                logger.warning(
                    "Snapshot generation \(requestToPersist.generation) failed: \(String(failure.prefix(512)), privacy: .public)"
                )
            } else {
                completed &+= 1
            }

            if let pending = pendingRequest {
                pendingRequest = nil
                current = pending
            } else {
                active = false
                return
            }
        }
    }

    func telemetry() -> CoalescingSnapshotWriterTelemetry {
        CoalescingSnapshotWriterTelemetry(
            offered: offered,
            started: started,
            completed: completed,
            failed: failed,
            superseded: superseded,
            inFlight: active ? 1 : 0,
            pending: pendingRequest == nil ? 0 : 1
        )
    }
}
