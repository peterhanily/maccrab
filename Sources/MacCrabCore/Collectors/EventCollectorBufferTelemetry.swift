import Foundation
import os

/// The two final detection lanes. This classifier is shared by collector-side
/// buffers and the downstream merger so a dropped OLD event is attributed with
/// the same rule it would have used had it survived to `DaemonState`.
public enum EventPipelineLane: Int, CaseIterable, Sendable, Hashable {
    case priority
    case file

    public var key: String {
        switch self {
        case .priority: return "priority"
        case .file: return "file"
        }
    }

    public static func routesToFile(_ category: EventCategory, action: String) -> Bool {
        guard category == .file else { return false }
        switch action {
        case "open", "btm_add": return false
        default: return true
        }
    }

    public static func finalLane(for event: Event) -> EventPipelineLane {
        routesToFile(event.eventCategory, action: event.eventAction) ? .file : .priority
    }
}

/// Compile-time bounded identity for every collector feeding the merged
/// detection pipeline. Never derive these labels from event data.
public enum EventPipelineSource: Int, CaseIterable, Sendable, Hashable {
    case endpointSecurity
    case kdebug
    case eslogger
    case unifiedLog
    case tcc
    case network

    public var key: String {
        switch self {
        case .endpointSecurity: return "ESCollector"
        case .kdebug: return "KdebugCollector"
        case .eslogger: return "EsloggerCollector"
        case .unifiedLog: return "UnifiedLogCollector"
        case .tcc: return "TCCMonitor"
        case .network: return "NetworkCollector"
        }
    }
}

/// Source identity must survive inside the downstream bounded stream because
/// `.bufferingNewest` returns the OLD evicted element, not the new offer.
public struct EventPipelineEnvelope: Sendable {
    public let source: EventPipelineSource
    public let event: Event

    public init(source: EventPipelineSource, event: Event) {
        self.source = source
        self.event = event
    }
}

/// One collector's bounded AsyncStream accounting. Arrays are indexed by the
/// fixed two-case lane enum; dictionaries are allocated only by heartbeat reads.
public struct EventCollectorBufferSnapshot: Sendable, Equatable {
    public let offeredByLane: [String: UInt64]
    public let droppedByLane: [String: UInt64]
    public let terminatedByLane: [String: UInt64]
    public let capacity: UInt64

    public init(
        offeredByLane: [String: UInt64],
        droppedByLane: [String: UInt64],
        terminatedByLane: [String: UInt64],
        capacity: UInt64
    ) {
        self.offeredByLane = offeredByLane
        self.droppedByLane = droppedByLane
        self.terminatedByLane = terminatedByLane
        self.capacity = capacity
    }

    public var droppedTotal: UInt64 {
        droppedByLane.values.reduce(UInt64(0), Self.addSaturating)
    }

    public var terminatedTotal: UInt64 {
        terminatedByLane.values.reduce(UInt64(0), Self.addSaturating)
    }

    private static func addSaturating(_ lhs: UInt64, _ rhs: UInt64) -> UInt64 {
        let (sum, overflow) = lhs.addingReportingOverflow(rhs)
        return overflow ? UInt64.max : sum
    }
}

/// Thread-safe fixed-cardinality counters attached to a collector's own
/// AsyncStream boundary. The result and both events are handled in one lock:
/// the new event supplies the offered/terminated lane, while `.dropped`'s OLD
/// event supplies the loss lane.
public final class EventCollectorBufferTelemetry: @unchecked Sendable {
    private struct State {
        var offered = [UInt64](repeating: 0, count: EventPipelineLane.allCases.count)
        var dropped = [UInt64](repeating: 0, count: EventPipelineLane.allCases.count)
        var terminated = [UInt64](repeating: 0, count: EventPipelineLane.allCases.count)
    }

    private let state = OSAllocatedUnfairLock<State>(initialState: State())
    private let capacity: UInt64

    public init(capacity: Int) {
        self.capacity = UInt64(max(0, capacity))
    }

    @inline(__always)
    public func recordYield(
        offered event: Event,
        result: AsyncStream<Event>.Continuation.YieldResult
    ) {
        let offeredLane = EventPipelineLane.finalLane(for: event)
        state.withLock { locked in
            Self.incrementSaturating(&locked.offered[offeredLane.rawValue])
            switch result {
            case .dropped(let oldEvent):
                let droppedLane = EventPipelineLane.finalLane(for: oldEvent)
                Self.incrementSaturating(&locked.dropped[droppedLane.rawValue])
            case .terminated:
                Self.incrementSaturating(&locked.terminated[offeredLane.rawValue])
            case .enqueued:
                break
            @unknown default:
                // A future result cannot be assumed accepted. Count it as a
                // terminal loss so backlog never grows from an unclassified
                // offer and the evidence gap stays visible.
                Self.incrementSaturating(&locked.terminated[offeredLane.rawValue])
            }
        }
    }

    public func snapshot() -> EventCollectorBufferSnapshot {
        state.withLock { locked in
            var offered: [String: UInt64] = [:]
            var dropped: [String: UInt64] = [:]
            var terminated: [String: UInt64] = [:]
            for lane in EventPipelineLane.allCases {
                offered[lane.key] = locked.offered[lane.rawValue]
                dropped[lane.key] = locked.dropped[lane.rawValue]
                terminated[lane.key] = locked.terminated[lane.rawValue]
            }
            return EventCollectorBufferSnapshot(
                offeredByLane: offered,
                droppedByLane: dropped,
                terminatedByLane: terminated,
                capacity: capacity
            )
        }
    }

    @inline(__always)
    private static func incrementSaturating(_ value: inout UInt64) {
        if value < UInt64.max { value += 1 }
    }
}
