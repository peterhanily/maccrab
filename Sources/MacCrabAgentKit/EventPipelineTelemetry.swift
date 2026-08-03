import Foundation
import MacCrabCore
import os

/// Lock-bounded telemetry for the merged event pipeline. All hot-path storage
/// is allocated at initialization: recording an event performs only fixed-array
/// indexing under the same unfair-lock primitive already used by DaemonState.
/// This is measurement only; it never gates, delays, or reorders an event.
final class EventPipelineTelemetry: @unchecked Sendable {
    struct Snapshot: Sendable, Equatable {
        /// Events that survived each collector's own bounded stream and were
        /// offered to the downstream merger.
        let offeredBySource: [String: UInt64]
        /// Fixed source × lane cross-tab. Separate source/lane marginals cannot
        /// prove whether Unified Log or ES supplied a saturated file lane.
        let offeredBySourceAndLane: [String: [String: UInt64]]
        /// All buffer losses, upstream plus downstream, with no stage double
        /// counting. The stage-specific cross-tabs below retain causality.
        let droppedBySourceAndLane: [String: [String: UInt64]]
        let terminatedBySourceAndLane: [String: [String: UInt64]]
        let collectorOfferedBySourceAndLane: [String: [String: UInt64]]
        let upstreamDroppedBySourceAndLane: [String: [String: UInt64]]
        let upstreamTerminatedBySourceAndLane: [String: [String: UInt64]]
        let mergedDroppedBySourceAndLane: [String: [String: UInt64]]
        let mergedTerminatedBySourceAndLane: [String: [String: UInt64]]
        let offeredByLane: [String: UInt64]
        let dequeuedByLane: [String: UInt64]
        /// One event-level mark immediately before RuleEngine evaluation starts,
        /// cross-tabbed by its fixed detection lane and normalized category.
        let ruleEvaluationReachedByLaneAndCategory: [String: [String: UInt64]]
        /// One event-level mark after both RuleEngine and SequenceEngine return.
        /// A reached/completed delta therefore identifies work parked inside the
        /// rule boundary without counting individual rules or matches.
        let ruleEvaluationCompletedByLaneAndCategory: [String: [String: UInt64]]
        let completedByLane: [String: UInt64]
        let backlogEstimateByLane: [String: UInt64]
        let inFlightByLane: [String: UInt64]
        let processingP99MicrosByLane: [String: UInt64]
        /// Sum of the fixed latency buckets. This must equal completed events
        /// for each lane and makes histogram-accounting drift observable.
        let latencySampleCountByLane: [String: UInt64]
        let upstreamDroppedByLane: [String: UInt64]
        let upstreamTerminatedByLane: [String: UInt64]
        let mergedDroppedByLane: [String: UInt64]
        let mergedTerminatedByLane: [String: UInt64]
        let collectorCapacityBySource: [String: UInt64]
        let detectionInputDroppedTotal: UInt64
    }

    private struct State {
        var offeredBySource: [UInt64]
        /// Source-major flattened storage: source * laneCount + lane.
        var offeredBySourceAndLane: [UInt64]
        var droppedBySourceAndLane: [UInt64]
        var terminatedBySourceAndLane: [UInt64]
        var offeredByLane: [UInt64]
        var droppedByLane: [UInt64]
        var terminatedByLane: [UInt64]
        var dequeuedByLane: [UInt64]
        /// Lane-major flattened storage: lane * categoryCount + category.
        var ruleEvaluationReachedByLaneAndCategory: [UInt64]
        var ruleEvaluationCompletedByLaneAndCategory: [UInt64]
        var completedByLane: [UInt64]
        /// Lane-major flattened storage: lane * bucketCount + bucket.
        var latencyBuckets: [UInt64]

        init(sourceCount: Int, laneCount: Int, bucketCount: Int) {
            offeredBySource = [UInt64](repeating: 0, count: sourceCount)
            offeredBySourceAndLane = [UInt64](
                repeating: 0,
                count: sourceCount * laneCount
            )
            droppedBySourceAndLane = [UInt64](
                repeating: 0,
                count: sourceCount * laneCount
            )
            terminatedBySourceAndLane = [UInt64](
                repeating: 0,
                count: sourceCount * laneCount
            )
            offeredByLane = [UInt64](repeating: 0, count: laneCount)
            droppedByLane = [UInt64](repeating: 0, count: laneCount)
            terminatedByLane = [UInt64](repeating: 0, count: laneCount)
            dequeuedByLane = [UInt64](repeating: 0, count: laneCount)
            ruleEvaluationReachedByLaneAndCategory = [UInt64](
                repeating: 0,
                count: laneCount * EventCategory.allCases.count
            )
            ruleEvaluationCompletedByLaneAndCategory = [UInt64](
                repeating: 0,
                count: laneCount * EventCategory.allCases.count
            )
            completedByLane = [UInt64](repeating: 0, count: laneCount)
            latencyBuckets = [UInt64](
                repeating: 0,
                count: laneCount * bucketCount
            )
        }
    }

    /// Upper-inclusive processing-time buckets. The overflow bucket reports the
    /// largest finite bound (60 s), which is already an actionable stall rather
    /// than a claim that the exact over-bound duration is known.
    private static let latencyBoundsMicros: [UInt64] = [
        100, 250, 500,
        1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 64_000,
        128_000, 256_000, 512_000,
        1_000_000, 2_000_000, 5_000_000, 10_000_000, 30_000_000, 60_000_000,
    ]
    private static let bucketCount = latencyBoundsMicros.count + 1

    private let state: OSAllocatedUnfairLock<State>

    init() {
        state = OSAllocatedUnfairLock(
            initialState: State(
                sourceCount: EventPipelineSource.allCases.count,
                laneCount: EventPipelineLane.allCases.count,
                bucketCount: Self.bucketCount
            )
        )
    }

    @inline(__always)
    func recordOffered(source: EventPipelineSource, lane: EventPipelineLane) {
        state.withLock { locked in
            Self.incrementSaturating(&locked.offeredBySource[source.rawValue])
            let crossIndex = source.rawValue * EventPipelineLane.allCases.count
                + lane.rawValue
            Self.incrementSaturating(
                &locked.offeredBySourceAndLane[crossIndex]
            )
            Self.incrementSaturating(&locked.offeredByLane[lane.rawValue])
        }
    }

    @inline(__always)
    func recordDequeued(lane: EventPipelineLane) {
        state.withLock { locked in
            Self.incrementSaturating(&locked.dequeuedByLane[lane.rawValue])
        }
    }

    /// Mark one event entering the single-event + sequence-rule boundary. This
    /// is event cardinality, not the number of rules evaluated or matches found.
    @inline(__always)
    func recordRuleEvaluationReached(
        lane: EventPipelineLane,
        category: EventCategory
    ) {
        let index = Self.ruleEvaluationIndex(lane: lane, category: category)
        state.withLock { locked in
            Self.incrementSaturating(
                &locked.ruleEvaluationReachedByLaneAndCategory[index]
            )
        }
    }

    /// Mark the same event after both RuleEngine and SequenceEngine returned.
    @inline(__always)
    func recordRuleEvaluationCompleted(
        lane: EventPipelineLane,
        category: EventCategory
    ) {
        let index = Self.ruleEvaluationIndex(lane: lane, category: category)
        state.withLock { locked in
            Self.incrementSaturating(
                &locked.ruleEvaluationCompletedByLaneAndCategory[index]
            )
        }
    }

    @inline(__always)
    func recordDropped(source: EventPipelineSource, lane: EventPipelineLane) {
        state.withLock { locked in
            let crossIndex = source.rawValue * EventPipelineLane.allCases.count
                + lane.rawValue
            Self.incrementSaturating(
                &locked.droppedBySourceAndLane[crossIndex]
            )
            Self.incrementSaturating(&locked.droppedByLane[lane.rawValue])
        }
    }

    @inline(__always)
    func recordTerminated(source: EventPipelineSource, lane: EventPipelineLane) {
        state.withLock { locked in
            let crossIndex = source.rawValue * EventPipelineLane.allCases.count
                + lane.rawValue
            Self.incrementSaturating(
                &locked.terminatedBySourceAndLane[crossIndex]
            )
            Self.incrementSaturating(&locked.terminatedByLane[lane.rawValue])
        }
    }

    /// The production downstream boundary in one operation. The continuation
    /// decides which OLD envelope was evicted; one telemetry lock then records
    /// the new offer and the exact old source/lane (or terminal new loss).
    @inline(__always)
    func yield(
        _ envelope: EventPipelineEnvelope,
        to continuation: AsyncStream<EventPipelineEnvelope>.Continuation,
        lane: EventPipelineLane
    ) {
        let result = continuation.yield(envelope)
        state.withLock { locked in
            Self.incrementSaturating(&locked.offeredBySource[envelope.source.rawValue])
            let offeredCross = envelope.source.rawValue * EventPipelineLane.allCases.count
                + lane.rawValue
            Self.incrementSaturating(&locked.offeredBySourceAndLane[offeredCross])
            Self.incrementSaturating(&locked.offeredByLane[lane.rawValue])

            switch result {
            case .dropped(let oldEnvelope):
                let oldLane = EventPipelineLane.finalLane(for: oldEnvelope.event)
                let droppedCross = oldEnvelope.source.rawValue
                    * EventPipelineLane.allCases.count + oldLane.rawValue
                Self.incrementSaturating(&locked.droppedBySourceAndLane[droppedCross])
                Self.incrementSaturating(&locked.droppedByLane[oldLane.rawValue])
            case .terminated:
                Self.incrementSaturating(&locked.terminatedBySourceAndLane[offeredCross])
                Self.incrementSaturating(&locked.terminatedByLane[lane.rawValue])
            case .enqueued:
                break
            @unknown default:
                Self.incrementSaturating(&locked.terminatedBySourceAndLane[offeredCross])
                Self.incrementSaturating(&locked.terminatedByLane[lane.rawValue])
            }
        }
    }

    @inline(__always)
    func recordCompleted(lane: EventPipelineLane, elapsedNanos: UInt64) {
        let elapsedMicros = elapsedNanos / 1_000
        var bucket = Self.latencyBoundsMicros.count
        for candidate in Self.latencyBoundsMicros.indices
        where elapsedMicros <= Self.latencyBoundsMicros[candidate] {
            bucket = candidate
            break
        }
        let selectedBucket = bucket

        state.withLock { locked in
            Self.incrementSaturating(&locked.completedByLane[lane.rawValue])
            let flatIndex = lane.rawValue * Self.bucketCount + selectedBucket
            Self.incrementSaturating(&locked.latencyBuckets[flatIndex])
        }
    }

    /// Snapshot cumulative counters. For `.bufferingNewest`, every `.dropped`
    /// result evicts one queued event while accepting the new one; `.terminated`
    /// rejects the new event. Therefore offered − dropped − terminated − dequeued
    /// is the queued-depth estimate (apart from a concurrent handoff). Every
    /// downstream marginal and cross-tab comes from this single locked state.
    func snapshot(
        upstreamBuffers: [EventPipelineSource: EventCollectorBufferSnapshot] = [:]
    ) -> Snapshot {
        state.withLock { locked in
            var offeredBySource: [String: UInt64] = [:]
            var offeredBySourceAndLane: [String: [String: UInt64]] = [:]
            var droppedBySourceAndLane: [String: [String: UInt64]] = [:]
            var terminatedBySourceAndLane: [String: [String: UInt64]] = [:]
            var collectorOfferedBySourceAndLane: [String: [String: UInt64]] = [:]
            var upstreamDroppedBySourceAndLane: [String: [String: UInt64]] = [:]
            var upstreamTerminatedBySourceAndLane: [String: [String: UInt64]] = [:]
            var mergedDroppedBySourceAndLane: [String: [String: UInt64]] = [:]
            var mergedTerminatedBySourceAndLane: [String: [String: UInt64]] = [:]
            var offeredByLane: [String: UInt64] = [:]
            var dequeuedByLane: [String: UInt64] = [:]
            var ruleEvaluationReachedByLaneAndCategory: [String: [String: UInt64]] = [:]
            var ruleEvaluationCompletedByLaneAndCategory: [String: [String: UInt64]] = [:]
            var completedByLane: [String: UInt64] = [:]
            var backlogByLane: [String: UInt64] = [:]
            var inFlightByLane: [String: UInt64] = [:]
            var p99ByLane: [String: UInt64] = [:]
            var latencySamplesByLane: [String: UInt64] = [:]
            var upstreamDroppedByLane: [String: UInt64] = [:]
            var upstreamTerminatedByLane: [String: UInt64] = [:]
            var mergedDroppedByLane: [String: UInt64] = [:]
            var mergedTerminatedByLane: [String: UInt64] = [:]
            var collectorCapacityBySource: [String: UInt64] = [:]
            var detectionInputDroppedTotal: UInt64 = 0

            for source in EventPipelineSource.allCases {
                offeredBySource[source.key] = locked.offeredBySource[source.rawValue]
                let collector = upstreamBuffers[source]
                collectorCapacityBySource[source.key] = collector?.capacity ?? 0
                var offeredLaneCounts: [String: UInt64] = [:]
                var combinedDroppedLaneCounts: [String: UInt64] = [:]
                var combinedTerminatedLaneCounts: [String: UInt64] = [:]
                var collectorOfferedLaneCounts: [String: UInt64] = [:]
                var upstreamDroppedLaneCounts: [String: UInt64] = [:]
                var upstreamTerminatedLaneCounts: [String: UInt64] = [:]
                var mergedDroppedLaneCounts: [String: UInt64] = [:]
                var mergedTerminatedLaneCounts: [String: UInt64] = [:]
                for lane in EventPipelineLane.allCases {
                    let crossIndex = source.rawValue * EventPipelineLane.allCases.count
                        + lane.rawValue
                    let upstreamDropped = collector?.droppedByLane[lane.key] ?? 0
                    let upstreamTerminated = collector?.terminatedByLane[lane.key] ?? 0
                    let mergedDropped = locked.droppedBySourceAndLane[crossIndex]
                    let mergedTerminated = locked.terminatedBySourceAndLane[crossIndex]
                    let combinedDropped = Self.addSaturating(upstreamDropped, mergedDropped)
                    let combinedTerminated = Self.addSaturating(
                        upstreamTerminated,
                        mergedTerminated
                    )

                    offeredLaneCounts[lane.key] = locked.offeredBySourceAndLane[crossIndex]
                    collectorOfferedLaneCounts[lane.key] = collector?.offeredByLane[lane.key] ?? 0
                    upstreamDroppedLaneCounts[lane.key] = upstreamDropped
                    upstreamTerminatedLaneCounts[lane.key] = upstreamTerminated
                    mergedDroppedLaneCounts[lane.key] = mergedDropped
                    mergedTerminatedLaneCounts[lane.key] = mergedTerminated
                    combinedDroppedLaneCounts[lane.key] = combinedDropped
                    combinedTerminatedLaneCounts[lane.key] = combinedTerminated
                    detectionInputDroppedTotal = Self.addSaturating(
                        detectionInputDroppedTotal,
                        Self.addSaturating(combinedDropped, combinedTerminated)
                    )
                }
                offeredBySourceAndLane[source.key] = offeredLaneCounts
                collectorOfferedBySourceAndLane[source.key] = collectorOfferedLaneCounts
                upstreamDroppedBySourceAndLane[source.key] = upstreamDroppedLaneCounts
                upstreamTerminatedBySourceAndLane[source.key] = upstreamTerminatedLaneCounts
                mergedDroppedBySourceAndLane[source.key] = mergedDroppedLaneCounts
                mergedTerminatedBySourceAndLane[source.key] = mergedTerminatedLaneCounts
                droppedBySourceAndLane[source.key] = combinedDroppedLaneCounts
                terminatedBySourceAndLane[source.key] = combinedTerminatedLaneCounts
            }

            for lane in EventPipelineLane.allCases {
                let laneIndex = lane.rawValue
                let offered = locked.offeredByLane[laneIndex]
                let dequeued = locked.dequeuedByLane[laneIndex]
                let completed = locked.completedByLane[laneIndex]
                let dropped = locked.droppedByLane[laneIndex]
                let terminated = locked.terminatedByLane[laneIndex]
                let removed = Self.addSaturating(
                    Self.addSaturating(dropped, terminated),
                    dequeued
                )
                let bucketRange = (laneIndex * Self.bucketCount)..<((laneIndex + 1) * Self.bucketCount)
                let latencySamples = bucketRange.reduce(UInt64(0)) {
                    Self.addSaturating($0, locked.latencyBuckets[$1])
                }
                let key = lane.key

                var ruleReachedByCategory: [String: UInt64] = [:]
                var ruleCompletedByCategory: [String: UInt64] = [:]
                for category in EventCategory.allCases {
                    let ruleIndex = Self.ruleEvaluationIndex(
                        lane: lane,
                        category: category
                    )
                    ruleReachedByCategory[category.rawValue] =
                        locked.ruleEvaluationReachedByLaneAndCategory[ruleIndex]
                    ruleCompletedByCategory[category.rawValue] =
                        locked.ruleEvaluationCompletedByLaneAndCategory[ruleIndex]
                }

                offeredByLane[key] = offered
                dequeuedByLane[key] = dequeued
                ruleEvaluationReachedByLaneAndCategory[key] = ruleReachedByCategory
                ruleEvaluationCompletedByLaneAndCategory[key] = ruleCompletedByCategory
                completedByLane[key] = completed
                backlogByLane[key] = offered >= removed ? offered - removed : 0
                inFlightByLane[key] = dequeued >= completed ? dequeued - completed : 0
                p99ByLane[key] = Self.percentile99(
                    state: locked,
                    laneIndex: laneIndex,
                    total: latencySamples
                )
                latencySamplesByLane[key] = latencySamples
                mergedDroppedByLane[key] = dropped
                mergedTerminatedByLane[key] = terminated
                upstreamDroppedByLane[key] = EventPipelineSource.allCases.reduce(UInt64(0)) {
                    Self.addSaturating(
                        $0,
                        upstreamBuffers[$1]?.droppedByLane[key] ?? 0
                    )
                }
                upstreamTerminatedByLane[key] = EventPipelineSource.allCases.reduce(UInt64(0)) {
                    Self.addSaturating(
                        $0,
                        upstreamBuffers[$1]?.terminatedByLane[key] ?? 0
                    )
                }
            }

            return Snapshot(
                offeredBySource: offeredBySource,
                offeredBySourceAndLane: offeredBySourceAndLane,
                droppedBySourceAndLane: droppedBySourceAndLane,
                terminatedBySourceAndLane: terminatedBySourceAndLane,
                collectorOfferedBySourceAndLane: collectorOfferedBySourceAndLane,
                upstreamDroppedBySourceAndLane: upstreamDroppedBySourceAndLane,
                upstreamTerminatedBySourceAndLane: upstreamTerminatedBySourceAndLane,
                mergedDroppedBySourceAndLane: mergedDroppedBySourceAndLane,
                mergedTerminatedBySourceAndLane: mergedTerminatedBySourceAndLane,
                offeredByLane: offeredByLane,
                dequeuedByLane: dequeuedByLane,
                ruleEvaluationReachedByLaneAndCategory: ruleEvaluationReachedByLaneAndCategory,
                ruleEvaluationCompletedByLaneAndCategory: ruleEvaluationCompletedByLaneAndCategory,
                completedByLane: completedByLane,
                backlogEstimateByLane: backlogByLane,
                inFlightByLane: inFlightByLane,
                processingP99MicrosByLane: p99ByLane,
                latencySampleCountByLane: latencySamplesByLane,
                upstreamDroppedByLane: upstreamDroppedByLane,
                upstreamTerminatedByLane: upstreamTerminatedByLane,
                mergedDroppedByLane: mergedDroppedByLane,
                mergedTerminatedByLane: mergedTerminatedByLane,
                collectorCapacityBySource: collectorCapacityBySource,
                detectionInputDroppedTotal: detectionInputDroppedTotal
            )
        }
    }

    @inline(__always)
    private static func incrementSaturating(_ value: inout UInt64) {
        if value < UInt64.max { value += 1 }
    }

    @inline(__always)
    private static func addSaturating(_ lhs: UInt64, _ rhs: UInt64) -> UInt64 {
        let (sum, overflow) = lhs.addingReportingOverflow(rhs)
        return overflow ? UInt64.max : sum
    }

    @inline(__always)
    private static func ruleEvaluationIndex(
        lane: EventPipelineLane,
        category: EventCategory
    ) -> Int {
        let categoryIndex: Int
        switch category {
        case .process: categoryIndex = 0
        case .file: categoryIndex = 1
        case .network: categoryIndex = 2
        case .authentication: categoryIndex = 3
        case .tcc: categoryIndex = 4
        case .registry: categoryIndex = 5
        }
        return lane.rawValue * EventCategory.allCases.count + categoryIndex
    }

    private static func percentile99(
        state: State,
        laneIndex: Int,
        total: UInt64
    ) -> UInt64 {
        guard total > 0 else { return 0 }
        // ceil(0.99 * total), expressed without overflowing multiplication.
        let target = total - total / 100
        var cumulative: UInt64 = 0
        let start = laneIndex * bucketCount
        for bucket in 0..<bucketCount {
            cumulative = addSaturating(cumulative, state.latencyBuckets[start + bucket])
            if cumulative >= target {
                return bucket < latencyBoundsMicros.count
                    ? latencyBoundsMicros[bucket]
                    : latencyBoundsMicros.last ?? 0
            }
        }
        return latencyBoundsMicros.last ?? 0
    }
}
