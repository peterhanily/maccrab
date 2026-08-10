// LLMRuntimeTelemetry.swift
// MacCrabCore
//
// Fixed-cardinality, content-free accounting for every LLM request. This is
// deliberately an in-memory process-lifetime ledger: heartbeat persistence is
// a separate integration layer and must never put prompts or dynamic labels on
// disk.

import Foundation
import Dispatch

/// Product features that can spend an LLM request.
///
/// This is intentionally a closed enum rather than a caller-supplied string:
/// telemetry cardinality stays bounded and no prompt-derived text can become a
/// label. New product features must add a case and a source-wiring test.
/// Every public request API requires the caller to choose a case. Keeping
/// `.unspecified` is useful for explicit transport-only probes and tests, but
/// omission is a compile error so a new product feature cannot drift silently.
public enum LLMRuntimeFeature: String, CaseIterable, Codable, Hashable, Sendable {
    case unspecified
    case intentClassification = "intent_classification"
    case alertInvestigation = "alert_investigation"
    case campaignInvestigation = "campaign_investigation"
    case activeDefense = "active_defense"
    case threatHunt = "threat_hunt"
    case ruleGeneration = "rule_generation"
    case alertClusterRationale = "alert_cluster_rationale"
    case securityPosture = "security_posture"
    case sdrContext = "sdr_context"
    case edrContext = "edr_context"
    case incidentReport = "incident_report"
}

/// The exhaustive terminal result of one public LLM request.
///
/// Every call to `query` or `queryWithExtendedThinking` enters exactly one of
/// these buckets. There is no generic "other" bucket: adding a new early-return
/// path without choosing a disposition is therefore visible in conservation
/// tests and review.
public enum LLMRequestOutcome: String, CaseIterable, Codable, Hashable, Sendable {
    case success
    case cacheHit = "cache_hit"
    case backendFailure = "backend_failure"
    case circuitRejection = "circuit_rejection"
    case privacyRejection = "privacy_rejection"
    case admissionShed = "admission_shed"
    case cancellation
    case responseOversize = "response_oversize"
}

/// Exhaustive terminal result of one semantic operation that consumes one or
/// more transport requests. A retry is deliberately not terminal.
public enum LLMSemanticValidationOutcome: String, CaseIterable, Codable, Hashable, Sendable {
    case accepted
    case finalRejection = "final_rejection"
}

/// Whether one rejected alert-investigation response is being retried or ends
/// the owning semantic operation. Keeping this closed prevents callers from
/// inventing telemetry labels or retry states.
public enum LLMAlertInvestigationRejectionDisposition: Sendable {
    case retry
    case final
}

/// One fixed reason bucket in the alert-investigation rejection ledger.
/// `observedAttempts` counts every rejected response (including the response
/// that triggered a retry); `terminalRejections` counts only the reason that
/// ultimately ended an investigation without an accepted result.
public struct LLMAlertInvestigationRejectionReasonCount: Codable, Sendable, Equatable {
    public let reason: LLMAlertInvestigationRejectionReason
    public let observedAttempts: UInt64
    public let terminalRejections: UInt64
}

/// Content-free, fixed-cardinality diagnostic counters for structured alert
/// investigation. The producer always emits every reason exactly once in enum
/// declaration order, including zero-valued reasons.
public struct LLMAlertInvestigationRejectionSnapshot: Codable, Sendable, Equatable {
    public let observedAttemptsTotal: UInt64
    public let terminalRejectionsTotal: UInt64
    public let byReason: [LLMAlertInvestigationRejectionReasonCount]

    public func counts(
        for reason: LLMAlertInvestigationRejectionReason
    ) -> LLMAlertInvestigationRejectionReasonCount? {
        byReason.first { $0.reason == reason }
    }

    public var fixedCardinalityMaintained: Bool {
        byReason.map(\.reason) == LLMAlertInvestigationRejectionReason.allCases
            && Set(byReason.map(\.reason)).count
                == LLMAlertInvestigationRejectionReason.allCases.count
    }

    public var conservationMaintained: Bool {
        guard fixedCardinalityMaintained else { return false }
        var observed: UInt64 = 0
        var terminal: UInt64 = 0
        for entry in byReason {
            let (nextObserved, observedOverflow) = observed.addingReportingOverflow(
                entry.observedAttempts
            )
            let (nextTerminal, terminalOverflow) = terminal.addingReportingOverflow(
                entry.terminalRejections
            )
            guard !observedOverflow, !terminalOverflow,
                  entry.terminalRejections <= entry.observedAttempts else {
                return false
            }
            observed = nextObserved
            terminal = nextTerminal
        }
        return observed == observedAttemptsTotal
            && terminal == terminalRejectionsTotal
            && terminalRejectionsTotal <= observedAttemptsTotal
    }
}

public struct LLMDownstreamValidationCounts: Codable, Sendable, Equatable {
    public internal(set) var operationsStartedTotal: UInt64 = 0
    public internal(set) var currentOperations: Int = 0
    public internal(set) var accepted: UInt64 = 0
    public internal(set) var retryRequested: UInt64 = 0
    public internal(set) var finalRejection: UInt64 = 0

    public init() {}

    public var conservationMaintained: Bool {
        guard currentOperations >= 0 else { return false }
        return operationsStartedTotal
            == accepted + finalRejection + UInt64(currentOperations)
    }

    mutating func begin() {
        operationsStartedTotal += 1
        currentOperations += 1
    }

    mutating func recordRetry() {
        retryRequested += 1
    }

    mutating func finish(_ outcome: LLMSemanticValidationOutcome) {
        currentOperations -= 1
        switch outcome {
        case .accepted: accepted += 1
        case .finalRejection: finalRejection += 1
        }
    }
}

/// Terminal counters for the closed `LLMRequestOutcome` set.
public struct LLMRequestOutcomeCounts: Codable, Sendable, Equatable {
    public internal(set) var success: UInt64 = 0
    public internal(set) var cacheHit: UInt64 = 0
    public internal(set) var backendFailure: UInt64 = 0
    public internal(set) var circuitRejection: UInt64 = 0
    public internal(set) var privacyRejection: UInt64 = 0
    public internal(set) var admissionShed: UInt64 = 0
    public internal(set) var cancellation: UInt64 = 0
    public internal(set) var responseOversize: UInt64 = 0

    public init() {}

    /// Sum of all terminal buckets. A live ledger conserves as
    /// `requestedTotal == total + currentInFlight`.
    public var total: UInt64 {
        success + cacheHit + backendFailure + circuitRejection
            + privacyRejection + admissionShed + cancellation
            + responseOversize
    }

    mutating func increment(_ outcome: LLMRequestOutcome) {
        switch outcome {
        case .success: success += 1
        case .cacheHit: cacheHit += 1
        case .backendFailure: backendFailure += 1
        case .circuitRejection: circuitRejection += 1
        case .privacyRejection: privacyRejection += 1
        case .admissionShed: admissionShed += 1
        case .cancellation: cancellation += 1
        case .responseOversize: responseOversize += 1
        }
    }
}

/// One non-cumulative request-latency bucket. A nil upper bound is +infinity.
/// Fixed bounds make the histogram safe to publish without dynamic labels.
public struct LLMLatencyBucket: Codable, Sendable, Equatable {
    public let upperBoundMilliseconds: UInt64?
    public let completedRequests: UInt64
}

/// Conserving counters for either the whole service or one fixed feature.
public struct LLMRuntimeCountersSnapshot: Codable, Sendable, Equatable {
    /// Calls observed before circuit, privacy, cache, and admission gates.
    public let requestedTotal: UInt64
    /// Requests that have not yet reached a terminal outcome.
    public let currentInFlight: Int
    /// Requests accepted by the bounded backend admission gate. This includes
    /// calls waiting for the global rate-limit slot.
    public let admittedBackendTotal: UInt64
    public let currentAdmittedBackendRequests: Int
    /// Actual backend method invocations (a cancelled rate-limit waiter is
    /// admitted but never increments this counter).
    public let backendCallsStartedTotal: UInt64
    /// Cancellations that occurred after backend admission, used by the second
    /// conservation equation without splitting the public terminal bucket.
    public let cancellationsAfterAdmissionTotal: UInt64
    public let outcomes: LLMRequestOutcomeCounts

    /// Half-open circuit attempts are visible separately from ordinary calls.
    /// "Did not recover" includes any terminal outcome other than a validated
    /// transport success (failure, cancellation, privacy/admission refusal, or
    /// oversize response).
    public let circuitRecoveryProbesStartedTotal: UInt64
    public let currentCircuitRecoveryProbes: Int
    public let circuitRecoveryProbesSucceededTotal: UInt64
    public let circuitRecoveryProbesDidNotRecoverTotal: UInt64

    /// Semantic/schema validation performed by the consuming feature after a
    /// transport-level success. Retry is an event, not a terminal outcome.
    public let downstreamValidation: LLMDownstreamValidationCounts

    /// Non-cumulative fixed request-latency buckets. Their counts sum to
    /// `outcomes.total`, including rejected and cached requests.
    public let requestLatencyBuckets: [LLMLatencyBucket]

    /// Exact UTF-8 byte counts; prompt/response content is never retained.
    public let requestedInputUTF8BytesTotal: UInt64
    public let backendInputUTF8BytesTotal: UInt64
    public let backendOutputUTF8BytesTotal: UInt64
    public let returnedOutputUTF8BytesTotal: UInt64

    /// Coarse capacity estimates only: ceil(UTF-8 bytes / 4). They are not
    /// provider billing tokens, and extended-thinking hidden tokens are not
    /// observable or included.
    public let estimatedBackendInputTokensTotal: UInt64
    public let estimatedBackendOutputTokensTotal: UInt64
    public let estimatedReturnedOutputTokensTotal: UInt64

    /// Exact request conservation at the instant of the snapshot.
    public let conservationMaintained: Bool
    /// Exact admitted-work conservation. Successful, failed, oversize, and
    /// post-admission-cancelled calls are the only admitted terminal outcomes.
    public let backendAdmissionConservationMaintained: Bool
    public let circuitRecoveryConservationMaintained: Bool
}

public struct LLMFeatureRuntimeTelemetry: Codable, Sendable, Equatable {
    public let feature: LLMRuntimeFeature
    public let counters: LLMRuntimeCountersSnapshot
}

/// Content-free process-lifetime snapshot suitable for heartbeat publication.
public struct LLMRuntimeTelemetrySnapshot: Codable, Sendable, Equatable {
    public let schemaVersion: Int
    public let capturedAtUnix: Double
    public let totals: LLMRuntimeCountersSnapshot
    /// Always contains every `LLMRuntimeFeature` exactly once in declaration
    /// order, including zero-valued and `.unspecified` entries.
    public let perFeature: [LLMFeatureRuntimeTelemetry]
    /// nil only when decoding a schema-1 heartbeat from an older engine. New
    /// producers always emit the exhaustive fixed reason set.
    public let alertInvestigationRejections: LLMAlertInvestigationRejectionSnapshot?

    public func counters(for feature: LLMRuntimeFeature) -> LLMRuntimeCountersSnapshot? {
        perFeature.first { $0.feature == feature }?.counters
    }
}

// MARK: - Internal actor-owned ledger

struct LLMRequestTelemetryToken: Sendable {
    let feature: LLMRuntimeFeature
    let startUptimeNanoseconds: UInt64
    var admittedToBackend = false
    var circuitRecoveryProbe = false
}

/// Opaque ownership proof for a live semantic-validation operation. The
/// initializer and identity are module-internal so callers can only obtain one
/// from `LLMService.beginDownstreamValidation(feature:)`.
public struct LLMSemanticOperationToken: Hashable, Sendable {
    let id: UInt64
    let feature: LLMRuntimeFeature
}

private struct LLMRuntimeCounters {
    /// Histogram bounds in milliseconds. Index `count` is the +infinity bucket.
    static let latencyUpperBoundsMilliseconds: [UInt64] = [
        1, 10, 50, 100, 250, 1_000, 5_000, 30_000, 120_000,
    ]

    var requestedTotal: UInt64 = 0
    var currentInFlight: Int = 0
    var admittedBackendTotal: UInt64 = 0
    var currentAdmittedBackendRequests: Int = 0
    var backendCallsStartedTotal: UInt64 = 0
    var cancellationsAfterAdmissionTotal: UInt64 = 0
    var outcomes = LLMRequestOutcomeCounts()
    var circuitRecoveryProbesStartedTotal: UInt64 = 0
    var currentCircuitRecoveryProbes: Int = 0
    var circuitRecoveryProbesSucceededTotal: UInt64 = 0
    var circuitRecoveryProbesDidNotRecoverTotal: UInt64 = 0
    var downstreamValidation = LLMDownstreamValidationCounts()
    var latencyBucketCounts = Array(
        repeating: UInt64(0),
        count: latencyUpperBoundsMilliseconds.count + 1
    )
    var requestedInputUTF8BytesTotal: UInt64 = 0
    var backendInputUTF8BytesTotal: UInt64 = 0
    var backendOutputUTF8BytesTotal: UInt64 = 0
    var returnedOutputUTF8BytesTotal: UInt64 = 0
    var estimatedBackendInputTokensTotal: UInt64 = 0
    var estimatedBackendOutputTokensTotal: UInt64 = 0
    var estimatedReturnedOutputTokensTotal: UInt64 = 0

    mutating func begin(requestedInputBytes: UInt64) {
        requestedTotal += 1
        currentInFlight += 1
        requestedInputUTF8BytesTotal += requestedInputBytes
    }

    mutating func admit() {
        admittedBackendTotal += 1
        currentAdmittedBackendRequests += 1
    }

    mutating func markCircuitRecoveryProbe() {
        circuitRecoveryProbesStartedTotal += 1
        currentCircuitRecoveryProbes += 1
    }

    mutating func beginDownstreamValidation() {
        downstreamValidation.begin()
    }

    mutating func recordDownstreamRetry() {
        downstreamValidation.recordRetry()
    }

    mutating func finishDownstreamValidation(_ outcome: LLMSemanticValidationOutcome) {
        downstreamValidation.finish(outcome)
    }

    mutating func startBackend(inputBytes: UInt64) {
        backendCallsStartedTotal += 1
        backendInputUTF8BytesTotal += inputBytes
        estimatedBackendInputTokensTotal += Self.estimatedTokens(forUTF8Bytes: inputBytes)
    }

    mutating func receiveBackendOutput(bytes: UInt64) {
        backendOutputUTF8BytesTotal += bytes
        estimatedBackendOutputTokensTotal += Self.estimatedTokens(forUTF8Bytes: bytes)
    }

    mutating func finish(
        outcome: LLMRequestOutcome,
        admittedToBackend: Bool,
        circuitRecoveryProbe: Bool,
        returnedOutputBytes: UInt64,
        elapsedNanoseconds: UInt64
    ) {
        currentInFlight -= 1
        if admittedToBackend {
            currentAdmittedBackendRequests -= 1
            if outcome == .cancellation {
                cancellationsAfterAdmissionTotal += 1
            }
        }
        if circuitRecoveryProbe {
            currentCircuitRecoveryProbes -= 1
            if outcome == .success {
                circuitRecoveryProbesSucceededTotal += 1
            } else {
                circuitRecoveryProbesDidNotRecoverTotal += 1
            }
        }
        outcomes.increment(outcome)
        returnedOutputUTF8BytesTotal += returnedOutputBytes
        estimatedReturnedOutputTokensTotal += Self.estimatedTokens(forUTF8Bytes: returnedOutputBytes)

        let elapsedMilliseconds = elapsedNanoseconds / 1_000_000
        let index = Self.latencyUpperBoundsMilliseconds.firstIndex {
            elapsedMilliseconds <= $0
        } ?? Self.latencyUpperBoundsMilliseconds.count
        latencyBucketCounts[index] += 1
    }

    func snapshot() -> LLMRuntimeCountersSnapshot {
        let buckets = latencyBucketCounts.enumerated().map { index, count in
            LLMLatencyBucket(
                upperBoundMilliseconds: index < Self.latencyUpperBoundsMilliseconds.count
                    ? Self.latencyUpperBoundsMilliseconds[index]
                    : nil,
                completedRequests: count
            )
        }
        let active = currentInFlight >= 0 ? UInt64(currentInFlight) : UInt64.max
        let activeAdmitted = currentAdmittedBackendRequests >= 0
            ? UInt64(currentAdmittedBackendRequests)
            : UInt64.max
        let admittedTerminal = outcomes.success + outcomes.backendFailure
            + outcomes.responseOversize + cancellationsAfterAdmissionTotal
        let activeRecovery = currentCircuitRecoveryProbes >= 0
            ? UInt64(currentCircuitRecoveryProbes)
            : UInt64.max

        return LLMRuntimeCountersSnapshot(
            requestedTotal: requestedTotal,
            currentInFlight: currentInFlight,
            admittedBackendTotal: admittedBackendTotal,
            currentAdmittedBackendRequests: currentAdmittedBackendRequests,
            backendCallsStartedTotal: backendCallsStartedTotal,
            cancellationsAfterAdmissionTotal: cancellationsAfterAdmissionTotal,
            outcomes: outcomes,
            circuitRecoveryProbesStartedTotal: circuitRecoveryProbesStartedTotal,
            currentCircuitRecoveryProbes: currentCircuitRecoveryProbes,
            circuitRecoveryProbesSucceededTotal: circuitRecoveryProbesSucceededTotal,
            circuitRecoveryProbesDidNotRecoverTotal: circuitRecoveryProbesDidNotRecoverTotal,
            downstreamValidation: downstreamValidation,
            requestLatencyBuckets: buckets,
            requestedInputUTF8BytesTotal: requestedInputUTF8BytesTotal,
            backendInputUTF8BytesTotal: backendInputUTF8BytesTotal,
            backendOutputUTF8BytesTotal: backendOutputUTF8BytesTotal,
            returnedOutputUTF8BytesTotal: returnedOutputUTF8BytesTotal,
            estimatedBackendInputTokensTotal: estimatedBackendInputTokensTotal,
            estimatedBackendOutputTokensTotal: estimatedBackendOutputTokensTotal,
            estimatedReturnedOutputTokensTotal: estimatedReturnedOutputTokensTotal,
            conservationMaintained: currentInFlight >= 0
                && requestedTotal == outcomes.total + active,
            backendAdmissionConservationMaintained:
                currentAdmittedBackendRequests >= 0
                && admittedBackendTotal == admittedTerminal + activeAdmitted,
            circuitRecoveryConservationMaintained:
                currentCircuitRecoveryProbes >= 0
                && circuitRecoveryProbesStartedTotal
                    == circuitRecoveryProbesSucceededTotal
                        + circuitRecoveryProbesDidNotRecoverTotal
                        + activeRecovery
        )
    }

    private static func estimatedTokens(forUTF8Bytes bytes: UInt64) -> UInt64 {
        guard bytes > 0 else { return 0 }
        return (bytes + 3) / 4
    }
}

struct LLMRuntimeTelemetryLedger {
    private var totals = LLMRuntimeCounters()
    private var byFeature: [LLMRuntimeFeature: LLMRuntimeCounters] =
        Dictionary(uniqueKeysWithValues: LLMRuntimeFeature.allCases.map {
            ($0, LLMRuntimeCounters())
        })
    private var nextSemanticOperationID: UInt64 = 0
    private var activeSemanticOperations: [UInt64: LLMRuntimeFeature] = [:]
    private var alertInvestigationRejectionCounts = Dictionary(
        uniqueKeysWithValues: LLMAlertInvestigationRejectionReason.allCases.map {
            ($0, (observed: UInt64(0), terminal: UInt64(0)))
        }
    )

    mutating func begin(
        feature: LLMRuntimeFeature,
        requestedInputBytes: UInt64
    ) -> LLMRequestTelemetryToken {
        totals.begin(requestedInputBytes: requestedInputBytes)
        byFeature[feature]!.begin(requestedInputBytes: requestedInputBytes)
        return LLMRequestTelemetryToken(
            feature: feature,
            startUptimeNanoseconds: DispatchTime.now().uptimeNanoseconds
        )
    }

    mutating func admit(_ token: inout LLMRequestTelemetryToken) {
        guard !token.admittedToBackend else { return }
        token.admittedToBackend = true
        totals.admit()
        byFeature[token.feature]!.admit()
    }

    mutating func markCircuitRecoveryProbe(_ token: inout LLMRequestTelemetryToken) {
        guard !token.circuitRecoveryProbe else { return }
        token.circuitRecoveryProbe = true
        totals.markCircuitRecoveryProbe()
        byFeature[token.feature]!.markCircuitRecoveryProbe()
    }

    mutating func beginDownstreamValidation(
        feature: LLMRuntimeFeature
    ) -> LLMSemanticOperationToken {
        repeat {
            nextSemanticOperationID &+= 1
            if nextSemanticOperationID == 0 { nextSemanticOperationID = 1 }
        } while activeSemanticOperations[nextSemanticOperationID] != nil
        let token = LLMSemanticOperationToken(
            id: nextSemanticOperationID,
            feature: feature
        )
        activeSemanticOperations[token.id] = feature
        totals.beginDownstreamValidation()
        byFeature[feature]!.beginDownstreamValidation()
        return token
    }

    @discardableResult
    mutating func recordDownstreamRetry(
        token: LLMSemanticOperationToken
    ) -> Bool {
        // Alert-investigation retries require a fixed reason. Route them
        // through recordAlertInvestigationRejection so schema-2 snapshots
        // cannot contain an unattributed rejection.
        guard token.feature != .alertInvestigation,
              activeSemanticOperations[token.id] == token.feature else {
            return false
        }
        totals.recordDownstreamRetry()
        byFeature[token.feature]!.recordDownstreamRetry()
        return true
    }

    @discardableResult
    mutating func finishDownstreamValidation(
        token: LLMSemanticOperationToken,
        outcome: LLMSemanticValidationOutcome
    ) -> Bool {
        // Accepted alert investigations have no rejection reason. Their final
        // rejections must use recordAlertInvestigationRejection atomically.
        guard !(token.feature == .alertInvestigation && outcome == .finalRejection),
              activeSemanticOperations[token.id] == token.feature else {
            return false
        }
        activeSemanticOperations.removeValue(forKey: token.id)
        totals.finishDownstreamValidation(outcome)
        byFeature[token.feature]!.finishDownstreamValidation(outcome)
        return true
    }

    /// Attribute a rejected structured response and atomically advance the
    /// generic semantic ledger. This avoids a retry/final count with no reason,
    /// or a reason count detached from a live alert-investigation operation.
    @discardableResult
    mutating func recordAlertInvestigationRejection(
        token: LLMSemanticOperationToken,
        reason: LLMAlertInvestigationRejectionReason,
        disposition: LLMAlertInvestigationRejectionDisposition
    ) -> Bool {
        guard token.feature == .alertInvestigation,
              activeSemanticOperations[token.id] == token.feature else {
            return false
        }
        var reasonCounts = alertInvestigationRejectionCounts[reason]!
        reasonCounts.observed += 1
        switch disposition {
        case .retry:
            totals.recordDownstreamRetry()
            byFeature[token.feature]!.recordDownstreamRetry()
        case .final:
            reasonCounts.terminal += 1
            activeSemanticOperations.removeValue(forKey: token.id)
            totals.finishDownstreamValidation(.finalRejection)
            byFeature[token.feature]!.finishDownstreamValidation(.finalRejection)
        }
        alertInvestigationRejectionCounts[reason] = reasonCounts
        return true
    }

    mutating func startBackend(
        token: LLMRequestTelemetryToken,
        inputBytes: UInt64
    ) {
        totals.startBackend(inputBytes: inputBytes)
        byFeature[token.feature]!.startBackend(inputBytes: inputBytes)
    }

    mutating func receiveBackendOutput(
        token: LLMRequestTelemetryToken,
        bytes: UInt64
    ) {
        totals.receiveBackendOutput(bytes: bytes)
        byFeature[token.feature]!.receiveBackendOutput(bytes: bytes)
    }

    mutating func finish(
        token: LLMRequestTelemetryToken,
        outcome: LLMRequestOutcome,
        returnedOutputBytes: UInt64
    ) {
        let now = DispatchTime.now().uptimeNanoseconds
        let elapsed = now >= token.startUptimeNanoseconds
            ? now - token.startUptimeNanoseconds
            : 0
        totals.finish(
            outcome: outcome,
            admittedToBackend: token.admittedToBackend,
            circuitRecoveryProbe: token.circuitRecoveryProbe,
            returnedOutputBytes: returnedOutputBytes,
            elapsedNanoseconds: elapsed
        )
        byFeature[token.feature]!.finish(
            outcome: outcome,
            admittedToBackend: token.admittedToBackend,
            circuitRecoveryProbe: token.circuitRecoveryProbe,
            returnedOutputBytes: returnedOutputBytes,
            elapsedNanoseconds: elapsed
        )
    }

    func snapshot(capturedAt: Date) -> LLMRuntimeTelemetrySnapshot {
        let rejectionEntries = LLMAlertInvestigationRejectionReason.allCases.map {
            reason in
            let counts = alertInvestigationRejectionCounts[reason]!
            return LLMAlertInvestigationRejectionReasonCount(
                reason: reason,
                observedAttempts: counts.observed,
                terminalRejections: counts.terminal
            )
        }
        return LLMRuntimeTelemetrySnapshot(
            schemaVersion: 2,
            capturedAtUnix: capturedAt.timeIntervalSince1970,
            totals: totals.snapshot(),
            perFeature: LLMRuntimeFeature.allCases.map {
                LLMFeatureRuntimeTelemetry(
                    feature: $0,
                    counters: byFeature[$0]!.snapshot()
                )
            },
            alertInvestigationRejections: LLMAlertInvestigationRejectionSnapshot(
                observedAttemptsTotal: rejectionEntries.reduce(0) {
                    $0 + $1.observedAttempts
                },
                terminalRejectionsTotal: rejectionEntries.reduce(0) {
                    $0 + $1.terminalRejections
                },
                byReason: rejectionEntries
            )
        )
    }
}

@inline(__always)
func llmUTF8ByteCount(_ systemPrompt: String, _ userPrompt: String) -> UInt64 {
    UInt64(systemPrompt.utf8.count) + UInt64(userPrompt.utf8.count)
}
