import Foundation
import os

public struct DNSCaptureDiagnostics: Sendable, Equatable {
    public var interface: String?
    public var available = false
    public var kernelStatisticsAvailable = false
    /// BPF counts packets at the descriptor, not parsed DNS messages.
    public var kernelReceivedTotal: UInt64 = 0
    public var kernelDroppedTotal: UInt64 = 0
    public var kernelStatisticsErrorsTotal: UInt64 = 0
    /// Successful observations of the configured descriptor, including checks
    /// that observed no new packets. This is capture liveness, not DNS coverage.
    public var successfulCaptureChecksTotal: UInt64 = 0
    public var captureCheckFailureActive = false
    public var bindingAgeSeconds: TimeInterval?
    public var successfulCaptureCheckAgeSeconds: TimeInterval?
    public var streamOfferedTotal: UInt64 = 0
    public var streamDroppedTotal: UInt64 = 0
    public var streamTerminatedTotal: UInt64 = 0

    public init() {}

    public var dictionary: [String: Any] {
        [
            "scope": "primary IPv4 interface; Ethernet, IPv4 UDP port 53",
            "excluded": ["scoped/VPN routes", "IPv6 transport", "DNS over TCP", "encrypted DNS"],
            "interface": interface as Any? ?? NSNull(),
            "available": available,
            "kernel_statistics_available": kernelStatisticsAvailable,
            "kernel_received_total": kernelReceivedTotal,
            "kernel_dropped_total": kernelDroppedTotal,
            "kernel_statistics_errors_total": kernelStatisticsErrorsTotal,
            "successful_capture_checks_total": successfulCaptureChecksTotal,
            "capture_check_failure_active": captureCheckFailureActive,
            "binding_age_seconds": bindingAgeSeconds as Any? ?? NSNull(),
            "successful_capture_check_age_seconds": successfulCaptureCheckAgeSeconds as Any? ?? NSNull(),
            "stream_capacity": 256,
            "stream_offered_total": streamOfferedTotal,
            "stream_dropped_total": streamDroppedTotal,
            "stream_terminated_total": streamTerminatedTotal,
        ]
    }
}

/// Shared with the detached reader; no per-packet actor task or unbounded queue.
final class DNSCaptureTelemetry: Sendable {
    private struct State {
        var diagnostics = DNSCaptureDiagnostics()
        var bindingConfiguredAt: UInt64?
        var successfulCaptureCheckAt: UInt64?
    }

    private let state = OSAllocatedUnfairLock(initialState: State())
    private let monotonicNow: @Sendable () -> UInt64

    init(monotonicNow: @escaping @Sendable () -> UInt64 = {
        DispatchTime.now().uptimeNanoseconds
    }) {
        self.monotonicNow = monotonicNow
    }

    func availability(_ status: DNSCaptureStatus) {
        state.withLock { state in
            switch status {
            case .capturing(let interface):
                if !state.diagnostics.available || state.diagnostics.interface != interface {
                    state.bindingConfiguredAt = monotonicNow()
                    state.successfulCaptureCheckAt = nil
                    state.diagnostics.kernelStatisticsAvailable = false
                    state.diagnostics.captureCheckFailureActive = false
                }
                state.diagnostics.interface = interface
                state.diagnostics.available = true
            case .unavailable:
                state.diagnostics.interface = nil
                state.diagnostics.available = false
                state.diagnostics.kernelStatisticsAvailable = false
                state.diagnostics.captureCheckFailureActive = false
                state.bindingConfiguredAt = nil
                state.successfulCaptureCheckAt = nil
            }
        }
    }

    /// Called only after the capture loop successfully reads BIOCGSTATS on its
    /// current descriptor. Unchanged packet totals still prove loop progress;
    /// yielding an event or repeating an availability report does not.
    func kernel(received: UInt32, dropped: UInt32) {
        state.withLock { state in
            guard state.diagnostics.available else { return }
            state.diagnostics.kernelStatisticsAvailable = true
            state.diagnostics.captureCheckFailureActive = false
            state.successfulCaptureCheckAt = monotonicNow()
            Self.add(&state.diagnostics.successfulCaptureChecksTotal, 1)
            Self.add(&state.diagnostics.kernelReceivedTotal, UInt64(received))
            Self.add(&state.diagnostics.kernelDroppedTotal, UInt64(dropped))
        }
    }

    func kernelStatisticsFailed() {
        state.withLock { state in
            guard state.diagnostics.available else { return }
            state.diagnostics.kernelStatisticsAvailable = false
            state.diagnostics.captureCheckFailureActive = true
            Self.add(&state.diagnostics.kernelStatisticsErrorsTotal, 1)
        }
    }

    func yielded(_ result: AsyncStream<DnsQuery>.Continuation.YieldResult) {
        state.withLock { state in
            Self.add(&state.diagnostics.streamOfferedTotal, 1)
            switch result {
            case .enqueued: break
            case .dropped: Self.add(&state.diagnostics.streamDroppedTotal, 1)
            case .terminated: Self.add(&state.diagnostics.streamTerminatedTotal, 1)
            @unknown default: Self.add(&state.diagnostics.streamTerminatedTotal, 1)
            }
        }
    }

    func snapshot() -> DNSCaptureDiagnostics {
        state.withLock { state in
            let now = monotonicNow()
            func age(_ instant: UInt64?) -> TimeInterval? {
                guard let instant, instant <= now else { return nil }
                return Double(now - instant) / 1_000_000_000
            }
            var result = state.diagnostics
            result.bindingAgeSeconds = age(state.bindingConfiguredAt)
            result.successfulCaptureCheckAgeSeconds = age(state.successfulCaptureCheckAt)
            return result
        }
    }

    private static func add(_ target: inout UInt64, _ amount: UInt64) {
        let sum = target.addingReportingOverflow(amount)
        target = sum.overflow ? .max : sum.partialValue
    }
}
