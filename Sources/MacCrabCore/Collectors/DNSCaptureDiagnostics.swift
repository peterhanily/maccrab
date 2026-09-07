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
    public var streamOfferedTotal: UInt64 = 0
    public var streamDroppedTotal: UInt64 = 0
    public var streamTerminatedTotal: UInt64 = 0

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
            "stream_capacity": 256,
            "stream_offered_total": streamOfferedTotal,
            "stream_dropped_total": streamDroppedTotal,
            "stream_terminated_total": streamTerminatedTotal,
        ]
    }
}

/// Shared with the detached reader; no per-packet actor task or unbounded queue.
final class DNSCaptureTelemetry: Sendable {
    private let state = OSAllocatedUnfairLock(initialState: DNSCaptureDiagnostics())

    func availability(_ status: DNSCaptureStatus) {
        state.withLock {
            switch status {
            case .capturing(let interface):
                if $0.interface != interface { $0.kernelStatisticsAvailable = false }
                $0.interface = interface
                $0.available = true
            case .unavailable: $0.interface = nil; $0.available = false; $0.kernelStatisticsAvailable = false
            }
        }
    }

    func kernel(received: UInt32, dropped: UInt32) {
        state.withLock {
            $0.kernelStatisticsAvailable = true
            Self.add(&$0.kernelReceivedTotal, UInt64(received))
            Self.add(&$0.kernelDroppedTotal, UInt64(dropped))
        }
    }

    func kernelStatisticsFailed() {
        state.withLock {
            $0.kernelStatisticsAvailable = false
            Self.add(&$0.kernelStatisticsErrorsTotal, 1)
        }
    }

    func yielded(_ result: AsyncStream<DnsQuery>.Continuation.YieldResult) {
        state.withLock {
            Self.add(&$0.streamOfferedTotal, 1)
            switch result {
            case .enqueued: break
            case .dropped: Self.add(&$0.streamDroppedTotal, 1)
            case .terminated: Self.add(&$0.streamTerminatedTotal, 1)
            @unknown default: Self.add(&$0.streamTerminatedTotal, 1)
            }
        }
    }

    func snapshot() -> DNSCaptureDiagnostics { state.withLock { $0 } }

    private static func add(_ target: inout UInt64, _ amount: UInt64) {
        let sum = target.addingReportingOverflow(amount)
        target = sum.overflow ? .max : sum.partialValue
    }
}
