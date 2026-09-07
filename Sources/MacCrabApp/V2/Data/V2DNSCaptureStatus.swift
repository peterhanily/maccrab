import Foundation

struct V2DNSCaptureStatus: Equatable, Sendable {
    let available: Bool
    let interface: String?
    let kernelStatisticsAvailable: Bool
    let kernelReceived: UInt64
    let kernelDropped: UInt64
    let statisticsErrors: UInt64
    let streamOffered: UInt64
    let streamDropped: UInt64
    let streamTerminated: UInt64

    init(_ raw: [String: Any]) {
        available = raw["available"] as? Bool ?? false
        let candidate = raw["interface"] as? String
        interface = candidate.flatMap { value in
            value.count <= 16 && !value.isEmpty
                && value.unicodeScalars.allSatisfy { CharacterSet.alphanumerics.contains($0) || $0 == "_" || $0 == "-" }
                ? value : nil
        }
        kernelStatisticsAvailable = raw["kernel_statistics_available"] as? Bool ?? false
        kernelReceived = raw["kernel_received_total"] as? UInt64 ?? 0
        kernelDropped = raw["kernel_dropped_total"] as? UInt64 ?? 0
        statisticsErrors = raw["kernel_statistics_errors_total"] as? UInt64 ?? 0
        streamOffered = raw["stream_offered_total"] as? UInt64 ?? 0
        streamDropped = raw["stream_dropped_total"] as? UInt64 ?? 0
        streamTerminated = raw["stream_terminated_total"] as? UInt64 ?? 0
    }

    var diagnosticDictionary: [String: Any] {
        var result: [String: Any] = ["available": available, "scope": "primary_ipv4_ethernet_udp_53",
            "exclusions": ["scoped_vpn", "ipv6_transport", "dns_tcp", "encrypted_dns"],
            "kernel_statistics_available": kernelStatisticsAvailable, "kernel_received_total": kernelReceived,
            "kernel_dropped_total": kernelDropped, "kernel_statistics_errors_total": statisticsErrors,
            "stream_offered_total": streamOffered, "stream_dropped_total": streamDropped,
            "stream_terminated_total": streamTerminated]
        if let interface { result["interface"] = interface }
        return result
    }
}
