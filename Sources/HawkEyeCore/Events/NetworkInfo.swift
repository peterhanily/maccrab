// NetworkInfo.swift
// HawkEyeCore
//
// Network connection metadata.
// Field names follow the Elastic Common Schema (ECS) for Sigma compatibility.

import Foundation

// MARK: - NetworkInfo

/// Describes a network connection associated with an event.
///
/// Maps to ECS `source.*`, `destination.*`, and `network.*` fields.
public struct NetworkInfo: Codable, Sendable, Hashable {

    // MARK: Source

    /// Source IP address (ECS `source.ip`).
    public let sourceIp: String

    /// Source port number (ECS `source.port`).
    public let sourcePort: UInt16

    // MARK: Destination

    /// Destination IP address (ECS `destination.ip`).
    public let destinationIp: String

    /// Destination port number (ECS `destination.port`).
    public let destinationPort: UInt16

    /// Resolved or requested hostname, if available (ECS `destination.domain`).
    public let destinationHostname: String?

    // MARK: Connection metadata

    /// Direction of the connection relative to this host.
    public let direction: NetworkDirection

    /// Transport protocol (e.g. `"tcp"`, `"udp"`).
    public let transport: String

    // MARK: Computed properties

    /// Whether the destination IP falls within an RFC 1918 private address range
    /// (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) or the loopback range
    /// (`127.0.0.0/8`).
    public var destinationIsPrivate: Bool {
        Self.isPrivateAddress(destinationIp)
    }

    // MARK: Initializer

    public init(
        sourceIp: String,
        sourcePort: UInt16,
        destinationIp: String,
        destinationPort: UInt16,
        destinationHostname: String? = nil,
        direction: NetworkDirection,
        transport: String
    ) {
        self.sourceIp = sourceIp
        self.sourcePort = sourcePort
        self.destinationIp = destinationIp
        self.destinationPort = destinationPort
        self.destinationHostname = destinationHostname
        self.direction = direction
        self.transport = transport
    }

    // MARK: Private helpers

    /// Parses a dotted-decimal IPv4 string into four octets.
    /// Returns `nil` for anything that isn't a valid IPv4 address.
    private static func parseIPv4(_ ip: String) -> (UInt8, UInt8, UInt8, UInt8)? {
        let parts = ip.split(separator: ".", maxSplits: 4, omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        guard let a = UInt8(parts[0]),
              let b = UInt8(parts[1]),
              let c = UInt8(parts[2]),
              let d = UInt8(parts[3])
        else { return nil }
        return (a, b, c, d)
    }

    /// Returns `true` when `ip` belongs to an RFC 1918 private range or loopback.
    private static func isPrivateAddress(_ ip: String) -> Bool {
        guard let (a, b, _, _) = parseIPv4(ip) else {
            // IPv6 – treat ::1 and fc00::/7 (ULA) as private
            let lower = ip.lowercased()
            if lower == "::1" { return true }
            if lower.hasPrefix("fc") || lower.hasPrefix("fd") { return true }
            return false
        }

        // 10.0.0.0/8
        if a == 10 { return true }
        // 172.16.0.0/12
        if a == 172, (16...31).contains(b) { return true }
        // 192.168.0.0/16
        if a == 192, b == 168 { return true }
        // 127.0.0.0/8 (loopback)
        if a == 127 { return true }

        return false
    }
}
