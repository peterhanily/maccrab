// DoHDetector.swift
// MacCrabCore
//
// Detects DNS-over-HTTPS (DoH) usage that bypasses standard DNS monitoring.
// Flags non-browser processes connecting to known DoH resolver IPs on port 443.
// Complements the existing dns_over_https_manual.yml rule (which catches curl/wget
// to DoH endpoints) by detecting any process making HTTPS connections to resolver IPs.

import Foundation
import os.log

/// Detects DNS-over-HTTPS (DoH) usage that bypasses standard DNS monitoring.
/// Flags non-browser processes connecting to known DoH resolver IPs on port 443.
public actor DoHDetector {
    private let logger = Logger(subsystem: "com.maccrab.detection", category: "doh-detector")

    /// Known DoH resolver IPs (Google, Cloudflare, Quad9, NextDNS, etc.)
    private static let dohResolverIPs: Set<String> = [
        // Google Public DNS
        "8.8.8.8", "8.8.4.4",
        "2001:4860:4860::8888", "2001:4860:4860::8844",
        // Cloudflare (1.1.1.1) and Cloudflare for Families (1.1.1.2/1.1.1.3)
        "1.1.1.1", "1.0.0.1",
        "1.1.1.2", "1.0.0.2",  // Cloudflare malware-blocking
        "1.1.1.3", "1.0.0.3",  // Cloudflare adult-content-blocking
        "2606:4700:4700::1111", "2606:4700:4700::1001",
        "2606:4700:4700::1112", "2606:4700:4700::1002",
        // Quad9
        "9.9.9.9", "149.112.112.112",
        "2620:fe::fe", "2620:fe::9",
        // OpenDNS / Cisco Umbrella
        "208.67.222.222", "208.67.220.220",
        "2620:119:35::35", "2620:119:53::53",
        // NextDNS
        "45.90.28.0", "45.90.30.0",
        // AdGuard DNS
        "94.140.14.14", "94.140.15.15",
        "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff",
        // Mullvad DNS
        "194.242.2.2", "193.19.108.2",
        // ControlD
        "76.76.2.0", "76.76.10.0",
        // DNS.SB
        "185.222.222.222", "45.11.45.11",
        // Comodo Secure DNS
        "8.26.56.26", "8.20.247.20",
    ]

    /// Processes that legitimately use DoH
    private static let allowedDoHProcesses: Set<String> = [
        "Google Chrome", "Google Chrome Helper",
        "firefox", "Firefox",
        "Safari", "com.apple.WebKit.Networking",
        "Microsoft Edge", "Microsoft Edge Helper",
        "Arc", "Arc Helper",
        "Brave Browser", "Brave Browser Helper",
        "Opera", "Vivaldi",
        "mDNSResponder",  // System DNS resolver
        "networkd",
    ]

    public struct DoHViolation: Sendable {
        public let processName: String
        public let processPath: String
        public let pid: Int32
        public let destinationIP: String
        public let resolverName: String  // "Google", "Cloudflare", etc.
    }

    public init() {}

    /// Check if a network connection is suspicious DoH usage.
    /// Returns a violation if a non-browser process connects to a DoH resolver on 443.
    public func check(
        processName: String,
        processPath: String,
        pid: Int32,
        destinationIP: String,
        destinationPort: UInt16
    ) -> DoHViolation? {
        // Only check HTTPS port
        guard destinationPort == 443 else { return nil }

        // Must be a known DoH resolver IP
        guard Self.dohResolverIPs.contains(destinationIP) else { return nil }

        // Skip allowed processes (browsers, system DNS)
        let name = (processPath as NSString).lastPathComponent
        if Self.allowedDoHProcesses.contains(name) || Self.allowedDoHProcesses.contains(processName) {
            return nil
        }

        // Skip system paths
        if processPath.hasPrefix("/System/") || processPath.hasPrefix("/usr/libexec/") {
            return nil
        }

        let resolverName = Self.resolverName(for: destinationIP)
        logger.warning("DoH evasion: \(processName) (pid \(pid)) → \(resolverName) (\(destinationIP):443)")

        return DoHViolation(
            processName: processName,
            processPath: processPath,
            pid: pid,
            destinationIP: destinationIP,
            resolverName: resolverName
        )
    }

    private static func resolverName(for ip: String) -> String {
        switch ip {
        case "8.8.8.8", "8.8.4.4",
             "2001:4860:4860::8888", "2001:4860:4860::8844":
            return "Google DNS"
        case "1.1.1.1", "1.0.0.1",
             "2606:4700:4700::1111", "2606:4700:4700::1001":
            return "Cloudflare DNS"
        case "1.1.1.2", "1.0.0.2",
             "2606:4700:4700::1112", "2606:4700:4700::1002":
            return "Cloudflare DNS (Malware Blocking)"
        case "1.1.1.3", "1.0.0.3": return "Cloudflare DNS (Families)"
        case "9.9.9.9", "149.112.112.112",
             "2620:fe::fe", "2620:fe::9":
            return "Quad9"
        case "208.67.222.222", "208.67.220.220",
             "2620:119:35::35", "2620:119:53::53":
            return "OpenDNS"
        case "45.90.28.0", "45.90.30.0": return "NextDNS"
        case "94.140.14.14", "94.140.15.15",
             "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff":
            return "AdGuard DNS"
        case "194.242.2.2", "193.19.108.2": return "Mullvad DNS"
        case "76.76.2.0", "76.76.10.0": return "ControlD DNS"
        case "185.222.222.222", "45.11.45.11": return "DNS.SB"
        case "8.26.56.26", "8.20.247.20": return "Comodo Secure DNS"
        default: return "DoH Resolver"
        }
    }
}
