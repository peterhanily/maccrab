// AINetworkSandbox.swift
// MacCrabCore
//
// Monitors network connections made by AI coding tool processes and their
// children, alerting when they connect to destinations not on the allowlist.
//
// AI tools (Copilot, Claude Code, Cursor, etc.) legitimately need to reach
// their own APIs, package registries, and source-control hosts. Connections
// to anything else — especially raw IPs, uncommon ports, or unknown domains —
// may indicate prompt-injection-driven exfiltration or supply-chain compromise.

import Foundation
import os.log

// MARK: - AINetworkSandbox

/// Sandboxes outbound network connections from AI coding tool process trees.
///
/// Maintains a domain/IP allowlist of known-safe destinations. Connections
/// that fall outside the allowlist produce a ``Violation`` that can be fed
/// into the alert pipeline.
public actor AINetworkSandbox {

    private let logger = Logger(subsystem: "com.maccrab", category: "ai-network-sandbox")

    // MARK: - Default Allowlist

    /// Known-safe destinations for AI coding tools.
    public static let defaultAllowlist: Set<String> = [
        // Package registries
        "registry.npmjs.org",
        "pypi.org", "files.pythonhosted.org",
        "rubygems.org",
        "crates.io",
        "pkg.go.dev", "proxy.golang.org", "sum.golang.org",
        // Source control
        "github.com", "api.github.com",
        "gitlab.com",
        "bitbucket.org",
        // AI services
        "api.anthropic.com",
        "api.openai.com",
        "api.githubcopilot.com",
        "generativelanguage.googleapis.com",
        // CDNs and common dev services
        "cdn.jsdelivr.net",
        "unpkg.com",
        "raw.githubusercontent.com",
        "objects.githubusercontent.com",
    ]

    /// IP addresses that are always allowed (well-known DNS, etc.).
    public static let defaultIPAllowlist: Set<String> = [
        // Google public DNS
        "8.8.8.8", "8.8.4.4",
        // Cloudflare DNS
        "1.1.1.1", "1.0.0.1",
    ]

    // MARK: - Violation

    /// Describes an unapproved network connection from an AI tool process.
    public struct Violation: Sendable {
        public let aiToolName: String
        public let processPid: Int32
        public let processPath: String
        public let destinationIP: String
        public let destinationPort: UInt16
        public let destinationDomain: String?
        public let reason: String

        public init(
            aiToolName: String,
            processPid: Int32,
            processPath: String,
            destinationIP: String,
            destinationPort: UInt16,
            destinationDomain: String?,
            reason: String
        ) {
            self.aiToolName = aiToolName
            self.processPid = processPid
            self.processPath = processPath
            self.destinationIP = destinationIP
            self.destinationPort = destinationPort
            self.destinationDomain = destinationDomain
            self.reason = reason
        }
    }

    // MARK: - Configuration

    /// Custom allowlist loaded from JSON config file.
    public struct AllowlistConfig: Codable, Sendable {
        public let domains: [String]?
        public let ips: [String]?

        public init(domains: [String]? = nil, ips: [String]? = nil) {
            self.domains = domains
            self.ips = ips
        }
    }

    // MARK: - State

    /// Combined domain allowlist (defaults + user-configured).
    private var domainAllowlist: Set<String>

    /// Combined IP allowlist (defaults + user-configured).
    private var ipAllowlist: Set<String>

    /// Recent violations for deduplication and audit.
    private var recentViolations: [Violation] = []

    /// Maximum number of cached violations.
    private let maxCachedViolations: Int

    // MARK: - Initialization

    public init(
        customConfigPath: String? = nil,
        maxCachedViolations: Int = 500
    ) {
        self.domainAllowlist = Self.defaultAllowlist
        self.ipAllowlist = Self.defaultIPAllowlist
        self.maxCachedViolations = maxCachedViolations

        // Attempt to load custom allowlist from config file
        let configPath = customConfigPath ?? Self.defaultConfigPath()
        if let config = Self.loadConfig(from: configPath) {
            if let domains = config.domains {
                self.domainAllowlist.formUnion(domains)
            }
            if let ips = config.ips {
                self.ipAllowlist.formUnion(ips)
            }
        }
    }

    // MARK: - Public API

    /// Check if a network connection from an AI tool process is allowed.
    /// Returns a ``Violation`` if the destination is not in the allowlist.
    public func checkConnection(
        aiToolName: String,
        processPid: Int32,
        processPath: String,
        destinationIP: String,
        destinationPort: UInt16,
        destinationDomain: String?
    ) -> Violation? {
        // Private/loopback addresses are always allowed
        if Self.isPrivateOrLoopback(destinationIP) {
            return nil
        }

        // Check domain allowlist (with subdomain suffix matching)
        if let domain = destinationDomain {
            if isDomainAllowed(domain) {
                return nil
            }
            // Domain is set but not allowed
            let violation = Violation(
                aiToolName: aiToolName,
                processPid: processPid,
                processPath: processPath,
                destinationIP: destinationIP,
                destinationPort: destinationPort,
                destinationDomain: destinationDomain,
                reason: "AI tool \(aiToolName) connected to unapproved domain: \(domain)"
            )
            cacheViolation(violation)
            logger.warning("AI network sandbox violation: \(aiToolName) pid=\(processPid) -> \(domain) (\(destinationIP):\(destinationPort))")
            return violation
        }

        // No domain — check IP allowlist
        if ipAllowlist.contains(destinationIP) {
            return nil
        }

        // IP is not in allowlist
        let violation = Violation(
            aiToolName: aiToolName,
            processPid: processPid,
            processPath: processPath,
            destinationIP: destinationIP,
            destinationPort: destinationPort,
            destinationDomain: nil,
            reason: "AI tool \(aiToolName) connected to unapproved IP: \(destinationIP):\(destinationPort)"
        )
        cacheViolation(violation)
        logger.warning("AI network sandbox violation: \(aiToolName) pid=\(processPid) -> \(destinationIP):\(destinationPort)")
        return violation
    }

    /// Evaluate an ``Event`` against the sandbox. Returns a ``Violation`` if
    /// the event represents a network connection from an AI tool to an
    /// unapproved destination, or `nil` if allowed.
    public func evaluate(event: Event, aiToolName: String) -> Violation? {
        guard let network = event.network else { return nil }
        return checkConnection(
            aiToolName: aiToolName,
            processPid: event.process.pid,
            processPath: event.process.executable,
            destinationIP: network.destinationIp,
            destinationPort: network.destinationPort,
            destinationDomain: network.destinationHostname
        )
    }

    /// Add domains to the allowlist at runtime.
    public func addAllowedDomains(_ domains: [String]) {
        domainAllowlist.formUnion(domains)
    }

    /// Add IPs to the allowlist at runtime.
    public func addAllowedIPs(_ ips: [String]) {
        ipAllowlist.formUnion(ips)
    }

    /// Reload the custom allowlist from disk.
    public func reloadConfig(from path: String? = nil) {
        let configPath = path ?? Self.defaultConfigPath()
        // Reset to defaults
        domainAllowlist = Self.defaultAllowlist
        ipAllowlist = Self.defaultIPAllowlist

        if let config = Self.loadConfig(from: configPath) {
            if let domains = config.domains {
                domainAllowlist.formUnion(domains)
            }
            if let ips = config.ips {
                ipAllowlist.formUnion(ips)
            }
            logger.info("Reloaded AI network allowlist from \(configPath)")
        }
    }

    /// Get recent violations for auditing.
    public func getRecentViolations() -> [Violation] {
        recentViolations
    }

    /// Get the current domain allowlist (for UI/diagnostics).
    public func getAllowedDomains() -> Set<String> {
        domainAllowlist
    }

    /// Get the current IP allowlist (for UI/diagnostics).
    public func getAllowedIPs() -> Set<String> {
        ipAllowlist
    }

    // MARK: - Domain Matching

    /// Check if a domain is allowed, supporting subdomain suffix matching.
    /// For example, if "github.com" is in the allowlist, then
    /// "api.github.com" and "raw.githubusercontent.com" would NOT match
    /// (they'd need their own entries), but "sub.github.com" WOULD match
    /// because it is a subdomain of "github.com".
    private func isDomainAllowed(_ domain: String) -> Bool {
        let lowered = domain.lowercased()

        // Exact match
        if domainAllowlist.contains(lowered) {
            return true
        }

        // Suffix match: check if the domain is a subdomain of any allowed domain
        for allowed in domainAllowlist {
            if lowered.hasSuffix("." + allowed) {
                return true
            }
        }

        return false
    }

    // MARK: - Private IP Detection

    /// Returns `true` for RFC 1918 private addresses, loopback, and IPv6 equivalents.
    private static func isPrivateOrLoopback(_ ip: String) -> Bool {
        // IPv6 loopback and ULA
        let lower = ip.lowercased()
        if lower == "::1" { return true }
        if lower.hasPrefix("fc") || lower.hasPrefix("fd") { return true }
        if lower.hasPrefix("fe80") { return true } // link-local

        // IPv4
        guard let octets = parseIPv4(ip) else { return false }
        let (a, b, _, _) = octets

        // 127.0.0.0/8 (loopback)
        if a == 127 { return true }
        // 10.0.0.0/8
        if a == 10 { return true }
        // 172.16.0.0/12
        if a == 172, (16...31).contains(b) { return true }
        // 192.168.0.0/16
        if a == 192, b == 168 { return true }
        // 169.254.0.0/16 (link-local)
        if a == 169, b == 254 { return true }

        return false
    }

    /// Parse a dotted-decimal IPv4 address into four octets.
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

    // MARK: - Configuration Loading

    private static func defaultConfigPath() -> String {
        let appSupport = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first.map { $0.appendingPathComponent("MacCrab").path }
            ?? NSHomeDirectory() + "/Library/Application Support/MacCrab"
        return (appSupport as NSString).appendingPathComponent("ai_network_allowlist.json")
    }

    private static func loadConfig(from path: String) -> AllowlistConfig? {
        guard FileManager.default.fileExists(atPath: path) else { return nil }
        do {
            let data = try Data(contentsOf: URL(fileURLWithPath: path))
            return try JSONDecoder().decode(AllowlistConfig.self, from: data)
        } catch {
            // Silently ignore malformed config — defaults still apply
            return nil
        }
    }

    // MARK: - Violation Cache

    private func cacheViolation(_ violation: Violation) {
        recentViolations.append(violation)
        if recentViolations.count > maxCachedViolations {
            recentViolations.removeFirst(recentViolations.count - maxCachedViolations)
        }
    }
}
