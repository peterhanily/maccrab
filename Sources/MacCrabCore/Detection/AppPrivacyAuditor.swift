import Foundation
import os.log

/// Audits application network behavior to identify privacy risks.
/// Tracks which apps contact which domains, how often, and how much data.
public actor AppPrivacyAuditor {
    private let logger = Logger(subsystem: "com.maccrab.detection", category: "privacy-audit")

    public struct AppProfile: Sendable {
        public let processName: String
        public let processPath: String
        public let domains: [DomainContact]
        public let totalConnections: Int
        public let totalBytesOut: Int
        public let uniqueDomains: Int
        public let riskLevel: String  // "low", "medium", "high"
        public let concerns: [String]
    }

    public struct DomainContact: Sendable {
        public let domain: String
        public let ip: String
        public let connectionCount: Int
        public let firstSeen: Date
        public let lastSeen: Date
    }

    /// Per-process network tracking
    private var processConnections: [String: [ConnectionRecord]] = [:]  // processPath -> connections
    private let maxRecordsPerProcess = 1000

    private struct ConnectionRecord {
        let domain: String?
        let ip: String
        let port: UInt16
        let timestamp: Date
        let bytesOut: Int
    }

    /// Known tracking/analytics domains
    private static let trackingDomains: Set<String> = [
        "google-analytics.com", "analytics.google.com",
        "facebook.com", "graph.facebook.com",
        "doubleclick.net", "googlesyndication.com",
        "amplitude.com", "mixpanel.com", "segment.io", "segment.com",
        "hotjar.com", "fullstory.com",
        "sentry.io", "bugsnag.com", "crashlytics.com",
        "appsflyer.com", "adjust.com", "branch.io",
        "intercom.io", "zendesk.com",
        "telemetry.microsoft.com", "vortex.data.microsoft.com",
        "incoming.telemetry.mozilla.org",
    ]

    /// Record a network connection for privacy tracking.
    public func recordConnection(processName: String, processPath: String, domain: String?, ip: String, port: UInt16, bytesOut: Int = 0) {
        let key = processPath
        var records = processConnections[key] ?? []
        records.append(ConnectionRecord(domain: domain, ip: ip, port: port, timestamp: Date(), bytesOut: bytesOut))
        if records.count > maxRecordsPerProcess {
            records = Array(records.suffix(maxRecordsPerProcess))
        }
        processConnections[key] = records
    }

    /// Generate privacy audit for all tracked apps.
    public func audit() -> [AppProfile] {
        var profiles: [AppProfile] = []

        for (processPath, records) in processConnections {
            let processName = (processPath as NSString).lastPathComponent

            // Skip system processes
            if processPath.hasPrefix("/System/") || processPath.hasPrefix("/usr/libexec/") { continue }

            // Group by domain
            var domainCounts: [String: (count: Int, ip: String, first: Date, last: Date)] = [:]
            var totalBytes = 0

            for record in records {
                let domain = record.domain ?? record.ip
                if var existing = domainCounts[domain] {
                    existing.count += 1
                    existing.last = max(existing.last, record.timestamp)
                    existing.first = min(existing.first, record.timestamp)
                    domainCounts[domain] = existing
                } else {
                    domainCounts[domain] = (1, record.ip, record.timestamp, record.timestamp)
                }
                totalBytes += record.bytesOut
            }

            let domains = domainCounts.map { DomainContact(domain: $0.key, ip: $0.value.ip, connectionCount: $0.value.count, firstSeen: $0.value.first, lastSeen: $0.value.last) }
                .sorted { $0.connectionCount > $1.connectionCount }

            // Assess privacy concerns
            var concerns: [String] = []
            let matchedTrackingDomains = domains.filter { d in Self.trackingDomains.contains(where: { d.domain.hasSuffix($0) }) }
            if !matchedTrackingDomains.isEmpty {
                concerns.append("Contacts \(matchedTrackingDomains.count) tracking/analytics domain(s)")
            }
            if domains.count > 20 {
                concerns.append("Contacts \(domains.count) unique domains (unusually high)")
            }
            if records.count > 100 {
                concerns.append("Made \(records.count) connections in tracking window")
            }

            let risk = concerns.count >= 2 ? "high" : (concerns.isEmpty ? "low" : "medium")

            profiles.append(AppProfile(
                processName: processName, processPath: processPath,
                domains: domains, totalConnections: records.count,
                totalBytesOut: totalBytes, uniqueDomains: domainCounts.count,
                riskLevel: risk, concerns: concerns
            ))
        }

        return profiles.sorted { $0.uniqueDomains > $1.uniqueDomains }
    }

    /// Purge old connection records.
    public func purge(olderThan: TimeInterval = 3600) {
        let cutoff = Date().addingTimeInterval(-olderThan)
        for (key, records) in processConnections {
            let filtered = records.filter { $0.timestamp >= cutoff }
            if filtered.isEmpty {
                processConnections.removeValue(forKey: key)
            } else {
                processConnections[key] = filtered
            }
        }
    }
}
