import Foundation
import os.log

/// Audits application network behavior to identify privacy risks.
/// Tracks which apps contact which domains, how often, and how much data.
public actor AppPrivacyAuditor {
    public init() {}
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
        public let bytesOut: Int
        public let firstSeen: Date
        public let lastSeen: Date
    }

    /// Alert-worthy egress anomaly. Returned by checkForAnomalies() for
    /// callers that want to surface findings as Alerts.
    public struct EgressAnomaly: Sendable {
        public enum Kind: String, Sendable {
            case bulkEgress         // >50 MB in tracking window
            case singleDomainSpike  // >10 MB to one unknown domain
            case trackingContact    // high-frequency contact with tracking domains
        }
        public let kind: Kind
        public let processName: String
        public let processPath: String
        public let detail: String
        public let bytesOut: Int
    }

    /// Per-process network tracking
    private var processConnections: [String: [ConnectionRecord]] = [:]
    private let maxRecordsPerProcess = 1000

    private struct ConnectionRecord {
        let domain: String?
        let ip: String
        let port: UInt16
        let timestamp: Date
        let bytesOut: Int
    }

    // MARK: - Tracking domain registry (70+ entries)

    /// Known tracking, analytics, telemetry, crash-reporting, and ad-network
    /// domains. Matched via suffix so subdomains are automatically covered.
    /// Expand as new vendors are identified; keep sorted alphabetically for
    /// easy diffing.
    private static let trackingDomains: Set<String> = [
        // Analytics — general
        "amplitude.com",
        "analytics.google.com",
        "appcues.com",
        "contentsquare.com",
        "crazyegg.com",
        "fullstory.com",
        "heap.io",
        "hotjar.com",
        "logrocket.com",
        "mixpanel.com",
        "mouseflow.com",
        "pendo.io",
        "posthog.com",
        "segment.com",
        "segment.io",
        "smartlook.com",
        "woopra.com",

        // A/B testing / feature flags
        "growthbook.io",
        "launchdarkly.com",
        "optimizely.com",
        "statsig.com",

        // Marketing automation / CRM
        "braze.com",
        "braze-eu.com",
        "customer.io",
        "hubspot.com",
        "klaviyo.com",
        "marketo.net",
        "pardot.com",

        // Ad networks / attribution
        "adjust.com",
        "adzerk.net",
        "appsflyer.com",
        "branch.io",
        "criteo.com",
        "doubleclick.net",
        "googlesyndication.com",
        "outbrain.com",
        "taboola.com",
        "thetradedesk.com",

        // Error / crash reporting
        "bugsnag.com",
        "crashlytics.com",
        "datadog.com",
        "dynatrace.com",
        "elastic.co",
        "honeybadger.io",
        "instabug.com",
        "newrelic.com",
        "raygun.com",
        "rollbar.com",
        "sentry.io",

        // Customer support / session replay
        "intercom.io",
        "zendesk.com",

        // Google telemetry and ad infrastructure
        "google-analytics.com",
        "googletagmanager.com",

        // Social SDKs
        "connect.facebook.net",
        "facebook.com",
        "graph.facebook.com",

        // Apple telemetry
        "metrics.apple.com",

        // Microsoft telemetry
        "self.events.data.microsoft.com",
        "settings-win.data.microsoft.com",
        "telemetry.microsoft.com",
        "vortex.data.microsoft.com",

        // Mozilla telemetry
        "incoming.telemetry.mozilla.org",
        "telemetry.mozilla.org",

        // Firebase (Google mobile analytics)
        "firebase.google.com",
        "firebaseio.com",
        "firebaseinstallations.googleapis.com",
    ]

    // MARK: - Public API

    /// Record a network connection for privacy tracking.
    public func recordConnection(
        processName: String, processPath: String,
        domain: String?, ip: String, port: UInt16, bytesOut: Int = 0
    ) {
        var records = processConnections[processPath] ?? []
        records.append(ConnectionRecord(domain: domain, ip: ip, port: port, timestamp: Date(), bytesOut: bytesOut))
        if records.count > maxRecordsPerProcess {
            records = Array(records.suffix(maxRecordsPerProcess))
        }
        processConnections[processPath] = records
    }

    /// Generate privacy audit for all tracked apps. Returns one profile per
    /// process with risk rating, concern strings, and per-domain breakdown.
    public func audit() -> [AppProfile] {
        var profiles: [AppProfile] = []

        for (processPath, records) in processConnections {
            let processName = (processPath as NSString).lastPathComponent
            if processPath.hasPrefix("/System/") || processPath.hasPrefix("/usr/libexec/") { continue }

            var domainStats: [String: (count: Int, bytes: Int, ip: String, first: Date, last: Date)] = [:]
            var totalBytes = 0

            for record in records {
                let key = record.domain ?? record.ip
                if var existing = domainStats[key] {
                    existing.count += 1
                    existing.bytes += record.bytesOut
                    existing.last = max(existing.last, record.timestamp)
                    existing.first = min(existing.first, record.timestamp)
                    domainStats[key] = existing
                } else {
                    domainStats[key] = (1, record.bytesOut, record.ip, record.timestamp, record.timestamp)
                }
                totalBytes += record.bytesOut
            }

            let domains = domainStats.map {
                DomainContact(
                    domain: $0.key, ip: $0.value.ip,
                    connectionCount: $0.value.count, bytesOut: $0.value.bytes,
                    firstSeen: $0.value.first, lastSeen: $0.value.last
                )
            }.sorted { $0.connectionCount > $1.connectionCount }

            var concerns: [String] = []
            let matchedTrackers = domains.filter { d in
                Self.trackingDomains.contains(where: { d.domain.hasSuffix($0) })
            }
            if !matchedTrackers.isEmpty {
                concerns.append("Contacts \(matchedTrackers.count) tracking/analytics domain(s): \(matchedTrackers.prefix(3).map(\.domain).joined(separator: ", "))")
            }
            if domains.count > 20 {
                concerns.append("Contacts \(domains.count) unique domains (unusually high)")
            }
            if records.count > 100 {
                concerns.append("Made \(records.count) connections in tracking window")
            }
            let mb = totalBytes / 1_048_576
            if mb > 50 {
                concerns.append("Sent \(mb) MB in tracking window (potential bulk egress)")
            }

            let risk = concerns.count >= 3 ? "high" : (concerns.isEmpty ? "low" : "medium")
            profiles.append(AppProfile(
                processName: processName, processPath: processPath,
                domains: domains, totalConnections: records.count,
                totalBytesOut: totalBytes, uniqueDomains: domainStats.count,
                riskLevel: risk, concerns: concerns
            ))
        }

        return profiles.sorted { $0.uniqueDomains > $1.uniqueDomains }
    }

    /// Check all tracked processes for alert-worthy egress anomalies. Call
    /// periodically (e.g., every 5 minutes) from DaemonTimers. Callers
    /// convert returned anomalies to Alerts or log events as appropriate.
    public func checkForAnomalies() -> [EgressAnomaly] {
        var anomalies: [EgressAnomaly] = []
        let bulkThresholdBytes = 50 * 1_048_576   // 50 MB
        let singleDomainThresholdBytes = 10 * 1_048_576  // 10 MB per domain

        for (processPath, records) in processConnections {
            let processName = (processPath as NSString).lastPathComponent
            if processPath.hasPrefix("/System/") || processPath.hasPrefix("/usr/libexec/") { continue }

            let totalBytes = records.reduce(0) { $0 + $1.bytesOut }
            if totalBytes > bulkThresholdBytes {
                anomalies.append(EgressAnomaly(
                    kind: .bulkEgress,
                    processName: processName,
                    processPath: processPath,
                    detail: "\(processName) sent \(totalBytes / 1_048_576) MB in tracking window",
                    bytesOut: totalBytes
                ))
            }

            // Per-domain egress: flag unknown domains with large transfers
            var perDomainBytes: [String: Int] = [:]
            for record in records {
                let key = record.domain ?? record.ip
                perDomainBytes[key, default: 0] += record.bytesOut
            }
            for (domain, bytes) in perDomainBytes where bytes > singleDomainThresholdBytes {
                let isKnownTracker = Self.trackingDomains.contains(where: { domain.hasSuffix($0) })
                if !isKnownTracker {
                    anomalies.append(EgressAnomaly(
                        kind: .singleDomainSpike,
                        processName: processName,
                        processPath: processPath,
                        detail: "\(processName) sent \(bytes / 1_048_576) MB to \(domain)",
                        bytesOut: bytes
                    ))
                }
            }

            // High-frequency tracker contact: >50 hits to a tracking domain
            var domainCounts: [String: Int] = [:]
            for record in records {
                if let d = record.domain { domainCounts[d, default: 0] += 1 }
            }
            let trackerHits = domainCounts.filter { d, _ in
                Self.trackingDomains.contains(where: { d.hasSuffix($0) })
            }
            let totalTrackerHits = trackerHits.values.reduce(0, +)
            if totalTrackerHits > 50 {
                let topDomain = trackerHits.max(by: { $0.value < $1.value })?.key ?? ""
                anomalies.append(EgressAnomaly(
                    kind: .trackingContact,
                    processName: processName,
                    processPath: processPath,
                    detail: "\(processName) made \(totalTrackerHits) contacts to tracking domains; top: \(topDomain)",
                    bytesOut: 0
                ))
            }
        }

        return anomalies
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
