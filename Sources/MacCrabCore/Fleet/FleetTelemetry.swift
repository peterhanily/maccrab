// FleetTelemetry.swift
// MacCrabCore
//
// Data models for fleet-wide telemetry sharing.
// Privacy-preserving: no command lines, no user names, pseudonymous host IDs.

import Foundation

/// Outbound telemetry payload sent to the fleet collector.
public struct FleetTelemetry: Codable, Sendable {
    /// Pseudonymous host identifier (SHA-256 of hostname + hardware UUID).
    public let hostId: String
    /// Timestamp of this telemetry batch.
    public let timestamp: Date
    /// MacCrab version.
    public let version: String
    /// Alert summaries since last push.
    public let alerts: [FleetAlertSummary]
    /// IOC sightings (hashes/IPs/domains seen locally that matched threat intel).
    public let iocSightings: [FleetIOCSighting]
    /// Top behavioral scores.
    public let behaviorScores: [FleetBehaviorScore]
}

/// Sanitized alert summary for fleet sharing.
public struct FleetAlertSummary: Codable, Sendable {
    public let ruleId: String
    public let ruleTitle: String
    public let severity: String
    public let processPath: String
    public let mitreTechniques: String
    public let timestamp: Date

    public init(ruleId: String, ruleTitle: String, severity: String, processPath: String, mitreTechniques: String, timestamp: Date) {
        self.ruleId = ruleId; self.ruleTitle = ruleTitle; self.severity = severity
        self.processPath = processPath; self.mitreTechniques = mitreTechniques; self.timestamp = timestamp
    }
}

/// An IOC (hash, IP, or domain) that was seen locally.
public struct FleetIOCSighting: Codable, Sendable {
    public let type: String // "hash", "ip", "domain"
    public let value: String
    public let context: String // Brief context (process name, not full cmdline)
    public let timestamp: Date
}

/// Per-process behavioral score summary.
public struct FleetBehaviorScore: Codable, Sendable {
    public let processPath: String
    public let score: Double
    public let topIndicators: [String]
}

/// Aggregated fleet data pulled from the collector.
public struct FleetAggregation: Codable, Sendable {
    /// IOCs seen across the fleet (with sighting counts).
    public let iocs: [FleetIOCAggregated]
    /// Processes with high behavioral scores fleet-wide.
    public let hotProcesses: [FleetHotProcess]
    /// Number of active fleet members.
    public let fleetSize: Int
    /// Timestamp of this aggregation.
    public let timestamp: Date
}

public struct FleetIOCAggregated: Codable, Sendable {
    public let type: String
    public let value: String
    public let sightingCount: Int
    public let hostCount: Int
    public let firstSeen: Date
    public let lastSeen: Date
}

public struct FleetHotProcess: Codable, Sendable {
    public let processPath: String
    public let avgScore: Double
    public let hostCount: Int
}

/// A cross-endpoint campaign: same rule firing on 3+ hosts.
public struct FleetCampaign: Codable, Sendable {
    public let ruleId: String
    public let ruleTitle: String
    public let severity: String
    public let alertCount: Int
    public let hostCount: Int
    public let processes: String?
    public let techniques: String?
    public let firstSeen: Double
    public let lastSeen: Double

    private enum CodingKeys: String, CodingKey {
        case ruleId = "rule_id"
        case ruleTitle = "rule_title"
        case severity
        case alertCount = "alert_count"
        case hostCount = "host_count"
        case processes
        case techniques
        case firstSeen = "first_seen"
        case lastSeen = "last_seen"
    }
}

/// Response wrapper for /api/fleet-campaigns.
public struct FleetCampaignResponse: Codable, Sendable {
    public let campaigns: [FleetCampaign]
    public let windowSeconds: Int?

    private enum CodingKeys: String, CodingKey {
        case campaigns
        case windowSeconds = "window_seconds"
    }
}
