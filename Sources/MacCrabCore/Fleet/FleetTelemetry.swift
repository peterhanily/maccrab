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
        // Privacy: redact the username (and any other PII) out of the path
        // before it can leave the host. FleetTelemetry's own header promises
        // "no user names", but processPath shipped raw (/Users/<name>/...).
        // A4-06: LLMSanitizer is best-effort heuristics (see its header), not a
        // contractual no-leak boundary — Fleet egress inherits that limitation.
        self.processPath = LLMSanitizer.sanitize(processPath)
        self.mitreTechniques = mitreTechniques; self.timestamp = timestamp
    }
}

/// An IOC (hash, IP, or domain) that was seen locally.
public struct FleetIOCSighting: Codable, Sendable {
    public let type: String // "hash", "ip", "domain"
    public let value: String
    public let context: String // Brief context (process name, not full cmdline)
    public let timestamp: Date

    public init(type: String, value: String, context: String, timestamp: Date) {
        self.type = type
        self.value = value          // the IOC itself — must NOT be redacted
        self.context = LLMSanitizer.sanitize(context)  // privacy: scrub PII from the context
        self.timestamp = timestamp
    }
}

/// Per-process behavioral score summary.
public struct FleetBehaviorScore: Codable, Sendable {
    public let processPath: String
    public let score: Double
    public let topIndicators: [String]

    public init(processPath: String, score: Double, topIndicators: [String]) {
        // Privacy: redact the username out of the path before egress.
        self.processPath = LLMSanitizer.sanitize(processPath)
        self.score = score
        self.topIndicators = topIndicators
    }
}

// v1.21.5: the pull models (FleetAggregation, FleetIOCAggregated,
// FleetHotProcess, FleetCampaign, FleetCampaignResponse) were removed —
// fleet is outbound-only; nothing the collector returns is consumed.
