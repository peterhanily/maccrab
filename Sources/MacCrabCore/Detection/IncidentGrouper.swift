// IncidentGrouper.swift
// MacCrabCore
//
// Clusters related alerts into incidents based on process lineage
// and time proximity. Produces high-level attack narratives from
// individual detections.

import Foundation
import os.log

/// Groups related alerts into incidents (attack timelines).
///
/// An incident is a cluster of alerts that share:
/// - Process lineage (same process tree)
/// - Time proximity (within a configurable window)
/// - MITRE tactic progression (reconnaissance → execution → persistence → C2)
public actor IncidentGrouper {

    private let logger = Logger(subsystem: "com.maccrab", category: "incidents")

    // MARK: - Types

    /// A group of related alerts forming an attack timeline.
    public struct Incident: Identifiable, Sendable {
        public let id: String
        public var title: String
        public var severity: Severity
        public var alerts: [IncidentAlert]
        public var firstSeen: Date
        public var lastSeen: Date
        public var processTree: Set<String> // Executable paths involved
        public var tactics: Set<String>     // MITRE tactics observed
        public var status: IncidentStatus

        /// Summary of the attack chain.
        public var narrative: String {
            let tacticsOrdered = tactics.sorted()
            let processNames = processTree.map { ($0 as NSString).lastPathComponent }
            let duration = Int(lastSeen.timeIntervalSince(firstSeen))
            return "\(alerts.count) alerts across \(processNames.count) processes over \(duration)s. Tactics: \(tacticsOrdered.joined(separator: " → "))"
        }
    }

    public struct IncidentAlert: Sendable {
        public let alertId: String
        public let timestamp: Date
        public let ruleTitle: String
        public let severity: Severity
        public let processPath: String
        public let tactics: [String]
    }

    public enum IncidentStatus: String, Sendable {
        case active     // Still receiving new alerts
        case stale      // No new alerts for > staleWindow
        case closed     // Manually closed
    }

    // MARK: - Configuration

    /// Maximum time between alerts in the same incident.
    private let correlationWindow: TimeInterval

    /// Time after last alert before an incident goes stale.
    private let staleWindow: TimeInterval

    /// Maximum number of incidents to track before evicting the oldest stale ones.
    private let maxIncidents: Int = 1_000

    /// Maximum number of entries in the processToIncident lookup map.
    private let maxProcessMappings: Int = 10_000

    // MARK: - State

    /// Active incidents keyed by ID.
    private var incidents: [String: Incident] = [:]

    /// Map from process path to incident ID for fast correlation.
    private var processToIncident: [String: String] = [:]

    // MARK: - Initialization

    public init(correlationWindow: TimeInterval = 300, staleWindow: TimeInterval = 600) {
        self.correlationWindow = correlationWindow
        self.staleWindow = staleWindow
    }

    // MARK: - Public API

    /// Process a new alert and assign it to an incident.
    /// Returns the incident ID (existing or newly created).
    @discardableResult
    public func processAlert(
        alertId: String,
        timestamp: Date,
        ruleTitle: String,
        severity: Severity,
        processPath: String,
        parentPath: String?,
        tactics: [String]
    ) -> String {
        let ia = IncidentAlert(
            alertId: alertId,
            timestamp: timestamp,
            ruleTitle: ruleTitle,
            severity: severity,
            processPath: processPath,
            tactics: tactics
        )

        // Try to find an existing incident for this process or its parent
        if let incidentId = findIncident(forProcess: processPath, parent: parentPath, at: timestamp) {
            addToIncident(id: incidentId, alert: ia)
            return incidentId
        }

        // Create a new incident
        let incidentId = "INC-\(UUID().uuidString.prefix(8))"
        var incident = Incident(
            id: incidentId,
            title: ruleTitle,
            severity: severity,
            alerts: [ia],
            firstSeen: timestamp,
            lastSeen: timestamp,
            processTree: [processPath],
            tactics: Set(tactics),
            status: .active
        )

        if let parent = parentPath {
            incident.processTree.insert(parent)
        }

        incidents[incidentId] = incident
        processToIncident[processPath] = incidentId
        if let parent = parentPath {
            processToIncident[parent] = incidentId
        }

        logger.info("New incident \(incidentId): \(ruleTitle)")
        return incidentId
    }

    /// Get all active incidents sorted by last activity.
    public func activeIncidents() -> [Incident] {
        sweepStale()
        return incidents.values
            .filter { $0.status == .active }
            .sorted { $0.lastSeen > $1.lastSeen }
    }

    /// Get all incidents (including stale).
    public func allIncidents() -> [Incident] {
        sweepStale()
        return incidents.values.sorted { $0.lastSeen > $1.lastSeen }
    }

    /// Get a specific incident.
    public func incident(id: String) -> Incident? {
        incidents[id]
    }

    /// Close an incident manually.
    public func closeIncident(id: String) {
        incidents[id]?.status = .closed
    }

    /// Statistics.
    public func stats() -> (active: Int, stale: Int, closed: Int, totalAlerts: Int) {
        sweepStale()
        let active = incidents.values.filter { $0.status == .active }.count
        let stale = incidents.values.filter { $0.status == .stale }.count
        let closed = incidents.values.filter { $0.status == .closed }.count
        let alerts = incidents.values.reduce(0) { $0 + $1.alerts.count }
        return (active, stale, closed, alerts)
    }

    // MARK: - Private

    private func findIncident(forProcess path: String, parent: String?, at time: Date) -> String? {
        // Check direct process match
        if let id = processToIncident[path],
           let incident = incidents[id],
           incident.status == .active,
           time.timeIntervalSince(incident.lastSeen) < correlationWindow {
            return id
        }

        // Check parent process match
        if let parent = parent,
           let id = processToIncident[parent],
           let incident = incidents[id],
           incident.status == .active,
           time.timeIntervalSince(incident.lastSeen) < correlationWindow {
            return id
        }

        return nil
    }

    private func addToIncident(id: String, alert: IncidentAlert) {
        guard var incident = incidents[id] else { return }

        // Deduplicate: don't add the same alert twice
        if incident.alerts.contains(where: { $0.alertId == alert.alertId }) { return }

        incident.alerts.append(alert)
        incident.lastSeen = alert.timestamp
        incident.processTree.insert(alert.processPath)
        incident.tactics.formUnion(alert.tactics)

        // Escalate severity if needed
        if alert.severity > incident.severity {
            incident.severity = alert.severity
        }

        // Update title to reflect the most severe alert
        if alert.severity >= incident.severity {
            incident.title = alert.ruleTitle
        }

        incidents[id] = incident
        processToIncident[alert.processPath] = id
    }

    private func sweepStale() {
        let now = Date()
        for (id, incident) in incidents where incident.status == .active {
            if now.timeIntervalSince(incident.lastSeen) > staleWindow {
                incidents[id]?.status = .stale
            }
        }
        // Purge very old stale incidents (> 24 hours)
        incidents = incidents.filter { _, inc in
            inc.status == .closed ? true : now.timeIntervalSince(inc.lastSeen) < 86400
        }

        // Enforce hard cap on incidents: evict oldest stale, then oldest closed
        if incidents.count > maxIncidents {
            let excess = incidents.count - maxIncidents
            let toEvict = incidents
                .filter { $0.value.status == .stale || $0.value.status == .closed }
                .sorted { $0.value.lastSeen < $1.value.lastSeen }
                .prefix(excess)
                .map(\.key)
            for id in toEvict {
                incidents.removeValue(forKey: id)
            }
        }

        // Enforce hard cap on processToIncident map
        if processToIncident.count > maxProcessMappings {
            // Remove mappings that point to incidents that no longer exist
            processToIncident = processToIncident.filter { _, incidentId in
                incidents[incidentId] != nil
            }
        }
    }
}
