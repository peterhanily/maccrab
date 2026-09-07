import Foundation

/// A successful read is not a protection verdict. Liveness, current health,
/// physical evidence counts and missing state remain distinct in schema 1.
public struct RuntimeStatusDocument: Codable, Sendable {
    public let schemaVersion: Int
    public let sourceDirectory: String
    public let observedAt: Date
    public let liveness: String
    public let heartbeatWrittenAt: Date?
    public let engineIdentity: EngineTelemetryIdentity?
    public let bootPhase: String?
    public let currentHealth: HeartbeatSnapshot?
    /// Data provenance, not receiver availability or a protection verdict.
    /// Reads always supply this fixed label; nil supports older schema-1
    /// documents that did not expose the Agent Trace trust boundary.
    public let agentTraceTrust: AgentTraceTrust?
    public let retainedEventCount: Int?
    public let retainedAlertCount: Int?

    public static func read(directory: String, now: Date = Date()) async throws -> Self {
        let fm = FileManager.default
        func optionalData(_ name: String) throws -> Data? {
            try RuntimeConfigurationFiles.readControlData(at: directory + "/" + name, maximumBytes: 4 * 1024 * 1024)
        }
        let liteData = try optionalData("heartbeat.json")
        let lite: [String: Any]?
        if let liteData {
            guard let object = try JSONSerialization.jsonObject(with: liteData) as? [String: Any] else {
                throw RuntimeConfigContractError("heartbeat.json must contain a JSON object")
            }
            lite = object
        } else { lite = nil }
        let identity = lite.flatMap(EngineTelemetryIdentity.init(heartbeat:))
        let written = (lite?["written_at_unix"] as? Double).map(Date.init(timeIntervalSince1970:))
        let fresh = written.map { now.timeIntervalSince($0) >= 0 && now.timeIntervalSince($0) <= 120 } ?? false
        let richData = try optionalData("heartbeat_rich.json")
        var health: HeartbeatSnapshot?
        if let richData {
            let snapshot = try JSONDecoder().decode(HeartbeatSnapshot.self, from: richData)
            let rich = try JSONSerialization.jsonObject(with: richData) as? [String: Any]
            if fresh, identity != nil,
               rich.flatMap(EngineTelemetryIdentity.init(heartbeat:)) == identity,
               !snapshot.isStale(now: now.timeIntervalSince1970, maxAge: 120) {
                health = snapshot
            }
        }
        var events: Int?
        if fm.fileExists(atPath: directory + "/events.db") {
            let store = try EventStore(directory: directory, forceReadOnly: true)
            events = try await store.maintenanceRetainedRecordCount()
        }
        var alerts: Int?
        if fm.fileExists(atPath: directory + "/alerts.db") {
            let store = try AlertStore(directory: directory, forceReadOnly: true)
            alerts = try await store.count()
        }
        return .init(schemaVersion: 1, sourceDirectory: directory, observedAt: now,
                     liveness: lite == nil ? "unavailable" : (fresh && identity != nil ? "fresh" : "stale_or_unknown"),
                     heartbeatWrittenAt: written, engineIdentity: identity,
                     bootPhase: fresh ? lite?["boot_phase"] as? String : nil,
                     currentHealth: health, agentTraceTrust: .unauthenticatedSelfReported,
                     retainedEventCount: events, retainedAlertCount: alerts)
    }
}
