import Foundation

/// Presentation contains only allowlisted categories. The persisted error and
/// recovery strings can contain paths or user content and are never retained.
struct V2StartupFailure: Equatable, Sendable {
    enum Reason: String, Sendable {
        case storagePressure = "storage_pressure"
        case keyUnavailable = "key_unavailable"
        case integrityFailure = "integrity_failure"
        case initializationFailed = "initialization_failed"
        case reportUnavailable = "report_unavailable"
    }
    enum Preservation: String, Sendable { case preserved, quarantined, unverified }

    let occurredAt: Date?
    let database: String
    let reason: Reason
    let preservation: Preservation
    let enginePID: Int?
    let engineStartedAt: Date?

    static func read(directory: String) -> V2StartupFailure? {
        let url = URL(fileURLWithPath: directory + "/last_crash.json")
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        guard let file = try? FileHandle(forReadingFrom: url) else { return unavailable }
        defer { try? file.close() }
        guard let data = try? file.read(upToCount: 65_537), data.count <= 65_536,
              let raw = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return unavailable }
        return decode(raw)
    }

    static let unavailable = V2StartupFailure(occurredAt: nil, database: "unknown",
        reason: .reportUnavailable, preservation: .unverified, enginePID: nil, engineStartedAt: nil)

    static func decode(_ raw: [String: Any]) -> V2StartupFailure {
        let databases = ["events.db", "alerts.db", "tracegraph.db", "traces.db"]
        let structured = (raw["schema_version"] as? Int) == 2
        let legacy = (String((raw["error"] as? String ?? "").prefix(4096))
            + " " + String((raw["recovery_action"] as? String ?? "").prefix(4096))).lowercased()
        let suppliedDatabase = raw["database"] as? String ?? "unknown"
        let database: String
        if structured {
            database = databases.contains(suppliedDatabase) ? suppliedDatabase : "unknown"
        } else {
            database = databases.first(where: { legacy.contains($0) })
                ?? (legacy.contains("eventstore") ? "events.db" : (legacy.contains("alertstore") ? "alerts.db" : "unknown"))
        }
        let reason: Reason
        if structured {
            reason = Reason(rawValue: raw["reason"] as? String ?? "") ?? .initializationFailed
        } else if ["keychain", "key unavailable", "key is unavailable", "key persistence", "encryption key"].contains(where: legacy.contains) {
            reason = .keyUnavailable
        } else if ["disk full", "low disk", "free space", "storage admission", "family cap", "footprint limit"].contains(where: legacy.contains) {
            reason = .storagePressure
        } else if ["corrupt", "integrity", "checksum", "malformed database"].contains(where: legacy.contains) {
            reason = .integrityFailure
        } else {
            reason = .initializationFailed
        }
        func date(_ key: String) -> Date? {
            guard let value = raw[key] as? Double, value.isFinite, value > 0 else { return nil }
            return Date(timeIntervalSince1970: value)
        }
        // Legacy recovery text does not establish whether a move completed.
        let preservation = structured
            ? Preservation(rawValue: raw["preservation_outcome"] as? String ?? "") ?? .unverified
            : .unverified
        return .init(occurredAt: date("occurred_at_unix"), database: database, reason: reason,
                     preservation: preservation, enginePID: structured ? raw["engine_pid"] as? Int : nil,
                     engineStartedAt: structured ? date("engine_started_at_unix") : nil)
    }

    func isHistorical(heartbeat: V2HeartbeatSnapshot?) -> Bool {
        guard let heartbeat, !heartbeat.isStale, heartbeat.isReady,
              let occurredAt, let startedAt = heartbeat.engineStartedAt else { return false }
        return startedAt > occurredAt && heartbeat.writtenAt >= startedAt
    }

    var reasonText: String {
        switch reason {
        case .storagePressure: return String(localized: "startup.failure.pressure", defaultValue: "Storage capacity or free space prevented startup.")
        case .keyUnavailable: return String(localized: "startup.failure.key", defaultValue: "The existing database encryption key was unavailable.")
        case .integrityFailure: return String(localized: "startup.failure.integrity", defaultValue: "The engine could not verify stored evidence integrity.")
        case .initializationFailed: return String(localized: "startup.failure.initialization", defaultValue: "A required store could not initialize.")
        case .reportUnavailable: return String(localized: "startup.failure.unreadable", defaultValue: "A startup failure report exists but could not be read or validated.")
        }
    }

    var preservationText: String {
        switch preservation {
        case .preserved: return String(localized: "startup.failure.preserved", defaultValue: "The engine reports that the existing database family was preserved.")
        case .quarantined: return String(localized: "startup.failure.quarantined", defaultValue: "The engine reports that the existing database family was moved to quarantine; replacement startup failed.")
        case .unverified: return String(localized: "startup.failure.unverified", defaultValue: "The report does not verify the final preservation outcome. Keep the existing store and its sidecar files together.")
        }
    }

    var nextAction: String {
        switch reason {
        case .storagePressure: return String(localized: "startup.failure.pressureAction", defaultValue: "Free space outside MacCrab's data directory, then retry startup. If a store limit is still blocking startup, export diagnostics for support. Do not delete evidence files to make room.")
        case .keyUnavailable: return String(localized: "startup.failure.keyAction", defaultValue: "Unlock the login keychain if applicable and retry after signing in. If the key remains unavailable, export diagnostics for support. Do not reset keys or replace the encrypted store.")
        case .integrityFailure: return String(localized: "startup.failure.integrityAction", defaultValue: "Preserve the database and sidecar files together and export diagnostics for support before attempting recovery. Repeated activation does not repair stored evidence.")
        case .initializationFailed, .reportUnavailable: return String(localized: "startup.failure.generalAction", defaultValue: "Export diagnostics for support and preserve the existing data directory. Review the storage issue before retrying activation.")
        }
    }

    var diagnosticDictionary: [String: Any] {
        var result: [String: Any] = ["database": database, "reason": reason.rawValue,
                                   "preservation_outcome": preservation.rawValue]
        if let occurredAt { result["occurred_at_unix"] = occurredAt.timeIntervalSince1970 }
        if let enginePID { result["engine_pid"] = enginePID }
        if let engineStartedAt { result["engine_started_at_unix"] = engineStartedAt.timeIntervalSince1970 }
        return result
    }
}
