import Foundation
import CoreFoundation
import MacCrabCore

/// Extra eligibility for cross-pause cache reuse, not a gate on historical
/// investigation. Read the small current liveness file without an mtime cache.
enum EventReaderEngineIdentity {
    static func read(directory: String, now: Date = Date()) -> EngineTelemetryIdentity? {
        guard let data = try? RuntimeConfigurationFiles.readControlData(
            at: directory + "/heartbeat.json", maximumBytes: 64 * 1_024),
              let raw = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }
        return decode(raw, now: now)
    }

    static func decode(_ raw: [String: Any], now: Date) -> EngineTelemetryIdentity? {
        func number(_ key: String) -> Double? {
            guard let value = raw[key] as? NSNumber,
                  CFGetTypeID(value) != CFBooleanGetTypeID(), value.doubleValue.isFinite else { return nil }
            return value.doubleValue
        }
        guard raw["boot_phase"] as? String == "ready",
              let liveness = raw["liveness"] as? NSNumber,
              CFGetTypeID(liveness) == CFBooleanGetTypeID(), liveness.boolValue,
              let written = number("written_at_unix"), let pid = number("engine_pid"),
              pid > 0, pid.rounded(.towardZero) == pid,
              let started = number("engine_started_at_unix"), started > 0, started <= written,
              let identity = EngineTelemetryIdentity(heartbeat: raw),
              !identity.version.isEmpty, !identity.build.isEmpty else { return nil }
        let age = now.timeIntervalSince1970 - written
        return age.isFinite && age >= 0 && age <= 120 ? identity : nil
    }
}
