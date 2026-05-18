// V2HeartbeatSnapshot.swift
// View model derived from the daemon's `heartbeat_rich.json` file
// (written every 30s by `Sources/MacCrabAgentKit/DaemonTimers.swift`).
// Used by the System workspace to replace hardcoded health metrics
// with real ones.

import Foundation

public struct V2HeartbeatSnapshot: Sendable, Equatable {
    public let writtenAt: Date
    public let uptimeSeconds: Int
    public let eventsProcessed: Int
    public let alertsEmitted: Int
    public let residentMemoryMB: Int?
    public let sysextHasFDA: Bool
    public let schemaVersion: Int
    public let eventTypeCounts1h: [String: Int]
    public let collectors: [Collector]
    // v1.12.6 Wave 9O: Wave-9K added these counters to
    // heartbeat_rich.json but pre-9O the dashboard snapshot didn't
    // decode them. Wired now so the System workspace can surface
    // payload-cap-firing rate and ES-collector drop rate.
    public let payloadTruncatedTotal: Int
    public let esloggerDroppedTotal: Int

    public struct Collector: Sendable, Equatable, Hashable {
        public let name: String
        public let eventCount: Int
        public let healthy: Bool
        /// Optional. Nil when the collector has never ticked (event-
        /// driven collector waiting for its first event, or non-event-
        /// driven collector that has not yet completed a poll
        /// iteration). Pre-fix the daemon omitted `last_tick_unix`
        /// from heartbeat.json in this case but the dashboard
        /// fallback `as? Double ?? 0` produced epoch-0 dates that
        /// rendered as "20583d ago".
        public let lastTickUnix: Double?

        public var lastTick: Date? {
            lastTickUnix.map(Date.init(timeIntervalSince1970:))
        }
    }

    /// Returns the freshest heartbeat from any candidate dir, or nil.
    public static func readFreshest() -> V2HeartbeatSnapshot? {
        let userDir = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)
            .first?.appendingPathComponent("MacCrab").path
            ?? NSHomeDirectory() + "/Library/Application Support/MacCrab"
        let systemDir = "/Library/Application Support/MacCrab"
        let candidates = Array(Set([userDir, systemDir]))
        let withMtime: [(String, Date)] = candidates.compactMap { dir in
            let path = dir + "/heartbeat_rich.json"
            guard let attrs = try? FileManager.default.attributesOfItem(atPath: path),
                  let mtime = attrs[.modificationDate] as? Date else { return nil }
            return (path, mtime)
        }
        guard let chosen = withMtime.max(by: { $0.1 < $1.1 }) else { return nil }
        // Discard stale heartbeats (>5 minutes old).
        if chosen.1.timeIntervalSinceNow < -300 { return nil }
        return decode(at: chosen.0)
    }

    private static func decode(at path: String) -> V2HeartbeatSnapshot? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let raw = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }
        let writtenAt = Date(timeIntervalSince1970: TimeInterval(
            raw["written_at_unix"] as? Double ?? 0
        ))
        let collectorRaw = raw["collector_health"] as? [[String: Any]] ?? []
        let collectors: [Collector] = collectorRaw.compactMap { c in
            guard let name = c["name"] as? String else { return nil }
            return Collector(
                name: name,
                eventCount: c["event_count"] as? Int ?? 0,
                healthy: c["healthy"] as? Bool ?? false,
                lastTickUnix: c["last_tick_unix"] as? Double
            )
        }
        let counts: [String: Int] = (raw["event_type_counts_1h"] as? [String: Any])?
            .compactMapValues { $0 as? Int } ?? [:]
        return V2HeartbeatSnapshot(
            writtenAt: writtenAt,
            uptimeSeconds: raw["uptime_seconds"] as? Int ?? 0,
            eventsProcessed: raw["events_processed"] as? Int ?? 0,
            alertsEmitted: raw["alerts_emitted"] as? Int ?? 0,
            residentMemoryMB: raw["resident_memory_mb"] as? Int,
            sysextHasFDA: raw["sysext_has_fda"] as? Bool ?? false,
            schemaVersion: raw["schema_version"] as? Int ?? 0,
            eventTypeCounts1h: counts,
            collectors: collectors,
            // Wave 9O: pre-9O these keys were emitted by DaemonTimers
            // (Wave 9K) but silently dropped here. Default to 0 when
            // missing so legacy heartbeats from older daemons that
            // pre-date Wave 9K render as "no truncation, no drops"
            // rather than crash.
            payloadTruncatedTotal: raw["payload_truncated_total"] as? Int ?? 0,
            esloggerDroppedTotal: raw["eslogger_dropped_total"] as? Int ?? 0
        )
    }
}

extension V2HeartbeatSnapshot {
    /// Human-friendly uptime, e.g. "2h 14m" or "12d".
    public var uptimeDisplay: String {
        let s = uptimeSeconds
        if s < 60        { return "\(s)s" }
        if s < 3600      { return "\(s / 60)m" }
        if s < 86_400    {
            let h = s / 3600, m = (s % 3600) / 60
            return m > 0 ? "\(h)h \(m)m" : "\(h)h"
        }
        let d = s / 86_400, h = (s % 86_400) / 3600
        return h > 0 ? "\(d)d \(h)h" : "\(d)d"
    }

    /// Rolling event rate in events/sec, derived from the 1h counts.
    public var eventsPerSecond1h: Double {
        let total = eventTypeCounts1h.values.reduce(0, +)
        return Double(total) / 3600.0
    }
}
