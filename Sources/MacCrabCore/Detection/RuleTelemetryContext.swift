import Foundation

/// Identifies the process epoch that produced a cumulative observation.
public struct EngineTelemetryIdentity: Codable, Sendable, Equatable {
    public let pid: Int
    public let startedAtUnix: Double
    public let version: String
    public let build: String

    public init(pid: Int, startedAtUnix: Double, version: String, build: String) {
        self.pid = pid
        self.startedAtUnix = startedAtUnix
        self.version = version
        self.build = build
    }

    public init?(heartbeat: [String: Any]) {
        guard let pid = heartbeat["engine_pid"] as? Int, pid > 0,
              let start = heartbeat["engine_started_at_unix"] as? Double,
              start.isFinite, start > 0,
              let version = heartbeat["engine_version"] as? String,
              let build = heartbeat["engine_build"] as? String else { return nil }
        self.init(pid: pid, startedAtUnix: start, version: version, build: build)
    }
}

/// A rule snapshot's age and epoch travel with its counters. Missing entries
/// establish only that no evaluation was recorded, not that a producer died.
public struct RuleTelemetryContext: Sendable {
    // Reader budgets, not producer format limits. Liveness contains only
    // scalar identity/status fields; the rich snapshot also carries collector
    // tables. Permit 64 KiB and 4 MiB respectively, keeping these two metadata
    // reads below 4.1 MiB of input. Rejected liveness leaves identity
    // unavailable; rejected rich metadata leaves the profile unavailable.
    // Neither file is partially decoded.
    static let maximumLivenessBytes = 64 * 1_024
    static let maximumRichHeartbeatBytes = 4 * 1_024 * 1_024

    public enum Freshness: String, Codable, Sendable {
        case current, missing, historical, identityUnknown, heartbeatUnavailable

        public var reason: String {
            switch self {
            case .current: return "Current engine telemetry"
            case .missing: return "Rule telemetry is unavailable"
            case .historical: return "Rule telemetry is historical"
            case .identityUnknown: return "Rule telemetry has no verified engine identity"
            case .heartbeatUnavailable: return "Current engine heartbeat is unavailable"
            }
        }
    }

    public enum Coverage: String, Codable, Sendable {
        case unknown, disabled, unobserved, quiet, matched
    }

    public let freshness: Freshness
    public let snapshotWrittenAt: Date?
    public let ageSeconds: TimeInterval?
    public let engineIdentity: EngineTelemetryIdentity?
    public let ruleProfile: String?
    /// Only verified current counters belong in current coverage surfaces.
    public let statsByID: [String: RuleEngine.RuleStats]
    public let autoDisabledRuleIDs: Set<String>
    private let loadedRuleIDs: Set<String>?
    private let enabledRuleIDs: Set<String>?
    public var current: Bool { freshness == .current }

    public init(
        snapshot: RuleEngine.TelemetrySnapshot?,
        heartbeatIdentity: EngineTelemetryIdentity?,
        heartbeatWrittenAt: Date?,
        ruleProfile: String?,
        now: Date,
        maximumAge: TimeInterval = 120
    ) {
        snapshotWrittenAt = snapshot?.writtenAt
        ageSeconds = snapshot.map { now.timeIntervalSince($0.writtenAt) }
        engineIdentity = snapshot?.engineIdentity
        let heartbeatAge = heartbeatWrittenAt.map { now.timeIntervalSince($0) }
        let heartbeatFresh = heartbeatAge.map { $0 >= 0 && $0 <= maximumAge } ?? false
        if snapshot == nil {
            freshness = .missing
        } else if snapshot?.engineIdentity == nil || heartbeatIdentity == nil {
            freshness = .identityUnknown
        } else if !heartbeatFresh {
            freshness = .heartbeatUnavailable
        } else if snapshot?.engineIdentity != heartbeatIdentity
                    || !(ageSeconds.map { $0 >= 0 && $0 <= maximumAge } ?? false)
                    || (snapshot?.writtenAt.timeIntervalSince1970 ?? 0)
                        < (heartbeatIdentity?.startedAtUnix ?? .infinity) {
            freshness = .historical
        } else {
            freshness = .current
        }
        self.ruleProfile = heartbeatFresh ? ruleProfile : nil
        if freshness == .current, let snapshot {
            statsByID = Dictionary(snapshot.stats.map { ($0.ruleId, $0) }, uniquingKeysWith: { _, last in last })
            autoDisabledRuleIDs = Set(snapshot.autoDisabledRuleIds)
            loadedRuleIDs = snapshot.loadedRuleIds.map { Set($0) }
            enabledRuleIDs = snapshot.enabledRuleIds.map { Set($0) }
        } else {
            statsByID = [:]
            autoDisabledRuleIDs = []
            loadedRuleIDs = nil
            enabledRuleIDs = nil
        }
    }

    public func coverage(ruleID: String, status: String, enabled: Bool) -> Coverage {
        if current, let loadedRuleIDs, let enabledRuleIDs {
            guard loadedRuleIDs.contains(ruleID) else { return .unknown }
            guard enabledRuleIDs.contains(ruleID) else { return .disabled }
            guard let stats = statsByID[ruleID], stats.evaluationCount > 0 else { return .unobserved }
            return stats.fireCount > 0 ? .matched : .quiet
        }
        if !enabled || status.lowercased() == "deprecated" { return .disabled }
        if autoDisabledRuleIDs.contains(ruleID) { return .disabled }
        if let ruleProfile, ruleProfile != "all", status.lowercased() != "stable" {
            return .disabled
        }
        return .unknown
    }

    public static func load(
        directory: String, now: Date = Date(), maximumAge: TimeInterval = 120
    ) -> RuleTelemetryContext {
        func object(_ filename: String, maximumBytes: Int) -> [String: Any]? {
            guard let data = BoundedRegularFileReader.read(
                at: directory + "/" + filename, maximumBytes: maximumBytes
            ) else { return nil }
            return try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        }
        let liveness = object("heartbeat.json", maximumBytes: maximumLivenessBytes)
        let rich = object("heartbeat_rich.json", maximumBytes: maximumRichHeartbeatBytes)
        // The liveness file is the current epoch authority. Rich metadata from
        // another epoch must never supply the active rule profile.
        let identity = liveness.flatMap(EngineTelemetryIdentity.init(heartbeat:))
        let richIdentity = rich.flatMap(EngineTelemetryIdentity.init(heartbeat:))
        let richAge = (rich?["written_at_unix"] as? Double).map { now.timeIntervalSince1970 - $0 }
        let profile = identity != nil && identity == richIdentity
            && (richAge.map { $0 >= 0 && $0 <= maximumAge } ?? false)
            ? (rich?["rule_profile"] as? String)?.lowercased() : nil
        return .init(
            snapshot: RuleEngine.readTelemetrySnapshot(at: directory + "/rule_telemetry.json"),
            heartbeatIdentity: identity,
            heartbeatWrittenAt: (liveness?["written_at_unix"] as? Double).map(Date.init(timeIntervalSince1970:)),
            ruleProfile: profile, now: now, maximumAge: maximumAge
        )
    }
}
