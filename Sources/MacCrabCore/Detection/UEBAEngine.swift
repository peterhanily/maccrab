// UEBAEngine.swift
// MacCrabCore
//
// Per-user entity behaviour analytics. Tracks a rolling baseline for
// every observed user — login hours, SSH remote IPs, tool-usage
// frequencies — and flags deviations. Addresses the "80% of attacks
// are malware-free / credential abuse" gap that signature and rule
// engines miss.
//
// Cold-start guard: anomalies only fire once a user has accumulated
// minObservationsForScoring events (default 100). New users are
// baselined silently for that period.

import Foundation
import os.log

// MARK: - UserEntityProfile

public struct UserEntityProfile: Codable, Sendable, Hashable {

    public let userName: String
    public var firstSeen: Date
    public var lastObserved: Date

    /// Rolling histogram of observed launch hours (local time), one
    /// bucket per hour of day. Combined across weekdays and weekends —
    /// used as the stable public API (tests depend on hourFrequency(_:)).
    public var loginHourCounts: [Int]

    /// Hour-of-day histograms split by weekday (Mon–Fri) and weekend
    /// (Sat–Sun). Gives sharper anomaly precision: 3 AM on a Saturday
    /// is less suspicious for a night-owl developer than 3 AM on a
    /// Tuesday.
    public var weekdayHourCounts: [Int]
    public var weekendHourCounts: [Int]
    public var weekdayObservations: Int
    public var weekendObservations: Int

    /// Set of SSH source IPs this user has logged in from.
    public var sshRemoteIPs: Set<String>

    /// Per-executable launch counts.
    public var toolUsage: [String: Int]

    public var totalObservations: Int

    public init(userName: String, now: Date = Date()) {
        self.userName = userName
        self.firstSeen = now
        self.lastObserved = now
        self.loginHourCounts = Array(repeating: 0, count: 24)
        self.weekdayHourCounts = Array(repeating: 0, count: 24)
        self.weekendHourCounts = Array(repeating: 0, count: 24)
        self.weekdayObservations = 0
        self.weekendObservations = 0
        self.sshRemoteIPs = []
        self.toolUsage = [:]
        self.totalObservations = 0
    }

    // MARK: - Codable (backward-compatible)

    private enum CodingKeys: String, CodingKey {
        case userName, firstSeen, lastObserved, loginHourCounts
        case weekdayHourCounts, weekendHourCounts
        case weekdayObservations, weekendObservations
        case sshRemoteIPs, toolUsage, totalObservations
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        userName              = try c.decode(String.self,   forKey: .userName)
        firstSeen             = try c.decode(Date.self,     forKey: .firstSeen)
        lastObserved          = try c.decode(Date.self,     forKey: .lastObserved)
        loginHourCounts       = try c.decode([Int].self,    forKey: .loginHourCounts)
        weekdayHourCounts     = try c.decodeIfPresent([Int].self, forKey: .weekdayHourCounts)
                                    ?? Array(repeating: 0, count: 24)
        weekendHourCounts     = try c.decodeIfPresent([Int].self, forKey: .weekendHourCounts)
                                    ?? Array(repeating: 0, count: 24)
        weekdayObservations   = try c.decodeIfPresent(Int.self, forKey: .weekdayObservations) ?? 0
        weekendObservations   = try c.decodeIfPresent(Int.self, forKey: .weekendObservations) ?? 0
        sshRemoteIPs          = try c.decode(Set<String>.self,     forKey: .sshRemoteIPs)
        toolUsage             = try c.decode([String: Int].self,   forKey: .toolUsage)
        totalObservations     = try c.decode(Int.self,    forKey: .totalObservations)
    }

    // MARK: - Frequency helpers

    /// Ratio of combined (weekday + weekend) observations at this hour.
    /// Stable public API — tests and callers that don't need weekday
    /// precision use this.
    public func hourFrequency(_ hour: Int) -> Double {
        guard (0..<24).contains(hour), totalObservations > 0 else { return 0 }
        return Double(loginHourCounts[hour]) / Double(totalObservations)
    }

    /// Ratio of weekday-only (or weekend-only) observations at this
    /// hour. Returns 0 when the corresponding observation count is too
    /// small to be meaningful (< 5 obs). Falls back to the combined
    /// `hourFrequency` when the split bucket is under-sampled.
    public func hourFrequency(_ hour: Int, isWeekend: Bool) -> Double {
        guard (0..<24).contains(hour) else { return 0 }
        let obs = isWeekend ? weekendObservations : weekdayObservations
        guard obs >= 5 else {
            // Not enough weekday/weekend data yet — fall back to combined.
            return hourFrequency(hour)
        }
        let counts = isWeekend ? weekendHourCounts : weekdayHourCounts
        return Double(counts[hour]) / Double(obs)
    }

    /// True when the tool has never (or almost never) been seen. Uses a
    /// flat minimum-count threshold rather than Welford for v1 since
    /// tool-usage distributions are heavy-tailed and z-score on counts
    /// is unstable for rare tools.
    public func toolIsNovel(_ path: String) -> Bool {
        (toolUsage[path] ?? 0) == 0
    }
}

// MARK: - UEBAAnomaly

public struct UEBAAnomaly: Sendable, Hashable {
    public enum Kind: String, Sendable, Hashable, CaseIterable {
        case unusualLoginHour   // activity at an hour < 2% of baseline
        case newSSHSource        // SSH from an IP never seen before
        case novelTool            // process executable never launched by this user before
        case coldStart            // cold-start gate still active (no anomalies possible yet)
    }
    public let kind: Kind
    public let userName: String
    public let detail: String
    public let severity: Severity

    public init(kind: Kind, userName: String, detail: String, severity: Severity) {
        self.kind = kind
        self.userName = userName
        self.detail = detail
        self.severity = severity
    }
}

// MARK: - UEBAEngine

public actor UEBAEngine {

    private let logger = Logger(subsystem: "com.maccrab.detection", category: "ueba")

    /// Before this many observations, we baseline silently instead of
    /// alerting. Default 100 events — roughly a day of normal use.
    private let minObservationsForScoring: Int

    /// Hour-frequency ratio below which we call it "unusual". Applies
    /// only once past the cold-start gate.
    private let hourAnomalyThreshold: Double

    private var profiles: [String: UserEntityProfile] = [:]

    /// Optional on-disk path for profile persistence. When set, load()
    /// is called during init and save() can be invoked periodically by
    /// a daemon timer.
    private let persistencePath: String?

    public init(
        minObservationsForScoring: Int = 100,
        hourAnomalyThreshold: Double = 0.02,
        persistencePath: String? = nil
    ) {
        self.minObservationsForScoring = minObservationsForScoring
        self.hourAnomalyThreshold = hourAnomalyThreshold
        self.persistencePath = persistencePath
        if let path = persistencePath {
            Task { await self.load(from: path) }
        }
    }

    // MARK: - Persistence

    /// Serialize every profile to JSON at `persistencePath`. Daemon
    /// timer should call this every 5 minutes or on graceful shutdown.
    public func save() async {
        guard let path = persistencePath else { return }
        let list = Array(profiles.values)
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        do {
            let data = try encoder.encode(list)
            try data.write(to: URL(fileURLWithPath: path), options: .atomic)
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o600], ofItemAtPath: path
            )
        } catch {
            logger.error("UEBA save failed: \(error.localizedDescription)")
        }
    }

    /// Load profiles from disk. Called during init when a
    /// persistencePath is provided.
    private func load(from path: String) async {
        guard FileManager.default.fileExists(atPath: path),
              let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
            return
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        do {
            let list = try decoder.decode([UserEntityProfile].self, from: data)
            profiles = Dictionary(uniqueKeysWithValues: list.map { ($0.userName, $0) })
            logger.info("UEBA loaded \(list.count) profiles from disk")
        } catch {
            logger.error("UEBA load failed: \(error.localizedDescription)")
        }
    }

    // MARK: - Observation

    /// Absorb a process event into the appropriate user's profile.
    /// Returns any anomalies the observation surfaced — callers can
    /// turn those into Alerts or feed them into the detection pipeline.
    @discardableResult
    public func observe(event: Event, now: Date = Date()) -> [UEBAAnomaly] {
        // UEBA only cares about process-launch events — file/network
        // events roll up under their originating process.
        guard event.eventCategory == .process,
              event.eventAction == "exec" || event.eventAction == "fork" else {
            return []
        }
        let user = event.process.userName
        guard !user.isEmpty else { return [] }

        var profile = profiles[user] ?? UserEntityProfile(userName: user, now: now)
        let cal = Calendar.current
        let hour = cal.component(.hour, from: now)
        let weekday = cal.component(.weekday, from: now) // 1=Sun, 7=Sat
        let isWeekend = weekday == 1 || weekday == 7
        let sshIP = event.process.session?.sshRemoteIP
        let toolPath = event.process.executable

        // Anomaly assessment happens BEFORE the profile is updated so
        // the observation itself doesn't baseline away its own novelty.
        let anomalies = assess(
            profile: profile, hour: hour, isWeekend: isWeekend,
            sshIP: sshIP, toolPath: toolPath
        )

        // Fold the observation in.
        profile.totalObservations += 1
        profile.lastObserved = now
        if (0..<24).contains(hour) {
            profile.loginHourCounts[hour] += 1
            if isWeekend {
                profile.weekendHourCounts[hour] += 1
                profile.weekendObservations += 1
            } else {
                profile.weekdayHourCounts[hour] += 1
                profile.weekdayObservations += 1
            }
        }
        if let ip = sshIP {
            profile.sshRemoteIPs.insert(ip)
        }
        profile.toolUsage[toolPath, default: 0] += 1
        profiles[user] = profile

        return anomalies
    }

    // MARK: - Queries

    public func profile(for userName: String) -> UserEntityProfile? {
        profiles[userName]
    }

    public func stats() -> (users: Int, totalObservations: Int) {
        let total = profiles.values.reduce(0) { $0 + $1.totalObservations }
        return (profiles.count, total)
    }

    public func allProfiles() -> [UserEntityProfile] {
        Array(profiles.values)
    }

    // MARK: - Private assessment

    private func assess(
        profile: UserEntityProfile,
        hour: Int,
        isWeekend: Bool,
        sshIP: String?,
        toolPath: String
    ) -> [UEBAAnomaly] {
        // Cold start — no alerting yet, we're still gathering baseline.
        if profile.totalObservations < minObservationsForScoring {
            return []
        }

        var out: [UEBAAnomaly] = []

        // Unusual login hour — uses weekday/weekend-split frequency when
        // the split bucket is adequately sampled, combined otherwise.
        if (0..<24).contains(hour) {
            let freq = profile.hourFrequency(hour, isWeekend: isWeekend)
            if freq < hourAnomalyThreshold {
                let dayKind = isWeekend ? "weekend" : "weekday"
                out.append(UEBAAnomaly(
                    kind: .unusualLoginHour,
                    userName: profile.userName,
                    detail: "Activity at \(dayKind) hour \(hour):00 has \(String(format: "%.2f%%", freq * 100)) baseline frequency",
                    severity: offHoursSeverity(hour: hour)
                ))
            }
        }

        // New SSH source IP
        if let ip = sshIP, !profile.sshRemoteIPs.contains(ip) {
            out.append(UEBAAnomaly(
                kind: .newSSHSource,
                userName: profile.userName,
                detail: "First-ever SSH login from \(ip) for user \(profile.userName)",
                severity: .high
            ))
        }

        // Novel tool
        if profile.toolIsNovel(toolPath) {
            out.append(UEBAAnomaly(
                kind: .novelTool,
                userName: profile.userName,
                detail: "First-ever execution of \(toolPath) for user \(profile.userName)",
                severity: .low
            ))
        }

        return out
    }

    /// Maps hour-of-day to anomaly severity for unusual login-hour
    /// detections. Deep-night and late-night hours are escalated because
    /// autonomous/automated access at those times is rare on user machines
    /// and warrants faster triage.
    private func offHoursSeverity(hour: Int) -> Severity {
        switch hour {
        case 0..<5:   return .high    // Deep night (midnight–4 AM)
        case 5..<7:   return .medium  // Very early morning
        case 7..<19:  return .low     // Core hours — freq < 2% is already odd
        case 19..<22: return .medium  // Evening
        default:      return .high    // Late night (10 PM–midnight)
        }
    }
}
